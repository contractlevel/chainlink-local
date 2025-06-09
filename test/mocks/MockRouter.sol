// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import {IAny2EVMMessageReceiver} from "@chainlink/contracts-ccip/src/v0.8/ccip/interfaces/IAny2EVMMessageReceiver.sol";
import {IRouter} from "@chainlink/contracts-ccip/src/v0.8/ccip/interfaces/IRouter.sol";
import {IRouterClient} from "@chainlink/contracts-ccip/src/v0.8/ccip/interfaces/IRouterClient.sol";

import {CallWithExactGas} from "@chainlink/contracts-ccip/src/v0.8/shared/call/CallWithExactGas.sol";
import {Client} from "@chainlink/contracts-ccip/src/v0.8/ccip/libraries/Client.sol";
import {Internal} from "@chainlink/contracts-ccip/src/v0.8/ccip/libraries/Internal.sol";

import {IERC20} from
    "@chainlink/contracts-ccip/src/v0.8/vendor/openzeppelin-solidity/v4.8.3/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from
    "@chainlink/contracts-ccip/src/v0.8/vendor/openzeppelin-solidity/v4.8.3/contracts/token/ERC20/utils/SafeERC20.sol";
import {ERC165Checker} from
    "@chainlink/contracts-ccip/src/v0.8/vendor/openzeppelin-solidity/v5.0.2/contracts/utils/introspection/ERC165Checker.sol";

contract MockCCIPRouter is IRouter, IRouterClient {
    using SafeERC20 for IERC20;
    using ERC165Checker for address;

    error InvalidAddress(bytes encodedAddress);
    error InvalidExtraArgsTag();
    error ReceiverError(bytes err);

    event MessageExecuted(bytes32 messageId, uint64 sourceChainSelector, address offRamp, bytes32 calldataHash);
    event MsgExecuted(bool success, bytes retData, uint256 gasUsed);

    uint16 public constant GAS_FOR_CALL_EXACT_CHECK = 5_000;
    uint32 public constant DEFAULT_GAS_LIMIT = 200_000;

    uint256 internal s_mockFeeTokenAmount; //use setFee() to change to non-zero to test fees

    mapping(address peer => uint64 chainSelector) s_peerToChainSelector;

    function routeMessage(
        Client.Any2EVMMessage calldata message,
        uint16 gasForCallExactCheck,
        uint256 gasLimit,
        address receiver
    ) external returns (bool success, bytes memory retData, uint256 gasUsed) {
        return _routeMessage(message, gasForCallExactCheck, gasLimit, receiver);
    }

    function _routeMessage(
        Client.Any2EVMMessage memory message,
        uint16 gasForCallExactCheck,
        uint256 gasLimit,
        address receiver
    ) internal returns (bool success, bytes memory retData, uint256 gasUsed) {
        // There are three cases in which we skip calling the receiver:
        // 1. If the message data is empty AND the gas limit is 0.
        //          This indicates a message that only transfers tokens. It is valid to only send tokens to a contract
        //          that supports the IAny2EVMMessageReceiver interface, but without this first check we would call the
        //          receiver without any gas, which would revert the transaction.
        // 2. If the receiver is not a contract.
        // 3. If the receiver is a contract but it does not support the IAny2EVMMessageReceiver interface.
        //
        // The ordering of these checks is important, as the first check is the cheapest to execute.
        if (
            (message.data.length == 0 && gasLimit == 0) || receiver.code.length == 0
                || !receiver.supportsInterface(type(IAny2EVMMessageReceiver).interfaceId)
        ) {
            return (true, "", 0);
        }

        bytes memory data = abi.encodeWithSelector(IAny2EVMMessageReceiver.ccipReceive.selector, message);

        (success, retData, gasUsed) =
            _callWithExactGasSafeReturnData(data, receiver, gasLimit, gasForCallExactCheck, Internal.MAX_RET_BYTES);

        // Event to assist testing, does not exist on real deployments
        emit MsgExecuted(success, retData, gasUsed);

        // Real router event
        emit MessageExecuted(message.messageId, message.sourceChainSelector, msg.sender, keccak256(data));
        return (success, retData, gasUsed);
    }

    /// @notice Sends the tx locally to the receiver instead of on the destination chain.
    /// @dev Ignores destinationChainSelector
    /// @dev Returns a mock message ID, which is not calculated from the message contents in the
    /// same way as the real message ID.
    function ccipSend(uint64 destinationChainSelector, Client.EVM2AnyMessage calldata message)
        external
        payable
        returns (bytes32)
    {
        if (message.receiver.length != 32) revert InvalidAddress(message.receiver);
        uint256 decodedReceiver = abi.decode(message.receiver, (uint256));
        // We want to disallow sending to address(0) and to precompiles, which exist on address(1) through address(9).
        if (decodedReceiver > type(uint160).max || decodedReceiver < 10) revert InvalidAddress(message.receiver);

        uint256 feeTokenAmount = getFee(destinationChainSelector, message);
        if (message.feeToken == address(0)) {
            if (msg.value < feeTokenAmount) revert InsufficientFeeTokenAmount();
        } else {
            if (msg.value > 0) revert InvalidMsgValue();
            IERC20(message.feeToken).safeTransferFrom(msg.sender, address(this), feeTokenAmount);
        }

        address receiver = address(uint160(decodedReceiver));
        uint256 gasLimit = _fromBytes(message.extraArgs).gasLimit;
        bytes32 mockMsgId = keccak256(abi.encode(message));

        Client.Any2EVMMessage memory executableMsg = Client.Any2EVMMessage({
            messageId: mockMsgId,
            sourceChainSelector: s_peerToChainSelector[msg.sender],
            sender: abi.encode(msg.sender),
            data: message.data,
            destTokenAmounts: message.tokenAmounts
        });

        for (uint256 i = 0; i < message.tokenAmounts.length; ++i) {
            IERC20(message.tokenAmounts[i].token).safeTransferFrom(msg.sender, receiver, message.tokenAmounts[i].amount);
        }

        (bool success, bytes memory retData,) =
            _routeMessage(executableMsg, GAS_FOR_CALL_EXACT_CHECK, gasLimit, receiver);

        if (!success) revert ReceiverError(retData);

        return mockMsgId;
    }

    function _fromBytes(bytes calldata extraArgs) internal pure returns (Client.EVMExtraArgsV2 memory) {
        if (extraArgs.length == 0) {
            return Client.EVMExtraArgsV2({gasLimit: DEFAULT_GAS_LIMIT, allowOutOfOrderExecution: false});
        }

        bytes4 extraArgsTag = bytes4(extraArgs);
        if (extraArgsTag == Client.EVM_EXTRA_ARGS_V2_TAG) {
            return abi.decode(extraArgs[4:], (Client.EVMExtraArgsV2));
        } else if (extraArgsTag == Client.EVM_EXTRA_ARGS_V1_TAG) {
            return
                Client.EVMExtraArgsV2({gasLimit: abi.decode(extraArgs[4:], (uint256)), allowOutOfOrderExecution: false});
        }

        revert InvalidExtraArgsTag();
    }

    /// @notice Always returns true to make sure this check can be performed on any chain.
    function isChainSupported(uint64) external pure returns (bool supported) {
        return true;
    }

    /// @notice Returns an empty array.
    function getSupportedTokens(uint64) external pure returns (address[] memory tokens) {
        return new address[](0);
    }

    /// @notice Returns 0 as the fee is not supported in this mock contract.
    function getFee(uint64, Client.EVM2AnyMessage memory) public view returns (uint256) {
        return s_mockFeeTokenAmount;
    }

    /// @notice Sets the fees returned by getFee but is only checked when using native fee tokens
    function setFee(uint256 feeAmount) external {
        s_mockFeeTokenAmount = feeAmount;
    }

    /// @notice Always returns address(1234567890)
    function getOnRamp(uint64 /* destChainSelector */ ) external pure returns (address onRampAddress) {
        return address(1234567890);
    }

    /// @notice Always returns true
    function isOffRamp(uint64, /* sourceChainSelector */ address /* offRamp */ ) external pure returns (bool) {
        return true;
    }

    function setPeerToChainSelector(address peer, uint64 chainSelector) external {
        s_peerToChainSelector[peer] = chainSelector;
    }

    /// @notice calls target address with exactly gasAmount gas and payload as calldata.
    /// Account for gasForCallExactCheck gas that will be used by this function. Will revert
    /// if the target is not a contact. Will revert when there is not enough gas to call the
    /// target with gasAmount gas.
    /// @dev Caps the return data length, which makes it immune to gas bomb attacks.
    /// @dev Return data cap logic borrowed from
    /// https://github.com/nomad-xyz/ExcessivelySafeCall/blob/main/src/ExcessivelySafeCall.sol.
    /// @return success whether the call succeeded
    /// @return retData the return data from the call, capped at maxReturnBytes bytes
    /// @return gasUsed the gas used by the external call. Does not include the overhead of this function.
    function _callWithExactGasSafeReturnData(
        bytes memory payload,
        address target,
        uint256 gasLimit,
        uint16 gasForCallExactCheck,
        uint16 maxReturnBytes
    ) internal returns (bool success, bytes memory retData, uint256 gasUsed) {
        // allocate retData memory ahead of time
        retData = new bytes(maxReturnBytes);

        assembly {
            // solidity calls check that a contract actually exists at the destination, so we do the same
            // Note we do this check prior to measuring gas so gasForCallExactCheck (our "cushion")
            // doesn't need to account for it.
            if iszero(extcodesize(target)) {
                mstore(0x0, NO_CONTRACT_SIG)
                revert(0x0, 0x4)
            }

            let g := gas()
            // Compute g -= gasForCallExactCheck and check for underflow
            // The gas actually passed to the callee is _min(gasAmount, 63//64*gas available).
            // We want to ensure that we revert if gasAmount >  63//64*gas available
            // as we do not want to provide them with less, however that check itself costs
            // gas. gasForCallExactCheck ensures we have at least enough gas to be able
            // to revert if gasAmount >  63//64*gas available.
            if lt(g, gasForCallExactCheck) {
                mstore(0x0, NO_GAS_FOR_CALL_EXACT_CHECK_SIG)
                revert(0x0, 0x4)
            }
            g := sub(g, gasForCallExactCheck)
            // if g - g//64 <= gasAmount, revert. We subtract g//64 because of EIP-150
            // if iszero(gt(sub(g, div(g, 64)), gasLimit)) {
            //     mstore(0x0, NOT_ENOUGH_GAS_FOR_CALL_SIG)
            //     revert(0x0, 0x4)
            // }

            // We save the gas before the call so we can calculate how much gas the call used
            let gasBeforeCall := gas()
            // call and return whether we succeeded. ignore return data
            // call(gas,addr,value,argsOffset,argsLength,retOffset,retLength)
            success := call(gasLimit, target, 0, add(payload, 0x20), mload(payload), 0x0, 0x0)
            gasUsed := sub(gasBeforeCall, gas())

            // limit our copy to maxReturnBytes bytes
            let toCopy := returndatasize()
            if gt(toCopy, maxReturnBytes) { toCopy := maxReturnBytes }
            // Store the length of the copied bytes
            mstore(retData, toCopy)
            // copy the bytes from retData[0:_toCopy]
            returndatacopy(add(retData, 0x20), 0x0, toCopy)
        }
        return (success, retData, gasUsed);
    }
}
