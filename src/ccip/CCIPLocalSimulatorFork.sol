// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.19;

import {Test, Vm} from "forge-std/Test.sol";
import {Register} from "./Register.sol";
import {Internal} from "@chainlink/contracts-ccip/src/v0.8/ccip/libraries/Internal.sol";
import {IERC20} from
    "@chainlink/contracts-ccip/src/v0.8/vendor/openzeppelin-solidity/v4.8.3/contracts/token/ERC20/IERC20.sol";

contract USDCTokenPool {
    struct MessageAndAttestation {
        bytes message;
        bytes attestation;
    }
}

/// @title IRouterFork Interface
interface IRouterFork {
    /**
     * @notice Structure representing an offRamp configuration
     *
     * @param sourceChainSelector - The chain selector for the source chain
     * @param offRamp - The address of the offRamp contract
     */
    struct OffRamp {
        uint64 sourceChainSelector;
        address offRamp;
    }

    /**
     * @notice Gets the list of offRamps
     *
     * @return offRamps - Array of OffRamp structs
     */
    function getOffRamps() external view returns (OffRamp[] memory);
}

/// @title IEVM2EVMOffRampFork Interface
interface IEVM2EVMOffRampFork {
    /**
     * @notice Executes a single CCIP message on the offRamp
     *
     * @param message - The CCIP message to be executed
     * @param offchainTokenData - Additional offchain token data
     */
    function executeSingleMessage(
        Internal.EVM2EVMMessage memory message,
        bytes[] memory offchainTokenData,
        uint32[] memory tokenGasOverrides
    ) external;
}

/// @title CCIPLocalSimulatorFork
/// @notice Works with Foundry only
contract CCIPLocalSimulatorFork is Test {
    /**
     * @notice Event emitted when a CCIP send request is made
     *
     * @param message - The EVM2EVM message that was sent
     */
    event CCIPSendRequested(Internal.EVM2EVMMessage message);

    /// @notice The immutable register instance
    Register immutable i_register;

    /// @notice The address of the LINK faucet
    address constant LINK_FAUCET = 0x4281eCF07378Ee595C564a59048801330f3084eE;

    /// @notice Mapping to track processed messages
    mapping(bytes32 messageId => bool isProcessed) internal s_processedMessages;

    /**
     * @notice Constructor to initialize the contract
     */
    constructor() {
        vm.recordLogs();
        i_register = new Register();
        vm.makePersistent(address(i_register));
    }

    /**
     * @notice To be called after the sending of the cross-chain message (`ccipSend`). Goes through the list of past logs and looks for the `CCIPSendRequested` event. Switches to a destination network fork. Routes the sent cross-chain message on the destination network.
     *
     * @param forkId - The ID of the destination network fork. This is the returned value of `createFork()` or `createSelectFork()`
     */
    function switchChainAndRouteMessage(uint256 forkId) external {
        Internal.EVM2EVMMessage memory message;
        Vm.Log[] memory entries = vm.getRecordedLogs();
        uint256 length = entries.length;
        for (uint256 i; i < length; ++i) {
            if (entries[i].topics[0] == CCIPSendRequested.selector) {
                message = abi.decode(entries[i].data, (Internal.EVM2EVMMessage));
                if (!s_processedMessages[message.messageId]) {
                    s_processedMessages[message.messageId] = true;
                    break;
                }
            }
        }

        vm.selectFork(forkId);
        assertEq(vm.activeFork(), forkId);

        IRouterFork.OffRamp[] memory offRamps =
            IRouterFork(i_register.getNetworkDetails(block.chainid).routerAddress).getOffRamps();
        length = offRamps.length;

        for (uint256 i = length; i > 0; --i) {
            if (offRamps[i - 1].sourceChainSelector == message.sourceChainSelector) {
                vm.startPrank(offRamps[i - 1].offRamp);
                uint256 numberOfTokens = message.tokenAmounts.length;
                bytes[] memory offchainTokenData = new bytes[](numberOfTokens);
                uint32[] memory tokenGasOverrides = new uint32[](numberOfTokens);
                for (uint256 j; j < numberOfTokens; ++j) {
                    tokenGasOverrides[j] = uint32(message.gasLimit);
                }
                IEVM2EVMOffRampFork(offRamps[i - 1].offRamp).executeSingleMessage(
                    message, offchainTokenData, tokenGasOverrides
                );
                vm.stopPrank();
                break;
            }
        }
    }

    /**
     * @notice Similar to switchChainAndRouteMessage but allows USDC transfer
     * @param forkId The ID of the destination network fork
     * @param attesters The attesters to be used
     * @param attesterPks The private keys of the attesters
     */
    function switchChainAndRouteMessageWithUSDC(
        uint256 forkId,
        address[] memory attesters,
        uint256[] memory attesterPks
    ) external {
        Internal.EVM2EVMMessage memory message;
        bytes memory cctpMessage;

        Vm.Log[] memory entries = vm.getRecordedLogs();
        uint256 length = entries.length;

        for (uint256 i; i < length; ++i) {
            if (entries[i].topics[0] == CCIPSendRequested.selector) {
                message = abi.decode(entries[i].data, (Internal.EVM2EVMMessage));
                if (!s_processedMessages[message.messageId]) {
                    s_processedMessages[message.messageId] = true;
                }
            }
            if (entries[i].topics[0] == keccak256("MessageSent(bytes)")) {
                cctpMessage = abi.decode(entries[i].data, (bytes));
            }
        }

        require(cctpMessage.length > 0, "No CCTP message found");
        bytes[] memory offchainTokenData = _createOffchainTokenData(cctpMessage, attesters, attesterPks);

        vm.selectFork(forkId);
        assertEq(vm.activeFork(), forkId);

        IRouterFork.OffRamp[] memory offRamps =
            IRouterFork(i_register.getNetworkDetails(block.chainid).routerAddress).getOffRamps();
        length = offRamps.length;

        for (uint256 i = length; i > 0; --i) {
            if (offRamps[i - 1].sourceChainSelector == message.sourceChainSelector) {
                vm.startPrank(offRamps[i - 1].offRamp);
                uint256 numberOfTokens = message.tokenAmounts.length;
                uint32[] memory tokenGasOverrides = new uint32[](numberOfTokens);
                for (uint256 j; j < numberOfTokens; ++j) {
                    tokenGasOverrides[j] = uint32(message.gasLimit);
                }
                IEVM2EVMOffRampFork(offRamps[i - 1].offRamp).executeSingleMessage(
                    message, offchainTokenData, tokenGasOverrides
                );
                vm.stopPrank();
                break;
            }
        }
    }

    /// @notice Creates the offchainTokenData array with the CCTP message
    /// @param cctpMessage The CCTP message to create the offchainTokenData from
    /// @param attesters The attesters to be used
    /// @param attesterPks The private keys of the attesters
    /// @return offchainTokenData The offchainTokenData array
    function _createOffchainTokenData(
        bytes memory cctpMessage,
        address[] memory attesters,
        uint256[] memory attesterPks
    ) internal pure returns (bytes[] memory offchainTokenData) {
        bytes32 messageHash = keccak256(cctpMessage);
        bytes memory attestation;

        // First, sort attesters and their private keys
        for (uint256 i = 0; i < attesters.length; i++) {
            for (uint256 j = i + 1; j < attesters.length; j++) {
                if (attesters[i] > attesters[j]) {
                    // Swap addresses
                    address tempAddr = attesters[i];
                    attesters[i] = attesters[j];
                    attesters[j] = tempAddr;
                    // Swap private keys
                    uint256 tempKey = attesterPks[i];
                    attesterPks[i] = attesterPks[j];
                    attesterPks[j] = tempKey;
                }
            }
        }

        // Create attestations from all attesters in increasing order
        for (uint256 i = 0; i < attesters.length; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(attesterPks[i], messageHash);

            // Ensure v is exactly 27 or 28 as required by CCTP's ECDSA
            if (v < 27) {
                v += 27;
            }

            // Create signature in the format expected by CCTP's ECDSA
            bytes memory signature = new bytes(65);
            assembly {
                mstore(add(signature, 32), r)
                mstore(add(signature, 64), s)
                mstore8(add(signature, 96), v)
            }

            // Append the signature to the attestation
            attestation = bytes.concat(attestation, signature);
        }

        // Create the message and attestation struct
        USDCTokenPool.MessageAndAttestation memory msgAndAttestation =
            USDCTokenPool.MessageAndAttestation({message: cctpMessage, attestation: attestation});

        // Create offchainTokenData array with our message and attestation
        offchainTokenData = new bytes[](1);
        offchainTokenData[0] = abi.encode(msgAndAttestation);
    }

    /**
     * @notice Returns the default values for currently CCIP supported networks. If network is not present or some of the values are changed, user can manually add new network details using the `setNetworkDetails` function.
     *
     * @param chainId - The blockchain network chain ID. For example 11155111 for Ethereum Sepolia. Not CCIP chain selector.
     *
     * @return networkDetails - The tuple containing:
     *          chainSelector - The unique CCIP Chain Selector.
     *          routerAddress - The address of the CCIP Router contract.
     *          linkAddress - The address of the LINK token.
     *          wrappedNativeAddress - The address of the wrapped native token that can be used for CCIP fees.
     *          ccipBnMAddress - The address of the CCIP BnM token.
     *          ccipLnMAddress - The address of the CCIP LnM token.
     */
    function getNetworkDetails(uint256 chainId) external view returns (Register.NetworkDetails memory) {
        return i_register.getNetworkDetails(chainId);
    }

    /**
     * @notice If network details are not present or some of the values are changed, user can manually add new network details using the `setNetworkDetails` function.
     *
     * @param chainId - The blockchain network chain ID. For example 11155111 for Ethereum Sepolia. Not CCIP chain selector.
     * @param networkDetails - The tuple containing:
     *          chainSelector - The unique CCIP Chain Selector.
     *          routerAddress - The address of the CCIP Router contract.
     *          linkAddress - The address of the LINK token.
     *          wrappedNativeAddress - The address of the wrapped native token that can be used for CCIP fees.
     *          ccipBnMAddress - The address of the CCIP BnM token.
     *          ccipLnMAddress - The address of the CCIP LnM token.
     */
    function setNetworkDetails(uint256 chainId, Register.NetworkDetails memory networkDetails) external {
        i_register.setNetworkDetails(chainId, networkDetails);
    }

    /**
     * @notice Requests LINK tokens from the faucet. The provided amount of tokens are transferred to provided destination address.
     *
     * @param to - The address to which LINK tokens are to be sent.
     * @param amount - The amount of LINK tokens to send.
     *
     * @return success - Returns `true` if the transfer of tokens was successful, otherwise `false`.
     */
    function requestLinkFromFaucet(address to, uint256 amount) external returns (bool success) {
        address linkAddress = i_register.getNetworkDetails(block.chainid).linkAddress;

        vm.startPrank(LINK_FAUCET);
        success = IERC20(linkAddress).transfer(to, amount);
        vm.stopPrank();
    }
}
