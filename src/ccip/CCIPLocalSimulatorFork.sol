// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.19;

import {Test, Vm, console2} from "forge-std/Test.sol";
import {Register} from "./Register.sol";
// import {Internal} from "@chainlink/contracts-ccip/contracts/libraries/Internal.sol";
import {Client} from "@chainlink/contracts-ccip/contracts/libraries/Client.sol";
import {IERC20} from "../vendor/openzeppelin-solidity/v4.8.3/contracts/token/ERC20/IERC20.sol";

// import {USDCTokenPool} from "@chainlink/contracts-ccip/contracts/pools/USDC/USDCTokenPool.sol";

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
     * @notice Return the configured onramp for specific a destination chain.
     *  @param destChainSelector The destination chain Id to get the onRamp for.
     * @return The address of the onRamp.
     */
    function getOnRamp(uint64 destChainSelector) external view returns (address);

    /**
     * @notice Gets the list of offRamps
     *
     * @return offRamps - Array of OffRamp structs
     */
    function getOffRamps() external view returns (OffRamp[] memory);
}

library Internal {
    /// @notice Family-agnostic header for OnRamp & OffRamp messages.
    /// The messageId is not expected to match hash(message), since it may originate from another ramp family.
    struct RampMessageHeader {
        bytes32 messageId; // Unique identifier for the message, generated with the source chain's encoding scheme (i.e. not necessarily abi.encoded).
        uint64 sourceChainSelector; // ─╮ the chain selector of the source chain, note: not chainId.
        uint64 destChainSelector; //    │ the chain selector of the destination chain, note: not chainId.
        uint64 sequenceNumber; //       │ sequence number, not unique across lanes.
        uint64 nonce; // ───────────────╯ nonce for this lane for this sender, not unique across senders/lanes.
    }

    /// @notice Family-agnostic message routed to an OffRamp.
    /// Note: hash(Any2EVMRampMessage) != hash(EVM2AnyRampMessage), hash(Any2EVMRampMessage) != messageId due to encoding
    /// and parameter differences.
    struct Any2EVMRampMessage {
        RampMessageHeader header; // Message header.
        bytes sender; // sender address on the source chain.
        bytes data; // arbitrary data payload supplied by the message sender.
        address receiver; // receiver address on the destination chain.
        uint256 gasLimit; // user supplied maximum gas amount available for dest chain execution.
        Any2EVMTokenTransfer[] tokenAmounts; // array of tokens and amounts to transfer.
    }

    struct Any2EVMTokenTransfer {
        // The source pool EVM address encoded to bytes. This value is trusted as it is obtained through the onRamp. It can
        // be relied upon by the destination pool to validate the source pool.
        bytes sourcePoolAddress;
        address destTokenAddress; // ─╮ Address of destination token
        uint32 destGasAmount; // ─────╯ The amount of gas available for the releaseOrMint and transfer calls on the offRamp.
        // Optional pool data to be transferred to the destination chain. Be default this is capped at
        // CCIP_LOCK_OR_BURN_V1_RET_BYTES bytes. If more data is required, the TokenTransferFeeConfig.destBytesOverhead
        // has to be set for the specific token.
        bytes extraData;
        uint256 amount; // Amount of tokens.
    }

    /// @notice Family-agnostic message emitted from the OnRamp.
    /// Note: hash(Any2EVMRampMessage) != hash(EVM2AnyRampMessage) due to encoding & parameter differences.
    /// messageId = hash(EVM2AnyRampMessage) using the source EVM chain's encoding format.
    struct EVM2AnyRampMessage {
        RampMessageHeader header; // Message header.
        address sender; // sender address on the source chain.
        bytes data; // arbitrary data payload supplied by the message sender.
        bytes receiver; // receiver address on the destination chain.
        bytes extraArgs; // destination-chain specific extra args, such as the gasLimit for EVM chains.
        address feeToken; // fee token.
        uint256 feeTokenAmount; // fee token amount.
        uint256 feeValueJuels; // fee amount in Juels.
        EVM2AnyTokenTransfer[] tokenAmounts; // array of tokens and amounts to transfer.
    }

    struct EVM2AnyTokenTransfer {
        // The source pool EVM address. This value is trusted as it was obtained through the onRamp. It can be relied
        // upon by the destination pool to validate the source pool.
        address sourcePoolAddress;
        // The EVM address of the destination token.
        // This value is UNTRUSTED as any pool owner can return whatever value they want.
        bytes destTokenAddress;
        // Optional pool data to be transferred to the destination chain. Be default this is capped at
        // CCIP_LOCK_OR_BURN_V1_RET_BYTES bytes. If more data is required, the TokenTransferFeeConfig.destBytesOverhead
        // has to be set for the specific token.
        bytes extraData;
        uint256 amount; // Amount of tokens.
        // Destination chain data used to execute the token transfer on the destination chain. For an EVM destination, it
        // consists of the amount of gas available for the releaseOrMint and transfer calls made by the offRamp.
        bytes destExecData;
    }
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
        Internal.Any2EVMRampMessage memory message,
        bytes[] calldata offchainTokenData,
        uint32[] calldata tokenGasOverrides
    ) external;
}

interface InternalPreV1dot6 {
    struct EVM2EVMMessage {
        uint64 sourceChainSelector; // ────────╮ the chain selector of the source chain, note: not chainId
        address sender; // ────────────────────╯ sender address on the source chain
        address receiver; // ──────────────────╮ receiver address on the destination chain
        uint64 sequenceNumber; // ─────────────╯ sequence number, not unique across lanes
        uint256 gasLimit; //                     user supplied maximum gas amount available for dest chain execution
        bool strict; // ───────────────────────╮ DEPRECATED
        uint64 nonce; //                       │ nonce for this lane for this sender, not unique across senders/lanes
        address feeToken; // ──────────────────╯ fee token
        uint256 feeTokenAmount; //               fee token amount
        bytes data; //                           arbitrary data payload supplied by the message sender
        Client.EVMTokenAmount[] tokenAmounts; // array of tokens and amounts to transfer
        bytes[] sourceTokenData; //              array of token data, one per token
        bytes32 messageId; //                    a hash of the message data
    }
}

interface IEVM2EVMOffRampPreV1dot6Fork {
    function executeSingleMessage(
        InternalPreV1dot6.EVM2EVMMessage memory message,
        bytes[] memory offchainTokenData,
        uint32[] memory tokenGasOverrides
    ) external;
}

/// @title CCIPLocalSimulatorFork
/// @notice Works with Foundry only
contract CCIPLocalSimulatorFork is Test {
    /**
     * @notice Events emitted when a CCIP send request is made
     */
    event CCIPSendRequested(InternalPreV1dot6.EVM2EVMMessage message);
    event CCIPMessageSent(
        uint64 indexed destChainSelector, uint64 indexed sequenceNumber, Internal.EVM2AnyRampMessage message
    );

    error InvalidExtraArgsTag();

    uint32 public constant DEFAULT_GAS_LIMIT = 200_000;

    /// @notice The immutable register instance
    Register immutable i_register;

    /// @notice The address of the LINK faucet
    address constant LINK_FAUCET = 0x4281eCF07378Ee595C564a59048801330f3084eE;

    /// @notice Mapping to track processed messages
    mapping(bytes32 messageId => bool isProcessed) internal s_processedMessages;

    bool internal s_routeWithUSDC;
    address[] internal s_cctpAttesters;
    uint256[] internal s_cctpAttesterPks;

    uint256 internal constant LEGACY_CCTP_MESSAGE_SIZE = 248;
    uint256 internal constant CCV_CCTP_MESSAGE_SIZE = 412;

    /**
     * @notice Constructor to initialize the contract
     */
    constructor() {
        vm.recordLogs();
        i_register = new Register();
        vm.makePersistent(address(i_register));
    }

    /**
     * @notice  To be called after the sending of the cross-chain message (`ccipSend`).
     *          Goes through the list of past logs and looks for the `CCIPSendRequested` and `CCIPMessageSent` events.
     *          Switches to a destination network fork. Routes the sent cross-chain message on the destination network.
     *          If you sent more than one message, it will try to route all of them to `forkId`.
     *
     * @param forkId - The ID of the destination network fork. This is the returned value of `createFork()` or `createSelectFork()`
     */
    function switchChainAndRouteMessage(uint256 forkId) external {
        uint256 sourceForkId = vm.activeFork();
        address sourceRouterAddress = i_register.getNetworkDetails(block.chainid).routerAddress;

        uint256[] memory forkIds = new uint256[](1);
        forkIds[0] = forkId;

        _routeCapturedMessages(forkIds, sourceForkId, sourceRouterAddress);
    }

    /**
     * @notice  To be called after the sending of the cross-chain message (`ccipSend`).
     *          Override variant of the `switchChainAndRouteMessage(uint256 forkId)` function in case of multiple destination forks.
     *          Goes through the list of past logs and looks for the `CCIPSendRequested` and `CCIPMessageSent` events.
     *          Loops through provided `forkIds` and tries to route the message to correct destination.
     *          If you haven't provide correct `forkId`, the message will get lost.
     *          If you sent more than one message, it will try to route all of them to correct destinations.
     *
     * @param forkIds - The IDs of the destination network forks. These are the returned values of `createFork()` or `createSelectFork()`
     */
    function switchChainAndRouteMessage(uint256[] memory forkIds) external {
        uint256 sourceForkId = vm.activeFork();
        address sourceRouterAddress = i_register.getNetworkDetails(block.chainid).routerAddress;

        _routeCapturedMessages(forkIds, sourceForkId, sourceRouterAddress);
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
        uint256 sourceForkId = vm.activeFork();
        address sourceRouterAddress = i_register.getNetworkDetails(block.chainid).routerAddress;

        uint256[] memory forkIds = new uint256[](1);
        forkIds[0] = forkId;

        s_routeWithUSDC = true;
        s_cctpAttesters = attesters;
        s_cctpAttesterPks = attesterPks;
        _routeCapturedMessages(forkIds, sourceForkId, sourceRouterAddress);
        delete s_routeWithUSDC;
        delete s_cctpAttesters;
        delete s_cctpAttesterPks;
    }

    function _getCctpMessage(Vm.Log[] memory entries, bytes32 messageId)
        internal
        pure
        returns (bytes memory cctpMessage)
    {
        uint256 length = entries.length;
        bytes32 messageSentTopic = keccak256("MessageSent(bytes)");

        for (uint256 i; i < length; ++i) {
            if (entries[i].topics[0] == messageSentTopic) {
                cctpMessage = abi.decode(entries[i].data, (bytes));
                if (cctpMessage.length < CCV_CCTP_MESSAGE_SIZE) {
                    continue;
                }
                if (_cctpMessageId(cctpMessage) == messageId) {
                    return cctpMessage;
                }
            }
        }

        revert("No CCTP message found");
    }

    function _getLegacyCctpMessage(Vm.Log[] memory entries, bytes memory sourceTokenData)
        internal
        pure
        returns (bytes memory cctpMessage)
    {
        uint64 expectedNonce = _legacySourceTokenDataNonce(sourceTokenData);
        uint32 expectedSourceDomain = _legacySourceTokenDataDomain(sourceTokenData);

        uint256 length = entries.length;
        bytes32 messageSentTopic = keccak256("MessageSent(bytes)");

        for (uint256 i; i < length; ++i) {
            if (entries[i].topics[0] == messageSentTopic) {
                cctpMessage = abi.decode(entries[i].data, (bytes));
                if (cctpMessage.length != LEGACY_CCTP_MESSAGE_SIZE) {
                    continue;
                }
                if (
                    _legacyCctpMessageNonce(cctpMessage) == expectedNonce
                        && _legacyCctpMessageSourceDomain(cctpMessage) == expectedSourceDomain
                ) {
                    return cctpMessage;
                }
            }
        }

        revert("No CCTP message found");
    }

    /// @notice Creates the offchainTokenData array with a CCV CCTP v2 verifier result
    /// @param entries The recorded logs to scan for the CCTP message
    /// @param messageId The CCIP message ID embedded in the CCTP hook data
    /// @return offchainTokenData The offchainTokenData array
    function _createOffchainTokenData(Vm.Log[] memory entries, bytes32 messageId)
        internal
        view
        returns (bytes[] memory offchainTokenData)
    {
        bytes memory cctpMessage = _getCctpMessage(entries, messageId);
        bytes4 versionTag = _cctpVerifierVersion(cctpMessage);
        bytes memory attestation = _createAttestation(cctpMessage);

        offchainTokenData = new bytes[](1);
        offchainTokenData[0] = bytes.concat(versionTag, cctpMessage, attestation);
    }

    function _createLegacyOffchainTokenData(
        uint256 numberOfTokens,
        bytes[] memory sourceTokenData,
        Vm.Log[] memory entries
    ) internal view returns (bytes[] memory offchainTokenData) {
        offchainTokenData = new bytes[](numberOfTokens);
        for (uint256 i; i < numberOfTokens; ++i) {
            if (i >= sourceTokenData.length || sourceTokenData[i].length < 64) {
                continue;
            }

            bytes memory cctpMessage = _getLegacyCctpMessage(entries, sourceTokenData[i]);
            MessageAndAttestation memory msgAndAttestation =
                MessageAndAttestation({message: cctpMessage, attestation: _createAttestation(cctpMessage)});
            offchainTokenData[i] = abi.encode(msgAndAttestation);
        }
    }

    function _createAttestation(bytes memory cctpMessage) internal view returns (bytes memory attestation) {
        bytes32 messageHash = keccak256(cctpMessage);
        address[] memory attesters = s_cctpAttesters;
        uint256[] memory attesterPks = s_cctpAttesterPks;

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
    }

    struct MessageAndAttestation {
        bytes message;
        bytes attestation;
    }

    function _cctpVerifierVersion(bytes memory cctpMessage) internal pure returns (bytes4 versionTag) {
        require(cctpMessage.length >= 380, "Invalid CCTP message");
        assembly {
            versionTag := mload(add(add(cctpMessage, 32), 376))
        }
    }

    function _cctpMessageId(bytes memory cctpMessage) internal pure returns (bytes32 messageId) {
        require(cctpMessage.length >= 412, "Invalid CCTP message");
        assembly {
            messageId := mload(add(add(cctpMessage, 32), 380))
        }
    }

    function _legacySourceTokenDataNonce(bytes memory sourceTokenData) internal pure returns (uint64 nonce) {
        require(sourceTokenData.length >= 64, "Invalid CCTP source token data");
        assembly {
            nonce := mload(add(add(sourceTokenData, 32), sub(mload(sourceTokenData), 64)))
        }
    }

    function _legacySourceTokenDataDomain(bytes memory sourceTokenData) internal pure returns (uint32 domain) {
        require(sourceTokenData.length >= 32, "Invalid CCTP source token data");
        assembly {
            domain := mload(add(add(sourceTokenData, 32), sub(mload(sourceTokenData), 32)))
        }
    }

    function _legacyCctpMessageSourceDomain(bytes memory cctpMessage) internal pure returns (uint32 domain) {
        require(cctpMessage.length >= 8, "Invalid CCTP message");
        assembly {
            domain := shr(224, mload(add(add(cctpMessage, 32), 4)))
        }
    }

    function _legacyCctpMessageNonce(bytes memory cctpMessage) internal pure returns (uint64 nonce) {
        require(cctpMessage.length >= 20, "Invalid CCTP message");
        assembly {
            nonce := shr(192, mload(add(add(cctpMessage, 32), 12)))
        }
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

    /**
     * @notice Internal function to route captured messages to their respective destination forks.
     *
     * @param forkIds - The IDs of the destination network forks. These are the returned values of `createFork()` or `createSelectFork()`, not chainIds.
     * @param sourceForkId - The ID of the source network fork. This is the returned value of `createFork()` or `createSelectFork()`, not chainId.
     * @param sourceRouterAddress - The address of the Router on the source chain.
     */
    function _routeCapturedMessages(uint256[] memory forkIds, uint256 sourceForkId, address sourceRouterAddress)
        internal
    {
        Vm.Log[] memory entries = vm.getRecordedLogs();
        uint256 logsLength = entries.length;

        for (uint256 i; i < logsLength; ++i) {
            if (entries[i].topics[0] == CCIPSendRequested.selector) {
                _routePreV1dot6Message(entries[i], entries, forkIds, sourceForkId, sourceRouterAddress);
            }

            if (entries[i].topics[0] == CCIPMessageSent.selector) {
                _routePostV1dot6Message(entries[i], entries, forkIds, sourceForkId, sourceRouterAddress);
            }
        }
    }

    function _routePreV1dot6Message(
        Vm.Log memory entry,
        Vm.Log[] memory entries,
        uint256[] memory forkIds,
        uint256 sourceForkId,
        address sourceRouterAddress
    ) internal {
        InternalPreV1dot6.EVM2EVMMessage memory message = abi.decode(entry.data, (InternalPreV1dot6.EVM2EVMMessage));

        if (s_processedMessages[message.messageId]) return;

        for (uint256 j; j < forkIds.length; ++j) {
            vm.selectFork(forkIds[j]);
            uint64 destinationChainSelector = i_register.getNetworkDetails(block.chainid).chainSelector;

            vm.selectFork(sourceForkId);
            address onRampContract = IRouterFork(sourceRouterAddress).getOnRamp(destinationChainSelector);

            if (entry.emitter == onRampContract) {
                vm.selectFork(forkIds[j]);

                IRouterFork.OffRamp[] memory offRamps =
                    IRouterFork(i_register.getNetworkDetails(block.chainid).routerAddress).getOffRamps();
                uint256 offRampsLength = offRamps.length;

                for (uint256 k = offRampsLength; k > 0; --k) {
                    if (offRamps[k - 1].sourceChainSelector == message.sourceChainSelector) {
                        vm.startPrank(offRamps[k - 1].offRamp);
                        uint256 numberOfTokens = message.tokenAmounts.length;
                        bytes[] memory offchainTokenData =
                            _offchainTokenDataPreV1dot6(numberOfTokens, message.sourceTokenData, entries);
                        uint32[] memory tokenGasOverrides = new uint32[](numberOfTokens);
                        for (uint256 l; l < numberOfTokens; ++l) {
                            tokenGasOverrides[l] = uint32(message.gasLimit);
                        }
                        try IEVM2EVMOffRampPreV1dot6Fork(offRamps[k - 1].offRamp)
                            .executeSingleMessage(message, offchainTokenData, tokenGasOverrides) {
                            vm.stopPrank();
                            s_processedMessages[message.messageId] = true;
                        } catch (bytes memory err) {
                            vm.stopPrank();
                            console2.logBytes(err);
                        }
                        break;
                    }
                }
            }
        }
    }

    function _routePostV1dot6Message(
        Vm.Log memory entry,
        Vm.Log[] memory entries,
        uint256[] memory forkIds,
        uint256 sourceForkId,
        address sourceRouterAddress
    ) internal {
        Internal.EVM2AnyRampMessage memory message = abi.decode(entry.data, (Internal.EVM2AnyRampMessage));

        if (s_processedMessages[message.header.messageId]) return;
        s_processedMessages[message.header.messageId] = true;

        for (uint256 j; j < forkIds.length; ++j) {
            vm.selectFork(forkIds[j]);
            uint64 destinationChainSelector = i_register.getNetworkDetails(block.chainid).chainSelector;

            vm.selectFork(sourceForkId);
            address onRampContract = IRouterFork(sourceRouterAddress).getOnRamp(destinationChainSelector);

            if (entry.emitter == onRampContract) {
                vm.selectFork(forkIds[j]);

                IRouterFork.OffRamp[] memory offRamps =
                    IRouterFork(i_register.getNetworkDetails(block.chainid).routerAddress).getOffRamps();
                uint256 offRampsLength = offRamps.length;

                for (uint256 k = offRampsLength; k > 0; --k) {
                    if (offRamps[k - 1].sourceChainSelector == message.header.sourceChainSelector) {
                        _executePostV1dot6Message(offRamps[k - 1].offRamp, message, entries);
                        break;
                    }
                }
            }
        }
    }

    function _executePostV1dot6Message(
        address offRamp,
        Internal.EVM2AnyRampMessage memory message,
        Vm.Log[] memory entries
    ) internal {
        vm.startPrank(offRamp);
        uint256 gasLimit = _fromBytes(message.extraArgs).gasLimit;
        uint256 numberOfTokens = message.tokenAmounts.length;
        Internal.Any2EVMTokenTransfer[] memory tokenAmounts = new Internal.Any2EVMTokenTransfer[](numberOfTokens);
        address decodedReceiver = _decodeEvmAddress(message.receiver);
        for (uint256 l; l < numberOfTokens; ++l) {
            address decodedDestToken = _decodeEvmAddress(message.tokenAmounts[l].destTokenAddress);
            tokenAmounts[l] = Internal.Any2EVMTokenTransfer({
                sourcePoolAddress: abi.encode(message.tokenAmounts[l].sourcePoolAddress),
                destTokenAddress: decodedDestToken,
                destGasAmount: abi.decode(message.tokenAmounts[l].destExecData, (uint32)),
                extraData: message.tokenAmounts[l].extraData,
                amount: message.tokenAmounts[l].amount
            });
        }
        Internal.Any2EVMRampMessage memory any2EVMRampMessage = Internal.Any2EVMRampMessage({
            header: message.header,
            sender: abi.encode(message.sender),
            data: message.data,
            receiver: decodedReceiver,
            gasLimit: gasLimit,
            tokenAmounts: tokenAmounts
        });
        bytes[] memory sourceTokenData = new bytes[](numberOfTokens);
        for (uint256 l; l < numberOfTokens; ++l) {
            sourceTokenData[l] = message.tokenAmounts[l].extraData;
        }
        bytes[] memory offchainTokenData =
            _offchainTokenData(numberOfTokens, message.header.messageId, sourceTokenData, entries);
        uint32[] memory tokenGasOverrides = new uint32[](numberOfTokens);
        for (uint256 l; l < numberOfTokens; ++l) {
            tokenGasOverrides[l] = uint32(gasLimit);
        }
        try IEVM2EVMOffRampFork(offRamp)
            .executeSingleMessage(any2EVMRampMessage, offchainTokenData, tokenGasOverrides) {
            vm.stopPrank();
        } catch (bytes memory err) {
            vm.stopPrank();
            console2.logBytes(err);
        }
    }

    function _offchainTokenData(
        uint256 numberOfTokens,
        bytes32 messageId,
        bytes[] memory sourceTokenData,
        Vm.Log[] memory entries
    ) internal returns (bytes[] memory offchainTokenData) {
        if (s_routeWithUSDC && numberOfTokens > 0) {
            if (sourceTokenData.length > 0 && sourceTokenData[0].length == 64) {
                return _createLegacyOffchainTokenData(numberOfTokens, sourceTokenData, entries);
            }
            return _createOffchainTokenData(entries, messageId);
        }

        return new bytes[](numberOfTokens);
    }

    function _offchainTokenDataPreV1dot6(
        uint256 numberOfTokens,
        bytes[] memory sourceTokenData,
        Vm.Log[] memory entries
    ) internal returns (bytes[] memory offchainTokenData) {
        if (s_routeWithUSDC && numberOfTokens > 0) {
            return _createLegacyOffchainTokenData(numberOfTokens, sourceTokenData, entries);
        }

        return new bytes[](numberOfTokens);
    }

    /**
     * @notice Internal helper function to decode extraArgs bytes to GenericExtraArgsV2 struct.
     *         Supports decoding of both GenericExtraArgsV2 and EVMExtraArgsV1 structs.
     *
     * @param extraArgs - The bytes representing the extra arguments.
     *
     * @return genericExtraArgs - The decoded GenericExtraArgsV2 struct.
     */
    function _fromBytes(bytes memory extraArgs) internal pure returns (Client.GenericExtraArgsV2 memory) {
        if (extraArgs.length == 0) {
            return Client.GenericExtraArgsV2({gasLimit: DEFAULT_GAS_LIMIT, allowOutOfOrderExecution: false});
        }

        bytes4 extraArgsTag = bytes4(extraArgs);
        bytes memory gasLimit = new bytes(extraArgs.length - 4);
        for (uint256 i = 4; i < extraArgs.length; ++i) {
            gasLimit[i - 4] = extraArgs[i];
        }

        if (extraArgsTag == Client.GENERIC_EXTRA_ARGS_V2_TAG) {
            return abi.decode(gasLimit, (Client.GenericExtraArgsV2));
        } else if (extraArgsTag == Client.EVM_EXTRA_ARGS_V1_TAG) {
            return
                Client.GenericExtraArgsV2({gasLimit: abi.decode(gasLimit, (uint256)), allowOutOfOrderExecution: false});
        }

        revert InvalidExtraArgsTag();
    }

    function _decodeEvmAddress(bytes memory encodedAddress) internal pure returns (address decodedAddress) {
        if (encodedAddress.length == 20) {
            return address(uint160(bytes20(encodedAddress)));
        }
        if (encodedAddress.length == 32) {
            return abi.decode(encodedAddress, (address));
        }

        revert("Invalid EVM address bytes");
    }
}
