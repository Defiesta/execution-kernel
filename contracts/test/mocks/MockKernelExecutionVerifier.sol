// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import { IKernelExecutionVerifier } from "../../src/interfaces/IKernelExecutionVerifier.sol";

/// @title MockKernelExecutionVerifier
/// @notice Configurable mock for testing KernelVault execution semantics
/// @dev Returns pre-configured ParsedJournal values without proof verification
contract MockKernelExecutionVerifier is IKernelExecutionVerifier {
    // ============ Configuration State ============

    /// @notice Pre-configured journal to return from verifyAndParse
    ParsedJournal public configuredJournal;

    /// @notice Whether verifyAndParse should revert
    bool public shouldRevert;

    /// @notice Custom revert message
    string public revertMessage;

    /// @notice Track the last call parameters for assertions
    bytes public lastJournal;
    bytes public lastSeal;

    // ============ Errors ============

    error MockRevert(string message);

    // ============ Configuration Functions ============

    /// @notice Configure the journal to return from verifyAndParse
    function setJournal(
        bytes32 agentId,
        bytes32 agentCodeHash,
        bytes32 constraintSetHash,
        bytes32 inputRoot,
        uint64 executionNonce,
        bytes32 inputCommitment,
        bytes32 actionCommitment
    ) external {
        configuredJournal = ParsedJournal({
            agentId: agentId,
            agentCodeHash: agentCodeHash,
            constraintSetHash: constraintSetHash,
            inputRoot: inputRoot,
            executionNonce: executionNonce,
            inputCommitment: inputCommitment,
            actionCommitment: actionCommitment
        });
    }

    /// @notice Configure just the essential fields for most tests
    function setEssentials(bytes32 agentId, uint64 executionNonce, bytes32 actionCommitment)
        external
    {
        configuredJournal.agentId = agentId;
        configuredJournal.executionNonce = executionNonce;
        configuredJournal.actionCommitment = actionCommitment;
    }

    /// @notice Set whether to revert on verifyAndParse
    function setShouldRevert(bool _shouldRevert, string calldata _message) external {
        shouldRevert = _shouldRevert;
        revertMessage = _message;
    }

    /// @notice Configure action commitment (convenience for testing commitment mismatches)
    function setActionCommitment(bytes32 commitment) external {
        configuredJournal.actionCommitment = commitment;
    }

    /// @notice Configure execution nonce (convenience for testing nonce logic)
    function setExecutionNonce(uint64 nonce) external {
        configuredJournal.executionNonce = nonce;
    }

    /// @notice Configure agent ID
    function setAgentId(bytes32 _agentId) external {
        configuredJournal.agentId = _agentId;
    }

    // ============ IKernelExecutionVerifier Implementation ============

    /// @inheritdoc IKernelExecutionVerifier
    function verifyAndParse(bytes calldata journal, bytes calldata seal)
        external
        override
        returns (ParsedJournal memory)
    {
        // Record call parameters for test assertions
        lastJournal = journal;
        lastSeal = seal;

        if (shouldRevert) {
            revert MockRevert(revertMessage);
        }

        return configuredJournal;
    }

    /// @inheritdoc IKernelExecutionVerifier
    /// @dev Returns empty journal for mock - use verifyAndParse for configured values
    function parseJournal(bytes calldata) external pure override returns (ParsedJournal memory) {
        // Return empty/default journal since we can't access storage in pure function
        return ParsedJournal({
            agentId: bytes32(0),
            agentCodeHash: bytes32(0),
            constraintSetHash: bytes32(0),
            inputRoot: bytes32(0),
            executionNonce: 0,
            inputCommitment: bytes32(0),
            actionCommitment: bytes32(0)
        });
    }

    /// @inheritdoc IKernelExecutionVerifier
    function allowedImageIds(bytes32) external pure override returns (bool) {
        return true; // Always allowed in mock
    }

    /// @inheritdoc IKernelExecutionVerifier
    function agentImageIds(bytes32) external pure override returns (bytes32) {
        return bytes32(uint256(1)); // Return non-zero to indicate registered
    }
}
