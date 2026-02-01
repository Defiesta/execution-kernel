// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import { IKernelExecutionVerifier } from "../../src/interfaces/IKernelExecutionVerifier.sol";

/// @title MockKernelExecutionVerifier
/// @notice Configurable mock for testing KernelVault execution semantics
/// @dev Returns pre-configured ParsedJournal values without proof verification
contract MockKernelExecutionVerifier is IKernelExecutionVerifier {
    // ============ Configuration State ============

    /// @notice Pre-configured journal to return
    ParsedJournal public configuredJournal;

    /// @notice Whether verification should revert
    bool public shouldRevert;

    /// @notice Custom revert message
    string public revertMessage;

    /// @notice Expected imageId for verifyAndParseWithImageId (if set, will validate)
    bytes32 public expectedImageId;

    /// @notice Whether to validate imageId in verifyAndParseWithImageId
    bool public validateImageId;

    // ============ Errors ============

    error MockRevert(string message);

    /// @notice ImageId mismatch error for testing
    error ImageIdMismatch(bytes32 expected, bytes32 actual);

    /// @notice Zero imageId error for testing
    error ZeroImageId();

    // ============ Configuration Functions ============

    /// @notice Configure the journal to return
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

    /// @notice Set whether to revert on verification
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

    /// @notice Configure expected imageId for verifyAndParseWithImageId validation
    /// @param _expectedImageId The imageId that must be provided
    /// @param _validate Whether to validate the imageId (revert on mismatch)
    function setExpectedImageId(bytes32 _expectedImageId, bool _validate) external {
        expectedImageId = _expectedImageId;
        validateImageId = _validate;
    }

    // ============ IKernelExecutionVerifier Implementation ============

    /// @notice Verify with caller-provided imageId (permissionless flow)
    /// @inheritdoc IKernelExecutionVerifier
    function verifyAndParseWithImageId(
        bytes32 _expectedImageId,
        bytes calldata,
        bytes calldata
    ) external view override returns (ParsedJournal memory) {
        if (shouldRevert) {
            revert MockRevert(revertMessage);
        }

        // Validate imageId is not zero
        if (_expectedImageId == bytes32(0)) {
            revert ZeroImageId();
        }

        // Optionally validate imageId matches expected
        if (validateImageId && _expectedImageId != expectedImageId) {
            revert ImageIdMismatch(expectedImageId, _expectedImageId);
        }

        return configuredJournal;
    }

    /// @inheritdoc IKernelExecutionVerifier
    /// @dev Returns empty journal for mock - pure function can't access storage
    function parseJournal(bytes calldata) external pure override returns (ParsedJournal memory) {
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
}
