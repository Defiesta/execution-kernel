// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title IKernelExecutionVerifier
/// @notice Interface for the KernelExecutionVerifier contract
interface IKernelExecutionVerifier {
    /// @notice Parsed fields from KernelJournalV1
    struct ParsedJournal {
        bytes32 agentId;
        bytes32 agentCodeHash;
        bytes32 constraintSetHash;
        bytes32 inputRoot;
        uint64 executionNonce;
        bytes32 inputCommitment;
        bytes32 actionCommitment;
    }

    /// @notice Verify a RISC Zero proof with a caller-provided imageId and parse the KernelJournalV1
    /// @dev The vault provides its pinned trustedImageId, enabling permissionless verification.
    /// @param expectedImageId The imageId to verify the proof against (pinned at vault deployment)
    /// @param journal The raw journal bytes (209 bytes expected)
    /// @param seal The RISC Zero proof seal
    /// @return parsed The parsed and validated journal fields
    function verifyAndParseWithImageId(
        bytes32 expectedImageId,
        bytes calldata journal,
        bytes calldata seal
    ) external view returns (ParsedJournal memory parsed);

    /// @notice Parse journal without proof verification (for testing/viewing)
    /// @param journal The raw journal bytes
    /// @return parsed The parsed journal fields
    function parseJournal(bytes calldata journal) external pure returns (ParsedJournal memory);
}
