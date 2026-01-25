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

    /// @notice Verify a RISC Zero proof and parse the KernelJournalV1
    /// @param journal The raw journal bytes (209 bytes expected)
    /// @param seal The RISC Zero proof seal
    /// @return parsed The parsed and validated journal fields
    function verifyAndParse(bytes calldata journal, bytes calldata seal)
        external
        returns (ParsedJournal memory parsed);

    /// @notice Parse journal without proof verification (for testing/viewing)
    /// @param journal The raw journal bytes
    /// @return parsed The parsed journal fields
    function parseJournal(bytes calldata journal) external pure returns (ParsedJournal memory);

    /// @notice Check if an image ID is allowed
    function allowedImageIds(bytes32 imageId) external view returns (bool);

    /// @notice Get the image ID for an agent
    function agentImageIds(bytes32 agentId) external view returns (bytes32);
}
