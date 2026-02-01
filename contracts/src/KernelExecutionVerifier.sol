// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import { IRiscZeroVerifier } from "./interfaces/IRiscZeroVerifier.sol";

/// @title KernelExecutionVerifier
/// @notice Verifies RISC Zero proofs of zkVM kernel execution and parses KernelJournalV1
/// @dev This contract:
///      1. Verifies RISC Zero proofs using an external verifier
///      2. Parses and validates the KernelJournalV1 binary format (209 bytes)
///      3. Enforces protocol invariants (version checks, execution status)
contract KernelExecutionVerifier {
    // ============ Constants ============

    /// @notice Expected protocol version in the journal
    uint32 public constant EXPECTED_PROTOCOL_VERSION = 1;

    /// @notice Expected kernel version in the journal
    uint32 public constant EXPECTED_KERNEL_VERSION = 1;

    /// @notice Execution status code indicating success
    uint8 public constant EXECUTION_STATUS_SUCCESS = 0x01;

    /// @notice Expected length of KernelJournalV1 in bytes
    uint256 public constant JOURNAL_LENGTH = 209;

    // ============ State ============

    /// @notice RISC Zero verifier contract
    IRiscZeroVerifier public immutable verifier;

    // ============ Errors ============

    /// @notice Journal length does not match expected 209 bytes
    error InvalidJournalLength(uint256 actual, uint256 expected);

    /// @notice Protocol version in journal does not match expected
    error InvalidProtocolVersion(uint32 actual, uint32 expected);

    /// @notice Kernel version in journal does not match expected
    error InvalidKernelVersion(uint32 actual, uint32 expected);

    /// @notice Execution status indicates failure
    error ExecutionFailed(uint8 status);

    /// @notice Zero imageId provided to verifyAndParseWithImageId
    error ZeroImageId();

    // ============ Structs ============

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

    // ============ Constructor ============

    /// @notice Initialize the verifier with a RISC Zero verifier address
    /// @param _verifier Address of the RISC Zero verifier contract
    constructor(address _verifier) {
        verifier = IRiscZeroVerifier(_verifier);
    }

    // ============ Core Verification ============

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
    ) external view returns (ParsedJournal memory parsed) {
        // Validate expectedImageId is not zero
        if (expectedImageId == bytes32(0)) revert ZeroImageId();

        // Parse journal
        parsed = _parseJournal(journal);

        // Compute journal digest and verify proof via RISC Zero verifier
        bytes32 journalDigest = sha256(journal);
        verifier.verify(seal, expectedImageId, journalDigest);

        return parsed;
    }

    /// @notice Parse journal without proof verification (for testing/viewing)
    /// @param journal The raw journal bytes
    /// @return parsed The parsed journal fields
    function parseJournal(bytes calldata journal) external pure returns (ParsedJournal memory) {
        return _parseJournal(journal);
    }

    // ============ Internal Functions ============

    /// @notice Parse and validate a KernelJournalV1 binary blob
    /// @dev Layout (209 bytes total):
    ///      - [0:4]     protocol_version (u32 LE)
    ///      - [4:8]     kernel_version (u32 LE)
    ///      - [8:40]    agent_id (bytes32)
    ///      - [40:72]   agent_code_hash (bytes32)
    ///      - [72:104]  constraint_set_hash (bytes32)
    ///      - [104:136] input_root (bytes32)
    ///      - [136:144] execution_nonce (u64 LE)
    ///      - [144:176] input_commitment (bytes32)
    ///      - [176:208] action_commitment (bytes32)
    ///      - [208]     execution_status (u8)
    function _parseJournal(bytes calldata journal) internal pure returns (ParsedJournal memory) {
        // Validate length
        if (journal.length != JOURNAL_LENGTH) {
            revert InvalidJournalLength(journal.length, JOURNAL_LENGTH);
        }

        // Parse and validate protocol_version (LE u32 at offset 0)
        uint32 protocolVersion = _readU32LE(journal, 0);
        if (protocolVersion != EXPECTED_PROTOCOL_VERSION) {
            revert InvalidProtocolVersion(protocolVersion, EXPECTED_PROTOCOL_VERSION);
        }

        // Parse and validate kernel_version (LE u32 at offset 4)
        uint32 kernelVersion = _readU32LE(journal, 4);
        if (kernelVersion != EXPECTED_KERNEL_VERSION) {
            revert InvalidKernelVersion(kernelVersion, EXPECTED_KERNEL_VERSION);
        }

        // Parse and validate execution_status (u8 at offset 208)
        uint8 executionStatus = uint8(journal[208]);
        if (executionStatus != EXECUTION_STATUS_SUCCESS) {
            revert ExecutionFailed(executionStatus);
        }

        // Parse remaining fields
        return ParsedJournal({
            agentId: bytes32(journal[8:40]),
            agentCodeHash: bytes32(journal[40:72]),
            constraintSetHash: bytes32(journal[72:104]),
            inputRoot: bytes32(journal[104:136]),
            executionNonce: _readU64LE(journal, 136),
            inputCommitment: bytes32(journal[144:176]),
            actionCommitment: bytes32(journal[176:208])
        });
    }

    /// @notice Read a little-endian u32 from calldata
    /// @param data The calldata bytes
    /// @param offset The byte offset to read from
    /// @return The decoded uint32 value
    function _readU32LE(bytes calldata data, uint256 offset) internal pure returns (uint32) {
        return uint32(uint8(data[offset])) | (uint32(uint8(data[offset + 1])) << 8)
            | (uint32(uint8(data[offset + 2])) << 16) | (uint32(uint8(data[offset + 3])) << 24);
    }

    /// @notice Read a little-endian u64 from calldata
    /// @param data The calldata bytes
    /// @param offset The byte offset to read from
    /// @return The decoded uint64 value
    function _readU64LE(bytes calldata data, uint256 offset) internal pure returns (uint64) {
        return uint64(uint8(data[offset])) | (uint64(uint8(data[offset + 1])) << 8)
            | (uint64(uint8(data[offset + 2])) << 16) | (uint64(uint8(data[offset + 3])) << 24)
            | (uint64(uint8(data[offset + 4])) << 32) | (uint64(uint8(data[offset + 5])) << 40)
            | (uint64(uint8(data[offset + 6])) << 48) | (uint64(uint8(data[offset + 7])) << 56);
    }
}
