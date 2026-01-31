// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {IRiscZeroVerifier} from "./interfaces/IRiscZeroVerifier.sol";

/// @title KernelExecutionVerifier
/// @notice Verifies RISC Zero proofs of zkVM kernel execution and parses KernelJournalV1
/// @dev This contract:
///      1. Verifies RISC Zero proofs using an external verifier
///      2. Parses and validates the KernelJournalV1 binary format (209 bytes)
///      3. Enforces protocol invariants (version checks, execution status)
///      4. Emits events for verified executions
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

    /// @notice Contract owner (can manage allowed image IDs)
    address public owner;

    /// @notice RISC Zero verifier contract
    IRiscZeroVerifier public immutable verifier;

    /// @notice Mapping of allowed zkVM image IDs
    mapping(bytes32 => bool) public allowedImageIds;
    /// @notice Mapping of agent IDs to their corresponding image IDs
    mapping(bytes32 => bytes32) public agentImageIds;

    // ============ Events ============

    /// @notice Emitted when a new image ID is registered
    /// @param imageId The registered zkVM image ID
    event AgentRegistered(bytes32 indexed agentId, bytes32 indexed imageId);

    /// @notice Emitted when an image ID is revoked
    /// @param imageId The revoked zkVM image ID
    event ImageIdRevoked(bytes32 indexed imageId);

    // ============ Errors ============

    /// @notice Journal length does not match expected 209 bytes
    error InvalidJournalLength(uint256 actual, uint256 expected);

    /// @notice Protocol version in journal does not match expected
    error InvalidProtocolVersion(uint32 actual, uint32 expected);

    /// @notice Kernel version in journal does not match expected
    error InvalidKernelVersion(uint32 actual, uint32 expected);

    /// @notice Execution status indicates failure
    error ExecutionFailed(uint8 status);

    /// @notice Provided image ID is not in the allow list
    error ImageIdNotAllowed(bytes32 imageId);

    /// @notice Provided agent ID is invalid (zero)
    error InvalidImageId(bytes32 imageId);

    /// @notice Provided agent ID is invalid (zero)
    error InvalidAgentId();

    /// @notice Provided agent ID is invalid (zero)
    error AgentNotRegistered(bytes32 agentId);

    /// @notice Caller is not the contract owner
    error OnlyOwner();

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

    // ============ Modifiers ============

    modifier onlyOwner() {
        if (msg.sender != owner) revert OnlyOwner();
        _;
    }

    // ============ Constructor ============

    /// @notice Initialize the verifier with a RISC Zero verifier address
    /// @param _verifier Address of the RISC Zero verifier contract
    constructor(address _verifier) {
        owner = msg.sender;
        verifier = IRiscZeroVerifier(_verifier);
    }

    // ============ Admin Functions ============

    /// @notice Register an allowed zkVM image ID
    /// @param imageId The image ID to allow
    /// @param agentId The agent ID associated with this image ID
    function registerAgent(bytes32 agentId, bytes32 imageId) external onlyOwner {
        if (agentId == bytes32(0)) revert InvalidAgentId();
        if (imageId == bytes32(0)) revert InvalidImageId(imageId);
        allowedImageIds[imageId] = true;
        agentImageIds[agentId] = imageId;
        emit AgentRegistered(agentId, imageId);
    }

    /// @notice Revoke an allowed zkVM image ID
    /// @param imageId The image ID to revoke
    function revokeImageId(bytes32 imageId) external onlyOwner {
        allowedImageIds[imageId] = false;
        emit ImageIdRevoked(imageId);
    }

    /// @notice Transfer ownership to a new address
    /// @param newOwner The new owner address
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "New owner cannot be zero address");
        owner = newOwner;
    }

    // ============ Core Verification ============

    /// @notice Verify a RISC Zero proof and parse the KernelJournalV1
    /// @param journal The raw journal bytes (209 bytes expected)
    /// @param seal The RISC Zero proof seal
    /// @return parsed The parsed and validated journal fields
    function verifyAndParse(bytes calldata journal, bytes calldata seal)
        external
        view
        returns (ParsedJournal memory parsed)
    {
        // 1. Parse journal
        parsed = _parseJournal(journal);

        bytes32 imageId = agentImageIds[parsed.agentId];
        // 2. Check imageId is registered
        if (imageId == bytes32(0)) revert AgentNotRegistered(parsed.agentId);
        // 3. Check imageId is allowed
        if (!allowedImageIds[imageId]) revert ImageIdNotAllowed(imageId);
        // 4. Compute journal digest and verify proof via RISC Zero verifier
        bytes32 journalDigest = sha256(journal);
        verifier.verify(seal, imageId, journalDigest);

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
