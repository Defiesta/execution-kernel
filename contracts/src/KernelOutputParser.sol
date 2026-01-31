// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title KernelOutputParser
/// @notice Library for parsing AgentOutput bytes into executable actions
/// @dev AgentOutput binary layout:
///      - u32 LE action_count
///      - for each action:
///          - u32 LE action_len
///          - ActionV1 bytes:
///              - u32 LE action_type
///              - bytes32 target
///              - u32 LE payload_len
///              - payload bytes
library KernelOutputParser {
    // ============ Constants ============

    /// @notice Maximum number of actions per output (aligned with Rust MAX_ACTIONS_PER_OUTPUT)
    uint256 public constant MAX_ACTIONS_PER_OUTPUT = 64;

    /// @notice Maximum payload size per action (aligned with Rust MAX_ACTION_PAYLOAD_BYTES)
    uint256 public constant MAX_ACTION_PAYLOAD_BYTES = 16_384;

    /// @notice Maximum encoded size of a single ActionV1 structure.
    /// @dev This bounds the `action_len` value (the u32 LE prefix for each action), NOT the
    ///      full wire encoding which includes an additional 4-byte length prefix.
    ///
    ///      Wire format per action:
    ///        [action_len: u32 LE]     <- 4 bytes, NOT included in this limit
    ///        [ActionV1 bytes]:        <- bounded by MAX_SINGLE_ACTION_BYTES
    ///          action_type: u32 LE   (4 bytes)
    ///          target: bytes32       (32 bytes)
    ///          payload_len: u32 LE   (4 bytes)
    ///          payload: bytes        (up to MAX_ACTION_PAYLOAD_BYTES)
    ///
    ///      Calculation: 4 + 32 + 4 + 16384 = 16424 bytes
    ///
    ///      IMPORTANT: This constant is intentionally byte-for-byte aligned with the Rust
    ///      implementation in kernel-core/src/types.rs (MAX_SINGLE_ACTION_BYTES).
    ///      Both implementations validate `action_len` (the value) against this limit,
    ///      ensuring consistent rejection of oversized actions across zkVM and EVM.
    uint256 public constant MAX_SINGLE_ACTION_BYTES = 40 + MAX_ACTION_PAYLOAD_BYTES;

    /// @notice Action type for generic contract call
    uint32 public constant ACTION_TYPE_CALL = 0x00000002;

    /// @notice Action type for ERC20 transfer
    uint32 public constant ACTION_TYPE_TRANSFER_ERC20 = 0x00000003;

    /// @notice Action type for no-op
    uint32 public constant ACTION_TYPE_NO_OP = 0x00000004;

    // ============ Errors ============

    /// @notice Thrown when action count exceeds maximum
    error TooManyActions(uint256 count, uint256 max);

    /// @notice Thrown when action payload exceeds maximum size
    error PayloadTooLarge(uint256 size, uint256 max);

    /// @notice Thrown when action length exceeds maximum
    error ActionTooLarge(uint256 size, uint256 max);

    /// @notice Thrown when output data is truncated/malformed
    error MalformedOutput(uint256 offset, uint256 required, uint256 available);

    // ============ Structs ============

    /// @notice Parsed action from AgentOutput
    struct Action {
        uint32 actionType;
        bytes32 target;
        bytes payload;
    }

    // ============ Functions ============

    /// @notice Parse AgentOutput bytes into an array of actions
    /// @param data The raw AgentOutput bytes
    /// @return actions Array of parsed actions
    function parseActions(bytes calldata data) internal pure returns (Action[] memory actions) {
        uint256 offset = 0;

        // Read action_count (u32 LE)
        if (data.length < 4) {
            revert MalformedOutput(offset, 4, data.length);
        }
        uint32 actionCount = _readU32LE(data, offset);
        offset += 4;

        // Validate action count
        if (actionCount > MAX_ACTIONS_PER_OUTPUT) {
            revert TooManyActions(actionCount, MAX_ACTIONS_PER_OUTPUT);
        }

        actions = new Action[](actionCount);

        for (uint256 i = 0; i < actionCount; i++) {
            // Read action_len (u32 LE)
            if (offset + 4 > data.length) {
                revert MalformedOutput(offset, 4, data.length - offset);
            }
            uint32 actionLen = _readU32LE(data, offset);
            offset += 4;

            // Validate action length against MAX_SINGLE_ACTION_BYTES.
            // Note: actionLen is the size of the ActionV1 encoding (what follows the prefix),
            // not including the 4-byte prefix itself. This matches Rust's validation semantics.
            if (actionLen > MAX_SINGLE_ACTION_BYTES) {
                revert ActionTooLarge(actionLen, MAX_SINGLE_ACTION_BYTES);
            }

            // Ensure we have enough data for the action
            if (offset + actionLen > data.length) {
                revert MalformedOutput(offset, actionLen, data.length - offset);
            }

            // Parse ActionV1:
            // - u32 LE action_type
            // - bytes32 target
            // - u32 LE payload_len
            // - payload bytes

            uint256 actionStart = offset;

            // Read action_type (u32 LE)
            if (actionLen < 4) {
                revert MalformedOutput(actionStart, 4, actionLen);
            }
            uint32 actionType = _readU32LE(data, offset);
            offset += 4;

            // Read target (bytes32) - use assembly for robust slice-to-bytes32
            if (actionLen < 36) {
                revert MalformedOutput(actionStart, 36, actionLen);
            }
            bytes32 target = _readBytes32(data, offset);
            offset += 32;

            // Read payload_len (u32 LE)
            if (actionLen < 40) {
                revert MalformedOutput(actionStart, 40, actionLen);
            }
            uint32 payloadLen = _readU32LE(data, offset);
            offset += 4;

            // Validate payload length
            if (payloadLen > MAX_ACTION_PAYLOAD_BYTES) {
                revert PayloadTooLarge(payloadLen, MAX_ACTION_PAYLOAD_BYTES);
            }

            // Validate actionLen matches expected structure
            uint256 expectedActionLen = 4 + 32 + 4 + payloadLen;
            if (actionLen != expectedActionLen) {
                revert MalformedOutput(actionStart, expectedActionLen, actionLen);
            }

            // Bound check before copying payload
            if (offset + payloadLen > data.length) {
                revert MalformedOutput(offset, payloadLen, data.length - offset);
            }

            // Read payload
            bytes memory payload = new bytes(payloadLen);
            for (uint256 j = 0; j < payloadLen; j++) {
                payload[j] = data[offset + j];
            }
            offset += payloadLen;

            // Defense-in-depth: verify we consumed exactly actionLen bytes
            if (offset != actionStart + actionLen) {
                revert MalformedOutput(actionStart, actionLen, offset - actionStart);
            }

            actions[i] = Action({ actionType: actionType, target: target, payload: payload });
        }

        // Verify we consumed all data
        if (offset != data.length) {
            revert MalformedOutput(offset, 0, data.length - offset);
        }
    }

    /// @notice Encode a single action into AgentOutput format (for testing)
    /// @param action The action to encode
    /// @return encoded The encoded action bytes (without the outer action_count)
    function encodeAction(Action memory action) internal pure returns (bytes memory) {
        // ActionV1: action_type (4) + target (32) + payload_len (4) + payload
        uint32 actionLen = uint32(4 + 32 + 4 + action.payload.length);

        bytes memory encoded = new bytes(4 + actionLen);
        uint256 offset = 0;

        // action_len (u32 LE)
        encoded[offset] = bytes1(uint8(actionLen & 0xFF));
        encoded[offset + 1] = bytes1(uint8((actionLen >> 8) & 0xFF));
        encoded[offset + 2] = bytes1(uint8((actionLen >> 16) & 0xFF));
        encoded[offset + 3] = bytes1(uint8((actionLen >> 24) & 0xFF));
        offset += 4;

        // action_type (u32 LE)
        encoded[offset] = bytes1(uint8(action.actionType & 0xFF));
        encoded[offset + 1] = bytes1(uint8((action.actionType >> 8) & 0xFF));
        encoded[offset + 2] = bytes1(uint8((action.actionType >> 16) & 0xFF));
        encoded[offset + 3] = bytes1(uint8((action.actionType >> 24) & 0xFF));
        offset += 4;

        // target (bytes32)
        for (uint256 i = 0; i < 32; i++) {
            encoded[offset + i] = action.target[i];
        }
        offset += 32;

        // payload_len (u32 LE)
        uint32 payloadLen = uint32(action.payload.length);
        encoded[offset] = bytes1(uint8(payloadLen & 0xFF));
        encoded[offset + 1] = bytes1(uint8((payloadLen >> 8) & 0xFF));
        encoded[offset + 2] = bytes1(uint8((payloadLen >> 16) & 0xFF));
        encoded[offset + 3] = bytes1(uint8((payloadLen >> 24) & 0xFF));
        offset += 4;

        // payload
        for (uint256 i = 0; i < action.payload.length; i++) {
            encoded[offset + i] = action.payload[i];
        }

        return encoded;
    }

    /// @notice Encode multiple actions into complete AgentOutput format (for testing)
    /// @param actions Array of actions to encode
    /// @return encoded The complete AgentOutput bytes
    function encodeAgentOutput(Action[] memory actions) internal pure returns (bytes memory) {
        // Calculate total size
        uint256 totalSize = 4; // action_count
        bytes[] memory encodedActions = new bytes[](actions.length);

        for (uint256 i = 0; i < actions.length; i++) {
            encodedActions[i] = encodeAction(actions[i]);
            totalSize += encodedActions[i].length;
        }

        bytes memory encoded = new bytes(totalSize);
        uint256 offset = 0;

        // action_count (u32 LE)
        uint32 actionCount = uint32(actions.length);
        encoded[offset] = bytes1(uint8(actionCount & 0xFF));
        encoded[offset + 1] = bytes1(uint8((actionCount >> 8) & 0xFF));
        encoded[offset + 2] = bytes1(uint8((actionCount >> 16) & 0xFF));
        encoded[offset + 3] = bytes1(uint8((actionCount >> 24) & 0xFF));
        offset += 4;

        // Append each encoded action
        for (uint256 i = 0; i < encodedActions.length; i++) {
            for (uint256 j = 0; j < encodedActions[i].length; j++) {
                encoded[offset + j] = encodedActions[i][j];
            }
            offset += encodedActions[i].length;
        }

        return encoded;
    }

    /// @notice Read a little-endian u32 from bytes
    function _readU32LE(bytes calldata data, uint256 offset) private pure returns (uint32) {
        return uint32(uint8(data[offset])) | (uint32(uint8(data[offset + 1])) << 8)
            | (uint32(uint8(data[offset + 2])) << 16) | (uint32(uint8(data[offset + 3])) << 24);
    }

    /// @notice Read a bytes32 from calldata using assembly for robustness
    function _readBytes32(bytes calldata data, uint256 offset)
        private
        pure
        returns (bytes32 result)
    {
        // Copy 32 bytes from calldata into memory and load as bytes32
        assembly {
            // calldataload loads 32 bytes from calldata at the given offset
            // data.offset gives the start of the calldata slice
            result := calldataload(add(data.offset, offset))
        }
    }
}
