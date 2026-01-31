// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/KernelOutputParser.sol";

/// @title KernelOutputParser Conformance Tests
/// @notice These tests verify that Solidity parsing produces identical results to Rust encoding.
/// @dev Golden vectors are shared with crates/protocol/kernel-core/tests/fixtures/action_vectors.json
contract KernelOutputParserConformanceTest is Test {
    // ============================================================================
    // Constants (must match Rust kernel-core)
    // ============================================================================

    uint32 constant ACTION_TYPE_CALL = 0x00000002;
    uint32 constant ACTION_TYPE_TRANSFER_ERC20 = 0x00000003;
    uint32 constant ACTION_TYPE_NO_OP = 0x00000004;

    // ============================================================================
    // Helper to convert memory to calldata
    // ============================================================================

    /// @notice Parse actions from memory bytes by forwarding through external call
    function parseActions(bytes calldata data)
        external
        pure
        returns (KernelOutputParser.Action[] memory)
    {
        return KernelOutputParser.parseActions(data);
    }

    /// @notice Internal helper that calls parseActions via this contract
    function _parseActions(bytes memory data)
        internal
        view
        returns (KernelOutputParser.Action[] memory)
    {
        return this.parseActions(data);
    }

    // ============================================================================
    // Golden Vector Tests
    // ============================================================================

    /// @notice Test parsing CALL action with value=0 and 4-byte selector
    /// @dev Vector: call_simple from action_vectors.json
    function test_call_simple() public view {
        // Encoded AgentOutput from Rust (little-endian)
        bytes memory encoded =
            hex"01000000a800000002000000000000000000000000000000111111111111111111111111111111111111111180000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000004abcdef1200000000000000000000000000000000000000000000000000000000";

        KernelOutputParser.Action[] memory actions = _parseActions(encoded);

        assertEq(actions.length, 1, "should have 1 action");
        assertEq(actions[0].actionType, ACTION_TYPE_CALL, "action type should be CALL");

        // Verify target (left-padded address)
        bytes32 expectedTarget =
            bytes32(hex"0000000000000000000000001111111111111111111111111111111111111111");
        assertEq(actions[0].target, expectedTarget, "target should match");

        // Verify payload structure (ABI-encoded value + calldata)
        assertEq(actions[0].payload.length, 128, "CALL payload should be 128 bytes");

        // Decode ABI payload: value (32) + offset (32) + length (32) + data (32)
        uint256 value = _readUint256BE(actions[0].payload, 0);
        uint256 offset = _readUint256BE(actions[0].payload, 32);
        uint256 dataLen = _readUint256BE(actions[0].payload, 64);

        assertEq(value, 0, "value should be 0");
        assertEq(offset, 64, "offset should be 64");
        assertEq(dataLen, 4, "calldata length should be 4");

        // Verify calldata bytes
        bytes4 selector = bytes4(
            bytes.concat(
                actions[0].payload[96],
                actions[0].payload[97],
                actions[0].payload[98],
                actions[0].payload[99]
            )
        );
        assertEq(selector, bytes4(hex"abcdef12"), "selector should match");

        // Verify commitment
        bytes32 commitment = sha256(encoded);
        bytes32 expectedCommitment =
            hex"e4698fa954ff344739ef6cf0659fd646f64bbc2e553b32d80314fe460cd066b4";
        assertEq(commitment, expectedCommitment, "commitment should match Rust");
    }

    /// @notice Test parsing CALL action with value=1000 and longer calldata
    /// @dev Vector: call_with_value from action_vectors.json
    function test_call_with_value() public view {
        bytes memory encoded =
            hex"01000000e8000000020000000000000000000000000000002222222222222222222222222222222222222222c000000000000000000000000000000000000000000000000000000000000000000003e80000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000004438ed173900000000000000000000000000000000000000000000000000000000000003e800000000000000000000000000000000000000000000000000000000000001f400000000000000000000000000000000000000000000000000000000";

        KernelOutputParser.Action[] memory actions = _parseActions(encoded);

        assertEq(actions.length, 1, "should have 1 action");
        assertEq(actions[0].actionType, ACTION_TYPE_CALL, "action type should be CALL");

        // Verify target
        bytes32 expectedTarget =
            bytes32(hex"0000000000000000000000002222222222222222222222222222222222222222");
        assertEq(actions[0].target, expectedTarget, "target should match");

        // Decode ABI payload
        uint256 value = _readUint256BE(actions[0].payload, 0);
        uint256 offset = _readUint256BE(actions[0].payload, 32);
        uint256 dataLen = _readUint256BE(actions[0].payload, 64);

        assertEq(value, 1000, "value should be 1000 wei");
        assertEq(offset, 64, "offset should be 64");
        assertEq(dataLen, 68, "calldata length should be 68");

        // Verify commitment
        bytes32 commitment = sha256(encoded);
        bytes32 expectedCommitment =
            hex"1cec43ea593376d3c8e6896b3a2ed9e2193f19fe8c77ffdac767baec4119077b";
        assertEq(commitment, expectedCommitment, "commitment should match Rust");
    }

    /// @notice Test parsing TRANSFER_ERC20 action
    /// @dev Vector: transfer_erc20 from action_vectors.json
    function test_transfer_erc20() public view {
        bytes memory encoded =
            hex"010000008800000003000000000000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48000000000000000000000000333333333333333333333333333333333333333300000000000000000000000000000000000000000000000000000000000f4240";

        KernelOutputParser.Action[] memory actions = _parseActions(encoded);

        assertEq(actions.length, 1, "should have 1 action");
        assertEq(
            actions[0].actionType,
            ACTION_TYPE_TRANSFER_ERC20,
            "action type should be TRANSFER_ERC20"
        );

        // Target is unused for ERC20 transfers
        assertEq(actions[0].target, bytes32(0), "target should be zero");

        // Verify payload is exactly 96 bytes (token + to + amount)
        assertEq(actions[0].payload.length, 96, "TRANSFER_ERC20 payload should be 96 bytes");

        // Decode ABI payload: token (32) + to (32) + amount (32)
        address token = _readAddressPadded(actions[0].payload, 0);
        address to = _readAddressPadded(actions[0].payload, 32);
        uint256 amount = _readUint256BE(actions[0].payload, 64);

        assertEq(token, 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48, "token should be USDC");
        assertEq(to, 0x3333333333333333333333333333333333333333, "recipient should match");
        assertEq(amount, 1_000_000, "amount should be 1M");

        // Verify commitment
        bytes32 commitment = sha256(encoded);
        bytes32 expectedCommitment =
            hex"31c0eeb34dce3bac1ceade09476fe68ae790cfe4054491f4573a2b06c7d5ffcf";
        assertEq(commitment, expectedCommitment, "commitment should match Rust");
    }

    /// @notice Test parsing NO_OP action
    /// @dev Vector: no_op from action_vectors.json
    function test_no_op() public view {
        bytes memory encoded =
            hex"010000002800000004000000000000000000000000000000000000000000000000000000000000000000000000000000";

        KernelOutputParser.Action[] memory actions = _parseActions(encoded);

        assertEq(actions.length, 1, "should have 1 action");
        assertEq(actions[0].actionType, ACTION_TYPE_NO_OP, "action type should be NO_OP");
        assertEq(actions[0].target, bytes32(0), "target should be zero");
        assertEq(actions[0].payload.length, 0, "NO_OP payload should be empty");

        // Verify commitment
        bytes32 commitment = sha256(encoded);
        bytes32 expectedCommitment =
            hex"3f17ba8eb8ba7cd69ea9e7571eafa53ea8373b5e9d005ddef9847fa3256607c2";
        assertEq(commitment, expectedCommitment, "commitment should match Rust");
    }

    /// @notice Test parsing empty AgentOutput
    /// @dev Vector: empty_output from action_vectors.json
    function test_empty_output() public view {
        bytes memory encoded = hex"00000000";

        KernelOutputParser.Action[] memory actions = _parseActions(encoded);

        assertEq(actions.length, 0, "should have 0 actions");

        // Verify commitment (used for constraint failures)
        bytes32 commitment = sha256(encoded);
        bytes32 expectedCommitment =
            hex"df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119";
        assertEq(commitment, expectedCommitment, "empty output commitment should match");
    }

    // ============================================================================
    // Round-Trip Tests
    // ============================================================================

    /// @notice Verify encode+decode produces identical actions
    function test_roundtrip_call() public view {
        KernelOutputParser.Action memory action = KernelOutputParser.Action({
            actionType: ACTION_TYPE_CALL,
            target: bytes32(hex"0000000000000000000000001111111111111111111111111111111111111111"),
            payload: hex"0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000041234567800000000000000000000000000000000000000000000000000000000"
        });

        KernelOutputParser.Action[] memory actions = new KernelOutputParser.Action[](1);
        actions[0] = action;

        bytes memory encoded = KernelOutputParser.encodeAgentOutput(actions);
        KernelOutputParser.Action[] memory decoded = _parseActions(encoded);

        assertEq(decoded.length, 1, "should decode 1 action");
        assertEq(decoded[0].actionType, action.actionType, "action type should match");
        assertEq(decoded[0].target, action.target, "target should match");
        assertEq(keccak256(decoded[0].payload), keccak256(action.payload), "payload should match");
    }

    /// @notice Verify Solidity encoding matches Rust encoding
    function test_solidity_encoding_matches_rust() public pure {
        // Build the same action as call_simple vector
        // Payload is ABI-encoded: value (32) + offset (32) + length (32) + padded calldata (32) = 128 bytes
        KernelOutputParser.Action memory action = KernelOutputParser.Action({
            actionType: ACTION_TYPE_CALL,
            target: bytes32(hex"0000000000000000000000001111111111111111111111111111111111111111"),
            payload: hex"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000004abcdef1200000000000000000000000000000000000000000000000000000000"
        });

        KernelOutputParser.Action[] memory actions = new KernelOutputParser.Action[](1);
        actions[0] = action;

        bytes memory solEncoded = KernelOutputParser.encodeAgentOutput(actions);
        bytes memory rustEncoded =
            hex"01000000a800000002000000000000000000000000000000111111111111111111111111111111111111111180000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000004abcdef1200000000000000000000000000000000000000000000000000000000";

        assertEq(keccak256(solEncoded), keccak256(rustEncoded), "Solidity encoding must match Rust");
    }

    // ============================================================================
    // Error Cases
    // ============================================================================

    /// @notice Test that malformed data reverts
    function test_malformed_truncated() public {
        bytes memory truncated = hex"010000"; // Too short

        vm.expectRevert();
        _parseActions(truncated);
    }

    /// @notice Test that too many actions reverts
    function test_too_many_actions() public {
        // action_count = 100 (exceeds MAX_ACTIONS_PER_OUTPUT = 64)
        bytes memory tooMany = hex"64000000";

        vm.expectRevert(abi.encodeWithSelector(KernelOutputParser.TooManyActions.selector, 100, 64));
        _parseActions(tooMany);
    }

    // ============================================================================
    // Helpers
    // ============================================================================

    /// @notice Read a big-endian uint256 from bytes at offset
    function _readUint256BE(bytes memory data, uint256 offset) internal pure returns (uint256) {
        require(data.length >= offset + 32, "insufficient data");
        uint256 value;
        assembly {
            value := mload(add(add(data, 32), offset))
        }
        return value;
    }

    /// @notice Read a left-padded address from bytes at offset
    function _readAddressPadded(bytes memory data, uint256 offset)
        internal
        pure
        returns (address)
    {
        require(data.length >= offset + 32, "insufficient data");
        // Address is in lower 20 bytes of the 32-byte slot
        uint256 raw = _readUint256BE(data, offset);
        return address(uint160(raw));
    }
}
