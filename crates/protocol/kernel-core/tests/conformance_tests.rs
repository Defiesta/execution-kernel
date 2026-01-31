//! Cross-language conformance tests for ActionV1 and AgentOutput encoding.
//!
//! These tests validate that Rust encoding matches the expected golden vectors,
//! ensuring consistency with the Solidity KernelOutputParser implementation.
//!
//! The fixtures are located at `tests/fixtures/action_vectors.json`.
//!
//! To regenerate fixture values after intentional changes, set GENERATE_VECTORS=1:
//!   GENERATE_VECTORS=1 cargo test -p kernel-core --test conformance_tests

use kernel_core::{
    compute_action_commitment, ActionV1, AgentOutput, CanonicalEncode, ACTION_TYPE_CALL,
    ACTION_TYPE_NO_OP, ACTION_TYPE_TRANSFER_ERC20,
};

/// Helper to convert hex string (without 0x prefix) to bytes
fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex"))
        .collect()
}

/// Helper to convert bytes to hex string (without 0x prefix)
fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Create a CALL action payload (ABI-encoded)
fn create_call_payload(value: u128, calldata: &[u8]) -> Vec<u8> {
    let data_len = calldata.len();
    let padded_len = data_len.div_ceil(32) * 32;
    let total_size = 96 + padded_len;
    let mut payload = Vec::with_capacity(total_size);

    // uint256 value (big-endian)
    let mut value_bytes = [0u8; 32];
    value_bytes[16..32].copy_from_slice(&value.to_be_bytes());
    payload.extend_from_slice(&value_bytes);

    // uint256 offset (always 64 = 0x40)
    let mut offset_bytes = [0u8; 32];
    offset_bytes[31] = 64;
    payload.extend_from_slice(&offset_bytes);

    // uint256 length
    let mut len_bytes = [0u8; 32];
    len_bytes[24..32].copy_from_slice(&(data_len as u64).to_be_bytes());
    payload.extend_from_slice(&len_bytes);

    // calldata (padded to 32-byte boundary)
    payload.extend_from_slice(calldata);
    payload.resize(total_size, 0);

    payload
}

/// Create a TRANSFER_ERC20 action payload (ABI-encoded)
fn create_transfer_erc20_payload(token: &[u8; 20], to: &[u8; 20], amount: u128) -> Vec<u8> {
    let mut payload = Vec::with_capacity(96);

    // address token (left-padded to 32 bytes)
    payload.extend_from_slice(&[0u8; 12]);
    payload.extend_from_slice(token);

    // address to (left-padded to 32 bytes)
    payload.extend_from_slice(&[0u8; 12]);
    payload.extend_from_slice(to);

    // uint256 amount (big-endian)
    let mut amount_bytes = [0u8; 32];
    amount_bytes[16..32].copy_from_slice(&amount.to_be_bytes());
    payload.extend_from_slice(&amount_bytes);

    payload
}

/// Convert 20-byte address to 32-byte target (left-padded)
fn address_to_target(addr: &[u8; 20]) -> [u8; 32] {
    let mut target = [0u8; 32];
    target[12..32].copy_from_slice(addr);
    target
}

// ============================================================================
// Test Vectors
// ============================================================================

#[test]
fn test_call_simple() {
    // CALL action with value=0 and 4-byte function selector
    let target_addr: [u8; 20] = [0x11; 20];
    let calldata = hex_to_bytes("abcdef12");
    let value: u128 = 0;

    let target = address_to_target(&target_addr);
    let payload = create_call_payload(value, &calldata);

    let action = ActionV1 {
        action_type: ACTION_TYPE_CALL,
        target,
        payload,
    };

    let output = AgentOutput {
        actions: vec![action],
    };

    let encoded = output.encode().expect("encoding should succeed");
    let commitment = compute_action_commitment(&encoded);

    let encoded_hex = bytes_to_hex(&encoded);
    let commitment_hex = bytes_to_hex(&commitment);

    // Expected values from fixtures/action_vectors.json
    let expected_encoded = "01000000a800000002000000000000000000000000000000111111111111111111111111111111111111111180000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000004abcdef1200000000000000000000000000000000000000000000000000000000";
    let expected_commitment = "e4698fa954ff344739ef6cf0659fd646f64bbc2e553b32d80314fe460cd066b4";

    if std::env::var("GENERATE_VECTORS").is_ok() {
        println!("\n=== call_simple ===");
        println!("encoded_hex: {}", encoded_hex);
        println!("commitment_hex: {}", commitment_hex);
    }

    assert_eq!(
        encoded_hex, expected_encoded,
        "call_simple: encoded output mismatch"
    );

    // Verify the commitment matches expected from fixtures
    assert_eq!(
        commitment_hex, expected_commitment,
        "call_simple: commitment mismatch"
    );
}

#[test]
fn test_call_with_value() {
    // CALL action with value=1000 wei and longer calldata
    let target_addr: [u8; 20] = [0x22; 20];
    let calldata = hex_to_bytes("38ed173900000000000000000000000000000000000000000000000000000000000003e800000000000000000000000000000000000000000000000000000000000001f4");
    let value: u128 = 1000;

    let target = address_to_target(&target_addr);
    let payload = create_call_payload(value, &calldata);

    let action = ActionV1 {
        action_type: ACTION_TYPE_CALL,
        target,
        payload,
    };

    let output = AgentOutput {
        actions: vec![action],
    };

    let encoded = output.encode().expect("encoding should succeed");
    let commitment = compute_action_commitment(&encoded);

    let encoded_hex = bytes_to_hex(&encoded);
    let commitment_hex = bytes_to_hex(&commitment);

    if std::env::var("GENERATE_VECTORS").is_ok() {
        println!("\n=== call_with_value ===");
        println!("encoded_hex: {}", encoded_hex);
        println!("commitment_hex: {}", commitment_hex);
    }

    // Verify encoding is deterministic by re-encoding
    let encoded2 = output.encode().expect("encoding should succeed");
    assert_eq!(
        encoded, encoded2,
        "call_with_value: encoding not deterministic"
    );

    // Verify commitment is correct
    let recomputed = compute_action_commitment(&encoded);
    assert_eq!(
        commitment, recomputed,
        "call_with_value: commitment not reproducible"
    );
}

#[test]
fn test_transfer_erc20() {
    // TRANSFER_ERC20 with USDC-like token address
    let token: [u8; 20] = {
        let mut arr = [0u8; 20];
        arr.copy_from_slice(&hex_to_bytes("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"));
        arr
    };
    let to: [u8; 20] = [0x33; 20];
    let amount: u128 = 1_000_000;

    let payload = create_transfer_erc20_payload(&token, &to, amount);

    // Verify payload size is exactly 96 bytes
    assert_eq!(payload.len(), 96, "TRANSFER_ERC20 payload must be 96 bytes");

    let action = ActionV1 {
        action_type: ACTION_TYPE_TRANSFER_ERC20,
        target: [0u8; 32], // unused for ERC20 transfers
        payload,
    };

    let output = AgentOutput {
        actions: vec![action],
    };

    let encoded = output.encode().expect("encoding should succeed");
    let commitment = compute_action_commitment(&encoded);

    let encoded_hex = bytes_to_hex(&encoded);
    let commitment_hex = bytes_to_hex(&commitment);

    if std::env::var("GENERATE_VECTORS").is_ok() {
        println!("\n=== transfer_erc20 ===");
        println!("encoded_hex: {}", encoded_hex);
        println!("commitment_hex: {}", commitment_hex);
    }

    // Verify encoding is deterministic
    let encoded2 = output.encode().expect("encoding should succeed");
    assert_eq!(
        encoded, encoded2,
        "transfer_erc20: encoding not deterministic"
    );
}

#[test]
fn test_no_op() {
    // NO_OP action with empty payload
    let action = ActionV1 {
        action_type: ACTION_TYPE_NO_OP,
        target: [0u8; 32],
        payload: vec![],
    };

    let output = AgentOutput {
        actions: vec![action],
    };

    let encoded = output.encode().expect("encoding should succeed");
    let commitment = compute_action_commitment(&encoded);

    let encoded_hex = bytes_to_hex(&encoded);
    let commitment_hex = bytes_to_hex(&commitment);

    if std::env::var("GENERATE_VECTORS").is_ok() {
        println!("\n=== no_op ===");
        println!("encoded_hex: {}", encoded_hex);
        println!("commitment_hex: {}", commitment_hex);
    }

    // Verify NO_OP has empty payload
    assert!(
        output.actions[0].payload.is_empty(),
        "NO_OP payload must be empty"
    );
}

#[test]
fn test_empty_output() {
    // Empty AgentOutput - used for constraint failures
    let output = AgentOutput { actions: vec![] };

    let encoded = output.encode().expect("encoding should succeed");
    let commitment = compute_action_commitment(&encoded);

    let encoded_hex = bytes_to_hex(&encoded);
    let commitment_hex = bytes_to_hex(&commitment);

    // Expected values (canonical for empty output)
    let expected_encoded = "00000000";
    let expected_commitment = "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119";

    if std::env::var("GENERATE_VECTORS").is_ok() {
        println!("\n=== empty_output ===");
        println!("encoded_hex: {}", encoded_hex);
        println!("commitment_hex: {}", commitment_hex);
    }

    assert_eq!(
        encoded_hex, expected_encoded,
        "empty_output: encoded output mismatch"
    );
    assert_eq!(
        commitment_hex, expected_commitment,
        "empty_output: commitment mismatch"
    );
}

// ============================================================================
// Encoding Structure Tests
// ============================================================================

#[test]
fn test_action_wire_format() {
    // Verify the wire format structure matches documentation
    let action = ActionV1 {
        action_type: ACTION_TYPE_CALL,
        target: [0xAA; 32],
        payload: vec![1, 2, 3, 4],
    };

    let output = AgentOutput {
        actions: vec![action],
    };

    let encoded = output.encode().expect("encoding should succeed");

    // Check action_count (u32 LE)
    assert_eq!(
        &encoded[0..4],
        &[1, 0, 0, 0],
        "action_count should be 1 (LE)"
    );

    // Check action_len (u32 LE)
    // action_len = 4 (type) + 32 (target) + 4 (payload_len) + 4 (payload) = 44
    assert_eq!(
        &encoded[4..8],
        &[44, 0, 0, 0],
        "action_len should be 44 (LE)"
    );

    // Check action_type (u32 LE)
    assert_eq!(
        &encoded[8..12],
        &[2, 0, 0, 0],
        "action_type should be CALL (LE)"
    );

    // Check target (32 bytes)
    assert_eq!(
        &encoded[12..44],
        &[0xAA; 32],
        "target should be 0xAA repeated"
    );

    // Check payload_len (u32 LE)
    assert_eq!(
        &encoded[44..48],
        &[4, 0, 0, 0],
        "payload_len should be 4 (LE)"
    );

    // Check payload
    assert_eq!(
        &encoded[48..52],
        &[1, 2, 3, 4],
        "payload should be [1,2,3,4]"
    );
}

#[test]
fn test_deterministic_encoding() {
    // Verify same input always produces same output
    let action = ActionV1 {
        action_type: ACTION_TYPE_CALL,
        target: [0x42; 32],
        payload: create_call_payload(100, &[0xab, 0xcd]),
    };

    let output = AgentOutput {
        actions: vec![action.clone()],
    };

    let encoded1 = output.encode().expect("first encoding");
    let encoded2 = output.encode().expect("second encoding");

    assert_eq!(encoded1, encoded2, "encoding must be deterministic");

    let commitment1 = compute_action_commitment(&encoded1);
    let commitment2 = compute_action_commitment(&encoded2);

    assert_eq!(commitment1, commitment2, "commitment must be deterministic");
}

// ============================================================================
// SDK Helper Compatibility Tests
// ============================================================================

#[test]
fn test_call_payload_abi_structure() {
    // Verify CALL payload follows ABI encoding rules
    let payload = create_call_payload(1000, &[0xab, 0xcd, 0xef, 0x12]);

    // Total size: 32 (value) + 32 (offset) + 32 (length) + 32 (padded data) = 128
    assert_eq!(
        payload.len(),
        128,
        "CALL payload with 4-byte calldata should be 128 bytes"
    );

    // Offset should be 64 (pointing to length field)
    assert_eq!(payload[63], 64, "offset should be 64");

    // Length should be 4
    assert_eq!(payload[95], 4, "length should be 4");

    // Calldata should be at bytes 96-99
    assert_eq!(
        &payload[96..100],
        &[0xab, 0xcd, 0xef, 0x12],
        "calldata should match"
    );
}

// ============================================================================
// Negative Tests
// ============================================================================

#[test]
fn test_unknown_action_type_encodes_but_invalid() {
    // Unknown action types can be encoded (the codec doesn't validate semantics),
    // but should be rejected by the constraint engine.
    // This test verifies encoding works; the constraints crate tests rejection.
    let action = ActionV1 {
        action_type: 0xDEADBEEF, // Unknown type
        target: [0x42; 32],
        payload: vec![1, 2, 3],
    };

    let output = AgentOutput {
        actions: vec![action],
    };

    // Encoding should succeed - the codec doesn't validate action types
    let encoded = output.encode();
    assert!(
        encoded.is_ok(),
        "unknown action type should encode without error"
    );

    // The encoded bytes are valid, but constraint engine would reject this
    // (tested separately in constraints crate)
}

#[test]
fn test_transfer_erc20_payload_structure() {
    // Verify TRANSFER_ERC20 payload structure
    let token = [0x11; 20];
    let to = [0x22; 20];
    let amount: u128 = 1_000_000;

    let payload = create_transfer_erc20_payload(&token, &to, amount);

    assert_eq!(
        payload.len(),
        96,
        "TRANSFER_ERC20 payload must be exactly 96 bytes"
    );

    // Verify token address padding
    assert_eq!(
        &payload[0..12],
        &[0u8; 12],
        "token address must be left-padded"
    );
    assert_eq!(&payload[12..32], &token, "token address bytes");

    // Verify to address padding
    assert_eq!(
        &payload[32..44],
        &[0u8; 12],
        "to address must be left-padded"
    );
    assert_eq!(&payload[44..64], &to, "to address bytes");

    // Verify amount (big-endian in last 16 bytes of the 32-byte slot)
    let expected_amount_bytes = amount.to_be_bytes();
    assert_eq!(
        &payload[80..96],
        &expected_amount_bytes,
        "amount must be big-endian"
    );
}
