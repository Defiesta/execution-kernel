//! Example Yield Agent Implementation
//!
//! This agent demonstrates E2E execution flow for yield farming:
//! 1. Deposit ETH to MockYieldSource
//! 2. Withdraw ETH + 10% yield from MockYieldSource
//!
//! # Input Format (48 bytes)
//!
//! ```text
//! [0:20]   vault_address (20 bytes)
//! [20:40]  mock_yield_address (20 bytes)
//! [40:48]  transfer_amount (u64 LE)
//! ```
//!
//! # Output Actions
//!
//! Two CALL actions targeting MockYieldSource:
//! 1. Deposit: `call{value: amount}("")` - sends ETH
//! 2. Withdraw: `call{value: 0}(withdraw(vault))` - triggers withdrawal
//!
//! # On-Chain Action Format (KernelOutputParser.sol)
//!
//! - `action_type`: 0x00000002 (ACTION_TYPE_CALL)
//! - `target`: bytes32 (address left-padded with 12 zero bytes)
//! - `payload`: abi.encode(uint256 value, bytes callData)

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;

use alloc::{vec, vec::Vec};
use kernel_sdk::prelude::*;

// Include the generated agent hash constant.
include!(concat!(env!("OUT_DIR"), "/agent_hash.rs"));

// ============================================================================
// Constants
// ============================================================================

/// Expected input size: 20 (vault) + 20 (yield source) + 8 (amount) = 48 bytes
const INPUT_SIZE: usize = 48;

/// Withdraw function selector: keccak256("withdraw(address)")[:4]
const WITHDRAW_SELECTOR: [u8; 4] = [0x51, 0xcf, 0xf8, 0xd9];

// ============================================================================
// Agent Entry Point
// ============================================================================

/// Canonical agent entrypoint for the yield agent.
///
/// # Arguments
///
/// - `ctx`: Execution context (contains agent_id used for withdraw call)
/// - `opaque_inputs`: 48-byte input with addresses and amount
///
/// # Returns
///
/// AgentOutput with two CALL actions: deposit and withdraw.
#[no_mangle]
#[allow(unsafe_code)]
pub extern "Rust" fn agent_main(_ctx: &AgentContext, opaque_inputs: &[u8]) -> AgentOutput {
    // Validate input size
    if opaque_inputs.len() != INPUT_SIZE {
        // Invalid input - return empty output (will be handled by constraints)
        return AgentOutput {
            actions: Vec::new(),
        };
    }

    // Parse input
    let vault_address: [u8; 20] = opaque_inputs[0..20].try_into().unwrap();
    let mock_yield_address: [u8; 20] = opaque_inputs[20..40].try_into().unwrap();
    let transfer_amount = u64::from_le_bytes(opaque_inputs[40..48].try_into().unwrap());

    // Build target (left-pad address to bytes32)
    let target = address_to_bytes32(&mock_yield_address);

    // Build Action 1: Deposit ETH to MockYieldSource
    // call{value: amount}("") - sends ETH with empty calldata
    let deposit_action = call_action(target, transfer_amount as u128, &[]);

    // Build Action 2: Withdraw from MockYieldSource
    // call{value: 0}(withdraw(vault_address))
    let withdraw_calldata = encode_withdraw_call(&vault_address);
    let withdraw_action = call_action(target, 0, &withdraw_calldata);

    // Return both actions (deposit first, then withdraw)
    AgentOutput {
        actions: vec![deposit_action, withdraw_action],
    }
}

// ============================================================================
// ABI Encoding Helpers
// ============================================================================

/// Encode the withdraw(address) function call.
///
/// Format: selector (4 bytes) + address (32 bytes, left-padded)
fn encode_withdraw_call(depositor: &[u8; 20]) -> Vec<u8> {
    let mut calldata = Vec::with_capacity(36);
    calldata.extend_from_slice(&WITHDRAW_SELECTOR);
    calldata.extend_from_slice(&address_to_bytes32(depositor));
    calldata
}

// ============================================================================
// Compile-time ABI Verification
// ============================================================================

/// Compile-time check that agent_main matches the canonical AgentEntrypoint type.
const _: AgentEntrypoint = agent_main;

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_input(vault: [u8; 20], yield_source: [u8; 20], amount: u64) -> Vec<u8> {
        let mut input = Vec::with_capacity(INPUT_SIZE);
        input.extend_from_slice(&vault);
        input.extend_from_slice(&yield_source);
        input.extend_from_slice(&amount.to_le_bytes());
        input
    }

    #[test]
    fn test_agent_main_produces_two_actions() {
        let ctx = AgentContext {
            protocol_version: 1,
            kernel_version: 1,
            agent_id: [0x42u8; 32],
            agent_code_hash: AGENT_CODE_HASH,
            constraint_set_hash: [0xbb; 32],
            input_root: [0xcc; 32],
            execution_nonce: 1,
        };

        let vault = [0x11u8; 20];
        let yield_source = [0x22u8; 20];
        let amount: u64 = 1_000_000_000_000_000_000; // 1 ETH

        let input = make_test_input(vault, yield_source, amount);
        let output = agent_main(&ctx, &input);

        assert_eq!(output.actions.len(), 2, "Expected 2 actions");

        // Both actions should target the yield source
        let expected_target = address_to_bytes32(&yield_source);
        assert_eq!(
            output.actions[0].target, expected_target,
            "Deposit target mismatch"
        );
        assert_eq!(
            output.actions[1].target, expected_target,
            "Withdraw target mismatch"
        );

        // Both actions should be CALL type
        assert_eq!(output.actions[0].action_type, ACTION_TYPE_CALL);
        assert_eq!(output.actions[1].action_type, ACTION_TYPE_CALL);
    }

    #[test]
    fn test_deposit_action_payload_format() {
        let ctx = AgentContext {
            protocol_version: 1,
            kernel_version: 1,
            agent_id: [0x42u8; 32],
            agent_code_hash: AGENT_CODE_HASH,
            constraint_set_hash: [0xbb; 32],
            input_root: [0xcc; 32],
            execution_nonce: 1,
        };

        let vault = [0x11u8; 20];
        let yield_source = [0x22u8; 20];
        let amount: u64 = 1_000_000_000_000_000_000; // 1 ETH

        let input = make_test_input(vault, yield_source, amount);
        let output = agent_main(&ctx, &input);

        let deposit_payload = &output.actions[0].payload;

        // Should be 96 bytes (32 + 32 + 32 + 0 padded)
        assert_eq!(
            deposit_payload.len(),
            96,
            "Deposit payload should be 96 bytes"
        );

        // Check value encoding (bytes 0-31)
        let value_bytes = &deposit_payload[0..32];
        // Value should be in last 8 bytes for u64 (big-endian in u256)
        assert_eq!(&value_bytes[24..32], &amount.to_be_bytes());

        // Check offset (bytes 32-63) = 64
        let offset_bytes = &deposit_payload[32..64];
        assert_eq!(offset_bytes[31], 64); // Last byte should be 64

        // Check length (bytes 64-95) = 0
        let length_bytes = &deposit_payload[64..96];
        assert_eq!(length_bytes, &[0u8; 32]); // All zeros for empty data
    }

    #[test]
    fn test_withdraw_action_payload_format() {
        let ctx = AgentContext {
            protocol_version: 1,
            kernel_version: 1,
            agent_id: [0x42u8; 32],
            agent_code_hash: AGENT_CODE_HASH,
            constraint_set_hash: [0xbb; 32],
            input_root: [0xcc; 32],
            execution_nonce: 1,
        };

        let vault = [0x11u8; 20];
        let yield_source = [0x22u8; 20];
        let amount: u64 = 1_000_000_000_000_000_000;

        let input = make_test_input(vault, yield_source, amount);
        let output = agent_main(&ctx, &input);

        let withdraw_payload = &output.actions[1].payload;

        // payload = 32 (value) + 32 (offset) + 32 (length) + 64 (padded calldata)
        // 36 bytes padded to 32-byte boundary = 64 bytes
        assert_eq!(
            withdraw_payload.len(),
            160,
            "Withdraw payload should be 160 bytes"
        );

        // Check value = 0 (bytes 0-31)
        assert_eq!(&withdraw_payload[0..32], &[0u8; 32]);

        // Check offset = 64 (bytes 32-63)
        assert_eq!(withdraw_payload[63], 64);

        // Check length = 36 (bytes 64-95)
        assert_eq!(withdraw_payload[95], 36);

        // Check selector (bytes 96-99)
        assert_eq!(&withdraw_payload[96..100], &WITHDRAW_SELECTOR);

        // Check vault address (bytes 100-131, left-padded)
        assert_eq!(&withdraw_payload[100..112], &[0u8; 12]); // Padding
        assert_eq!(&withdraw_payload[112..132], &vault);
    }

    #[test]
    fn test_withdraw_calldata_encoding() {
        let vault = [0x11u8; 20];
        let calldata = encode_withdraw_call(&vault);

        // calldata = 4 (selector) + 32 (address) = 36 bytes
        assert_eq!(calldata.len(), 36, "Withdraw calldata should be 36 bytes");

        // Check selector
        assert_eq!(&calldata[0..4], &WITHDRAW_SELECTOR);

        // Check vault address (left-padded to 32 bytes)
        assert_eq!(&calldata[4..16], &[0u8; 12]); // Padding
        assert_eq!(&calldata[16..36], &vault);
    }

    #[test]
    fn test_address_to_bytes32_from_sdk() {
        let addr = [0xabu8; 20];
        let result = address_to_bytes32(&addr);

        assert_eq!(&result[0..12], &[0u8; 12], "First 12 bytes should be 0");
        assert_eq!(&result[12..32], &addr, "Last 20 bytes should be address");
    }

    #[test]
    fn test_invalid_input_size_returns_empty() {
        let ctx = AgentContext {
            protocol_version: 1,
            kernel_version: 1,
            agent_id: [0x42u8; 32],
            agent_code_hash: AGENT_CODE_HASH,
            constraint_set_hash: [0xbb; 32],
            input_root: [0xcc; 32],
            execution_nonce: 1,
        };

        // Test too short
        let short_input = alloc::vec![0u8; 40];
        let output = agent_main(&ctx, &short_input);
        assert!(
            output.actions.is_empty(),
            "Short input should produce empty output"
        );

        // Test too long
        let long_input = alloc::vec![0u8; 50];
        let output = agent_main(&ctx, &long_input);
        assert!(
            output.actions.is_empty(),
            "Long input should produce empty output"
        );
    }

    #[test]
    fn test_withdraw_selector_is_correct() {
        // keccak256("withdraw(address)") = 0x51cff8d9...
        // This is the standard selector for withdraw(address)
        assert_eq!(WITHDRAW_SELECTOR, [0x51, 0xcf, 0xf8, 0xd9]);
    }
}
