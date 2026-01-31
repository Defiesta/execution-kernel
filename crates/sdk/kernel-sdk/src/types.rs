//! Type definitions and re-exports for agent development.
//!
//! This module provides the core types that agents use to produce output:
//! - [`AgentOutput`] - The structured output returned by agents
//! - [`ActionV1`] - Individual actions within the output
//!
//! # On-Chain Executable Action Types (Protocol v1)
//!
//! The following action types are supported by KernelVault for on-chain execution:
//!
//! - [`ACTION_TYPE_CALL`] - Generic contract call (0x00000002)
//!   - Payload: `abi.encode(uint256 value, bytes callData)`
//!   - Execution: `target.call{value: value}(callData)`
//!
//! - [`ACTION_TYPE_TRANSFER_ERC20`] - ERC20 token transfer (0x00000003)
//!   - Payload: `abi.encode(address token, address to, uint256 amount)`
//!   - Execution: `IERC20(token).transfer(to, amount)`
//!
//! - [`ACTION_TYPE_NO_OP`] - No operation (0x00000004)
//!   - Payload: empty
//!   - Execution: skipped
//!
//! # Important Notes
//!
//! - Higher-level strategy concepts (e.g., "open position", "swap") are agent
//!   abstractions that must be compiled down to CALL or TRANSFER_ERC20 actions.
//! - The target field is a bytes32 with the EVM address left-padded (12 zero bytes + 20-byte address).
//! - All payloads must be ABI-encoded to match Solidity's expectations.
//!
//! # Size Limits
//!
//! - [`MAX_ACTIONS_PER_OUTPUT`] - Maximum 64 actions per output
//! - [`MAX_ACTION_PAYLOAD_BYTES`] - Maximum 16,384 bytes per action payload

use alloc::vec::Vec;

// Re-export core types from kernel-core
pub use kernel_core::{ActionV1, AgentOutput, MAX_ACTIONS_PER_OUTPUT, MAX_ACTION_PAYLOAD_BYTES};

// ============================================================================
// Action Type Constants (re-exported from kernel-core)
// ============================================================================
//
// These are re-exports of the canonical constants from kernel-core.
// kernel-core is the single source of truth for action type values.

/// CALL action type for on-chain execution (0x00000002).
///
/// See [`kernel_core::ACTION_TYPE_CALL`] for full documentation.
pub use kernel_core::ACTION_TYPE_CALL;

/// ERC20 transfer action type for on-chain execution (0x00000003).
///
/// See [`kernel_core::ACTION_TYPE_TRANSFER_ERC20`] for full documentation.
pub use kernel_core::ACTION_TYPE_TRANSFER_ERC20;

/// No-op action type (0x00000004).
///
/// See [`kernel_core::ACTION_TYPE_NO_OP`] for full documentation.
pub use kernel_core::ACTION_TYPE_NO_OP;

/// Echo action type for testing (0x00000001).
///
/// Only available with the `testing` feature or in test mode.
/// This action type is NOT executable by KernelVault.
///
/// Note: This is defined locally rather than re-exported from kernel-core
/// because the cfg gates don't propagate across crate boundaries.
#[cfg(any(test, feature = "testing"))]
pub const ACTION_TYPE_ECHO: u32 = 0x00000001;

// ============================================================================
// Helper Constructors
// ============================================================================

/// Create an Echo action (testing only).
///
/// # Arguments
/// * `target` - 32-byte target identifier
/// * `payload` - Arbitrary payload bytes
#[cfg(any(test, feature = "testing"))]
#[inline]
#[must_use]
pub fn echo_action(target: [u8; 32], payload: Vec<u8>) -> ActionV1 {
    ActionV1 {
        action_type: ACTION_TYPE_ECHO,
        target,
        payload,
    }
}

/// Create a CALL action for on-chain execution.
///
/// This creates an action that will be executed by KernelVault.execute()
/// as: `target.call{value: value}(call_data)`
///
/// # Arguments
/// * `target` - 32-byte target (EVM address left-padded with 12 zero bytes)
/// * `value` - ETH value to send (in wei)
/// * `call_data` - Raw calldata bytes (function selector + encoded args)
///
/// # Payload Format
///
/// The payload is ABI-encoded as: `abi.encode(uint256 value, bytes callData)`
/// - bytes 0-31: value as uint256 (big-endian)
/// - bytes 32-63: offset to bytes data (always 64)
/// - bytes 64-95: length of callData
/// - bytes 96+: callData (padded to 32-byte boundary)
#[inline]
#[must_use]
pub fn call_action(target: [u8; 32], value: u128, call_data: &[u8]) -> ActionV1 {
    ActionV1 {
        action_type: ACTION_TYPE_CALL,
        target,
        payload: encode_call_payload(value, call_data),
    }
}

/// Create a TRANSFER_ERC20 action for on-chain execution.
///
/// This creates an action that will be executed by KernelVault.execute()
/// as: `IERC20(token).transfer(to, amount)`
///
/// # Arguments
/// * `token` - 20-byte ERC20 token address
/// * `to` - 20-byte recipient address
/// * `amount` - Amount to transfer (in token's smallest unit)
///
/// # Target
///
/// The target is set to zero (unused for ERC20 transfers).
/// The token address is encoded in the payload.
#[inline]
#[must_use]
pub fn transfer_erc20_action(token: &[u8; 20], to: &[u8; 20], amount: u128) -> ActionV1 {
    ActionV1 {
        action_type: ACTION_TYPE_TRANSFER_ERC20,
        target: [0u8; 32], // Target unused for ERC20 transfers
        payload: encode_transfer_erc20_payload(token, to, amount),
    }
}

/// Create a NO_OP action.
///
/// This action is skipped during on-chain execution.
/// Useful for padding or placeholder actions.
#[inline]
#[must_use]
pub fn no_op_action() -> ActionV1 {
    ActionV1 {
        action_type: ACTION_TYPE_NO_OP,
        target: [0u8; 32],
        payload: Vec::new(),
    }
}

/// Convert a 20-byte EVM address to bytes32 (left-padded).
///
/// The resulting bytes32 has:
/// - Upper 12 bytes: 0x00
/// - Lower 20 bytes: The EVM address
#[inline]
#[must_use]
pub fn address_to_bytes32(addr: &[u8; 20]) -> [u8; 32] {
    let mut result = [0u8; 32];
    result[12..32].copy_from_slice(addr);
    result
}

// ============================================================================
// Payload Encoding Helpers
// ============================================================================

/// Encode a u256 value in big-endian format (for ABI encoding).
#[inline]
fn encode_u256_be(value: u128) -> [u8; 32] {
    let mut result = [0u8; 32];
    // Value fits in u128, so only fill lower 16 bytes (big-endian)
    result[16..32].copy_from_slice(&value.to_be_bytes());
    result
}

/// Encode the CALL payload: abi.encode(uint256 value, bytes callData)
///
/// ABI encoding for (uint256, bytes):
/// - bytes 0-31: value (uint256, big-endian)
/// - bytes 32-63: offset to bytes data (always 64 = 0x40)
/// - bytes 64-95: length of bytes data
/// - bytes 96+: bytes data (padded to 32-byte boundary)
fn encode_call_payload(value: u128, call_data: &[u8]) -> Vec<u8> {
    let data_len = call_data.len();
    // Pad data to 32-byte boundary
    let padded_len = data_len.div_ceil(32) * 32;

    // Total size: 32 (value) + 32 (offset) + 32 (length) + padded_data
    let total_size = 96 + padded_len;
    let mut payload = Vec::with_capacity(total_size);

    // 1. uint256 value
    payload.extend_from_slice(&encode_u256_be(value));

    // 2. offset to bytes data (always 64 = 0x40)
    payload.extend_from_slice(&encode_u256_be(64));

    // 3. length of bytes data
    payload.extend_from_slice(&encode_u256_be(data_len as u128));

    // 4. bytes data (padded)
    payload.extend_from_slice(call_data);
    // Pad to 32-byte boundary
    payload.resize(total_size, 0);

    payload
}

/// Encode the TRANSFER_ERC20 payload: abi.encode(address token, address to, uint256 amount)
///
/// ABI encoding for (address, address, uint256):
/// - bytes 0-31: token address (left-padded to 32 bytes)
/// - bytes 32-63: to address (left-padded to 32 bytes)
/// - bytes 64-95: amount (uint256, big-endian)
fn encode_transfer_erc20_payload(token: &[u8; 20], to: &[u8; 20], amount: u128) -> Vec<u8> {
    let mut payload = Vec::with_capacity(96);

    // 1. address token (left-padded)
    payload.extend_from_slice(&address_to_bytes32(token));

    // 2. address to (left-padded)
    payload.extend_from_slice(&address_to_bytes32(to));

    // 3. uint256 amount
    payload.extend_from_slice(&encode_u256_be(amount));

    payload
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_echo_action() {
        let action = echo_action([0x42; 32], alloc::vec![1, 2, 3]);
        assert_eq!(action.action_type, ACTION_TYPE_ECHO);
        assert_eq!(action.target, [0x42; 32]);
        assert_eq!(action.payload, alloc::vec![1, 2, 3]);
    }

    #[test]
    fn test_call_action() {
        let target = address_to_bytes32(&[0x11; 20]);
        let action = call_action(target, 1000, &[0xab, 0xcd, 0xef, 0x12]);

        assert_eq!(action.action_type, ACTION_TYPE_CALL);
        assert_eq!(action.target, target);
        // Payload should be ABI-encoded: value (32) + offset (32) + length (32) + data (32 padded)
        assert_eq!(action.payload.len(), 128);

        // Verify value encoding (big-endian u256)
        let mut expected_value = [0u8; 32];
        expected_value[16..32].copy_from_slice(&1000u128.to_be_bytes());
        assert_eq!(&action.payload[0..32], &expected_value);

        // Verify offset (64 = 0x40)
        assert_eq!(action.payload[63], 64);

        // Verify length (4)
        assert_eq!(action.payload[95], 4);

        // Verify calldata
        assert_eq!(&action.payload[96..100], &[0xab, 0xcd, 0xef, 0x12]);
    }

    #[test]
    fn test_transfer_erc20_action() {
        let token = [0x11; 20];
        let to = [0x22; 20];
        let action = transfer_erc20_action(&token, &to, 1_000_000);

        assert_eq!(action.action_type, ACTION_TYPE_TRANSFER_ERC20);
        assert_eq!(action.target, [0u8; 32]); // Target unused for ERC20
        assert_eq!(action.payload.len(), 96);

        // Verify token address (left-padded)
        assert_eq!(&action.payload[0..12], &[0u8; 12]);
        assert_eq!(&action.payload[12..32], &token);

        // Verify to address (left-padded)
        assert_eq!(&action.payload[32..44], &[0u8; 12]);
        assert_eq!(&action.payload[44..64], &to);

        // Verify amount (big-endian u256)
        let mut expected_amount = [0u8; 32];
        expected_amount[16..32].copy_from_slice(&1_000_000u128.to_be_bytes());
        assert_eq!(&action.payload[64..96], &expected_amount);
    }

    #[test]
    fn test_no_op_action() {
        let action = no_op_action();
        assert_eq!(action.action_type, ACTION_TYPE_NO_OP);
        assert_eq!(action.target, [0u8; 32]);
        assert!(action.payload.is_empty());
    }

    #[test]
    fn test_address_to_bytes32() {
        let addr = [0xab; 20];
        let bytes32 = address_to_bytes32(&addr);

        assert_eq!(&bytes32[0..12], &[0u8; 12]);
        assert_eq!(&bytes32[12..32], &addr);
    }

    #[test]
    fn test_agent_output_construction() {
        let output = AgentOutput {
            actions: alloc::vec![
                call_action(address_to_bytes32(&[0x11; 20]), 0, &[]),
                no_op_action(),
            ],
        };

        assert_eq!(output.actions.len(), 2);
    }

    // ========================================================================
    // Action Type Re-export Invariant Tests
    // ========================================================================

    #[test]
    fn test_action_types_match_kernel_core() {
        // Verify that our re-exports match kernel-core's values
        assert_eq!(ACTION_TYPE_CALL, kernel_core::ACTION_TYPE_CALL);
        assert_eq!(
            ACTION_TYPE_TRANSFER_ERC20,
            kernel_core::ACTION_TYPE_TRANSFER_ERC20
        );
        assert_eq!(ACTION_TYPE_NO_OP, kernel_core::ACTION_TYPE_NO_OP);
        // Note: ACTION_TYPE_ECHO is available in test via cfg(test)
        assert_eq!(ACTION_TYPE_ECHO, 0x00000001);
    }

    #[test]
    fn test_action_types_have_expected_values() {
        // Verify the actual numeric values match KernelOutputParser.sol
        assert_eq!(ACTION_TYPE_CALL, 0x00000002);
        assert_eq!(ACTION_TYPE_TRANSFER_ERC20, 0x00000003);
        assert_eq!(ACTION_TYPE_NO_OP, 0x00000004);
        assert_eq!(ACTION_TYPE_ECHO, 0x00000001);
    }
}
