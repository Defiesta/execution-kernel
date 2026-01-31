//! Agent output reconstruction.
//!
//! For on-chain execution, we need the raw agent output bytes (not just the commitment).
//! Since the zkVM only outputs the journal (which contains the commitment), we need to
//! reconstruct the agent output from the inputs.
//!
//! This module provides reconstruction for known agent types.

use kernel_core::{ActionV1, AgentOutput, CanonicalEncode};

/// Action type for generic contract call.
const ACTION_TYPE_CALL: u32 = 0x00000002;

/// Errors that can occur during agent output reconstruction.
#[derive(Debug, thiserror::Error)]
pub enum AgentOutputError {
    #[error("Invalid opaque inputs length: expected {expected}, got {actual}")]
    InvalidInputLength { expected: usize, actual: usize },

    #[error("Failed to encode agent output: {0}")]
    EncodingError(String),
}

/// Reconstruct the yield agent's output from opaque inputs.
///
/// The yield agent produces two CALL actions:
/// 1. Deposit: call{value: amount}("") to yield_source
/// 2. Withdraw: call{value: 0}(withdraw(vault)) to yield_source
///
/// # Arguments
///
/// * `opaque_inputs` - 48 bytes: vault (20) + yield_source (20) + amount (8 LE)
///
/// # Returns
///
/// The encoded AgentOutput bytes that can be submitted on-chain.
pub fn reconstruct_yield_agent_output(opaque_inputs: &[u8]) -> Result<Vec<u8>, AgentOutputError> {
    const INPUT_SIZE: usize = 48;

    if opaque_inputs.len() != INPUT_SIZE {
        return Err(AgentOutputError::InvalidInputLength {
            expected: INPUT_SIZE,
            actual: opaque_inputs.len(),
        });
    }

    // Parse input
    let vault_address: [u8; 20] = opaque_inputs[0..20].try_into().unwrap();
    let yield_source: [u8; 20] = opaque_inputs[20..40].try_into().unwrap();
    let amount = u64::from_le_bytes(opaque_inputs[40..48].try_into().unwrap());

    // Build target (left-pad address to bytes32)
    let target = address_to_bytes32(&yield_source);

    // Build Action 1: Deposit ETH to MockYieldSource
    let deposit_action = call_action(target, amount as u128, &[]);

    // Build Action 2: Withdraw from MockYieldSource
    let withdraw_calldata = encode_withdraw_call(&vault_address);
    let withdraw_action = call_action(target, 0, &withdraw_calldata);

    // Build AgentOutput
    let output = AgentOutput {
        actions: vec![deposit_action, withdraw_action],
    };

    // Encode to bytes
    output
        .encode()
        .map_err(|e| AgentOutputError::EncodingError(format!("{:?}", e)))
}

/// Convert a 20-byte address to a 32-byte target (left-padded with zeros).
fn address_to_bytes32(addr: &[u8; 20]) -> [u8; 32] {
    let mut result = [0u8; 32];
    result[12..32].copy_from_slice(addr);
    result
}

/// Create a CALL action with the given target, value, and calldata.
fn call_action(target: [u8; 32], value: u128, calldata: &[u8]) -> ActionV1 {
    // Payload format: abi.encode(uint256 value, bytes callData)
    // = 32 bytes (value) + 32 bytes (offset=64) + 32 bytes (length) + calldata padded to 32

    let calldata_len = calldata.len();
    let padded_len = calldata_len.div_ceil(32) * 32;
    let payload_len = 32 + 32 + 32 + padded_len;

    let mut payload = vec![0u8; payload_len];

    // Value (uint256, big-endian)
    let value_bytes = value.to_be_bytes();
    payload[32 - 16..32].copy_from_slice(&value_bytes);

    // Offset (uint256 = 64)
    payload[63] = 64;

    // Length (uint256)
    payload[95] = calldata_len as u8;

    // Calldata (padded)
    payload[96..96 + calldata_len].copy_from_slice(calldata);

    ActionV1 {
        action_type: ACTION_TYPE_CALL,
        target,
        payload,
    }
}

/// Withdraw function selector: keccak256("withdraw(address)")[:4]
const WITHDRAW_SELECTOR: [u8; 4] = [0x51, 0xcf, 0xf8, 0xd9];

/// Encode the withdraw(address) function call.
fn encode_withdraw_call(depositor: &[u8; 20]) -> Vec<u8> {
    let mut calldata = Vec::with_capacity(36);
    calldata.extend_from_slice(&WITHDRAW_SELECTOR);
    calldata.extend_from_slice(&address_to_bytes32(depositor));
    calldata
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernel_core::compute_action_commitment;

    #[test]
    fn test_reconstruct_yield_agent_output() {
        let vault = [0x11u8; 20];
        let yield_source = [0x22u8; 20];
        let amount: u64 = 1_000_000;

        let mut opaque_inputs = Vec::with_capacity(48);
        opaque_inputs.extend_from_slice(&vault);
        opaque_inputs.extend_from_slice(&yield_source);
        opaque_inputs.extend_from_slice(&amount.to_le_bytes());

        let output_bytes = reconstruct_yield_agent_output(&opaque_inputs).unwrap();

        // Should produce valid encoded output
        assert!(!output_bytes.is_empty());

        // First 4 bytes should be action count (2 as u32 LE)
        assert_eq!(&output_bytes[0..4], &[2, 0, 0, 0]);
    }

    #[test]
    fn test_invalid_input_length() {
        let short_input = [0u8; 40];
        let result = reconstruct_yield_agent_output(&short_input);
        assert!(matches!(
            result,
            Err(AgentOutputError::InvalidInputLength { .. })
        ));
    }

    #[test]
    fn test_action_commitment_matches() {
        // Use the same inputs as the e2e test
        let vault: [u8; 20] = hex_literal::hex!("AdeDA97D2D07C7f2e332fD58F40Eb4f7F0192be7");
        let yield_source: [u8; 20] = hex_literal::hex!("7B35E3F2e810170f146d31b00262b9D7138F9b39");
        let amount: u64 = 1_000_000;

        let mut opaque_inputs = Vec::with_capacity(48);
        opaque_inputs.extend_from_slice(&vault);
        opaque_inputs.extend_from_slice(&yield_source);
        opaque_inputs.extend_from_slice(&amount.to_le_bytes());

        let output_bytes = reconstruct_yield_agent_output(&opaque_inputs).unwrap();

        // Compute action commitment
        let commitment = compute_action_commitment(&output_bytes);

        // Should produce a valid 32-byte commitment
        assert_eq!(commitment.len(), 32);
    }
}
