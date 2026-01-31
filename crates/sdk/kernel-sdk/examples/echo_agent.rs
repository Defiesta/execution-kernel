//! Reference Agent Implementation
//!
//! This is the canonical reference agent that demonstrates proper use of
//! the kernel-sdk. It shows how to create agents that produce on-chain
//! executable actions.
//!
//! # Usage
//!
//! This example is designed to be compiled as part of a zkVM guest binary.
//! In a real deployment, this would be the main entry point of the guest.
//!
//! # Production Actions
//!
//! For on-chain execution via KernelVault, agents must produce one of:
//! - `ACTION_TYPE_CALL` (0x02) - Generic contract call
//! - `ACTION_TYPE_TRANSFER_ERC20` (0x03) - ERC20 token transfer
//! - `ACTION_TYPE_NO_OP` (0x04) - No operation (skipped)
//!
//! # Properties
//!
//! - **Deterministic**: Same inputs always produce same outputs
//! - **Bounded**: Payload is truncated to `MAX_ACTION_PAYLOAD_BYTES`
//! - **Pure**: No side effects, I/O, or randomness
//! - **Minimal**: Uses only SDK-approved APIs

// In a real guest binary, you would use:
// #![no_std]
// #![no_main]
// extern crate alloc;

use kernel_sdk::prelude::*;

/// Canonical agent entrypoint.
///
/// This function is called by the kernel with the execution context
/// and opaque inputs.
///
/// # Symbol Requirements
///
/// - Name must be exactly `agent_main`
/// - Must use `#[no_mangle]` to prevent name mangling
/// - Must use `extern "Rust"` for safe Rust ABI
///
/// # Arguments
///
/// - `ctx`: Execution context with identity and metadata
/// - `opaque_inputs`: Agent-specific input data
///
/// # Panic Behavior
///
/// Panicking inside `agent_main` will:
/// - Abort guest execution
/// - Invalidate the proof
/// - Result in no journal being produced
///
/// Agents should handle errors gracefully and return empty outputs
/// rather than panicking when possible.
#[no_mangle]
pub extern "Rust" fn agent_main(ctx: &AgentContext, _opaque_inputs: &[u8]) -> AgentOutput {
    // Validate kernel version (optional but recommended)
    if !ctx.is_kernel_v1() {
        // Return empty output for unsupported versions
        // (kernel would have rejected us anyway, but being defensive)
        return AgentOutput { actions: vec![] };
    }

    // For production, create a NO_OP action that echoes the input length
    // This is a simple demonstration - real agents would parse inputs and
    // create CALL or TRANSFER_ERC20 actions for actual on-chain execution
    AgentOutput {
        actions: vec![no_op_action()],
    }
}

// ============================================================================
// Alternative Implementations (for reference)
// ============================================================================

/// No-op agent that produces no actions.
///
/// Useful for testing constraint enforcement with empty outputs.
#[allow(dead_code)]
fn noop_agent(_ctx: &AgentContext, _opaque_inputs: &[u8]) -> AgentOutput {
    AgentOutput { actions: vec![] }
}

/// Production agent that creates CALL actions for on-chain execution.
///
/// Demonstrates use of the SDK's `call_action` constructor for
/// creating actions that will be executed by KernelVault.
#[allow(dead_code)]
fn call_agent(_ctx: &AgentContext, opaque_inputs: &[u8]) -> AgentOutput {
    // Need at least 28 bytes: target_addr (20) + value (8)
    if opaque_inputs.len() < 28 {
        return AgentOutput { actions: vec![] };
    }

    // Parse inputs using SDK byte helpers
    let target_addr: [u8; 20] = match opaque_inputs[0..20].try_into() {
        Ok(addr) => addr,
        Err(_) => return AgentOutput { actions: vec![] },
    };

    let value = match kernel_sdk::bytes::read_u64_le(opaque_inputs, 20) {
        Some(v) => v as u128,
        None => return AgentOutput { actions: vec![] },
    };

    // Remaining bytes are calldata
    let calldata = &opaque_inputs[28..];

    // Create CALL action using SDK helper
    let target = address_to_bytes32(&target_addr);
    let action = call_action(target, value, calldata);

    AgentOutput {
        actions: vec![action],
    }
}

/// Production agent that creates TRANSFER_ERC20 actions.
///
/// Demonstrates use of the SDK's `transfer_erc20_action` constructor.
#[allow(dead_code)]
fn transfer_agent(_ctx: &AgentContext, opaque_inputs: &[u8]) -> AgentOutput {
    // Need exactly 48 bytes: token (20) + to (20) + amount (8)
    if opaque_inputs.len() < 48 {
        return AgentOutput { actions: vec![] };
    }

    let token: [u8; 20] = opaque_inputs[0..20].try_into().unwrap();
    let to: [u8; 20] = opaque_inputs[20..40].try_into().unwrap();
    let amount = u64::from_le_bytes(opaque_inputs[40..48].try_into().unwrap()) as u128;

    let action = transfer_erc20_action(&token, &to, amount);

    AgentOutput {
        actions: vec![action],
    }
}

// ============================================================================
// Main (required for example compilation)
// ============================================================================

/// Example main function.
///
/// In a real zkVM guest, this would be replaced with the zkVM's entry point.
/// This exists only to allow the example to compile as a standalone binary.
fn main() {
    // Create a mock context for demonstration
    let ctx = AgentContext::new(
        1,
        1,
        [0x42u8; 32],
        [0xaau8; 32],
        [0xbbu8; 32],
        [0xccu8; 32],
        12345,
    );

    let inputs = [1u8, 2, 3, 4, 5];
    let output = agent_main(&ctx, &inputs);
    println!("Agent produced {} action(s)", output.actions.len());
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_context(
        agent_id: [u8; 32],
        code_hash: [u8; 32],
        constraint_hash: [u8; 32],
        input_root: [u8; 32],
    ) -> AgentContext {
        AgentContext::new(
            1, // protocol_version
            1, // kernel_version
            agent_id,
            code_hash,
            constraint_hash,
            input_root,
            12345, // execution_nonce
        )
    }

    #[test]
    fn test_agent_main_produces_noop() {
        let ctx = make_test_context([0x42u8; 32], [0xaau8; 32], [0xbbu8; 32], [0xccu8; 32]);
        let inputs = [1u8, 2, 3, 4, 5];

        let output = agent_main(&ctx, &inputs);

        assert_eq!(output.actions.len(), 1);
        assert_eq!(output.actions[0].action_type, ACTION_TYPE_NO_OP);
    }

    #[test]
    fn test_noop_agent() {
        let ctx = make_test_context([0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32]);
        let inputs = [1u8, 2, 3];

        let output = noop_agent(&ctx, &inputs);
        assert_eq!(output.actions.len(), 0);
    }

    #[test]
    fn test_call_agent_valid_input() {
        let ctx = make_test_context([0x11u8; 32], [0u8; 32], [0u8; 32], [0u8; 32]);

        // Build input: target_addr (20) + value (8) + calldata
        let mut inputs = Vec::with_capacity(32);
        inputs.extend_from_slice(&[0x42u8; 20]); // target address
        inputs.extend_from_slice(&1000u64.to_le_bytes()); // value
        inputs.extend_from_slice(&[0xab, 0xcd, 0xef, 0x12]); // calldata

        let output = call_agent(&ctx, &inputs);

        assert_eq!(output.actions.len(), 1);
        assert_eq!(output.actions[0].action_type, ACTION_TYPE_CALL);
    }

    #[test]
    fn test_call_agent_invalid_input() {
        let ctx = make_test_context([0x11u8; 32], [0u8; 32], [0u8; 32], [0u8; 32]);
        let inputs = [1u8, 2, 3]; // Too short

        let output = call_agent(&ctx, &inputs);
        assert_eq!(output.actions.len(), 0); // Graceful degradation
    }

    #[test]
    fn test_transfer_agent_valid_input() {
        let ctx = make_test_context([0x11u8; 32], [0u8; 32], [0u8; 32], [0u8; 32]);

        // Build input: token (20) + to (20) + amount (8)
        let mut inputs = Vec::with_capacity(48);
        inputs.extend_from_slice(&[0x11u8; 20]); // token
        inputs.extend_from_slice(&[0x22u8; 20]); // to
        inputs.extend_from_slice(&1_000_000u64.to_le_bytes()); // amount

        let output = transfer_agent(&ctx, &inputs);

        assert_eq!(output.actions.len(), 1);
        assert_eq!(output.actions[0].action_type, ACTION_TYPE_TRANSFER_ERC20);
    }
}
