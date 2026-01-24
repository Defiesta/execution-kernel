//! Example Agent Implementation
//!
//! This crate provides a minimal example agent that demonstrates the canonical
//! `agent_main` entrypoint. It is used for testing the kernel's agent execution
//! flow.
//!
//! # Behavior
//!
//! The agent checks the first byte of `opaque_inputs`:
//! - If `opaque_inputs[0] == 1` → Echo action with full inputs as payload
//! - Otherwise → Empty output (no actions)
//!
//! This allows testing both action-producing and no-action execution paths.

#![no_std]
// Use `deny` instead of `forbid` to allow targeted exception for #[no_mangle]
// The #[no_mangle] attribute is required for the canonical agent_main symbol,
// and triggers the unsafe_code lint because symbol collisions are UB.
#![deny(unsafe_code)]

extern crate alloc;

use kernel_sdk::prelude::*;

/// Canonical agent entrypoint.
///
/// This function is called by the kernel to execute the agent logic.
/// The symbol name `agent_main` is mandatory and fixed.
///
/// # Arguments
///
/// - `ctx`: Execution context with identity and metadata
/// - `opaque_inputs`: Agent-specific input data
///
/// # Safety Note
///
/// The `#[no_mangle]` attribute is required so the kernel can find this symbol.
/// The `unsafe_code` lint is allowed here because the symbol name is canonical
/// and expected by the kernel - there is no risk of collision.
#[no_mangle]
#[allow(unsafe_code)]
pub extern "Rust" fn agent_main(ctx: &AgentContext, opaque_inputs: &[u8]) -> AgentOutput {
    let should_echo = !opaque_inputs.is_empty() && opaque_inputs[0] == 1;

    if should_echo {
        // Truncate to max payload size if needed
        let payload_len = opaque_inputs.len().min(MAX_ACTION_PAYLOAD_BYTES);
        let mut payload = Vec::with_capacity(payload_len);
        payload.extend_from_slice(&opaque_inputs[..payload_len]);

        let action = echo_action(ctx.agent_id, payload);

        let mut actions = Vec::with_capacity(1);
        actions.push(action);
        AgentOutput { actions }
    } else {
        AgentOutput { actions: Vec::new() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_main_echo() {
        let ctx = AgentContext {
            protocol_version: 1,
            kernel_version: 1,
            agent_id: [0x42u8; 32],
            agent_code_hash: [0xaau8; 32],
            constraint_set_hash: [0xbbu8; 32],
            input_root: [0xccu8; 32],
            execution_nonce: 1,
        };

        let inputs = [1u8, 2, 3, 4, 5]; // First byte is 1 -> should echo
        let output = agent_main(&ctx, &inputs);

        assert_eq!(output.actions.len(), 1);
        assert_eq!(output.actions[0].action_type, ACTION_TYPE_ECHO);
        assert_eq!(output.actions[0].target, ctx.agent_id);
        assert_eq!(output.actions[0].payload, inputs.to_vec());
    }

    #[test]
    fn test_agent_main_no_echo() {
        let ctx = AgentContext {
            protocol_version: 1,
            kernel_version: 1,
            agent_id: [0x42u8; 32],
            agent_code_hash: [0xaau8; 32],
            constraint_set_hash: [0xbbu8; 32],
            input_root: [0xccu8; 32],
            execution_nonce: 1,
        };

        let inputs = [0u8, 2, 3, 4, 5]; // First byte is 0 -> no echo
        let output = agent_main(&ctx, &inputs);

        assert!(output.actions.is_empty());
    }

    #[test]
    fn test_agent_main_empty_inputs() {
        let ctx = AgentContext {
            protocol_version: 1,
            kernel_version: 1,
            agent_id: [0x42u8; 32],
            agent_code_hash: [0xaau8; 32],
            constraint_set_hash: [0xbbu8; 32],
            input_root: [0xccu8; 32],
            execution_nonce: 1,
        };

        let inputs: [u8; 0] = []; // Empty -> no echo
        let output = agent_main(&ctx, &inputs);

        assert!(output.actions.is_empty());
    }
}
