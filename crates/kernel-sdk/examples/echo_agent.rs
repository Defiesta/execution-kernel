//! Reference Echo Agent Implementation
//!
//! This is the canonical reference agent that demonstrates proper use of
//! the kernel-sdk. It implements the simplest possible agent behavior:
//! echoing the opaque inputs back as an Echo action.
//!
//! # Usage
//!
//! This example is designed to be compiled as part of a zkVM guest binary.
//! In a real deployment, this would be the main entry point of the guest.
//!
//! # Behavior
//!
//! 1. Receives `AgentContext` from the kernel
//! 2. Creates a single `Echo` action
//! 3. Uses `agent_id` as the target
//! 4. Uses `opaque_inputs` as the payload (truncated to max size)
//! 5. Returns `AgentOutput` with the single action
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
/// This function is called by the kernel with the execution context.
/// It must return an `AgentOutput` containing zero or more actions.
///
/// # Symbol Requirements
///
/// - Name must be exactly `agent_main`
/// - Must use `#[no_mangle]` to prevent name mangling
/// - Must use `extern "C"` for C ABI compatibility
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
#[allow(improper_ctypes_definitions)] // AgentOutput uses zkVM ABI, not literal C FFI
pub extern "C" fn agent_main(ctx: &AgentContext) -> AgentOutput {
    // Validate kernel version (optional but recommended)
    if !ctx.is_kernel_v1() {
        // Return empty output for unsupported versions
        // (kernel would have rejected us anyway, but being defensive)
        return AgentOutput { actions: vec![] };
    }

    // Truncate payload to max size if needed
    let max_payload = kernel_sdk::types::MAX_ACTION_PAYLOAD_BYTES;
    let payload_len = if ctx.opaque_inputs.len() > max_payload {
        max_payload
    } else {
        ctx.opaque_inputs.len()
    };

    // Create the echo action
    let action = ActionV1 {
        action_type: ACTION_TYPE_ECHO,
        target: *ctx.agent_id,
        payload: ctx.opaque_inputs[..payload_len].to_vec(),
    };

    // Return the output
    AgentOutput {
        actions: vec![action],
    }
}

// ============================================================================
// Alternative Implementations (for reference)
// ============================================================================

/// No-op agent that produces no actions.
///
/// Useful for testing constraint enforcement with empty outputs.
#[allow(dead_code)]
fn noop_agent(_ctx: &AgentContext) -> AgentOutput {
    AgentOutput { actions: vec![] }
}

/// Multi-action agent that produces one echo per input byte.
///
/// Demonstrates bounded iteration and multiple action production.
#[allow(dead_code)]
fn multi_echo_agent(ctx: &AgentContext) -> AgentOutput {
    // Limit to MAX_ACTIONS_PER_OUTPUT actions
    let action_count = if ctx.opaque_inputs.len() > MAX_ACTIONS_PER_OUTPUT {
        MAX_ACTIONS_PER_OUTPUT
    } else {
        ctx.opaque_inputs.len()
    };

    let actions: Vec<ActionV1> = ctx.opaque_inputs[..action_count]
        .iter()
        .map(|&byte| ActionV1 {
            action_type: ACTION_TYPE_ECHO,
            target: *ctx.agent_id,
            payload: vec![byte],
        })
        .collect();

    AgentOutput { actions }
}

/// Trading agent that opens a position based on input parameters.
///
/// Demonstrates use of the SDK's action constructors.
#[allow(dead_code)]
fn trading_agent(ctx: &AgentContext) -> AgentOutput {
    // Need at least 41 bytes: asset_id (32) + notional (8) + direction (1)
    if ctx.opaque_inputs.len() < 41 {
        return AgentOutput { actions: vec![] };
    }

    // Parse inputs using SDK byte helpers
    let asset_id = match kernel_sdk::bytes::read_bytes32(ctx.opaque_inputs, 0) {
        Some(id) => id,
        None => return AgentOutput { actions: vec![] },
    };

    let notional = match kernel_sdk::bytes::read_u64_le(ctx.opaque_inputs, 32) {
        Some(n) => n,
        None => return AgentOutput { actions: vec![] },
    };

    let direction = match kernel_sdk::bytes::read_u8(ctx.opaque_inputs, 40) {
        Some(d) => d,
        None => return AgentOutput { actions: vec![] },
    };

    // Create open position action using SDK helper
    let action = open_position_action(
        *ctx.agent_id,  // target: self
        asset_id,
        notional,
        10_000,         // 1x leverage
        direction,
    );

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
    let agent_id = [0x42u8; 32];
    let code_hash = [0xaau8; 32];
    let constraint_hash = [0xbbu8; 32];
    let input_root = [0xccu8; 32];
    let inputs = [1u8, 2, 3, 4, 5];

    let ctx = AgentContext::new(
        1,
        1,
        &agent_id,
        &code_hash,
        &constraint_hash,
        &input_root,
        12345,
        &inputs,
    );

    let output = agent_main(&ctx);
    println!("Agent produced {} action(s)", output.actions.len());
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_context<'a>(
        agent_id: &'a [u8; 32],
        code_hash: &'a [u8; 32],
        constraint_hash: &'a [u8; 32],
        input_root: &'a [u8; 32],
        inputs: &'a [u8],
    ) -> AgentContext<'a> {
        AgentContext::new(
            1, // protocol_version
            1, // kernel_version
            agent_id,
            code_hash,
            constraint_hash,
            input_root,
            12345, // execution_nonce
            inputs,
        )
    }

    #[test]
    fn test_echo_agent_basic() {
        let agent_id = [0x42u8; 32];
        let code_hash = [0xaau8; 32];
        let constraint_hash = [0xbbu8; 32];
        let input_root = [0xccu8; 32];
        let inputs = [1u8, 2, 3, 4, 5];

        let ctx = make_test_context(
            &agent_id,
            &code_hash,
            &constraint_hash,
            &input_root,
            &inputs,
        );

        let output = agent_main(&ctx);

        assert_eq!(output.actions.len(), 1);
        assert_eq!(output.actions[0].action_type, ACTION_TYPE_ECHO);
        assert_eq!(output.actions[0].target, agent_id);
        assert_eq!(output.actions[0].payload, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_echo_agent_empty_input() {
        let agent_id = [0x42u8; 32];
        let code_hash = [0u8; 32];
        let constraint_hash = [0u8; 32];
        let input_root = [0u8; 32];
        let inputs: [u8; 0] = [];

        let ctx = make_test_context(
            &agent_id,
            &code_hash,
            &constraint_hash,
            &input_root,
            &inputs,
        );

        let output = agent_main(&ctx);

        assert_eq!(output.actions.len(), 1);
        assert_eq!(output.actions[0].payload.len(), 0);
    }

    #[test]
    fn test_noop_agent() {
        let agent_id = [0u8; 32];
        let code_hash = [0u8; 32];
        let constraint_hash = [0u8; 32];
        let input_root = [0u8; 32];
        let inputs = [1u8, 2, 3];

        let ctx = make_test_context(
            &agent_id,
            &code_hash,
            &constraint_hash,
            &input_root,
            &inputs,
        );

        let output = noop_agent(&ctx);
        assert_eq!(output.actions.len(), 0);
    }

    #[test]
    fn test_multi_echo_agent() {
        let agent_id = [0x42u8; 32];
        let code_hash = [0u8; 32];
        let constraint_hash = [0u8; 32];
        let input_root = [0u8; 32];
        let inputs = [1u8, 2, 3, 4, 5];

        let ctx = make_test_context(
            &agent_id,
            &code_hash,
            &constraint_hash,
            &input_root,
            &inputs,
        );

        let output = multi_echo_agent(&ctx);

        assert_eq!(output.actions.len(), 5);
        for (i, action) in output.actions.iter().enumerate() {
            assert_eq!(action.action_type, ACTION_TYPE_ECHO);
            assert_eq!(action.payload, vec![(i + 1) as u8]);
        }
    }

    #[test]
    fn test_trading_agent_valid_input() {
        let agent_id = [0x11u8; 32];
        let code_hash = [0u8; 32];
        let constraint_hash = [0u8; 32];
        let input_root = [0u8; 32];

        // Build input: asset_id (32) + notional (8) + direction (1)
        let mut inputs = Vec::with_capacity(41);
        inputs.extend_from_slice(&[0x42u8; 32]); // asset_id
        inputs.extend_from_slice(&1000u64.to_le_bytes()); // notional
        inputs.push(0); // direction = long

        let ctx = make_test_context(
            &agent_id,
            &code_hash,
            &constraint_hash,
            &input_root,
            &inputs,
        );

        let output = trading_agent(&ctx);

        assert_eq!(output.actions.len(), 1);
        assert_eq!(output.actions[0].action_type, ACTION_TYPE_OPEN_POSITION);
    }

    #[test]
    fn test_trading_agent_invalid_input() {
        let agent_id = [0x11u8; 32];
        let code_hash = [0u8; 32];
        let constraint_hash = [0u8; 32];
        let input_root = [0u8; 32];
        let inputs = [1u8, 2, 3]; // Too short

        let ctx = make_test_context(
            &agent_id,
            &code_hash,
            &constraint_hash,
            &input_root,
            &inputs,
        );

        let output = trading_agent(&ctx);
        assert_eq!(output.actions.len(), 0); // Graceful degradation
    }
}
