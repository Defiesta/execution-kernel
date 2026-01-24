//! Agent ABI Definitions and Reference Implementations
//!
//! This crate provides the canonical agent interface types and reference
//! implementations for testing.
//!
//! # Canonical Types (from kernel-sdk)
//!
//! - [`AgentContext`] - Execution context provided to agents
//! - [`AgentEntrypoint`] - Type alias for the canonical agent_main signature
//! - [`AgentOutput`] - Structured output containing ordered actions
//!
//! # Entrypoint Symbol
//!
//! The canonical entrypoint symbol name is defined by [`AGENT_ENTRYPOINT_SYMBOL`].
//! All agents must expose exactly this function:
//!
//! ```ignore
//! #[no_mangle]
//! pub extern "Rust" fn agent_main(ctx: &AgentContext, opaque_inputs: &[u8]) -> AgentOutput
//! ```
//!
//! # Reference Agents (feature: `reference-agents`)
//!
//! When the `reference-agents` feature is enabled (default), the following
//! test implementations are available:
//!
//! - [`TrivialAgent`] - Echoes input as a single action
//! - [`NoOpAgent`] - Produces no actions
//! - [`MultiActionAgent`] - Produces multiple actions for testing
//!
//! These are NOT production-ready and exist only for testing.

// Re-export canonical types from kernel-sdk
pub use kernel_sdk::agent::{AgentContext, AgentEntrypoint};
pub use kernel_sdk::types::AgentOutput;

/// Canonical entrypoint symbol name.
///
/// All agents must export a function with this exact symbol name.
/// The kernel uses this symbol to locate the agent entrypoint.
pub const AGENT_ENTRYPOINT_SYMBOL: &str = "agent_main";

// ============================================================================
// Legacy Types (for backward compatibility during transition)
// ============================================================================

use kernel_core::{ActionV1, AgentError, MAX_ACTIONS_PER_OUTPUT};

/// Legacy agent context (owned fields).
///
/// **DEPRECATED**: Use [`AgentContext`] from kernel-sdk instead.
/// This type is kept for backward compatibility during the transition
/// to the canonical `agent_main` entrypoint.
#[deprecated(
    since = "0.2.0",
    note = "Use kernel_sdk::agent::AgentContext instead"
)]
#[derive(Clone, Debug)]
pub struct LegacyAgentContext {
    /// 32-byte agent identifier
    pub agent_id: [u8; 32],
    /// SHA-256 hash of the agent's own code
    pub agent_code_hash: [u8; 32],
    /// SHA-256 hash of the constraint set being enforced
    pub constraint_set_hash: [u8; 32],
    /// External state root (market/vault snapshot)
    pub input_root: [u8; 32],
    /// Execution nonce for replay protection
    pub execution_nonce: u64,
}

/// Legacy agent trait interface.
///
/// **DEPRECATED**: Implement `agent_main` function directly instead.
/// This trait is kept for backward compatibility during the transition.
#[deprecated(
    since = "0.2.0",
    note = "Implement extern \"Rust\" fn agent_main(ctx: &AgentContext, opaque_inputs: &[u8]) -> AgentOutput instead"
)]
pub trait Agent {
    /// Execute the agent with the given context and inputs.
    fn run(ctx: &LegacyAgentContext, inputs: &[u8]) -> Result<kernel_core::AgentOutput, AgentError>;
}

// ============================================================================
// Reference Agent Implementations (behind feature flag)
// ============================================================================

#[cfg(feature = "reference-agents")]
mod reference_agents {
    use super::*;

    /// Action type for echo action (used by TrivialAgent)
    pub const ACTION_TYPE_ECHO: u32 = 0x00000001;

    /// Trivial reference agent implementation.
    ///
    /// WARNING: This is NOT production-ready and exists only for testing.
    /// It converts input bytes into a single "echo" action.
    pub struct TrivialAgent;

    #[allow(deprecated)]
    impl Agent for TrivialAgent {
        /// Converts input into a single echo action.
        ///
        /// The action targets the agent's own ID and carries
        /// the input as payload (truncated to max payload size).
        fn run(ctx: &LegacyAgentContext, inputs: &[u8]) -> Result<kernel_core::AgentOutput, AgentError> {
            // Truncate to max payload size if needed
            let payload_len = inputs.len().min(kernel_core::MAX_ACTION_PAYLOAD_BYTES);
            let payload = inputs[..payload_len].to_vec();

            let action = ActionV1 {
                action_type: ACTION_TYPE_ECHO,
                target: ctx.agent_id,
                payload,
            };

            Ok(kernel_core::AgentOutput {
                actions: vec![action],
            })
        }
    }

    /// No-op agent that produces no actions.
    ///
    /// Useful for testing constraint enforcement with empty output.
    pub struct NoOpAgent;

    #[allow(deprecated)]
    impl Agent for NoOpAgent {
        fn run(_ctx: &LegacyAgentContext, _inputs: &[u8]) -> Result<kernel_core::AgentOutput, AgentError> {
            Ok(kernel_core::AgentOutput { actions: vec![] })
        }
    }

    /// Agent that produces multiple actions for testing.
    pub struct MultiActionAgent;

    #[allow(deprecated)]
    impl Agent for MultiActionAgent {
        /// Produces one action per byte of input (up to MAX_ACTIONS_PER_OUTPUT).
        fn run(ctx: &LegacyAgentContext, inputs: &[u8]) -> Result<kernel_core::AgentOutput, AgentError> {
            let action_count = inputs.len().min(MAX_ACTIONS_PER_OUTPUT);

            let actions: Vec<ActionV1> = inputs[..action_count]
                .iter()
                .enumerate()
                .map(|(i, &byte)| ActionV1 {
                    action_type: i as u32,
                    target: ctx.agent_id,
                    payload: vec![byte],
                })
                .collect();

            Ok(kernel_core::AgentOutput { actions })
        }
    }
}

#[cfg(feature = "reference-agents")]
pub use reference_agents::*;
