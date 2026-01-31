//! Wrapper crate binding example-yield-agent to kernel-guest.
//!
//! This crate implements [`kernel_guest::AgentEntrypoint`] for the example-yield-agent,
//! allowing it to be used with the agent-agnostic kernel execution functions.
//!
//! # Usage
//!
//! ```ignore
//! // In a zkVM guest main.rs or test:
//! let result = guest_wrapper_yield_agent::kernel_main(&input_bytes)?;
//! ```

use kernel_core::AgentOutput;
use kernel_guest::AgentEntrypoint;
use kernel_sdk::agent::AgentContext;

// Re-export the agent code hash for convenience.
pub use example_yield_agent::AGENT_CODE_HASH;

/// Wrapper implementing [`AgentEntrypoint`] for the example-yield-agent.
pub struct YieldAgentWrapper;

impl AgentEntrypoint for YieldAgentWrapper {
    fn code_hash(&self) -> [u8; 32] {
        example_yield_agent::AGENT_CODE_HASH
    }

    fn run(&self, ctx: &AgentContext, opaque_inputs: &[u8]) -> AgentOutput {
        example_yield_agent::agent_main(ctx, opaque_inputs)
    }
}

/// Convenience function for kernel execution with the yield-agent.
///
/// This is equivalent to calling:
/// ```ignore
/// kernel_guest::kernel_main_with_agent(input_bytes, &YieldAgentWrapper)
/// ```
pub fn kernel_main(input_bytes: &[u8]) -> Result<Vec<u8>, kernel_guest::KernelError> {
    kernel_guest::kernel_main_with_agent(input_bytes, &YieldAgentWrapper)
}

/// Convenience function for kernel execution with the yield-agent and custom constraints.
///
/// This is equivalent to calling:
/// ```ignore
/// kernel_guest::kernel_main_with_agent_and_constraints(input_bytes, &YieldAgentWrapper, constraint_set)
/// ```
pub fn kernel_main_with_constraints(
    input_bytes: &[u8],
    constraint_set: &constraints::ConstraintSetV1,
) -> Result<Vec<u8>, kernel_guest::KernelError> {
    kernel_guest::kernel_main_with_agent_and_constraints(
        input_bytes,
        &YieldAgentWrapper,
        constraint_set,
    )
}

// Re-export kernel_guest types for convenience.
pub use kernel_guest::KernelError;
