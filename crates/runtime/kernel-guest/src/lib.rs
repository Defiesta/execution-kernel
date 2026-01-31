//! Kernel Guest Execution Logic
//!
//! This crate implements the core kernel execution logic that runs inside
//! the zkVM guest. It provides agent-agnostic kernel execution functions
//! that accept injected agent implementations.
//!
//! # Execution Flow
//!
//! 1. Decode input bytes → `KernelInputV1`
//! 2. Validate protocol and kernel versions
//! 3. **Verify agent code hash matches injected agent** (P0.5)
//! 4. Compute input commitment (SHA256)
//! 5. Build `AgentContext` from kernel input
//! 6. Call agent via `AgentEntrypoint` trait
//! 7. Enforce constraints on agent output (UNSKIPPABLE)
//! 8. Compute action commitment (SHA256)
//! 9. Return encoded `KernelJournalV1`
//!
//! # Agent Injection
//!
//! Agents are injected via the [`AgentEntrypoint`] trait. Wrapper crates
//! implement this trait to bind specific agents to the kernel without
//! requiring kernel-guest to have dependencies on individual agent crates.
//!
//! # Agent Code Hash Binding (P0.5)
//!
//! The kernel verifies that `KernelInputV1.agent_code_hash` matches the
//! hash returned by [`AgentEntrypoint::code_hash()`]. This binding ensures:
//!
//! - Proofs are tied to the specific agent implementation that ran
//! - Malicious agent substitution is detected and rejected
//! - Verifiers can trust that the claimed agent actually executed
//!
//! If the hash doesn't match, `KernelError::AgentCodeHashMismatch` is returned.

use constraints::{enforce_constraints, ConstraintSetV1, EMPTY_OUTPUT_COMMITMENT};
use kernel_core::*;
use kernel_sdk::agent::AgentContext;

// Re-export KernelError for wrapper crates to use.
pub use kernel_core::KernelError;

// ============================================================================
// Agent Entrypoint Trait
// ============================================================================

/// Trait for injecting agent implementations into the kernel.
///
/// Wrapper crates implement this trait to bind a specific agent to the kernel
/// without requiring kernel-guest to have compile-time dependencies on
/// individual agent crates.
///
/// # Example
///
/// ```ignore
/// use kernel_guest::AgentEntrypoint;
/// use kernel_sdk::agent::AgentContext;
/// use kernel_core::AgentOutput;
///
/// pub struct MyAgentWrapper;
///
/// impl AgentEntrypoint for MyAgentWrapper {
///     fn code_hash(&self) -> [u8; 32] {
///         my_agent::AGENT_CODE_HASH
///     }
///
///     fn run(&self, ctx: &AgentContext, opaque_inputs: &[u8]) -> AgentOutput {
///         my_agent::agent_main(ctx, opaque_inputs)
///     }
/// }
/// ```
pub trait AgentEntrypoint {
    /// Returns the agent's code hash (computed at build time).
    ///
    /// This hash uniquely identifies the agent implementation and is
    /// verified against `KernelInputV1.agent_code_hash` to ensure the
    /// proof is bound to the correct agent code.
    fn code_hash(&self) -> [u8; 32];

    /// Executes the agent logic.
    ///
    /// # Arguments
    ///
    /// * `ctx` - Execution context with identity and metadata
    /// * `opaque_inputs` - Agent-specific input data (max 64,000 bytes)
    ///
    /// # Returns
    ///
    /// `AgentOutput` containing ordered actions to be executed.
    fn run(&self, ctx: &AgentContext, opaque_inputs: &[u8]) -> AgentOutput;
}

// ============================================================================
// Agent-Injected Kernel Execution (Primary API)
// ============================================================================

/// Execute kernel with an injected agent implementation.
///
/// This is the primary API for kernel execution. The agent is provided via
/// the [`AgentEntrypoint`] trait, allowing the kernel to be agent-agnostic.
///
/// # Agent Code Hash Binding (P0.5)
///
/// Step 3 verifies that `KernelInputV1.agent_code_hash` matches
/// `agent.code_hash()`. This ensures proofs are cryptographically bound
/// to the specific agent code that executed.
///
/// # Constraint Enforcement (P0.3)
///
/// Constraints are ALWAYS enforced after agent execution. If any constraint
/// is violated:
/// - `execution_status` is set to `Failure` (0x02)
/// - `action_commitment` is computed over an empty `AgentOutput`
/// - A valid journal is still produced
///
/// # Arguments
///
/// * `input_bytes` - Canonical encoding of KernelInputV1
/// * `agent` - Agent implementation (provides code hash and execution logic)
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - Canonical encoding of KernelJournalV1 (always produced)
/// * `Err(KernelError)` - Critical failure (decoding, version mismatch, hash mismatch)
///
/// # Determinism
///
/// This function is fully deterministic. Same input bytes and agent will
/// always produce the same output bytes.
pub fn kernel_main_with_agent(
    input_bytes: &[u8],
    agent: &dyn AgentEntrypoint,
) -> Result<Vec<u8>, KernelError> {
    kernel_main_with_agent_and_constraints(input_bytes, agent, &ConstraintSetV1::default())
}

/// Execute kernel with an injected agent and custom constraint set.
///
/// This variant allows specifying a custom constraint set instead of
/// using the default. Useful for testing and specialized deployments.
///
/// # Arguments
///
/// * `input_bytes` - Canonical encoding of KernelInputV1
/// * `agent` - Agent implementation (provides code hash and execution logic)
/// * `constraint_set` - Custom constraint set to enforce
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - Canonical encoding of KernelJournalV1 (always produced)
/// * `Err(KernelError)` - Critical failure (decoding, version mismatch, hash mismatch)
pub fn kernel_main_with_agent_and_constraints(
    input_bytes: &[u8],
    agent: &dyn AgentEntrypoint,
    constraint_set: &ConstraintSetV1,
) -> Result<Vec<u8>, KernelError> {
    // 1. Decode input
    let input = KernelInputV1::decode(input_bytes)?;

    // 2. Validate versions (already checked in decode, but be explicit)
    if input.protocol_version != PROTOCOL_VERSION {
        return Err(KernelError::UnsupportedProtocolVersion {
            expected: PROTOCOL_VERSION,
            actual: input.protocol_version,
        });
    }

    if input.kernel_version != KERNEL_VERSION {
        return Err(KernelError::UnsupportedKernelVersion {
            expected: KERNEL_VERSION,
            actual: input.kernel_version,
        });
    }

    // 3. Verify agent code hash matches injected agent (P0.5 binding)
    //
    // This check ensures that the agent_code_hash declared in the input
    // matches the actual agent implementation. Without this, a malicious
    // prover could claim they ran agent X but actually run agent Y.
    if input.agent_code_hash != agent.code_hash() {
        return Err(KernelError::AgentCodeHashMismatch);
    }

    // 4. Compute input commitment (over full input bytes)
    let input_commitment = compute_input_commitment(input_bytes);

    // 5. Build agent context from input (using kernel-sdk AgentContext)
    let agent_ctx = AgentContext::new(
        input.protocol_version,
        input.kernel_version,
        input.agent_id,
        input.agent_code_hash,
        input.constraint_set_hash,
        input.input_root,
        input.execution_nonce,
    );

    // 6. Execute agent via injected implementation
    let agent_output = agent.run(&agent_ctx, &input.opaque_agent_inputs);

    // 7. ENFORCE CONSTRAINTS (UNSKIPPABLE)
    // This is the critical safety check that validates all agent actions.
    let (validated_output, execution_status) =
        match enforce_constraints(&input, &agent_output, constraint_set) {
            Ok(validated) => {
                // Constraints passed - use validated output
                (validated, ExecutionStatus::Success)
            }
            Err(_violation) => {
                // Constraints violated - use empty output and Failure status
                // The violation details are not included in the journal for P0.3
                // but could be logged or added in future versions.
                (AgentOutput { actions: vec![] }, ExecutionStatus::Failure)
            }
        };

    // 8. Compute action commitment
    // On Success: computed over validated output
    // On Failure: computed over empty output (deterministic constant)
    let action_commitment = if execution_status == ExecutionStatus::Success {
        let output_bytes = validated_output
            .encode()
            .map_err(KernelError::EncodingFailed)?;
        compute_action_commitment(&output_bytes)
    } else {
        // Use pre-computed constant for empty output commitment
        EMPTY_OUTPUT_COMMITMENT
    };

    // 9. Construct journal with all identity and commitment fields
    let journal = KernelJournalV1 {
        protocol_version: PROTOCOL_VERSION,
        kernel_version: KERNEL_VERSION,
        agent_id: input.agent_id,
        agent_code_hash: input.agent_code_hash,
        constraint_set_hash: input.constraint_set_hash,
        input_root: input.input_root,
        execution_nonce: input.execution_nonce,
        input_commitment,
        action_commitment,
        execution_status,
    };

    // 10. Encode and return journal (always produced)
    journal.encode().map_err(KernelError::EncodingFailed)
}
