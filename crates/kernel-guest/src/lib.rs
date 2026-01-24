//! Kernel Guest Execution Logic
//!
//! This crate implements the core kernel execution logic that runs inside
//! the zkVM guest. It orchestrates agent execution through the canonical
//! `agent_main` entrypoint.
//!
//! # Execution Flow
//!
//! 1. Decode input bytes → `KernelInputV1`
//! 2. Validate protocol and kernel versions
//! 3. **Verify agent code hash matches linked agent** (P0.5)
//! 4. Compute input commitment (SHA256)
//! 5. Build `AgentContext` from kernel input
//! 6. Call `agent_main` via `extern "Rust"` ABI
//! 7. Enforce constraints on agent output (UNSKIPPABLE)
//! 8. Compute action commitment (SHA256)
//! 9. Return encoded `KernelJournalV1`
//!
//! # Agent Entrypoint
//!
//! The agent is invoked through an `extern "Rust"` function with the symbol
//! `agent_main`. This function is linked at compile time (for static
//! agents like `example-agent`) or at load time (for dynamic agents).
//!
//! # Agent Code Hash Binding (P0.5)
//!
//! When the `example-agent` feature is enabled, the kernel verifies that
//! `KernelInputV1.agent_code_hash` matches the hash of the linked agent
//! (`example_agent::AGENT_CODE_HASH`). This binding ensures:
//!
//! - Proofs are tied to the specific agent implementation that ran
//! - Malicious agent substitution is detected and rejected
//! - Verifiers can trust that the claimed agent actually executed
//!
//! If the hash doesn't match, `KernelError::AgentCodeHashMismatch` is returned.

use kernel_core::*;
use kernel_sdk::agent::AgentContext;
use constraints::{enforce_constraints, ConstraintSetV1, EMPTY_OUTPUT_COMMITMENT};

// Import the agent code hash when example-agent feature is enabled.
// This constant is generated at build time by example-agent's build.rs.
#[cfg(feature = "example-agent")]
use example_agent::AGENT_CODE_HASH as LINKED_AGENT_CODE_HASH;

// ============================================================================
// Agent Entrypoint Declaration
// ============================================================================

// The agent_main function is provided by the linked agent crate.
// For example, when the `example-agent` feature is enabled, the
// example_agent::agent_main function is linked.
//
// Using `extern "Rust"` is safe for Rust types like &AgentContext and
// AgentOutput (which contains Vec). This avoids the ABI-safety issues
// that would arise with `extern "C"`.
//
// IMPORTANT: `extern "Rust"` requires the agent and kernel to be compiled
// with the same rustc toolchain. The workspace pins the toolchain via
// rust-toolchain.toml to ensure deterministic builds and ABI compatibility.
extern "Rust" {
    fn agent_main(ctx: &AgentContext, opaque_inputs: &[u8]) -> AgentOutput;
}

/// Safe wrapper for calling the agent entrypoint.
#[inline]
fn call_agent(ctx: &AgentContext, opaque_inputs: &[u8]) -> AgentOutput {
    // Safe: extern "Rust" guarantees correct ABI for Rust types
    unsafe { agent_main(ctx, opaque_inputs) }
}

// ============================================================================
// Main Kernel Execution
// ============================================================================

/// Main kernel execution function.
///
/// This is the core execution logic that:
/// 1. Decodes and validates input
/// 2. Verifies protocol and kernel versions
/// 3. Verifies agent code hash matches linked agent (P0.5)
/// 4. Computes input commitment
/// 5. Executes the agent via `agent_main`
/// 6. Enforces constraints on agent output (UNSKIPPABLE)
/// 7. Computes action commitment
/// 8. Constructs and returns the journal
///
/// # P0.5 Agent Code Hash Binding
///
/// When the `example-agent` feature is enabled, step 3 verifies that
/// `KernelInputV1.agent_code_hash` matches the compile-time constant
/// `LINKED_AGENT_CODE_HASH` from the linked agent crate. This ensures
/// proofs are cryptographically bound to specific agent code.
///
/// # P0.3 Constraint Enforcement
///
/// Constraints are ALWAYS enforced after agent execution. If any constraint
/// is violated:
/// - `execution_status` is set to `Failure` (0x02)
/// - `action_commitment` is computed over an empty `AgentOutput`
/// - A valid journal is still produced
///
/// This ensures constraint violations are provable and verifiable on-chain.
///
/// # Arguments
/// * `input_bytes` - Canonical encoding of KernelInputV1
///
/// # Returns
/// * `Ok(Vec<u8>)` - Canonical encoding of KernelJournalV1 (always produced)
/// * `Err(KernelError)` - Critical failure (decoding, version mismatch)
///
/// # Determinism
///
/// This function is fully deterministic. Same input bytes will
/// always produce the same output bytes across:
/// - Different machines
/// - Different provers
/// - Rebuilds with pinned toolchain
pub fn kernel_main(input_bytes: &[u8]) -> Result<Vec<u8>, KernelError> {
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

    // 3. Verify agent code hash matches linked agent (P0.5 binding)
    //
    // This check ensures that the agent_code_hash declared in the input
    // matches the actual agent linked into this guest binary. Without this,
    // a malicious prover could claim they ran agent X but actually run agent Y.
    //
    // When example-agent feature is enabled, we compare against the
    // compile-time constant LINKED_AGENT_CODE_HASH from example_agent crate.
    // When the feature is disabled, there is no linked agent to verify.
    #[cfg(feature = "example-agent")]
    {
        if input.agent_code_hash != LINKED_AGENT_CODE_HASH {
            return Err(KernelError::AgentCodeHashMismatch);
        }
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

    // 6. Execute agent via canonical agent_main entrypoint
    let agent_output = call_agent(&agent_ctx, &input.opaque_agent_inputs);

    // 7. Get constraint set (P0.3: use default permissive constraints)
    let constraint_set = ConstraintSetV1::default();

    // 8. ENFORCE CONSTRAINTS (UNSKIPPABLE)
    // This is the critical safety check that validates all agent actions.
    let (validated_output, execution_status) =
        match enforce_constraints(&input, &agent_output, &constraint_set) {
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

    // 9. Compute action commitment
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

    // 10. Construct journal with all identity and commitment fields
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

/// Execute kernel with custom constraint set.
///
/// This variant allows specifying a custom constraint set instead of
/// using the default. Useful for testing and specialized deployments.
pub fn kernel_main_with_constraints(
    input_bytes: &[u8],
    constraint_set: &ConstraintSetV1,
) -> Result<Vec<u8>, KernelError> {
    // 1. Decode input
    let input = KernelInputV1::decode(input_bytes)?;

    // 2. Validate versions
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

    // 3. Verify agent code hash matches linked agent (P0.5 binding)
    #[cfg(feature = "example-agent")]
    {
        if input.agent_code_hash != LINKED_AGENT_CODE_HASH {
            return Err(KernelError::AgentCodeHashMismatch);
        }
    }

    // 4. Compute input commitment
    let input_commitment = compute_input_commitment(input_bytes);

    // 5. Build agent context (using kernel-sdk AgentContext)
    let agent_ctx = AgentContext::new(
        input.protocol_version,
        input.kernel_version,
        input.agent_id,
        input.agent_code_hash,
        input.constraint_set_hash,
        input.input_root,
        input.execution_nonce,
    );

    // 6. Execute agent via canonical agent_main entrypoint
    let agent_output = call_agent(&agent_ctx, &input.opaque_agent_inputs);

    // 7. ENFORCE CONSTRAINTS (UNSKIPPABLE)
    let (validated_output, execution_status) =
        match enforce_constraints(&input, &agent_output, constraint_set) {
            Ok(validated) => (validated, ExecutionStatus::Success),
            Err(_violation) => (AgentOutput { actions: vec![] }, ExecutionStatus::Failure),
        };

    // 8. Compute action commitment
    let action_commitment = if execution_status == ExecutionStatus::Success {
        let output_bytes = validated_output
            .encode()
            .map_err(KernelError::EncodingFailed)?;
        compute_action_commitment(&output_bytes)
    } else {
        EMPTY_OUTPUT_COMMITMENT
    };

    // 9. Construct and return journal
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

    journal.encode().map_err(KernelError::EncodingFailed)
}
