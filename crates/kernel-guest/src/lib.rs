use kernel_core::*;
use agent_traits::{Agent, AgentContext, TrivialAgent};
use constraints::{enforce_constraints, ConstraintSetV1, EMPTY_OUTPUT_COMMITMENT};

/// Main kernel execution function.
///
/// This is the core execution logic that:
/// 1. Decodes and validates input
/// 2. Verifies protocol and kernel versions
/// 3. Computes input commitment
/// 4. Executes the agent
/// 5. Enforces constraints on agent output (UNSKIPPABLE)
/// 6. Computes action commitment
/// 7. Constructs and returns the journal
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

    // 3. Compute input commitment (over full input bytes)
    let input_commitment = compute_input_commitment(input_bytes);

    // 4. Build agent context from input
    let agent_ctx = AgentContext {
        agent_id: input.agent_id,
        agent_code_hash: input.agent_code_hash,
        constraint_set_hash: input.constraint_set_hash,
        input_root: input.input_root,
        execution_nonce: input.execution_nonce,
    };

    // 5. Execute agent
    let agent_output = TrivialAgent::run(&agent_ctx, &input.opaque_agent_inputs)
        .map_err(KernelError::AgentExecutionFailed)?;

    // 6. Get constraint set (P0.3: use default permissive constraints)
    let constraint_set = ConstraintSetV1::default();

    // 7. ENFORCE CONSTRAINTS (UNSKIPPABLE)
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

    // 3. Compute input commitment
    let input_commitment = compute_input_commitment(input_bytes);

    // 4. Build agent context
    let agent_ctx = AgentContext {
        agent_id: input.agent_id,
        agent_code_hash: input.agent_code_hash,
        constraint_set_hash: input.constraint_set_hash,
        input_root: input.input_root,
        execution_nonce: input.execution_nonce,
    };

    // 5. Execute agent
    let agent_output = TrivialAgent::run(&agent_ctx, &input.opaque_agent_inputs)
        .map_err(KernelError::AgentExecutionFailed)?;

    // 6. ENFORCE CONSTRAINTS (UNSKIPPABLE)
    let (validated_output, execution_status) =
        match enforce_constraints(&input, &agent_output, constraint_set) {
            Ok(validated) => (validated, ExecutionStatus::Success),
            Err(_violation) => (AgentOutput { actions: vec![] }, ExecutionStatus::Failure),
        };

    // 7. Compute action commitment
    let action_commitment = if execution_status == ExecutionStatus::Success {
        let output_bytes = validated_output
            .encode()
            .map_err(KernelError::EncodingFailed)?;
        compute_action_commitment(&output_bytes)
    } else {
        EMPTY_OUTPUT_COMMITMENT
    };

    // 8. Construct and return journal
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
