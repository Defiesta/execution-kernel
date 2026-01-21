use kernel_core::*;
use agent_traits::{Agent, AgentContext, TrivialAgent};
use constraints::{check, validate_output_structure, ConstraintMeta};

/// Main kernel execution function.
///
/// This is the core execution logic that:
/// 1. Decodes and validates input
/// 2. Verifies protocol and kernel versions
/// 3. Computes input commitment
/// 4. Executes the agent
/// 5. Validates and checks constraints on output
/// 6. Computes action commitment
/// 7. Constructs and returns the journal
///
/// # Arguments
/// * `input_bytes` - Canonical encoding of KernelInputV1
///
/// # Returns
/// * `Ok(Vec<u8>)` - Canonical encoding of KernelJournalV1
/// * `Err(KernelError)` - Execution failed, no journal produced
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

    // 6. Validate output structure
    validate_output_structure(&agent_output)
        .map_err(KernelError::ConstraintViolation)?;

    // 7. Build constraint metadata
    let constraint_meta = ConstraintMeta {
        agent_id: input.agent_id,
        agent_code_hash: input.agent_code_hash,
        constraint_set_hash: input.constraint_set_hash,
        input_root: input.input_root,
        execution_nonce: input.execution_nonce,
    };

    // 8. Check constraints (MANDATORY)
    check(&agent_output, &constraint_meta)
        .map_err(KernelError::ConstraintViolation)?;

    // 9. Compute action commitment
    let agent_output_bytes = agent_output.encode();
    let action_commitment = compute_action_commitment(&agent_output_bytes);

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
        execution_status: ExecutionStatus::Success,
    };

    Ok(journal.encode())
}
