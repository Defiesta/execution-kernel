use kernel_core::{AgentOutput, ConstraintError};

/// Metadata for constraint checking.
///
/// Contains context information needed to evaluate constraints
/// against the agent's output.
#[derive(Clone, Debug)]
pub struct ConstraintMeta {
    /// 32-byte agent identifier
    pub agent_id: [u8; 32],
    /// SHA-256 hash of the agent code
    pub agent_code_hash: [u8; 32],
    /// SHA-256 hash of the constraint set being enforced
    pub constraint_set_hash: [u8; 32],
    /// External state root that was observed
    pub input_root: [u8; 32],
    /// Execution nonce
    pub execution_nonce: u64,
}

/// Check agent output against constraint set.
///
/// This function is MANDATORY - the kernel MUST call it and
/// MUST abort if it returns an error.
///
/// # P0.1 Implementation
///
/// For P0.1, this is a stub that always returns Ok(()).
/// Full constraint enforcement will be implemented in P0.2+.
///
/// # Future Implementation
///
/// Will validate:
/// - Action types are allowed for this agent
/// - Targets are within permitted scope
/// - Payload values are within bounds
/// - Total value/risk is within limits
/// - Rate limits are respected
///
/// # Arguments
/// * `output` - The agent's structured output
/// * `meta` - Constraint checking metadata
///
/// # Returns
/// * `Ok(())` - All constraints satisfied
/// * `Err(ConstraintError)` - A constraint was violated
pub fn check(_output: &AgentOutput, _meta: &ConstraintMeta) -> Result<(), ConstraintError> {
    // P0.1: Stub implementation - always passes
    // P0.2+: Will implement actual constraint checking
    Ok(())
}

/// Validate that output is well-formed before constraint checking.
///
/// Ensures basic structural validity:
/// - Action count within limits
/// - Payload sizes within limits
/// - Required fields present
pub fn validate_output_structure(output: &AgentOutput) -> Result<(), ConstraintError> {
    use kernel_core::{MAX_ACTIONS_PER_OUTPUT, MAX_ACTION_PAYLOAD_BYTES};

    if output.actions.len() > MAX_ACTIONS_PER_OUTPUT {
        return Err(ConstraintError::InvalidOutput);
    }

    for action in &output.actions {
        if action.payload.len() > MAX_ACTION_PAYLOAD_BYTES {
            return Err(ConstraintError::InvalidOutput);
        }
    }

    Ok(())
}
