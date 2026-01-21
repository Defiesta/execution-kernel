use kernel_core::{AgentOutput, ActionV1, AgentError, MAX_ACTIONS_PER_OUTPUT};

/// Context provided to agents during execution.
///
/// Contains all identity and state information the agent needs
/// to make decisions and produce actions.
#[derive(Clone, Debug)]
pub struct AgentContext {
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

/// Canonical agent interface.
///
/// All agents must implement this trait. The kernel calls `run()`
/// with the execution context and opaque inputs, and expects
/// a structured `AgentOutput` containing ordered actions.
///
/// # Determinism Requirements
///
/// Implementations MUST be fully deterministic:
/// - No randomness or time dependencies
/// - No floating-point operations
/// - No unordered iteration
/// - Bounded loops and memory usage
pub trait Agent {
    /// Execute the agent with the given context and inputs.
    ///
    /// # Arguments
    /// * `ctx` - Execution context with identity and state information
    /// * `inputs` - Opaque agent-specific input data
    ///
    /// # Returns
    /// * `Ok(AgentOutput)` - Structured output containing ordered actions
    /// * `Err(AgentError)` - Execution failed, kernel will abort
    fn run(ctx: &AgentContext, inputs: &[u8]) -> Result<AgentOutput, AgentError>;
}

/// Trivial reference agent implementation.
///
/// WARNING: This is NOT production-ready and exists only for testing.
/// It converts input bytes into a single "echo" action.
pub struct TrivialAgent;

/// Action type for echo action (used by TrivialAgent)
pub const ACTION_TYPE_ECHO: u32 = 0x00000001;

impl Agent for TrivialAgent {
    /// Converts input into a single echo action.
    ///
    /// The action targets the agent's own ID and carries
    /// the input as payload (truncated to max payload size).
    fn run(ctx: &AgentContext, inputs: &[u8]) -> Result<AgentOutput, AgentError> {
        // Truncate to max payload size if needed
        let payload_len = inputs.len().min(kernel_core::MAX_ACTION_PAYLOAD_BYTES);
        let payload = inputs[..payload_len].to_vec();

        let action = ActionV1 {
            action_type: ACTION_TYPE_ECHO,
            target: ctx.agent_id,
            payload,
        };

        Ok(AgentOutput {
            actions: vec![action],
        })
    }
}

/// No-op agent that produces no actions.
///
/// Useful for testing constraint enforcement with empty output.
pub struct NoOpAgent;

impl Agent for NoOpAgent {
    fn run(_ctx: &AgentContext, _inputs: &[u8]) -> Result<AgentOutput, AgentError> {
        Ok(AgentOutput { actions: vec![] })
    }
}

/// Agent that produces multiple actions for testing.
pub struct MultiActionAgent;

impl Agent for MultiActionAgent {
    /// Produces one action per byte of input (up to MAX_ACTIONS_PER_OUTPUT).
    fn run(ctx: &AgentContext, inputs: &[u8]) -> Result<AgentOutput, AgentError> {
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

        Ok(AgentOutput { actions })
    }
}
