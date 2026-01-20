use kernel_core::{AgentOutput, MAX_AGENT_OUTPUT_BYTES};

#[derive(Clone, Debug, PartialEq)]
pub enum AgentError {
    InvalidInput,
    ExecutionFailed,
    OutputTooLarge,
}

pub trait Agent {
    fn run(input_root: [u8; 32], inputs: &[u8]) -> Result<AgentOutput, AgentError>;
}

pub struct TrivialAgent;

impl Agent for TrivialAgent {
    /// WARNING: TrivialAgent is NOT production-ready and should only be used for testing.
    /// It simply echoes input as output without any validation or processing.
    fn run(_input_root: [u8; 32], inputs: &[u8]) -> Result<AgentOutput, AgentError> {
        if inputs.len() > MAX_AGENT_OUTPUT_BYTES {
            return Err(AgentError::OutputTooLarge);
        }
        
        // Pre-allocate with known size for efficiency
        let mut data = Vec::with_capacity(inputs.len());
        data.extend_from_slice(inputs);
        
        Ok(AgentOutput { data })
    }
}