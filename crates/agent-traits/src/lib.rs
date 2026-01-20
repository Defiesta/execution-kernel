use kernel_core::AgentOutput;

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
    fn run(_input_root: [u8; 32], inputs: &[u8]) -> Result<AgentOutput, AgentError> {
        if inputs.len() > 1000 {
            return Err(AgentError::OutputTooLarge);
        }
        
        Ok(AgentOutput {
            data: inputs.to_vec(),
        })
    }
}