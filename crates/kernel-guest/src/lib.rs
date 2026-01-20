use kernel_core::*;
use agent_traits::{Agent, TrivialAgent};
use constraints::{check, Meta};

#[derive(Clone, Debug, PartialEq)]
pub enum KernelError {
    InvalidInput(CodecError),
    UnsupportedProtocolVersion(u32),
    UnsupportedKernelVersion(u32),
    InputTooLarge(usize),
    AgentExecutionFailed,
    ConstraintViolation,
    InvalidAgentOutput,
}

impl From<CodecError> for KernelError {
    fn from(error: CodecError) -> Self {
        match error {
            CodecError::InputTooLarge => KernelError::InputTooLarge(MAX_AGENT_INPUT_BYTES),
            other => KernelError::InvalidInput(other),
        }
    }
}

pub fn kernel_main(input_bytes: &[u8]) -> Result<Vec<u8>, KernelError> {
    let input = KernelInputV1::decode(input_bytes)?;
    
    if input.protocol_version != PROTOCOL_VERSION {
        return Err(KernelError::UnsupportedProtocolVersion(input.protocol_version));
    }
    
    let input_commitment = compute_input_commitment(input_bytes);
    
    let agent_output = TrivialAgent::run(input.agent_id, &input.agent_input)
        .map_err(|_| KernelError::AgentExecutionFailed)?;
    
    
    let meta = Meta {
        agent_id: input.agent_id,
    };
    
    check(&agent_output, &meta)
        .map_err(|_| KernelError::ConstraintViolation)?;
    
    let agent_output_bytes = agent_output.encode();
    let action_commitment = compute_action_commitment(&agent_output_bytes);
    
    let journal = KernelJournalV1 {
        protocol_version: PROTOCOL_VERSION,
        kernel_version: KERNEL_VERSION,
        input_commitment,
        action_commitment,
        execution_status: ExecutionStatus::Success,
    };
    
    Ok(journal.encode())
}