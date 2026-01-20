use kernel_core::*;
use agent_traits::{Agent, TrivialAgent};
use constraints::{check, Meta};

#[derive(Clone, Debug, PartialEq)]
pub enum KernelError {
    CodecError(CodecError),
    InvalidProtocolVersion,
    InvalidKernelVersion,
    AgentExecutionFailed,
    ConstraintViolation,
}

impl From<CodecError> for KernelError {
    fn from(error: CodecError) -> Self {
        KernelError::CodecError(error)
    }
}

pub fn kernel_main(input_bytes: &[u8]) -> Result<Vec<u8>, KernelError> {
    let input = KernelInputV1::decode(input_bytes)?;
    
    if input.protocol_version != PROTOCOL_VERSION {
        return Err(KernelError::InvalidProtocolVersion);
    }
    
    let input_commitment = compute_input_commitment(input_bytes);
    
    let agent_output = TrivialAgent::run([0u8; 32], &input.agent_input)
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