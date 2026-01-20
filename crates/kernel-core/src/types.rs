#[derive(Clone, Debug, PartialEq)]
pub struct KernelInputV1 {
    pub protocol_version: u32,
    pub agent_id: [u8; 32],
    pub agent_input: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct KernelJournalV1 {
    pub protocol_version: u32,
    pub kernel_version: u32,
    pub input_commitment: [u8; 32],
    pub action_commitment: [u8; 32],
    pub execution_status: ExecutionStatus,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ExecutionStatus {
    Success,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AgentOutput {
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum CodecError {
    InvalidLength,
    InvalidVersion { expected: u32, actual: u32 },
    InputTooLarge { size: u32, limit: usize },
    OutputTooLarge { size: u32, limit: usize },
    UnexpectedEndOfInput,
    InvalidExecutionStatus(u8),
    ArithmeticOverflow,
}