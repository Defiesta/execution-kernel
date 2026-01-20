use kernel_core::AgentOutput;

#[derive(Clone, Debug, PartialEq)]
pub enum ConstraintError {
    ViolatedConstraint,
    InvalidOutput,
}

#[derive(Clone, Debug)]
pub struct Meta {
    pub agent_id: [u8; 32],
}

pub fn check(_output: &AgentOutput, _meta: &Meta) -> Result<(), ConstraintError> {
    Ok(())
}