use thiserror::Error;

#[derive(Error, Debug)]
pub enum KernelError {
    #[error("Constraint violation: {0}")]
    ConstraintViolation(String),
    
    #[error("Agent execution failed: {0}")]
    AgentExecutionFailed(String),
    
    #[error("Invalid vault state: {0}")]
    InvalidVaultState(String),
    
    #[error("Invalid market state: {0}")]
    InvalidMarketState(String),
    
    #[error("Resource limit exceeded: {0}")]
    ResourceLimitExceeded(String),
    
    #[error("Invalid agent action: {0}")]
    InvalidAction(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    #[error("Unknown agent hash: {0:?}")]
    UnknownAgent([u8; 32]),
}

pub type Result<T> = std::result::Result<T, KernelError>;