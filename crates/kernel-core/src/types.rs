/// Kernel input structure for P0.1 protocol.
///
/// Contains all consensus-critical fields needed to bind the proof to:
/// - The specific kernel semantics (kernel_version)
/// - The agent code being executed (agent_code_hash)
/// - The constraint policy enforced (constraint_set_hash)
/// - The external state observed (input_root)
/// - Replay protection (execution_nonce)
#[derive(Clone, Debug, PartialEq)]
pub struct KernelInputV1 {
    /// Protocol version for wire format compatibility
    pub protocol_version: u32,
    /// Kernel version declaring which semantics are being proven
    pub kernel_version: u32,
    /// 32-byte agent identifier
    pub agent_id: [u8; 32],
    /// SHA-256 hash of the agent binary/code
    pub agent_code_hash: [u8; 32],
    /// SHA-256 hash of the constraint set being enforced
    pub constraint_set_hash: [u8; 32],
    /// External state root (market/vault snapshot) the agent observes
    pub input_root: [u8; 32],
    /// Monotonic nonce for replay protection
    pub execution_nonce: u64,
    /// Opaque agent-specific input data (max 64KB)
    pub opaque_agent_inputs: Vec<u8>,
}

/// Kernel journal (output) structure for P0.1 protocol.
///
/// Contains all fields needed for on-chain verification:
/// - Identity fields (agent_id, agent_code_hash) for binding to strategy
/// - Constraint policy (constraint_set_hash) for proving policy enforcement
/// - Replay protection (execution_nonce) for ordering/dedup
/// - Cryptographic commitments for input/output verification
///
/// Journal size: 169 bytes fixed (4+4+32+32+32+32+8+32+32+1)
#[derive(Clone, Debug, PartialEq)]
pub struct KernelJournalV1 {
    /// Protocol version for wire format compatibility
    pub protocol_version: u32,
    /// Kernel version that produced this journal
    pub kernel_version: u32,
    /// Agent identifier (copied from input for verifier convenience)
    pub agent_id: [u8; 32],
    /// Agent code hash (proof binds to this specific agent)
    pub agent_code_hash: [u8; 32],
    /// Constraint set hash (proof binds to this policy)
    pub constraint_set_hash: [u8; 32],
    /// Input root (external state that was observed)
    pub input_root: [u8; 32],
    /// Execution nonce for replay protection
    pub execution_nonce: u64,
    /// SHA-256(full_input_bytes) - commits to entire input
    pub input_commitment: [u8; 32],
    /// SHA-256(agent_output_bytes) - commits to actions
    pub action_commitment: [u8; 32],
    /// Execution result status
    pub execution_status: ExecutionStatus,
}

/// Execution status enum.
///
/// Encoding: Success = 0x00
/// Any other value is invalid and must be rejected on decode.
///
/// For P0.1, only Success is defined. Failure cases abort before
/// journal commit, so no failure status is needed in the journal.
#[derive(Clone, Debug, PartialEq)]
pub enum ExecutionStatus {
    /// Execution completed successfully. Encoded as 0x00.
    Success,
}

/// Structured action format for agent output.
///
/// Each action has:
/// - action_type: 4-byte identifier for the action kind
/// - target: 32-byte target address/identifier
/// - payload: Variable-length action data (max 16KB per action)
///
/// Actions are ordered and the ordering is consensus-critical.
/// The kernel enforces deterministic ordering by requiring agents
/// to produce actions in their canonical order.
#[derive(Clone, Debug, PartialEq)]
pub struct ActionV1 {
    /// 4-byte action type identifier
    pub action_type: u32,
    /// 32-byte target address/identifier
    pub target: [u8; 32],
    /// Action-specific payload (max 16KB)
    pub payload: Vec<u8>,
}

/// Maximum payload size per action (16KB)
pub const MAX_ACTION_PAYLOAD_BYTES: usize = 16_384;

/// Maximum number of actions per output
pub const MAX_ACTIONS_PER_OUTPUT: usize = 64;

/// Structured agent output containing ordered actions.
///
/// Actions must be in canonical order as produced by the agent.
/// The action_commitment is computed over the encoded AgentOutput.
#[derive(Clone, Debug, PartialEq)]
pub struct AgentOutput {
    /// Ordered list of actions (max 64 actions)
    pub actions: Vec<ActionV1>,
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
    TooManyActions { count: u32, limit: usize },
    ActionPayloadTooLarge { size: u32, limit: usize },
}

/// Kernel-level execution errors.
///
/// Separate from CodecError to distinguish parsing failures from
/// execution failures. All errors result in kernel abort before
/// journal commit.
#[derive(Clone, Debug, PartialEq)]
pub enum KernelError {
    /// Input decoding failed
    Codec(CodecError),
    /// Protocol version not supported
    UnsupportedProtocolVersion { expected: u32, actual: u32 },
    /// Kernel version not supported
    UnsupportedKernelVersion { expected: u32, actual: u32 },
    /// Agent execution failed
    AgentExecutionFailed(AgentError),
    /// Constraint check failed
    ConstraintViolation(ConstraintError),
    /// Agent ID validation failed
    InvalidAgentId,
    /// Agent code hash mismatch
    AgentCodeHashMismatch,
}

/// Agent execution errors
#[derive(Clone, Debug, PartialEq)]
pub enum AgentError {
    /// Input data is invalid for this agent
    InvalidInput,
    /// Agent panicked or failed during execution
    ExecutionFailed,
    /// Output exceeds size limits
    OutputTooLarge,
    /// Too many actions produced
    TooManyActions,
}

/// Constraint checking errors
#[derive(Clone, Debug, PartialEq)]
pub enum ConstraintError {
    /// An action violated a constraint
    ViolatedConstraint { action_index: usize, reason: &'static str },
    /// Output structure is invalid
    InvalidOutput,
}

impl From<CodecError> for KernelError {
    fn from(e: CodecError) -> Self {
        KernelError::Codec(e)
    }
}
