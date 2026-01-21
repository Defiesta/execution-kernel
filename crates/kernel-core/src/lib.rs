pub mod types;
pub mod codec;
pub mod hash;

pub use types::*;
pub use codec::*;
pub use hash::*;

/// Protocol version for wire format compatibility
pub const PROTOCOL_VERSION: u32 = 1;

/// Kernel version declaring execution semantics
pub const KERNEL_VERSION: u32 = 1;

/// Maximum size of opaque agent inputs (64KB)
pub const MAX_AGENT_INPUT_BYTES: usize = 64_000;

/// Maximum total size of agent output when encoded
pub const MAX_AGENT_OUTPUT_BYTES: usize = 64_000;

/// Maximum memory allocation for bounded execution
pub const MAX_ALLOCATION_BYTES: usize = 1_000_000;
