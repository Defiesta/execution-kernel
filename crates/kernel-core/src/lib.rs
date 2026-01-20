pub mod types;
pub mod codec;
pub mod hash;

pub use types::*;
pub use codec::*;
pub use hash::*;

pub const PROTOCOL_VERSION: u32 = 1;
pub const KERNEL_VERSION: u32 = 1;
pub const MAX_AGENT_INPUT_BYTES: usize = 64_000;