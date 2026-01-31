//! Core types, codec, and hashing for the execution kernel.
//!
//! This crate provides the foundational types and utilities used by both
//! the kernel-guest (zkVM execution) and kernel-sdk (agent development).
//!
//! # no_std Support
//!
//! This crate is `#![no_std]` by default and uses `alloc` for heap allocations.
//! Enable the `std` feature for host-side tooling that needs std functionality.

#![no_std]
#![forbid(unsafe_code)]
#![deny(clippy::std_instead_of_alloc)]
#![deny(clippy::std_instead_of_core)]

extern crate alloc;

pub mod codec;
pub mod hash;
pub mod types;

pub use codec::*;
pub use hash::*;
pub use types::*;

// Re-export action type constants at crate root for convenience
pub use types::{ACTION_TYPE_CALL, ACTION_TYPE_NO_OP, ACTION_TYPE_TRANSFER_ERC20};

#[cfg(any(test, feature = "testing"))]
pub use types::ACTION_TYPE_ECHO;

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
