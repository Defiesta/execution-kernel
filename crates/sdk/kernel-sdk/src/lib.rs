//! Canonical Agent SDK for zkVM Guest Execution
//!
//! This crate provides the minimal, stable interface for developing agents
//! that execute inside the zkVM guest. It enforces a strict boundary between
//! untrusted agent code and trusted kernel/constraint logic.
//!
//! # Design Principles
//!
//! 1. **Stability** - The interface is versioned and backwards-compatible
//! 2. **Minimalism** - Agents receive only what they strictly need
//! 3. **Isolation** - Agents cannot access forbidden APIs or kernel internals
//! 4. **Determinism** - Agent execution must be fully deterministic
//! 5. **Auditability** - Agent behavior must be inspectable and reproducible
//!
//! # SDK Structure
//!
//! - [`agent`] - Agent context and entrypoint definitions
//! - [`types`] - Action types, AgentOutput, and helper constructors
//! - [`math`] - Deterministic math helpers (checked arithmetic, basis points)
//! - [`bytes`] - Safe byte manipulation utilities
//!
//! # Canonical Entrypoint
//!
//! Every agent MUST expose exactly this function:
//!
//! ```ignore
//! #[no_mangle]
//! pub extern "Rust" fn agent_main(ctx: &AgentContext, opaque_inputs: &[u8]) -> AgentOutput
//! ```
//!
//! - Uses `extern "Rust"` for safe ABI with Rust types
//! - The symbol name `agent_main` is fixed and mandatory
//! - No other entrypoints are recognized by the kernel
//! - Panics abort execution and invalidate the proof
//!
//! # Example Agent
//!
//! ```ignore
//! use kernel_sdk::prelude::*;
//!
//! #[no_mangle]
//! pub extern "Rust" fn agent_main(ctx: &AgentContext, opaque_inputs: &[u8]) -> AgentOutput {
//!     // Echo the opaque inputs back as an action
//!     let action = echo_action(ctx.agent_id, opaque_inputs.to_vec());
//!
//!     // Build output with explicit, bounded allocation
//!     let mut actions = Vec::with_capacity(1);
//!     actions.push(action);
//!     AgentOutput { actions }
//! }
//! ```
//!
//! # Allowed Behavior
//!
//! Agents may use:
//! - Pure Rust logic (no unsafe unless carefully audited)
//! - Deterministic math (integer arithmetic only)
//! - Byte manipulation via SDK helpers
//! - Fixed-size or bounded collections
//!
//! # Forbidden Behavior
//!
//! Agents MUST NOT:
//! - Read system time (`std::time`)
//! - Generate randomness (`rand`)
//! - Perform I/O (`std::fs`, `std::net`)
//! - Call syscalls or host functions
//! - Access kernel internals
//! - Allocate unbounded memory
//!
//! The SDK is `#![no_std]` and `#![forbid(unsafe_code)]`, which prevents many
//! violations at compile time. Additional restrictions are enforced by the
//! guest runtime and zkVM execution environment.
//!
//! **Build requirements:** Agents should compile with `default-features = false`
//! and without `std`. CI should reject transitive `std` dependencies.
//!
//! # Versioning
//!
//! The agent interface is tied to `kernel_version`. Breaking changes
//! require a new major kernel version. Agents can check the version
//! via `ctx.kernel_version`.

#![no_std]
#![forbid(unsafe_code)]
#![deny(clippy::std_instead_of_alloc)]
#![deny(clippy::std_instead_of_core)]

extern crate alloc;

// ============================================================================
// Public Modules
// ============================================================================

pub mod agent;
pub mod bytes;
pub mod math;
pub mod types;

// ============================================================================
// Prelude - Common Imports
// ============================================================================

/// Prelude module for convenient imports.
///
/// Use `use kernel_sdk::prelude::*;` to import common types and functions.
///
/// **Note:** The `vec![]` macro is intentionally NOT exported to discourage
/// unbounded allocations. Prefer:
/// - `Vec::with_capacity(n)` + `push()` for bounded, explicit allocations
/// - `Vec::from([a, b, c])` for small, fixed-size outputs
///
/// If you need `vec![]`, you can still use `alloc::vec![]` directly.
pub mod prelude {
    // Agent context + entrypoint type
    pub use crate::agent::{AgentContext, AgentEntrypoint};

    // Core types
    pub use crate::types::{
        ActionV1, AgentOutput, MAX_ACTIONS_PER_OUTPUT, MAX_ACTION_PAYLOAD_BYTES,
    };

    // Action type constants (re-exported from kernel-core)
    pub use crate::types::{ACTION_TYPE_CALL, ACTION_TYPE_NO_OP, ACTION_TYPE_TRANSFER_ERC20};

    #[cfg(any(test, feature = "testing"))]
    pub use crate::types::ACTION_TYPE_ECHO;

    // Action constructors
    pub use crate::types::{address_to_bytes32, call_action, no_op_action, transfer_erc20_action};

    #[cfg(any(test, feature = "testing"))]
    pub use crate::types::echo_action;

    // Math helpers (canonical primitives)
    pub use crate::math::{
        // Basis points
        apply_bps,
        calculate_bps,
        // Checked arithmetic
        checked_add_u64,
        checked_div_u64,
        checked_mul_div_u64,
        checked_mul_u64,
        checked_sub_u64,
        drawdown_bps,
        // Saturating arithmetic
        saturating_add_u64,
        saturating_mul_u64,
        saturating_sub_u64,
        BPS_DENOMINATOR,
    };

    // Byte helpers (fixed offset)
    pub use crate::bytes::{
        is_zero_bytes32, read_bytes32, read_slice, read_u32_le, read_u64_le, read_u8,
    };

    // Byte helpers (cursor-style)
    pub use crate::bytes::{
        read_bool_u8_at, read_bytes32_at, read_slice_at, read_u32_le_at, read_u64_le_at, read_u8_at,
    };

    // Re-export Vec for no_std agent code
    // Note: vec![] macro intentionally not exported to discourage unbounded allocations
    pub use alloc::vec::Vec;
}

// ============================================================================
// Re-exports at Crate Root
// ============================================================================

pub use agent::{AgentContext, AgentEntrypoint};
pub use types::{ActionV1, AgentOutput};

// ============================================================================
// SDK Version
// ============================================================================

/// SDK major version.
pub const SDK_VERSION_MAJOR: u8 = 0;

/// SDK minor version.
pub const SDK_VERSION_MINOR: u8 = 1;

/// SDK patch version.
pub const SDK_VERSION_PATCH: u8 = 0;

/// SDK version (major.minor.patch encoded as u32).
///
/// Format: `(major << 16) | (minor << 8) | patch`
pub const SDK_VERSION: u32 = ((SDK_VERSION_MAJOR as u32) << 16)
    | ((SDK_VERSION_MINOR as u32) << 8)
    | (SDK_VERSION_PATCH as u32);

/// Minimum supported kernel version.
pub const MIN_KERNEL_VERSION: u32 = 1;

/// Maximum supported kernel version.
pub const MAX_KERNEL_VERSION: u32 = 1;

/// Check if a kernel version is supported by this SDK.
#[inline]
pub fn is_kernel_version_supported(version: u32) -> bool {
    version >= MIN_KERNEL_VERSION && version <= MAX_KERNEL_VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sdk_version() {
        assert_eq!(SDK_VERSION, 0x00_01_00);
        assert_eq!(SDK_VERSION_MAJOR, 0);
        assert_eq!(SDK_VERSION_MINOR, 1);
        assert_eq!(SDK_VERSION_PATCH, 0);
    }

    #[test]
    fn test_kernel_version_supported() {
        assert!(is_kernel_version_supported(1));
        assert!(!is_kernel_version_supported(0));
        assert!(!is_kernel_version_supported(2));
    }

    /// Ensure all prelude exports compile and are accessible.
    /// This catches accidental rename/missing export regressions.
    #[test]
    fn test_prelude_imports_compile() {
        #[allow(unused_imports)]
        use crate::prelude::*;

        // Verify key types are accessible with 2-arg signature
        fn _check_types() {
            let _: fn(&AgentContext, &[u8]) -> AgentOutput = |_, _| AgentOutput {
                actions: Vec::new(),
            };
        }
    }
}
