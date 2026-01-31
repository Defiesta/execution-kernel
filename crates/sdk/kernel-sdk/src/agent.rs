//! Agent context and entrypoint definitions.
//!
//! This module defines the canonical agent interface used by the kernel.
//! Agents receive an [`AgentContext`] and opaque inputs, and must return
//! an [`AgentOutput`].
//!
//! # Canonical Entrypoint
//!
//! Every agent MUST expose exactly this function signature:
//!
//! ```ignore
//! #[no_mangle]
//! pub extern "Rust" fn agent_main(ctx: &AgentContext, opaque_inputs: &[u8]) -> AgentOutput
//! ```
//!
//! - The symbol name `agent_main` is fixed and mandatory
//! - Uses `extern "Rust"` for safe ABI with Rust types
//! - No other entrypoints are recognized by the kernel
//! - Panics abort execution and invalidate the proof
//!
//! # Example
//!
//! ```ignore
//! use kernel_sdk::prelude::*;
//!
//! #[no_mangle]
//! pub extern "Rust" fn agent_main(ctx: &AgentContext, opaque_inputs: &[u8]) -> AgentOutput {
//!     // Pure, deterministic logic only
//!     AgentOutput { actions: Vec::new() }
//! }
//! ```

use crate::types::AgentOutput;

/// Execution context provided to agents by the kernel.
///
/// This structure contains all identity and metadata information an agent
/// needs to make decisions. The actual input data is passed separately
/// as `opaque_inputs` to the entrypoint.
///
/// # Design Rationale
///
/// - All fields are owned/Copy types (no lifetimes)
/// - `opaque_inputs` is passed as a separate argument to the entrypoint
/// - This keeps the context a clean "header" structure
///
/// # ABI Stability
///
/// This struct uses `#[repr(C)]` to ensure a stable, predictable memory layout
/// across crate versions and compiler updates.
///
/// # Validation
///
/// All data in this context has been validated by the kernel:
/// - Protocol and kernel versions are supported
/// - Identifiers and hashes are correctly formatted
/// - Size limits are enforced
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AgentContext {
    /// Protocol version for wire format compatibility.
    ///
    /// Currently must be 1. Agents can check this to ensure compatibility.
    pub protocol_version: u32,

    /// Kernel semantics version.
    ///
    /// Currently must be 1. Breaking changes to the agent interface
    /// require a new kernel version.
    pub kernel_version: u32,

    /// 32-byte agent identifier.
    ///
    /// Uniquely identifies this agent within the protocol.
    /// Commonly used as the default target for actions.
    pub agent_id: [u8; 32],

    /// SHA-256 hash of the agent binary.
    ///
    /// The proof binds to this specific agent code.
    /// Agents can use this to verify they are running expected code.
    pub agent_code_hash: [u8; 32],

    /// SHA-256 hash of the constraint set being enforced.
    ///
    /// Identifies the economic safety rules applied to this execution.
    /// Agents can use this to adjust behavior based on constraint policy.
    pub constraint_set_hash: [u8; 32],

    /// External state root (market/vault snapshot).
    ///
    /// Merkle root or hash of the external state the agent observes.
    /// The proof binds to this specific state snapshot.
    pub input_root: [u8; 32],

    /// Monotonic nonce for replay protection.
    ///
    /// Must be strictly increasing across executions for the same agent.
    /// Used by the settlement layer to prevent replay attacks.
    pub execution_nonce: u64,
}

impl AgentContext {
    /// Create a new AgentContext from kernel input data.
    ///
    /// This is called by the kernel, not by agents.
    /// Agents receive the context as a parameter to `agent_main`.
    #[doc(hidden)]
    pub fn new(
        protocol_version: u32,
        kernel_version: u32,
        agent_id: [u8; 32],
        agent_code_hash: [u8; 32],
        constraint_set_hash: [u8; 32],
        input_root: [u8; 32],
        execution_nonce: u64,
    ) -> Self {
        Self {
            protocol_version,
            kernel_version,
            agent_id,
            agent_code_hash,
            constraint_set_hash,
            input_root,
            execution_nonce,
        }
    }

    /// Check if the protocol version is supported.
    ///
    /// Returns true if `protocol_version == 1`.
    #[inline]
    pub fn is_protocol_v1(&self) -> bool {
        self.protocol_version == 1
    }

    /// Check if the kernel version is supported.
    ///
    /// Returns true if `kernel_version == 1`.
    #[inline]
    pub fn is_kernel_v1(&self) -> bool {
        self.kernel_version == 1
    }
}

/// Type alias for the canonical agent entrypoint function.
///
/// Agents must implement a function with this signature and expose it
/// with `#[no_mangle]` and the name `agent_main`.
///
/// # Signature
///
/// ```ignore
/// fn agent_main(ctx: &AgentContext, opaque_inputs: &[u8]) -> AgentOutput
/// ```
///
/// - `ctx`: Execution context with identity and metadata
/// - `opaque_inputs`: Agent-specific input data (max 64,000 bytes)
/// - Returns: `AgentOutput` containing ordered actions
///
/// # Opaque Inputs Convention
///
/// If cooldown or drawdown constraints are enabled, the **first 36 bytes**
/// of `opaque_inputs` must contain a `StateSnapshotV1`:
///
/// | Offset | Field             | Type | Size |
/// |--------|-------------------|------|------|
/// | 0      | snapshot_version  | u32  | 4    |
/// | 4      | last_execution_ts | u64  | 8    |
/// | 12     | current_ts        | u64  | 8    |
/// | 20     | current_equity    | u64  | 8    |
/// | 28     | peak_equity       | u64  | 8    |
///
/// Any bytes after the first 36 are agent-specific and ignored by the
/// constraint engine. See `spec/constraints.md` for full details.
pub type AgentEntrypoint = extern "Rust" fn(&AgentContext, &[u8]) -> AgentOutput;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_context_creation() {
        let ctx = AgentContext::new(
            1,
            1,
            [0x42u8; 32],
            [0xaau8; 32],
            [0xbbu8; 32],
            [0xccu8; 32],
            12345,
        );

        assert_eq!(ctx.protocol_version, 1);
        assert_eq!(ctx.kernel_version, 1);
        assert_eq!(ctx.agent_id, [0x42u8; 32]);
        assert_eq!(ctx.execution_nonce, 12345);
        assert!(ctx.is_protocol_v1());
        assert!(ctx.is_kernel_v1());
    }

    #[test]
    fn test_agent_context_copy() {
        let ctx = AgentContext::new(1, 1, [0x42u8; 32], [0u8; 32], [0u8; 32], [0u8; 32], 42);

        // AgentContext is Copy
        let ctx2 = ctx;
        assert_eq!(ctx.agent_id, ctx2.agent_id);
        assert_eq!(ctx.execution_nonce, ctx2.execution_nonce);
    }

    #[test]
    fn test_agent_context_repr_c() {
        // Verify the struct has a predictable size
        // 4 + 4 + 32 + 32 + 32 + 32 + 8 = 144 bytes
        assert_eq!(core::mem::size_of::<AgentContext>(), 144);
    }
}
