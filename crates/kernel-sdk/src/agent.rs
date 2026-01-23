//! Agent context and entrypoint definitions.
//!
//! This module defines the canonical agent interface used by the kernel.
//! Agents receive an [`AgentContext`] and must return an [`AgentOutput`].
//!
//! # Canonical Entrypoint
//!
//! Every agent MUST expose exactly this function signature:
//!
//! ```ignore
//! #[no_mangle]
//! pub extern "C" fn agent_main(ctx: &AgentContext) -> AgentOutput
//! ```
//!
//! - The symbol name `agent_main` is fixed and mandatory
//! - No other entrypoints are recognized by the kernel
//! - Panics abort execution and invalidate the proof
//!
//! # Example
//!
//! ```ignore
//! use kernel_sdk::prelude::*;
//!
//! #[no_mangle]
//! pub extern "C" fn agent_main(ctx: &AgentContext) -> AgentOutput {
//!     // Pure, deterministic logic only
//!     AgentOutput { actions: vec![] }
//! }
//! ```

use crate::types::AgentOutput;

/// Execution context provided to agents by the kernel.
///
/// This structure contains all information an agent needs to make decisions
/// and produce actions. All fields are immutable and pre-validated by the kernel.
///
/// # ABI Stability
///
/// This struct uses `#[repr(C)]` to ensure a stable, predictable memory layout
/// across crate versions and compiler updates. This is required because the
/// canonical entrypoint uses `extern "C"` ABI.
///
/// # Immutability
///
/// - All fields are references or Copy types
/// - No interior mutability is permitted
/// - Agents cannot modify the context
///
/// # Validation
///
/// All data in this context has been validated by the kernel:
/// - Protocol and kernel versions are supported
/// - Identifiers and hashes are correctly formatted
/// - Size limits are enforced
///
/// # Lifetime
///
/// The `'a` lifetime is tied to the kernel's input buffer. The context
/// is valid for the duration of the `agent_main` call.
#[repr(C)]
#[derive(Clone, Debug)]
pub struct AgentContext<'a> {
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
    pub agent_id: &'a [u8; 32],

    /// SHA-256 hash of the agent binary.
    ///
    /// The proof binds to this specific agent code.
    /// Agents can use this to verify they are running expected code.
    pub agent_code_hash: &'a [u8; 32],

    /// SHA-256 hash of the constraint set being enforced.
    ///
    /// Identifies the economic safety rules applied to this execution.
    /// Agents can use this to adjust behavior based on constraint policy.
    pub constraint_set_hash: &'a [u8; 32],

    /// External state root (market/vault snapshot).
    ///
    /// Merkle root or hash of the external state the agent observes.
    /// The proof binds to this specific state snapshot.
    pub input_root: &'a [u8; 32],

    /// Monotonic nonce for replay protection.
    ///
    /// Must be strictly increasing across executions for the same agent.
    /// Used by the settlement layer to prevent replay attacks.
    pub execution_nonce: u64,

    /// Opaque agent-specific input data.
    ///
    /// This byte slice contains agent-defined data. The kernel does not
    /// interpret this data beyond size validation (max 64,000 bytes).
    ///
    /// # Snapshot Prefix Convention
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
    pub opaque_inputs: &'a [u8],
}

impl<'a> AgentContext<'a> {
    /// Create a new AgentContext from kernel input data.
    ///
    /// This is called by the kernel, not by agents.
    /// Agents receive the context as a parameter to `agent_main`.
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)] // Intentional: matches kernel input structure
    pub fn new(
        protocol_version: u32,
        kernel_version: u32,
        agent_id: &'a [u8; 32],
        agent_code_hash: &'a [u8; 32],
        constraint_set_hash: &'a [u8; 32],
        input_root: &'a [u8; 32],
        execution_nonce: u64,
        opaque_inputs: &'a [u8],
    ) -> Self {
        Self {
            protocol_version,
            kernel_version,
            agent_id,
            agent_code_hash,
            constraint_set_hash,
            input_root,
            execution_nonce,
            opaque_inputs,
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

    /// Get the length of opaque inputs.
    #[inline]
    pub fn inputs_len(&self) -> usize {
        self.opaque_inputs.len()
    }

    /// Check if opaque inputs is empty.
    #[inline]
    pub fn inputs_is_empty(&self) -> bool {
        self.opaque_inputs.is_empty()
    }

    /// Check if opaque inputs contains at least a state snapshot prefix.
    ///
    /// Returns true if `opaque_inputs.len() >= 36`.
    #[inline]
    pub fn has_snapshot_prefix(&self) -> bool {
        self.opaque_inputs.len() >= 36
    }

    /// Get the agent-specific portion of opaque inputs (bytes after snapshot).
    ///
    /// Returns the bytes after the 36-byte snapshot prefix, or the full
    /// slice if shorter than 36 bytes.
    #[inline]
    pub fn agent_inputs(&self) -> &[u8] {
        if self.opaque_inputs.len() > 36 {
            &self.opaque_inputs[36..]
        } else {
            &[]
        }
    }
}

/// Type alias for the canonical agent entrypoint function.
///
/// Agents must implement a function with this signature and expose it
/// with `#[no_mangle] pub extern "C"` and the name `agent_main`.
///
/// The lifetime parameter `'a` is tied to the kernel's input buffer.
///
/// Note: `AgentOutput` is not FFI-safe (no `#[repr(C)]`), but this is
/// acceptable because zkVM guest execution uses its own ABI mechanisms
/// rather than literal C FFI.
#[allow(improper_ctypes_definitions)]
pub type AgentEntrypoint<'a> = extern "C" fn(&AgentContext<'a>) -> AgentOutput;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_context_creation() {
        let agent_id = [0x42u8; 32];
        let code_hash = [0xaau8; 32];
        let constraint_hash = [0xbbu8; 32];
        let input_root = [0xccu8; 32];
        let inputs = [1u8, 2, 3, 4, 5];

        let ctx = AgentContext::new(
            1,
            1,
            &agent_id,
            &code_hash,
            &constraint_hash,
            &input_root,
            12345,
            &inputs,
        );

        assert_eq!(ctx.protocol_version, 1);
        assert_eq!(ctx.kernel_version, 1);
        assert_eq!(ctx.agent_id, &agent_id);
        assert_eq!(ctx.execution_nonce, 12345);
        assert_eq!(ctx.opaque_inputs, &inputs);
        assert!(ctx.is_protocol_v1());
        assert!(ctx.is_kernel_v1());
        assert_eq!(ctx.inputs_len(), 5);
        assert!(!ctx.inputs_is_empty());
    }

    #[test]
    fn test_agent_context_empty_inputs() {
        let agent_id = [0u8; 32];
        let code_hash = [0u8; 32];
        let constraint_hash = [0u8; 32];
        let input_root = [0u8; 32];
        let inputs: [u8; 0] = [];

        let ctx = AgentContext::new(
            1,
            1,
            &agent_id,
            &code_hash,
            &constraint_hash,
            &input_root,
            0,
            &inputs,
        );

        assert!(ctx.inputs_is_empty());
        assert_eq!(ctx.inputs_len(), 0);
        assert!(!ctx.has_snapshot_prefix());
        assert!(ctx.agent_inputs().is_empty());
    }

    #[test]
    fn test_agent_context_with_snapshot_prefix() {
        let agent_id = [0u8; 32];
        let code_hash = [0u8; 32];
        let constraint_hash = [0u8; 32];
        let input_root = [0u8; 32];
        // 36 bytes snapshot + 4 bytes agent data
        let inputs = [0u8; 40];

        let ctx = AgentContext::new(
            1,
            1,
            &agent_id,
            &code_hash,
            &constraint_hash,
            &input_root,
            0,
            &inputs,
        );

        assert!(ctx.has_snapshot_prefix());
        assert_eq!(ctx.agent_inputs().len(), 4);
    }

    #[test]
    fn test_agent_context_clone() {
        let agent_id = [0x42u8; 32];
        let code_hash = [0u8; 32];
        let constraint_hash = [0u8; 32];
        let input_root = [0u8; 32];
        let inputs = [1u8, 2, 3];

        let ctx = AgentContext::new(
            1,
            1,
            &agent_id,
            &code_hash,
            &constraint_hash,
            &input_root,
            42,
            &inputs,
        );

        let ctx2 = ctx.clone();
        assert_eq!(ctx.agent_id, ctx2.agent_id);
        assert_eq!(ctx.execution_nonce, ctx2.execution_nonce);
    }
}
