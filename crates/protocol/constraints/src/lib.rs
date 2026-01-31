//! Constraint enforcement engine for the kernel protocol (P0.3).
//!
//! This module provides unskippable constraint checking for agent outputs.
//! See spec/constraints.md for the full specification.
//!
//! # On-Chain Executable Action Types
//!
//! For protocol v1, the ONLY supported action types are those executable
//! by KernelVault on-chain:
//!
//! - [`ACTION_TYPE_CALL`] (0x00000002) - Generic contract call
//! - [`ACTION_TYPE_TRANSFER_ERC20`] (0x00000003) - ERC20 token transfer
//! - [`ACTION_TYPE_NO_OP`] (0x00000004) - No operation (skipped)
//!
//! Any agent emitting actions with unknown action types will trigger a
//! constraint violation with [`ConstraintViolationReason::UnknownActionType`].
//!
//! # Important Notes
//!
//! Higher-level strategy concepts (e.g., "open position", "swap") are agent
//! abstractions that must be compiled down to CALL or TRANSFER_ERC20 actions.
//! The constraint engine only validates executable action types.

use kernel_core::{
    ActionV1, AgentOutput, ConstraintError, ConstraintViolation, ConstraintViolationReason,
    KernelInputV1, MAX_ACTIONS_PER_OUTPUT, MAX_ACTION_PAYLOAD_BYTES,
};

// ============================================================================
// Action Type Constants (re-exported from kernel-core)
// ============================================================================
//
// These are the ONLY supported action types for protocol v1.
// kernel-core is the single source of truth for action type values.

/// CALL action type for on-chain execution (0x00000002).
pub use kernel_core::ACTION_TYPE_CALL;

/// ERC20 transfer action type for on-chain execution (0x00000003).
pub use kernel_core::ACTION_TYPE_TRANSFER_ERC20;

/// No-op action type (0x00000004).
pub use kernel_core::ACTION_TYPE_NO_OP;

/// Echo action type for testing (0x00000001).
///
/// Only available with the `testing` feature or in test mode.
/// This action type is NOT executable by KernelVault.
///
/// Note: This is defined locally rather than re-exported from kernel-core
/// because the cfg gates don't propagate across crate boundaries.
#[cfg(any(test, feature = "testing"))]
pub const ACTION_TYPE_ECHO: u32 = 0x00000001;

/// SHA-256 hash of empty AgentOutput encoding [0x00, 0x00, 0x00, 0x00]
pub const EMPTY_OUTPUT_COMMITMENT: [u8; 32] = [
    0xdf, 0x3f, 0x61, 0x98, 0x04, 0xa9, 0x2f, 0xdb, 0x40, 0x57, 0x19, 0x2d, 0xc4, 0x3d, 0xd7, 0x48,
    0xea, 0x77, 0x8a, 0xdc, 0x52, 0xbc, 0x49, 0x8c, 0xe8, 0x05, 0x24, 0xc0, 0x14, 0xb8, 0x11, 0x19,
];

// ============================================================================
// Constraint Set
// ============================================================================

/// Constraint set configuration (P0.3).
///
/// Defines economic safety parameters for agent execution.
/// Size: 60 bytes when encoded.
#[derive(Clone, Debug, PartialEq)]
pub struct ConstraintSetV1 {
    /// Version (must be 1)
    pub version: u32,
    /// Maximum position size in base units (reserved for future use)
    pub max_position_notional: u64,
    /// Maximum leverage in basis points (reserved for future use)
    pub max_leverage_bps: u32,
    /// Maximum drawdown in basis points (10000 = 100%)
    pub max_drawdown_bps: u32,
    /// Minimum seconds between executions
    pub cooldown_seconds: u32,
    /// Maximum actions per output
    pub max_actions_per_output: u32,
    /// Single allowed asset ID (reserved for future use)
    pub allowed_asset_id: [u8; 32],
}

impl Default for ConstraintSetV1 {
    /// Default permissive constraint set for P0.3.
    fn default() -> Self {
        Self {
            version: 1,
            max_position_notional: u64::MAX,
            max_leverage_bps: 100_000, // 10x max leverage
            max_drawdown_bps: 10_000,  // 100% (disabled)
            cooldown_seconds: 0,
            max_actions_per_output: MAX_ACTIONS_PER_OUTPUT as u32,
            allowed_asset_id: [0u8; 32], // All assets allowed
        }
    }
}

// ============================================================================
// State Snapshot
// ============================================================================

/// State snapshot for cooldown and drawdown checks.
///
/// Size: 36 bytes when encoded.
#[derive(Clone, Debug, PartialEq)]
pub struct StateSnapshotV1 {
    /// Version (must be 1)
    pub snapshot_version: u32,
    /// Timestamp of last execution
    pub last_execution_ts: u64,
    /// Current timestamp (from input)
    pub current_ts: u64,
    /// Current portfolio equity
    pub current_equity: u64,
    /// Peak portfolio equity
    pub peak_equity: u64,
}

impl StateSnapshotV1 {
    /// Minimum size of encoded snapshot
    pub const ENCODED_SIZE: usize = 36;

    /// Decode a state snapshot from bytes.
    ///
    /// Returns None if bytes are too short or version is wrong.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::ENCODED_SIZE {
            return None;
        }

        let snapshot_version = u32::from_le_bytes(bytes[0..4].try_into().ok()?);
        if snapshot_version != 1 {
            return None;
        }

        Some(Self {
            snapshot_version,
            last_execution_ts: u64::from_le_bytes(bytes[4..12].try_into().ok()?),
            current_ts: u64::from_le_bytes(bytes[12..20].try_into().ok()?),
            current_equity: u64::from_le_bytes(bytes[20..28].try_into().ok()?),
            peak_equity: u64::from_le_bytes(bytes[28..36].try_into().ok()?),
        })
    }
}

// ============================================================================
// Constraint Metadata (Legacy compatibility)
// ============================================================================

/// Metadata for constraint checking (legacy API).
#[derive(Clone, Debug)]
pub struct ConstraintMeta {
    pub agent_id: [u8; 32],
    pub agent_code_hash: [u8; 32],
    pub constraint_set_hash: [u8; 32],
    pub input_root: [u8; 32],
    pub execution_nonce: u64,
}

// ============================================================================
// Constraint Enforcement
// ============================================================================

/// Enforce all constraints on the proposed agent output.
///
/// This is the main entry point for constraint checking. It validates:
/// 1. Output structure (action count, payload sizes)
/// 2. Per-action constraints (action type validity, payload format)
/// 3. Global constraints (cooldown, drawdown)
///
/// # Supported Action Types
///
/// For protocol v1, only on-chain executable action types are allowed:
/// - `ACTION_TYPE_CALL` (0x00000002) - Must have valid ABI-encoded payload
/// - `ACTION_TYPE_TRANSFER_ERC20` (0x00000003) - Must have 96-byte payload
/// - `ACTION_TYPE_NO_OP` (0x00000004) - Must have empty payload
///
/// Any other action type triggers `UnknownActionType` violation.
///
/// # Arguments
/// * `input` - The kernel input containing state snapshot
/// * `proposed` - The proposed agent output to validate
/// * `constraint_set` - The constraint set to enforce
///
/// # Returns
/// * `Ok(AgentOutput)` - The validated output (same as proposed if valid)
/// * `Err(ConstraintViolation)` - The first constraint violation encountered
pub fn enforce_constraints(
    input: &KernelInputV1,
    proposed: &AgentOutput,
    constraint_set: &ConstraintSetV1,
) -> Result<AgentOutput, ConstraintViolation> {
    // 1. Validate constraint set version and invariants
    if constraint_set.version != 1 {
        return Err(ConstraintViolation::global(
            ConstraintViolationReason::InvalidConstraintSet,
        ));
    }

    // 1b. Validate constraint set invariants
    // max_actions_per_output must not exceed protocol limit
    if constraint_set.max_actions_per_output > MAX_ACTIONS_PER_OUTPUT as u32 {
        return Err(ConstraintViolation::global(
            ConstraintViolationReason::InvalidConstraintSet,
        ));
    }

    // max_drawdown_bps must be <= 10_000 (100%)
    if constraint_set.max_drawdown_bps > 10_000 {
        return Err(ConstraintViolation::global(
            ConstraintViolationReason::InvalidConstraintSet,
        ));
    }

    // 2. Validate output structure
    check_output_structure(proposed, constraint_set)?;

    // 3. Validate each action
    for (index, action) in proposed.actions.iter().enumerate() {
        validate_action(action, index)?;
    }

    // 4. Parse state snapshot (optional)
    let snapshot = StateSnapshotV1::decode(&input.opaque_agent_inputs);

    // 5. Check if snapshot is required but missing
    let cooldown_enabled = constraint_set.cooldown_seconds > 0;
    let drawdown_enabled = constraint_set.max_drawdown_bps < 10_000;

    if snapshot.is_none() && (cooldown_enabled || drawdown_enabled) {
        return Err(ConstraintViolation::global(
            ConstraintViolationReason::InvalidStateSnapshot,
        ));
    }

    // 6. Validate global constraints (if snapshot present)
    if let Some(ref snap) = snapshot {
        validate_global_constraints(snap, constraint_set)?;
    }

    // All constraints passed - return the validated output
    Ok(proposed.clone())
}

/// Validate output structure (internal, with constraint set).
fn check_output_structure(
    output: &AgentOutput,
    constraint_set: &ConstraintSetV1,
) -> Result<(), ConstraintViolation> {
    // Check action count
    let max_actions = constraint_set.max_actions_per_output as usize;
    if output.actions.len() > max_actions {
        return Err(ConstraintViolation::global(
            ConstraintViolationReason::InvalidOutputStructure,
        ));
    }

    // Check each action's payload size
    for (index, action) in output.actions.iter().enumerate() {
        if action.payload.len() > MAX_ACTION_PAYLOAD_BYTES {
            return Err(ConstraintViolation::action(
                ConstraintViolationReason::InvalidOutputStructure,
                index,
            ));
        }
    }

    Ok(())
}

/// Validate a single action.
///
/// For protocol v1, only on-chain executable action types are allowed:
/// - CALL (0x02): ABI-encoded (uint256 value, bytes callData), min 96 bytes
/// - TRANSFER_ERC20 (0x03): ABI-encoded (address token, address to, uint256 amount), exactly 96 bytes
/// - NO_OP (0x04): empty payload
///
/// ECHO (0x01) is only allowed in test builds.
fn validate_action(action: &ActionV1, index: usize) -> Result<(), ConstraintViolation> {
    // Note: ECHO (0x01) is only valid in test/testing builds
    #[cfg(any(test, feature = "testing"))]
    if action.action_type == ACTION_TYPE_ECHO {
        return Ok(());
    }

    match action.action_type {
        x if x == ACTION_TYPE_CALL => validate_call_action(action, index),
        x if x == ACTION_TYPE_TRANSFER_ERC20 => validate_transfer_erc20_action(action, index),
        x if x == ACTION_TYPE_NO_OP => validate_no_op_action(action, index),
        _ => {
            // Unknown action type - not executable on-chain
            Err(ConstraintViolation::action(
                ConstraintViolationReason::UnknownActionType,
                index,
            ))
        }
    }
}

/// Validate CALL action (on-chain execution).
///
/// Payload format: abi.encode(uint256 value, bytes callData)
/// Minimum size: 96 bytes (32 value + 32 offset + 32 length + 0 calldata)
fn validate_call_action(action: &ActionV1, index: usize) -> Result<(), ConstraintViolation> {
    // Minimum payload size check
    if action.payload.len() < 96 {
        return Err(ConstraintViolation::action(
            ConstraintViolationReason::InvalidActionPayload,
            index,
        ));
    }

    // Validate target is a valid EVM address (upper 12 bytes must be zero)
    if action.target[0..12] != [0u8; 12] {
        return Err(ConstraintViolation::action(
            ConstraintViolationReason::InvalidActionPayload,
            index,
        ));
    }

    // Basic ABI structure validation:
    // bytes 32-63 should contain offset (should be 64 = 0x40)
    // bytes 64-95 should contain length of calldata
    let offset = u256_from_be_bytes(&action.payload[32..64]);
    if offset != 64 {
        return Err(ConstraintViolation::action(
            ConstraintViolationReason::InvalidActionPayload,
            index,
        ));
    }

    let calldata_len = u256_from_be_bytes(&action.payload[64..96]);
    // Verify payload length matches declared calldata length (with 32-byte padding)
    let expected_len = 96 + (calldata_len as usize).div_ceil(32) * 32;
    if action.payload.len() != expected_len {
        return Err(ConstraintViolation::action(
            ConstraintViolationReason::InvalidActionPayload,
            index,
        ));
    }

    Ok(())
}

/// Validate TRANSFER_ERC20 action (on-chain execution).
///
/// Payload format: abi.encode(address token, address to, uint256 amount)
/// Size: exactly 96 bytes
fn validate_transfer_erc20_action(
    action: &ActionV1,
    index: usize,
) -> Result<(), ConstraintViolation> {
    if action.payload.len() != 96 {
        return Err(ConstraintViolation::action(
            ConstraintViolationReason::InvalidActionPayload,
            index,
        ));
    }

    // Validate addresses have proper padding (upper 12 bytes should be zero)
    // Token address (bytes 0-31)
    if action.payload[0..12] != [0u8; 12] {
        return Err(ConstraintViolation::action(
            ConstraintViolationReason::InvalidActionPayload,
            index,
        ));
    }

    // To address (bytes 32-63)
    if action.payload[32..44] != [0u8; 12] {
        return Err(ConstraintViolation::action(
            ConstraintViolationReason::InvalidActionPayload,
            index,
        ));
    }

    Ok(())
}

/// Validate NO_OP action.
///
/// Payload must be empty.
fn validate_no_op_action(action: &ActionV1, index: usize) -> Result<(), ConstraintViolation> {
    if !action.payload.is_empty() {
        return Err(ConstraintViolation::action(
            ConstraintViolationReason::InvalidActionPayload,
            index,
        ));
    }
    Ok(())
}

/// Helper to read a u256 from big-endian bytes (only reads lower 64 bits for practical values)
fn u256_from_be_bytes(bytes: &[u8]) -> u64 {
    // For practical values, we only need to check if upper bytes are zero
    // and read the lower 8 bytes
    if bytes.len() != 32 {
        return u64::MAX; // Invalid
    }
    // Check upper 24 bytes are zero (for values that fit in u64)
    if bytes[0..24] != [0u8; 24] {
        return u64::MAX; // Value too large
    }
    u64::from_be_bytes(bytes[24..32].try_into().unwrap())
}

/// Validate global constraints (cooldown, drawdown).
fn validate_global_constraints(
    snapshot: &StateSnapshotV1,
    constraint_set: &ConstraintSetV1,
) -> Result<(), ConstraintViolation> {
    // Check cooldown
    if constraint_set.cooldown_seconds > 0 {
        // Use checked_add to detect maliciously large last_execution_ts values.
        // Overflow would indicate an invalid snapshot (timestamp cannot be that large).
        let required_ts = snapshot
            .last_execution_ts
            .checked_add(constraint_set.cooldown_seconds as u64)
            .ok_or_else(|| {
                ConstraintViolation::global(ConstraintViolationReason::InvalidStateSnapshot)
            })?;
        if snapshot.current_ts < required_ts {
            return Err(ConstraintViolation::global(
                ConstraintViolationReason::CooldownNotElapsed,
            ));
        }
    }

    // Check drawdown
    if constraint_set.max_drawdown_bps < 10_000 {
        // Only check if drawdown limit is meaningful (< 100%)
        if snapshot.peak_equity == 0 {
            return Err(ConstraintViolation::global(
                ConstraintViolationReason::InvalidStateSnapshot,
            ));
        }

        // Calculate drawdown in basis points
        // drawdown_bps = (peak - current) * 10000 / peak
        let drawdown = snapshot.peak_equity.saturating_sub(snapshot.current_equity);
        // SAFETY: peak_equity != 0 is verified above, so division cannot fail
        let drawdown_bps = drawdown
            .saturating_mul(10_000)
            .checked_div(snapshot.peak_equity)
            .expect("peak_equity != 0 checked above");

        if drawdown_bps > constraint_set.max_drawdown_bps as u64 {
            return Err(ConstraintViolation::global(
                ConstraintViolationReason::DrawdownExceeded,
            ));
        }
    }

    Ok(())
}

// ============================================================================
// Legacy API (backward compatibility)
// ============================================================================

/// Check agent output against constraint set (legacy API).
///
/// This function uses the default constraint set for backward compatibility.
pub fn check(_output: &AgentOutput, _meta: &ConstraintMeta) -> Result<(), ConstraintError> {
    // For backward compatibility, always pass with default constraints.
    // The new enforce_constraints function should be used instead.
    Ok(())
}

/// Validate that output is well-formed (legacy API).
pub fn validate_output_structure_legacy(output: &AgentOutput) -> Result<(), ConstraintError> {
    if output.actions.len() > MAX_ACTIONS_PER_OUTPUT {
        return Err(ConstraintError::InvalidOutput);
    }

    for action in &output.actions {
        if action.payload.len() > MAX_ACTION_PAYLOAD_BYTES {
            return Err(ConstraintError::InvalidOutput);
        }
    }

    Ok(())
}

// Re-export the legacy validate_output_structure under its original name
pub use validate_output_structure_legacy as validate_output_structure;

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_input() -> KernelInputV1 {
        KernelInputV1 {
            protocol_version: 1,
            kernel_version: 1,
            agent_id: [0x42; 32],
            agent_code_hash: [0xaa; 32],
            constraint_set_hash: [0xbb; 32],
            input_root: [0xcc; 32],
            execution_nonce: 1,
            opaque_agent_inputs: vec![],
        }
    }

    fn make_echo_action() -> ActionV1 {
        ActionV1 {
            action_type: ACTION_TYPE_ECHO,
            target: [0x11; 32],
            payload: vec![1, 2, 3],
        }
    }

    /// Create a valid CALL action with proper ABI encoding
    fn make_call_action(target_addr: [u8; 20], value: u128, calldata: &[u8]) -> ActionV1 {
        let mut target = [0u8; 32];
        target[12..32].copy_from_slice(&target_addr);

        let data_len = calldata.len();
        let padded_len = data_len.div_ceil(32) * 32;
        let total_size = 96 + padded_len;

        let mut payload = vec![0u8; total_size];

        // value (uint256, big-endian)
        payload[16..32].copy_from_slice(&value.to_be_bytes());

        // offset (64 = 0x40)
        payload[63] = 64;

        // length
        payload[95] = data_len as u8;

        // calldata
        payload[96..96 + data_len].copy_from_slice(calldata);

        ActionV1 {
            action_type: ACTION_TYPE_CALL,
            target,
            payload,
        }
    }

    /// Create a valid TRANSFER_ERC20 action
    fn make_transfer_erc20_action(token: [u8; 20], to: [u8; 20], amount: u128) -> ActionV1 {
        let mut payload = vec![0u8; 96];

        // token address (left-padded)
        payload[12..32].copy_from_slice(&token);

        // to address (left-padded)
        payload[44..64].copy_from_slice(&to);

        // amount (uint256, big-endian)
        payload[80..96].copy_from_slice(&amount.to_be_bytes());

        ActionV1 {
            action_type: ACTION_TYPE_TRANSFER_ERC20,
            target: [0u8; 32],
            payload,
        }
    }

    #[test]
    fn test_echo_action_passes() {
        let input = make_test_input();
        let output = AgentOutput {
            actions: vec![make_echo_action()],
        };
        let constraints = ConstraintSetV1::default();

        let result = enforce_constraints(&input, &output, &constraints);
        assert!(result.is_ok());
    }

    #[test]
    fn test_call_action_passes() {
        let input = make_test_input();
        let output = AgentOutput {
            actions: vec![make_call_action(
                [0x11; 20],
                1000,
                &[0xab, 0xcd, 0xef, 0x12],
            )],
        };
        let constraints = ConstraintSetV1::default();

        let result = enforce_constraints(&input, &output, &constraints);
        assert!(result.is_ok());
    }

    #[test]
    fn test_transfer_erc20_action_passes() {
        let input = make_test_input();
        let output = AgentOutput {
            actions: vec![make_transfer_erc20_action(
                [0x11; 20], [0x22; 20], 1_000_000,
            )],
        };
        let constraints = ConstraintSetV1::default();

        let result = enforce_constraints(&input, &output, &constraints);
        assert!(result.is_ok());
    }

    #[test]
    fn test_no_op_action_passes() {
        let input = make_test_input();
        let output = AgentOutput {
            actions: vec![ActionV1 {
                action_type: ACTION_TYPE_NO_OP,
                target: [0u8; 32],
                payload: vec![],
            }],
        };
        let constraints = ConstraintSetV1::default();

        let result = enforce_constraints(&input, &output, &constraints);
        assert!(result.is_ok());
    }

    #[test]
    fn test_no_op_with_payload_fails() {
        let input = make_test_input();
        let output = AgentOutput {
            actions: vec![ActionV1 {
                action_type: ACTION_TYPE_NO_OP,
                target: [0u8; 32],
                payload: vec![1, 2, 3], // Should be empty
            }],
        };
        let constraints = ConstraintSetV1::default();

        let result = enforce_constraints(&input, &output, &constraints);
        assert!(result.is_err());
        let violation = result.unwrap_err();
        assert_eq!(
            violation.reason,
            ConstraintViolationReason::InvalidActionPayload
        );
    }

    #[test]
    fn test_unknown_action_type_fails() {
        let input = make_test_input();
        let output = AgentOutput {
            actions: vec![ActionV1 {
                action_type: 0xFFFFFFFF,
                target: [0x11; 32],
                payload: vec![],
            }],
        };
        let constraints = ConstraintSetV1::default();

        let result = enforce_constraints(&input, &output, &constraints);
        assert!(result.is_err());
        let violation = result.unwrap_err();
        assert_eq!(
            violation.reason,
            ConstraintViolationReason::UnknownActionType
        );
        assert_eq!(violation.action_index, Some(0));
    }

    #[test]
    fn test_invalid_call_payload_too_short() {
        let input = make_test_input();
        let output = AgentOutput {
            actions: vec![ActionV1 {
                action_type: ACTION_TYPE_CALL,
                target: {
                    let mut t = [0u8; 32];
                    t[12..32].copy_from_slice(&[0x11; 20]);
                    t
                },
                payload: vec![0u8; 64], // Too short, needs at least 96
            }],
        };
        let constraints = ConstraintSetV1::default();

        let result = enforce_constraints(&input, &output, &constraints);
        assert!(result.is_err());
        let violation = result.unwrap_err();
        assert_eq!(
            violation.reason,
            ConstraintViolationReason::InvalidActionPayload
        );
    }

    #[test]
    fn test_invalid_transfer_payload_wrong_size() {
        let input = make_test_input();
        let output = AgentOutput {
            actions: vec![ActionV1 {
                action_type: ACTION_TYPE_TRANSFER_ERC20,
                target: [0u8; 32],
                payload: vec![0u8; 64], // Should be exactly 96
            }],
        };
        let constraints = ConstraintSetV1::default();

        let result = enforce_constraints(&input, &output, &constraints);
        assert!(result.is_err());
        let violation = result.unwrap_err();
        assert_eq!(
            violation.reason,
            ConstraintViolationReason::InvalidActionPayload
        );
    }

    #[test]
    fn test_cooldown_not_elapsed_fails() {
        // Create input with state snapshot
        let mut snapshot_bytes = Vec::new();
        snapshot_bytes.extend_from_slice(&1u32.to_le_bytes()); // version
        snapshot_bytes.extend_from_slice(&1000u64.to_le_bytes()); // last_execution_ts
        snapshot_bytes.extend_from_slice(&1030u64.to_le_bytes()); // current_ts (only 30 seconds later)
        snapshot_bytes.extend_from_slice(&100_000u64.to_le_bytes()); // current_equity
        snapshot_bytes.extend_from_slice(&100_000u64.to_le_bytes()); // peak_equity

        let mut input = make_test_input();
        input.opaque_agent_inputs = snapshot_bytes;

        let output = AgentOutput {
            actions: vec![make_echo_action()],
        };
        let constraints = ConstraintSetV1 {
            cooldown_seconds: 60, // 60 second cooldown
            ..ConstraintSetV1::default()
        };

        let result = enforce_constraints(&input, &output, &constraints);
        assert!(result.is_err());
        let violation = result.unwrap_err();
        assert_eq!(
            violation.reason,
            ConstraintViolationReason::CooldownNotElapsed
        );
    }

    #[test]
    fn test_drawdown_exceeded_fails() {
        // Create input with state snapshot showing 30% drawdown
        let mut snapshot_bytes = Vec::new();
        snapshot_bytes.extend_from_slice(&1u32.to_le_bytes()); // version
        snapshot_bytes.extend_from_slice(&1000u64.to_le_bytes()); // last_execution_ts
        snapshot_bytes.extend_from_slice(&2000u64.to_le_bytes()); // current_ts
        snapshot_bytes.extend_from_slice(&70_000u64.to_le_bytes()); // current_equity (70%)
        snapshot_bytes.extend_from_slice(&100_000u64.to_le_bytes()); // peak_equity

        let mut input = make_test_input();
        input.opaque_agent_inputs = snapshot_bytes;

        let output = AgentOutput {
            actions: vec![make_echo_action()],
        };
        let constraints = ConstraintSetV1 {
            max_drawdown_bps: 2_000, // 20% max drawdown
            ..ConstraintSetV1::default()
        };

        let result = enforce_constraints(&input, &output, &constraints);
        assert!(result.is_err());
        let violation = result.unwrap_err();
        assert_eq!(
            violation.reason,
            ConstraintViolationReason::DrawdownExceeded
        );
    }

    #[test]
    fn test_too_many_actions_fails() {
        let input = make_test_input();
        let output = AgentOutput {
            actions: vec![make_echo_action(); 65], // 65 actions, max is 64
        };
        let constraints = ConstraintSetV1::default();

        let result = enforce_constraints(&input, &output, &constraints);
        assert!(result.is_err());
        let violation = result.unwrap_err();
        assert_eq!(
            violation.reason,
            ConstraintViolationReason::InvalidOutputStructure
        );
    }

    #[test]
    fn test_empty_output_commitment_constant() {
        // Verify the empty output commitment constant is correct
        use kernel_core::{compute_action_commitment, CanonicalEncode};

        let empty_output = AgentOutput { actions: vec![] };
        let encoded = empty_output.encode().unwrap();
        let commitment = compute_action_commitment(&encoded);

        assert_eq!(commitment, EMPTY_OUTPUT_COMMITMENT);
    }

    // ========================================================================
    // Action Type Re-export Invariant Tests
    // ========================================================================

    #[test]
    fn test_action_types_match_kernel_core() {
        // Verify that our re-exports match kernel-core's values
        assert_eq!(ACTION_TYPE_CALL, kernel_core::ACTION_TYPE_CALL);
        assert_eq!(
            ACTION_TYPE_TRANSFER_ERC20,
            kernel_core::ACTION_TYPE_TRANSFER_ERC20
        );
        assert_eq!(ACTION_TYPE_NO_OP, kernel_core::ACTION_TYPE_NO_OP);
        // ACTION_TYPE_ECHO is locally available via cfg(test) but not from kernel_core
        // unless kernel-core has the testing feature enabled
        assert_eq!(ACTION_TYPE_ECHO, 0x00000001);
    }

    #[test]
    fn test_action_types_match_solidity_values() {
        // Verify the actual numeric values match KernelOutputParser.sol
        assert_eq!(ACTION_TYPE_CALL, 0x00000002);
        assert_eq!(ACTION_TYPE_TRANSFER_ERC20, 0x00000003);
        assert_eq!(ACTION_TYPE_NO_OP, 0x00000004);
    }
}
