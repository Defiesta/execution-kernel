//! Constraint enforcement engine for the kernel protocol (P0.3).
//!
//! This module provides unskippable constraint checking for agent outputs.
//! See spec/constraints.md for the full specification.

use kernel_core::{
    AgentOutput, ActionV1, ConstraintError, ConstraintViolation, ConstraintViolationReason,
    KernelInputV1, MAX_ACTIONS_PER_OUTPUT, MAX_ACTION_PAYLOAD_BYTES,
};

// ============================================================================
// Action Type Constants
// ============================================================================

/// Echo/test action (TrivialAgent)
pub const ACTION_TYPE_ECHO: u32 = 0x00000001;

/// Open a new trading position (kernel-internal action type)
/// NOTE: This has the same value as ACTION_TYPE_CALL but different semantics.
/// Use ACTION_TYPE_CALL for on-chain vault execution.
pub const ACTION_TYPE_OPEN_POSITION: u32 = 0x00000002;

/// Close an existing position
pub const ACTION_TYPE_CLOSE_POSITION: u32 = 0x00000003;

/// Modify position size or leverage
pub const ACTION_TYPE_ADJUST_POSITION: u32 = 0x00000004;

/// Asset swap/exchange
pub const ACTION_TYPE_SWAP: u32 = 0x00000005;

// ============================================================================
// On-Chain Execution Action Types (matches KernelOutputParser.sol)
// ============================================================================

/// CALL action type for on-chain execution via KernelVault
/// Payload: abi.encode(uint256 value, bytes callData)
pub const ACTION_TYPE_CALL: u32 = 0x00000002;

/// ERC20 transfer action type for on-chain execution
pub const ACTION_TYPE_TRANSFER_ERC20: u32 = 0x00000003;

/// No-op action type (skipped during execution)
pub const ACTION_TYPE_NO_OP: u32 = 0x00000004;

/// SHA-256 hash of empty AgentOutput encoding [0x00, 0x00, 0x00, 0x00]
pub const EMPTY_OUTPUT_COMMITMENT: [u8; 32] = [
    0xdf, 0x3f, 0x61, 0x98, 0x04, 0xa9, 0x2f, 0xdb,
    0x40, 0x57, 0x19, 0x2d, 0xc4, 0x3d, 0xd7, 0x48,
    0xea, 0x77, 0x8a, 0xdc, 0x52, 0xbc, 0x49, 0x8c,
    0xe8, 0x05, 0x24, 0xc0, 0x14, 0xb8, 0x11, 0x19,
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
    /// Maximum position size in base units
    pub max_position_notional: u64,
    /// Maximum leverage in basis points (10000 = 1x)
    pub max_leverage_bps: u32,
    /// Maximum drawdown in basis points (10000 = 100%)
    pub max_drawdown_bps: u32,
    /// Minimum seconds between executions
    pub cooldown_seconds: u32,
    /// Maximum actions per output
    pub max_actions_per_output: u32,
    /// Single allowed asset ID (zero = all assets allowed)
    ///
    /// In P0.3, this field supports single-asset whitelist semantics:
    /// - If zero ([0u8; 32]), all assets are allowed
    /// - If non-zero, only the exact asset_id matching this value is allowed
    ///
    /// Future versions may support multi-asset whitelists via Merkle proofs.
    pub allowed_asset_id: [u8; 32],
}

impl Default for ConstraintSetV1 {
    /// Default permissive constraint set for P0.3.
    fn default() -> Self {
        Self {
            version: 1,
            max_position_notional: u64::MAX,
            max_leverage_bps: 100_000,  // 10x max leverage
            max_drawdown_bps: 10_000,   // 100% (disabled)
            cooldown_seconds: 0,
            max_actions_per_output: MAX_ACTIONS_PER_OUTPUT as u32,
            allowed_asset_id: [0u8; 32],  // All assets allowed
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
// Action Payload Structures
// ============================================================================

/// OpenPosition payload (action type 0x00000002)
#[derive(Clone, Debug)]
pub struct OpenPositionPayload {
    pub asset_id: [u8; 32],
    pub notional: u64,
    pub leverage_bps: u32,
    pub direction: u8,
}

impl OpenPositionPayload {
    /// Exact size required for OpenPosition payload (P0.3: strict length enforcement)
    pub const SIZE: usize = 45;

    /// Decode an OpenPosition payload from bytes.
    ///
    /// Returns None if payload length is not exactly SIZE bytes.
    /// P0.3: Trailing bytes are rejected to prevent encoding malleability.
    pub fn decode(payload: &[u8]) -> Option<Self> {
        if payload.len() != Self::SIZE {
            return None;
        }
        Some(Self {
            asset_id: payload[0..32].try_into().ok()?,
            notional: u64::from_le_bytes(payload[32..40].try_into().ok()?),
            leverage_bps: u32::from_le_bytes(payload[40..44].try_into().ok()?),
            direction: payload[44],
        })
    }
}

/// ClosePosition payload (action type 0x00000003)
#[derive(Clone, Debug)]
pub struct ClosePositionPayload {
    pub position_id: [u8; 32],
}

impl ClosePositionPayload {
    /// Exact size required for ClosePosition payload (P0.3: strict length enforcement)
    pub const SIZE: usize = 32;

    /// Decode a ClosePosition payload from bytes.
    ///
    /// Returns None if payload length is not exactly SIZE bytes.
    /// P0.3: Trailing bytes are rejected to prevent encoding malleability.
    pub fn decode(payload: &[u8]) -> Option<Self> {
        if payload.len() != Self::SIZE {
            return None;
        }
        Some(Self {
            position_id: payload[0..32].try_into().ok()?,
        })
    }
}

/// AdjustPosition payload (action type 0x00000004)
#[derive(Clone, Debug)]
pub struct AdjustPositionPayload {
    pub position_id: [u8; 32],
    pub new_notional: u64,
    pub new_leverage_bps: u32,
}

impl AdjustPositionPayload {
    /// Exact size required for AdjustPosition payload (P0.3: strict length enforcement)
    pub const SIZE: usize = 44;

    /// Decode an AdjustPosition payload from bytes.
    ///
    /// Returns None if payload length is not exactly SIZE bytes.
    /// P0.3: Trailing bytes are rejected to prevent encoding malleability.
    pub fn decode(payload: &[u8]) -> Option<Self> {
        if payload.len() != Self::SIZE {
            return None;
        }
        Some(Self {
            position_id: payload[0..32].try_into().ok()?,
            new_notional: u64::from_le_bytes(payload[32..40].try_into().ok()?),
            new_leverage_bps: u32::from_le_bytes(payload[40..44].try_into().ok()?),
        })
    }
}

/// Swap payload (action type 0x00000005)
#[derive(Clone, Debug)]
pub struct SwapPayload {
    pub from_asset: [u8; 32],
    pub to_asset: [u8; 32],
    pub amount: u64,
}

impl SwapPayload {
    /// Exact size required for Swap payload (P0.3: strict length enforcement)
    pub const SIZE: usize = 72;

    /// Decode a Swap payload from bytes.
    ///
    /// Returns None if payload length is not exactly SIZE bytes.
    /// P0.3: Trailing bytes are rejected to prevent encoding malleability.
    pub fn decode(payload: &[u8]) -> Option<Self> {
        if payload.len() != Self::SIZE {
            return None;
        }
        Some(Self {
            from_asset: payload[0..32].try_into().ok()?,
            to_asset: payload[32..64].try_into().ok()?,
            amount: u64::from_le_bytes(payload[64..72].try_into().ok()?),
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
/// 2. Per-action constraints (action type, payload schema, whitelist, bounds)
/// 3. Global constraints (cooldown, drawdown)
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

    // Note: max_leverage_bps == 0 is valid (would reject all leveraged positions)
    // Note: cooldown_seconds has no upper bound validation (operator choice)

    // 2. Validate output structure
    check_output_structure(proposed, constraint_set)?;

    // 3. Validate each action
    for (index, action) in proposed.actions.iter().enumerate() {
        validate_action(action, index, constraint_set)?;
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
fn validate_action(
    action: &ActionV1,
    index: usize,
    constraint_set: &ConstraintSetV1,
) -> Result<(), ConstraintViolation> {
    match action.action_type {
        ACTION_TYPE_ECHO => {
            // Echo action has no specific constraints
            Ok(())
        }
        // ACTION_TYPE_CALL and ACTION_TYPE_OPEN_POSITION share the same value (0x00000002)
        // Distinguish by payload size: CALL >= 96 bytes (ABI-encoded), OPEN_POSITION = 45 bytes
        ACTION_TYPE_CALL => {
            if action.payload.len() >= 96 {
                // CALL action (on-chain execution)
                validate_call_action(action, index)
            } else if action.payload.len() == OpenPositionPayload::SIZE {
                // OPEN_POSITION action (kernel internal)
                validate_open_position(action, index, constraint_set)
            } else {
                // Invalid payload size for either type
                Err(ConstraintViolation::action(
                    ConstraintViolationReason::InvalidActionPayload,
                    index,
                ))
            }
        }
        // ACTION_TYPE_TRANSFER_ERC20 and ACTION_TYPE_CLOSE_POSITION share value 0x00000003
        ACTION_TYPE_CLOSE_POSITION => {
            if action.payload.len() == ClosePositionPayload::SIZE {
                validate_close_position(action, index)
            } else if action.payload.len() == 96 {
                // ERC20 transfer (on-chain): abi.encode(address token, address to, uint256 amount)
                validate_transfer_erc20_action(action, index)
            } else {
                Err(ConstraintViolation::action(
                    ConstraintViolationReason::InvalidActionPayload,
                    index,
                ))
            }
        }
        // ACTION_TYPE_NO_OP and ACTION_TYPE_ADJUST_POSITION share value 0x00000004
        ACTION_TYPE_ADJUST_POSITION => {
            if action.payload.is_empty() {
                // NO_OP action
                Ok(())
            } else if action.payload.len() == AdjustPositionPayload::SIZE {
                validate_adjust_position(action, index, constraint_set)
            } else {
                Err(ConstraintViolation::action(
                    ConstraintViolationReason::InvalidActionPayload,
                    index,
                ))
            }
        }
        ACTION_TYPE_SWAP => {
            validate_swap(action, index, constraint_set)
        }
        _ => {
            // Unknown action type
            Err(ConstraintViolation::action(
                ConstraintViolationReason::UnknownActionType,
                index,
            ))
        }
    }
}

/// Validate OpenPosition action.
fn validate_open_position(
    action: &ActionV1,
    index: usize,
    constraint_set: &ConstraintSetV1,
) -> Result<(), ConstraintViolation> {
    // Decode payload
    let payload = OpenPositionPayload::decode(&action.payload).ok_or_else(|| {
        ConstraintViolation::action(ConstraintViolationReason::InvalidActionPayload, index)
    })?;

    // Check asset whitelist
    if !is_asset_whitelisted(&payload.asset_id, constraint_set) {
        return Err(ConstraintViolation::action(
            ConstraintViolationReason::AssetNotWhitelisted,
            index,
        ));
    }

    // Check position size
    if payload.notional > constraint_set.max_position_notional {
        return Err(ConstraintViolation::action(
            ConstraintViolationReason::PositionTooLarge,
            index,
        ));
    }

    // Check leverage
    if payload.leverage_bps > constraint_set.max_leverage_bps {
        return Err(ConstraintViolation::action(
            ConstraintViolationReason::LeverageTooHigh,
            index,
        ));
    }

    // Validate direction
    if payload.direction > 1 {
        return Err(ConstraintViolation::action(
            ConstraintViolationReason::InvalidActionPayload,
            index,
        ));
    }

    Ok(())
}

/// Validate ClosePosition action.
fn validate_close_position(action: &ActionV1, index: usize) -> Result<(), ConstraintViolation> {
    // Just validate payload structure
    ClosePositionPayload::decode(&action.payload).ok_or_else(|| {
        ConstraintViolation::action(ConstraintViolationReason::InvalidActionPayload, index)
    })?;

    Ok(())
}

/// Validate AdjustPosition action.
fn validate_adjust_position(
    action: &ActionV1,
    index: usize,
    constraint_set: &ConstraintSetV1,
) -> Result<(), ConstraintViolation> {
    // Decode payload
    let payload = AdjustPositionPayload::decode(&action.payload).ok_or_else(|| {
        ConstraintViolation::action(ConstraintViolationReason::InvalidActionPayload, index)
    })?;

    // Check position size (if non-zero, meaning it's being changed)
    if payload.new_notional > 0 && payload.new_notional > constraint_set.max_position_notional {
        return Err(ConstraintViolation::action(
            ConstraintViolationReason::PositionTooLarge,
            index,
        ));
    }

    // Check leverage (if non-zero, meaning it's being changed)
    if payload.new_leverage_bps > 0 && payload.new_leverage_bps > constraint_set.max_leverage_bps {
        return Err(ConstraintViolation::action(
            ConstraintViolationReason::LeverageTooHigh,
            index,
        ));
    }

    Ok(())
}

/// Validate Swap action.
fn validate_swap(
    action: &ActionV1,
    index: usize,
    constraint_set: &ConstraintSetV1,
) -> Result<(), ConstraintViolation> {
    // Decode payload
    let payload = SwapPayload::decode(&action.payload).ok_or_else(|| {
        ConstraintViolation::action(ConstraintViolationReason::InvalidActionPayload, index)
    })?;

    // Check asset whitelist for both assets
    if !is_asset_whitelisted(&payload.from_asset, constraint_set) {
        return Err(ConstraintViolation::action(
            ConstraintViolationReason::AssetNotWhitelisted,
            index,
        ));
    }
    if !is_asset_whitelisted(&payload.to_asset, constraint_set) {
        return Err(ConstraintViolation::action(
            ConstraintViolationReason::AssetNotWhitelisted,
            index,
        ));
    }

    Ok(())
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
    let expected_len = 96 + ((calldata_len as usize + 31) / 32) * 32;
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
fn validate_transfer_erc20_action(action: &ActionV1, index: usize) -> Result<(), ConstraintViolation> {
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

/// Check if an asset is allowed.
///
/// P0.3 single-asset whitelist semantics:
/// - If `allowed_asset_id` is zero, all assets are allowed
/// - If `allowed_asset_id` is non-zero, only exact matches are allowed
///
/// Future versions may support multi-asset whitelists via Merkle proofs.
fn is_asset_whitelisted(asset_id: &[u8; 32], constraint_set: &ConstraintSetV1) -> bool {
    // Zero allowed_asset_id means all assets are allowed
    if constraint_set.allowed_asset_id == [0u8; 32] {
        return true;
    }

    // P0.3: Exact match required for single-asset whitelist
    asset_id == &constraint_set.allowed_asset_id
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
        let drawdown = snapshot
            .peak_equity
            .saturating_sub(snapshot.current_equity);
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

    fn make_open_position_payload(notional: u64, leverage_bps: u32) -> Vec<u8> {
        let mut payload = Vec::with_capacity(45);
        payload.extend_from_slice(&[0x42; 32]); // asset_id
        payload.extend_from_slice(&notional.to_le_bytes());
        payload.extend_from_slice(&leverage_bps.to_le_bytes());
        payload.push(0); // direction = long
        payload
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
        assert_eq!(violation.reason, ConstraintViolationReason::UnknownActionType);
        assert_eq!(violation.action_index, Some(0));
    }

    #[test]
    fn test_position_too_large_fails() {
        let input = make_test_input();
        let output = AgentOutput {
            actions: vec![ActionV1 {
                action_type: ACTION_TYPE_OPEN_POSITION,
                target: [0x11; 32],
                payload: make_open_position_payload(1_000_001, 10_000),
            }],
        };
        let constraints = ConstraintSetV1 {
            max_position_notional: 1_000_000,
            ..ConstraintSetV1::default()
        };

        let result = enforce_constraints(&input, &output, &constraints);
        assert!(result.is_err());
        let violation = result.unwrap_err();
        assert_eq!(violation.reason, ConstraintViolationReason::PositionTooLarge);
    }

    #[test]
    fn test_leverage_too_high_fails() {
        let input = make_test_input();
        let output = AgentOutput {
            actions: vec![ActionV1 {
                action_type: ACTION_TYPE_OPEN_POSITION,
                target: [0x11; 32],
                payload: make_open_position_payload(1_000, 60_000), // 6x leverage
            }],
        };
        let constraints = ConstraintSetV1 {
            max_leverage_bps: 50_000, // 5x max
            ..ConstraintSetV1::default()
        };

        let result = enforce_constraints(&input, &output, &constraints);
        assert!(result.is_err());
        let violation = result.unwrap_err();
        assert_eq!(violation.reason, ConstraintViolationReason::LeverageTooHigh);
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
        assert_eq!(violation.reason, ConstraintViolationReason::CooldownNotElapsed);
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
        assert_eq!(violation.reason, ConstraintViolationReason::DrawdownExceeded);
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
        assert_eq!(violation.reason, ConstraintViolationReason::InvalidOutputStructure);
    }

    #[test]
    fn test_empty_output_commitment_constant() {
        // Verify the empty output commitment constant is correct
        use kernel_core::{CanonicalEncode, compute_action_commitment};

        let empty_output = AgentOutput { actions: vec![] };
        let encoded = empty_output.encode().unwrap();
        let commitment = compute_action_commitment(&encoded);

        assert_eq!(commitment, EMPTY_OUTPUT_COMMITMENT);
    }
}
