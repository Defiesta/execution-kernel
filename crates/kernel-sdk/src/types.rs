//! Type definitions and re-exports for agent development.
//!
//! This module provides the core types that agents use to produce output:
//! - [`AgentOutput`] - The structured output returned by agents
//! - [`ActionV1`] - Individual actions within the output
//!
//! # Action Types
//!
//! The following action type constants are provided:
//! - [`ACTION_TYPE_ECHO`] - Echo/test action (0x00000001)
//! - [`ACTION_TYPE_OPEN_POSITION`] - Open a trading position (0x00000002)
//! - [`ACTION_TYPE_CLOSE_POSITION`] - Close a position (0x00000003)
//! - [`ACTION_TYPE_ADJUST_POSITION`] - Modify position size/leverage (0x00000004)
//! - [`ACTION_TYPE_SWAP`] - Asset swap/exchange (0x00000005)
//!
//! # Size Limits
//!
//! - [`MAX_ACTIONS_PER_OUTPUT`] - Maximum 64 actions per output
//! - [`MAX_ACTION_PAYLOAD_BYTES`] - Maximum 16,384 bytes per action payload
//!
//! # Payload Decoding
//!
//! For inspecting action payloads, use the `decode_*_payload` helpers:
//! - [`decode_open_position_payload`]
//! - [`decode_close_position_payload`]
//! - [`decode_adjust_position_payload`]
//! - [`decode_swap_payload`]

use alloc::vec::Vec;

// Re-export core types from kernel-core
pub use kernel_core::{
    ActionV1,
    AgentOutput,
    MAX_ACTION_PAYLOAD_BYTES,
    MAX_ACTIONS_PER_OUTPUT,
};

// ============================================================================
// Action Type Constants
// ============================================================================

/// Echo action type (0x00000001).
///
/// Used for testing and debugging. Payload is opaque bytes with no schema.
pub const ACTION_TYPE_ECHO: u32 = 0x00000001;

/// Open position action type (0x00000002).
///
/// Opens a new trading position. Payload schema (45 bytes):
/// - `asset_id`: [u8; 32] - Asset identifier
/// - `notional`: u64 - Position size in base units (little-endian)
/// - `leverage_bps`: u32 - Leverage in basis points (little-endian)
/// - `direction`: u8 - 0 = Long, 1 = Short
pub const ACTION_TYPE_OPEN_POSITION: u32 = 0x00000002;

/// Close position action type (0x00000003).
///
/// Closes an existing position. Payload schema (32 bytes):
/// - `position_id`: [u8; 32] - Position identifier to close
pub const ACTION_TYPE_CLOSE_POSITION: u32 = 0x00000003;

/// Adjust position action type (0x00000004).
///
/// Modifies an existing position. Payload schema (44 bytes):
/// - `position_id`: [u8; 32] - Position identifier
/// - `new_notional`: u64 - New position size (0 = unchanged, little-endian)
/// - `new_leverage_bps`: u32 - New leverage (0 = unchanged, little-endian)
pub const ACTION_TYPE_ADJUST_POSITION: u32 = 0x00000004;

/// Swap action type (0x00000005).
///
/// Asset swap/exchange. Payload schema (72 bytes):
/// - `from_asset`: [u8; 32] - Source asset identifier
/// - `to_asset`: [u8; 32] - Destination asset identifier
/// - `amount`: u64 - Amount to swap (little-endian)
pub const ACTION_TYPE_SWAP: u32 = 0x00000005;

// ============================================================================
// Payload Size Constants
// ============================================================================

/// Expected payload size for OpenPosition action (45 bytes).
pub const OPEN_POSITION_PAYLOAD_SIZE: usize = 45;

/// Expected payload size for ClosePosition action (32 bytes).
pub const CLOSE_POSITION_PAYLOAD_SIZE: usize = 32;

/// Expected payload size for AdjustPosition action (44 bytes).
pub const ADJUST_POSITION_PAYLOAD_SIZE: usize = 44;

/// Expected payload size for Swap action (72 bytes).
pub const SWAP_PAYLOAD_SIZE: usize = 72;

// ============================================================================
// Helper Constructors
// ============================================================================

/// Create an Echo action.
///
/// # Arguments
/// * `target` - 32-byte target identifier
/// * `payload` - Arbitrary payload bytes
#[inline]
#[must_use]
pub fn echo_action(target: [u8; 32], payload: Vec<u8>) -> ActionV1 {
    ActionV1 {
        action_type: ACTION_TYPE_ECHO,
        target,
        payload,
    }
}

/// Create an OpenPosition action.
///
/// # Arguments
/// * `target` - 32-byte target (typically contract address)
/// * `asset_id` - 32-byte asset identifier
/// * `notional` - Position size in base units
/// * `leverage_bps` - Leverage in basis points (10000 = 1x)
/// * `direction` - 0 = Long, 1 = Short (values > 1 will fail constraint checks)
///
/// # Panics (debug builds only)
///
/// Debug-asserts that `direction <= 1`. In release builds, invalid directions
/// pass through and will be rejected by the constraint engine.
#[inline]
#[must_use]
pub fn open_position_action(
    target: [u8; 32],
    asset_id: [u8; 32],
    notional: u64,
    leverage_bps: u32,
    direction: u8,
) -> ActionV1 {
    debug_assert!(direction <= 1, "direction must be 0 (Long) or 1 (Short)");

    let mut payload = Vec::with_capacity(OPEN_POSITION_PAYLOAD_SIZE);
    payload.extend_from_slice(&asset_id);
    payload.extend_from_slice(&notional.to_le_bytes());
    payload.extend_from_slice(&leverage_bps.to_le_bytes());
    payload.push(direction);

    debug_assert_eq!(payload.len(), OPEN_POSITION_PAYLOAD_SIZE);

    ActionV1 {
        action_type: ACTION_TYPE_OPEN_POSITION,
        target,
        payload,
    }
}

/// Create a ClosePosition action.
///
/// # Arguments
/// * `target` - 32-byte target (typically contract address)
/// * `position_id` - 32-byte position identifier to close
#[inline]
#[must_use]
pub fn close_position_action(target: [u8; 32], position_id: [u8; 32]) -> ActionV1 {
    ActionV1 {
        action_type: ACTION_TYPE_CLOSE_POSITION,
        target,
        payload: position_id.to_vec(),
    }
}

/// Create an AdjustPosition action.
///
/// # Arguments
/// * `target` - 32-byte target (typically contract address)
/// * `position_id` - 32-byte position identifier
/// * `new_notional` - New position size (0 = unchanged)
/// * `new_leverage_bps` - New leverage in bps (0 = unchanged)
#[inline]
#[must_use]
pub fn adjust_position_action(
    target: [u8; 32],
    position_id: [u8; 32],
    new_notional: u64,
    new_leverage_bps: u32,
) -> ActionV1 {
    let mut payload = Vec::with_capacity(ADJUST_POSITION_PAYLOAD_SIZE);
    payload.extend_from_slice(&position_id);
    payload.extend_from_slice(&new_notional.to_le_bytes());
    payload.extend_from_slice(&new_leverage_bps.to_le_bytes());

    debug_assert_eq!(payload.len(), ADJUST_POSITION_PAYLOAD_SIZE);

    ActionV1 {
        action_type: ACTION_TYPE_ADJUST_POSITION,
        target,
        payload,
    }
}

/// Create a Swap action.
///
/// # Arguments
/// * `target` - 32-byte target (typically DEX contract address)
/// * `from_asset` - 32-byte source asset identifier
/// * `to_asset` - 32-byte destination asset identifier
/// * `amount` - Amount to swap
#[inline]
#[must_use]
pub fn swap_action(
    target: [u8; 32],
    from_asset: [u8; 32],
    to_asset: [u8; 32],
    amount: u64,
) -> ActionV1 {
    let mut payload = Vec::with_capacity(SWAP_PAYLOAD_SIZE);
    payload.extend_from_slice(&from_asset);
    payload.extend_from_slice(&to_asset);
    payload.extend_from_slice(&amount.to_le_bytes());

    debug_assert_eq!(payload.len(), SWAP_PAYLOAD_SIZE);

    ActionV1 {
        action_type: ACTION_TYPE_SWAP,
        target,
        payload,
    }
}

// ============================================================================
// Payload Decode Helpers
// ============================================================================
//
// These decode helpers perform **structural validation only** (correct size
// and byte layout). Semantic validation (e.g., `direction <= 1`, leverage
// bounds) is performed by the constraint engine, not here.
//
// This separation allows agents to inspect payloads without duplicating
// constraint logic.

/// Decoded OpenPosition payload fields.
///
/// Note: This struct contains the raw decoded values. Semantic validation
/// (e.g., `direction <= 1`) is performed by the constraint engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedOpenPosition {
    /// 32-byte asset identifier
    pub asset_id: [u8; 32],
    /// Position size in base units
    pub notional: u64,
    /// Leverage in basis points (10000 = 1x)
    pub leverage_bps: u32,
    /// Direction: 0 = Long, 1 = Short (not validated here)
    pub direction: u8,
}

/// Decoded AdjustPosition payload fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedAdjustPosition {
    /// 32-byte position identifier
    pub position_id: [u8; 32],
    /// New position size (0 = unchanged)
    pub new_notional: u64,
    /// New leverage in basis points (0 = unchanged)
    pub new_leverage_bps: u32,
}

/// Decoded Swap payload fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedSwap {
    /// 32-byte source asset identifier
    pub from_asset: [u8; 32],
    /// 32-byte destination asset identifier
    pub to_asset: [u8; 32],
    /// Amount to swap
    pub amount: u64,
}

/// Decode an OpenPosition action payload.
///
/// Returns `None` if the payload is malformed (wrong size).
///
/// **Note:** This validates layout only; semantic validation (e.g.,
/// `direction <= 1`) is performed by the constraint engine.
#[inline]
#[must_use]
pub fn decode_open_position_payload(payload: &[u8]) -> Option<DecodedOpenPosition> {
    if payload.len() != OPEN_POSITION_PAYLOAD_SIZE {
        return None;
    }

    let asset_id: [u8; 32] = payload[0..32].try_into().ok()?;
    let notional = u64::from_le_bytes(payload[32..40].try_into().ok()?);
    let leverage_bps = u32::from_le_bytes(payload[40..44].try_into().ok()?);
    let direction = payload[44];

    Some(DecodedOpenPosition {
        asset_id,
        notional,
        leverage_bps,
        direction,
    })
}

/// Decode a ClosePosition action payload.
///
/// Returns `None` if the payload is malformed (wrong size).
/// Returns the 32-byte position_id directly.
#[inline]
#[must_use]
pub fn decode_close_position_payload(payload: &[u8]) -> Option<[u8; 32]> {
    if payload.len() != CLOSE_POSITION_PAYLOAD_SIZE {
        return None;
    }
    let arr: [u8; 32] = payload.try_into().ok()?;
    Some(arr)
}

/// Decode an AdjustPosition action payload.
///
/// Returns `None` if the payload is malformed (wrong size).
///
/// **Note:** This validates layout only; semantic validation is performed
/// by the constraint engine.
#[inline]
#[must_use]
pub fn decode_adjust_position_payload(payload: &[u8]) -> Option<DecodedAdjustPosition> {
    if payload.len() != ADJUST_POSITION_PAYLOAD_SIZE {
        return None;
    }

    let position_id: [u8; 32] = payload[0..32].try_into().ok()?;
    let new_notional = u64::from_le_bytes(payload[32..40].try_into().ok()?);
    let new_leverage_bps = u32::from_le_bytes(payload[40..44].try_into().ok()?);

    Some(DecodedAdjustPosition {
        position_id,
        new_notional,
        new_leverage_bps,
    })
}

/// Decode a Swap action payload.
///
/// Returns `None` if the payload is malformed (wrong size).
///
/// **Note:** This validates layout only; semantic validation is performed
/// by the constraint engine.
#[inline]
#[must_use]
pub fn decode_swap_payload(payload: &[u8]) -> Option<DecodedSwap> {
    if payload.len() != SWAP_PAYLOAD_SIZE {
        return None;
    }

    let from_asset: [u8; 32] = payload[0..32].try_into().ok()?;
    let to_asset: [u8; 32] = payload[32..64].try_into().ok()?;
    let amount = u64::from_le_bytes(payload[64..72].try_into().ok()?);

    Some(DecodedSwap {
        from_asset,
        to_asset,
        amount,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_echo_action() {
        let action = echo_action([0x42; 32], alloc::vec![1, 2, 3]);
        assert_eq!(action.action_type, ACTION_TYPE_ECHO);
        assert_eq!(action.target, [0x42; 32]);
        assert_eq!(action.payload, alloc::vec![1, 2, 3]);
    }

    #[test]
    fn test_open_position_action() {
        let action = open_position_action(
            [0x11; 32],
            [0x42; 32],
            1000,
            10000,
            0,
        );

        assert_eq!(action.action_type, ACTION_TYPE_OPEN_POSITION);
        assert_eq!(action.payload.len(), OPEN_POSITION_PAYLOAD_SIZE);

        // Verify payload structure (canonical layout)
        assert_eq!(&action.payload[0..32], &[0x42; 32]); // asset_id
        assert_eq!(&action.payload[32..40], &1000u64.to_le_bytes()); // notional
        assert_eq!(&action.payload[40..44], &10000u32.to_le_bytes()); // leverage
        assert_eq!(action.payload[44], 0); // direction
    }

    #[test]
    fn test_close_position_action() {
        let action = close_position_action([0x11; 32], [0x99; 32]);

        assert_eq!(action.action_type, ACTION_TYPE_CLOSE_POSITION);
        assert_eq!(action.payload.len(), CLOSE_POSITION_PAYLOAD_SIZE);
        assert_eq!(action.payload, [0x99; 32].to_vec());
    }

    #[test]
    fn test_adjust_position_action() {
        let action = adjust_position_action(
            [0x11; 32],
            [0x99; 32],
            2000,
            20000,
        );

        assert_eq!(action.action_type, ACTION_TYPE_ADJUST_POSITION);
        assert_eq!(action.payload.len(), ADJUST_POSITION_PAYLOAD_SIZE);

        // Verify payload structure (canonical layout)
        assert_eq!(&action.payload[0..32], &[0x99; 32]); // position_id
        assert_eq!(&action.payload[32..40], &2000u64.to_le_bytes()); // new_notional
        assert_eq!(&action.payload[40..44], &20000u32.to_le_bytes()); // new_leverage_bps
    }

    #[test]
    fn test_swap_action() {
        let action = swap_action(
            [0x11; 32],
            [0xaa; 32],
            [0xbb; 32],
            5000,
        );

        assert_eq!(action.action_type, ACTION_TYPE_SWAP);
        assert_eq!(action.payload.len(), SWAP_PAYLOAD_SIZE);

        // Verify payload structure (canonical layout)
        assert_eq!(&action.payload[0..32], &[0xaa; 32]); // from_asset
        assert_eq!(&action.payload[32..64], &[0xbb; 32]); // to_asset
        assert_eq!(&action.payload[64..72], &5000u64.to_le_bytes()); // amount
    }

    #[test]
    fn test_agent_output_construction() {
        let output = AgentOutput {
            actions: alloc::vec![
                echo_action([0x42; 32], alloc::vec![1]),
                echo_action([0x43; 32], alloc::vec![2]),
            ],
        };

        assert_eq!(output.actions.len(), 2);
    }

    // ========================================================================
    // Decode Helper Tests
    // ========================================================================

    #[test]
    fn test_decode_open_position_payload() {
        let action = open_position_action(
            [0x11; 32],
            [0x42; 32],
            1000,
            10000,
            1, // Short
        );

        let decoded = decode_open_position_payload(&action.payload).unwrap();
        assert_eq!(decoded.asset_id, [0x42; 32]);
        assert_eq!(decoded.notional, 1000);
        assert_eq!(decoded.leverage_bps, 10000);
        assert_eq!(decoded.direction, 1);
    }

    #[test]
    fn test_decode_open_position_payload_wrong_size() {
        assert!(decode_open_position_payload(&[0u8; 44]).is_none()); // Too short
        assert!(decode_open_position_payload(&[0u8; 46]).is_none()); // Too long
    }

    #[test]
    fn test_decode_close_position_payload() {
        let action = close_position_action([0x11; 32], [0x99; 32]);

        let decoded = decode_close_position_payload(&action.payload).unwrap();
        assert_eq!(decoded, [0x99; 32]);
    }

    #[test]
    fn test_decode_close_position_payload_wrong_size() {
        assert!(decode_close_position_payload(&[0u8; 31]).is_none());
        assert!(decode_close_position_payload(&[0u8; 33]).is_none());
    }

    #[test]
    fn test_decode_adjust_position_payload() {
        let action = adjust_position_action(
            [0x11; 32],
            [0x99; 32],
            2000,
            20000,
        );

        let decoded = decode_adjust_position_payload(&action.payload).unwrap();
        assert_eq!(decoded.position_id, [0x99; 32]);
        assert_eq!(decoded.new_notional, 2000);
        assert_eq!(decoded.new_leverage_bps, 20000);
    }

    #[test]
    fn test_decode_adjust_position_payload_wrong_size() {
        assert!(decode_adjust_position_payload(&[0u8; 43]).is_none());
        assert!(decode_adjust_position_payload(&[0u8; 45]).is_none());
    }

    #[test]
    fn test_decode_swap_payload() {
        let action = swap_action(
            [0x11; 32],
            [0xaa; 32],
            [0xbb; 32],
            5000,
        );

        let decoded = decode_swap_payload(&action.payload).unwrap();
        assert_eq!(decoded.from_asset, [0xaa; 32]);
        assert_eq!(decoded.to_asset, [0xbb; 32]);
        assert_eq!(decoded.amount, 5000);
    }

    #[test]
    fn test_decode_swap_payload_wrong_size() {
        assert!(decode_swap_payload(&[0u8; 71]).is_none());
        assert!(decode_swap_payload(&[0u8; 73]).is_none());
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        // OpenPosition roundtrip
        let op_action = open_position_action([0x11; 32], [0x42; 32], 9999, 50000, 0);
        let op_decoded = decode_open_position_payload(&op_action.payload).unwrap();
        assert_eq!(op_decoded.asset_id, [0x42; 32]);
        assert_eq!(op_decoded.notional, 9999);
        assert_eq!(op_decoded.leverage_bps, 50000);
        assert_eq!(op_decoded.direction, 0);

        // AdjustPosition roundtrip
        let adj_action = adjust_position_action([0x11; 32], [0x88; 32], 12345, 30000);
        let adj_decoded = decode_adjust_position_payload(&adj_action.payload).unwrap();
        assert_eq!(adj_decoded.position_id, [0x88; 32]);
        assert_eq!(adj_decoded.new_notional, 12345);
        assert_eq!(adj_decoded.new_leverage_bps, 30000);

        // Swap roundtrip
        let swap = swap_action([0x11; 32], [0xcc; 32], [0xdd; 32], 77777);
        let swap_decoded = decode_swap_payload(&swap.payload).unwrap();
        assert_eq!(swap_decoded.from_asset, [0xcc; 32]);
        assert_eq!(swap_decoded.to_asset, [0xdd; 32]);
        assert_eq!(swap_decoded.amount, 77777);
    }
}
