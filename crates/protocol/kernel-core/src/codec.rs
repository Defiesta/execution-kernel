//! Canonical binary codec.
//!
//! See `spec/codec.md` for encoding specification.
//!
//! # Canonical Ordering
//!
//! Actions in `AgentOutput` are treated as an **unordered set** for commitment
//! purposes. The kernel sorts actions into canonical order before encoding to
//! ensure deterministic `action_commitment` regardless of agent-provided order.
//!
//! **Implication**: Agents cannot rely on action ordering for "do X then Y"
//! semantics. The constraint engine evaluates actions in canonical sorted order,
//! and `violation_action_index` refers to the position in that sorted order.

use crate::types::*;
use crate::{KERNEL_VERSION, MAX_AGENT_INPUT_BYTES, MAX_AGENT_OUTPUT_BYTES, PROTOCOL_VERSION};
use alloc::vec::Vec;

// ============================================================================
// Helper Functions - Encoding
// ============================================================================

/// Encode a u32 as little-endian bytes and append to buffer.
#[inline]
pub fn put_u32_le(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_le_bytes());
}

/// Encode a u64 as little-endian bytes and append to buffer.
#[inline]
pub fn put_u64_le(buf: &mut Vec<u8>, value: u64) {
    buf.extend_from_slice(&value.to_le_bytes());
}

/// Append a 32-byte array to buffer.
#[inline]
pub fn put_bytes32(buf: &mut Vec<u8>, bytes: &[u8; 32]) {
    buf.extend_from_slice(bytes);
}

/// Encode variable-length bytes with u32 length prefix.
/// Returns error if data exceeds max_len.
#[inline]
pub fn put_var_bytes(buf: &mut Vec<u8>, data: &[u8], max_len: usize) -> Result<(), CodecError> {
    let len = data.len();
    if len > max_len {
        return Err(CodecError::InputTooLarge {
            size: len.min(u32::MAX as usize) as u32,
            limit: max_len,
        });
    }
    if len > u32::MAX as usize {
        return Err(CodecError::ArithmeticOverflow);
    }
    put_u32_le(buf, len as u32);
    buf.extend_from_slice(data);
    Ok(())
}

// ============================================================================
// Helper Functions - Decoding
// ============================================================================

/// Decode a u32 from little-endian bytes at offset.
/// Advances offset by 4 on success.
#[inline]
pub fn get_u32_le(bytes: &[u8], offset: &mut usize) -> Result<u32, CodecError> {
    let end = offset
        .checked_add(4)
        .ok_or(CodecError::ArithmeticOverflow)?;
    if end > bytes.len() {
        return Err(CodecError::UnexpectedEndOfInput);
    }
    let value = u32::from_le_bytes(
        bytes[*offset..end]
            .try_into()
            .map_err(|_| CodecError::UnexpectedEndOfInput)?,
    );
    *offset = end;
    Ok(value)
}

/// Decode a u64 from little-endian bytes at offset.
/// Advances offset by 8 on success.
#[inline]
pub fn get_u64_le(bytes: &[u8], offset: &mut usize) -> Result<u64, CodecError> {
    let end = offset
        .checked_add(8)
        .ok_or(CodecError::ArithmeticOverflow)?;
    if end > bytes.len() {
        return Err(CodecError::UnexpectedEndOfInput);
    }
    let value = u64::from_le_bytes(
        bytes[*offset..end]
            .try_into()
            .map_err(|_| CodecError::UnexpectedEndOfInput)?,
    );
    *offset = end;
    Ok(value)
}

/// Decode a 32-byte array at offset.
/// Advances offset by 32 on success.
#[inline]
pub fn get_bytes32(bytes: &[u8], offset: &mut usize) -> Result<[u8; 32], CodecError> {
    let end = offset
        .checked_add(32)
        .ok_or(CodecError::ArithmeticOverflow)?;
    if end > bytes.len() {
        return Err(CodecError::UnexpectedEndOfInput);
    }
    let value: [u8; 32] = bytes[*offset..end]
        .try_into()
        .map_err(|_| CodecError::UnexpectedEndOfInput)?;
    *offset = end;
    Ok(value)
}

/// Decode a u8 at offset.
/// Advances offset by 1 on success.
#[inline]
pub fn get_u8(bytes: &[u8], offset: &mut usize) -> Result<u8, CodecError> {
    if *offset >= bytes.len() {
        return Err(CodecError::UnexpectedEndOfInput);
    }
    let value = bytes[*offset];
    *offset += 1;
    Ok(value)
}

/// Decode variable-length bytes with u32 length prefix.
/// Advances offset by 4 + length on success.
/// Returns error if length exceeds max_len.
#[inline]
pub fn get_var_bytes(
    bytes: &[u8],
    offset: &mut usize,
    max_len: usize,
) -> Result<Vec<u8>, CodecError> {
    let len_u32 = get_u32_le(bytes, offset)?;

    if len_u32 > max_len as u32 {
        return Err(CodecError::InputTooLarge {
            size: len_u32,
            limit: max_len,
        });
    }

    let len = len_u32 as usize;
    let end = offset
        .checked_add(len)
        .ok_or(CodecError::ArithmeticOverflow)?;

    if end > bytes.len() {
        return Err(CodecError::UnexpectedEndOfInput);
    }

    let data = bytes[*offset..end].to_vec();
    *offset = end;
    Ok(data)
}

/// Decode a fixed-length slice at offset.
/// Advances offset by len on success.
#[inline]
pub fn get_slice<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
    len: usize,
) -> Result<&'a [u8], CodecError> {
    let end = offset
        .checked_add(len)
        .ok_or(CodecError::ArithmeticOverflow)?;
    if end > bytes.len() {
        return Err(CodecError::UnexpectedEndOfInput);
    }
    let slice = &bytes[*offset..end];
    *offset = end;
    Ok(slice)
}

/// Ensure there are no trailing bytes after decoding.
/// Returns error if offset does not equal total length.
#[inline]
pub fn ensure_no_trailing_bytes(bytes: &[u8], offset: usize) -> Result<(), CodecError> {
    if offset != bytes.len() {
        return Err(CodecError::InvalidLength);
    }
    Ok(())
}

// ============================================================================
// Traits
// ============================================================================

/// Trait for canonical binary encoding.
///
/// Implementations must produce deterministic, reproducible byte sequences.
pub trait CanonicalEncode {
    /// Compute the exact encoded length.
    ///
    /// This is used for pre-allocation to avoid reallocations during encoding.
    /// Returns an error if the structure cannot be validly encoded (e.g., exceeds size limits).
    fn encoded_len(&self) -> Result<usize, CodecError>;

    /// Append canonical encoding into the provided buffer.
    ///
    /// The buffer is not cleared; bytes are appended to the end.
    fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), CodecError>;

    /// Convenience: allocate a Vec and encode into it.
    fn encode(&self) -> Result<Vec<u8>, CodecError> {
        let len = self.encoded_len()?;
        let mut out = Vec::with_capacity(len);
        self.encode_into(&mut out)?;
        debug_assert_eq!(out.len(), len);
        Ok(out)
    }
}

/// Trait for canonical binary decoding.
pub trait CanonicalDecode: Sized {
    fn decode(bytes: &[u8]) -> Result<Self, CodecError>;
}

// ============================================================================
// KernelInputV1 Codec
// ============================================================================

/// KernelInputV1 encoding layout (little-endian):
/// - protocol_version: u32 (4 bytes)
/// - kernel_version: u32 (4 bytes)
/// - agent_id: [u8; 32] (32 bytes)
/// - agent_code_hash: [u8; 32] (32 bytes)
/// - constraint_set_hash: [u8; 32] (32 bytes)
/// - input_root: [u8; 32] (32 bytes)
/// - execution_nonce: u64 (8 bytes)
/// - opaque_agent_inputs_len: u32 (4 bytes)
/// - opaque_agent_inputs: [u8; len] (variable)
///
/// Fixed header: 144 bytes + 4 byte length prefix + variable input data
/// Minimum size with empty input: 148 bytes
impl CanonicalEncode for KernelInputV1 {
    fn encoded_len(&self) -> Result<usize, CodecError> {
        let data_len = self.opaque_agent_inputs.len();
        if data_len > MAX_AGENT_INPUT_BYTES {
            return Err(CodecError::InputTooLarge {
                size: data_len.min(u32::MAX as usize) as u32,
                limit: MAX_AGENT_INPUT_BYTES,
            });
        }
        // 144 (fixed) + 4 (length prefix) + data_len
        Ok(148 + data_len)
    }

    fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), CodecError> {
        // Validate versions match expected (prevents encoding invalid structures)
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(CodecError::InvalidVersion {
                expected: PROTOCOL_VERSION,
                actual: self.protocol_version,
            });
        }
        if self.kernel_version != KERNEL_VERSION {
            return Err(CodecError::InvalidVersion {
                expected: KERNEL_VERSION,
                actual: self.kernel_version,
            });
        }

        let data_len = self.opaque_agent_inputs.len();
        if data_len > MAX_AGENT_INPUT_BYTES {
            return Err(CodecError::InputTooLarge {
                size: data_len.min(u32::MAX as usize) as u32,
                limit: MAX_AGENT_INPUT_BYTES,
            });
        }
        if data_len > u32::MAX as usize {
            return Err(CodecError::ArithmeticOverflow);
        }

        let before = out.len();

        put_u32_le(out, self.protocol_version);
        put_u32_le(out, self.kernel_version);
        put_bytes32(out, &self.agent_id);
        put_bytes32(out, &self.agent_code_hash);
        put_bytes32(out, &self.constraint_set_hash);
        put_bytes32(out, &self.input_root);
        put_u64_le(out, self.execution_nonce);
        put_u32_le(out, data_len as u32);
        out.extend_from_slice(&self.opaque_agent_inputs);

        debug_assert_eq!(
            out.len() - before,
            self.encoded_len().unwrap(),
            "KernelInputV1: encoded_len() / encode_into() mismatch"
        );
        Ok(())
    }
}

impl CanonicalDecode for KernelInputV1 {
    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        // Minimum size: fixed fields (144) + length prefix (4) = 148 bytes
        if bytes.len() < 148 {
            return Err(CodecError::UnexpectedEndOfInput);
        }

        let mut offset = 0;

        let protocol_version = get_u32_le(bytes, &mut offset)?;
        if protocol_version != PROTOCOL_VERSION {
            return Err(CodecError::InvalidVersion {
                expected: PROTOCOL_VERSION,
                actual: protocol_version,
            });
        }

        let kernel_version = get_u32_le(bytes, &mut offset)?;
        if kernel_version != KERNEL_VERSION {
            return Err(CodecError::InvalidVersion {
                expected: KERNEL_VERSION,
                actual: kernel_version,
            });
        }

        let agent_id = get_bytes32(bytes, &mut offset)?;
        let agent_code_hash = get_bytes32(bytes, &mut offset)?;
        let constraint_set_hash = get_bytes32(bytes, &mut offset)?;
        let input_root = get_bytes32(bytes, &mut offset)?;
        let execution_nonce = get_u64_le(bytes, &mut offset)?;
        let opaque_agent_inputs = get_var_bytes(bytes, &mut offset, MAX_AGENT_INPUT_BYTES)?;

        ensure_no_trailing_bytes(bytes, offset)?;

        Ok(KernelInputV1 {
            protocol_version,
            kernel_version,
            agent_id,
            agent_code_hash,
            constraint_set_hash,
            input_root,
            execution_nonce,
            opaque_agent_inputs,
        })
    }
}

// ============================================================================
// KernelJournalV1 Codec
// ============================================================================

/// KernelJournalV1 encoding layout (little-endian):
/// - protocol_version: u32 (4 bytes)
/// - kernel_version: u32 (4 bytes)
/// - agent_id: [u8; 32] (32 bytes)
/// - agent_code_hash: [u8; 32] (32 bytes)
/// - constraint_set_hash: [u8; 32] (32 bytes)
/// - input_root: [u8; 32] (32 bytes)
/// - execution_nonce: u64 (8 bytes)
/// - input_commitment: [u8; 32] (32 bytes)
/// - action_commitment: [u8; 32] (32 bytes)
/// - execution_status: u8 (1 byte)
///
/// Total fixed size: 4+4+32+32+32+32+8+32+32+1 = 209 bytes
const JOURNAL_SIZE: usize = 209;

impl CanonicalEncode for KernelJournalV1 {
    fn encoded_len(&self) -> Result<usize, CodecError> {
        Ok(JOURNAL_SIZE)
    }

    fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), CodecError> {
        // Validate versions match expected (prevents encoding invalid structures)
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(CodecError::InvalidVersion {
                expected: PROTOCOL_VERSION,
                actual: self.protocol_version,
            });
        }
        if self.kernel_version != KERNEL_VERSION {
            return Err(CodecError::InvalidVersion {
                expected: KERNEL_VERSION,
                actual: self.kernel_version,
            });
        }

        let before = out.len();

        put_u32_le(out, self.protocol_version);
        put_u32_le(out, self.kernel_version);
        put_bytes32(out, &self.agent_id);
        put_bytes32(out, &self.agent_code_hash);
        put_bytes32(out, &self.constraint_set_hash);
        put_bytes32(out, &self.input_root);
        put_u64_le(out, self.execution_nonce);
        put_bytes32(out, &self.input_commitment);
        put_bytes32(out, &self.action_commitment);

        // ExecutionStatus encoding: Success = 0x01, Failure = 0x02
        // 0x00 is reserved to catch uninitialized memory
        out.push(match self.execution_status {
            ExecutionStatus::Success => 0x01,
            ExecutionStatus::Failure => 0x02,
        });

        debug_assert_eq!(
            out.len() - before,
            JOURNAL_SIZE,
            "KernelJournalV1: encoded_len() / encode_into() mismatch"
        );
        Ok(())
    }
}

impl CanonicalDecode for KernelJournalV1 {
    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        if bytes.len() != JOURNAL_SIZE {
            return Err(CodecError::InvalidLength);
        }

        let mut offset = 0;

        let protocol_version = get_u32_le(bytes, &mut offset)?;
        if protocol_version != PROTOCOL_VERSION {
            return Err(CodecError::InvalidVersion {
                expected: PROTOCOL_VERSION,
                actual: protocol_version,
            });
        }

        let kernel_version = get_u32_le(bytes, &mut offset)?;
        if kernel_version != KERNEL_VERSION {
            return Err(CodecError::InvalidVersion {
                expected: KERNEL_VERSION,
                actual: kernel_version,
            });
        }

        let agent_id = get_bytes32(bytes, &mut offset)?;
        let agent_code_hash = get_bytes32(bytes, &mut offset)?;
        let constraint_set_hash = get_bytes32(bytes, &mut offset)?;
        let input_root = get_bytes32(bytes, &mut offset)?;
        let execution_nonce = get_u64_le(bytes, &mut offset)?;
        let input_commitment = get_bytes32(bytes, &mut offset)?;
        let action_commitment = get_bytes32(bytes, &mut offset)?;

        // ExecutionStatus decoding: 0x01 = Success, 0x02 = Failure
        // 0x00 and anything else is invalid
        let status_byte = get_u8(bytes, &mut offset)?;
        let execution_status = match status_byte {
            0x01 => ExecutionStatus::Success,
            0x02 => ExecutionStatus::Failure,
            _ => return Err(CodecError::InvalidExecutionStatus(status_byte)),
        };

        debug_assert_eq!(offset, JOURNAL_SIZE);

        Ok(KernelJournalV1 {
            protocol_version,
            kernel_version,
            agent_id,
            agent_code_hash,
            constraint_set_hash,
            input_root,
            execution_nonce,
            input_commitment,
            action_commitment,
            execution_status,
        })
    }
}

// ============================================================================
// ActionV1 Codec
// ============================================================================

/// ActionV1 encoding layout (little-endian):
/// - action_type: u32 (4 bytes)
/// - target: [u8; 32] (32 bytes)
/// - payload_len: u32 (4 bytes)
/// - payload: [u8; len] (variable)
///
/// Fixed header: 40 bytes + variable payload
impl CanonicalEncode for ActionV1 {
    fn encoded_len(&self) -> Result<usize, CodecError> {
        let payload_len = self.payload.len();
        if payload_len > MAX_ACTION_PAYLOAD_BYTES {
            return Err(CodecError::ActionPayloadTooLarge {
                size: payload_len.min(u32::MAX as usize) as u32,
                limit: MAX_ACTION_PAYLOAD_BYTES,
            });
        }
        // 4 (action_type) + 32 (target) + 4 (payload_len) + payload
        Ok(40 + payload_len)
    }

    fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), CodecError> {
        let payload_len = self.payload.len();
        if payload_len > MAX_ACTION_PAYLOAD_BYTES {
            return Err(CodecError::ActionPayloadTooLarge {
                size: payload_len.min(u32::MAX as usize) as u32,
                limit: MAX_ACTION_PAYLOAD_BYTES,
            });
        }
        if payload_len > u32::MAX as usize {
            return Err(CodecError::ArithmeticOverflow);
        }

        let before = out.len();

        put_u32_le(out, self.action_type);
        put_bytes32(out, &self.target);
        put_u32_le(out, payload_len as u32);
        out.extend_from_slice(&self.payload);

        debug_assert_eq!(
            out.len() - before,
            self.encoded_len().unwrap(),
            "ActionV1: encoded_len() / encode_into() mismatch"
        );
        Ok(())
    }
}

impl CanonicalDecode for ActionV1 {
    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        // Minimum: action_type (4) + target (32) + payload_len (4) = 40 bytes
        if bytes.len() < 40 {
            return Err(CodecError::UnexpectedEndOfInput);
        }

        let mut offset = 0;

        let action_type = get_u32_le(bytes, &mut offset)?;
        let target = get_bytes32(bytes, &mut offset)?;

        // Read payload length and check against action-specific limit
        let payload_len_u32 = get_u32_le(bytes, &mut offset)?;
        if payload_len_u32 > MAX_ACTION_PAYLOAD_BYTES as u32 {
            return Err(CodecError::ActionPayloadTooLarge {
                size: payload_len_u32,
                limit: MAX_ACTION_PAYLOAD_BYTES,
            });
        }

        let payload_len = payload_len_u32 as usize;
        let end = offset
            .checked_add(payload_len)
            .ok_or(CodecError::ArithmeticOverflow)?;
        if end > bytes.len() {
            return Err(CodecError::UnexpectedEndOfInput);
        }

        let payload = bytes[offset..end].to_vec();
        offset = end;

        ensure_no_trailing_bytes(bytes, offset)?;

        Ok(ActionV1 {
            action_type,
            target,
            payload,
        })
    }
}

// ============================================================================
// AgentOutput Codec
// ============================================================================

/// AgentOutput encoding layout (little-endian):
/// - action_count: u32 (4 bytes)
/// - for each action:
///   - action_len: u32 (4 bytes) - length of the following action encoding
///   - action: ActionV1 encoding (variable)
///
/// # Canonical Ordering
///
/// Actions are automatically sorted into canonical order before encoding.
/// This ensures deterministic `action_commitment` regardless of the order
/// agents produce actions.
///
/// **Important**: Encoding preserves the agent's action order. The agent is responsible
/// for deterministic ordering of actions. This ensures commitment values are reproducible
/// when the agent produces the same output.
impl CanonicalEncode for AgentOutput {
    fn encoded_len(&self) -> Result<usize, CodecError> {
        let n = self.actions.len();
        if n > MAX_ACTIONS_PER_OUTPUT {
            return Err(CodecError::TooManyActions {
                count: n.min(u32::MAX as usize) as u32,
                limit: MAX_ACTIONS_PER_OUTPUT,
            });
        }

        // 4 for count + sum(4 + action_len) for each action
        let mut total = 4usize;
        for action in &self.actions {
            let action_len = action.encoded_len()?;
            total = total
                .checked_add(4)
                .and_then(|t| t.checked_add(action_len))
                .ok_or(CodecError::ArithmeticOverflow)?;
        }

        // Enforce global output size limit
        if total > MAX_AGENT_OUTPUT_BYTES {
            return Err(CodecError::OutputTooLarge {
                size: total.min(u32::MAX as usize) as u32,
                limit: MAX_AGENT_OUTPUT_BYTES,
            });
        }

        Ok(total)
    }

    fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), CodecError> {
        let n = self.actions.len();
        if n > MAX_ACTIONS_PER_OUTPUT {
            return Err(CodecError::TooManyActions {
                count: n.min(u32::MAX as usize) as u32,
                limit: MAX_ACTIONS_PER_OUTPUT,
            });
        }
        if n > u32::MAX as usize {
            return Err(CodecError::ArithmeticOverflow);
        }

        // Preserve agent's action order (agent is responsible for deterministic ordering)
        // Track starting position to verify total size
        let start_len = out.len();

        put_u32_le(out, n as u32);

        for action in &self.actions {
            let action_len = action.encoded_len()?;
            if action_len > MAX_SINGLE_ACTION_BYTES {
                return Err(CodecError::ActionTooLarge {
                    size: action_len.min(u32::MAX as usize) as u32,
                    limit: MAX_SINGLE_ACTION_BYTES,
                });
            }
            put_u32_le(out, action_len as u32);
            let before = out.len();
            action.encode_into(out)?;
            debug_assert_eq!(
                out.len() - before,
                action_len,
                "encoded_len() / encode_into() mismatch"
            );
        }

        // Verify total encoded size doesn't exceed limit
        let encoded_size = out.len() - start_len;
        if encoded_size > MAX_AGENT_OUTPUT_BYTES {
            return Err(CodecError::OutputTooLarge {
                size: encoded_size.min(u32::MAX as usize) as u32,
                limit: MAX_AGENT_OUTPUT_BYTES,
            });
        }

        Ok(())
    }
}

impl CanonicalDecode for AgentOutput {
    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        // Enforce total size limit on input
        if bytes.len() > MAX_AGENT_OUTPUT_BYTES {
            return Err(CodecError::OutputTooLarge {
                size: bytes.len().min(u32::MAX as usize) as u32,
                limit: MAX_AGENT_OUTPUT_BYTES,
            });
        }

        if bytes.len() < 4 {
            return Err(CodecError::UnexpectedEndOfInput);
        }

        let mut offset = 0;

        let action_count_u32 = get_u32_le(bytes, &mut offset)?;
        if action_count_u32 > MAX_ACTIONS_PER_OUTPUT as u32 {
            return Err(CodecError::TooManyActions {
                count: action_count_u32,
                limit: MAX_ACTIONS_PER_OUTPUT,
            });
        }

        let action_count = action_count_u32 as usize;
        let mut actions = Vec::with_capacity(action_count);

        for _ in 0..action_count {
            // Read action length prefix
            let action_len_u32 = get_u32_le(bytes, &mut offset)?;

            // Reject absurdly large action lengths before attempting allocation
            if action_len_u32 > MAX_SINGLE_ACTION_BYTES as u32 {
                return Err(CodecError::ActionTooLarge {
                    size: action_len_u32,
                    limit: MAX_SINGLE_ACTION_BYTES,
                });
            }

            let action_len = action_len_u32 as usize;
            let action_end = offset
                .checked_add(action_len)
                .ok_or(CodecError::ArithmeticOverflow)?;

            if action_end > bytes.len() {
                return Err(CodecError::UnexpectedEndOfInput);
            }

            let action = ActionV1::decode(&bytes[offset..action_end])?;
            actions.push(action);
            offset = action_end;
        }

        ensure_no_trailing_bytes(bytes, offset)?;

        Ok(AgentOutput { actions })
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_get_u32_le_basic() {
        let bytes = [0x01, 0x02, 0x03, 0x04, 0x05];
        let mut offset = 0;
        let value = get_u32_le(&bytes, &mut offset).unwrap();
        assert_eq!(value, 0x04030201);
        assert_eq!(offset, 4);
    }

    #[test]
    fn test_get_u32_le_insufficient_bytes() {
        let bytes = [0x01, 0x02, 0x03];
        let mut offset = 0;
        assert!(matches!(
            get_u32_le(&bytes, &mut offset),
            Err(CodecError::UnexpectedEndOfInput)
        ));
    }

    #[test]
    fn test_get_var_bytes_basic() {
        // Length prefix (4) + 3 bytes data
        let bytes = [0x03, 0x00, 0x00, 0x00, 0xAA, 0xBB, 0xCC];
        let mut offset = 0;
        let data = get_var_bytes(&bytes, &mut offset, 100).unwrap();
        assert_eq!(data, vec![0xAA, 0xBB, 0xCC]);
        assert_eq!(offset, 7);
    }

    #[test]
    fn test_get_var_bytes_exceeds_max() {
        let bytes = [0x10, 0x00, 0x00, 0x00]; // length = 16
        let mut offset = 0;
        assert!(matches!(
            get_var_bytes(&bytes, &mut offset, 10),
            Err(CodecError::InputTooLarge {
                size: 16,
                limit: 10
            })
        ));
    }

    #[test]
    fn test_encode_into_matches_encode() {
        let input = KernelInputV1 {
            protocol_version: PROTOCOL_VERSION,
            kernel_version: KERNEL_VERSION,
            agent_id: [0x42; 32],
            agent_code_hash: [0xAA; 32],
            constraint_set_hash: [0xBB; 32],
            input_root: [0xCC; 32],
            execution_nonce: 12345,
            opaque_agent_inputs: vec![1, 2, 3, 4, 5],
        };

        let encoded = input.encode().unwrap();

        let mut buf = Vec::new();
        input.encode_into(&mut buf).unwrap();

        assert_eq!(encoded, buf);
        assert_eq!(encoded.len(), input.encoded_len().unwrap());
    }

    #[test]
    fn test_action_encode_into() {
        let action = ActionV1 {
            action_type: 0x01,
            target: [0x42; 32],
            payload: vec![1, 2, 3],
        };

        let encoded = action.encode().unwrap();
        assert_eq!(encoded.len(), action.encoded_len().unwrap());
        assert_eq!(encoded.len(), 40 + 3); // header + payload
    }

    #[test]
    fn test_agent_output_preserves_action_order() {
        // Encoding preserves agent's action order - agent is responsible for deterministic ordering.
        let action_a = ActionV1 {
            action_type: 0x02,
            target: [0x11; 32],
            payload: vec![],
        };
        let action_b = ActionV1 {
            action_type: 0x01,
            target: [0x22; 32],
            payload: vec![],
        };

        let output = AgentOutput {
            actions: vec![action_a.clone(), action_b.clone()],
        };

        let encoded = output.encode().unwrap();

        // Verify encoding preserves order by inspecting the first action in the encoded bytes.
        let mut offset = 0;
        let _count = get_u32_le(&encoded, &mut offset).unwrap();
        let first_action_len = get_u32_le(&encoded, &mut offset).unwrap() as usize;
        let first_action = ActionV1::decode(&encoded[offset..offset + first_action_len]).unwrap();

        // action_a (type 0x02) should be first since order is preserved
        assert_eq!(first_action.action_type, 0x02);
        assert_eq!(first_action.target, [0x11; 32]);
    }

    #[test]
    fn test_agent_output_decode_preserves_wire_order() {
        // Verify that decode preserves the order from the wire.
        let action_a = ActionV1 {
            action_type: 0x02,
            target: [0x11; 32],
            payload: vec![],
        };
        let action_b = ActionV1 {
            action_type: 0x01,
            target: [0x22; 32],
            payload: vec![],
        };

        let output = AgentOutput {
            actions: vec![action_a, action_b],
        };

        // encode() preserves order
        let encoded = output.encode().unwrap();
        let decoded = AgentOutput::decode(&encoded).unwrap();

        // decoded order matches original order (agent is responsible for deterministic ordering)
        assert_eq!(decoded.actions.len(), 2);
        assert_eq!(decoded.actions[0].action_type, 0x02); // first stays first
        assert_eq!(decoded.actions[1].action_type, 0x01); // second stays second
    }
}
