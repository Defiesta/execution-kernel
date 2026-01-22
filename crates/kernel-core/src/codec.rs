// Canonical binary codec for P0.1 kernel protocol.
// See spec/codec.md for encoding specification.

use crate::types::*;
use crate::{MAX_AGENT_INPUT_BYTES, PROTOCOL_VERSION, KERNEL_VERSION};

// ============================================================================
// Helper Functions
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
    buf.extend_from_slice(&(len as u32).to_le_bytes());
    buf.extend_from_slice(data);
    Ok(())
}

/// Decode a u32 from little-endian bytes at offset.
/// Advances offset by 4 on success.
#[inline]
pub fn get_u32_le(bytes: &[u8], offset: &mut usize) -> Result<u32, CodecError> {
    if bytes.len() < *offset + 4 {
        return Err(CodecError::UnexpectedEndOfInput);
    }
    let value = u32::from_le_bytes(
        bytes[*offset..*offset + 4]
            .try_into()
            .map_err(|_| CodecError::UnexpectedEndOfInput)?
    );
    *offset += 4;
    Ok(value)
}

/// Decode a u64 from little-endian bytes at offset.
/// Advances offset by 8 on success.
#[inline]
pub fn get_u64_le(bytes: &[u8], offset: &mut usize) -> Result<u64, CodecError> {
    if bytes.len() < *offset + 8 {
        return Err(CodecError::UnexpectedEndOfInput);
    }
    let value = u64::from_le_bytes(
        bytes[*offset..*offset + 8]
            .try_into()
            .map_err(|_| CodecError::UnexpectedEndOfInput)?
    );
    *offset += 8;
    Ok(value)
}

/// Decode a 32-byte array at offset.
/// Advances offset by 32 on success.
#[inline]
pub fn get_bytes32(bytes: &[u8], offset: &mut usize) -> Result<[u8; 32], CodecError> {
    if bytes.len() < *offset + 32 {
        return Err(CodecError::UnexpectedEndOfInput);
    }
    let value: [u8; 32] = bytes[*offset..*offset + 32]
        .try_into()
        .map_err(|_| CodecError::UnexpectedEndOfInput)?;
    *offset += 32;
    Ok(value)
}

/// Decode variable-length bytes with u32 length prefix.
/// Advances offset by 4 + length on success.
/// Returns error if length exceeds max_len.
#[inline]
pub fn get_var_bytes(bytes: &[u8], offset: &mut usize, max_len: usize) -> Result<Vec<u8>, CodecError> {
    let len_u32 = get_u32_le(bytes, offset)?;
    // Rewind offset since get_u32_le advanced it, but we need to check bounds
    *offset -= 4;

    if len_u32 > max_len as u32 {
        return Err(CodecError::InputTooLarge {
            size: len_u32,
            limit: max_len,
        });
    }

    let len = len_u32 as usize;
    *offset += 4; // Re-advance past length

    if bytes.len() < *offset + len {
        return Err(CodecError::UnexpectedEndOfInput);
    }

    let data = bytes[*offset..*offset + len].to_vec();
    *offset += len;
    Ok(data)
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

pub trait CanonicalEncode {
    fn encode(&self) -> Result<Vec<u8>, CodecError>;
}

pub trait CanonicalDecode: Sized {
    fn decode(bytes: &[u8]) -> Result<Self, CodecError>;
}

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
    fn encode(&self) -> Result<Vec<u8>, CodecError> {
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

        // Fixed fields (144) + length prefix (4) + data
        let total_len = 144 + 4 + data_len;
        let mut buf = Vec::with_capacity(total_len);

        buf.extend_from_slice(&self.protocol_version.to_le_bytes());
        buf.extend_from_slice(&self.kernel_version.to_le_bytes());
        buf.extend_from_slice(&self.agent_id);
        buf.extend_from_slice(&self.agent_code_hash);
        buf.extend_from_slice(&self.constraint_set_hash);
        buf.extend_from_slice(&self.input_root);
        buf.extend_from_slice(&self.execution_nonce.to_le_bytes());
        buf.extend_from_slice(&(data_len as u32).to_le_bytes());
        buf.extend_from_slice(&self.opaque_agent_inputs);

        Ok(buf)
    }
}

impl CanonicalDecode for KernelInputV1 {
    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        // Minimum size: fixed fields (144) + length prefix (4) = 148 bytes
        if bytes.len() < 148 {
            return Err(CodecError::UnexpectedEndOfInput);
        }

        let mut offset = 0;

        // protocol_version
        let protocol_version = u32::from_le_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .map_err(|_| CodecError::UnexpectedEndOfInput)?
        );
        offset += 4;

        if protocol_version != PROTOCOL_VERSION {
            return Err(CodecError::InvalidVersion {
                expected: PROTOCOL_VERSION,
                actual: protocol_version,
            });
        }

        // kernel_version
        let kernel_version = u32::from_le_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .map_err(|_| CodecError::UnexpectedEndOfInput)?
        );
        offset += 4;

        if kernel_version != KERNEL_VERSION {
            return Err(CodecError::InvalidVersion {
                expected: KERNEL_VERSION,
                actual: kernel_version,
            });
        }

        // agent_id
        let agent_id: [u8; 32] = bytes[offset..offset + 32]
            .try_into()
            .map_err(|_| CodecError::UnexpectedEndOfInput)?;
        offset += 32;

        // agent_code_hash
        let agent_code_hash: [u8; 32] = bytes[offset..offset + 32]
            .try_into()
            .map_err(|_| CodecError::UnexpectedEndOfInput)?;
        offset += 32;

        // constraint_set_hash
        let constraint_set_hash: [u8; 32] = bytes[offset..offset + 32]
            .try_into()
            .map_err(|_| CodecError::UnexpectedEndOfInput)?;
        offset += 32;

        // input_root
        let input_root: [u8; 32] = bytes[offset..offset + 32]
            .try_into()
            .map_err(|_| CodecError::UnexpectedEndOfInput)?;
        offset += 32;

        // execution_nonce
        let execution_nonce = u64::from_le_bytes(
            bytes[offset..offset + 8]
                .try_into()
                .map_err(|_| CodecError::UnexpectedEndOfInput)?
        );
        offset += 8;

        // opaque_agent_inputs length
        let agent_input_len_u32 = u32::from_le_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .map_err(|_| CodecError::UnexpectedEndOfInput)?
        );

        if agent_input_len_u32 > MAX_AGENT_INPUT_BYTES as u32 {
            return Err(CodecError::InputTooLarge {
                size: agent_input_len_u32,
                limit: MAX_AGENT_INPUT_BYTES,
            });
        }

        let agent_input_len = agent_input_len_u32 as usize;
        offset += 4;

        if bytes.len() < offset + agent_input_len {
            return Err(CodecError::UnexpectedEndOfInput);
        }

        let opaque_agent_inputs = bytes[offset..offset + agent_input_len].to_vec();
        offset += agent_input_len;

        if offset != bytes.len() {
            return Err(CodecError::InvalidLength);
        }

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
    fn encode(&self) -> Result<Vec<u8>, CodecError> {
        let mut buf = Vec::with_capacity(JOURNAL_SIZE);

        buf.extend_from_slice(&self.protocol_version.to_le_bytes());
        buf.extend_from_slice(&self.kernel_version.to_le_bytes());
        buf.extend_from_slice(&self.agent_id);
        buf.extend_from_slice(&self.agent_code_hash);
        buf.extend_from_slice(&self.constraint_set_hash);
        buf.extend_from_slice(&self.input_root);
        buf.extend_from_slice(&self.execution_nonce.to_le_bytes());
        buf.extend_from_slice(&self.input_commitment);
        buf.extend_from_slice(&self.action_commitment);

        // ExecutionStatus encoding: Success = 0x01 (0x00 reserved to catch uninitialized memory)
        buf.push(match self.execution_status {
            ExecutionStatus::Success => 0x01,
        });

        debug_assert_eq!(buf.len(), JOURNAL_SIZE);
        Ok(buf)
    }
}

impl CanonicalDecode for KernelJournalV1 {
    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        if bytes.len() != JOURNAL_SIZE {
            return Err(CodecError::InvalidLength);
        }

        let mut offset = 0;

        let protocol_version = u32::from_le_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .map_err(|_| CodecError::UnexpectedEndOfInput)?
        );
        offset += 4;

        // Validate protocol version for upgrade safety
        if protocol_version != PROTOCOL_VERSION {
            return Err(CodecError::InvalidVersion {
                expected: PROTOCOL_VERSION,
                actual: protocol_version,
            });
        }

        let kernel_version = u32::from_le_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .map_err(|_| CodecError::UnexpectedEndOfInput)?
        );
        offset += 4;

        // Validate kernel version for upgrade safety
        if kernel_version != KERNEL_VERSION {
            return Err(CodecError::InvalidVersion {
                expected: KERNEL_VERSION,
                actual: kernel_version,
            });
        }

        let agent_id: [u8; 32] = bytes[offset..offset + 32]
            .try_into()
            .map_err(|_| CodecError::UnexpectedEndOfInput)?;
        offset += 32;

        let agent_code_hash: [u8; 32] = bytes[offset..offset + 32]
            .try_into()
            .map_err(|_| CodecError::UnexpectedEndOfInput)?;
        offset += 32;

        let constraint_set_hash: [u8; 32] = bytes[offset..offset + 32]
            .try_into()
            .map_err(|_| CodecError::UnexpectedEndOfInput)?;
        offset += 32;

        let input_root: [u8; 32] = bytes[offset..offset + 32]
            .try_into()
            .map_err(|_| CodecError::UnexpectedEndOfInput)?;
        offset += 32;

        let execution_nonce = u64::from_le_bytes(
            bytes[offset..offset + 8]
                .try_into()
                .map_err(|_| CodecError::UnexpectedEndOfInput)?
        );
        offset += 8;

        let input_commitment: [u8; 32] = bytes[offset..offset + 32]
            .try_into()
            .map_err(|_| CodecError::UnexpectedEndOfInput)?;
        offset += 32;

        let action_commitment: [u8; 32] = bytes[offset..offset + 32]
            .try_into()
            .map_err(|_| CodecError::UnexpectedEndOfInput)?;
        offset += 32;

        // ExecutionStatus decoding: 0x01 = Success, 0x00 and anything else is invalid
        let execution_status = match bytes[offset] {
            0x01 => ExecutionStatus::Success,
            status => return Err(CodecError::InvalidExecutionStatus(status)),
        };
        offset += 1;
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

/// ActionV1 encoding layout (little-endian):
/// - action_type: u32 (4 bytes)
/// - target: [u8; 32] (32 bytes)
/// - payload_len: u32 (4 bytes)
/// - payload: [u8; len] (variable)
///
/// Fixed header: 40 bytes + variable payload
impl CanonicalEncode for ActionV1 {
    fn encode(&self) -> Result<Vec<u8>, CodecError> {
        let payload_len = self.payload.len();
        if payload_len > MAX_ACTION_PAYLOAD_BYTES {
            return Err(CodecError::ActionPayloadTooLarge {
                size: payload_len as u32,
                limit: MAX_ACTION_PAYLOAD_BYTES,
            });
        }
        if payload_len > u32::MAX as usize {
            return Err(CodecError::ArithmeticOverflow);
        }

        let total_len = 4 + 32 + 4 + payload_len;
        let mut buf = Vec::with_capacity(total_len);

        buf.extend_from_slice(&self.action_type.to_le_bytes());
        buf.extend_from_slice(&self.target);
        buf.extend_from_slice(&(payload_len as u32).to_le_bytes());
        buf.extend_from_slice(&self.payload);

        Ok(buf)
    }
}

impl CanonicalDecode for ActionV1 {
    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        // Minimum: action_type (4) + target (32) + payload_len (4) = 40 bytes
        if bytes.len() < 40 {
            return Err(CodecError::UnexpectedEndOfInput);
        }

        let mut offset = 0;

        let action_type = u32::from_le_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .map_err(|_| CodecError::UnexpectedEndOfInput)?
        );
        offset += 4;

        let target: [u8; 32] = bytes[offset..offset + 32]
            .try_into()
            .map_err(|_| CodecError::UnexpectedEndOfInput)?;
        offset += 32;

        let payload_len_u32 = u32::from_le_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .map_err(|_| CodecError::UnexpectedEndOfInput)?
        );

        if payload_len_u32 > MAX_ACTION_PAYLOAD_BYTES as u32 {
            return Err(CodecError::ActionPayloadTooLarge {
                size: payload_len_u32,
                limit: MAX_ACTION_PAYLOAD_BYTES,
            });
        }

        let payload_len = payload_len_u32 as usize;
        offset += 4;

        if bytes.len() < offset + payload_len {
            return Err(CodecError::UnexpectedEndOfInput);
        }

        let payload = bytes[offset..offset + payload_len].to_vec();
        offset += payload_len;

        if offset != bytes.len() {
            return Err(CodecError::InvalidLength);
        }

        Ok(ActionV1 {
            action_type,
            target,
            payload,
        })
    }
}

/// AgentOutput encoding layout (little-endian):
/// - action_count: u32 (4 bytes)
/// - for each action:
///   - action_len: u32 (4 bytes) - length of the following action encoding
///   - action: ActionV1 encoding (variable)
///
/// IMPORTANT: Actions are automatically sorted into canonical order before encoding.
/// This ensures deterministic action_commitment regardless of the order agents produce actions.
/// Ordering: action_type (ascending) → target (lexicographic) → payload (lexicographic)
impl CanonicalEncode for AgentOutput {
    fn encode(&self) -> Result<Vec<u8>, CodecError> {
        let action_count = self.actions.len();
        if action_count > MAX_ACTIONS_PER_OUTPUT {
            return Err(CodecError::TooManyActions {
                count: action_count as u32,
                limit: MAX_ACTIONS_PER_OUTPUT,
            });
        }
        if action_count > u32::MAX as usize {
            return Err(CodecError::ArithmeticOverflow);
        }

        // Sort actions into canonical order for deterministic encoding
        let mut sorted_actions = self.actions.clone();
        sorted_actions.sort();

        // Estimate capacity: 4 bytes for count + ~100 bytes per action average
        let mut buf = Vec::with_capacity(4 + action_count * 100);

        buf.extend_from_slice(&(action_count as u32).to_le_bytes());

        for action in &sorted_actions {
            let action_bytes = action.encode()?;
            buf.extend_from_slice(&(action_bytes.len() as u32).to_le_bytes());
            buf.extend_from_slice(&action_bytes);
        }

        Ok(buf)
    }
}

impl CanonicalDecode for AgentOutput {
    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        if bytes.len() < 4 {
            return Err(CodecError::UnexpectedEndOfInput);
        }

        let mut offset = 0;

        let action_count_u32 = u32::from_le_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .map_err(|_| CodecError::UnexpectedEndOfInput)?
        );

        if action_count_u32 > MAX_ACTIONS_PER_OUTPUT as u32 {
            return Err(CodecError::TooManyActions {
                count: action_count_u32,
                limit: MAX_ACTIONS_PER_OUTPUT,
            });
        }

        let action_count = action_count_u32 as usize;
        offset += 4;

        let mut actions = Vec::with_capacity(action_count);

        for _ in 0..action_count {
            // Read action length prefix
            if bytes.len() < offset + 4 {
                return Err(CodecError::UnexpectedEndOfInput);
            }

            let action_len_u32 = u32::from_le_bytes(
                bytes[offset..offset + 4]
                    .try_into()
                    .map_err(|_| CodecError::UnexpectedEndOfInput)?
            );

            // Reject absurdly large action lengths before attempting allocation
            if action_len_u32 > MAX_SINGLE_ACTION_BYTES as u32 {
                return Err(CodecError::ActionTooLarge {
                    size: action_len_u32,
                    limit: MAX_SINGLE_ACTION_BYTES,
                });
            }

            let action_len = action_len_u32 as usize;
            offset += 4;

            if bytes.len() < offset + action_len {
                return Err(CodecError::UnexpectedEndOfInput);
            }

            let action = ActionV1::decode(&bytes[offset..offset + action_len])?;
            actions.push(action);
            offset += action_len;
        }

        if offset != bytes.len() {
            return Err(CodecError::InvalidLength);
        }

        Ok(AgentOutput { actions })
    }
}
