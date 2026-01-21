use crate::types::*;
use crate::{MAX_AGENT_INPUT_BYTES, PROTOCOL_VERSION, KERNEL_VERSION};

pub trait CanonicalEncode {
    fn encode(&self) -> Vec<u8>;
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
    fn encode(&self) -> Vec<u8> {
        let data_len = self.opaque_agent_inputs.len();
        if data_len > u32::MAX as usize {
            panic!("Input data too large for u32 length prefix");
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

        buf
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
    fn encode(&self) -> Vec<u8> {
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

        // ExecutionStatus encoding: Success = 0x00
        buf.push(match self.execution_status {
            ExecutionStatus::Success => 0x00,
        });

        debug_assert_eq!(buf.len(), JOURNAL_SIZE);
        buf
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

        let kernel_version = u32::from_le_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .map_err(|_| CodecError::UnexpectedEndOfInput)?
        );
        offset += 4;

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

        // ExecutionStatus decoding: 0x00 = Success, anything else is invalid
        let execution_status = match bytes[offset] {
            0x00 => ExecutionStatus::Success,
            status => return Err(CodecError::InvalidExecutionStatus(status)),
        };

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
    fn encode(&self) -> Vec<u8> {
        let payload_len = self.payload.len();
        if payload_len > MAX_ACTION_PAYLOAD_BYTES {
            panic!("Action payload exceeds maximum size");
        }
        if payload_len > u32::MAX as usize {
            panic!("Payload too large for u32 length prefix");
        }

        let total_len = 4 + 32 + 4 + payload_len;
        let mut buf = Vec::with_capacity(total_len);

        buf.extend_from_slice(&self.action_type.to_le_bytes());
        buf.extend_from_slice(&self.target);
        buf.extend_from_slice(&(payload_len as u32).to_le_bytes());
        buf.extend_from_slice(&self.payload);

        buf
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
/// - actions: [ActionV1; count] (variable, each action is variable-length)
///
/// Actions are encoded sequentially without additional framing.
impl CanonicalEncode for AgentOutput {
    fn encode(&self) -> Vec<u8> {
        let action_count = self.actions.len();
        if action_count > MAX_ACTIONS_PER_OUTPUT {
            panic!("Too many actions in output");
        }
        if action_count > u32::MAX as usize {
            panic!("Action count too large for u32");
        }

        // Estimate capacity: 4 bytes for count + ~100 bytes per action average
        let mut buf = Vec::with_capacity(4 + action_count * 100);

        buf.extend_from_slice(&(action_count as u32).to_le_bytes());

        for action in &self.actions {
            let action_bytes = action.encode();
            buf.extend_from_slice(&(action_bytes.len() as u32).to_le_bytes());
            buf.extend_from_slice(&action_bytes);
        }

        buf
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
