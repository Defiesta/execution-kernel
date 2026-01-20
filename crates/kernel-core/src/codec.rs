use crate::types::*;
use crate::{MAX_AGENT_INPUT_BYTES, MAX_AGENT_OUTPUT_BYTES, PROTOCOL_VERSION};

pub trait CanonicalEncode {
    fn encode(&self) -> Vec<u8>;
}

pub trait CanonicalDecode: Sized {
    fn decode(bytes: &[u8]) -> Result<Self, CodecError>;
}

impl CanonicalEncode for KernelInputV1 {
    fn encode(&self) -> Vec<u8> {
        let data_len = self.agent_input.len();
        if data_len > u32::MAX as usize {
            panic!("Input data too large for u32 length prefix");
        }
        
        let total_len = 4 + 32 + 4 + data_len;
        let mut buf = Vec::with_capacity(total_len);
        
        buf.extend_from_slice(&self.protocol_version.to_le_bytes());
        buf.extend_from_slice(&self.agent_id);
        buf.extend_from_slice(&(data_len as u32).to_le_bytes());
        buf.extend_from_slice(&self.agent_input);
        
        buf
    }
}

impl CanonicalDecode for KernelInputV1 {
    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        if bytes.len() < 4 {
            return Err(CodecError::UnexpectedEndOfInput);
        }
        
        let mut offset = 0;
        
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
        
        if bytes.len() < offset + 32 {
            return Err(CodecError::UnexpectedEndOfInput);
        }
        
        let agent_id: [u8; 32] = bytes[offset..offset + 32]
            .try_into()
            .map_err(|_| CodecError::UnexpectedEndOfInput)?;
        offset += 32;
        
        if bytes.len() < offset + 4 {
            return Err(CodecError::UnexpectedEndOfInput);
        }
        
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
        
        let agent_input = bytes[offset..offset + agent_input_len].to_vec();
        offset += agent_input_len;
        
        if offset != bytes.len() {
            return Err(CodecError::InvalidLength);
        }
        
        Ok(KernelInputV1 {
            protocol_version,
            agent_id,
            agent_input,
        })
    }
}

impl CanonicalEncode for KernelJournalV1 {
    fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        
        buf.extend_from_slice(&self.protocol_version.to_le_bytes());
        buf.extend_from_slice(&self.kernel_version.to_le_bytes());
        buf.extend_from_slice(&self.input_commitment);
        buf.extend_from_slice(&self.action_commitment);
        buf.push(match self.execution_status {
            ExecutionStatus::Success => 0,
        });
        
        buf
    }
}

impl CanonicalDecode for KernelJournalV1 {
    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        if bytes.len() != 73 {
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
        
        let input_commitment: [u8; 32] = bytes[offset..offset + 32]
            .try_into()
            .map_err(|_| CodecError::UnexpectedEndOfInput)?;
        offset += 32;
        
        let action_commitment: [u8; 32] = bytes[offset..offset + 32]
            .try_into()
            .map_err(|_| CodecError::UnexpectedEndOfInput)?;
        offset += 32;
        
        let execution_status = match bytes[offset] {
            0 => ExecutionStatus::Success,
            status => return Err(CodecError::InvalidExecutionStatus(status)),
        };
        
        Ok(KernelJournalV1 {
            protocol_version,
            kernel_version,
            input_commitment,
            action_commitment,
            execution_status,
        })
    }
}

impl CanonicalEncode for AgentOutput {
    fn encode(&self) -> Vec<u8> {
        let data_len = self.data.len();
        if data_len > u32::MAX as usize {
            panic!("Output data too large for u32 length prefix");
        }
        if data_len > MAX_AGENT_OUTPUT_BYTES {
            panic!("Output data exceeds maximum allowed size");
        }
        
        let total_len = 4 + data_len;
        let mut buf = Vec::with_capacity(total_len);
        
        buf.extend_from_slice(&(data_len as u32).to_le_bytes());
        buf.extend_from_slice(&self.data);
        buf
    }
}

impl CanonicalDecode for AgentOutput {
    fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        if bytes.len() < 4 {
            return Err(CodecError::UnexpectedEndOfInput);
        }
        
        let data_len_u32 = u32::from_le_bytes(
            bytes[0..4]
                .try_into()
                .map_err(|_| CodecError::UnexpectedEndOfInput)?
        );
        
        if data_len_u32 > MAX_AGENT_OUTPUT_BYTES as u32 {
            return Err(CodecError::OutputTooLarge {
                size: data_len_u32,
                limit: MAX_AGENT_OUTPUT_BYTES,
            });
        }
        
        let data_len = data_len_u32 as usize;
        
        if bytes.len() != 4 + data_len {
            return Err(CodecError::InvalidLength);
        }
        
        let data = bytes[4..4 + data_len].to_vec();
        
        Ok(AgentOutput { data })
    }
}