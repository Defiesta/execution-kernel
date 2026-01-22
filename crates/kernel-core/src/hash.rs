use sha2::{Sha256, Digest};
use crate::types::{KernelInputV1, CodecError};
use crate::codec::CanonicalEncode;

pub fn compute_input_commitment(input_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input_bytes);
    hasher.finalize().into()
}

pub fn compute_action_commitment(agent_output_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(agent_output_bytes);
    hasher.finalize().into()
}

/// Compute SHA-256 commitment for a KernelInputV1 structure.
///
/// This is a convenience function that encodes the input and computes
/// the commitment in one step. Useful for tests and external tooling.
pub fn kernel_input_v1_commitment(input: &KernelInputV1) -> Result<[u8; 32], CodecError> {
    let bytes = input.encode()?;
    Ok(compute_input_commitment(&bytes))
}