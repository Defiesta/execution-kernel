//! SHA-256 hashing utilities for commitment computation.
//!
//! This module provides the canonical hashing functions used for computing
//! input and action commitments in the kernel protocol.

use sha2::{Digest, Sha256};

use crate::codec::CanonicalEncode;
use crate::types::{CodecError, KernelInputV1};

/// Compute SHA-256 hash of arbitrary bytes.
///
/// This is the canonical hash function used throughout the protocol.
/// All commitment computations use this function internally.
#[inline]
#[must_use]
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// Compute SHA-256 commitment over encoded KernelInputV1 bytes.
///
/// The input bytes should be the complete canonical encoding of a KernelInputV1.
/// This function does not validate the encoding; it simply hashes the bytes.
#[inline]
#[must_use]
pub fn compute_input_commitment(input_bytes: &[u8]) -> [u8; 32] {
    sha256(input_bytes)
}

/// Compute SHA-256 commitment over encoded AgentOutput bytes.
///
/// The output bytes should be the complete canonical encoding of an AgentOutput.
/// This function does not validate the encoding; it simply hashes the bytes.
#[inline]
#[must_use]
pub fn compute_action_commitment(agent_output_bytes: &[u8]) -> [u8; 32] {
    sha256(agent_output_bytes)
}

/// Convenience: encode KernelInputV1 canonically, then hash it.
///
/// This is useful for tests and external tooling where you have a structured
/// KernelInputV1 and want to compute its commitment directly.
///
/// # Allocation
///
/// This function allocates a `Vec<u8>` to hold the encoded bytes.
/// For allocation-sensitive contexts (e.g., guest execution), consider
/// using `encode()` with a pre-allocated buffer and `sha256()` directly.
pub fn kernel_input_v1_commitment(input: &KernelInputV1) -> Result<[u8; 32], CodecError> {
    let bytes = input.encode()?;
    Ok(sha256(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_empty() {
        // SHA-256 of empty input is well-known
        let hash = sha256(&[]);
        // e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        assert_eq!(hash[0], 0xe3);
        assert_eq!(hash[1], 0xb0);
        assert_eq!(hash[31], 0x55);
    }

    #[test]
    fn test_sha256_deterministic() {
        let data = b"hello world";
        let hash1 = sha256(data);
        let hash2 = sha256(data);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_commitment_functions_use_sha256() {
        let data = b"test data";
        let direct = sha256(data);
        let input_commit = compute_input_commitment(data);
        let action_commit = compute_action_commitment(data);

        // All should produce the same hash for the same input
        assert_eq!(direct, input_commit);
        assert_eq!(direct, action_commit);
    }
}
