//! IMAGE_ID computation for RISC Zero ELF binaries.
//!
//! This module provides functionality to compute the IMAGE_ID from an ELF binary,
//! which is the cryptographic commitment used for on-chain verification.
//!
//! The IMAGE_ID computation requires the `risc0` feature to be enabled.

use std::path::Path;

/// Error type for IMAGE_ID computation.
#[derive(Debug, thiserror::Error)]
pub enum ImageIdError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("IMAGE_ID computation failed: {0}")]
    Computation(String),

    #[error("risc0 feature not enabled - cannot compute IMAGE_ID")]
    FeatureNotEnabled,
}

/// Computes the IMAGE_ID from an ELF binary file.
///
/// The IMAGE_ID is a 32-byte cryptographic commitment to the ELF binary that
/// uniquely identifies the program. This is the value registered on-chain
/// for proof verification.
///
/// # Arguments
///
/// * `elf_path` - Path to the ELF binary file
///
/// # Returns
///
/// A 32-byte array containing the IMAGE_ID in little-endian format,
/// matching the on-chain representation.
///
/// # Errors
///
/// Returns an error if:
/// - The `risc0` feature is not enabled
/// - The file cannot be read
/// - The ELF binary is invalid
#[cfg(feature = "risc0")]
pub fn compute_image_id_from_file(elf_path: &Path) -> Result<[u8; 32], ImageIdError> {
    let elf_bytes = std::fs::read(elf_path)?;
    compute_image_id_from_bytes(&elf_bytes)
}

/// Computes the IMAGE_ID from ELF binary bytes.
///
/// See [`compute_image_id_from_file`] for details.
#[cfg(feature = "risc0")]
pub fn compute_image_id_from_bytes(elf_bytes: &[u8]) -> Result<[u8; 32], ImageIdError> {
    use risc0_zkvm::compute_image_id;

    let digest =
        compute_image_id(elf_bytes).map_err(|e| ImageIdError::Computation(e.to_string()))?;

    // Convert Digest to [u32; 8], then to [u8; 32] little-endian.
    // This matches the on-chain format used in print_registration_info.rs:
    // ZKVM_GUEST_ID.iter().flat_map(|x| x.to_le_bytes()).collect()
    let words: [u32; 8] = digest.into();
    let mut bytes = [0u8; 32];
    for (i, word) in words.iter().enumerate() {
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
    }

    Ok(bytes)
}

/// Stub implementation when risc0 feature is not enabled.
#[cfg(not(feature = "risc0"))]
pub fn compute_image_id_from_file(_elf_path: &Path) -> Result<[u8; 32], ImageIdError> {
    Err(ImageIdError::FeatureNotEnabled)
}

/// Stub implementation when risc0 feature is not enabled.
#[cfg(not(feature = "risc0"))]
pub fn compute_image_id_from_bytes(_elf_bytes: &[u8]) -> Result<[u8; 32], ImageIdError> {
    Err(ImageIdError::FeatureNotEnabled)
}

/// Returns whether IMAGE_ID computation is available.
///
/// This returns `true` only if the `risc0` feature is enabled.
pub fn is_available() -> bool {
    cfg!(feature = "risc0")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_available() {
        // Should return false unless risc0 feature is enabled
        #[cfg(not(feature = "risc0"))]
        assert!(!is_available());

        #[cfg(feature = "risc0")]
        assert!(is_available());
    }

    #[test]
    #[cfg(not(feature = "risc0"))]
    fn test_compute_without_feature_returns_error() {
        let result = compute_image_id_from_bytes(&[]);
        assert!(matches!(result, Err(ImageIdError::FeatureNotEnabled)));
    }
}
