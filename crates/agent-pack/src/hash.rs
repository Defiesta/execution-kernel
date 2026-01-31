//! SHA-256 hashing utilities for Agent Pack.
//!
//! Provides functions for computing and formatting SHA-256 hashes
//! in the format expected by Agent Pack manifests.

use sha2::{Digest, Sha256};
use std::path::Path;

/// Computes SHA-256 hash of the given bytes.
///
/// Returns a 32-byte array containing the hash.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Computes SHA-256 hash of a file.
///
/// # Errors
///
/// Returns an error if the file cannot be read.
pub fn sha256_file(path: &Path) -> Result<[u8; 32], std::io::Error> {
    let data = std::fs::read(path)?;
    Ok(sha256(&data))
}

/// Formats a 32-byte hash as a hex string with 0x prefix.
///
/// This is the canonical format for hashes in Agent Pack manifests.
pub fn format_hex(hash: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(hash))
}

/// Parses a hex string (with or without 0x prefix) into a 32-byte array.
///
/// # Errors
///
/// Returns an error if the string is not valid hex or not exactly 32 bytes.
pub fn parse_hex_32(s: &str) -> Result<[u8; 32], HexError> {
    let s = s.strip_prefix("0x").unwrap_or(s);

    if s.len() != 64 {
        return Err(HexError::InvalidLength {
            expected: 64,
            actual: s.len(),
        });
    }

    let bytes = hex::decode(s).map_err(|e| HexError::InvalidHex(e.to_string()))?;

    bytes.try_into().map_err(|_| HexError::InvalidLength {
        expected: 64,
        actual: s.len(),
    })
}

/// Validates that a string is a valid 32-byte hex value with 0x prefix.
///
/// Returns `Ok(())` if valid, or an error describing the problem.
pub fn validate_hex_32(s: &str) -> Result<(), HexError> {
    if !s.starts_with("0x") {
        return Err(HexError::MissingPrefix);
    }

    let _ = parse_hex_32(s)?;
    Ok(())
}

/// Errors that can occur when parsing hex strings.
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum HexError {
    #[error("hex string must start with '0x' prefix")]
    MissingPrefix,

    #[error("invalid hex string length: expected {expected} chars, got {actual}")]
    InvalidLength { expected: usize, actual: usize },

    #[error("invalid hex characters: {0}")]
    InvalidHex(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_known_value() {
        // SHA-256 of empty string
        let hash = sha256(b"");
        let hex = format_hex(&hash);
        assert_eq!(
            hex,
            "0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_sha256_hello_world() {
        let hash = sha256(b"hello world");
        let hex = format_hex(&hash);
        assert_eq!(
            hex,
            "0xb94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_format_and_parse_roundtrip() {
        let original = [0x42u8; 32];
        let hex = format_hex(&original);
        let parsed = parse_hex_32(&hex).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_parse_hex_without_prefix() {
        let hex = "4242424242424242424242424242424242424242424242424242424242424242";
        let result = parse_hex_32(hex).unwrap();
        assert_eq!(result, [0x42u8; 32]);
    }

    #[test]
    fn test_validate_hex_valid() {
        let valid = "0x0000000000000000000000000000000000000000000000000000000000000001";
        assert!(validate_hex_32(valid).is_ok());
    }

    #[test]
    fn test_validate_hex_missing_prefix() {
        let no_prefix = "0000000000000000000000000000000000000000000000000000000000000001";
        assert_eq!(validate_hex_32(no_prefix), Err(HexError::MissingPrefix));
    }

    #[test]
    fn test_validate_hex_wrong_length() {
        let too_short = "0x0001";
        let result = validate_hex_32(too_short);
        assert!(matches!(result, Err(HexError::InvalidLength { .. })));
    }

    #[test]
    fn test_validate_hex_bad_chars() {
        let bad_chars = "0xGGGG000000000000000000000000000000000000000000000000000000000001";
        let result = validate_hex_32(bad_chars);
        assert!(matches!(result, Err(HexError::InvalidHex(_))));
    }
}
