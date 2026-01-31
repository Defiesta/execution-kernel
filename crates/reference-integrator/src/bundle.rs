//! Bundle loading and parsing for Agent Pack bundles.
//!
//! This module provides utilities to load and parse Agent Pack bundles,
//! resolving paths and extracting metadata needed for verification and execution.

use agent_pack::AgentPackManifest;
use std::path::{Path, PathBuf};

/// A loaded Agent Pack bundle with resolved paths.
#[derive(Debug, Clone)]
pub struct LoadedBundle {
    /// The parsed manifest.
    pub manifest: AgentPackManifest,
    /// Absolute path to the manifest file.
    pub manifest_path: PathBuf,
    /// Absolute path to the ELF binary.
    pub elf_path: PathBuf,
    /// Base directory of the bundle.
    pub base_dir: PathBuf,
}

/// Errors that can occur during bundle loading.
#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    #[error("Bundle directory not found: {0}")]
    DirectoryNotFound(PathBuf),

    #[error("Manifest not found at: {0}")]
    ManifestNotFound(PathBuf),

    #[error("Failed to read manifest: {0}")]
    ManifestReadError(String),

    #[error("ELF file not found at: {0}")]
    ElfNotFound(PathBuf),

    #[error("Invalid manifest: {0}")]
    InvalidManifest(String),
}

impl LoadedBundle {
    /// Load an Agent Pack bundle from a directory.
    ///
    /// Expects the directory to contain:
    /// - `agent-pack.json` - The manifest file
    /// - The ELF binary at the path specified in `artifacts.elf_path`
    ///
    /// # Arguments
    ///
    /// * `bundle_dir` - Path to the bundle directory
    ///
    /// # Returns
    ///
    /// A `LoadedBundle` with resolved absolute paths, or an error if loading fails.
    pub fn load<P: AsRef<Path>>(bundle_dir: P) -> Result<Self, BundleError> {
        let bundle_dir = bundle_dir.as_ref();

        // Verify bundle directory exists
        if !bundle_dir.exists() {
            return Err(BundleError::DirectoryNotFound(bundle_dir.to_path_buf()));
        }

        let base_dir = bundle_dir
            .canonicalize()
            .map_err(|_| BundleError::DirectoryNotFound(bundle_dir.to_path_buf()))?;

        // Look for manifest
        let manifest_path = base_dir.join("agent-pack.json");
        if !manifest_path.exists() {
            return Err(BundleError::ManifestNotFound(manifest_path));
        }

        // Load manifest
        let manifest = AgentPackManifest::from_file(&manifest_path)
            .map_err(|e| BundleError::ManifestReadError(e.to_string()))?;

        // Resolve ELF path relative to bundle directory
        let elf_path = base_dir.join(&manifest.artifacts.elf_path);
        if !elf_path.exists() {
            return Err(BundleError::ElfNotFound(elf_path));
        }

        Ok(Self {
            manifest,
            manifest_path,
            elf_path,
            base_dir,
        })
    }

    /// Get the agent ID as a 32-byte array.
    ///
    /// Parses the hex-encoded `agent_id` from the manifest.
    pub fn agent_id_bytes(&self) -> Result<[u8; 32], BundleError> {
        parse_hex_32(&self.manifest.agent_id)
            .map_err(|e| BundleError::InvalidManifest(format!("Invalid agent_id: {}", e)))
    }

    /// Get the agent code hash as a 32-byte array.
    ///
    /// Parses the hex-encoded `agent_code_hash` from the manifest.
    pub fn agent_code_hash_bytes(&self) -> Result<[u8; 32], BundleError> {
        parse_hex_32(&self.manifest.agent_code_hash)
            .map_err(|e| BundleError::InvalidManifest(format!("Invalid agent_code_hash: {}", e)))
    }

    /// Get the image ID as a 32-byte array.
    ///
    /// Parses the hex-encoded `image_id` from the manifest.
    pub fn image_id_bytes(&self) -> Result<[u8; 32], BundleError> {
        parse_hex_32(&self.manifest.image_id)
            .map_err(|e| BundleError::InvalidManifest(format!("Invalid image_id: {}", e)))
    }

    /// Read the ELF binary contents.
    pub fn read_elf(&self) -> Result<Vec<u8>, BundleError> {
        std::fs::read(&self.elf_path)
            .map_err(|e| BundleError::ManifestReadError(format!("Failed to read ELF: {}", e)))
    }
}

/// Parse a 0x-prefixed hex string into a 32-byte array.
fn parse_hex_32(hex_str: &str) -> Result<[u8; 32], String> {
    let hex_clean = hex_str.strip_prefix("0x").unwrap_or(hex_str);

    if hex_clean.len() != 64 {
        return Err(format!(
            "Expected 64 hex chars (32 bytes), got {}",
            hex_clean.len()
        ));
    }

    let bytes = hex::decode(hex_clean).map_err(|e| format!("Invalid hex: {}", e))?;

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hex_32_valid() {
        let hex = "0x0000000000000000000000000000000000000000000000000000000000000001";
        let result = parse_hex_32(hex);
        assert!(result.is_ok());
        let bytes = result.unwrap();
        assert_eq!(bytes[31], 1);
    }

    #[test]
    fn test_parse_hex_32_without_prefix() {
        let hex = "0000000000000000000000000000000000000000000000000000000000000042";
        let result = parse_hex_32(hex);
        assert!(result.is_ok());
        let bytes = result.unwrap();
        assert_eq!(bytes[31], 0x42);
    }

    #[test]
    fn test_parse_hex_32_too_short() {
        let hex = "0x1234";
        let result = parse_hex_32(hex);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_hex_32_invalid_hex() {
        let hex = "0xGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG";
        let result = parse_hex_32(hex);
        assert!(result.is_err());
    }
}
