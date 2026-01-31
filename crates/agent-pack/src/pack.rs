//! Bundle packing functionality for Agent Pack.
//!
//! This module provides the logic for creating distributable Agent Pack bundles
//! from a manifest template and ELF binary.

use crate::hash::{format_hex, sha256_file};
use crate::manifest::AgentPackManifest;
use std::path::Path;

/// Options for creating an Agent Pack bundle.
#[derive(Debug, Clone)]
pub struct PackOptions {
    /// Whether to copy the ELF into the bundle's artifacts directory.
    pub copy_elf: bool,
    /// Whether to overwrite existing files in the output directory.
    pub force: bool,
}

impl Default for PackOptions {
    fn default() -> Self {
        Self {
            copy_elf: true,
            force: false,
        }
    }
}

/// Result of a successful pack operation.
#[derive(Debug)]
pub struct PackResult {
    /// Path to the created manifest.
    pub manifest_path: std::path::PathBuf,
    /// Path to the copied ELF file (if copy_elf was true).
    pub elf_path: Option<std::path::PathBuf>,
    /// Computed ELF SHA-256 hash.
    pub elf_sha256: String,
    /// Computed IMAGE_ID (if risc0 feature enabled).
    pub image_id: Option<String>,
    /// Computed Cargo.lock SHA-256 (if provided).
    pub cargo_lock_sha256: Option<String>,
}

/// Errors that can occur during packing.
#[derive(Debug, thiserror::Error)]
pub enum PackError {
    #[error("manifest not found: {0}")]
    ManifestNotFound(String),

    #[error("ELF file not found: {0}")]
    ElfNotFound(String),

    #[error("Cargo.lock not found: {0}")]
    CargoLockNotFound(String),

    #[error("output directory already exists (use --force to overwrite): {0}")]
    OutputExists(String),

    #[error("failed to create directory: {0}")]
    CreateDir(String),

    #[error("failed to read file: {0}")]
    ReadFile(String),

    #[error("failed to write file: {0}")]
    WriteFile(String),

    #[error("failed to copy file: {0}")]
    CopyFile(String),

    #[error("failed to parse manifest: {0}")]
    ParseManifest(String),

    #[error("failed to serialize manifest: {0}")]
    SerializeManifest(String),
}

/// Creates an Agent Pack bundle from a manifest template and ELF binary.
///
/// This function:
/// 1. Reads the input manifest
/// 2. Creates the output directory structure
/// 3. Copies the ELF file to the artifacts directory (if copy_elf is true)
/// 4. Computes cryptographic hashes (elf_sha256, image_id, cargo_lock_sha256)
/// 5. Updates the manifest with computed values and relative paths
/// 6. Writes the final manifest to the output directory
///
/// The resulting bundle can be verified with:
/// ```bash
/// agent-pack verify --manifest <out>/agent-pack.json --base-dir <out>
/// ```
pub fn pack_bundle(
    manifest_path: &Path,
    elf_path: &Path,
    output_dir: &Path,
    cargo_lock_path: Option<&Path>,
    options: &PackOptions,
) -> Result<PackResult, PackError> {
    // Validate inputs exist
    if !manifest_path.exists() {
        return Err(PackError::ManifestNotFound(
            manifest_path.display().to_string(),
        ));
    }

    if !elf_path.exists() {
        return Err(PackError::ElfNotFound(elf_path.display().to_string()));
    }

    if let Some(lock_path) = cargo_lock_path {
        if !lock_path.exists() {
            return Err(PackError::CargoLockNotFound(
                lock_path.display().to_string(),
            ));
        }
    }

    // Check output directory
    if output_dir.exists() && !options.force {
        // Check if it's non-empty
        let is_empty = output_dir
            .read_dir()
            .map(|mut d| d.next().is_none())
            .unwrap_or(false);

        if !is_empty {
            return Err(PackError::OutputExists(output_dir.display().to_string()));
        }
    }

    // Create output directory structure
    let artifacts_dir = output_dir.join("artifacts");
    std::fs::create_dir_all(&artifacts_dir)
        .map_err(|e| PackError::CreateDir(format!("{}: {}", artifacts_dir.display(), e)))?;

    // Load manifest
    let mut manifest = AgentPackManifest::from_file(manifest_path)
        .map_err(|e| PackError::ParseManifest(e.to_string()))?;

    // Compute ELF hash
    let elf_hash = sha256_file(elf_path)
        .map_err(|e| PackError::ReadFile(format!("{}: {}", elf_path.display(), e)))?;
    let elf_sha256 = format_hex(&elf_hash);

    // Compute IMAGE_ID if risc0 feature is enabled
    #[cfg(feature = "risc0")]
    let image_id = {
        use crate::image_id::compute_image_id_from_file;
        match compute_image_id_from_file(elf_path) {
            Ok(id) => Some(format_hex(&id)),
            Err(_) => None,
        }
    };

    #[cfg(not(feature = "risc0"))]
    let image_id: Option<String> = None;

    // Compute Cargo.lock hash if provided
    let cargo_lock_sha256 = if let Some(lock_path) = cargo_lock_path {
        let hash = sha256_file(lock_path)
            .map_err(|e| PackError::ReadFile(format!("{}: {}", lock_path.display(), e)))?;
        Some(format_hex(&hash))
    } else {
        None
    };

    // Determine ELF filename and destination
    let elf_filename = elf_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "guest.elf".to_string());

    let dest_elf_path = if options.copy_elf {
        let dest = artifacts_dir.join(&elf_filename);
        std::fs::copy(elf_path, &dest).map_err(|e| {
            PackError::CopyFile(format!(
                "{} -> {}: {}",
                elf_path.display(),
                dest.display(),
                e
            ))
        })?;
        Some(dest)
    } else {
        None
    };

    // Update manifest with computed values
    manifest.artifacts.elf_sha256 = elf_sha256.clone();
    manifest.artifacts.elf_path = format!("artifacts/{}", elf_filename);

    if let Some(ref id) = image_id {
        manifest.image_id = id.clone();
    }

    if let Some(ref lock_hash) = cargo_lock_sha256 {
        manifest.build.cargo_lock_sha256 = lock_hash.clone();
    }

    // Write manifest to output directory
    let output_manifest_path = output_dir.join("agent-pack.json");
    manifest
        .to_file(&output_manifest_path)
        .map_err(|e| PackError::SerializeManifest(e.to_string()))?;

    Ok(PackResult {
        manifest_path: output_manifest_path,
        elf_path: dest_elf_path,
        elf_sha256,
        image_id,
        cargo_lock_sha256,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn create_test_manifest(dir: &Path) -> std::path::PathBuf {
        let manifest = AgentPackManifest::new_template(
            "test-agent".to_string(),
            "1.0.0".to_string(),
            "0x0000000000000000000000000000000000000000000000000000000000000001".to_string(),
        );
        let path = dir.join("manifest.json");
        manifest.to_file(&path).unwrap();
        path
    }

    fn create_test_elf(dir: &Path) -> std::path::PathBuf {
        let path = dir.join("test.elf");
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(b"MOCK_ELF_BINARY_CONTENT").unwrap();
        path
    }

    fn create_test_cargo_lock(dir: &Path) -> std::path::PathBuf {
        let path = dir.join("Cargo.lock");
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(b"# Cargo.lock\nversion = 3\n").unwrap();
        path
    }

    #[test]
    fn test_pack_bundle_basic() {
        let temp = TempDir::new().unwrap();
        let input_dir = temp.path().join("input");
        let output_dir = temp.path().join("output");
        std::fs::create_dir_all(&input_dir).unwrap();

        let manifest_path = create_test_manifest(&input_dir);
        let elf_path = create_test_elf(&input_dir);

        let result = pack_bundle(
            &manifest_path,
            &elf_path,
            &output_dir,
            None,
            &PackOptions::default(),
        )
        .unwrap();

        // Check manifest was created
        assert!(result.manifest_path.exists());
        assert!(output_dir.join("agent-pack.json").exists());

        // Check ELF was copied
        assert!(result.elf_path.is_some());
        assert!(output_dir.join("artifacts/test.elf").exists());

        // Check hash was computed
        assert!(result.elf_sha256.starts_with("0x"));
        assert_eq!(result.elf_sha256.len(), 66); // 0x + 64 hex chars
    }

    #[test]
    fn test_pack_bundle_with_cargo_lock() {
        let temp = TempDir::new().unwrap();
        let input_dir = temp.path().join("input");
        let output_dir = temp.path().join("output");
        std::fs::create_dir_all(&input_dir).unwrap();

        let manifest_path = create_test_manifest(&input_dir);
        let elf_path = create_test_elf(&input_dir);
        let cargo_lock_path = create_test_cargo_lock(&input_dir);

        let result = pack_bundle(
            &manifest_path,
            &elf_path,
            &output_dir,
            Some(&cargo_lock_path),
            &PackOptions::default(),
        )
        .unwrap();

        assert!(result.cargo_lock_sha256.is_some());
        assert!(result.cargo_lock_sha256.unwrap().starts_with("0x"));
    }

    #[test]
    fn test_pack_bundle_no_copy_elf() {
        let temp = TempDir::new().unwrap();
        let input_dir = temp.path().join("input");
        let output_dir = temp.path().join("output");
        std::fs::create_dir_all(&input_dir).unwrap();

        let manifest_path = create_test_manifest(&input_dir);
        let elf_path = create_test_elf(&input_dir);

        let options = PackOptions {
            copy_elf: false,
            force: false,
        };

        let result = pack_bundle(&manifest_path, &elf_path, &output_dir, None, &options).unwrap();

        // ELF should not be copied
        assert!(result.elf_path.is_none());
        assert!(!output_dir.join("artifacts/test.elf").exists());

        // But manifest should still exist
        assert!(result.manifest_path.exists());
    }

    #[test]
    fn test_pack_bundle_errors_on_missing_manifest() {
        let temp = TempDir::new().unwrap();
        let output_dir = temp.path().join("output");
        let elf_path = temp.path().join("test.elf");
        std::fs::write(&elf_path, b"ELF").unwrap();

        let result = pack_bundle(
            &temp.path().join("nonexistent.json"),
            &elf_path,
            &output_dir,
            None,
            &PackOptions::default(),
        );

        assert!(matches!(result, Err(PackError::ManifestNotFound(_))));
    }

    #[test]
    fn test_pack_bundle_errors_on_missing_elf() {
        let temp = TempDir::new().unwrap();
        let manifest_path = create_test_manifest(temp.path());
        let output_dir = temp.path().join("output");

        let result = pack_bundle(
            &manifest_path,
            &temp.path().join("nonexistent.elf"),
            &output_dir,
            None,
            &PackOptions::default(),
        );

        assert!(matches!(result, Err(PackError::ElfNotFound(_))));
    }

    #[test]
    fn test_pack_bundle_errors_on_existing_output() {
        let temp = TempDir::new().unwrap();
        let input_dir = temp.path().join("input");
        let output_dir = temp.path().join("output");
        std::fs::create_dir_all(&input_dir).unwrap();
        std::fs::create_dir_all(&output_dir).unwrap();

        // Create a file in output to make it non-empty
        std::fs::write(output_dir.join("existing.txt"), b"data").unwrap();

        let manifest_path = create_test_manifest(&input_dir);
        let elf_path = create_test_elf(&input_dir);

        let result = pack_bundle(
            &manifest_path,
            &elf_path,
            &output_dir,
            None,
            &PackOptions::default(),
        );

        assert!(matches!(result, Err(PackError::OutputExists(_))));
    }

    #[test]
    fn test_pack_bundle_force_overwrites() {
        let temp = TempDir::new().unwrap();
        let input_dir = temp.path().join("input");
        let output_dir = temp.path().join("output");
        std::fs::create_dir_all(&input_dir).unwrap();
        std::fs::create_dir_all(&output_dir).unwrap();

        // Create a file in output to make it non-empty
        std::fs::write(output_dir.join("existing.txt"), b"data").unwrap();

        let manifest_path = create_test_manifest(&input_dir);
        let elf_path = create_test_elf(&input_dir);

        let options = PackOptions {
            copy_elf: true,
            force: true,
        };

        let result = pack_bundle(&manifest_path, &elf_path, &output_dir, None, &options);

        assert!(result.is_ok());
    }
}
