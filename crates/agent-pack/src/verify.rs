//! Verification logic for Agent Pack manifests.
//!
//! Provides comprehensive validation of manifest contents, including:
//! - Structure validation (required fields, formats)
//! - Hex string validation (32-byte values with 0x prefix)
//! - Semver validation
//! - Hash verification against actual files

use crate::hash::{self, validate_hex_32, HexError};
use crate::manifest::{AgentPackManifest, FORMAT_VERSION};
use std::path::Path;

/// Result of manifest verification.
#[derive(Debug)]
pub struct VerificationReport {
    /// List of errors found during verification
    pub errors: Vec<VerificationError>,
    /// List of warnings (non-fatal issues)
    pub warnings: Vec<String>,
    /// Whether all critical checks passed
    pub passed: bool,
}

impl VerificationReport {
    fn new() -> Self {
        Self {
            errors: Vec::new(),
            warnings: Vec::new(),
            passed: true,
        }
    }

    fn add_error(&mut self, error: VerificationError) {
        self.errors.push(error);
        self.passed = false;
    }

    fn add_warning(&mut self, warning: String) {
        self.warnings.push(warning);
    }
}

impl std::fmt::Display for VerificationReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.passed {
            writeln!(f, "Verification PASSED")?;
        } else {
            writeln!(f, "Verification FAILED")?;
        }

        if !self.errors.is_empty() {
            writeln!(f, "\nErrors:")?;
            for (i, error) in self.errors.iter().enumerate() {
                writeln!(f, "  {}. {}", i + 1, error)?;
            }
        }

        if !self.warnings.is_empty() {
            writeln!(f, "\nWarnings:")?;
            for (i, warning) in self.warnings.iter().enumerate() {
                writeln!(f, "  {}. {}", i + 1, warning)?;
            }
        }

        Ok(())
    }
}

/// Verification errors.
#[derive(Debug, thiserror::Error)]
pub enum VerificationError {
    #[error("invalid format_version: expected '{expected}', got '{actual}'")]
    InvalidFormatVersion { expected: String, actual: String },

    #[error("invalid hex field '{field}': {reason}")]
    InvalidHex { field: String, reason: String },

    #[error("invalid semver '{field}': {value}")]
    InvalidSemver { field: String, value: String },

    #[error("ELF file not found: {path}")]
    ElfNotFound { path: String },

    #[error("ELF hash mismatch: expected {expected}, computed {computed}")]
    ElfHashMismatch { expected: String, computed: String },

    #[error("IMAGE_ID mismatch: expected {expected}, computed {computed}")]
    ImageIdMismatch { expected: String, computed: String },

    #[error("placeholder value found in field '{field}' - run 'agent-pack compute' first")]
    PlaceholderFound { field: String },
}

/// Verifies a manifest's structure and format.
///
/// This performs "offline" validation that doesn't require any files:
/// - Format version check
/// - Hex string validation
/// - Semver validation
/// - Placeholder detection
pub fn verify_manifest_structure(manifest: &AgentPackManifest) -> VerificationReport {
    let mut report = VerificationReport::new();

    // Check format version
    if manifest.format_version != FORMAT_VERSION {
        report.add_error(VerificationError::InvalidFormatVersion {
            expected: FORMAT_VERSION.to_string(),
            actual: manifest.format_version.clone(),
        });
    }

    // Validate hex fields
    let hex_fields = [
        ("agent_id", &manifest.agent_id),
        ("agent_code_hash", &manifest.agent_code_hash),
        ("image_id", &manifest.image_id),
        ("artifacts.elf_sha256", &manifest.artifacts.elf_sha256),
        ("build.cargo_lock_sha256", &manifest.build.cargo_lock_sha256),
    ];

    for (field, value) in hex_fields {
        // Check for placeholder values
        if value.contains("TODO") {
            report.add_error(VerificationError::PlaceholderFound {
                field: field.to_string(),
            });
            continue;
        }

        // Validate hex format
        if let Err(e) = validate_hex_32(value) {
            report.add_error(VerificationError::InvalidHex {
                field: field.to_string(),
                reason: match e {
                    HexError::MissingPrefix => "missing 0x prefix".to_string(),
                    HexError::InvalidLength { expected, actual } => {
                        format!("expected {} hex chars, got {}", expected, actual)
                    }
                    HexError::InvalidHex(msg) => msg,
                },
            });
        }
    }

    // Validate semver
    if !is_valid_semver(&manifest.agent_version) {
        report.add_error(VerificationError::InvalidSemver {
            field: "agent_version".to_string(),
            value: manifest.agent_version.clone(),
        });
    }

    // Warnings for optional but recommended fields
    if manifest.git.is_none() {
        report.add_warning("git info not provided - recommended for traceability".to_string());
    }

    if manifest.networks.is_empty() {
        report.add_warning("no network deployments specified".to_string());
    }

    report
}

/// Verifies a manifest against actual files.
///
/// In addition to structure verification, this:
/// - Verifies ELF file exists and matches declared hash
/// - Recomputes IMAGE_ID (if risc0 feature enabled)
///
/// # Arguments
///
/// * `manifest` - The manifest to verify
/// * `base_path` - Base directory for resolving relative paths in the manifest
pub fn verify_manifest_with_files(
    manifest: &AgentPackManifest,
    base_path: &Path,
) -> VerificationReport {
    let mut report = verify_manifest_structure(manifest);

    // Skip file verification if structure validation failed
    if !report.passed {
        return report;
    }

    // Resolve ELF path
    let elf_path = base_path.join(&manifest.artifacts.elf_path);

    if !elf_path.exists() {
        report.add_error(VerificationError::ElfNotFound {
            path: elf_path.display().to_string(),
        });
        return report;
    }

    // Verify ELF hash
    match hash::sha256_file(&elf_path) {
        Ok(computed_hash) => {
            let computed_hex = hash::format_hex(&computed_hash);
            if computed_hex != manifest.artifacts.elf_sha256 {
                report.add_error(VerificationError::ElfHashMismatch {
                    expected: manifest.artifacts.elf_sha256.clone(),
                    computed: computed_hex,
                });
            }
        }
        Err(e) => {
            report.add_warning(format!(
                "Could not read ELF file for hash verification: {}",
                e
            ));
        }
    }

    // Verify IMAGE_ID if risc0 feature is enabled
    #[cfg(feature = "risc0")]
    {
        use crate::image_id::compute_image_id_from_file;

        match compute_image_id_from_file(&elf_path) {
            Ok(computed_id) => {
                let computed_hex = hash::format_hex(&computed_id);
                if computed_hex != manifest.image_id {
                    report.add_error(VerificationError::ImageIdMismatch {
                        expected: manifest.image_id.clone(),
                        computed: computed_hex,
                    });
                }
            }
            Err(e) => {
                report.add_warning(format!("Could not compute IMAGE_ID: {}", e));
            }
        }
    }

    #[cfg(not(feature = "risc0"))]
    {
        report.add_warning(
            "IMAGE_ID verification skipped - build with --features risc0 to enable".to_string(),
        );
    }

    report
}

/// Simple semver validation.
///
/// Accepts versions like "1.0.0", "0.1.0-alpha", "2.0.0-rc.1+build.123"
fn is_valid_semver(version: &str) -> bool {
    // Basic format: MAJOR.MINOR.PATCH with optional prerelease and build metadata
    let parts: Vec<&str> = version.split(['-', '+']).collect();

    if parts.is_empty() {
        return false;
    }

    // Check MAJOR.MINOR.PATCH
    let version_core: Vec<&str> = parts[0].split('.').collect();
    if version_core.len() != 3 {
        return false;
    }

    // Each part must be a valid number
    for part in version_core {
        if part.is_empty() || part.parse::<u64>().is_err() {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::AgentPackManifest;

    fn valid_manifest() -> AgentPackManifest {
        AgentPackManifest {
            format_version: "1".to_string(),
            agent_name: "test-agent".to_string(),
            agent_version: "1.0.0".to_string(),
            agent_id: "0x0000000000000000000000000000000000000000000000000000000000000001"
                .to_string(),
            protocol_version: 1,
            kernel_version: 1,
            risc0_version: "3.0.4".to_string(),
            rust_toolchain: "1.75.0".to_string(),
            agent_code_hash: "0x5aac6b1fedf1b0c0ccc037c3223b7b5c8b679f48b9c599336c0dc777be88924b"
                .to_string(),
            image_id: "0x5f42241afd61bf9e341442c8baffa9c544cf20253720f2540cf6705f27bae2c4"
                .to_string(),
            artifacts: crate::manifest::Artifacts {
                elf_path: "artifacts/zkvm-guest.elf".to_string(),
                elf_sha256: "0xabcdef0000000000000000000000000000000000000000000000000000000123"
                    .to_string(),
            },
            build: crate::manifest::BuildInfo {
                cargo_lock_sha256:
                    "0x1234560000000000000000000000000000000000000000000000000000000abc".to_string(),
                build_command: "cargo build --release".to_string(),
                reproducible: true,
            },
            inputs: "Test input".to_string(),
            actions_profile: "Test actions".to_string(),
            networks: std::collections::BTreeMap::new(),
            git: None,
            notes: None,
        }
    }

    #[test]
    fn test_valid_manifest_passes() {
        let manifest = valid_manifest();
        let report = verify_manifest_structure(&manifest);
        assert!(report.passed, "Report: {}", report);
    }

    #[test]
    fn test_invalid_format_version() {
        let mut manifest = valid_manifest();
        manifest.format_version = "2".to_string();
        let report = verify_manifest_structure(&manifest);
        assert!(!report.passed);
        assert!(report
            .errors
            .iter()
            .any(|e| matches!(e, VerificationError::InvalidFormatVersion { .. })));
    }

    #[test]
    fn test_invalid_hex_missing_prefix() {
        let mut manifest = valid_manifest();
        manifest.agent_id =
            "0000000000000000000000000000000000000000000000000000000000000001".to_string();
        let report = verify_manifest_structure(&manifest);
        assert!(!report.passed);
    }

    #[test]
    fn test_placeholder_detected() {
        let mut manifest = valid_manifest();
        manifest.image_id = "0xTODO_COMPUTE_THIS".to_string();
        let report = verify_manifest_structure(&manifest);
        assert!(!report.passed);
        assert!(report
            .errors
            .iter()
            .any(|e| matches!(e, VerificationError::PlaceholderFound { .. })));
    }

    #[test]
    fn test_valid_semver() {
        assert!(is_valid_semver("1.0.0"));
        assert!(is_valid_semver("0.1.0"));
        assert!(is_valid_semver("10.20.30"));
        assert!(is_valid_semver("1.0.0-alpha"));
        assert!(is_valid_semver("1.0.0-rc.1"));
        assert!(is_valid_semver("1.0.0+build.123"));
    }

    #[test]
    fn test_invalid_semver() {
        assert!(!is_valid_semver("1.0"));
        assert!(!is_valid_semver("1"));
        assert!(!is_valid_semver(""));
        assert!(!is_valid_semver("v1.0.0"));
        assert!(!is_valid_semver("1.0.0.0"));
    }
}
