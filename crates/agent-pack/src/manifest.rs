//! Agent Pack manifest types and serialization.
//!
//! Defines the [`AgentPackManifest`] structure that represents a portable,
//! verifiable bundle for distributing agents.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The Agent Pack manifest format version.
pub const FORMAT_VERSION: &str = "1";

/// An Agent Pack manifest containing all metadata required for verification.
///
/// This structure is designed to be:
/// - **Self-contained**: All information needed for offline verification
/// - **Deterministic**: Uses BTreeMap for ordered serialization
/// - **Verifiable**: Contains cryptographic commitments that can be recomputed
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentPackManifest {
    /// Format version of this manifest (currently "1")
    pub format_version: String,

    /// Human-readable agent name (e.g., "yield-agent")
    pub agent_name: String,

    /// Semantic version of the agent (e.g., "0.1.0")
    pub agent_version: String,

    /// 32-byte agent identifier as hex string with 0x prefix
    pub agent_id: String,

    /// Protocol version this agent targets
    pub protocol_version: u32,

    /// Kernel version this agent was built for
    pub kernel_version: u32,

    /// RISC Zero zkVM version used for compilation
    pub risc0_version: String,

    /// Rust toolchain version used for compilation
    pub rust_toolchain: String,

    /// SHA-256 hash of the agent code, as computed by build.rs
    /// 32-byte hex string with 0x prefix
    pub agent_code_hash: String,

    /// RISC Zero IMAGE_ID computed from the ELF binary
    /// 32-byte hex string with 0x prefix
    pub image_id: String,

    /// Build artifact information
    pub artifacts: Artifacts,

    /// Build configuration and reproducibility info
    pub build: BuildInfo,

    /// Human-readable description of expected input format
    pub inputs: String,

    /// Human-readable description of actions produced
    pub actions_profile: String,

    /// Network-specific deployment addresses
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub networks: BTreeMap<String, NetworkConfig>,

    /// Git repository information
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git: Option<GitInfo>,

    /// Additional notes or comments
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

/// Build artifact paths and hashes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Artifacts {
    /// Relative path to the ELF binary
    pub elf_path: String,

    /// SHA-256 hash of the ELF binary
    /// 32-byte hex string with 0x prefix
    pub elf_sha256: String,
}

/// Build configuration for reproducibility.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BuildInfo {
    /// SHA-256 hash of Cargo.lock
    /// 32-byte hex string with 0x prefix
    pub cargo_lock_sha256: String,

    /// Command used to build the agent
    pub build_command: String,

    /// Whether the build is reproducible (e.g., using Docker)
    pub reproducible: bool,
}

/// Network-specific deployment configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NetworkConfig {
    /// Address of the RISC Zero verifier contract
    pub verifier: String,

    /// Address of the vault or target contract (if applicable)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault: Option<String>,
}

/// Git repository information.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GitInfo {
    /// Repository URL
    pub repo: String,

    /// Commit hash
    pub commit: String,
}

impl AgentPackManifest {
    /// Creates a new manifest with placeholder values for computed fields.
    ///
    /// Use this when initializing a new manifest template. The following fields
    /// will contain "TODO" placeholders that must be computed:
    /// - `agent_code_hash`
    /// - `image_id`
    /// - `artifacts.elf_sha256`
    /// - `build.cargo_lock_sha256`
    pub fn new_template(name: String, version: String, agent_id: String) -> Self {
        let placeholder =
            "0xTODO_COMPUTE_THIS_VALUE_________________________________________________";

        Self {
            format_version: FORMAT_VERSION.to_string(),
            agent_name: name,
            agent_version: version,
            agent_id,
            protocol_version: 1,
            kernel_version: 1,
            risc0_version: "3.0.4".to_string(),
            rust_toolchain: "1.75.0".to_string(),
            agent_code_hash: placeholder.to_string(),
            image_id: placeholder.to_string(),
            artifacts: Artifacts {
                elf_path: "artifacts/zkvm-guest.elf".to_string(),
                elf_sha256: placeholder.to_string(),
            },
            build: BuildInfo {
                cargo_lock_sha256: placeholder.to_string(),
                build_command: "RISC0_USE_DOCKER=1 cargo build --release -p risc0-methods"
                    .to_string(),
                reproducible: true,
            },
            inputs: "TODO: Describe your agent's input format".to_string(),
            actions_profile: "TODO: Describe the actions your agent produces".to_string(),
            networks: BTreeMap::new(),
            git: None,
            notes: None,
        }
    }

    /// Serializes the manifest to pretty-printed JSON.
    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserializes a manifest from JSON.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Loads a manifest from a file path.
    pub fn from_file(path: &std::path::Path) -> Result<Self, ManifestError> {
        let content =
            std::fs::read_to_string(path).map_err(|e| ManifestError::Io(e.to_string()))?;
        Self::from_json(&content).map_err(|e| ManifestError::Parse(e.to_string()))
    }

    /// Saves the manifest to a file path.
    pub fn to_file(&self, path: &std::path::Path) -> Result<(), ManifestError> {
        let json = self
            .to_json_pretty()
            .map_err(|e| ManifestError::Serialize(e.to_string()))?;
        std::fs::write(path, json).map_err(|e| ManifestError::Io(e.to_string()))
    }
}

/// Errors that can occur when working with manifests.
#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("I/O error: {0}")]
    Io(String),

    #[error("Failed to parse manifest: {0}")]
    Parse(String),

    #[error("Failed to serialize manifest: {0}")]
    Serialize(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manifest_roundtrip() {
        let manifest = AgentPackManifest::new_template(
            "test-agent".to_string(),
            "1.0.0".to_string(),
            "0x0000000000000000000000000000000000000000000000000000000000000001".to_string(),
        );

        let json = manifest.to_json_pretty().unwrap();
        let parsed = AgentPackManifest::from_json(&json).unwrap();

        assert_eq!(manifest, parsed);
    }

    #[test]
    fn test_template_has_placeholders() {
        let manifest = AgentPackManifest::new_template(
            "test".to_string(),
            "1.0.0".to_string(),
            "0x42".to_string(),
        );

        assert!(manifest.agent_code_hash.contains("TODO"));
        assert!(manifest.image_id.contains("TODO"));
        assert!(manifest.artifacts.elf_sha256.contains("TODO"));
        assert!(manifest.build.cargo_lock_sha256.contains("TODO"));
    }
}
