//! Agent Pack - Portable bundles for verifiable agent distribution.
//!
//! This crate provides tools for creating and verifying Agent Pack bundles,
//! which are self-contained packages containing all metadata needed to verify
//! an agent's identity and provenance.
//!
//! # Overview
//!
//! An Agent Pack manifest binds together:
//! - Agent metadata (name, version, ID)
//! - Cryptographic commitments (code hash, IMAGE_ID)
//! - Build information for reproducibility
//! - Network deployment addresses
//!
//! # Example
//!
//! ```rust,no_run
//! use agent_pack::{AgentPackManifest, verify_manifest_structure};
//!
//! // Load a manifest
//! let manifest = AgentPackManifest::from_file("agent-pack.json".as_ref()).unwrap();
//!
//! // Verify its structure
//! let report = verify_manifest_structure(&manifest);
//! if report.passed {
//!     println!("Manifest is valid!");
//! } else {
//!     eprintln!("Verification failed:\n{}", report);
//! }
//! ```
//!
//! # Features
//!
//! - `risc0` - Enable IMAGE_ID computation from ELF binaries
//! - `onchain` - Enable on-chain verification against KernelExecutionVerifier

pub mod hash;
pub mod image_id;
pub mod manifest;
#[cfg(feature = "onchain")]
pub mod onchain;
pub mod pack;
pub mod scaffold;
pub mod verify;

// Re-export main types at crate root
pub use hash::{format_hex, parse_hex_32, sha256, sha256_file, validate_hex_32, HexError};
pub use image_id::{compute_image_id_from_bytes, compute_image_id_from_file, ImageIdError};
pub use manifest::{
    AgentPackManifest, Artifacts, BuildInfo, GitInfo, ManifestError, NetworkConfig, FORMAT_VERSION,
};
pub use pack::{pack_bundle, PackError, PackOptions, PackResult};
pub use scaffold::{scaffold, ScaffoldError, ScaffoldOptions, ScaffoldResult, TemplateType};
pub use verify::{
    verify_manifest_structure, verify_manifest_with_files, VerificationError, VerificationReport,
};

/// Crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
