//! Reference Integrator - A production-quality reference implementation for
//! integrating with Agent Pack bundles.
//!
//! This crate demonstrates the complete marketplace integration flow:
//! 1. Load an Agent Pack bundle
//! 2. Verify offline (structure, hashes, imageId)
//! 3. Verify on-chain (imageId registration)
//! 4. Build kernel input
//! 5. Generate proof
//! 6. Execute on-chain via vault
//!
//! # Features
//!
//! - `cli` (default) - Enables the `refint` CLI binary
//! - `onchain` - Enables on-chain verification and execution (requires alloy + tokio)
//! - `prove` - Enables proof generation (requires risc0-zkvm)
//! - `full` - Enables all features
//!
//! # Example: Basic Offline Verification
//!
//! ```rust,no_run
//! use reference_integrator::{LoadedBundle, verify_offline};
//!
//! // Load the bundle
//! let bundle = LoadedBundle::load("./my-agent-bundle").unwrap();
//!
//! // Verify offline
//! let result = verify_offline(&bundle);
//! if result.passed {
//!     println!("Bundle verified successfully!");
//! } else {
//!     eprintln!("Verification failed:\n{}", result.report);
//! }
//! ```
//!
//! # Example: Full Integration Flow (requires features)
//!
//! ```rust,ignore
//! use reference_integrator::{
//!     LoadedBundle, verify_offline, verify_onchain, build_and_encode_input,
//!     prove, execute_onchain, InputParams, ProvingMode,
//! };
//!
//! // 1. Load and verify bundle
//! let bundle = LoadedBundle::load("./my-agent-bundle")?;
//!
//! // 2. Offline verification
//! let offline = verify_offline(&bundle);
//! assert!(offline.passed, "Offline verification failed");
//!
//! // 3. On-chain verification
//! let onchain = verify_onchain(&bundle, RPC_URL, VERIFIER_ADDR).await?;
//! assert!(matches!(onchain, OnchainVerificationResult::Match));
//!
//! // 4. Build input
//! let params = InputParams {
//!     execution_nonce: 1,
//!     opaque_agent_inputs: vec![/* agent-specific data */],
//!     ..Default::default()
//! };
//! let input_bytes = build_and_encode_input(&bundle, &params)?;
//!
//! // 5. Generate proof
//! let elf = bundle.read_elf()?;
//! let proof = prove(&elf, &input_bytes, ProvingMode::Groth16)?;
//!
//! // 6. Execute on-chain
//! let result = execute_onchain(
//!     VAULT_ADDR, RPC_URL, PRIVATE_KEY,
//!     &proof.journal_bytes, &proof.seal_bytes, &agent_output_bytes
//! ).await?;
//!
//! println!("Executed! Tx: {}", result.tx_hash);
//! ```

pub mod agent_output;
pub mod bundle;
pub mod execute;
pub mod input;
pub mod prove;
pub mod verify;

// Re-export main types at crate root for convenience
pub use agent_output::{reconstruct_yield_agent_output, AgentOutputError};
pub use bundle::{BundleError, LoadedBundle};
pub use execute::{is_onchain_available, ExecuteError};
pub use input::{
    build_and_encode_input, build_kernel_input, build_kernel_input_raw, parse_hex, parse_hex_32,
    InputError, InputParams,
};
pub use prove::{is_proving_available, ProveError, ProveResult, ProvingMode};
pub use verify::{verify_offline, verify_structure, OfflineVerificationResult, VerifyError};

// Conditional re-exports based on features
#[cfg(feature = "onchain")]
pub use execute::execute_onchain;

#[cfg(feature = "onchain")]
pub use verify::{verify_full, verify_onchain, OnchainVerificationResult};

#[cfg(feature = "prove")]
pub use prove::prove;

// Re-export useful types from dependencies
pub use kernel_core::{
    AgentOutput, CanonicalDecode, CanonicalEncode, ExecutionStatus, KernelInputV1, KernelJournalV1,
    KERNEL_VERSION, PROTOCOL_VERSION,
};

/// Crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Check which features are enabled.
pub fn feature_status() -> FeatureStatus {
    FeatureStatus {
        cli: cfg!(feature = "cli"),
        onchain: cfg!(feature = "onchain"),
        prove: cfg!(feature = "prove"),
    }
}

/// Status of optional features.
#[derive(Debug, Clone)]
pub struct FeatureStatus {
    /// CLI binary is available.
    pub cli: bool,
    /// On-chain verification and execution is available.
    pub onchain: bool,
    /// Proof generation is available.
    pub prove: bool,
}

impl std::fmt::Display for FeatureStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Feature Status:")?;
        writeln!(
            f,
            "  cli:     {}",
            if self.cli { "enabled" } else { "disabled" }
        )?;
        writeln!(
            f,
            "  onchain: {}",
            if self.onchain { "enabled" } else { "disabled" }
        )?;
        writeln!(
            f,
            "  prove:   {}",
            if self.prove { "enabled" } else { "disabled" }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        // Verify version string has expected format (e.g., "0.1.0")
        assert!(VERSION.contains('.'));
    }

    #[test]
    fn test_feature_status() {
        let status = feature_status();
        // Just verify it compiles and runs
        let _ = format!("{}", status);
    }
}
