//! Proof generation for kernel execution.
//!
//! This module wraps RISC Zero zkVM proving functionality to generate proofs
//! of kernel execution. It is feature-gated behind the `prove` feature.

#[cfg(feature = "prove")]
use kernel_core::CanonicalDecode;
use kernel_core::KernelJournalV1;

/// Proving mode options.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProvingMode {
    /// Generate a Groth16 proof (suitable for on-chain verification).
    /// This is slower but produces a small proof that can be verified on-chain.
    #[default]
    Groth16,
    /// Generate a fast proof (for development/testing).
    /// Not suitable for on-chain verification.
    Dev,
}

/// Result of proof generation.
#[derive(Debug, Clone)]
pub struct ProveResult {
    /// The journal bytes (209 bytes, contains execution result).
    pub journal_bytes: Vec<u8>,
    /// The seal bytes (proof data for on-chain verification).
    pub seal_bytes: Vec<u8>,
    /// The decoded journal for inspection.
    pub journal: KernelJournalV1,
}

/// Errors that can occur during proving.
#[derive(Debug, thiserror::Error)]
pub enum ProveError {
    #[error("Failed to read ELF file: {0}")]
    ElfReadError(String),

    #[error("Failed to build executor environment: {0}")]
    EnvBuildError(String),

    #[error("Proof generation failed: {0}")]
    ProofGenerationFailed(String),

    #[error("Receipt verification failed: {0}")]
    ReceiptVerificationFailed(String),

    #[error("Failed to decode journal: {0}")]
    JournalDecodeError(String),

    #[error("Proving feature not enabled. Build with --features prove")]
    FeatureNotEnabled,
}

/// Generate a proof of kernel execution.
///
/// This function:
/// 1. Loads the ELF binary from the bundle
/// 2. Runs the zkVM prover with the input bytes
/// 3. Extracts the journal (execution result) and seal (proof)
///
/// # Arguments
///
/// * `elf_bytes` - The ELF binary bytes (from bundle.read_elf())
/// * `input_bytes` - Encoded KernelInputV1 bytes
/// * `mode` - Proving mode (Groth16 for on-chain, Dev for testing)
///
/// # Returns
///
/// A `ProveResult` containing journal bytes, seal bytes, and decoded journal.
///
/// # Feature
///
/// This function requires the `prove` feature to be enabled.
#[cfg(feature = "prove")]
pub fn prove(
    elf_bytes: &[u8],
    input_bytes: &[u8],
    mode: ProvingMode,
) -> Result<ProveResult, ProveError> {
    use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts};

    // Build executor environment with input
    let env = ExecutorEnv::builder()
        .write(&input_bytes.to_vec())
        .map_err(|e| ProveError::EnvBuildError(format!("Failed to write input: {}", e)))?
        .build()
        .map_err(|e| ProveError::EnvBuildError(e.to_string()))?;

    // Select prover options based on mode
    let opts = match mode {
        ProvingMode::Groth16 => ProverOpts::groth16(),
        ProvingMode::Dev => ProverOpts::default(),
    };

    // Run the prover
    let prover = default_prover();
    let prove_info = prover
        .prove_with_opts(env, elf_bytes, &opts)
        .map_err(|e| ProveError::ProofGenerationFailed(e.to_string()))?;

    let receipt = prove_info.receipt;

    // Extract journal bytes
    let journal_bytes = receipt.journal.bytes.clone();

    // Decode journal
    let journal = KernelJournalV1::decode(&journal_bytes)
        .map_err(|e| ProveError::JournalDecodeError(format!("{:?}", e)))?;

    // Extract seal bytes based on proof type
    let seal_bytes = match &receipt.inner {
        risc0_zkvm::InnerReceipt::Groth16(groth16_receipt) => {
            // For on-chain verification: [4-byte selector][seal]
            let selector = &groth16_receipt.verifier_parameters.as_bytes()[..4];
            let mut encoded_seal = Vec::with_capacity(4 + groth16_receipt.seal.len());
            encoded_seal.extend_from_slice(selector);
            encoded_seal.extend_from_slice(&groth16_receipt.seal);
            encoded_seal
        }
        _ => {
            // For dev mode, return empty seal (not verifiable on-chain)
            Vec::new()
        }
    };

    Ok(ProveResult {
        journal_bytes,
        seal_bytes,
        journal,
    })
}

/// Stub implementation when prove feature is not enabled.
#[cfg(not(feature = "prove"))]
pub fn prove(
    _elf_bytes: &[u8],
    _input_bytes: &[u8],
    _mode: ProvingMode,
) -> Result<ProveResult, ProveError> {
    Err(ProveError::FeatureNotEnabled)
}

/// Check if proving is available.
///
/// Returns true if the crate was compiled with the `prove` feature.
pub fn is_proving_available() -> bool {
    cfg!(feature = "prove")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proving_mode_default() {
        assert_eq!(ProvingMode::default(), ProvingMode::Groth16);
    }

    #[test]
    fn test_is_proving_available() {
        // This test just verifies the function compiles and runs
        let available = is_proving_available();
        #[cfg(feature = "prove")]
        assert!(available);
        #[cfg(not(feature = "prove"))]
        assert!(!available);
    }

    #[cfg(not(feature = "prove"))]
    #[test]
    fn test_prove_without_feature() {
        let result = prove(&[], &[], ProvingMode::Groth16);
        assert!(matches!(result, Err(ProveError::FeatureNotEnabled)));
    }
}
