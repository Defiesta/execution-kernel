//! Verification routines for Agent Pack bundles.
//!
//! Provides both offline verification (structure, hashes, imageId) and
//! on-chain verification (comparing manifest imageId with registry).

use crate::bundle::LoadedBundle;
use agent_pack::{verify_manifest_structure, verify_manifest_with_files, VerificationReport};

/// Result of offline verification.
#[derive(Debug)]
pub struct OfflineVerificationResult {
    /// The verification report from agent-pack.
    pub report: VerificationReport,
    /// Whether all checks passed.
    pub passed: bool,
}

/// Errors that can occur during verification.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("Offline verification failed: {0}")]
    OfflineFailed(String),

    #[cfg(feature = "onchain")]
    #[error("On-chain verification error: {0}")]
    OnchainError(String),

    #[cfg(feature = "onchain")]
    #[error("Agent not registered on-chain")]
    NotRegistered,

    #[cfg(feature = "onchain")]
    #[error("Image ID mismatch: on-chain={onchain}, manifest={manifest}")]
    ImageIdMismatch { onchain: String, manifest: String },
}

/// Verify a bundle offline (structure and file hashes).
///
/// This performs:
/// 1. Manifest structure validation (required fields, hex format, semver)
/// 2. ELF file existence and SHA-256 hash verification
/// 3. IMAGE_ID verification (if built with `risc0` feature in agent-pack)
///
/// # Arguments
///
/// * `bundle` - The loaded bundle to verify
///
/// # Returns
///
/// An `OfflineVerificationResult` containing the detailed report and pass/fail status.
pub fn verify_offline(bundle: &LoadedBundle) -> OfflineVerificationResult {
    // Use agent-pack's verification which checks structure + files
    let report = verify_manifest_with_files(&bundle.manifest, &bundle.base_dir);

    OfflineVerificationResult {
        passed: report.passed,
        report,
    }
}

/// Verify only the manifest structure (no file checks).
///
/// Useful for quick validation when you only have the manifest.
pub fn verify_structure(bundle: &LoadedBundle) -> OfflineVerificationResult {
    let report = verify_manifest_structure(&bundle.manifest);

    OfflineVerificationResult {
        passed: report.passed,
        report,
    }
}

/// Result of on-chain verification.
#[cfg(feature = "onchain")]
#[derive(Debug)]
pub enum OnchainVerificationResult {
    /// The manifest imageId matches the on-chain registry.
    Match,
    /// The imageIds do not match.
    Mismatch { onchain: String, manifest: String },
    /// The agent is not registered on-chain.
    NotRegistered,
}

/// Verify a bundle's imageId against the on-chain registry.
///
/// Queries the KernelExecutionVerifier contract to check if the agent's
/// imageId matches what's registered on-chain.
///
/// # Arguments
///
/// * `bundle` - The loaded bundle to verify
/// * `rpc_url` - RPC endpoint URL
/// * `verifier_address` - KernelExecutionVerifier contract address
///
/// # Returns
///
/// `OnchainVerificationResult` indicating match, mismatch, or not registered.
#[cfg(feature = "onchain")]
pub async fn verify_onchain(
    bundle: &LoadedBundle,
    rpc_url: &str,
    verifier_address: &str,
) -> Result<OnchainVerificationResult, VerifyError> {
    use agent_pack::onchain::{
        verify_onchain as ap_verify_onchain, OnchainVerifyResult as ApResult,
    };

    let result = ap_verify_onchain(
        rpc_url,
        verifier_address,
        &bundle.manifest.agent_id,
        &bundle.manifest.image_id,
    )
    .await
    .map_err(|e| VerifyError::OnchainError(e.to_string()))?;

    match result {
        ApResult::Match => Ok(OnchainVerificationResult::Match),
        ApResult::Mismatch { onchain, manifest } => {
            Ok(OnchainVerificationResult::Mismatch { onchain, manifest })
        }
        ApResult::NotRegistered => Ok(OnchainVerificationResult::NotRegistered),
    }
}

/// Verify a bundle both offline and on-chain.
///
/// This is the recommended verification flow for marketplaces:
/// 1. First verify offline (structure + hashes)
/// 2. Then verify on-chain (imageId registration)
///
/// Only proceeds to on-chain verification if offline passes.
///
/// # Arguments
///
/// * `bundle` - The loaded bundle to verify
/// * `rpc_url` - RPC endpoint URL
/// * `verifier_address` - KernelExecutionVerifier contract address
///
/// # Returns
///
/// Success if both verifications pass, error otherwise.
#[cfg(feature = "onchain")]
pub async fn verify_full(
    bundle: &LoadedBundle,
    rpc_url: &str,
    verifier_address: &str,
) -> Result<(), VerifyError> {
    // Step 1: Offline verification
    let offline_result = verify_offline(bundle);
    if !offline_result.passed {
        return Err(VerifyError::OfflineFailed(format!(
            "{}",
            offline_result.report
        )));
    }

    // Step 2: On-chain verification
    let onchain_result = verify_onchain(bundle, rpc_url, verifier_address).await?;

    match onchain_result {
        OnchainVerificationResult::Match => Ok(()),
        OnchainVerificationResult::Mismatch { onchain, manifest } => {
            Err(VerifyError::ImageIdMismatch { onchain, manifest })
        }
        OnchainVerificationResult::NotRegistered => Err(VerifyError::NotRegistered),
    }
}

#[cfg(test)]
mod tests {
    // Note: Full integration tests require the agent-pack fixtures
    // See tests/integration.rs for bundle loading tests
}
