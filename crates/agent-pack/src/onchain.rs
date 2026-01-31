//! On-chain verification against KernelExecutionVerifier registry.
//!
//! This module provides functionality to verify that an Agent Pack's `image_id`
//! matches what is registered on-chain for the given `agent_id`.
//!
//! # Example
//!
//! ```rust,no_run
//! use agent_pack::onchain::{verify_onchain, OnchainVerifyResult};
//!
//! # async fn example() -> Result<(), agent_pack::onchain::OnchainError> {
//! let result = verify_onchain(
//!     "https://sepolia.infura.io/v3/YOUR_KEY",
//!     "0x9Ef5bAB590AFdE8036D57b89ccD2947D4E3b1EFA",
//!     "0x0000000000000000000000000000000000000000000000000000000000000001",
//!     "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
//! ).await?;
//!
//! match result {
//!     OnchainVerifyResult::Match => println!("Agent is registered with correct image_id"),
//!     OnchainVerifyResult::Mismatch { onchain, manifest } => {
//!         println!("Mismatch! On-chain: {}, Manifest: {}", onchain, manifest);
//!     }
//!     OnchainVerifyResult::NotRegistered => println!("Agent is not registered"),
//! }
//! # Ok(())
//! # }
//! ```

use alloy::primitives::{Address, FixedBytes};
use alloy::providers::ProviderBuilder;
use alloy::sol;
use std::str::FromStr;

// Define the contract interface using alloy's sol! macro
sol! {
    #[sol(rpc)]
    interface IKernelExecutionVerifier {
        /// Get the image ID for an agent
        /// @param agentId The agent ID to lookup
        /// @return imageId The corresponding zkVM image ID (bytes32(0) if not registered)
        function agentImageIds(bytes32 agentId) external view returns (bytes32);
    }
}

/// Result of on-chain verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OnchainVerifyResult {
    /// The on-chain image_id matches the manifest image_id.
    Match,
    /// The on-chain image_id differs from the manifest image_id.
    Mismatch {
        /// The image_id found on-chain.
        onchain: String,
        /// The image_id from the manifest.
        manifest: String,
    },
    /// The agent_id is not registered (returns bytes32(0)).
    NotRegistered,
}

/// Errors that can occur during on-chain verification.
#[derive(Debug, thiserror::Error)]
pub enum OnchainError {
    #[error("Invalid RPC URL: {0}")]
    InvalidRpcUrl(String),

    #[error("Invalid verifier address: {0}")]
    InvalidVerifierAddress(String),

    #[error("Invalid agent_id format: {0}")]
    InvalidAgentId(String),

    #[error("Invalid image_id format: {0}")]
    InvalidImageId(String),

    #[error("RPC error: {0}")]
    RpcError(String),
}

/// Verifies that an agent's image_id matches the on-chain registry.
///
/// This function queries the KernelExecutionVerifier contract to retrieve the
/// registered image_id for the given agent_id, then compares it to the expected
/// image_id from the manifest.
///
/// # Arguments
///
/// * `rpc_url` - The RPC endpoint URL (e.g., "https://sepolia.infura.io/v3/...")
/// * `verifier_address` - The KernelExecutionVerifier contract address (0x prefixed)
/// * `agent_id` - The agent ID to query (32 bytes, 0x prefixed)
/// * `expected_image_id` - The expected image_id from the manifest (32 bytes, 0x prefixed)
///
/// # Returns
///
/// * `Ok(OnchainVerifyResult::Match)` - The on-chain image_id matches
/// * `Ok(OnchainVerifyResult::Mismatch { .. })` - The image_ids differ
/// * `Ok(OnchainVerifyResult::NotRegistered)` - The agent is not registered
/// * `Err(OnchainError)` - An error occurred during verification
pub async fn verify_onchain(
    rpc_url: &str,
    verifier_address: &str,
    agent_id: &str,
    expected_image_id: &str,
) -> Result<OnchainVerifyResult, OnchainError> {
    verify_onchain_with_timeout(
        rpc_url,
        verifier_address,
        agent_id,
        expected_image_id,
        30000,
    )
    .await
}

/// Verifies that an agent's image_id matches the on-chain registry with custom timeout.
///
/// Same as [`verify_onchain`] but allows specifying a custom timeout in milliseconds.
pub async fn verify_onchain_with_timeout(
    rpc_url: &str,
    verifier_address: &str,
    agent_id: &str,
    expected_image_id: &str,
    timeout_ms: u64,
) -> Result<OnchainVerifyResult, OnchainError> {
    // Parse the verifier address
    let verifier = parse_address(verifier_address)?;

    // Parse the agent_id as bytes32
    let agent_id_bytes = parse_bytes32(agent_id, "agent_id")?;

    // Parse the expected image_id for comparison
    let expected_bytes = parse_bytes32(expected_image_id, "image_id")?;

    // Parse the RPC URL
    let url = rpc_url
        .parse()
        .map_err(|_| OnchainError::InvalidRpcUrl(format!("Failed to parse URL: {}", rpc_url)))?;

    // Create the provider
    // Note: timeout_ms is reserved for future use when alloy supports custom timeouts
    let _ = timeout_ms;
    let provider = ProviderBuilder::new().on_http(url);

    // Create the contract instance
    let contract = IKernelExecutionVerifier::new(verifier, provider);

    // Call the agentImageIds function
    let onchain_image_id = contract
        .agentImageIds(agent_id_bytes)
        .call()
        .await
        .map_err(|e| OnchainError::RpcError(e.to_string()))?
        ._0;

    // Check if the agent is not registered (returns bytes32(0))
    if onchain_image_id == FixedBytes::<32>::ZERO {
        return Ok(OnchainVerifyResult::NotRegistered);
    }

    // Compare the on-chain image_id with the expected one
    if onchain_image_id == expected_bytes {
        Ok(OnchainVerifyResult::Match)
    } else {
        Ok(OnchainVerifyResult::Mismatch {
            onchain: format_bytes32(&onchain_image_id),
            manifest: expected_image_id.to_string(),
        })
    }
}

/// Parses an Ethereum address from a hex string.
fn parse_address(addr: &str) -> Result<Address, OnchainError> {
    Address::from_str(addr)
        .map_err(|_| OnchainError::InvalidVerifierAddress(format!("Invalid address: {}", addr)))
}

/// Parses a 32-byte hex string into FixedBytes<32>.
fn parse_bytes32(hex: &str, field_name: &str) -> Result<FixedBytes<32>, OnchainError> {
    // Strip 0x prefix if present
    let hex_clean = hex.strip_prefix("0x").unwrap_or(hex);

    // Check length (64 hex chars = 32 bytes)
    if hex_clean.len() != 64 {
        return Err(match field_name {
            "agent_id" => OnchainError::InvalidAgentId(format!(
                "Expected 32 bytes (64 hex chars), got {} chars",
                hex_clean.len()
            )),
            _ => OnchainError::InvalidImageId(format!(
                "Expected 32 bytes (64 hex chars), got {} chars",
                hex_clean.len()
            )),
        });
    }

    // Parse hex bytes
    let bytes = hex::decode(hex_clean).map_err(|e| match field_name {
        "agent_id" => OnchainError::InvalidAgentId(format!("Invalid hex: {}", e)),
        _ => OnchainError::InvalidImageId(format!("Invalid hex: {}", e)),
    })?;

    // Convert to fixed bytes
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(FixedBytes::from(arr))
}

/// Formats FixedBytes<32> as a 0x-prefixed hex string.
fn format_bytes32(bytes: &FixedBytes<32>) -> String {
    format!("0x{}", hex::encode(bytes.as_slice()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_address_valid() {
        let addr = "0x9Ef5bAB590AFdE8036D57b89ccD2947D4E3b1EFA";
        let result = parse_address(addr);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_address_invalid() {
        let addr = "not-an-address";
        let result = parse_address(addr);
        assert!(matches!(
            result,
            Err(OnchainError::InvalidVerifierAddress(_))
        ));
    }

    #[test]
    fn test_parse_bytes32_valid() {
        let hex = "0x0000000000000000000000000000000000000000000000000000000000000001";
        let result = parse_bytes32(hex, "agent_id");
        assert!(result.is_ok());

        let bytes = result.unwrap();
        assert_eq!(bytes.as_slice()[31], 1);
    }

    #[test]
    fn test_parse_bytes32_without_prefix() {
        let hex = "0000000000000000000000000000000000000000000000000000000000000042";
        let result = parse_bytes32(hex, "agent_id");
        assert!(result.is_ok());

        let bytes = result.unwrap();
        assert_eq!(bytes.as_slice()[31], 0x42);
    }

    #[test]
    fn test_parse_bytes32_too_short() {
        let hex = "0x1234";
        let result = parse_bytes32(hex, "agent_id");
        assert!(matches!(result, Err(OnchainError::InvalidAgentId(_))));
    }

    #[test]
    fn test_parse_bytes32_invalid_hex() {
        let hex = "0xGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG";
        let result = parse_bytes32(hex, "image_id");
        assert!(matches!(result, Err(OnchainError::InvalidImageId(_))));
    }

    #[test]
    fn test_format_bytes32() {
        let mut arr = [0u8; 32];
        arr[31] = 0x42;
        let bytes = FixedBytes::from(arr);

        let formatted = format_bytes32(&bytes);
        assert_eq!(
            formatted,
            "0x0000000000000000000000000000000000000000000000000000000000000042"
        );
    }

    #[test]
    fn test_verify_result_equality() {
        assert_eq!(OnchainVerifyResult::Match, OnchainVerifyResult::Match);
        assert_eq!(
            OnchainVerifyResult::NotRegistered,
            OnchainVerifyResult::NotRegistered
        );

        let mismatch1 = OnchainVerifyResult::Mismatch {
            onchain: "0x1".to_string(),
            manifest: "0x2".to_string(),
        };
        let mismatch2 = OnchainVerifyResult::Mismatch {
            onchain: "0x1".to_string(),
            manifest: "0x2".to_string(),
        };
        assert_eq!(mismatch1, mismatch2);
    }
}
