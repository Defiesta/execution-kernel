//! On-chain execution via KernelVault contract.
//!
//! This module provides functionality to submit proofs to the KernelVault
//! contract for execution. It is feature-gated behind the `onchain` feature.

/// Result of on-chain execution.
#[cfg(feature = "onchain")]
#[derive(Debug, Clone)]
pub struct ExecuteResult {
    /// Transaction hash.
    pub tx_hash: String,
    /// Block number where the transaction was included.
    pub block_number: Option<u64>,
    /// Whether the transaction succeeded.
    pub success: bool,
}

/// Errors that can occur during execution.
#[derive(Debug, thiserror::Error)]
pub enum ExecuteError {
    #[error("Invalid RPC URL: {0}")]
    InvalidRpcUrl(String),

    #[error("Invalid vault address: {0}")]
    InvalidVaultAddress(String),

    #[error("Invalid private key")]
    InvalidPrivateKey,

    #[error("Transaction failed: {0}")]
    TransactionFailed(String),

    #[error("RPC error: {0}")]
    RpcError(String),

    #[error("On-chain feature not enabled. Build with --features onchain")]
    FeatureNotEnabled,
}

/// Execute a proven result on-chain via the KernelVault contract.
///
/// This function:
/// 1. Connects to the RPC endpoint
/// 2. Builds a transaction calling vault.execute(journal, seal, agentOutputBytes)
/// 3. Signs and sends the transaction
/// 4. Waits for confirmation
///
/// # Arguments
///
/// * `vault_address` - KernelVault contract address (0x prefixed)
/// * `rpc_url` - RPC endpoint URL
/// * `private_key` - Private key for signing (0x prefixed hex)
/// * `journal_bytes` - The journal from proof generation (209 bytes)
/// * `seal_bytes` - The seal from proof generation
/// * `agent_output_bytes` - The raw agent output (actions that were committed)
///
/// # Returns
///
/// An `ExecuteResult` with transaction details.
///
/// # Feature
///
/// This function requires the `onchain` feature to be enabled.
#[cfg(feature = "onchain")]
pub async fn execute_onchain(
    vault_address: &str,
    rpc_url: &str,
    private_key: &str,
    journal_bytes: &[u8],
    seal_bytes: &[u8],
    agent_output_bytes: &[u8],
) -> Result<ExecuteResult, ExecuteError> {
    use alloy::network::EthereumWallet;
    use alloy::primitives::{Address, Bytes};
    use alloy::providers::ProviderBuilder;
    use alloy::signers::local::PrivateKeySigner;
    use alloy::sol;
    use std::str::FromStr;

    // Define the vault interface
    sol! {
        #[sol(rpc)]
        interface IKernelVault {
            function execute(bytes calldata journal, bytes calldata seal, bytes calldata agentOutputBytes) external;
        }
    }

    // Parse vault address
    let vault = Address::from_str(vault_address)
        .map_err(|_| ExecuteError::InvalidVaultAddress(vault_address.to_string()))?;

    // Parse RPC URL
    let url = rpc_url
        .parse()
        .map_err(|_| ExecuteError::InvalidRpcUrl(rpc_url.to_string()))?;

    // Parse private key
    let pk_clean = private_key.strip_prefix("0x").unwrap_or(private_key);
    let signer: PrivateKeySigner = pk_clean
        .parse()
        .map_err(|_| ExecuteError::InvalidPrivateKey)?;

    let wallet = EthereumWallet::from(signer);

    // Create provider with wallet and recommended fillers (gas estimation, nonce, etc.)
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(wallet)
        .on_http(url);

    // Create contract instance
    let contract = IKernelVault::new(vault, provider);

    // Build the transaction
    let journal = Bytes::copy_from_slice(journal_bytes);
    let seal = Bytes::copy_from_slice(seal_bytes);
    let agent_output = Bytes::copy_from_slice(agent_output_bytes);

    // Send the transaction
    let tx = contract
        .execute(journal, seal, agent_output)
        .send()
        .await
        .map_err(|e| ExecuteError::TransactionFailed(e.to_string()))?;

    // Wait for confirmation
    let receipt = tx
        .get_receipt()
        .await
        .map_err(|e| ExecuteError::RpcError(e.to_string()))?;

    let tx_hash = format!("0x{}", hex::encode(receipt.transaction_hash.as_slice()));
    let block_number = receipt.block_number;
    let success = receipt.status();

    Ok(ExecuteResult {
        tx_hash,
        block_number,
        success,
    })
}

/// Stub implementation when onchain feature is not enabled.
#[cfg(not(feature = "onchain"))]
pub async fn execute_onchain(
    _vault_address: &str,
    _rpc_url: &str,
    _private_key: &str,
    _journal_bytes: &[u8],
    _seal_bytes: &[u8],
    _agent_output_bytes: &[u8],
) -> Result<(), ExecuteError> {
    Err(ExecuteError::FeatureNotEnabled)
}

/// Check if on-chain execution is available.
///
/// Returns true if the crate was compiled with the `onchain` feature.
pub fn is_onchain_available() -> bool {
    cfg!(feature = "onchain")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_onchain_available() {
        let available = is_onchain_available();
        #[cfg(feature = "onchain")]
        assert!(available);
        #[cfg(not(feature = "onchain"))]
        assert!(!available);
    }
}
