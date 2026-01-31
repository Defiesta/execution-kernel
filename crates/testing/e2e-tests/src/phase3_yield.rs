//! Phase 3 E2E Yield Test
//!
//! This module tests the complete execution flow:
//! Vault -> ZK Agent -> ETH leaves vault -> ETH returns with +10% -> Vault PPS increases
//!
//! # Prerequisites
//!
//! 1. KernelVault deployed with correct agentId and imageId registered
//! 2. MockYieldSource deployed and funded with yield reserves
//! 3. Vault has ETH to execute the deposit
//! 4. RISC Zero toolchain installed with Groth16 support
//!
//! # Environment Variables
//!
//! - `VAULT_ADDRESS`: Deployed KernelVault address
//! - `MOCK_YIELD_ADDRESS`: Deployed MockYieldSource address
//! - `RPC_URL`: Ethereum RPC endpoint
//! - `PRIVATE_KEY`: Private key for transaction signing
//! - `EXECUTION_NONCE`: Nonce for this execution (must match vault state)
//! - `TRANSFER_AMOUNT`: Amount of ETH to transfer (in wei)
//!
//! # Running
//!
//! ```bash
//! VAULT_ADDRESS=0x... \
//! MOCK_YIELD_ADDRESS=0x... \
//! RPC_URL=http://localhost:8545 \
//! PRIVATE_KEY=0x... \
//! EXECUTION_NONCE=1 \
//! TRANSFER_AMOUNT=1000000000000000000 \
//! cargo test --release -p e2e-tests --features phase3-e2e phase3_yield -- --nocapture
//! ```

#![cfg(feature = "phase3-e2e")]

use kernel_core::{CanonicalEncode, KernelInputV1, KERNEL_VERSION, PROTOCOL_VERSION};

/// Build the 48-byte agent input for the yield agent.
///
/// Format:
/// - [0:20]  vault_address (20 bytes)
/// - [20:40] mock_yield_address (20 bytes)
/// - [40:48] transfer_amount (u64 LE)
pub fn build_yield_agent_input(
    vault_address: &[u8; 20],
    mock_yield_address: &[u8; 20],
    transfer_amount: u64,
) -> Vec<u8> {
    let mut input = Vec::with_capacity(48);
    input.extend_from_slice(vault_address);
    input.extend_from_slice(mock_yield_address);
    input.extend_from_slice(&transfer_amount.to_le_bytes());
    input
}

/// Parse a hex address string (with or without 0x prefix) to [u8; 20].
pub fn parse_address(hex_str: &str) -> Result<[u8; 20], String> {
    let hex_str = hex_str.trim_start_matches("0x");
    if hex_str.len() != 40 {
        return Err(format!("Invalid address length: {}", hex_str.len()));
    }
    let bytes = hex::decode(hex_str).map_err(|e| format!("Invalid hex: {}", e))?;
    let arr: [u8; 20] = bytes.try_into().map_err(|_| "Invalid address length")?;
    Ok(arr)
}

/// Build a KernelInputV1 for the yield agent.
pub fn build_kernel_input(
    agent_id: [u8; 32],
    execution_nonce: u64,
    vault_address: &[u8; 20],
    mock_yield_address: &[u8; 20],
    transfer_amount: u64,
) -> KernelInputV1 {
    KernelInputV1 {
        protocol_version: PROTOCOL_VERSION,
        kernel_version: KERNEL_VERSION,
        agent_id,
        agent_code_hash: example_yield_agent::AGENT_CODE_HASH,
        constraint_set_hash: [0xbb; 32], // Default constraint set
        input_root: [0; 32],
        execution_nonce,
        opaque_agent_inputs: build_yield_agent_input(
            vault_address,
            mock_yield_address,
            transfer_amount,
        ),
    }
}

/// Compute the agent output bytes for verification.
///
/// This reconstructs what the agent would output given the inputs,
/// which is needed for the vault.execute() call.
pub fn compute_agent_output_bytes(
    vault_address: &[u8; 20],
    mock_yield_address: &[u8; 20],
    transfer_amount: u64,
) -> Vec<u8> {
    use kernel_sdk::prelude::{address_to_bytes32, call_action, AgentOutput};

    // Reconstruct the same actions the agent produces
    let target = address_to_bytes32(mock_yield_address);

    // Action 1: Deposit
    let deposit_action = call_action(target, transfer_amount as u128, &[]);

    // Action 2: Withdraw
    let withdraw_selector: [u8; 4] = [0x51, 0xcf, 0xf8, 0xd9];
    let mut withdraw_calldata = Vec::with_capacity(36);
    withdraw_calldata.extend_from_slice(&withdraw_selector);
    withdraw_calldata.extend_from_slice(&address_to_bytes32(vault_address));
    let withdraw_action = call_action(target, 0, &withdraw_calldata);

    // Actions are now preserved in order (deposit first, then withdraw)
    let output = AgentOutput {
        actions: vec![deposit_action, withdraw_action],
    };

    output.encode().expect("encode should succeed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_yield_agent_input() {
        let vault = [0x11u8; 20];
        let yield_source = [0x22u8; 20];
        let amount: u64 = 1_000_000_000_000_000_000;

        let input = build_yield_agent_input(&vault, &yield_source, amount);

        assert_eq!(input.len(), 48);
        assert_eq!(&input[0..20], &vault);
        assert_eq!(&input[20..40], &yield_source);
        assert_eq!(
            u64::from_le_bytes(input[40..48].try_into().unwrap()),
            amount
        );
    }

    #[test]
    fn test_parse_address() {
        let addr = parse_address("0x1234567890123456789012345678901234567890").unwrap();
        assert_eq!(
            addr,
            [
                0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x78,
                0x90, 0x12, 0x34, 0x56, 0x78, 0x90
            ]
        );

        // Without 0x prefix
        let addr2 = parse_address("1234567890123456789012345678901234567890").unwrap();
        assert_eq!(addr, addr2);
    }

    #[test]
    fn test_build_kernel_input() {
        let agent_id = [0x42u8; 32];
        let vault = [0x11u8; 20];
        let yield_source = [0x22u8; 20];
        let amount: u64 = 1_000_000_000_000_000_000;

        let input = build_kernel_input(agent_id, 1, &vault, &yield_source, amount);

        assert_eq!(input.protocol_version, PROTOCOL_VERSION);
        assert_eq!(input.kernel_version, KERNEL_VERSION);
        assert_eq!(input.agent_id, agent_id);
        assert_eq!(input.agent_code_hash, example_yield_agent::AGENT_CODE_HASH);
        assert_eq!(input.execution_nonce, 1);
        assert_eq!(input.opaque_agent_inputs.len(), 48);
    }

    #[test]
    fn test_compute_agent_output_bytes() {
        let vault = [0x11u8; 20];
        let yield_source = [0x22u8; 20];
        let amount: u64 = 1_000_000_000_000_000_000;

        let output_bytes = compute_agent_output_bytes(&vault, &yield_source, amount);

        // Output should have 2 actions
        // This is a basic sanity check - detailed validation is done elsewhere
        assert!(!output_bytes.is_empty());
    }
}

// ============================================================================
// Registration Info (prints IMAGE_ID and AGENT_CODE_HASH)
// ============================================================================

#[cfg(all(test, feature = "phase3-e2e"))]
mod registration_info {
    use risc0_methods::ZKVM_GUEST_ID;

    /// Print the registration values needed for on-chain deployment.
    ///
    /// Run with:
    /// ```bash
    /// cargo test -p e2e-tests --features phase3-e2e print_yield_agent_registration_info -- --nocapture
    /// ```
    #[test]
    fn print_yield_agent_registration_info() {
        println!("\n");
        println!("╔══════════════════════════════════════════════════════════════════╗");
        println!("║           YIELD AGENT ON-CHAIN REGISTRATION VALUES               ║");
        println!("╚══════════════════════════════════════════════════════════════════╝");
        println!();

        // IMAGE_ID (from methods crate - depends on zkvm-guest build)
        let image_id_bytes: Vec<u8> = ZKVM_GUEST_ID.iter().flat_map(|x| x.to_le_bytes()).collect();
        println!("IMAGE_ID (for KernelExecutionVerifier.registerAgent):");
        println!("  0x{}", hex::encode(&image_id_bytes));
        println!();

        // AGENT_CODE_HASH
        println!("AGENT_CODE_HASH (for KernelInputV1.agent_code_hash):");
        println!("  0x{}", hex::encode(&example_yield_agent::AGENT_CODE_HASH));
        println!();

        // AGENT_ID explanation
        println!("AGENT_ID (for KernelVault constructor & KernelInputV1.agent_id):");
        println!("  This is any bytes32 YOU choose to identify this vault/agent pair.");
        println!("  Example: 0x0000000000000000000000000000000000000000000000000000000000000001");
        println!();

        println!("══════════════════════════════════════════════════════════════════");
        println!("Registration commands (using Foundry cast):");
        println!("══════════════════════════════════════════════════════════════════");
        println!();
        println!("export IMAGE_ID=0x{}", hex::encode(&image_id_bytes));
        println!(
            "export AGENT_ID=0x0000000000000000000000000000000000000000000000000000000000000001"
        );
        println!();
        println!("# Register agent with verifier:");
        println!("cast send $VERIFIER_ADDRESS \"registerAgent(bytes32,bytes32)\" $AGENT_ID $IMAGE_ID --private-key $PRIVATE_KEY --rpc-url $RPC_URL");
        println!();
    }
}

// ============================================================================
// zkVM Proof Generation Tests
// ============================================================================

#[cfg(all(test, feature = "phase3-e2e"))]
mod zkvm_tests {
    use super::*;
    use kernel_core::{
        compute_action_commitment, compute_input_commitment, CanonicalDecode, ExecutionStatus,
        KernelJournalV1,
    };
    use risc0_methods::{ZKVM_GUEST_ELF, ZKVM_GUEST_ID};
    use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts};

    /// Test that the yield agent produces a valid proof with correct journal.
    ///
    /// This test runs the yield agent through the zkVM prover and verifies
    /// the resulting proof and journal contents.
    ///
    /// NOTE: This test requires the kernel-guest to be built with the
    /// `example-yield-agent` feature. The methods crate must be rebuilt
    /// with this feature enabled.
    #[test]
    #[ignore = "requires kernel-guest built with example-yield-agent feature"]
    fn test_yield_agent_proof_generation() {
        let agent_id = [0x42u8; 32];
        let vault = [0x11u8; 20];
        let yield_source = [0x22u8; 20];
        let amount: u64 = 1_000_000_000_000_000_000; // 1 ETH

        // Build kernel input
        let input = build_kernel_input(agent_id, 1, &vault, &yield_source, amount);
        let input_bytes = input.encode().expect("encode should succeed");

        // Build executor environment
        let env = ExecutorEnv::builder()
            .write(&input_bytes)
            .expect("failed to write input")
            .build()
            .expect("failed to build executor env");

        // Run the prover
        println!("Starting zkVM proof generation for yield agent...");
        let prover = default_prover();
        let prove_info = prover
            .prove_with_opts(env, ZKVM_GUEST_ELF, &ProverOpts::groth16())
            .expect("proof generation failed");

        println!("Proof generated successfully!");

        // Verify receipt
        let receipt = prove_info.receipt;
        receipt
            .verify(ZKVM_GUEST_ID)
            .expect("receipt verification failed");

        println!("Receipt verified against IMAGE_ID");

        // Decode journal
        let journal_bytes = receipt.journal.bytes.clone();
        let journal =
            KernelJournalV1::decode(&journal_bytes).expect("KernelJournalV1 decode failed");

        // Verify execution succeeded
        assert_eq!(
            journal.execution_status,
            ExecutionStatus::Success,
            "Expected Success status"
        );

        // Verify identity fields
        assert_eq!(journal.protocol_version, PROTOCOL_VERSION);
        assert_eq!(journal.kernel_version, KERNEL_VERSION);
        assert_eq!(journal.agent_id, agent_id);
        assert_eq!(
            journal.agent_code_hash,
            example_yield_agent::AGENT_CODE_HASH
        );
        assert_eq!(journal.execution_nonce, 1);

        // Verify input commitment
        let expected_input_commitment = compute_input_commitment(&input_bytes);
        assert_eq!(
            journal.input_commitment, expected_input_commitment,
            "Input commitment mismatch"
        );

        // Verify action commitment
        let expected_output_bytes = compute_agent_output_bytes(&vault, &yield_source, amount);
        let expected_action_commitment = compute_action_commitment(&expected_output_bytes);
        assert_eq!(
            journal.action_commitment, expected_action_commitment,
            "Action commitment mismatch"
        );

        // Extract seal for on-chain verification
        if let risc0_zkvm::InnerReceipt::Groth16(groth16_receipt) = &receipt.inner {
            let selector = &groth16_receipt.verifier_parameters.as_bytes()[..4];
            let mut encoded_seal = Vec::with_capacity(4 + groth16_receipt.seal.len());
            encoded_seal.extend_from_slice(selector);
            encoded_seal.extend_from_slice(&groth16_receipt.seal);

            let image_id_bytes: Vec<u8> =
                ZKVM_GUEST_ID.iter().flat_map(|x| x.to_le_bytes()).collect();

            println!("\n=== On-chain verification data (yield agent) ===");
            println!(
                "seal (with selector, hex): 0x{}",
                hex::encode(&encoded_seal)
            );
            println!("seal length: {} bytes", encoded_seal.len());
            println!("journal (hex): 0x{}", hex::encode(&journal_bytes));
            println!("journal length: {} bytes", journal_bytes.len());
            println!("image_id (bytes32): 0x{}", hex::encode(&image_id_bytes));
            println!("agent_id (bytes32): 0x{}", hex::encode(&agent_id));
            println!(
                "agent_code_hash (bytes32): 0x{}",
                hex::encode(&example_yield_agent::AGENT_CODE_HASH)
            );
            println!(
                "agent_output (hex): 0x{}",
                hex::encode(&expected_output_bytes)
            );
        }

        println!("\nYield agent proof generation test passed!");
    }
}

// ============================================================================
// On-Chain E2E Tests
// ============================================================================

#[cfg(all(test, feature = "phase3-e2e"))]
mod onchain_tests {
    use super::*;
    use alloy::{
        network::EthereumWallet,
        primitives::{Address, Bytes, FixedBytes, U256},
        providers::{Provider, ProviderBuilder},
        signers::local::PrivateKeySigner,
        sol,
    };
    use std::env;
    use std::str::FromStr;

    // Define the KernelVault interface
    sol! {
        #[sol(rpc)]
        interface IKernelVault {
            function execute(bytes calldata journal, bytes calldata seal, bytes calldata agentOutputBytes) external;
            function lastExecutionNonce() external view returns (uint64);
            function lastExecutionTimestamp() external view returns (uint64);
            function agentId() external view returns (bytes32);
        }

        #[sol(rpc)]
        interface IMockYieldSource {
            function deposits(address depositor) external view returns (uint256);
        }
    }

    /// Load test configuration from environment variables.
    fn load_config() -> Result<TestConfig, String> {
        // Try to load .env file (optional)
        let _ = dotenvy::dotenv();

        Ok(TestConfig {
            vault_address: env::var("VAULT_ADDRESS")
                .map_err(|_| "VAULT_ADDRESS not set")?
                .parse()
                .map_err(|e| format!("Invalid VAULT_ADDRESS: {}", e))?,
            mock_yield_address: env::var("MOCK_YIELD_ADDRESS")
                .map_err(|_| "MOCK_YIELD_ADDRESS not set")?
                .parse()
                .map_err(|e| format!("Invalid MOCK_YIELD_ADDRESS: {}", e))?,
            rpc_url: env::var("RPC_URL").map_err(|_| "RPC_URL not set")?,
            private_key: env::var("PRIVATE_KEY").map_err(|_| "PRIVATE_KEY not set")?,
            execution_nonce: env::var("EXECUTION_NONCE")
                .map_err(|_| "EXECUTION_NONCE not set")?
                .parse()
                .map_err(|e| format!("Invalid EXECUTION_NONCE: {}", e))?,
            transfer_amount: env::var("TRANSFER_AMOUNT")
                .map_err(|_| "TRANSFER_AMOUNT not set")?
                .parse()
                .map_err(|e| format!("Invalid TRANSFER_AMOUNT: {}", e))?,
        })
    }

    struct TestConfig {
        vault_address: Address,
        mock_yield_address: Address,
        rpc_url: String,
        private_key: String,
        execution_nonce: u64,
        transfer_amount: u64,
    }

    /// Full E2E test that:
    /// 1. Generates a zkVM proof
    /// 2. Submits it to the deployed KernelVault
    /// 3. Verifies the execution results
    ///
    /// This test requires:
    /// - Deployed contracts (KernelVault, MockYieldSource)
    /// - Funded vault with ETH
    /// - Correct environment variables
    #[tokio::test]
    #[ignore = "requires deployed contracts and environment setup"]
    async fn test_full_e2e_yield_execution() {
        use kernel_core::{CanonicalDecode, ExecutionStatus, KernelJournalV1};
        use risc0_methods::{ZKVM_GUEST_ELF, ZKVM_GUEST_ID};
        use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts};

        // Load configuration
        let config = load_config().expect("Failed to load test config");

        // Convert addresses to [u8; 20]
        let vault_bytes: [u8; 20] = config.vault_address.into_array();
        let yield_source_bytes: [u8; 20] = config.mock_yield_address.into_array();

        // Setup provider and wallet with recommended fillers for gas estimation
        let signer = PrivateKeySigner::from_str(&config.private_key).expect("Invalid private key");
        let wallet = EthereumWallet::from(signer);
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(wallet)
            .on_http(config.rpc_url.parse().expect("Invalid RPC URL"));

        // Create contract instances
        let vault = IKernelVault::new(config.vault_address, &provider);
        let yield_source = IMockYieldSource::new(config.mock_yield_address, &provider);

        // Get initial state
        let initial_nonce = vault
            .lastExecutionNonce()
            .call()
            .await
            .expect("Failed to get nonce")
            ._0;
        let initial_vault_balance = provider
            .get_balance(config.vault_address)
            .await
            .expect("Failed to get balance");
        let agent_id_bytes32: FixedBytes<32> = vault
            .agentId()
            .call()
            .await
            .expect("Failed to get agentId")
            ._0;
        let agent_id: [u8; 32] = agent_id_bytes32.into();

        println!("=== Initial State ===");
        println!("Vault address: {}", config.vault_address);
        println!("MockYieldSource address: {}", config.mock_yield_address);
        println!("Initial nonce: {}", initial_nonce);
        println!("Initial vault balance: {} wei", initial_vault_balance);
        println!("Agent ID: 0x{}", hex::encode(&agent_id));
        println!("Transfer amount: {} wei", config.transfer_amount);

        // Build kernel input
        let kernel_input = build_kernel_input(
            agent_id,
            config.execution_nonce,
            &vault_bytes,
            &yield_source_bytes,
            config.transfer_amount,
        );
        let input_bytes = kernel_input.encode().expect("encode should succeed");

        // Generate zkVM proof
        println!("\n=== Generating zkVM Proof ===");
        let env = ExecutorEnv::builder()
            .write(&input_bytes)
            .expect("failed to write input")
            .build()
            .expect("failed to build executor env");

        let prover = default_prover();
        let prove_info = prover
            .prove_with_opts(env, ZKVM_GUEST_ELF, &ProverOpts::groth16())
            .expect("proof generation failed");

        let receipt = prove_info.receipt;
        receipt
            .verify(ZKVM_GUEST_ID)
            .expect("receipt verification failed");

        println!("Proof generated and verified!");

        // Extract journal and seal
        let journal_bytes = receipt.journal.bytes.clone();
        let journal = KernelJournalV1::decode(&journal_bytes).expect("decode failed");

        assert_eq!(journal.execution_status, ExecutionStatus::Success);

        // Extract Groth16 seal with selector prefix
        let encoded_seal =
            if let risc0_zkvm::InnerReceipt::Groth16(groth16_receipt) = &receipt.inner {
                let selector = &groth16_receipt.verifier_parameters.as_bytes()[..4];
                let mut seal = Vec::with_capacity(4 + groth16_receipt.seal.len());
                seal.extend_from_slice(selector);
                seal.extend_from_slice(&groth16_receipt.seal);
                seal
            } else {
                panic!("Expected Groth16 receipt");
            };

        // Compute agent output bytes
        let agent_output_bytes =
            compute_agent_output_bytes(&vault_bytes, &yield_source_bytes, config.transfer_amount);

        println!("\n=== Submitting Transaction ===");
        println!("Journal length: {} bytes", journal_bytes.len());
        println!("Seal length: {} bytes", encoded_seal.len());
        println!("Agent output length: {} bytes", agent_output_bytes.len());

        // Submit execute transaction
        let tx = vault.execute(
            Bytes::from(journal_bytes.clone()),
            Bytes::from(encoded_seal),
            Bytes::from(agent_output_bytes),
        );

        let pending_tx = tx.send().await.expect("Failed to send transaction");
        println!("Transaction sent: {:?}", pending_tx.tx_hash());

        let tx_receipt = pending_tx
            .get_receipt()
            .await
            .expect("Failed to get receipt");

        println!(
            "Transaction confirmed in block: {:?}",
            tx_receipt.block_number
        );
        println!("Gas used: {:?}", tx_receipt.gas_used);

        // Verify results
        println!("\n=== Verifying Results ===");

        let final_nonce = vault
            .lastExecutionNonce()
            .call()
            .await
            .expect("Failed to get nonce")
            ._0;
        let final_vault_balance = provider
            .get_balance(config.vault_address)
            .await
            .expect("Failed to get balance");
        let yield_source_deposit = yield_source
            .deposits(config.vault_address)
            .call()
            .await
            .expect("Failed to get deposits")
            ._0;

        println!("Final nonce: {}", final_nonce);
        println!("Final vault balance: {} wei", final_vault_balance);
        println!(
            "MockYieldSource deposits[vault]: {} wei",
            yield_source_deposit
        );

        // Assertions
        assert_eq!(
            final_nonce, config.execution_nonce,
            "Nonce should match execution nonce"
        );

        // After deposit and withdrawal, vault should have gained 10% yield
        let expected_yield = config.transfer_amount / 10;
        let expected_final_balance = initial_vault_balance + U256::from(expected_yield);
        assert_eq!(
            final_vault_balance, expected_final_balance,
            "Vault should have gained 10% yield"
        );

        // MockYieldSource deposits should be cleared after withdrawal
        assert_eq!(
            yield_source_deposit,
            U256::ZERO,
            "MockYieldSource deposits should be cleared"
        );

        println!("\n=== E2E Test Passed! ===");
        println!("Yield earned: {} wei (10%)", expected_yield);
    }
}
