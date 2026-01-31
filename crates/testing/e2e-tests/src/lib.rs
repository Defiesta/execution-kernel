//! End-to-End zkVM Proof Tests
//!
//! This crate provides integration tests that verify the complete execution flow:
//! Agent → Guest Build → Input Generation → zkVM Execution → Proof → Verification
//!
//! # Test Coverage
//!
//! 1. **Success Path**: Valid input produces valid proof with yield agent
//! 2. **Hash Mismatch**: Wrong agent_code_hash fails during guest execution
//! 3. **Empty Output**: Invalid input (wrong size) produces empty output
//!
//! # Running Tests
//!
//! ```bash
//! # Install RISC Zero toolchain first
//! cargo install cargo-risczero
//! cargo risczero install
//!
//! # Run E2E proof tests
//! cargo test -p e2e-tests --features risc0-e2e -- --nocapture
//! ```
//!
//! # CI Integration
//!
//! These tests are gated behind the `risc0-e2e` feature to allow CI to run
//! without the RISC Zero toolchain installed. Add `--features risc0-e2e` to
//! enable proof generation in CI environments with RISC Zero available.

#![cfg_attr(not(feature = "risc0-e2e"), allow(dead_code))]

// Phase 3 E2E Yield Tests
#[cfg(feature = "phase3-e2e")]
pub mod phase3_yield;

use kernel_core::{
    compute_action_commitment, AgentOutput, CanonicalEncode, KernelInputV1, KERNEL_VERSION,
    PROTOCOL_VERSION,
};

/// Helper to construct a valid KernelInputV1 with the correct agent_code_hash for yield agent.
///
/// Uses `example_yield_agent::AGENT_CODE_HASH` to ensure hash verification passes.
/// Creates a 48-byte opaque input with: vault (20 bytes) + yield source (20 bytes) + amount (8 bytes).
pub fn make_valid_input(vault: [u8; 20], yield_source: [u8; 20], amount: u64) -> KernelInputV1 {
    let mut opaque_agent_inputs = Vec::with_capacity(48);
    opaque_agent_inputs.extend_from_slice(&vault);
    opaque_agent_inputs.extend_from_slice(&yield_source);
    opaque_agent_inputs.extend_from_slice(&amount.to_le_bytes());

    KernelInputV1 {
        protocol_version: PROTOCOL_VERSION,
        kernel_version: KERNEL_VERSION,
        agent_id: [0x42; 32],
        agent_code_hash: example_yield_agent::AGENT_CODE_HASH,
        constraint_set_hash: [0xbb; 32],
        input_root: [0xcc; 32],
        execution_nonce: 1,
        opaque_agent_inputs,
    }
}

/// Helper to construct a KernelInputV1 with a WRONG agent_code_hash.
///
/// Used to test that hash mismatches cause execution failures.
pub fn make_input_with_wrong_hash(
    vault: [u8; 20],
    yield_source: [u8; 20],
    amount: u64,
) -> KernelInputV1 {
    let mut opaque_agent_inputs = Vec::with_capacity(48);
    opaque_agent_inputs.extend_from_slice(&vault);
    opaque_agent_inputs.extend_from_slice(&yield_source);
    opaque_agent_inputs.extend_from_slice(&amount.to_le_bytes());

    KernelInputV1 {
        protocol_version: PROTOCOL_VERSION,
        kernel_version: KERNEL_VERSION,
        agent_id: [0x42; 32],
        agent_code_hash: [0x00; 32], // Wrong hash - all zeros
        constraint_set_hash: [0xbb; 32],
        input_root: [0xcc; 32],
        execution_nonce: 1,
        opaque_agent_inputs,
    }
}

/// Helper to construct a KernelInputV1 with invalid input size (wrong for yield agent).
///
/// Used to test that invalid inputs produce empty output.
pub fn make_input_with_invalid_size(opaque_agent_inputs: Vec<u8>) -> KernelInputV1 {
    KernelInputV1 {
        protocol_version: PROTOCOL_VERSION,
        kernel_version: KERNEL_VERSION,
        agent_id: [0x42; 32],
        agent_code_hash: example_yield_agent::AGENT_CODE_HASH,
        constraint_set_hash: [0xbb; 32],
        input_root: [0xcc; 32],
        execution_nonce: 1,
        opaque_agent_inputs,
    }
}

/// Compute the expected action commitment for yield agent output.
///
/// When the yield agent receives valid 48-byte input, it produces:
/// - Two CALL actions (deposit and withdraw)
pub fn compute_yield_commitment(vault: [u8; 20], yield_source: [u8; 20], amount: u64) -> [u8; 32] {
    use kernel_sdk::prelude::{address_to_bytes32, call_action};

    let target = address_to_bytes32(&yield_source);

    // Build deposit action (same logic as yield agent)
    let deposit_action = call_action(target, amount as u128, &[]);

    // Build withdraw action (same logic as yield agent)
    let withdraw_selector: [u8; 4] = [0x51, 0xcf, 0xf8, 0xd9];
    let mut withdraw_calldata = Vec::with_capacity(36);
    withdraw_calldata.extend_from_slice(&withdraw_selector);
    withdraw_calldata.extend_from_slice(&address_to_bytes32(&vault));
    let withdraw_action = call_action(target, 0, &withdraw_calldata);

    let output = AgentOutput {
        actions: vec![deposit_action, withdraw_action],
    };

    let output_bytes = output.encode().expect("encode should succeed");
    compute_action_commitment(&output_bytes)
}

// ============================================================================
// zkVM Proof Tests (require risc0-e2e feature)
// ============================================================================

#[cfg(all(test, feature = "risc0-e2e"))]
mod zkvm_tests {
    use super::*;
    use constraints::EMPTY_OUTPUT_COMMITMENT;
    use kernel_core::{
        compute_input_commitment, CanonicalDecode, ExecutionStatus, KernelJournalV1,
    };
    use risc0_methods::{ZKVM_GUEST_ELF, ZKVM_GUEST_ID};
    use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts};

    /// Test 1: Successful execution with yield agent produces valid proof.
    ///
    /// This test verifies the complete happy path:
    /// 1. Construct valid 48-byte input for yield agent
    /// 2. Run zkVM prover to execute kernel-guest
    /// 3. Verify receipt against IMAGE_ID
    /// 4. Decode journal and verify:
    ///    - execution_status == Success
    ///    - input_commitment matches SHA256(input_bytes)
    ///    - action_commitment matches expected yield output
    #[test]
    fn test_e2e_success_with_yield_agent() {
        // Construct valid input for yield agent (48 bytes)
        let vault = [0x11u8; 20];
        let yield_source = [0x22u8; 20];
        let amount: u64 = 1_000_000_000_000_000_000; // 1 ETH

        let input = make_valid_input(vault, yield_source, amount);
        let input_bytes = input.encode().expect("encode should succeed");

        // Build executor environment with input
        let env = ExecutorEnv::builder()
            .write(&input_bytes)
            .expect("failed to write input")
            .build()
            .expect("failed to build executor env");

        // Run the prover
        println!("Starting zkVM proof generation...");
        let prover = default_prover();
        let prove_info = prover
            .prove_with_opts(env, ZKVM_GUEST_ELF, &ProverOpts::groth16())
            .expect("proof generation failed");

        println!("Proof generated successfully!");

        // Extract the receipt
        let receipt = prove_info.receipt;

        // Verify the receipt against IMAGE_ID
        receipt
            .verify(ZKVM_GUEST_ID)
            .expect("receipt verification failed");

        println!("Receipt verified against IMAGE_ID");

        // Extract the journal bytes (raw bytes committed via env::commit_slice)
        let journal_bytes = receipt.journal.bytes.clone();
        let journal =
            KernelJournalV1::decode(&journal_bytes).expect("KernelJournalV1 decode failed");

        // Verify execution succeeded
        assert_eq!(
            journal.execution_status,
            ExecutionStatus::Success,
            "Expected Success status"
        );

        // Verify identity fields match input
        assert_eq!(journal.protocol_version, PROTOCOL_VERSION);
        assert_eq!(journal.kernel_version, KERNEL_VERSION);
        assert_eq!(journal.agent_id, [0x42; 32]);
        assert_eq!(
            journal.agent_code_hash,
            example_yield_agent::AGENT_CODE_HASH
        );
        assert_eq!(journal.constraint_set_hash, [0xbb; 32]);
        assert_eq!(journal.input_root, [0xcc; 32]);
        assert_eq!(journal.execution_nonce, 1);

        // Verify input commitment
        let expected_input_commitment = compute_input_commitment(&input_bytes);
        assert_eq!(
            journal.input_commitment, expected_input_commitment,
            "Input commitment mismatch"
        );

        // Verify action commitment (yield agent produces 2 CALL actions)
        let expected_action_commitment = compute_yield_commitment(vault, yield_source, amount);
        assert_eq!(
            journal.action_commitment, expected_action_commitment,
            "Action commitment mismatch"
        );

        // Extract seal for on-chain verification
        if let risc0_zkvm::InnerReceipt::Groth16(groth16_receipt) = &receipt.inner {
            // Convert image_id [u32; 8] to bytes32 (little-endian)
            let image_id_bytes: Vec<u8> =
                ZKVM_GUEST_ID.iter().flat_map(|x| x.to_le_bytes()).collect();

            // Convert agent_id to hex for on-chain use
            let agent_id_bytes: [u8; 32] = [0x42; 32];

            // The on-chain verifier expects: [4-byte selector][256-byte seal]
            let selector = &groth16_receipt.verifier_parameters.as_bytes()[..4];
            let mut encoded_seal = Vec::with_capacity(4 + groth16_receipt.seal.len());
            encoded_seal.extend_from_slice(selector);
            encoded_seal.extend_from_slice(&groth16_receipt.seal);

            println!("\n=== On-chain verification data ===");
            println!(
                "verifier_parameters: 0x{}",
                hex::encode(groth16_receipt.verifier_parameters.as_bytes())
            );
            println!("selector (first 4 bytes): 0x{}", hex::encode(selector));
            println!(
                "seal (with selector, hex): 0x{}",
                hex::encode(&encoded_seal)
            );
            println!("seal length (with selector): {} bytes", encoded_seal.len());
            println!("journal (hex): 0x{}", hex::encode(&receipt.journal.bytes));
            println!("journal length: {} bytes", receipt.journal.bytes.len());
            println!("image_id (bytes32): 0x{}", hex::encode(&image_id_bytes));
            println!("image_id (u32[8]): {:?}", ZKVM_GUEST_ID);
            println!("agent_id (bytes32): 0x{}", hex::encode(&agent_id_bytes));
        }
        println!("All assertions passed!");
    }

    /// Test 2: Wrong agent_code_hash causes execution failure.
    ///
    /// When the input declares a different agent_code_hash than the linked agent,
    /// kernel_main returns AgentCodeHashMismatch error, which causes the guest
    /// to panic. This aborts proof generation - no valid receipt is produced.
    #[test]
    fn test_e2e_agent_code_hash_mismatch() {
        // Construct input with WRONG agent_code_hash
        let vault = [0x11u8; 20];
        let yield_source = [0x22u8; 20];
        let amount: u64 = 1_000_000_000_000_000_000;

        let input = make_input_with_wrong_hash(vault, yield_source, amount);
        let input_bytes = input.encode().expect("encode should succeed");

        // Build executor environment
        let env = ExecutorEnv::builder()
            .write(&input_bytes)
            .expect("failed to write input")
            .build()
            .expect("failed to build executor env");

        // Run the prover - should fail because guest panics
        println!("Starting zkVM proof generation (expecting failure)...");
        let prover = default_prover();
        let result = prover.prove_with_opts(env, ZKVM_GUEST_ELF, &ProverOpts::groth16());

        // Proof generation should fail
        assert!(
            result.is_err(),
            "Expected proof generation to fail due to hash mismatch"
        );

        // Verify the error message mentions the panic
        let err = result.unwrap_err();
        let err_string = format!("{:?}", err);
        println!("Got expected error: {}", err_string);

        // The error should indicate guest execution failed
        assert!(
            err_string.contains("panic")
                || err_string.contains("failed")
                || err_string.contains("execution"),
            "Error should indicate execution failure"
        );

        println!("Hash mismatch correctly caused execution failure!");
    }

    /// Test 3: Invalid input size produces empty output with correct commitment.
    ///
    /// When opaque_inputs is not exactly 48 bytes, the yield agent produces no actions.
    /// This should:
    /// - Still succeed (empty output is valid)
    /// - Have action_commitment == EMPTY_OUTPUT_COMMITMENT
    #[test]
    fn test_e2e_empty_output_invalid_input_size() {
        // Construct input with wrong size (not 48 bytes)
        let opaque_inputs = vec![0, 2, 3, 4, 5]; // Only 5 bytes - invalid for yield agent
        let input = make_input_with_invalid_size(opaque_inputs);
        let input_bytes = input.encode().expect("encode should succeed");

        // Build executor environment
        let env = ExecutorEnv::builder()
            .write(&input_bytes)
            .expect("failed to write input")
            .build()
            .expect("failed to build executor env");

        // Run the prover
        println!("Starting zkVM proof generation (empty output case)...");
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

        // Extract the journal bytes
        let journal_bytes = receipt.journal.bytes.clone();
        let journal =
            KernelJournalV1::decode(&journal_bytes).expect("KernelJournalV1 decode failed");

        // Verify execution succeeded (empty output is valid)
        assert_eq!(
            journal.execution_status,
            ExecutionStatus::Success,
            "Expected Success status for empty output"
        );

        // Verify action commitment is the empty output commitment
        assert_eq!(
            journal.action_commitment, EMPTY_OUTPUT_COMMITMENT,
            "Expected EMPTY_OUTPUT_COMMITMENT for invalid input size"
        );

        // Also verify against manually computed empty commitment
        let empty_output = AgentOutput { actions: vec![] };
        let empty_bytes = empty_output.encode().expect("encode should succeed");
        let expected_commitment = compute_action_commitment(&empty_bytes);
        assert_eq!(
            journal.action_commitment, expected_commitment,
            "Empty commitment should match computed value"
        );

        println!("Empty output test passed!");
    }

    /// Test 4: Determinism - same input produces same journal.
    ///
    /// Running the same input twice should produce identical journal bytes,
    /// demonstrating deterministic execution.
    #[test]
    fn test_e2e_determinism() {
        // Construct valid input for yield agent
        let vault = [0xde; 20];
        let yield_source = [0xad; 20];
        let amount: u64 = 0xdeadbeef;

        let input = make_valid_input(vault, yield_source, amount);
        let input_bytes = input.encode().expect("encode should succeed");

        // Run prover twice
        let mut journals = Vec::new();

        for i in 0..2 {
            println!("Determinism test: run {}/2", i + 1);

            let env = ExecutorEnv::builder()
                .write(&input_bytes)
                .expect("failed to write input")
                .build()
                .expect("failed to build executor env");

            let prover = default_prover();
            let prove_info = prover
                .prove_with_opts(env, ZKVM_GUEST_ELF, &ProverOpts::groth16())
                .expect("proof generation failed");

            let journal_bytes = prove_info.receipt.journal.bytes.clone();
            journals.push(journal_bytes);
        }

        // Journals should be identical
        assert_eq!(
            journals[0], journals[1],
            "Determinism violated: journals differ"
        );

        println!("Determinism verified: both runs produced identical journals");
    }
}

// ============================================================================
// Non-zkVM Tests (always run)
// ============================================================================

#[cfg(test)]
mod unit_tests {
    use super::*;
    use kernel_core::CanonicalDecode;

    #[test]
    fn test_make_valid_input_uses_correct_hash() {
        let vault = [0x11; 20];
        let yield_source = [0x22; 20];
        let input = make_valid_input(vault, yield_source, 1000);
        assert_eq!(input.agent_code_hash, example_yield_agent::AGENT_CODE_HASH);
    }

    #[test]
    fn test_make_input_with_wrong_hash_is_wrong() {
        let vault = [0x11; 20];
        let yield_source = [0x22; 20];
        let input = make_input_with_wrong_hash(vault, yield_source, 1000);
        assert_ne!(input.agent_code_hash, example_yield_agent::AGENT_CODE_HASH);
        assert_eq!(input.agent_code_hash, [0x00; 32]);
    }

    #[test]
    fn test_make_valid_input_creates_48_byte_opaque_input() {
        let vault = [0x11; 20];
        let yield_source = [0x22; 20];
        let input = make_valid_input(vault, yield_source, 1000);
        assert_eq!(input.opaque_agent_inputs.len(), 48);
    }

    #[test]
    fn test_compute_yield_commitment_is_deterministic() {
        let vault = [0x11; 20];
        let yield_source = [0x22; 20];
        let amount = 1_000_000_000u64;

        let commitment1 = compute_yield_commitment(vault, yield_source, amount);
        let commitment2 = compute_yield_commitment(vault, yield_source, amount);

        assert_eq!(commitment1, commitment2);
    }

    #[test]
    fn test_input_encoding_roundtrip() {
        let vault = [0x11; 20];
        let yield_source = [0x22; 20];
        let input = make_valid_input(vault, yield_source, 1_000_000);
        let encoded = input.encode().expect("encode should succeed");
        let decoded = KernelInputV1::decode(&encoded).expect("decode should succeed");

        assert_eq!(decoded.protocol_version, input.protocol_version);
        assert_eq!(decoded.agent_code_hash, input.agent_code_hash);
        assert_eq!(decoded.opaque_agent_inputs, input.opaque_agent_inputs);
    }
}
