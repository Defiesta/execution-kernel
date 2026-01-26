//! End-to-End zkVM Proof Tests
//!
//! This crate provides integration tests that verify the complete execution flow:
//! Agent → Guest Build → Input Generation → zkVM Execution → Proof → Verification
//!
//! # Test Coverage
//!
//! 1. **Success Path**: Valid input with echo action produces valid proof
//! 2. **Hash Mismatch**: Wrong agent_code_hash fails during guest execution
//! 3. **Empty Output**: No-echo input produces empty output with correct commitment
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

use kernel_core::{
    compute_action_commitment, compute_input_commitment, AgentOutput, CanonicalDecode,
    CanonicalEncode, ExecutionStatus, KernelInputV1, KernelJournalV1, KERNEL_VERSION,
    PROTOCOL_VERSION,
};

/// Helper to construct a valid KernelInputV1 with the correct agent_code_hash.
///
/// Uses `example_agent::AGENT_CODE_HASH` to ensure hash verification passes.
pub fn make_valid_input(opaque_agent_inputs: Vec<u8>) -> KernelInputV1 {
    KernelInputV1 {
        protocol_version: PROTOCOL_VERSION,
        kernel_version: KERNEL_VERSION,
        agent_id: [0x42; 32],
        agent_code_hash: example_agent::AGENT_CODE_HASH,
        constraint_set_hash: [0xbb; 32],
        input_root: [0xcc; 32],
        execution_nonce: 1,
        opaque_agent_inputs,
    }
}

/// Helper to construct a KernelInputV1 with a WRONG agent_code_hash.
///
/// Used to test that hash mismatches cause execution failures.
pub fn make_input_with_wrong_hash(opaque_agent_inputs: Vec<u8>) -> KernelInputV1 {
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

/// Compute the expected action commitment for an echo output.
///
/// When the example-agent echoes, it produces:
/// - action_type: 0x00000001 (ECHO)
/// - target: agent_id
/// - payload: opaque_inputs (truncated to MAX_ACTION_PAYLOAD_BYTES)
pub fn compute_echo_commitment(agent_id: [u8; 32], payload: &[u8]) -> [u8; 32] {
    use kernel_core::ActionV1;
    use kernel_sdk::types::MAX_ACTION_PAYLOAD_BYTES;

    let payload_len = payload.len().min(MAX_ACTION_PAYLOAD_BYTES);
    let action = ActionV1 {
        action_type: 0x00000001, // ACTION_TYPE_ECHO
        target: agent_id,
        payload: payload[..payload_len].to_vec(),
    };

    let output = AgentOutput {
        actions: vec![action],
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
    use methods::{ZKVM_GUEST_ELF, ZKVM_GUEST_ID};
    use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts};

    /// Test 1: Successful execution with echo action produces valid proof.
    ///
    /// This test verifies the complete happy path:
    /// 1. Construct valid input with echo trigger (first byte = 1)
    /// 2. Run zkVM prover to execute kernel-guest
    /// 3. Verify receipt against IMAGE_ID
    /// 4. Decode journal and verify:
    ///    - execution_status == Success
    ///    - input_commitment matches SHA256(input_bytes)
    ///    - action_commitment matches expected echo output
    #[test]
    fn test_e2e_success_with_echo() {
        // Construct input that triggers echo (first byte = 1)
        let opaque_inputs = vec![1, 2, 3, 4, 5];
        let input = make_valid_input(opaque_inputs.clone());
        let input_bytes = input.encode().expect("encode should succeed");

        // Build executor environment with input
        // Use .write() to serialize the Vec<u8> so env::read() can deserialize it
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
        assert_eq!(journal.agent_code_hash, example_agent::AGENT_CODE_HASH);
        assert_eq!(journal.constraint_set_hash, [0xbb; 32]);
        assert_eq!(journal.input_root, [0xcc; 32]);
        assert_eq!(journal.execution_nonce, 1);

        // Verify input commitment
        let expected_input_commitment = compute_input_commitment(&input_bytes);
        assert_eq!(
            journal.input_commitment, expected_input_commitment,
            "Input commitment mismatch"
        );

        // Verify action commitment (echo action)
        let expected_action_commitment = compute_echo_commitment([0x42; 32], &opaque_inputs);
        assert_eq!(
            journal.action_commitment, expected_action_commitment,
            "Action commitment mismatch"
        );
        
        // Extract seal for on-chain verification
        // The seal is inside the Groth16Receipt
        if let risc0_zkvm::InnerReceipt::Groth16(groth16_receipt) = &receipt.inner {
            // Convert image_id [u32; 8] to bytes32 (little-endian)
            let image_id_bytes: Vec<u8> = ZKVM_GUEST_ID
                .iter()
                .flat_map(|x| x.to_le_bytes())
                .collect();

            // Convert agent_id to hex for on-chain use
            let agent_id_bytes: [u8; 32] = [0x42; 32];

            // The on-chain verifier expects: [4-byte selector][256-byte seal]
            // The selector is the first 4 bytes of verifier_parameters digest
            let selector = &groth16_receipt.verifier_parameters.as_bytes()[..4];
            let mut encoded_seal = Vec::with_capacity(4 + groth16_receipt.seal.len());
            encoded_seal.extend_from_slice(selector);
            encoded_seal.extend_from_slice(&groth16_receipt.seal);

            println!("\n=== On-chain verification data ===");
            println!("verifier_parameters: 0x{}", hex::encode(groth16_receipt.verifier_parameters.as_bytes()));
            println!("selector (first 4 bytes): 0x{}", hex::encode(selector));
            println!("seal (with selector, hex): 0x{}", hex::encode(&encoded_seal));
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
        let input = make_input_with_wrong_hash(vec![1, 2, 3]);
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
        // (exact error message depends on risc0-zkvm version)
        assert!(
            err_string.contains("panic")
                || err_string.contains("failed")
                || err_string.contains("execution"),
            "Error should indicate execution failure"
        );

        println!("Hash mismatch correctly caused execution failure!");
    }

    /// Test 3: Empty output when no-echo trigger produces correct commitment.
    ///
    /// When opaque_inputs[0] != 1, the example-agent produces no actions.
    /// This should:
    /// - Still succeed (empty output is valid)
    /// - Have action_commitment == EMPTY_OUTPUT_COMMITMENT
    #[test]
    fn test_e2e_empty_output() {
        // Construct input that does NOT trigger echo (first byte = 0)
        let opaque_inputs = vec![0, 2, 3, 4, 5];
        let input = make_valid_input(opaque_inputs);
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

        // Extract the journal bytes (raw bytes committed via env::commit_slice)
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
            "Expected EMPTY_OUTPUT_COMMITMENT for no-echo case"
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
        // Construct input
        let input = make_valid_input(vec![1, 0xde, 0xad, 0xbe, 0xef]);
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

    #[test]
    fn test_make_valid_input_uses_correct_hash() {
        let input = make_valid_input(vec![1, 2, 3]);
        assert_eq!(input.agent_code_hash, example_agent::AGENT_CODE_HASH);
    }

    #[test]
    fn test_make_input_with_wrong_hash_is_wrong() {
        let input = make_input_with_wrong_hash(vec![1, 2, 3]);
        assert_ne!(input.agent_code_hash, example_agent::AGENT_CODE_HASH);
        assert_eq!(input.agent_code_hash, [0x00; 32]);
    }

    #[test]
    fn test_compute_echo_commitment_is_deterministic() {
        let agent_id = [0x42; 32];
        let payload = vec![1, 2, 3, 4, 5];

        let commitment1 = compute_echo_commitment(agent_id, &payload);
        let commitment2 = compute_echo_commitment(agent_id, &payload);

        assert_eq!(commitment1, commitment2);
    }

    #[test]
    fn test_input_encoding_roundtrip() {
        let input = make_valid_input(vec![1, 2, 3, 4, 5]);
        let encoded = input.encode().expect("encode should succeed");
        let decoded = KernelInputV1::decode(&encoded).expect("decode should succeed");

        assert_eq!(decoded.protocol_version, input.protocol_version);
        assert_eq!(decoded.agent_code_hash, input.agent_code_hash);
        assert_eq!(decoded.opaque_agent_inputs, input.opaque_agent_inputs);
    }
}
