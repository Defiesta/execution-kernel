// Re-export the agent code hash from the wrapper crate for tests to use.
pub use kernel_guest_binding_yield::AGENT_CODE_HASH;

#[cfg(test)]
mod tests {
    use constraints::EMPTY_OUTPUT_COMMITMENT;
    use kernel_core::codec::{
        ensure_no_trailing_bytes, get_bytes32, get_u32_le, get_u64_le, put_bytes32, put_u32_le,
        put_u64_le,
    };
    use kernel_core::*;
    use kernel_guest_binding_yield::kernel_main;
    use kernel_sdk::prelude::{address_to_bytes32, call_action};

    // Import the agent code hash from the linked yield-agent crate.
    // This is the compile-time constant that the kernel verifies against.
    use crate::AGENT_CODE_HASH;

    /// Helper to create a valid KernelInputV1 with the correct agent_code_hash for yield agent.
    ///
    /// This uses `AGENT_CODE_HASH` from the linked yield-agent crate,
    /// ensuring the hash verification in kernel_main will pass.
    /// Creates 48-byte opaque input: vault (20 bytes) + yield_source (20 bytes) + amount (8 bytes).
    fn make_input(vault: [u8; 20], yield_source: [u8; 20], amount: u64) -> KernelInputV1 {
        let mut opaque_agent_inputs = Vec::with_capacity(48);
        opaque_agent_inputs.extend_from_slice(&vault);
        opaque_agent_inputs.extend_from_slice(&yield_source);
        opaque_agent_inputs.extend_from_slice(&amount.to_le_bytes());

        KernelInputV1 {
            protocol_version: PROTOCOL_VERSION,
            kernel_version: KERNEL_VERSION,
            agent_id: [0x42; 32],
            agent_code_hash: AGENT_CODE_HASH, // Correct hash from linked agent
            constraint_set_hash: [0xbb; 32],
            input_root: [0xcc; 32],
            execution_nonce: 1,
            opaque_agent_inputs,
        }
    }

    /// Helper to create a KernelInputV1 with raw opaque input bytes.
    fn make_input_raw(opaque_agent_inputs: Vec<u8>) -> KernelInputV1 {
        KernelInputV1 {
            protocol_version: PROTOCOL_VERSION,
            kernel_version: KERNEL_VERSION,
            agent_id: [0x42; 32],
            agent_code_hash: AGENT_CODE_HASH,
            constraint_set_hash: [0xbb; 32],
            input_root: [0xcc; 32],
            execution_nonce: 1,
            opaque_agent_inputs,
        }
    }

    /// Helper to create a KernelInputV1 with a WRONG agent_code_hash.
    ///
    /// This uses a dummy hash that will NOT match the linked agent,
    /// useful for testing hash mismatch scenarios.
    #[allow(dead_code)]
    fn make_input_with_wrong_hash(
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
            agent_code_hash: [0xde; 32], // Wrong hash - will fail hash check
            constraint_set_hash: [0xbb; 32],
            input_root: [0xcc; 32],
            execution_nonce: 1,
            opaque_agent_inputs,
        }
    }

    #[test]
    fn test_kernel_input_encoding_round_trip() {
        let original = make_input([0x11; 20], [0x22; 20], 1000);

        let encoded = original.encode().unwrap();
        let decoded = KernelInputV1::decode(&encoded).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_kernel_journal_encoding_round_trip() {
        let original = KernelJournalV1 {
            protocol_version: PROTOCOL_VERSION,
            kernel_version: KERNEL_VERSION,
            agent_id: [0x42; 32],
            agent_code_hash: [0xaa; 32],
            constraint_set_hash: [0xbb; 32],
            input_root: [0xcc; 32],
            execution_nonce: 12345,
            input_commitment: [0xdd; 32],
            action_commitment: [0xee; 32],
            execution_status: ExecutionStatus::Success,
        };

        let encoded = original.encode().unwrap();
        let decoded = KernelJournalV1::decode(&encoded).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_action_encoding_round_trip() {
        let original = ActionV1 {
            action_type: 0x12345678,
            target: [0x99; 32],
            payload: vec![10, 20, 30, 40],
        };

        let encoded = original.encode().unwrap();
        let decoded = ActionV1::decode(&encoded).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_agent_output_encoding_round_trip() {
        let original = AgentOutput {
            actions: vec![
                ActionV1 {
                    action_type: 1,
                    target: [0x11; 32],
                    payload: vec![1, 2, 3],
                },
                ActionV1 {
                    action_type: 2,
                    target: [0x22; 32],
                    payload: vec![4, 5, 6, 7, 8],
                },
            ],
        };

        let encoded = original.encode().unwrap();
        let decoded = AgentOutput::decode(&encoded).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_empty_agent_output_encoding() {
        let original = AgentOutput { actions: vec![] };

        let encoded = original.encode().unwrap();
        let decoded = AgentOutput::decode(&encoded).unwrap();

        assert_eq!(original, decoded);
        assert_eq!(encoded.len(), 4); // Just the count field
    }

    #[test]
    fn test_action_canonicalization() {
        // Create actions in non-canonical order
        let actions_unordered = vec![
            ActionV1 {
                action_type: 2, // Higher type
                target: [0x11; 32],
                payload: vec![1],
            },
            ActionV1 {
                action_type: 1, // Lower type - should sort first
                target: [0x22; 32],
                payload: vec![2],
            },
            ActionV1 {
                action_type: 1,     // Same type, different target
                target: [0x11; 32], // Lower target - should sort before [0x22]
                payload: vec![3],
            },
        ];

        let output1 = AgentOutput {
            actions: actions_unordered.clone(),
        };
        let canonical1 = output1.into_canonical();

        // Verify ordering: action_type ascending, then target lexicographic
        assert_eq!(canonical1.actions[0].action_type, 1);
        assert_eq!(canonical1.actions[0].target, [0x11; 32]);
        assert_eq!(canonical1.actions[0].payload, vec![3]);

        assert_eq!(canonical1.actions[1].action_type, 1);
        assert_eq!(canonical1.actions[1].target, [0x22; 32]);
        assert_eq!(canonical1.actions[1].payload, vec![2]);

        assert_eq!(canonical1.actions[2].action_type, 2);
        assert_eq!(canonical1.actions[2].target, [0x11; 32]);
        assert_eq!(canonical1.actions[2].payload, vec![1]);

        // Different initial order should produce same canonical output
        let actions_reversed: Vec<ActionV1> = actions_unordered.iter().rev().cloned().collect();
        let output2 = AgentOutput {
            actions: actions_reversed,
        };
        let canonical2 = output2.into_canonical();

        // Encoding should be identical regardless of initial order
        assert_eq!(canonical1.encode().unwrap(), canonical2.encode().unwrap());
    }

    #[test]
    fn test_input_commitment_golden_vector() {
        // Using simple input bytes for reproducible test
        let input_bytes = vec![1, 2, 3, 4];
        let commitment = compute_input_commitment(&input_bytes);

        // SHA256([1,2,3,4])
        let expected = [
            0x9f, 0x64, 0xa7, 0x47, 0xe1, 0xb9, 0x7f, 0x13, 0x1f, 0xab, 0xb6, 0xb4, 0x47, 0x29,
            0x6c, 0x9b, 0x6f, 0x02, 0x01, 0xe7, 0x9f, 0xb3, 0xc5, 0x35, 0x6e, 0x6c, 0x77, 0xe8,
            0x9b, 0x6a, 0x80, 0x6a,
        ];

        assert_eq!(commitment, expected);
    }

    #[test]
    fn test_action_commitment_golden_vector() {
        // Empty actions list encodes to [0, 0, 0, 0] (count = 0)
        let agent_output = AgentOutput { actions: vec![] };
        let output_bytes = agent_output.encode().unwrap();
        let commitment = compute_action_commitment(&output_bytes);

        // SHA256([0, 0, 0, 0]) - empty action list
        let expected = [
            0xdf, 0x3f, 0x61, 0x98, 0x04, 0xa9, 0x2f, 0xdb, 0x40, 0x57, 0x19, 0x2d, 0xc4, 0x3d,
            0xd7, 0x48, 0xea, 0x77, 0x8a, 0xdc, 0x52, 0xbc, 0x49, 0x8c, 0xe8, 0x05, 0x24, 0xc0,
            0x14, 0xb8, 0x11, 0x19,
        ];

        assert_eq!(commitment, expected);
    }

    #[test]
    fn test_determinism() {
        let input = make_input([0x11; 20], [0x22; 20], 100);
        let input_bytes = input.encode().unwrap();

        let result1 = kernel_main(&input_bytes).unwrap();
        let result2 = kernel_main(&input_bytes).unwrap();

        assert_eq!(result1, result2);
    }

    #[test]
    fn test_invalid_protocol_version() {
        // Encode a valid input, then corrupt the protocol_version bytes
        let input = make_input([0x11; 20], [0x22; 20], 1000);
        let mut input_bytes = input.encode().unwrap();

        // Corrupt protocol_version to 999 (little-endian, first 4 bytes)
        input_bytes[0..4].copy_from_slice(&999u32.to_le_bytes());

        let result = KernelInputV1::decode(&input_bytes);
        assert!(matches!(
            result,
            Err(CodecError::InvalidVersion {
                expected: 1,
                actual: 999
            })
        ));
    }

    #[test]
    fn test_invalid_kernel_version() {
        // Encode a valid input, then corrupt the kernel_version bytes
        let input = make_input([0x11; 20], [0x22; 20], 1000);
        let mut input_bytes = input.encode().unwrap();

        // Corrupt kernel_version to 999 (little-endian, bytes 4-7)
        input_bytes[4..8].copy_from_slice(&999u32.to_le_bytes());

        let result = KernelInputV1::decode(&input_bytes);
        assert!(matches!(
            result,
            Err(CodecError::InvalidVersion {
                expected: 1,
                actual: 999
            })
        ));
    }

    #[test]
    fn test_journal_invalid_protocol_version() {
        let journal = KernelJournalV1 {
            protocol_version: PROTOCOL_VERSION,
            kernel_version: KERNEL_VERSION,
            agent_id: [0; 32],
            agent_code_hash: [0; 32],
            constraint_set_hash: [0; 32],
            input_root: [0; 32],
            execution_nonce: 0,
            input_commitment: [0; 32],
            action_commitment: [0; 32],
            execution_status: ExecutionStatus::Success,
        };

        let mut encoded = journal.encode().unwrap();
        // Corrupt protocol version to 999 (little-endian)
        encoded[0..4].copy_from_slice(&999u32.to_le_bytes());

        let result = KernelJournalV1::decode(&encoded);
        assert!(matches!(
            result,
            Err(CodecError::InvalidVersion {
                expected: 1,
                actual: 999
            })
        ));
    }

    #[test]
    fn test_journal_invalid_kernel_version() {
        let journal = KernelJournalV1 {
            protocol_version: PROTOCOL_VERSION,
            kernel_version: KERNEL_VERSION,
            agent_id: [0; 32],
            agent_code_hash: [0; 32],
            constraint_set_hash: [0; 32],
            input_root: [0; 32],
            execution_nonce: 0,
            input_commitment: [0; 32],
            action_commitment: [0; 32],
            execution_status: ExecutionStatus::Success,
        };

        let mut encoded = journal.encode().unwrap();
        // Corrupt kernel version to 999 (at offset 4, little-endian)
        encoded[4..8].copy_from_slice(&999u32.to_le_bytes());

        let result = KernelJournalV1::decode(&encoded);
        assert!(matches!(
            result,
            Err(CodecError::InvalidVersion {
                expected: 1,
                actual: 999
            })
        ));
    }

    #[test]
    fn test_input_too_large() {
        let large_input = vec![0u8; MAX_AGENT_INPUT_BYTES + 1];
        let input = make_input_raw(large_input);

        // Encode-side now catches oversized inputs
        let result = input.encode();
        assert!(matches!(result, Err(CodecError::InputTooLarge { .. })));
    }

    #[test]
    fn test_malformed_input() {
        let malformed = vec![1, 2, 3];
        let result = KernelInputV1::decode(&malformed);

        assert!(matches!(result, Err(CodecError::UnexpectedEndOfInput)));
    }

    #[test]
    fn test_journal_fixed_size() {
        let journal = KernelJournalV1 {
            protocol_version: PROTOCOL_VERSION,
            kernel_version: KERNEL_VERSION,
            agent_id: [0; 32],
            agent_code_hash: [0; 32],
            constraint_set_hash: [0; 32],
            input_root: [0; 32],
            execution_nonce: 0,
            input_commitment: [0; 32],
            action_commitment: [0; 32],
            execution_status: ExecutionStatus::Success,
        };

        let encoded = journal.encode().unwrap();
        // protocol_version: 4 + kernel_version: 4 + agent_id: 32 +
        // agent_code_hash: 32 + constraint_set_hash: 32 + input_root: 32 +
        // execution_nonce: 8 + input_commitment: 32 + action_commitment: 32 +
        // execution_status: 1 = 209 bytes
        assert_eq!(encoded.len(), 209);
    }

    #[test]
    fn test_constraints_enforcement() {
        let input = make_input([0x11; 20], [0x22; 20], 1000);
        let input_bytes = input.encode().unwrap();
        let result = kernel_main(&input_bytes);

        assert!(result.is_ok());
    }

    #[test]
    fn test_empty_input_produces_empty_output() {
        // Empty input (wrong size for yield agent) should produce empty output
        let input = make_input_raw(vec![]);
        let input_bytes = input.encode().unwrap();
        let result = kernel_main(&input_bytes);

        assert!(result.is_ok());

        let journal_bytes = result.unwrap();
        let journal = KernelJournalV1::decode(&journal_bytes).unwrap();
        assert_eq!(journal.execution_status, ExecutionStatus::Success);
        // Yield agent returns empty output for invalid input size
        assert_eq!(journal.action_commitment, EMPTY_OUTPUT_COMMITMENT);
    }

    #[test]
    fn test_max_size_input() {
        // Max size input - won't be 48 bytes so yield agent returns empty output
        let input = make_input_raw(vec![0x42; MAX_AGENT_INPUT_BYTES]);
        let input_bytes = input.encode().unwrap();
        let result = kernel_main(&input_bytes);

        assert!(result.is_ok());
    }

    #[test]
    fn test_journal_contains_identity_fields() {
        let input = KernelInputV1 {
            protocol_version: PROTOCOL_VERSION,
            kernel_version: KERNEL_VERSION,
            agent_id: [0x11; 32],
            agent_code_hash: AGENT_CODE_HASH, // Must match linked agent
            constraint_set_hash: [0x33; 32],
            input_root: [0x44; 32],
            execution_nonce: 9999,
            opaque_agent_inputs: vec![0u8; 48], // Valid size for yield agent (all zeros)
        };

        let input_bytes = input.encode().unwrap();
        let journal_bytes = kernel_main(&input_bytes).unwrap();
        let journal = KernelJournalV1::decode(&journal_bytes).unwrap();

        // Verify identity fields are copied to journal
        assert_eq!(journal.agent_id, [0x11; 32]);
        assert_eq!(journal.agent_code_hash, AGENT_CODE_HASH);
        assert_eq!(journal.constraint_set_hash, [0x33; 32]);
        assert_eq!(journal.input_root, [0x44; 32]);
        assert_eq!(journal.execution_nonce, 9999);
    }

    #[test]
    fn test_too_many_actions() {
        // Create bytes that would decode to too many actions
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&((MAX_ACTIONS_PER_OUTPUT + 1) as u32).to_le_bytes());

        let result = AgentOutput::decode(&bytes);
        assert!(matches!(result, Err(CodecError::TooManyActions { .. })));
    }

    #[test]
    fn test_action_payload_too_large() {
        let mut bytes = Vec::new();
        // action_type
        bytes.extend_from_slice(&1u32.to_le_bytes());
        // target
        bytes.extend_from_slice(&[0u8; 32]);
        // payload_len (too large)
        bytes.extend_from_slice(&((MAX_ACTION_PAYLOAD_BYTES + 1) as u32).to_le_bytes());
        // We don't need actual payload data, decode will fail on length check

        let result = ActionV1::decode(&bytes);
        assert!(matches!(
            result,
            Err(CodecError::ActionPayloadTooLarge { .. })
        ));
    }

    #[test]
    fn test_execution_status_encoding() {
        // Success encodes as 0x01 (0x00 reserved to catch uninitialized memory)
        let journal = KernelJournalV1 {
            protocol_version: PROTOCOL_VERSION,
            kernel_version: KERNEL_VERSION,
            agent_id: [0; 32],
            agent_code_hash: [0; 32],
            constraint_set_hash: [0; 32],
            input_root: [0; 32],
            execution_nonce: 0,
            input_commitment: [0; 32],
            action_commitment: [0; 32],
            execution_status: ExecutionStatus::Success,
        };

        let encoded = journal.encode().unwrap();
        // Last byte should be 0x01 for Success
        assert_eq!(*encoded.last().unwrap(), 0x01);
    }

    #[test]
    fn test_invalid_execution_status_decode() {
        let journal = KernelJournalV1 {
            protocol_version: PROTOCOL_VERSION,
            kernel_version: KERNEL_VERSION,
            agent_id: [0; 32],
            agent_code_hash: [0; 32],
            constraint_set_hash: [0; 32],
            input_root: [0; 32],
            execution_nonce: 0,
            input_commitment: [0; 32],
            action_commitment: [0; 32],
            execution_status: ExecutionStatus::Success,
        };

        let mut encoded = journal.encode().unwrap();
        // Corrupt the status byte to an invalid value
        *encoded.last_mut().unwrap() = 0xFF;

        let result = KernelJournalV1::decode(&encoded);
        assert!(matches!(
            result,
            Err(CodecError::InvalidExecutionStatus(0xFF))
        ));

        // Also verify that 0x00 is invalid (reserved to catch uninitialized memory)
        *encoded.last_mut().unwrap() = 0x00;
        let result = KernelJournalV1::decode(&encoded);
        assert!(matches!(
            result,
            Err(CodecError::InvalidExecutionStatus(0x00))
        ));
    }

    #[test]
    fn test_determinism_with_edge_cases() {
        let test_cases = vec![
            vec![],                       // Empty
            vec![0; 48],                  // Valid size for yield agent
            vec![0xFF; 100],              // Repeated bytes
            (0..48).collect::<Vec<u8>>(), // Sequential bytes (valid size)
        ];

        for test_input in test_cases {
            let input = make_input_raw(test_input);
            let input_bytes = input.encode().unwrap();

            // Run multiple times to ensure determinism
            let result1 = kernel_main(&input_bytes).unwrap();
            let result2 = kernel_main(&input_bytes).unwrap();
            let result3 = kernel_main(&input_bytes).unwrap();

            assert_eq!(result1, result2);
            assert_eq!(result2, result3);
        }
    }

    #[test]
    fn test_nonce_in_journal() {
        let vault = [0x11; 20];
        let yield_source = [0x22; 20];
        let amount: u64 = 1000;

        let mut opaque_agent_inputs = Vec::with_capacity(48);
        opaque_agent_inputs.extend_from_slice(&vault);
        opaque_agent_inputs.extend_from_slice(&yield_source);
        opaque_agent_inputs.extend_from_slice(&amount.to_le_bytes());

        let input1 = KernelInputV1 {
            protocol_version: PROTOCOL_VERSION,
            kernel_version: KERNEL_VERSION,
            agent_id: [0x42; 32],
            agent_code_hash: AGENT_CODE_HASH, // Must match linked agent
            constraint_set_hash: [0xbb; 32],
            input_root: [0xcc; 32],
            execution_nonce: 1,
            opaque_agent_inputs: opaque_agent_inputs.clone(),
        };

        let input2 = KernelInputV1 {
            execution_nonce: 2,
            ..input1.clone()
        };

        let journal1 =
            KernelJournalV1::decode(&kernel_main(&input1.encode().unwrap()).unwrap()).unwrap();
        let journal2 =
            KernelJournalV1::decode(&kernel_main(&input2.encode().unwrap()).unwrap()).unwrap();

        assert_eq!(journal1.execution_nonce, 1);
        assert_eq!(journal2.execution_nonce, 2);

        // Different nonces should produce different input commitments
        assert_ne!(journal1.input_commitment, journal2.input_commitment);
    }

    #[test]
    fn test_input_header_size() {
        // Verify minimum input size with empty data
        let input = make_input_raw(vec![]);
        let encoded = input.encode().unwrap();

        // Fixed fields (144) + length prefix (4) + 0 bytes data = 148
        assert_eq!(encoded.len(), 148);
    }

    // ========================================================================
    // P0.2: Trailing Bytes Rejection Tests
    // ========================================================================

    #[test]
    fn test_trailing_bytes_rejected_input() {
        // Create a valid KernelInputV1 encoding
        let input = KernelInputV1 {
            protocol_version: PROTOCOL_VERSION,
            kernel_version: KERNEL_VERSION,
            agent_id: [0u8; 32],
            agent_code_hash: [0u8; 32],
            constraint_set_hash: [0u8; 32],
            input_root: [0u8; 32],
            execution_nonce: 0,
            opaque_agent_inputs: vec![],
        };
        let mut encoded = input.encode().unwrap();

        // Append trailing byte
        encoded.push(0xFF);

        // Decode should fail with InvalidLength
        let result = KernelInputV1::decode(&encoded);
        assert!(
            matches!(result, Err(CodecError::InvalidLength)),
            "Expected InvalidLength error for trailing bytes, got {:?}",
            result
        );
    }

    #[test]
    fn test_trailing_bytes_rejected_journal() {
        // Create a valid KernelJournalV1 encoding
        let journal = KernelJournalV1 {
            protocol_version: PROTOCOL_VERSION,
            kernel_version: KERNEL_VERSION,
            agent_id: [0u8; 32],
            agent_code_hash: [0u8; 32],
            constraint_set_hash: [0u8; 32],
            input_root: [0u8; 32],
            execution_nonce: 0,
            input_commitment: [0u8; 32],
            action_commitment: [0u8; 32],
            execution_status: ExecutionStatus::Success,
        };
        let mut encoded = journal.encode().unwrap();
        assert_eq!(encoded.len(), 209); // Fixed size

        // Append trailing byte
        encoded.push(0xFF);
        assert_eq!(encoded.len(), 210);

        // Decode should fail with InvalidLength
        let result = KernelJournalV1::decode(&encoded);
        assert!(
            matches!(result, Err(CodecError::InvalidLength)),
            "Expected InvalidLength error for trailing bytes, got {:?}",
            result
        );
    }

    #[test]
    fn test_trailing_bytes_rejected_action() {
        // Create a valid ActionV1 encoding
        let action = ActionV1 {
            action_type: 1,
            target: [0x42u8; 32],
            payload: vec![1, 2, 3],
        };
        let mut encoded = action.encode().unwrap();

        // Append trailing byte
        encoded.push(0xFF);

        // Decode should fail with InvalidLength
        let result = ActionV1::decode(&encoded);
        assert!(
            matches!(result, Err(CodecError::InvalidLength)),
            "Expected InvalidLength error for trailing bytes, got {:?}",
            result
        );
    }

    #[test]
    fn test_trailing_bytes_rejected_agent_output() {
        // Create a valid AgentOutput encoding with one action
        let output = AgentOutput {
            actions: vec![ActionV1 {
                action_type: 1,
                target: [0x42u8; 32],
                payload: vec![],
            }],
        };
        let mut encoded = output.encode().unwrap();

        // Append trailing byte
        encoded.push(0xFF);

        // Decode should fail with InvalidLength
        let result = AgentOutput::decode(&encoded);
        assert!(
            matches!(result, Err(CodecError::InvalidLength)),
            "Expected InvalidLength error for trailing bytes, got {:?}",
            result
        );
    }

    // ========================================================================
    // P0.2: Commitment Helper Tests
    // ========================================================================

    #[test]
    fn test_kernel_input_v1_commitment_helper() {
        // Create input and compute commitment using helper
        let input = KernelInputV1 {
            protocol_version: PROTOCOL_VERSION,
            kernel_version: KERNEL_VERSION,
            agent_id: [0u8; 32],
            agent_code_hash: [0u8; 32],
            constraint_set_hash: [0u8; 32],
            input_root: [0u8; 32],
            execution_nonce: 0,
            opaque_agent_inputs: vec![],
        };

        // Using helper function
        let commitment_via_helper = kernel_input_v1_commitment(&input).unwrap();

        // Manual computation (encode then hash)
        let encoded = input.encode().unwrap();
        let commitment_manual = compute_input_commitment(&encoded);

        // Both should produce the same result
        assert_eq!(commitment_via_helper, commitment_manual);

        // Verify known golden value
        let expected_hex = "f0b4a449964d5ff3e473605e3ed1af1223f60135392d8add3244d2926ab9ab3f";
        let expected: [u8; 32] = hex_to_bytes32(expected_hex);
        assert_eq!(commitment_via_helper, expected);
    }

    #[test]
    fn test_kernel_input_v1_commitment_helper_standard_case() {
        let input = KernelInputV1 {
            protocol_version: PROTOCOL_VERSION,
            kernel_version: KERNEL_VERSION,
            agent_id: [0x42u8; 32],
            agent_code_hash: [0xaau8; 32],
            constraint_set_hash: [0xbbu8; 32],
            input_root: [0xccu8; 32],
            execution_nonce: 12345,
            opaque_agent_inputs: vec![1, 2, 3, 4, 5],
        };

        let commitment = kernel_input_v1_commitment(&input).unwrap();

        // Verify known golden value
        let expected_hex = "6e4a2cce578937164ab4c0016a678b8e9d24a729c7c418b793b447fd299ff6a4";
        let expected: [u8; 32] = hex_to_bytes32(expected_hex);
        assert_eq!(commitment, expected);
    }

    // ========================================================================
    // P0.2: Golden Vector Tests
    // ========================================================================

    #[test]
    fn test_golden_vector_kernel_input_minimal() {
        // Golden vector: minimal_zeros
        let encoded_hex = "01000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        let commitment_hex = "f0b4a449964d5ff3e473605e3ed1af1223f60135392d8add3244d2926ab9ab3f";

        let encoded = hex_to_vec(encoded_hex);
        let expected_commitment = hex_to_bytes32(commitment_hex);

        // Decode and verify
        let decoded = KernelInputV1::decode(&encoded).unwrap();
        assert_eq!(decoded.protocol_version, 1);
        assert_eq!(decoded.kernel_version, 1);
        assert_eq!(decoded.agent_id, [0u8; 32]);
        assert_eq!(decoded.execution_nonce, 0);
        assert!(decoded.opaque_agent_inputs.is_empty());

        // Re-encode and verify round-trip
        let re_encoded = decoded.encode().unwrap();
        assert_eq!(re_encoded, encoded);

        // Verify commitment
        let commitment = compute_input_commitment(&encoded);
        assert_eq!(commitment, expected_commitment);
    }

    #[test]
    fn test_golden_vector_kernel_input_standard() {
        // Golden vector: standard_case
        let encoded_hex = "01000000010000004242424242424242424242424242424242424242424242424242424242424242aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc3930000000000000050000000102030405";
        let commitment_hex = "6e4a2cce578937164ab4c0016a678b8e9d24a729c7c418b793b447fd299ff6a4";

        let encoded = hex_to_vec(encoded_hex);
        let expected_commitment = hex_to_bytes32(commitment_hex);

        // Decode and verify
        let decoded = KernelInputV1::decode(&encoded).unwrap();
        assert_eq!(decoded.protocol_version, 1);
        assert_eq!(decoded.kernel_version, 1);
        assert_eq!(decoded.agent_id, [0x42u8; 32]);
        assert_eq!(decoded.agent_code_hash, [0xaau8; 32]);
        assert_eq!(decoded.execution_nonce, 12345);
        assert_eq!(decoded.opaque_agent_inputs, vec![1, 2, 3, 4, 5]);

        // Re-encode and verify round-trip
        let re_encoded = decoded.encode().unwrap();
        assert_eq!(re_encoded, encoded);

        // Verify commitment
        let commitment = compute_input_commitment(&encoded);
        assert_eq!(commitment, expected_commitment);
    }

    #[test]
    fn test_golden_vector_kernel_journal_minimal() {
        // Golden vector: journal minimal_zeros (209 bytes)
        let encoded_hex = "0100000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";

        let encoded = hex_to_vec(encoded_hex);
        assert_eq!(encoded.len(), 209); // Fixed size

        // Decode and verify
        let decoded = KernelJournalV1::decode(&encoded).unwrap();
        assert_eq!(decoded.protocol_version, 1);
        assert_eq!(decoded.kernel_version, 1);
        assert_eq!(decoded.agent_id, [0u8; 32]);
        assert_eq!(decoded.execution_status, ExecutionStatus::Success);

        // Re-encode and verify round-trip
        let re_encoded = decoded.encode().unwrap();
        assert_eq!(re_encoded, encoded);
    }

    #[test]
    fn test_golden_vector_kernel_journal_standard() {
        // Golden vector: journal standard_case (209 bytes)
        let encoded_hex = "01000000010000004242424242424242424242424242424242424242424242424242424242424242aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc3930000000000000ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee01";

        let encoded = hex_to_vec(encoded_hex);
        assert_eq!(encoded.len(), 209);

        // Decode and verify
        let decoded = KernelJournalV1::decode(&encoded).unwrap();
        assert_eq!(decoded.protocol_version, 1);
        assert_eq!(decoded.agent_id, [0x42u8; 32]);
        assert_eq!(decoded.agent_code_hash, [0xaau8; 32]);
        assert_eq!(decoded.execution_nonce, 12345);
        assert_eq!(decoded.input_commitment, [0xddu8; 32]);
        assert_eq!(decoded.action_commitment, [0xeeu8; 32]);
        assert_eq!(decoded.execution_status, ExecutionStatus::Success);

        // Re-encode and verify round-trip
        let re_encoded = decoded.encode().unwrap();
        assert_eq!(re_encoded, encoded);
    }

    // ========================================================================
    // P0.2: Negative Vector Tests
    // ========================================================================

    #[test]
    fn test_negative_vector_truncated() {
        // Truncated input (only 2 bytes)
        let encoded = hex_to_vec("0102");
        let result = KernelInputV1::decode(&encoded);
        assert!(matches!(result, Err(CodecError::UnexpectedEndOfInput)));
    }

    #[test]
    fn test_negative_vector_trailing_bytes() {
        // Valid encoding with extra trailing byte 0xff
        let encoded_hex = "01000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ff";
        let encoded = hex_to_vec(encoded_hex);

        let result = KernelInputV1::decode(&encoded);
        assert!(matches!(result, Err(CodecError::InvalidLength)));
    }

    #[test]
    fn test_negative_vector_wrong_version() {
        // Protocol version set to 999 (0xe7030000 in little-endian)
        let encoded_hex = "e7030000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        let encoded = hex_to_vec(encoded_hex);

        let result = KernelInputV1::decode(&encoded);
        assert!(matches!(
            result,
            Err(CodecError::InvalidVersion {
                expected: 1,
                actual: 999
            })
        ));
    }

    #[test]
    fn test_negative_vector_empty_input() {
        // Empty byte array
        let encoded: Vec<u8> = vec![];
        let result = KernelInputV1::decode(&encoded);
        assert!(matches!(result, Err(CodecError::UnexpectedEndOfInput)));
    }

    // ========================================================================
    // P0.2: Helper Function Tests
    // ========================================================================

    #[test]
    fn test_codec_helper_put_get_u32() {
        let mut buf = Vec::new();
        put_u32_le(&mut buf, 0x12345678);
        assert_eq!(buf, vec![0x78, 0x56, 0x34, 0x12]);

        let mut offset = 0;
        let value = get_u32_le(&buf, &mut offset).unwrap();
        assert_eq!(value, 0x12345678);
        assert_eq!(offset, 4);
    }

    #[test]
    fn test_codec_helper_put_get_u64() {
        let mut buf = Vec::new();
        put_u64_le(&mut buf, 0x123456789ABCDEF0);
        assert_eq!(buf, vec![0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12]);

        let mut offset = 0;
        let value = get_u64_le(&buf, &mut offset).unwrap();
        assert_eq!(value, 0x123456789ABCDEF0);
        assert_eq!(offset, 8);
    }

    #[test]
    fn test_codec_helper_put_get_bytes32() {
        let bytes: [u8; 32] = [0x42; 32];
        let mut buf = Vec::new();
        put_bytes32(&mut buf, &bytes);
        assert_eq!(buf.len(), 32);

        let mut offset = 0;
        let result = get_bytes32(&buf, &mut offset).unwrap();
        assert_eq!(result, bytes);
        assert_eq!(offset, 32);
    }

    #[test]
    fn test_codec_helper_ensure_no_trailing_bytes() {
        // Exact match - should succeed
        let result = ensure_no_trailing_bytes(&[1, 2, 3], 3);
        assert!(result.is_ok());

        // Trailing bytes - should fail
        let result = ensure_no_trailing_bytes(&[1, 2, 3, 4], 3);
        assert!(matches!(result, Err(CodecError::InvalidLength)));
    }

    #[test]
    fn test_codec_helper_get_u32_insufficient_bytes() {
        let buf = vec![0x01, 0x02]; // Only 2 bytes
        let mut offset = 0;
        let result = get_u32_le(&buf, &mut offset);
        assert!(matches!(result, Err(CodecError::UnexpectedEndOfInput)));
    }

    #[test]
    fn test_codec_helper_get_bytes32_insufficient_bytes() {
        let buf = vec![0x42; 16]; // Only 16 bytes
        let mut offset = 0;
        let result = get_bytes32(&buf, &mut offset);
        assert!(matches!(result, Err(CodecError::UnexpectedEndOfInput)));
    }

    // ========================================================================
    // P0.3: Constraint System Tests
    // ========================================================================

    #[test]
    fn test_failure_status_encoding() {
        // Failure encodes as 0x02
        let journal = KernelJournalV1 {
            protocol_version: PROTOCOL_VERSION,
            kernel_version: KERNEL_VERSION,
            agent_id: [0; 32],
            agent_code_hash: [0; 32],
            constraint_set_hash: [0; 32],
            input_root: [0; 32],
            execution_nonce: 0,
            input_commitment: [0; 32],
            action_commitment: [0; 32],
            execution_status: ExecutionStatus::Failure,
        };

        let encoded = journal.encode().unwrap();
        // Last byte should be 0x02 for Failure
        assert_eq!(*encoded.last().unwrap(), 0x02);

        // Round-trip should preserve Failure status
        let decoded = KernelJournalV1::decode(&encoded).unwrap();
        assert_eq!(decoded.execution_status, ExecutionStatus::Failure);
    }

    #[test]
    fn test_empty_output_commitment_constant() {
        use constraints::EMPTY_OUTPUT_COMMITMENT;

        // SHA-256 of [0x00, 0x00, 0x00, 0x00] (empty AgentOutput)
        let empty_output = AgentOutput { actions: vec![] };
        let encoded = empty_output.encode().unwrap();
        assert_eq!(encoded, vec![0x00, 0x00, 0x00, 0x00]);

        let commitment = compute_action_commitment(&encoded);
        assert_eq!(commitment, EMPTY_OUTPUT_COMMITMENT);

        // Verify the constant matches the expected hex value
        let expected_hex = "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119";
        let expected = hex_to_bytes32(expected_hex);
        assert_eq!(EMPTY_OUTPUT_COMMITMENT, expected);
    }

    #[test]
    fn test_constraint_violation_reason_codes() {
        // Verify violation reason codes match specification
        assert_eq!(
            ConstraintViolationReason::InvalidOutputStructure.code(),
            0x01
        );
        assert_eq!(ConstraintViolationReason::UnknownActionType.code(), 0x02);
        assert_eq!(ConstraintViolationReason::AssetNotWhitelisted.code(), 0x03);
        assert_eq!(ConstraintViolationReason::PositionTooLarge.code(), 0x04);
        assert_eq!(ConstraintViolationReason::LeverageTooHigh.code(), 0x05);
        assert_eq!(ConstraintViolationReason::DrawdownExceeded.code(), 0x06);
        assert_eq!(ConstraintViolationReason::CooldownNotElapsed.code(), 0x07);
        assert_eq!(ConstraintViolationReason::InvalidStateSnapshot.code(), 0x08);
        assert_eq!(ConstraintViolationReason::InvalidConstraintSet.code(), 0x09);
        assert_eq!(ConstraintViolationReason::InvalidActionPayload.code(), 0x0A);
    }

    #[test]
    fn test_kernel_main_success_status() {
        // Normal execution should produce Success status
        let input = make_input([0x11; 20], [0x22; 20], 1000);
        let input_bytes = input.encode().unwrap();

        let journal_bytes = kernel_main(&input_bytes).unwrap();
        let journal = KernelJournalV1::decode(&journal_bytes).unwrap();

        assert_eq!(journal.execution_status, ExecutionStatus::Success);
    }

    #[test]
    fn test_kernel_main_with_constraints_success() {
        use constraints::ConstraintSetV1;
        use kernel_guest_binding_yield::kernel_main_with_constraints;

        let input = make_input([0x11; 20], [0x22; 20], 1000);
        let input_bytes = input.encode().unwrap();
        let constraints = ConstraintSetV1::default();

        let journal_bytes = kernel_main_with_constraints(&input_bytes, &constraints).unwrap();
        let journal = KernelJournalV1::decode(&journal_bytes).unwrap();

        assert_eq!(journal.execution_status, ExecutionStatus::Success);
    }

    #[test]
    fn test_constraint_set_default_values() {
        use constraints::ConstraintSetV1;

        let constraints = ConstraintSetV1::default();

        assert_eq!(constraints.version, 1);
        assert_eq!(constraints.max_position_notional, u64::MAX);
        assert_eq!(constraints.max_leverage_bps, 100_000); // 10x
        assert_eq!(constraints.max_drawdown_bps, 10_000); // 100%
        assert_eq!(constraints.cooldown_seconds, 0);
        assert_eq!(
            constraints.max_actions_per_output,
            MAX_ACTIONS_PER_OUTPUT as u32
        );
        assert_eq!(constraints.allowed_asset_id, [0u8; 32]);
    }

    #[test]
    fn test_state_snapshot_decoding() {
        use constraints::StateSnapshotV1;

        // Valid snapshot
        let mut snapshot_bytes = Vec::new();
        snapshot_bytes.extend_from_slice(&1u32.to_le_bytes()); // version
        snapshot_bytes.extend_from_slice(&1000u64.to_le_bytes()); // last_execution_ts
        snapshot_bytes.extend_from_slice(&2000u64.to_le_bytes()); // current_ts
        snapshot_bytes.extend_from_slice(&100_000u64.to_le_bytes()); // current_equity
        snapshot_bytes.extend_from_slice(&110_000u64.to_le_bytes()); // peak_equity

        let snapshot = StateSnapshotV1::decode(&snapshot_bytes).unwrap();
        assert_eq!(snapshot.snapshot_version, 1);
        assert_eq!(snapshot.last_execution_ts, 1000);
        assert_eq!(snapshot.current_ts, 2000);
        assert_eq!(snapshot.current_equity, 100_000);
        assert_eq!(snapshot.peak_equity, 110_000);
    }

    #[test]
    fn test_state_snapshot_decoding_too_short() {
        use constraints::StateSnapshotV1;

        // Too short - should return None
        let short_bytes = vec![1, 2, 3];
        assert!(StateSnapshotV1::decode(&short_bytes).is_none());
    }

    #[test]
    fn test_state_snapshot_decoding_wrong_version() {
        use constraints::StateSnapshotV1;

        // Wrong version
        let mut bad_version = Vec::new();
        bad_version.extend_from_slice(&2u32.to_le_bytes()); // version = 2 (invalid)
        bad_version.extend_from_slice(&[0u8; 32]); // pad to 36 bytes

        assert!(StateSnapshotV1::decode(&bad_version).is_none());
    }

    #[test]
    fn test_enforce_constraints_call_action() {
        use constraints::{enforce_constraints, ConstraintSetV1, ACTION_TYPE_CALL};

        let input = make_input_raw(vec![]);

        // Create a valid CALL action with proper ABI encoding
        // Target: EVM address (upper 12 bytes must be zero)
        let mut target = [0u8; 32];
        target[12..32].copy_from_slice(&[0x11u8; 20]);

        // Payload: abi.encode(uint256 value, bytes callData)
        // For empty calldata: value (32) + offset=64 (32) + length=0 (32) = 96 bytes
        let mut payload = Vec::with_capacity(96);
        payload.extend_from_slice(&[0u8; 32]); // value = 0
                                               // offset = 64 (big-endian u256)
        payload.extend_from_slice(&[0u8; 31]);
        payload.push(64);
        // length = 0 (big-endian u256)
        payload.extend_from_slice(&[0u8; 32]);

        let output = AgentOutput {
            actions: vec![ActionV1 {
                action_type: ACTION_TYPE_CALL,
                target,
                payload,
            }],
        };
        let constraints = ConstraintSetV1::default();

        let result = enforce_constraints(&input, &output, &constraints);
        assert!(result.is_ok());
    }

    #[test]
    fn test_enforce_constraints_unknown_action_type() {
        use constraints::{enforce_constraints, ConstraintSetV1};

        let input = make_input_raw(vec![]);
        let output = AgentOutput {
            actions: vec![ActionV1 {
                action_type: 0xFFFFFFFF, // Unknown type
                target: [0x11; 32],
                payload: vec![],
            }],
        };
        let constraints = ConstraintSetV1::default();

        let result = enforce_constraints(&input, &output, &constraints);
        assert!(result.is_err());
        let violation = result.unwrap_err();
        assert_eq!(
            violation.reason,
            ConstraintViolationReason::UnknownActionType
        );
        assert_eq!(violation.action_index, Some(0));
    }

    #[test]
    fn test_enforce_constraints_too_many_actions() {
        use constraints::{enforce_constraints, ConstraintSetV1, ACTION_TYPE_CALL};

        let input = make_input_raw(vec![]);
        let output = AgentOutput {
            actions: vec![
                ActionV1 {
                    action_type: ACTION_TYPE_CALL,
                    target: [0x11; 32],
                    payload: vec![0u8; 96],
                };
                65 // 65 actions, max is 64
            ],
        };
        let constraints = ConstraintSetV1::default();

        let result = enforce_constraints(&input, &output, &constraints);
        assert!(result.is_err());
        let violation = result.unwrap_err();
        assert_eq!(
            violation.reason,
            ConstraintViolationReason::InvalidOutputStructure
        );
    }

    #[test]
    fn test_journal_failure_has_empty_commitment() {
        use constraints::EMPTY_OUTPUT_COMMITMENT;

        // Create a journal with Failure status
        let journal = KernelJournalV1 {
            protocol_version: PROTOCOL_VERSION,
            kernel_version: KERNEL_VERSION,
            agent_id: [0x42; 32],
            agent_code_hash: [0xaa; 32],
            constraint_set_hash: [0xbb; 32],
            input_root: [0xcc; 32],
            execution_nonce: 1,
            input_commitment: [0xdd; 32],
            action_commitment: EMPTY_OUTPUT_COMMITMENT, // On failure
            execution_status: ExecutionStatus::Failure,
        };

        // Verify round-trip preserves all fields
        let encoded = journal.encode().unwrap();
        let decoded = KernelJournalV1::decode(&encoded).unwrap();

        assert_eq!(decoded.execution_status, ExecutionStatus::Failure);
        assert_eq!(decoded.action_commitment, EMPTY_OUTPUT_COMMITMENT);
    }

    // ========================================================================
    // P0.3: ConstraintSet Invariant Validation Tests
    // ========================================================================

    #[test]
    fn test_invalid_constraint_set_max_actions_too_large() {
        use constraints::{enforce_constraints, ConstraintSetV1, ACTION_TYPE_CALL};

        let input = make_input_raw(vec![]);
        let output = AgentOutput {
            actions: vec![ActionV1 {
                action_type: ACTION_TYPE_CALL,
                target: [0x11; 32],
                payload: vec![0u8; 96],
            }],
        };

        // max_actions_per_output exceeds protocol limit (64)
        let constraints = ConstraintSetV1 {
            max_actions_per_output: 65,
            ..ConstraintSetV1::default()
        };

        let result = enforce_constraints(&input, &output, &constraints);
        assert!(result.is_err());
        let violation = result.unwrap_err();
        assert_eq!(
            violation.reason,
            ConstraintViolationReason::InvalidConstraintSet
        );
        assert_eq!(violation.action_index, None); // Global constraint
    }

    #[test]
    fn test_invalid_constraint_set_drawdown_too_large() {
        use constraints::{enforce_constraints, ConstraintSetV1, ACTION_TYPE_CALL};

        let input = make_input_raw(vec![]);
        let output = AgentOutput {
            actions: vec![ActionV1 {
                action_type: ACTION_TYPE_CALL,
                target: [0x11; 32],
                payload: vec![0u8; 96],
            }],
        };

        // max_drawdown_bps exceeds 10000 (100%)
        let constraints = ConstraintSetV1 {
            max_drawdown_bps: 10_001,
            ..ConstraintSetV1::default()
        };

        let result = enforce_constraints(&input, &output, &constraints);
        assert!(result.is_err());
        let violation = result.unwrap_err();
        assert_eq!(
            violation.reason,
            ConstraintViolationReason::InvalidConstraintSet
        );
        assert_eq!(violation.action_index, None); // Global constraint
    }

    // ========================================================================
    // P0.4: Yield Agent Tests
    // ========================================================================

    #[test]
    fn test_yield_agent_valid_input_success() {
        // When yield agent receives valid 48-byte input, it produces 2 CALL actions
        let input = KernelInputV1 {
            protocol_version: PROTOCOL_VERSION,
            kernel_version: KERNEL_VERSION,
            agent_id: [0x42; 32],
            agent_code_hash: AGENT_CODE_HASH, // Must match linked agent
            constraint_set_hash: [0xbb; 32],
            input_root: [0xcc; 32],
            execution_nonce: 1,
            opaque_agent_inputs: vec![0u8; 48], // Valid 48-byte input
        };

        let input_bytes = input.encode().unwrap();
        let journal_bytes = kernel_main(&input_bytes).unwrap();
        let journal = KernelJournalV1::decode(&journal_bytes).unwrap();

        // Verify SUCCESS status
        assert_eq!(journal.execution_status, ExecutionStatus::Success);

        // Verify identity fields are preserved
        assert_eq!(journal.agent_id, [0x42; 32]);
        assert_eq!(journal.agent_code_hash, AGENT_CODE_HASH);
        assert_eq!(journal.constraint_set_hash, [0xbb; 32]);
        assert_eq!(journal.input_root, [0xcc; 32]);
        assert_eq!(journal.execution_nonce, 1);

        // Action commitment should NOT be the empty output commitment (agent produces 2 actions)
        assert_ne!(journal.action_commitment, EMPTY_OUTPUT_COMMITMENT);
    }

    #[test]
    fn test_yield_agent_invalid_input_empty_output() {
        // When yield agent receives wrong-sized input, it produces no actions
        let input = KernelInputV1 {
            protocol_version: PROTOCOL_VERSION,
            kernel_version: KERNEL_VERSION,
            agent_id: [0x42; 32],
            agent_code_hash: AGENT_CODE_HASH, // Must match linked agent
            constraint_set_hash: [0xbb; 32],
            input_root: [0xcc; 32],
            execution_nonce: 2,
            opaque_agent_inputs: vec![0, 2, 3, 4, 5], // Only 5 bytes - invalid
        };

        let input_bytes = input.encode().unwrap();
        let journal_bytes = kernel_main(&input_bytes).unwrap();
        let journal = KernelJournalV1::decode(&journal_bytes).unwrap();

        // Verify SUCCESS status (empty output is valid)
        assert_eq!(journal.execution_status, ExecutionStatus::Success);

        // Action commitment should be the empty output commitment
        assert_eq!(journal.action_commitment, EMPTY_OUTPUT_COMMITMENT);
    }

    #[test]
    fn test_yield_agent_determinism() {
        // Verify that the same input produces the same output
        let input = KernelInputV1 {
            protocol_version: PROTOCOL_VERSION,
            kernel_version: KERNEL_VERSION,
            agent_id: [0x11; 32],
            agent_code_hash: AGENT_CODE_HASH, // Must match linked agent
            constraint_set_hash: [0x33; 32],
            input_root: [0x44; 32],
            execution_nonce: 100,
            opaque_agent_inputs: vec![0u8; 48], // Valid 48-byte input
        };

        let input_bytes = input.encode().unwrap();

        // Run multiple times
        let result1 = kernel_main(&input_bytes).unwrap();
        let result2 = kernel_main(&input_bytes).unwrap();
        let result3 = kernel_main(&input_bytes).unwrap();

        // All results should be identical
        assert_eq!(result1, result2);
        assert_eq!(result2, result3);
    }

    #[test]
    fn test_yield_agent_action_commitment_verification() {
        // Verify that the action commitment is correctly computed for yield agent
        let vault = [0x11u8; 20];
        let yield_source = [0x22u8; 20];
        let amount: u64 = 1_000_000_000_000_000_000; // 1 ETH

        let mut opaque_inputs = Vec::with_capacity(48);
        opaque_inputs.extend_from_slice(&vault);
        opaque_inputs.extend_from_slice(&yield_source);
        opaque_inputs.extend_from_slice(&amount.to_le_bytes());

        let input = KernelInputV1 {
            protocol_version: PROTOCOL_VERSION,
            kernel_version: KERNEL_VERSION,
            agent_id: [0x42; 32],
            agent_code_hash: AGENT_CODE_HASH, // Must match linked agent
            constraint_set_hash: [0xbb; 32],
            input_root: [0xcc; 32],
            execution_nonce: 4,
            opaque_agent_inputs: opaque_inputs,
        };

        let input_bytes = input.encode().unwrap();
        let journal_bytes = kernel_main(&input_bytes).unwrap();
        let journal = KernelJournalV1::decode(&journal_bytes).unwrap();

        assert_eq!(journal.execution_status, ExecutionStatus::Success);

        // Manually compute expected action commitment
        let target = address_to_bytes32(&yield_source);

        // Deposit action
        let deposit_action = call_action(target, amount as u128, &[]);

        // Withdraw action
        let withdraw_selector: [u8; 4] = [0x51, 0xcf, 0xf8, 0xd9];
        let mut withdraw_calldata = Vec::with_capacity(36);
        withdraw_calldata.extend_from_slice(&withdraw_selector);
        withdraw_calldata.extend_from_slice(&address_to_bytes32(&vault));
        let withdraw_action = call_action(target, 0, &withdraw_calldata);

        let expected_output = AgentOutput {
            actions: vec![deposit_action, withdraw_action],
        };
        let expected_output_bytes = expected_output.encode().unwrap();
        let expected_commitment = compute_action_commitment(&expected_output_bytes);

        assert_eq!(journal.action_commitment, expected_commitment);
    }

    // ========================================================================
    // P0.5: Agent Code Hash Binding Tests
    // ========================================================================

    #[test]
    fn test_agent_code_hash_match_passes() {
        // When agent_code_hash matches the linked agent, execution succeeds.
        let input = make_input([0x11; 20], [0x22; 20], 1000);

        let input_bytes = input.encode().unwrap();
        let result = kernel_main(&input_bytes);

        // Should succeed because hash matches
        assert!(result.is_ok(), "Expected success but got: {:?}", result);

        let journal_bytes = result.unwrap();
        let journal = KernelJournalV1::decode(&journal_bytes).unwrap();

        // Verify SUCCESS status
        assert_eq!(journal.execution_status, ExecutionStatus::Success);

        // Verify the journal contains the correct agent_code_hash
        assert_eq!(journal.agent_code_hash, AGENT_CODE_HASH);
    }

    #[test]
    fn test_agent_code_hash_mismatch_fails() {
        // When agent_code_hash does NOT match the linked agent, execution fails.
        let wrong_hash = [0xde; 32]; // Wrong hash

        let mut opaque_inputs = Vec::with_capacity(48);
        opaque_inputs.extend_from_slice(&[0x11; 20]);
        opaque_inputs.extend_from_slice(&[0x22; 20]);
        opaque_inputs.extend_from_slice(&1000u64.to_le_bytes());

        let input = KernelInputV1 {
            protocol_version: PROTOCOL_VERSION,
            kernel_version: KERNEL_VERSION,
            agent_id: [0x42; 32],
            agent_code_hash: wrong_hash, // WRONG hash
            constraint_set_hash: [0xbb; 32],
            input_root: [0xcc; 32],
            execution_nonce: 1,
            opaque_agent_inputs: opaque_inputs,
        };

        let input_bytes = input.encode().unwrap();
        let result = kernel_main(&input_bytes);

        // Should fail with AgentCodeHashMismatch
        assert!(result.is_err(), "Expected error but got success");
        assert!(
            matches!(result, Err(KernelError::AgentCodeHashMismatch)),
            "Expected AgentCodeHashMismatch but got: {:?}",
            result
        );
    }

    #[test]
    fn test_agent_code_hash_with_constraints() {
        // Test that agent code hash verification works with custom constraints too.
        use constraints::ConstraintSetV1;
        use kernel_guest_binding_yield::kernel_main_with_constraints;

        // With valid hash - should succeed
        let valid_input = make_input([0x11; 20], [0x22; 20], 1000);
        let constraints = ConstraintSetV1::default();
        let input_bytes = valid_input.encode().unwrap();
        let result = kernel_main_with_constraints(&input_bytes, &constraints);
        assert!(result.is_ok(), "Expected success with valid hash");

        // With invalid hash - should fail
        let mut opaque_inputs = Vec::with_capacity(48);
        opaque_inputs.extend_from_slice(&[0x11; 20]);
        opaque_inputs.extend_from_slice(&[0x22; 20]);
        opaque_inputs.extend_from_slice(&1000u64.to_le_bytes());

        let invalid_input = KernelInputV1 {
            protocol_version: PROTOCOL_VERSION,
            kernel_version: KERNEL_VERSION,
            agent_id: [0x42; 32],
            agent_code_hash: [0xff; 32], // WRONG hash
            constraint_set_hash: [0xbb; 32],
            input_root: [0xcc; 32],
            execution_nonce: 2,
            opaque_agent_inputs: opaque_inputs,
        };
        let input_bytes = invalid_input.encode().unwrap();
        let result = kernel_main_with_constraints(&input_bytes, &constraints);
        assert!(
            matches!(result, Err(KernelError::AgentCodeHashMismatch)),
            "Expected AgentCodeHashMismatch but got: {:?}",
            result
        );
    }

    #[test]
    fn test_agent_code_hash_constant_is_stable() {
        // Verify the agent code hash is a 32-byte value (sanity check).
        assert_eq!(AGENT_CODE_HASH.len(), 32);

        // Hash should not be all zeros (would indicate a problem)
        assert_ne!(
            AGENT_CODE_HASH, [0u8; 32],
            "Agent hash should not be all zeros"
        );

        // Hash should not be all 0xFF (would indicate a problem)
        assert_ne!(
            AGENT_CODE_HASH, [0xffu8; 32],
            "Agent hash should not be all 0xFF"
        );
    }

    // ========================================================================
    // Test Helpers
    // ========================================================================

    fn hex_to_vec(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex_to_bytes32(hex: &str) -> [u8; 32] {
        let vec = hex_to_vec(hex);
        assert_eq!(vec.len(), 32, "Expected 32 bytes, got {}", vec.len());
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&vec);
        arr
    }
}
