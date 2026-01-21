#[cfg(test)]
mod tests {
    use kernel_core::*;
    use kernel_guest::kernel_main;

    /// Helper to create a valid KernelInputV1 with default values
    fn make_input(agent_input: Vec<u8>) -> KernelInputV1 {
        KernelInputV1 {
            protocol_version: PROTOCOL_VERSION,
            kernel_version: KERNEL_VERSION,
            agent_id: [0x42; 32],
            agent_code_hash: [0xaa; 32],
            constraint_set_hash: [0xbb; 32],
            input_root: [0xcc; 32],
            execution_nonce: 1,
            opaque_agent_inputs: agent_input,
        }
    }

    #[test]
    fn test_kernel_input_encoding_round_trip() {
        let original = make_input(vec![1, 2, 3, 4, 5]);

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
                action_type: 2,  // Higher type
                target: [0x11; 32],
                payload: vec![1],
            },
            ActionV1 {
                action_type: 1,  // Lower type - should sort first
                target: [0x22; 32],
                payload: vec![2],
            },
            ActionV1 {
                action_type: 1,  // Same type, different target
                target: [0x11; 32],  // Lower target - should sort before [0x22]
                payload: vec![3],
            },
        ];

        let output1 = AgentOutput { actions: actions_unordered.clone() };
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
        let output2 = AgentOutput { actions: actions_reversed };
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
            0x9f, 0x64, 0xa7, 0x47, 0xe1, 0xb9, 0x7f, 0x13,
            0x1f, 0xab, 0xb6, 0xb4, 0x47, 0x29, 0x6c, 0x9b,
            0x6f, 0x02, 0x01, 0xe7, 0x9f, 0xb3, 0xc5, 0x35,
            0x6e, 0x6c, 0x77, 0xe8, 0x9b, 0x6a, 0x80, 0x6a
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
            0xdf, 0x3f, 0x61, 0x98, 0x04, 0xa9, 0x2f, 0xdb,
            0x40, 0x57, 0x19, 0x2d, 0xc4, 0x3d, 0xd7, 0x48,
            0xea, 0x77, 0x8a, 0xdc, 0x52, 0xbc, 0x49, 0x8c,
            0xe8, 0x05, 0x24, 0xc0, 0x14, 0xb8, 0x11, 0x19
        ];

        assert_eq!(commitment, expected);
    }

    #[test]
    fn test_determinism() {
        let input = make_input(vec![100, 200]);
        let input_bytes = input.encode().unwrap();

        let result1 = kernel_main(&input_bytes).unwrap();
        let result2 = kernel_main(&input_bytes).unwrap();

        assert_eq!(result1, result2);
    }

    #[test]
    fn test_invalid_protocol_version() {
        let mut input = make_input(vec![1, 2, 3]);
        input.protocol_version = 999;

        let input_bytes = input.encode().unwrap();
        let result = KernelInputV1::decode(&input_bytes);

        assert!(matches!(result, Err(CodecError::InvalidVersion { expected: 1, actual: 999 })));
    }

    #[test]
    fn test_invalid_kernel_version() {
        let mut input = make_input(vec![1, 2, 3]);
        input.kernel_version = 999;

        let input_bytes = input.encode().unwrap();
        let result = KernelInputV1::decode(&input_bytes);

        assert!(matches!(result, Err(CodecError::InvalidVersion { expected: 1, actual: 999 })));
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
        assert!(matches!(result, Err(CodecError::InvalidVersion { expected: 1, actual: 999 })));
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
        assert!(matches!(result, Err(CodecError::InvalidVersion { expected: 1, actual: 999 })));
    }

    #[test]
    fn test_input_too_large() {
        let large_input = vec![0u8; MAX_AGENT_INPUT_BYTES + 1];
        let input = make_input(large_input);

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
        let input = make_input(vec![1, 2, 3]);
        let input_bytes = input.encode().unwrap();
        let result = kernel_main(&input_bytes);

        assert!(result.is_ok());
    }

    #[test]
    fn test_empty_input() {
        let input = make_input(vec![]);
        let input_bytes = input.encode().unwrap();
        let result = kernel_main(&input_bytes);

        assert!(result.is_ok());

        let journal_bytes = result.unwrap();
        let journal = KernelJournalV1::decode(&journal_bytes).unwrap();
        assert_eq!(journal.execution_status, ExecutionStatus::Success);
    }

    #[test]
    fn test_max_size_input() {
        let input = make_input(vec![0x42; MAX_AGENT_INPUT_BYTES]);
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
            agent_code_hash: [0x22; 32],
            constraint_set_hash: [0x33; 32],
            input_root: [0x44; 32],
            execution_nonce: 9999,
            opaque_agent_inputs: vec![1, 2, 3],
        };

        let input_bytes = input.encode().unwrap();
        let journal_bytes = kernel_main(&input_bytes).unwrap();
        let journal = KernelJournalV1::decode(&journal_bytes).unwrap();

        // Verify identity fields are copied to journal
        assert_eq!(journal.agent_id, [0x11; 32]);
        assert_eq!(journal.agent_code_hash, [0x22; 32]);
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
        assert!(matches!(result, Err(CodecError::ActionPayloadTooLarge { .. })));
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
        assert!(matches!(result, Err(CodecError::InvalidExecutionStatus(0xFF))));

        // Also verify that 0x00 is invalid (reserved to catch uninitialized memory)
        *encoded.last_mut().unwrap() = 0x00;
        let result = KernelJournalV1::decode(&encoded);
        assert!(matches!(result, Err(CodecError::InvalidExecutionStatus(0x00))));
    }

    #[test]
    fn test_determinism_with_edge_cases() {
        let test_cases = vec![
            vec![],                              // Empty
            vec![0],                             // Single byte
            vec![0xFF; 100],                     // Repeated bytes
            (0..255).collect::<Vec<u8>>(),       // Sequential bytes
        ];

        for test_input in test_cases {
            let input = make_input(test_input);
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
        let input1 = KernelInputV1 {
            protocol_version: PROTOCOL_VERSION,
            kernel_version: KERNEL_VERSION,
            agent_id: [0x42; 32],
            agent_code_hash: [0xaa; 32],
            constraint_set_hash: [0xbb; 32],
            input_root: [0xcc; 32],
            execution_nonce: 1,
            opaque_agent_inputs: vec![1, 2, 3],
        };

        let input2 = KernelInputV1 {
            execution_nonce: 2,
            ..input1.clone()
        };

        let journal1 = KernelJournalV1::decode(&kernel_main(&input1.encode().unwrap()).unwrap()).unwrap();
        let journal2 = KernelJournalV1::decode(&kernel_main(&input2.encode().unwrap()).unwrap()).unwrap();

        assert_eq!(journal1.execution_nonce, 1);
        assert_eq!(journal2.execution_nonce, 2);

        // Different nonces should produce different input commitments
        assert_ne!(journal1.input_commitment, journal2.input_commitment);
    }

    #[test]
    fn test_input_header_size() {
        // Verify minimum input size with empty data
        let input = make_input(vec![]);
        let encoded = input.encode().unwrap();

        // Fixed fields (144) + length prefix (4) + 0 bytes data = 148
        assert_eq!(encoded.len(), 148);
    }
}
