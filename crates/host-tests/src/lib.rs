#[cfg(test)]
mod tests {
    use kernel_core::*;
    use kernel_guest::kernel_main;

    #[test]
    fn test_kernel_input_encoding_round_trip() {
        let original = KernelInputV1 {
            protocol_version: 1,
            agent_id: [0x42; 32],
            agent_input: vec![1, 2, 3, 4, 5],
        };

        let encoded = original.encode();
        let decoded = KernelInputV1::decode(&encoded).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_kernel_journal_encoding_round_trip() {
        let original = KernelJournalV1 {
            protocol_version: 1,
            kernel_version: 1,
            input_commitment: [0xaa; 32],
            action_commitment: [0xbb; 32],
            execution_status: ExecutionStatus::Success,
        };

        let encoded = original.encode();
        let decoded = KernelJournalV1::decode(&encoded).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_agent_output_encoding_round_trip() {
        let original = AgentOutput {
            data: vec![10, 20, 30, 40],
        };

        let encoded = original.encode();
        let decoded = AgentOutput::decode(&encoded).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_input_commitment_golden_vector() {
        let input_bytes = vec![1, 2, 3, 4];
        let commitment = compute_input_commitment(&input_bytes);
        
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
        let agent_output = AgentOutput { data: vec![5, 6, 7, 8] };
        let output_bytes = agent_output.encode();
        let commitment = compute_action_commitment(&output_bytes);
        
        let expected = [
            0xf4, 0xef, 0xd2, 0x8a, 0x94, 0x8f, 0x87, 0xf5,
            0x31, 0x86, 0x97, 0x5e, 0xe0, 0x8f, 0xad, 0x42,
            0x57, 0x9e, 0x8d, 0x8d, 0xad, 0x9c, 0x2a, 0x98,
            0xd1, 0x8c, 0xa3, 0x5a, 0x68, 0xb8, 0x3e, 0x76
        ];
        
        assert_eq!(commitment, expected);
    }

    #[test]
    fn test_determinism() {
        let input = KernelInputV1 {
            protocol_version: 1,
            agent_id: [0x12; 32],
            agent_input: vec![100, 200],
        };

        let input_bytes = input.encode();
        
        let result1 = kernel_main(&input_bytes).unwrap();
        let result2 = kernel_main(&input_bytes).unwrap();

        assert_eq!(result1, result2);
    }

    #[test]
    fn test_invalid_protocol_version() {
        let input = KernelInputV1 {
            protocol_version: 999,
            agent_id: [0x12; 32],
            agent_input: vec![1, 2, 3],
        };

        let input_bytes = input.encode();
        let result = KernelInputV1::decode(&input_bytes);
        
        assert!(matches!(result, Err(CodecError::InvalidVersion)));
    }

    #[test]
    fn test_input_too_large() {
        let large_input = vec![0u8; MAX_AGENT_INPUT_BYTES + 1];
        let input = KernelInputV1 {
            protocol_version: 1,
            agent_id: [0x12; 32],
            agent_input: large_input,
        };

        let input_bytes = input.encode();
        let result = KernelInputV1::decode(&input_bytes);
        
        assert!(matches!(result, Err(CodecError::InputTooLarge)));
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
            protocol_version: 1,
            kernel_version: 1,
            input_commitment: [0; 32],
            action_commitment: [0; 32],
            execution_status: ExecutionStatus::Success,
        };

        let encoded = journal.encode();
        assert_eq!(encoded.len(), 73);
    }

    #[test]
    fn test_constraints_enforcement() {
        let input = KernelInputV1 {
            protocol_version: 1,
            agent_id: [0x99; 32],
            agent_input: vec![1, 2, 3],
        };

        let input_bytes = input.encode();
        let result = kernel_main(&input_bytes);
        
        assert!(result.is_ok());
    }

    #[test]
    fn test_unsupported_protocol_version_error() {
        use kernel_guest::{kernel_main, KernelError};
        
        let input = KernelInputV1 {
            protocol_version: 999,
            agent_id: [0x12; 32], 
            agent_input: vec![1, 2, 3],
        };

        let input_bytes = input.encode();
        let result = kernel_main(&input_bytes);
        
        assert!(matches!(result, Err(KernelError::InvalidInput(CodecError::InvalidVersion))));
    }
}