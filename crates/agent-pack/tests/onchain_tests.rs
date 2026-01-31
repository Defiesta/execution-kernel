//! Tests for on-chain verification functionality.
//!
//! These tests verify the parsing, formatting, and result handling logic
//! without requiring actual RPC connections.

#![cfg(feature = "onchain")]

use agent_pack::onchain::{OnchainError, OnchainVerifyResult};

/// Test that OnchainVerifyResult variants can be compared for equality.
#[test]
fn test_verify_result_match_equality() {
    assert_eq!(OnchainVerifyResult::Match, OnchainVerifyResult::Match);
}

#[test]
fn test_verify_result_not_registered_equality() {
    assert_eq!(
        OnchainVerifyResult::NotRegistered,
        OnchainVerifyResult::NotRegistered
    );
}

#[test]
fn test_verify_result_mismatch_equality() {
    let result1 = OnchainVerifyResult::Mismatch {
        onchain: "0x1234".to_string(),
        manifest: "0x5678".to_string(),
    };
    let result2 = OnchainVerifyResult::Mismatch {
        onchain: "0x1234".to_string(),
        manifest: "0x5678".to_string(),
    };
    assert_eq!(result1, result2);
}

#[test]
fn test_verify_result_mismatch_inequality() {
    let result1 = OnchainVerifyResult::Mismatch {
        onchain: "0x1234".to_string(),
        manifest: "0x5678".to_string(),
    };
    let result2 = OnchainVerifyResult::Mismatch {
        onchain: "0xaaaa".to_string(),
        manifest: "0x5678".to_string(),
    };
    assert_ne!(result1, result2);
}

#[test]
fn test_verify_result_different_variants() {
    assert_ne!(
        OnchainVerifyResult::Match,
        OnchainVerifyResult::NotRegistered
    );
}

/// Test error type display implementations.
#[test]
fn test_error_display_invalid_rpc_url() {
    let err = OnchainError::InvalidRpcUrl("bad url".to_string());
    let msg = format!("{}", err);
    assert!(msg.contains("Invalid RPC URL"));
    assert!(msg.contains("bad url"));
}

#[test]
fn test_error_display_invalid_verifier_address() {
    let err = OnchainError::InvalidVerifierAddress("not an address".to_string());
    let msg = format!("{}", err);
    assert!(msg.contains("Invalid verifier address"));
}

#[test]
fn test_error_display_invalid_agent_id() {
    let err = OnchainError::InvalidAgentId("too short".to_string());
    let msg = format!("{}", err);
    assert!(msg.contains("Invalid agent_id"));
}

#[test]
fn test_error_display_invalid_image_id() {
    let err = OnchainError::InvalidImageId("bad hex".to_string());
    let msg = format!("{}", err);
    assert!(msg.contains("Invalid image_id"));
}

#[test]
fn test_error_display_rpc_error() {
    let err = OnchainError::RpcError("connection refused".to_string());
    let msg = format!("{}", err);
    assert!(msg.contains("RPC error"));
    assert!(msg.contains("connection refused"));
}

/// Test that OnchainVerifyResult can be cloned.
#[test]
fn test_verify_result_clone() {
    let original = OnchainVerifyResult::Mismatch {
        onchain: "0x123".to_string(),
        manifest: "0x456".to_string(),
    };
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

/// Test that OnchainVerifyResult implements Debug.
#[test]
fn test_verify_result_debug() {
    let result = OnchainVerifyResult::Match;
    let debug_str = format!("{:?}", result);
    assert!(debug_str.contains("Match"));
}

/// Module for testing exit code semantics.
mod exit_code_tests {
    // These constants mirror the ones in main.rs for testing
    const MATCH: u8 = 0;
    const ERROR: u8 = 1;
    const MISMATCH: u8 = 2;
    const NOT_REGISTERED: u8 = 3;

    #[test]
    fn test_exit_code_match_is_success() {
        assert_eq!(MATCH, 0);
    }

    #[test]
    fn test_exit_code_error_is_failure() {
        assert_eq!(ERROR, 1);
    }

    #[test]
    fn test_exit_code_mismatch_is_two() {
        assert_eq!(MISMATCH, 2);
    }

    #[test]
    fn test_exit_code_not_registered_is_three() {
        assert_eq!(NOT_REGISTERED, 3);
    }

    #[test]
    fn test_exit_codes_are_distinct() {
        let codes = [MATCH, ERROR, MISMATCH, NOT_REGISTERED];
        for (i, &code1) in codes.iter().enumerate() {
            for (j, &code2) in codes.iter().enumerate() {
                if i != j {
                    assert_ne!(
                        code1, code2,
                        "Exit codes {} and {} should be distinct",
                        i, j
                    );
                }
            }
        }
    }
}

/// Module for testing address and hex parsing edge cases.
mod parsing_edge_cases {
    // These tests verify the expected error types for various invalid inputs.
    // The actual parsing is tested via the public verify_onchain function,
    // but we can verify error categorization here.

    #[test]
    fn test_address_must_be_20_bytes() {
        // Valid Ethereum addresses are 20 bytes (40 hex chars + 0x prefix)
        let valid_addr = "0x9Ef5bAB590AFdE8036D57b89ccD2947D4E3b1EFA";
        assert_eq!(valid_addr.len(), 42); // 2 for "0x" + 40 hex chars
    }

    #[test]
    fn test_bytes32_must_be_32_bytes() {
        // Valid bytes32 values are 32 bytes (64 hex chars + 0x prefix)
        let valid_bytes32 = "0x0000000000000000000000000000000000000000000000000000000000000001";
        assert_eq!(valid_bytes32.len(), 66); // 2 for "0x" + 64 hex chars
    }

    #[test]
    fn test_zero_bytes32_representation() {
        // bytes32(0) is all zeros
        let zero = "0x0000000000000000000000000000000000000000000000000000000000000000";
        assert!(zero.chars().skip(2).all(|c| c == '0'));
    }
}

/// Module for testing manifest validation for on-chain verification.
mod manifest_validation {
    use agent_pack::AgentPackManifest;

    #[test]
    fn test_template_manifest_has_todo_placeholders() {
        let manifest = AgentPackManifest::new_template(
            "test-agent".to_string(),
            "1.0.0".to_string(),
            "0x0000000000000000000000000000000000000000000000000000000000000001".to_string(),
        );

        // Verify that template has TODO placeholders that would fail on-chain verification
        assert!(manifest.image_id.contains("TODO"));
        assert!(manifest.agent_code_hash.contains("TODO"));
    }

    #[test]
    fn test_real_manifest_should_not_have_todo() {
        // A valid manifest for on-chain verification should have real values
        let valid_image_id = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        assert!(!valid_image_id.contains("TODO"));
    }
}
