//! Helpers for constructing KernelInputV1 structures.
//!
//! This module provides utilities to build kernel inputs from bundle metadata
//! and user-provided execution parameters.

use crate::bundle::{BundleError, LoadedBundle};
use kernel_core::{CanonicalEncode, CodecError, KernelInputV1, KERNEL_VERSION, PROTOCOL_VERSION};

/// Parameters for building a kernel input.
#[derive(Debug, Clone)]
pub struct InputParams {
    /// Constraint set hash (32 bytes).
    pub constraint_set_hash: [u8; 32],
    /// External state root / input root (32 bytes).
    pub input_root: [u8; 32],
    /// Execution nonce for replay protection.
    pub execution_nonce: u64,
    /// Opaque agent-specific input data (max 64KB).
    pub opaque_agent_inputs: Vec<u8>,
}

impl Default for InputParams {
    fn default() -> Self {
        Self {
            constraint_set_hash: [0u8; 32],
            input_root: [0u8; 32],
            execution_nonce: 1,
            opaque_agent_inputs: Vec::new(),
        }
    }
}

/// Errors that can occur during input building.
#[derive(Debug, thiserror::Error)]
pub enum InputError {
    #[error("Failed to parse bundle data: {0}")]
    BundleError(#[from] BundleError),

    #[error("Failed to encode input: {0}")]
    EncodeError(String),

    #[error("Opaque inputs too large: {size} bytes (max 64000)")]
    InputsTooLarge { size: usize },
}

impl From<CodecError> for InputError {
    fn from(e: CodecError) -> Self {
        InputError::EncodeError(format!("{:?}", e))
    }
}

/// Build a KernelInputV1 from a loaded bundle and execution parameters.
///
/// This function combines metadata from the bundle (agent_id, agent_code_hash)
/// with user-provided execution parameters to create a complete kernel input.
///
/// # Arguments
///
/// * `bundle` - The loaded Agent Pack bundle
/// * `params` - Execution parameters (constraint_set_hash, input_root, nonce, opaque_inputs)
///
/// # Returns
///
/// A `KernelInputV1` ready for encoding and proving.
pub fn build_kernel_input(
    bundle: &LoadedBundle,
    params: &InputParams,
) -> Result<KernelInputV1, InputError> {
    // Validate opaque inputs size
    if params.opaque_agent_inputs.len() > 64_000 {
        return Err(InputError::InputsTooLarge {
            size: params.opaque_agent_inputs.len(),
        });
    }

    let agent_id = bundle.agent_id_bytes()?;
    let agent_code_hash = bundle.agent_code_hash_bytes()?;

    Ok(KernelInputV1 {
        protocol_version: PROTOCOL_VERSION,
        kernel_version: KERNEL_VERSION,
        agent_id,
        agent_code_hash,
        constraint_set_hash: params.constraint_set_hash,
        input_root: params.input_root,
        execution_nonce: params.execution_nonce,
        opaque_agent_inputs: params.opaque_agent_inputs.clone(),
    })
}

/// Build and encode a KernelInputV1 to bytes.
///
/// Convenience function that builds the input and encodes it in one step.
///
/// # Arguments
///
/// * `bundle` - The loaded Agent Pack bundle
/// * `params` - Execution parameters
///
/// # Returns
///
/// Encoded input bytes ready for the prover.
pub fn build_and_encode_input(
    bundle: &LoadedBundle,
    params: &InputParams,
) -> Result<Vec<u8>, InputError> {
    let input = build_kernel_input(bundle, params)?;
    input.encode().map_err(InputError::from)
}

/// Build a KernelInputV1 from raw parameters (without a bundle).
///
/// Use this when you have the raw values rather than a bundle.
/// This is the low-level API for advanced integrators.
///
/// # Arguments
///
/// * `agent_id` - 32-byte agent identifier
/// * `agent_code_hash` - 32-byte agent code hash
/// * `constraint_set_hash` - 32-byte constraint set hash
/// * `input_root` - 32-byte external state root
/// * `execution_nonce` - Monotonic nonce for replay protection
/// * `opaque_agent_inputs` - Agent-specific input data
///
/// # Returns
///
/// A `KernelInputV1` ready for encoding and proving.
pub fn build_kernel_input_raw(
    agent_id: [u8; 32],
    agent_code_hash: [u8; 32],
    constraint_set_hash: [u8; 32],
    input_root: [u8; 32],
    execution_nonce: u64,
    opaque_agent_inputs: Vec<u8>,
) -> Result<KernelInputV1, InputError> {
    if opaque_agent_inputs.len() > 64_000 {
        return Err(InputError::InputsTooLarge {
            size: opaque_agent_inputs.len(),
        });
    }

    Ok(KernelInputV1 {
        protocol_version: PROTOCOL_VERSION,
        kernel_version: KERNEL_VERSION,
        agent_id,
        agent_code_hash,
        constraint_set_hash,
        input_root,
        execution_nonce,
        opaque_agent_inputs,
    })
}

/// Parse a hex string (with or without 0x prefix) into bytes.
pub fn parse_hex(hex_str: &str) -> Result<Vec<u8>, String> {
    let hex_clean = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    hex::decode(hex_clean).map_err(|e| format!("Invalid hex: {}", e))
}

/// Parse a hex string into a 32-byte array.
pub fn parse_hex_32(hex_str: &str) -> Result<[u8; 32], String> {
    let bytes = parse_hex(hex_str)?;
    if bytes.len() != 32 {
        return Err(format!("Expected 32 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_input_params() {
        let params = InputParams::default();
        assert_eq!(params.constraint_set_hash, [0u8; 32]);
        assert_eq!(params.input_root, [0u8; 32]);
        assert_eq!(params.execution_nonce, 1);
        assert!(params.opaque_agent_inputs.is_empty());
    }

    #[test]
    fn test_build_kernel_input_raw() {
        let result = build_kernel_input_raw(
            [0x42; 32],
            [0xaa; 32],
            [0xbb; 32],
            [0xcc; 32],
            1,
            vec![1, 2, 3],
        );
        assert!(result.is_ok());

        let input = result.unwrap();
        assert_eq!(input.protocol_version, PROTOCOL_VERSION);
        assert_eq!(input.kernel_version, KERNEL_VERSION);
        assert_eq!(input.agent_id, [0x42; 32]);
        assert_eq!(input.opaque_agent_inputs, vec![1, 2, 3]);
    }

    #[test]
    fn test_build_kernel_input_raw_too_large() {
        let large_inputs = vec![0u8; 65_000];
        let result = build_kernel_input_raw(
            [0x42; 32],
            [0xaa; 32],
            [0xbb; 32],
            [0xcc; 32],
            1,
            large_inputs,
        );
        assert!(matches!(result, Err(InputError::InputsTooLarge { .. })));
    }

    #[test]
    fn test_parse_hex() {
        let result = parse_hex("0x1234");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![0x12, 0x34]);
    }

    #[test]
    fn test_parse_hex_without_prefix() {
        let result = parse_hex("abcd");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![0xab, 0xcd]);
    }

    #[test]
    fn test_parse_hex_32() {
        let hex = "0x0000000000000000000000000000000000000000000000000000000000000001";
        let result = parse_hex_32(hex);
        assert!(result.is_ok());
        let bytes = result.unwrap();
        assert_eq!(bytes[31], 1);
    }
}
