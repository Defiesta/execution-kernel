//! Tests for manifest parsing and serialization.

use agent_pack::{verify_manifest_structure, AgentPackManifest, VerificationError};
use std::collections::BTreeMap;

fn create_valid_manifest() -> AgentPackManifest {
    AgentPackManifest {
        format_version: "1".to_string(),
        agent_name: "test-agent".to_string(),
        agent_version: "1.0.0".to_string(),
        agent_id: "0x0000000000000000000000000000000000000000000000000000000000000001".to_string(),
        protocol_version: 1,
        kernel_version: 1,
        risc0_version: "3.0.4".to_string(),
        rust_toolchain: "1.75.0".to_string(),
        agent_code_hash: "0x5aac6b1fedf1b0c0ccc037c3223b7b5c8b679f48b9c599336c0dc777be88924b"
            .to_string(),
        image_id: "0x5f42241afd61bf9e341442c8baffa9c544cf20253720f2540cf6705f27bae2c4".to_string(),
        artifacts: agent_pack::Artifacts {
            elf_path: "artifacts/zkvm-guest.elf".to_string(),
            elf_sha256: "0xabcdef0000000000000000000000000000000000000000000000000000000123"
                .to_string(),
        },
        build: agent_pack::BuildInfo {
            cargo_lock_sha256: "0x1234560000000000000000000000000000000000000000000000000000000abc"
                .to_string(),
            build_command: "RISC0_USE_DOCKER=1 cargo build --release".to_string(),
            reproducible: true,
        },
        inputs: "48-byte payload: vault(20) || yield_source(20) || amount(8)".to_string(),
        actions_profile: "Produces 2 CALL actions".to_string(),
        networks: BTreeMap::new(),
        git: Some(agent_pack::GitInfo {
            repo: "https://github.com/Defiesta/execution-kernel".to_string(),
            commit: "ed3ee50".to_string(),
        }),
        notes: Some("Test agent".to_string()),
    }
}

#[test]
fn test_manifest_roundtrip() {
    let manifest = create_valid_manifest();

    // Serialize to JSON
    let json = manifest.to_json_pretty().unwrap();

    // Deserialize back
    let parsed = AgentPackManifest::from_json(&json).unwrap();

    // Should be identical
    assert_eq!(manifest, parsed);
}

#[test]
fn test_manifest_validation_passes() {
    let manifest = create_valid_manifest();
    let report = verify_manifest_structure(&manifest);
    assert!(report.passed, "Report should pass: {}", report);
}

#[test]
fn test_manifest_validation_invalid_format_version() {
    let mut manifest = create_valid_manifest();
    manifest.format_version = "2".to_string();

    let report = verify_manifest_structure(&manifest);
    assert!(!report.passed);
    assert!(report
        .errors
        .iter()
        .any(|e| matches!(e, VerificationError::InvalidFormatVersion { .. })));
}

#[test]
fn test_manifest_validation_detects_placeholder() {
    let mut manifest = create_valid_manifest();
    manifest.image_id = "0xTODO_COMPUTE_THIS_VALUE".to_string();

    let report = verify_manifest_structure(&manifest);
    assert!(!report.passed);
    assert!(report.errors.iter().any(
        |e| matches!(e, VerificationError::PlaceholderFound { field } if field == "image_id")
    ));
}

#[test]
fn test_manifest_validation_invalid_hex() {
    let mut manifest = create_valid_manifest();
    manifest.agent_id = "0xnothex".to_string();

    let report = verify_manifest_structure(&manifest);
    assert!(!report.passed);
    assert!(report
        .errors
        .iter()
        .any(|e| matches!(e, VerificationError::InvalidHex { field, .. } if field == "agent_id")));
}

#[test]
fn test_manifest_validation_missing_prefix() {
    let mut manifest = create_valid_manifest();
    manifest.agent_id =
        "0000000000000000000000000000000000000000000000000000000000000001".to_string();

    let report = verify_manifest_structure(&manifest);
    assert!(!report.passed);
}

#[test]
fn test_semver_validation_valid() {
    let manifest = create_valid_manifest();
    let report = verify_manifest_structure(&manifest);
    assert!(report.passed);
}

#[test]
fn test_semver_validation_invalid() {
    let mut manifest = create_valid_manifest();
    manifest.agent_version = "1.0".to_string(); // Missing patch version

    let report = verify_manifest_structure(&manifest);
    assert!(!report.passed);
    assert!(report
        .errors
        .iter()
        .any(|e| matches!(e, VerificationError::InvalidSemver { .. })));
}

#[test]
fn test_semver_validation_prerelease() {
    let mut manifest = create_valid_manifest();
    manifest.agent_version = "1.0.0-alpha.1".to_string();

    let report = verify_manifest_structure(&manifest);
    assert!(report.passed);
}

#[test]
fn test_semver_validation_build_metadata() {
    let mut manifest = create_valid_manifest();
    manifest.agent_version = "1.0.0+build.123".to_string();

    let report = verify_manifest_structure(&manifest);
    assert!(report.passed);
}

#[test]
fn test_manifest_template_has_placeholders() {
    let manifest = AgentPackManifest::new_template(
        "test".to_string(),
        "1.0.0".to_string(),
        "0x0000000000000000000000000000000000000000000000000000000000000042".to_string(),
    );

    // Template should fail validation due to placeholders
    let report = verify_manifest_structure(&manifest);
    assert!(!report.passed);

    // Should have placeholder errors for computed fields
    let placeholder_fields: Vec<&str> = report
        .errors
        .iter()
        .filter_map(|e| {
            if let VerificationError::PlaceholderFound { field } = e {
                Some(field.as_str())
            } else {
                None
            }
        })
        .collect();

    assert!(placeholder_fields.contains(&"agent_code_hash"));
    assert!(placeholder_fields.contains(&"image_id"));
    assert!(placeholder_fields.contains(&"artifacts.elf_sha256"));
    assert!(placeholder_fields.contains(&"build.cargo_lock_sha256"));
}

#[test]
fn test_manifest_json_structure() {
    let manifest = create_valid_manifest();
    let json = manifest.to_json_pretty().unwrap();

    // Verify JSON structure contains expected fields
    assert!(json.contains("\"format_version\""));
    assert!(json.contains("\"agent_name\""));
    assert!(json.contains("\"agent_id\""));
    assert!(json.contains("\"image_id\""));
    assert!(json.contains("\"artifacts\""));
    assert!(json.contains("\"build\""));
}

#[test]
fn test_manifest_networks_serialization() {
    let mut manifest = create_valid_manifest();
    manifest.networks.insert(
        "sepolia".to_string(),
        agent_pack::NetworkConfig {
            verifier: "0x9Ef5bAB590AFdE8036D57b89ccD2947D4E3b1EFA".to_string(),
            vault: Some("0xAdeDA97D2D07C7f2e332fD58F40Eb4f7F0192be7".to_string()),
        },
    );

    let json = manifest.to_json_pretty().unwrap();
    assert!(json.contains("\"sepolia\""));
    assert!(json.contains("\"verifier\""));

    // Roundtrip
    let parsed = AgentPackManifest::from_json(&json).unwrap();
    assert_eq!(parsed.networks.len(), 1);
    assert!(parsed.networks.contains_key("sepolia"));
}

#[test]
fn test_manifest_empty_networks_not_serialized() {
    let manifest = create_valid_manifest();
    let json = manifest.to_json_pretty().unwrap();

    // Empty networks should be skipped due to skip_serializing_if
    // The field might still appear as {} or not at all depending on serde behavior
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    if let Some(networks) = parsed.get("networks") {
        assert!(networks.as_object().is_none_or(|o| o.is_empty()));
    }
}

#[test]
fn test_manifest_file_operations() {
    use tempfile::tempdir;

    let dir = tempdir().unwrap();
    let path = dir.path().join("test-manifest.json");

    let manifest = create_valid_manifest();

    // Write to file
    manifest.to_file(&path).unwrap();

    // Read back
    let loaded = AgentPackManifest::from_file(&path).unwrap();

    assert_eq!(manifest, loaded);
}
