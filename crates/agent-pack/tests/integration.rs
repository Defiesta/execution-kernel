//! Integration tests for the agent-pack crate.
//!
//! These tests exercise the full workflow: create manifest, compute hashes, verify.

use agent_pack::{
    format_hex, pack_bundle, sha256, sha256_file, verify_manifest_structure,
    verify_manifest_with_files, AgentPackManifest, Artifacts, BuildInfo, PackOptions,
};
use std::io::Write;
use tempfile::TempDir;

/// Creates a valid manifest with all computed values.
fn create_valid_manifest(elf_sha256: &str, cargo_lock_sha256: &str) -> AgentPackManifest {
    AgentPackManifest {
        format_version: "1".to_string(),
        agent_name: "integration-test-agent".to_string(),
        agent_version: "1.0.0".to_string(),
        agent_id: "0x0000000000000000000000000000000000000000000000000000000000000001".to_string(),
        protocol_version: 1,
        kernel_version: 1,
        risc0_version: "3.0.4".to_string(),
        rust_toolchain: "1.75.0".to_string(),
        agent_code_hash: "0x5aac6b1fedf1b0c0ccc037c3223b7b5c8b679f48b9c599336c0dc777be88924b"
            .to_string(),
        image_id: "0x5f42241afd61bf9e341442c8baffa9c544cf20253720f2540cf6705f27bae2c4".to_string(),
        artifacts: Artifacts {
            elf_path: "test.elf".to_string(),
            elf_sha256: elf_sha256.to_string(),
        },
        build: BuildInfo {
            cargo_lock_sha256: cargo_lock_sha256.to_string(),
            build_command: "cargo build --release".to_string(),
            reproducible: true,
        },
        inputs: "Test input format".to_string(),
        actions_profile: "Test actions".to_string(),
        networks: std::collections::BTreeMap::new(),
        git: None,
        notes: None,
    }
}

#[test]
fn test_full_workflow_create_and_verify() {
    // Create a temporary directory for our test files
    let temp_dir = TempDir::new().expect("Failed to create temp dir");

    // Create a mock ELF file with known content
    let elf_content = b"MOCK_ELF_BINARY_CONTENT_FOR_TESTING";
    let elf_path = temp_dir.path().join("test.elf");
    std::fs::write(&elf_path, elf_content).expect("Failed to write ELF file");

    // Compute the SHA256 of the ELF
    let elf_hash = sha256(elf_content);
    let elf_sha256 = format_hex(&elf_hash);

    // Create a mock Cargo.lock
    let cargo_lock_content = b"# Cargo.lock\nversion = 3\n[[package]]\nname = \"test\"";
    let cargo_lock_hash = sha256(cargo_lock_content);
    let cargo_lock_sha256 = format_hex(&cargo_lock_hash);

    // Create a manifest with computed hashes
    let manifest = create_valid_manifest(&elf_sha256, &cargo_lock_sha256);

    // Verify structure
    let structure_report = verify_manifest_structure(&manifest);
    assert!(
        structure_report.passed,
        "Structure verification failed: {}",
        structure_report
    );

    // Verify with files
    let file_report = verify_manifest_with_files(&manifest, temp_dir.path());
    assert!(
        file_report.passed,
        "File verification failed: {}",
        file_report
    );
}

#[test]
fn test_verification_fails_on_hash_mismatch() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");

    // Create an ELF file
    let elf_path = temp_dir.path().join("test.elf");
    std::fs::write(&elf_path, b"original content").expect("Failed to write ELF file");

    // Create manifest with a mismatched hash
    let wrong_hash = "0xabcdef0000000000000000000000000000000000000000000000000000000123";
    let manifest = create_valid_manifest(wrong_hash, wrong_hash);

    // Structure should pass (format is valid)
    let structure_report = verify_manifest_structure(&manifest);
    assert!(structure_report.passed);

    // File verification should fail (hash mismatch)
    let file_report = verify_manifest_with_files(&manifest, temp_dir.path());
    assert!(
        !file_report.passed,
        "Expected verification to fail due to hash mismatch"
    );
}

#[test]
fn test_verification_fails_on_missing_elf() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");

    // Create manifest pointing to non-existent ELF
    let manifest = create_valid_manifest(
        "0xabcdef0000000000000000000000000000000000000000000000000000000123",
        "0x1234560000000000000000000000000000000000000000000000000000000abc",
    );

    // File verification should fail (ELF not found)
    let file_report = verify_manifest_with_files(&manifest, temp_dir.path());
    assert!(
        !file_report.passed,
        "Expected verification to fail due to missing ELF"
    );
}

#[test]
fn test_manifest_file_roundtrip() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");

    // Create a valid manifest
    let manifest = create_valid_manifest(
        "0xabcdef0000000000000000000000000000000000000000000000000000000123",
        "0x1234560000000000000000000000000000000000000000000000000000000abc",
    );

    // Save to file
    let manifest_path = temp_dir.path().join("agent-pack.json");
    manifest
        .to_file(&manifest_path)
        .expect("Failed to save manifest");

    // Load from file
    let loaded = AgentPackManifest::from_file(&manifest_path).expect("Failed to load manifest");

    // Verify they're equal
    assert_eq!(manifest, loaded);
}

#[test]
fn test_sha256_file_function() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");

    // Create a file with known content
    let content = b"Hello, SHA-256!";
    let file_path = temp_dir.path().join("test.txt");
    let mut file = std::fs::File::create(&file_path).expect("Failed to create file");
    file.write_all(content).expect("Failed to write");

    // Compute hash using the file function
    let file_hash = sha256_file(&file_path).expect("Failed to hash file");

    // Compute hash using the bytes function
    let bytes_hash = sha256(content);

    // They should match
    assert_eq!(file_hash, bytes_hash);
}

#[test]
fn test_template_initialization() {
    // Create a template
    let template = AgentPackManifest::new_template(
        "my-agent".to_string(),
        "0.1.0".to_string(),
        "0x0000000000000000000000000000000000000000000000000000000000000001".to_string(),
    );

    // Verify it has placeholders
    assert!(template.agent_code_hash.contains("TODO"));
    assert!(template.image_id.contains("TODO"));
    assert!(template.artifacts.elf_sha256.contains("TODO"));
    assert!(template.build.cargo_lock_sha256.contains("TODO"));

    // Structure verification should fail due to placeholders
    let report = verify_manifest_structure(&template);
    assert!(!report.passed, "Template should fail verification");

    // Check that placeholder errors are detected
    let has_placeholder_error = report
        .errors
        .iter()
        .any(|e| matches!(e, agent_pack::VerificationError::PlaceholderFound { .. }));
    assert!(has_placeholder_error, "Should detect placeholder values");
}

#[test]
fn test_example_manifest_validates() {
    // Load the example manifest from the dist directory
    let example_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("dist/agent-pack.example.json");

    if example_path.exists() {
        let manifest =
            AgentPackManifest::from_file(&example_path).expect("Failed to load example manifest");

        // Structure should validate
        let report = verify_manifest_structure(&manifest);
        assert!(report.passed, "Example manifest should pass: {}", report);
    }
}

// ============================================================================
// Pack Command Integration Tests
// ============================================================================

/// Helper to create a valid input manifest for pack tests.
/// Unlike the template, this has valid values for all fields except those
/// that pack will compute (elf_sha256, cargo_lock_sha256).
fn create_pack_input_manifest(dir: &std::path::Path) -> std::path::PathBuf {
    // Start with valid values for fields pack doesn't compute
    let manifest = AgentPackManifest {
        format_version: "1".to_string(),
        agent_name: "pack-test-agent".to_string(),
        agent_version: "1.0.0".to_string(),
        agent_id: "0x0000000000000000000000000000000000000000000000000000000000000042".to_string(),
        protocol_version: 1,
        kernel_version: 1,
        risc0_version: "3.0.4".to_string(),
        rust_toolchain: "1.75.0".to_string(),
        // These are computed by build.rs/risc0, not pack - use valid dummy values
        agent_code_hash: "0xabcdef0000000000000000000000000000000000000000000000000000000001"
            .to_string(),
        image_id: "0xabcdef0000000000000000000000000000000000000000000000000000000002".to_string(),
        artifacts: Artifacts {
            elf_path: "placeholder.elf".to_string(),
            // This will be computed by pack
            elf_sha256: "0xabcdef0000000000000000000000000000000000000000000000000000000003"
                .to_string(),
        },
        build: BuildInfo {
            // This can be computed by pack if cargo_lock provided
            cargo_lock_sha256: "0xabcdef0000000000000000000000000000000000000000000000000000000004"
                .to_string(),
            build_command: "cargo build --release".to_string(),
            reproducible: true,
        },
        inputs: "Test input".to_string(),
        actions_profile: "Test actions".to_string(),
        networks: std::collections::BTreeMap::new(),
        git: None,
        notes: None,
    };
    let path = dir.join("input-manifest.json");
    manifest.to_file(&path).expect("Failed to write manifest");
    path
}

/// Helper to create a mock ELF file.
fn create_mock_elf(dir: &std::path::Path, filename: &str) -> std::path::PathBuf {
    let path = dir.join(filename);
    std::fs::write(&path, b"MOCK_ELF_BINARY_FOR_PACK_TESTING").expect("Failed to write ELF");
    path
}

#[test]
fn test_pack_creates_bundle_structure() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let input_dir = temp_dir.path().join("input");
    let output_dir = temp_dir.path().join("bundle");
    std::fs::create_dir_all(&input_dir).expect("Failed to create input dir");

    let manifest_path = create_pack_input_manifest(&input_dir);
    let elf_path = create_mock_elf(&input_dir, "guest.elf");

    let result = pack_bundle(
        &manifest_path,
        &elf_path,
        &output_dir,
        None,
        &PackOptions::default(),
    )
    .expect("pack_bundle should succeed");

    // Verify bundle structure
    assert!(
        output_dir.join("agent-pack.json").exists(),
        "Manifest should exist in bundle"
    );
    assert!(
        output_dir.join("artifacts").exists(),
        "Artifacts dir should exist"
    );
    assert!(
        output_dir.join("artifacts/guest.elf").exists(),
        "ELF should be copied to artifacts"
    );

    // Verify result paths
    assert_eq!(result.manifest_path, output_dir.join("agent-pack.json"));
    assert!(result.elf_path.is_some());
    assert!(result.elf_sha256.starts_with("0x"));
}

#[test]
fn test_pack_manifest_has_relative_elf_path() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let input_dir = temp_dir.path().join("input");
    let output_dir = temp_dir.path().join("bundle");
    std::fs::create_dir_all(&input_dir).expect("Failed to create input dir");

    let manifest_path = create_pack_input_manifest(&input_dir);
    let elf_path = create_mock_elf(&input_dir, "my-agent.elf");

    pack_bundle(
        &manifest_path,
        &elf_path,
        &output_dir,
        None,
        &PackOptions::default(),
    )
    .expect("pack_bundle should succeed");

    // Load the output manifest and check elf_path is relative
    let output_manifest = AgentPackManifest::from_file(&output_dir.join("agent-pack.json"))
        .expect("Failed to load output manifest");

    assert_eq!(
        output_manifest.artifacts.elf_path, "artifacts/my-agent.elf",
        "ELF path should be relative"
    );
    // Path should be relative (not start with /)
    assert!(
        !output_manifest.artifacts.elf_path.starts_with('/'),
        "ELF path should not be absolute"
    );
}

#[test]
fn test_pack_bundle_verifies() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let input_dir = temp_dir.path().join("input");
    let output_dir = temp_dir.path().join("bundle");
    std::fs::create_dir_all(&input_dir).expect("Failed to create input dir");

    let manifest_path = create_pack_input_manifest(&input_dir);
    let elf_path = create_mock_elf(&input_dir, "guest.elf");

    pack_bundle(
        &manifest_path,
        &elf_path,
        &output_dir,
        None,
        &PackOptions::default(),
    )
    .expect("pack_bundle should succeed");

    // Load the packed manifest
    let packed_manifest = AgentPackManifest::from_file(&output_dir.join("agent-pack.json"))
        .expect("Failed to load packed manifest");

    // Verify with files using output_dir as base
    let report = verify_manifest_with_files(&packed_manifest, &output_dir);
    assert!(
        report.passed,
        "Packed bundle should verify successfully: {}",
        report
    );
}

#[test]
fn test_pack_tamper_detection_elf_modified() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let input_dir = temp_dir.path().join("input");
    let output_dir = temp_dir.path().join("bundle");
    std::fs::create_dir_all(&input_dir).expect("Failed to create input dir");

    let manifest_path = create_pack_input_manifest(&input_dir);
    let elf_path = create_mock_elf(&input_dir, "guest.elf");

    pack_bundle(
        &manifest_path,
        &elf_path,
        &output_dir,
        None,
        &PackOptions::default(),
    )
    .expect("pack_bundle should succeed");

    // First verify the bundle passes before tampering
    let packed_manifest = AgentPackManifest::from_file(&output_dir.join("agent-pack.json"))
        .expect("Failed to load packed manifest");
    let report_before = verify_manifest_with_files(&packed_manifest, &output_dir);
    assert!(
        report_before.passed,
        "Bundle should verify before tampering: {}",
        report_before
    );

    // Tamper with the copied ELF
    let bundle_elf = output_dir.join("artifacts/guest.elf");
    std::fs::write(&bundle_elf, b"TAMPERED_ELF_CONTENT").expect("Failed to tamper ELF");

    // Verification should now fail due to hash mismatch
    let report_after = verify_manifest_with_files(&packed_manifest, &output_dir);
    assert!(
        !report_after.passed,
        "Tampered bundle should fail verification"
    );

    // Check that the error is specifically about ELF hash mismatch
    let has_hash_mismatch = report_after
        .errors
        .iter()
        .any(|e| matches!(e, agent_pack::VerificationError::ElfHashMismatch { .. }));
    assert!(has_hash_mismatch, "Should detect ELF hash mismatch");
}

#[test]
fn test_pack_with_cargo_lock() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let input_dir = temp_dir.path().join("input");
    let output_dir = temp_dir.path().join("bundle");
    std::fs::create_dir_all(&input_dir).expect("Failed to create input dir");

    let manifest_path = create_pack_input_manifest(&input_dir);
    let elf_path = create_mock_elf(&input_dir, "guest.elf");

    // Create a Cargo.lock file
    let cargo_lock_path = input_dir.join("Cargo.lock");
    std::fs::write(&cargo_lock_path, b"# Cargo.lock\nversion = 3\n")
        .expect("Failed to write Cargo.lock");

    let result = pack_bundle(
        &manifest_path,
        &elf_path,
        &output_dir,
        Some(&cargo_lock_path),
        &PackOptions::default(),
    )
    .expect("pack_bundle should succeed");

    // Verify cargo_lock_sha256 was computed
    assert!(result.cargo_lock_sha256.is_some());

    // Load manifest and check field was updated
    let packed_manifest = AgentPackManifest::from_file(&output_dir.join("agent-pack.json"))
        .expect("Failed to load packed manifest");

    // Verify it's a proper hash
    assert!(packed_manifest.build.cargo_lock_sha256.starts_with("0x"));
    assert_eq!(packed_manifest.build.cargo_lock_sha256.len(), 66);
}

#[test]
fn test_pack_using_example_manifest() {
    // Use the example manifest from dist as a realistic test case
    let example_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("dist/agent-pack.example.json");

    if !example_path.exists() {
        // Skip if example doesn't exist (shouldn't happen, but be defensive)
        return;
    }

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let output_dir = temp_dir.path().join("bundle");

    // Create a mock ELF
    let elf_path = temp_dir.path().join("guest.elf");
    std::fs::write(&elf_path, b"EXAMPLE_ELF_FOR_PACK_TEST").expect("Failed to write ELF");

    pack_bundle(
        &example_path,
        &elf_path,
        &output_dir,
        None,
        &PackOptions::default(),
    )
    .expect("pack_bundle with example manifest should succeed");

    // Bundle should be created
    assert!(output_dir.join("agent-pack.json").exists());
    assert!(output_dir.join("artifacts/guest.elf").exists());

    // Load and verify structure
    let packed_manifest = AgentPackManifest::from_file(&output_dir.join("agent-pack.json"))
        .expect("Failed to load packed manifest");

    // Should preserve agent name and other metadata from example
    assert_eq!(packed_manifest.agent_name, "yield-agent");

    // ELF sha256 should be freshly computed (not the example's fake value)
    assert!(packed_manifest.artifacts.elf_sha256.starts_with("0x"));
    assert_eq!(packed_manifest.artifacts.elf_sha256.len(), 66);

    // Verify the bundle passes verification
    let report = verify_manifest_with_files(&packed_manifest, &output_dir);
    assert!(
        report.passed,
        "Packed example bundle should verify: {}",
        report
    );
}
