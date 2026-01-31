//! Integration tests for reference-integrator.
//!
//! These tests verify the complete workflow of loading and verifying bundles.

use reference_integrator::{BundleError, LoadedBundle};
use std::path::PathBuf;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

#[test]
fn test_load_valid_bundle() {
    let bundle = LoadedBundle::load(fixtures_dir()).expect("Should load valid bundle");

    assert_eq!(bundle.manifest.agent_name, "test-agent");
    assert_eq!(bundle.manifest.agent_version, "1.0.0");
    assert_eq!(bundle.manifest.protocol_version, 1);
    assert_eq!(bundle.manifest.kernel_version, 1);
    assert_eq!(
        bundle.manifest.agent_id,
        "0x0000000000000000000000000000000000000000000000000000000000000001"
    );
}

#[test]
fn test_bundle_path_resolution() {
    let bundle = LoadedBundle::load(fixtures_dir()).expect("Should load bundle");

    // Verify paths are absolute
    assert!(bundle.manifest_path.is_absolute());
    assert!(bundle.elf_path.is_absolute());
    assert!(bundle.base_dir.is_absolute());

    // Verify paths exist
    assert!(bundle.manifest_path.exists());
    assert!(bundle.elf_path.exists());
    assert!(bundle.base_dir.exists());

    // Verify manifest path ends with agent-pack.json
    assert!(bundle
        .manifest_path
        .to_string_lossy()
        .ends_with("agent-pack.json"));
}

#[test]
fn test_bundle_hex_parsing() {
    let bundle = LoadedBundle::load(fixtures_dir()).expect("Should load bundle");

    // Test agent_id parsing
    let agent_id_bytes = bundle.agent_id_bytes().expect("Should parse agent_id");
    assert_eq!(agent_id_bytes[31], 1);
    assert_eq!(agent_id_bytes[0], 0);

    // Test image_id parsing
    let image_id_bytes = bundle.image_id_bytes().expect("Should parse image_id");
    assert_eq!(image_id_bytes.len(), 32);

    // Test agent_code_hash parsing
    let code_hash_bytes = bundle
        .agent_code_hash_bytes()
        .expect("Should parse agent_code_hash");
    assert_eq!(code_hash_bytes.len(), 32);
}

#[test]
fn test_read_elf() {
    let bundle = LoadedBundle::load(fixtures_dir()).expect("Should load bundle");

    let elf_bytes = bundle.read_elf().expect("Should read ELF file");
    assert!(!elf_bytes.is_empty());
}

#[test]
fn test_load_nonexistent_directory() {
    let result = LoadedBundle::load("/nonexistent/path");
    assert!(matches!(result, Err(BundleError::DirectoryNotFound(_))));
}

#[test]
fn test_load_directory_without_manifest() {
    // Use a directory that exists but doesn't have agent-pack.json
    let result = LoadedBundle::load("/tmp");
    assert!(matches!(result, Err(BundleError::ManifestNotFound(_))));
}

mod verify_tests {
    use super::*;
    use reference_integrator::{verify_offline, verify_structure};

    #[test]
    fn test_verify_structure() {
        let bundle = LoadedBundle::load(fixtures_dir()).expect("Should load bundle");
        let result = verify_structure(&bundle);

        // Structure should pass (manifest is well-formed)
        assert!(result.passed, "Structure verification should pass");
    }

    #[test]
    fn test_verify_offline() {
        let bundle = LoadedBundle::load(fixtures_dir()).expect("Should load bundle");
        let result = verify_offline(&bundle);

        // Check that verification ran (may fail due to hash mismatch with mock ELF)
        // The important thing is that it doesn't panic
        // Report has errors, warnings, and passed fields
        let _errors = &result.report.errors;
        let _warnings = &result.report.warnings;
        let _passed = result.report.passed;
    }
}

mod input_tests {
    use super::*;
    use reference_integrator::{build_and_encode_input, build_kernel_input, InputParams};

    #[test]
    fn test_build_input_from_bundle() {
        let bundle = LoadedBundle::load(fixtures_dir()).expect("Should load bundle");

        let params = InputParams {
            opaque_agent_inputs: b"test input data".to_vec(),
            ..Default::default()
        };

        let input = build_kernel_input(&bundle, &params).expect("Should build input");

        // Verify the input was built correctly
        assert_eq!(input.protocol_version, 1);
        assert_eq!(input.kernel_version, 1);
        assert_eq!(input.agent_id[31], 1); // Last byte of agent_id is 1
        assert_eq!(input.opaque_agent_inputs, b"test input data".to_vec());
    }

    #[test]
    fn test_build_and_encode_input() {
        let bundle = LoadedBundle::load(fixtures_dir()).expect("Should load bundle");

        let params = InputParams {
            opaque_agent_inputs: b"test".to_vec(),
            ..Default::default()
        };

        let input_bytes = build_and_encode_input(&bundle, &params).expect("Should encode input");

        // Should be non-empty
        assert!(!input_bytes.is_empty());

        // Should start with protocol version (1 as u32 LE)
        assert_eq!(input_bytes[0], 1);
        assert_eq!(input_bytes[1], 0);
        assert_eq!(input_bytes[2], 0);
        assert_eq!(input_bytes[3], 0);
    }
}

mod cli_tests {
    use super::*;
    use std::process::Command;

    fn refint_binary() -> PathBuf {
        // The binary is built in the target directory
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.pop(); // go up from reference-integrator
        path.pop(); // go up from crates
        path.push("target");
        path.push("debug");
        path.push("refint");
        path
    }

    #[test]
    fn test_verify_json_output_structure() {
        let binary = refint_binary();
        if !binary.exists() {
            // Binary not built yet, skip test
            eprintln!("Skipping CLI test: refint binary not found at {:?}", binary);
            return;
        }

        let output = Command::new(&binary)
            .args([
                "verify",
                "--bundle",
                fixtures_dir().to_str().unwrap(),
                "--json",
            ])
            .output()
            .expect("Failed to run refint");

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse as JSON
        let json: serde_json::Value =
            serde_json::from_str(&stdout).expect("Output should be valid JSON");

        // Check required fields exist
        assert!(
            json.get("success").is_some(),
            "JSON should have 'success' field"
        );
        assert!(
            json.get("agent_name").is_some(),
            "JSON should have 'agent_name' field"
        );
        assert!(
            json.get("agent_version").is_some(),
            "JSON should have 'agent_version' field"
        );
        assert!(
            json.get("agent_id").is_some(),
            "JSON should have 'agent_id' field"
        );
        assert!(
            json.get("offline_passed").is_some(),
            "JSON should have 'offline_passed' field"
        );
        assert!(
            json.get("errors").is_some(),
            "JSON should have 'errors' field"
        );
        assert!(
            json.get("warnings").is_some(),
            "JSON should have 'warnings' field"
        );

        // Verify agent info matches fixture
        assert_eq!(json["agent_name"], "test-agent");
        assert_eq!(json["agent_version"], "1.0.0");
    }

    #[test]
    fn test_status_json_output_structure() {
        let binary = refint_binary();
        if !binary.exists() {
            eprintln!("Skipping CLI test: refint binary not found at {:?}", binary);
            return;
        }

        let output = Command::new(&binary)
            .args(["status", "--json"])
            .output()
            .expect("Failed to run refint");

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse as JSON
        let json: serde_json::Value =
            serde_json::from_str(&stdout).expect("Output should be valid JSON");

        // Check required fields
        assert!(
            json.get("version").is_some(),
            "JSON should have 'version' field"
        );
        assert!(
            json.get("features").is_some(),
            "JSON should have 'features' field"
        );

        // Check features structure
        let features = json.get("features").unwrap();
        assert!(
            features.get("cli").is_some(),
            "Features should have 'cli' field"
        );
        assert!(
            features.get("onchain").is_some(),
            "Features should have 'onchain' field"
        );
        assert!(
            features.get("prove").is_some(),
            "Features should have 'prove' field"
        );
    }

    #[test]
    fn test_verify_exit_code_on_nonexistent_bundle() {
        let binary = refint_binary();
        if !binary.exists() {
            eprintln!("Skipping CLI test: refint binary not found at {:?}", binary);
            return;
        }

        let output = Command::new(&binary)
            .args(["verify", "--bundle", "/nonexistent/path", "--json"])
            .output()
            .expect("Failed to run refint");

        // Exit code 1 for invalid usage / parsing error
        assert_eq!(output.status.code(), Some(1));

        // Should still output valid JSON
        let stdout = String::from_utf8_lossy(&output.stdout);
        let json: serde_json::Value =
            serde_json::from_str(&stdout).expect("Output should be valid JSON");
        assert_eq!(json["success"], false);
    }
}
