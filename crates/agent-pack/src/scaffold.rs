//! Agent project scaffolding generator.
//!
//! Generates a complete, ready-to-build agent project structure from templates.
//! This reduces time-to-first-agent from days of manual setup to under 1 minute.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Options for scaffolding a new agent project.
#[derive(Debug, Clone)]
pub struct ScaffoldOptions {
    /// Agent project name (e.g., "my-yield-agent")
    pub name: String,

    /// Pre-set agent ID (32 bytes)
    pub agent_id: [u8; 32],

    /// Output directory
    pub output_dir: PathBuf,

    /// Template type
    pub template: TemplateType,

    /// Whether to initialize git
    pub init_git: bool,
}

/// Available template types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TemplateType {
    /// Minimal agent returning no-op action
    #[default]
    Minimal,

    /// Yield farming agent pattern (copy of example-yield-agent)
    Yield,
}

impl TemplateType {
    /// Parse template type from string.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "minimal" => Some(Self::Minimal),
            "yield" => Some(Self::Yield),
            _ => None,
        }
    }
}

/// Errors that can occur during scaffolding.
#[derive(Debug, thiserror::Error)]
pub enum ScaffoldError {
    #[error("Output directory already exists: {0}")]
    DirectoryExists(PathBuf),

    #[error("Failed to create directory: {0}")]
    CreateDir(String),

    #[error("Failed to write file: {0}")]
    WriteFile(String),

    #[error("Failed to initialize git: {0}")]
    GitInit(String),

    #[error("Invalid project name: {0}")]
    InvalidName(String),
}

/// Result of successful scaffolding.
#[derive(Debug)]
pub struct ScaffoldResult {
    /// Path to the created project directory
    pub project_dir: PathBuf,

    /// Whether git was initialized
    pub git_initialized: bool,
}

/// Generate a new agent project from template.
pub fn scaffold(options: &ScaffoldOptions) -> Result<ScaffoldResult, ScaffoldError> {
    // Validate project name
    validate_project_name(&options.name)?;

    // Check if output directory exists
    if options.output_dir.exists() {
        return Err(ScaffoldError::DirectoryExists(options.output_dir.clone()));
    }

    // Create directory structure
    create_directory_structure(&options.output_dir)?;

    // Generate files based on template type
    generate_files(options)?;

    // Initialize git if requested
    let git_initialized = if options.init_git {
        init_git(&options.output_dir).is_ok()
    } else {
        false
    };

    Ok(ScaffoldResult {
        project_dir: options.output_dir.clone(),
        git_initialized,
    })
}

/// Validate project name follows Rust naming conventions.
fn validate_project_name(name: &str) -> Result<(), ScaffoldError> {
    if name.is_empty() {
        return Err(ScaffoldError::InvalidName(
            "name cannot be empty".to_string(),
        ));
    }

    // Check for valid Rust crate name characters
    let valid = name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if !valid {
        return Err(ScaffoldError::InvalidName(
            "name must contain only alphanumeric characters, hyphens, or underscores".to_string(),
        ));
    }

    // Cannot start with a digit
    if name.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        return Err(ScaffoldError::InvalidName(
            "name cannot start with a digit".to_string(),
        ));
    }

    Ok(())
}

/// Create the directory structure.
fn create_directory_structure(root: &Path) -> Result<(), ScaffoldError> {
    let dirs = [
        root.to_path_buf(),
        root.join("agent/src"),
        root.join("wrapper/src"),
        root.join("tests/src"),
        root.join("dist"),
    ];

    for dir in dirs {
        fs::create_dir_all(&dir)
            .map_err(|e| ScaffoldError::CreateDir(format!("{}: {}", dir.display(), e)))?;
    }

    Ok(())
}

/// Generate all template files.
fn generate_files(options: &ScaffoldOptions) -> Result<(), ScaffoldError> {
    let name = &options.name;
    let name_snake = to_snake_case(name);
    let name_pascal = to_pascal_case(name);
    let agent_id_hex = format_agent_id(&options.agent_id);

    // Root files
    write_file(
        &options.output_dir.join("Cargo.toml"),
        &generate_root_cargo_toml(name),
    )?;
    write_file(
        &options.output_dir.join("README.md"),
        &generate_readme(name),
    )?;
    write_file(&options.output_dir.join(".gitignore"), GITIGNORE_TEMPLATE)?;

    // Agent crate
    write_file(
        &options.output_dir.join("agent/Cargo.toml"),
        &generate_agent_cargo_toml(name),
    )?;
    write_file(
        &options.output_dir.join("agent/build.rs"),
        &generate_agent_build_rs(name),
    )?;

    let agent_lib = match options.template {
        TemplateType::Minimal => generate_agent_lib_minimal(),
        TemplateType::Yield => generate_agent_lib_yield(),
    };
    write_file(&options.output_dir.join("agent/src/lib.rs"), &agent_lib)?;

    // Wrapper crate
    write_file(
        &options.output_dir.join("wrapper/Cargo.toml"),
        &generate_wrapper_cargo_toml(name),
    )?;
    write_file(
        &options.output_dir.join("wrapper/src/lib.rs"),
        &generate_wrapper_lib(&name_snake, &name_pascal),
    )?;

    // Tests crate
    write_file(
        &options.output_dir.join("tests/Cargo.toml"),
        &generate_tests_cargo_toml(name),
    )?;
    write_file(
        &options.output_dir.join("tests/src/lib.rs"),
        &generate_tests_lib(&name_snake),
    )?;

    // Manifest
    write_file(
        &options.output_dir.join("dist/agent-pack.json"),
        &generate_manifest(name, &agent_id_hex),
    )?;

    Ok(())
}

/// Write a file, creating parent directories if needed.
fn write_file(path: &Path, content: &str) -> Result<(), ScaffoldError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| ScaffoldError::CreateDir(format!("{}: {}", parent.display(), e)))?;
    }

    fs::write(path, content)
        .map_err(|e| ScaffoldError::WriteFile(format!("{}: {}", path.display(), e)))
}

/// Initialize a git repository.
fn init_git(dir: &Path) -> Result<(), ScaffoldError> {
    let output = Command::new("git")
        .args(["init"])
        .current_dir(dir)
        .output()
        .map_err(|e| ScaffoldError::GitInit(e.to_string()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ScaffoldError::GitInit(stderr.to_string()));
    }

    Ok(())
}

/// Convert a name to snake_case.
fn to_snake_case(name: &str) -> String {
    name.replace('-', "_")
}

/// Convert a name to PascalCase.
fn to_pascal_case(name: &str) -> String {
    name.split(['-', '_'])
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                None => String::new(),
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
            }
        })
        .collect()
}

/// Format agent ID bytes as 0x-prefixed hex string.
fn format_agent_id(bytes: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(bytes))
}

// ============================================================================
// Template Generators
// ============================================================================

fn generate_root_cargo_toml(name: &str) -> String {
    format!(
        r#"[workspace]
resolver = "2"
members = [
    "agent",
    "wrapper",
    "tests",
]

[workspace.package]
edition = "2021"
license = "Apache-2.0"

[workspace.dependencies]
sha2 = "0.10"

[profile.release]
lto = true
opt-level = 3
codegen-units = 1

# Project: {name}
# Generated by: agent-pack scaffold
"#,
        name = name
    )
}

fn generate_readme(name: &str) -> String {
    let name_snake = to_snake_case(name);
    format!(
        r#"# {name}

A verifiable agent for the Defiesta Execution Kernel.

## Quick Start

```bash
# Build the agent and compute AGENT_CODE_HASH
cargo build --release

# Run unit tests
cargo test

# Build for zkVM (requires RISC Zero toolchain)
cargo build --release --features risc0

# Compute hashes after zkVM build
agent-pack compute --elf target/riscv-guest/riscv32im-risc0-zkvm-elf/release/zkvm-guest --out dist/agent-pack.json
```

## Project Structure

```
{name}/
├── Cargo.toml           # Workspace manifest
├── agent/               # Core agent logic
│   ├── Cargo.toml
│   ├── build.rs         # AGENT_CODE_HASH computation
│   └── src/lib.rs       # agent_main() implementation
├── wrapper/             # AgentEntrypoint binding
│   ├── Cargo.toml
│   └── src/lib.rs       # Kernel binding
├── tests/               # Test harness
│   ├── Cargo.toml
│   └── src/lib.rs       # Unit tests
└── dist/
    └── agent-pack.json  # Agent manifest
```

## Implementing Your Agent

Edit `agent/src/lib.rs` to implement your agent logic in the `agent_main` function:

```rust
#[no_mangle]
pub extern "Rust" fn agent_main(
    ctx: &AgentContext,
    opaque_inputs: &[u8],
) -> AgentOutput {{
    // Your logic here
}}
```

## Testing

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture
```

## Agent Pack Commands

```bash
# Initialize manifest (already done by scaffold)
agent-pack init --name {name_snake} --version 0.1.0 --agent-id 0x...

# Compute hashes from ELF
agent-pack compute --elf <path-to-elf> --out dist/agent-pack.json

# Verify manifest
agent-pack verify --manifest dist/agent-pack.json

# Create distribution bundle
agent-pack pack --manifest dist/agent-pack.json --elf <path-to-elf> --out dist/bundle
```

## License

Apache-2.0
"#,
        name = name,
        name_snake = name_snake
    )
}

const GITIGNORE_TEMPLATE: &str = r#"# Build artifacts
/target/
**/*.rs.bk

# IDE
.idea/
.vscode/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db

# Cargo
Cargo.lock

# Agent Pack artifacts
/dist/artifacts/
/dist/bundle/
"#;

fn generate_agent_cargo_toml(name: &str) -> String {
    format!(
        r#"[package]
name = "{name}"
version = "0.1.0"
edition.workspace = true
license.workspace = true
description = "Agent implementation for {name}"

[lib]
crate-type = ["rlib"]

[dependencies]
kernel-sdk = {{ git = "https://github.com/Defiesta/execution-kernel", branch = "main" }}

[build-dependencies]
sha2.workspace = true
"#,
        name = name
    )
}

fn generate_agent_build_rs(name: &str) -> String {
    format!(
        r#"//! Build script for {name}
//!
//! Generates a compile-time constant `AGENT_CODE_HASH` that uniquely identifies
//! this agent's source code. This hash is used by the kernel to verify that
//! the `agent_code_hash` field in `KernelInputV1` matches the actually-linked
//! agent binary.
//!
//! # What is Hashed
//!
//! The hash is computed as: SHA256(src/lib.rs || 0x00 || Cargo.toml)

use sha2::{{Digest, Sha256}};
use std::env;
use std::fs;
use std::io::Write;
use std::path::Path;

fn main() {{
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    let manifest_path = Path::new(&manifest_dir);

    // Files to hash (deterministic order)
    let files_to_hash = ["src/lib.rs", "Cargo.toml"];

    // Rerun if any source file changes
    for file in &files_to_hash {{
        let path = manifest_path.join(file);
        println!("cargo:rerun-if-changed={{}}", path.display());
    }}

    // Also rerun if build.rs itself changes
    println!("cargo:rerun-if-changed=build.rs");

    // Compute hash: SHA256(file1 || 0x00 || file2 || 0x00 || ...)
    let mut hasher = Sha256::new();

    for (i, file) in files_to_hash.iter().enumerate() {{
        let path = manifest_path.join(file);
        let content =
            fs::read(&path).unwrap_or_else(|e| panic!("Failed to read {{}}: {{}}", path.display(), e));

        hasher.update(&content);

        // Add separator between files (not after last file)
        if i < files_to_hash.len() - 1 {{
            hasher.update([0x00]);
        }}
    }}

    let hash: [u8; 32] = hasher.finalize().into();

    // Generate Rust source file
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
    let out_path = Path::new(&out_dir).join("agent_hash.rs");

    let mut file = fs::File::create(&out_path)
        .unwrap_or_else(|e| panic!("Failed to create {{}}: {{}}", out_path.display(), e));

    writeln!(file, "// Auto-generated by build.rs - DO NOT EDIT").unwrap();
    writeln!(file, "//").unwrap();
    writeln!(
        file,
        "// This hash uniquely identifies the {name} source code."
    )
    .unwrap();
    writeln!(
        file,
        "// It is computed as SHA256(src/lib.rs || 0x00 || Cargo.toml)."
    )
    .unwrap();
    writeln!(file).unwrap();
    writeln!(file, "/// SHA-256 hash of the agent source code.").unwrap();
    writeln!(file, "///").unwrap();
    writeln!(
        file,
        "/// This constant binds the zkVM proof to this specific agent implementation."
    )
    .unwrap();
    write!(file, "pub const AGENT_CODE_HASH: [u8; 32] = [").unwrap();
    for (i, byte) in hash.iter().enumerate() {{
        if i > 0 {{
            write!(file, ", ").unwrap();
        }}
        write!(file, "0x{{:02x}}", byte).unwrap();
    }}
    writeln!(file, "];").unwrap();

    // Print hash for build logs (useful for debugging)
    let hash_hex: String = hash.iter().map(|b| format!("{{:02x}}", b)).collect();
    println!(
        "cargo:warning=AGENT_CODE_HASH ({name}): {{}}",
        hash_hex
    );
}}
"#,
        name = name
    )
}

fn generate_agent_lib_minimal() -> String {
    r#"//! Minimal Agent Implementation
//!
//! This is a template agent that returns a single NO_OP action.
//! Implement your logic in the `agent_main` function.
//!
//! # Canonical Entrypoint
//!
//! Every agent MUST expose exactly this function signature:
//!
//! ```ignore
//! #[no_mangle]
//! pub extern "Rust" fn agent_main(ctx: &AgentContext, opaque_inputs: &[u8]) -> AgentOutput
//! ```

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;

use alloc::vec;
use kernel_sdk::prelude::*;

// Include the generated agent hash constant.
include!(concat!(env!("OUT_DIR"), "/agent_hash.rs"));

/// Canonical agent entrypoint.
///
/// # Arguments
///
/// - `ctx`: Execution context (contains agent_id, kernel_version, etc.)
/// - `opaque_inputs`: Raw input bytes from the kernel
///
/// # Returns
///
/// AgentOutput containing the actions to execute.
#[no_mangle]
#[allow(unsafe_code)]
pub extern "Rust" fn agent_main(_ctx: &AgentContext, _opaque_inputs: &[u8]) -> AgentOutput {
    // TODO: Implement your agent logic here
    //
    // Example: Parse inputs
    // if opaque_inputs.len() < 4 {
    //     return AgentOutput { actions: vec![] };
    // }
    //
    // Example: Create actions
    // let action = call_action(target, value, &calldata);

    // Return a no-op action (placeholder)
    AgentOutput {
        actions: vec![no_op_action()],
    }
}

// ============================================================================
// Compile-time ABI Verification
// ============================================================================

/// Compile-time check that agent_main matches the canonical AgentEntrypoint type.
const _: AgentEntrypoint = agent_main;

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_context() -> AgentContext {
        AgentContext {
            protocol_version: 1,
            kernel_version: 1,
            agent_id: [0u8; 32],
            agent_code_hash: AGENT_CODE_HASH,
            constraint_set_hash: [0u8; 32],
            input_root: [0u8; 32],
            execution_nonce: 1,
        }
    }

    #[test]
    fn test_agent_produces_output() {
        let ctx = make_test_context();
        let input = [];

        let output = agent_main(&ctx, &input);

        // Agent should produce at least one action
        assert!(!output.actions.is_empty(), "agent should produce actions");
    }

    #[test]
    fn test_agent_is_deterministic() {
        let ctx = make_test_context();
        let input = [1, 2, 3, 4];

        let output1 = agent_main(&ctx, &input);
        let output2 = agent_main(&ctx, &input);

        assert_eq!(
            output1.actions.len(),
            output2.actions.len(),
            "agent should be deterministic"
        );
    }

    #[test]
    fn test_agent_code_hash_is_32_bytes() {
        assert_eq!(AGENT_CODE_HASH.len(), 32);
    }
}
"#
    .to_string()
}

fn generate_agent_lib_yield() -> String {
    r#"//! Yield Agent Implementation
//!
//! This agent demonstrates a yield farming pattern:
//! 1. Deposit ETH to a yield source
//! 2. Withdraw ETH + yield from the source
//!
//! # Input Format (48 bytes)
//!
//! ```text
//! [0:20]   vault_address (20 bytes)
//! [20:40]  yield_source_address (20 bytes)
//! [40:48]  transfer_amount (u64 LE)
//! ```
//!
//! # Output Actions
//!
//! Two CALL actions:
//! 1. Deposit: `call{value: amount}("")` - sends ETH
//! 2. Withdraw: `call{value: 0}(withdraw(vault))` - triggers withdrawal

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;

use alloc::{vec, vec::Vec};
use kernel_sdk::prelude::*;

// Include the generated agent hash constant.
include!(concat!(env!("OUT_DIR"), "/agent_hash.rs"));

// ============================================================================
// Constants
// ============================================================================

/// Expected input size: 20 (vault) + 20 (yield source) + 8 (amount) = 48 bytes
const INPUT_SIZE: usize = 48;

/// Withdraw function selector: keccak256("withdraw(address)")[:4]
const WITHDRAW_SELECTOR: [u8; 4] = [0x51, 0xcf, 0xf8, 0xd9];

// ============================================================================
// Agent Entry Point
// ============================================================================

/// Canonical agent entrypoint for the yield agent.
///
/// # Arguments
///
/// - `ctx`: Execution context (contains agent_id used for withdraw call)
/// - `opaque_inputs`: 48-byte input with addresses and amount
///
/// # Returns
///
/// AgentOutput with two CALL actions: deposit and withdraw.
#[no_mangle]
#[allow(unsafe_code)]
pub extern "Rust" fn agent_main(_ctx: &AgentContext, opaque_inputs: &[u8]) -> AgentOutput {
    // Validate input size
    if opaque_inputs.len() != INPUT_SIZE {
        // Invalid input - return empty output (will be handled by constraints)
        return AgentOutput {
            actions: Vec::new(),
        };
    }

    // Parse input
    let vault_address: [u8; 20] = opaque_inputs[0..20].try_into().unwrap();
    let yield_source_address: [u8; 20] = opaque_inputs[20..40].try_into().unwrap();
    let transfer_amount = u64::from_le_bytes(opaque_inputs[40..48].try_into().unwrap());

    // Build target (left-pad address to bytes32)
    let target = address_to_bytes32(&yield_source_address);

    // Build Action 1: Deposit ETH to yield source
    // call{value: amount}("") - sends ETH with empty calldata
    let deposit_action = call_action(target, transfer_amount as u128, &[]);

    // Build Action 2: Withdraw from yield source
    // call{value: 0}(withdraw(vault_address))
    let withdraw_calldata = encode_withdraw_call(&vault_address);
    let withdraw_action = call_action(target, 0, &withdraw_calldata);

    // Return both actions (deposit first, then withdraw)
    AgentOutput {
        actions: vec![deposit_action, withdraw_action],
    }
}

// ============================================================================
// ABI Encoding Helpers
// ============================================================================

/// Encode the withdraw(address) function call.
///
/// Format: selector (4 bytes) + address (32 bytes, left-padded)
fn encode_withdraw_call(depositor: &[u8; 20]) -> Vec<u8> {
    let mut calldata = Vec::with_capacity(36);
    calldata.extend_from_slice(&WITHDRAW_SELECTOR);
    calldata.extend_from_slice(&address_to_bytes32(depositor));
    calldata
}

// ============================================================================
// Compile-time ABI Verification
// ============================================================================

/// Compile-time check that agent_main matches the canonical AgentEntrypoint type.
const _: AgentEntrypoint = agent_main;

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_input(vault: [u8; 20], yield_source: [u8; 20], amount: u64) -> Vec<u8> {
        let mut input = Vec::with_capacity(INPUT_SIZE);
        input.extend_from_slice(&vault);
        input.extend_from_slice(&yield_source);
        input.extend_from_slice(&amount.to_le_bytes());
        input
    }

    fn make_test_context() -> AgentContext {
        AgentContext {
            protocol_version: 1,
            kernel_version: 1,
            agent_id: [0x42u8; 32],
            agent_code_hash: AGENT_CODE_HASH,
            constraint_set_hash: [0xbb; 32],
            input_root: [0xcc; 32],
            execution_nonce: 1,
        }
    }

    #[test]
    fn test_agent_produces_two_actions() {
        let ctx = make_test_context();

        let vault = [0x11u8; 20];
        let yield_source = [0x22u8; 20];
        let amount: u64 = 1_000_000_000_000_000_000; // 1 ETH

        let input = make_test_input(vault, yield_source, amount);
        let output = agent_main(&ctx, &input);

        assert_eq!(output.actions.len(), 2, "Expected 2 actions");

        // Both actions should target the yield source
        let expected_target = address_to_bytes32(&yield_source);
        assert_eq!(
            output.actions[0].target, expected_target,
            "Deposit target mismatch"
        );
        assert_eq!(
            output.actions[1].target, expected_target,
            "Withdraw target mismatch"
        );

        // Both actions should be CALL type
        assert_eq!(output.actions[0].action_type, ACTION_TYPE_CALL);
        assert_eq!(output.actions[1].action_type, ACTION_TYPE_CALL);
    }

    #[test]
    fn test_invalid_input_size_returns_empty() {
        let ctx = make_test_context();

        // Test too short
        let short_input = alloc::vec![0u8; 40];
        let output = agent_main(&ctx, &short_input);
        assert!(
            output.actions.is_empty(),
            "Short input should produce empty output"
        );

        // Test too long
        let long_input = alloc::vec![0u8; 50];
        let output = agent_main(&ctx, &long_input);
        assert!(
            output.actions.is_empty(),
            "Long input should produce empty output"
        );
    }

    #[test]
    fn test_agent_is_deterministic() {
        let ctx = make_test_context();
        let input = make_test_input([0x11u8; 20], [0x22u8; 20], 1000);

        let output1 = agent_main(&ctx, &input);
        let output2 = agent_main(&ctx, &input);

        assert_eq!(output1.actions.len(), output2.actions.len());
        for (a1, a2) in output1.actions.iter().zip(output2.actions.iter()) {
            assert_eq!(a1.action_type, a2.action_type);
            assert_eq!(a1.target, a2.target);
            assert_eq!(a1.payload, a2.payload);
        }
    }
}
"#
    .to_string()
}

fn generate_wrapper_cargo_toml(name: &str) -> String {
    format!(
        r#"[package]
name = "{name}-wrapper"
version = "0.1.0"
edition.workspace = true
license.workspace = true
description = "Wrapper crate binding {name} to kernel-guest"

[lib]
crate-type = ["rlib"]

[dependencies]
kernel-guest = {{ git = "https://github.com/Defiesta/execution-kernel", branch = "main" }}
kernel-sdk = {{ git = "https://github.com/Defiesta/execution-kernel", branch = "main" }}
kernel-core = {{ git = "https://github.com/Defiesta/execution-kernel", branch = "main", default-features = false }}
constraints = {{ git = "https://github.com/Defiesta/execution-kernel", branch = "main" }}
{name} = {{ path = "../agent" }}

[features]
default = []
risc0 = ["kernel-guest/risc0"]
"#,
        name = name
    )
}

fn generate_wrapper_lib(name_snake: &str, name_pascal: &str) -> String {
    format!(
        r#"//! Wrapper crate binding {name_snake} to kernel-guest.
//!
//! This crate implements [`kernel_guest::AgentEntrypoint`] for the {name_snake},
//! allowing it to be used with the agent-agnostic kernel execution functions.
//!
//! # Usage
//!
//! ```ignore
//! // In a zkVM guest main.rs or test:
//! let result = {name_snake}_wrapper::kernel_main(&input_bytes)?;
//! ```

use kernel_core::AgentOutput;
use kernel_guest::AgentEntrypoint;
use kernel_sdk::agent::AgentContext;

// Re-export the agent code hash for convenience.
pub use {name_snake}::AGENT_CODE_HASH;

/// Wrapper implementing [`AgentEntrypoint`] for the {name_snake}.
pub struct {name_pascal}Wrapper;

impl AgentEntrypoint for {name_pascal}Wrapper {{
    fn code_hash(&self) -> [u8; 32] {{
        {name_snake}::AGENT_CODE_HASH
    }}

    fn run(&self, ctx: &AgentContext, opaque_inputs: &[u8]) -> AgentOutput {{
        {name_snake}::agent_main(ctx, opaque_inputs)
    }}
}}

/// Convenience function for kernel execution with the {name_snake}.
///
/// This is equivalent to calling:
/// ```ignore
/// kernel_guest::kernel_main_with_agent(input_bytes, &{name_pascal}Wrapper)
/// ```
pub fn kernel_main(input_bytes: &[u8]) -> Result<Vec<u8>, kernel_guest::KernelError> {{
    kernel_guest::kernel_main_with_agent(input_bytes, &{name_pascal}Wrapper)
}}

/// Convenience function for kernel execution with the {name_snake} and custom constraints.
///
/// This is equivalent to calling:
/// ```ignore
/// kernel_guest::kernel_main_with_agent_and_constraints(input_bytes, &{name_pascal}Wrapper, constraint_set)
/// ```
pub fn kernel_main_with_constraints(
    input_bytes: &[u8],
    constraint_set: &constraints::ConstraintSetV1,
) -> Result<Vec<u8>, kernel_guest::KernelError> {{
    kernel_guest::kernel_main_with_agent_and_constraints(
        input_bytes,
        &{name_pascal}Wrapper,
        constraint_set,
    )
}}

// Re-export kernel_guest types for convenience.
pub use kernel_guest::KernelError;
"#,
        name_snake = name_snake,
        name_pascal = name_pascal
    )
}

fn generate_tests_cargo_toml(name: &str) -> String {
    format!(
        r#"[package]
name = "{name}-tests"
version = "0.1.0"
edition.workspace = true
license.workspace = true
description = "Test suite for {name}"

[lib]
crate-type = ["rlib"]

[dependencies]
kernel-sdk = {{ git = "https://github.com/Defiesta/execution-kernel", branch = "main" }}
{name} = {{ path = "../agent" }}

[dev-dependencies]
# Add test dependencies here
"#,
        name = name
    )
}

fn generate_tests_lib(name_snake: &str) -> String {
    format!(
        r#"//! Test suite for {name_snake}.

#![cfg(test)]

use kernel_sdk::prelude::*;
use {name_snake}::*;

fn make_test_context() -> AgentContext {{
    AgentContext {{
        protocol_version: 1,
        kernel_version: 1,
        agent_id: [0u8; 32],
        agent_code_hash: AGENT_CODE_HASH,
        constraint_set_hash: [0u8; 32],
        input_root: [0u8; 32],
        execution_nonce: 1,
    }}
}}

#[test]
fn test_agent_produces_output() {{
    let ctx = make_test_context();
    let input = [];

    let output = agent_main(&ctx, &input);

    // Agent should produce at least one action
    assert!(!output.actions.is_empty(), "agent should produce actions");
}}

#[test]
fn test_agent_is_deterministic() {{
    let ctx = make_test_context();
    let input = [1, 2, 3, 4];

    let output1 = agent_main(&ctx, &input);
    let output2 = agent_main(&ctx, &input);

    assert_eq!(
        output1.actions.len(),
        output2.actions.len(),
        "agent should be deterministic"
    );
}}

#[test]
fn test_agent_code_hash_exists() {{
    // Verify the hash is 32 bytes and not all zeros
    assert_eq!(AGENT_CODE_HASH.len(), 32);

    // Hash should not be all zeros (would indicate build.rs didn't run)
    let all_zeros = AGENT_CODE_HASH.iter().all(|&b| b == 0);
    assert!(!all_zeros, "AGENT_CODE_HASH should not be all zeros");
}}
"#,
        name_snake = name_snake
    )
}

fn generate_manifest(name: &str, agent_id_hex: &str) -> String {
    let placeholder = "0xTODO_COMPUTE_THIS_VALUE_________________________________________________";
    format!(
        r#"{{
  "format_version": "1",
  "agent_name": "{name}",
  "agent_version": "0.1.0",
  "agent_id": "{agent_id}",
  "protocol_version": 1,
  "kernel_version": 1,
  "risc0_version": "3.0.4",
  "rust_toolchain": "1.75.0",
  "agent_code_hash": "{placeholder}",
  "image_id": "{placeholder}",
  "artifacts": {{
    "elf_path": "artifacts/zkvm-guest.elf",
    "elf_sha256": "{placeholder}"
  }},
  "build": {{
    "cargo_lock_sha256": "{placeholder}",
    "build_command": "RISC0_USE_DOCKER=1 cargo build --release -p risc0-methods",
    "reproducible": true
  }},
  "inputs": "TODO: Describe your agent's input format",
  "actions_profile": "TODO: Describe the actions your agent produces"
}}
"#,
        name = name,
        agent_id = agent_id_hex,
        placeholder = placeholder
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_snake_case() {
        assert_eq!(to_snake_case("my-agent"), "my_agent");
        assert_eq!(to_snake_case("my_agent"), "my_agent");
        assert_eq!(to_snake_case("myagent"), "myagent");
    }

    #[test]
    fn test_to_pascal_case() {
        assert_eq!(to_pascal_case("my-agent"), "MyAgent");
        assert_eq!(to_pascal_case("my_agent"), "MyAgent");
        assert_eq!(to_pascal_case("myagent"), "Myagent");
        assert_eq!(to_pascal_case("my-yield-agent"), "MyYieldAgent");
    }

    #[test]
    fn test_validate_project_name() {
        assert!(validate_project_name("my-agent").is_ok());
        assert!(validate_project_name("my_agent").is_ok());
        assert!(validate_project_name("myagent123").is_ok());

        assert!(validate_project_name("").is_err());
        assert!(validate_project_name("123agent").is_err());
        assert!(validate_project_name("my agent").is_err());
        assert!(validate_project_name("my.agent").is_err());
    }

    #[test]
    fn test_format_agent_id() {
        let id = [0u8; 32];
        assert_eq!(
            format_agent_id(&id),
            "0x0000000000000000000000000000000000000000000000000000000000000000"
        );

        let id = [0x42u8; 32];
        assert_eq!(
            format_agent_id(&id),
            "0x4242424242424242424242424242424242424242424242424242424242424242"
        );
    }

    #[test]
    fn test_template_type_parse() {
        assert_eq!(TemplateType::parse("minimal"), Some(TemplateType::Minimal));
        assert_eq!(TemplateType::parse("MINIMAL"), Some(TemplateType::Minimal));
        assert_eq!(TemplateType::parse("yield"), Some(TemplateType::Yield));
        assert_eq!(TemplateType::parse("YIELD"), Some(TemplateType::Yield));
        assert_eq!(TemplateType::parse("unknown"), None);
    }
}
