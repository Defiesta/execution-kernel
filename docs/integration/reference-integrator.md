# Reference Integrator

The `reference-integrator` crate provides a complete reference implementation for integrating with Agent Pack bundles. It demonstrates how external marketplaces, backends, and applications can:

1. **Ingest** Agent Pack bundles
2. **Verify** them offline and on-chain
3. **Build** kernel inputs for execution
4. **Prove** execution using RISC Zero zkVM
5. **Execute** proofs on-chain via the KernelVault

## Installation

Add the crate to your `Cargo.toml`:

```toml
[dependencies]
reference-integrator = { path = "../execution-kernel/crates/reference-integrator" }
```

### Feature Flags

| Feature   | Description                                    | Dependencies              |
|-----------|------------------------------------------------|---------------------------|
| `cli`     | CLI binary (`refint`) (default)                | `clap`                    |
| `onchain` | On-chain verification and execution            | `alloy`, `tokio`          |
| `prove`   | Proof generation with RISC Zero zkVM           | `risc0-zkvm`              |
| `full`    | All features enabled                           | All of the above          |

Example with all features:

```toml
[dependencies]
reference-integrator = { path = "...", features = ["full"] }
```

## Library API

### Loading Bundles

```rust
use reference_integrator::LoadedBundle;

// Load a bundle from a directory
let bundle = LoadedBundle::load("./my-agent-bundle")?;

// Access manifest data
println!("Agent: {} v{}", bundle.manifest.agent_name, bundle.manifest.agent_version);
println!("Agent ID: {}", bundle.manifest.agent_id);

// Read the ELF binary
let elf_bytes = bundle.read_elf()?;

// Parse hex values to bytes
let agent_id_bytes: [u8; 32] = bundle.agent_id_bytes()?;
let image_id_bytes: [u8; 32] = bundle.image_id_bytes()?;
```

### Offline Verification

```rust
use reference_integrator::{verify_offline, verify_structure};

// Full verification (structure + file hashes)
let result = verify_offline(&bundle);
if result.passed {
    println!("Bundle verified successfully");
} else {
    for error in &result.report.errors {
        eprintln!("Error: {}", error);
    }
}

// Quick structure-only verification
let result = verify_structure(&bundle);
```

### On-Chain Verification

Requires the `onchain` feature.

```rust
use reference_integrator::verify_onchain;

let result = verify_onchain(
    &bundle,
    "https://sepolia.infura.io/v3/YOUR_KEY",
    "0x9Ef5bAB590AFdE8036D57b89ccD2947D4E3b1EFA",
).await?;

match result {
    OnchainVerificationResult::Match => println!("Image ID matches on-chain registry"),
    OnchainVerificationResult::Mismatch { onchain, manifest } => {
        eprintln!("Mismatch: on-chain={}, manifest={}", onchain, manifest);
    }
    OnchainVerificationResult::NotRegistered => {
        eprintln!("Agent not registered on-chain");
    }
}
```

### Building Kernel Inputs

```rust
use reference_integrator::{build_kernel_input, build_and_encode_input, InputParams};

// Define execution parameters
let params = InputParams {
    constraint_set_hash: [0u8; 32],
    input_root: [0u8; 32],
    execution_nonce: 1,
    opaque_agent_inputs: b"your agent input data".to_vec(),
};

// Build a KernelInputV1 struct
let input = build_kernel_input(&bundle, &params)?;

// Or build and encode to bytes in one step
let input_bytes = build_and_encode_input(&bundle, &params)?;
```

### Proof Generation

Requires the `prove` feature.

```rust
use reference_integrator::{prove, ProvingMode};

let elf_bytes = bundle.read_elf()?;
let input_bytes = build_and_encode_input(&bundle, &params)?;

// Generate a Groth16 proof (suitable for on-chain verification)
let result = prove(&elf_bytes, &input_bytes, ProvingMode::Groth16)?;

println!("Journal: {} bytes", result.journal_bytes.len());
println!("Seal: {} bytes", result.seal_bytes.len());

// For development/testing, use Dev mode (faster but not on-chain verifiable)
let result = prove(&elf_bytes, &input_bytes, ProvingMode::Dev)?;
```

### On-Chain Execution

Requires the `onchain` feature.

```rust
use reference_integrator::execute_onchain;

let tx_hash = execute_onchain(
    "https://sepolia.infura.io/v3/YOUR_KEY",
    "0xAdeDA97D2D07C7f2e332fD58F40Eb4f7F0192be7",  // KernelVault
    "YOUR_PRIVATE_KEY",
    &journal_bytes,
    &seal_bytes,
    &agent_output_bytes,
).await?;

println!("Transaction: {}", tx_hash);
```

## CLI Usage

The `refint` CLI provides command-line access to all functionality.

### Build the CLI

```bash
# Default (CLI only)
cargo build -p reference-integrator --release

# With on-chain features
cargo build -p reference-integrator --release --features onchain

# With proving
cargo build -p reference-integrator --release --features prove

# Full features
cargo build -p reference-integrator --release --features full
```

### Commands

#### verify

Verify a bundle offline (structure and file hashes).

```bash
refint verify ./my-agent-bundle

# Structure-only (skip file hash verification)
refint verify ./my-agent-bundle --structure-only

# On-chain verification (requires --features onchain)
refint verify ./my-agent-bundle --onchain \
  --rpc https://sepolia.infura.io/v3/YOUR_KEY \
  --verifier 0x9Ef5bAB590AFdE8036D57b89ccD2947D4E3b1EFA
```

#### prove

Generate a proof of kernel execution (requires `--features prove`).

```bash
refint prove ./my-agent-bundle \
  --agent-input "$(cat input.bin | xxd -p)" \
  --out-dir ./output

# Development mode (faster, not on-chain verifiable)
refint prove ./my-agent-bundle \
  --agent-input "0x1234..." \
  --out-dir ./output \
  --dev

# With all input parameters
refint prove ./my-agent-bundle \
  --constraint-set-hash 0x... \
  --input-root 0x... \
  --out-dir ./output
```

Output files:
- `journal.bin` - The execution journal (209 bytes)
- `seal.bin` - The proof seal
- `agent_output.bin` - The agent's output

#### execute

Execute a proof on-chain via the KernelVault (requires `--features onchain`).

```bash
refint execute ./my-agent-bundle \
  --rpc https://sepolia.infura.io/v3/YOUR_KEY \
  --vault 0xAdeDA97D2D07C7f2e332fD58F40Eb4f7F0192be7 \
  --private-key env:PRIVATE_KEY \
  --journal ./output/journal.bin \
  --seal ./output/seal.bin \
  --agent-output ./output/agent_output.bin
```

Private key formats:
- `env:VAR_NAME` - Read from environment variable
- Raw hex string (not recommended for production)

#### status

Show feature availability status.

```bash
refint status
```

Output:
```
reference-integrator v0.1.0

Feature Status:
  CLI:           enabled
  On-chain:      enabled (compile with --features onchain)
  Proving:       disabled (compile with --features prove)
```

### Exit Codes

| Code | Meaning                                      |
|------|----------------------------------------------|
| 0    | Success                                      |
| 1    | Error (invalid input, file not found, etc.)  |
| 2    | Verification failed (hash mismatch, etc.)    |
| 3    | On-chain: agent not registered               |

## Complete Workflow Example

Here's a complete example of ingesting, verifying, proving, and executing an agent:

```rust
use reference_integrator::*;

async fn process_agent_bundle(bundle_path: &str) -> Result<String, Box<dyn std::error::Error>> {
    // 1. Load the bundle
    let bundle = LoadedBundle::load(bundle_path)?;
    println!("Loaded: {} v{}", bundle.manifest.agent_name, bundle.manifest.agent_version);

    // 2. Verify offline
    let offline_result = verify_offline(&bundle);
    if !offline_result.passed {
        return Err("Offline verification failed".into());
    }

    // 3. Verify on-chain registration
    let onchain_result = verify_onchain(
        &bundle,
        "https://sepolia.infura.io/v3/YOUR_KEY",
        "0x9Ef5bAB590AFdE8036D57b89ccD2947D4E3b1EFA",
    ).await?;

    match onchain_result {
        OnchainVerificationResult::Match => {},
        _ => return Err("On-chain verification failed".into()),
    }

    // 4. Build kernel input
    let params = InputParams {
        opaque_agent_inputs: b"market data here".to_vec(),
        ..Default::default()
    };
    let input_bytes = build_and_encode_input(&bundle, &params)?;

    // 5. Generate proof
    let elf_bytes = bundle.read_elf()?;
    let prove_result = prove(&elf_bytes, &input_bytes, ProvingMode::Groth16)?;

    // 6. Execute on-chain
    let tx_hash = execute_onchain(
        "https://sepolia.infura.io/v3/YOUR_KEY",
        "0xAdeDA97D2D07C7f2e332fD58F40Eb4f7F0192be7",
        std::env::var("PRIVATE_KEY")?.as_str(),
        &prove_result.journal_bytes,
        &prove_result.seal_bytes,
        &prove_result.journal.agent_output.actions_bytes,
    ).await?;

    Ok(tx_hash)
}
```

## Marketplace Integration

For marketplaces accepting agent submissions:

1. **Receive** the Agent Pack bundle (directory with `agent-pack.json` + ELF)
2. **Verify structure** - Quick check that manifest is well-formed
3. **Verify offline** - Full verification including file hashes
4. **Verify on-chain** - Confirm the agent is registered in KernelExecutionVerifier
5. **Store** the bundle for later execution requests

```bash
# CI/CD verification pipeline
refint verify ./submission --onchain \
  --rpc $RPC_URL \
  --verifier $VERIFIER_ADDRESS

# Exit code 0 = accept, non-zero = reject
```

## Contract Addresses (Sepolia)

| Contract                  | Address                                      |
|---------------------------|----------------------------------------------|
| KernelExecutionVerifier   | `0x9Ef5bAB590AFdE8036D57b89ccD2947D4E3b1EFA` |
| KernelVault               | `0xAdeDA97D2D07C7f2e332fD58F40Eb4f7F0192be7` |
| RISC Zero Verifier Router | `0x925d8331ddc0a1F0d96E68CF073DFE1d92b69187` |

## Error Handling

All public functions return `Result` types with descriptive errors:

```rust
use reference_integrator::{BundleError, VerifyError, InputError, ProveError};

match LoadedBundle::load("./bundle") {
    Ok(bundle) => { /* ... */ }
    Err(BundleError::DirectoryNotFound(path)) => {
        eprintln!("Bundle directory not found: {}", path.display());
    }
    Err(BundleError::ManifestNotFound(path)) => {
        eprintln!("Missing agent-pack.json at: {}", path.display());
    }
    Err(BundleError::ElfNotFound(path)) => {
        eprintln!("ELF file not found: {}", path.display());
    }
    Err(e) => eprintln!("Error: {}", e),
}
```

## Testing

Run the test suite:

```bash
# Unit tests
cargo test -p reference-integrator

# With all features
cargo test -p reference-integrator --features full
```
