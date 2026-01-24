# Execution Kernel - Canonical zkVM Guest Program

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](#testing)
[![Deterministic](https://img.shields.io/badge/execution-deterministic-blue)](#consensus-critical-properties)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

## Overview

This repository implements the **Canonical zkVM Guest Program**. The kernel provides consensus-critical, deterministic agent execution within a RISC Zero zkVM environment.

**Purpose:** Define what constitutes a valid agent execution through cryptographically verifiable zero-knowledge proofs.

## Architecture

The project is organized as a Rust workspace with the following crates:

| Crate | Description |
|-------|-------------|
| `kernel-core` | Core types, deterministic binary codec, and SHA-256 hashing |
| `kernel-guest` | RISC Zero guest binary implementation |
| `kernel-sdk` | Canonical agent interface and SDK |
| `constraints` | Constraint engine with action validation, asset whitelists, position limits |
| `example-agent` | Reference agent implementation with `agent_main` entrypoint |
| `methods` | RISC Zero build crate - exports `ZKVM_GUEST_ELF` and `ZKVM_GUEST_ID` |
| `e2e-tests` | End-to-end zkVM proof tests |
| `host-tests` | Unit test suite (92 tests) |

## Protocol Constants

- `PROTOCOL_VERSION = 1`
- `KERNEL_VERSION = 1`
- `MAX_AGENT_INPUT_BYTES = 64,000`
- `MAX_ACTIONS_PER_OUTPUT = 64`
- `HASH_FUNCTION = SHA-256`

## Building

```bash
# Build all crates
cargo build --release

# Build with zkVM features (when RISC Zero dependencies are available)
cargo build --release --features risc0
```

## Testing

### Unit Tests

```bash
# Run all unit tests
cargo test

# Run tests with verbose output
cargo test -- --nocapture

# Run specific test categories
cargo test test_determinism
cargo test test_golden_vector
cargo test test_constraint
```

### E2E zkVM Proof Tests

End-to-end tests that generate actual RISC Zero proofs:

```bash
# Install RISC Zero toolchain first
cargo install cargo-risczero
cargo risczero install

# Run E2E proof tests (requires RISC Zero)
cargo test -p e2e-tests --features risc0-e2e -- --test-threads=1 --nocapture
```

**Note:** Use `--test-threads=1` to avoid parallel proof generation exhausting memory.

### Guest Program Flow

1. Read input from zkVM environment
2. Decode and validate `KernelInputV1`
3. Verify protocol version and agent code hash
4. Compute input commitment
5. Execute agent via `agent_main()` entrypoint
6. Enforce constraints (mandatory, unskippable)
7. Construct canonical journal (Success or Failure)
8. Commit journal or abort on hard error

## On-Chain Verification

The E2E tests extract data needed for Solidity verifier integration:

```rust
// From receipt after proof generation
seal: bytes      // 256-byte Groth16 proof
journal: bytes   // KernelJournalV1 (variable length)
imageId: bytes32 // ZKVM_GUEST_ID (guest identity)
```

## Usage

### Quick Start

```bash
# Clone and test the implementation
git clone https://github.com/Defiesta/execution-kernel.git
cd execution-kernel
cargo test
```

### Creating a Kernel Input

```rust
use kernel_core::*;

let input = KernelInputV1 {
    protocol_version: PROTOCOL_VERSION,
    kernel_version: KERNEL_VERSION,
    agent_id: [0x42; 32],
    agent_code_hash: example_agent::AGENT_CODE_HASH,  // Must match linked agent
    constraint_set_hash: [0xbb; 32],
    input_root: [0xcc; 32],
    execution_nonce: 1,
    opaque_agent_inputs: vec![1, 2, 3, 4, 5],  // Max 64KB
};

let input_bytes = input.encode()?;  // Deterministic binary encoding
```

### Running the Kernel

```rust
use kernel_guest::kernel_main;
use kernel_core::*;

// Execute kernel with encoded input
let journal_bytes = kernel_main(&input_bytes)?;

// Decode the resulting journal
let journal = KernelJournalV1::decode(&journal_bytes)?;

// Journal contains:
// - input_commitment: SHA256(input_bytes)
// - action_commitment: SHA256(agent_output_bytes) or empty commitment on failure
// - execution_status: Success (0x01) or Failure (0x02)
```

## Consensus-Critical Properties

This implementation prioritizes **determinism and correctness over convenience**:

- No floating-point operations
- No randomness or time dependencies
- No unordered iteration
- Bounded memory and computation
- Explicit error handling with abort-before-commit
- Canonical binary encoding without auto-derive
- Strict trailing bytes rejection

Any deviation from these principles breaks protocol consensus.

## Development

### Documentation

- `docs/P0.1_DOCUMENTATION.md` - Foundational concepts and design rationale
- `docs/P0.2_DOCUMENTATION.md` - Canonical codec specification
- `docs/P0.3_DOCUMENTATION.md` - Constraint system documentation
- `spec/codec.md` - Wire format specification
- `spec/constraints.md` - Constraint system specification
- `spec/sdk.md` - Kernel SDK specification
- `spec/e2e-tests.md` - E2E testing specification

## Security Considerations

The kernel assumes a **malicious host environment** and defends against:

- **Input forgery attempts** - All inputs are cryptographically committed via SHA-256
- **Agent substitution attacks** - `agent_code_hash` binding prevents unauthorized agents
- **Constraint bypass attempts** - Constraint checking is mandatory and unskippable
- **Non-determinism exploitation** - Strict deterministic execution requirements
- **Protocol version confusion** - Explicit version validation on all inputs
- **Encoding malleability** - Exact payload lengths, trailing bytes rejected
- **Timestamp overflow attacks** - Checked arithmetic for cooldown calculations

All security properties are enforced cryptographically through zkVM proofs.

**Note:** The `action.target` field is not validated by the constraint engine. Executor contracts are responsible for target validation.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
