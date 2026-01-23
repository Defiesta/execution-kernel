# Execution Kernel - Canonical zkVM Guest Program

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](#testing)
[![Tests](https://img.shields.io/badge/tests-82%20passed-brightgreen)](#testing)
[![Deterministic](https://img.shields.io/badge/execution-deterministic-blue)](#consensus-critical-properties)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

## Overview

This repository implements the **Canonical zkVM Guest Program**. The kernel provides consensus-critical, deterministic agent execution within a RISC Zero zkVM environment.

**Purpose:** Define what constitutes a valid agent execution through cryptographically verifiable zero-knowledge proofs.

## Architecture

The project is organized as a Rust workspace with the following crates:

- **`kernel-core`** - Core types, deterministic binary codec, and SHA-256 hashing
- **`kernel-guest`** - RISC Zero guest binary implementation
- **`agent-traits`** - Canonical agent interface (with trivial reference implementation)
- **`constraints`** - Constraint engine with action validation, asset whitelists, position limits, and global invariants
- **`host-tests`** - Test suite (82 tests)

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

Run the test suite:

```bash
# Run all tests
cargo test

# Run tests with verbose output
cargo test -- --nocapture

# Run specific test categories
cargo test test_determinism
cargo test test_golden_vector
cargo test test_constraint
```

### Test Coverage

The test suite includes **82 comprehensive tests**:

- **Encoding round-trip tests** - Verify canonical codec correctness for all protocol types
- **Golden vector tests** - SHA-256 commitment verification with known outputs
- **Determinism tests** - Same input produces identical journal bytes
- **Trailing bytes rejection tests** - Strict decoding for all types
- **Constraint validation tests** - All violation codes, payload schemas, whitelist checks
- **Overflow protection tests** - Cooldown timestamp arithmetic safety
- **Protocol validation tests** - Version checks and identity field propagation

### Deterministic Binary Codec

All protocol objects use explicit manual encoding:

- Little-endian integers (`u32::to_le_bytes()`)
- Length-prefixed byte arrays (`[length: u32][data: bytes]`)
- Fixed-size arrays (agent_id, commitments)
- No serde auto-derive to ensure determinism
- Strict trailing bytes rejection


### Failure Semantics

- **Hard failures** (decoding, version mismatch): Kernel aborts, no journal produced
- **Constraint violations**: Failure journal produced with `execution_status = 0x02` and empty action commitment

### Guest Program Flow

1. Read input from zkVM environment
2. Decode and validate `KernelInputV1`
3. Verify protocol version
4. Compute input commitment
5. Execute agent with bounded input
6. Enforce constraints (mandatory, unskippable)
7. Construct canonical journal (Success or Failure)
8. Commit journal or abort on hard error

## Usage

### Quick Start

```bash
# Clone and test the implementation
git clone <repository-url>
cd execution-kernel
cargo test

# All tests should pass with output:
# test result: ok. 82 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

### Creating a Kernel Input

```rust
use kernel_core::*;

let input = KernelInputV1 {
    protocol_version: PROTOCOL_VERSION,
    kernel_version: KERNEL_VERSION,
    agent_id: [0x42; 32],
    agent_code_hash: [0xaa; 32],
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
- `spec/constraints.md` - Constraint system specification (locked)

## Security Considerations

The kernel assumes a **malicious host environment** and defends against:

- **Input forgery attempts** - All inputs are cryptographically committed via SHA-256
- **Constraint bypass attempts** - Constraint checking is mandatory and unskippable
- **Non-determinism exploitation** - Strict deterministic execution requirements
- **Protocol version confusion** - Explicit version validation on all inputs
- **Encoding malleability** - Exact payload lengths, trailing bytes rejected
- **Timestamp overflow attacks** - Checked arithmetic for cooldown calculations

All security properties are enforced cryptographically through zkVM proofs.

**Note:** The `action.target` field is not validated by the constraint engine in P0.3. Executor contracts are responsible for target validation.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
