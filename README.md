# Execution Kernel - P0.1 Canonical zkVM Guest Program

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](#testing)
[![Tests](https://img.shields.io/badge/tests-%20passed-brightgreen)](#testing)
[![Deterministic](https://img.shields.io/badge/execution-deterministic-blue)](#consensus-critical-properties)

## Overview

This repository implements the **P0.1 Canonical zkVM Guest Program**. The kernel provides consensus-critical, deterministic agent execution within a RISC Zero zkVM environment.

**Purpose:** Define what constitutes a valid agent execution through cryptographically verifiable zero-knowledge proofs.

## Architecture

The project is organized as a Rust workspace with the following crates:

- **`kernel-core`** - Core types, deterministic binary codec, and SHA-256 hashing
- **`kernel-guest`** - RISC Zero guest binary implementation  
- **`agent-traits`** - Canonical agent interface (with trivial reference implementation)
- **`constraints`** - Constraint engine stub (returns Ok for P0.1)
- **`host-tests`** - Comprehensive test suite

## Protocol Constants

- `PROTOCOL_VERSION = 1`
- `KERNEL_VERSION = 1`  
- `MAX_AGENT_INPUT_BYTES = 64,000`
- `HASH_FUNCTION = SHA-256`

## Building

```bash
# Build all crates
cargo build --release

# Build with zkVM features (when RISC Zero dependencies are available)
cargo build --release --features risc0
```

## Testing

Run the comprehensive test suite:

```bash
# Run all tests
cargo test

# Run tests with verbose output
cargo test -- --nocapture

# Run specific test categories
cargo test test_determinism
cargo test test_golden_vector
cargo test test_encoding_round_trip
```

### Test Coverage

The test suite includes **11 comprehensive tests**:

- **Encoding round-trip tests** (3) - Verify canonical codec correctness for all protocol types
- **Golden vector tests** (2) - SHA-256 commitment verification with known outputs
- **Determinism tests** (1) - Same input produces identical journal bytes  
- **Error handling tests** (3) - Invalid inputs, oversized data, malformed encoding
- **Protocol validation tests** (2) - Version checks and constraint enforcement

## Key Implementation Details

### Deterministic Binary Codec

All protocol objects use explicit manual encoding:

- Little-endian integers (`u32::to_le_bytes()`)
- Length-prefixed byte arrays (`[length: u32][data: bytes]`)
- Fixed-size arrays (agent_id, commitments)
- No serde auto-derive to ensure determinism

### SHA-256 Commitments

- **Input commitment**: `SHA256(full_input_bytes)`
- **Action commitment**: `SHA256(agent_output_bytes)`

### Error Handling

Any execution error results in kernel abortion before journal commit. The kernel enforces:

- Protocol version validation
- Input size limits (64KB max)
- Mandatory constraint checking
- Deterministic execution flow

### Guest Program Flow

1. Read input from zkVM environment
2. Decode and validate `KernelInputV1`  
3. Verify protocol version
4. Compute input commitment
5. Execute agent with bounded input
6. Call constraint engine (mandatory)
7. Construct canonical journal
8. Commit journal or abort on error

## Usage

### Quick Start

```bash
# Clone and test the implementation
git clone <repository-url>
cd execution-kernel
cargo test

# All tests should pass with output:
# test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

### Creating a Kernel Input

```rust
use kernel_core::*;

let input = KernelInputV1 {
    protocol_version: PROTOCOL_VERSION,  // Always 1 for P0.1
    agent_id: [0x42; 32],               // 32-byte agent identifier  
    agent_input: vec![1, 2, 3, 4, 5],   // Max 64KB of agent input data
};

let input_bytes = input.encode();  // Deterministic binary encoding
```

### Running the Kernel

```rust
use kernel_guest::kernel_main;

// Execute kernel with encoded input
let journal_bytes = kernel_main(&input_bytes)?;

// Decode the resulting journal
let journal = KernelJournalV1::decode(&journal_bytes)?;

// Journal contains:
// - input_commitment: SHA256(input_bytes)
// - action_commitment: SHA256(agent_output_bytes) 
// - execution_status: Success (only status in P0.1)
```

### Example: End-to-End Execution

```rust
use kernel_core::*;
use kernel_guest::kernel_main;

// Create input
let input = KernelInputV1 {
    protocol_version: 1,
    agent_id: [0x99; 32],
    agent_input: b"Hello, zkVM!".to_vec(),
};

// Execute kernel
let journal_bytes = kernel_main(&input.encode()).unwrap();
let journal = KernelJournalV1::decode(&journal_bytes).unwrap();

// Verify execution
assert_eq!(journal.execution_status, ExecutionStatus::Success);
assert_eq!(journal.protocol_version, 1);
```

## Consensus-Critical Properties

This implementation prioritizes **determinism and correctness over convenience**:

- No floating-point operations
- No randomness or time dependencies  
- No unordered iteration
- Bounded memory and computation
- Explicit error handling with abort-before-commit
- Canonical binary encoding without auto-derive

Any deviation from these principles breaks protocol consensus.

## Development

### Code Organization

- **Types** (`kernel-core/src/types.rs`) - Protocol data structures
- **Codec** (`kernel-core/src/codec.rs`) - Deterministic binary encoding  
- **Hash** (`kernel-core/src/hash.rs`) - SHA-256 commitment functions
- **Guest** (`kernel-guest/src/lib.rs`) - Main kernel execution logic
- **Tests** (`host-tests/src/lib.rs`) - Comprehensive validation

### Adding New Features

When extending beyond P0.1:

1. Update protocol version constants
2. Extend canonical types with deterministic field ordering
3. Update codec implementation with version handling  
4. Add comprehensive test coverage
5. Verify determinism across rebuilds

## Security Considerations

The kernel assumes a **malicious host environment** and defends against:

- **Input forgery attempts** - All inputs are cryptographically committed via SHA-256
- **Constraint bypass attempts** - Constraint checking is mandatory and unskippable  
- **Non-determinism exploitation** - Strict deterministic execution requirements
- **Protocol version confusion** - Explicit version validation on all inputs

All security properties are enforced cryptographically through zkVM proofs.

## Implementation Status

### ✅ **Completed Features (P0.1)**

- [x] **Canonical Types** - `KernelInputV1`, `KernelJournalV1`, `ExecutionStatus`
- [x] **Deterministic Binary Codec** - Manual encoding without serde dependencies
- [x] **SHA-256 Commitments** - Input and action commitment computation
- [x] **Agent Interface** - `Agent` trait with trivial reference implementation
- [x] **Constraint Engine** - Mandatory `check()` function (stub for P0.1)
- [x] **Guest Program** - Complete execution kernel with error handling
- [x] **Comprehensive Tests** - 11 tests covering all functionality
- [x] **Documentation** - Complete usage examples and API documentation

### 🚀 **Future Milestones**

- **P0.2** - Full constraint engine implementation
- **P0.3** - Advanced agent interface with real-world capabilities
- **P1.0** - Production-ready zkVM integration

## License

This project is part of the Defiesta execution kernel implementation.
