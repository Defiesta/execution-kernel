# Execution Kernel - Canonical zkVM Guest Program

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](#testing)
[![Deterministic](https://img.shields.io/badge/execution-deterministic-blue)](#consensus-critical-properties)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

## Overview

This repository implements the **Canonical zkVM Guest Program**. The kernel provides consensus-critical, deterministic agent execution within a RISC Zero zkVM environment.

**Purpose:** Define what constitutes a valid agent execution through cryptographically verifiable zero-knowledge proofs.

## Architecture

The project is organized as a Rust workspace:

```
crates/
├── protocol/                    # Core protocol types
│   ├── kernel-core/             # Types, deterministic codec, SHA-256 hashing
│   └── constraints/             # Constraint engine with action validation
├── sdk/
│   └── kernel-sdk/              # Agent development SDK
├── runtime/                     # zkVM execution
│   ├── kernel-guest/            # Agent-agnostic kernel execution logic
│   └── risc0-methods/           # RISC Zero build - exports ELF and IMAGE_ID
├── agents/
│   ├── examples/
│   │   └── example-yield-agent/ # Yield farming agent implementation
│   └── wrappers/
│       └── kernel-guest-binding-yield/  # Binds yield agent to kernel
└── testing/
    ├── kernel-host-tests/       # Unit test suite
    └── e2e-tests/               # End-to-end zkVM proof tests
```

### Agent-Agnostic Design

The kernel uses trait-based dependency injection, allowing new agents without modifying kernel code:

```rust
pub trait AgentEntrypoint {
    fn code_hash(&self) -> [u8; 32];
    fn run(&self, ctx: &AgentContext, opaque_inputs: &[u8]) -> AgentOutput;
}

// Execute kernel with any agent
let journal = kernel_main_with_agent(&input_bytes, &MyAgent)?;
```

Wrapper crates (e.g., `kernel-guest-binding-yield`) bind specific agents to the kernel.

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

# Build with zkVM features
cargo build --release --features risc0
```

## Testing

### Unit Tests

```bash
# Run all unit tests
cargo test

# Run tests with verbose output
cargo test -- --nocapture
```

### E2E zkVM Proof Tests

End-to-end tests that generate actual RISC Zero proofs:

```bash
# Install RISC Zero toolchain first
cargo install cargo-risczero
cargo risczero install

# Run E2E proof tests
cargo test -p e2e-tests --features risc0-e2e -- --nocapture
```

### On-Chain E2E Test

Full end-to-end test with on-chain verification on Sepolia testnet.

See [e2e-tests/README.md](crates/testing/e2e-tests/README.md) for detailed instructions.

## On-Chain Deployment (Sepolia)

| Contract | Address |
|----------|---------|
| KernelExecutionVerifier | `0x9Ef5bAB590AFdE8036D57b89ccD2947D4E3b1EFA` |
| KernelVault | `0xAdeDA97D2D07C7f2e332fD58F40Eb4f7F0192be7` |
| MockYieldSource | `0x7B35E3F2e810170f146d31b00262b9D7138F9b39` |
| RISC Zero Verifier Router | `0x925d8331ddc0a1F0d96E68CF073DFE1d92b69187` |

### Yield Agent Registration

| Field | Value |
|-------|-------|
| IMAGE_ID | `0x5f42241afd61bf9e341442c8baffa9c544cf20253720f2540cf6705f27bae2c4` |
| AGENT_CODE_HASH | `0x5aac6b1fedf1b0c0ccc037c3223b7b5c8b679f48b9c599336c0dc777be88924b` |
| AGENT_ID | `0x0000000000000000000000000000000000000000000000000000000000000001` |

## Usage

### Quick Start

```bash
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
    agent_code_hash: example_yield_agent::AGENT_CODE_HASH,
    constraint_set_hash: [0xbb; 32],
    input_root: [0xcc; 32],
    execution_nonce: 1,
    opaque_agent_inputs: vec![/* 48 bytes for yield agent */],
};

let input_bytes = input.encode()?;
```

### Running the Kernel

```rust
use kernel_guest::kernel_main_with_agent;
use kernel_guest_binding_yield::YieldAgentWrapper;
use kernel_core::*;

// Execute kernel with yield agent
let journal_bytes = kernel_main_with_agent(&input_bytes, &YieldAgentWrapper)?;

// Decode the resulting journal
let journal = KernelJournalV1::decode(&journal_bytes)?;

// Journal contains:
// - input_commitment: SHA256(input_bytes)
// - action_commitment: SHA256(agent_output_bytes)
// - execution_status: Success (0x01) or Failure (0x02)
```

### Guest Program Flow

1. Read input from zkVM environment
2. Decode and validate `KernelInputV1`
3. Verify protocol version and agent code hash
4. Compute input commitment
5. Execute agent via `AgentEntrypoint::run()`
6. Enforce constraints (mandatory, unskippable)
7. Construct canonical journal (Success or Failure)
8. Commit journal or abort on hard error

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

## Security Considerations

The kernel assumes a **malicious host environment** and defends against:

- **Input forgery attempts** - All inputs are cryptographically committed via SHA-256
- **Agent substitution attacks** - `agent_code_hash` binding prevents unauthorized agents
- **Constraint bypass attempts** - Constraint checking is mandatory and unskippable
- **Non-determinism exploitation** - Strict deterministic execution requirements
- **Protocol version confusion** - Explicit version validation on all inputs
- **Encoding malleability** - Exact payload lengths, trailing bytes rejected

All security properties are enforced cryptographically through zkVM proofs.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
