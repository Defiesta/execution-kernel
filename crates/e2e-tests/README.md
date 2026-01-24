# E2E zkVM Proof Tests

End-to-end integration tests that verify the complete execution kernel flow using RISC Zero zkVM proofs.

## Overview

These tests verify:

1. **Agent → Guest → Proof → Verification** pipeline works correctly
2. **Agent code hash binding** prevents unauthorized agent substitution
3. **Determinism** - same input always produces same output
4. **Commitment integrity** - input and action commitments are correctly computed

## Prerequisites

### Install RISC Zero Toolchain

```bash
# Install cargo-risczero
cargo install cargo-risczero

# Install the RISC Zero toolchain (includes riscv32im target)
cargo risczero install
```

### Verify Installation

```bash
cargo risczero --version
```

## Running Tests

### Unit Tests (no zkVM required)

```bash
# Run unit tests without proof generation
cargo test -p e2e-tests
```

### Full E2E Proof Tests

```bash
# Run with zkVM proof generation (requires RISC Zero toolchain)
cargo test -p e2e-tests --features risc0-e2e -- --nocapture
```

### Individual Test

```bash
# Run specific test
cargo test -p e2e-tests --features risc0-e2e test_e2e_success_with_echo -- --nocapture
```

## Test Cases

### 1. `test_e2e_success_with_echo`

Verifies the happy path:
- Valid input with `opaque_inputs[0] == 1` (echo trigger)
- Proof generation succeeds
- Receipt verifies against IMAGE_ID
- Journal contains correct:
  - `execution_status == Success`
  - `input_commitment == SHA256(input_bytes)`
  - `action_commitment == SHA256(encoded_echo_output)`

### 2. `test_e2e_agent_code_hash_mismatch`

Verifies security:
- Input with wrong `agent_code_hash` (all zeros)
- Guest execution fails with `AgentCodeHashMismatch`
- No valid proof/receipt is produced

### 3. `test_e2e_empty_output`

Verifies empty output handling:
- Input with `opaque_inputs[0] != 1` (no echo)
- Proof generation succeeds (empty output is valid)
- `action_commitment == EMPTY_OUTPUT_COMMITMENT`

### 4. `test_e2e_determinism`

Verifies deterministic execution:
- Same input run twice
- Both runs produce identical journal bytes

## CI Integration

These tests are **feature-gated** to avoid requiring RISC Zero in all CI environments:

```yaml
# In CI, only run E2E tests in environments with RISC Zero installed
- name: Run E2E proof tests
  if: ${{ matrix.risc0-enabled }}
  run: cargo test -p e2e-tests --features risc0-e2e
```

For CI without RISC Zero:

```yaml
# Unit tests always work
- name: Run unit tests
  run: cargo test -p e2e-tests
```

## Reproducible Builds

For deterministic guest ELF builds (useful for IMAGE_ID reproducibility):

```bash
RISC0_USE_DOCKER=1 cargo test -p e2e-tests --features risc0-e2e
```

This requires Docker and uses the official RISC Zero Docker image.

## Troubleshooting

### "risc0-zkvm not found"

Install the RISC Zero toolchain:

```bash
cargo risczero install
```

### "failed to find riscv32im-risc0-zkvm-elf target"

The RISC Zero toolchain may not be installed correctly. Reinstall:

```bash
cargo risczero install --force
```

### Slow proof generation

Proof generation can take several minutes. For faster iteration during development, you can use the `dev` prover mode (add `--features dev-mode` if available in your risc0-zkvm version).

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        e2e-tests                                │
│  ┌────────────────┐   ┌────────────────┐   ┌────────────────┐  │
│  │ Test Input     │──▶│ methods crate  │──▶│ Prover         │  │
│  │ (KernelInputV1)│   │ (ELF+IMAGE_ID) │   │ (risc0-zkvm)   │  │
│  └────────────────┘   └────────────────┘   └───────┬────────┘  │
│                                                     │          │
│                                            ┌────────▼────────┐ │
│                                            │ Receipt         │ │
│                                            │ (Proof+Journal) │ │
│                                            └────────┬────────┘ │
│                                                     │          │
│  ┌────────────────┐                        ┌────────▼────────┐ │
│  │ Decode Journal │◀───────────────────────│ Verify Receipt  │ │
│  │ (KernelJournalV1)│                       │ (IMAGE_ID)      │ │
│  └────────┬───────┘                        └─────────────────┘ │
│           │                                                     │
│  ┌────────▼───────┐                                            │
│  │ Assert Fields  │                                            │
│  │ (status, etc.) │                                            │
│  └────────────────┘                                            │
└─────────────────────────────────────────────────────────────────┘
```

## Files

- `src/lib.rs` - Test implementations and helper functions
- `Cargo.toml` - Dependencies with `risc0-e2e` feature gate
- `README.md` - This file

## Related Crates

- `methods` - Builds kernel-guest as RISC Zero guest, exports ELF/IMAGE_ID
- `kernel-guest` - The guest program that runs in zkVM
- `example-agent` - Provides `agent_main` and `AGENT_CODE_HASH`
- `kernel-core` - Types and encoding used by both host and guest
