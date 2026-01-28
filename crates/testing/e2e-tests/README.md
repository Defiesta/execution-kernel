# E2E zkVM Proof Tests

End-to-end integration tests that verify the complete execution kernel flow using RISC Zero zkVM proofs, including on-chain verification and execution.

## Overview

These tests verify:

1. **Agent → Guest → Proof → Verification** pipeline works correctly
2. **Agent code hash binding** prevents unauthorized agent substitution
3. **Determinism** - same input always produces same output
4. **Commitment integrity** - input and action commitments are correctly computed
5. **On-chain execution** - proofs verify on-chain and trigger vault actions

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

### Install Foundry (for on-chain tests)

```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

## Running Tests

### Unit Tests (no zkVM required)

```bash
# Run unit tests without proof generation
cargo test -p e2e-tests
```

### Full E2E Proof Tests (off-chain)

```bash
# Run with zkVM proof generation (requires RISC Zero toolchain)
cargo test -p e2e-tests --features risc0-e2e -- --nocapture
```

### Phase 3 Yield Agent Tests

```bash
# Run yield agent proof tests
cargo test -p e2e-tests --features phase3-e2e -- --nocapture
```

## Test Cases

### 1. `test_e2e_success_with_yield_agent`

Verifies the happy path with the yield agent:
- Valid 48-byte input (vault address + yield source address + amount)
- Proof generation succeeds
- Receipt verifies against IMAGE_ID
- Journal contains correct:
  - `execution_status == Success`
  - `input_commitment == SHA256(input_bytes)`
  - `action_commitment` matches expected yield agent output (2 CALL actions)

### 2. `test_e2e_agent_code_hash_mismatch`

Verifies security:
- Input with wrong `agent_code_hash` (all zeros)
- Guest execution fails with `AgentCodeHashMismatch`
- No valid proof/receipt is produced

### 3. `test_e2e_empty_output_invalid_input_size`

Verifies empty output handling:
- Input with wrong size (not 48 bytes for yield agent)
- Proof generation succeeds (empty output is valid)
- `action_commitment == EMPTY_OUTPUT_COMMITMENT`

### 4. `test_e2e_determinism`

Verifies deterministic execution:
- Same input run twice
- Both runs produce identical journal bytes

---

## On-Chain E2E Test: `test_full_e2e_yield_execution`

This is the complete end-to-end test that generates a zkVM proof and submits it to a deployed smart contract on Sepolia testnet.

### What It Tests

The test verifies the full yield farming flow:

```
Vault (has ETH)
    │
    ▼ zkVM generates proof of agent execution
Agent produces 2 actions:
    1. CALL: deposit ETH to MockYieldSource
    2. CALL: withdraw ETH + 10% yield from MockYieldSource
    │
    ▼ Submit proof to vault.execute()
On-chain verifier validates RISC Zero proof
    │
    ▼ Vault executes agent's actions
MockYieldSource receives deposit, returns deposit + 10% yield
    │
    ▼
Vault balance increases by 10% of transfer amount
```

### Deployed Contracts (Sepolia)

The following contracts are already deployed and ready to use:

| Contract | Address |
|----------|---------|
| KernelExecutionVerifier | `0x9Ef5bAB590AFdE8036D57b89ccD2947D4E3b1EFA` |
| KernelVault | `0xAdeDA97D2D07C7f2e332fD58F40Eb4f7F0192be7` |
| MockYieldSource | `0x7B35E3F2e810170f146d31b00262b9D7138F9b39` |
| RISC Zero Verifier Router | `0x925d8331ddc0a1F0d96E68CF073DFE1d92b69187` |

### Funding Requirements

Before running the test, ensure both contracts have sufficient Sepolia ETH:

1. **KernelVault** - Needs ETH to transfer to the yield source
2. **MockYieldSource** - Needs ETH reserves to pay the 10% yield

```bash
# Check current balances
cast balance 0xAdeDA97D2D07C7f2e332fD58F40Eb4f7F0192be7 --rpc-url $RPC_URL  # Vault
cast balance 0x7B35E3F2e810170f146d31b00262b9D7138F9b39 --rpc-url $RPC_URL  # MockYieldSource

# Fund the vault (if needed)
cast send 0xAdeDA97D2D07C7f2e332fD58F40Eb4f7F0192be7 \
    --value 0.5ether \
    --private-key $PRIVATE_KEY --rpc-url $RPC_URL

# Fund the MockYieldSource (if needed - must have enough to pay 10% yield)
cast send 0x7B35E3F2e810170f146d31b00262b9D7138F9b39 \
    --value 1ether \
    --private-key $PRIVATE_KEY --rpc-url $RPC_URL
```

**Example**: If you transfer 0.1 ETH, the MockYieldSource needs at least 0.01 ETH in reserves to pay the 10% yield.

### Running the On-Chain Test

```bash
# Set all required environment variables
export VAULT_ADDRESS=0xAdeDA97D2D07C7f2e332fD58F40Eb4f7F0192be7
export MOCK_YIELD_ADDRESS=0x7B35E3F2e810170f146d31b00262b9D7138F9b39
export RPC_URL=https://eth-sepolia.g.alchemy.com/v2/YOUR_KEY
export PRIVATE_KEY=0x...
export EXECUTION_NONCE=1        # Must match vault's lastExecutionNonce + 1
export TRANSFER_AMOUNT=10000000000000000  # 0.01 ETH in wei

# Run the test
cargo test --release -p e2e-tests --features phase3-e2e \
    test_full_e2e_yield_execution -- --ignored --nocapture
```

### Expected Output

```
=== Initial State ===
Vault address: 0xAdeDA97D2D07C7f2e332fD58F40Eb4f7F0192be7
MockYieldSource address: 0x7B35E3F2e810170f146d31b00262b9D7138F9b39
Initial nonce: 1
Initial vault balance: 1010000000000000000 wei
Agent ID: 0x0000000000000000000000000000000000000000000000000000000000000001
Transfer amount: 100000000000000000 wei

=== Generating zkVM Proof ===
Proof generated and verified!

=== Submitting Transaction ===
Journal length: 209 bytes
Seal length: 260 bytes
Agent output length: 348 bytes
Transaction sent: 0x376a678046d5166c0f712ab90afe85d769a44c11e4d919d5f6e8ad776c7a8cac
Transaction confirmed in block: Some(10141050)
Gas used: 403945

=== Verifying Results ===
Final nonce: 2
Final vault balance: 1020000000000000000 wei
MockYieldSource deposits[vault]: 0 wei

=== E2E Test Passed! ===
Yield earned: 10000000000000000 wei (10%)
```

### Checking Current Vault State

Before running the test, check the vault state:

```bash
# Get current nonce (use nonce + 1 for EXECUTION_NONCE)
cast call $VAULT_ADDRESS "lastExecutionNonce()(uint64)" --rpc-url $RPC_URL

# Get vault balance
cast balance $VAULT_ADDRESS --rpc-url $RPC_URL

# Get MockYieldSource balance (needs enough for yield)
cast balance $MOCK_YIELD_ADDRESS --rpc-url $RPC_URL
```

### Troubleshooting On-Chain Tests

#### "execution reverted: Invalid proof"

- Ensure the IMAGE_ID is registered with the verifier
- Verify the IMAGE_ID matches the built kernel-guest

```bash
# Check if agent is registered
cast call $VERIFIER_ADDRESS "registeredImageIds(bytes32)(bytes32)" $AGENT_ID --rpc-url $RPC_URL
```

#### "execution reverted: Invalid nonce"

- Check the current nonce and use the next one:

```bash
cast call $VAULT_ADDRESS "lastExecutionNonce()(uint64)" --rpc-url $RPC_URL
```

#### "execution reverted: Insufficient balance"

- Ensure the vault has enough ETH for the transfer
- Ensure MockYieldSource has enough ETH to pay the 10% yield

---

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

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              e2e-tests                                      │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                     Off-Chain (zkVM Proof)                          │   │
│  │  ┌────────────────┐   ┌────────────────┐   ┌────────────────┐       │   │
│  │  │ Test Input     │──▶│ risc0-methods  │──▶│ Prover         │       │   │
│  │  │ (KernelInputV1)│   │ (ELF+IMAGE_ID) │   │ (risc0-zkvm)   │       │   │
│  │  └────────────────┘   └────────────────┘   └───────┬────────┘       │   │
│  │                                                     │                │   │
│  │                                            ┌────────▼────────┐       │   │
│  │                                            │ Receipt         │       │   │
│  │                                            │ (Seal+Journal)  │       │   │
│  │                                            └────────┬────────┘       │   │
│  └─────────────────────────────────────────────────────┼────────────────┘   │
│                                                        │                    │
│  ┌─────────────────────────────────────────────────────┼────────────────┐   │
│  │                     On-Chain (Sepolia)              │                │   │
│  │                                            ┌────────▼────────┐       │   │
│  │  ┌────────────────┐                        │ KernelVault     │       │   │
│  │  │ RISC Zero      │◀───────────────────────│ .execute()      │       │   │
│  │  │ Verifier       │   verify proof         └────────┬────────┘       │   │
│  │  └────────────────┘                                 │                │   │
│  │                                                     │ execute actions│   │
│  │                                            ┌────────▼────────┐       │   │
│  │                                            │ MockYieldSource │       │   │
│  │                                            │ (deposit+yield) │       │   │
│  │                                            └─────────────────┘       │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Agent Registration Values

| Field | Value |
|-------|-------|
| IMAGE_ID | `0x5f42241afd61bf9e341442c8baffa9c544cf20253720f2540cf6705f27bae2c4` |
| AGENT_CODE_HASH | `0x5aac6b1fedf1b0c0ccc037c3223b7b5c8b679f48b9c599336c0dc777be88924b` |
| AGENT_ID | `0x0000000000000000000000000000000000000000000000000000000000000001` |

## Files

- `src/lib.rs` - Test implementations and helper functions
- `src/phase3_yield.rs` - Yield agent tests and on-chain E2E test
- `Cargo.toml` - Dependencies with feature gates
- `README.md` - This file

## Related Crates

- `risc0-methods` - Builds kernel-guest as RISC Zero guest, exports ELF/IMAGE_ID
- `kernel-guest` - The guest program that runs in zkVM (agent-agnostic)
- `kernel-guest-binding-yield` - Binds yield agent to kernel-guest
- `example-yield-agent` - Provides `agent_main` and `AGENT_CODE_HASH`
- `kernel-core` - Types and encoding used by both host and guest
