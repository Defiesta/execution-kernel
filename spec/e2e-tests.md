# End-to-End zkVM Proof Tests Specification

**Version:** 0.1.0
**Status:** Canonical
**Crates:** `methods`, `e2e-tests`

---

## 1. Overview

The E2E testing framework validates the complete execution kernel pipeline from agent execution through zkVM proof generation to on-chain verification data extraction.

### 1.1 Purpose

Verify that:
1. The kernel executes correctly inside RISC Zero zkVM
2. Proofs are generated and verifiable against `IMAGE_ID`
3. Journal contents match expected values
4. Security properties (agent code hash binding) are enforced
5. On-chain verification data (seal, journal, imageId) is extractable

### 1.2 Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           E2E Test Pipeline                             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  1. Input Construction                                                  │
│     ┌──────────────────┐                                                │
│     │ KernelInputV1    │ ← agent_code_hash =                            │
│     │ + opaque_inputs  │              example_agent::AGENT_CODE_HASH    │
│     └────────┬─────────┘                                                │
│              │ encode()                                                 │
│              ▼                                                          │
│  2. zkVM Execution                                                      │
│     ┌──────────────────┐     ┌─────────────────────────────────────┐    │
│     │ ExecutorEnv      │────▶│ zkvm-guest (RISC-V ELF)             │    │
│     │ .write(&bytes)   │     │  └─► kernel_guest::kernel_main()    │    │
│     └──────────────────┘     │       └─► agent_main() [linked]     │    │
│                              └────────────────┬────────────────────┘    │
│                                               │ env::commit_slice()     │
│                                               ▼                         │
│  3. Proof Generation                                                    │
│     ┌──────────────────┐                                                │
│     │ ProveInfo        │                                                │
│     │  ├─ receipt      │ ← Groth16Receipt with seal                     │
│     │  └─ stats        │                                                │
│     └────────┬─────────┘                                                │
│              │                                                          │
│              ▼                                                          │
│  4. Verification                                                        │
│     ┌──────────────────┐                                                │
│     │ receipt.verify() │ ← Against ZKVM_GUEST_ID                        │
│     └────────┬─────────┘                                                │
│              │                                                          │
│              ▼                                                          │
│  5. Journal Extraction                                                  │
│     ┌──────────────────┐                                                │
│     │ KernelJournalV1  │ ← Decode from receipt.journal.bytes            │
│     │  ├─ status       │                                                │
│     │  ├─ commitments  │                                                │
│     │  └─ identity     │                                                │
│     └──────────────────┘                                                │
│                                                                         │
│  6. On-Chain Data                                                       │
│     ┌──────────────────┐                                                │
│     │ seal (256 bytes) │ ← Groth16 proof for Solidity verifier          │
│     │ journal (bytes)  │ ← Public outputs                               │
│     │ imageId (bytes32)│ ← Guest program identity                       │
│     └──────────────────┘                                                │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Crate Structure

### 2.1 methods Crate

**Purpose:** Build the zkVM guest and export ELF/IMAGE_ID constants.

```
crates/methods/
├── Cargo.toml          # risc0-build dependency
├── build.rs            # Invokes risc0_build::embed_methods()
├── src/
│   └── lib.rs          # include!(methods.rs) → exports ZKVM_GUEST_*
└── zkvm-guest/         # Standalone guest wrapper
    ├── Cargo.toml      # [workspace] + kernel-guest dependency
    └── src/
        └── main.rs     # Entry point calling kernel_guest::kernel_main()
```

#### 2.1.1 Exports

| Constant | Type | Description |
|----------|------|-------------|
| `ZKVM_GUEST_ELF` | `&[u8]` | Compiled RISC-V ELF binary |
| `ZKVM_GUEST_ID` | `[u32; 8]` | IMAGE_ID (cryptographic identity) |

#### 2.1.2 zkvm-guest Wrapper

The wrapper is necessary because:
1. `risc0-build` expects guest crates as subdirectories
2. `kernel-guest` is a workspace member with complex dependencies
3. A standalone `[workspace]` declaration avoids lockfile conflicts

```rust
// zkvm-guest/src/main.rs
fn main() {
    use risc0_zkvm::guest::env;

    let input_bytes: Vec<u8> = env::read();

    match kernel_guest::kernel_main(&input_bytes) {
        Ok(journal_bytes) => env::commit_slice(&journal_bytes),
        Err(error) => panic!("Kernel execution failed: {:?}", error),
    }
}
```

### 2.2 e2e-tests Crate

**Purpose:** Host-side integration tests with zkVM proof generation.

```
crates/e2e-tests/
├── Cargo.toml      # Feature-gated risc0-zkvm dependency
├── src/
│   └── lib.rs      # Test implementations
└── README.md       # Usage documentation
```

#### 2.2.1 Feature Gates

| Feature | Dependencies | Purpose |
|---------|--------------|---------|
| `default` | None | Unit tests only |
| `risc0-e2e` | `methods`, `risc0-zkvm/prove` | Full zkVM proof tests |

---

## 3. Test Cases

### 3.1 test_e2e_success_with_echo

**Purpose:** Verify the happy path with valid input and echo action.

**Input:**
- `opaque_inputs[0] == 1` (triggers echo)
- `agent_code_hash == example_agent::AGENT_CODE_HASH`

**Expected:**
- Proof generation succeeds
- `receipt.verify(ZKVM_GUEST_ID)` passes
- `journal.execution_status == Success`
- `journal.input_commitment == SHA256(input_bytes)`
- `journal.action_commitment == SHA256(echo_output_bytes)`

### 3.2 test_e2e_agent_code_hash_mismatch

**Purpose:** Verify security - wrong agent code hash aborts execution.

**Input:**
- `agent_code_hash == [0x00; 32]` (wrong hash)

**Expected:**
- Guest panics with `AgentCodeHashMismatch`
- No valid proof/receipt produced
- `prover.prove()` returns error

### 3.3 test_e2e_empty_output

**Purpose:** Verify empty output handling.

**Input:**
- `opaque_inputs[0] != 1` (no echo trigger)

**Expected:**
- Proof generation succeeds
- `journal.execution_status == Success`
- `journal.action_commitment == EMPTY_OUTPUT_COMMITMENT`

### 3.4 test_e2e_determinism

**Purpose:** Verify deterministic execution.

**Method:**
- Run same input twice
- Compare journal bytes

**Expected:**
- `journals[0] == journals[1]`

---

## 4. On-Chain Verification Data

### 4.1 Data Structure

For Solidity verifier integration, extract:

| Field | Source | Format |
|-------|--------|--------|
| `seal` | `receipt.inner.Groth16.seal` | `bytes` (256 bytes) |
| `journal` | `receipt.journal.bytes` | `bytes` (variable) |
| `imageId` | `ZKVM_GUEST_ID` | `bytes32` (little-endian) |

### 4.2 imageId Conversion

```rust
// Convert [u32; 8] to bytes32 (little-endian)
let image_id_bytes: Vec<u8> = ZKVM_GUEST_ID
    .iter()
    .flat_map(|x| x.to_le_bytes())
    .collect();
```

### 4.3 Solidity Verifier Interface

```solidity
interface IRiscZeroVerifier {
    function verify(
        bytes calldata seal,
        bytes32 imageId,
        bytes32 journalDigest  // or bytes calldata journal
    ) external view;
}
```

---

## 5. IMAGE_ID Immutability

### 5.1 What Changes IMAGE_ID

| Change | IMAGE_ID Changes? |
|--------|-------------------|
| Agent code modification | Yes |
| Kernel logic modification | Yes |
| Compiler version change | Yes |
| Dependency version change | Possibly |
| Input data change | No |

### 5.2 Per-Agent Deployment

Each agent deployment produces a unique `IMAGE_ID`:

```
Agent A → zkvm-guest + kernel-guest + agent-a → IMAGE_ID_A
Agent B → zkvm-guest + kernel-guest + agent-b → IMAGE_ID_B
```

### 5.3 Reproducible Builds

For deterministic `IMAGE_ID` across environments:

```bash
RISC0_USE_DOCKER=1 cargo build -p methods
```

---

## 6. CI Integration

### 6.1 Without RISC Zero

```yaml
# Unit tests always work
- name: Run unit tests
  run: cargo test -p e2e-tests
```

### 6.2 With RISC Zero

```yaml
# E2E tests require RISC Zero toolchain
- name: Install RISC Zero
  run: |
    cargo install cargo-risczero
    cargo risczero install

- name: Run E2E proof tests
  run: cargo test -p e2e-tests --features risc0-e2e -- --test-threads=1
```

**Note:** Use `--test-threads=1` to avoid parallel proof generation exhausting memory.

---

## 7. Helper Functions

### 7.1 make_valid_input

```rust
pub fn make_valid_input(opaque_agent_inputs: Vec<u8>) -> KernelInputV1 {
    KernelInputV1 {
        protocol_version: PROTOCOL_VERSION,
        kernel_version: KERNEL_VERSION,
        agent_id: [0x42; 32],
        agent_code_hash: example_agent::AGENT_CODE_HASH,
        constraint_set_hash: [0xbb; 32],
        input_root: [0xcc; 32],
        execution_nonce: 1,
        opaque_agent_inputs,
    }
}
```

### 7.2 make_input_with_wrong_hash

```rust
pub fn make_input_with_wrong_hash(opaque_agent_inputs: Vec<u8>) -> KernelInputV1 {
    KernelInputV1 {
        agent_code_hash: [0x00; 32],  // Wrong hash
        // ... rest same as make_valid_input
    }
}
```

### 7.3 compute_echo_commitment

```rust
pub fn compute_echo_commitment(agent_id: [u8; 32], payload: &[u8]) -> [u8; 32] {
    let action = ActionV1 {
        action_type: ACTION_TYPE_ECHO,
        target: agent_id,
        payload: payload[..min(payload.len(), MAX_ACTION_PAYLOAD_BYTES)].to_vec(),
    };
    let output = AgentOutput { actions: vec![action] };
    compute_action_commitment(&output.encode().unwrap())
}
```

---

## 8. Error Handling

### 8.1 Guest Panic Behavior

| Error | Guest Behavior | Host Result |
|-------|----------------|-------------|
| `AgentCodeHashMismatch` | `panic!()` | Proof fails |
| `Codec(...)` | `panic!()` | Proof fails |
| `VersionMismatch` | `panic!()` | Proof fails |
| Constraint violation | Return failure journal | Proof succeeds |

### 8.2 Resource Exhaustion

Parallel proof generation may cause OOM (exit code 137). Mitigations:
- Run tests sequentially: `--test-threads=1`
- Increase Docker memory limits
- Run tests individually

---

## 9. Dependencies

### 9.1 methods Crate

```toml
[build-dependencies]
risc0-build = { version = "3.0", default-features = false }

[package.metadata.risc0]
methods = ["zkvm-guest"]
```

### 9.2 e2e-tests Crate

```toml
[dependencies]
kernel-core = { path = "../kernel-core" }
kernel-sdk = { path = "../kernel-sdk" }
constraints = { path = "../constraints" }
example-agent = { path = "../example-agent" }
methods = { path = "../methods", optional = true }
risc0-zkvm = { version = "3.0", default-features = false, optional = true }

[dev-dependencies]
hex = "0.4"

[features]
risc0-e2e = ["dep:methods", "dep:risc0-zkvm", "risc0-zkvm/prove"]
```

---

## Appendix A: Example Test Output

```
=== On-chain verification data ===
seal (hex): 0x00892d14f88aca6a...
seal length: 256 bytes
journal (hex): 0x01000000010000004242...
journal length: 209 bytes
image_id (bytes32): 0xb326f06dbfc60f5e72d2d7cddf94f7991cff99dfd67f69357713bb9f49c3d195
image_id (u32[8]): [1844455091, 1578092223, 3453473394, 2583139551, 3751411484, 896106454, 2679837559, 2513552201]
```

---

## Appendix B: Proof Generation Time

| Test | Approximate Time |
|------|------------------|
| `test_e2e_success_with_echo` | ~100s |
| `test_e2e_agent_code_hash_mismatch` | <1s (no proof) |
| `test_e2e_empty_output` | ~100s |
| `test_e2e_determinism` | ~200s (2 proofs) |

Times vary based on hardware and Docker configuration.
