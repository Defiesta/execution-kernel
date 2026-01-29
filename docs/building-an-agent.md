# Building an Agent

This document walks through the process of creating an agent from scratch. By the end, you will understand what code to write, how the pieces fit together, and what artifacts you'll produce for deployment.

We'll follow the natural order of development: first the agent logic, then the build infrastructure for the code hash, then the wrapper that connects to the kernel, and finally the zkVM guest that produces the imageId.

## Setting Up Your Agent Crate

An agent crate is a standard Rust library crate. Create it with cargo:

```bash
cargo new --lib my-agent
```

Your agent will depend on two crates from the execution kernel: `kernel-core` for the protocol types, and `kernel-sdk` for helper functions. Add these to your Cargo.toml.

The agent crate should compile for both native targets (for testing) and the RISC-V target (for zkVM execution). Avoid dependencies that don't support `no_std` or that introduce non-determinism. Common pitfalls include crates that use HashMap (unordered iteration), floating-point math, or system time.

## Implementing agent_main

The core of your agent is a single function:

```rust
use kernel_sdk::agent::AgentContext;
use kernel_core::AgentOutput;

pub fn agent_main(ctx: &AgentContext, opaque_inputs: &[u8]) -> AgentOutput {
    // Your logic here
}
```

This function receives two arguments. The `AgentContext` contains metadata about the execution—most importantly, the `agent_id` that identifies which vault or account this execution is for. The `opaque_inputs` slice contains whatever data the caller provided, in whatever format you define.

Your function returns `AgentOutput`, which contains a vector of actions. If your agent decides to do nothing, return an output with an empty actions vector. If your agent wants to execute something, construct the appropriate actions and return them.

The kernel-sdk provides helpers for common action types. To transfer ERC20 tokens:

```rust
use kernel_sdk::prelude::*;

let action = transfer_erc20_action(token_address, recipient, amount);
```

To call an arbitrary contract:

```rust
let action = call_action(target, value, &calldata);
```

These functions handle the encoding details so you don't have to worry about the binary format.

A minimal agent that always does nothing would be:

```rust
pub fn agent_main(_ctx: &AgentContext, _opaque_inputs: &[u8]) -> AgentOutput {
    AgentOutput { actions: vec![] }
}
```

A more realistic agent would parse the opaque inputs, make decisions based on that data, and construct appropriate actions. The example-yield-agent in the repository demonstrates this pattern: it parses addresses and amounts from the input bytes, constructs deposit and withdraw actions, and returns them.

## Parsing Your Inputs

The opaque_inputs slice is entirely your responsibility. The kernel doesn't know or care what format you use. You might use a simple fixed-layout binary format, or something more sophisticated.

For a fixed layout, you'd define your expected structure and parse it directly:

```rust
if opaque_inputs.len() != 48 {
    // Invalid input length, return empty output
    return AgentOutput { actions: vec![] };
}

let vault_address: [u8; 20] = opaque_inputs[0..20].try_into().unwrap();
let target_address: [u8; 20] = opaque_inputs[20..40].try_into().unwrap();
let amount = u64::from_le_bytes(opaque_inputs[40..48].try_into().unwrap());
```

The key principle is defensive parsing. If the input is malformed, return an empty output rather than panicking. A panic aborts proof generation entirely, which may not be what you want. An empty output produces a valid proof showing the agent chose to do nothing, which the caller can handle appropriately.

## The Code Hash Build Script

Every agent needs a build script that computes the agent_code_hash. This hash is embedded in the compiled binary and serves as a cryptographic commitment to the agent's source code.

Create a `build.rs` file in your agent crate:

```rust
use sha2::{Digest, Sha256};
use std::{env, fs, path::Path};

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let src_dir = Path::new(&manifest_dir).join("src");

    // Collect all .rs files in src/
    let mut source_files: Vec<_> = fs::read_dir(&src_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map_or(false, |ext| ext == "rs"))
        .map(|e| e.path())
        .collect();
    source_files.sort();

    // Hash the contents
    let mut hasher = Sha256::new();
    for path in &source_files {
        let contents = fs::read_to_string(path).unwrap();
        hasher.update(path.file_name().unwrap().to_string_lossy().as_bytes());
        hasher.update(contents.as_bytes());
    }
    let hash = hasher.finalize();

    // Generate the constant
    let hash_hex = hex::encode(&hash);
    let hash_bytes: Vec<String> = hash.iter().map(|b| format!("0x{:02x}", b)).collect();

    let out_dir = env::var("OUT_DIR").unwrap();
    let dest = Path::new(&out_dir).join("agent_code_hash.rs");

    fs::write(
        &dest,
        format!(
            "pub const AGENT_CODE_HASH: [u8; 32] = [{}];\n",
            hash_bytes.join(", ")
        ),
    )
    .unwrap();

    println!("cargo:warning=AGENT_CODE_HASH: {}", hash_hex);
    println!("cargo:rerun-if-changed=src/");
}
```

Then include the generated constant in your lib.rs:

```rust
include!(concat!(env!("OUT_DIR"), "/agent_code_hash.rs"));
```

This makes `AGENT_CODE_HASH` available as a public constant. The kernel wrapper will use this to implement the `AgentEntrypoint::code_hash()` method.

The hash changes whenever your source files change. This is intentional—it ensures that different versions of your agent have different code hashes, which can be verified on-chain.

## Creating the Wrapper Crate

The wrapper crate connects your agent to the kernel. It implements `AgentEntrypoint` and provides a convenience function for running the kernel with your agent.

Create a new crate, typically named something like `kernel-guest-binding-myagent`:

```bash
cargo new --lib kernel-guest-binding-myagent
```

The wrapper depends on your agent crate, the kernel-guest crate, and kernel-core:

```toml
[dependencies]
kernel-guest = { path = "../runtime/kernel-guest" }
kernel-core = { path = "../protocol/kernel-core" }
kernel-sdk = { path = "../sdk/kernel-sdk" }
my-agent = { path = "../agents/examples/my-agent" }
```

The implementation is straightforward:

```rust
use kernel_guest::AgentEntrypoint;
use kernel_sdk::agent::AgentContext;
use kernel_core::AgentOutput;

pub use my_agent::AGENT_CODE_HASH;

pub struct MyAgentWrapper;

impl AgentEntrypoint for MyAgentWrapper {
    fn code_hash(&self) -> [u8; 32] {
        my_agent::AGENT_CODE_HASH
    }

    fn run(&self, ctx: &AgentContext, opaque_inputs: &[u8]) -> AgentOutput {
        my_agent::agent_main(ctx, opaque_inputs)
    }
}

pub fn kernel_main(input_bytes: &[u8]) -> Result<Vec<u8>, kernel_guest::KernelError> {
    kernel_guest::kernel_main_with_agent(input_bytes, &MyAgentWrapper)
}
```

The wrapper re-exports `AGENT_CODE_HASH` so consumers can access it. It implements the trait by delegating to your agent's `agent_main`. And it provides `kernel_main` as a convenience for the zkVM guest.

You can also provide a version that accepts custom constraints:

```rust
pub fn kernel_main_with_constraints(
    input_bytes: &[u8],
    constraints: &ConstraintSetV1,
) -> Result<Vec<u8>, kernel_guest::KernelError> {
    kernel_guest::kernel_main_with_agent_and_constraints(input_bytes, &MyAgentWrapper, constraints)
}
```

## The zkVM Guest Entry Point

The final piece is the zkVM guest crate. This is what actually runs inside the RISC Zero zkVM. It's typically located in `risc0-methods/zkvm-guest/` and has a special Cargo.toml that targets the zkVM.

The guest's main.rs is minimal:

```rust
#![no_main]

risc0_zkvm::guest::entry!(main);

fn main() {
    use risc0_zkvm::guest::env;

    let input_bytes: Vec<u8> = env::read();

    match kernel_guest_binding_myagent::kernel_main(&input_bytes) {
        Ok(journal_bytes) => {
            env::commit_slice(&journal_bytes);
        }
        Err(error) => {
            panic!("Kernel execution failed: {:?}", error);
        }
    }
}
```

The guest reads input from the zkVM environment, calls the kernel through your wrapper, and commits the resulting journal. If the kernel returns an error (a hard failure), the guest panics, aborting proof generation.

The risc0-methods crate has a build.rs that compiles this guest and produces the ELF binary and imageId:

```rust
risc0_build::embed_methods();
```

This generates `ZKVM_GUEST_ELF` and `ZKVM_GUEST_ID` constants that you can use in your host-side code.

## Understanding the ImageId

The imageId is a 32-byte hash that uniquely identifies your compiled zkVM guest. It's computed from the ELF binary, which includes your agent code, the wrapper code, the kernel code, and all dependencies.

The imageId is what you register on-chain. When you submit a proof, the on-chain verifier checks that the proof was generated by a guest with the expected imageId. This is what makes the system secure—a malicious actor cannot substitute a different agent because any change would result in a different imageId.

ImageId stability matters for deployment. If you recompile your zkVM guest and get a different imageId, you'll need to register the new imageId on-chain. This can happen due to:

- Changes to your agent code
- Changes to the kernel or wrapper
- Changes to dependencies (version updates)
- Different compiler versions
- Different build environments

For reproducible builds, RISC Zero provides Docker-based compilation:

```bash
RISC0_USE_DOCKER=1 cargo build
```

This ensures that the same source code produces the same ELF and imageId regardless of your local environment.

## What You End Up With

After building, you have three critical artifacts:

**AGENT_CODE_HASH** is a 32-byte hash of your agent source code, embedded in your agent crate. It identifies your agent's logic independently of the kernel version.

**ZKVM_GUEST_ELF** is the compiled zkVM guest binary. You provide this to the prover when generating proofs.

**ZKVM_GUEST_ID** is the imageId, a 32-byte hash of the ELF. You register this on-chain to authorize your agent.

These three values appear in different places:

- The imageId is registered with the `KernelExecutionVerifier` contract
- The agent_code_hash appears in every journal your agent produces
- The ELF is used off-chain by whoever runs the prover

## Testing Your Agent

Before deploying, test your agent at multiple levels.

Unit tests in your agent crate can test the `agent_main` function directly:

```rust
#[test]
fn test_agent_produces_expected_actions() {
    let ctx = AgentContext { /* ... */ };
    let input = /* your test input */;
    let output = agent_main(&ctx, &input);
    assert_eq!(output.actions.len(), 2);
    // ... more assertions
}
```

Integration tests using kernel-host-tests run your agent through the full kernel without the zkVM:

```rust
let input = KernelInputV1 {
    agent_code_hash: AGENT_CODE_HASH,
    // ... other fields
};
let journal_bytes = kernel_main(&input.encode().unwrap()).unwrap();
let journal = KernelJournalV1::decode(&journal_bytes).unwrap();
assert_eq!(journal.execution_status, ExecutionStatus::Success);
```

E2E tests with the `risc0-e2e` feature generate actual proofs:

```rust
let prover = default_prover();
let prove_info = prover
    .prove_with_opts(env, ZKVM_GUEST_ELF, &ProverOpts::groth16())
    .expect("proof generation failed");
```

And the full on-chain test submits proofs to deployed contracts:

```bash
cargo test --release -p e2e-tests --features phase3-e2e \
    test_full_e2e_yield_execution -- --ignored --nocapture
```

Start with unit tests for fast iteration, then integration tests to verify kernel interaction, and finally E2E tests to confirm the complete flow works.

## Deployment Checklist

When you're ready to deploy:

1. Verify that your agent_code_hash is stable across builds
2. Build the zkVM guest with Docker for reproducible imageId
3. Note the imageId from the build output
4. Register the imageId with the KernelExecutionVerifier contract
5. Configure the vault to trust your agent's identifier
6. Run the on-chain E2E test to verify the full flow

The imageId registration typically looks like:

```bash
cast send $VERIFIER_ADDRESS "registerAgent(bytes32,bytes32)" \
    $AGENT_ID $IMAGE_ID \
    --private-key $PRIVATE_KEY --rpc-url $RPC_URL
```

Once registered, your agent is live. Proofs generated with your imageId will be accepted by the verifier, and vaults configured to trust your agent can execute its actions.
