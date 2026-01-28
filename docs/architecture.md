# Architecture

The Execution Kernel is the consensus-critical component that defines what constitutes a valid agent execution. It runs inside a RISC Zero zkVM, producing cryptographic proofs that bind an agent's decisions to verifiable commitments. These proofs enable smart contracts to trust off-chain computation without re-executing it.

This document explains how the system is structured and why each component exists.

## The Role of the Execution Kernel

In the broader protocol, capital is held in on-chain vaults. These vaults delegate decision-making to agents—programs that analyze market conditions and produce actions like deposits, withdrawals, or trades. The challenge is trust: how can a vault execute an agent's instructions without the agent having custody of funds, and without the vault needing to understand or re-execute the agent's logic?

The execution kernel solves this by acting as a verifiable sandbox. An agent runs inside the kernel, which runs inside a zkVM. The zkVM produces a proof that the agent executed correctly according to its own code, that the kernel enforced all protocol constraints, and that the resulting actions are exactly what the agent decided. The vault can verify this proof on-chain and execute the actions with cryptographic certainty that they came from a legitimate execution.

The kernel itself is deliberately minimal. It decodes inputs, invokes the agent, enforces constraints, and commits the results to a journal. It does not contain business logic, trading strategies, or protocol-specific rules. Those belong to agents. The kernel's job is to be a trusted, deterministic execution environment that agents plug into.

## Crate Organization

The repository separates concerns into distinct layers, each with a clear responsibility.

### Protocol Layer

The `protocol/` directory contains the foundational types and rules that define the execution protocol itself.

**kernel-core** provides the canonical data structures: `KernelInputV1`, `KernelJournalV1`, `ActionV1`, and `AgentOutput`. It also implements the deterministic binary codec used to serialize these structures. This codec is consensus-critical—every implementation that interacts with the protocol must encode and decode data identically. The crate deliberately avoids serde and other auto-derivation to maintain byte-level determinism.

**constraints** implements the constraint engine that validates agent outputs. When an agent produces actions, the constraint engine checks that they conform to protocol rules: action types must be recognized, payloads must be well-formed, and various limits must be respected. The constraint engine can reject an agent's output, causing the execution to produce a Failure status rather than Success. Importantly, constraint violations do not prevent proof generation—they result in a valid proof of a failed execution, which the on-chain verifier can distinguish from a successful one.

### SDK Layer

The `sdk/kernel-sdk` crate provides utilities for agent developers. It includes helper functions for constructing actions, working with addresses, and managing the `AgentContext` that the kernel provides to agents. Agent developers import this crate to access these conveniences without depending on kernel internals.

The SDK also defines the `AgentOutput` type and action construction helpers like `call_action` and `transfer_erc20_action`. These ensure that agents produce well-formed outputs that the kernel and constraint engine can process.

### Runtime Layer

The `runtime/` directory contains the components that actually execute inside the zkVM.

**kernel-guest** is the core execution logic. It defines the `AgentEntrypoint` trait and the `kernel_main_with_agent` function that orchestrates execution. When the zkVM runs, it executes code from this crate. The kernel-guest is agent-agnostic—it contains no references to specific agents. Instead, it accepts any type implementing `AgentEntrypoint` and invokes it generically.

**risc0-methods** is the RISC Zero build crate. It compiles the zkVM guest program and exports two critical artifacts: `ZKVM_GUEST_ELF` (the compiled binary) and `ZKVM_GUEST_ID` (the imageId, a cryptographic hash of the binary). The imageId uniquely identifies the guest program and is used for on-chain verification.

### Agents Layer

The `agents/` directory is where specific agent implementations live.

**agents/examples/** contains reference agent implementations. The `example-yield-agent` demonstrates a complete agent that deposits into a yield source and withdraws with profits. It serves as both a working example and a test fixture for the protocol.

**agents/wrappers/** contains binding crates that connect specific agents to the kernel. A wrapper crate implements `AgentEntrypoint` by delegating to a concrete agent's `agent_main` function. This indirection is what makes the kernel agent-agnostic—the kernel depends only on the trait, and the wrapper provides the concrete implementation.

### Testing Layer

The `testing/` directory contains test suites that verify the system works correctly.

**kernel-host-tests** runs unit tests outside the zkVM, testing codec correctness, constraint enforcement, and kernel logic without the overhead of proof generation.

**e2e-tests** runs full end-to-end tests that generate actual RISC Zero proofs and, optionally, submit them to deployed smart contracts on Sepolia. These tests verify the complete flow from agent execution to on-chain verification.

## Why Agent-Agnostic?

The kernel is deliberately designed to have no knowledge of specific agents. This separation exists for several reasons.

First, it enables agent developers to work independently. An agent developer creates their agent crate, writes a small wrapper, and produces a zkVM guest without modifying any kernel code. They don't need to submit pull requests, wait for reviews, or coordinate with kernel maintainers.

Second, it ensures that the kernel remains minimal and auditable. The kernel is consensus-critical—any bug could compromise the entire protocol. By keeping agent-specific logic out of the kernel, we reduce the attack surface and make the kernel easier to reason about and verify.

Third, it creates a clean upgrade path. When the protocol evolves, kernel changes and agent changes can happen independently. An agent can be updated without touching the kernel, and the kernel can be upgraded without breaking existing agents (as long as the `AgentEntrypoint` interface remains stable).

The mechanism for this separation is Rust's trait system. The kernel defines:

```rust
pub trait AgentEntrypoint {
    fn code_hash(&self) -> [u8; 32];
    fn run(&self, ctx: &AgentContext, opaque_inputs: &[u8]) -> AgentOutput;
}
```

Any type implementing this trait can be passed to `kernel_main_with_agent`. The wrapper crates provide these implementations, connecting generic kernel code to specific agent implementations.

## The ImageId and Agent Binding

A critical property of the system is that one imageId corresponds to exactly one agent. This binding is what makes on-chain verification meaningful.

The imageId is a cryptographic hash of the compiled zkVM guest binary. This binary includes the kernel code, the wrapper code, and the agent code—all compiled together into a single ELF. If any of these components change, the imageId changes.

When a vault is configured, it registers which imageId it trusts for a given agent identifier. When a proof is submitted, the on-chain verifier checks that the proof was generated by a guest with the registered imageId. This ensures that only the expected agent, running in the expected kernel, can produce valid proofs for that vault.

The agent_code_hash provides an additional layer of binding. Each agent has a build script that computes a hash of its source code at compile time. This hash is embedded in the agent binary and returned by the `AgentEntrypoint::code_hash()` method. The kernel includes this hash in the journal, and the on-chain contracts can verify it matches expectations.

The relationship between these identifiers is:

1. **Agent source code** → compiled into agent crate → **agent_code_hash** embedded at build time
2. **Agent crate + wrapper + kernel** → compiled into zkVM guest → **imageId** computed from ELF
3. **imageId** registered on-chain with verifier contract
4. **Proof** ties together: execution inputs → agent decisions → journal containing agent_code_hash
5. **On-chain verification** confirms proof matches registered imageId, journal is well-formed

This chain of cryptographic commitments ensures that a valid proof could only have been produced by the exact agent code that was registered, running in the exact kernel version that was compiled.

## Determinism Requirements

The execution kernel runs in a zkVM, which means every execution must be perfectly deterministic. Given the same inputs, the kernel must produce the same outputs, byte for byte, every time. Any non-determinism would cause proof generation to fail or produce inconsistent results.

This requirement permeates the entire codebase:

- No floating-point arithmetic (hardware differences cause divergence)
- No randomness or time-dependent operations
- No hash maps or other unordered collections (iteration order varies)
- Manual binary encoding instead of serde (auto-derive can change between versions)
- Explicit bounds on all loops and allocations (unbounded operations can diverge)
- Checked arithmetic to handle overflow consistently

The constraint engine and codec are particularly careful about determinism. The codec uses explicit little-endian encoding with length prefixes, rejecting any input with trailing bytes. The constraint engine processes actions in order without sorting or reordering.

These constraints may seem burdensome, but they're essential. The zkVM can only prove what it can reproduce, and reproducibility requires determinism.

## Failure Handling

The kernel distinguishes between two kinds of failures.

**Soft failures** occur when an agent produces output that violates constraints. The constraint engine detects the violation and the kernel produces a journal with `execution_status = Failure`. This is still a valid proof—it proves that the agent tried to do something invalid. The on-chain verifier can accept this proof but recognize that no actions should be executed.

**Hard failures** occur when something is fundamentally wrong: the input is malformed, the protocol version is unsupported, or the agent_code_hash doesn't match. In these cases, the kernel panics, aborting proof generation entirely. No valid proof is produced, so nothing can be submitted on-chain.

This distinction is important for the protocol. Soft failures are expected—agents might occasionally produce invalid outputs, and the system handles this gracefully. Hard failures indicate bugs or attacks, and the system correctly refuses to produce proofs for them.

The journal always contains commitments to the inputs (`input_commitment`) and, for successful executions, commitments to the outputs (`action_commitment`). For failed executions, the action commitment is set to a well-known constant (`EMPTY_OUTPUT_COMMITMENT`). This allows on-chain contracts to verify that a failure occurred without needing to parse the agent's attempted actions.
