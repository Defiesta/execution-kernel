# Agents

An agent is a program that makes decisions about capital allocation. It receives inputs describing the current state of the world, analyzes them according to its strategy, and produces a set of actions to be executed on-chain. The execution kernel provides the trusted environment where this decision-making happens, and the zkVM provides the cryptographic proof that the decisions were made correctly.

This document explains what agents are, how they interact with the kernel, and how they become executable zkVM programs.

## What is an Agent?

In this system, an agent is not a smart contract, not an off-chain bot, and not a traditional program that runs continuously. An agent is a pure function: given some inputs, it produces some outputs. It has no persistent state, no network access, no ability to read the current time, and no way to interact with the outside world except through the inputs it receives and the outputs it produces.

This purity is not a limitation—it's the foundation of verifiability. Because an agent is a pure function, we can prove exactly what it did. The inputs are committed to in the proof, the outputs are committed to in the proof, and anyone can verify that the outputs are exactly what the agent's code would produce given those inputs.

An agent's inputs arrive as opaque bytes in the `opaque_agent_inputs` field of `KernelInputV1`. The kernel doesn't interpret these bytes; it passes them directly to the agent. The agent is responsible for parsing and validating its own input format. This design allows different agents to have completely different input schemas without requiring changes to the kernel.

An agent's outputs are structured as `AgentOutput`, which contains a vector of `ActionV1` entries. Each action has a type (like CALL or TRANSFER_ERC20), a target address, and a payload. The kernel commits to these outputs and passes them through the constraint engine for validation.

## The agent_main Contract

Every agent must implement a function with the following signature:

```rust
pub fn agent_main(ctx: &AgentContext, opaque_inputs: &[u8]) -> AgentOutput
```

This function is the agent's entire interface with the kernel. The kernel calls it exactly once per execution, passing the context and the raw input bytes, and expects an `AgentOutput` in return.

The `AgentContext` provides information the agent might need about its execution environment: the agent's own identifier, the constraint set hash, and other metadata. Most agents use this sparingly—the primary input is the opaque bytes.

The `AgentOutput` contains the actions the agent wants to execute. An agent can produce zero actions (if it decides to do nothing), one action (the common case), or multiple actions (for complex strategies). The kernel will validate all actions against the constraint engine before committing them.

The agent_main function must be deterministic. Given the same context and inputs, it must produce the same output every time. This is enforced by the zkVM environment, which will fail to generate a proof if execution diverges.

The agent_main function should not panic except in truly exceptional circumstances. If an agent encounters invalid input, it should return an empty `AgentOutput` rather than panicking. Panics abort proof generation entirely, which may not be the desired behavior.

## Producing Actions

The `AgentOutput` type is simple: it contains a vector of actions. Each action represents an instruction that will be executed on-chain if the proof verifies successfully.

Actions have three fields: `action_type` identifies what kind of action this is, `target` specifies the address or identifier the action applies to, and `payload` contains action-specific data.

The kernel-sdk provides helper functions for constructing common action types:

```rust
// Create a CALL action (invoke a contract with value and calldata)
let action = call_action(target, value, &calldata);

// Create a TRANSFER_ERC20 action
let action = transfer_erc20_action(token, recipient, amount);
```

These helpers handle the encoding details, ensuring the payload is correctly formatted for the constraint engine and on-chain executor.

The order of actions in `AgentOutput` is preserved through encoding and execution. If an agent produces actions A, B, C in that order, they will be validated and executed in that order. Agents that need specific ordering (like approve-then-transfer patterns) can rely on this property.

## Why Agents Don't Touch the Kernel

A natural question is why agents don't simply import kernel-guest and call functions directly. The answer involves both practical and security considerations.

From a practical standpoint, direct coupling would mean that every agent change requires recompiling the kernel. Agent developers would need to fork the kernel repository, modify it, and maintain their fork. This creates friction and makes it harder to adopt kernel upgrades.

From a security standpoint, the kernel is consensus-critical code that must be carefully audited. If agents could arbitrarily call kernel internals, the audit surface would expand to include every agent. By forcing agents to communicate through the narrow `agent_main` interface, we can audit the kernel independently and trust that its invariants hold regardless of what agents do.

The separation also enables different trust models. A vault might trust a specific kernel version (identified by imageId) while being skeptical of individual agents. The architecture supports this: the kernel's behavior is fixed by its imageId, while agents are identified by their agent_code_hash within that kernel.

## The Role of Wrapper Crates

Agents don't implement `AgentEntrypoint` directly. Instead, a wrapper crate provides this implementation, connecting the kernel's generic interface to the agent's specific `agent_main` function.

A wrapper crate is typically very small. It imports the agent crate, implements `AgentEntrypoint` by delegating to `agent_main`, and provides a convenience function for calling `kernel_main_with_agent`. The entire implementation might be twenty lines of code.

Why have this extra layer? Several reasons:

First, it keeps the agent crate focused on agent logic. The agent developer writes their strategy without worrying about traits, zkVM specifics, or kernel integration. The wrapper handles all of that.

Second, it allows the same agent to be wrapped differently for different purposes. A test wrapper might add logging or instrumentation. A production wrapper might be minimal. Multiple wrappers can exist for the same agent.

Third, it provides a natural boundary for the imageId. The imageId is computed from the compiled zkVM guest, which includes the wrapper. If you want a new imageId (perhaps to register a new agent version), you create a new wrapper. The agent crate itself doesn't need to change.

Fourth, it keeps kernel-guest dependencies minimal. The kernel-guest crate doesn't depend on any specific agent—it only depends on the trait definition. This makes the kernel smaller, faster to compile, and easier to audit.

## From Agent to zkVM Program

The journey from agent source code to executable zkVM program involves several compilation steps, each producing artifacts that matter for the protocol.

The agent crate compiles first. During this compilation, a build script (build.rs) computes the agent_code_hash by hashing the agent's source files. This hash is embedded as a constant in the compiled agent library.

The wrapper crate compiles next. It links against the agent crate and implements `AgentEntrypoint`. The wrapper's `code_hash()` method returns the agent_code_hash from the agent crate.

The zkvm-guest crate compiles last. This is the actual zkVM entry point—it has a `main()` function that reads input from the zkVM environment, calls the wrapper's `kernel_main()` function, and commits the result to the journal. The zkvm-guest is compiled to a RISC-V ELF binary targeting the RISC Zero zkVM.

The risc0-methods build process then takes this ELF binary and computes its imageId. The imageId is a cryptographic hash of the binary contents. It uniquely identifies this specific combination of kernel + wrapper + agent.

At the end of this process, you have:

- **agent_code_hash**: A hash of the agent source, embedded in the binary
- **ZKVM_GUEST_ELF**: The compiled zkVM guest binary
- **ZKVM_GUEST_ID**: The imageId, a hash of the ELF

These artifacts are used for deployment. The imageId is registered with the on-chain verifier. The ELF is used by the prover to generate proofs. The agent_code_hash appears in journals and can be verified on-chain.

## Agent Lifecycle

An agent's lifecycle in production looks like this:

1. **Development**: The agent developer writes the agent crate with its `agent_main` function. They test locally using the host-tests framework, which runs the kernel outside the zkVM for fast iteration.

2. **Integration**: The developer creates a wrapper crate and builds the zkVM guest. They run e2e-tests to verify that proof generation works and produces the expected journal contents.

3. **Deployment**: The imageId is registered with the KernelExecutionVerifier contract, associating it with a specific agent identifier. The vault is configured to trust this agent.

4. **Execution**: When the agent needs to run, an off-chain coordinator constructs the `KernelInputV1` with the appropriate inputs, runs the prover to generate a proof, and submits the proof to the vault.

5. **Verification**: The vault calls the verifier contract, which checks the proof against the registered imageId. If valid, the vault parses the journal and executes the agent's actions.

6. **Upgrades**: If the agent needs to be updated, the developer modifies the agent crate, creates a new wrapper, builds a new ELF with a new imageId, and registers the new imageId on-chain. The old version can be deprecated or kept active depending on governance decisions.

Throughout this lifecycle, the separation between agent, wrapper, and kernel remains clear. Each component can evolve independently, and the cryptographic bindings ensure that only the expected combinations can produce valid proofs.
