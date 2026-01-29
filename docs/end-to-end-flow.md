# End-to-End Flow

This document traces the complete lifecycle of an agent execution, from the moment a capital allocator decides to run their strategy through the on-chain execution of the resulting actions. Understanding this flow is essential for integrators who need to know what happens at each stage and why.

## The Starting Point

Consider a capital allocator who has deposited funds into a vault. The vault is configured to trust a specific agent, identified by its imageId registered with the on-chain verifier. The allocator wants the agent to analyze current market conditions and potentially rebalance their position.

The allocator (or an automated system acting on their behalf) gathers the inputs the agent needs: perhaps oracle prices, current positions, risk parameters, or other relevant data. These inputs are serialized into the `opaque_agent_inputs` field of `KernelInputV1`.

The complete input structure includes:

- Protocol and kernel versions (for compatibility checking)
- The agent_id (identifying which vault/account this execution is for)
- The agent_code_hash (which agent should run)
- The constraint_set_hash and input_root (for additional verification)
- The execution_nonce (preventing replay attacks)
- The opaque_agent_inputs (the actual data for the agent)

This structure is encoded using the deterministic binary codec. The encoded bytes are what will be fed into the zkVM.

## Off-Chain Execution

The prover—a machine with the RISC Zero toolchain and sufficient computational resources—receives the encoded input and begins proof generation.

The prover loads the zkVM guest ELF (the compiled binary containing the kernel and agent) and initializes the zkVM environment with the input bytes. It then executes the guest program:

1. The zkVM guest reads the input bytes from its environment
2. It calls the kernel's entry point, passing the input
3. The kernel decodes and validates `KernelInputV1`
4. The kernel verifies that the embedded agent_code_hash matches what was declared in the input
5. The kernel computes the input_commitment (SHA-256 of the raw input bytes)
6. The kernel invokes the agent through the `AgentEntrypoint` trait
7. The agent parses its opaque inputs and produces an `AgentOutput`
8. The kernel runs the constraint engine on the agent's output
9. If constraints pass, the kernel computes the action_commitment (SHA-256 of the encoded output)
10. The kernel constructs `KernelJournalV1` with all commitments and the execution status
11. The kernel encodes the journal and returns it
12. The zkVM guest commits the journal bytes to the proof

While this execution happens, the zkVM records every operation. After execution completes, the prover uses this record to construct a cryptographic proof—specifically, a Groth16 proof that can be verified efficiently on-chain.

The proof generation is computationally intensive, potentially taking minutes for complex executions. The result is a receipt containing the proof (called the "seal") and the journal (the public outputs of the computation).

## What the Journal Contains

The journal is the publicly visible output of the zkVM execution. It's what the on-chain verifier and vault will use to determine what happened. The journal contains:

**Protocol and kernel versions** allow on-chain contracts to reject proofs from incompatible protocol versions. This provides a clean upgrade path—old proofs aren't valid for new protocol versions.

**Identity fields** (agent_id, agent_code_hash, constraint_set_hash, input_root, execution_nonce) are copied from the input and appear in the journal. This allows on-chain verification that the proof corresponds to the expected execution context.

**Input commitment** is the SHA-256 hash of the raw input bytes. Anyone who knows what inputs were provided can verify this matches. This binds the proof to specific inputs without revealing them on-chain.

**Action commitment** is the SHA-256 hash of the encoded `AgentOutput`. For successful executions, this commits to exactly what actions the agent produced. For failed executions, this is set to the well-known empty output commitment.

**Execution status** indicates whether the execution succeeded or failed. Success means the agent produced valid output that passed constraint checking. Failure means the agent's output violated constraints.

The journal is exactly 209 bytes—a fixed size that makes on-chain parsing straightforward and gas-efficient.

## Proof Submission

The off-chain coordinator now has a receipt containing the Groth16 proof and the journal. To execute the agent's actions, it must submit this to the vault.

The submission call includes three pieces of data:

1. **The journal** (209 bytes) — the kernel's output
2. **The seal** (260 bytes with selector) — the Groth16 proof
3. **The agent output bytes** — the actual `AgentOutput` that the agent produced

The agent output bytes aren't technically necessary for verification—the journal contains a commitment to them. But the vault needs to know what actions to execute, and providing the full output is more gas-efficient than having the agent embed full action data in the journal.

## On-Chain Verification

The vault receives the submission and begins verification.

First, it calls the KernelExecutionVerifier contract with the journal and seal. The verifier:

1. Extracts the agent_id from the journal
2. Looks up the registered imageId for that agent
3. Calls the RISC Zero verifier router with the seal, journal, and expected imageId
4. The router verifies the Groth16 proof

If verification fails, the transaction reverts. No actions are executed.

If verification succeeds, the proof is valid. The verifier has cryptographic certainty that:

- The journal was produced by a zkVM guest with the registered imageId
- That guest executed the kernel with the agent bound to that imageId
- The kernel ran to completion and produced this journal honestly

## Parsing and Validation

After proof verification, the vault parses the journal using the KernelOutputParser library:

```solidity
KernelOutputParser.ParsedJournal memory parsed = KernelOutputParser.parse(journal);
```

The parser extracts all fields from the journal's binary format. The vault then performs additional validation:

- Does the agent_id match this vault's configured agent?
- Is the execution_nonce correct (prevents replay)?
- Is the execution_status Success?

If any of these checks fail, the transaction reverts or handles the failure gracefully.

For successful executions, the vault verifies that the provided agent output bytes hash to the action_commitment in the journal:

```solidity
require(
    sha256(agentOutputBytes) == parsed.actionCommitment,
    "Action commitment mismatch"
);
```

This ensures that the agent output bytes haven't been tampered with—they're exactly what the agent produced inside the zkVM.

## Action Execution

The vault now has verified, authenticated actions from the agent. It decodes the `AgentOutput` structure and iterates through the actions.

For each action, the vault checks the action type and executes accordingly:

**CALL actions** result in the vault calling the target address with the specified value and calldata. This is how agents interact with DeFi protocols—depositing into yield sources, executing swaps, managing positions.

**TRANSFER_ERC20 actions** result in the vault transferring tokens. The vault parses the token address, recipient, and amount from the payload and calls the token's transfer function.

Each action type has specific validation. CALL actions verify that the target is properly formatted (the upper 12 bytes of the 32-byte target must be zero, indicating an Ethereum address). TRANSFER_ERC20 actions verify the payload contains valid addresses and amounts.

If any action fails (perhaps the vault has insufficient balance, or the target contract reverts), the entire transaction reverts. This atomicity ensures that either all actions execute or none do—there's no partial state.

## Failure Cases

Not every execution succeeds, and the system handles failures at multiple levels.

**Constraint violations** occur when the agent produces output that doesn't conform to the constraint set. Perhaps the agent tried to exceed position limits, or produced an unrecognized action type. The kernel detects this, sets `execution_status = Failure`, and returns a journal with the empty output commitment. The proof is valid—it proves that the agent tried something invalid. The on-chain vault can verify this proof but will see the Failure status and decline to execute any actions.

**Hard failures** occur when something is fundamentally wrong—malformed input, wrong protocol version, agent_code_hash mismatch. The kernel panics, proof generation aborts, and no valid proof is produced. This is appropriate because these failures indicate bugs or attacks, not legitimate agent behavior.

**On-chain failures** can occur even with valid proofs. Perhaps the nonce is wrong (replay attempt), or the vault's state has changed since the proof was generated, or the agent's actions are no longer possible. The transaction reverts, but the proof remains valid—it could potentially be resubmitted if the on-chain state permits.

The important property is that the zkVM guarantees are preserved across all cases. A valid proof always means the kernel executed correctly with the declared agent. The execution status tells you whether that execution succeeded or failed. And the commitments bind everything together cryptographically.

## The Security Model

This end-to-end flow achieves several security properties:

**No custody transfer.** The agent never has custody of funds. It produces instructions that the vault executes. If an agent is buggy or malicious, the worst it can do is produce invalid instructions (which fail constraint checks) or valid instructions that the capital allocator didn't intend (which is a governance/configuration problem, not a security breach).

**Verifiable execution.** Every claim is backed by cryptographic proof. The proof covers the entire execution—input parsing, agent logic, constraint checking, output encoding. There's no trusted intermediary who could lie about what happened.

**Deterministic replay.** Given the input bytes and the imageId, anyone can re-execute the computation and verify they get the same result. The zkVM doesn't add any magic—it just proves that standard computation happened correctly.

**Atomic commitment.** The journal commits to both inputs and outputs atomically. You can't have a valid proof that commits to different inputs than were actually used, or different outputs than were actually produced.

**Replay protection.** The execution_nonce ensures that each proof can only be used once. Even if an attacker obtains a valid proof, they can't replay it—the vault will reject the stale nonce.

**Upgrade safety.** Protocol versions in the journal allow contracts to reject proofs from deprecated kernel versions. ImageId registration allows precise control over which agent versions are authorized.

## Practical Considerations

Several practical aspects affect how the flow works in production.

**Proof generation time** varies with execution complexity and prover hardware. Simple agents might prove in a minute; complex ones might take longer. The off-chain coordinator needs appropriate hardware and timeout handling.

**Gas costs** for on-chain verification are significant but fixed. The Groth16 verification is constant-cost regardless of what the agent did. Parsing and action execution add variable costs depending on the number and complexity of actions.

**Latency** from decision to execution includes proof generation time plus transaction confirmation time. For time-sensitive strategies, this may be a constraint. The architecture supports batching multiple independent executions if needed.

**State synchronization** matters because the agent runs with a snapshot of inputs, but the on-chain state can change before the proof is submitted. Agents should be designed to handle this—perhaps by including slippage tolerances or validity windows in their logic.

**Error handling** on the coordinator side should distinguish between proof generation failures (retry with same inputs), constraint violations (review agent logic), and on-chain failures (check state, possibly retry).

The system is designed to make these practical considerations manageable while maintaining the core security properties. The cryptographic guarantees don't depend on the coordinator being trusted—they hold as long as the zkVM and on-chain verifier are correct.
