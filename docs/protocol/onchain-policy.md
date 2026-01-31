# On-Chain Execution Policy

This document describes the security model and execution policy enforced by KernelVault when processing verified agent actions. Understanding the division of responsibility between on-chain contracts and off-chain constraint enforcement is critical for vault operators and integrators.

## Trust Model

The Execution Kernel protocol operates with a clear separation of concerns:

**Off-chain (zkVM Kernel):**
- Validates agent code hash matches registered agent
- Enforces constraint policies (position limits, asset whitelists, cooldowns)
- Produces cryptographic commitments binding proof to specific actions
- Determines execution status (Success or Failure)

**On-chain (KernelVault):**
- Verifies RISC Zero proof is valid
- Validates agent ID matches vault configuration
- Enforces nonce ordering for replay protection
- Verifies action commitment matches provided actions
- Atomically executes actions exactly as proven

The vault does not re-validate constraints. If a proof passes verification and status is Success, the vault trusts that the kernel has already enforced all constraint policies. This design keeps on-chain gas costs low while maintaining security through cryptographic binding.

## Action Commitment Binding

Every KernelJournalV1 contains an `action_commitment` field, which is the SHA-256 hash of the encoded AgentOutput. When `execute()` is called:

1. The vault computes `sha256(agentOutputBytes)` from the provided action data
2. It compares this against `parsed.actionCommitment` from the verified journal
3. If they differ, execution reverts with `ActionCommitmentMismatch`

This binding ensures that the actions executed on-chain are exactly the actions that were proven in the zkVM. An attacker cannot substitute different actions because doing so would produce a different commitment that won't match the proof.

## Nonce Ordering and Replay Protection

Each execution carries a monotonically increasing `execution_nonce`. The vault enforces:

- **Replay prevention**: Nonces must be strictly greater than `lastExecutionNonce`
- **Gap tolerance**: The gap between nonces cannot exceed `MAX_NONCE_GAP` (100)

The gap tolerance exists for liveness: if proof N is lost or stuck, proofs N+1 through N+100 can still be executed. Skipped nonces are permanently lost and emit a `NoncesSkipped` event for observability.

```solidity
if (providedNonce <= lastNonce) revert InvalidNonce(lastNonce, providedNonce);
if (gap > MAX_NONCE_GAP) revert NonceGapTooLarge(lastNonce, providedNonce, MAX_NONCE_GAP);
```

## Execution Status Policy

The journal includes an `execution_status` field:
- `0x01` (Success): Constraints passed, actions should be executed
- `0x02` (Failure): Constraints violated, action_commitment is empty output

The KernelExecutionVerifier rejects journals with Failure status before they reach the vault. This prevents any state changes when constraints were violated during kernel execution.

## Atomic Execution

All actions within a single `execute()` call are atomic. If any action fails (e.g., insufficient balance, target reverts), the entire transaction reverts and no state changes persist.

This atomicity is critical for maintaining invariants. An agent producing a multi-action output (transfer A, then call B) can rely on both actions either succeeding together or failing together.

## Action Execution Details

### TRANSFER_ERC20 (0x03)

Transfers tokens from the vault to a recipient. The vault enforces:

- Token address must match `vault.asset` (single-asset MVP restriction)
- Payload must be exactly 96 bytes (ABI-encoded token, to, amount)

```solidity
IERC20(token).transfer(to, amount)
```

### CALL (0x02)

Invokes an arbitrary contract method with optional ETH value. The vault enforces:

- Target must be a valid EVM address (upper 12 bytes of target must be zero)
- Payload must be at least 64 bytes (ABI-encoded value, calldata)

```solidity
target.call{value: value}(callData)
```

If the call returns `success = false`, the vault reverts with `CallFailed(target, returnData)`.

### NO_OP (0x04)

A placeholder action that updates `lastExecutionTimestamp` but performs no state changes. Useful for heartbeat signals or padding.

## Why Commitments Prevent Tampering

Consider an attacker who has a valid proof for transferring 100 USDC to Alice. They want to modify the actions to transfer 1,000,000 USDC to themselves instead.

1. The proof binds to a specific `action_commitment`
2. The commitment is SHA-256(encoded_actions) for 100 USDC to Alice
3. Changing any detail (amount, recipient, token) produces a different commitment
4. The vault computes sha256(attacker's modified actions) and compares
5. Mismatch → revert

The attacker cannot produce a valid proof for their modified actions without access to the agent's private key and re-running the zkVM execution. The proof verification would also fail because the journal digest (which includes the commitment) would differ.

## Failure Handling Summary

| Failure Mode | On-Chain Effect | Error |
|-------------|-----------------|-------|
| Proof verification fails | Revert | (from verifier) |
| Journal status = Failure | Revert | `ExecutionFailed(status)` |
| Agent ID mismatch | Revert | `AgentIdMismatch(expected, actual)` |
| Nonce ≤ lastNonce | Revert | `InvalidNonce(lastNonce, providedNonce)` |
| Nonce gap > 100 | Revert | `NonceGapTooLarge(lastNonce, providedNonce, 100)` |
| Commitment mismatch | Revert | `ActionCommitmentMismatch(expected, actual)` |
| Action execution fails | Revert | `CallFailed` / `TransferFailed` |
| Unknown action type | Revert | `UnknownActionType(actionType)` |
| Invalid payload format | Revert | `InvalidTransferPayload` / `InvalidCallPayload` |

## Testing Execution Semantics

The test suite `KernelVault.ExecutionSemantics.t.sol` validates all execution behaviors using a mock verifier that returns configurable journal values without requiring actual proofs. This enables comprehensive testing of:

- Action side effects (balance changes, storage updates)
- Atomicity guarantees (rollback on partial failure)
- Failure mode error messages and conditions
- Event emission and nonce management
- Golden vector commitment compatibility
