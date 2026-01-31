# ActionV1 Specification

This document defines the canonical encoding and semantics of on-chain executable actions
in the Execution Kernel protocol (v1). ActionV1 is the fundamental unit of work that agents
propose and KernelVault executes.

## Design Philosophy

ActionV1 represents executable-only actions. Each action type maps directly to an on-chain
operation that KernelVault performs upon proof verification. The protocol intentionally
excludes abstract or domain-specific concepts like "open position" or "swap" — agents must
compile their intent into primitive CALL or TRANSFER_ERC20 operations.

This constraint ensures that action semantics are unambiguous: what gets proven is exactly
what gets executed.

## Wire Format

ActionV1 uses a length-prefixed encoding with little-endian integers:

```
┌─────────────────┬──────────────┬───────────────────┬───────────────┬─────────────┐
│ action_len (u32)│ action_type  │ target (bytes32)  │ payload_len   │ payload     │
│ 4 bytes, LE     │ u32, 4B LE   │ 32 bytes          │ u32, 4B LE    │ variable    │
└─────────────────┴──────────────┴───────────────────┴───────────────┴─────────────┘
```

The `action_len` field contains the total size of the ActionV1 encoding that follows
(action_type + target + payload_len + payload), not including the 4-byte prefix itself.

## Action Types

The protocol defines exactly three executable action types:

| Type           | Value        | Purpose                        |
|----------------|--------------|--------------------------------|
| CALL           | `0x00000002` | Generic contract call          |
| TRANSFER_ERC20 | `0x00000003` | ERC20 token transfer           |
| NO_OP          | `0x00000004` | Placeholder (skipped)          |

A fourth type, ECHO (`0x00000001`), exists for testing but is not executable on-chain
and is gated behind compile-time feature flags.

### Target Encoding

The `target` field is a 32-byte value representing an EVM address with left-padding:

```
┌────────────────────────┬────────────────────────────────────────┐
│ 12 zero bytes          │ 20-byte EVM address                    │
│ 0x000000000000...      │ 0x1234567890abcdef...                  │
└────────────────────────┴────────────────────────────────────────┘
```

Constraint validation ensures the upper 12 bytes are zero for CALL actions.

## CALL Action

CALL actions invoke arbitrary contract methods with optional ETH value.

**On-chain execution:**
```solidity
target.call{value: value}(callData)
```

**Payload format:** ABI-encoded `abi.encode(uint256 value, bytes callData)`

```
Offset   Field          Type       Size     Description
──────────────────────────────────────────────────────────────────
0        value          uint256    32       ETH to send (big-endian)
32       offset         uint256    32       Offset to bytes data (always 64)
64       length         uint256    32       Length of callData
96       callData       bytes      var      Function selector + arguments
```

The minimum payload size is 96 bytes (value + offset + length + zero-length callData).
The callData portion is padded to a 32-byte boundary per ABI encoding rules.

**Example:** Transfer 1 ETH to a contract with selector `0xabcdef12`

```
value:    0x000...0de0b6b3a7640000  (1e18 in hex, 32 bytes BE)
offset:   0x000...40                 (64, pointer to bytes data)
length:   0x000...04                 (4 bytes of calldata)
callData: 0xabcdef12000...           (selector, padded to 32 bytes)
```

## TRANSFER_ERC20 Action

TRANSFER_ERC20 actions transfer tokens from the vault to a recipient.

**On-chain execution:**
```solidity
IERC20(token).transfer(to, amount)
```

**Payload format:** ABI-encoded `abi.encode(address token, address to, uint256 amount)`

```
Offset   Field    Type       Size     Description
──────────────────────────────────────────────────────────────────
0        token    address    32       Token address (left-padded)
32       to       address    32       Recipient address (left-padded)
64       amount   uint256    32       Amount to transfer (big-endian)
```

The payload is exactly 96 bytes. Both addresses use the same left-padding as `target`.

**Target field:** Unused for TRANSFER_ERC20; set to zero bytes.

## NO_OP Action

NO_OP actions are skipped during execution. They exist for padding or as placeholders.

**Payload:** Must be empty (0 bytes).

**Target field:** Set to zero bytes.

## AgentOutput Encoding

Multiple actions are wrapped in an AgentOutput structure:

```
┌──────────────────┬─────────────────┬─────────────────┬─────┐
│ action_count     │ ActionV1[0]     │ ActionV1[1]     │ ... │
│ u32, 4 bytes LE  │ (prefixed)      │ (prefixed)      │     │
└──────────────────┴─────────────────┴─────────────────┴─────┘
```

Each ActionV1 includes its own 4-byte length prefix as shown in the wire format above.

## Size Limits

| Constant                  | Value    | Enforced By            |
|---------------------------|----------|------------------------|
| MAX_ACTIONS_PER_OUTPUT    | 64       | Rust codec, Solidity   |
| MAX_ACTION_PAYLOAD_BYTES  | 16,384   | Rust codec, Solidity   |
| MAX_SINGLE_ACTION_BYTES   | 16,424   | Rust codec, Solidity   |
| MAX_AGENT_OUTPUT_BYTES    | 64,000   | Rust codec             |

## Commitment Computation

The `action_commitment` in KernelJournalV1 binds the proof to the specific actions:

```
action_commitment = SHA-256(encoded_agent_output_bytes)
```

This commitment is computed over the complete AgentOutput encoding, including the
action_count prefix and all length-prefixed actions. Agents and verifiers use this
commitment to ensure the decoded actions match what was proven.

For constraint failures, the commitment is computed over an empty AgentOutput:

```
empty_output = AgentOutput { actions: [] }
encoded = [0x00, 0x00, 0x00, 0x00]  // action_count = 0
EMPTY_OUTPUT_COMMITMENT = SHA-256(encoded)
                        = df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119
```

## Cross-Language Alignment

The encoding and constants are intentionally identical between:

- **Rust** (`kernel-core`, `kernel-sdk`, `constraints` crates)
- **Solidity** (`KernelOutputParser.sol`, `KernelVault.sol`)

Both implementations validate the same limits and reject malformed data identically.
The golden vectors in `crates/protocol/kernel-core/tests/fixtures/action_vectors.json`
provide cross-language conformance tests to prevent drift.

## Constraint Validation

The constraint engine validates actions before commitment:

| Check                           | Violation Reason         |
|---------------------------------|--------------------------|
| Unknown action_type             | `UnknownActionType`      |
| CALL payload < 96 bytes         | `InvalidActionPayload`   |
| CALL offset != 64               | `InvalidActionPayload`   |
| CALL target upper 12 bytes != 0 | `InvalidActionPayload`   |
| TRANSFER_ERC20 payload != 96    | `InvalidActionPayload`   |
| TRANSFER_ERC20 address padding  | `InvalidActionPayload`   |
| NO_OP payload not empty         | `InvalidActionPayload`   |

Constraint violations result in `ExecutionStatus::Failure` with the action_commitment
set to `EMPTY_OUTPUT_COMMITMENT`.
