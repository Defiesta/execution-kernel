# Binary Format Specification

This document describes the binary formats shared between the Rust zkVM kernel and the Solidity contracts. All formats are byte-for-byte aligned with the Rust implementation in `kernel-core`.

## KernelJournalV1 (209 bytes)

The journal is the output committed by the zkVM kernel after execution.

| Offset | Field | Type | Size | Endianness |
|--------|-------|------|------|------------|
| 0-3 | protocol_version | u32 | 4 | Little-endian |
| 4-7 | kernel_version | u32 | 4 | Little-endian |
| 8-39 | agent_id | bytes32 | 32 | Raw bytes |
| 40-71 | agent_code_hash | bytes32 | 32 | Raw bytes |
| 72-103 | constraint_set_hash | bytes32 | 32 | Raw bytes |
| 104-135 | input_root | bytes32 | 32 | Raw bytes |
| 136-143 | execution_nonce | u64 | 8 | Little-endian |
| 144-175 | input_commitment | bytes32 | 32 | Raw bytes |
| 176-207 | action_commitment | bytes32 | 32 | Raw bytes |
| 208 | execution_status | u8 | 1 | Single byte (0x01=Success, 0x02=Failure) |

## AgentOutput

The `AgentOutput` contains the actions produced by the agent. The `action_commitment` in the journal is `sha256(AgentOutput bytes)`.

### Overall Structure

```
[action_count: u32 LE]           # Number of actions (max 64)
[action 0]
[action 1]
...
[action N-1]
```

### Per-Action Structure

```
[action_len: u32 LE]             # Length of ActionV1 bytes (NOT included in size limit)
[ActionV1 bytes]:                # Bounded by MAX_SINGLE_ACTION_BYTES (16424)
  [action_type: u32 LE]          # 4 bytes
  [target: bytes32]              # 32 bytes
  [payload_len: u32 LE]          # 4 bytes
  [payload: bytes]               # Up to MAX_ACTION_PAYLOAD_BYTES (16384)
```

### Size Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_ACTIONS_PER_OUTPUT` | 64 | Maximum actions per AgentOutput |
| `MAX_ACTION_PAYLOAD_BYTES` | 16,384 | Maximum payload size per action |
| `MAX_SINGLE_ACTION_BYTES` | 16,424 | Maximum ActionV1 encoded size (40 + payload) |

**Important**: `MAX_SINGLE_ACTION_BYTES` bounds the `action_len` value (the ActionV1 encoding), NOT the full wire encoding which includes an additional 4-byte length prefix. This matches the Rust implementation in `kernel-core/src/types.rs`.

### Action Types

| Type | Value | Payload Format | Description |
|------|-------|----------------|-------------|
| `ACTION_TYPE_CALL` | `0x00000002` | `abi.encode(uint256 value, bytes callData)` | Generic contract call |
| `ACTION_TYPE_TRANSFER_ERC20` | `0x00000003` | `abi.encode(address token, address to, uint256 amount)` | ERC20 token transfer |

## Cross-Implementation Alignment

The Solidity contracts (`KernelOutputParser.sol`, `KernelExecutionVerifier.sol`) are intentionally byte-for-byte aligned with the Rust implementation. Key alignment points:

1. **Integer encoding**: All integers use little-endian byte order
2. **Size validation**: Both implementations validate `action_len` against `MAX_SINGLE_ACTION_BYTES`, excluding the 4-byte length prefix
3. **Constants**: All size constants match between Rust (`kernel-core/src/types.rs`) and Solidity (`KernelOutputParser.sol`)

This ensures that any valid output from the zkVM kernel will be correctly parsed by the Solidity contracts, and any invalid output will be rejected by both.
