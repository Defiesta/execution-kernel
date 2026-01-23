# Canonical Codec and Commitments

This document specifies the canonical binary encoding for all kernel protocol types.
All implementations MUST produce identical byte sequences for the same logical values.

## Design Principles

1. **Deterministic**: Same logical value always encodes to identical bytes
2. **Self-describing lengths**: Variable-length fields use length prefixes
3. **Little-endian**: All multi-byte integers use little-endian byte order
4. **Strict decoding**: Trailing bytes and invalid values are rejected
5. **Bounded sizes**: All fields have explicit size limits

---

## Primitive Types

### Integers

| Type | Size | Encoding |
|------|------|----------|
| `u32` | 4 bytes | Little-endian |
| `u64` | 8 bytes | Little-endian |

### Fixed-Size Byte Arrays

| Type | Size | Encoding |
|------|------|----------|
| `[u8; 32]` | 32 bytes | Raw bytes (no prefix) |

### Variable-Length Byte Arrays

```
┌────────────┬────────────────┐
│ length: u32│ data: [u8]     │
└────────────┴────────────────┘
```

- Length prefix is u32 little-endian
- Data follows immediately
- Maximum lengths are type-specific

---

## KernelInputV1

Total size: 148 + `opaque_agent_inputs.len()` bytes

```
Offset │ Field                 │ Type      │ Size
───────┼───────────────────────┼───────────┼──────
0      │ protocol_version      │ u32       │ 4
4      │ kernel_version        │ u32       │ 4
8      │ agent_id              │ [u8; 32]  │ 32
40     │ agent_code_hash       │ [u8; 32]  │ 32
72     │ constraint_set_hash   │ [u8; 32]  │ 32
104    │ input_root            │ [u8; 32]  │ 32
136    │ execution_nonce       │ u64       │ 8
144    │ opaque_agent_inputs   │ Vec<u8>   │ 4 + len
```

### Validation Rules (Decode)

1. `protocol_version` MUST equal `PROTOCOL_VERSION` (1)
2. `kernel_version` MUST equal `KERNEL_VERSION` (1)
3. `opaque_agent_inputs.len()` MUST NOT exceed `MAX_AGENT_INPUT_BYTES` (64,000)
4. Total bytes consumed MUST equal input length (no trailing bytes)

---

## KernelJournalV1

Fixed size: 209 bytes

```
Offset │ Field                 │ Type            │ Size
───────┼───────────────────────┼─────────────────┼──────
0      │ protocol_version      │ u32             │ 4
4      │ kernel_version        │ u32             │ 4
8      │ agent_id              │ [u8; 32]        │ 32
40     │ agent_code_hash       │ [u8; 32]        │ 32
72     │ constraint_set_hash   │ [u8; 32]        │ 32
104    │ input_root            │ [u8; 32]        │ 32
136    │ execution_nonce       │ u64             │ 8
144    │ input_commitment      │ [u8; 32]        │ 32
176    │ action_commitment     │ [u8; 32]        │ 32
208    │ execution_status      │ ExecutionStatus │ 1
```

### Validation Rules (Decode)

1. `protocol_version` MUST equal `PROTOCOL_VERSION` (1)
2. `kernel_version` MUST equal `KERNEL_VERSION` (1)
3. `execution_status` MUST be valid (0x01 or 0x02)
4. Total bytes MUST equal 209 (no trailing bytes)

---

## ExecutionStatus

Single byte encoding:

| Value | Name | Description |
|-------|------|-------------|
| `0x00` | Reserved | Invalid (catches uninitialized memory) |
| `0x01` | `Success` | Execution completed and all constraints passed |
| `0x02` | `Failure` | Execution completed but constraints violated |
| `0x03-0xFF` | Reserved | Reserved for future use |

### Rationale

- `0x00` is deliberately invalid to catch uninitialized memory bugs
- `0x01` for Success follows boolean conventions (1 = true = success)
- `0x02` for Failure distinguishes constraint violations from panics/aborts

### P0.3 Failure Semantics

When `execution_status == Failure`:
- `action_commitment` is computed over an **empty AgentOutput** `{ actions: [] }`
- The empty output encodes to `[0x00, 0x00, 0x00, 0x00]`
- `action_commitment = SHA-256([0x00, 0x00, 0x00, 0x00])` = `df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119`

---

## ActionV1

Variable size: 40 + `payload.len()` bytes

```
Offset │ Field        │ Type     │ Size
───────┼──────────────┼──────────┼──────
0      │ action_type  │ u32      │ 4
4      │ target       │ [u8; 32] │ 32
36     │ payload      │ Vec<u8>  │ 4 + len
```

### Validation Rules (Decode)

1. `payload.len()` MUST NOT exceed `MAX_ACTION_PAYLOAD_BYTES` (16,384)
2. Total bytes consumed MUST equal input length (no trailing bytes)

### Canonical Ordering

Actions are sorted before encoding for determinism:

1. Primary: `action_type` (ascending)
2. Secondary: `target` (lexicographic)
3. Tertiary: `payload` (lexicographic)

Note: `payload_len` is NOT part of the sort key (it's derivable from payload).

---

## AgentOutput

Variable size: 4 + sum of encoded action sizes

```
┌───────────────┬──────────────────────────────────┐
│ action_count  │ actions[0..action_count]         │
│ (u32)         │ (length-prefixed ActionV1 list)  │
└───────────────┴──────────────────────────────────┘
```

Each action is prefixed with its encoded length:
```
┌────────────┬──────────────────┐
│ action_len │ ActionV1 bytes   │
│ (u32)      │ (action_len)     │
└────────────┴──────────────────┘
```

### Size Limits

- `action_count` MUST NOT exceed `MAX_ACTIONS_PER_OUTPUT` (64)
- Each `action_len` MUST NOT exceed `MAX_SINGLE_ACTION_BYTES` (16,424)

### Maximum Encoded Size

```
max_size = 4 + 64 * (4 + 4 + 32 + 4 + 16384)
         = 4 + 64 * 16428
         = 1,051,396 bytes (~1 MB)
```

### Canonicalization

The `encode()` method automatically sorts actions into canonical order.
This ensures identical outputs regardless of the order actions were added.

---

## Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `PROTOCOL_VERSION` | 1 | Current protocol version |
| `KERNEL_VERSION` | 1 | Current kernel version |
| `MAX_AGENT_INPUT_BYTES` | 64,000 | Maximum opaque_agent_inputs size |
| `MAX_ACTIONS_PER_OUTPUT` | 64 | Maximum actions per output |
| `MAX_ACTION_PAYLOAD_BYTES` | 16,384 | Maximum payload per action |
| `MAX_SINGLE_ACTION_BYTES` | 16,424 | Maximum encoded action size |
| `EMPTY_OUTPUT_COMMITMENT` | `df3f61...` | SHA-256 of empty AgentOutput |

---

## Error Handling

### CodecError Variants

| Variant | Description |
|---------|-------------|
| `InvalidLength` | Trailing bytes after valid data |
| `InvalidVersion { expected, actual }` | Version mismatch |
| `InputTooLarge { size, limit }` | opaque_agent_inputs exceeds limit |
| `OutputTooLarge { size, limit }` | Output exceeds size limit |
| `UnexpectedEndOfInput` | Insufficient bytes for decoding |
| `InvalidExecutionStatus(u8)` | Invalid status byte |
| `ArithmeticOverflow` | Integer overflow during size calculation |
| `TooManyActions { count, limit }` | Action count exceeds limit |
| `ActionPayloadTooLarge { size, limit }` | Payload exceeds limit |
| `ActionTooLarge { size, limit }` | Encoded action exceeds limit |

---

## Commitment Computation

### Input Commitment

```
input_commitment = SHA-256(encoded_kernel_input_v1)
```

The commitment is computed over the entire encoded KernelInputV1 bytes.

### Action Commitment

```
action_commitment = SHA-256(encoded_agent_output)
```

The commitment is computed over the canonicalized, encoded AgentOutput.

On constraint failure (P0.3):
```
empty_output = AgentOutput { actions: [] }
encoded = [0x00, 0x00, 0x00, 0x00]
action_commitment = SHA-256(encoded) = df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119
```

---

## Test Vectors

Golden test vectors are available in `tests/vectors/`:
- `kernel_input_v1.json` - KernelInputV1 encoding vectors
- `kernel_journal_v1.json` - KernelJournalV1 encoding vectors
- `constraints/constraint_vectors.json` - Constraint enforcement vectors

Each vector includes:
- Encoded hex bytes
- Decoded field values
- SHA-256 commitment (where applicable)
