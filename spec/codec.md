# Canonical Codec Specification

This document specifies the canonical binary encoding for the kernel protocol (version 1).
All encodings are deterministic and consensus-critical.

## Design Principles

1. **Determinism**: Identical data structures always produce identical byte sequences
2. **Self-describing lengths**: Variable-length fields are prefixed with their byte length
3. **Little-endian integers**: All multi-byte integers use little-endian byte order
4. **No implicit padding**: Structures are tightly packed with no alignment padding
5. **Strict decoding**: Trailing bytes, invalid versions, and out-of-range values are rejected

---

## Primitive Encoding Rules

### Integers

| Type | Encoding | Size |
|------|----------|------|
| `u32` | Little-endian | 4 bytes |
| `u64` | Little-endian | 8 bytes |
| `u8` | Raw byte | 1 byte |

### Fixed-Size Byte Arrays

| Type | Encoding | Size |
|------|----------|------|
| `[u8; 32]` | Raw bytes (no length prefix) | 32 bytes |

### Variable-Length Byte Arrays

| Type | Encoding | Size |
|------|----------|------|
| `Vec<u8>` | `[length: u32][data: u8*]` | 4 + length bytes |

The `length` field specifies the **number of bytes** in the data that follows.

---

## KernelInputV1

### Layout

| Offset | Field | Type | Size | Description |
|--------|-------|------|------|-------------|
| 0 | `protocol_version` | u32 | 4 | Wire format version |
| 4 | `kernel_version` | u32 | 4 | Kernel semantics version |
| 8 | `agent_id` | [u8; 32] | 32 | Agent identifier |
| 40 | `agent_code_hash` | [u8; 32] | 32 | SHA-256 of agent binary |
| 72 | `constraint_set_hash` | [u8; 32] | 32 | SHA-256 of constraint set |
| 104 | `input_root` | [u8; 32] | 32 | External state root (market/vault snapshot) |
| 136 | `execution_nonce` | u64 | 8 | Replay protection nonce |
| 144 | `opaque_agent_inputs_len` | u32 | 4 | Length of agent input data (bytes) |
| 148 | `opaque_agent_inputs` | [u8; *] | variable | Agent-specific input (max 64,000 bytes) |

### Size

- **Fixed header**: 148 bytes
- **Total**: 148 + `opaque_agent_inputs_len` bytes
- **Minimum**: 148 bytes (empty input)
- **Maximum**: 148 + 64,000 = 64,148 bytes

### Validation Rules

1. `protocol_version` MUST equal `PROTOCOL_VERSION` (currently 1)
2. `kernel_version` MUST equal `KERNEL_VERSION` (currently 1)
3. `opaque_agent_inputs_len` MUST NOT exceed `MAX_AGENT_INPUT_BYTES` (64,000)
4. Total bytes MUST equal exactly 148 + `opaque_agent_inputs_len` (no trailing bytes)
5. Decoders MUST reject if `148 + opaque_agent_inputs_len` would overflow

---

## KernelJournalV1

### Layout

| Offset | Field | Type | Size | Description |
|--------|-------|------|------|-------------|
| 0 | `protocol_version` | u32 | 4 | Wire format version |
| 4 | `kernel_version` | u32 | 4 | Kernel semantics version |
| 8 | `agent_id` | [u8; 32] | 32 | Agent identifier (copied from input) |
| 40 | `agent_code_hash` | [u8; 32] | 32 | Agent code hash (copied from input) |
| 72 | `constraint_set_hash` | [u8; 32] | 32 | Constraint set hash (copied from input) |
| 104 | `input_root` | [u8; 32] | 32 | External state root (copied from input) |
| 136 | `execution_nonce` | u64 | 8 | Execution nonce (copied from input) |
| 144 | `input_commitment` | [u8; 32] | 32 | SHA-256 of encoded KernelInputV1 |
| 176 | `action_commitment` | [u8; 32] | 32 | SHA-256 of encoded AgentOutput |
| 208 | `execution_status` | u8 | 1 | Execution result |

### Size

- **Fixed**: 209 bytes (always)

### Validation Rules

1. `protocol_version` MUST equal `PROTOCOL_VERSION` (currently 1)
2. `kernel_version` MUST equal `KERNEL_VERSION` (currently 1)
3. `execution_status` MUST equal 0x01 (Success)
4. Total bytes MUST equal exactly 209 (no more, no less)

---

## ExecutionStatus

### Encoding

| Value | Status | Description |
|-------|--------|-------------|
| 0x00 | Reserved | Invalid (catches uninitialized memory) |
| 0x01 | Success | Execution completed successfully |
| 0x02-0xFF | Reserved | Invalid (reserved for future expansion) |

### Rationale

In protocol version 1, the journal is **only published for successful execution**. Failures cause the kernel to abort before committing a journal. Therefore, only 0x01 (Success) is a valid value. The value 0x00 is explicitly reserved to detect bugs where uninitialized memory is accidentally interpreted as a valid status.

Decoders MUST reject any value other than 0x01.

---

## ActionV1

### Layout

| Offset | Field | Type | Size | Description |
|--------|-------|------|------|-------------|
| 0 | `action_type` | u32 | 4 | Action type identifier |
| 4 | `target` | [u8; 32] | 32 | Target address/identifier |
| 36 | `payload_len` | u32 | 4 | Length of payload data (bytes) |
| 40 | `payload` | [u8; *] | variable | Action-specific data (max 16,384 bytes) |

### Size

- **Fixed header**: 40 bytes
- **Total**: 40 + `payload_len` bytes
- **Minimum**: 40 bytes (empty payload)
- **Maximum**: 40 + 16,384 = 16,424 bytes (`MAX_SINGLE_ACTION_BYTES`)

### Validation Rules

1. `payload_len` MUST NOT exceed `MAX_ACTION_PAYLOAD_BYTES` (16,384)
2. Total bytes MUST equal exactly 40 + `payload_len` (no trailing bytes)
3. When embedded in AgentOutput, the `action_len` prefix MUST exactly equal the actual byte length of the ActionV1 encoding (i.e., `action_len == 40 + payload_len`)

---

## AgentOutput

### Layout

| Offset | Field | Type | Size | Description |
|--------|-------|------|------|-------------|
| 0 | `action_count` | u32 | 4 | Number of actions |
| 4 | actions[0..n] | ActionV1[] | variable | Length-prefixed actions |

Each action is encoded as:
- `action_len: u32` (4 bytes) - Byte length of the following ActionV1 encoding
- `action: ActionV1` (variable) - The encoded action

### Size

- **Minimum**: 4 bytes (zero actions)
- **Maximum**: computed as follows:
  - Per-action overhead: `action_len` prefix (4) + `MAX_SINGLE_ACTION_BYTES` (16,424) = 16,428 bytes
  - Total: 4 + `MAX_ACTIONS_PER_OUTPUT` × 16,428 = 4 + 64 × 16,428 = **1,051,396 bytes**

### Validation Rules

1. `action_count` MUST NOT exceed `MAX_ACTIONS_PER_OUTPUT` (64)
2. Each `action_len` MUST NOT exceed `MAX_SINGLE_ACTION_BYTES` (16,424)
3. Each `action_len` MUST exactly equal the number of bytes consumed by the following ActionV1 encoding
4. Exactly `action_count` actions MUST be present; fewer bytes implies `UnexpectedEndOfInput`, more bytes implies `InvalidLength`
5. Total bytes MUST equal the sum of all prefixes and action encodings (no trailing bytes)

---

## Canonical Ordering

Actions MUST be sorted into canonical order before encoding. This ensures deterministic `action_commitment` regardless of the order agents produce actions.

### Ordering Rules

Actions are sorted using lexicographic comparison in this priority:

1. `action_type` (ascending, unsigned integer comparison)
2. `target` (lexicographic byte comparison, 32 bytes)
3. `payload` (lexicographic byte comparison of raw payload bytes)

**Important**: The `payload_len` field is **not** part of the sort key; only the raw payload bytes are compared. Actions with identical `action_type`, `target`, and `payload` bytes are considered equal regardless of encoding.

### Example

Given actions:
- A: `{type: 2, target: 0x11..., payload: [1]}`
- B: `{type: 1, target: 0x22..., payload: [2]}`
- C: `{type: 1, target: 0x11..., payload: [3]}`

Canonical order: **C, B, A**

Reasoning:
1. C and B have `action_type=1`, A has `action_type=2` → A comes last
2. Between C and B: C has `target=0x11...`, B has `target=0x22...` → C comes first (0x11 < 0x22)

---

## Commitment Computation

### Input Commitment

```
input_commitment = SHA-256(encoded_KernelInputV1)
```

The commitment is computed over the **complete canonical encoding** of KernelInputV1, including:
- All fixed header fields (148 bytes)
- The `opaque_agent_inputs_len` length prefix (4 bytes)
- The `opaque_agent_inputs` data bytes

### Action Commitment

```
action_commitment = SHA-256(encoded_AgentOutput)
```

The commitment is computed over the **complete canonical encoding** of AgentOutput, including:
- The `action_count` field (4 bytes)
- All `action_len` prefixes and ActionV1 encodings
- Actions MUST be in canonical order (see Canonical Ordering)

---

## Error Handling

### Codec Errors

| Error | Condition |
|-------|-----------|
| `UnexpectedEndOfInput` | Insufficient bytes to decode a field |
| `InvalidLength` | Trailing bytes after complete structure, or length mismatch |
| `InvalidVersion` | Protocol or kernel version does not match expected constant |
| `InputTooLarge` | `opaque_agent_inputs_len` > 64,000 |
| `ActionPayloadTooLarge` | `payload_len` > 16,384 |
| `TooManyActions` | `action_count` > 64 |
| `ActionTooLarge` | Individual action encoding > 16,424 bytes |
| `InvalidExecutionStatus` | Status byte is not 0x01 |
| `ArithmeticOverflow` | Length calculation (e.g., offset + field_len) would overflow |

### Strict Decoding

Decoders MUST reject:
- Inputs with trailing bytes beyond the expected structure size
- Unknown or unsupported version numbers (protocol_version or kernel_version)
- Out-of-range size values (exceeding defined maximums)
- Invalid enumeration values (execution_status ≠ 0x01)
- Any computation where `offset + field_len` would overflow `usize`

---

## Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `PROTOCOL_VERSION` | 1 | Current protocol version |
| `KERNEL_VERSION` | 1 | Current kernel version |
| `MAX_AGENT_INPUT_BYTES` | 64,000 | Maximum agent input size (bytes) |
| `MAX_ACTION_PAYLOAD_BYTES` | 16,384 | Maximum action payload size (bytes) |
| `MAX_ACTIONS_PER_OUTPUT` | 64 | Maximum actions per output |
| `MAX_SINGLE_ACTION_BYTES` | 16,424 | Maximum encoded ActionV1 size (40 + 16,384) |
| `JOURNAL_SIZE` | 209 | Fixed KernelJournalV1 size (bytes) |

**Note**: `MAX_AGENT_INPUT_BYTES` is 64,000 bytes, not 64 KiB (65,536). This is an intentional limit.

---

## Test Vectors

See `tests/vectors/` for golden test vectors including:
- `kernel_input_v1.json` - KernelInputV1 encoding vectors
- `kernel_journal_v1.json` - KernelJournalV1 encoding vectors

Each vector file contains:
- Positive vectors with fields, encoded hex, and commitment hex
- Negative vectors with invalid encodings and expected errors
