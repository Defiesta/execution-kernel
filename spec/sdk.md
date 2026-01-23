# Kernel SDK Specification

**Version:** 0.1.0
**Status:** Canonical
**Crate:** `kernel-sdk`

---

## 1. Overview

The Kernel SDK provides the canonical interface for developing agents that execute inside the zkVM guest environment. It enforces a strict boundary between untrusted agent code and trusted kernel/constraint logic.

### 1.1 Design Principles

1. **Stability** - The interface is versioned and backwards-compatible within major versions
2. **Minimalism** - Agents receive only what they strictly need
3. **Isolation** - Agents cannot access forbidden APIs or kernel internals
4. **Determinism** - Agent execution must be fully deterministic
5. **Auditability** - Agent behavior must be inspectable and reproducible

### 1.2 Crate Attributes

```rust
#![no_std]
#![forbid(unsafe_code)]
#![deny(clippy::std_instead_of_alloc)]
#![deny(clippy::std_instead_of_core)]
```

The SDK is `no_std` and forbids unsafe code. Agents inherit these constraints when using the SDK.

---

## 2. Canonical Entrypoint

Every agent MUST expose exactly this function:

```rust
#[no_mangle]
#[allow(improper_ctypes_definitions)]
pub extern "C" fn agent_main(ctx: &AgentContext) -> AgentOutput
```

### 2.1 Symbol Requirements

| Requirement | Value |
|-------------|-------|
| Symbol name | `agent_main` (exact, no mangling) |
| ABI | `extern "C"` |
| Input | `&AgentContext<'a>` |
| Output | `AgentOutput` |

### 2.2 Panic Behavior

Panicking inside `agent_main`:
- Aborts guest execution immediately
- Invalidates the proof (no journal produced)
- Results in execution failure

Agents SHOULD handle errors gracefully and return empty outputs rather than panicking.

---

## 3. AgentContext

The `AgentContext` structure contains all information an agent needs to make decisions and produce actions.

### 3.1 Structure Definition

```rust
#[repr(C)]
#[derive(Clone, Debug)]
pub struct AgentContext<'a> {
    pub protocol_version: u32,
    pub kernel_version: u32,
    pub agent_id: &'a [u8; 32],
    pub agent_code_hash: &'a [u8; 32],
    pub constraint_set_hash: &'a [u8; 32],
    pub input_root: &'a [u8; 32],
    pub execution_nonce: u64,
    pub opaque_inputs: &'a [u8],
}
```

### 3.2 Field Specifications

| Field | Type | Size | Description |
|-------|------|------|-------------|
| `protocol_version` | `u32` | 4 bytes | Wire format version (must be 1) |
| `kernel_version` | `u32` | 4 bytes | Kernel semantics version (must be 1) |
| `agent_id` | `&[u8; 32]` | 32 bytes | Unique agent identifier |
| `agent_code_hash` | `&[u8; 32]` | 32 bytes | SHA-256 of agent binary |
| `constraint_set_hash` | `&[u8; 32]` | 32 bytes | SHA-256 of constraint set |
| `input_root` | `&[u8; 32]` | 32 bytes | External state root (market snapshot) |
| `execution_nonce` | `u64` | 8 bytes | Monotonic replay protection counter |
| `opaque_inputs` | `&[u8]` | Variable | Agent-specific input data (max 64,000 bytes) |

### 3.3 Snapshot Prefix Convention

If cooldown or drawdown constraints are enabled, the **first 36 bytes** of `opaque_inputs` MUST contain a `StateSnapshotV1`:

| Offset | Field | Type | Size |
|--------|-------|------|------|
| 0 | `snapshot_version` | u32 | 4 |
| 4 | `last_execution_ts` | u64 | 8 |
| 12 | `current_ts` | u64 | 8 |
| 20 | `current_equity` | u64 | 8 |
| 28 | `peak_equity` | u64 | 8 |

All integers are **little-endian**. Bytes after offset 36 are agent-specific and ignored by the constraint engine.

### 3.4 Helper Methods

```rust
impl<'a> AgentContext<'a> {
    /// Check if protocol version is 1
    pub fn is_protocol_v1(&self) -> bool;

    /// Check if kernel version is 1
    pub fn is_kernel_v1(&self) -> bool;

    /// Get length of opaque_inputs
    pub fn inputs_len(&self) -> usize;

    /// Check if opaque_inputs is empty
    pub fn inputs_is_empty(&self) -> bool;

    /// Check if opaque_inputs contains snapshot prefix (>= 36 bytes)
    pub fn has_snapshot_prefix(&self) -> bool;

    /// Get agent-specific portion (bytes after snapshot prefix)
    pub fn agent_inputs(&self) -> &[u8];
}
```

---

## 4. AgentOutput

The `AgentOutput` structure is re-exported from `kernel-core`.

### 4.1 Structure Definition

```rust
pub struct AgentOutput {
    pub actions: Vec<ActionV1>,
}
```

### 4.2 Limits

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_ACTIONS_PER_OUTPUT` | 64 | Maximum actions per output |
| `MAX_ACTION_PAYLOAD_BYTES` | 16,384 | Maximum bytes per action payload |

---

## 5. Action Types

### 5.1 ActionV1 Structure

```rust
pub struct ActionV1 {
    pub action_type: u32,
    pub target: [u8; 32],
    pub payload: Vec<u8>,
}
```

### 5.2 Action Type Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `ACTION_TYPE_ECHO` | `0x00000001` | Echo/test action |
| `ACTION_TYPE_OPEN_POSITION` | `0x00000002` | Open trading position |
| `ACTION_TYPE_CLOSE_POSITION` | `0x00000003` | Close position |
| `ACTION_TYPE_ADJUST_POSITION` | `0x00000004` | Modify position |
| `ACTION_TYPE_SWAP` | `0x00000005` | Asset swap/exchange |

### 5.3 Payload Schemas

All multi-byte integers are **little-endian**.

#### 5.3.1 Echo (0x00000001)

| Field | Type | Size | Description |
|-------|------|------|-------------|
| (opaque) | `[u8]` | Variable | Arbitrary payload, no schema |

#### 5.3.2 OpenPosition (0x00000002)

**Total size: 45 bytes**

| Offset | Field | Type | Size | Description |
|--------|-------|------|------|-------------|
| 0 | `asset_id` | `[u8; 32]` | 32 | Asset identifier |
| 32 | `notional` | `u64` | 8 | Position size in base units |
| 40 | `leverage_bps` | `u32` | 4 | Leverage in basis points |
| 44 | `direction` | `u8` | 1 | 0 = Long, 1 = Short |

#### 5.3.3 ClosePosition (0x00000003)

**Total size: 32 bytes**

| Offset | Field | Type | Size | Description |
|--------|-------|------|------|-------------|
| 0 | `position_id` | `[u8; 32]` | 32 | Position to close |

#### 5.3.4 AdjustPosition (0x00000004)

**Total size: 44 bytes**

| Offset | Field | Type | Size | Description |
|--------|-------|------|------|-------------|
| 0 | `position_id` | `[u8; 32]` | 32 | Position to modify |
| 32 | `new_notional` | `u64` | 8 | New size (0 = unchanged) |
| 40 | `new_leverage_bps` | `u32` | 4 | New leverage (0 = unchanged) |

#### 5.3.5 Swap (0x00000005)

**Total size: 72 bytes**

| Offset | Field | Type | Size | Description |
|--------|-------|------|------|-------------|
| 0 | `from_asset` | `[u8; 32]` | 32 | Source asset |
| 32 | `to_asset` | `[u8; 32]` | 32 | Destination asset |
| 64 | `amount` | `u64` | 8 | Amount to swap |

---

## 6. Action Constructors

All constructors are marked `#[must_use]` and `#[inline]`.

### 6.1 Function Signatures

```rust
pub fn echo_action(target: [u8; 32], payload: Vec<u8>) -> ActionV1;

pub fn open_position_action(
    target: [u8; 32],
    asset_id: [u8; 32],
    notional: u64,
    leverage_bps: u32,
    direction: u8,  // debug_assert!(direction <= 1)
) -> ActionV1;

pub fn close_position_action(
    target: [u8; 32],
    position_id: [u8; 32],
) -> ActionV1;

pub fn adjust_position_action(
    target: [u8; 32],
    position_id: [u8; 32],
    new_notional: u64,
    new_leverage_bps: u32,
) -> ActionV1;

pub fn swap_action(
    target: [u8; 32],
    from_asset: [u8; 32],
    to_asset: [u8; 32],
    amount: u64,
) -> ActionV1;
```

### 6.2 Debug Assertions

In debug builds, constructors assert:
- `open_position_action`: `direction <= 1`
- All constructors: `payload.len() == EXPECTED_SIZE` (after construction)

---

## 7. Payload Decode Helpers

Decode helpers perform **structural validation only** (correct size). Semantic validation (e.g., `direction <= 1`) is performed by the constraint engine.

### 7.1 Decoded Types

```rust
pub struct DecodedOpenPosition {
    pub asset_id: [u8; 32],
    pub notional: u64,
    pub leverage_bps: u32,
    pub direction: u8,  // Not validated here
}

pub struct DecodedAdjustPosition {
    pub position_id: [u8; 32],
    pub new_notional: u64,
    pub new_leverage_bps: u32,
}

pub struct DecodedSwap {
    pub from_asset: [u8; 32],
    pub to_asset: [u8; 32],
    pub amount: u64,
}
```

### 7.2 Decode Functions

```rust
pub fn decode_open_position_payload(payload: &[u8]) -> Option<DecodedOpenPosition>;
pub fn decode_close_position_payload(payload: &[u8]) -> Option<[u8; 32]>;
pub fn decode_adjust_position_payload(payload: &[u8]) -> Option<DecodedAdjustPosition>;
pub fn decode_swap_payload(payload: &[u8]) -> Option<DecodedSwap>;
```

All return `None` if payload size is incorrect.

---

## 8. Math Helpers

All math operations use integer arithmetic only. No floating point.

### 8.1 Rounding Policy

All division operations use **floor division** (truncation toward zero). This is deterministic and matches standard Rust integer division.

### 8.2 Checked Arithmetic

Returns `None` on overflow/underflow/divide-by-zero:

```rust
pub fn checked_add_u64(a: u64, b: u64) -> Option<u64>;
pub fn checked_sub_u64(a: u64, b: u64) -> Option<u64>;
pub fn checked_mul_u64(a: u64, b: u64) -> Option<u64>;
pub fn checked_div_u64(a: u64, b: u64) -> Option<u64>;

pub fn checked_add_u32(a: u32, b: u32) -> Option<u32>;
pub fn checked_sub_u32(a: u32, b: u32) -> Option<u32>;
pub fn checked_mul_u32(a: u32, b: u32) -> Option<u32>;
pub fn checked_div_u32(a: u32, b: u32) -> Option<u32>;
```

### 8.3 Compound Arithmetic

```rust
/// Computes (a * b) / denom with overflow protection.
/// Returns None if denom == 0 or a * b overflows.
pub fn checked_mul_div_u64(a: u64, b: u64, denom: u64) -> Option<u64>;
```

This is the canonical primitive for ratio calculations. Prefer this over separate mul/div calls.

### 8.4 Saturating Arithmetic

Returns boundary value instead of overflowing:

```rust
pub fn saturating_add_u64(a: u64, b: u64) -> u64;  // Returns u64::MAX on overflow
pub fn saturating_sub_u64(a: u64, b: u64) -> u64;  // Returns 0 on underflow
pub fn saturating_mul_u64(a: u64, b: u64) -> u64;  // Returns u64::MAX on overflow
```

### 8.5 Basis Points

```rust
pub const BPS_DENOMINATOR: u64 = 10_000;

/// Apply bps to value: value * bps / 10000 (floor division)
pub fn apply_bps(value: u64, bps: u64) -> Option<u64>;

/// Calculate bps: numerator * 10000 / denominator (floor division)
pub fn calculate_bps(numerator: u64, denominator: u64) -> Option<u64>;

/// Calculate drawdown: (peak - current) * 10000 / peak
/// Returns 0 if current >= peak, None if peak == 0
pub fn drawdown_bps(current_equity: u64, peak_equity: u64) -> Option<u64>;

/// Check if bps is valid percentage (0..=10000)
/// NOTE: Do NOT use for leverage_bps which can exceed 10000
pub fn is_valid_pct_bps(bps: u64) -> bool;
```

### 8.6 Min/Max/Clamp

```rust
pub fn min_u64(a: u64, b: u64) -> u64;
pub fn max_u64(a: u64, b: u64) -> u64;
pub fn min_u32(a: u32, b: u32) -> u32;
pub fn max_u32(a: u32, b: u32) -> u32;

pub fn clamp_u64(value: u64, min: u64, max: u64) -> u64;
pub fn clamp_u32(value: u32, min: u32, max: u32) -> u32;
```

---

## 9. Byte Helpers

All integer encoding uses **little-endian** byte order.

### 9.1 Fixed-Offset Readers

Return `None` if insufficient bytes:

```rust
pub fn read_u8(bytes: &[u8], offset: usize) -> Option<u8>;
pub fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32>;
pub fn read_u64_le(bytes: &[u8], offset: usize) -> Option<u64>;
pub fn read_bytes32(bytes: &[u8], offset: usize) -> Option<[u8; 32]>;
pub fn read_slice(bytes: &[u8], offset: usize, len: usize) -> Option<&[u8]>;
pub fn read_bool_u8(bytes: &[u8], offset: usize) -> Option<bool>;
```

### 9.2 Cursor-Style Readers

Advance `offset` on success. For `read_bool_u8_at`, offset is **not advanced** on invalid values (fail-without-consuming):

```rust
pub fn read_u8_at(bytes: &[u8], offset: &mut usize) -> Option<u8>;
pub fn read_u32_le_at(bytes: &[u8], offset: &mut usize) -> Option<u32>;
pub fn read_u64_le_at(bytes: &[u8], offset: &mut usize) -> Option<u64>;
pub fn read_bytes32_at(bytes: &[u8], offset: &mut usize) -> Option<[u8; 32]>;
pub fn read_slice_at<'a>(bytes: &'a [u8], offset: &mut usize, len: usize) -> Option<&'a [u8]>;
pub fn read_bool_u8_at(bytes: &[u8], offset: &mut usize) -> Option<bool>;
```

#### 9.2.1 read_bool_u8_at Semantics

- Returns `Some(false)` for byte `0x00`
- Returns `Some(true)` for byte `0x01`
- Returns `None` for any other value (offset unchanged)
- Returns `None` if out of bounds (offset unchanged)

### 9.3 Writers

```rust
pub fn write_u8(buf: &mut Vec<u8>, value: u8);
pub fn write_u32_le(buf: &mut Vec<u8>, value: u32);
pub fn write_u64_le(buf: &mut Vec<u8>, value: u64);
pub fn write_bytes32(buf: &mut Vec<u8>, value: &[u8; 32]);
pub fn write_slice(buf: &mut Vec<u8>, value: &[u8]);
```

### 9.4 Comparison Helpers

**WARNING:** These are NOT constant-time. Do NOT use for secret data.

```rust
pub fn bytes_eq(a: &[u8], b: &[u8]) -> bool;
pub fn bytes32_eq(a: &[u8; 32], b: &[u8; 32]) -> bool;
pub fn is_zero_bytes32(value: &[u8; 32]) -> bool;
pub fn is_all_zeros(value: &[u8]) -> bool;
```

### 9.5 Conversion Helpers

```rust
/// Exact 32 bytes required
pub fn slice_to_bytes32(slice: &[u8]) -> Option<[u8; 32]>;

/// Pads with zeros if shorter, None if longer than 32
pub fn slice_to_bytes32_padded(slice: &[u8]) -> Option<[u8; 32]>;

/// Truncate slice to max length
pub fn truncate_slice(slice: &[u8], max_len: usize) -> &[u8];

/// Clone and truncate
pub fn clone_truncated(slice: &[u8], max_len: usize) -> Vec<u8>;
```

### 9.6 Bounded Allocation

```rust
/// Create Vec with capacity capped at max_capacity.
/// NOTE: Does NOT prevent growth beyond max_capacity.
pub fn vec_with_capped_initial_capacity<T>(capacity: usize, max_capacity: usize) -> Vec<T>;
```

---

## 10. Versioning

### 10.1 SDK Version

```rust
pub const SDK_VERSION_MAJOR: u8 = 0;
pub const SDK_VERSION_MINOR: u8 = 1;
pub const SDK_VERSION_PATCH: u8 = 0;

/// Encoded as (major << 16) | (minor << 8) | patch
pub const SDK_VERSION: u32 = 0x00_01_00;
```

### 10.2 Kernel Version Compatibility

```rust
pub const MIN_KERNEL_VERSION: u32 = 1;
pub const MAX_KERNEL_VERSION: u32 = 1;

pub fn is_kernel_version_supported(version: u32) -> bool;
```

---

## 11. Prelude

The prelude provides convenient imports for common agent development:

```rust
use kernel_sdk::prelude::*;
```

### 11.1 Exported Items

| Category | Items |
|----------|-------|
| Context | `AgentContext`, `AgentEntrypoint` |
| Types | `ActionV1`, `AgentOutput`, `MAX_ACTIONS_PER_OUTPUT`, `MAX_ACTION_PAYLOAD_BYTES` |
| Action Constants | `ACTION_TYPE_ECHO`, `ACTION_TYPE_OPEN_POSITION`, `ACTION_TYPE_CLOSE_POSITION`, `ACTION_TYPE_ADJUST_POSITION`, `ACTION_TYPE_SWAP` |
| Constructors | `echo_action`, `open_position_action`, `close_position_action`, `adjust_position_action`, `swap_action` |
| Decode Helpers | `decode_*_payload`, `DecodedOpenPosition`, `DecodedAdjustPosition`, `DecodedSwap` |
| Math | `checked_add_u64`, `checked_sub_u64`, `checked_mul_u64`, `checked_div_u64`, `checked_mul_div_u64`, `saturating_add_u64`, `saturating_sub_u64`, `saturating_mul_u64`, `apply_bps`, `calculate_bps`, `drawdown_bps`, `BPS_DENOMINATOR` |
| Bytes (fixed) | `read_u8`, `read_u32_le`, `read_u64_le`, `read_bytes32`, `read_slice`, `is_zero_bytes32` |
| Bytes (cursor) | `read_u8_at`, `read_u32_le_at`, `read_u64_le_at`, `read_bytes32_at`, `read_slice_at`, `read_bool_u8_at` |
| Alloc | `Vec` (NOT `vec![]` macro) |

### 11.2 vec![] Macro Exclusion

The `vec![]` macro is intentionally NOT exported to discourage unbounded allocations.

**Recommended patterns:**
```rust
// Explicit bounded allocation
let mut actions = Vec::with_capacity(1);
actions.push(action);

// Small fixed-size outputs
let actions = Vec::from([action1, action2]);
```

If needed, `alloc::vec![]` is still available directly.

---

## 12. Forbidden Behavior

Agents MUST NOT:

| Forbidden | Reason |
|-----------|--------|
| `std::time` | Non-deterministic |
| `rand` / randomness | Non-deterministic |
| `std::fs`, `std::net` | I/O forbidden in guest |
| Syscalls / host functions | Isolation violation |
| Kernel internals | Isolation violation |
| Unbounded memory | Resource exhaustion |

### 12.1 Enforcement Layers

1. **Compile-time:** `#![no_std]` prevents most `std` usage
2. **Lint-time:** `clippy::std_instead_of_*` catches accidental `std` imports
3. **Runtime:** zkVM guest environment rejects forbidden operations

### 12.2 Build Requirements

Agents should compile with:
- `default-features = false`
- No `std` feature enabled
- CI should reject transitive `std` dependencies

---

## 13. SDK vs Constraint Engine Responsibilities

| Responsibility | SDK | Constraint Engine |
|----------------|-----|-------------------|
| Payload encoding | ✅ Canonical constructors | - |
| Payload decoding | ✅ Structural validation | - |
| Direction validation | ❌ (debug assert only) | ✅ Enforced |
| Leverage bounds | ❌ | ✅ Enforced |
| Position size limits | ❌ | ✅ Enforced |
| Asset whitelist | ❌ | ✅ Enforced |
| Cooldown timing | ❌ | ✅ Enforced |
| Drawdown limits | ❌ | ✅ Enforced |
| Action count limits | ❌ | ✅ Enforced |
| Payload size limits | ❌ | ✅ Enforced |

---

## 14. Example Agent

```rust
use kernel_sdk::prelude::*;

#[no_mangle]
#[allow(improper_ctypes_definitions)]
pub extern "C" fn agent_main(ctx: &AgentContext) -> AgentOutput {
    // Validate kernel version
    if !ctx.is_kernel_v1() {
        return AgentOutput { actions: Vec::new() };
    }

    // Parse agent-specific inputs (after 36-byte snapshot prefix)
    let inputs = ctx.agent_inputs();
    if inputs.len() < 41 {
        return AgentOutput { actions: Vec::new() };
    }

    // Decode trading parameters
    let mut offset = 0;
    let asset_id = match read_bytes32_at(inputs, &mut offset) {
        Some(id) => id,
        None => return AgentOutput { actions: Vec::new() },
    };
    let notional = match read_u64_le_at(inputs, &mut offset) {
        Some(n) => n,
        None => return AgentOutput { actions: Vec::new() },
    };
    let direction = match read_u8_at(inputs, &mut offset) {
        Some(d) if d <= 1 => d,
        _ => return AgentOutput { actions: Vec::new() },
    };

    // Create action with bounded allocation
    let action = open_position_action(
        *ctx.agent_id,
        asset_id,
        notional,
        10_000,  // 1x leverage
        direction,
    );

    let mut actions = Vec::with_capacity(1);
    actions.push(action);
    AgentOutput { actions }
}
```

---

## 15. CI Verification

### 15.1 no_std Build Check

```bash
rustup target add wasm32-unknown-unknown
cargo build -p kernel-sdk --no-default-features --target wasm32-unknown-unknown
```

### 15.2 Clippy Check

```bash
cargo clippy -p kernel-sdk --no-default-features \
    --target wasm32-unknown-unknown -- -D warnings
```

### 15.3 Transitive std Check

```bash
cargo tree -p kernel-sdk -e features --no-default-features | rg '\bstd\b' && exit 1 || true
```

---

## Appendix A: Payload Size Constants

```rust
pub const OPEN_POSITION_PAYLOAD_SIZE: usize = 45;
pub const CLOSE_POSITION_PAYLOAD_SIZE: usize = 32;
pub const ADJUST_POSITION_PAYLOAD_SIZE: usize = 44;
pub const SWAP_PAYLOAD_SIZE: usize = 72;
```

---

## Appendix B: Type Aliases

```rust
/// Canonical agent entrypoint function signature
pub type AgentEntrypoint<'a> = extern "C" fn(&AgentContext<'a>) -> AgentOutput;
```

---

## Appendix C: Crate Root Re-exports

Available at `kernel_sdk::`:

```rust
pub use agent::{AgentContext, AgentEntrypoint};
pub use types::{ActionV1, AgentOutput};
```
