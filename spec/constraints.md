# Constraint System Specification

This document specifies the constraint enforcement system for the kernel protocol (P0.3).
Constraints are enforced inside the guest (zkVM) and are unskippable.

## Overview

The constraint system validates agent-proposed actions against economic safety rules before commitment. Key properties:

1. **Unskippable**: Constraints are enforced after every agent execution, unconditionally
2. **Deterministic**: Same inputs always produce same validation results
3. **Provable**: Constraint violations result in a valid proof with Failure status
4. **Auditable**: Clear error codes identify which constraint was violated

---

## Failure Semantics

When a constraint is violated:

1. `execution_status` is set to `Failure` (0x02)
2. `action_commitment` is computed over an **empty AgentOutput** (zero actions)
3. A valid `KernelJournalV1` is always produced
4. The proof is still valid, but verifiers/contracts should reject state transitions

This design ensures:
- Constraint violations are provable and verifiable on-chain
- No ambiguity between "success with zero actions" and "constraint failure"
- Host and prover behavior is consistent

---

## Action Types

### Supported Action Types (P0.3)

| Code | Name | Description |
|------|------|-------------|
| `0x00000001` | `Echo` | Echo/test action (TrivialAgent) |
| `0x00000002` | `OpenPosition` | Open a new trading position |
| `0x00000003` | `ClosePosition` | Close an existing position |
| `0x00000004` | `AdjustPosition` | Modify position size or leverage |
| `0x00000005` | `Swap` | Asset swap/exchange |

Any action type not in this list is **invalid** and causes a constraint violation.

### Action Payload Schemas

**Encoding:** All integer fields in action payloads use little-endian encoding, consistent with the kernel codec specification.

#### Echo (0x00000001)

No schema enforcement. Payload is opaque bytes.

#### OpenPosition (0x00000002)

```
Offset | Field         | Type      | Size | Description
-------|---------------|-----------|------|-------------
0      | asset_id      | [u8; 32]  | 32   | Asset identifier
32     | notional      | u64       | 8    | Position size in base units
40     | leverage_bps  | u32       | 4    | Leverage in basis points (10000 = 1x)
44     | direction     | u8        | 1    | 0 = Long, 1 = Short
```

**Total: 45 bytes (exact)**

P0.3 requires exact payload length. Trailing bytes are rejected to prevent encoding malleability.

#### ClosePosition (0x00000003)

```
Offset | Field         | Type      | Size | Description
-------|---------------|-----------|------|-------------
0      | position_id   | [u8; 32]  | 32   | Position identifier to close
```

**Total: 32 bytes (exact)**

P0.3 requires exact payload length. Trailing bytes are rejected to prevent encoding malleability.

#### AdjustPosition (0x00000004)

```
Offset | Field         | Type      | Size | Description
-------|---------------|-----------|------|-------------
0      | position_id   | [u8; 32]  | 32   | Position identifier
32     | new_notional  | u64       | 8    | New position size (0 = unchanged)
40     | new_leverage  | u32       | 4    | New leverage in bps (0 = unchanged)
```

**Total: 44 bytes (exact)**

P0.3 requires exact payload length. Trailing bytes are rejected to prevent encoding malleability.

#### Swap (0x00000005)

```
Offset | Field         | Type      | Size | Description
-------|---------------|-----------|------|-------------
0      | from_asset    | [u8; 32]  | 32   | Source asset identifier
32     | to_asset      | [u8; 32]  | 32   | Destination asset identifier
64     | amount        | u64       | 8    | Amount to swap
```

**Total: 72 bytes (exact)**

P0.3 requires exact payload length. Trailing bytes are rejected to prevent encoding malleability.

---

## Constraint Set

### ConstraintSetV1 Schema

The constraint set defines the economic safety parameters. For P0.3, constraints are embedded in the guest binary and referenced by `constraint_set_hash`.

```
Offset | Field                   | Type      | Size | Description
-------|-------------------------|-----------|------|-------------
0      | version                 | u32       | 4    | Must be 1
4      | max_position_notional   | u64       | 8    | Maximum position size
12     | max_leverage_bps        | u32       | 4    | Maximum leverage (basis points)
16     | max_drawdown_bps        | u32       | 4    | Maximum drawdown (basis points)
20     | cooldown_seconds        | u32       | 4    | Minimum seconds between executions
24     | max_actions_per_output  | u32       | 4    | Maximum actions per output
28     | allowed_asset_id        | [u8; 32]  | 32   | Single allowed asset ID (P0.3)
```

Total: 60 bytes

### Constraint Set Validation (P0.3)

The following invariants are validated:
- `version` must be 1
- `max_actions_per_output` must be ≤ 64 (protocol maximum); may be 0 (rejects any non-empty output)
- `max_drawdown_bps` must be ≤ 10,000 (100%)
- `max_leverage_bps` may be 0 (only `leverage_bps == 0` passes)
- `cooldown_seconds` has no upper bound (operator choice)

### Default Constraint Set (P0.3)

For P0.3, a permissive default constraint set is used:

```rust
ConstraintSetV1 {
    version: 1,
    max_position_notional: u64::MAX,      // No position size limit
    max_leverage_bps: 100_000,            // 10x max leverage
    max_drawdown_bps: 10_000,             // 100% drawdown allowed (disabled)
    cooldown_seconds: 0,                  // No cooldown
    max_actions_per_output: 64,           // Match protocol max
    allowed_asset_id: [0u8; 32],          // Zero = all assets allowed
}
```

---

## State Snapshot

To enforce cooldown and drawdown constraints, the guest requires a state snapshot. This is provided in the `opaque_agent_inputs` field with the following prefix structure:

### StateSnapshotV1 Schema

```
Offset | Field                | Type      | Size | Description
-------|----------------------|-----------|------|-------------
0      | snapshot_version     | u32       | 4    | Must be 1
4      | last_execution_ts    | u64       | 8    | Timestamp of last execution
12     | current_ts           | u64       | 8    | Current timestamp (from input)
20     | current_equity       | u64       | 8    | Current portfolio equity
28     | peak_equity          | u64       | 8    | Peak portfolio equity
```

Total: 36 bytes

**Snapshot Prefix Rule:** The snapshot is decoded from the first 36 bytes of `opaque_agent_inputs`. Any trailing bytes are agent-specific data and are ignored by the constraint engine. This allows agents to pass additional state through `opaque_agent_inputs` without affecting constraint validation.

### Snapshot Parsing Rules

```
IF snapshot is missing AND (constraint_set.cooldown_seconds > 0 OR constraint_set.max_drawdown_bps < 10_000):
    Violation: InvalidStateSnapshot (0x08)
ELSE IF snapshot is missing:
    snapshot is considered empty; global checks are skipped
```

**Rationale:** When cooldown or drawdown constraints are enabled, they are safety-critical. Allowing missing snapshots would bypass these protections.

**Snapshot Optionality (P0.3):** Snapshot is optional unless cooldown or drawdown constraints are enabled. Malformed snapshots with wrong version are treated as missing. This means a wrong-version snapshot combined with disabled cooldown/drawdown will pass validation.

**Missing Snapshot Definition:** A snapshot is considered missing if `opaque_agent_inputs.len() < 36` or if `snapshot_version != 1`.

---

## Constraint Rules

### Evaluation Order

Constraints are evaluated in the following deterministic order:

1. **Output structure validation**
   - `action_count` <= `max_actions_per_output`
   - Each action payload size <= `MAX_ACTION_PAYLOAD_BYTES`

2. **Per-action validation** (for each action in order)
   - Action type must be known/supported
   - Payload must match expected schema for action type
   - Asset whitelist check (if applicable)
   - Position size check (if applicable)
   - Leverage check (if applicable)

3. **Global invariants**
   - Cooldown check (if `cooldown_seconds > 0`; missing snapshot → `InvalidStateSnapshot`)
   - Drawdown check (if `max_drawdown_bps < 10_000`; missing snapshot → `InvalidStateSnapshot`)

Evaluation stops at the first violation.

### Rule Details

#### Output Structure (Rule 1)

```
REQUIRE: output.actions.len() <= constraint_set.max_actions_per_output
REQUIRE: for all actions: action.payload.len() <= MAX_ACTION_PAYLOAD_BYTES
```

Violation: `InvalidOutputStructure` (0x01)

#### Unknown Action Type (Rule 2a)

```
REQUIRE: action.action_type IN supported_action_types
```

Violation: `UnknownActionType` (0x02)

#### Asset Whitelist (Rule 2b)

```
IF constraint_set.allowed_asset_id != [0; 32]:
    REQUIRE: asset_id == allowed_asset_id (exact match)
```

Violation: `AssetNotWhitelisted` (0x03)

**P0.3 Semantics:** Single-asset whitelist via exact ID match.
- If `allowed_asset_id == [0; 32]`, all assets are allowed
- If `allowed_asset_id != [0; 32]`, only the exact matching asset_id is allowed

Future versions may support multi-asset whitelists via Merkle proofs.

#### Position Size (Rule 2c)

For OpenPosition and AdjustPosition:

```
REQUIRE: notional <= constraint_set.max_position_notional
```

Violation: `PositionTooLarge` (0x04)

**AdjustPosition Semantics:** For AdjustPosition, position size checks apply only when `new_notional > 0`. A value of 0 means "unchanged" and bypasses the check.

#### Leverage (Rule 2d)

For OpenPosition and AdjustPosition:

```
REQUIRE: leverage_bps <= constraint_set.max_leverage_bps
```

Violation: `LeverageTooHigh` (0x05)

**AdjustPosition Semantics:** For AdjustPosition, leverage checks apply only when `new_leverage_bps > 0`. A value of 0 means "unchanged" and bypasses the check.

#### Drawdown (Rule 3a)

```
IF constraint_set.max_drawdown_bps < 10_000:
    IF state_snapshot.peak_equity == 0:
        Violation: InvalidStateSnapshot (0x08)

    # Handle equity growth (current > peak) as 0 drawdown
    drawdown = if current_equity >= peak_equity { 0 } else { peak_equity - current_equity }
    drawdown_bps = drawdown * 10000 / peak_equity

    REQUIRE: drawdown_bps <= constraint_set.max_drawdown_bps
```

Violation: `DrawdownExceeded` (0x06)

**Drawdown Disabled Rule:** Drawdown checks are disabled if and only if `max_drawdown_bps == 10_000` (100%). Any value less than 10,000 enables drawdown enforcement. This is consistent with the snapshot parsing rules above.

**Note:** When `current_equity >= peak_equity`, drawdown is defined as 0 (no drawdown). This prevents underflow and makes the rule deterministic.

#### Cooldown (Rule 3b)

**Snapshot Present:** `state_snapshot is present` means the snapshot prefix decodes successfully (`snapshot_version == 1` and `opaque_agent_inputs.len() >= 36`).

```
IF constraint_set.cooldown_seconds > 0 AND state_snapshot is present:
    required_ts = last_execution_ts + cooldown_seconds
    IF required_ts overflows (u64):
        Violation: InvalidStateSnapshot (0x08)
    REQUIRE: current_ts >= required_ts
```

Violation: `CooldownNotElapsed` (0x07)

**Overflow Protection (P0.3):** If `last_execution_ts + cooldown_seconds` overflows, the snapshot is considered invalid. This prevents maliciously large timestamp values from bypassing cooldown checks via saturation.

**Timestamp Arithmetic:** All timestamp arithmetic is performed in `u64`; overflow is treated as `InvalidStateSnapshot`.

---

## Violation Reason Codes

| Code | Name | Description |
|------|------|-------------|
| 0x01 | `InvalidOutputStructure` | Too many actions or payload too large |
| 0x02 | `UnknownActionType` | Action type not recognized |
| 0x03 | `AssetNotWhitelisted` | Asset not in allowed list |
| 0x04 | `PositionTooLarge` | Position exceeds size limit |
| 0x05 | `LeverageTooHigh` | Leverage exceeds limit |
| 0x06 | `DrawdownExceeded` | Portfolio drawdown too high |
| 0x07 | `CooldownNotElapsed` | Too soon since last execution |
| 0x08 | `InvalidStateSnapshot` | Snapshot malformed or invalid |
| 0x09 | `InvalidConstraintSet` | Constraint configuration invalid |
| 0x0A | `InvalidActionPayload` | Payload doesn't match schema |

---

## Empty Output Commitment

On constraint failure, the `action_commitment` is computed over an empty `AgentOutput`:

```
empty_output = AgentOutput { actions: vec![] }
empty_encoded = encode(empty_output)  // = [0x00, 0x00, 0x00, 0x00] (action_count = 0)
action_commitment = SHA-256(empty_encoded)
```

The constant empty output commitment is:
```
df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119
```

This is the SHA-256 hash of `[0x00, 0x00, 0x00, 0x00]`.

---

## Target Field (P0.3 Limitation)

The `action.target` field is **not validated** by the constraint engine in P0.3. This field is passed through to executor contracts without any constraint enforcement.

**Security Note:** Executor contracts are responsible for validating the `target` field according to their own rules. The constraint system does not restrict which targets can be called.

**Security Posture:** If the executor allows arbitrary calls based on `target`, then P0.3 constraints do not prevent malicious call targets. Operators must ensure executors implement appropriate target validation.

Future versions may add per-action-type target validation (e.g., only allowing specific contract addresses for swaps).

---

## Determinism Requirements

The constraint engine MUST be fully deterministic:

- **No host time**: Use `current_ts` from state snapshot
- **No randomness**: All decisions based on input data only
- **No floating point**: Use integer arithmetic with explicit rounding
- **Bounded iteration**: All loops have fixed bounds
- **Stable ordering**: Evaluate actions in input order

---

## Test Vector Format

Test vectors are JSON files in `tests/vectors/constraints/`:

```json
{
  "name": "test_case_name",
  "description": "Human-readable description",
  "constraint_set": {
    "version": 1,
    "max_position_notional": 1000000,
    "max_leverage_bps": 50000,
    "max_drawdown_bps": 2000,
    "cooldown_seconds": 60,
    "max_actions_per_output": 64,
    "allowed_asset_id": "0000...0000"
  },
  "state_snapshot": {
    "snapshot_version": 1,
    "last_execution_ts": 1000,
    "current_ts": 1100,
    "current_equity": 100000,
    "peak_equity": 100000
  },
  "proposed_actions": [
    {
      "action_type": 2,
      "target": "1111...1111",
      "payload_hex": "..."
    }
  ],
  "expected": {
    "status": "Success",
    "action_commitment": "...",
    "violation_reason": null
  }
}
```

For failure cases:

```json
{
  "expected": {
    "status": "Failure",
    "action_commitment": "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119",
    "violation_reason": "LeverageTooHigh",
    "violation_action_index": 0
  }
}
```

---

## Integration with Kernel

### kernel_main Flow (P0.3)

```
1. Decode KernelInputV1
2. Validate versions
3. Compute input_commitment
4. Execute agent → proposed_output
5. Enforce constraints:
   IF enforce_constraints(input, proposed_output) == Ok(validated):
       output = validated
       status = Success
   ELSE:
       output = AgentOutput { actions: [] }
       status = Failure
6. Compute action_commitment over output
7. Construct and return KernelJournalV1
```

The journal is **always** produced, even on constraint failure.

---

## Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `ACTION_TYPE_ECHO` | 0x00000001 | Echo/test action |
| `ACTION_TYPE_OPEN_POSITION` | 0x00000002 | Open position |
| `ACTION_TYPE_CLOSE_POSITION` | 0x00000003 | Close position |
| `ACTION_TYPE_ADJUST_POSITION` | 0x00000004 | Adjust position |
| `ACTION_TYPE_SWAP` | 0x00000005 | Asset swap |
| `EMPTY_OUTPUT_COMMITMENT` | `df3f61...` | SHA-256 of empty output |
