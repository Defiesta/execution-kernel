//! Deterministic math helpers for agent development.
//!
//! This module provides safe, deterministic mathematical operations
//! that are suitable for use in zkVM guest code. All operations:
//!
//! - Use integer arithmetic only (no floating point)
//! - Have explicit overflow handling (checked/saturating)
//! - Are fully deterministic across platforms
//!
//! # Basis Points
//!
//! Many financial calculations use basis points (bps) where:
//! - 1 bps = 0.01% = 1/10000
//! - 100 bps = 1%
//! - 10000 bps = 100%
//!
//! # Rounding Policy
//!
//! All division operations use **floor division** (truncation toward zero).
//! This is the standard integer division behavior in Rust. For example:
//! - `apply_bps(1000, 1)` returns `Some(0)` (0.01% of 1000 truncates to 0)
//! - `calculate_bps(1, 3)` returns `Some(3333)` (not 3334)
//!
//! If you need different rounding behavior (e.g., round-half-up for prices),
//! implement separate helpers; do not modify these canonical floor-division
//! functions.
//!
//! # Example
//!
//! ```
//! use kernel_sdk::math::*;
//!
//! // Calculate 5% of 1000
//! let result = apply_bps(1000, 500); // 500 bps = 5%
//! assert_eq!(result, Some(50));
//!
//! // Safe addition
//! let sum = checked_add_u64(100, 200);
//! assert_eq!(sum, Some(300));
//! ```

// ============================================================================
// Checked Arithmetic
// ============================================================================

/// Checked addition for u64.
///
/// Returns `None` if the addition would overflow.
#[inline]
pub fn checked_add_u64(a: u64, b: u64) -> Option<u64> {
    a.checked_add(b)
}

/// Checked subtraction for u64.
///
/// Returns `None` if the subtraction would underflow.
#[inline]
pub fn checked_sub_u64(a: u64, b: u64) -> Option<u64> {
    a.checked_sub(b)
}

/// Checked multiplication for u64.
///
/// Returns `None` if the multiplication would overflow.
#[inline]
pub fn checked_mul_u64(a: u64, b: u64) -> Option<u64> {
    a.checked_mul(b)
}

/// Checked division for u64.
///
/// Returns `None` if the divisor is zero.
#[inline]
pub fn checked_div_u64(a: u64, b: u64) -> Option<u64> {
    a.checked_div(b)
}

/// Checked addition for u32.
///
/// Returns `None` if the addition would overflow.
#[inline]
pub fn checked_add_u32(a: u32, b: u32) -> Option<u32> {
    a.checked_add(b)
}

/// Checked subtraction for u32.
///
/// Returns `None` if the subtraction would underflow.
#[inline]
pub fn checked_sub_u32(a: u32, b: u32) -> Option<u32> {
    a.checked_sub(b)
}

/// Checked multiplication for u32.
///
/// Returns `None` if the multiplication would overflow.
#[inline]
pub fn checked_mul_u32(a: u32, b: u32) -> Option<u32> {
    a.checked_mul(b)
}

/// Checked division for u32.
///
/// Returns `None` if the divisor is zero.
#[inline]
pub fn checked_div_u32(a: u32, b: u32) -> Option<u32> {
    a.checked_div(b)
}

// ============================================================================
// Compound Arithmetic
// ============================================================================

/// Checked multiply-then-divide for u64.
///
/// Computes `(a * b) / denom` with overflow protection.
/// Returns `None` if:
/// - `denom` is zero
/// - The intermediate multiplication `a * b` overflows
///
/// **Rounding:** Uses floor division (truncation toward zero).
///
/// This is the canonical primitive for ratio calculations. Prefer this
/// over separate mul/div calls to reduce error-prone patterns.
#[inline]
#[must_use]
pub fn checked_mul_div_u64(a: u64, b: u64, denom: u64) -> Option<u64> {
    if denom == 0 {
        return None;
    }
    a.checked_mul(b).map(|v| v / denom)
}

// ============================================================================
// Saturating Arithmetic
// ============================================================================

/// Saturating addition for u64.
///
/// Returns `u64::MAX` if the addition would overflow.
#[inline]
pub fn saturating_add_u64(a: u64, b: u64) -> u64 {
    a.saturating_add(b)
}

/// Saturating subtraction for u64.
///
/// Returns 0 if the subtraction would underflow.
#[inline]
pub fn saturating_sub_u64(a: u64, b: u64) -> u64 {
    a.saturating_sub(b)
}

/// Saturating multiplication for u64.
///
/// Returns `u64::MAX` if the multiplication would overflow.
#[inline]
pub fn saturating_mul_u64(a: u64, b: u64) -> u64 {
    a.saturating_mul(b)
}

// ============================================================================
// Basis Points Calculations
// ============================================================================

/// Basis points denominator (10000 = 100%).
pub const BPS_DENOMINATOR: u64 = 10_000;

/// Check if a percentage basis points value is valid (0..=10000).
///
/// This is a convenience helper for agents to self-validate **percentage**
/// bps values (e.g., drawdown thresholds, fee rates) before submission.
/// The constraint engine performs its own validation.
///
/// Returns `true` if `bps <= BPS_DENOMINATOR` (i.e., 0% to 100%).
///
/// **Note:** This is for percentage values only. Leverage bps values can
/// exceed 10,000 (e.g., 50,000 = 5x leverage) and should NOT use this check.
#[inline]
pub fn is_valid_pct_bps(bps: u64) -> bool {
    bps <= BPS_DENOMINATOR
}

/// Apply basis points to a value.
///
/// Computes `value * bps / 10000` with overflow protection.
/// Returns `None` if intermediate multiplication overflows.
///
/// **Rounding:** Floor division (truncates toward zero).
///
/// # Arguments
/// * `value` - The base value
/// * `bps` - Basis points to apply (10000 = 100%)
///
/// # Example
/// ```
/// use kernel_sdk::math::apply_bps;
///
/// // 5% of 1000
/// assert_eq!(apply_bps(1000, 500), Some(50));
///
/// // 100% of 1000
/// assert_eq!(apply_bps(1000, 10000), Some(1000));
///
/// // 0.01% of 1000
/// assert_eq!(apply_bps(1000, 1), Some(0)); // Rounds down
/// ```
#[inline]
pub fn apply_bps(value: u64, bps: u64) -> Option<u64> {
    checked_mul_div_u64(value, bps, BPS_DENOMINATOR)
}

/// Calculate basis points between two values.
///
/// Computes `(numerator * 10000) / denominator` with overflow protection.
/// Returns `None` if denominator is zero or multiplication overflows.
///
/// **Rounding:** Floor division (truncates toward zero).
///
/// # Arguments
/// * `numerator` - The numerator value
/// * `denominator` - The denominator value (must be non-zero)
///
/// # Example
/// ```
/// use kernel_sdk::math::calculate_bps;
///
/// // 50 is 5% of 1000
/// assert_eq!(calculate_bps(50, 1000), Some(500));
///
/// // 1000 is 100% of 1000
/// assert_eq!(calculate_bps(1000, 1000), Some(10000));
///
/// // Floor division: 1/3 = 3333 bps, not 3334
/// assert_eq!(calculate_bps(1, 3), Some(3333));
/// ```
#[inline]
pub fn calculate_bps(numerator: u64, denominator: u64) -> Option<u64> {
    checked_mul_div_u64(numerator, BPS_DENOMINATOR, denominator)
}

/// Calculate drawdown in basis points.
///
/// Computes `(peak - current) * 10000 / peak` with safety checks.
/// Returns 0 if current >= peak (no drawdown / equity growth).
/// Returns `None` if peak is zero.
///
/// **Rounding:** Floor division (truncates toward zero).
///
/// # Arguments
/// * `current_equity` - Current portfolio equity
/// * `peak_equity` - Peak portfolio equity
///
/// # Example
/// ```
/// use kernel_sdk::math::drawdown_bps;
///
/// // 30% drawdown: current=70, peak=100
/// assert_eq!(drawdown_bps(70, 100), Some(3000));
///
/// // No drawdown: current >= peak
/// assert_eq!(drawdown_bps(110, 100), Some(0));
///
/// // Zero peak is invalid
/// assert_eq!(drawdown_bps(50, 0), None);
/// ```
#[inline]
pub fn drawdown_bps(current_equity: u64, peak_equity: u64) -> Option<u64> {
    if peak_equity == 0 {
        return None;
    }
    if current_equity >= peak_equity {
        return Some(0);
    }
    let drawdown = peak_equity - current_equity;
    checked_mul_div_u64(drawdown, BPS_DENOMINATOR, peak_equity)
}

// ============================================================================
// Min/Max Helpers
// ============================================================================

/// Return the minimum of two u64 values.
#[inline]
pub fn min_u64(a: u64, b: u64) -> u64 {
    if a < b {
        a
    } else {
        b
    }
}

/// Return the maximum of two u64 values.
#[inline]
pub fn max_u64(a: u64, b: u64) -> u64 {
    if a > b {
        a
    } else {
        b
    }
}

/// Return the minimum of two u32 values.
#[inline]
pub fn min_u32(a: u32, b: u32) -> u32 {
    if a < b {
        a
    } else {
        b
    }
}

/// Return the maximum of two u32 values.
#[inline]
pub fn max_u32(a: u32, b: u32) -> u32 {
    if a > b {
        a
    } else {
        b
    }
}

/// Clamp a u64 value to a range.
///
/// Returns `min` if `value < min`, `max` if `value > max`, otherwise `value`.
#[inline]
pub fn clamp_u64(value: u64, min: u64, max: u64) -> u64 {
    if value < min {
        min
    } else if value > max {
        max
    } else {
        value
    }
}

/// Clamp a u32 value to a range.
///
/// Returns `min` if `value < min`, `max` if `value > max`, otherwise `value`.
#[inline]
pub fn clamp_u32(value: u32, min: u32, max: u32) -> u32 {
    if value < min {
        min
    } else if value > max {
        max
    } else {
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checked_add() {
        assert_eq!(checked_add_u64(100, 200), Some(300));
        assert_eq!(checked_add_u64(u64::MAX, 1), None);
        assert_eq!(checked_add_u32(100, 200), Some(300));
        assert_eq!(checked_add_u32(u32::MAX, 1), None);
    }

    #[test]
    fn test_checked_sub() {
        assert_eq!(checked_sub_u64(300, 100), Some(200));
        assert_eq!(checked_sub_u64(100, 200), None);
        assert_eq!(checked_sub_u32(300, 100), Some(200));
        assert_eq!(checked_sub_u32(100, 200), None);
    }

    #[test]
    fn test_checked_mul() {
        assert_eq!(checked_mul_u64(100, 200), Some(20000));
        assert_eq!(checked_mul_u64(u64::MAX, 2), None);
        assert_eq!(checked_mul_u32(100, 200), Some(20000));
        assert_eq!(checked_mul_u32(u32::MAX, 2), None);
    }

    #[test]
    fn test_checked_div() {
        assert_eq!(checked_div_u64(200, 100), Some(2));
        assert_eq!(checked_div_u64(100, 0), None);
        assert_eq!(checked_div_u32(200, 100), Some(2));
        assert_eq!(checked_div_u32(100, 0), None);
    }

    #[test]
    fn test_checked_mul_div() {
        // Basic case: (10 * 20) / 5 = 40
        assert_eq!(checked_mul_div_u64(10, 20, 5), Some(40));

        // Division by zero
        assert_eq!(checked_mul_div_u64(10, 20, 0), None);

        // Multiplication overflow
        assert_eq!(checked_mul_div_u64(u64::MAX, 2, 1), None);

        // Floor division: (7 * 3) / 4 = 21 / 4 = 5 (not 5.25)
        assert_eq!(checked_mul_div_u64(7, 3, 4), Some(5));
    }

    #[test]
    fn test_saturating_ops() {
        assert_eq!(saturating_add_u64(u64::MAX, 1), u64::MAX);
        assert_eq!(saturating_sub_u64(100, 200), 0);
        assert_eq!(saturating_mul_u64(u64::MAX, 2), u64::MAX);
    }

    #[test]
    fn test_is_valid_pct_bps() {
        assert!(is_valid_pct_bps(0));
        assert!(is_valid_pct_bps(5000));
        assert!(is_valid_pct_bps(10000));
        assert!(!is_valid_pct_bps(10001));
        assert!(!is_valid_pct_bps(u64::MAX));

        // Leverage bps can exceed 10000, so don't use is_valid_pct_bps for that
        // 50000 bps = 5x leverage - NOT a valid "percentage"
        assert!(!is_valid_pct_bps(50000));
    }

    #[test]
    fn test_apply_bps() {
        assert_eq!(apply_bps(1000, 500), Some(50)); // 5%
        assert_eq!(apply_bps(1000, 10000), Some(1000)); // 100%
        assert_eq!(apply_bps(1000, 0), Some(0)); // 0%
        assert_eq!(apply_bps(1000, 1), Some(0)); // 0.01% rounds down
        assert_eq!(apply_bps(10000, 1), Some(1)); // 0.01% of 10000
    }

    #[test]
    fn test_calculate_bps() {
        assert_eq!(calculate_bps(50, 1000), Some(500)); // 5%
        assert_eq!(calculate_bps(1000, 1000), Some(10000)); // 100%
        assert_eq!(calculate_bps(100, 0), None); // Division by zero

        // Floor division verification: 1/3 = 0.3333... = 3333.33... bps -> 3333
        assert_eq!(calculate_bps(1, 3), Some(3333));

        // Overflow: u64::MAX * 10000 overflows
        assert_eq!(calculate_bps(u64::MAX, 1), None);
    }

    #[test]
    fn test_drawdown_bps() {
        assert_eq!(drawdown_bps(70, 100), Some(3000)); // 30% drawdown
        assert_eq!(drawdown_bps(100, 100), Some(0)); // No drawdown
        assert_eq!(drawdown_bps(110, 100), Some(0)); // Equity growth
        assert_eq!(drawdown_bps(50, 0), None); // Invalid peak
    }

    #[test]
    fn test_min_max() {
        assert_eq!(min_u64(10, 20), 10);
        assert_eq!(max_u64(10, 20), 20);
        assert_eq!(min_u32(10, 20), 10);
        assert_eq!(max_u32(10, 20), 20);
    }

    #[test]
    fn test_clamp() {
        assert_eq!(clamp_u64(50, 10, 100), 50);
        assert_eq!(clamp_u64(5, 10, 100), 10);
        assert_eq!(clamp_u64(150, 10, 100), 100);
        assert_eq!(clamp_u32(50, 10, 100), 50);
    }
}
