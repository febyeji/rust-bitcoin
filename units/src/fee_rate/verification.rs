// SPDX-License-Identifier: CC0-1.0

//! Verification tests for the `fee_rate` module.

use super::FeeRate;
use crate::amount::Amount;
use crate::weight::Weight;

// Note regarding the `unwind` parameter: this defines how many iterations
// of loops kani will unwind before handing off to the SMT solver. Basically
// it should be set as low as possible such that Kani still succeeds (doesn't
// return "undecidable").
//
// There is more info here: https://model-checking.github.io/kani/tutorial-loop-unwinding.html

/// Verifies that `from_sat_per_kwu(r).to_sat_per_kwu_floor() == r` for all `u32` values.
///
/// This proves the internal representation (sat/MvB) preserves full precision
/// when constructed from sat/kwu — the floor division in `to_sat_per_kwu_floor`
/// is exact (lossless) for fee rates created via `from_sat_per_kwu`.
#[kani::unwind(4)]
#[kani::proof]
fn fee_rate_sat_per_kwu_roundtrip() {
    let r = kani::any::<u32>();
    let fee_rate = FeeRate::from_sat_per_kwu(r);
    assert_eq!(fee_rate.to_sat_per_kwu_floor(), u64::from(r));
}

/// Verifies the core fee calculation property: for any fee rate (sat/kwu) and
/// weight (wu), `mul_by_weight` returns exactly `ceil(rate * weight / 1000)`.
///
/// This proves two critical safety properties:
/// 1. Fees are never rounded **down** (no underpayment).
/// 2. Fees are the **smallest** integer that is not less than the true fee
///    (no unnecessary overpayment beyond the 1-sat ceiling).
///
/// When `mul_by_weight` returns an error, this proof also verifies that the
/// true result would genuinely overflow (either the intermediate u64
/// multiplication or the Amount maximum).
#[kani::unwind(4)]
#[kani::proof]
fn fee_calculation_ceil_exact() {
    let r = kani::any::<u32>();
    let w = kani::any::<u64>();

    let fee_rate = FeeRate::from_sat_per_kwu(r);
    let weight = Weight::from_wu(w);

    // Compute the mathematically exact result using u128 (no overflow possible).
    let exact_product = u128::from(r) * u128::from(w);
    let expected_fee =
        if exact_product % 1000 == 0 { exact_product / 1000 } else { exact_product / 1000 + 1 };

    match fee_rate.mul_by_weight(weight) {
        crate::NumOpResult::Valid(amount) => {
            // The fee must be exactly ceil(r * w / 1000).
            assert_eq!(u128::from(amount.to_sat()), expected_fee);
        }
        crate::NumOpResult::Error(_) => {
            // Verify the error is genuine: either the intermediate multiplication
            // overflows u64 or the ceiling result exceeds Amount::MAX.
            let overflows_u64 = exact_product > u128::from(u64::MAX);
            let exceeds_amount_max = expected_fee > u128::from(Amount::MAX.to_sat());
            assert!(overflows_u64 || exceeds_amount_max);
        }
    }
}
