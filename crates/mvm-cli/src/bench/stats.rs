//! Percentile statistics (pure).

/// Linear-interpolated percentile over an unsorted sample. `p` is in
/// `[0, 100]`. Returns `NaN` for an empty sample (callers summarise
/// only non-empty run sets).
pub fn percentile(samples: &[f64], p: f64) -> f64 {
    if samples.is_empty() {
        return f64::NAN;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    if sorted.len() == 1 {
        return sorted[0];
    }
    let rank = (p / 100.0) * ((sorted.len() - 1) as f64);
    let lo = rank.floor() as usize;
    let hi = rank.ceil() as usize;
    if lo == hi {
        sorted[lo]
    } else {
        let frac = rank - lo as f64;
        sorted[lo] + (sorted[hi] - sorted[lo]) * frac
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx(a: f64, b: f64) {
        assert!((a - b).abs() < 1e-9, "expected {b}, got {a}");
    }

    #[test]
    fn percentile_linear_interpolation_on_known_vector() {
        let v = vec![10.0, 20.0, 30.0, 40.0]; // n=4
        approx(percentile(&v, 0.0), 10.0);
        approx(percentile(&v, 100.0), 40.0);
        // p50 = midpoint of the [0..3] index range = rank 1.5 → 25.
        approx(percentile(&v, 50.0), 25.0);
    }

    #[test]
    fn percentile_single_and_empty() {
        approx(percentile(&[7.0], 50.0), 7.0);
        assert!(percentile(&[], 50.0).is_nan());
    }
}
