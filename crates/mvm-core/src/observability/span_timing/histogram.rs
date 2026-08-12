//! Fixed-memory latency histogram with logarithmic buckets.
//!
//! Each power of two is split into [`SUB_COUNT`] linear sub-buckets, which
//! bounds the relative error of any recorded value at ~12% while keeping the
//! whole histogram at a constant 2 KiB. That matters because one of these is
//! held per instrumented span name for the lifetime of the process, so an
//! unbounded sample vector would grow without limit on a long-running daemon.

/// Bits of sub-bucket resolution within each power of two.
const SUB_BITS: u32 = 2;
/// Linear sub-buckets per power of two.
const SUB_COUNT: u64 = 1 << SUB_BITS;
/// Total bucket count: one set of sub-buckets per `u64` exponent.
pub const BUCKET_COUNT: usize = 64 * SUB_COUNT as usize;

/// Bucket a duration in nanoseconds falls into.
///
/// Values below [`SUB_COUNT`] are stored exactly in the leading buckets; every
/// larger value maps to `(exponent, sub)` where `exponent` is the position of
/// its most significant bit.
pub fn bucket_index(ns: u64) -> usize {
    if ns < SUB_COUNT {
        return ns as usize;
    }
    let exp = 63 - ns.leading_zeros();
    let sub = (ns >> (exp - SUB_BITS)) & (SUB_COUNT - 1);
    ((exp as usize) << SUB_BITS) | sub as usize
}

/// Smallest nanosecond value that maps to `index`.
pub fn bucket_lower(index: usize) -> u64 {
    if (index as u64) < SUB_COUNT {
        return index as u64;
    }
    let exp = (index >> SUB_BITS) as u32;
    let sub = (index as u64) & (SUB_COUNT - 1);
    (SUB_COUNT | sub) << (exp - SUB_BITS)
}

/// Width in nanoseconds of the value range covered by `index`.
pub fn bucket_width(index: usize) -> u64 {
    if (index as u64) < SUB_COUNT {
        return 1;
    }
    let exp = (index >> SUB_BITS) as u32;
    1 << (exp - SUB_BITS)
}

/// A latency distribution over nanosecond samples.
#[derive(Clone)]
pub struct LogHistogram {
    buckets: Box<[u64; BUCKET_COUNT]>,
    count: u64,
}

impl Default for LogHistogram {
    fn default() -> Self {
        Self::new()
    }
}

impl LogHistogram {
    /// An empty histogram.
    pub fn new() -> Self {
        Self {
            buckets: Box::new([0; BUCKET_COUNT]),
            count: 0,
        }
    }

    /// Record one nanosecond sample.
    pub fn record(&mut self, ns: u64) {
        self.buckets[bucket_index(ns)] += 1;
        self.count += 1;
    }

    /// Number of samples recorded.
    pub fn count(&self) -> u64 {
        self.count
    }

    /// Fold `other` into `self`.
    pub fn merge(&mut self, other: &LogHistogram) {
        for (slot, add) in self.buckets.iter_mut().zip(other.buckets.iter()) {
            *slot += add;
        }
        self.count += other.count;
    }

    /// Estimate the value at `q` (0.0..=1.0), interpolating within the
    /// containing bucket. Returns `None` when no samples have been recorded.
    ///
    /// The result carries the histogram's ~12% bucket error; it is a profiling
    /// signal, not an SLO measurement.
    pub fn quantile(&self, q: f64) -> Option<u64> {
        if self.count == 0 {
            return None;
        }
        let q = q.clamp(0.0, 1.0);
        // Rank is 1-based so that q=0 selects the first sample and q=1 the last.
        let target = (q * self.count as f64).ceil().max(1.0) as u64;
        let mut seen = 0u64;
        for (index, &n) in self.buckets.iter().enumerate() {
            if n == 0 {
                continue;
            }
            if seen + n >= target {
                let into = target - seen;
                let width = bucket_width(index);
                // Spread the bucket's samples evenly across its value range.
                let offset = (width.saturating_mul(into.saturating_sub(1))) / n;
                return Some(bucket_lower(index) + offset.min(width.saturating_sub(1)));
            }
            seen += n;
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_values_are_exact() {
        for ns in 0..SUB_COUNT {
            assert_eq!(bucket_index(ns), ns as usize);
            assert_eq!(bucket_lower(bucket_index(ns)), ns);
        }
    }

    #[test]
    fn bucket_lower_is_the_inverse_of_bucket_index() {
        for ns in [4u64, 5, 7, 8, 15, 1_000, 1_000_000, 1_000_000_000, u64::MAX] {
            let index = bucket_index(ns);
            let lower = bucket_lower(index);
            assert!(lower <= ns, "lower {lower} > ns {ns}");
            assert!(
                ns - lower < bucket_width(index),
                "ns {ns} outside bucket {index} starting at {lower}"
            );
        }
    }

    #[test]
    fn bucket_index_is_monotonic() {
        let mut last = 0;
        for shift in 0..64 {
            let index = bucket_index(1u64 << shift);
            assert!(index >= last, "index went backwards at 2^{shift}");
            last = index;
        }
    }

    #[test]
    fn bucket_index_stays_in_range() {
        assert!(bucket_index(u64::MAX) < BUCKET_COUNT);
    }

    #[test]
    fn relative_error_is_bounded() {
        // Every value lands in a bucket whose width is at most 1/4 of the
        // bucket's own lower bound, i.e. <= ~25% worst case, ~12% typical.
        for ns in [100u64, 12_345, 999_999, 5_000_000_000] {
            let index = bucket_index(ns);
            let width = bucket_width(index);
            let lower = bucket_lower(index);
            assert!(
                (width as f64) / (lower as f64) <= 0.25,
                "bucket at {ns} too wide: width {width} lower {lower}"
            );
        }
    }

    #[test]
    fn quantile_of_empty_histogram_is_none() {
        assert_eq!(LogHistogram::new().quantile(0.5), None);
    }

    #[test]
    fn quantile_tracks_a_uniform_distribution() {
        let mut h = LogHistogram::new();
        for ns in 1..=1000u64 {
            h.record(ns * 1_000);
        }
        assert_eq!(h.count(), 1000);
        let p50 = h.quantile(0.5).expect("p50");
        let p95 = h.quantile(0.95).expect("p95");
        // Within the histogram's bucket error of the true 500k / 950k.
        assert!((400_000..=600_000).contains(&p50), "p50 = {p50}");
        assert!((850_000..=1_050_000).contains(&p95), "p95 = {p95}");
        assert!(p50 < p95);
    }

    #[test]
    fn quantile_of_a_single_sample_is_that_sample() {
        let mut h = LogHistogram::new();
        h.record(1_000_000);
        let p50 = h.quantile(0.5).expect("p50");
        assert!((900_000..=1_100_000).contains(&p50), "p50 = {p50}");
    }

    #[test]
    fn merge_sums_counts_and_preserves_distribution() {
        let mut a = LogHistogram::new();
        let mut b = LogHistogram::new();
        for _ in 0..10 {
            a.record(1_000);
            b.record(1_000_000);
        }
        a.merge(&b);
        assert_eq!(a.count(), 20);
        let p10 = a.quantile(0.1).expect("p10");
        let p90 = a.quantile(0.9).expect("p90");
        assert!(p10 < 2_000, "p10 = {p10}");
        assert!(p90 > 500_000, "p90 = {p90}");
    }
}
