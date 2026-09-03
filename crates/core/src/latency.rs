//! A compact distribution of millisecond latencies.
//!
//! Kept per peer, so it has to be small: an archive of a churny node has
//! hundreds of thousands of peers, and anything per-peer is multiplied by that.
//! Twenty power-of-two buckets cover sub-millisecond to nine minutes in eighty
//! bytes, which is enough to read a distribution and estimate a median without
//! keeping a single sample.

/// Buckets. Bucket `i` holds latencies in `[2^i - 1, 2^(i+1) - 1)` ms, and the
/// last one is an overflow that catches everything slower.
pub const BUCKETS: usize = 20;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Latencies {
    buckets: [u32; BUCKETS],
    count: u64,
    total_ms: u64,
    min_ms: u64,
    max_ms: u64,
}

impl Latencies {
    pub fn add(&mut self, ms: u64) {
        let bucket = bucket_of(ms);
        self.buckets[bucket] = self.buckets[bucket].saturating_add(1);
        if self.count == 0 {
            self.min_ms = ms;
        } else {
            self.min_ms = self.min_ms.min(ms);
        }
        self.max_ms = self.max_ms.max(ms);
        self.count += 1;
        self.total_ms = self.total_ms.saturating_add(ms);
    }

    pub fn count(&self) -> u64 {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn min_ms(&self) -> u64 {
        self.min_ms
    }

    pub fn max_ms(&self) -> u64 {
        self.max_ms
    }

    pub fn mean_ms(&self) -> f64 {
        if self.count == 0 {
            0.0
        } else {
            self.total_ms as f64 / self.count as f64
        }
    }

    pub fn buckets(&self) -> &[u32; BUCKETS] {
        &self.buckets
    }

    /// Estimate a percentile, in milliseconds.
    ///
    /// The samples themselves are gone, so this interpolates within the bucket
    /// the percentile falls in. It is accurate to that bucket's width, which
    /// doubles as latencies grow -- fine for "about 40 ms", useless for
    /// distinguishing 40 ms from 45 ms, which is the trade a fixed eighty bytes
    /// per peer buys.
    pub fn percentile_ms(&self, p: f64) -> Option<u64> {
        if self.count == 0 {
            return None;
        }
        let target = (self.count as f64 * p.clamp(0.0, 1.0)).ceil().max(1.0) as u64;
        let mut seen = 0u64;
        for (index, &n) in self.buckets.iter().enumerate() {
            let before = seen;
            seen += u64::from(n);
            if seen >= target {
                let (low, high) = bucket_range(index);
                // Where in this bucket the target sample falls.
                let position = (target - before) as f64 / f64::from(n.max(1));
                let width = high.unwrap_or(low.saturating_mul(2)).saturating_sub(low);
                let estimate = low + (width as f64 * position) as u64;
                // Never claim a value outside what was actually observed.
                return Some(estimate.clamp(self.min_ms, self.max_ms));
            }
        }
        Some(self.max_ms)
    }

    /// Fold another distribution in, for aggregating peers into a group.
    pub fn merge(&mut self, other: &Latencies) {
        if other.count == 0 {
            return;
        }
        for (slot, n) in self.buckets.iter_mut().zip(other.buckets) {
            *slot = slot.saturating_add(n);
        }
        self.min_ms = if self.count == 0 {
            other.min_ms
        } else {
            self.min_ms.min(other.min_ms)
        };
        self.max_ms = self.max_ms.max(other.max_ms);
        self.count += other.count;
        self.total_ms = self.total_ms.saturating_add(other.total_ms);
    }
}

/// Which bucket a latency falls in.
fn bucket_of(ms: u64) -> usize {
    (ms.saturating_add(1).ilog2() as usize).min(BUCKETS - 1)
}

/// The `[low, high)` millisecond range a bucket covers. The last bucket has no
/// upper bound.
pub fn bucket_range(index: usize) -> (u64, Option<u64>) {
    let low = (1u64 << index) - 1;
    if index == BUCKETS - 1 {
        (low, None)
    } else {
        (low, Some((1u64 << (index + 1)) - 1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buckets_partition_the_millisecond_range() {
        assert_eq!(bucket_of(0), 0);
        assert_eq!(bucket_of(1), 1);
        assert_eq!(bucket_of(2), 1);
        assert_eq!(bucket_of(3), 2);
        assert_eq!(bucket_of(1000), 9);
        // Everything past the last edge lands in the overflow bucket.
        assert_eq!(bucket_of(1 << 19), BUCKETS - 1);
        assert_eq!(bucket_of(u64::MAX), BUCKETS - 1);

        // Every bucket's range starts where the previous one ends.
        for index in 1..BUCKETS {
            let (low, _) = bucket_range(index);
            let (_, previous_high) = bucket_range(index - 1);
            assert_eq!(Some(low), previous_high);
        }
    }

    #[test]
    fn reports_exact_counts_and_extremes() {
        let mut l = Latencies::default();
        assert!(l.is_empty());
        assert_eq!(l.percentile_ms(0.5), None);

        for ms in [5, 100, 7, 3000, 0] {
            l.add(ms);
        }
        assert_eq!(l.count(), 5);
        assert_eq!(l.min_ms(), 0);
        assert_eq!(l.max_ms(), 3000);
        assert_eq!(l.mean_ms(), 3112.0 / 5.0);
    }

    #[test]
    fn a_percentile_never_escapes_what_was_observed() {
        let mut l = Latencies::default();
        for _ in 0..100 {
            l.add(40);
        }
        // One bucket, one value: every percentile is that value.
        assert_eq!(l.percentile_ms(0.5), Some(40));
        assert_eq!(l.percentile_ms(0.99), Some(40));
        assert_eq!(l.percentile_ms(0.0), Some(40));
    }

    #[test]
    fn a_median_lands_in_the_right_bucket() {
        let mut l = Latencies::default();
        for _ in 0..90 {
            l.add(2);
        }
        for _ in 0..10 {
            l.add(5000);
        }
        let median = l.percentile_ms(0.5).unwrap();
        assert!(
            (1..4).contains(&median),
            "median {median} should be near 2 ms"
        );
        let p95 = l.percentile_ms(0.95).unwrap();
        assert!(p95 >= 4095, "p95 {p95} should be up in the slow bucket");
    }

    #[test]
    fn merging_preserves_the_totals() {
        let mut a = Latencies::default();
        let mut b = Latencies::default();
        for ms in [1, 2, 3] {
            a.add(ms);
        }
        for ms in [400, 500] {
            b.add(ms);
        }
        let mut merged = a.clone();
        merged.merge(&b);
        assert_eq!(merged.count(), 5);
        assert_eq!(merged.min_ms(), 1);
        assert_eq!(merged.max_ms(), 500);
        assert_eq!(merged.mean_ms(), 906.0 / 5.0);

        // Merging an empty distribution changes nothing.
        let mut untouched = a.clone();
        untouched.merge(&Latencies::default());
        assert_eq!(untouched, a);
    }
}
