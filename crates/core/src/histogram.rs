//! Timeline histogram over an unknown, streaming time range.
//!
//! An archive's time range is not known until the last event has been read, so
//! this starts at a fine bin width and halves its resolution whenever it would
//! otherwise exceed [`MAX_BINS`] — doubling the bin width and merging adjacent
//! pairs. Memory stays bounded, no second pass is needed, and counts stay exact.

use crate::kind::{Group, GROUPS};

/// Bin count ceiling. Above roughly this many bins a chart cannot show the
/// difference anyway, and it bounds memory at 4096 bins × 8 groups × 8 bytes.
pub const MAX_BINS: usize = 4096;

/// Starting bin width. Widths only ever double from here.
pub const MIN_BIN_MS: u64 = 100;

/// Counts per group over time.
#[derive(Debug, Clone)]
pub struct Histogram {
    /// Timestamp (ms) at the start of bin 0.
    start_ms: u64,
    bin_ms: u64,
    /// `bins[bin][group]`.
    bins: Vec<[u64; GROUPS.len()]>,
    total: u64,
}

impl Default for Histogram {
    fn default() -> Self {
        Self::new()
    }
}

impl Histogram {
    pub fn new() -> Self {
        Histogram {
            start_ms: 0,
            bin_ms: MIN_BIN_MS,
            bins: Vec::new(),
            total: 0,
        }
    }

    pub fn bin_ms(&self) -> u64 {
        self.bin_ms
    }

    pub fn start_ms(&self) -> u64 {
        self.start_ms
    }

    pub fn total(&self) -> u64 {
        self.total
    }

    pub fn bins(&self) -> &[[u64; GROUPS.len()]] {
        &self.bins
    }

    pub fn is_empty(&self) -> bool {
        self.bins.is_empty()
    }

    /// Record one event.
    ///
    /// Timestamps are not guaranteed to be monotonic (events come from several
    /// extractors), so earlier-than-`start_ms` arrivals extend the histogram
    /// backwards rather than being dropped.
    pub fn add(&mut self, timestamp_ms: u64, group: Group) {
        self.total += 1;
        if self.bins.is_empty() {
            // Anchor bin 0 on a multiple of the bin width so that later
            // coarsening merges aligned pairs.
            self.start_ms = timestamp_ms - (timestamp_ms % self.bin_ms);
            self.bins.push([0; GROUPS.len()]);
        }

        if timestamp_ms < self.start_ms {
            self.extend_backwards(timestamp_ms);
        }
        let mut index = ((timestamp_ms - self.start_ms) / self.bin_ms) as usize;
        while index >= self.bins.len() {
            if self.bins.len() == MAX_BINS {
                self.coarsen();
                index = ((timestamp_ms - self.start_ms) / self.bin_ms) as usize;
                continue;
            }
            self.bins.push([0; GROUPS.len()]);
        }
        self.bins[index][group.index()] += 1;
    }

    fn extend_backwards(&mut self, timestamp_ms: u64) {
        let new_start = timestamp_ms - (timestamp_ms % self.bin_ms);
        let extra = ((self.start_ms - new_start) / self.bin_ms) as usize;
        // Coarsen first if prepending would overflow the bin budget.
        if self.bins.len() + extra > MAX_BINS {
            self.coarsen();
            self.extend_backwards(timestamp_ms);
            return;
        }
        let mut prefix = vec![[0u64; GROUPS.len()]; extra];
        prefix.append(&mut self.bins);
        self.bins = prefix;
        self.start_ms = new_start;
    }

    /// Halve the resolution: merge adjacent pairs and double the bin width.
    fn coarsen(&mut self) {
        let merged: Vec<[u64; GROUPS.len()]> = self
            .bins
            .chunks(2)
            .map(|pair| {
                let mut sum = pair[0];
                if let Some(second) = pair.get(1) {
                    for (slot, value) in sum.iter_mut().zip(second) {
                        *slot += value;
                    }
                }
                sum
            })
            .collect();
        self.bins = merged;
        self.bin_ms *= 2;
        // `start_ms` was aligned to the old width; realign to the new one so bin
        // boundaries stay on multiples of `bin_ms`.
        self.start_ms -= self.start_ms % self.bin_ms;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn total_of(histogram: &Histogram) -> u64 {
        histogram.bins().iter().flat_map(|bin| bin.iter()).sum()
    }

    #[test]
    fn counts_land_in_the_right_bin() {
        let mut histogram = Histogram::new();
        histogram.add(1_000, Group::EbpfMessage);
        histogram.add(1_050, Group::EbpfMessage);
        histogram.add(1_100, Group::Rpc);

        assert_eq!(histogram.bin_ms(), MIN_BIN_MS);
        assert_eq!(histogram.bins()[0][Group::EbpfMessage.index()], 2);
        assert_eq!(histogram.bins()[1][Group::Rpc.index()], 1);
        assert_eq!(total_of(&histogram), 3);
    }

    /// Coarsening must never lose or duplicate an event.
    #[test]
    fn coarsening_preserves_every_count() {
        let mut histogram = Histogram::new();
        let count = 200_000u64;
        for i in 0..count {
            // Spread over ~20 seconds at 100 ms bins: far past MAX_BINS.
            histogram.add(1_700_000_000_000 + i * 3, GROUPS[(i % 8) as usize]);
        }

        assert!(histogram.bin_ms() > MIN_BIN_MS, "must have coarsened");
        assert!(histogram.bins().len() <= MAX_BINS);
        assert_eq!(total_of(&histogram), count);
        assert_eq!(histogram.total(), count);

        // Each group got an eighth of the events.
        for group in GROUPS {
            let per_group: u64 = histogram.bins().iter().map(|b| b[group.index()]).sum();
            assert_eq!(per_group, count / 8);
        }
    }

    /// Extractors are independent, so a later event can carry an earlier
    /// timestamp. Those must extend the range, not be dropped.
    #[test]
    fn out_of_order_timestamps_extend_backwards() {
        let mut histogram = Histogram::new();
        histogram.add(10_000, Group::EbpfMessage);
        histogram.add(5_000, Group::Rpc);
        histogram.add(10_000, Group::EbpfMessage);

        assert_eq!(total_of(&histogram), 3);
        assert!(histogram.start_ms() <= 5_000);
        let first = (5_000 - histogram.start_ms()) / histogram.bin_ms();
        assert_eq!(histogram.bins()[first as usize][Group::Rpc.index()], 1);
    }

    #[test]
    fn a_very_wide_range_stays_bounded() {
        let mut histogram = Histogram::new();
        histogram.add(0, Group::Ipc);
        // Nearly a year later.
        histogram.add(30_000_000_000, Group::Ipc);

        assert!(histogram.bins().len() <= MAX_BINS);
        assert_eq!(total_of(&histogram), 2);
    }

    #[test]
    fn bins_stay_aligned_to_their_width() {
        let mut histogram = Histogram::new();
        for i in 0..100_000u64 {
            histogram.add(1_700_000_000_123 + i * 7, Group::Log);
        }
        assert_eq!(histogram.start_ms() % histogram.bin_ms(), 0);
    }
}
