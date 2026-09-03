//! Timeline histogram over an unknown, streaming time range.
//!
//! An archive's time range is not known until the last event has been read, so
//! this starts at a fine bin width and halves its resolution whenever it would
//! otherwise exceed [`MAX_BINS`] — doubling the bin width and merging adjacent
//! pairs. Memory stays bounded, no second pass is needed, and counts stay exact.
//!
//! Counts are kept per *kind*, not per group, so the UI can break a group down
//! by type (connection events by inbound/outbound/closed/…) over the whole
//! archive rather than only over the events that fit in the retention budget.
//! Group series are the sum of their kinds.

/// Bin count ceiling. Above roughly this many bins a chart cannot show the
/// difference anyway, and it bounds memory at `MAX_BINS × kinds × 8` bytes —
/// a few megabytes for the ~100 kinds a real archive contains.
pub const MAX_BINS: usize = 4096;

/// Starting bin width. Widths only ever double from here.
pub const MIN_BIN_MS: u64 = 100;

/// Per-kind event counts over time.
#[derive(Debug, Clone)]
pub struct Histogram {
    start_ms: u64,
    bin_ms: u64,
    bins: usize,
    /// `series[kind][bin]`. Every row is exactly `bins` long.
    series: Vec<Vec<u64>>,
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
            bins: 0,
            series: Vec::new(),
            total: 0,
        }
    }

    pub fn bin_ms(&self) -> u64 {
        self.bin_ms
    }

    /// Timestamp at the start of bin 0. Bin `i` covers
    /// `[start_ms + i*bin_ms, start_ms + (i+1)*bin_ms)`.
    pub fn start_ms(&self) -> u64 {
        self.start_ms
    }

    pub fn bins(&self) -> usize {
        self.bins
    }

    pub fn total(&self) -> u64 {
        self.total
    }

    pub fn is_empty(&self) -> bool {
        self.bins == 0
    }

    /// Counts per bin for one kind. Empty if the kind was never seen.
    pub fn series(&self, kind: u16) -> &[u64] {
        self.series
            .get(kind as usize)
            .map_or(&[], |row| row.as_slice())
    }

    /// Record one event.
    ///
    /// Timestamps are not guaranteed to be monotonic — the extractors are
    /// independent — so an earlier-than-`start_ms` arrival extends the histogram
    /// backwards rather than being dropped.
    pub fn add(&mut self, timestamp_ms: u64, kind: u16) {
        self.total += 1;
        self.ensure_kind(kind);

        if self.bins == 0 {
            // Anchor bin 0 on a multiple of the bin width, purely so the first
            // bin boundary is a round number.
            self.start_ms = timestamp_ms - (timestamp_ms % self.bin_ms);
            self.set_bins(1);
        }
        if timestamp_ms < self.start_ms {
            self.extend_backwards(timestamp_ms);
        }
        if timestamp_ms < self.start_ms {
            // The range could not reach back far enough. Count it in the first
            // bin rather than dropping it, so totals stay exact.
            self.series[kind as usize][0] += 1;
            return;
        }

        loop {
            let index = ((timestamp_ms - self.start_ms) / self.bin_ms) as usize;
            if index < self.bins {
                self.series[kind as usize][index] += 1;
                return;
            }
            if index < MAX_BINS {
                self.set_bins(index + 1);
                continue;
            }
            self.coarsen();
        }
    }

    fn ensure_kind(&mut self, kind: u16) {
        let needed = kind as usize + 1;
        while self.series.len() < needed {
            self.series.push(vec![0; self.bins]);
        }
    }

    fn set_bins(&mut self, bins: usize) {
        self.bins = bins;
        for row in &mut self.series {
            row.resize(bins, 0);
        }
    }

    /// Grow the range backwards to cover `timestamp_ms`.
    ///
    /// New bins are placed on the existing grid — `start_ms` is moved back by a
    /// whole number of bins — so bin boundaries stay consistent with the counts
    /// already recorded. The shift is clamped so `start_ms` never crosses zero:
    /// a malformed event can carry a timestamp near the epoch (prost does not
    /// enforce proto2 `required`), and an underflow here would wrap into an
    /// enormous allocation and abort the module.
    fn extend_backwards(&mut self, timestamp_ms: u64) {
        loop {
            let wanted = (self.start_ms - timestamp_ms).div_ceil(self.bin_ms);
            if self.bins as u64 + wanted <= MAX_BINS as u64 {
                let extra = wanted.min(self.start_ms / self.bin_ms) as usize;
                if extra > 0 {
                    for row in &mut self.series {
                        let mut grown = vec![0u64; extra];
                        grown.append(row);
                        *row = grown;
                    }
                    self.bins += extra;
                    self.start_ms -= extra as u64 * self.bin_ms;
                }
                return;
            }
            self.coarsen();
        }
    }

    /// Halve the resolution: merge adjacent pairs and double the bin width.
    ///
    /// `start_ms` deliberately stays put. Merging pairs makes bin 0 cover
    /// `[start, start + 2·bin_ms)`, which is exactly what the doubled width
    /// describes; re-aligning `start_ms` to the new width here would shift every
    /// bin by half its width, and the error would compound on each coarsening.
    fn coarsen(&mut self) {
        for row in &mut self.series {
            let merged: Vec<u64> = row.chunks(2).map(|pair| pair.iter().sum()).collect();
            *row = merged;
        }
        self.bins = self.bins.div_ceil(2);
        self.bin_ms *= 2;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn total_of(histogram: &Histogram) -> u64 {
        (0..histogram.series.len())
            .map(|k| histogram.series(k as u16).iter().sum::<u64>())
            .sum()
    }

    #[test]
    fn counts_land_in_the_right_bin() {
        let mut histogram = Histogram::new();
        histogram.add(1_000, 0);
        histogram.add(1_050, 0);
        histogram.add(1_100, 1);

        assert_eq!(histogram.bin_ms(), MIN_BIN_MS);
        assert_eq!(histogram.series(0)[0], 2);
        assert_eq!(histogram.series(1)[1], 1);
        assert_eq!(total_of(&histogram), 3);
    }

    #[test]
    fn an_unseen_kind_has_an_empty_series() {
        let mut histogram = Histogram::new();
        histogram.add(1_000, 3);
        assert_eq!(histogram.series(9), &[] as &[u64]);
        // Kinds below the highest seen exist but are all zero.
        assert_eq!(histogram.series(0).iter().sum::<u64>(), 0);
        assert_eq!(histogram.series(0).len(), histogram.bins());
    }

    /// Coarsening must never lose or duplicate an event.
    #[test]
    fn coarsening_preserves_every_count() {
        let mut histogram = Histogram::new();
        let count = 200_000u64;
        for i in 0..count {
            histogram.add(1_700_000_000_000 + i * 3, (i % 8) as u16);
        }

        assert!(histogram.bin_ms() > MIN_BIN_MS, "must have coarsened");
        assert!(histogram.bins() <= MAX_BINS);
        assert_eq!(total_of(&histogram), count);
        assert_eq!(histogram.total(), count);
        for kind in 0..8u16 {
            assert_eq!(histogram.series(kind).iter().sum::<u64>(), count / 8);
        }
    }

    /// Every event must remain findable in the bin its timestamp maps to. This
    /// is what the coarsening alignment gets wrong if `start_ms` is re-aligned.
    #[test]
    fn events_stay_in_the_bin_their_timestamp_maps_to() {
        let mut histogram = Histogram::new();
        let times: Vec<u64> = (0..50_000u64).map(|i| 1_700_000_000_000 + i * 37).collect();
        for (i, t) in times.iter().enumerate() {
            histogram.add(*t, (i % 3) as u16);
        }
        assert!(histogram.bin_ms() > MIN_BIN_MS, "must have coarsened");

        // Recount independently and compare bin for bin.
        let mut expected = vec![vec![0u64; histogram.bins()]; 3];
        for (i, t) in times.iter().enumerate() {
            let bin = ((t - histogram.start_ms()) / histogram.bin_ms()) as usize;
            assert!(
                bin < histogram.bins(),
                "timestamp {t} maps outside the histogram"
            );
            expected[i % 3][bin] += 1;
        }
        for kind in 0..3u16 {
            assert_eq!(histogram.series(kind), expected[kind as usize].as_slice());
        }
    }

    /// Extractors are independent, so a later event can carry an earlier
    /// timestamp. Those must extend the range, not be dropped or misplaced.
    #[test]
    fn out_of_order_timestamps_extend_backwards() {
        let mut histogram = Histogram::new();
        histogram.add(10_000, 0);
        histogram.add(5_000, 1);
        histogram.add(10_000, 0);

        assert_eq!(total_of(&histogram), 3);
        assert!(histogram.start_ms() <= 5_000);
        let bin = ((5_000 - histogram.start_ms()) / histogram.bin_ms()) as usize;
        assert_eq!(histogram.series(1)[bin], 1);
        let bin = ((10_000 - histogram.start_ms()) / histogram.bin_ms()) as usize;
        assert_eq!(histogram.series(0)[bin], 2);
    }

    /// A single event far in the past forces repeated coarsening; it must still
    /// land in the right bin afterwards.
    #[test]
    fn a_very_wide_range_stays_bounded_and_correct() {
        let mut histogram = Histogram::new();
        histogram.add(30_000_000_000, 0);
        histogram.add(0, 1);

        assert!(histogram.bins() <= MAX_BINS);
        assert_eq!(total_of(&histogram), 2);
        let bin = ((30_000_000_000 - histogram.start_ms()) / histogram.bin_ms()) as usize;
        assert_eq!(histogram.series(0)[bin], 1);
        assert_eq!(histogram.series(1)[0], 1);
    }

    /// A malformed event can carry a timestamp at the epoch while the rest of
    /// the archive is recent. That must not underflow `start_ms`: in a release
    /// wasm build the wrap becomes an enormous allocation and aborts the module.
    #[test]
    fn an_epoch_timestamp_among_recent_ones_is_counted_not_fatal() {
        let mut histogram = Histogram::new();
        for i in 0..1_000u64 {
            histogram.add(1_788_000_000_000 + i * 250, 0);
        }
        histogram.add(0, 1);
        histogram.add(1, 1);

        assert_eq!(histogram.total(), 1_002);
        assert_eq!(total_of(&histogram), 1_002, "no event is lost");
        assert!(histogram.bins() <= MAX_BINS);
        assert_eq!(histogram.series(1).iter().sum::<u64>(), 2);
    }

    #[test]
    fn every_series_has_the_same_length() {
        let mut histogram = Histogram::new();
        for i in 0..20_000u64 {
            histogram.add(1_700_000_000_000 + i * 11, (i % 17) as u16);
        }
        for kind in 0..17u16 {
            assert_eq!(
                histogram.series(kind).len(),
                histogram.bins(),
                "kind {kind}"
            );
        }
    }
}
