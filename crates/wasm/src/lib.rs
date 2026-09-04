//! The wasm-bindgen boundary for the archive viewer.
//!
//! This is deliberately thin: all decoding, aggregation and view logic lives in
//! `archive-viewer-core`, where it can be tested natively. Everything crossing
//! into JavaScript is a JSON string, which the page parses. The payloads are
//! small — a page of rows, a summary object — so this costs little and keeps the
//! JavaScript free of generated bindings.

use archive_viewer_core::analysis::Analysis;
use archive_viewer_core::inspect::{self, Schema};
use archive_viewer_core::view::{self, Filter, QueryCache};
use asmap::Asmap;
use wasm_bindgen::prelude::*;

/// Default retention budget.
///
/// Deliberately well under the address space: wasm32 tops out at 4 GiB, browsers
/// in practice allow rather less, and the zstd decoder needs its own 128 MiB
/// window on top. Retention failing is a labelled partial view; the module
/// running out of memory is a dead page.
const DEFAULT_BUDGET: f64 = 512.0 * 1024.0 * 1024.0;

/// Hard ceiling, whatever the page asks for.
const MAX_BUDGET: f64 = 2.0 * 1024.0 * 1024.0 * 1024.0;

/// One viewing session. Several rotated archive files can be fed in and are
/// reported as one continuous archive.
#[wasm_bindgen]
pub struct Session {
    analysis: Analysis,
    cache: QueryCache,
    schema: Schema,
    /// Optional: enables grouping peers by autonomous system.
    asmap: Option<Asmap>,
}

#[wasm_bindgen]
impl Session {
    /// `budget_bytes` caps how much raw event data is retained for the event
    /// table and inspector. Aggregates always cover every event regardless.
    #[wasm_bindgen(constructor)]
    pub fn new(budget_bytes: Option<f64>) -> Result<Session, JsError> {
        #[cfg(feature = "dev-panics")]
        console_error_panic_hook::set_once();

        let budget = budget_bytes
            .unwrap_or(DEFAULT_BUDGET)
            .clamp(0.0, MAX_BUDGET);
        let schema = Schema::new().map_err(|e| JsError::new(&e))?;
        Ok(Session {
            analysis: Analysis::new(budget as u64),
            cache: QueryCache::new(),
            schema,
            asmap: None,
        })
    }

    /// Start reading a file. Any file still open is finished first.
    #[wasm_bindgen(js_name = beginFile)]
    pub fn begin_file(&mut self, name: &str, size: f64) {
        self.analysis
            .begin_file(name.to_string(), size.max(0.0) as u64);
    }

    /// Feed the next chunk of the current file.
    ///
    /// A decoding error means the file is not a peer-observer archive (or is
    /// corrupt); it is recorded against that file and the session stays usable.
    pub fn push(&mut self, chunk: &[u8]) -> Result<(), JsError> {
        self.analysis
            .push(chunk)
            .map_err(|e| JsError::new(&e.to_string()))
    }

    /// Finish the current file.
    #[wasm_bindgen(js_name = endFile)]
    pub fn end_file(&mut self) {
        self.analysis.end_file();
    }

    /// Counters for the progress display while loading.
    pub fn progress(&self) -> String {
        view::progress(&self.analysis).to_string()
    }

    /// Totals, per-file detail and the event breakdown.
    pub fn summary(&self) -> String {
        view::summary(&self.analysis).to_string()
    }

    /// Per-group event counts over time, downsampled to at most `bins` columns.
    pub fn timeline(&self, bins: u32) -> String {
        view::timeline(&self.analysis, bins as usize).to_string()
    }

    /// One group over time, broken down by kind -- connection events by type,
    /// messages by command, and so on. Covers every event in the archive, not
    /// only the retained ones.
    #[wasm_bindgen(js_name = timelineGroup)]
    pub fn timeline_group(&self, group: &str, bins: u32) -> String {
        view::timeline_group(&self.analysis, group, bins as usize).to_string()
    }

    /// Groups that actually occur in the archive, busiest first.
    #[wasm_bindgen(js_name = groupsPresent)]
    pub fn groups_present(&self) -> String {
        serde_json::json!(view::groups_present(&self.analysis)).to_string()
    }

    /// A page of the peer table.
    pub fn peers(&self, sort: &str, descending: bool, offset: u32, limit: u32) -> String {
        view::peers(
            &self.analysis,
            sort,
            descending,
            offset as usize,
            limit as usize,
        )
        .to_string()
    }

    /// One peer in full.
    #[wasm_bindgen(js_name = peerDetail)]
    pub fn peer_detail(&self, peer_id: f64) -> String {
        view::peer_detail(&self.analysis, peer_id.max(0.0) as u64).to_string()
    }

    /// A page of the raw event table. `filter_json` is the UI's filter object.
    pub fn query(&mut self, filter_json: &str, offset: u32, limit: u32) -> Result<String, JsError> {
        let filter: Filter = serde_json::from_str(filter_json)
            .map_err(|e| JsError::new(&format!("bad filter: {e}")))?;
        let result = view::query(
            &self.analysis,
            &mut self.cache,
            &filter,
            offset as usize,
            limit as usize,
        );
        Ok(result.to_string())
    }

    /// A page of the sequence diagram: the same rows as [`Session::query`],
    /// plus the request/reply ties among them.
    pub fn sequence(
        &mut self,
        filter_json: &str,
        offset: u32,
        limit: u32,
    ) -> Result<String, JsError> {
        let filter: Filter = serde_json::from_str(filter_json)
            .map_err(|e| JsError::new(&format!("bad filter: {e}")))?;
        let result = view::sequence(
            &self.analysis,
            &mut self.cache,
            &filter,
            offset as usize,
            limit as usize,
        );
        Ok(result.to_string())
    }

    /// How long connections lasted, one distribution per connection type.
    #[wasm_bindgen(js_name = connectionDurations)]
    pub fn connection_durations(&self, ending: &str) -> String {
        view::connection_durations(&self.analysis, ending).to_string()
    }

    /// One peer's traffic over its own lifetime, inbound against outbound.
    #[wasm_bindgen(js_name = peerTimeline)]
    pub fn peer_timeline(&self, peer_id: f64, max_bins: u32) -> String {
        view::peer_timeline(&self.analysis, peer_id as u64, max_bins as usize).to_string()
    }

    /// A raster of per-peer activity over time: one row per peer, one column
    /// per pixel, split by direction.
    #[allow(clippy::too_many_arguments)]
    #[wasm_bindgen(js_name = peerActivity)]
    pub fn peer_activity(
        &self,
        filter_json: &str,
        columns: u32,
        max_rows: u32,
        min_duration_ms: f64,
        sort: &str,
        weight: &str,
    ) -> Result<String, JsError> {
        let filter: Filter = serde_json::from_str(filter_json)
            .map_err(|e| JsError::new(&format!("bad filter: {e}")))?;
        Ok(view::peer_activity(
            &self.analysis,
            &filter,
            columns as usize,
            max_rows as usize,
            min_duration_ms.max(0.0) as u64,
            sort,
            weight,
        )
        .to_string())
    }

    /// Transaction relay: who announced what first, and what duplicates cost.
    pub fn relay(&self, sort: &str, descending: bool, limit: u32) -> String {
        view::relay(&self.analysis, sort, descending, limit as usize).to_string()
    }

    /// How each kind of request fared, and how long the answers took.
    pub fn exchanges(&self) -> String {
        view::exchanges(&self.analysis).to_string()
    }

    /// Load a Bitcoin Core asmap file, enabling the networks view.
    ///
    /// The page fetches this at runtime rather than embedding it: it is ~1.5 MB,
    /// it is updated independently of this tool, and everything else works
    /// without it.
    #[wasm_bindgen(js_name = loadAsmap)]
    pub fn load_asmap(&mut self, bytes: Vec<u8>) -> Result<(), JsError> {
        let asmap = Asmap::from_bytes(bytes)
            .map_err(|e| JsError::new(&format!("not a valid asmap file: {e}")))?;
        self.asmap = Some(asmap);
        Ok(())
    }

    /// Whether an asmap file has been loaded.
    #[wasm_bindgen(js_name = asmapLoaded)]
    pub fn asmap_loaded(&self) -> bool {
        self.asmap.is_some()
    }

    /// Peers grouped by autonomous system, busiest first.
    pub fn networks(&self, offset: u32, limit: u32) -> String {
        view::networks(
            &self.analysis,
            self.asmap.as_ref(),
            offset as usize,
            limit as usize,
        )
        .to_string()
    }

    /// The peers making up one network. `asn` is negative for the buckets that
    /// have no autonomous system, which `label` then distinguishes.
    #[wasm_bindgen(js_name = networkPeers)]
    pub fn network_peers(&self, asn: f64, label: &str, limit: u32) -> String {
        let asn = (asn >= 0.0).then_some(asn as u32);
        view::network_peers(
            &self.analysis,
            self.asmap.as_ref(),
            asn,
            label,
            limit as usize,
        )
        .to_string()
    }
    /// The full decoded contents of one retained event, for the inspector.
    #[wasm_bindgen(js_name = eventJson)]
    pub fn event_json(&self, index: u32) -> Result<String, JsError> {
        inspect::event_json(&self.analysis, &self.schema, index)
            .map(|value| value.to_string())
            .map_err(|e| JsError::new(&e))
    }
}
