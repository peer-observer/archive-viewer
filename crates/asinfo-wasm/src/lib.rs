//! ASN naming, as a module the page loads on demand.
//!
//! `asinfo` embeds the whole ipverse/as-metadata dataset at compile time, which
//! is around 4 MB — more than the entire rest of the viewer. Names are only ever
//! shown on the networks view, so rather than making every visitor download them
//! this lives in a separate WebAssembly module that the page fetches the first
//! time that view is opened.

use wasm_bindgen::prelude::*;

/// Describe many autonomous systems at once.
///
/// Takes a JSON array of ASNs and returns a JSON object keyed by ASN, so a whole
/// table of networks is named in one call across the boundary rather than one
/// call per row.
#[wasm_bindgen(js_name = describeMany)]
pub fn describe_many(asns_json: &str) -> Result<String, JsError> {
    let asns: Vec<u32> = serde_json::from_str(asns_json)
        .map_err(|e| JsError::new(&format!("expected a JSON array of ASNs: {e}")))?;

    let mut out = serde_json::Map::new();
    for asn in asns {
        if let Some(info) = asinfo::lookup(asn) {
            out.insert(
                asn.to_string(),
                serde_json::json!({
                    "handle": info.handle,
                    "description": info.description,
                    "country": info.country.as_str(),
                }),
            );
        }
    }
    Ok(serde_json::Value::Object(out).to_string())
}

/// Dataset version, so the page can show where the names came from.
#[wasm_bindgen(js_name = datasetVersion)]
pub fn dataset_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
