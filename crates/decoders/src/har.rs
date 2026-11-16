//! Decodes a HAR file: the network log browsers export from their developer
//! tools ("Save all as HAR"). Lets people see what trackers received on a
//! page today, before the browser extension exists.
//!
//! HAR files can contain cookies and passwords; this module only reads the
//! request URL, method and body, and nothing leaves the machine.

use crate::{Request, decode};
use ga_core::DecodedPayload;
use serde_json::Value;
use std::collections::HashMap;

#[derive(Debug, thiserror::Error)]
pub enum HarError {
    #[error("not a valid HAR file: {0}")]
    Json(#[from] serde_json::Error),
    #[error("not a HAR file: no log.entries")]
    NoEntries,
}

#[derive(Debug, Clone)]
pub struct HarHit {
    /// Title of the page the request belonged to, when the HAR records it.
    pub page: Option<String>,
    pub payload: DecodedPayload,
}

#[derive(Debug, Clone, Default)]
pub struct HarDecode {
    pub requests: usize,
    pub hits: Vec<HarHit>,
    /// Hosts of requests that were not decoded, with counts.
    pub other_hosts: Vec<(String, usize)>,
}

pub fn decode_har(json: &str) -> Result<HarDecode, HarError> {
    let har: Value = serde_json::from_str(json.trim_start_matches('\u{feff}'))?;
    let entries = har.pointer("/log/entries").and_then(Value::as_array).ok_or(HarError::NoEntries)?;

    let pages: HashMap<&str, &str> = har
        .pointer("/log/pages")
        .and_then(Value::as_array)
        .map(|pages| {
            pages
                .iter()
                .filter_map(|p| Some((p.get("id")?.as_str()?, p.get("title")?.as_str()?)))
                .collect()
        })
        .unwrap_or_default();

    let mut out = HarDecode {
        requests: entries.len(),
        ..HarDecode::default()
    };
    let mut other: HashMap<String, usize> = HashMap::new();

    for entry in entries {
        let Some(req) = entry.get("request") else { continue };
        let Some(url) = req.get("url").and_then(Value::as_str) else { continue };
        let method = req.get("method").and_then(Value::as_str).unwrap_or("GET");
        let body = req.pointer("/postData/text").and_then(Value::as_str);
        let page = entry
            .get("pageref")
            .and_then(Value::as_str)
            .and_then(|id| pages.get(id))
            .map(|t| (*t).to_owned());

        let decoded = decode(&Request { method, url, body });
        if decoded.is_empty() {
            if let Some(host) = url::Url::parse(url).ok().and_then(|u| u.host_str().map(str::to_owned)) {
                *other.entry(host).or_default() += 1;
            }
        }
        out.hits.extend(decoded.into_iter().map(|payload| HarHit {
            page: page.clone(),
            payload,
        }));
    }

    let mut other: Vec<(String, usize)> = other.into_iter().collect();
    other.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    out.other_hosts = other;
    Ok(out)
}
