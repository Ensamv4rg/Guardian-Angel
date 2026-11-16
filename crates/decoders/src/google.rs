//! Google Analytics: GA4 (`/g/collect`) and Universal Analytics (`/collect`).

use crate::params::{Parsed, PrefixSpec, Spec, form, map_params, merge, payload};
use ga_core::{DataKind::*, DecodedPayload};

const GA4: &[Spec] = &[
    ("tid", "Google Analytics property", TrackerAccount),
    ("cid", "Client ID", PersistentId),
    ("uid", "User ID", UserId),
    ("sid", "Session ID", PersistentId),
    ("en", "Event", Event),
    ("dl", "Page address", PageUrl),
    ("dt", "Page title", PageTitle),
    ("dr", "Came from", Referrer),
    ("ul", "Language", Device),
    ("sr", "Screen size", Device),
    ("uaf", "Browser family", Device),
    ("uam", "Device model", Device),
    ("uap", "Operating system", Device),
    ("uapv", "Operating system version", Device),
    ("uafvl", "Browser versions", Device),
    ("gclid", "Google Ads click ID", ClickId),
    ("_et", "Engagement time (ms)", Event),
];

const GA4_PREFIXES: &[PrefixSpec] = &[
    ("epn.", "Event detail", Event),
    ("ep.", "Event detail", Event),
    ("upn.", "User property", PersonalDetail),
    ("up.", "User property", PersonalDetail),
    ("pr", "Product", Purchase),
];

/// GA4 sends shared parameters in the URL and one line per event in the body.
pub fn ga4(p: &Parsed) -> Option<Vec<DecodedPayload>> {
    let host_ok = p.host_is("google-analytics.com") || p.host == "analytics.google.com";
    if !host_ok || p.path != "/g/collect" {
        return None;
    }
    let lines: Vec<&str> = p
        .body
        .as_deref()
        .map(|b| b.lines().filter(|l| !l.trim().is_empty()).collect())
        .unwrap_or_default();

    let hits = if lines.is_empty() {
        vec![p.query.clone()]
    } else {
        lines
            .into_iter()
            .map(|line| {
                let mut params = p.query.clone();
                merge(&mut params, form(line));
                params
            })
            .collect()
    };
    Some(
        hits.iter()
            .map(|params| payload("Google", "Google Analytics 4", p, map_params(params, GA4, GA4_PREFIXES)))
            .collect(),
    )
}

const UA: &[Spec] = &[
    ("tid", "Google Analytics property", TrackerAccount),
    ("cid", "Client ID", PersistentId),
    ("uid", "User ID", UserId),
    ("t", "Hit type", Event),
    ("dl", "Page address", PageUrl),
    ("dp", "Page path", PageUrl),
    ("dt", "Page title", PageTitle),
    ("dr", "Came from", Referrer),
    ("ec", "Event category", Event),
    ("ea", "Event action", Event),
    ("el", "Event label", Event),
    ("ti", "Transaction ID", Purchase),
    ("tr", "Order value", Purchase),
    ("cu", "Currency", Purchase),
    ("ul", "Language", Device),
    ("sr", "Screen size", Device),
    ("vp", "Window size", Device),
    ("gclid", "Google Ads click ID", ClickId),
];

const UA_PREFIXES: &[PrefixSpec] = &[("cd", "Custom dimension", Other), ("pr", "Product", Purchase)];

/// Universal Analytics (retired by Google in 2023-24 but still on many sites).
pub fn universal_analytics(p: &Parsed) -> Option<Vec<DecodedPayload>> {
    let path_ok = matches!(p.path.as_str(), "/collect" | "/j/collect" | "/r/collect" | "/batch");
    if !p.host_is("google-analytics.com") || !path_ok {
        return None;
    }
    let hits: Vec<Vec<(String, String)>> = match p.body.as_deref() {
        Some(body) => body
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|line| {
                let mut params = p.query.clone();
                merge(&mut params, form(line));
                params
            })
            .collect(),
        None => vec![p.query.clone()],
    };
    // Only version-1 hits are Universal Analytics.
    let hits: Vec<_> = hits.into_iter().filter(|h| h.iter().any(|(k, v)| k == "v" && v == "1")).collect();
    if hits.is_empty() {
        return None;
    }
    Some(
        hits.iter()
            .map(|params| payload("Google", "Google Universal Analytics", p, map_params(params, UA, UA_PREFIXES)))
            .collect(),
    )
}
