//! A plain-language summary of a tracker request in a format no specific
//! decoder knows: its parameters and JSON fields, with IDs, emails, scrambled
//! values and page addresses picked out by their names and shapes.

use crate::Request;
use crate::params::{Parsed, json_text, looks_hashed, payload};
use ga_core::{DataKind, DecodedField, DecodedPayload};
use serde_json::Value;

const MAX_FIELDS: usize = 40;
const MAX_VALUE: usize = 300;

/// Parameter names that hold a long-lived ID for you or your device.
const ID_KEYS: &[&str] = &[
    "uid", "userid", "user_id", "cid", "clientid", "client_id", "anonymousid", "anonymous_id", "deviceid", "device_id",
    "did", "idfa", "idfv", "gaid", "aaid", "adid", "ad_id", "advertisingid", "advertising_id", "visitorid", "visitor_id",
    "vid", "guid", "uuid", "distinct_id", "_fbp", "fbp", "puid", "mid", "muid", "tuid", "external_id", "installation_id",
    "install_id", "machine_id", "machineid", "session_id", "sessionid", "sid",
];
const CLICK_KEYS: &[&str] = &["gclid", "fbclid", "_fbc", "fbc", "ttclid", "msclkid", "dclid", "wbraid", "gbraid", "li_fat_id", "epik", "twclid"];
const URL_KEYS: &[&str] = &["url", "dl", "page", "page_url", "location", "href", "u", "ref", "referrer", "dr", "r"];
const DEVICE_KEYS: &[&str] = &["ua", "useragent", "user_agent", "sr", "screen", "lang", "language", "ul", "os", "os_version", "model", "device", "tz", "timezone"];

fn kind_for(key: &str, value: &str) -> DataKind {
    let k = key.rsplit(['.', '[']).next().unwrap_or(key).trim_end_matches(']').to_ascii_lowercase();
    if value.contains('@') && value.contains('.') && !value.contains(' ') && value.len() < 120 {
        DataKind::Email
    } else if looks_hashed(value) && (k.contains("em") || k.contains("mail")) {
        DataKind::HashedEmail
    } else if looks_hashed(value) {
        DataKind::HashedPersonalDetail
    } else if CLICK_KEYS.contains(&k.as_str()) {
        DataKind::ClickId
    } else if ID_KEYS.contains(&k.as_str()) || (k.ends_with("_id") || k.ends_with("id")) && value.len() >= 12 {
        DataKind::PersistentId
    } else if value.starts_with("http://") || value.starts_with("https://") || URL_KEYS.contains(&k.as_str()) {
        DataKind::PageUrl
    } else if DEVICE_KEYS.contains(&k.as_str()) {
        DataKind::Device
    } else if matches!(k.as_str(), "e" | "ev" | "en" | "event" | "event_name" | "action" | "type" | "t") {
        DataKind::Event
    } else {
        DataKind::Other
    }
}

fn label(kind: DataKind, key: &str) -> String {
    let what = match kind {
        DataKind::Email => "Email address",
        DataKind::HashedEmail => "Email address (scrambled)",
        DataKind::HashedPersonalDetail => "Scrambled value (often an email or phone number)",
        DataKind::ClickId => "Ad click ID",
        DataKind::PersistentId => "ID for you or your device",
        DataKind::PageUrl => "Address",
        DataKind::Device => "Device detail",
        DataKind::Event => "What you did",
        _ => "Parameter",
    };
    format!("{what} ({key})")
}

fn field(key: String, value: String) -> Option<DecodedField> {
    if value.is_empty() {
        return None;
    }
    let kind = kind_for(&key, &value);
    let value = if value.len() > MAX_VALUE {
        format!("{}...", value.chars().take(MAX_VALUE).collect::<String>())
    } else {
        value
    };
    Some(DecodedField {
        label: label(kind, &key),
        key,
        kind,
        value,
    })
}

fn flatten(prefix: &str, value: &Value, depth: usize, out: &mut Vec<(String, String)>) {
    match value {
        Value::Object(map) if depth < 3 => {
            for (k, v) in map {
                let key = if prefix.is_empty() { k.clone() } else { format!("{prefix}.{k}") };
                flatten(&key, v, depth + 1, out);
            }
        }
        Value::Array(items) if depth < 3 => {
            for (i, v) in items.iter().take(5).enumerate() {
                flatten(&format!("{prefix}[{i}]"), v, depth + 1, out);
            }
        }
        other => {
            if let Some(text) = json_text(other) {
                out.push((prefix.to_owned(), text));
            }
        }
    }
}

/// Summarises any request. `None` when it carries nothing at all.
pub fn summarize(request: &Request<'_>) -> Option<DecodedPayload> {
    let parsed = Parsed::new(request)?;
    let mut params = parsed.query_and_form_body();
    if let Some(json) = parsed.json_body() {
        flatten("", &json, 0, &mut params);
    }
    let mut fields: Vec<DecodedField> = params.into_iter().filter_map(|(k, v)| field(k, v)).collect();
    if fields.is_empty() {
        return None;
    }
    // Most telling first, then cut to a readable size.
    fields.sort_by_key(|f| f.kind);
    fields.truncate(MAX_FIELDS);
    Some(payload("", "Unrecognised format", &parsed, fields))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_out_ids_emails_and_pages() {
        let p = summarize(&Request {
            method: "POST",
            url: "https://telemetry.example/v1/events?app=chat&deviceId=4f8c2a91e7b34d5f",
            body: Some(r#"{"user":{"email":"a@b.com","id":"user-123"},"event":"opened","page":"https://site.example/x"}"#),
        })
        .unwrap();
        let kind = |k: &str| p.fields.iter().find(|f| f.key == k).map(|f| f.kind);
        assert_eq!(kind("deviceId"), Some(DataKind::PersistentId));
        assert_eq!(kind("user.email"), Some(DataKind::Email));
        assert_eq!(kind("event"), Some(DataKind::Event));
        assert_eq!(kind("page"), Some(DataKind::PageUrl));
        assert_eq!(p.fields[0].kind, DataKind::Email, "most sensitive first");
        assert!(summarize(&Request { method: "GET", url: "https://x.example/pixel.gif", body: None }).is_none());
    }
}
