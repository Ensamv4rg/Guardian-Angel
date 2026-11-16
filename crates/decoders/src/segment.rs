//! Twilio Segment (`api.segment.io/v1/...`): JSON events, often carrying
//! plain email addresses in `traits`.

use crate::params::{Parsed, Spec, json_text, looks_hashed, map_json, map_json_object, payload};
use ga_core::{DataKind::*, DecodedField, DecodedPayload};
use serde_json::Value;

const EVENT: &[Spec] = &[
    ("/type", "Call type", Event),
    ("/event", "Event", Event),
    ("/name", "Page name", PageTitle),
    ("/userId", "User ID", UserId),
    ("/anonymousId", "Anonymous ID", PersistentId),
    ("/writeKey", "Segment source key", TrackerAccount),
    ("/context/page/url", "Page address", PageUrl),
    ("/context/page/title", "Page title", PageTitle),
    ("/context/page/referrer", "Came from", Referrer),
    ("/context/locale", "Language", Device),
    ("/context/userAgent", "Browser", Device),
    ("/context/ip", "IP address", PersonalDetail),
];

pub fn segment(p: &Parsed) -> Option<Vec<DecodedPayload>> {
    let host_ok = p.host == "api.segment.io" || p.host == "api.segment.com";
    if !host_ok || !p.path.starts_with("/v1/") {
        return None;
    }
    let body = p.json_body()?;
    let events: Vec<&Value> = match body.get("batch").and_then(Value::as_array) {
        Some(batch) => batch.iter().collect(),
        None => vec![&body],
    };
    Some(
        events
            .into_iter()
            .map(|e| {
                let mut fields = map_json(e, EVENT);
                fields.extend(traits(e.get("traits").or_else(|| e.pointer("/context/traits"))));
                fields.extend(map_json_object(e.get("properties"), "properties", "Event detail", Event));
                payload("Twilio Segment", "Twilio Segment", p, fields)
            })
            .collect(),
    )
}

/// `traits` describe the person: email, name, phone, address...
fn traits(value: Option<&Value>) -> Vec<DecodedField> {
    let Some(Value::Object(map)) = value else { return Vec::new() };
    map.iter()
        .filter_map(|(k, v)| {
            let text = json_text(v)?;
            let kind = match k.to_ascii_lowercase().as_str() {
                "email" if looks_hashed(&text) => HashedEmail,
                "email" => Email,
                _ if looks_hashed(&text) => HashedPersonalDetail,
                _ => PersonalDetail,
            };
            Some(DecodedField {
                key: format!("traits.{k}"),
                label: format!("About you: {k}"),
                kind,
                value: text,
            })
        })
        .collect()
}
