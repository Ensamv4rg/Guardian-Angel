//! Request parsing and field-mapping helpers shared by the decoders.

use crate::Request;
use ga_core::{DataKind, DecodedField, DecodedPayload};
use serde_json::Value;

/// A request split into the parts decoders look at.
pub struct Parsed {
    pub url: String,
    pub host: String,
    pub path: String,
    pub query: Vec<(String, String)>,
    pub body: Option<String>,
}

impl Parsed {
    pub fn new(req: &Request<'_>) -> Option<Self> {
        let url = url::Url::parse(req.url).ok()?;
        Some(Self {
            url: req.url.to_owned(),
            host: url.host_str()?.to_ascii_lowercase(),
            path: url.path().to_owned(),
            query: url.query_pairs().map(|(k, v)| (k.into_owned(), v.into_owned())).collect(),
            body: req.body.filter(|b| !b.trim().is_empty()).map(str::to_owned),
        })
    }

    pub fn host_is(&self, domain: &str) -> bool {
        self.host == domain || self.host.ends_with(&format!(".{domain}"))
    }

    /// URL parameters plus form-encoded body parameters (body wins on clashes).
    pub fn query_and_form_body(&self) -> Vec<(String, String)> {
        let mut params = self.query.clone();
        if let Some(body) = &self.body
            && !body.trim_start().starts_with(['{', '['])
        {
            merge(&mut params, form(body));
        }
        params
    }

    pub fn json_body(&self) -> Option<Value> {
        serde_json::from_str(self.body.as_deref()?).ok()
    }
}

pub fn form(text: &str) -> Vec<(String, String)> {
    url::form_urlencoded::parse(text.trim().as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

/// Adds `extra` to `base`, replacing values of keys already present.
pub fn merge(base: &mut Vec<(String, String)>, extra: Vec<(String, String)>) {
    for (k, v) in extra {
        match base.iter_mut().find(|(bk, _)| *bk == k) {
            Some(slot) => slot.1 = v,
            None => base.push((k, v)),
        }
    }
}

/// Known parameter: exact key, label, kind.
pub type Spec = (&'static str, &'static str, DataKind);
/// Parameter family by prefix, e.g. `ep.` -> "Event detail".
pub type PrefixSpec = (&'static str, &'static str, DataKind);

/// Maps parameters to fields. Exact keys first, then prefixes; anything else
/// is dropped. Empty values are skipped.
pub fn map_params(params: &[(String, String)], specs: &[Spec], prefixes: &[PrefixSpec]) -> Vec<DecodedField> {
    let mut fields = Vec::new();
    for (key, value) in params {
        if value.is_empty() {
            continue;
        }
        let found = specs
            .iter()
            .find(|(k, _, _)| k == key)
            .map(|(_, label, kind)| ((*label).to_owned(), *kind))
            .or_else(|| {
                prefixes.iter().find(|(p, _, _)| key.starts_with(p)).map(|(p, label, kind)| {
                    // `cd[shoe_size]` -> "Event detail: shoe_size"
                    let name = key[p.len()..].trim_end_matches(']');
                    (format!("{label}: {name}"), *kind)
                })
            });
        if let Some((label, kind)) = found {
            fields.push(DecodedField {
                key: key.clone(),
                label,
                kind,
                value: value.clone(),
            });
        }
    }
    fields
}

/// Reads JSON values by pointer (e.g. `/context/page/url`) into fields.
pub fn map_json(value: &Value, specs: &[Spec]) -> Vec<DecodedField> {
    specs
        .iter()
        .filter_map(|(pointer, label, kind)| {
            let text = json_text(value.pointer(pointer)?)?;
            Some(DecodedField {
                key: pointer.trim_start_matches('/').replace('/', "."),
                label: (*label).to_owned(),
                kind: *kind,
                value: text,
            })
        })
        .collect()
}

/// Every entry of a JSON object as fields, e.g. all `properties.*`.
pub fn map_json_object(value: Option<&Value>, key_prefix: &str, label: &str, kind: DataKind) -> Vec<DecodedField> {
    let Some(Value::Object(map)) = value else { return Vec::new() };
    map.iter()
        .filter_map(|(k, v)| {
            Some(DecodedField {
                key: format!("{key_prefix}.{k}"),
                label: format!("{label}: {k}"),
                kind,
                value: json_text(v)?,
            })
        })
        .collect()
}

pub fn json_text(v: &Value) -> Option<String> {
    match v {
        Value::Null => None,
        Value::String(s) if s.is_empty() => None,
        Value::String(s) => Some(s.clone()),
        Value::Bool(_) | Value::Number(_) => Some(v.to_string()),
        Value::Array(_) | Value::Object(_) => Some(v.to_string()),
    }
}

/// SHA-256 hex, the format trackers use for "privacy-safe" emails.
pub fn looks_hashed(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

pub fn payload(company: &'static str, product: &'static str, p: &Parsed, fields: Vec<DecodedField>) -> DecodedPayload {
    DecodedPayload {
        company,
        product,
        request_url: p.url.clone(),
        fields,
    }
}
