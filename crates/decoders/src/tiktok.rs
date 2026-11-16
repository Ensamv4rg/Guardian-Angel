//! TikTok Pixel (`analytics.tiktok.com/api/v2/pixel`): JSON events. Only the
//! well-established fields are decoded; the rest is omitted.

use crate::params::{Parsed, Spec, map_json, payload};
use ga_core::{DataKind::*, DecodedPayload};

const PIXEL: &[Spec] = &[
    ("/event", "Event", Event),
    ("/context/page/url", "Page address", PageUrl),
    ("/context/page/referrer", "Came from", Referrer),
    ("/context/user/email", "Email address (hashed)", HashedEmail),
    ("/context/user/phone_number", "Phone number (hashed)", HashedPersonalDetail),
    ("/context/user/external_id", "Site's ID for you", UserId),
    ("/context/ad/callback", "TikTok ad click ID", ClickId),
    ("/properties/value", "Order value", Purchase),
    ("/properties/currency", "Currency", Purchase),
];

pub fn pixel(p: &Parsed) -> Option<Vec<DecodedPayload>> {
    if p.host != "analytics.tiktok.com" || !p.path.starts_with("/api/v2/pixel") {
        return None;
    }
    let body = p.json_body()?;
    Some(vec![payload("ByteDance", "TikTok Pixel", p, map_json(&body, PIXEL))])
}
