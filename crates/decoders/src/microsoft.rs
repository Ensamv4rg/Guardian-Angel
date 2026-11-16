//! Microsoft Advertising UET (`bat.bing.com`) and LinkedIn Insight Tag
//! (`px.ads.linkedin.com`). LinkedIn is owned by Microsoft.

use crate::params::{Parsed, Spec, map_params, payload};
use ga_core::{DataKind::*, DecodedPayload};

const UET: &[Spec] = &[
    ("ti", "Microsoft Ads tag ID", TrackerAccount),
    ("evt", "Event", Event),
    ("ea", "Event action", Event),
    ("ec", "Event category", Event),
    ("el", "Event label", Event),
    ("p", "Page address", PageUrl),
    ("tl", "Page title", PageTitle),
    ("r", "Came from", Referrer),
    ("msclkid", "Microsoft ad click ID", ClickId),
    ("gv", "Order value", Purchase),
    ("gc", "Currency", Purchase),
    ("lg", "Language", Device),
    ("sw", "Screen width", Device),
    ("sh", "Screen height", Device),
];

pub fn bing_uet(p: &Parsed) -> Option<Vec<DecodedPayload>> {
    if p.host != "bat.bing.com" || !p.path.starts_with("/action/") {
        return None;
    }
    let params = p.query_and_form_body();
    Some(vec![payload(
        "Microsoft",
        "Microsoft Advertising (Bing UET)",
        p,
        map_params(&params, UET, &[]),
    )])
}

const INSIGHT: &[Spec] = &[
    ("pid", "LinkedIn partner ID", TrackerAccount),
    ("url", "Page address", PageUrl),
    ("conversionId", "Conversion", Event),
    ("li_fat_id", "LinkedIn ad click ID", ClickId),
];

pub fn linkedin_insight(p: &Parsed) -> Option<Vec<DecodedPayload>> {
    if p.host != "px.ads.linkedin.com" || !matches!(p.path.as_str(), "/collect" | "/collect/") {
        return None;
    }
    let params = p.query_and_form_body();
    Some(vec![payload("Microsoft", "LinkedIn Insight Tag", p, map_params(&params, INSIGHT, &[]))])
}
