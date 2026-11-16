//! Meta (Facebook) Pixel: `facebook.com/tr`.

use crate::params::{Parsed, PrefixSpec, Spec, map_params, payload};
use ga_core::{DataKind::*, DecodedPayload};

const PIXEL: &[Spec] = &[
    ("id", "Meta Pixel ID", TrackerAccount),
    ("ev", "Event", Event),
    ("dl", "Page address", PageUrl),
    ("rl", "Came from", Referrer),
    ("fbp", "Meta browser ID (_fbp cookie)", PersistentId),
    ("fbc", "Facebook ad click ID", ClickId),
    ("ud[em]", "Email address (hashed)", HashedEmail),
    ("ud[ph]", "Phone number (hashed)", HashedPersonalDetail),
    ("ud[fn]", "First name (hashed)", HashedPersonalDetail),
    ("ud[ln]", "Last name (hashed)", HashedPersonalDetail),
    ("ud[ge]", "Gender (hashed)", HashedPersonalDetail),
    ("ud[db]", "Date of birth (hashed)", HashedPersonalDetail),
    ("ud[ct]", "City (hashed)", HashedPersonalDetail),
    ("ud[st]", "State (hashed)", HashedPersonalDetail),
    ("ud[zp]", "Postcode (hashed)", HashedPersonalDetail),
    ("ud[country]", "Country (hashed)", HashedPersonalDetail),
    ("ud[external_id]", "Site's ID for you (hashed)", UserId),
    ("cd[value]", "Order value", Purchase),
    ("cd[currency]", "Currency", Purchase),
    ("cd[content_ids]", "Product IDs", Purchase),
    ("cd[content_name]", "Product name", Purchase),
    ("cd[num_items]", "Number of items", Purchase),
    ("sw", "Screen width", Device),
    ("sh", "Screen height", Device),
];

const PIXEL_PREFIXES: &[PrefixSpec] = &[("cd[", "Event detail", Event), ("ud[", "Personal detail", HashedPersonalDetail)];

pub fn pixel(p: &Parsed) -> Option<Vec<DecodedPayload>> {
    if !p.host_is("facebook.com") || !matches!(p.path.as_str(), "/tr" | "/tr/") {
        return None;
    }
    let params = p.query_and_form_body();
    Some(vec![payload("Meta", "Meta Pixel", p, map_params(&params, PIXEL, PIXEL_PREFIXES))])
}
