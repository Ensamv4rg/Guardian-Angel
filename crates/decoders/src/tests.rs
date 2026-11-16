use super::*;
use ga_core::{DataKind, DecodedField, DecodedPayload};

const HASH: &str = "a6b54c20a7b96eeac1a911e6da3124a560fe6dc042ebf270e3676e7095b95652";

fn get(url: &str) -> Vec<DecodedPayload> {
    decode(&Request { method: "GET", url, body: None })
}

fn post(url: &str, body: &str) -> Vec<DecodedPayload> {
    decode(&Request { method: "POST", url, body: Some(body) })
}

fn field<'a>(p: &'a DecodedPayload, key: &str) -> &'a DecodedField {
    p.fields.iter().find(|f| f.key == key).unwrap_or_else(|| panic!("no field {key} in {:?}", p.fields))
}

#[test]
fn decodes_ga4_page_view() {
    let hits = get(
        "https://region1.google-analytics.com/g/collect?v=2&tid=G-ABC123&gtm=45je&_p=987&cid=1234567890.1700000000\
         &ul=en-us&sr=1920x1080&uaf=chrome&sid=1700000000&dl=https%3A%2F%2Fshop.example%2Fcart&dt=Your%20cart&en=page_view",
    );
    assert_eq!(hits.len(), 1);
    let h = &hits[0];
    assert_eq!((h.company, h.product), ("Google", "Google Analytics 4"));
    assert_eq!(field(h, "cid").kind, DataKind::PersistentId);
    assert_eq!(field(h, "cid").label, "Client ID");
    assert_eq!(field(h, "dl").value, "https://shop.example/cart");
    assert_eq!(field(h, "dt").value, "Your cart");
    assert_eq!(field(h, "en").value, "page_view");
    // Unknown internal parameters are left out, not guessed.
    assert!(h.fields.iter().all(|f| f.key != "gtm" && f.key != "_p"));
}

#[test]
fn splits_ga4_batched_events() {
    let hits = post(
        "https://region1.google-analytics.com/g/collect?v=2&tid=G-ABC123&cid=1.2&dl=https%3A%2F%2Fshop.example%2F",
        "en=add_to_cart&ep.item_name=Running%20shoes\nen=purchase&epn.value=59.9\n",
    );
    assert_eq!(hits.len(), 2);
    assert_eq!(field(&hits[0], "en").value, "add_to_cart");
    assert_eq!(field(&hits[0], "ep.item_name").label, "Event detail: item_name");
    assert_eq!(field(&hits[0], "ep.item_name").value, "Running shoes");
    assert_eq!(field(&hits[1], "en").value, "purchase");
    // Shared URL parameters apply to every event.
    assert_eq!(field(&hits[1], "cid").value, "1.2");
}

#[test]
fn decodes_universal_analytics_only_for_version_1() {
    let hits = get("https://www.google-analytics.com/collect?v=1&t=pageview&tid=UA-1-1&cid=555.666&dl=https%3A%2F%2Fnews.example%2F");
    assert_eq!(hits[0].product, "Google Universal Analytics");
    assert_eq!(field(&hits[0], "t").value, "pageview");
    assert!(get("https://www.google-analytics.com/collect?v=9&cid=1").is_empty());
}

#[test]
fn decodes_meta_pixel_with_hashed_email_get_and_post() {
    let url = format!(
        "https://www.facebook.com/tr/?id=999&ev=Purchase&dl=https%3A%2F%2Fshop.example%2Fthanks\
         &ud[em]={HASH}&cd[value]=59.90&cd[currency]=EUR&cd[shoe_size]=42&fbp=fb.1.1700.123"
    );
    let h = &get(&url)[0];
    assert_eq!(h.product, "Meta Pixel");
    assert_eq!(field(h, "ud[em]").kind, DataKind::HashedEmail);
    assert_eq!(field(h, "cd[value]").value, "59.90");
    assert_eq!(field(h, "cd[shoe_size]").label, "Event detail: shoe_size");
    // Most sensitive kind first.
    assert_eq!(h.kinds()[0], DataKind::HashedEmail);

    let posted = post("https://www.facebook.com/tr/", &format!("id=999&ev=Lead&ud%5Bem%5D={HASH}"));
    assert_eq!(field(&posted[0], "ud[em]").kind, DataKind::HashedEmail);
    assert_eq!(field(&posted[0], "ev").value, "Lead");
}

#[test]
fn decodes_bing_and_linkedin() {
    let bing = &get("https://bat.bing.com/action/0?ti=12345&evt=pageLoad&p=https%3A%2F%2Fshop.example%2F&tl=Shop&msclkid=abc")[0];
    assert_eq!(bing.company, "Microsoft");
    assert_eq!(field(bing, "msclkid").kind, DataKind::ClickId);

    let li = &get("https://px.ads.linkedin.com/collect?pid=111&url=https%3A%2F%2Fsaas.example%2Fpricing&fmt=js")[0];
    assert_eq!(li.product, "LinkedIn Insight Tag");
    assert_eq!(field(li, "url").value, "https://saas.example/pricing");
}

#[test]
fn decodes_segment_batch_with_plain_email() {
    let body = r#"{"batch":[
        {"type":"identify","userId":"u-42","anonymousId":"anon-1","traits":{"email":"jo@example.com","plan":"pro"}},
        {"type":"track","event":"Checkout Started","anonymousId":"anon-1",
         "properties":{"revenue":59.9},"context":{"page":{"url":"https://shop.example/checkout"}}}
    ]}"#;
    let hits = post("https://api.segment.io/v1/batch", body);
    assert_eq!(hits.len(), 2);
    assert_eq!(field(&hits[0], "traits.email").kind, DataKind::Email);
    assert_eq!(field(&hits[0], "traits.email").value, "jo@example.com");
    assert_eq!(field(&hits[0], "userId").kind, DataKind::UserId);
    assert_eq!(field(&hits[1], "event").value, "Checkout Started");
    assert_eq!(field(&hits[1], "properties.revenue").value, "59.9");
    assert_eq!(field(&hits[1], "context.page.url").kind, DataKind::PageUrl);
}

#[test]
fn decodes_tiktok_pixel() {
    let body = format!(
        r#"{{"event":"CompletePayment","context":{{"page":{{"url":"https://shop.example/done"}},"user":{{"email":"{HASH}"}}}},"properties":{{"value":59.9,"currency":"EUR"}}}}"#
    );
    let h = &post("https://analytics.tiktok.com/api/v2/pixel", &body)[0];
    assert_eq!(h.company, "ByteDance");
    assert_eq!(field(h, "context.user.email").kind, DataKind::HashedEmail);
    assert_eq!(field(h, "properties.value").value, "59.9");
}

#[test]
fn ignores_everything_else() {
    assert!(get("https://example.org/collect?v=1&cid=1").is_empty());
    assert!(get("https://notfacebook.com/tr/?id=1").is_empty());
    assert!(get("not a url").is_empty());
    assert!(post("https://api.segment.io/v1/batch", "{ broken json").is_empty());
}

#[test]
fn decodes_har_files() {
    let har = serde_json::json!({"log": {
        "pages": [{"id": "page_1", "title": "Shop - Checkout"}],
        "entries": [
            {"pageref": "page_1", "request": {"method": "GET",
              "url": "https://region1.google-analytics.com/g/collect?v=2&tid=G-1&cid=1.2&en=page_view"}},
            {"pageref": "page_1", "request": {"method": "POST", "url": "https://www.facebook.com/tr/",
              "postData": {"mimeType": "application/x-www-form-urlencoded", "text": "id=9&ev=PageView"}}},
            {"pageref": "page_1", "request": {"method": "GET", "url": "https://cdn.example.org/logo.png"}},
            {"pageref": "page_1", "request": {"method": "GET", "url": "https://cdn.example.org/app.js"}}
        ]
    }});
    let r = har::decode_har(&har.to_string()).unwrap();
    assert_eq!(r.requests, 4);
    assert_eq!(r.hits.len(), 2);
    assert_eq!(r.hits[0].page.as_deref(), Some("Shop - Checkout"));
    assert_eq!(r.hits[1].payload.product, "Meta Pixel");
    assert_eq!(r.other_hosts, vec![("cdn.example.org".to_owned(), 2)]);

    assert!(har::decode_har("{}").is_err());
    assert!(har::decode_har("not json").is_err());
}
