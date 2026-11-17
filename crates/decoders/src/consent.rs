//! Privacy choices carried inside tracker requests, so a report can say
//! whether a site kept sending your data after you said no.
//!
//! - Google Consent Mode: `gcs=G1xy` (x = ads storage, y = analytics; 1 yes, 0 no).
//! - IAB TCF v2: `gdpr=1` and `gdpr_consent=<string>`, the consent string most
//!   EU cookie banners produce. Purposes 1 (store information on your
//!   device), 3 and 4 (personalised ads) are read from it.
//! - US Privacy (CCPA): `us_privacy=1YYN`; the third letter `Y` means you
//!   opted out of the sale of your data.
//! - `npa=1`: non-personalised ads requested.

use crate::Request;
use crate::params::Parsed;
use ga_core::ConsentSignal;

pub fn signals(request: &Request<'_>) -> Vec<ConsentSignal> {
    let Some(parsed) = Parsed::new(request) else { return Vec::new() };
    let params = parsed.query_and_form_body();
    let get = |key: &str| params.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str()).filter(|v| !v.is_empty());
    let mut out = Vec::new();

    if let Some(gcs) = get("gcs")
        && let Some(signal) = google_consent_mode(gcs)
    {
        out.push(signal);
    }
    if get("gdpr") == Some("1")
        && let Some(tc) = get("gdpr_consent").or_else(|| get("gdpr_pd")).or_else(|| get("tcstring"))
        && let Some(signal) = tcf(tc)
    {
        out.push(signal);
    }
    if let Some(usp) = get("us_privacy").or_else(|| get("ccpa"))
        && let Some(signal) = us_privacy(usp)
    {
        out.push(signal);
    }
    if get("npa") == Some("1") {
        out.push(ConsentSignal {
            source: "Ad request".into(),
            summary: "Asked for non-personalised ads".into(),
            refused: true,
        });
    }
    out
}

fn google_consent_mode(gcs: &str) -> Option<ConsentSignal> {
    let b = gcs.as_bytes();
    if b.len() != 4 || &b[..2] != b"G1" {
        return None;
    }
    let word = |c: u8| match c {
        b'1' => "allowed",
        b'0' => "refused",
        _ => "not set",
    };
    Some(ConsentSignal {
        source: "Google Consent Mode".into(),
        summary: format!("Advertising cookies {}, analytics cookies {}", word(b[2]), word(b[3])),
        refused: b[2] == b'0' || b[3] == b'0',
    })
}

/// Reads purposes 1, 3 and 4 from a TCF v2 consent string.
pub fn tcf(tc: &str) -> Option<ConsentSignal> {
    let core = tc.split('.').next()?;
    let bytes = base64url(core)?;
    let bit = |i: usize| bytes.get(i / 8).is_some_and(|b| b & (0x80 >> (i % 8)) != 0);
    let version = (0..6).fold(0u8, |v, i| (v << 1) | u8::from(bit(i)));
    if version != 2 {
        return None;
    }
    // Field widths before PurposesConsent: 6+36+36+12+12+6+12+12+6+1+1+12.
    const PURPOSES: usize = 152;
    if bytes.len() * 8 < PURPOSES + 24 {
        return None;
    }
    let purpose = |n: usize| bit(PURPOSES + n - 1);
    let (storage, ads) = (purpose(1), purpose(3) || purpose(4));
    let word = |yes: bool| if yes { "allowed" } else { "refused" };
    Some(ConsentSignal {
        source: "Cookie banner (IAB TCF)".into(),
        summary: format!("Storing information on your device {}, personalised ads {}", word(storage), word(ads)),
        refused: !storage || !ads,
    })
}

fn us_privacy(usp: &str) -> Option<ConsentSignal> {
    let b = usp.as_bytes();
    if b.len() != 4 || b[0] != b'1' {
        return None;
    }
    let opted_out = b[2] == b'Y';
    Some(ConsentSignal {
        source: "US Privacy (CCPA)".into(),
        summary: if opted_out { "You opted out of the sale of your data".into() } else { "Sale of your data not opted out".into() },
        refused: opted_out,
    })
}

fn base64url(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in text.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' | b'+' => 62,
            b'_' | b'/' => 63,
            b'=' => break,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(url: &str) -> Vec<ConsentSignal> {
        signals(&Request {
            method: "GET",
            url,
            body: None,
        })
    }

    #[test]
    fn reads_google_consent_mode() {
        let s = req("https://www.google-analytics.com/g/collect?v=2&gcs=G100&cid=1.2");
        assert_eq!(s.len(), 1);
        assert!(s[0].refused);
        assert!(s[0].summary.contains("Advertising cookies refused"));
        assert!(!req("https://x.example/c?gcs=G111")[0].refused);
    }

    #[test]
    fn reads_tcf_consent_strings() {
        // Everything refused: an official example string with no purposes set.
        let refused = tcf("CPXxRfAPXxRfAAfKABENB-CgAAAAAAAAAAYgAAAAAAAA").expect("valid TCF v2");
        assert!(refused.refused, "{}", refused.summary);
        // Build one with purposes 1-10 allowed.
        let mut bits = [false; 200];
        bits[4] = true; // version 2 = 000010
        for p in 0..10 {
            bits[152 + p] = true;
        }
        let bytes: Vec<u8> = bits.chunks(8).map(|c| c.iter().fold(0u8, |v, b| (v << 1) | u8::from(*b))).collect();
        let text = encode(&bytes);
        let allowed = tcf(&text).unwrap();
        assert!(!allowed.refused, "{}", allowed.summary);
        let via_request = req(&format!("https://ads.example/bid?gdpr=1&gdpr_consent={text}"));
        assert_eq!(via_request.len(), 1);
    }

    #[test]
    fn reads_us_privacy_and_npa() {
        let s = req("https://ads.example/x?us_privacy=1YYN&npa=1");
        assert_eq!(s.len(), 2);
        assert!(s.iter().all(|x| x.refused));
        assert!(!req("https://ads.example/x?us_privacy=1YNN")[0].refused);
        assert!(req("https://ads.example/x?v=1").is_empty());
    }

    fn encode(bytes: &[u8]) -> String {
        const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        let (mut acc, mut bits) = (0u32, 0u32);
        for b in bytes {
            acc = (acc << 8) | u32::from(*b);
            bits += 8;
            while bits >= 6 {
                bits -= 6;
                out.push(T[((acc >> bits) & 63) as usize] as char);
            }
        }
        if bits > 0 {
            out.push(T[((acc << (6 - bits)) & 63) as usize] as char);
        }
        out
    }
}
