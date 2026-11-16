//! What a cookie is for, judged from its name. Covers cookies on sites that
//! are not on a tracker list: many tracking tools set their cookies under the
//! website's own domain (`_ga` on example.com), which a domain list misses.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CookiePurpose {
    /// Set by a known tracking tool under the site's own domain.
    Tracking,
    /// Keeps you signed in or remembers your session.
    Login,
    /// Bot protection and anti-forgery tokens.
    Security,
    /// Language, theme, region.
    Preferences,
    /// Records your cookie-banner choice.
    Consent,
    Unknown,
}

/// Exact names (lowercase) set by tracking tools on the site's own domain.
const TRACKING_EXACT: &[(&str, &str)] = &[
    ("_ga", "Google Analytics"),
    ("_gid", "Google Analytics"),
    ("__utma", "Google Analytics"),
    ("__utmb", "Google Analytics"),
    ("__utmc", "Google Analytics"),
    ("__utmz", "Google Analytics"),
    ("_fbp", "Meta Pixel"),
    ("_fbc", "Meta Pixel"),
    ("_uetsid", "Microsoft Advertising"),
    ("_uetvid", "Microsoft Advertising"),
    ("_uetmsclkid", "Microsoft Advertising"),
    ("_clck", "Microsoft Clarity"),
    ("_clsk", "Microsoft Clarity"),
    ("_ttp", "TikTok Pixel"),
    ("_tt_enable_cookie", "TikTok Pixel"),
    ("_pin_unauth", "Pinterest Tag"),
    ("_pinterest_ct_ua", "Pinterest Tag"),
    ("_rdt_uuid", "Reddit Pixel"),
    ("_scid", "Snap Pixel"),
    ("li_fat_id", "LinkedIn Insight Tag"),
    ("ajs_anonymous_id", "Twilio Segment"),
    ("ajs_user_id", "Twilio Segment"),
    ("__hstc", "HubSpot"),
    ("__hssc", "HubSpot"),
    ("__hssrc", "HubSpot"),
    ("hubspotutk", "HubSpot"),
    ("_hjid", "Hotjar"),
];

/// Name prefixes (lowercase) set by tracking tools.
const TRACKING_PREFIX: &[(&str, &str)] = &[
    ("_ga_", "Google Analytics"),
    ("_gat", "Google Analytics"),
    ("_gcl_", "Google Ads"),
    ("_hj", "Hotjar"),
    ("amp_", "Amplitude"),
    ("ttcsid", "TikTok Pixel"),
];

const SECURITY_EXACT: &[&str] = &[
    "__cf_bm",
    "cf_clearance",
    "__cflb",
    "_cfuvid",
    "csrftoken",
    "xsrf-token",
    "_csrf",
    "csrf_token",
    "__requestverificationtoken",
];

const CONSENT_EXACT: &[&str] = &["optanonalertboxclosed", "euconsent-v2", "usprivacy", "didomi_token"];

const LOGIN_EXACT: &[&str] = &["phpsessid", "jsessionid", "asp.net_sessionid", "connect.sid", "sid", "laravel_session"];

const PREFERENCE_EXACT: &[&str] = &["lang", "language", "locale", "theme", "timezone", "tz", "currency", "country", "region"];

/// The purpose of a cookie, and the tracking tool behind it when known.
pub fn identify(name: &str) -> (CookiePurpose, Option<&'static str>) {
    let n = name.to_ascii_lowercase();
    if let Some((_, tool)) = TRACKING_EXACT.iter().find(|(k, _)| *k == n) {
        return (CookiePurpose::Tracking, Some(tool));
    }
    if let Some((_, tool)) = TRACKING_PREFIX.iter().find(|(p, _)| n.starts_with(p)) {
        return (CookiePurpose::Tracking, Some(tool));
    }
    // Mixpanel: mp_<token>_mixpanel
    if n.starts_with("mp_") && n.ends_with("_mixpanel") {
        return (CookiePurpose::Tracking, Some("Mixpanel"));
    }
    if CONSENT_EXACT.contains(&n.as_str()) || n.contains("consent") || n.starts_with("cookielawinfo") || n.starts_with("cmplz_") {
        return (CookiePurpose::Consent, None);
    }
    if SECURITY_EXACT.contains(&n.as_str()) || n.contains("csrf") || n.contains("xsrf") {
        return (CookiePurpose::Security, None);
    }
    if LOGIN_EXACT.contains(&n.as_str())
        || n.starts_with("__host-")
        || n.starts_with("__secure-")
        || ["session", "auth", "token", "login", "logged"].iter().any(|w| n.contains(w))
    {
        return (CookiePurpose::Login, None);
    }
    if PREFERENCE_EXACT.contains(&n.as_str()) || n.contains("pref") || n.ends_with("_lang") || n.ends_with("_locale") {
        return (CookiePurpose::Preferences, None);
    }
    (CookiePurpose::Unknown, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_first_party_trackers() {
        assert_eq!(identify("_ga"), (CookiePurpose::Tracking, Some("Google Analytics")));
        assert_eq!(identify("_ga_ABC123"), (CookiePurpose::Tracking, Some("Google Analytics")));
        assert_eq!(identify("_fbp"), (CookiePurpose::Tracking, Some("Meta Pixel")));
        assert_eq!(identify("_hjSessionUser_123"), (CookiePurpose::Tracking, Some("Hotjar")));
        assert_eq!(identify("mp_abc123_mixpanel"), (CookiePurpose::Tracking, Some("Mixpanel")));
    }

    #[test]
    fn recognises_everyday_cookies() {
        assert_eq!(identify("PHPSESSID").0, CookiePurpose::Login);
        assert_eq!(identify("__Host-next-auth.csrf-token").0, CookiePurpose::Security);
        assert_eq!(identify("user_session").0, CookiePurpose::Login);
        assert_eq!(identify("__cf_bm").0, CookiePurpose::Security);
        assert_eq!(identify("OptanonConsent").0, CookiePurpose::Consent);
        assert_eq!(identify("lang").0, CookiePurpose::Preferences);
        assert_eq!(identify("site_prefs").0, CookiePurpose::Preferences);
        assert_eq!(identify("x9q2").0, CookiePurpose::Unknown);
    }
}
