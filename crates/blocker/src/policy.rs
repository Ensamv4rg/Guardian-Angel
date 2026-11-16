//! What to block (FR-7): a profile, the user's own allow and block lists, a
//! pause switch, and domains that are never blocked (NFR-10).

use ga_core::{Category, normalize_host};
use ga_knowledge::TrackerDb;
use std::collections::BTreeSet;

/// How aggressively to block. Each step adds categories to the one before.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Profile {
    /// Advertising, data brokers and ad verification. Rarely breaks anything.
    Relaxed,
    /// Also analytics and session recording.
    #[default]
    Balanced,
    /// Also social widgets, tag managers and customer-data tools. May break
    /// embedded posts, chat widgets and some sign-up forms.
    Strict,
}

impl Profile {
    pub fn blocks(self, category: Category) -> bool {
        use Category::*;
        match category {
            // Blocking google.com or yahoo.com would break normal use.
            Platform => false,
            Advertising | AudienceData | AdVerification => true,
            Analytics | SessionRecording => self != Profile::Relaxed,
            Social | TagManagement | CustomerData => self == Profile::Strict,
        }
    }
}

/// Never blocked, whatever the profile or lists say: Windows Update,
/// Defender, activation and certificate revocation checks.
const PROTECTED: &[&str] = &[
    "windowsupdate.com",
    "update.microsoft.com",
    "delivery.mp.microsoft.com",
    "definitionupdates.microsoft.com",
    "wdcp.microsoft.com",
    "wdcpalt.microsoft.com",
    "smartscreen.microsoft.com",
    "smartscreen-prod.microsoft.com",
    "activation.sls.microsoft.com",
    "validation.sls.microsoft.com",
    "licensing.mp.microsoft.com",
    "crl.microsoft.com",
    "oneocsp.microsoft.com",
    "digicert.com",
    "pki.goog",
    "lencr.org",
    "sectigo.com",
    "globalsign.com",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllowReason {
    NotATracker,
    /// The tracker's category is not blocked by the current profile.
    NotInProfile,
    UserAllowed,
    Protected,
    Paused,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow(AllowReason),
    Block {
        /// Company behind the domain, or "Your block list".
        company: String,
        category: Option<Category>,
        /// The listed domain that matched.
        matched: String,
    },
}

#[derive(Debug, Clone, Default)]
pub struct Policy {
    pub profile: Profile,
    allow: BTreeSet<String>,
    block: BTreeSet<String>,
    paused_until_unix: Option<i64>,
}

impl Policy {
    pub fn new(profile: Profile) -> Self {
        Self {
            profile,
            ..Self::default()
        }
    }

    /// Always allow this domain and its subdomains.
    pub fn allow(&mut self, domain: &str) {
        let d = normalize_host(domain);
        self.block.remove(&d);
        self.allow.insert(d);
    }

    /// Always block this domain and its subdomains (unless protected).
    pub fn block(&mut self, domain: &str) {
        let d = normalize_host(domain);
        self.allow.remove(&d);
        self.block.insert(d);
    }

    /// Stops all blocking until the given time ("pause for 10 minutes").
    pub fn pause_until(&mut self, unix: i64) {
        self.paused_until_unix = Some(unix);
    }

    pub fn resume(&mut self) {
        self.paused_until_unix = None;
    }

    pub fn decide(&self, db: &TrackerDb, domain: &str, now_unix: i64) -> Decision {
        let domain = normalize_host(domain.trim_end_matches('.'));
        if self.paused_until_unix.is_some_and(|until| now_unix < until) {
            return Decision::Allow(AllowReason::Paused);
        }
        if matches_any(&domain, PROTECTED.iter().copied()) {
            return Decision::Allow(AllowReason::Protected);
        }
        if matches_any(&domain, self.allow.iter().map(String::as_str)) {
            return Decision::Allow(AllowReason::UserAllowed);
        }
        let tracker = db.classify(&domain);
        if let Some(matched) = longest_match(&domain, &self.block) {
            return Decision::Block {
                company: tracker
                    .map(|m| m.company.to_owned())
                    .unwrap_or_else(|| "Your block list".to_owned()),
                category: tracker.map(|m| m.category),
                matched,
            };
        }
        match tracker {
            Some(m) if self.profile.blocks(m.category) => Decision::Block {
                company: m.company.to_owned(),
                category: Some(m.category),
                matched: m.domain.to_owned(),
            },
            Some(_) => Decision::Allow(AllowReason::NotInProfile),
            None => Decision::Allow(AllowReason::NotATracker),
        }
    }
}

/// `domain` equals `rule` or is a subdomain of it.
fn covers(domain: &str, rule: &str) -> bool {
    domain == rule
        || (domain.len() > rule.len()
            && domain.ends_with(rule)
            && domain.as_bytes()[domain.len() - rule.len() - 1] == b'.')
}

fn matches_any<'a>(domain: &str, rules: impl IntoIterator<Item = &'a str>) -> bool {
    rules.into_iter().any(|r| covers(domain, r))
}

fn longest_match(domain: &str, rules: &BTreeSet<String>) -> Option<String> {
    rules
        .iter()
        .filter(|r| covers(domain, r))
        .max_by_key(|r| r.len())
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> TrackerDb {
        TrackerDb::bundled().unwrap()
    }

    fn blocked(p: &Policy, domain: &str) -> bool {
        matches!(p.decide(&db(), domain, 1_000), Decision::Block { .. })
    }

    #[test]
    fn profiles_add_categories_step_by_step() {
        let relaxed = Policy::new(Profile::Relaxed);
        let balanced = Policy::new(Profile::Balanced);
        let strict = Policy::new(Profile::Strict);

        // Advertising: blocked by all.
        assert!(blocked(&relaxed, "stats.g.doubleclick.net"));
        // Analytics: Balanced and up.
        assert!(!blocked(&relaxed, "www.google-analytics.com"));
        assert!(blocked(&balanced, "www.google-analytics.com"));
        // Social and tag managers: Strict only.
        assert!(!blocked(&balanced, "connect.facebook.com"));
        assert!(!blocked(&balanced, "www.googletagmanager.com"));
        assert!(blocked(&strict, "connect.facebook.com"));
        assert!(blocked(&strict, "www.googletagmanager.com"));
        // Platform: never.
        assert!(!blocked(&strict, "www.google.com"));
        // Unknown: never.
        assert!(!blocked(&strict, "example.org"));
    }

    #[test]
    fn decision_names_the_company() {
        let d = Policy::new(Profile::Relaxed).decide(&db(), "ad.doubleclick.net.", 0);
        assert_eq!(
            d,
            Decision::Block {
                company: "Google".into(),
                category: Some(Category::Advertising),
                matched: "doubleclick.net".into(),
            }
        );
    }

    #[test]
    fn user_lists_override_profile() {
        let mut p = Policy::new(Profile::Strict);
        p.allow("google-analytics.com");
        assert_eq!(
            p.decide(&db(), "www.google-analytics.com", 0),
            Decision::Allow(AllowReason::UserAllowed)
        );

        p.block("annoying.example");
        let d = p.decide(&db(), "cdn.annoying.example", 0);
        assert!(matches!(d, Decision::Block { ref company, .. } if company == "Your block list"));

        // Blocking again moves it back off the allow list.
        p.block("google-analytics.com");
        assert!(blocked(&p, "www.google-analytics.com"));
    }

    #[test]
    fn protected_domains_are_never_blocked() {
        let mut p = Policy::new(Profile::Strict);
        p.block("windowsupdate.com");
        p.block("digicert.com");
        assert_eq!(
            p.decide(&db(), "ctldl.windowsupdate.com", 0),
            Decision::Allow(AllowReason::Protected)
        );
        assert_eq!(p.decide(&db(), "ocsp.digicert.com", 0), Decision::Allow(AllowReason::Protected));
    }

    #[test]
    fn pause_expires() {
        let mut p = Policy::new(Profile::Strict);
        p.pause_until(1_600);
        assert_eq!(p.decide(&db(), "doubleclick.net", 1_000), Decision::Allow(AllowReason::Paused));
        assert!(matches!(p.decide(&db(), "doubleclick.net", 1_600), Decision::Block { .. }));
        p.pause_until(5_000);
        p.resume();
        assert!(matches!(p.decide(&db(), "doubleclick.net", 1_000), Decision::Block { .. }));
    }

    #[test]
    fn suffix_matching_respects_label_boundaries() {
        assert!(covers("a.b.com", "b.com"));
        assert!(covers("b.com", "b.com"));
        assert!(!covers("ab.com", "b.com"));
        assert!(!covers("com", "b.com"));
    }
}
