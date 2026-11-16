//! A simple, explainable privacy score: 100 minus capped penalties, each
//! shown to the user so the number is never a mystery.

use ga_core::{AppScan, Confidence, Exposure, ExtensionScan, PrivacyScan, Risk};
use ga_report::CookieReport;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Penalty {
    pub reason: String,
    pub points: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Score {
    /// 0 (worst) to 100 (best).
    pub value: u32,
    pub penalties: Vec<Penalty>,
}

/// (points each, cap) per kind of finding.
const SETTING: (u32, u32) = (3, 30);
const RISKY_EXTENSION: (u32, u32) = (8, 24);
const TRACKING_COMPANY: (u32, u32) = (1, 20);
const APP_WITH_SDK: (u32, u32) = (2, 16);

fn penalty(count: usize, (each, cap): (u32, u32), reason: String) -> Option<Penalty> {
    let points = (count as u32).saturating_mul(each).min(cap);
    (points > 0).then_some(Penalty { reason, points })
}

pub fn score(
    privacy: Option<&PrivacyScan>,
    extensions: Option<&ExtensionScan>,
    cookies: Option<&CookieReport>,
    apps: Option<&AppScan>,
) -> Score {
    let mut penalties = Vec::new();
    if let Some(p) = privacy {
        let n = p.settings.iter().filter(|s| s.exposure == Exposure::Exposed).count();
        penalties.extend(penalty(n, SETTING, format!("{n} Windows settings share your data")));
    }
    if let Some(e) = extensions {
        let n = e.extensions.iter().filter(|x| x.enabled && x.risk == Risk::High).count();
        penalties.extend(penalty(n, RISKY_EXTENSION, format!("{n} enabled extensions can read every website")));
    }
    if let Some(c) = cookies {
        let n = c.companies.len();
        penalties.extend(penalty(n, TRACKING_COMPANY, format!("{n} tracking companies have cookies in your browsers")));
    }
    if let Some(a) = apps {
        let n = a.apps.iter().filter(|x| x.findings.iter().any(|f| f.confidence == Confidence::High)).count();
        penalties.extend(penalty(n, APP_WITH_SDK, format!("{n} apps include tracking or telemetry SDKs")));
    }
    let lost: u32 = penalties.iter().map(|p| p.points).sum();
    Score {
        value: 100u32.saturating_sub(lost),
        penalties,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_machine_scores_100_and_penalties_are_capped() {
        assert_eq!(score(None, None, None, None).value, 100);
        let p = penalty(50, SETTING, "x".into()).unwrap();
        assert_eq!(p.points, 30);
        assert!(penalty(0, SETTING, "x".into()).is_none());
    }
}
