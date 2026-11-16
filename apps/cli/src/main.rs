//! `guardian`: runs Guardian Angel scans from the terminal.
//!
//! This is a development tool. The real product runs the same crates inside
//! the background service and shows results in the desktop UI.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ga_core::{AppAccess, Exposure, PrivacyScan};
use ga_knowledge::TrackerDb;
use ga_report::{CookieReport, build_cookie_report};
use std::collections::BTreeSet;
use std::fmt::Display;

#[derive(Parser)]
#[command(name = "guardian", version, about = "See who is tracking you on this computer")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scan browser cookies and group them by the company behind them.
    Cookies {
        /// Print the full report as JSON instead of a table.
        #[arg(long)]
        json: bool,
        /// How many companies to list (0 = all).
        #[arg(long, default_value_t = 25)]
        top: usize,
    },
    /// Check Windows privacy settings and which apps used your camera,
    /// microphone or location.
    Privacy {
        /// Print the full result as JSON instead of text.
        #[arg(long)]
        json: bool,
        /// List every app with recorded use, not just the 20 most recent.
        #[arg(long)]
        all_apps: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Cookies { json, top } => {
            let db = TrackerDb::bundled().context("loading the tracker list")?;
            let scan = ga_scanners::browsers::scan_cookies();
            let report = build_cookie_report(&scan, &db);
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print_report(&report, top);
            }
        }
        Command::Privacy { json, all_apps } => {
            let scan = ga_scanners::windows_privacy::scan_privacy();
            if json {
                println!("{}", serde_json::to_string_pretty(&scan)?);
            } else {
                print_privacy(&scan, all_apps);
            }
        }
    }
    Ok(())
}

/// How many recently used apps to list without `--all-apps`.
const RECENT_APPS: usize = 20;

fn print_privacy(scan: &PrivacyScan, all_apps: bool) {
    let count = |e: Exposure| scan.settings.iter().filter(|s| s.exposure == e).count();
    println!("Guardian Angel - Windows privacy settings");
    println!(
        "{} settings share your data, {} protect you, {} could not be determined.",
        count(Exposure::Exposed),
        count(Exposure::Protected),
        count(Exposure::Unknown)
    );

    for (exposure, heading, mark) in [
        (Exposure::Exposed, "Sharing your data", "!"),
        (Exposure::Unknown, "Could not determine", "?"),
        (Exposure::Protected, "Protecting you", "ok"),
    ] {
        let group: Vec<_> = scan.settings.iter().filter(|s| s.exposure == exposure).collect();
        if group.is_empty() {
            continue;
        }
        println!();
        println!("{heading}");
        for s in group {
            let policy = if s.set_by_policy { " (set by policy)" } else { "" };
            println!("  {mark:>2}  {:<42} {}{policy}", s.title, s.state);
            if exposure != Exposure::Protected {
                for line in wrap(s.explanation, 80) {
                    println!("        {line}");
                }
            }
        }
    }

    // Apps that update into versioned folders (Discord, Zoom) appear once per
    // install path. Show each app once per capability: entries arrive sorted
    // most recent first, so the first one seen is the latest use.
    let mut used: Vec<(&AppAccess, usize)> = Vec::new();
    for a in scan
        .app_access
        .iter()
        .filter(|a| a.in_use_now || a.last_used_start_unix.is_some())
    {
        match used
            .iter_mut()
            .find(|(u, _)| u.capability == a.capability && u.app.eq_ignore_ascii_case(&a.app))
        {
            Some((_, paths)) => *paths += 1,
            None => used.push((a, 1)),
        }
    }
    println!();
    println!("Apps that used your camera, microphone or location ({})", used.len());
    if used.is_empty() {
        println!("  None recorded.");
        return;
    }
    let now = unix_now();
    let shown = if all_apps { used.len() } else { RECENT_APPS.min(used.len()) };
    for (a, paths) in &used[..shown] {
        let when = if a.in_use_now {
            "IN USE NOW".to_owned()
        } else {
            a.last_used_start_unix.map(|t| ago(now, t)).unwrap_or_default()
        };
        let versions = if *paths > 1 { format!("  ({paths} install folders)") } else { String::new() };
        println!(
            "  {:<11} {:<34} {when}{versions}",
            a.capability.to_string(),
            truncate(&a.app, 34)
        );
    }
    if shown < used.len() {
        println!("  ... and {} more (use --all-apps to list all)", used.len() - shown);
    }
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// "5 minutes ago", "3 days ago", ...
fn ago(now: i64, then: i64) -> String {
    let secs = (now - then).max(0);
    let (n, unit) = match secs {
        0..60 => return "just now".to_owned(),
        60..3_600 => (secs / 60, "minute"),
        3_600..86_400 => (secs / 3_600, "hour"),
        86_400..2_592_000 => (secs / 86_400, "day"),
        2_592_000..31_536_000 => (secs / 2_592_000, "month"),
        _ => (secs / 31_536_000, "year"),
    };
    format!("{n} {unit}{} ago", if n == 1 { "" } else { "s" })
}

/// Greedy word wrap.
fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        if !line.is_empty() && line.len() + 1 + word.len() > width {
            lines.push(std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines
}

fn print_report(r: &CookieReport, top: usize) {
    println!("Guardian Angel - cookie scan");
    println!(
        "Scanned {} browser profile(s) and found {} cookies.",
        r.profiles_scanned,
        thousands(r.total_cookies)
    );

    if r.total_cookies > 0 {
        let pct = r.tracker_cookies * 100 / r.total_cookies;
        println!(
            "{} of them ({pct}%) belong to {} known tracking companies.",
            thousands(r.tracker_cookies),
            r.companies.len()
        );
    }

    if !r.companies.is_empty() {
        println!();
        println!("  #  Company                Cookies  What they do                       Browsers");
        let shown = if top == 0 { r.companies.len() } else { top.min(r.companies.len()) };
        for (i, c) in r.companies.iter().take(shown).enumerate() {
            println!(
                "{:>3}  {:<22} {:>7}  {:<34} {}",
                i + 1,
                truncate(&c.company, 22),
                thousands(c.cookie_count),
                truncate(&join(&c.categories), 34),
                join(&c.browsers)
            );
        }
        if shown < r.companies.len() {
            println!("     ... and {} more (use --top 0 to list all)", r.companies.len() - shown);
        }
    }

    if r.unclassified_cookies > 0 {
        println!();
        println!(
            "Not in the tracker list yet: {} cookies from {} sites.",
            thousands(r.unclassified_cookies),
            thousands(r.unclassified_domains)
        );
        let most: Vec<String> = r
            .top_unclassified
            .iter()
            .map(|d| format!("{} ({})", d.domain, d.cookie_count))
            .collect();
        println!("Most cookies: {}", most.join(", "));
    }

    if !r.warnings.is_empty() {
        println!();
        println!("Could not scan everything:");
        for w in &r.warnings {
            println!("  ! {} ({}): {}", w.browser, w.profile, w.message);
        }
    }
}

fn join<T: Display>(items: &BTreeSet<T>) -> String {
    items.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_owned()
    } else {
        let cut: String = s.chars().take(max - 3).collect();
        format!("{cut}...")
    }
}

fn thousands(n: usize) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, ch) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{ago, thousands, truncate, wrap};

    #[test]
    fn formats_relative_times() {
        assert_eq!(ago(1_000, 990), "just now");
        assert_eq!(ago(10_000, 10_000 - 60), "1 minute ago");
        assert_eq!(ago(10_000_000, 10_000_000 - 3 * 86_400), "3 days ago");
        assert_eq!(ago(100, 200), "just now");
    }

    #[test]
    fn wraps_text() {
        assert_eq!(wrap("one two three", 7), vec!["one two", "three"]);
        assert!(wrap("", 10).is_empty());
    }

    #[test]
    fn formats_thousands() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1_000), "1,000");
        assert_eq!(thousands(1_234_567), "1,234,567");
    }

    #[test]
    fn truncates_long_names() {
        assert_eq!(truncate("Google", 22), "Google");
        assert_eq!(truncate("Integral Ad Science Holdings", 10), "Integra...");
    }
}
