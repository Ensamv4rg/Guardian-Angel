//! `guardian`: runs Guardian Angel scans from the terminal.
//!
//! This is a development tool. The real product runs the same crates inside
//! the background service and shows results in the desktop UI.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ga_core::{AppAccess, ExtensionScan, ExtensionSource, Exposure, PrivacyScan, Risk, SiteAccess};
use ga_blocker::{DnsBlocker, Policy, Profile, ResolverConfig};
use ga_knowledge::TrackerDb;
use ga_report::{CookieReport, NetworkReport, build_cookie_report, build_network_report};
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
    /// List browser extensions and what they can access.
    Extensions {
        /// Print the full result as JSON instead of text.
        #[arg(long)]
        json: bool,
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
    /// Run the blocking DNS resolver on a local port for testing. Does not
    /// change Windows' DNS settings.
    Dns {
        /// Local port to listen on (127.0.0.1).
        #[arg(long, default_value_t = 15353)]
        port: u16,
        #[arg(long, value_enum, default_value_t = ProfileArg::Balanced)]
        profile: ProfileArg,
        /// How long to run, in seconds.
        #[arg(long, default_value_t = 60)]
        seconds: u64,
        /// Upstream DNS server. Default: the servers Windows is using.
        #[arg(long)]
        upstream: Option<std::net::IpAddr>,
    },
    /// Decode what trackers received, from a HAR file exported from your
    /// browser's developer tools (Network tab, "Save all as HAR").
    DecodeHar {
        /// Path to the .har file.
        file: std::path::PathBuf,
        /// Print the full result as JSON instead of text.
        #[arg(long)]
        json: bool,
    },
    /// Watch which programs contact tracking companies, for a set time.
    Network {
        /// How long to watch, in seconds.
        #[arg(long, default_value_t = 60)]
        seconds: u64,
        /// Print the full report as JSON instead of text.
        #[arg(long)]
        json: bool,
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
        Command::Extensions { json } => {
            let scan = ga_scanners::extensions::scan_extensions();
            if json {
                println!("{}", serde_json::to_string_pretty(&scan)?);
            } else {
                print_extensions(&scan);
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
        Command::Dns {
            port,
            profile,
            seconds,
            upstream,
        } => run_dns(port, profile.into(), seconds, upstream)?,
        Command::DecodeHar { file, json } => {
            let text = std::fs::read_to_string(&file).with_context(|| format!("reading {}", file.display()))?;
            let decoded = ga_decoders::har::decode_har(&text)?;
            if json {
                let hits: Vec<_> = decoded.hits.iter().map(|h| (&h.page, &h.payload)).collect();
                println!("{}", serde_json::to_string_pretty(&hits)?);
            } else {
                let db = TrackerDb::bundled().context("loading the tracker list")?;
                print_har(&decoded, &db);
            }
        }
        Command::Network { seconds, json } => {
            let db = TrackerDb::bundled().context("loading the tracker list")?;
            let monitor = ga_netmon::DnsMonitor::start()?;
            if !json {
                println!("Watching which programs look up which websites for {seconds} seconds.");
                println!("Use your computer normally; results appear at the end.");
            }
            std::thread::sleep(std::time::Duration::from_secs(seconds));
            let capture = monitor.stop();
            let report = build_network_report(&capture, &db);
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print_network(&report);
            }
        }
    }
    Ok(())
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum ProfileArg {
    Relaxed,
    Balanced,
    Strict,
}

impl From<ProfileArg> for Profile {
    fn from(p: ProfileArg) -> Self {
        match p {
            ProfileArg::Relaxed => Profile::Relaxed,
            ProfileArg::Balanced => Profile::Balanced,
            ProfileArg::Strict => Profile::Strict,
        }
    }
}

fn run_dns(port: u16, profile: Profile, seconds: u64, upstream: Option<std::net::IpAddr>) -> Result<()> {
    use std::net::SocketAddr;
    use std::sync::{Arc, RwLock};
    use std::time::Duration;

    let upstreams = match upstream {
        Some(ip) => vec![SocketAddr::new(ip, 53)],
        None => ga_blocker::upstream::system_upstreams(),
    };
    anyhow::ensure!(
        !upstreams.is_empty(),
        "No DNS servers found on any connected adapter; pass one with --upstream"
    );
    let db = Arc::new(TrackerDb::bundled().context("loading the tracker list")?);

    tokio::runtime::Runtime::new()?.block_on(async {
        let blocker = DnsBlocker::bind(
            ResolverConfig {
                listen: SocketAddr::from(([127, 0, 0, 1], port)),
                upstreams: upstreams.clone(),
                upstream_timeout: Duration::from_secs(2),
            },
            db,
            Arc::new(RwLock::new(Policy::new(profile))),
        )
        .await
        .with_context(|| format!("could not listen on 127.0.0.1:{port} (is it in use?)"))?;
        let stats = blocker.stats();

        let list: Vec<String> = upstreams.iter().map(|u| u.ip().to_string()).collect();
        println!(
            "Blocking DNS resolver on 127.0.0.1:{port} ({profile:?} profile), forwarding to {} for {seconds} s.",
            list.join(", ")
        );
        println!("Windows is not using it; send test queries to 127.0.0.1:{port} with a DNS tool that supports custom ports.");

        let _ = tokio::time::timeout(Duration::from_secs(seconds), blocker.run()).await;

        let s = stats.lock().unwrap_or_else(|p| p.into_inner()).clone();
        println!();
        println!(
            "{} queries, {} blocked, {} upstream failures.",
            s.queries, s.blocked, s.upstream_failures
        );
        for (company, n) in &s.blocked_by_company {
            println!("  blocked {n:>4}  {company}");
        }
        anyhow::Ok(())
    })
}

fn print_har(r: &ga_decoders::har::HarDecode, db: &TrackerDb) {
    println!("Guardian Angel - what trackers received");
    println!(
        "{} requests in the file, {} tracker hits decoded.",
        thousands(r.requests),
        thousands(r.hits.len())
    );

    let mut last_page: Option<&str> = None;
    for hit in &r.hits {
        let page = hit.page.as_deref();
        if page != last_page {
            println!();
            println!("Page: {}", page.unwrap_or("(unknown page)"));
            last_page = page;
        }
        let p = &hit.payload;
        let sent: Vec<&str> = p.kinds().iter().map(|k| k.describe()).collect();
        println!();
        println!("  {} ({}) received {}.", p.product, p.company, sent.join(", "));
        for f in &p.fields {
            println!("      {:<32} {}", truncate(&f.label, 32), truncate(&f.value, 70));
        }
    }

    // Tracker requests the decoders do not understand yet, by company.
    let mut undecoded: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    for (host, n) in &r.other_hosts {
        if let Some(m) = db.classify(host) {
            *undecoded.entry(m.company).or_default() += n;
        }
    }
    if !undecoded.is_empty() {
        println!();
        println!("Other tracker requests that cannot be decoded yet:");
        for (company, n) in undecoded {
            println!("  {n:>5}  {company}");
        }
    }
}

fn print_network(r: &NetworkReport) {
    println!();
    println!("Guardian Angel - network activity over {} seconds", r.duration_secs);
    println!(
        "{} DNS lookups, {} of them ({}%) to {} known tracking companies.",
        thousands(r.total_lookups as usize),
        thousands(r.tracker_lookups as usize),
        if r.total_lookups == 0 { 0 } else { r.tracker_lookups * 100 / r.total_lookups },
        r.companies.len()
    );

    if !r.companies.is_empty() {
        println!();
        println!("  Company                Lookups  Contacted by");
        for c in &r.companies {
            println!(
                "  {:<22} {:>7}  {}",
                truncate(&c.company, 22),
                thousands(c.lookups as usize),
                truncate(&join(&c.processes), 60)
            );
        }
    }

    let trackers: Vec<_> = r.processes.iter().filter(|p| p.tracker_lookups > 0).collect();
    if !trackers.is_empty() {
        println!();
        println!("  Program                        Tracker lookups  Companies");
        for p in trackers {
            println!(
                "  {:<30} {:>15}  {}",
                truncate(&p.process, 30),
                thousands(p.tracker_lookups as usize),
                truncate(&join(&p.companies), 50)
            );
        }
    }
}

fn print_extensions(scan: &ExtensionScan) {
    let count = |r: Risk| scan.extensions.iter().filter(|e| e.risk == r).count();
    println!("Guardian Angel - browser extensions");
    println!(
        "Scanned {} browser profile(s) and found {} extensions: {} high risk, {} medium, {} low.",
        scan.profiles_scanned,
        scan.extensions.len(),
        count(Risk::High),
        count(Risk::Medium),
        count(Risk::Low)
    );

    for e in &scan.extensions {
        println!();
        let disabled = if e.enabled { "" } else { "  [disabled]" };
        println!(
            "  [{}] {} {}  ({} / {}){disabled}",
            e.risk, e.name, e.version, e.browser, e.profile
        );
        if e.source != ExtensionSource::Store {
            println!("        Source: {}", e.source);
        }
        for reason in &e.risk_reasons {
            println!("        - {reason}");
        }
        if let SiteAccess::SomeSites(hosts) = &e.site_access
            && hosts.len() > 1
        {
            println!("        Sites: {}", truncate(&hosts.join(", "), 90));
        }
    }

    if !scan.warnings.is_empty() {
        println!();
        println!("Could not scan everything:");
        for w in &scan.warnings {
            println!("  ! {} ({}): {}", w.browser, w.profile, w.message);
        }
    }
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
            .map(|d| format!("{} ({})", d.domain, d.count))
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
