//! `guardian`: runs Guardian Angel scans from the terminal.
//!
//! This is a development tool. The real product runs the same crates inside
//! the background service and shows results in the desktop UI.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
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
    }
    Ok(())
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
    use super::{thousands, truncate};

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
