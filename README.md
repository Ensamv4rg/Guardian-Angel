# Guardian Angel

See who is collecting data from your computer, explained by company, with one-click fixes.

Design proposal: https://claude.ai/artifact/PRVZ8nW3mQiCMLxHzkce4j

## Status

Early development. Working today:

- Browser cookie scanner for Chrome, Edge, Brave, Vivaldi, Opera, Opera GX and Firefox (domains and names only; values are never read)
- Blocking DNS resolver (Relaxed / Balanced / Strict profiles, user allow and block lists, pause, protected Windows Update and certificate domains). Forwards to the DNS servers Windows already uses. Not yet connected to Windows' DNS settings.
- Tracker payload decoders (Google Analytics 4 and Universal Analytics, Meta Pixel, Bing UET, LinkedIn Insight, Segment, TikTok Pixel) and `decode-har` to see what trackers received on a page
- Live network monitor: which programs look up which domains, grouped by tracking company (Windows DNS client ETW events; no admin needed if the account is in Performance Log Users)
- Browser extension scanner for Chromium browsers and Firefox: granted site access, sensitive permissions, install source, risk level
- Windows privacy settings scanner (diagnostic data, advertising ID, location, typing and speech, app tracking, suggested apps), read-only
- History of which apps used the camera, microphone or location
- Seed tracker list (~50 companies) in `data/sources/seed_trackers.json`
- Report grouped by company
- `guardian` command-line tool for development

## Known gaps before release

- Scanners read the **current user** only (`%LOCALAPPDATA%`, `%APPDATA%`, `HKCU`). When the engine runs as a Windows Service (SYSTEM), it must enumerate every user profile folder and registry hive (`HKEY_USERS\<SID>`). Folder roots and the registry are already injected, not hardcoded, to allow this.
- Tested on Windows 10 22H2 only. Needs a test matrix: Windows 11, clean installs, Home / Pro / Enterprise.
- Windows 11-only settings (e.g. Recall) are not checked yet.
- Network monitor sees only lookups that go through the Windows DNS client. Browsers using DNS-over-HTTPS (Secure DNS) bypass it; the planned local DNS resolver closes this gap. Bytes per process (Kernel-Network ETW) are not collected yet.
- The DNS resolver handles UDP only; large replies that need TCP fall back badly. Port 53 is already taken on some PCs (e.g. by Internet Connection Sharing), so the service needs a strategy for that before Windows can be pointed at the resolver.
- Decoders cover 7 trackers. Session-recording tools (Hotjar, Clarity) send compressed or WebSocket data and are reported as "cannot be decoded yet".
- Without admin rights, Windows services show as `PID 1234` instead of a program name, and very short-lived programs may too.
- Activity history is not reported: only its Group Policy values are reliably readable.

## Requirements

- Windows 10 22H2 or Windows 11
- Rust stable with the MSVC toolchain (pinned by `rust-toolchain.toml`)
- Visual Studio Build Tools with the C++ workload

## Run

```
cargo test --workspace
cargo run -p ga-cli -- cookies
cargo run -p ga-cli -- cookies --json
cargo run -p ga-cli -- extensions
cargo run -p ga-cli -- privacy
cargo run -p ga-cli -- network --seconds 60
cargo run -p ga-cli -- dns --port 15353 --profile balanced --seconds 60
cargo run -p ga-cli -- decode-har page.har
cargo run -p ga-cli -- privacy --all-apps
```

Close Chrome and Edge first: they lock their cookie databases while running.

## Layout

| Path | What it is |
| --- | --- |
| `crates/core` | Shared types |
| `crates/knowledge` | Tracker knowledge base (domain to company) |
| `crates/scanners` | Local scanners (browser cookies so far) |
| `crates/report` | Company-centric report builder |
| `crates/netmon` | Live network monitoring (ETW) |
| `crates/blocker` | Blocking DNS resolver and blocking policy |
| `crates/decoders` | Tracker payload decoders and HAR reader |
| `crates/platform-win` | The only crate allowed `unsafe`: thin Windows API wrappers |
| `apps/cli` | `guardian` development CLI |
| `data/sources` | Tracker list sources |

Only `platform-win` may use `unsafe`, and every block there needs a `SAFETY:` comment; the workspace forbids `unsafe` everywhere else.
