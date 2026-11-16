# Guardian Angel

See who is collecting data from your computer, explained by company, with one-click fixes.

Design proposal: https://claude.ai/artifact/PRVZ8nW3mQiCMLxHzkce4j

## Status

Early development. Working today:

- Browser cookie scanner for Chrome, Edge, Brave, Vivaldi, Opera, Opera GX and Firefox (domains and names only; values are never read)
- Desktop app SDK scanner: finds tracking and telemetry SDKs (Sentry, App Center, Application Insights, Mixpanel, Amplitude, Segment, Firebase and more) in installed apps, including inside Electron `app.asar` archives; "sure" when the SDK is bundled, "mentions" when only its address is in the code
- Decrypting HTTPS proxy, opt-in per app: decodes tracker payloads from desktop apps, tunnels everything else untouched, learns which apps refuse inspection (certificate pinning) and stops trying, passes WebSockets through, and serves a revocation list so Windows' own TLS accepts its certificates
- Privacy fixes with undo: every change is recorded in a journal before it is made, rolled back if any step fails, and undo leaves alone any value you changed since (`guardian fix`, `guardian undo`)
- Background service (`guardian-service`): runs the scans per Windows user, raises alerts when something gets worse, runs the network monitor and hosts the proxy. Clients talk to it over a named pipe that only signed-in local users can open, and each user only ever sees their own data
- Desktop app (Tauri 2 + React): overview with a privacy score, trackers, apps, network, traffic inspection, extensions, Windows settings with fix and undo, and alerts
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

- The service is not yet tested installed as SYSTEM; console mode is. It serves each connecting user from their own profile folder and `HKEY_USERS\<SID>` hive. The network monitor and proxy are machine-wide (program names only; proxy app choices are shared).
- The service does not yet point Windows at the DNS resolver or the proxy, or install the inspection certificate: each needs a consent flow with automatic rollback.
- Tested on Windows 10 22H2 only. Needs a test matrix: Windows 11, clean installs, Home / Pro / Enterprise.
- Windows 11-only settings (e.g. Recall) are not checked yet.
- Network monitor sees only lookups that go through the Windows DNS client. Browsers using DNS-over-HTTPS (Secure DNS) bypass it; the planned local DNS resolver closes this gap. Bytes per process (Kernel-Network ETW) are not collected yet.
- The DNS resolver handles UDP only; large replies that need TCP fall back badly. Port 53 is already taken on some PCs (e.g. by Internet Connection Sharing), so the service needs a strategy for that before Windows can be pointed at the resolver.
- The proxy only works for apps that send traffic through it: today, apps started with a proxy flag. Setting the Windows proxy and trusting the certificate (with the user's consent and automatic rollback) belong to the service. It refuses plain-HTTP proxy requests, speaks HTTP/1.1 only towards apps, does not decode compressed request bodies yet, and keeps its CA key in the user profile without DPAPI encryption yet.
- The app SDK scanner reads up to 64 MB of code per app; a first full scan takes about 1.5 minutes here, mostly waiting on antivirus. The service should cache results per file and rescan only what changed. Store (MSIX) apps are not scanned.
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
cargo run -p ga-cli -- apps
cargo run -p ga-cli -- proxy --export-ca guardian-ca.pem
cargo run -p ga-cli -- proxy --inspect Discord.exe --seconds 120
cargo run -p ga-cli -- fix --all            # shows the plan; add --apply to change settings
cargo run -p ga-cli -- undo                 # lists changes; `undo <id>` or `undo --all`
```

Service and desktop app:

```
cargo run --release -p ga-service -- console     # the engine, as the current user
cargo run -p ga-cli -- service status            # talk to it over the pipe
cd apps/desktop && pnpm install && pnpm tauri dev
```

`guardian-service install` (administrator) registers it as a Windows service running as SYSTEM. For UI work in a browser, `pnpm dev` alone serves the UI at http://localhost:1420 and relays to the running service through `target/release/guardian.exe`.
cargo run -p ga-cli -- privacy --all-apps
```

Close Chrome and Edge first: they lock their cookie databases while running.

## Layout

| Path | What it is |
| --- | --- |
| `crates/core` | Shared types |
| `crates/knowledge` | Tracker knowledge base (domain to company) |
| `crates/scanners` | Local scanners: cookies, extensions, privacy settings, app SDKs |
| `crates/report` | Company-centric report builder |
| `crates/netmon` | Live network monitoring (ETW) |
| `crates/blocker` | Blocking DNS resolver and blocking policy |
| `crates/decoders` | Tracker payload decoders and HAR reader |
| `crates/ipc` | Pipe protocol between the service and its clients |
| `crates/engine` | Per-user scans, alerts, score, network monitor and proxy behind the protocol |
| `apps/service` | `guardian-service`: Windows service and console mode |
| `apps/desktop` | Desktop app: Tauri 2 shell (`src-tauri`) and React UI (`src`) |
| `crates/proxy` | Opt-in decrypting HTTPS proxy and its per-install certificate authority |
| `crates/platform-win` | The only crate allowed `unsafe`: thin Windows API wrappers |
| `apps/cli` | `guardian` development CLI |
| `data/sources` | Tracker list and SDK signature catalog |

Only `platform-win` may use `unsafe`, and every block there needs a `SAFETY:` comment; the workspace forbids `unsafe` everywhere else.
