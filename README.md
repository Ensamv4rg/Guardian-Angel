# Guardian Angel

Guardian Angel shows who is collecting data from your Windows PC, explains it in plain language, and lets you block or fix it with one click. Everything is analysed on your computer; nothing is sent anywhere.

## What it does

| Area | What you see |
| --- | --- |
| **Overview** | A privacy score out of 100, with the reasons it is not 100, and live scan progress |
| **Trackers** | Companies with cookies in your browsers, plus what every other cookie is for, including tracking tools hiding under websites' own names |
| **Apps** | Tracking and telemetry SDKs built into your desktop apps (Sentry, App Center, Mixpanel, Segment, Firebase and more) |
| **Network** | Which programs contact which tracking companies, live |
| **Inspect traffic** | Exactly what an app you pick sends to trackers, decoded into plain language |
| **Extensions** | Browser extensions and what each one can read |
| **Windows settings** | Settings that share your data, with a fix button and undo for each |
| **Alerts** | What got worse since the last scan: a new risky extension, a setting switched back on, a new SDK in an app |

Guardian Angel never changes anything without you asking, and every change can be undone. Uninstalling puts back every setting it changed.

## Install

Download `GuardianAngel-Setup-<version>.exe` from the [Releases](../../releases) page, run it and accept the Windows prompt. Nothing else needs to be installed first. The installer:

- installs the app and its background service, which starts with Windows
- opens Guardian Angel when it finishes

To remove it, use **Settings > Apps > Guardian Angel > Uninstall**. This restores the Windows settings Guardian Angel changed, removes its inspection certificate if you allowed one, and deletes its data.

Requirements: Windows 10 (22H2) or Windows 11, 64-bit.

## How it works

```
 Desktop app (Tauri + React)          Browser extension (planned)
            |  named pipe, signed-in local users only
            v
 Background service (Rust, runs as SYSTEM)
   scanners: cookies, extensions, settings, app SDKs
   network monitor (Windows DNS events)    inspection proxy (opt-in, per app)
   blocking DNS resolver (not yet active)  settings fixes with an undo journal
```

- The service answers each request for the Windows user who asked, from that user's own profile and registry, so one user never sees another's data.
- The desktop app has no privileges of its own. It only talks to the service, plus two actions that belong to you: trusting the inspection certificate (Windows asks you to confirm) and restarting an app with inspection on.
- Only `crates/platform-win` may use `unsafe` Rust; every block there carries a `SAFETY:` comment. The rest of the workspace forbids it.

## Development

### Prerequisites

- Rust stable with the MSVC toolchain (pinned by `rust-toolchain.toml`) and Visual Studio Build Tools with the C++ workload
- Node.js 22 and pnpm

### Run from source

Start the engine in a terminal and leave it open:

```
cargo run --release -p ga-service -- console
```

Then the desktop app, with live reload:

```
.\scripts\build-installer.ps1 -SidecarOnly
cd apps\desktop
pnpm install
pnpm tauri dev
```

`-SidecarOnly` copies the service where Tauri expects it; it is needed once, and again after changing the service. For interface work in a normal browser, `pnpm dev` alone serves the UI at http://localhost:1420 and relays to the running engine.

### Build the installer

```
.\scripts\build-installer.ps1
```

The installer is written to `target\release\bundle\nsis\`. The first build downloads Tauri's NSIS tools and takes about 15 minutes.

### Publish a release

GitHub Actions builds and publishes the installer (`.github/workflows/release.yml`). Set the new `version` in `apps/desktop/src-tauri/tauri.conf.json`, commit, then push a matching tag:

```
git tag v0.1.0
git push origin v0.1.0
```

The installer appears on the Releases page about 20 minutes later. The workflow stops if the tag and the version differ. A tag with a dash, such as `v0.2.0-beta.1`, becomes a pre-release. To test the build without publishing, run the workflow by hand from the Actions tab; the installer is attached to the run.

Always build the desktop app with `pnpm tauri build`, never `cargo build`: only Tauri's build embeds the interface (a plain cargo build points the app at `localhost:1420`). Keep the `tauri` crate and the `@tauri-apps/*` npm packages on the same minor version (2.11), or the build refuses to run.

### Test

```
cargo test --workspace
cargo clippy --workspace --all-targets
cd apps\desktop && npx tsc -p .
```

Tests never change your system. One registry test writes to a scratch key and is ignored unless run with `--ignored`.

### Command-line tool

`guardian` (in `apps/cli`) runs each part on its own, which helps when developing a scanner:

| Command | What it does |
| --- | --- |
| `guardian cookies` | Browser cookies by company (close browsers first; they lock their cookie files) |
| `guardian extensions` | Browser extensions and their risk |
| `guardian privacy` | Windows privacy settings and camera, microphone and location use |
| `guardian apps` | SDKs in installed apps |
| `guardian network --seconds 60` | Live DNS lookups by program and company |
| `guardian fix --all` | Shows what would change; add `--apply` to change settings |
| `guardian undo` | Lists changes; `undo <id>` or `undo --all` reverses them |
| `guardian proxy --inspect Discord.exe` | Runs the inspection proxy for one app |
| `guardian dns --port 15353` | Runs the blocking DNS resolver on a test port |
| `guardian decode-har page.har` | Decodes tracker requests in a browser network export |
| `guardian service status` | Sends one request to the running engine |

Add `--json` to most commands for machine-readable output.

### Repository layout

| Path | What it is |
| --- | --- |
| `apps/desktop` | Desktop app: Tauri shell (`src-tauri`), React UI (`src`), installer hooks (`src-tauri/windows`) |
| `apps/service` | `guardian-service`: the Windows service, plus `console`, `install` and `uninstall` |
| `apps/cli` | `guardian` command-line tool |
| `crates/engine` | Per-user scans, alerts, score, network monitor and proxy behind the protocol |
| `crates/ipc` | Pipe protocol between the service and its clients |
| `crates/scanners` | Cookies, extensions, privacy settings, app SDKs |
| `crates/report` | Reports by company, cookie purposes |
| `crates/netmon` | Live network monitoring from Windows DNS events |
| `crates/blocker` | Blocking DNS resolver and settings fixes with undo |
| `crates/proxy` | Opt-in decrypting HTTPS proxy and its per-install certificate authority |
| `crates/decoders` | Tracker payload decoders and HAR reader |
| `crates/knowledge` | Tracker list: domain to company |
| `crates/core` | Shared types |
| `crates/platform-win` | Thin Windows API wrappers; the only crate allowed `unsafe` |
| `data/sources` | Tracker list and SDK signature catalog |
| `scripts` | Installer build script |

## Known gaps

- **Not yet on:** blocking (the DNS resolver works but Windows is not pointed at it) and inspecting apps that do not take a proxy flag (needs the Windows proxy setting). Both need a consent step with automatic rollback.
- **Code signing:** the installer and app are not signed yet, so Windows SmartScreen warns on first run.
- **Testing:** tested on Windows 10 22H2. Needs Windows 11 and Home / Pro / Enterprise runs, and the installed service needs a full test as SYSTEM.
- **Network monitor:** sees lookups through the Windows DNS client only; browsers using Secure DNS bypass it. Data volumes per program are not measured yet.
- **App scan:** reads up to 64 MB of code per app; the first scan takes about 1.5 minutes. Results are not cached per file yet. Store (MSIX) apps are not scanned.
- **Proxy:** HTTP/1.1 towards apps only, no plain-HTTP proxying, compressed request bodies are not decoded, and the CA key is protected by folder permissions but not yet encrypted.
- **Decoders:** 7 trackers. Session-recording tools (Hotjar, Clarity) are listed but not decoded.
- **DNS resolver:** UDP only. Port 53 is taken on some PCs (for example by Internet Connection Sharing).
- **Settings:** Windows 11-only settings (Recall) and activity history are not checked yet.
- **Tracker list:** a hand-curated seed list of about 50 companies; importing DuckDuckGo Tracker Radar needs a licence check first.

Design proposal and roadmap: https://claude.ai/artifact/PRVZ8nW3mQiCMLxHzkce4j
