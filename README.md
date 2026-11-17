# Guardian Angel

Guardian Angel shows who is collecting data from your Windows PC, explains it in plain language, and lets you block or fix it with one click. Your data is analysed on your computer and never leaves it.

## What it does

| Area | What you see |
| --- | --- |
| **Overview** | A privacy score out of 100, with the reasons it is not 100, and live scan progress |
| **Trackers** | Companies with cookies in your browsers, plus what every other cookie is for, including tracking tools hiding under websites' own names. Delete tracking cookies while staying signed in |
| **Apps** | Tracking and telemetry SDKs built into your desktop apps (Sentry, App Center, Mixpanel, Segment, Firebase and more) |
| **Network** | Which programs contact which tracking companies, live |
| **What trackers got** | What every browser and app sent to tracking companies (only connections to known trackers are read), which site or app sent it, which cookies each tracker set and where, whether sites that you said no to kept sending your ID, and ready-written data requests (access, delete, opt out) for GDPR, CCPA or elsewhere, with reply deadlines |
| **Inspect traffic** | Exactly what an app you pick sends to trackers, decoded into plain language |
| **Blocking** | Stops every app and browser on the PC from reaching tracking companies (three levels, pause, never-block list) |
| **Extensions** | Browser extensions and what each one can read |
| **Windows settings** | Settings that share your data, with a fix button and undo for each |
| **Alerts** | What got worse since the last scan: a new risky extension, a setting switched back on, a new SDK in an app |

Guardian Angel never changes anything without you asking, and every change can be undone. Uninstalling puts back every setting it changed.

## Install

Download `GuardianAngel-Setup-<version>.exe` from the [Releases](../../releases) page, run it and accept the Windows prompt. Nothing else needs to be installed first. The installer:

- installs the app and its background service, which starts with Windows
- opens Guardian Angel when it finishes

To remove it, use **Settings > Apps > Guardian Angel > Uninstall**. This restores the Windows settings Guardian Angel changed (privacy settings, network DNS settings and the proxy setting), removes its inspection certificate if you allowed one, and deletes its data.

Requirements: Windows 10 (22H2) or Windows 11, 64-bit.

## How it works

```
 Desktop app (Tauri + React)          Browser extension (planned)
            |  named pipe, signed-in local users only
            v
 Background service (Rust, runs as SYSTEM)
   scanners: cookies, extensions, settings, app SDKs
   network monitor (Windows DNS events)    inspection proxy (opt-in, per app)
   blocking DNS resolver (opt-in)          settings fixes with an undo journal
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

GitHub Actions builds and publishes the installer (`.github/workflows/release.yml`). Set the new `version` in `apps/desktop/src-tauri/tauri.conf.json`, commit and push. Then, on GitHub, open **Actions > Release > Run workflow** and leave **Publish a release** ticked. It tags the commit `v<version>` and the installer appears on the Releases page about 20 minutes later. Pushing a tag yourself (`git tag v0.1.0`, `git push origin v0.1.0`) does the same.

The run stops at once if that version was already released, or if a pushed tag doesn't match the version. A version with a dash, such as `0.2.0-beta.1`, becomes a pre-release. For a test build without publishing, untick **Publish a release**; the installer is then only attached to the run.

### Automatic updates

Installed copies check `latest.json` on the newest (non-pre-release) GitHub Release when they open and every six hours, and offer "Update now". The update is a signed installer: the app refuses one not signed with the project's key.

The key pair lives in `%USERPROFILE%\.tauri\guardian-angel.key` (private, no password) and `.key.pub`. The public half is in `tauri.conf.json` (`plugins.updater.pubkey`). The private half is the repository secret `TAURI_SIGNING_PRIVATE_KEY` (**Settings > Secrets and variables > Actions**), so the release workflow can sign.

Keep a backup of the private key somewhere safe outside this PC. If it is lost, installed copies can no longer be updated and users must reinstall once with a new key.

A release built without the secret still installs, but is not offered as an update. Updates download from GitHub without signing in, so they only work once the repository (or a separate releases repository) is public.

### Tracker list

`data/sources/seed_trackers.json` is a hand-picked list; `data/sources/ddg_trackers.json` is generated from DuckDuckGo's [Tracker Radar](https://github.com/duckduckgo/tracker-radar) blocklist. Refresh it with `.\scripts\update-tracker-list.ps1` and commit the result. Where both list a domain, the hand-picked entry wins.

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
| `guardian apps` | SDKs in installed apps; `--dir <folder>` reads every file in one folder |
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
| `scripts` | Installer build and tracker list update |

## Known gaps

- **Blocking:** works through DNS, so browsers with Secure DNS (DNS over HTTPS) turned on skip it for websites, and apps that bring their own DNS are not covered. Changing the network setting needs the installed service. It is machine-wide: any signed-in user can turn it on or off.
- **Windows proxy:** only apps that follow Windows' proxy setting can be inspected that way (most do; some games and command-line tools do not). Not used when another proxy (work or school) is set. VPN and dial-up connections keep their own setting.
- **Cookie deletion:** needs the browser closed; open browsers are skipped. It cannot be undone.
- **What trackers got:** platforms people sign in to (Google search, Facebook, LinkedIn) are never decrypted, so trackers served from their main domains (such as the Meta Pixel's `facebook.com/tr`) are not read. Apps that pin their certificates are passed through untouched and listed. Privacy contacts were checked against each company's own pages in November 2026 and cover 11 large companies; for others the letter is ready to copy.
- **Code signing:** the installer and app are not signed yet, so Windows SmartScreen warns on first run.
- **Testing:** tested on Windows 10 22H2. Needs Windows 11 and Home / Pro / Enterprise runs, and the installed service needs a full test as SYSTEM.
- **Network monitor:** sees lookups through the Windows DNS client only; browsers using Secure DNS bypass it. Data volumes per program are not measured yet.
- **App scan:** reads up to 64 MB of code per app (the Apps page lists partly scanned apps and can scan one completely); the first scan takes about 1.5 minutes. Results are not cached per file yet. Store (MSIX) apps are not scanned.
- **Proxy:** HTTP/1.1 towards apps only, no plain-HTTP proxying, compressed request bodies are not decoded, and the CA key is protected by folder permissions but not yet encrypted.
- **Decoders:** 7 trackers. Session-recording tools (Hotjar, Clarity) are listed but not decoded.
- **DNS resolver:** UDP only. Port 53 is taken on some PCs (for example by Internet Connection Sharing).
- **Settings:** Windows 11-only settings (Recall) and activity history are not checked yet.
- **Tracker list:** DuckDuckGo's data is licensed for non-commercial use only. A commercial release needs a licence from DuckDuckGo or a replacement list.

## Credits

Tracker data from [DuckDuckGo Tracker Radar](https://github.com/duckduckgo/tracker-radar), licensed [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/). `data/sources/ddg_trackers.json` is an adapted version (domains mapped to Guardian Angel's categories and company names) under the same licence.

Design proposal and roadmap: https://claude.ai/artifact/PRVZ8nW3mQiCMLxHzkce4j
