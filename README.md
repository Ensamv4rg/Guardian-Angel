# Guardian Angel

See who is collecting data from your computer, explained by company, with one-click fixes.

Design proposal: https://claude.ai/artifact/PRVZ8nW3mQiCMLxHzkce4j

## Status

Early development. Working today:

- Browser cookie scanner for Chrome, Edge, Brave, Vivaldi, Opera, Opera GX and Firefox (domains and names only; values are never read)
- Seed tracker list (~50 companies) in `data/sources/seed_trackers.json`
- Report grouped by company
- `guardian` command-line tool for development

## Requirements

- Windows 10 22H2 or Windows 11
- Rust stable with the MSVC toolchain (pinned by `rust-toolchain.toml`)
- Visual Studio Build Tools with the C++ workload

## Run

```
cargo test --workspace
cargo run -p ga-cli -- cookies
cargo run -p ga-cli -- cookies --json
```

Close Chrome and Edge first: they lock their cookie databases while running.

## Layout

| Path | What it is |
| --- | --- |
| `crates/core` | Shared types |
| `crates/knowledge` | Tracker knowledge base (domain to company) |
| `crates/scanners` | Local scanners (browser cookies so far) |
| `crates/report` | Company-centric report builder |
| `apps/cli` | `guardian` development CLI |
| `data/sources` | Tracker list sources |

Only a future `platform-win` crate may use `unsafe`; the workspace forbids it everywhere else.
