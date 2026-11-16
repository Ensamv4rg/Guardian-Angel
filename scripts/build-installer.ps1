# Builds the one-click Windows installer:
#   target\release\bundle\nsis\Guardian Angel_<version>_x64-setup.exe
#
# Usage (from the repository root):
#   .\scripts\build-installer.ps1               # full installer
#   .\scripts\build-installer.ps1 -SidecarOnly  # only prepare the service for `pnpm tauri dev`
#
# Needs: Rust (MSVC), Node.js, pnpm. Tauri downloads its NSIS tools the first time.

param([switch]$SidecarOnly)

# Native tools (cargo, pnpm) write progress to stderr, which Windows
# PowerShell 5.1 would treat as an error under "Stop". Each step checks its
# exit code instead.
$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

Write-Host "Building the background service..."
cargo build --release -p ga-service
if ($LASTEXITCODE -ne 0) { throw "service build failed" }

# Tauri bundles extra programs ("sidecars") named with the target triple.
$triple = (rustc -vV | Select-String "^host: (.+)$").Matches[0].Groups[1].Value
$binaries = Join-Path $root "apps\desktop\src-tauri\binaries"
New-Item -ItemType Directory -Force $binaries | Out-Null
Copy-Item "target\release\guardian-service.exe" (Join-Path $binaries "guardian-service-$triple.exe") -Force
if ($SidecarOnly) {
    Write-Host "Service copied for the desktop app. Now run: cd apps\desktop; pnpm tauri dev"
    return
}

Write-Host "Building the desktop app and installer..."
Set-Location (Join-Path $root "apps\desktop")
pnpm install --frozen-lockfile
if ($LASTEXITCODE -ne 0) { throw "pnpm install failed" }
pnpm tauri build
if ($LASTEXITCODE -ne 0) { throw "installer build failed" }

$setup = Get-ChildItem (Join-Path $root "target\release\bundle\nsis") -Filter "*-setup.exe" | Sort-Object LastWriteTime | Select-Object -Last 1
Write-Host ""
Write-Host "Installer ready: $($setup.FullName)"
