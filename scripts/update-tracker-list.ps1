# Downloads DuckDuckGo's current tracker list and regenerates
# data/sources/ddg_trackers.json. Commit the result; the next build ships it.
#
# The data is licensed CC BY-NC-SA 4.0 (non-commercial use with attribution).
# A commercial release needs a licence from DuckDuckGo.

$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$url = "https://staticcdn.duckduckgo.com/trackerblocking/v6/current/extension-tds.json"
$download = Join-Path ([IO.Path]::GetTempPath()) "guardian-angel-tds.json"
Write-Host "Downloading $url"
Invoke-WebRequest -UseBasicParsing $url -OutFile $download
if (-not (Test-Path $download)) { throw "download failed" }

cargo run --quiet --release -p ga-knowledge --bin kb-builder -- $download "data/sources/ddg_trackers.json"
if ($LASTEXITCODE -ne 0) { throw "conversion failed" }
Remove-Item $download
git --no-pager diff --stat -- data/sources/ddg_trackers.json
