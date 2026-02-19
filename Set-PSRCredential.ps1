#!/usr/bin/env pwsh
#Requires -Version 7.0
<#
.SYNOPSIS
    One-time setup: store your Anthropic API key as a private GitHub Gist.

.DESCRIPTION
    Creates a private Gist on your GitHub account containing the API key.
    The Gist ID is saved locally so Parse-PSR.ps1 can fetch it automatically
    on any machine where you're logged in via `gh auth login`.

    Credential resolution after setup:
      Any machine  →  gh auth login  →  Gist fetch  →  local DPAPI cache
      Offline      →  DPAPI cache (written after first successful Gist fetch)

.EXAMPLE
    .\Set-PSRCredential.ps1
#>

$ErrorActionPreference = "Stop"
$GistIdFile = Join-Path $env:APPDATA "PSR-Tools\gist_id.txt"
$CredFile   = Join-Path $env:APPDATA "PSR-Tools\api_key.cred"
$GhExe      = "C:\Program Files\GitHub CLI\gh.exe"

# ── Check gh is available and authenticated ────────────────────────────────────
if (-not (Test-Path $GhExe)) {
    Write-Error "GitHub CLI not found at $GhExe. Install from https://cli.github.com"
    exit 1
}

$authCheck = & $GhExe auth status 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "Not logged into GitHub. Launching login..." -ForegroundColor Yellow
    & $GhExe auth login
}

$whoami = (& $GhExe api user --jq .login 2>&1).Trim()
Write-Host "Logged in as: $whoami" -ForegroundColor Green

# ── Check for existing Gist ────────────────────────────────────────────────────
if (Test-Path $GistIdFile) {
    $existingId = (Get-Content $GistIdFile -Raw).Trim()
    Write-Host ""
    Write-Host "Existing Gist ID found: $existingId" -ForegroundColor Cyan
    $overwrite = Read-Host "Overwrite with a new key? [y/N]"
    if ($overwrite -notmatch "^[Yy]") {
        Write-Host "No changes made." -ForegroundColor Gray
        exit 0
    }
}

# ── Prompt for API key ─────────────────────────────────────────────────────────
Write-Host ""
Write-Host "Get your API key at: https://console.anthropic.com/settings/keys" -ForegroundColor Cyan
$secure = Read-Host "Paste Anthropic API key" -AsSecureString
$plain  = [System.Net.NetworkCredential]::new("", $secure).Password

if (-not $plain -or $plain -notmatch "^sk-ant-") {
    Write-Error "That doesn't look like a valid Anthropic API key (expected sk-ant-...)."
    exit 1
}

# ── Create private Gist ────────────────────────────────────────────────────────
$tmpFile = Join-Path $env:TEMP "anthropic_api_key.txt"
Set-Content -Path $tmpFile -Value $plain -Encoding UTF8 -NoNewline

$gistOutput = & $GhExe gist create $tmpFile `
    --desc "PSR-Tools Anthropic API key ($whoami)" `
    --filename "anthropic_api_key.txt" 2>&1

Remove-Item $tmpFile -Force

if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to create Gist: $gistOutput"
    exit 1
}

# gh gist create returns the Gist URL — extract the ID from it
$gistUrl = $gistOutput | Select-String "https://gist.github.com/\S+" | ForEach-Object { $_.Matches[0].Value }
$gistId  = $gistUrl -replace ".*/", ""

if (-not $gistId) {
    Write-Error "Could not parse Gist ID from output: $gistOutput"
    exit 1
}

# ── Save Gist ID locally (not sensitive — just a pointer) ─────────────────────
$dir = Split-Path $GistIdFile
if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
Set-Content -Path $GistIdFile -Value $gistId -Encoding UTF8

# ── Also cache to DPAPI for offline/fast access ───────────────────────────────
ConvertTo-SecureString $plain -AsPlainText -Force |
    ConvertFrom-SecureString |
    Set-Content -Path $CredFile -Encoding UTF8

Write-Host ""
Write-Host "Done!" -ForegroundColor Green
Write-Host "  Gist URL : $gistUrl" -ForegroundColor Cyan
Write-Host "  Gist ID  : $gistId  (saved to $GistIdFile)"
Write-Host "  Local cache: $CredFile (DPAPI encrypted)"
Write-Host ""
Write-Host "On a new machine: run 'gh auth login' then run Parse-PSR.ps1 — it fetches automatically."
