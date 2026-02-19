#!/usr/bin/env pwsh
#Requires -Version 7.0
<#
.SYNOPSIS
    Store your Anthropic API key securely on this machine.

.DESCRIPTION
    Encrypts the API key with Windows DPAPI and saves it to
    %APPDATA%\PSR-Tools\api_key.cred. The encrypted file is tied
    to your Windows user account — it cannot be decrypted on any
    other machine or by any other user.

    Run this once per machine. Parse-PSR.ps1 will load the key
    automatically on every subsequent run.

.EXAMPLE
    .\Set-PSRCredential.ps1
#>

$CredFile = Join-Path $env:APPDATA "PSR-Tools\api_key.cred"

# Warn if a key is already stored
if (Test-Path $CredFile) {
    $overwrite = Read-Host "A key is already stored. Overwrite? [y/N]"
    if ($overwrite -notmatch "^[Yy]") { Write-Host "No changes made."; exit 0 }
}

Write-Host ""
Write-Host "Get your API key at: https://console.anthropic.com/settings/keys" -ForegroundColor Cyan
$secure = Read-Host "Paste Anthropic API key" -AsSecureString
$plain  = [System.Net.NetworkCredential]::new("", $secure).Password

if (-not $plain -or $plain -notmatch "^sk-ant-") {
    Write-Error "That doesn't look like a valid Anthropic API key (expected sk-ant-...)."
    exit 1
}

$dir = Split-Path $CredFile
if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

ConvertTo-SecureString $plain -AsPlainText -Force |
    ConvertFrom-SecureString |
    Set-Content -Path $CredFile -Encoding UTF8

Write-Host ""
Write-Host "Saved to: $CredFile" -ForegroundColor Green
Write-Host "Encrypted with your Windows account (DPAPI) — never uploaded anywhere." -ForegroundColor DarkGray
Write-Host "Parse-PSR.ps1 will use this key automatically from now on." -ForegroundColor Green
