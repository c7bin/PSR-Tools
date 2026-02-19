#!/usr/bin/env pwsh
#Requires -Version 7.0
<#
.SYNOPSIS
    Parse a Windows PSR (Problem Steps Recorder) .zip file into structured outputs.

.DESCRIPTION
    Extracts steps, metadata, and screenshots from a PSR-generated .zip/.mht file.
    Outputs: steps.txt, metadata.xml, summary.json, and screenshots/*.jpg

.PARAMETER ZipPath
    Path to the PSR .zip file. If omitted, uses the newest .zip in Downloads.

.PARAMETER OutputBase
    Base folder for output. Defaults to the script's own directory + \output.

.EXAMPLE
    .\Parse-PSR.ps1
    .\Parse-PSR.ps1 -ZipPath "C:\Users\jacob\Downloads\1.zip"
#>
param(
    [string]$ZipPath     = "",
    [string]$OutputBase  = "",
    [string]$ApiKey      = "",   # Anthropic API key; falls back to $env:ANTHROPIC_API_KEY
    [switch]$SkipGenerate        # Skip Claude generation, output parsed files only
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Resolve output base ────────────────────────────────────────────────────────
if (-not $OutputBase) {
    $OutputBase = Join-Path $PSScriptRoot "output"
}

# ── Resolve zip path ───────────────────────────────────────────────────────────
if (-not $ZipPath) {
    $downloads = [System.IO.Path]::Combine($env:USERPROFILE, "Downloads")
    $newest = Get-ChildItem -Path $downloads -Filter "*.zip" -File |
              Sort-Object LastWriteTime -Descending |
              Select-Object -First 1
    if (-not $newest) {
        Write-Error "No .zip files found in $downloads"
        exit 1
    }
    $ZipPath = $newest.FullName
    Write-Host "Using newest zip: $ZipPath"
}

if (-not (Test-Path $ZipPath)) {
    Write-Error "Zip not found: $ZipPath"
    exit 1
}

# ── Extract zip to temp folder ─────────────────────────────────────────────────
$tempDir = Join-Path $env:TEMP ("PSR_" + [System.IO.Path]::GetRandomFileName())
Write-Host "Extracting to temp: $tempDir"
Expand-Archive -Path $ZipPath -DestinationPath $tempDir -Force

# Find the .mht file
$mhtFile = Get-ChildItem -Path $tempDir -Filter "*.mht" -Recurse | Select-Object -First 1
if (-not $mhtFile) {
    Write-Error "No .mht file found inside $ZipPath"
    exit 1
}

$recordingName = [System.IO.Path]::GetFileNameWithoutExtension($mhtFile.Name)
Write-Host "Found MHT: $($mhtFile.Name)  →  Recording: $recordingName"

# ── Set up output directory ────────────────────────────────────────────────────
$outDir = Join-Path $OutputBase $recordingName
$screenshotDir = Join-Path $outDir "screenshots"
New-Item -ItemType Directory -Path $outDir       -Force | Out-Null
New-Item -ItemType Directory -Path $screenshotDir -Force | Out-Null

Write-Host "Output folder: $outDir"

# ── Read the raw MHT content ───────────────────────────────────────────────────
# MHT files can be UTF-8 or Windows-1252; try UTF-8 first
$rawBytes  = [System.IO.File]::ReadAllBytes($mhtFile.FullName)
$rawContent = [System.Text.Encoding]::UTF8.GetString($rawBytes)

# ── Parse MIME boundary ────────────────────────────────────────────────────────
# The first line should be like: --=====MHTML_BOUNDARY==== or similar
$boundaryMatch = [regex]::Match($rawContent, 'boundary="([^"]+)"')
if (-not $boundaryMatch.Success) {
    # Try unquoted boundary
    $boundaryMatch = [regex]::Match($rawContent, 'boundary=([^\r\n]+)')
}
if (-not $boundaryMatch.Success) {
    Write-Error "Could not find MIME boundary in MHT file"
    exit 1
}
$boundary = $boundaryMatch.Groups[1].Value.Trim()
Write-Host "MIME boundary: $boundary"

# Split into MIME parts
$parts = $rawContent -split [regex]::Escape("--$boundary")
Write-Host "Found $($parts.Count - 2) MIME parts (excluding preamble/epilogue)"

# ── Extract main HTML section ──────────────────────────────────────────────────
$mainHtml = ""
$imageCount = 0
$imageSections = @()

foreach ($part in $parts) {
    $part = $part.TrimStart("`r", "`n")
    if ($part.StartsWith("--") -or $part.Trim() -eq "") { continue }

    # Parse part headers
    $headerEnd = $part.IndexOf("`r`n`r`n")
    if ($headerEnd -lt 0) { $headerEnd = $part.IndexOf("`n`n") }
    if ($headerEnd -lt 0) { continue }

    $headerBlock = $part.Substring(0, $headerEnd)
    $body        = $part.Substring($headerEnd).TrimStart("`r", "`n")

    # Content-Type
    $ctMatch = [regex]::Match($headerBlock, 'Content-Type:\s*([^\r\n;]+)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    $ct = if ($ctMatch.Success) { $ctMatch.Groups[1].Value.Trim() } else { "" }

    # Content-Transfer-Encoding
    $cteMatch = [regex]::Match($headerBlock, 'Content-Transfer-Encoding:\s*([^\r\n]+)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    $cte = if ($cteMatch.Success) { $cteMatch.Groups[1].Value.Trim().ToLower() } else { "" }

    if ($ct -match "text/html") {
        if ($cte -eq "quoted-printable") {
            # Decode quoted-printable
            $body = $body -replace "=`r`n", "" -replace "=`n", ""
            $body = [regex]::Replace($body, "=([0-9A-Fa-f]{2})", {
                param($m) [char]([convert]::ToInt32($m.Groups[1].Value, 16))
            })
        }
        if ($mainHtml -eq "") {
            $mainHtml = $body
        }
    }
    elseif ($ct -match "image/jpeg" -and $cte -eq "base64") {
        $imageCount++
        $imageSections += $body.Trim() -replace "\s+", ""
    }
}

Write-Host "Main HTML length: $($mainHtml.Length) chars"
Write-Host "Image sections found: $imageCount"

# ── Save screenshots ───────────────────────────────────────────────────────────
$savedImages = 0
for ($i = 0; $i -lt $imageSections.Count; $i++) {
    try {
        $b64 = $imageSections[$i]
        # Clean up any remaining whitespace
        $b64 = $b64 -replace '[^A-Za-z0-9+/=]', ''
        # Pad if needed
        $pad = $b64.Length % 4
        if ($pad -ne 0) { $b64 += "=" * (4 - $pad) }

        $bytes = [Convert]::FromBase64String($b64)
        $imgPath = Join-Path $screenshotDir ("screenshot{0:D4}.jpg" -f ($i + 1))
        [System.IO.File]::WriteAllBytes($imgPath, $bytes)
        $savedImages++
    }
    catch {
        Write-Warning "Failed to decode image $($i+1): $_"
    }
}
Write-Host "Saved $savedImages screenshots to $screenshotDir"

# ── Extract XML metadata block ─────────────────────────────────────────────────
# PSR embeds XML inside a <script id="myXML"> or <xml id="recordeddata"> tag
$xmlMatch = [regex]::Match($mainHtml, '<script[^>]+id="myXML"[^>]*>([\s\S]*?)</script>', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
if (-not $xmlMatch.Success) {
    $xmlMatch = [regex]::Match($mainHtml, '<xml[^>]+>([\s\S]*?)</xml>', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
}

$metadataXml = ""
if ($xmlMatch.Success) {
    $metadataXml = $xmlMatch.Groups[1].Value.Trim()
    $metaPath = Join-Path $outDir "metadata.xml"
    [System.IO.File]::WriteAllText($metaPath, $metadataXml, [System.Text.Encoding]::UTF8)
    Write-Host "Saved metadata.xml ($($metadataXml.Length) chars)"
} else {
    Write-Warning "No embedded XML metadata found in HTML"
}

# ── Extract step descriptions from HTML ───────────────────────────────────────
# PSR HTML structure: <div class="stepDiv"> ... <p><b>Step N: (HH:MM:SS)</b> action text</p>
$stepMatches = [regex]::Matches($mainHtml,
    '<b[^>]*>Step\s+(\d+):\s*\(([^)]+)\)</b>\s*([\s\S]*?)(?=<b[^>]*>Step\s+\d+:|</div>|$)',
    [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

# Fallback: simpler pattern
if ($stepMatches.Count -eq 0) {
    $stepMatches = [regex]::Matches($mainHtml,
        'Step\s+(\d+):\s*\(([^)]+)\)\s*</b>\s*([^<]+)',
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
}

Write-Host "Step matches found: $($stepMatches.Count)"

$steps = @()
foreach ($m in $stepMatches) {
    $stepNum  = [int]$m.Groups[1].Value
    $timestamp = $m.Groups[2].Value.Trim()
    # Strip remaining HTML tags from description
    $desc = $m.Groups[3].Value -replace '<[^>]+>', '' -replace '&amp;', '&' -replace '&lt;', '<' -replace '&gt;', '>' -replace '&nbsp;', ' ' -replace '\s+', ' '
    $desc = $desc.Trim()
    $steps += [PSCustomObject]@{ Step=$stepNum; Timestamp=$timestamp; Description=$desc }
}

# ── Parse XML metadata for structured step info ────────────────────────────────
$xmlSteps = @()
if ($metadataXml) {
    try {
        # Parse directly — PSR XML has its own <?xml?> declaration and <Report> root
        # Strip the declaration if present so we can parse cleanly
        $xmlToParse = $metadataXml -replace '^\s*<\?xml[^?]*\?>\s*', ''
        [xml]$xmlDoc = $xmlToParse

        # PSR XML: //EachAction nodes (may also appear as UserAction in older versions)
        $actionNodes = $xmlDoc.SelectNodes("//EachAction")
        if (-not $actionNodes -or $actionNodes.Count -eq 0) {
            $actionNodes = $xmlDoc.SelectNodes("//UserAction")
        }
        if (-not $actionNodes -or $actionNodes.Count -eq 0) {
            $actionNodes = $xmlDoc.SelectNodes("//Step")
        }

        Write-Host "XML action nodes found: $($actionNodes.Count)"

        function Get-NodeText($parent, $name) {
            $n = $parent.SelectSingleNode($name)
            if ($n) { $n.InnerText } else { "" }
        }
        function Get-Attr($elem, $name) {
            $a = $elem.GetAttribute($name)
            if ($a) { $a } else { "" }
        }

        foreach ($node in $actionNodes) {
            # EachAction: step metadata is a mix of XML attributes (FileName, ActionNumber)
            # and child elements (Description, Action, CursorCoordsXY, ScreenshotFileName)
            $uiaList = [System.Collections.Generic.List[hashtable]]::new()

            # UIAStack contains <Level> elements whose data is all in XML attributes
            $levelNodes = $node.SelectNodes(".//Level")
            foreach ($lv in $levelNodes) {
                $uiaList.Add([ordered]@{
                    AutomationId = Get-Attr $lv "AutomationId"
                    ClassName    = Get-Attr $lv "ClassName"
                    Name         = Get-Attr $lv "Name"
                    ControlType  = Get-Attr $lv "ControlType"
                })
            }

            $xmlStep = [ordered]@{
                Index          = Get-Attr    $node "ActionNumber"
                Description    = Get-NodeText $node "Description"
                Action         = Get-NodeText $node "Action"
                Process        = Get-Attr    $node "FileName"
                CursorCoords   = Get-NodeText $node "CursorCoordsXY"
                ScreenCoords   = Get-NodeText $node "ScreenCoordsXYWH"
                Screenshot     = Get-NodeText $node "ScreenshotFileName"
                UIAElements    = $uiaList.ToArray()
            }

            $xmlSteps += $xmlStep
        }
    }
    catch {
        Write-Warning "XML parsing error: $_"
    }
}

# ── Merge HTML steps + XML metadata ───────────────────────────────────────────
$merged = @()
$maxSteps = [Math]::Max($steps.Count, $xmlSteps.Count)
for ($i = 0; $i -lt $maxSteps; $i++) {
    $htmlStep = if ($i -lt $steps.Count) { $steps[$i] } else { $null }
    $xmlStep  = if ($i -lt $xmlSteps.Count) { $xmlSteps[$i] } else { $null }

    $entry = [ordered]@{
        step        = if ($htmlStep) { $htmlStep.Step } else { $i + 1 }
        timestamp   = if ($htmlStep) { $htmlStep.Timestamp } else { "" }
        description = if ($htmlStep) { $htmlStep.Description } elseif ($xmlStep) { $xmlStep.Description } else { "" }
        process     = if ($xmlStep)  { $xmlStep.Process } else { "" }
        action      = if ($xmlStep)  { $xmlStep.Action  } else { "" }
        coords      = if ($xmlStep)  { $xmlStep.CursorCoords } else { "" }
        screenshot  = "screenshot{0:D4}.jpg" -f ($i + 1)
        uiaElements = if ($xmlStep)  { $xmlStep.UIAElements } else { @() }
    }
    $merged += $entry
}

# ── Write steps.txt ────────────────────────────────────────────────────────────
$stepsLines = @()
$stepsLines += "PSR Recording: $recordingName"
$stepsLines += "Steps: $($merged.Count)    Screenshots: $savedImages"
$stepsLines += ("=" * 70)
foreach ($s in $merged) {
    $stepsLines += ""
    $stepsLines += "[Step $($s.step)] ($($s.timestamp))"
    $stepsLines += "  Description : $($s.description)"
    if ($s.process) { $stepsLines += "  Process     : $($s.process)" }
    if ($s.action)  { $stepsLines += "  Action      : $($s.action)"  }
    if ($s.coords)  { $stepsLines += "  Coords      : $($s.coords)"  }
    if (@($s.uiaElements).Count -gt 0) {
        $stepsLines += "  UI Elements :"
        foreach ($e in $s.uiaElements) {
            $parts2 = @()
            if ($e.AutomationId) { $parts2 += "AutomationId=$($e.AutomationId)" }
            if ($e.ClassName)    { $parts2 += "Class=$($e.ClassName)" }
            if ($e.Name)         { $parts2 += "Name=$($e.Name)" }
            if ($e.ControlType)  { $parts2 += "Type=$($e.ControlType)" }
            $stepsLines += "    - " + ($parts2 -join ", ")
        }
    }
}

$stepsPath = Join-Path $outDir "steps.txt"
[System.IO.File]::WriteAllLines($stepsPath, $stepsLines, [System.Text.Encoding]::UTF8)
Write-Host "Saved steps.txt ($($stepsLines.Count) lines)"

# ── Write summary.json ─────────────────────────────────────────────────────────
$summary = [ordered]@{
    recording   = $recordingName
    sourceZip   = $ZipPath
    stepCount   = $merged.Count
    screenshots = $savedImages
    steps       = $merged
}

$jsonPath = Join-Path $outDir "summary.json"
$summary | ConvertTo-Json -Depth 10 | Set-Content -Path $jsonPath -Encoding UTF8
Write-Host "Saved summary.json"

# ── Cleanup temp ───────────────────────────────────────────────────────────────
Remove-Item -Path $tempDir -Recurse -Force

# ── Credential helpers ─────────────────────────────────────────────────────────
# Uses DPAPI via ConvertFrom-SecureString (no Key param = Windows user+machine bound).
# Encrypted blob stored at %APPDATA%\PSR-Tools\api_key.cred — useless on any other
# account or machine, safe to leave on disk.

$script:CredFile   = Join-Path $env:APPDATA "PSR-Tools\api_key.cred"
$script:GistIdFile = Join-Path $env:APPDATA "PSR-Tools\gist_id.txt"
$script:GhExe      = "C:\Program Files\GitHub CLI\gh.exe"

function Save-ApiKey([string]$Plain) {
    $dir = Split-Path $script:CredFile
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    ConvertTo-SecureString $Plain -AsPlainText -Force |
        ConvertFrom-SecureString |
        Set-Content -Path $script:CredFile -Encoding UTF8
}

function Get-ApiKey([string]$Explicit) {
    # 1. Explicit -ApiKey param (CI / one-off override)
    if ($Explicit) { return $Explicit }

    # 2. Environment variable
    if ($env:ANTHROPIC_API_KEY) { return $env:ANTHROPIC_API_KEY }

    # 3. DPAPI local cache (fast, offline — written by both Gist fetch and direct setup)
    if (Test-Path $script:CredFile) {
        try {
            $plain = Get-Content $script:CredFile -Raw |
                     ConvertTo-SecureString |
                     ForEach-Object { [System.Net.NetworkCredential]::new("", $_).Password }
            if ($plain) { return $plain }
        } catch {
            Write-Warning "  Stored key could not be decrypted — will re-fetch."
            Remove-Item $script:CredFile -Force
        }
    }

    # 4. Private GitHub Gist (cross-machine — requires gh auth login)
    if ((Test-Path $script:GistIdFile) -and (Test-Path $script:GhExe)) {
        $gistId    = (Get-Content $script:GistIdFile -Raw).Trim()
        $authCheck = & $script:GhExe auth status 2>&1
        if ($LASTEXITCODE -eq 0) {
            try {
                $lines = @(& $script:GhExe gist view $gistId --raw 2>$null)
                $plain = ($lines | Where-Object { $_ -match '^sk-ant-' } | Select-Object -First 1)
                if ($plain) { $plain = $plain.Trim() }
                if ($LASTEXITCODE -eq 0 -and $plain -match "^sk-ant-") {
                    Write-Host "  API key fetched from GitHub Gist." -ForegroundColor DarkGray
                    Save-ApiKey $plain   # cache locally for next run
                    return $plain
                }
            } catch {
                Write-Warning "  Could not fetch Gist $gistId`: $_"
            }
        } else {
            Write-Host "  Gist ID found but not logged into GitHub." -ForegroundColor DarkYellow
            Write-Host "  Run: gh auth login   (then re-run this script)" -ForegroundColor DarkYellow
        }
    }

    # 5. config.json migration (one-time, then key moves to encrypted file)
    $configPath = Join-Path $PSScriptRoot "config.json"
    if (Test-Path $configPath) {
        try {
            $cfg       = Get-Content $configPath -Raw | ConvertFrom-Json
            $candidate = $cfg.anthropic_api_key.Trim()
            if ($candidate -and $candidate -notmatch "YOUR_KEY" -and $candidate -match "^sk-ant-api") {
                Write-Host "  Migrating key from config.json to encrypted credential file..." -ForegroundColor DarkYellow
                Save-ApiKey $candidate
                Write-Host "  Saved. You can now delete config.json." -ForegroundColor Green
                return $candidate
            }
        } catch { }
    }

    # 6. Interactive prompt — first-time setup on a machine with no Gist configured
    Write-Host ""
    Write-Host "  Anthropic API key needed." -ForegroundColor Cyan
    Write-Host "  Tip: run Set-PSRCredential.ps1 once to store it in a private GitHub Gist" -ForegroundColor DarkGray
    Write-Host "       so it's available automatically on every machine." -ForegroundColor DarkGray
    Write-Host "  Get a key at: https://console.anthropic.com/settings/keys" -ForegroundColor Cyan
    $secure = Read-Host "  Paste API key" -AsSecureString
    $plain  = [System.Net.NetworkCredential]::new("", $secure).Password
    if (-not $plain) { return $null }

    $save = Read-Host "  Cache encrypted locally for this machine? [Y/n]"
    if ($save -eq "" -or $save -match "^[Yy]") {
        Save-ApiKey $plain
        Write-Host "  Cached to $($script:CredFile)" -ForegroundColor Green
    }

    return $plain
}

# ── Claude API: generate automation.ps1 + walkthrough.md ──────────────────────
if (-not $SkipGenerate) {
    $ApiKey = Get-ApiKey -Explicit $ApiKey

    if (-not $ApiKey) {
        Write-Warning "No API key provided — skipping automation.ps1 / walkthrough.md generation."
    } else {
        Write-Host ""
        Write-Host "Calling Claude API (Haiku) to generate outputs..."

        $stepsContent = Get-Content $stepsPath -Raw

        $prompt = @"
You are given a Windows PSR (Problem Steps Recorder) recording. Produce two outputs.

RECORDING DATA:
$stepsContent

─────────────────────────────────────────
OUTPUT 1 — automation.ps1

Write a concise PowerShell script that achieves the same GOAL as this recording.

Rules:
- Interpret what the user was trying to accomplish, not how they did it in the UI
- Use native PowerShell cmdlets (New-Item, Copy-Item, Move-Item, Rename-Item, etc.)
- No UIAutomation, no mouse simulation, no SendKeys, no replaying clicks
- Use parameters for anything variable (filename, path, target URL, etc.)
- Include a short .SYNOPSIS block
- Keep it under 40 lines

─────────────────────────────────────────
OUTPUT 2 — walkthrough.md

Write a clear step-by-step markdown guide for a human following the same process.
Include: numbered steps, what to click/type, and why. Reference screenshot filenames
(screenshot0001.jpg … screenshot$('{0:D4}' -f $savedImages).jpg) where relevant.

─────────────────────────────────────────
Return your response using exactly these XML tags, with no other text outside them:

<automation_ps1>
(script here)
</automation_ps1>

<walkthrough_md>
(markdown here)
</walkthrough_md>
"@

        $requestBody = [ordered]@{
            model      = "claude-haiku-4-5-20251001"
            max_tokens = 2048
            messages   = @(
                @{ role = "user"; content = $prompt }
            )
        } | ConvertTo-Json -Depth 6 -Compress

        try {
            $response = Invoke-RestMethod `
                -Uri     "https://api.anthropic.com/v1/messages" `
                -Method  POST `
                -Headers @{
                    "x-api-key"         = $ApiKey
                    "anthropic-version" = "2023-06-01"
                    "content-type"      = "application/json"
                } `
                -Body $requestBody

            $raw = $response.content[0].text

            # Extract <automation_ps1> block
            $psMatch = [regex]::Match($raw, '(?s)<automation_ps1>\s*(.*?)\s*</automation_ps1>')
            if ($psMatch.Success) {
                $automationPath = Join-Path $outDir "automation.ps1"
                Set-Content -Path $automationPath -Value $psMatch.Groups[1].Value.Trim() -Encoding UTF8
                Write-Host "  Saved automation.ps1"
            } else {
                Write-Warning "  Could not parse <automation_ps1> block from response"
            }

            # Extract <walkthrough_md> block
            $mdMatch = [regex]::Match($raw, '(?s)<walkthrough_md>\s*(.*?)\s*</walkthrough_md>')
            if ($mdMatch.Success) {
                $walkthroughPath = Join-Path $outDir "walkthrough.md"
                Set-Content -Path $walkthroughPath -Value $mdMatch.Groups[1].Value.Trim() -Encoding UTF8
                Write-Host "  Saved walkthrough.md"
            } else {
                Write-Warning "  Could not parse <walkthrough_md> block from response"
            }
        }
        catch {
            Write-Warning "Claude API call failed: $_"
        }
    }
}

Write-Host ""
Write-Host "Done! Output at: $outDir"
Write-Host "  steps.txt      — human-readable step list"
Write-Host "  metadata.xml   — raw PSR XML"
Write-Host "  summary.json   — structured step data"
Write-Host "  screenshots\   — $savedImages JPEG screenshots"
if (-not $SkipGenerate) {
    Write-Host "  automation.ps1 — Claude-generated PowerShell script"
    Write-Host "  walkthrough.md — Claude-generated step guide"
}
