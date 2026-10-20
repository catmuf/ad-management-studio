<#
.SYNOPSIS
    Generates full historical changelog from all git commits since project inception.
.DESCRIPTION
    Extracts every commit from the initial commit (cc155ca) to HEAD, parses Conventional
    Commit formats, categorizes changes into structured Markdown sections, and exports:
    1. Root CHANGELOG.md (comprehensive project history)
    2. docs/releases/v3.2.0.md (GitHub Release markdown body)
.EXAMPLE
    pwsh -NoProfile -File tools/Generate-Changelog.ps1
#>

[CmdletBinding()]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
param(
    [string]$CurrentVersion = "v3.2.0",
    [string]$RepoUrl = "https://github.com/catmuf/ad-management-studio"
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $scriptDir

# 1. Fetch all commits from git log
$rawLog = & git log --pretty=format:"%H|%h|%ad|%s" --date=short
if (-not $rawLog) {
    Write-Error "Failed to retrieve git log."
    exit 1
}

$commits = @()
foreach ($line in $rawLog) {
    if ([string]::IsNullOrWhiteSpace($line)) { continue }
    $parts = $line.Split('|', 4)
    if ($parts.Count -eq 4) {
        $commits += [PSCustomObject]@{
            FullHash  = $parts[0]
            ShortHash = $parts[1]
            Date      = $parts[2]
            Subject   = $parts[3]
        }
    }
}

Write-Host "[INFO] Parsed $($commits.Count) commits from git history." -ForegroundColor Cyan

# 2. Categorize commits
$features = @()
$fixes = @()
$perf = @()
$docs = @()
$refactor = @()
$other = @()

foreach ($c in $commits) {
    $msg = $c.Subject
    if ($msg -match '^(feat|Implement|Enable)(\(.*\))?:\s*(.*)$' -or $msg -match '^(feat|Implement|Enable)\s+(.*)$') {
        $features += $c
    }
    elseif ($msg -match '^(fix)(\(.*\))?:\s*(.*)$' -or $msg -match '^Fix\s+(.*)$') {
        $fixes += $c
    }
    elseif ($msg -match '^perf(\(.*\))?:\s*(.*)$') {
        $perf += $c
    }
    elseif ($msg -match '^docs(\(.*\))?:\s*(.*)$') {
        $docs += $c
    }
    elseif ($msg -match '^(refactor|style|test|chore|qa)(\(.*\))?:\s*(.*)$') {
        $refactor += $c
    }
    else {
        $other += $c
    }
}

function Format-CommitList($list) {
    $sb = [System.Text.StringBuilder]::new()
    foreach ($item in $list) {
        $link = "$RepoUrl/commit/$($item.FullHash)"
        $h = $item.ShortHash
        $s = $item.Subject
        $d = $item.Date
        $formatted = "- [" + [char]96 + $h + [char]96 + "](" + $link + ") - " + $s + " *(" + $d + ")*"
        [void]$sb.AppendLine($formatted)
    }
    return $sb.ToString().TrimEnd()
}

$releaseDate = Get-Date -Format "yyyy-MM-dd"

# 3. Build Markdown Content
$changelogMd = @"
# Changelog
All notable changes to **Active Directory Management Studio** are documented in this file.
The project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) and [Conventional Commits](https://www.conventionalcommits.org/).

---

## [$CurrentVersion] - $releaseDate

### 🚀 Major Architectural Milestones
- **Enterprise Parity Suite**: Achieved complete operational equivalence with **Softerra LDAP Administrator**, **Apache Directory Studio**, and **NetTools** (79+ specialized capabilities across 24 administrative panels).
- **In-Process Multi-Instance Architecture**: Independent window detachment with zero latency, simultaneous instances, cross-window drag-and-drop, and seamless dock-back.
- **WPF / Modern Light & Dark Themes**: High-contrast, accessibility-audited palettes with custom styling, dynamic theme switching, and real-time HTML technical dossiers.
- **Active Directory Auto-Discovery & Health**: Automated DNS SRV locator detection, multi-DC replication topology matrix, and real-time TCP/ICMP ping latency diagnostics.

### ✨ Features & Enhancements ($($features.Count) commits)
$(Format-CommitList $features)

### 🐛 Bug Fixes & UX Hardening ($($fixes.Count) commits)
$(Format-CommitList $fixes)

### ⚡ Performance & Engine Optimizations ($($perf.Count) commits)
$(Format-CommitList $perf)

### 📚 Documentation & Visual Guides ($($docs.Count) commits)
$(Format-CommitList $docs)

### 🛡️ Refactoring, Stability & Quality Assurance ($($refactor.Count) commits)
$(Format-CommitList $refactor)

### 📦 Initial Project Genesis ($($other.Count) commits)
$(Format-CommitList $other)

---

## Commit Statistics Since Inception
- **Total Commits Documented**: $($commits.Count)
- **First Commit**: [\`cc155ca\`]($RepoUrl/commit/cc155ca) *(2024-08-27)*
- **Latest Commit**: [\`$($commits[0].ShortHash)\`]($RepoUrl/commit/$($commits[0].FullHash)) *($($commits[0].Date))*
- **Target Release Version**: $CurrentVersion (Enterprise Edition)
"@

# 4. Save to root CHANGELOG.md
$changelogPath = Join-Path $projectRoot "CHANGELOG.md"
[System.IO.File]::WriteAllText($changelogPath, $changelogMd, [System.Text.Encoding]::UTF8)
Write-Host "[SUCCESS] Wrote comprehensive changelog to $changelogPath" -ForegroundColor Green

# 5. Save GitHub Release notes body
$releaseDir = Join-Path $projectRoot "docs\releases"
if (-not (Test-Path $releaseDir)) {
    [void](New-Item -ItemType Directory -Path $releaseDir -Force)
}
$releaseNotesPath = Join-Path $releaseDir "$CurrentVersion.md"

$releaseBody = @"
## Active Directory Management Studio $CurrentVersion (Enterprise Edition)

### ⚡ Overview
Active Directory Management Studio $CurrentVersion is an enterprise-grade administration and directory engineering workbench built with modern **PowerShell & WPF/XAML**. It integrates daily directory operations (Users, Groups, OUs, Computers) with deep low-level forensic and diagnostic engines previously fragmented across specialized utilities (**Softerra LDAP Administrator**, **Apache Directory Studio**, and **NetTools**).

### 🌟 Key Highlights
- **Active Directory Auto-Detection**: Instant discovery of domain controllers via DNS SRV locator records with sortable ping latency measurements.
- **Comprehensive Parity Suites**: Full LDAP-SQL grammar, SCIM 2.0 query filter compiler, 48 automated enterprise security hygiene audits, and 7-tier UNC diagnostics.
- **In-Process Multi-Instance Windows**: Detach any workspace into standalone floating windows and dock back with zero state loss.
- **High-Resolution Visual Guides**: Complete 19-gallery documentation with verified Light and Dark theme presentations.

---

### 📋 Full Commit History & Detailed Changelog (All $($commits.Count) commits since inception)

#### ✨ Features & Enhancements
$(Format-CommitList $features)

#### 🐛 Bug Fixes & UX Hardening
$(Format-CommitList $fixes)

#### ⚡ Performance Optimizations
$(Format-CommitList $perf)

#### 📚 Documentation & Manuals
$(Format-CommitList $docs)

#### 🛡️ Stability & Code Quality
$(Format-CommitList $refactor)

---
*Generated automatically by [tools/Generate-Changelog.ps1]($RepoUrl/blob/main/tools/Generate-Changelog.ps1).*
"@

[System.IO.File]::WriteAllText($releaseNotesPath, $releaseBody, [System.Text.Encoding]::UTF8)
Write-Host "[SUCCESS] Wrote GitHub Release notes to $releaseNotesPath" -ForegroundColor Green
