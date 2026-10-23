<#
.SYNOPSIS
    Generates full historical changelog from all git commits since project inception.
.DESCRIPTION
    Extracts every commit from initial commit (cc155ca) to HEAD, maps each commit to
    its specific Semantic Version release milestone (v0.1.0 through v3.3.0), and exports:
    1. Root CHANGELOG.md (comprehensive version-by-version release history + commit matrix)
    2. docs/releases/v*.md (individual GitHub Release markdown bodies for all 11 releases)
.EXAMPLE
    pwsh -NoProfile -File tools/Generate-Changelog.ps1
#>

[CmdletBinding()]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
param(
    [string]$RepoUrl = "https://github.com/catmuf/ad-management-studio"
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $scriptDir

# 1. Fetch all commits in chronological order (oldest to newest)
$rawLog = & git log --reverse --pretty=format:"%H|%h|%ad|%s" --date=short
if (-not $rawLog) {
    Write-Error "Failed to retrieve git log."
    exit 1
}

$allCommits = @()
foreach ($line in $rawLog) {
    if ([string]::IsNullOrWhiteSpace($line)) { continue }
    $parts = $line.Split('|', 4)
    if ($parts.Count -eq 4) {
        $allCommits += [PSCustomObject]@{
            FullHash  = $parts[0]
            ShortHash = $parts[1]
            Date      = $parts[2]
            Subject   = $parts[3]
            Version   = ""
            Index     = $allCommits.Count + 1
        }
    }
}

Write-Host "[INFO] Loaded $($allCommits.Count) commits from git history." -ForegroundColor Cyan

# 2. Define historical release milestones
$milestones = @(
    [PSCustomObject]@{
        Version     = "v3.3.0"
        Title       = "Simple Search Mode, Sub-Second Startup, Active Connection Controls & Architecture Hardening"
        Date        = "2026-10-23"
        StartCommit = "ed38733"
        TipCommit   = "HEAD"
        Summary     = "Delivers sub-second application startup via direct XAML streaming and lazy RSAT loading, simple directory search mode with collapsible advanced filters and arrow toggle, active connection management enhancements (expandable DC table, sort arrows, live filter, internal horizontal scrolling), sidebar toggle button and Ctrl+B shortcut, configurable default startup tabs with session state saving, combobox virtualization with debouncing, light mode connection dialog fixes, and architectural JIT decomposition of ADService."
    },
    [PSCustomObject]@{
        Version     = "v3.2.0"
        Title       = "Native Menu Bar, AD Auto-Detect, Ping Latency & SemVer Standardization"
        Date        = "2026-10-20"
        StartCommit = "39892e0"
        TipCommit   = "ee7d53a"
        Summary     = "Introduces native Windows horizontal menu bar (11 top-level menus, live checkmarks), Quick Tools dropdown, startup performance optimization via DataGrid UI virtualization and NameScope indexing, search bar alignment & sync, automated DNS SRV domain controller auto-detection with sortable ping latency measurements, standard SemVer v3.2.0 branding, and 19 regenerated application screenshots."
    },
    [PSCustomObject]@{
        Version     = "v3.1.0"
        Title       = "Platform Hardening, PSSA Compliance & Multi-Dossier Tabs"
        Date        = "2026-10-15"
        StartCommit = "5353d4d"
        TipCommit   = "0761bc1"
        Summary     = "Deep stability hardening across all 24 administrative panels, recursive event loop elimination, 100% PSScriptAnalyzer compliance, ISO 8601 millisecond logging, multi-dossier tab preservation during navigation, and connection profile deduplication."
    },
    [PSCustomObject]@{
        Version     = "v3.0.0"
        Title       = "Multi-Instance Detached Windows & Headless Automation CLI"
        Date        = "2026-10-13"
        StartCommit = "18bf0c5"
        TipCommit   = "5e81af1"
        Summary     = "Architectural breakthrough with in-process simultaneous multi-instance detached windows, crash-free zero-latency dock-back, headless automation CLI (tools/ad-studio-cli.ps1) with 5 command modes, structured error logging service, and advanced identity / SDProp trigger engine."
    },
    [PSCustomObject]@{
        Version     = "v2.4.0"
        Title       = "Light Theme, In-App HTML Technical Dossier & NetTools Suite"
        Date        = "2026-10-08"
        StartCommit = "442d254"
        TipCommit   = "3b8defa"
        Summary     = "Introduces high-contrast accessibility-audited Light Theme, rich in-app HTML technical identity dossier, complete 16-module NetTools diagnostic parity (Effective Rights, Token Bloat, Replication Suite, 7-Tier UNC diagnostics), and in-window tab drag-and-drop workspace manager."
    },
    [PSCustomObject]@{
        Version     = "v2.3.0"
        Title       = "Enterprise Parity, SCIM 2.0 Cloud Export & Security Audits"
        Date        = "2026-10-07"
        StartCommit = "628d823"
        TipCommit   = "347b6fd"
        Summary     = "Achieves deep parity with Softerra LDAP Administrator and Apache Directory Studio, adding SCIM 2.0 cloud export, Active Directory Recycle Bin, Server Monitor telemetry, 15 security audit categories (48 reports), LDIF Document Outline tree, and schema class/attribute inspector."
    },
    [PSCustomObject]@{
        Version     = "v2.2.0"
        Title       = "Dynamic Column Chooser, Member Manager & Responsive UI"
        Date        = "2026-10-06"
        StartCommit = "e956b31"
        TipCommit   = "7a834fd"
        Summary     = "Adds dynamic table column chooser across all directory grids, dedicated group membership manager dialog (search, add, remove, transitive toggle), responsive toolbars with WrapPanels, and universal UI contrast improvements."
    },
    [PSCustomObject]@{
        Version     = "v2.1.0"
        Title       = "Interactive Search, Live Schema & Dynamic LDAP-SQL Grid"
        Date        = "2026-10-05"
        StartCommit = "6100fe7"
        TipCommit   = "aba6c61"
        Summary     = "Introduces real-time inline attribute dropdown search and filtering, live Active Directory schema attribute population, dynamic DataGrid column generation for ANSI LDAP-SQL results, and instant client-side user account filtering."
    },
    [PSCustomObject]@{
        Version     = "v2.0.0"
        Title       = "Professional SysAdmin Edition & Softerra Core Engines"
        Date        = "2026-10-02"
        StartCommit = "62d738d"
        TipCommit   = "9100df3"
        Summary     = "Major overhaul of the interface into a professional SysAdmin edition, integrating dedicated Softerra LDAP engines and service modules, dialog controllers in main.ps1, and the comprehensive SysAdmin Handbook."
    },
    [PSCustomObject]@{
        Version     = "v1.0.0"
        Title       = "Complete Overhaul to Active Directory Management Studio"
        Date        = "2026-09-23"
        StartCommit = "0422fe6"
        TipCommit   = "0422fe6"
        Summary     = "Foundation release completely refactoring the legacy project into Active Directory Management Studio with modern PowerShell and WPF/XAML architecture."
    },
    [PSCustomObject]@{
        Version     = "v0.1.0"
        Title       = "Initial Project Genesis & Legacy Core"
        Date        = "2024-08-27"
        StartCommit = "cc155ca"
        TipCommit   = "3b526d6"
        Summary     = "Initial repository creation, baseline user management PowerShell scripts, and project configuration."
    }
)

# 3. Associate each commit with its milestone
# We process milestones from newest to oldest in chronological order of ranges
# Build map:
$commitIndexMap = @{}
for ($i = 0; $i -lt $allCommits.Count; $i++) {
    $commitIndexMap[$allCommits[$i].ShortHash] = $i
}

foreach ($m in $milestones) {
    $startIndex = $commitIndexMap[$m.StartCommit]
    if ($m.TipCommit -eq "HEAD") {
        $endIndex = $allCommits.Count - 1
        $m.TipCommit = $allCommits[$endIndex].ShortHash
    } else {
        $endIndex = $commitIndexMap[$m.TipCommit]
    }
    if ($null -eq $startIndex -or $null -eq $endIndex) {
        Write-Error "Could not find commit range for $($m.Version) ($($m.StartCommit) .. $($m.TipCommit))"
        exit 1
    }
    for ($i = $startIndex; $i -le $endIndex; $i++) {
        $allCommits[$i].Version = $m.Version
    }
}

# Verify every commit has a version
$unassigned = $allCommits | Where-Object { [string]::IsNullOrEmpty($_.Version) }
if ($unassigned.Count -gt 0) {
    Write-Warning "Unassigned commits found: $($unassigned.Count)"
    foreach ($u in $unassigned) {
        Write-Warning "  $($u.ShortHash) - $($u.Subject)"
    }
}

# 4. Helper function to format commits
function Format-CommitItem($list) {
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

# 5. Build individual release files in docs/releases/
$releaseDir = Join-Path $projectRoot "docs\releases"
if (-not (Test-Path $releaseDir)) {
    [void](New-Item -ItemType Directory -Path $releaseDir -Force)
}

$utf8Bom = [System.Text.UTF8Encoding]::new($true)

foreach ($m in $milestones) {
    $mCommits = $allCommits | Where-Object { $_.Version -eq $m.Version }
    # Reverse so newest commit within release is first
    $mCommitsReversed = @($mCommits)
    [array]::Reverse($mCommitsReversed)

    $feats = @($mCommitsReversed | Where-Object { $_.Subject -match '^(feat|Implement|Enable)' })
    $fixes = @($mCommitsReversed | Where-Object { $_.Subject -match '^(fix|Fix)' })
    $perfs = @($mCommitsReversed | Where-Object { $_.Subject -match '^perf' })
    $docss = @($mCommitsReversed | Where-Object { $_.Subject -match '^docs' })
    $qa    = @($mCommitsReversed | Where-Object { $_.Subject -match '^(refactor|style|test|chore|qa)' })
    $other = @($mCommitsReversed | Where-Object { $_ -notin $feats -and $_ -notin $fixes -and $_ -notin $perfs -and $_ -notin $docss -and $_ -notin $qa })

    $mBody = [System.Text.StringBuilder]::new()
    $tipLink = "[" + [char]96 + $m.TipCommit + [char]96 + "]($RepoUrl/commit/$($m.TipCommit))"
    $startLink = "[" + [char]96 + $m.StartCommit + [char]96 + "]($RepoUrl/commit/$($m.StartCommit))"

    [void]$mBody.AppendLine("## Active Directory Management Studio $($m.Version) - $($m.Title)")
    [void]$mBody.AppendLine("")
    [void]$mBody.AppendLine("**Release Date:** $($m.Date) | **Total Commits:** $($mCommits.Count) | **Tip Commit:** $tipLink")
    [void]$mBody.AppendLine("")
    [void]$mBody.AppendLine("### ⚡ Overview & Highlights")
    [void]$mBody.AppendLine($m.Summary)
    [void]$mBody.AppendLine("")
    [void]$mBody.AppendLine("---")
    [void]$mBody.AppendLine("")
    [void]$mBody.AppendLine("### 📋 Commits in this Release")

    if ($feats.Count -gt 0) {
        [void]$mBody.AppendLine("")
        [void]$mBody.AppendLine("#### ✨ Features & Capabilities ($($feats.Count))")
        [void]$mBody.AppendLine((Format-CommitItem $feats))
    }
    if ($fixes.Count -gt 0) {
        [void]$mBody.AppendLine("")
        [void]$mBody.AppendLine("#### 🐛 Bug Fixes & UX Hardening ($($fixes.Count))")
        [void]$mBody.AppendLine((Format-CommitItem $fixes))
    }
    if ($perfs.Count -gt 0) {
        [void]$mBody.AppendLine("")
        [void]$mBody.AppendLine("#### ⚡ Performance Optimizations ($($perfs.Count))")
        [void]$mBody.AppendLine((Format-CommitItem $perfs))
    }
    if ($docss.Count -gt 0) {
        [void]$mBody.AppendLine("")
        [void]$mBody.AppendLine("#### 📚 Documentation & Manuals ($($docss.Count))")
        [void]$mBody.AppendLine((Format-CommitItem $docss))
    }
    if ($qa.Count -gt 0) {
        [void]$mBody.AppendLine("")
        [void]$mBody.AppendLine("#### 🛡️ Stability & Code Quality ($($qa.Count))")
        [void]$mBody.AppendLine((Format-CommitItem $qa))
    }
    if ($other.Count -gt 0) {
        [void]$mBody.AppendLine("")
        [void]$mBody.AppendLine("#### 📦 Project Genesis & Maintenance ($($other.Count))")
        [void]$mBody.AppendLine((Format-CommitItem $other))
    }

    [void]$mBody.AppendLine("")
    [void]$mBody.AppendLine("---")
    [void]$mBody.AppendLine("*Generated automatically by [tools/Generate-Changelog.ps1]($RepoUrl/blob/main/tools/Generate-Changelog.ps1).*")

    $relFile = Join-Path $releaseDir "$($m.Version).md"
    [System.IO.File]::WriteAllText($relFile, $mBody.ToString(), $utf8Bom)
    Write-Host "[SUCCESS] Wrote release notes for $($m.Version) to $relFile" -ForegroundColor Green
}

# 6. Build Comprehensive CHANGELOG.md
$sbChange = [System.Text.StringBuilder]::new()
[void]$sbChange.AppendLine("# Changelog")
[void]$sbChange.AppendLine("All notable changes to **Active Directory Management Studio** are documented in this file.")
[void]$sbChange.AppendLine("The project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) and [Conventional Commits](https://www.conventionalcommits.org/).")
[void]$sbChange.AppendLine("")
[void]$sbChange.AppendLine("---")
[void]$sbChange.AppendLine("")
[void]$sbChange.AppendLine("## 📊 Complete Commit-to-Version Reference Table (All $($allCommits.Count) Commits)")
[void]$sbChange.AppendLine("")
[void]$sbChange.AppendLine("| # | Version | Commit | Date | Subject |")
[void]$sbChange.AppendLine("| :---: | :---: | :---: | :---: | :--- |")

# List commits in chronological reverse (newest #82 down to #1)
$commitsReversed = @($allCommits)
[array]::Reverse($commitsReversed)

foreach ($c in $commitsReversed) {
    $link = "$RepoUrl/commit/$($c.FullHash)"
    $shortLink = "[" + [char]96 + $c.ShortHash + [char]96 + "](" + $link + ")"
    # Sanitize pipe characters in subject if any
    $cleanSub = $c.Subject.Replace("|", "-")
    [void]$sbChange.AppendLine("| $($c.Index) | **$($c.Version)** | $shortLink | $($c.Date) | $cleanSub |")
}

[void]$sbChange.AppendLine("")
[void]$sbChange.AppendLine("---")
[void]$sbChange.AppendLine("")
[void]$sbChange.AppendLine("## 🚀 Detailed Release History by Version")

foreach ($m in $milestones) {
    $mCommits = $allCommits | Where-Object { $_.Version -eq $m.Version }
    $mCommitsReversed = @($mCommits)
    [array]::Reverse($mCommitsReversed)

    $feats = @($mCommitsReversed | Where-Object { $_.Subject -match '^(feat|Implement|Enable)' })
    $fixes = @($mCommitsReversed | Where-Object { $_.Subject -match '^(fix|Fix)' })
    $perfs = @($mCommitsReversed | Where-Object { $_.Subject -match '^perf' })
    $docss = @($mCommitsReversed | Where-Object { $_.Subject -match '^docs' })
    $qa    = @($mCommitsReversed | Where-Object { $_.Subject -match '^(refactor|style|test|chore|qa)' })
    $other = @($mCommitsReversed | Where-Object { $_ -notin $feats -and $_ -notin $fixes -and $_ -notin $perfs -and $_ -notin $docss -and $_ -notin $qa })

    [void]$sbChange.AppendLine("")
    [void]$sbChange.AppendLine("### [$($m.Version)] - $($m.Date)")
    [void]$sbChange.AppendLine("#### $($m.Title)")
    [void]$sbChange.AppendLine("")
    [void]$sbChange.AppendLine("$($m.Summary)")
    [void]$sbChange.AppendLine("")
    $startLink = "[" + [char]96 + $m.StartCommit + [char]96 + "]($RepoUrl/commit/$($m.StartCommit))"
    $tipLink   = "[" + [char]96 + $m.TipCommit + [char]96 + "]($RepoUrl/commit/$($m.TipCommit))"
    [void]$sbChange.AppendLine("- **Release Commit Range**: $startLink .. $tipLink")
    [void]$sbChange.AppendLine("- **Commits in Release**: $($mCommits.Count)")
    [void]$sbChange.AppendLine("- **Dedicated Release Notes**: [docs/releases/$($m.Version).md](docs/releases/$($m.Version).md)")

    if ($feats.Count -gt 0) {
        [void]$sbChange.AppendLine("")
        [void]$sbChange.AppendLine("##### ✨ Features & Capabilities ($($feats.Count))")
        [void]$sbChange.AppendLine((Format-CommitItem $feats))
    }
    if ($fixes.Count -gt 0) {
        [void]$sbChange.AppendLine("")
        [void]$sbChange.AppendLine("##### 🐛 Bug Fixes & UX Hardening ($($fixes.Count))")
        [void]$sbChange.AppendLine((Format-CommitItem $fixes))
    }
    if ($perfs.Count -gt 0) {
        [void]$sbChange.AppendLine("")
        [void]$sbChange.AppendLine("##### ⚡ Performance & Engine Optimizations ($($perfs.Count))")
        [void]$sbChange.AppendLine((Format-CommitItem $perfs))
    }
    if ($docss.Count -gt 0) {
        [void]$sbChange.AppendLine("")
        [void]$sbChange.AppendLine("##### 📚 Documentation & Visual Guides ($($docss.Count))")
        [void]$sbChange.AppendLine((Format-CommitItem $docss))
    }
    if ($qa.Count -gt 0) {
        [void]$sbChange.AppendLine("")
        [void]$sbChange.AppendLine("##### 🛡️ Stability & Code Quality ($($qa.Count))")
        [void]$sbChange.AppendLine((Format-CommitItem $qa))
    }
    if ($other.Count -gt 0) {
        [void]$sbChange.AppendLine("")
        [void]$sbChange.AppendLine("##### 📦 Maintenance & Setup ($($other.Count))")
        [void]$sbChange.AppendLine((Format-CommitItem $other))
    }

    [void]$sbChange.AppendLine("")
    [void]$sbChange.AppendLine("---")
}

$changelogPath = Join-Path $projectRoot "CHANGELOG.md"
[System.IO.File]::WriteAllText($changelogPath, $sbChange.ToString(), $utf8Bom)
Write-Host "[SUCCESS] Wrote full historical changelog to $changelogPath" -ForegroundColor Green
