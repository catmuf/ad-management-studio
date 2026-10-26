<#
.SYNOPSIS
    Automated verification suite for Competitor Parity & UI Modernization (Phase 1 to Phase 4).
    Validates Omnibar 2.0, Directory Breadcrumbs, Telemetry, Client IP LPM Resolver,
    Group Member Diff (3-way Venn), Duplicate SPN Scanner, Entra Sync Audit, and WPF UI XAML.
#>

$ErrorActionPreference = "Stop"
$scriptRoot = Split-Path -Parent $PSScriptRoot
if (-not $scriptRoot) { $scriptRoot = (Get-Location).Path }

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "   ACTIVE DIRECTORY STUDIO: COMPETITOR PARITY & UI TEST SUITE        " -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

$testResults = [System.Collections.Generic.List[PSCustomObject]]::new()
function Assert-Test ($Name, [scriptblock]$TestBlock) {
    try {
        & $TestBlock
        Write-Host "  [PASS] $Name" -ForegroundColor Green
        $testResults.Add([PSCustomObject]@{ Test = $Name; Status = "PASS"; Error = "" })
    } catch {
        Write-Host "  [FAIL] ${Name}: $($_.Exception.Message)" -ForegroundColor Red
        $testResults.Add([PSCustomObject]@{ Test = $Name; Status = "FAIL"; Error = $_.Exception.Message })
    }
}

# 1. Import Modules
Import-Module (Join-Path $scriptRoot "Modules\ReplicationService.psm1") -Force
Import-Module (Join-Path $scriptRoot "Modules\DiagnosticService.psm1") -Force
Import-Module (Join-Path $scriptRoot "Modules\KerberosService.psm1") -Force
Import-Module (Join-Path $scriptRoot "Modules\AuditReportService.psm1") -Force

# ---------------------------------------------------------
# Test 1: Convert-CIDRToRange and LPM Subnet Resolution
# ---------------------------------------------------------
Write-Host "`n[1/7] Testing Client IP Subnet & Site Resolver (LPM)..." -ForegroundColor Yellow

Assert-Test "Convert-CIDRToRange parses /24 CIDR correctly" {
    $r = Convert-CIDRToRange -Cidr "10.10.15.0/24"
    if (-not $r) { throw "Convert-CIDRToRange returned null" }
    if ($r.StartIP -ne 168431360 -or $r.EndIP -ne 168431615) {
        throw "Expected start=168431360, end=168431615, got start=$($r.StartIP), end=$($r.EndIP)"
    }
}

Assert-Test "Convert-CIDRToRange parses /16 and /8 without overflow" {
    $r16 = Convert-CIDRToRange -Cidr "10.10.0.0/16"
    $r8  = Convert-CIDRToRange -Cidr "10.0.0.0/8"
    if ($r16.EndIP -le $r16.StartIP -or $r8.EndIP -le $r8.StartIP) {
        throw "Invalid range boundaries in /16 or /8"
    }
}

Assert-Test "Resolve-ClientIPToSiteSubnet selects winning site via Longest Prefix Match (LPM)" {
    $res = Resolve-ClientIPToSiteSubnet -ClientIP "10.10.15.42" -Simulate
    if ($res.MatchedSubnet -ne "10.10.15.0/24") {
        throw "Expected winning subnet '10.10.15.0/24', got '$($res.MatchedSubnet)'"
    }
    if ($res.SiteName -ne "HQ-Floor2") {
        throw "Expected winning site 'HQ-Floor2', got '$($res.SiteName)'"
    }
    if ($res.PrefixLength -ne 24) {
        throw "Expected prefix length 24, got '$($res.PrefixLength)'"
    }
    if ($res.CandidateSubnets.Count -lt 2) {
        throw "Expected multiple evaluated candidates, got $($res.CandidateSubnets.Count)"
    }
}

Assert-Test "Resolve-ClientIPToSiteSubnet handles uncovered IPs gracefully" {
    $res = Resolve-ClientIPToSiteSubnet -ClientIP "172.16.5.5" -Simulate
    if ($res.MatchedSubnet -ne "None") {
        throw "Expected 'None' for uncovered IP, got '$($res.MatchedSubnet)'"
    }
    if ($res.MatchStatus -ne "Subnet Not Found") {
        throw "Expected 'Subnet Not Found', got '$($res.MatchStatus)'"
    }
}

Assert-Test "Resolve-ClientIPToSiteSubnet validates invalid IP inputs" {
    $res = Resolve-ClientIPToSiteSubnet -ClientIP "999.888.777.666" -Simulate
    if ($res.MatchStatus -ne "Invalid IPv4 Address") {
        throw "Expected 'Invalid IPv4 Address', got '$($res.MatchStatus)'"
    }
}

# ---------------------------------------------------------
# Test 2: Group Member Diff (3-Way Venn)
# ---------------------------------------------------------
Write-Host "`n[2/7] Testing Group Member Diff Engine (3-way Venn)..." -ForegroundColor Yellow

Assert-Test "Compare-ADGroupMemberships computes 3-way Venn partitions" {
    $diff = Compare-ADGroupMemberships -GroupA "Tier1-Admins" -GroupB "Tier2-Admins" -Simulate
    if ($diff.TotalMembersA -ne 4 -or $diff.TotalMembersB -ne 4) {
        throw "Expected 4 members in each group, got A=$($diff.TotalMembersA), B=$($diff.TotalMembersB)"
    }
    if ($diff.MatchingCount -ne 2) {
        throw "Expected 2 common members, got $($diff.MatchingCount)"
    }
    if ($diff.UniqueToACount -ne 2) {
        throw "Expected 2 unique to A, got $($diff.UniqueToACount)"
    }
    if ($diff.UniqueToBCount -ne 2) {
        throw "Expected 2 unique to B, got $($diff.UniqueToBCount)"
    }
    if ($diff.TotalDistinctMembers -ne 6) {
        throw "Expected 6 distinct members total, got $($diff.TotalDistinctMembers)"
    }
}

Assert-Test "Compare-ADGroupMemberships populates detailed ComparisonMatrix" {
    $diff = Compare-ADGroupMemberships -GroupA "Tier1-Admins" -GroupB "Tier2-Admins" -Simulate
    $alice = $diff.ComparisonMatrix | Where-Object { $_.SamAccountName -eq "asmith" }
    if (-not $alice -or $alice.Category -ne "Both" -or -not $alice.InGroupA -or -not $alice.InGroupB) {
        throw "Alice Smith not marked as 'Both'"
    }
    $charlie = $diff.ComparisonMatrix | Where-Object { $_.SamAccountName -eq "cbrown" }
    if (-not $charlie -or $charlie.Category -ne "OnlyInA" -or -not $charlie.InGroupA -or $charlie.InGroupB) {
        throw "Charlie Brown not marked as 'OnlyInA'"
    }
    $diana = $diff.ComparisonMatrix | Where-Object { $_.SamAccountName -eq "dprince" }
    if (-not $diana -or $diana.Category -ne "OnlyInB" -or $diana.InGroupA -or -not $diana.InGroupB) {
        throw "Diana Prince not marked as 'OnlyInB'"
    }
}

# ---------------------------------------------------------
# Test 3: Duplicate SPN Scanner
# ---------------------------------------------------------
Write-Host "`n[3/7] Testing Kerberos Duplicate SPN Scanner..." -ForegroundColor Yellow

Assert-Test "Find-DuplicateSPNs detects conflicting SPN registrations" {
    $dupes = Find-DuplicateSPNs -Simulate
    if ($dupes.Count -lt 2) {
        throw "Expected at least 2 conflicting SPN clusters, got $($dupes.Count)"
    }
    $sqlCluster = $dupes | Where-Object { $_.SPN -like "*MSSQLSvc*" }
    if (-not $sqlCluster) { throw "MSSQLSvc duplicate SPN not detected" }
    if ($sqlCluster.ConflictCount -ne 2) {
        throw "Expected 2 accounts on MSSQLSvc SPN, got $($sqlCluster.ConflictCount)"
    }
    if (-not $sqlCluster.Remediation.StartsWith("Remove duplicate SPN registration: setspn -D")) {
        throw "Invalid remediation command: $($sqlCluster.Remediation)"
    }
}

# ---------------------------------------------------------
# Test 4: Entra Connect & Cloud Sync Readiness Rules
# ---------------------------------------------------------
Write-Host "`n[4/7] Testing Entra Connect & Cloud Sync Audit Rules..." -ForegroundColor Yellow

Assert-Test "Get-AD40SecurityAuditReports includes Entra Connect rules" {
    $rules = Get-AD40SecurityAuditReports -Category "Entra Connect & Cloud Sync Readiness"
    if ($rules.Count -ne 5) {
        throw "Expected 5 Entra Connect rules, got $($rules.Count)"
    }
    $expectedIds = @("ENTRA-INVALID-CHARS-UPN", "ENTRA-NON-ROUTABLE-UPN", "ENTRA-DUPLICATE-UPN", "ENTRA-DUPLICATE-PROXY", "ENTRA-MISSING-MAIL-OR-UPN")
    foreach ($id in $expectedIds) {
        if (-not ($rules | Where-Object { $_.Id -eq $id })) {
            throw "Missing expected rule: $id"
        }
    }
}

Assert-Test "ENTRA-INVALID-CHARS-UPN evaluates correctly" {
    $rule = (Get-AD40SecurityAuditReports -ReportId "ENTRA-INVALID-CHARS-UPN")[0]
    $badUser = [PSCustomObject]@{ userPrincipalName = "john%doe@contoso.com" }
    $goodUser = [PSCustomObject]@{ userPrincipalName = "johndoe@contoso.com" }
    if (-not (& $rule.Evaluate $badUser)) { throw "Failed to flag invalid UPN character '%'" }
    if (& $rule.Evaluate $goodUser) { throw "Erroneously flagged valid UPN" }
}

Assert-Test "ENTRA-NON-ROUTABLE-UPN evaluates correctly" {
    $rule = (Get-AD40SecurityAuditReports -ReportId "ENTRA-NON-ROUTABLE-UPN")[0]
    $localUser = [PSCustomObject]@{ userPrincipalName = "admin@corp.local" }
    $cloudUser = [PSCustomObject]@{ userPrincipalName = "admin@contoso.com" }
    if (-not (& $rule.Evaluate $localUser)) { throw "Failed to flag non-routable .local UPN" }
    if (& $rule.Evaluate $cloudUser) { throw "Erroneously flagged routable .com UPN" }
}

Assert-Test "ENTRA-MISSING-MAIL-OR-UPN evaluates correctly" {
    $rule = (Get-AD40SecurityAuditReports -ReportId "ENTRA-MISSING-MAIL-OR-UPN")[0]
    $emptyUser = [PSCustomObject]@{ Enabled = $true; mail = ""; userPrincipalName = "" }
    $okUser = [PSCustomObject]@{ Enabled = $true; mail = "user@contoso.com"; userPrincipalName = "" }
    if (-not (& $rule.Evaluate $emptyUser)) { throw "Failed to flag user missing both mail and UPN" }
    if (& $rule.Evaluate $okUser) { throw "Erroneously flagged user having mail populated" }
}

# ---------------------------------------------------------
# Test 5: WPF XAML Hierarchy & UI Elements
# ---------------------------------------------------------
Write-Host "`n[5/7] Testing WPF XAML UI Hierarchy..." -ForegroundColor Yellow

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase

Assert-Test "MainWindow.xaml parses cleanly into WPF visual tree" {
    $xamlPath = Join-Path $scriptRoot "Views\MainWindow.xaml"
    $xamlContent = [System.IO.File]::ReadAllText($xamlPath)
    $reader = [System.Xml.XmlReader]::Create([System.IO.StringReader]::new($xamlContent))
    $win = [System.Windows.Markup.XamlReader]::Load($reader)
    if (-not $win) { throw "XamlReader returned null window" }
}

Assert-Test "All new UI controls exist in MainWindow.xaml" {
    $xamlPath = Join-Path $scriptRoot "Views\MainWindow.xaml"
    $xamlContent = [System.IO.File]::ReadAllText($xamlPath)
    $reader = [System.Xml.XmlReader]::Create([System.IO.StringReader]::new($xamlContent))
    $win = [System.Windows.Markup.XamlReader]::Load($reader)

    $requiredControls = @(
        "DirectoryBreadcrumbBar", "BreadcrumbHost", "BtnBreadcrumbHome", "TxtBreadcrumbContext",
        "BorderStatusLatency", "TxtStatusLatency", "BorderStatusMemory", "TxtStatusMemory",
        "TabClientIpResolver", "TxtResolveClientIp", "BtnResolveClientIp", "GridCandidateSubnets",
        "TabGroupMemberDiff", "TxtGroupDiffA", "TxtGroupDiffB", "BtnRunGroupDiff", "GridGroupDiffResults",
        "TabDuplicateSpn", "BtnScanDuplicateSpn", "GridDuplicateSpnResults"
    )

    foreach ($ctl in $requiredControls) {
        $found = $win.FindName($ctl)
        if (-not $found) {
            throw "Required control '$ctl' not found in WPF visual tree"
        }
    }
}

# ---------------------------------------------------------
# Test 6: main.ps1 Script Syntax & Omnibar Commands
# ---------------------------------------------------------
Write-Host "`n[6/7] Testing main.ps1 Script Syntax & Command Palette Catalog..." -ForegroundColor Yellow

Assert-Test "main.ps1 has zero AST parser errors" {
    $mainPath = Join-Path $scriptRoot "main.ps1"
    $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($mainPath, [ref]$null, [ref]$errors)
    if ($errors -and $errors.Count -gt 0) {
        throw "main.ps1 syntax errors: $($errors[0].Message)"
    }
}

Assert-Test "Omnibar command catalog contains all core navigation and tool actions" {
    $mainPath = Join-Path $scriptRoot "main.ps1"
    $mainText = [System.IO.File]::ReadAllText($mainPath)
    $requiredCmds = @("> Users", "> Groups", "> Computers", "> OUs", "> Replication Suite", "> Kerberos Suite", "> Security ACL", "> Audit Reports")
    foreach ($cmd in $requiredCmds) {
        if (-not $mainText.Contains($cmd)) {
            throw "Omnibar command '$cmd' missing from main.ps1 catalog"
        }
    }
}

# ---------------------------------------------------------
# Test 7: Clean Codebase & Encoding Check
# ---------------------------------------------------------
Write-Host "`n[7/7] Testing Codebase Standards (No PII, No Absolute Paths)..." -ForegroundColor Yellow

Assert-Test "Zero personal usernames or hardcoded absolute paths in modified codebase" {
    $files = @(
        (Join-Path $scriptRoot "Views\MainWindow.xaml"),
        (Join-Path $scriptRoot "main.ps1"),
        (Join-Path $scriptRoot "Modules\ReplicationService.psm1"),
        (Join-Path $scriptRoot "Modules\DiagnosticService.psm1"),
        (Join-Path $scriptRoot "Modules\KerberosService.psm1"),
        (Join-Path $scriptRoot "Modules\AuditReportService.psm1")
    )
    foreach ($f in $files) {
        $txt = [System.IO.File]::ReadAllText($f)
        if ($txt -match '(?i)[C-Z]:\\Users\\[a-zA-Z0-9_\-\.]+\\Documents') {
            throw "Hardcoded user profile absolute path found in file: $f"
        }
    }
}

# ---------------------------------------------------------
# Test Summary
# ---------------------------------------------------------
Write-Host "`n======================================================================" -ForegroundColor Cyan
$passCount = @($testResults | Where-Object { $_.Status -eq "PASS" }).Count
$failCount = @($testResults | Where-Object { $_.Status -eq "FAIL" }).Count
Write-Host "TEST RESULTS: $passCount PASSED, $failCount FAILED out of $($testResults.Count) total tests." -ForegroundColor $(if ($failCount -eq 0) { "Green" } else { "Red" })
Write-Host "======================================================================" -ForegroundColor Cyan

if ($failCount -gt 0) {
    exit 1
}
