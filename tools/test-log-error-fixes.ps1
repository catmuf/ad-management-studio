<#
.SYNOPSIS
    Test verification suite for the latest error log fixes:
    1. Show-ObjectHtmlView & Show-ObjectHtmlDossier scope in .GetNewClosure()
    2. Safe DateTime parsing for "Not Set" and "Never" in AuditReportService
    3. Safe LargeInteger COM extraction for maxPwdAge
    4. Clean handling of missing group identities in Get-ADGroupMembersList
#>

$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Running Error Log Fixes Test Suite                       " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $scriptRoot

$adModulePath = Join-Path $projectRoot "Modules\ADService.psm1"
$auditModulePath = Join-Path $projectRoot "Modules\AuditReportService.psm1"

Import-Module $adModulePath -Force -DisableNameChecking
Import-Module $auditModulePath -Force -DisableNameChecking

$totalPassed = 0
$totalFailed = 0

function Assert-Condition {
    param (
        [string]$TestName,
        [bool]$Condition,
        [string]$FailureMessage = ""
    )
    if ($Condition) {
        Write-Host "  [PASS] $TestName" -ForegroundColor Green
        $script:totalPassed++
    } else {
        Write-Host "  [FAIL] $TestName" -ForegroundColor Red
        if ($FailureMessage) { Write-Host "         $FailureMessage" -ForegroundColor Yellow }
        $script:totalFailed++
    }
}

# -------------------------------------------------------------
# Test 1: Closure invocation of Show-ObjectHtmlView
# -------------------------------------------------------------
Write-Host "`n[1/4] Testing global:Show-ObjectHtmlView from closure scope..." -ForegroundColor White

# Prepare and execute main.ps1 offscreen
$mainScript = Get-Content (Join-Path $projectRoot "main.ps1") -Raw -Encoding utf8
$mainScriptOffscreen = $mainScript -replace '\[void\]\$window\.ShowDialog\(\)', '$window.WindowStartupLocation = [System.Windows.WindowStartupLocation]::Manual; $window.Left = -32000; $window.Top = -32000; $window.Show()'
. ([scriptblock]::Create($mainScriptOffscreen))
[System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::ApplicationIdle)

$testClosure = {
    $cmd = Get-Command -Name "Show-ObjectHtmlView" -ErrorAction SilentlyContinue
    return ($null -ne $cmd)
}.GetNewClosure()

$closureInvoked = & $testClosure
Assert-Condition "Show-ObjectHtmlView resolves within dynamic .GetNewClosure() closure" ($closureInvoked -eq $true)

$dossierCmd = Get-Command -Name "Show-ObjectHtmlDossier" -ErrorAction SilentlyContinue
Assert-Condition "Show-ObjectHtmlDossier resolves within dynamic scope" ($null -ne $dossierCmd)

# -------------------------------------------------------------
# Test 2: Safe DateTime parsing for "Not Set" in Inactive Accounts
# -------------------------------------------------------------
Write-Host "`n[2/4] Testing Safe DateTime parsing for 'Not Set' & 'Never' in AuditReportService..." -ForegroundColor White

$noExceptionThrown = $true
try {
    $reportResult = Get-ADSecurityAuditReport -Category "InactiveAccounts" -Days 90
    Assert-Condition "InactiveAccounts audit runs cleanly without System.FormatException" ($true)
}
catch {
    $noExceptionThrown = $false
    Assert-Condition "InactiveAccounts audit runs cleanly without System.FormatException" ($false) "$_"
}

# -------------------------------------------------------------
# Test 3: Safe maxPwdAge COM handling
# -------------------------------------------------------------
Write-Host "`n[3/4] Testing Safe maxPwdAge COM handling..." -ForegroundColor White

$noCastException = $true
try {
    $pwdReport = Get-ADSecurityAuditReport -Category "PasswordExpiringSoon" -Days 14
    Assert-Condition "PasswordExpiringSoon audit executes without PSInvalidCastException" ($true)
}
catch {
    $noCastException = $false
    Assert-Condition "PasswordExpiringSoon audit executes without PSInvalidCastException" ($false) "$_"
}

# -------------------------------------------------------------
# Test 4: Missing Group identities in Get-ADGroupMembersList
# -------------------------------------------------------------
Write-Host "`n[4/4] Testing missing group identities in Get-ADGroupMembersList..." -ForegroundColor White

$missingGroupRes = Get-ADGroupMembersList -GroupName "NonExistentGroup_123456789" -ErrorAction SilentlyContinue
Assert-Condition "Get-ADGroupMembersList returns empty array for non-existent group" ($missingGroupRes.Count -eq 0)

$privReport = Get-ADSecurityAuditReport -Category "PrivilegedAccounts"
Assert-Condition "PrivilegedAccounts audit executes cleanly across missing or localized groups" ($null -ne $privReport)

if ($window) { $window.Close() }

Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host " Test Execution Completed" -ForegroundColor Cyan
Write-Host " Passed: $totalPassed" -ForegroundColor Green
Write-Host " Failed: $totalFailed" -ForegroundColor $(if ($totalFailed -gt 0) { "Red" } else { "Green" })
Write-Host "==========================================================" -ForegroundColor Cyan

if ($totalFailed -gt 0) { exit 1 } else { exit 0 }
