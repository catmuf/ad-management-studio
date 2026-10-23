<#
.SYNOPSIS
    Unit test suite for Active Directory MaxPageSize (RFC 2696), Range Retrieval (RFC 3268),
    and streaming data export capabilities.
#>

$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Running AD MaxPageSize & Range Retrieval Test Suite      " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $scriptRoot

$adModulePath = Join-Path $projectRoot "Modules\ADService.psm1"
$exportModulePath = Join-Path $projectRoot "Modules\ExportService.psm1"

Import-Module $adModulePath -Force -DisableNameChecking
Import-Module $exportModulePath -Force -DisableNameChecking

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
# Test 1: Get-ADObjectRangedAttribute RFC 3268
# -------------------------------------------------------------
Write-Host "`n[1/4] Testing Get-ADObjectRangedAttribute (RFC 3268 Range Retrieval)..." -ForegroundColor White

$smallMock = 1..100 | ForEach-Object { "CN=User$_,OU=Users,DC=corp,DC=local" }
$smallResult = Get-ADObjectRangedAttribute -DistinguishedName "CN=SmallGroup,OU=Groups,DC=corp,DC=local" -AttributeName "member" -Step 1500 -MockData $smallMock

Assert-Condition "Non-ranged attribute (<= 1500) returns direct values" ($smallResult.Success -and $smallResult.Count -eq 100 -and -not $smallResult.IsRanged)
Assert-Condition "Non-ranged attribute completes in 1 step" ($smallResult.RangeSteps -eq 1)

$largeMock = 1..3500 | ForEach-Object { "CN=EnterpriseUser$_,OU=Users,DC=corp,DC=local" }
$largeResult = Get-ADObjectRangedAttribute -DistinguishedName "CN=LargeGroup,OU=Groups,DC=corp,DC=local" -AttributeName "member" -Step 1500 -MockData $largeMock

Assert-Condition "Large multi-valued attribute (> 1500) successfully stitches all 3500 values" ($largeResult.Success -and $largeResult.Count -eq 3500)
Assert-Condition "Large multi-valued attribute marks IsRanged as true" ($largeResult.IsRanged -eq $true)
Assert-Condition "3500 values in steps of 1500 takes 3 range chunks (0-1499, 1500-2999, 3000-3499)" ($largeResult.RangeSteps -eq 3)
Assert-Condition "First and last items preserve exact values" ($largeResult.Values[0] -eq "CN=EnterpriseUser1,OU=Users,DC=corp,DC=local" -and $largeResult.Values[3499] -eq "CN=EnterpriseUser3500,OU=Users,DC=corp,DC=local")

# -------------------------------------------------------------
# Test 2: Invoke-LdapQuery Streaming & Cancellation
# -------------------------------------------------------------
Write-Host "`n[2/4] Testing Invoke-LdapQuery Streaming & Cancellation..." -ForegroundColor White

$mockQueryItems = 1..750 | ForEach-Object {
    [PSCustomObject]@{
        DistinguishedName = "CN=User$_,OU=Staff,DC=domain,DC=com"
        sAMAccountName    = "user$_"
        displayName       = "User $_"
        objectClass       = "user"
    }
}

$receivedBatches = [System.Collections.Generic.List[int]]::new()
$batchCallback = {
    param($batch, $countSoFar)
    $script:receivedBatches.Add($batch.Count)
}

$streamRes = Invoke-LdapQuery -Filter "(objectClass=user)" -MockData $mockQueryItems -BatchSize 200 -OnBatchReceived $batchCallback

Assert-Condition "Invoke-LdapQuery completes successfully with mock stream" ($streamRes.Success -and $streamRes.Count -eq 750)
Assert-Condition "Batches invoked with 200, 200, 200, 150 distribution" ($receivedBatches.Count -eq 4 -and $receivedBatches[0] -eq 200 -and $receivedBatches[3] -eq 150)

# Cancellation test
$cts = New-Object System.Threading.CancellationTokenSource
$cancelBatch = {
    param($batch, $countSoFar)
    if ($countSoFar -ge 300) {
        $cts.Cancel()
    }
}

$cancelRes = Invoke-LdapQuery -Filter "(objectClass=user)" -MockData $mockQueryItems -BatchSize 100 -OnBatchReceived $cancelBatch -CancellationToken $cts.Token
Assert-Condition "Invoke-LdapQuery honors cancellation token and reports WasCancelled" ($cancelRes.WasCancelled -eq $true -and $cancelRes.Count -lt 750)

# -------------------------------------------------------------
# Test 3: Export-LdapQueryToCsvStream Direct-to-Disk Streaming
# -------------------------------------------------------------
Write-Host "`n[3/4] Testing Export-LdapQueryToCsvStream..." -ForegroundColor White

$tempCsv = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "test_ldap_stream_$([System.Guid]::NewGuid().ToString('N')).csv")

try {
    $exportMockData = 1..250 | ForEach-Object {
        [PSCustomObject]@{
            distinguishedName = "CN=ExportUser$_,DC=corp,DC=com"
            sAMAccountName    = "expuser$_"
            displayName       = "Export User $_"
            mail              = "exp$_@corp.com"
            objectClass       = "user"
        }
    }

    $exportRes = Export-LdapQueryToCsvStream -Filter "(objectClass=user)" -FilePath $tempCsv -MockData $exportMockData -Delimiter ";" -PropertiesToExport @('distinguishedName', 'sAMAccountName', 'displayName', 'mail')

    Assert-Condition "Export-LdapQueryToCsvStream succeeds" ($exportRes.Success -and $exportRes.Count -eq 250)
    Assert-Condition "CSV file exists on disk" (Test-Path $tempCsv)

    $csvLines = Get-Content -Path $tempCsv -Encoding UTF8
    Assert-Condition "CSV has 251 lines (header + 250 rows)" ($csvLines.Count -eq 251)
    Assert-Condition "CSV header matches requested properties" ($csvLines[0] -eq '"distinguishedName";"sAMAccountName";"displayName";"mail"')
    Assert-Condition "First record formatted with escaped quotes and delimiter" ($csvLines[1] -eq '"CN=ExportUser1,DC=corp,DC=com";"expuser1";"Export User 1";"exp1@corp.com"')

    # Verify UTF-8 with BOM
    $bytes = [System.IO.File]::ReadAllBytes($tempCsv)
    $hasBom = ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)
    Assert-Condition "Exported CSV contains UTF-8 BOM" ($hasBom -eq $true)
}
finally {
    if (Test-Path $tempCsv) { Remove-Item $tempCsv -Force -ErrorAction SilentlyContinue }
}

# -------------------------------------------------------------
# Test 4: Dashboard Stats Unbounded PageSize Validation
# -------------------------------------------------------------
Write-Host "`n[4/4] Verifying Dashboard Stats PageSize Configuration..." -ForegroundColor White

$adServiceCode = Get-Content -Path $adModulePath -Raw
$hasResultSetSize5000 = ($adServiceCode -match "Get-ADUser[^\r\n]*-ResultSetSize 5000" -or $adServiceCode -match "Get-ADGroup[^\r\n]*-ResultSetSize 5000")
$hasResultPageSize1000 = ($adServiceCode -match "Get-ADUser[^\r\n]*-ResultPageSize 1000" -and $adServiceCode -match "Get-ADGroup[^\r\n]*-ResultPageSize 1000")

Assert-Condition "Artificial 5,000 ResultSetSize cap eliminated from Get-ADDashboardStats" (-not $hasResultSetSize5000)
Assert-Condition "ResultPageSize 1000 configured for unbounded Active Directory paging" ($hasResultPageSize1000)

Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host " Test Execution Completed" -ForegroundColor Cyan
Write-Host " Passed: $totalPassed" -ForegroundColor Green
Write-Host " Failed: $totalFailed" -ForegroundColor $(if ($totalFailed -gt 0) { "Red" } else { "Green" })
Write-Host "==========================================================" -ForegroundColor Cyan

if ($totalFailed -gt 0) { exit 1 } else { exit 0 }
