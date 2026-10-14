# Automated Test Suite for Advanced AD Diagnostics & NetTools Suite Features
# Validates 100% compliance across all 4 enhanced modules:
# 1. AclService (Get-ADEffectivePermissions6Way, Repair-AdminSDHolderOrphan)
# 2. KerberosService (Measure-ADUserTokenSizeWithThresholds, Get-ADRidPoolExhaustionStatus)
# 3. DiagnosticService (Find-CircularGroupReferencesWithChain, Break-CircularGroupReference, Compare-ADObjectsSideBySide)
# 4. NetworkService (Test-ADUncPath7Tier, Test-ADDomainControllerPorts)

$ErrorActionPreference = "Stop"

# Test Counters
$script:PassedCount = 0
$script:FailedCount = 0
$script:TestResults = [System.Collections.Generic.List[PSCustomObject]]::new()

function Assert-Condition {
    param (
        [string]$TestName,
        [bool]$Condition,
        [string]$FailureMessage = ""
    )

    if ($Condition) {
        $script:PassedCount++
        Write-Host "  [PASS] $TestName" -ForegroundColor Green
        $script:TestResults.Add([PSCustomObject]@{
            TestName = $TestName
            Status   = "Passed"
            Message  = "OK"
        })
    } else {
        $script:FailedCount++
        Write-Host "  [FAIL] $TestName - $FailureMessage" -ForegroundColor Red
        $script:TestResults.Add([PSCustomObject]@{
            TestName = $TestName
            Status   = "Failed"
            Message  = $FailureMessage
        })
    }
}

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "Starting Advanced AD Diagnostics & NetTools Test Suite" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

# -------------------------------------------------------------------
# Module Imports
# -------------------------------------------------------------------
$moduleBase = Join-Path (Split-Path $PSScriptRoot -Parent) "Modules"

$aclModulePath = Join-Path $moduleBase "AclService.psm1"
$kerbModulePath = Join-Path $moduleBase "KerberosService.psm1"
$diagModulePath = Join-Path $moduleBase "DiagnosticService.psm1"
$netModulePath = Join-Path $moduleBase "NetworkService.psm1"

Import-Module $aclModulePath -Force
Import-Module $kerbModulePath -Force
Import-Module $diagModulePath -Force
Import-Module $netModulePath -Force

Write-Host "`n--- 1. Testing AclService: Get-ADEffectivePermissions6Way ---" -ForegroundColor Yellow

# Test 1.1: 6-Way Breakdown Categories Structure
$effAdmin = Get-ADEffectivePermissions6Way -TargetObject "OU=Domain Controllers,DC=corp,DC=local" -Trustee "Domain Admins"
Assert-Condition "6Way: Returns valid result object" ($null -ne $effAdmin) "Result is null"
Assert-Condition "6Way: TargetObject and Trustee are set" ($effAdmin.TargetObject -match "Domain Controllers" -and $effAdmin.Trustee -eq "Domain Admins") "Target/Trustee mismatch"
Assert-Condition "6Way: Categories hashtable contains 6 keys" ($effAdmin.Categories.Keys.Count -eq 6) "Expected 6 categories, found $($effAdmin.Categories.Keys.Count)"

$expectedCategories = @(
    "Basic Permissions",
    "Extended Rights",
    "Validated Rights",
    "Child Objects",
    "Property Sets",
    "Attributes"
)
foreach ($cat in $expectedCategories) {
    Assert-Condition "6Way: Category '$cat' exists and is non-empty" ($effAdmin.Categories.Contains($cat) -and $effAdmin.Categories[$cat].Count -gt 0) "Category missing or empty"
}

# Test 1.2: Flags (Explicit vs Inherited vs Denied)
Assert-Condition "6Way: Admin grants explicit permissions" ($effAdmin.ExplicitCount -gt 0 -and $effAdmin.GrantedCount -gt 0) "Admin has no explicit or granted rights"
$fullCtrl = $effAdmin.Permissions | Where-Object { $_.RightName -eq "Full Control" }
Assert-Condition "6Way: Full Control right found with valid structure" ($null -ne $fullCtrl) "Full Control right missing"
Assert-Condition "6Way: Full Control has Category 'Basic Permissions'" ($fullCtrl.Category -eq "Basic Permissions") "Category mismatch"
Assert-Condition "6Way: Full Control has IsGranted = true" ($fullCtrl.IsGranted -eq $true) "IsGranted is not true"

# Test 1.3: Inherited Permissions check
$effStandard = Get-ADEffectivePermissions6Way -TargetObject "CN=TestGroup,OU=Groups,DC=corp,DC=local" -Trustee "StandardInheritedUser"
Assert-Condition "6Way: Inherited flags populated for standard user" ($effStandard.InheritedCount -gt 0) "Inherited rights count is 0"
$genericRead = $effStandard.Permissions | Where-Object { $_.RightName -eq "Generic Read" }
Assert-Condition "6Way: Generic Read has IsInherited = true" ($genericRead.IsInherited -eq $true) "IsInherited is false"

# Test 1.4: Denied Permissions check
$effDenied = Get-ADEffectivePermissions6Way -TargetObject "CN=RestrictedData,DC=corp,DC=local" -Trustee "DeniedUserAccount"
Assert-Condition "6Way: Denied flags populated for denied user" ($effDenied.DeniedCount -gt 0) "Denied count is 0"
$deniedItem = $effDenied.Permissions | Where-Object { $_.IsDenied -eq $true }
Assert-Condition "6Way: At least one permission has IsDenied = true and StatusBadge contains Deny" ($null -ne $deniedItem -and $deniedItem[0].StatusBadge -match "Deny") "Denied flags missing"

Write-Host "`n--- 2. Testing AclService: Repair-AdminSDHolderOrphan ---" -ForegroundColor Yellow

# Test 2.1: 1-Click Remediation resets adminCount = 0 and clears SE_DACL_PROTECTED
$repairResult = Repair-AdminSDHolderOrphan -Identity "CN=svc-orphan-backup,OU=Service Accounts,DC=corp,DC=local"
Assert-Condition "Repair-AdminSDHolder: Success = true" ($repairResult.Success -eq $true) "Success is false"
Assert-Condition "Repair-AdminSDHolder: adminCount reset to 0" ($repairResult.AdminCount -eq 0 -and $repairResult.AdminCountCleared -eq $true) "AdminCount not reset"
Assert-Condition "Repair-AdminSDHolder: SE_DACL_PROTECTED flag cleared" ($repairResult.SeDaclProtectedCleared -eq $true) "SE_DACL_PROTECTED not cleared"
Assert-Condition "Repair-AdminSDHolder: Inheritance successfully enabled" ($repairResult.InheritanceEnabled -eq $true) "Inheritance not enabled"
Assert-Condition "Repair-AdminSDHolder: StatusBadge = 'Remediated'" ($repairResult.StatusBadge -eq "Remediated") "StatusBadge is not Remediated"

# Test 2.2: Remediation with -ClearAdminCount switch
$repairClear = Repair-AdminSDHolderOrphan -Identity "CN=svc-legacy-admin,OU=Legacy,DC=corp,DC=local" -ClearAdminCount
Assert-Condition "Repair-AdminSDHolder (Clear): Success = true" ($repairClear.Success -eq $true) "Success is false"
Assert-Condition "Repair-AdminSDHolder (Clear): AdminCountCleared = true" ($repairClear.AdminCountCleared -eq $true) "AdminCountCleared is false"
Assert-Condition "Repair-AdminSDHolder (Clear): SeDaclProtectedCleared = true" ($repairClear.SeDaclProtectedCleared -eq $true) "SeDaclProtectedCleared is false"

Write-Host "`n--- 3. Testing KerberosService: Measure-ADUserTokenSizeWithThresholds ---" -ForegroundColor Yellow

# Test 3.1: Microsoft Formula Accuracy: Token Size = 1200 + 40d + 8s
# Test calculation: d = 10, s = 20 -> 1200 + (40 * 10) + (8 * 20) = 1200 + 400 + 160 = 1760 bytes
$tokenCalc = Measure-ADUserTokenSizeWithThresholds -Identity "TestFormulaUser" -DomainLocalGroupCount 10 -UniversalGroupCount 0 -GlobalGroupCount 20 -SidHistoryCount 0
Assert-Condition "TokenSize Formula: Exact calculation matches 1760 bytes" ($tokenCalc.ExactBytes -eq 1760 -and $tokenCalc.EstimatedTokenSizeBytes -eq 1760) "Expected 1760, got $($tokenCalc.ExactBytes)"
Assert-Condition "TokenSize Formula: Base overhead is 1200 bytes" ($tokenCalc.BaseOverheadBytes -eq 1200) "Base overhead is not 1200"
Assert-Condition "TokenSize Formula: Inherited size is 560 bytes" ($tokenCalc.InheritedTokenSizeBytes -eq 560) "Inherited size is not 560"
Assert-Condition "TokenSize Formula: d parameter is 10" ($tokenCalc.DCount -eq 10) "dCount is not 10"
Assert-Condition "TokenSize Formula: s parameter is 20" ($tokenCalc.SCount -eq 20) "sCount is not 20"
Assert-Condition "TokenSize Formula: Healthy status when below thresholds" ($tokenCalc.ThresholdStatus -match "Healthy" -and -not $tokenCalc.IISWarning -and -not $tokenCalc.SharePointWarning -and -not $tokenCalc.HardLogonFailure) "Unexpected warning"

# Test 3.2: IIS Warning Threshold (>= 12,000 bytes / 12KB)
# d = 270, s = 10 -> 1200 + (40 * 270) + (8 * 10) = 1200 + 10800 + 80 = 12080 bytes (groups = 280 < 300)
$tokenIis = Measure-ADUserTokenSizeWithThresholds -Identity "TestIisUser" -DomainLocalGroupCount 270 -UniversalGroupCount 0 -GlobalGroupCount 10 -SidHistoryCount 0
Assert-Condition "TokenSize IIS: 12KB threshold reached (12,000 bytes)" ($tokenIis.ExactBytes -ge 12000) "Bytes < 12000"
Assert-Condition "TokenSize IIS: IISWarning flag is true" ($tokenIis.IISWarning -eq $true) "IISWarning is false"
Assert-Condition "TokenSize IIS: ThresholdStatus reflects IIS warning" ($tokenIis.ThresholdStatus -match "IIS HTTP 400") "ThresholdStatus mismatch: $($tokenIis.ThresholdStatus)"
Assert-Condition "TokenSize IIS: Warnings list contains HTTP 400 warning" (($tokenIis.Warnings | Where-Object { $_ -match "HTTP 400" }).Count -gt 0) "Warning message missing"

# Test 3.3: SharePoint Warning Threshold (>= 24,000 bytes / 24KB or >= 300 groups)
# d = 550, s = 100 -> 1200 + (40 * 550) + (8 * 100) = 1200 + 22000 + 800 = 24000 bytes
$tokenSp = Measure-ADUserTokenSizeWithThresholds -Identity "TestSharePointUser" -DomainLocalGroupCount 550 -UniversalGroupCount 0 -GlobalGroupCount 100 -SidHistoryCount 0
Assert-Condition "TokenSize SharePoint: 24KB threshold reached (24,000 bytes)" ($tokenSp.ExactBytes -ge 24000) "Bytes < 24000"
Assert-Condition "TokenSize SharePoint: SharePointWarning flag is true" ($tokenSp.SharePointWarning -eq $true) "SharePointWarning is false"
Assert-Condition "TokenSize SharePoint: ThresholdStatus reflects SharePoint warning" ($tokenSp.ThresholdStatus -match "SharePoint Bloat") "ThresholdStatus mismatch: $($tokenSp.ThresholdStatus)"

# Test 3.4: Hard Logon Failure Threshold (> 1015 groups or >= 48,000 bytes)
# totalGroups = 1020 (> 1015)
$tokenHard = Measure-ADUserTokenSizeWithThresholds -Identity "TestHardFailureUser" -DomainLocalGroupCount 200 -UniversalGroupCount 0 -GlobalGroupCount 820 -SidHistoryCount 0
Assert-Condition "TokenSize Hard Failure: Group count > 1015" ($tokenHard.GroupCount -gt 1015) "GroupCount is not > 1015"
Assert-Condition "TokenSize Hard Failure: HardLogonFailure flag is true" ($tokenHard.HardLogonFailure -eq $true) "HardLogonFailure is false"
Assert-Condition "TokenSize Hard Failure: StatusBadge = 'Critical'" ($tokenHard.StatusBadge -eq "Critical") "StatusBadge is not Critical"
Assert-Condition "TokenSize Hard Failure: Warnings contains 1015 groups / STATUS_TOO_MANY_CONTEXT_IDS" (($tokenHard.Warnings | Where-Object { $_ -match "1015|STATUS_TOO_MANY_CONTEXT_IDS" }).Count -gt 0) "Critical warning missing"

Write-Host "`n--- 4. Testing KerberosService: Get-ADRidPoolExhaustionStatus ---" -ForegroundColor Yellow

# Test 4.1: Forest RID Space Telemetry
$ridStatus = Get-ADRidPoolExhaustionStatus
Assert-Condition "RID Status: Returns valid object" ($null -ne $ridStatus) "Result is null"
Assert-Condition "RID Status: ForestCapacity is 1,073,741,823 (~1 Billion)" ($ridStatus.ForestCapacity -eq 1073741823) "Forest capacity is $($ridStatus.ForestCapacity)"
Assert-Condition "RID Status: ForestHeadroom is positive" ($ridStatus.ForestHeadroom -gt 0) "Headroom is not positive"
Assert-Condition "RID Status: ForestAllocationPercentage is calculated" ($ridStatus.ForestAllocationPercentage -ge 0.0) "Allocation percent missing"
Assert-Condition "RID Status: TotalDCsScanned > 0" ($ridStatus.TotalDCsScanned -gt 0) "No DCs scanned"

# Test 4.2: Per-DC RID Sets, Headroom, Allocation Percentages, and Warning Flags (<20% remaining)
$lowHeadroomDcs = @($ridStatus.PerDcPools | Where-Object { $_.WarningFlag -eq $true })
Assert-Condition "RID Status: Per-DC pool telemetry exists" ($ridStatus.PerDcPools.Count -gt 0) "PerDcPools is empty"
Assert-Condition "RID Status: DC with <20% headroom detected and flagged" ($lowHeadroomDcs.Count -gt 0) "No DC flagged with low headroom"

$firstLowDc = $lowHeadroomDcs[0]
Assert-Condition "RID Status: Flagged DC has RemainingPercentage < 20%" ($firstLowDc.RemainingPercentage -lt 20.0) "Remaining percentage >= 20"
Assert-Condition "RID Status: Flagged DC has StatusBadge matching Warning" ($firstLowDc.StatusBadge -match "Warning") "StatusBadge is not Warning"
Assert-Condition "RID Status: Flagged DC reports Headroom and AllocationPercentage" ($firstLowDc.Headroom -gt 0 -and $firstLowDc.AllocationPercentage -gt 0) "Headroom or allocation invalid"

$healthyDcs = @($ridStatus.PerDcPools | Where-Object { $_.WarningFlag -eq $false })
Assert-Condition "RID Status: Healthy DC has WarningFlag = false" ($healthyDcs.Count -gt 0 -and $healthyDcs[0].RemainingPercentage -ge 20.0) "Healthy DC validation failed"

Write-Host "`n--- 5. Testing DiagnosticService: Find-CircularGroupReferencesWithChain ---" -ForegroundColor Yellow

# Test 5.1: Custom 3-Group Circular Loop Detection with exact chain
$mockGraph = @{
    "Group-Alpha" = @("Group-Beta")
    "Group-Beta"  = @("Group-Gamma")
    "Group-Gamma" = @("Group-Alpha")
}
$circularResult = Find-CircularGroupReferencesWithChain -MockGraph $mockGraph
Assert-Condition "Circular Loop: Detected at least 1 cycle" ($circularResult.Count -ge 1) "No cycle detected"

$cycle1 = $circularResult[0]
Assert-Condition "Circular Loop: Exact nesting chain contains '[LOOP]'" ($cycle1.NestingChain -match '\[LOOP\]') "Chain missing [LOOP] indicator: $($cycle1.NestingChain)"
Assert-Condition "Circular Loop: Chain includes Group-Alpha, Group-Beta, Group-Gamma" ($cycle1.NestingChain -match "Group-Alpha" -and $cycle1.NestingChain -match "Group-Beta" -and $cycle1.NestingChain -match "Group-Gamma") "Chain members missing"
Assert-Condition "Circular Loop: LoopLength = 3" ($cycle1.LoopLength -eq 3) "LoopLength is $($cycle1.LoopLength)"
Assert-Condition "Circular Loop: RootCauseIsolation isolates culprit and parent" (-not [string]::IsNullOrEmpty($cycle1.RootCauseIsolation) -and -not [string]::IsNullOrEmpty($cycle1.ParentGroup)) "Root cause isolation empty"
Assert-Condition "Circular Loop: RemediationCommand includes Break-CircularGroupReference" ($cycle1.RemediationCommand -match "Break-CircularGroupReference") "Remediation command missing"
Assert-Condition "Circular Loop: StatusBadge = 'Circular Loop Detected'" ($cycle1.StatusBadge -eq "Circular Loop Detected") "StatusBadge mismatch"

# Test 5.2: 2-Group Direct Mutual Circular Loop Detection
$mock2Group = @{
    "Group-DirectA" = @("Group-DirectB")
    "Group-DirectB" = @("Group-DirectA")
}
$circular2Group = Find-CircularGroupReferencesWithChain -MockGraph $mock2Group
Assert-Condition "Circular Loop: 2-Group direct loop detected" ($circular2Group.Count -ge 1 -and $circular2Group[0].LoopLength -eq 2) "2-group loop not detected"

# Test 5.3: Scan execution without parameters returns collection
$defaultCircular = @(Find-CircularGroupReferencesWithChain)
Assert-Condition "Circular Loop: Execution without parameters returns valid collection" ($defaultCircular -is [array]) "Default scan failed"

Write-Host "`n--- 6. Testing DiagnosticService: Break-CircularGroupReference ---" -ForegroundColor Yellow

# Test 6.1: Safely breaks circular link
$breakResult = Break-CircularGroupReference -ParentGroup "Group-Gamma" -MemberToRemove "Group-Alpha"
Assert-Condition "Break Loop: Success = true" ($breakResult.Success -eq $true) "Success is false"
Assert-Condition "Break Loop: ParentGroup = 'Group-Gamma'" ($breakResult.ParentGroup -eq "Group-Gamma") "ParentGroup mismatch"
Assert-Condition "Break Loop: RemovedMember = 'Group-Alpha'" ($breakResult.RemovedMember -eq "Group-Alpha") "RemovedMember mismatch"
Assert-Condition "Break Loop: StatusBadge = 'Remediated'" ($breakResult.StatusBadge -eq "Remediated") "StatusBadge is not Remediated"
Assert-Condition "Break Loop: HierarchyStatus = 'Valid Group Hierarchy Restored'" ($breakResult.HierarchyStatus -match "Valid Group Hierarchy Restored") "HierarchyStatus mismatch"

Write-Host "`n--- 7. Testing DiagnosticService: Compare-ADObjectsSideBySide ---" -ForegroundColor Yellow

# Test 7.1: Compare Memberships with Color-Coded Diff
$mockA = @{
    "memberOf" = @("Domain Users", "Remote-VPN-Users", "Tier1-Helpdesk")
}
$mockB = @{
    "memberOf" = @("Domain Users", "Remote-VPN-Users", "Server-Operators")
}
$cmpMembers = Compare-ADObjectsSideBySide -IdentityA "UserAlpha" -IdentityB "UserBeta" -CompareMode "Memberships" -MockDataA $mockA -MockDataB $mockB

Assert-Condition "Compare Members: CommonCount = 2 (Domain Users, Remote-VPN-Users)" ($cmpMembers.CommonCount -eq 2) "CommonCount is $($cmpMembers.CommonCount)"
Assert-Condition "Compare Members: OnlyInACount = 1 (Tier1-Helpdesk)" ($cmpMembers.OnlyInACount -eq 1) "OnlyInACount is $($cmpMembers.OnlyInACount)"
Assert-Condition "Compare Members: OnlyInBCount = 1 (Server-Operators)" ($cmpMembers.OnlyInBCount -eq 1) "OnlyInBCount is $($cmpMembers.OnlyInBCount)"

$commonRow = $cmpMembers.DiffRows | Where-Object { $_.ItemName -eq "Domain Users" }
Assert-Condition "Compare Members: Common item has DiffStatus = 'Common' and Color #107C41 (Green)" ($commonRow.DiffStatus -eq "Common" -and $commonRow.StatusColor -eq "#107C41") "Common color mismatch"

$onlyARow = $cmpMembers.DiffRows | Where-Object { $_.ItemName -eq "Tier1-Helpdesk" }
Assert-Condition "Compare Members: Only in A item has DiffStatus = 'Only in A' and Color #0078D4 (Blue)" ($onlyARow.DiffStatus -eq "Only in A" -and $onlyARow.StatusColor -eq "#0078D4") "Only in A color mismatch"

$onlyBRow = $cmpMembers.DiffRows | Where-Object { $_.ItemName -eq "Server-Operators" }
Assert-Condition "Compare Members: Only in B item has DiffStatus = 'Only in B' and Color #D13438 (Red)" ($onlyBRow.DiffStatus -eq "Only in B" -and $onlyBRow.StatusColor -eq "#D13438") "Only in B color mismatch"

# Test 7.2: Compare Attributes with Value Mismatches (Orange #D83B01)
$mockAttrA = @{
    "department" = "Engineering"
    "title"      = "Senior Systems Architect"
    "employeeID" = "E1001"
}
$mockAttrB = @{
    "department" = "Engineering"
    "title"      = "DevOps Engineer"
    "office"     = "Building 4"
}
$cmpAttrs = Compare-ADObjectsSideBySide -IdentityA "UserAlpha" -IdentityB "UserBeta" -CompareMode "Attributes" -MockDataA $mockAttrA -MockDataB $mockAttrB

Assert-Condition "Compare Attributes: CommonCount = 1 (department=Engineering)" ($cmpAttrs.CommonCount -eq 1) "CommonCount is $($cmpAttrs.CommonCount)"
Assert-Condition "Compare Attributes: MismatchCount = 1 (title)" ($cmpAttrs.MismatchCount -eq 1) "MismatchCount is $($cmpAttrs.MismatchCount)"
Assert-Condition "Compare Attributes: OnlyInACount = 1 (employeeID)" ($cmpAttrs.OnlyInACount -eq 1) "OnlyInACount is $($cmpAttrs.OnlyInACount)"
Assert-Condition "Compare Attributes: OnlyInBCount = 1 (office)" ($cmpAttrs.OnlyInBCount -eq 1) "OnlyInBCount is $($cmpAttrs.OnlyInBCount)"

$mismatchRow = $cmpAttrs.DiffRows | Where-Object { $_.ItemName -eq "title" }
Assert-Condition "Compare Attributes: Mismatch item has Color #D83B01 (Orange)" ($mismatchRow.DiffStatus -eq "Value Mismatch" -and $mismatchRow.StatusColor -eq "#D83B01") "Mismatch color mismatch"

Write-Host "`n--- 8. Testing NetworkService: Test-ADUncPath7Tier ---" -ForegroundColor Yellow

# Test 8.1: Automated 7-Tier Verification
$uncResult = Test-ADUncPath7Tier -UncPath "\\dc01.corp.local\SYSVOL\corp.local"
Assert-Condition "UNC 7-Tier: Returns result object" ($null -ne $uncResult) "Result is null"
Assert-Condition "UNC 7-Tier: Exactly 7 tiers evaluated" ($uncResult.Tiers.Count -eq 7) "Expected 7 tiers, got $($uncResult.Tiers.Count)"
Assert-Condition "UNC 7-Tier: OverallVerdict is 'Passed'" ($uncResult.OverallVerdict -eq "Passed") "OverallVerdict is $($uncResult.OverallVerdict)"
Assert-Condition "UNC 7-Tier: TiersPassed = 7" ($uncResult.TiersPassed -eq 7) "TiersPassed is $($uncResult.TiersPassed)"

$tierNames = @(
    "DNS Resolution",
    "NetBIOS Resolution",
    "TCP Port 445",
    "SMB Negotiate",
    "Kerberos/NTLM Auth",
    "Share Tree Connect",
    "File Read/Write"
)
for ($i = 0; $i -lt 7; $i++) {
    $t = $uncResult.Tiers[$i]
    $expectedName = $tierNames[$i]
    Assert-Condition "UNC 7-Tier: Tier $($i+1) is '$expectedName' with Status 'Passed'" ($t.TierName -eq $expectedName -and $t.StatusBadge -eq "Passed") "Tier $($i+1) mismatch"
}

# Test 8.2: Syntax validation failure on invalid UNC
$invalidUnc = Test-ADUncPath7Tier -UncPath "invalid-unc-path-format"
Assert-Condition "UNC 7-Tier: Invalid UNC returns OverallVerdict = 'Failed'" ($invalidUnc.OverallVerdict -eq "Failed") "Did not fail on invalid path"

Write-Host "`n--- 9. Testing NetworkService: Test-ADDomainControllerPorts ---" -ForegroundColor Yellow

# Test 9.1: Scans 8 Critical AD Ports on all DCs
$dcPortScan = Test-ADDomainControllerPorts -DomainControllers @("DC01.corp.local", "DC02.corp.local")
Assert-Condition "DC Ports: TargetDomainControllers count = 2" ($dcPortScan.TargetDomainControllers.Count -eq 2) "DC count mismatch"
Assert-Condition "DC Ports: TotalDCsScanned = 2" ($dcPortScan.TotalDCsScanned -eq 2) "Scanned count mismatch"
Assert-Condition "DC Ports: Exactly 16 ports scanned (8 ports x 2 DCs)" ($dcPortScan.TotalPortsScanned -eq 16) "Expected 16, got $($dcPortScan.TotalPortsScanned)"
Assert-Condition "DC Ports: AllPortsOperational is true" ($dcPortScan.AllPortsOperational -eq $true) "AllPortsOperational is false"
Assert-Condition "DC Ports: StatusBadge = 'All 8 Ports Operational'" ($dcPortScan.StatusBadge -eq "All 8 Ports Operational") "StatusBadge is not All 8 Ports Operational"

$requiredPorts = @(53, 88, 135, 389, 445, 636, 3268, 3269)
foreach ($pNum in $requiredPorts) {
    $scannedPort = $dcPortScan.PortResults | Where-Object { $_.DomainController -eq "DC01.corp.local" -and $_.Port -eq $pNum }
    Assert-Condition "DC Ports: DC01 port $pNum ($($scannedPort.ServiceName)) scanned and open" ($null -ne $scannedPort -and $scannedPort.IsOpen -eq $true) "Port $pNum failed"
}

Assert-Condition "DC Ports: PerDcSummary contains 2 DCs with 8 open ports each" ($dcPortScan.PerDcSummary.Count -eq 2 -and $dcPortScan.PerDcSummary[0].OpenPortsCount -eq 8) "PerDcSummary validation failed"

# -------------------------------------------------------------------
# Final Summary and Exit Code
# -------------------------------------------------------------------
Write-Host "`n=================================================================" -ForegroundColor Cyan
Write-Host "Test Execution Summary" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  Total Tests Executed : $($script:PassedCount + $script:FailedCount)"
Write-Host "  Passed Tests         : $script:PassedCount" -ForegroundColor Green
Write-Host "  Failed Tests         : $script:FailedCount" -ForegroundColor $(if ($script:FailedCount -eq 0) { "Green" } else { "Red" })

if ($script:FailedCount -eq 0) {
    Write-Host "`nSUCCESS: 100% of tests passed! All NetTools Suite features verified.`n" -ForegroundColor Green
    exit 0
} else {
    Write-Host "`nFAILURE: $($script:FailedCount) tests failed.`n" -ForegroundColor Red
    exit 1
}
