<#
.SYNOPSIS
    Unit and integration tests for Directory Provisioning & Softerra Engine features.
.DESCRIPTION
    Validates:
    1. TemplateService: Invoke-TemplateSubstitution, Resolve-AccountNameConflict, Get-ADProvisioningTemplates, Save-ADProvisioningTemplates
    2. ADService: Get-ADVlvUsersList, Restore-ADDeletedObject, Invoke-ADSqlExtendedQuery, Get-AD40SecurityAuditReports
    Ensures 100% pass rate under Windows PowerShell 5.1 and PowerShell 7+.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$script:passCount = 0
$script:failCount = 0
$script:testIndex = 0

function Assert-Test {
    param(
        [string]$Description,
        [bool]$Condition,
        [string]$Details = ""
    )
    $script:testIndex++
    if ($Condition) {
        $script:passCount++
        Write-Host "  [PASS] Test $script:testIndex : $Description" -ForegroundColor Green
    } else {
        $script:failCount++
        Write-Host "  [FAIL] Test $script:testIndex : $Description" -ForegroundColor Red
        if ($Details) {
            Write-Host "         Details: $Details" -ForegroundColor Yellow
        }
    }
}

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Directory Provisioning & Softerra Engine Test Suite" -ForegroundColor Cyan
Write-Host "PowerShell Version: $($PSVersionTable.PSVersion)" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# -------------------------------------------------------------
# Module Imports
# -------------------------------------------------------------
$modulesDir = Join-Path -Path $PSScriptRoot -ChildPath "..\Modules"
$templateServicePath = Join-Path -Path $modulesDir -ChildPath "TemplateService.psm1"
$adServicePath       = Join-Path -Path $modulesDir -ChildPath "ADService.psm1"

Import-Module $templateServicePath -Force
Import-Module $adServicePath -Force

Write-Host "`n--- 1. Testing TemplateService: Invoke-TemplateSubstitution ---" -ForegroundColor Magenta

# Test 1: %lower:givenName.1%%lower:sn%
$attrs1 = @{ givenName = "John"; sn = "Doe" }
$res1 = Invoke-TemplateSubstitution -Template "%lower:givenName.1%%lower:sn%" -Attributes $attrs1
Assert-Test "Macro %lower:givenName.1%%lower:sn% produces 'jdoe'" ($res1 -eq "jdoe") "Got: '$res1'"

# Test 2: %lower:sAMAccountName%@corp.local
$attrs2 = @{ sAMAccountName = "AdminUser" }
$res2 = Invoke-TemplateSubstitution -Template "%lower:sAMAccountName%@corp.local" -Attributes $attrs2
Assert-Test "Macro %lower:sAMAccountName%@corp.local produces 'adminuser@corp.local'" ($res2 -eq "adminuser@corp.local") "Got: '$res2'"

# Test 3: %upper:sn%
$attrs3 = @{ sn = "Smith" }
$res3 = Invoke-TemplateSubstitution -Template "%upper:sn%" -Attributes $attrs3
Assert-Test "Macro %upper:sn% produces 'SMITH'" ($res3 -eq "SMITH") "Got: '$res3'"

# Test 4: %initial:givenName%
$attrs4 = @{ givenName = "Jane" }
$res4 = Invoke-TemplateSubstitution -Template "%initial:givenName%" -Attributes $attrs4
Assert-Test "Macro %initial:givenName% produces 'J'" ($res4 -eq "J") "Got: '$res4'"

# Test 5: Substring substr:start:len
$attrs5 = @{ givenName = "Alexander" }
$res5 = Invoke-TemplateSubstitution -Template "%substr:1:4:givenName%" -Attributes $attrs5
Assert-Test "Macro %substr:1:4:givenName% produces 'Alex'" ($res5 -eq "Alex") "Got: '$res5'"

# Test 6: Count slice %givenName:3% and %givenName.2%
$attrs6 = @{ givenName = "Michael" }
$res6a = Invoke-TemplateSubstitution -Template "%givenName:3%" -Attributes $attrs6
$res6b = Invoke-TemplateSubstitution -Template "%givenName.2%" -Attributes $attrs6
Assert-Test "Macro count slice %givenName:3% and %givenName.2% produce 'Mic' and 'Mi'" ($res6a -eq "Mic" -and $res6b -eq "Mi") "Got: '$res6a', '$res6b'"

# Test 7: Custom attributes and missing attribute fallback
$attrs7 = @{ employeeId = "EMP-1042"; title = "Engineer" }
$res7 = Invoke-TemplateSubstitution -Template "%employeeId% - %title% (%missing%)" -Attributes $attrs7
Assert-Test "Custom attributes and missing attribute handle gracefully" ($res7 -eq "EMP-1042 - Engineer ()") "Got: '$res7'"


Write-Host "`n--- 2. Testing TemplateService: Resolve-AccountNameConflict ---" -ForegroundColor Magenta

# Test 8: Non-colliding candidate returns unmodified
$predicate8 = { param($candidate, $attr) $null = $candidate; $null = $attr; return $false }
$res8 = Resolve-AccountNameConflict -Candidate "jdoe" -ExistsPredicate $predicate8
Assert-Test "Non-colliding candidate returns candidate directly ('jdoe')" ($res8 -eq "jdoe") "Got: '$res8'"

# Test 9: Colliding candidate appends incremental numbers (1, 2, ...)
$existing9 = @("jdoe", "jdoe1")
$predicate9 = { param($candidate, $attr) $null = $attr; return ($candidate -in $existing9) }
$res9 = Resolve-AccountNameConflict -Candidate "jdoe" -ExistsPredicate $predicate9
Assert-Test "Colliding candidate 'jdoe' resolves to 'jdoe2' when 'jdoe' and 'jdoe1' exist" ($res9 -eq "jdoe2") "Got: '$res9'"

# Test 10: UPN collision resolution
$existing10 = @("jdoe@corp.local", "jdoe1@corp.local")
$predicate10 = { param($candidate, $attr) $null = $attr; return ($candidate -in $existing10) }
$res10 = Resolve-AccountNameConflict -Candidate "jdoe@corp.local" -AttributeName "userPrincipalName" -ExistsPredicate $predicate10
Assert-Test "UPN collision 'jdoe@corp.local' resolves to 'jdoe2@corp.local'" ($res10 -eq "jdoe2@corp.local") "Got: '$res10'"

# Test 11: 20-character limit constraint on sAMAccountName
$longBase = "verylongaccountnametest" # 23 characters
$existing11 = @($longBase.Substring(0, 20))
$predicate11 = { param($candidate, $attr) $null = $attr; return ($candidate -in $existing11) }
$res11 = Resolve-AccountNameConflict -Candidate $longBase -AttributeName "sAMAccountName" -ExistsPredicate $predicate11
Assert-Test "sAMAccountName stays within 20 character limit ($($res11.Length) chars: '$res11')" ($res11.Length -le 20) "Got: '$res11'"


Write-Host "`n--- 3. Testing TemplateService: Provisioning Profile Management ---" -ForegroundColor Magenta

# Test 12: Retrieves default provisioning profiles
$templates12 = Get-ADProvisioningTemplates
Assert-Test "Get-ADProvisioningTemplates returns default profile catalog" ($templates12 -and $templates12.Count -ge 3) "Count: $($templates12.Count)"

# Test 13: Filters template by Id
$tmpl13 = Get-ADProvisioningTemplates -Id "standard-employee"
Assert-Test "Filter template by Id 'standard-employee' succeeds" ($tmpl13 -and $tmpl13.Id -eq "standard-employee") "Id: $($tmpl13.Id)"

# Test 14: Save and retrieve custom template in config.json
$tempConfigPath = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "ad_test_config_$([Guid]::NewGuid().ToString('N')).json"
try {
    $customProfile = New-ADProvisioningProfile -Id "qa-tester" -Name "QA Tester Profile" -Department "Quality Assurance" -SamAccountNamePattern "qa-%lower:givenName.1%%lower:sn%"
    $saveOk = Save-ADProvisioningTemplates -Templates @($customProfile) -ConfigPath $tempConfigPath
    $loadedTemplates = @(Get-ADProvisioningTemplates -ConfigPath $tempConfigPath)
    Assert-Test "Save-ADProvisioningTemplates and Get-ADProvisioningTemplates persist custom profile" ($saveOk -and $loadedTemplates.Count -ge 1 -and $loadedTemplates[0].Id -eq "qa-tester") "Loaded: $($loadedTemplates[0].Id)"
} finally {
    if (Test-Path $tempConfigPath) { Remove-Item $tempConfigPath -Force -ErrorAction SilentlyContinue }
}

# Test 15: Invoke-ADObjectProvisioningPlan generates complete user plan
$tmpl15 = Get-ADProvisioningTemplates -Id "standard-employee"
$userInputs15 = @{ givenName = "Alice"; sn = "Johnson"; Department = "Engineering" }
$plan15 = Invoke-ADObjectProvisioningPlan -Template $tmpl15 -UserInput $userInputs15 -ExistsPredicate { param($name) $null = $name; return $false }
Assert-Test "Invoke-ADObjectProvisioningPlan generates conflict-free provisioning plan" (
    $plan15.SamAccountName -eq "ajohnson" -and
    $plan15.UserPrincipalName -eq "ajohnson@corp.local" -and
    $plan15.DisplayName -eq "Alice Johnson" -and
    $plan15.Mail -eq "alice.johnson@corp.local"
) "Got: Sam=$($plan15.SamAccountName), UPN=$($plan15.UserPrincipalName)"


Write-Host "`n--- 4. Testing ADService: Get-ADVlvUsersList (Virtual List View) ---" -ForegroundColor Magenta

# Mock dataset for Virtual List View testing
$mockVlvUsers = New-Object System.Collections.Generic.List[PSCustomObject]
for ($i = 1; $i -le 100; $i++) {
    $mockVlvUsers.Add([PSCustomObject]@{
        sAMAccountName    = ("user{0:D3}" -f $i)
        displayName       = ("Employee {0:D3}" -f $i)
        mail              = ("user{0:D3}@corp.local" -f $i)
        userAccountControl = 512
        distinguishedName = ("CN=user{0:D3},OU=Users,DC=corp,DC=local" -f $i)
    })
}

# Test 16: VLV sliding-window offset and page size
$vlvPage1 = Get-ADVlvUsersList -Offset 1 -PageSize 10 -MockData $mockVlvUsers
$vlvPage2 = Get-ADVlvUsersList -Offset 11 -PageSize 10 -MockData $mockVlvUsers
Assert-Test "Get-ADVlvUsersList sliding-window offset retrieves correct page slices" (
    $vlvPage1.Results.Count -eq 10 -and
    $vlvPage1.Results[0].sAMAccountName -eq "user001" -and
    $vlvPage2.Results[0].sAMAccountName -eq "user011"
) "Page1 first: $($vlvPage1.Results[0].sAMAccountName), Page2 first: $($vlvPage2.Results[0].sAMAccountName)"

# Test 17: RFC 2891 server-side sort descending
$vlvDesc = Get-ADVlvUsersList -Offset 1 -PageSize 5 -SortAttribute "sAMAccountName" -SortDescending -MockData $mockVlvUsers
Assert-Test "Get-ADVlvUsersList sorts descending according to RFC 2891" (
    $vlvDesc.Results.Count -eq 5 -and
    $vlvDesc.Results[0].sAMAccountName -eq "user100"
) "First descending: $($vlvDesc.Results[0].sAMAccountName)"

# Test 18: VLV metadata verification
Assert-Test "Get-ADVlvUsersList returns standard VLV metadata (TotalEstimated, PageSize, HasMore)" (
    $vlvPage1.TotalEstimated -eq 100 -and
    $vlvPage1.PageSize -eq 10 -and
    $vlvPage1.HasMore -eq $true
) "TotalEstimated=$($vlvPage1.TotalEstimated), HasMore=$($vlvPage1.HasMore)"


Write-Host "`n--- 5. Testing ADService: Restore-ADDeletedObject ---" -ForegroundColor Magenta

# Test 19: Tombstone RDN cleaning (\0ADEL:<GUID> stripping)
$tombstoneDN = "CN=Jane Smith\0ADEL:9a3b2c1d-1111-2222-3333-444455556666,CN=Deleted Objects,DC=corp,DC=local"
$restoreSim = Restore-ADDeletedObject -Identity $tombstoneDN -TargetOU "OU=Users,DC=corp,DC=local" -Simulate
Assert-Test "Restore-ADDeletedObject strips \0ADEL:<GUID> suffix from tombstone DN" (
    $restoreSim.Success -eq $true -and
    $restoreSim.CleanName -eq "Jane Smith" -and
    $restoreSim.RestoredDN -eq "CN=Jane Smith,OU=Users,DC=corp,DC=local"
) "CleanName: '$($restoreSim.CleanName)', RestoredDN: '$($restoreSim.RestoredDN)'"

# Test 20: Handles literal 0x0ADEL / DEL:<guid> variation
$tombstoneDN2 = "CN=AdminAccountDEL:12345678-abcd-1234-abcd-123456789abc,CN=Deleted Objects,DC=corp,DC=local"
$restoreSim2 = Restore-ADDeletedObject -Identity $tombstoneDN2 -TargetOU "OU=Admin,DC=corp,DC=local" -Simulate
Assert-Test "Restore-ADDeletedObject strips standard DEL:<GUID> suffix" (
    $restoreSim2.Success -eq $true -and
    $restoreSim2.CleanName -eq "AdminAccount"
) "CleanName: '$($restoreSim2.CleanName)'"

# Test 21: isDeleted attribute cleared in reanimation simulation
Assert-Test "Restore-ADDeletedObject marks isDeletedCleared = true" (
    $restoreSim.IsDeletedCleared -eq $true
) "IsDeletedCleared=$($restoreSim.IsDeletedCleared)"


Write-Host "`n--- 6. Testing ADService: Invoke-ADSqlExtendedQuery ---" -ForegroundColor Magenta

# Mock objects for SQL testing
$mockSqlUsers = @(
    [PSCustomObject]@{ sAMAccountName = "user_enabled1"; userAccountControl = 512; department = "Engineering"; title = "Developer"; manager = "CN=mgr1,OU=Management,DC=corp,DC=local"; DistinguishedName = "CN=user_enabled1,OU=Users,DC=corp,DC=local" },
    [PSCustomObject]@{ sAMAccountName = "user_disabled1"; userAccountControl = 514; department = "Engineering"; title = "Intern"; manager = "CN=mgr1,OU=Management,DC=corp,DC=local"; DistinguishedName = "CN=user_disabled1,OU=Users,DC=corp,DC=local" },
    [PSCustomObject]@{ sAMAccountName = "user_noexpire1"; userAccountControl = 66048; department = "Finance"; title = "Analyst"; manager = "CN=mgr2,OU=Management,DC=corp,DC=local"; DistinguishedName = "CN=user_noexpire1,OU=Users,DC=corp,DC=local" },
    [PSCustomObject]@{ sAMAccountName = "user_enabled2"; userAccountControl = 512; department = "Finance"; title = "Accountant"; manager = "CN=mgr2,OU=Management,DC=corp,DC=local"; DistinguishedName = "CN=user_enabled2,OU=Users,DC=corp,DC=local" }
)

# Test 22: Bitwise & operator: userAccountControl & 2 = 2 (disabled accounts)
$sqlRes22 = Invoke-ADSqlExtendedQuery -SqlQuery "SELECT sAMAccountName FROM Users WHERE userAccountControl & 2 = 2" -MockData $mockSqlUsers
Assert-Test "SQL bitwise operator '& 2 = 2' identifies disabled accounts" (
    $sqlRes22.Success -eq $true -and
    $sqlRes22.Count -eq 1 -and
    $sqlRes22.Results[0].sAMAccountName -eq "user_disabled1"
) "Count: $($sqlRes22.Count), Name: $($sqlRes22.Results[0].sAMAccountName)"

# Test 23: Bitwise & operator: userAccountControl & 2 = 0 (enabled accounts)
$sqlRes23 = Invoke-ADSqlExtendedQuery -SqlQuery "SELECT sAMAccountName FROM Users WHERE userAccountControl & 2 = 0" -MockData $mockSqlUsers
Assert-Test "SQL bitwise operator '& 2 = 0' identifies enabled accounts" (
    $sqlRes23.Success -eq $true -and
    $sqlRes23.Count -eq 3
) "Count: $($sqlRes23.Count)"

# Test 24: Bitwise & operator: userAccountControl & 65536 = 65536 (passwords never expire)
$sqlRes24 = Invoke-ADSqlExtendedQuery -SqlQuery "SELECT sAMAccountName FROM Users WHERE userAccountControl & 65536 = 65536" -MockData $mockSqlUsers
Assert-Test "SQL bitwise operator '& 65536 = 65536' identifies DONT_EXPIRE_PASSWORD" (
    $sqlRes24.Success -eq $true -and
    $sqlRes24.Count -eq 1 -and
    $sqlRes24.Results[0].sAMAccountName -eq "user_noexpire1"
) "Count: $($sqlRes24.Count), Name: $($sqlRes24.Results[0].sAMAccountName)"

# Test 25: SQL JOIN between two datasets
$mockManagers = @(
    [PSCustomObject]@{ distinguishedName = "CN=mgr1,OU=Management,DC=corp,DC=local"; displayName = "Senior Director Alpha"; sAMAccountName = "mgr1" },
    [PSCustomObject]@{ distinguishedName = "CN=mgr2,OU=Management,DC=corp,DC=local"; displayName = "Senior Director Beta"; sAMAccountName = "mgr2" }
)
$mockJoinData = @{
    u = $mockSqlUsers
    m = $mockManagers
}
$joinQuery = "SELECT u.sAMAccountName, m.displayName AS ManagerName FROM Users u JOIN Managers m ON u.manager = m.distinguishedName WHERE u.department = 'Engineering'"
$joinRes = Invoke-ADSqlExtendedQuery -SqlQuery $joinQuery -MockData $mockJoinData
Assert-Test "Directory Hash-JOIN correctly joins Users and Managers with column projections" (
    $joinRes.Success -eq $true -and
    $joinRes.Count -eq 2 -and
    $joinRes.Results[0].ManagerName -eq "Senior Director Alpha"
) "Count: $($joinRes.Count), ManagerName: $($joinRes.Results[0].ManagerName)"

# Test 26: DML simulation UPDATE
$updateQuery = "UPDATE 'OU=Users,DC=corp,DC=local' SET department = 'Operations', title = 'Lead' WHERE sAMAccountName = 'user_enabled1'"
$updateSim = Invoke-ADSqlExtendedQuery -SqlQuery $updateQuery -Simulate -MockData $mockSqlUsers
Assert-Test "DML UPDATE simulation generates proposed modifications without modifying target" (
    $updateSim.Success -eq $true -and
    $updateSim.Simulated -eq $true -and
    $updateSim.RowsAffected -eq 1 -and
    $updateSim.ProposedChanges.Count -eq 2
) "RowsAffected=$($updateSim.RowsAffected), Changes=$($updateSim.ProposedChanges.Count)"

# Test 27: DML simulation INSERT
$insertQuery = "INSERT INTO 'OU=Users,DC=corp,DC=local' (sAMAccountName, givenName, sn, mail) VALUES ('newuser', 'New', 'User', 'newuser@corp.local')"
$insertSim = Invoke-ADSqlExtendedQuery -SqlQuery $insertQuery -Simulate
Assert-Test "DML INSERT simulation validates proposed attributes and target container" (
    $insertSim.Success -eq $true -and
    $insertSim.Simulated -eq $true -and
    $insertSim.ProposedDN -eq "CN=newuser,OU=Users,DC=corp,DC=local"
) "ProposedDN: $($insertSim.ProposedDN)"

# Test 28: DML simulation DELETE
$deleteQuery = "DELETE FROM 'OU=Users,DC=corp,DC=local' WHERE sAMAccountName = 'user_disabled1'"
$deleteSim = Invoke-ADSqlExtendedQuery -SqlQuery $deleteQuery -Simulate -MockData $mockSqlUsers
Assert-Test "DML DELETE simulation identifies objects transitioning to tombstone" (
    $deleteSim.Success -eq $true -and
    $deleteSim.Simulated -eq $true -and
    $deleteSim.RowsAffected -eq 1
) "RowsAffected: $($deleteSim.RowsAffected)"


Write-Host "`n--- 7. Testing ADService: Get-AD40SecurityAuditReports ---" -ForegroundColor Magenta

# Test 29: Catalog contains 40+ definitions
$auditCatalog = Get-AD40SecurityAuditReports
Assert-Test "Get-AD40SecurityAuditReports provides at least 40 audit query definitions (Total: $($auditCatalog.Count))" (
    $auditCatalog -and $auditCatalog.Count -ge 40
) "Catalog count: $($auditCatalog.Count)"

# Test 30: All 5 security categories are represented
$categories = @($auditCatalog | Select-Object -ExpandProperty Category -Unique)
$expectedCats = @("Account Security", "Account Lifecycle", "Group Hygiene", "Computer Health", "PKI/Certificates")
$allCatsPresent = $true
foreach ($cat in $expectedCats) {
    if ($cat -notin $categories) { $allCatsPresent = $false }
}
Assert-Test "Audit catalog covers Account Security, Account Lifecycle, Group Hygiene, Computer Health, and PKI/Certificates" (
    $allCatsPresent -eq $true
) "Categories: $($categories -join ', ')"

# Test 31: Category filter returns matching definitions
$pkiReports = Get-AD40SecurityAuditReports -Category "PKI/Certificates"
Assert-Test "Filtering audit catalog by category 'PKI/Certificates' returns matching queries" (
    $pkiReports.Count -ge 8 -and
    ($pkiReports | Where-Object { $_.Category -ne "PKI/Certificates" }).Count -eq 0
) "PKI report count: $($pkiReports.Count)"

# Test 32: Report execution against mock objects evaluates findings correctly
$mockAuditUsers = @(
    [PSCustomObject]@{ sAMAccountName = "admin_vuln"; userAccountControl = 65536; servicePrincipalName = "HOST/svc1"; adminCount = 1 },
    [PSCustomObject]@{ sAMAccountName = "user_safe"; userAccountControl = 512; servicePrincipalName = $null; adminCount = 0 }
)
$auditExecution = Get-AD40SecurityAuditReports -Execute -ReportId "SEC-PASS-NEVER-EXPIRE" -MockData $mockAuditUsers
Assert-Test "Get-AD40SecurityAuditReports execution accurately identifies non-compliant objects" (
    $auditExecution.Count -eq 1 -and
    $auditExecution[0].Findings.Count -eq 1 -and
    $auditExecution[0].Findings[0].sAMAccountName -eq "admin_vuln"
) "Findings: $($auditExecution[0].Findings.Count), Found: $($auditExecution[0].Findings[0].sAMAccountName)"


Write-Host "`n--- 8. Testing Module Member Exports ---" -ForegroundColor Magenta

# Test 33: Verify exports from TemplateService.psm1
$templateExports = (Get-Command -Module TemplateService).Name
$requiredTemplateExports = @(
    "Invoke-TemplateSubstitution",
    "Resolve-AccountNameConflict",
    "Get-ADProvisioningTemplates",
    "Save-ADProvisioningTemplates"
)
$allTemplateExported = $true
foreach ($fn in $requiredTemplateExports) {
    if ($fn -notin $templateExports) { $allTemplateExported = $false; Write-Warning "Missing template export: $fn" }
}
Assert-Test "TemplateService cleanly exports all required provisioning functions" ($allTemplateExported -eq $true) "Exported: $($templateExports -join ', ')"

# Test 34: Verify exports from ADService.psm1
$adExports = (Get-Command -Module ADService).Name
$requiredAdExports = @(
    "Get-ADVlvUsersList",
    "Restore-ADDeletedObject",
    "Invoke-ADSqlExtendedQuery",
    "Get-AD40SecurityAuditReports"
)
$allAdExported = $true
foreach ($fn in $requiredAdExports) {
    if ($fn -notin $adExports) { $allAdExported = $false; Write-Warning "Missing AD export: $fn" }
}
Assert-Test "ADService cleanly exports all required engine & audit functions" ($allAdExported -eq $true) "Exported: $($adExports -join ', ')"


Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "Test Execution Summary" -ForegroundColor Cyan
Write-Host "Total Tests: $($script:testIndex)" -ForegroundColor Cyan
Write-Host "Passed:      $($script:passCount)" -ForegroundColor Green
Write-Host "Failed:      $($script:failCount)" -ForegroundColor $(if ($script:failCount -eq 0) { "Green" } else { "Red" })
Write-Host "Pass Rate:   $([Math]::Round(($script:passCount / $script:testIndex) * 100, 1))%" -ForegroundColor $(if ($script:failCount -eq 0) { "Green" } else { "Red" })
Write-Host "============================================================" -ForegroundColor Cyan

if ($script:failCount -gt 0) {
    exit 1
} else {
    exit 0
}
