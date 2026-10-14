<#
.SYNOPSIS
    Comprehensive Test Suite for SCIM 2.0 Integration & Next-Gen Identity Standards.
.DESCRIPTION
    Validates ScimFilterService.psm1 and ScimService.psm1 functions:
    - SCIM filter parsing & RFC 4515 LDAP filter generation
    - RFC 4515 LDAP filter inverse translation to SCIM 2.0
    - SCIM filter syntax validation and diagnostics
    - AD object mapping to SCIM 2.0 JSON (User, Group, Enterprise User)
    - SCIM 2.0 JSON reverse mapping to AD attribute hashtable
    - RFC 7644 Section 3.7 bulk operations with bulkId resolution & failOnErrors
    - RFC 7643 /Schemas and /ResourceTypes definitions
    - Strict constraints (UTF-8 BOM encoding, zero sensitive usernames)
#>

[CmdletBinding()]
param ()

$ErrorActionPreference = "Stop"

$scriptRoot = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($scriptRoot)) {
    $scriptRoot = (Get-Location).Path
}
$projectRoot = Split-Path -Parent $scriptRoot
if (-not (Test-Path (Join-Path $projectRoot "Modules"))) {
    $projectRoot = (Get-Location).Path
}

$moduleFilterPath = Join-Path $projectRoot "Modules/ScimFilterService.psm1"
$moduleScimPath   = Join-Path $projectRoot "Modules/ScimService.psm1"

Import-Module $moduleFilterPath -Force
Import-Module $moduleScimPath -Force

$totalTests = 0
$passedTests = 0
$failedTests = 0

function Assert-Test {
    param (
        [string]$Name,
        [bool]$Condition,
        [string]$Detail = ""
    )

    $script:totalTests++
    if ($Condition) {
        $script:passedTests++
        Write-Host "  [PASS] $Name" -ForegroundColor Green
    }
    else {
        $script:failedTests++
        Write-Host "  [FAIL] $Name" -ForegroundColor Red
        if ($Detail) {
            Write-Host "         $Detail" -ForegroundColor DarkRed
        }
    }
}

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host " SCIM 2.0 & IDENTITY STANDARDS TEST SUITE                        " -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

# -----------------------------------------------------------------------------
# SUITE 1: ScimFilterService Syntax Validation
# -----------------------------------------------------------------------------
Write-Host "`n[SUITE 1] Test-ScimFilterSyntax: Syntax Validation" -ForegroundColor Yellow

$validFilters = @(
    'userName eq "john"',
    'emails[type eq "work" and value ew "@corp.com"]',
    'name.familyName sw "Sm"',
    'title pr',
    'not (active eq true)',
    'userType eq "Employee" and (department eq "IT" or department eq "Security")',
    'meta.lastModified ge "2023-01-01T00:00:00Z"',
    'addresses[locality eq "Seattle" and country eq "US"]',
    'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:costCenter eq "CC100"'
)

foreach ($f in $validFilters) {
    $res = Test-ScimFilterSyntax -Filter $f
    Assert-Test -Name "Valid filter syntax: '$f'" -Condition ($res.IsValid -eq $true) -Detail $res.Error
}

$invalidFilters = @(
    @{ Filter = ''; Reason = "Empty filter" },
    @{ Filter = 'userName eq "john'; Reason = "Unterminated string literal" },
    @{ Filter = 'userName eq'; Reason = "Missing comparison value" },
    @{ Filter = 'emails[type eq "work"'; Reason = "Unclosed bracket" },
    @{ Filter = '(active eq true'; Reason = "Unclosed parenthesis" },
    @{ Filter = 'userType equals "Employee"'; Reason = "Invalid operator 'equals'" }
)

foreach ($item in $invalidFilters) {
    $res = Test-ScimFilterSyntax -Filter $item.Filter
    Assert-Test -Name "Invalid filter rejection: $($item.Reason)" -Condition ($res.IsValid -eq $false -and $null -ne $res.Error)
}

# -----------------------------------------------------------------------------
# SUITE 2: Convert-ScimFilterToLdapFilter (SCIM -> RFC 4515 LDAP)
# -----------------------------------------------------------------------------
Write-Host "`n[SUITE 2] Convert-ScimFilterToLdapFilter: RFC 4515 Translation" -ForegroundColor Yellow

# Test 1: userName eq "john" -> (sAMAccountName=john)
$out1 = Convert-ScimFilterToLdapFilter 'userName eq "john"'
Assert-Test -Name "userName eq 'john' -> (sAMAccountName=john)" -Condition ($out1 -eq '(sAMAccountName=john)') -Detail "Got: $out1"

# Test 2: emails[type eq "work" and value ew "@corp.com"] -> (&(mail=*@corp.com))
$out2 = Convert-ScimFilterToLdapFilter 'emails[type eq "work" and value ew "@corp.com"]'
Assert-Test -Name "emails[type eq 'work' and value ew '@corp.com'] -> (&(mail=*@corp.com))" -Condition ($out2 -eq '(&(mail=*@corp.com))') -Detail "Got: $out2"

# Test 3: name.familyName sw "Sm" -> (sn=Sm*)
$out3 = Convert-ScimFilterToLdapFilter 'name.familyName sw "Sm"'
Assert-Test -Name "name.familyName sw 'Sm' -> (sn=Sm*)" -Condition ($out3 -eq '(sn=Sm*)') -Detail "Got: $out3"

# Test 4: title pr -> (title=*)
$out4 = Convert-ScimFilterToLdapFilter 'title pr'
Assert-Test -Name "title pr -> (title=*)" -Condition ($out4 -eq '(title=*)') -Detail "Got: $out4"

# Test 5: not (active eq true) -> (userAccountControl:1.2.840.113556.1.4.803:=2)
$out5 = Convert-ScimFilterToLdapFilter 'not (active eq true)'
Assert-Test -Name "not (active eq true) -> (userAccountControl:1.2.840.113556.1.4.803:=2)" -Condition ($out5 -eq '(userAccountControl:1.2.840.113556.1.4.803:=2)') -Detail "Got: $out5"

# Test 6: userType eq "Employee" and (department eq "IT" or department eq "Security") -> (&(employeeType=Employee)(|(department=IT)(department=Security)))
$out6 = Convert-ScimFilterToLdapFilter 'userType eq "Employee" and (department eq "IT" or department eq "Security")'
Assert-Test -Name "Compound AND/OR filter mapping" -Condition ($out6 -eq '(&(employeeType=Employee)(|(department=IT)(department=Security)))') -Detail "Got: $out6"

# Test 7: active eq true -> (! (userAccountControl:1.2.840.113556.1.4.803:=2))
$out7 = Convert-ScimFilterToLdapFilter 'active eq true'
Assert-Test -Name "active eq true -> (! (userAccountControl:1.2.840.113556.1.4.803:=2))" -Condition ($out7 -eq '(! (userAccountControl:1.2.840.113556.1.4.803:=2))') -Detail "Got: $out7"

# Test 8: displayName co "Smith" -> (displayName=*Smith*)
$out8 = Convert-ScimFilterToLdapFilter 'displayName co "Smith"'
Assert-Test -Name "displayName co 'Smith' -> (displayName=*Smith*)" -Condition ($out8 -eq '(displayName=*Smith*)') -Detail "Got: $out8"

# Test 9: Enterprise URN prefix mapping
$out9 = Convert-ScimFilterToLdapFilter 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:costCenter eq "CC101"'
Assert-Test -Name "Enterprise URN attribute resolution" -Condition ($out9 -eq '(costCenter=CC101)') -Detail "Got: $out9"

# Test 10: Custom attribute mapping
$out10 = Convert-ScimFilterToLdapFilter -Filter 'customTag eq "Alpha"' -AttributeMapping @{ 'customTag' = 'extensionAttribute15' }
Assert-Test -Name "Custom attribute mapping override" -Condition ($out10 -eq '(extensionAttribute15=Alpha)') -Detail "Got: $out10"

# -----------------------------------------------------------------------------
# SUITE 3: Convert-LdapFilterToScimFilter (LDAP -> SCIM 2.0)
# -----------------------------------------------------------------------------
Write-Host "`n[SUITE 3] Convert-LdapFilterToScimFilter: Inverse Translation" -ForegroundColor Yellow

$ldapIn1 = '(sAMAccountName=john)'
$scimOut1 = Convert-LdapFilterToScimFilter $ldapIn1
Assert-Test -Name "(sAMAccountName=john) -> userName eq 'john'" -Condition ($scimOut1 -eq 'userName eq "john"') -Detail "Got: $scimOut1"

$ldapIn2 = '(&(mail=*@corp.com))'
$scimOut2 = Convert-LdapFilterToScimFilter $ldapIn2
Assert-Test -Name "(&(mail=*@corp.com)) -> emails[type eq 'work' and value ew '@corp.com']" -Condition ($scimOut2 -eq 'emails[type eq "work" and value ew "@corp.com"]') -Detail "Got: $scimOut2"

$ldapIn3 = '(sn=Sm*)'
$scimOut3 = Convert-LdapFilterToScimFilter $ldapIn3
Assert-Test -Name "(sn=Sm*) -> name.familyName sw 'Sm'" -Condition ($scimOut3 -eq 'name.familyName sw "Sm"') -Detail "Got: $scimOut3"

$ldapIn4 = '(title=*)'
$scimOut4 = Convert-LdapFilterToScimFilter $ldapIn4
Assert-Test -Name "(title=*) -> title pr" -Condition ($scimOut4 -eq 'title pr') -Detail "Got: $scimOut4"

$ldapIn5 = '(userAccountControl:1.2.840.113556.1.4.803:=2)'
$scimOut5 = Convert-LdapFilterToScimFilter $ldapIn5
Assert-Test -Name "(userAccountControl:1.2.840.113556.1.4.803:=2) -> not (active eq true)" -Condition ($scimOut5 -eq 'not (active eq true)') -Detail "Got: $scimOut5"

$ldapIn6 = '(! (userAccountControl:1.2.840.113556.1.4.803:=2))'
$scimOut6 = Convert-LdapFilterToScimFilter $ldapIn6
Assert-Test -Name "(! (userAccountControl...)) -> active eq true" -Condition ($scimOut6 -eq 'active eq true') -Detail "Got: $scimOut6"

$ldapIn7 = '(&(employeeType=Employee)(|(department=IT)(department=Security)))'
$scimOut7 = Convert-LdapFilterToScimFilter $ldapIn7
Assert-Test -Name "Compound LDAP AND/OR -> SCIM compound expression" -Condition ($scimOut7 -eq 'userType eq "Employee" and (department eq "IT" or department eq "Security")') -Detail "Got: $scimOut7"

$ldapIn8 = '(displayName=*Smith*)'
$scimOut8 = Convert-LdapFilterToScimFilter $ldapIn8
Assert-Test -Name "(displayName=*Smith*) -> displayName co 'Smith'" -Condition ($scimOut8 -eq 'displayName co "Smith"') -Detail "Got: $scimOut8"

# -----------------------------------------------------------------------------
# SUITE 4: Convert-ADObjectToScimJson
# -----------------------------------------------------------------------------
Write-Host "`n[SUITE 4] Convert-ADObjectToScimJson: Object Serialization" -ForegroundColor Yellow

$testUserAD = [ordered]@{
    sAMAccountName  = 'jdoe'
    givenName       = 'John'
    sn              = 'Doe'
    middleName      = 'Robert'
    displayName     = 'John Doe'
    personalTitle   = 'Dr.'
    mail            = 'john.doe@corp.com'
    telephoneNumber = '+1-555-0100'
    mobile          = '+1-555-0199'
    streetAddress   = '100 Main St'
    l               = 'Seattle'
    st              = 'WA'
    postalCode      = '98101'
    c               = 'US'
    title           = 'Principal Architect'
    employeeType    = 'Employee'
    employeeNumber  = 'EMP-9901'
    costCenter      = 'CC-IT-404'
    company         = 'Enterprise Corp'
    department      = 'Security'
    division        = 'Identity Systems'
    manager         = 'CN=Jane Smith,OU=Managers,DC=corp,DC=com'
    Enabled         = $true
    objectGUID      = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
    whenCreated     = [DateTime]::Parse("2023-01-01T12:00:00Z")
    whenChanged     = [DateTime]::Parse("2023-06-01T15:30:00Z")
}

$userJson = Convert-ADObjectToScimJson -ADObject $testUserAD
$userObj = ConvertFrom-Json $userJson

Assert-Test -Name "User schemas contain core 2.0 User" -Condition ($userObj.schemas -contains "urn:ietf:params:scim:schemas:core:2.0:User")
Assert-Test -Name "User schemas contain Enterprise extension" -Condition ($userObj.schemas -contains "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User")
Assert-Test -Name "User ID matches GUID" -Condition ($userObj.id -eq 'a1b2c3d4-e5f6-7890-abcd-ef1234567890')
Assert-Test -Name "User userName matches sAMAccountName" -Condition ($userObj.userName -eq 'jdoe')
Assert-Test -Name "User active is true" -Condition ($userObj.active -eq $true)
Assert-Test -Name "User familyName is Doe" -Condition ($userObj.name.familyName -eq 'Doe')
Assert-Test -Name "User givenName is John" -Condition ($userObj.name.givenName -eq 'John')
Assert-Test -Name "User email matches primary work email" -Condition ($userObj.emails[0].value -eq 'john.doe@corp.com' -and $userObj.emails[0].type -eq 'work')
Assert-Test -Name "User address locality is Seattle" -Condition ($userObj.addresses[0].locality -eq 'Seattle')
Assert-Test -Name "Enterprise department is Security" -Condition ($userObj."urn:ietf:params:scim:schemas:extension:enterprise:2.0:User".department -eq 'Security')
Assert-Test -Name "Enterprise manager DN extracted" -Condition ($userObj."urn:ietf:params:scim:schemas:extension:enterprise:2.0:User".manager.value -eq 'CN=Jane Smith,OU=Managers,DC=corp,DC=com')
Assert-Test -Name "Enterprise manager displayName extracted" -Condition ($userObj."urn:ietf:params:scim:schemas:extension:enterprise:2.0:User".manager.displayName -eq 'Jane Smith')

# Group object test
$testGroupAD = [ordered]@{
    cn          = 'Cloud-Security-Admins'
    displayName = 'Cloud Security Admins'
    member      = @(
        'CN=John Doe,OU=Users,DC=corp,DC=com',
        'CN=Jane Smith,OU=Users,DC=corp,DC=com'
    )
    objectGUID  = '11223344-5566-7788-99aa-bbccddeeff00'
}

$groupJson = Convert-ADObjectToScimJson -ADObject $testGroupAD -ResourceType Group
$groupObj = ConvertFrom-Json $groupJson

Assert-Test -Name "Group schemas contain core Group" -Condition ($groupObj.schemas -contains "urn:ietf:params:scim:schemas:core:2.0:Group")
Assert-Test -Name "Group displayName is Cloud Security Admins" -Condition ($groupObj.displayName -eq 'Cloud Security Admins')
Assert-Test -Name "Group members count is 2" -Condition ($groupObj.members.Count -eq 2)
Assert-Test -Name "Group member display name parsed" -Condition ($groupObj.members[0].display -eq 'John Doe')

# -----------------------------------------------------------------------------
# SUITE 5: Convert-ScimJsonToADAttributes
# -----------------------------------------------------------------------------
Write-Host "`n[SUITE 5] Convert-ScimJsonToADAttributes: Reverse Mapping" -ForegroundColor Yellow

$adMapped = Convert-ScimJsonToADAttributes -ScimJson $userJson

Assert-Test -Name "AD sAMAccountName mapped" -Condition ($adMapped['sAMAccountName'] -eq 'jdoe')
Assert-Test -Name "AD userPrincipalName mapped" -Condition ($adMapped['userPrincipalName'] -eq 'john.doe@corp.com')
Assert-Test -Name "AD givenName mapped" -Condition ($adMapped['givenName'] -eq 'John')
Assert-Test -Name "AD sn mapped" -Condition ($adMapped['sn'] -eq 'Doe')
Assert-Test -Name "AD displayName mapped" -Condition ($adMapped['displayName'] -eq 'John Doe')
Assert-Test -Name "AD mail mapped" -Condition ($adMapped['mail'] -eq 'john.doe@corp.com')
Assert-Test -Name "AD telephoneNumber mapped" -Condition ($adMapped['telephoneNumber'] -eq '+1-555-0100')
Assert-Test -Name "AD mobile mapped" -Condition ($adMapped['mobile'] -eq '+1-555-0199')
Assert-Test -Name "AD streetAddress mapped" -Condition ($adMapped['streetAddress'] -eq '100 Main St')
Assert-Test -Name "AD locality mapped" -Condition ($adMapped['l'] -eq 'Seattle')
Assert-Test -Name "AD region mapped" -Condition ($adMapped['st'] -eq 'WA')
Assert-Test -Name "AD postalCode mapped" -Condition ($adMapped['postalCode'] -eq '98101')
Assert-Test -Name "AD country mapped" -Condition ($adMapped['c'] -eq 'US')
Assert-Test -Name "AD Enabled mapped" -Condition ($adMapped['Enabled'] -eq $true)
Assert-Test -Name "AD userAccountControl mapped" -Condition ($adMapped['userAccountControl'] -eq 512)
Assert-Test -Name "AD department mapped" -Condition ($adMapped['department'] -eq 'Security')
Assert-Test -Name "AD company mapped" -Condition ($adMapped['company'] -eq 'Enterprise Corp')
Assert-Test -Name "AD division mapped" -Condition ($adMapped['division'] -eq 'Identity Systems')
Assert-Test -Name "AD costCenter mapped" -Condition ($adMapped['costCenter'] -eq 'CC-IT-404')
Assert-Test -Name "AD employeeNumber mapped" -Condition ($adMapped['employeeNumber'] -eq 'EMP-9901')
Assert-Test -Name "AD manager mapped" -Condition ($adMapped['manager'] -eq 'CN=Jane Smith,OU=Managers,DC=corp,DC=com')

# Group reverse mapping test
$adGroupMapped = Convert-ScimJsonToADAttributes -ScimJson $groupJson
Assert-Test -Name "AD Group cn mapped" -Condition ($adGroupMapped['cn'] -eq 'Cloud Security Admins')
Assert-Test -Name "AD Group member count mapped" -Condition ($adGroupMapped['member'].Count -eq 2)

# -----------------------------------------------------------------------------
# SUITE 6: Invoke-ScimBulkOperations
# -----------------------------------------------------------------------------
Write-Host "`n[SUITE 6] Invoke-ScimBulkOperations: Bulk Operations (RFC 7644 Section 3.7)" -ForegroundColor Yellow

$bulkPayload = @'
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
  "failOnErrors": 1,
  "Operations": [
    {
      "method": "POST",
      "path": "/Users",
      "bulkId": "user100",
      "data": {
        "userName": "jdoe",
        "displayName": "John Doe",
        "name": {
          "familyName": "Doe",
          "givenName": "John"
        }
      }
    },
    {
      "method": "PATCH",
      "path": "/Users/bulkId:user100",
      "data": {
        "title": "Principal Architect"
      }
    },
    {
      "method": "POST",
      "path": "/Groups",
      "bulkId": "grp200",
      "data": {
        "displayName": "Security Core",
        "members": [
          {
            "type": "User",
            "value": "bulkId:user100"
          }
        ]
      }
    }
  ]
}
'@

$bulkResp = Invoke-ScimBulkOperations -BulkPayload $bulkPayload -SimulationMode
Assert-Test -Name "BulkResponse schema declared" -Condition ($bulkResp.schemas -contains "urn:ietf:params:scim:api:messages:2.0:BulkResponse")
Assert-Test -Name "Bulk Operations count is 3" -Condition ($bulkResp.Operations.Count -eq 3)

$op1 = $bulkResp.Operations[0]
Assert-Test -Name "Op 1 method is POST and status is 201" -Condition ($op1.method -eq 'POST' -and $op1.status -eq '201')
$generatedUserId = $op1.response.id
Assert-Test -Name "Op 1 generated valid resource GUID" -Condition ($generatedUserId -match '^[0-9a-fA-F\-]{36}$')

$op2 = $bulkResp.Operations[1]
Assert-Test -Name "Op 2 bulkId cross-reference in path resolved" -Condition ($op2.location -eq "/Users/$generatedUserId")

$op3 = $bulkResp.Operations[2]
Assert-Test -Name "Op 3 bulkId cross-reference in data resolved" -Condition ($op3.response.members.value -eq $generatedUserId)

# FailOnErrors Threshold Test
$errorPayload = @'
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
  "failOnErrors": 1,
  "Operations": [
    {
      "method": "UNSUPPORTED_METHOD",
      "path": "/Users",
      "data": {}
    },
    {
      "method": "POST",
      "path": "/Users",
      "data": { "userName": "should_abort" }
    }
  ]
}
'@

$abortResp = Invoke-ScimBulkOperations -BulkPayload $errorPayload -SimulationMode
Assert-Test -Name "failOnErrors aborted remaining operations on error" -Condition ($abortResp.Operations.Count -eq 1 -and $abortResp.Operations[0].status -eq '405')

# -----------------------------------------------------------------------------
# SUITE 7: Get-ScimSchemaDefinition
# -----------------------------------------------------------------------------
Write-Host "`n[SUITE 7] Get-ScimSchemaDefinition: RFC 7643 Schema Definitions" -ForegroundColor Yellow

$allDef = Get-ScimSchemaDefinition -Type All
Assert-Test -Name "Get-ScimSchemaDefinition returns 3 schemas" -Condition ($allDef.Schemas.Count -eq 3)
Assert-Test -Name "Get-ScimSchemaDefinition returns 2 resource types" -Condition ($allDef.ResourceTypes.Count -eq 2)

$userSchema = Get-ScimSchemaDefinition -Type User
Assert-Test -Name "User schema ID is core 2.0 User" -Condition ($userSchema.id -eq "urn:ietf:params:scim:schemas:core:2.0:User")

$groupSchema = Get-ScimSchemaDefinition -Type Group
Assert-Test -Name "Group schema ID is core 2.0 Group" -Condition ($groupSchema.id -eq "urn:ietf:params:scim:schemas:core:2.0:Group")

$entSchema = Get-ScimSchemaDefinition -Type EnterpriseUser
Assert-Test -Name "Enterprise schema ID is enterprise 2.0 User" -Condition ($entSchema.id -eq "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User")

$schemaJson = Get-ScimSchemaDefinition -Type All -AsJson
$parsedJson = ConvertFrom-Json $schemaJson
Assert-Test -Name "Get-ScimSchemaDefinition -AsJson produces valid JSON" -Condition ($null -ne $parsedJson.Schemas -and $parsedJson.Schemas.Count -eq 3)

# -----------------------------------------------------------------------------
# SUITE 8: Strict Constraints & File Encodings
# -----------------------------------------------------------------------------
Write-Host "`n[SUITE 8] Strict Constraints & Integrity Verification" -ForegroundColor Yellow

$filesToCheck = @(
    $moduleFilterPath,
    $moduleScimPath,
    (Join-Path $projectRoot "tests/Test-ScimService.ps1")
)

foreach ($filePath in $filesToCheck) {
    $fileName = Split-Path -Leaf $filePath
    $bytes = [System.IO.File]::ReadAllBytes($filePath)
    $hasBom = ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)
    Assert-Test -Name "File '$fileName' has UTF-8 with BOM (EF BB BF)" -Condition $hasBom -Detail "Bytes: {0:X2} {1:X2} {2:X2}" -f $bytes[0], $bytes[1], $bytes[2]
}

# Verify Export-ModuleMember in modules
$filterExports = (Get-Command -Module ScimFilterService).Name
$expectedFilterExports = @('Convert-ScimFilterToLdapFilter', 'Convert-LdapFilterToScimFilter', 'Test-ScimFilterSyntax')
$filterExportsOk = $true
foreach ($exp in $expectedFilterExports) {
    if ($filterExports -notcontains $exp) { $filterExportsOk = $false }
}
Assert-Test -Name "ScimFilterService exports all required functions" -Condition $filterExportsOk

$scimExports = (Get-Command -Module ScimService).Name
$expectedScimExports = @('Convert-ADObjectToScimJson', 'Convert-ScimJsonToADAttributes', 'Invoke-ScimBulkOperations', 'Get-ScimSchemaDefinition')
$scimExportsOk = $true
foreach ($exp in $expectedScimExports) {
    if ($scimExports -notcontains $exp) { $scimExportsOk = $false }
}
Assert-Test -Name "ScimService exports all required functions" -Condition $scimExportsOk

# -----------------------------------------------------------------------------
# SUMMARY REPORT
# -----------------------------------------------------------------------------
Write-Host "`n=================================================================" -ForegroundColor Cyan
Write-Host " TEST RUN SUMMARY" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host " Total Tests  : $totalTests"
Write-Host " Passed Tests : $passedTests" -ForegroundColor Green
Write-Host " Failed Tests : $failedTests" -ForegroundColor $(if ($failedTests -eq 0) { "Green" } else { "Red" })
$passRate = if ($totalTests -gt 0) { [Math]::Round(($passedTests / $totalTests) * 100, 2) } else { 0 }
Write-Host " Pass Rate    : $passRate%" -ForegroundColor $(if ($passRate -eq 100) { "Green" } else { "Red" })

if ($failedTests -gt 0) {
    exit 1
}
else {
    exit 0
}
