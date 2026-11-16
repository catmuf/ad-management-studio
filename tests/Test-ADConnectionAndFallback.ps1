<#
.SYNOPSIS
    Automated test suite verifying live Domain Controller connection context propagation,
    custom credential isolation, and dual-engine RSAT -> ADSI/LDAP fallback across all core
    Active Directory listings, Dashboard stats, and OU Tree views.
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
[CmdletBinding()]
param ()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$script:pass = 0
$script:fail = 0

function Assert-Check {
    param([string]$Name, [bool]$Condition, [string]$Detail = "")
    if ($Condition) {
        Write-Host "  [PASS] $Name$(if ($Detail) { " ($Detail)" })" -ForegroundColor Green
        $script:pass++
    } else {
        Write-Host "  [FAIL] $Name$(if ($Detail) { " ($Detail)" })" -ForegroundColor Red
        $script:fail++
    }
}

Write-Host "=== Running AD Connection Context & ADSI Fallback Test Suite ===" -ForegroundColor Cyan

Import-Module (Join-Path $repoRoot 'Modules\ConfigService.psm1') -DisableNameChecking -Force
Import-Module (Join-Path $repoRoot 'Modules\ADService.psm1') -DisableNameChecking -Force

# 1. Verify Set/Get-ADConnectionContext & SSL port auto-resolution
$secPw = ConvertTo-SecureString 'P@ssw0rd!Test' -AsPlainText -Force
$testCred = [System.Management.Automation.PSCredential]::new('CORP\adadmin', $secPw)
Set-ADConnectionContext -Server '10.20.30.40' -Port 636 -UseSSL $true -DefaultNamingContext 'DC=corp,DC=example,DC=com' -DomainName 'corp.example.com' -Credential $testCred
$ctx = Get-ADConnectionContext

Assert-Check "Connection context stores custom DC IP/FQDN" ($ctx.Server -eq '10.20.30.40')
Assert-Check "Connection context stores LDAPS port 636 and SSL flag" ($ctx.Port -eq 636 -and $ctx.UseSSL -eq $true)
Assert-Check "Connection context stores DefaultNamingContext & SearchBase" ($ctx.DefaultNamingContext -eq 'DC=corp,DC=example,DC=com' -and $ctx.SearchBase -eq 'DC=corp,DC=example,DC=com')
Assert-Check "Connection context records HasCredential in memory" ($ctx.HasCredential -eq $true)

# 2. Verify New-ADDirectoryEntry and Resolve-ADEffectiveConnection honor Server:Port & Credential
$adMod = Get-Module ADService
$eff = & $adMod { Resolve-ADEffectiveConnection }
Assert-Check "Resolve-ADEffectiveConnection builds host:port cleanly" ($eff.HostPort -eq '10.20.30.40:636' -and $eff.UseSSL -eq $true -and $eff.Credential.UserName -eq 'CORP\adadmin')

$de = & $adMod { param($c) New-ADDirectoryEntry -DistinguishedName 'DC=corp,DC=example,DC=com' -Connection $c } $eff
$dePath = [System.DirectoryServices.DirectoryEntry].GetProperty('Path').GetValue($de)
$deAuth = [int][System.DirectoryServices.DirectoryEntry].GetProperty('AuthenticationType').GetValue($de)
Assert-Check "New-ADDirectoryEntry points to remote LDAP URL with SecureSocketsLayer" ($dePath -eq 'LDAP://10.20.30.40:636/DC=corp,DC=example,DC=com' -and (($deAuth -band [int][System.DirectoryServices.AuthenticationTypes]::SecureSocketsLayer) -ne 0))
& $adMod { param($d) Invoke-ADSafeDispose @($d) } $de

# 3. Verify Dual-Engine Fallback without RSAT (Users, Detail, Groups, OU Tree, OU Flat, ObjectsInOU, Dashboard)
$mockUsers = @(
    [PSCustomObject]@{
        name = 'Alice Admin'; displayname = 'Alice Admin'; givenname = 'Alice'; sn = 'Admin'
        samaccountname = 'aadmin'; userprincipalname = 'aadmin@corp.example.com'; mail = 'alice@corp.example.com'
        title = 'Lead Admin'; department = 'IT'; useraccountcontrol = 512; lockouttime = 0
        DistinguishedName = 'CN=Alice Admin,OU=Admins,DC=corp,DC=example,DC=com'
        objectguid = '11111111-1111-1111-1111-111111111111'; objectsid = 'S-1-5-21-1001'
        whencreated = [DateTime]::UtcNow.AddDays(-10); whenchanged = [DateTime]::UtcNow
        memberof = @('CN=Domain Admins,OU=Groups,DC=corp,DC=example,DC=com')
    },
    [PSCustomObject]@{
        name = 'Bob Locked'; displayname = 'Bob Locked'; givenname = 'Bob'; sn = 'Locked'
        samaccountname = 'blocked'; userprincipalname = 'blocked@corp.example.com'; mail = 'bob@corp.example.com'
        title = 'Analyst'; department = 'Finance'; useraccountcontrol = 514; lockouttime = 133000000000000000
        DistinguishedName = 'CN=Bob Locked,OU=Finance,DC=corp,DC=example,DC=com'
        objectguid = '22222222-2222-2222-2222-222222222222'; objectsid = 'S-1-5-21-1002'
        whencreated = [DateTime]::UtcNow.AddDays(-5); whenchanged = [DateTime]::UtcNow
        memberof = @()
    }
)
$mockGroups = @(
    [PSCustomObject]@{
        name = 'Domain Admins'; samaccountname = 'Domain Admins'; grouptype = -2147483646
        description = 'Administrators'; member = @('CN=Alice Admin,OU=Admins,DC=corp,DC=example,DC=com')
        DistinguishedName = 'CN=Domain Admins,OU=Groups,DC=corp,DC=example,DC=com'
        objectguid = '33333333-3333-3333-3333-333333333333'; objectsid = 'S-1-5-21-512'
    }
)
$mockOUs = @(
    [PSCustomObject]@{ ou = 'CorpRoot'; name = 'CorpRoot'; description = 'Top'; DistinguishedName = 'OU=CorpRoot,DC=corp,DC=example,DC=com'; canonicalname = '' },
    [PSCustomObject]@{ ou = 'Admins';   name = 'Admins';   description = 'Sec'; DistinguishedName = 'OU=Admins,OU=CorpRoot,DC=corp,DC=example,DC=com'; canonicalname = '' },
    [PSCustomObject]@{ ou = 'Finance';  name = 'Finance';  description = 'Fin'; DistinguishedName = 'OU=Finance,OU=CorpRoot,DC=corp,DC=example,DC=com'; canonicalname = '' }
)
$mockChildObjs = @(
    [PSCustomObject]@{ name = 'Admins'; ObjectClass = 'organizationalUnit'; DistinguishedName = 'OU=Admins,OU=CorpRoot,DC=corp,DC=example,DC=com' },
    [PSCustomObject]@{ name = 'Alice Admin'; samaccountname = 'aadmin'; ObjectClass = 'user'; useraccountcontrol = 512; DistinguishedName = 'CN=Alice Admin,OU=Admins,DC=corp,DC=example,DC=com' }
)

& $adMod {
    param($u, $g, $o, $c)
    $script:MockU = $u; $script:MockG = $g; $script:MockO = $o; $script:MockC = $c
    $script:CapturedLdapCalls = [System.Collections.Generic.List[string]]::new()
    function script:Test-ADShouldUseRsat { param($Connection) return $false }
    function script:Invoke-LdapQuery {
        param([string]$Filter, [string]$SearchBase = "", $Scope = 'Subtree', $PropertiesToLoad = @(), [int]$PageSize = 1000, [int]$SizeLimit = 0, [string]$Server = "", [int]$Port = 0, $UseSSL = $null, $Credential = $null)
        [void]$script:CapturedLdapCalls.Add("$Server|$Port|$UseSSL|$SearchBase|$Filter")
        if ($Filter -match 'objectCategory=person') { return [PSCustomObject]@{ Success = $true; Error = ""; Results = $script:MockU } }
        if ($Filter -eq '(objectClass=group)')    { return [PSCustomObject]@{ Success = $true; Error = ""; Results = $script:MockG } }
        if ($Filter -eq '(objectClass=organizationalUnit)') { return [PSCustomObject]@{ Success = $true; Error = ""; Results = $script:MockO } }
        return [PSCustomObject]@{ Success = $true; Error = ""; Results = $script:MockC }
    }
} $mockUsers $mockGroups $mockOUs $mockChildObjs

$uList = @(Get-ADUsersList)
Assert-Check "Get-ADUsersList returns users via ADSI/LDAP fallback without RSAT" ($uList.Count -eq 2 -and $uList[0].SamAccountName -eq 'aadmin' -and $uList[0].StatusBadge -eq 'Active')
Assert-Check "Get-ADUsersList decodes Disabled + Locked flags from UAC/lockoutTime" ($uList[1].Enabled -eq $false -and $uList[1].LockedOut -eq $true -and $uList[1].StatusBadge -eq 'Disabled')

$uDetail = Get-ADUserDetail -Identity 'aadmin'
Assert-Check "Get-ADUserDetail resolves user & group memberships via ADSI/LDAP fallback" ($null -ne $uDetail -and $uDetail.User.SamAccountName -eq 'aadmin' -and $uDetail.Groups.Count -eq 1)

$gList = @(Get-ADGroupsList)
Assert-Check "Get-ADGroupsList decodes Security Global groupType via ADSI fallback" ($gList.Count -eq 1 -and $gList[0].GroupCategory -eq 'Security' -and $gList[0].GroupScope -eq 'Global' -and $gList[0].MemberCount -eq 1)

$tree = Get-ADOUTree
Assert-Check "Get-ADOUTree builds domain root and nested parent-child OU nodes via ADSI fallback" ($null -ne $tree -and $tree.DistinguishedName -eq 'DC=corp,DC=example,DC=com' -and $tree.Children.Count -eq 1 -and $tree.Children[0].Children.Count -eq 2)

$flat = @(Get-ADOUFlatList)
Assert-Check "Get-ADOUFlatList derives canonical hierarchy even when canonicalName is omitted" ($flat.Count -eq 3 -and $flat[1].PathString -match 'CorpRoot/')

$ouObjs = @(Get-ADObjectsInOU -SearchBase 'OU=CorpRoot,DC=corp,DC=example,DC=com')
Assert-Check "Get-ADObjectsInOU retrieves child OUs and users sorted with OU first" ($ouObjs.Count -eq 2 -and $ouObjs[0].ObjectClass -eq 'OU' -and $ouObjs[1].ObjectClass -eq 'User')

$stats = Get-ADDashboardStats
Assert-Check "Get-ADDashboardStats calculates users/active/disabled/locked/groups/OUs via ADSI fallback" ($stats.TotalUsers -eq 2 -and $stats.ActiveUsers -eq 1 -and $stats.DisabledUsers -eq 1 -and $stats.LockedUsers -eq 1 -and $stats.TotalGroups -eq 1 -and $stats.TotalOUs -eq 3)

$calls = & $adMod { $script:CapturedLdapCalls }
Assert-Check "All ADSI fallback queries propagated session Server:Port:SSL & SearchBase" (($calls | Where-Object { $_ -like '10.20.30.40|636|True|*' }).Count -eq $calls.Count)

# Reset ADService session before Step 4 live UI harness so startup Background tick stays clean
Set-ADConnectionContext -ClearCredential
& $adMod {
    Remove-Item function:script:Test-ADShouldUseRsat -ErrorAction SilentlyContinue
    Remove-Item function:script:Invoke-LdapQuery -ErrorAction SilentlyContinue
}
Import-Module (Join-Path $repoRoot 'Modules\ADService.psm1') -DisableNameChecking -Force

# 4. Verify stale in-memory module reload, Connect-ADProfileContext live UI refresh, and child-scope terminal launch
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
$cfgFilePath = Join-Path $repoRoot 'config.json'
$cfgOrigBytes = if (Test-Path $cfgFilePath) { [System.IO.File]::ReadAllBytes($cfgFilePath) } else { $null }
try {
Push-Location $repoRoot
# Simulate stale module from an earlier terminal session before launching main.ps1
New-Module -Name ADService -ScriptBlock { function Get-ADUsersList { @() } } | Import-Module -Force -Global

$mainRaw = Get-Content (Join-Path $repoRoot 'main.ps1') -Raw -Encoding utf8
$mainOffscreen = $mainRaw -replace '\[void\]\$window\.ShowDialog\(\)', '$window.WindowStartupLocation = [System.Windows.WindowStartupLocation]::Manual; $window.Left = -32000; $window.Top = -32000; $window.Show()'
$global:Error.Clear()
. ([scriptblock]::Create($mainOffscreen))
[System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Loaded)
[System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Background)
[System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::ContextIdle)
$startupErrs = @($global:Error | ForEach-Object { $_.Exception.Message })

Assert-Check "Force-reloading ADService replaces stale session module (Set-ADConnectionContext available)" ($null -ne (Get-Command Set-ADConnectionContext -ErrorAction SilentlyContinue))
Assert-Check "Zero startup errors in `$global:Error without RSAT module" ($startupErrs.Count -eq 0) "Found=$($startupErrs.Count) $(if ($startupErrs.Count -gt 0) { $startupErrs[0] })"
$tmpCfgDefault = Join-Path ([System.IO.Path]::GetTempPath()) ("adstudio_defcfg_" + [guid]::NewGuid().ToString('N') + ".json")
$tmpCfgSaved = Join-Path ([System.IO.Path]::GetTempPath()) ("adstudio_savecfg_" + [guid]::NewGuid().ToString('N') + ".json")
try {
    $defCfg = Get-AppSettings -ConfigPath $tmpCfgDefault
    Assert-Check "Get-AppSettings defaults UI.Theme to Light when config does not exist" ($defCfg.UI.Theme -eq 'Light')
    $defCfg.UI.Theme = 'Dark'
    [void](Save-AppSettings -Config $defCfg -ConfigPath $tmpCfgSaved)
    $loadedSavedCfg = Get-AppSettings -ConfigPath $tmpCfgSaved
    Assert-Check "Get-AppSettings preserves user-saved Dark theme" ($loadedSavedCfg.UI.Theme -eq 'Dark')
} finally {
    Remove-Item -Path $tmpCfgDefault, $tmpCfgSaved -Force -ErrorAction SilentlyContinue
}
Assert-Check "Application starts in Light Mode by default with synchronized menu and settings controls" ($state.CurrentTheme -eq 'Light' -and $controls['MenuThemeLight'].IsChecked -eq $true -and $controls['CmbThemeMode'].SelectedIndex -eq 1)

# Re-inject offline mock context resolver + ADService mock after main.ps1 loaded
function global:Get-ADEnvironmentContext {
    param($Config, [string]$Server = "", [int]$Port = 389, [bool]$UseSSL = $false, [string]$SearchBase = "", $Credential = $null)
    $null = $Config; $null = $Credential
    $effBase = if ($SearchBase) { $SearchBase } else { 'DC=corp,DC=example,DC=com' }
    return [PSCustomObject]@{
        IsConnected          = $true
        Server               = if ($Server) { $Server } else { 'dc01.corp.example.com' }
        Port                 = if ($Port -gt 0) { $Port } else { 389 }
        UseSSL               = $UseSSL
        DomainName           = 'corp.example.com'
        ForestName           = 'corp.example.com'
        NetBIOSName          = 'CORP'
        PDCEmulator          = if ($Server) { $Server } else { 'dc01.corp.example.com' }
        DefaultNamingContext = $effBase
        RootNamingContext    = 'DC=corp,DC=example,DC=com'
        ConfigurationNC      = 'CN=Configuration,DC=corp,DC=example,DC=com'
        SearchBase           = $effBase
        DomainControllers    = @('dc01.corp.example.com')
        CurrentUser          = 'CORP\adadmin'
        IsRSAT               = $false
        LatencyMs            = 4
        ErrorMessage         = ''
    }
}
function global:Test-ADConnectionDiagnostic {
    param([string]$Server = "", [int]$Port = 389, [int]$TimeoutMs = 3000, [bool]$UseSSL = $false, $Credential = $null)
    $null = $TimeoutMs; $null = $UseSSL; $null = $Credential
    return [PSCustomObject]@{
        Success = $true; PortOpen = $true; TcpPortOpen = $true; IPAddress = '10.20.30.40'
        DefaultNamingContext = 'DC=corp,DC=example,DC=com'; DomainNamingNC = 'DC=corp,DC=example,DC=com'
        Server = $Server; Port = $Port; DnsResolved = $true; LatencyMs = 4; RootDseQueried = $true; ErrorMessage = ''
    }
}
function global:Get-ADUsersList { return $mockUsers | ForEach-Object { [PSCustomObject]@{ DisplayName = $_.displayname; SamAccountName = $_.samaccountname; Mail = $_.mail; Title = $_.title; Department = $_.department; StatusBadge = 'Active'; StatusColor = '#107C41'; Enabled = $true; LockedOut = $false; OUPath = 'Admins'; DistinguishedName = $_.DistinguishedName } } }
function global:Get-ADGroupsList { return @([PSCustomObject]@{ Name = 'Domain Admins'; SamAccountName = 'Domain Admins'; GroupCategory = 'Security'; GroupScope = 'Global'; MemberCount = 1; DistinguishedName = 'CN=Domain Admins,DC=corp,DC=example,DC=com' }) }
function global:Get-ADComputersList { return @([PSCustomObject]@{ Name = 'DC01'; DNSHostName = 'dc01.corp.example.com'; Status = 'Enabled'; IsEnabled = $true; DistinguishedName = 'CN=DC01,OU=Domain Controllers,DC=corp,DC=example,DC=com' }) }
function global:Get-ADSchemaAttributes { return @([PSCustomObject]@{ Name = 'sAMAccountName'; Syntax = 'String' }) }
function global:Get-ADOUTree { return [PSCustomObject]@{ Name = 'corp.example.com'; DisplayName = 'corp.example.com (Domain Root)'; DistinguishedName = 'DC=corp,DC=example,DC=com'; Children = @([PSCustomObject]@{ Name = 'Admins'; DisplayName = 'Admins'; DistinguishedName = 'OU=Admins,DC=corp,DC=example,DC=com'; Children = @() }) } }
function global:Get-ADOUFlatList { return @([PSCustomObject]@{ Name = 'Admins'; DisplayName = 'Admins'; DistinguishedName = 'OU=Admins,DC=corp,DC=example,DC=com' }) }
function global:Get-ADDashboardStats { return [PSCustomObject]@{ TotalUsers = 2; ActiveUsers = 2; DisabledUsers = 0; LockedUsers = 0; TotalGroups = 1; TotalOUs = 1; DomainName = 'corp.example.com'; PDC = '10.20.30.40' } }
function global:Save-AppSettings { param($Config) $null = $Config; return $true }

Show-Panel 'Connections'
[System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::ContextIdle)
$connOk = Connect-ADProfileContext -ProfileName 'LabDC' -Server '10.20.30.40' -Port 636 -UseSSL $true -Credential $testCred -UseCurrentCredentials $false -Username 'CORP\adadmin' -Silent $true

Assert-Check "Connect-ADProfileContext succeeds on remote DC" ($connOk -is [bool] -and $connOk -eq $true)
Assert-Check "Header domain & DC badges updated live" ($controls['TxtDomainBadge'].Text -eq 'Connected: corp.example.com' -and $controls['TxtDCBadge'].Text -eq '10.20.30.40')
Assert-Check "Status bar displays ldaps:// URI & custom bind user" ($controls['TxtStatusServerUri'].Text -eq 'ldaps://10.20.30.40:636' -and $controls['TxtStatusBindUser'].Text -eq 'CORP\adadmin')
Assert-Check "Directory Search Base DN populated automatically" ($controls['TxtSearchBaseDn'].Text -eq 'DC=corp,DC=example,DC=com')
Assert-Check "TreeOUs & CmbUserOUFilter populated despite being on Connections panel" ($controls['TreeOUs'].Items.Count -eq 1 -and $controls['CmbUserOUFilter'].Items.Count -eq 2)
Assert-Check "GridUsers & GridGroups populated immediately after Connect" ($controls['GridUsers'].Items.Count -eq 2 -and $controls['GridGroups'].Items.Count -eq 1)
Assert-Check "Dashboard KPI cards reflect newly connected DC stats" ($controls['CardTotalUsers'].Text -eq '2' -and $controls['CardTotalGroups'].Text -eq '1' -and $controls['CardTotalOUs'].Text -eq '1')

$dlg = Load-XamlWindow -XamlPath (Join-Path $repoRoot 'Views\ConnectionDialog.xaml')
$dlgControlsOk = ($null -ne $dlg.FindName('BtnSaveProfile')) -and ($null -ne $dlg.FindName('BtnSaveOnly')) -and ($null -ne $dlg.FindName('ChkUseSSL')) -and ($null -ne $dlg.FindName('ChkCurrentCredentials')) -and ($null -ne $dlg.FindName('TxtUsername')) -and ($null -ne $dlg.FindName('TxtPassword'))
Assert-Check "ConnectionDialog XAML exposes Save & Connect, Save Only, SSL & Credential controls" $dlgControlsOk
$dlg.Close()

$window.Close()

# 5. Verify direct child-scope launch (matching .\main.ps1 terminal invocation) & lazy module resolution
$childTestTail = @'
$window.WindowStartupLocation = [System.Windows.WindowStartupLocation]::Manual
$window.Left = -32000
$window.Top = -32000
$window.Show()
[System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Loaded)
[System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Background)
[System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::ContextIdle)
foreach ($pName in @('SecurityAcl', 'ReplicationSuite', 'DirectorySearch', 'KerberosSuite', 'DiagnosticsToolbox', 'NetworkDiagnostics')) {
    Show-Panel $pName
    [System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::ContextIdle)
}
$window.Close()
'@
$mainChildLaunch = $mainRaw -replace '\[void\]\$window\.ShowDialog\(\)', $childTestTail
$global:Error.Clear()
& ([scriptblock]::Create($mainChildLaunch))
$childErrs = @($global:Error | ForEach-Object { $_.Exception.Message })
Assert-Check "Child-scope .\main.ps1 launch & all 6 lazy-loaded Show-Panel transitions emit 0 errors" ($childErrs.Count -eq 0) "Found=$($childErrs.Count) $(if ($childErrs.Count -gt 0) { $childErrs[0] })"
Assert-Check "Lazy modules AclService, ReplicationService, ScimService loaded into session via Show-Panel" ((Get-Module -Name AclService) -and (Get-Module -Name ReplicationService) -and (Get-Module -Name ScimService))

} finally {
    Pop-Location -ErrorAction SilentlyContinue
    if ($null -ne $cfgOrigBytes) {
        [System.IO.File]::WriteAllBytes($cfgFilePath, $cfgOrigBytes)
    }
}

Write-Host "`nSummary: $($script:pass) Passed, $($script:fail) Failed" -ForegroundColor $(if ($script:fail -eq 0) { 'Green' } else { 'Red' })
if ($script:fail -gt 0) { exit 1 }
exit 0
