[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
[CmdletBinding()]
param()

$projectRoot = (Get-Location).Path
$ErrorActionPreference = "Continue"

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "   TESTING MULTI-SEARCH HTML DOSSIER VERIFICATION" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Drawing, System.Windows.Forms

# Load required modules
$modules = @(
    "ConfigService.psm1", "LoggingService.psm1", "ValidationService.psm1",
    "ADService.psm1", "ExportService.psm1", "TemplateService.psm1",
    "AclService.psm1", "KerberosService.psm1", "DiagnosticService.psm1",
    "NetworkService.psm1", "ReplicationService.psm1", "GpoService.psm1",
    "SpecializedEditorService.psm1", "ScimFilterService.psm1", "ScimService.psm1"
)
foreach ($m in $modules) {
    Import-Module (Join-Path $projectRoot "Modules\$m") -DisableNameChecking -Force
}

# Mock Directory operations to ensure immediate, deterministic offline test execution
function global:Get-ADObjectRawAttributes {
    param($DistinguishedName, [switch]$IncludeOperational)
    $null = $DistinguishedName; $null = $IncludeOperational
    return @(
        [PSCustomObject]@{ Name = "cn"; Value = "Test Object"; Type = "String"; IsOperational = $false },
        [PSCustomObject]@{ Name = "sAMAccountName"; Value = "testobj"; Type = "String"; IsOperational = $false },
        [PSCustomObject]@{ Name = "distinguishedName"; Value = $DistinguishedName; Type = "String"; IsOperational = $false },
        [PSCustomObject]@{ Name = "mail"; Value = "test@example.com"; Type = "String"; IsOperational = $false }
    )
}

function global:Get-ADUserDetail {
    param($Identity)
    $name = ($Identity -split ',')[0] -replace '^CN=', ''
    $u = [PSCustomObject]@{
        SamAccountName    = $name.ToLower()
        DisplayName       = $name
        DistinguishedName = $Identity
        Enabled           = $true
        LockedOut         = $false
        Mail              = "$($name.ToLower())@example.com"
        Department        = "Engineering"
        Title             = "Engineer"
        OUPath            = "example.com/Engineering"
    }
    return [PSCustomObject]@{
        User   = $u
        Groups = @([PSCustomObject]@{ Name = "Domain Users"; DistinguishedName = "CN=Domain Users,CN=Users,DC=example,DC=com" })
    }
}

function global:Find-ADObjectsQuickSearch {
    param($Query, [int]$MaxResults = 10)
    $null = $Query; $null = $MaxResults
    return @(
        [PSCustomObject]@{
            Name              = "Search User 1"
            SamAccountName    = "suser1"
            DisplayName       = "Search User 1"
            ObjectClass       = "user"
            DistinguishedName = "CN=Search User 1,OU=Finance,DC=example,DC=com"
        },
        [PSCustomObject]@{
            Name              = "Search User 2"
            SamAccountName    = "suser2"
            DisplayName       = "Search User 2"
            ObjectClass       = "user"
            DistinguishedName = "CN=Search User 2,OU=Engineering,DC=example,DC=com"
        },
        [PSCustomObject]@{
            Name              = "Search User 3"
            SamAccountName    = "suser3"
            DisplayName       = "Search User 3"
            ObjectClass       = "user"
            DistinguishedName = "CN=Search User 3,OU=HR,DC=example,DC=com"
        }
    )
}

# Load main.ps1 offscreen
$mainScript = Get-Content (Join-Path $projectRoot "main.ps1") -Raw
$mainScriptOffscreen = $mainScript -replace '\[void\]\$window\.ShowDialog\(\)', '$window.WindowStartupLocation = [System.Windows.WindowStartupLocation]::Manual; $window.Left = -32000; $window.Top = -32000; $window.Show()'

. ([scriptblock]::Create($mainScriptOffscreen))

function Wait-WpfEvents {
    try {
        [System.Windows.Forms.Application]::DoEvents()
        [System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Background)
    } catch {
        $null = $_
    }
}

$passCount = 0
$failCount = 0

function Assert-Test {
    param(
        [string]$Name,
        [bool]$Condition,
        [string]$Details = ""
    )
    if ($Condition) {
        $script:passCount++
        Write-Host "  [PASS] $Name" -ForegroundColor Green
    } else {
        $script:failCount++
        Write-Host "  [FAIL] ${Name}: $Details" -ForegroundColor Red
    }
}

Wait-WpfEvents

# ==============================================================================
# TEST CASE 1: First Search in Omnibar -> HTML Dossier
# ==============================================================================
Write-Host "`n--- Test 1: First Search in Omnibar ---" -ForegroundColor Yellow
$user1 = [PSCustomObject]@{
    Name              = "Search User 1"
    SamAccountName    = "suser1"
    DisplayName       = "Search User 1"
    ObjectClass       = "user"
    DistinguishedName = "CN=Search User 1,OU=Finance,DC=example,DC=com"
}
$controls['ListGlobalSearchResults'].ItemsSource = @($user1)
$controls['ListGlobalSearchResults'].SelectedItem = $user1
Wait-WpfEvents

$tab1 = $state.OpenTabs | Where-Object { $_.Id -eq $state.ActiveTabId } | Select-Object -First 1
Assert-Test -Name "Search 1 opens active HtmlView tab" -Condition ($tab1 -and $tab1.PanelName -eq "HtmlView")
Assert-Test -Name "Search 1 tab title is 'Dossier: Search User 1'" -Condition ($tab1.Title -eq "Dossier: Search User 1")

$b1 = if ($tab1.DockedPanelControls) { $tab1.DockedPanelControls['BrowserHtmlView'] } else { $controls['BrowserHtmlView'] }
for ($w = 0; $w -lt 5; $w++) {
    if ($b1 -and $b1.Document -and $b1.Document.body -and $b1.Document.body.innerHTML.Length -gt 100) { break }
    Start-Sleep -Milliseconds 150
    Wait-WpfEvents
}
$docLen1 = if ($b1 -and $b1.Document -and $b1.Document.body) { $b1.Document.body.innerHTML.Length } else { 0 }
Assert-Test -Name "Search 1 BrowserHtmlView is NOT blank (body > 100)" -Condition ($docLen1 -gt 100) -Details "Body length: $docLen1"

# ==============================================================================
# TEST CASE 2: Second Search in Omnibar -> New Tab with Rendered Content
# ==============================================================================
Write-Host "`n--- Test 2: Second Search in Omnibar ---" -ForegroundColor Yellow
$user2 = [PSCustomObject]@{
    Name              = "Search User 2"
    SamAccountName    = "suser2"
    DisplayName       = "Search User 2"
    ObjectClass       = "user"
    DistinguishedName = "CN=Search User 2,OU=Engineering,DC=example,DC=com"
}
$controls['ListGlobalSearchResults'].ItemsSource = @($user2)
$controls['ListGlobalSearchResults'].SelectedItem = $user2
Wait-WpfEvents

$tab2 = $state.OpenTabs | Where-Object { $_.Id -eq $state.ActiveTabId } | Select-Object -First 1
Assert-Test -Name "Search 2 opens new active HtmlView tab" -Condition ($tab2 -and $tab2.PanelName -eq "HtmlView" -and $tab2.Id -ne $tab1.Id)
Assert-Test -Name "Search 2 tab title is 'Dossier: Search User 2'" -Condition ($tab2.Title -eq "Dossier: Search User 2")

$b2 = if ($tab2.DockedPanelControls) { $tab2.DockedPanelControls['BrowserHtmlView'] } else { $controls['BrowserHtmlView'] }
for ($w = 0; $w -lt 5; $w++) {
    if ($b2 -and $b2.Document -and $b2.Document.body -and $b2.Document.body.innerHTML.Length -gt 100) { break }
    Start-Sleep -Milliseconds 150
    Wait-WpfEvents
}
$docLen2 = if ($b2 -and $b2.Document -and $b2.Document.body) { $b2.Document.body.innerHTML.Length } else { 0 }
Assert-Test -Name "Search 2 BrowserHtmlView is NOT blank (body > 100)" -Condition ($docLen2 -gt 100) -Details "Body length: $docLen2"

# ==============================================================================
# TEST CASE 3: Third Search in Omnibar -> Third Tab with Rendered Content
# ==============================================================================
Write-Host "`n--- Test 3: Third Search in Omnibar ---" -ForegroundColor Yellow
$user3 = [PSCustomObject]@{
    Name              = "Search User 3"
    SamAccountName    = "suser3"
    DisplayName       = "Search User 3"
    ObjectClass       = "user"
    DistinguishedName = "CN=Search User 3,OU=HR,DC=example,DC=com"
}
$controls['ListGlobalSearchResults'].ItemsSource = @($user3)
$controls['ListGlobalSearchResults'].SelectedItem = $user3
Wait-WpfEvents

$tab3 = $state.OpenTabs | Where-Object { $_.Id -eq $state.ActiveTabId } | Select-Object -First 1
Assert-Test -Name "Search 3 opens third active HtmlView tab" -Condition ($tab3 -and $tab3.PanelName -eq "HtmlView" -and $tab3.Id -ne $tab2.Id -and $tab3.Id -ne $tab1.Id)
Assert-Test -Name "Search 3 tab title is 'Dossier: Search User 3'" -Condition ($tab3.Title -eq "Dossier: Search User 3")

$b3 = if ($tab3.DockedPanelControls) { $tab3.DockedPanelControls['BrowserHtmlView'] } else { $controls['BrowserHtmlView'] }
for ($w = 0; $w -lt 5; $w++) {
    if ($b3 -and $b3.Document -and $b3.Document.body -and $b3.Document.body.innerHTML.Length -gt 100) { break }
    Start-Sleep -Milliseconds 150
    Wait-WpfEvents
}
$docLen3 = if ($b3 -and $b3.Document -and $b3.Document.body) { $b3.Document.body.innerHTML.Length } else { 0 }
Assert-Test -Name "Search 3 BrowserHtmlView is NOT blank (body > 100)" -Condition ($docLen3 -gt 100) -Details "Body length: $docLen3"

# ==============================================================================
# TEST CASE 4: Tab Switching Preserves All Dossiers Without Blank View
# ==============================================================================
Write-Host "`n--- Test 4: Switching Back to Search 1 Tab ---" -ForegroundColor Yellow
Select-WorkspaceTab -TabId $tab1.Id
Wait-WpfEvents

$b1Switched = if ($tab1.DockedPanelControls) { $tab1.DockedPanelControls['BrowserHtmlView'] } else { $controls['BrowserHtmlView'] }
for ($w = 0; $w -lt 5; $w++) {
    if ($b1Switched -and $b1Switched.Document -and $b1Switched.Document.body -and $b1Switched.Document.body.innerHTML.Length -gt 100) { break }
    Start-Sleep -Milliseconds 150
    Wait-WpfEvents
}
$docLen1Switched = if ($b1Switched -and $b1Switched.Document -and $b1Switched.Document.body) { $b1Switched.Document.body.innerHTML.Length } else { 0 }
Assert-Test -Name "Search 1 tab after switch back is NOT blank (body > 100)" -Condition ($docLen1Switched -gt 100) -Details "Body length: $docLen1Switched"

Write-Host "`n--- Test 5: Switching Back to Search 2 Tab ---" -ForegroundColor Yellow
Select-WorkspaceTab -TabId $tab2.Id
Wait-WpfEvents

$b2Switched = if ($tab2.DockedPanelControls) { $tab2.DockedPanelControls['BrowserHtmlView'] } else { $controls['BrowserHtmlView'] }
for ($w = 0; $w -lt 5; $w++) {
    if ($b2Switched -and $b2Switched.Document -and $b2Switched.Document.body -and $b2Switched.Document.body.innerHTML.Length -gt 100) { break }
    Start-Sleep -Milliseconds 150
    Wait-WpfEvents
}
$docLen2Switched = if ($b2Switched -and $b2Switched.Document -and $b2Switched.Document.body) { $b2Switched.Document.body.innerHTML.Length } else { 0 }
Assert-Test -Name "Search 2 tab after switch back is NOT blank (body > 100)" -Condition ($docLen2Switched -gt 100) -Details "Body length: $docLen2Switched"

try { $window.Close() } catch { $null = $_ }

Write-Host "`n================================================================" -ForegroundColor Cyan
Write-Host "   RESULTS SUMMARY" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "Total Passed: $passCount" -ForegroundColor Green
Write-Host "Total Failed: $failCount" -ForegroundColor $(if ($failCount -eq 0) { "Green" } else { "Red" })

if ($failCount -gt 0) {
    exit 1
} else {
    exit 0
}
