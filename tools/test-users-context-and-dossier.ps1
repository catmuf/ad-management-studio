[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
[CmdletBinding()]
param()

$projectRoot = (Get-Location).Path
$ErrorActionPreference = "Continue"

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "   TESTING USERS CONTEXT MENU PARITY & AUTO HTML DOSSIER" -ForegroundColor Cyan
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
        [PSCustomObject]@{ Name = "cn"; Value = "Test User"; Type = "String"; IsOperational = $false },
        [PSCustomObject]@{ Name = "sAMAccountName"; Value = "testuser"; Type = "String"; IsOperational = $false },
        [PSCustomObject]@{ Name = "distinguishedName"; Value = "CN=Test User,OU=Finance,DC=example,DC=com"; Type = "String"; IsOperational = $false },
        [PSCustomObject]@{ Name = "mail"; Value = "testuser@example.com"; Type = "String"; IsOperational = $false }
    )
}

function global:Get-ADUserDetail {
    param($Identity)
    $null = $Identity
    $u = [PSCustomObject]@{
        SamAccountName    = "testuser"
        DisplayName       = "Test User"
        DistinguishedName = "CN=Test User,OU=Finance,DC=example,DC=com"
        Enabled           = $true
        LockedOut         = $false
        Mail              = "testuser@example.com"
        Department        = "Finance"
        Title             = "Analyst"
        OUPath            = "example.com/Finance"
    }
    return [PSCustomObject]@{
        User   = $u
        Groups = @([PSCustomObject]@{ Name = "Finance Users"; DistinguishedName = "CN=Finance Users,OU=Groups,DC=example,DC=com" })
    }
}

function global:Find-ADObjectsQuickSearch {
    param($Query, [int]$MaxResults = 10)
    $null = $Query; $null = $MaxResults
    return @(
        [PSCustomObject]@{
            Name              = "Test User"
            SamAccountName    = "testuser"
            DisplayName       = "Test User"
            ObjectClass       = "user"
            DistinguishedName = "CN=Test User,OU=Finance,DC=example,DC=com"
        }
    )
}

# Load main.ps1 offscreen
$mainScript = Get-Content (Join-Path $projectRoot "main.ps1") -Raw -Encoding utf8
$mainScriptOffscreen = $mainScript -replace '\[void\]\$window\.ShowDialog\(\)', '$window.WindowStartupLocation = [System.Windows.WindowStartupLocation]::Manual; $window.Left = -32000; $window.Top = -32000; $window.Show()'

. ([scriptblock]::Create($mainScriptOffscreen))

function Wait-WpfEvents {
    try {
        [System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Background, (New-Object System.Threading.CancellationToken), (New-Object System.TimeSpan(0, 0, 0, 0, 200)))
    } catch {
        $null = $_
    }
}

Wait-WpfEvents
Write-Host "MainWindow loaded offscreen successfully." -ForegroundColor Green

$passCount = 0
$failCount = 0

function Assert-Test {
    param([string]$Name, [bool]$Condition, [string]$Details = "")
    if ($Condition) {
        Write-Host "  [PASS] $Name" -ForegroundColor Green
        $script:passCount++
    } else {
        Write-Host "  [FAIL] $($Name): $Details" -ForegroundColor Red
        $script:failCount++
    }
}

$testUserObj = [PSCustomObject]@{
    SamAccountName    = "testuser"
    DisplayName       = "Test User"
    DistinguishedName = "CN=Test User,OU=Finance,DC=example,DC=com"
    Enabled           = $true
    LockedOut         = $false
    Mail              = "testuser@example.com"
    Department        = "Finance"
    Title             = "Analyst"
    OUPath            = "example.com/Finance"
}

# ==============================================================================
# TEST CASE 1: Primary Tab 1 Users Context Menu All 24 Options
# ==============================================================================
Write-Host "`n--- Test Case 1: Primary Tab 1 Users Context Menu (24 Items) ---" -ForegroundColor Yellow

Add-WorkspaceTab -PanelName "Users" -Activate $true
Wait-WpfEvents
$controls['GridUsers'].ItemsSource = @($testUserObj)
$controls['GridUsers'].SelectedItem = $testUserObj

$userMenuItems = @(
    "CtxUserEdit", "CtxUserRename", "CtxUserResetPwd", "CtxUserUnlock",
    "CtxUserToggleStatus", "CtxUserMoveOU", "CtxUserDelete", "CtxUserLocateInTree",
    "CtxUserCopyDN", "CtxUserCopyRdn", "CtxUserCopyCanonical", "CtxUserCopySam",
    "CtxUserCopyUrl", "CtxUserCopyLdif", "CtxUserAddToBasket", "CtxUserAddToBookmarks",
    "CtxUserInspectAttr", "CtxUserCompare", "CtxUserViewDetails", "CtxUserViewHtml",
    "CtxUserOpenBrowser", "CtxUserExternalTools", "CtxUserUseWithAcl",
    "CtxUserUseWithTokenSize", "CtxUserUseWithLockout", "CtxUserUseWithReplication",
    "CtxUserUseWithResolver", "CtxUserCopyToDetached"
)

foreach ($mName in $userMenuItems) {
    $item = $controls[$mName]
    Assert-Test -Name "Tab 1 Primary MenuItem '$mName' exists" -Condition ($null -ne $item)
}

# Test previously broken functions on Tab 1
try {
    # Test CtxUserResetPwd
    $dlgOpened = $false
    # Mock Open-PasswordDialog to verify it gets called cleanly
    $origPwdDlg = ${function:Open-PasswordDialog}
    ${function:Open-PasswordDialog} = { param($User) $script:dlgOpened = ($User.SamAccountName -eq "testuser") }
    $controls['CtxUserResetPwd'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.MenuItem]::ClickEvent))
    Assert-Test -Name "Tab 1 CtxUserResetPwd correctly calls Open-PasswordDialog" -Condition $dlgOpened
    ${function:Open-PasswordDialog} = $origPwdDlg
} catch {
    Assert-Test -Name "Tab 1 CtxUserResetPwd failed with exception" -Condition $false -Details "$_"
}

try {
    # Test CtxUserMoveOU
    $moveCalled = $false
    $origMove = ${function:Open-MoveDialog}
    ${function:Open-MoveDialog} = { param($Principal, $Type) $script:moveCalled = ($Principal.SamAccountName -eq "testuser" -and $Type -eq "User") }
    $controls['CtxUserMoveOU'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.MenuItem]::ClickEvent))
    Assert-Test -Name "Tab 1 CtxUserMoveOU correctly calls Open-MoveDialog" -Condition $moveCalled
    ${function:Open-MoveDialog} = $origMove
} catch {
    Assert-Test -Name "Tab 1 CtxUserMoveOU failed with exception" -Condition $false -Details "$_"
}

try {
    # Test CtxUserViewDetails
    $detailsCalled = $false
    $origDetails = ${function:Open-UserDetailDialog}
    ${function:Open-UserDetailDialog} = { param($User) $script:detailsCalled = ($User.SamAccountName -eq "testuser") }
    $controls['CtxUserViewDetails'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.MenuItem]::ClickEvent))
    Assert-Test -Name "Tab 1 CtxUserViewDetails correctly calls Open-UserDetailDialog" -Condition $detailsCalled
    ${function:Open-UserDetailDialog} = $origDetails
} catch {
    Assert-Test -Name "Tab 1 CtxUserViewDetails failed with exception" -Condition $false -Details "$_"
}

try {
    # Test CtxUserCopyDN
    $copiedText = ""
    $origClip = ${function:Set-AppClipboardText}
    ${function:Set-AppClipboardText} = { param($Text) $script:copiedText = $Text }
    $controls['CtxUserCopyDN'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.MenuItem]::ClickEvent))
    Assert-Test -Name "Tab 1 CtxUserCopyDN copied DN to clipboard" -Condition ($copiedText -eq $testUserObj.DistinguishedName)
    ${function:Set-AppClipboardText} = $origClip
} catch {
    Assert-Test -Name "Tab 1 CtxUserCopyDN threw exception" -Condition $false -Details "$_"
}

# ==============================================================================
# TEST CASE 2: Secondary Tab 2 Users Context Menu (Users (2) Cloned Instance)
# ==============================================================================
Write-Host "`n--- Test Case 2: Secondary Tab 2 Users Context Menu (Multi-Instance Parity) ---" -ForegroundColor Yellow

Add-WorkspaceTab -PanelName "Users" -NewInstance -Activate $true
Wait-WpfEvents

$tab2 = $state.OpenTabs | Where-Object { $_.Id -eq $state.ActiveTabId } | Select-Object -First 1
Assert-Test -Name "Tab 2 (Users (2)) created and active" -Condition ($tab2 -and $tab2.PanelName -eq "Users")

$c2 = $tab2.DockedPanelControls
Assert-Test -Name "Tab 2 DockedPanelControls available" -Condition ($null -ne $c2)

$grid2 = $c2['GridUsers']
Assert-Test -Name "Tab 2 GridUsers available" -Condition ($null -ne $grid2)

$grid2.ItemsSource = @($testUserObj)
$grid2.SelectedItem = $testUserObj

foreach ($mName in $userMenuItems) {
    $item = $c2[$mName]
    Assert-Test -Name "Tab 2 Cloned MenuItem '$mName' exists" -Condition ($null -ne $item)
}

# Test actions on secondary panel Tab 2
try {
    $dlgOpened2 = $false
    $origPwdDlg = ${function:Open-PasswordDialog}
    ${function:Open-PasswordDialog} = { param($User) $script:dlgOpened2 = ($User.SamAccountName -eq "testuser") }
    $c2['CtxUserResetPwd'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.MenuItem]::ClickEvent))
    Assert-Test -Name "Tab 2 CtxUserResetPwd correctly executes Open-PasswordDialog" -Condition $dlgOpened2
    ${function:Open-PasswordDialog} = $origPwdDlg
} catch {
    Assert-Test -Name "Tab 2 CtxUserResetPwd failed with exception" -Condition $false -Details "$_"
}

try {
    $moveCalled2 = $false
    $origMove = ${function:Open-MoveDialog}
    ${function:Open-MoveDialog} = { param($Principal, $Type) $script:moveCalled2 = ($Principal.SamAccountName -eq "testuser" -and $Type -eq "User") }
    $c2['CtxUserMoveOU'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.MenuItem]::ClickEvent))
    Assert-Test -Name "Tab 2 CtxUserMoveOU correctly executes Open-MoveDialog" -Condition $moveCalled2
    ${function:Open-MoveDialog} = $origMove
} catch {
    Assert-Test -Name "Tab 2 CtxUserMoveOU failed with exception" -Condition $false -Details "$_"
}

try {
    $detailsCalled2 = $false
    $origDetails = ${function:Open-UserDetailDialog}
    ${function:Open-UserDetailDialog} = { param($User) $script:detailsCalled2 = ($User.SamAccountName -eq "testuser") }
    $c2['CtxUserViewDetails'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.MenuItem]::ClickEvent))
    Assert-Test -Name "Tab 2 CtxUserViewDetails correctly executes Open-UserDetailDialog" -Condition $detailsCalled2
    ${function:Open-UserDetailDialog} = $origDetails
} catch {
    Assert-Test -Name "Tab 2 CtxUserViewDetails failed with exception" -Condition $false -Details "$_"
}

try {
    $deleteCalled2 = $false
    $origDelete = ${function:Remove-UserAction}
    ${function:Remove-UserAction} = { param($TargetUser) $script:deleteCalled2 = ($TargetUser.SamAccountName -eq "testuser") }
    $c2['CtxUserDelete'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.MenuItem]::ClickEvent))
    Assert-Test -Name "Tab 2 CtxUserDelete passes secondary selected user" -Condition $deleteCalled2
    ${function:Remove-UserAction} = $origDelete
} catch {
    Assert-Test -Name "Tab 2 CtxUserDelete failed with exception" -Condition $false -Details "$_"
}

# ==============================================================================
# TEST CASE 3: Global Omnibar Search -> Automatic HTML Dossier Rendering
# ==============================================================================
Write-Host "`n--- Test Case 3: Global Search Omnibar -> Instant HTML Dossier ---" -ForegroundColor Yellow

# Set up Omnibar search item
$searchResultObj = [PSCustomObject]@{
    Name              = "Test User"
    SamAccountName    = "testuser"
    DisplayName       = "Test User"
    ObjectClass       = "user"
    DistinguishedName = "CN=Test User,OU=Finance,DC=example,DC=com"
}

$controls['ListGlobalSearchResults'].ItemsSource = @($searchResultObj)
# Trigger item selection as user does by clicking item in search dropdown
$controls['ListGlobalSearchResults'].SelectedItem = $searchResultObj
Wait-WpfEvents

$activeTab = $state.OpenTabs | Where-Object { $_.Id -eq $state.ActiveTabId } | Select-Object -First 1
Assert-Test -Name "Omnibar selection opens and activates HtmlView tab" -Condition ($activeTab -and $activeTab.PanelName -eq "HtmlView")

# Verify HTML Dossier content is rendered IMMEDIATELY without pressing "Go"
$renderedHtml = if ($activeTab.State -and $activeTab.State.ContainsKey('CurrentHtmlRaw')) { $activeTab.State['CurrentHtmlRaw'] } else { "" }
Assert-Test -Name "HTML Dossier raw markup is populated immediately" -Condition (-not [string]::IsNullOrEmpty($renderedHtml) -and $renderedHtml.Length -gt 100) -Details "Html length: $($renderedHtml.Length)"

Assert-Test -Name "HTML Dossier DN is populated on tab state" -Condition ($activeTab.State['CurrentHtmlDN'] -eq $searchResultObj.DistinguishedName)

$dControls = if ($activeTab.DockedPanelControls) { $activeTab.DockedPanelControls } else { $controls }
Assert-Test -Name "TxtHtmlViewDN is set on active controls" -Condition ($dControls['TxtHtmlViewDN'].Text -eq $searchResultObj.DistinguishedName)
Assert-Test -Name "TxtHtmlViewStatusBadge displays object name" -Condition ($dControls['TxtHtmlViewStatusBadge'].Text -eq "Test User")

# Verify tab title is updated
Assert-Test -Name "Tab title updated to 'Dossier: Test User'" -Condition ($activeTab.Title -eq "Dossier: Test User")

# ==============================================================================
# TEST CASE 4: Tab Switching Preserves Rendered HTML Dossier Without Wiping
# ==============================================================================
Write-Host "`n--- Test Case 4: Session State Preservation Across Tab Switching ---" -ForegroundColor Yellow

# Switch to Users Tab 1
$tab1 = $state.OpenTabs | Where-Object { $_.PanelName -eq "Users" } | Select-Object -First 1
Select-WorkspaceTab -TabId $tab1.Id
Wait-WpfEvents
Assert-Test -Name "Switched away to Users tab" -Condition ($state.ActiveTabId -eq $tab1.Id)

# Switch back to Dossier tab
Select-WorkspaceTab -TabId $activeTab.Id
Wait-WpfEvents
Assert-Test -Name "Switched back to Dossier tab" -Condition ($state.ActiveTabId -eq $activeTab.Id)

# Verify HTML state is still intact
$persistedHtml = $activeTab.State['CurrentHtmlRaw']
Assert-Test -Name "HTML Dossier content preserved after switching back" -Condition (-not [string]::IsNullOrEmpty($persistedHtml) -and $persistedHtml.Length -gt 100)

# ==============================================================================
# TEST CASE 5: Secondary Groups & Computers Context Menu Parity
# ==============================================================================
Write-Host "`n--- Test Case 5: Groups and Computers Secondary Context Menu Parity ---" -ForegroundColor Yellow

Add-WorkspaceTab -PanelName "Groups" -Activate $false
Add-WorkspaceTab -PanelName "Groups" -NewInstance -Activate $true
Wait-WpfEvents
$grpTab2 = $state.OpenTabs | Where-Object { $_.Id -eq $state.ActiveTabId } | Select-Object -First 1
Assert-Test -Name "Groups (2) tab created and active" -Condition ($grpTab2 -and $grpTab2.PanelName -eq "Groups" -and $grpTab2.InstanceNumber -gt 1)

$grpCtrls2 = $grpTab2.DockedPanelControls
Assert-Test -Name "Groups (2) DockedPanelControls available" -Condition ($null -ne $grpCtrls2)

$grpMenuItems = @(
    "CtxGroupManageMembers", "CtxGroupRename", "CtxGroupMoveOU", "CtxGroupDelete",
    "CtxGroupCopyDN", "CtxGroupCopyRdn", "CtxGroupCopyCanonical", "CtxGroupCopyUrl",
    "CtxGroupCopyLdif", "CtxGroupAddToBasket", "CtxGroupLocateInTree", "CtxGroupInspectAttr",
    "CtxGroupCompare", "CtxGroupViewHtml", "CtxGroupOpenBrowser", "CtxGroupUseWithAcl"
)
foreach ($m in $grpMenuItems) {
    Assert-Test -Name "Groups (2) MenuItem '$m' exists" -Condition ($grpCtrls2 -and ($null -ne $grpCtrls2[$m]))
}

Add-WorkspaceTab -PanelName "Computers" -Activate $false
Add-WorkspaceTab -PanelName "Computers" -NewInstance -Activate $true
Wait-WpfEvents
$compTab2 = $state.OpenTabs | Where-Object { $_.Id -eq $state.ActiveTabId } | Select-Object -First 1
Assert-Test -Name "Computers (2) tab created and active" -Condition ($compTab2 -and $compTab2.PanelName -eq "Computers" -and $compTab2.InstanceNumber -gt 1)

$compCtrls2 = $compTab2.DockedPanelControls
Assert-Test -Name "Computers (2) DockedPanelControls available" -Condition ($null -ne $compCtrls2)

$compMenuItems = @(
    "CtxCompRdp", "CtxCompPing", "CtxCompRename", "CtxCompCopyDN", "CtxCompCopyName",
    "CtxCompCopyRdn", "CtxCompCopyCanonical", "CtxCompCopyLdif", "CtxCompAddToBasket",
    "CtxCompLocateInTree", "CtxCompInspectAttr", "CtxCompCompare", "CtxCompViewHtml",
    "CtxCompOpenBrowser", "CtxCompExternalTools", "CtxCompUseWithAcl", "CtxCompUseWithSpn"
)
foreach ($m in $compMenuItems) {
    Assert-Test -Name "Computers (2) MenuItem '$m' exists" -Condition ($compCtrls2 -and ($null -ne $compCtrls2[$m]))
}

# ==============================================================================
# FINAL RESULTS SUMMARY
# ==============================================================================
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
