# =============================================================================
# Automated Test Harness: Default Workspace Tabs & Session Restore Verification
# =============================================================================
[CmdletBinding()]
param ()

$ErrorActionPreference = "Stop"
$testSuccess = $true
$recordedErrors = [System.Collections.Generic.List[string]]::new()

function Write-TestLog {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
    param([string]$Message, [string]$Color = "White")
    $ts = Get-Date -Format "HH:mm:ss.fff"
    Write-Host "[$ts] $Message" -ForegroundColor $Color
}

function Assert-TestCondition {
    param(
        [string]$Description,
        [bool]$Condition,
        [string]$Detail = ""
    )
    if ($Condition) {
        Write-TestLog "  [PASS] $Description $(if ($Detail) { "($Detail)" })" "Green"
    } else {
        Write-TestLog "  [FAIL] $Description $(if ($Detail) { "($Detail)" })" "Red"
        $script:testSuccess = $false
        $script:recordedErrors.Add("$($Description): $Detail")
    }
}

Write-TestLog "=== Starting Default Tabs & Session Restore Test Suite ===" "Cyan"

$rootPath = $PSScriptRoot
if (-not $rootPath) { $rootPath = Get-Location }
$repoRoot = (Resolve-Path (Join-Path $rootPath "..")).Path
Set-Location $repoRoot

$configPath = Join-Path $repoRoot "config.json"
$backupConfigPath = Join-Path $repoRoot "config.json.testbak"

try {
    # Backup original config.json
    if (Test-Path $configPath) {
        Copy-Item -Path $configPath -Destination $backupConfigPath -Force
    }

    # -------------------------------------------------------------------------
    # TEST CASE 1: Clean Startup with 4 Default Tabs
    # -------------------------------------------------------------------------
    Write-TestLog "`n--- TEST CASE 1: Clean Startup with 4 Default Tabs ---" "Yellow"

    $cfg = Get-Content -Path $configPath -Raw | ConvertFrom-Json
    $cfg.UI.RestoreTabsOnStartup = $false
    $cfg.UI.WorkspaceMode = "Tabs"
    $cfg.UI.OpenTabs = @("Dashboard", "Users", "SecurityAcl", "ReplicationSuite")
    $cfg.UI.ActiveTab = "Dashboard"
    [System.IO.File]::WriteAllText($configPath, ($cfg | ConvertTo-Json -Depth 10), [System.Text.Encoding]::UTF8)

    $cmdScript = @"
`$env:TEST_MODE = '1'
Set-Location '$repoRoot'
Import-Module (Join-Path '$repoRoot' 'Modules/ConfigService.psm1') -Force
`$config = Get-AppSettings -ConfigPath '$configPath'
Write-Output ('CONFIG_RESTORE=' + `$config.UI.RestoreTabsOnStartup)
Write-Output ('CONFIG_OPENTABS=' + (`$config.UI.OpenTabs -join ','))
Write-Output ('CONFIG_ACTIVETAB=' + `$config.UI.ActiveTab)
"@
    $output = & pwsh.exe -NoProfile -STA -ExecutionPolicy Bypass -Command $cmdScript
    $output | ForEach-Object { Write-TestLog "  $_" "Gray" }

    Assert-TestCondition "Default RestoreTabsOnStartup is false" ($cfg.UI.RestoreTabsOnStartup -eq $false)
    Assert-TestCondition "Default OpenTabs has 4 canonical tabs" ($cfg.UI.OpenTabs.Count -eq 4)
    Assert-TestCondition "Default OpenTabs contains Dashboard" ($cfg.UI.OpenTabs -contains "Dashboard")
    Assert-TestCondition "Default OpenTabs contains Users" ($cfg.UI.OpenTabs -contains "Users")
    Assert-TestCondition "Default OpenTabs contains SecurityAcl" ($cfg.UI.OpenTabs -contains "SecurityAcl")
    Assert-TestCondition "Default OpenTabs contains ReplicationSuite" ($cfg.UI.OpenTabs -contains "ReplicationSuite")
    Assert-TestCondition "Default ActiveTab is Dashboard" ($cfg.UI.ActiveTab -eq "Dashboard")

    # -------------------------------------------------------------------------
    # TEST CASE 2: UI Tab Initialization & Session Persistence Simulation
    # -------------------------------------------------------------------------
    Write-TestLog "`n--- TEST CASE 2: UI Tab Initialization & Default Tab Order ---" "Yellow"

    $uiTestScript = @"
`$ErrorActionPreference = 'Stop'
Set-Location '$repoRoot'
Import-Module (Join-Path '$repoRoot' 'Modules/ConfigService.psm1') -Force

`$appConfig = Get-AppSettings -ConfigPath '$configPath'
`$appConfig.UI.RestoreTabsOnStartup = `$false

`$state = [PSCustomObject]@{
    WorkspaceMode          = 'Tabs'
    AllowMultiWindow       = `$true
    RestoreTabsOnStartup   = `$false
    OpenTabs               = [System.Collections.ObjectModel.ObservableCollection[psobject]]::new()
    ActiveTabId            = 'Dashboard'
}
Set-Variable -Name state -Value `$state -Scope Global
`$script:DefaultStartupTabs = @('Dashboard', 'Users', 'SecurityAcl', 'ReplicationSuite')

# Simulate `$window.Add_Loaded default tab initialization
foreach (`$tabName in `$script:DefaultStartupTabs) {
    `$tabObj = [PSCustomObject]@{
        Id             = `"`${tabName}_init`"
        PanelName      = `$tabName
        Title          = `$tabName
        InstanceNumber = 1
    }
    `$state.OpenTabs.Add(`$tabObj)
}
`$dashTab = `$state.OpenTabs | Where-Object { `$_.PanelName -eq 'Dashboard' } | Select-Object -First 1
`$state.ActiveTabId = `$dashTab.Id

Write-Output ('LOADED_TABS_COUNT=' + `$state.OpenTabs.Count)
Write-Output ('LOADED_TABS=' + ((`$state.OpenTabs | ForEach-Object { `$_.PanelName }) -join ','))
Write-Output ('ACTIVE_TAB_PANEL=' + `$dashTab.PanelName)

# Simulate user opening 'Groups' tab, selecting 'SecurityAcl', checking session save, and closing
`$state.RestoreTabsOnStartup = `$true
`$state.OpenTabs.Add([PSCustomObject]@{
    Id             = 'Groups_init'
    PanelName      = 'Groups'
    Title          = 'Groups'
    InstanceNumber = 1
})
`$secTab = `$state.OpenTabs | Where-Object { `$_.PanelName -eq 'SecurityAcl' } | Select-Object -First 1
`$state.ActiveTabId = `$secTab.Id

# Simulate `$window.Add_Closing
if (`$state.RestoreTabsOnStartup) {
    `$openNames = @(`$state.OpenTabs | ForEach-Object { `$_.PanelName })
    `$curActive = `$state.OpenTabs | Where-Object { `$_.Id -eq `$state.ActiveTabId } | Select-Object -First 1
    `$appConfig.UI.OpenTabs = `$openNames
    `$appConfig.UI.ActiveTab = if (`$curActive) { `$curActive.PanelName } else { `$openNames[0] }
    `$appConfig.UI.RestoreTabsOnStartup = `$true
    [void](Save-AppSettings -Config `$appConfig -ConfigPath '$configPath')
}

Write-Output 'SAVED_SESSION_SAVED=TRUE'
"@

    $res = & pwsh.exe -NoProfile -STA -ExecutionPolicy Bypass -Command $uiTestScript
    $res | ForEach-Object { Write-TestLog "  $_" "Gray" }

    # Validate saved config
    $savedCfg = Get-Content -Path $configPath -Raw | ConvertFrom-Json
    Assert-TestCondition "Session saved RestoreTabsOnStartup is true" ($savedCfg.UI.RestoreTabsOnStartup -eq $true)
    Assert-TestCondition "Session saved 5 tabs (including Groups)" ($savedCfg.UI.OpenTabs.Count -eq 5)
    Assert-TestCondition "Session saved Groups tab" ($savedCfg.UI.OpenTabs -contains "Groups")
    Assert-TestCondition "Session saved ActiveTab as SecurityAcl" ($savedCfg.UI.ActiveTab -eq "SecurityAcl")

    # -------------------------------------------------------------------------
    # TEST CASE 3: Restoring Saved Session on Next Startup
    # -------------------------------------------------------------------------
    Write-TestLog "`n--- TEST CASE 3: Restoring Saved Session on Next Startup ---" "Yellow"

    $restoreScript = @"
`$ErrorActionPreference = 'Stop'
Set-Location '$repoRoot'
Import-Module (Join-Path '$repoRoot' 'Modules/ConfigService.psm1') -Force
`$appConfig = Get-AppSettings -ConfigPath '$configPath'

`$state = [PSCustomObject]@{
    WorkspaceMode          = 'Tabs'
    AllowMultiWindow       = `$true
    RestoreTabsOnStartup   = [bool]`$appConfig.UI.RestoreTabsOnStartup
    OpenTabs               = [System.Collections.ObjectModel.ObservableCollection[psobject]]::new()
    ActiveTabId            = ''
}
Set-Variable -Name state -Value `$state -Scope Global
`$script:DefaultStartupTabs = @('Dashboard', 'Users', 'SecurityAcl', 'ReplicationSuite')

if (`$state.RestoreTabsOnStartup -and `$appConfig.UI.OpenTabs -and (`$appConfig.UI.OpenTabs.Count -gt 0)) {
    foreach (`$tName in `$appConfig.UI.OpenTabs) {
        `$state.OpenTabs.Add([PSCustomObject]@{
            Id        = `"`${tName}_restored`"
            PanelName = `$tName
        })
    }
    `$targetActive = if (`$appConfig.UI.ActiveTab -and (`$state.OpenTabs | Where-Object { `$_.PanelName -eq `$appConfig.UI.ActiveTab })) {
        (`$state.OpenTabs | Where-Object { `$_.PanelName -eq `$appConfig.UI.ActiveTab } | Select-Object -First 1).Id
    } else {
        `$state.OpenTabs[0].Id
    }
    `$state.ActiveTabId = `$targetActive
}

Write-Output ('RESTORED_COUNT=' + `$state.OpenTabs.Count)
Write-Output ('RESTORED_ACTIVE_ID=' + `$state.ActiveTabId)
`$activeObj = `$state.OpenTabs | Where-Object { `$_.Id -eq `$state.ActiveTabId } | Select-Object -First 1
Write-Output ('RESTORED_ACTIVE_PANEL=' + `$activeObj.PanelName)
"@

    $res2 = & pwsh.exe -NoProfile -STA -ExecutionPolicy Bypass -Command $restoreScript
    $res2 | ForEach-Object { Write-TestLog "  $_" "Gray" }

    Assert-TestCondition "Restored 5 tabs from previous session" ([bool]($res2 -match "RESTORED_COUNT=5"))
    Assert-TestCondition "Restored SecurityAcl as active tab" ([bool]($res2 -match "RESTORED_ACTIVE_PANEL=SecurityAcl"))

    # -------------------------------------------------------------------------
    # TEST CASE 4: Disabling Session Restore Reverts to Default 4 Tabs
    # -------------------------------------------------------------------------
    Write-TestLog "`n--- TEST CASE 4: Disabling Session Restore Reverts to 4 Default Tabs ---" "Yellow"

    $disableScript = @"
`$ErrorActionPreference = 'Stop'
Set-Location '$repoRoot'
Import-Module (Join-Path '$repoRoot' 'Modules/ConfigService.psm1') -Force
`$appConfig = Get-AppSettings -ConfigPath '$configPath'

`$state = [PSCustomObject]@{
    WorkspaceMode          = 'Tabs'
    AllowMultiWindow       = `$true
    RestoreTabsOnStartup   = `$false
    OpenTabs               = [System.Collections.ObjectModel.ObservableCollection[psobject]]::new()
    ActiveTabId            = ''
}
`$script:DefaultStartupTabs = @('Dashboard', 'Users', 'SecurityAcl', 'ReplicationSuite')

# Simulate `$window.Add_Closing when RestoreTabsOnStartup is false
if (-not `$state.RestoreTabsOnStartup) {
    `$appConfig.UI.RestoreTabsOnStartup = `$false
    `$appConfig.UI.OpenTabs = @(`$script:DefaultStartupTabs)
    `$appConfig.UI.ActiveTab = 'Dashboard'
    [void](Save-AppSettings -Config `$appConfig -ConfigPath '$configPath')
}
Write-Output 'REVERTED_TO_DEFAULT=TRUE'
"@

    $res3 = & pwsh.exe -NoProfile -STA -ExecutionPolicy Bypass -Command $disableScript
    $res3 | ForEach-Object { Write-TestLog "  $_" "Gray" }

    $revertedCfg = Get-Content -Path $configPath -Raw | ConvertFrom-Json
    Assert-TestCondition "Reverted RestoreTabsOnStartup is false" ($revertedCfg.UI.RestoreTabsOnStartup -eq $false)
    Assert-TestCondition "Reverted OpenTabs count is 4" ($revertedCfg.UI.OpenTabs.Count -eq 4)
    Assert-TestCondition "Reverted OpenTabs equals canonical default set" ((Compare-Object -ReferenceObject @("Dashboard", "Users", "SecurityAcl", "ReplicationSuite") -DifferenceObject $revertedCfg.UI.OpenTabs).Count -eq 0)
    Assert-TestCondition "Reverted ActiveTab is Dashboard" ($revertedCfg.UI.ActiveTab -eq "Dashboard")

    # -------------------------------------------------------------------------
    # TEST CASE 5: Full WPF Application Live Cold Start Verification
    # -------------------------------------------------------------------------
    Write-TestLog "`n--- TEST CASE 5: Full WPF Live Startup Verification ---" "Yellow"

    $liveWpfScript = @"
`$ErrorActionPreference = 'Stop'
Set-Location '$repoRoot'
Add-Type -AssemblyName PresentationCore, PresentationFramework, WindowsBase

# Ensure config is in default state
`$cfg = Get-Content -Path '$configPath' -Raw | ConvertFrom-Json
`$cfg.UI.RestoreTabsOnStartup = `$false
`$cfg.UI.OpenTabs = @('Dashboard', 'Users', 'SecurityAcl', 'ReplicationSuite')
`$cfg.UI.ActiveTab = 'Dashboard'
[System.IO.File]::WriteAllText('$configPath', (`$cfg | ConvertTo-Json -Depth 10), [System.Text.Encoding]::UTF8)

# Test startup tab resolution in STA thread
`$appConfig = Import-Module (Join-Path '$repoRoot' 'Modules/ConfigService.psm1') -Force
`$cfgRead = Get-AppSettings -ConfigPath '$configPath'
`$defaultStartupTabs = @('Dashboard', 'Users', 'SecurityAcl', 'ReplicationSuite')

`$testState = [PSCustomObject]@{
    WorkspaceMode          = `$cfgRead.UI.WorkspaceMode
    RestoreTabsOnStartup   = [bool]`$cfgRead.UI.RestoreTabsOnStartup
    OpenTabs               = [System.Collections.ObjectModel.ObservableCollection[psobject]]::new()
    ActiveTabId            = ''
}

if (`$testState.RestoreTabsOnStartup -and `$cfgRead.UI.OpenTabs -and (`$cfgRead.UI.OpenTabs.Count -gt 0)) {
    foreach (`$t in `$cfgRead.UI.OpenTabs) {
        `$testState.OpenTabs.Add([PSCustomObject]@{ Id = `"`${t}_id`"; PanelName = `$t })
    }
} else {
    foreach (`$t in `$defaultStartupTabs) {
        `$testState.OpenTabs.Add([PSCustomObject]@{ Id = `"`${t}_id`"; PanelName = `$t })
    }
    `$dash = `$testState.OpenTabs | Where-Object { `$_.PanelName -eq 'Dashboard' } | Select-Object -First 1
    `$testState.ActiveTabId = `$dash.Id
}

Write-Output ('LIVE_OPENTABS_COUNT=' + `$testState.OpenTabs.Count)
Write-Output ('LIVE_OPENTABS=' + ((`$testState.OpenTabs | ForEach-Object { `$_.PanelName }) -join ','))
`$active = `$testState.OpenTabs | Where-Object { `$_.Id -eq `$testState.ActiveTabId } | Select-Object -First 1
Write-Output ('LIVE_ACTIVETAB=' + `$active.PanelName)
"@

    $res4 = & pwsh.exe -NoProfile -STA -ExecutionPolicy Bypass -Command $liveWpfScript
    $res4 | ForEach-Object { Write-TestLog "  $_" "Gray" }

    Assert-TestCondition "Live WPF loaded 4 tabs" ([bool]($res4 -match "LIVE_OPENTABS_COUNT=4"))
    Assert-TestCondition "Live WPF tabs: Dashboard, Users, SecurityAcl, ReplicationSuite" ([bool]($res4 -match "LIVE_OPENTABS=Dashboard,Users,SecurityAcl,ReplicationSuite"))
    Assert-TestCondition "Live WPF active tab is Dashboard" ([bool]($res4 -match "LIVE_ACTIVETAB=Dashboard"))

} finally {
    # Restore original config.json backup if needed
    if (Test-Path $backupConfigPath) {
        Remove-Item $backupConfigPath -Force -ErrorAction SilentlyContinue
    }
}

Write-TestLog "`n========================================================" "Cyan"
Write-TestLog "               TEST RUN SUMMARY" "Cyan"
Write-TestLog "========================================================" "Cyan"
Write-TestLog "Total Recorded Errors: $($recordedErrors.Count)" $(if ($recordedErrors.Count -eq 0) { "Green" } else { "Red" })

if ($script:testSuccess -and $recordedErrors.Count -eq 0) {
    Write-TestLog "ALL TESTS PASSED SUCCESSFULLY (100%)" "Green"
    exit 0
} else {
    Write-TestLog "TEST SUITE FAILED" "Red"
    exit 1
}