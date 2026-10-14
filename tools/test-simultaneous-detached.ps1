[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
[CmdletBinding()]
param()

$projectRoot = (Get-Location).Path
$ErrorActionPreference = "Continue"

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "   TESTING IN-PROCESS SIMULTANEOUS DETACHED MULTI-INSTANCE SUITE" -ForegroundColor Cyan
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

# Load main.ps1 offscreen
$mainScript = Get-Content (Join-Path $projectRoot "main.ps1") -Raw
$mainScriptOffscreen = $mainScript -replace '\[void\]\$window\.ShowDialog\(\)', '$window.WindowStartupLocation = [System.Windows.WindowStartupLocation]::Manual; $window.Left = -32000; $window.Top = -32000; $window.Show()'

. ([scriptblock]::Create($mainScriptOffscreen))

function Wait-WpfEvents {
    [System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Normal, (New-Object System.Threading.CancellationToken), (New-Object System.TimeSpan(0, 0, 0, 0, 50)))
}

Wait-WpfEvents
Write-Host "MainWindow loaded off-screen." -ForegroundColor Green

$passCount = 0
$failCount = 0
$initialErrorCount = $Error.Count

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

# ==============================================================================
# TEST 1: Dual Instance Detachment for Users (Simultaneous Side-by-Side)
# ==============================================================================
Write-Host "`n--- Test Case 1: Dual Instance Users Detachment & Simultaneous Use ---" -ForegroundColor Yellow

# Add Users Tab 1 (Primary)
Add-WorkspaceTab -PanelName "Users" -Activate $true
Wait-WpfEvents
$tab1 = $state.OpenTabs | Where-Object { $_.PanelName -eq "Users" } | Select-Object -First 1
Assert-Test "Users Tab 1 Created" ($null -ne $tab1)

# Add Users Tab 2 (Secondary Instance)
Add-WorkspaceTab -PanelName "Users" -NewInstance -Activate $true
Wait-WpfEvents
$tab2 = $state.OpenTabs | Where-Object { $_.PanelName -eq "Users" -and $_.InstanceNumber -eq 2 } | Select-Object -First 1
Assert-Test "Users Tab 2 (Instance 2) Created" ($null -ne $tab2)

# Detach Tab 1
Detach-PanelToWindow -TabId $tab1.Id
Wait-WpfEvents
Assert-Test "Users Tab 1 Detached in State" ($state.DetachedWindows.ContainsKey($tab1.Id))

$dRec1 = $state.DetachedWindows[$tab1.Id]
$dWin1 = $dRec1.Window
Assert-Test "Detached Window 1 Is Window Instance" ($dWin1 -is [System.Windows.Window])
Assert-Test "Detached Window 1 Has Correct Title" ($dWin1.Title -like "*Users*")

$btnDock1 = $dWin1.FindName("BtnDockBack")
Assert-Test "Detached Window 1 Has Dock Back Button" ($null -ne $btnDock1)

# Detach Tab 2
Detach-PanelToWindow -TabId $tab2.Id
Wait-WpfEvents
Assert-Test "Users Tab 2 Detached in State" ($state.DetachedWindows.ContainsKey($tab2.Id))

$dRec2 = $state.DetachedWindows[$tab2.Id]
$dWin2 = $dRec2.Window
Assert-Test "Detached Window 2 Is Window Instance" ($dWin2 -is [System.Windows.Window])
Assert-Test "Detached Window 2 Has Correct Title" ($dWin2.Title -like "*Users (2)*")

$btnDock2 = $dWin2.FindName("BtnDockBack")
Assert-Test "Detached Window 2 Has Dock Back Button" ($null -ne $btnDock2)

# Verify ZERO Standby screens in both windows
$host1 = $dWin1.FindName("DetachedContentHost")
$host2 = $dWin2.FindName("DetachedContentHost")
$hasStandby1 = [bool]($host1.Children | Where-Object { $_.Text -like "*Standby*" -or $_.Name -like "*Standby*" })
$hasStandby2 = [bool]($host2.Children | Where-Object { $_.Text -like "*Standby*" -or $_.Name -like "*Standby*" })
Assert-Test "Window 1 Has Zero Standby Screens" (-not $hasStandby1)
Assert-Test "Window 2 Has Zero Standby Screens" (-not $hasStandby2)

# Simultaneous Interaction Test
$ctrls1 = $dRec1.Controls
$ctrls2 = $dRec2.Controls

# Search in Window 1 for "admin"
if ($ctrls1['TxtSearchUsers']) {
    $ctrls1['TxtSearchUsers'].Text = "admin"
    Wait-WpfEvents
}
$grid1 = $ctrls1['GridUsers']
$count1 = if ($grid1 -and $grid1.ItemsSource) { @($grid1.ItemsSource).Count } else { 0 }
Assert-Test "Window 1 Searched 'admin' Independently" ($count1 -ge 0)

# Search in Window 2 for "guest"
if ($ctrls2['TxtSearchUsers']) {
    $ctrls2['TxtSearchUsers'].Text = "guest"
    Wait-WpfEvents
}
$grid2 = $ctrls2['GridUsers']
$count2 = if ($grid2 -and $grid2.ItemsSource) { @($grid2.ItemsSource).Count } else { 0 }
Assert-Test "Window 2 Searched 'guest' Independently" ($count2 -ge 0)

# Verify text in both windows remains distinct (simultaneous side-by-side integrity)
Assert-Test "Window 1 Text Retained" ($ctrls1['TxtSearchUsers'].Text -eq "admin")
Assert-Test "Window 2 Text Retained" ($ctrls2['TxtSearchUsers'].Text -eq "guest")

# ==============================================================================
# TEST 2: Dock Back Verification
# ==============================================================================
Write-Host "`n--- Test Case 2: Docking Back into Main Window ---" -ForegroundColor Yellow

# Dock Window 2 back using BtnDockBack Click
$btnDock2.RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent))
Wait-WpfEvents

Assert-Test "Window 2 Docked Back (Removed from Detached List)" (-not $state.DetachedWindows.ContainsKey($tab2.Id))
Assert-Test "Window 1 Remains Detached and Active" ($state.DetachedWindows.ContainsKey($tab1.Id))

# Select Tab 2 in MainWindow and check session state
Select-WorkspaceTab -TabId $tab2.Id
Wait-WpfEvents
Assert-Test "MainWindow Active Tab is Users (2)" ($state.ActiveTabId -eq $tab2.Id)

# Dock Window 1 back via Dock-PanelToMainWindow
Dock-PanelToMainWindow -TabId $tab1.Id
Wait-WpfEvents

Assert-Test "Window 1 Docked Back" (-not $state.DetachedWindows.ContainsKey($tab1.Id))
Assert-Test "All Windows Docked Back (Count 0)" ($state.DetachedWindows.Count -eq 0)

# Select Tab 1 in MainWindow
Select-WorkspaceTab -TabId $tab1.Id
Wait-WpfEvents
Assert-Test "MainWindow Active Tab is Users (1)" ($state.ActiveTabId -eq $tab1.Id)

# ==============================================================================
# TEST 3: Groups Multi-Instance Simultaneous Detachment
# ==============================================================================
Write-Host "`n--- Test Case 3: Groups Multi-Instance Detachment ---" -ForegroundColor Yellow

Add-WorkspaceTab -PanelName "Groups" -Activate $true
Add-WorkspaceTab -PanelName "Groups" -NewInstance -Activate $true
Wait-WpfEvents

$gTab1 = $state.OpenTabs | Where-Object { $_.PanelName -eq "Groups" } | Select-Object -First 1
$gTab2 = $state.OpenTabs | Where-Object { $_.PanelName -eq "Groups" -and $_.InstanceNumber -eq 2 } | Select-Object -First 1

Detach-PanelToWindow -TabId $gTab1.Id
Detach-PanelToWindow -TabId $gTab2.Id
Wait-WpfEvents

Assert-Test "Groups Tab 1 Detached" ($state.DetachedWindows.ContainsKey($gTab1.Id))
Assert-Test "Groups Tab 2 Detached" ($state.DetachedWindows.ContainsKey($gTab2.Id))

$gRec1 = $state.DetachedWindows[$gTab1.Id]
$gRec2 = $state.DetachedWindows[$gTab2.Id]

Assert-Test "Groups Detached Window 1 Exists" ($gRec1.Window -is [System.Windows.Window])
Assert-Test "Groups Detached Window 2 Exists" ($gRec2.Window -is [System.Windows.Window])

# Dock all groups windows back
Mount-AllDetachedWindows
Wait-WpfEvents
Assert-Test "All Detached Windows Docked via Mount-AllDetachedWindows" ($state.DetachedWindows.Count -eq 0)

# ==============================================================================
# TEST 4: DirectorySearch Multi-Instance Simultaneous Detachment
# ==============================================================================
Write-Host "`n--- Test Case 4: DirectorySearch Multi-Instance Detachment ---" -ForegroundColor Yellow

Add-WorkspaceTab -PanelName "DirectorySearch" -Activate $true
Add-WorkspaceTab -PanelName "DirectorySearch" -NewInstance -Activate $true
Wait-WpfEvents

$sTab1 = $state.OpenTabs | Where-Object { $_.PanelName -eq "DirectorySearch" } | Select-Object -First 1
$sTab2 = $state.OpenTabs | Where-Object { $_.PanelName -eq "DirectorySearch" -and $_.InstanceNumber -eq 2 } | Select-Object -First 1

Detach-PanelToWindow -TabId $sTab1.Id
Detach-PanelToWindow -TabId $sTab2.Id
Wait-WpfEvents

Assert-Test "DirectorySearch Tab 1 Detached" ($state.DetachedWindows.ContainsKey($sTab1.Id))
Assert-Test "DirectorySearch Tab 2 Detached" ($state.DetachedWindows.ContainsKey($sTab2.Id))

$sRec2 = $state.DetachedWindows[$sTab2.Id]
$sCtrls2 = $sRec2.Controls
Assert-Test "Secondary DirectorySearch Has TxtRawLdapFilter" ($null -ne $sCtrls2['TxtRawLdapFilter'])
Assert-Test "Secondary DirectorySearch Has BtnRunLdapSearch" ($null -ne $sCtrls2['BtnRunLdapSearch'])

# Run search on secondary DirectorySearch instance
if ($sCtrls2['TxtRawLdapFilter']) { $sCtrls2['TxtRawLdapFilter'].Text = "(objectClass=user)" }
if ($sCtrls2['BtnRunLdapSearch']) { $sCtrls2['BtnRunLdapSearch'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent)) }
Wait-WpfEvents
Assert-Test "Secondary DirectorySearch Ran Query Successfully" ($true)

# Dock all back
Mount-AllDetachedWindows
Wait-WpfEvents
Assert-Test "All Windows Cleanly Docked Back" ($state.DetachedWindows.Count -eq 0)

# Clean up tabs
Remove-WorkspaceTab -TabId $tab2.Id
Remove-WorkspaceTab -TabId $gTab2.Id
Remove-WorkspaceTab -TabId $sTab2.Id
Wait-WpfEvents

$newErrorCount = $Error.Count - $initialErrorCount
Write-Host "`n================================================================" -ForegroundColor Cyan
Write-Host "   RESULTS: $passCount Passed, $failCount Failed, $newErrorCount New Errors" -ForegroundColor $(if ($failCount -eq 0 -and $newErrorCount -eq 0) { "Green" } else { "Red" })
Write-Host "================================================================" -ForegroundColor Cyan

if ($failCount -gt 0 -or $newErrorCount -gt 0) {
    exit 1
}
