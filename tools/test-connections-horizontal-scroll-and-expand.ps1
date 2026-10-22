[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
[CmdletBinding()]
param ()

$ErrorActionPreference = "Stop"
$testSuccess = $true
$recordedErrors = [System.Collections.Generic.List[string]]::new()

function Write-TestLog {
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

Write-TestLog "=== Starting Connections Table Horizontal Scroll & Expand View Test Suite ===" "Cyan"

$repoRoot = (Get-Location).Path
Add-Type -AssemblyName PresentationCore, PresentationFramework, WindowsBase

# Load modules
$modules = @(
    "ConfigService.psm1", "LoggingService.psm1", "ValidationService.psm1",
    "ADService.psm1", "ExportService.psm1", "TemplateService.psm1",
    "AclService.psm1", "KerberosService.psm1", "DiagnosticService.psm1",
    "NetworkService.psm1", "ReplicationService.psm1", "GpoService.psm1",
    "SpecializedEditorService.psm1", "ScimFilterService.psm1", "ScimService.psm1"
)
foreach ($m in $modules) {
    Import-Module (Join-Path $repoRoot "Modules\$m") -DisableNameChecking -Force
}

# Load main.ps1 offscreen
$mainScript = Get-Content (Join-Path $repoRoot "main.ps1") -Raw -Encoding utf8
$mainScriptOffscreen = $mainScript -replace '\[void\]\$window\.ShowDialog\(\)', '$window.WindowStartupLocation = [System.Windows.WindowStartupLocation]::Manual; $window.Left = -32000; $window.Top = -32000; $window.Show()'

. ([scriptblock]::Create($mainScriptOffscreen))
[System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Loaded)
[System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::ContextIdle)

Show-Panel -PanelName 'Connections'
[System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Loaded)
[System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::ContextIdle)

$gridConns = $controls['GridActiveConnections']
$btnToggle = $controls['BtnToggleConnectionsView']
$bottomPanel = $controls['BlockConnectionsBottomPanel']
$panelConns = $controls['PanelConnections']

Assert-TestCondition "GridActiveConnections exists" ($null -ne $gridConns)
Assert-TestCondition "BtnToggleConnectionsView exists" ($null -ne $btnToggle)
Assert-TestCondition "BlockConnectionsBottomPanel exists" ($null -ne $bottomPanel)

# -----------------------------------------------------------------------------
# TEST 1: Horizontal Scrollbar Configuration
# -----------------------------------------------------------------------------
Write-TestLog "`n--- [TEST 1] Horizontal Scrollbar Configuration ---" "Yellow"

$scrollViewer = $panelConns.Children[0]
Assert-TestCondition "PanelConnections outer ScrollViewer has HorizontalScrollBarVisibility=Auto" ($scrollViewer.HorizontalScrollBarVisibility -eq [System.Windows.Controls.ScrollBarVisibility]::Auto)
Assert-TestCondition "GridActiveConnections has HorizontalScrollBarVisibility=Auto" ($gridConns.HorizontalScrollBarVisibility -eq [System.Windows.Controls.ScrollBarVisibility]::Auto)

$lastCol = $gridConns.Columns[$gridConns.Columns.Count - 1]
Assert-TestCondition "Last column is 'Discovery Source'" ($lastCol.Header -eq "Discovery Source")
Assert-TestCondition "Discovery Source column has defined Width >= 140" ($lastCol.ActualWidth -ge 0 -and $lastCol.MinWidth -ge 140)

# -----------------------------------------------------------------------------
# TEST 2: Bottom Panels MUST NEVER Disappear on Toggle
# -----------------------------------------------------------------------------
Write-TestLog "`n--- [TEST 2] Bottom Panels Persistence on Expand View ---" "Yellow"

Assert-TestCondition "Initial Bottom Panel is Visible" ($bottomPanel.Visibility -eq [System.Windows.Visibility]::Visible)

# Click Expand View
$btnToggle.RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent))
[System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::ContextIdle)

Assert-TestCondition "Expanded View: Bottom Panel REMAINS Visible (Never Disappears)" ($bottomPanel.Visibility -eq [System.Windows.Visibility]::Visible)
Assert-TestCondition "Expanded View: GridActiveConnections MinHeight increased to 450" ($gridConns.MinHeight -eq 450)
Assert-TestCondition "Expanded View: GridActiveConnections MaxHeight increased to 700" ($gridConns.MaxHeight -eq 700)
Assert-TestCondition "Expanded View: Button content is '⤡ Compact View'" ($btnToggle.Content -eq "⤡ Compact View")

# Click Compact View
$btnToggle.RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent))
[System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::ContextIdle)

Assert-TestCondition "Compact View: Bottom Panel REMAINS Visible" ($bottomPanel.Visibility -eq [System.Windows.Visibility]::Visible)
Assert-TestCondition "Compact View: GridActiveConnections MinHeight is 240" ($gridConns.MinHeight -eq 240)
Assert-TestCondition "Compact View: GridActiveConnections MaxHeight is 320" ($gridConns.MaxHeight -eq 320)
Assert-TestCondition "Compact View: Button content is '⤢ Expand View'" ($btnToggle.Content -eq "⤢ Expand View")

$window.Close()
[System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::ContextIdle)

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
