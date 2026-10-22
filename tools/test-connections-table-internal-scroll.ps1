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

function Get-VisualChild {
    param(
        [System.Windows.DependencyObject]$parent,
        [type]$targetType
    )
    if (-not $parent) { return $null }
    $count = [System.Windows.Media.VisualTreeHelper]::GetChildrenCount($parent)
    for ($i = 0; $i -lt $count; $i++) {
        $child = [System.Windows.Media.VisualTreeHelper]::GetChild($parent, $i)
        if ($targetType.IsAssignableFrom($child.GetType())) {
            return $child
        }
        $sub = Get-VisualChild -parent $child -targetType $targetType
        if ($null -ne $sub) { return $sub }
    }
    return $null
}

Write-TestLog "=== Starting Connections Table Internal Horizontal Scroll Test Suite ===" "Cyan"

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

# Populate GridActiveConnections with sample servers
$sampleDCs = [System.Collections.Generic.List[object]]::new()
for ($i = 1; $i -le 10; $i++) {
    $sampleDCs.Add([PSCustomObject]@{
        StatusBadge = "● Online"
        HostName    = "dc$i.corp.enterprise.local"
        Domain      = "corp.enterprise.local"
        Role        = if ($i -eq 1) { "PDC Emulator, Schema Master" } else { "Domain Controller" }
        IPAddress   = "10.0.10.$i"
        Port        = 389
        PingMs      = 1.5 * $i
        PingDisplay = "$([math]::Round(1.5 * $i, 1)) ms"
        Mode        = "LDAP"
        Source      = "AD DS Auto-Discovery / DNS SRV"
    })
}

$gridConns.ItemsSource = $sampleDCs
[System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Render)
[System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::ContextIdle)

# -----------------------------------------------------------------------------
# TEST 1: Outer Page ScrollViewer Is Horizontally Locked (Disabled)
# -----------------------------------------------------------------------------
Write-TestLog "`n--- [TEST 1] Outer ScrollViewer Horizontal Constraint ---" "Yellow"

$outerScrollViewer = $panelConns.Children[0]
Assert-TestCondition "PanelConnections outer ScrollViewer HorizontalScrollBarVisibility is Disabled" ($outerScrollViewer.HorizontalScrollBarVisibility -eq [System.Windows.Controls.ScrollBarVisibility]::Disabled)
Assert-TestCondition "Outer ScrollViewer ScrollableWidth is 0 (No whole-page horizontal shift)" ($outerScrollViewer.ScrollableWidth -eq 0)

# -----------------------------------------------------------------------------
# TEST 2: DataGrid Internal ScrollViewer (DG_ScrollViewer) Has Active Horizontal Scrollbar
# -----------------------------------------------------------------------------
Write-TestLog "`n--- [TEST 2] Internal DataGrid Horizontal Scrollbar ---" "Yellow"

$dgScrollViewer = Get-VisualChild -parent $gridConns -targetType ([System.Windows.Controls.ScrollViewer])
Assert-TestCondition "Internal DG_ScrollViewer found inside GridActiveConnections" ($null -ne $dgScrollViewer)

if ($dgScrollViewer) {
    Write-TestLog "  -> DG_ScrollViewer ExtentWidth: $($dgScrollViewer.ExtentWidth)px | ViewportWidth: $($dgScrollViewer.ViewportWidth)px | ScrollableWidth: $($dgScrollViewer.ScrollableWidth)px" "Gray"

    Assert-TestCondition "DG_ScrollViewer ExtentWidth exceeds ViewportWidth" ($dgScrollViewer.ExtentWidth -gt $dgScrollViewer.ViewportWidth)
    Assert-TestCondition "DG_ScrollViewer ComputedHorizontalScrollBarVisibility is Visible" ($dgScrollViewer.ComputedHorizontalScrollBarVisibility -eq [System.Windows.Visibility]::Visible)
    Assert-TestCondition "DG_ScrollViewer ScrollableWidth > 0" ($dgScrollViewer.ScrollableWidth -gt 0)

    # Scroll internally to right
    $dgScrollViewer.ScrollToHorizontalOffset($dgScrollViewer.ScrollableWidth)
    [System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Render)
    [System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::ContextIdle)

    Assert-TestCondition "DG_ScrollViewer scrolled horizontally to offset > 0" ($dgScrollViewer.HorizontalOffset -gt 0)
    Assert-TestCondition "Outer ScrollViewer still has ScrollableWidth = 0 after table scroll" ($outerScrollViewer.ScrollableWidth -eq 0)
}

# -----------------------------------------------------------------------------
# TEST 3: Column Widths and Layout Integrity
# -----------------------------------------------------------------------------
Write-TestLog "`n--- [TEST 3] Column Widths & Structure ---" "Yellow"

$expectedColumns = @(
    @{ Header = "Status"; Width = 95 },
    @{ Header = "Server / Host"; Width = 200 },
    @{ Header = "Domain"; Width = 140 },
    @{ Header = "Role"; Width = 150 },
    @{ Header = "IP Address"; Width = 130 },
    @{ Header = "Port"; Width = 70 },
    @{ Header = "Ping Connection (ms)"; Width = 155 },
    @{ Header = "Mode"; Width = 100 },
    @{ Header = "Discovery Source"; Width = 200 }
)

Assert-TestCondition "GridActiveConnections has $($expectedColumns.Count) columns" ($gridConns.Columns.Count -eq $expectedColumns.Count)

$totalExpectedWidth = 0
for ($colIdx = 0; $colIdx -lt $expectedColumns.Count; $colIdx++) {
    $col = $gridConns.Columns[$colIdx]
    $exp = $expectedColumns[$colIdx]
    $totalExpectedWidth += $exp.Width
    Assert-TestCondition "Column $colIdx is '$($exp.Header)' with configured width $($exp.Width)" ($col.Header -eq $exp.Header -and $col.Width.Value -eq $exp.Width)
}
Write-TestLog "  -> Total table column width: $($totalExpectedWidth)px" "Gray"
Assert-TestCondition "Total configured column width is 1240px" ($totalExpectedWidth -eq 1240)

# -----------------------------------------------------------------------------
# TEST 4: View Toggle Integrity (Bottom Panels Preserved)
# -----------------------------------------------------------------------------
Write-TestLog "`n--- [TEST 4] View Toggle & Bottom Panels Preservation ---" "Yellow"

Assert-TestCondition "Initial Bottom Panel is Visible" ($bottomPanel.Visibility -eq [System.Windows.Visibility]::Visible)

# Expand View
$btnToggle.RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent))
[System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::ContextIdle)

Assert-TestCondition "Expanded: Bottom Panel remains Visible" ($bottomPanel.Visibility -eq [System.Windows.Visibility]::Visible)
Assert-TestCondition "Expanded: GridActiveConnections MinHeight is 450" ($gridConns.MinHeight -eq 450)
if ($dgScrollViewer) {
    Assert-TestCondition "Expanded: Internal horizontal scrollbar remains Visible" ($dgScrollViewer.ComputedHorizontalScrollBarVisibility -eq [System.Windows.Visibility]::Visible)
}

# Compact View
$btnToggle.RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent))
[System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::ContextIdle)

Assert-TestCondition "Compact: Bottom Panel remains Visible" ($bottomPanel.Visibility -eq [System.Windows.Visibility]::Visible)
Assert-TestCondition "Compact: GridActiveConnections MinHeight is 240" ($gridConns.MinHeight -eq 240)

$window.Close()
[System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::ContextIdle)

Write-TestLog "`n========================================================" "Cyan"
Write-TestLog "               TEST RUN SUMMARY" "Cyan"
Write-TestLog "========================================================" "Cyan"
Write-TestLog "Total Recorded Errors: $($recordedErrors.Count)" $(if ($recordedErrors.Count -eq 0) { "Green" } else { "Red" })

if ($script:testSuccess -and $recordedErrors.Count -eq 0) {
    Write-TestLog "ALL INTERNAL HORIZONTAL SCROLL TESTS PASSED (100%)" "Green"
    exit 0
} else {
    Write-TestLog "SOME TESTS FAILED!" "Red"
    foreach ($err in $recordedErrors) {
        Write-TestLog " - $err" "Red"
    }
    exit 1
}
