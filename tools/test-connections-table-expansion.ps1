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

Write-TestLog "=== Starting Connections Table Expansion Test Suite ===" "Cyan"

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

# -----------------------------------------------------------------------------
# TEST 1: Initial Dimensions & Controls Verification
# -----------------------------------------------------------------------------
Write-TestLog "`n--- [TEST 1] Connections Table Default Sizing & Controls ---" "Yellow"

$gridConns = $controls['GridActiveConnections']
$btnToggle = $controls['BtnToggleConnectionsView']
$bottomPanel = $controls['BlockConnectionsBottomPanel']

Assert-TestCondition "GridActiveConnections exists" ($null -ne $gridConns)
Assert-TestCondition "BtnToggleConnectionsView exists" ($null -ne $btnToggle)
Assert-TestCondition "BlockConnectionsBottomPanel exists" ($null -ne $bottomPanel)

Assert-TestCondition "Default MinHeight is 250" ($gridConns.MinHeight -eq 250) "Actual: $($gridConns.MinHeight)"
Assert-TestCondition "Default MaxHeight is 580" ($gridConns.MaxHeight -eq 580) "Actual: $($gridConns.MaxHeight)"
Assert-TestCondition "Default BottomPanel is Visible" ($bottomPanel.Visibility -eq [System.Windows.Visibility]::Visible)
Assert-TestCondition "Default Button Content is '⤢ Expand View'" ($btnToggle.Content -eq "⤢ Expand View")

# -----------------------------------------------------------------------------
# TEST 2: Populating Multiple Servers (12 servers / mirrors)
# -----------------------------------------------------------------------------
Write-TestLog "`n--- [TEST 2] Populating 12 Servers & Capacity ---" "Yellow"

$mockServers = [System.Collections.ArrayList]::new()
for ($i = 1; $i -le 12; $i++) {
    [void]$mockServers.Add([PSCustomObject]@{
        StatusBadge = "● Online"
        HostName    = "VS-DC-$('{0:D2}' -f $i).contoso.local"
        Domain      = "contoso.local"
        Role        = if ($i -eq 1) { "PDC Emulator" } else { "Domain Controller" }
        IPAddress   = "10.0.0.$($i + 10)"
        Port        = 389
        PingDisplay = "$($i * 2) ms"
        PingMs      = $i * 2
        Mode        = "Read/Write"
        Source      = "AD Domain Services"
    })
}

$gridConns.ItemsSource = $mockServers
[System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Loaded)
[System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::ContextIdle)

Assert-TestCondition "DataGrid has 12 items loaded" ($gridConns.Items.Count -eq 12)

# -----------------------------------------------------------------------------
# TEST 3: Toggle Expand View (Full Table Capacity)
# -----------------------------------------------------------------------------
Write-TestLog "`n--- [TEST 3] Toggle to Expanded View ---" "Yellow"

# Simulate Click
$btnToggle.RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent))
[System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::ContextIdle)

Assert-TestCondition "Expanded View: Button content is '⤡ Compact View'" ($btnToggle.Content -eq "⤡ Compact View")
Assert-TestCondition "Expanded View: Bottom panel is Collapsed" ($bottomPanel.Visibility -eq [System.Windows.Visibility]::Collapsed)
Assert-TestCondition "Expanded View: MaxHeight expanded to 1200" ($gridConns.MaxHeight -eq 1200) "Actual: $($gridConns.MaxHeight)"

# -----------------------------------------------------------------------------
# TEST 4: Toggle Back to Standard View
# -----------------------------------------------------------------------------
Write-TestLog "`n--- [TEST 4] Toggle Back to Standard View ---" "Yellow"

$btnToggle.RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent))
[System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::ContextIdle)

Assert-TestCondition "Standard View: Button content is '⤢ Expand View'" ($btnToggle.Content -eq "⤢ Expand View")
Assert-TestCondition "Standard View: Bottom panel is Visible" ($bottomPanel.Visibility -eq [System.Windows.Visibility]::Visible)
Assert-TestCondition "Standard View: MaxHeight restored to 580" ($gridConns.MaxHeight -eq 580) "Actual: $($gridConns.MaxHeight)"

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
