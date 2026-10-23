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

Write-TestLog "=== Starting Log Errors Revision & Resilience Test Suite ===" "Cyan"

$repoRoot = (Get-Location).Path
Add-Type -AssemblyName PresentationCore, PresentationFramework, WindowsBase

# Load LoggingService
Import-Module (Join-Path $repoRoot "Modules\LoggingService.psm1") -DisableNameChecking -Force

# -----------------------------------------------------------------------------
# TEST 1: WpfDispatcher Quota Exhaustion & Software Rendering Fallback
# -----------------------------------------------------------------------------
Write-TestLog "`n--- [TEST 1] WPF Dispatcher Win32 Quota Resilience ---" "Yellow"

$dispatcher = [System.Windows.Threading.Dispatcher]::CurrentDispatcher
[System.Windows.Media.RenderOptions]::ProcessRenderMode = [System.Windows.Interop.RenderMode]::Default

Register-WpfExceptionHandler -Dispatcher $dispatcher -Window $null

# Simulate a Win32Exception 1816 (Cuota insuficiente para procesar este comando)
$win32Ex = [System.ComponentModel.Win32Exception]::new(1816, "Cuota insuficiente para procesar este comando.")

$ctor = [System.Windows.Threading.DispatcherUnhandledExceptionEventArgs].GetConstructor([System.Reflection.BindingFlags]::Instance -bor [System.Reflection.BindingFlags]::NonPublic, $null, @([System.Windows.Threading.Dispatcher]), $null)
$ueArgs = $ctor.Invoke(@($dispatcher))
$exField = [System.Windows.Threading.DispatcherUnhandledExceptionEventArgs].GetField("_exception", [System.Reflection.BindingFlags]::Instance -bor [System.Reflection.BindingFlags]::NonPublic)
$exField.SetValue($ueArgs, $win32Ex)

$field = [System.Windows.Threading.Dispatcher].GetField("UnhandledException", [System.Reflection.BindingFlags]::Instance -bor [System.Reflection.BindingFlags]::NonPublic)
$handlerDelegate = $field.GetValue($dispatcher)
$handlerDelegate.Invoke($dispatcher, $ueArgs)

Assert-TestCondition -Description "Quota exception was marked Handled" -Condition ($ueArgs.Handled -eq $true)
Assert-TestCondition -Description "ProcessRenderMode switched to SoftwareOnly on quota exhaustion" -Condition ([System.Windows.Media.RenderOptions]::ProcessRenderMode -eq [System.Windows.Interop.RenderMode]::SoftwareOnly)

# -----------------------------------------------------------------------------
# TEST 2: Rapid Identical Exception Throttling (Flood Prevention)
# -----------------------------------------------------------------------------
Write-TestLog "`n--- [TEST 2] Rapid Identical Dispatcher Exception Throttling ---" "Yellow"

for ($i = 0; $i -lt 5; $i++) {
    $burstArgs = $ctor.Invoke(@($dispatcher))
    $exField.SetValue($burstArgs, $win32Ex)
    $handlerDelegate.Invoke($dispatcher, $burstArgs)
}

$logMod = Get-Module LoggingService
$suppressedCount = & $logMod { $script:SuppressedWpfExceptionCount }

Assert-TestCondition -Description "Repetitive burst exceptions were suppressed without crashing" -Condition ($suppressedCount -ge 4) -Detail "Suppressed: $suppressedCount"

# -----------------------------------------------------------------------------
# TEST 3: Directory Search Outcome Badge & No CommandNotFoundException
# -----------------------------------------------------------------------------
Write-TestLog "`n--- [TEST 3] Directory Search Outcome Badge Execution ---" "Yellow"

# Load modules
$modules = @(
    "ConfigService.psm1", "ValidationService.psm1",
    "ADService.psm1", "ExportService.psm1", "TemplateService.psm1",
    "AclService.psm1", "KerberosService.psm1", "DiagnosticService.psm1",
    "NetworkService.psm1", "ReplicationService.psm1", "GpoService.psm1",
    "SpecializedEditorService.psm1", "ScimFilterService.psm1", "ScimService.psm1"
)
foreach ($m in $modules) {
    Import-Module (Join-Path $repoRoot "Modules\$m") -DisableNameChecking -Force
}

$mainScript = Get-Content (Join-Path $repoRoot "main.ps1") -Raw -Encoding utf8
$mainScriptOffscreen = $mainScript -replace '\[void\]\$window\.ShowDialog\(\)', '$window.WindowStartupLocation = [System.Windows.WindowStartupLocation]::Manual; $window.Left = -32000; $window.Top = -32000; $window.Show()'

. ([scriptblock]::Create($mainScriptOffscreen))
[System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Loaded)
[System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::ContextIdle)

Show-Panel -PanelName 'DirectorySearch'
[System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Loaded)
[System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::ContextIdle)

Assert-TestCondition -Description "Controls table exists" -Condition ($null -ne $controls)
$cmbFilterAttr = $controls['CmbFilterAttr']
$txtSearchAttr = $controls['TxtSearchAttrFilter']
$null = $txtSearchAttr
$outcomeText = $controls['TxtSearchAttrOutcome']

Assert-TestCondition -Description "CmbFilterAttr exists" -Condition ($null -ne $cmbFilterAttr)
Assert-TestCondition -Description "TxtSearchAttrOutcome exists" -Condition ($null -ne $outcomeText)

# Test direct execution of Set-SearchAttrOutcomeBadge
$exThrown = $null
try {
    Set-SearchAttrOutcomeBadge -Status "Info" -Message "Displaying all 50 attributes (test)"
} catch {
    $exThrown = $_
}
Assert-TestCondition -Description "Set-SearchAttrOutcomeBadge executes cleanly without CommandNotFoundException" -Condition ($null -eq $exThrown)

# Test selection change
if ($cmbFilterAttr -and $cmbFilterAttr.Items.Count -gt 1) {
    $targetIdx = if ($cmbFilterAttr.SelectedIndex -eq 0) { 1 } else { 0 }
    $cmbFilterAttr.SelectedIndex = $targetIdx
    [System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::ContextIdle)
    Assert-TestCondition -Description "Selection change updates outcome text without error" -Condition ($outcomeText.Text -match "Selected attribute") -Detail "Outcome: $($outcomeText.Text)"
}

$window.Close()
[System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::ContextIdle)

Write-TestLog "`n========================================================" "Cyan"
Write-TestLog "               TEST RUN SUMMARY" "Cyan"
Write-TestLog "========================================================" "Cyan"
Write-TestLog "Total Recorded Errors: $($recordedErrors.Count)" $(if ($recordedErrors.Count -eq 0) { "Green" } else { "Red" })

if ($script:testSuccess -and $recordedErrors.Count -eq 0) {
    Write-TestLog "ALL LOG ERRORS REVISION TESTS PASSED (100%)" "Green"
    exit 0
} else {
    Write-TestLog "SOME TESTS FAILED!" "Red"
    foreach ($err in $recordedErrors) {
        Write-TestLog " - $err" "Red"
    }
    exit 1
}
