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

Write-TestLog "=== Starting Attribute Quick Filter Performance & Debounce Test Suite ===" "Cyan"

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

# Switch to Directory Search panel
Show-Panel -PanelName 'DirectorySearch'
[System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Loaded)
[System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::ContextIdle)

# Expand Advanced Search so visual builder is loaded
Toggle-DirectorySearchAdvancedView
[System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::ContextIdle)

$txtSearchAttr = $controls['TxtSearchAttrFilter']
$cmbFilterAttr = $controls['CmbFilterAttr']
$outcomeText = $controls['TxtSearchAttrOutcome']

Assert-TestCondition "TxtSearchAttrFilter exists" ($null -ne $txtSearchAttr)
Assert-TestCondition "CmbFilterAttr exists" ($null -ne $cmbFilterAttr)
Assert-TestCondition "OutcomeText exists" ($null -ne $outcomeText)

# -----------------------------------------------------------------------------
# TEST 1: Rapid Keystrokes & Debouncing
# -----------------------------------------------------------------------------
Write-TestLog "`n--- [TEST 1] Rapid Keystrokes & Debounce (No Lag / No DropDown Force) ---" "Yellow"

$sw = [System.Diagnostics.Stopwatch]::StartNew()
# Simulate typing "u", "us", "use", "user" rapidly
$txtSearchAttr.Text = "u"
$txtSearchAttr.Text = "us"
$txtSearchAttr.Text = "use"
$txtSearchAttr.Text = "user"
$sw.Stop()

Write-TestLog "  Rapid text property changes completed in $($sw.ElapsedMilliseconds) ms" "Gray"
Assert-TestCondition "Rapid keystrokes executed in under 50ms" ($sw.ElapsedMilliseconds -lt 50) "Actual: $($sw.ElapsedMilliseconds)ms"

# While timer is waiting, dropdown should NOT be open
Assert-TestCondition "CmbFilterAttr drop down is NOT forced open while typing" (-not $cmbFilterAttr.IsDropDownOpen)

# Wait 250ms for debounce timer to fire
[System.Threading.Thread]::Sleep(250)
[System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::ContextIdle)

Write-TestLog "  Outcome after debounce: '$($outcomeText.Text)'" "Gray"
Assert-TestCondition "Outcome reflects matching attributes for 'user'" ($outcomeText.Text -match "user|matching")
Assert-TestCondition "DropDown remains closed during typing in external box" (-not $cmbFilterAttr.IsDropDownOpen)

# -----------------------------------------------------------------------------
# TEST 2: Rapid Backspaces to Empty (Zero Freeze / Smooth Recovery)
# -----------------------------------------------------------------------------
Write-TestLog "`n--- [TEST 2] Rapid Backspaces to Empty ---" "Yellow"

$swBack = [System.Diagnostics.Stopwatch]::StartNew()
# Simulate holding down backspace
$txtSearchAttr.Text = "use"
$txtSearchAttr.Text = "us"
$txtSearchAttr.Text = "u"
$txtSearchAttr.Text = ""
$swBack.Stop()

Write-TestLog "  Rapid backspace changes completed in $($swBack.ElapsedMilliseconds) ms" "Gray"
Assert-TestCondition "Rapid backspaces executed in under 50ms without freeze" ($swBack.ElapsedMilliseconds -lt 50) "Actual: $($swBack.ElapsedMilliseconds)ms"

# Wait 250ms for debounce timer to fire
[System.Threading.Thread]::Sleep(250)
[System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::ContextIdle)

Write-TestLog "  Outcome after backspace to empty: '$($outcomeText.Text)'" "Gray"
Assert-TestCondition "Outcome badge displays all attributes without freeze" ($outcomeText.Text -match "Displaying all")
Assert-TestCondition "Placeholder is visible when empty" ($controls['TxtSearchAttrPlaceholder'].Visibility -eq [System.Windows.Visibility]::Visible)

# -----------------------------------------------------------------------------
# TEST 3: Capped Matches (Top 100) on Broad Queries
# -----------------------------------------------------------------------------
Write-TestLog "`n--- [TEST 3] Broad Query (e.g. 'a') Capped to 100 Items ---" "Yellow"

$txtSearchAttr.Text = "a"
[System.Threading.Thread]::Sleep(250)
[System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::ContextIdle)

Write-TestLog "  Outcome for 'a': '$($outcomeText.Text)'" "Gray"
Write-TestLog "  Items in dropdown collection: $($cmbFilterAttr.Items.Count)" "Gray"

Assert-TestCondition "Dropdown collection is capped at <= 100 items for high performance" ($cmbFilterAttr.Items.Count -le 100) "Items: $($cmbFilterAttr.Items.Count)"
Assert-TestCondition "Outcome displays total matches and shows top 100 note" ($outcomeText.Text -match "top 100|matching")

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
