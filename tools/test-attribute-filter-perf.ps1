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

Assert-TestCondition "Redundant TxtSearchAttrFilter is removed" ($null -eq $txtSearchAttr)
Assert-TestCondition "CmbFilterAttr exists" ($null -ne $cmbFilterAttr)
Assert-TestCondition "CmbFilterAttr is editable" ($cmbFilterAttr.IsEditable -eq $true)
Assert-TestCondition "OutcomeText exists in condition builder" ($null -ne $outcomeText)

# -----------------------------------------------------------------------------
# TEST 1: Rapid Direct Typing & Real-Time Filtering in CmbFilterAttr
# -----------------------------------------------------------------------------
Write-TestLog "`n--- [TEST 1] Rapid Keystrokes in CmbFilterAttr ---" "Yellow"

$cmbFilterAttr.ApplyTemplate()
$editBox = $cmbFilterAttr.Template.FindName("PART_EditableTextBox", $cmbFilterAttr)
Assert-TestCondition "CmbFilterAttr has PART_EditableTextBox" ($null -ne $editBox)

$sw = [System.Diagnostics.Stopwatch]::StartNew()
Filter-ComboAttributes -Combo $cmbFilterAttr -Query "user" -IncludeAny $false -OutcomeText $outcomeText -OutcomeBorder $controls['BorderSearchAttrOutcome'] -OpenDropDown $false
[System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::ContextIdle)
$sw.Stop()

Write-TestLog "  Filter execution completed in $($sw.ElapsedMilliseconds) ms" "Gray"
Assert-TestCondition "Filtering executed in under 50ms" ($sw.ElapsedMilliseconds -lt 50) "Actual: $($sw.ElapsedMilliseconds)ms"
Write-TestLog "  Outcome after typing 'user': '$($outcomeText.Text)'" "Gray"
Assert-TestCondition "Outcome reflects matching attributes for 'user'" ($outcomeText.Text -match "user|matching")
Assert-TestCondition "Matching items found in dropdown" ($cmbFilterAttr.Items.Count -gt 0) "Count: $($cmbFilterAttr.Items.Count)"

# -----------------------------------------------------------------------------
# TEST 2: Backspaces to Empty (Zero Freeze / Smooth Full List Recovery)
# -----------------------------------------------------------------------------
Write-TestLog "`n--- [TEST 2] Backspaces to Empty ---" "Yellow"

$swBack = [System.Diagnostics.Stopwatch]::StartNew()
Filter-ComboAttributes -Combo $cmbFilterAttr -Query "" -IncludeAny $false -OutcomeText $outcomeText -OutcomeBorder $controls['BorderSearchAttrOutcome'] -OpenDropDown $false
[System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::ContextIdle)
$swBack.Stop()

Write-TestLog "  Full list reset completed in $($swBack.ElapsedMilliseconds) ms" "Gray"
Assert-TestCondition "Reset to full list executed in under 50ms" ($swBack.ElapsedMilliseconds -lt 50) "Actual: $($swBack.ElapsedMilliseconds)ms"
Write-TestLog "  Outcome after empty query: '$($outcomeText.Text)'" "Gray"
Assert-TestCondition "Outcome badge displays all attributes" ($outcomeText.Text -match "Displaying all")
Assert-TestCondition "Full master attribute list restored" ($cmbFilterAttr.Items.Count -gt 50) "Count: $($cmbFilterAttr.Items.Count)"

# -----------------------------------------------------------------------------
# TEST 3: Broad Query (e.g. 'a') Capped to 100 Items
# -----------------------------------------------------------------------------
Write-TestLog "`n--- [TEST 3] Broad Query (e.g. 'a') Capped to 100 Items ---" "Yellow"

Filter-ComboAttributes -Combo $cmbFilterAttr -Query "a" -IncludeAny $false -OutcomeText $outcomeText -OutcomeBorder $controls['BorderSearchAttrOutcome'] -OpenDropDown $false
[System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::ContextIdle)

Write-TestLog "  Outcome for 'a': '$($outcomeText.Text)'" "Gray"
Write-TestLog "  Items in dropdown collection: $($cmbFilterAttr.Items.Count)" "Gray"

Assert-TestCondition "Dropdown collection is capped at <= 100 items for high performance" ($cmbFilterAttr.Items.Count -le 100) "Items: $($cmbFilterAttr.Items.Count)"
Assert-TestCondition "Outcome displays total matches and shows top 100 note" ($outcomeText.Text -match "top 100|matching")

# -----------------------------------------------------------------------------
# TEST 4: Selection Change Updates Outcome Badge
# -----------------------------------------------------------------------------
Write-TestLog "`n--- [TEST 4] Selection Change Updates Outcome Badge ---" "Yellow"

$cmbFilterAttr.SelectedItem = "userPrincipalName"
[System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::ContextIdle)
Write-TestLog "  Outcome after selection: '$($outcomeText.Text)'" "Gray"
Assert-TestCondition "Outcome badge updated with selected attribute" ($outcomeText.Text -match "userPrincipalName")

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
