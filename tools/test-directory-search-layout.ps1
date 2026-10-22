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

Write-TestLog "=== Starting Directory Search Simple/Advanced Layout Test Suite ===" "Cyan"

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

# -----------------------------------------------------------------------------
# TEST 1: Default Simple Search State
# -----------------------------------------------------------------------------
Write-TestLog "`n--- [TEST 1] Directory Search Initial Simple Mode ---" "Yellow"

$advBlock = $controls['BlockAdvancedSearchFilters']
$advActions = $controls['BlockAdvancedActionButtons']
$btnToggle = $controls['BtnToggleAdvancedSearch']
$txtQuery = $controls['TxtRawLdapFilter']
$btnRun = $controls['BtnRunLdapSearch']
$gridResults = $controls['GridSearchResults']

Assert-TestCondition "BlockAdvancedSearchFilters exists" ($null -ne $advBlock)
Assert-TestCondition "BlockAdvancedActionButtons exists" ($null -ne $advActions)
Assert-TestCondition "BtnToggleAdvancedSearch exists" ($null -ne $btnToggle)
Assert-TestCondition "TxtRawLdapFilter exists" ($null -ne $txtQuery)
Assert-TestCondition "BtnRunLdapSearch exists" ($null -ne $btnRun)
Assert-TestCondition "GridSearchResults exists" ($null -ne $gridResults)

Assert-TestCondition "Advanced filters block is Collapsed by default" ($advBlock.Visibility -eq [System.Windows.Visibility]::Collapsed)
Assert-TestCondition "Advanced action buttons are Collapsed by default" ($advActions.Visibility -eq [System.Windows.Visibility]::Collapsed)
Assert-TestCondition "Toggle button text is '▼ Advanced Search'" ($btnToggle.Content -eq "▼ Advanced Search")

# -----------------------------------------------------------------------------
# TEST 2: Core Simple Search Controls Accessibility
# -----------------------------------------------------------------------------
Write-TestLog "`n--- [TEST 2] Core Controls in Simple Search Mode ---" "Yellow"

Assert-TestCondition "Search Base input is visible" ($controls['TxtSearchBaseDn'].IsVisible -or $controls['TxtSearchBaseDn'].Visibility -eq [System.Windows.Visibility]::Visible)
Assert-TestCondition "Scope dropdown is visible" ($controls['CmbSearchScope'].Visibility -eq [System.Windows.Visibility]::Visible)
Assert-TestCondition "Presets dropdown is visible" ($controls['CmbSearchPresets'].Visibility -eq [System.Windows.Visibility]::Visible)
Assert-TestCondition "Query input has default '(objectClass=user)'" ($txtQuery.Text -eq "(objectClass=user)")
Assert-TestCondition "Inspect Attributes button is visible" ($controls['BtnSearchInspectAttr'].Visibility -eq [System.Windows.Visibility]::Visible)
Assert-TestCondition "Export Results button is visible" ($controls['BtnExportSearchResults'].Visibility -eq [System.Windows.Visibility]::Visible)
Assert-TestCondition "Add to Basket button is visible" ($controls['BtnSearchAddToBasket'].Visibility -eq [System.Windows.Visibility]::Visible)

# -----------------------------------------------------------------------------
# TEST 3: Toggle to Advanced Search Mode (Click Arrow Button)
# -----------------------------------------------------------------------------
Write-TestLog "`n--- [TEST 3] Toggle Arrow Button to Expand Advanced Search ---" "Yellow"

$btnToggle.RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent))
[System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::ContextIdle)

Assert-TestCondition "Advanced filters block is now Visible" ($advBlock.Visibility -eq [System.Windows.Visibility]::Visible)
Assert-TestCondition "Advanced action buttons are now Visible" ($advActions.Visibility -eq [System.Windows.Visibility]::Visible)
Assert-TestCondition "Toggle button text is '▲ Simple Search'" ($btnToggle.Content -eq "▲ Simple Search")

# Verify advanced controls are now active
Assert-TestCondition "Add Condition button exists and accessible" ($controls['BtnInsertCondition'].Visibility -eq [System.Windows.Visibility]::Visible)
Assert-TestCondition "Normalize Filter button exists and accessible" ($controls['BtnNormalizeFilter'].Visibility -eq [System.Windows.Visibility]::Visible)
Assert-TestCondition "SCIM-LDAP button exists and accessible" ($controls['BtnConvertScim'].Visibility -eq [System.Windows.Visibility]::Visible)
Assert-TestCondition "RegEx CheckBox exists and accessible" ($controls['ChkUseRegexFilter'].Visibility -eq [System.Windows.Visibility]::Visible)
Assert-TestCondition "Export LDIF button is now Visible" ($controls['BtnSearchExportLdif'].Visibility -eq [System.Windows.Visibility]::Visible)
Assert-TestCondition "Export JSON button is now Visible" ($controls['BtnSearchExportJson'].Visibility -eq [System.Windows.Visibility]::Visible)

# -----------------------------------------------------------------------------
# TEST 4: Toggle Back to Simple Search Mode (Click Arrow Button)
# -----------------------------------------------------------------------------
Write-TestLog "`n--- [TEST 4] Toggle Arrow Button to Return to Simple Search ---" "Yellow"

$btnToggle.RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent))
[System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::ContextIdle)

Assert-TestCondition "Advanced filters block collapsed back" ($advBlock.Visibility -eq [System.Windows.Visibility]::Collapsed)
Assert-TestCondition "Advanced action buttons collapsed back" ($advActions.Visibility -eq [System.Windows.Visibility]::Collapsed)
Assert-TestCondition "Toggle button text reverted to '▼ Advanced Search'" ($btnToggle.Content -eq "▼ Advanced Search")

# -----------------------------------------------------------------------------
# TEST 5: Toggle via Keyboard Shortcut (F4)
# -----------------------------------------------------------------------------
Write-TestLog "`n--- [TEST 5] Toggle via Keyboard Shortcut (F4) ---" "Yellow"

Toggle-DirectorySearchAdvancedView
[System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::ContextIdle)

Assert-TestCondition "F4 Toggle opened Advanced Search" ($advBlock.Visibility -eq [System.Windows.Visibility]::Visible)
Assert-TestCondition "Button text updated to '▲ Simple Search'" ($btnToggle.Content -eq "▲ Simple Search")

Toggle-DirectorySearchAdvancedView
[System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::ContextIdle)

Assert-TestCondition "F4 Toggle closed Advanced Search back to Simple" ($advBlock.Visibility -eq [System.Windows.Visibility]::Collapsed)
Assert-TestCondition "Button text reverted to '▼ Advanced Search'" ($btnToggle.Content -eq "▼ Advanced Search")

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
