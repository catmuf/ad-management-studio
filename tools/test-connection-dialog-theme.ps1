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

Write-TestLog "=== Starting Connection Dialog Theming & Contrast Test Suite ===" "Cyan"

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
# TEST 1: LIGHT MODE VERIFICATION
# -----------------------------------------------------------------------------
Write-TestLog "`n--- [TEST 1] Light Mode Connection Dialog Styling ---" "Yellow"

Set-ApplicationTheme -Theme 'Light'
[System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::ContextIdle)

$dlgPath = Join-Path $repoRoot 'Views/ConnectionDialog.xaml'
$dlg = Load-XamlWindow -XamlPath $dlgPath
$dlg.Owner = $window
$dlg.WindowStartupLocation = [System.Windows.WindowStartupLocation]::Manual
$dlg.Left = -32000
$dlg.Top = -32000
$dlg.Show()
[System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Loaded)
[System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::ContextIdle)

$dlgWinBg = $dlg.Background.ToString()
$dlgWinFg = $dlg.Foreground.ToString()

Write-TestLog "  Dialog Background: $dlgWinBg" "Gray"
Write-TestLog "  Dialog Foreground: $dlgWinFg" "Gray"

Assert-TestCondition "Light Mode Dialog Background is light" ($dlgWinBg -in @('#FFF8FAFC', '#FFFFFFFF')) "Bg: $dlgWinBg"
Assert-TestCondition "Light Mode Dialog Foreground is dark slate" ($dlgWinFg -eq '#FF0F172A') "Fg: $dlgWinFg"

$tbName = $dlg.FindName('TxtProfileName')
$tbHost = $dlg.FindName('TxtServerHost')
$btnTest = $dlg.FindName('BtnTestConnection')
$btnCancel = $dlg.FindName('BtnCancel')
$btnSave = $dlg.FindName('BtnSaveProfile')

Write-TestLog "  TxtProfileName Bg: $($tbName.Background) | Fg: $($tbName.Foreground)" "Gray"
Write-TestLog "  TxtServerHost  Bg: $($tbHost.Background) | Fg: $($tbHost.Foreground)" "Gray"
Write-TestLog "  BtnTestConn    Bg: $($btnTest.Background) | Fg: $($btnTest.Foreground)" "Gray"
Write-TestLog "  BtnCancel      Bg: $($btnCancel.Background) | Fg: $($btnCancel.Foreground)" "Gray"
Write-TestLog "  BtnSaveProfile Bg: $($btnSave.Background) | Fg: $($btnSave.Foreground)" "Gray"

Assert-TestCondition "Light Mode TextBox Background is white" ($tbName.Background.ToString() -eq '#FFFFFFFF')
Assert-TestCondition "Light Mode TextBox Foreground is dark slate" ($tbName.Foreground.ToString() -eq '#FF0F172A')
Assert-TestCondition "Light Mode ModernButton Background is light" ($btnTest.Background.ToString() -in @('#FFF1F5F9', '#FFE2E8F0'))
Assert-TestCondition "Light Mode ModernButton Foreground is dark" ($btnTest.Foreground.ToString() -eq '#FF0F172A')
Assert-TestCondition "Light Mode Save Button is Accent Primary" ($btnSave.Background.ToString() -in @('#FF0078D4', '#FF2563EB'))

# Scan all TextBlocks inside ConnectionDialog
function Get-DialogTextBlock($el) {
    $res = [System.Collections.Generic.List[PSCustomObject]]::new()
    if ($null -eq $el) { return $res }
    if ($el -is [System.Windows.Controls.TextBlock] -and $el.Text) {
        $res.Add([PSCustomObject]@{ Text = $el.Text; Fg = $el.Foreground.ToString() })
    }
    if ($el -is [System.Windows.Controls.Panel]) {
        foreach ($c in $el.Children) {
            foreach ($item in (Get-DialogTextBlock $c)) { $res.Add($item) }
        }
    }
    if ($el -is [System.Windows.Controls.ContentControl]) {
        foreach ($item in (Get-DialogTextBlock $el.Content)) { $res.Add($item) }
    }
    if ($el -is [System.Windows.Controls.ScrollViewer]) {
        foreach ($item in (Get-DialogTextBlock $el.Content)) { $res.Add($item) }
    }
    if ($el -is [System.Windows.Controls.Border]) {
        foreach ($item in (Get-DialogTextBlock $el.Child)) { $res.Add($item) }
    }
    return $res
}

$allTbs = Get-DialogTextBlock $dlg.Content
$unreadableCount = 0
foreach ($t in $allTbs) {
    if ($t.Fg -in @('#FFE5E7EB', '#FFFFFFFF', '#FFF8FAFC', '#FFF1F5F9')) {
        Write-TestLog "  UNREADABLE FAINT TEXT: '$($t.Text)' with Foreground: $($t.Fg)" "Red"
        $unreadableCount++
    }
}
Assert-TestCondition "Zero unreadable/faint labels in Light Mode" ($unreadableCount -eq 0) "Found: $unreadableCount"

$dlg.Close()
[System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::ContextIdle)

# -----------------------------------------------------------------------------
# TEST 2: DARK MODE VERIFICATION
# -----------------------------------------------------------------------------
Write-TestLog "`n--- [TEST 2] Dark Mode Connection Dialog Styling ---" "Yellow"

Set-ApplicationTheme -Theme 'Dark'
[System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::ContextIdle)

$dlgDark = Load-XamlWindow -XamlPath $dlgPath
$dlgDark.Owner = $window
$dlgDark.WindowStartupLocation = [System.Windows.WindowStartupLocation]::Manual
$dlgDark.Left = -32000
$dlgDark.Top = -32000
$dlgDark.Show()
[System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Loaded)
[System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::ContextIdle)

$dlgDarkBg = $dlgDark.Background.ToString()
$dlgDarkFg = $dlgDark.Foreground.ToString()
$tbDark = $dlgDark.FindName('TxtProfileName')

Write-TestLog "  Dark Dialog Background: $dlgDarkBg" "Gray"
Write-TestLog "  Dark Dialog Foreground: $dlgDarkFg" "Gray"
Write-TestLog "  Dark TxtProfileName Bg: $($tbDark.Background) | Fg: $($tbDark.Foreground)" "Gray"

Assert-TestCondition "Dark Mode Dialog Background is dark" ($dlgDarkBg -in @('#FF0F1015', '#FF14161C', '#FF181A20'))
Assert-TestCondition "Dark Mode Dialog Foreground is light" ($dlgDarkFg -in @('#FFFFFFFF', '#FFF3F4F6'))
Assert-TestCondition "Dark Mode TextBox Background is dark" ($tbDark.Background.ToString() -in @('#FF181A22', '#FF22252F'))
Assert-TestCondition "Dark Mode TextBox Foreground is white" ($tbDark.Foreground.ToString() -eq '#FFFFFFFF')

$dlgDark.Close()
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