[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
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

Write-TestLog "=== Starting HTML View Multi-Instance & Set-SafeBrowserHtml Test Suite ===" "Cyan"

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

# Mock Directory operations to ensure immediate, deterministic offline test execution
function global:Get-ADObjectRawAttributes {
    param([string]$DistinguishedName, [string]$Server = "", [switch]$IncludeOperational)
    $null = $DistinguishedName; $null = $Server; $null = $IncludeOperational
    return @(
        [PSCustomObject]@{ Name = "cn"; Value = "Test Administrator"; Type = "String"; IsOperational = $false },
        [PSCustomObject]@{ Name = "sAMAccountName"; Value = "testadmin"; Type = "String"; IsOperational = $false },
        [PSCustomObject]@{ Name = "distinguishedName"; Value = $DistinguishedName; Type = "String"; IsOperational = $false },
        [PSCustomObject]@{ Name = "displayName"; Value = "Test Administrator"; Type = "String"; IsOperational = $false },
        [PSCustomObject]@{ Name = "mail"; Value = "testadmin@corp.local"; Type = "String"; IsOperational = $false }
    )
}

function global:Get-ADUserDetail {
    param($Identity)
    $name = ($Identity -split ",")[0] -replace "^CN=", ""
    return [PSCustomObject]@{
        SamAccountName    = $name.ToLower()
        DisplayName       = $name
        DistinguishedName = $Identity
    }
}

# Clear any previous global errors
$global:Error.Clear()

$mainScript = Get-Content (Join-Path $repoRoot "main.ps1") -Raw -Encoding utf8
$mainScriptOffscreen = $mainScript -replace '\[void\]\$window\.ShowDialog\(\)', '$window.WindowStartupLocation = [System.Windows.WindowStartupLocation]::Manual; $window.Left = -32000; $window.Top = -32000; $window.Show()'

. ([scriptblock]::Create($mainScriptOffscreen))
[System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Loaded)
[System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::ContextIdle)

# -----------------------------------------------------------------------------
# TEST 1: Global Function Availability
# -----------------------------------------------------------------------------
Write-TestLog "`n--- [TEST 1] Global Function & Alias Resolution ---" "Yellow"

$cmdInfo = Get-Command Set-SafeBrowserHtml -ErrorAction SilentlyContinue
Assert-TestCondition -Description "Set-SafeBrowserHtml is resolvable globally" -Condition ($null -ne $cmdInfo)
Assert-TestCondition -Description "Set-Status is resolvable globally" -Condition ($null -ne (Get-Command Set-Status -ErrorAction SilentlyContinue))

# -----------------------------------------------------------------------------
# TEST 2: Multi-Instance HTML View Creation
# -----------------------------------------------------------------------------
Write-TestLog "`n--- [TEST 2] Secondary Instance HTML View Creation ---" "Yellow"

# Open primary instance (Instance 1)
Add-WorkspaceTab -PanelName 'HtmlView' -Activate $true
[System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::ContextIdle)

# Open secondary instance (Instance 2)
Add-WorkspaceTab -PanelName 'HtmlView' -NewInstance -Activate $true
[System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::ContextIdle)

$htmlTabs = @($state.OpenTabs | Where-Object { $_.PanelName -eq 'HtmlView' })
Assert-TestCondition -Description "Two HtmlView tabs created" -Condition ($htmlTabs.Count -ge 2) -Detail "Count: $($htmlTabs.Count)"

$activeTab = $state.OpenTabs | Where-Object { $_.Id -eq $state.ActiveTabId } | Select-Object -First 1
Assert-TestCondition -Description "Active tab is secondary HtmlView instance" -Condition ($activeTab.InstanceNumber -ge 2) -Detail "Instance: $($activeTab.InstanceNumber)"

# -----------------------------------------------------------------------------
# TEST 3: Render Dossier in Secondary Instance Closure
# -----------------------------------------------------------------------------
Write-TestLog "`n--- [TEST 3] Render Dossier Execution in Secondary Instance ---" "Yellow"

$secControls = $activeTab.DockedPanelControls
Assert-TestCondition -Description "Secondary instance controls collection exists" -Condition ($null -ne $secControls)

$btnGo = $secControls['BtnHtmlViewGo']
$txtDN = $secControls['TxtHtmlViewDN']
$browser = $secControls['BrowserHtmlView']

Assert-TestCondition -Description "BtnHtmlViewGo exists" -Condition ($null -ne $btnGo)
Assert-TestCondition -Description "TxtHtmlViewDN exists" -Condition ($null -ne $txtDN)
Assert-TestCondition -Description "BrowserHtmlView exists" -Condition ($null -ne $browser)

$null = $global:Error.Count

# Trigger rendering with sample DN
$txtDN.Text = "CN=Test Administrator,OU=Admins,DC=corp,DC=local"
$btnGo.RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent))
[System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Render)
[System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::ContextIdle)

# Check if any CommandNotFoundException was logged
$cmdNotFoundErrors = @($global:Error | Where-Object { $_.Exception -is [System.Management.Automation.CommandNotFoundException] -and $_.Exception.Message -match "Set-SafeBrowserHtml" })
Assert-TestCondition -Description "Zero CommandNotFoundException errors for Set-SafeBrowserHtml" -Condition ($cmdNotFoundErrors.Count -eq 0)

Assert-TestCondition -Description "Badge updated with display name in secondary instance" -Condition ($secControls['TxtHtmlViewStatusBadge'].Text -eq "Test Administrator") -Detail "Badge: $($secControls['TxtHtmlViewStatusBadge'].Text)"

$window.Close()
[System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::ContextIdle)

Write-TestLog "`n========================================================" "Cyan"
Write-TestLog "               TEST RUN SUMMARY" "Cyan"
Write-TestLog "========================================================" "Cyan"
Write-TestLog "Total Recorded Errors: $($recordedErrors.Count)" $(if ($recordedErrors.Count -eq 0) { "Green" } else { "Red" })

if ($script:testSuccess -and $recordedErrors.Count -eq 0) {
    Write-TestLog "ALL HTML VIEW MULTI-INSTANCE TESTS PASSED (100%)" "Green"
    exit 0
} else {
    Write-TestLog "SOME TESTS FAILED!" "Red"
    foreach ($err in $recordedErrors) {
        Write-TestLog " - $err" "Red"
    }
    exit 1
}
