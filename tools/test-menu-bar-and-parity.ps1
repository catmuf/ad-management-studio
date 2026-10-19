[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidGlobalVars', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingEmptyCatchBlock', '')]
[CmdletBinding()]
param()

$projectRoot = (Get-Location).Path

$logOutput = [System.Collections.Generic.List[string]]::new()
$recordedErrors = [System.Collections.Generic.List[string]]::new()
$totalOperations = 0
$passedOperations = 0

function Write-TestLog {
    param (
        [string]$Message,
        [string]$Color = "White"
    )
    $formatted = "[TEST $(Get-Date -Format 'HH:mm:ss.fff')] $Message"
    Write-Host $formatted -ForegroundColor $Color
    $logOutput.Add($formatted)
}

function Invoke-DispatcherPump {
    try {
        [void][System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([System.Windows.Threading.DispatcherPriority]::Normal, [System.TimeSpan]::FromMilliseconds(50), [Action]{})
    } catch { }
}

function Invoke-MockMessageBoxShow {
    param($text, $title, $button, $icon)
    $null = $button; $null = $icon
    Write-TestLog "  [MOCK-MSG] $($title): $text" "DarkGray"
    return [System.Windows.MessageBoxResult]::OK
}

function Invoke-MockInputBox {
    param($prompt, $title, $default)
    $null = $prompt; $null = $title
    Write-TestLog "  [MOCK-INPUT] $title -> returning: $default" "DarkGray"
    return $default
}

function Assert-TestAction {
    param (
        [string]$ActionName,
        [string]$Description,
        [scriptblock]$Action
    )
    $script:totalOperations++
    $beforeErrCount = $global:Error.Count
    Write-TestLog "Testing [$ActionName]: $Description" "Gray"
    try {
        & $Action
        Invoke-DispatcherPump
        $newErrors = $global:Error.Count - $beforeErrCount
        if ($newErrors -gt 0) {
            $latestErr = $global:Error[0]
            Write-TestLog "  -> ERROR in [$ActionName]: $latestErr" "Red"
            $recordedErrors.Add("[$ActionName] $latestErr")
        } else {
            $script:passedOperations++
            Write-TestLog "  -> PASS [$ActionName]" "Green"
        }
    } catch {
        Write-TestLog "  -> EXCEPTION in [$ActionName]: $_" "Red"
        $recordedErrors.Add("[$ActionName] $_")
    }
}

Write-TestLog "======================================================================" "Cyan"
Write-TestLog "Starting Horizontal Menu Bar & Competitor Features Test Suite" "Cyan"
Write-TestLog "======================================================================" "Cyan"

# Load modules
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

# Neutralize dialogs and run offscreen
$mainScript = Get-Content (Join-Path $projectRoot "main.ps1") -Raw -Encoding utf8

$offscreenReplacement = @'
$window.WindowStartupLocation = [System.Windows.WindowStartupLocation]::Manual
$window.Left = -32000
$window.Top = -32000
$window.Show()
'@

$neutralizeDialogs = @'
$dlg.WindowStartupLocation = [System.Windows.WindowStartupLocation]::Manual
$dlg.Left = -32000
$dlg.Top = -32000
$dlg.Show()
try {
    [void][System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Input)
} catch { }
$dlg.Close()
'@

$mainScriptOffscreen = $mainScript.Replace('[void]$window.ShowDialog()', $offscreenReplacement)
$mainScriptOffscreen = $mainScriptOffscreen.Replace('[System.Windows.MessageBox]::Show', 'Invoke-MockMessageBoxShow')
$mainScriptOffscreen = $mainScriptOffscreen.Replace('[Microsoft.VisualBasic.Interaction]::InputBox', 'Invoke-MockInputBox')
$mainScriptOffscreen = $mainScriptOffscreen.Replace('[void]$dlg.ShowDialog()', $neutralizeDialogs)
$mainScriptOffscreen = $mainScriptOffscreen.Replace('[void]$win.ShowDialog()', '$win.Close()')
$mainScriptOffscreen = $mainScriptOffscreen.Replace('$dialogRes = $win.ShowDialog()', '$win.Close(); $dialogRes = $true')

# Execute main.ps1 offscreen
. ([scriptblock]::Create($mainScriptOffscreen))
Invoke-DispatcherPump

Write-TestLog "Offscreen MainWindow initialized successfully." "Green"

function Get-ActivePanelName {
    $activeTab = $state.OpenTabs | Where-Object { $_.Id -eq $state.ActiveTabId } | Select-Object -First 1
    if ($activeTab) { return $activeTab.PanelName }
    return $state.ActiveTabId
}

function Invoke-MenuItemClick {
    param([string]$MenuName)
    $item = $controls[$MenuName]
    if ($item) {
        $item.RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.MenuItem]::ClickEvent))
    } else {
        throw "Menu item $MenuName not found in controls dictionary!"
    }
}

# 1. Test Horizontal Menu Bar Elements Existence
Write-TestLog "`n--- [Menu Bar Existence] Verifying 11 Top-Level Menus & Submenus ---" "Cyan"

Assert-TestAction "MenuBarCheck" "Verify Menu Bar Controls Registered" {
    $menus = @(
        'MenuFileConnectProfile', 'MenuFileExportCsv', 'MenuEditUndo',
        'MenuViewRefresh', 'MenuViewShowOperational', 'MenuViewAutoFitColumns', 'MenuViewResetColumns',
        'MenuFileNewUser', 'MenuDirObjectCompare', 'MenuSecScanAdminSd', 'MenuDirRecycleBin',
        'MenuSearchDirectory', 'MenuSearchSql', 'MenuToolsBulkEditor', 'MenuToolsLdifStudio',
        'MenuSecAclBrowser', 'MenuReplTopology', 'MenuDiagGroupLoops', 'MenuToolsAuditReports',
        'MenuSecDelegation', 'MenuThemeDark', 'MenuThemeLight', 'MenuReplTrusts',
        'MenuDiagErrorCodeLookup', 'MenuDiagOrgStructure', 'MenuHelpAbout'
    )
    foreach ($m in $menus) {
        if (-not $controls[$m]) { throw "Menu control $m is not registered!" }
    }
}

# 2. Test Menu Bar Navigation & Panel Activation
Write-TestLog "`n--- [Menu Bar Testing] Exercising Top-Level Menu Actions ---" "Cyan"

Assert-TestAction "MenuFileConnectProfile" "File -> Manage Connection Profiles" {
    Invoke-MenuItemClick "MenuFileConnectProfile"
    $p = Get-ActivePanelName
    if ($p -ne "Connections") { throw "Panel did not switch to Connections! Current: $p" }
}

Assert-TestAction "MenuFileExportCsv" "File -> Export Active Subtree to CSV" {
    Invoke-MenuItemClick "MenuFileExportCsv"
}

Assert-TestAction "MenuEditUndo" "Edit -> Undo Last Directory Action" {
    Invoke-MenuItemClick "MenuEditUndo"
}

Assert-TestAction "MenuViewRefresh" "View -> Refresh Active View" {
    Invoke-MenuItemClick "MenuViewRefresh"
}

Assert-TestAction "MenuViewAutoFitColumns" "View -> Auto-Fit Table Columns" {
    Invoke-MenuItemClick "MenuViewAutoFitColumns"
}

Assert-TestAction "MenuViewResetColumns" "View -> Reset Table Columns to Default" {
    Invoke-MenuItemClick "MenuViewResetColumns"
}

Assert-TestAction "MenuFileNewUser" "File -> New Object -> New User" {
    Invoke-MenuItemClick "MenuFileNewUser"
    $p = Get-ActivePanelName
    if ($p -ne "Users") { throw "Panel did not switch to Users! Current: $p" }
}

Assert-TestAction "MenuDirObjectCompare" "Directory -> Dual Object Diff Comparator" {
    Invoke-MenuItemClick "MenuDirObjectCompare"
    $p = Get-ActivePanelName
    if ($p -ne "ObjectCompare") { throw "Panel did not switch to ObjectCompare! Current: $p" }
}

Assert-TestAction "MenuSecScanAdminSd" "Security -> AdminSDHolder Protection Scanner" {
    Invoke-MenuItemClick "MenuSecScanAdminSd"
    $p = Get-ActivePanelName
    if ($p -ne "SecurityAcl") { throw "Panel did not switch to SecurityAcl! Current: $p" }
}

Assert-TestAction "MenuDirRecycleBin" "Directory -> Active Directory Recycle Bin" {
    Invoke-MenuItemClick "MenuDirRecycleBin"
    $p = Get-ActivePanelName
    if ($p -ne "RecycleBin") { throw "Panel did not switch to RecycleBin! Current: $p" }
}

Assert-TestAction "MenuSearchDirectory" "Search -> RFC 4515 Directory Search" {
    Invoke-MenuItemClick "MenuSearchDirectory"
    $p = Get-ActivePanelName
    if ($p -ne "DirectorySearch") { throw "Panel did not switch to DirectorySearch! Current: $p" }
}

Assert-TestAction "MenuSearchSql" "Search -> Extended LDAP-SQL Console" {
    Invoke-MenuItemClick "MenuSearchSql"
    $p = Get-ActivePanelName
    if ($p -ne "LdapSql") { throw "Panel did not switch to LdapSql! Current: $p" }
}

Assert-TestAction "MenuToolsBulkEditor" "Tools -> Bulk CSV Provisioning & Mutation" {
    Invoke-MenuItemClick "MenuToolsBulkEditor"
    $p = Get-ActivePanelName
    if ($p -ne "BulkEditor") { throw "Panel did not switch to BulkEditor! Current: $p" }
}

Assert-TestAction "MenuToolsLdifStudio" "Tools -> LDIF Studio & Script Execution" {
    Invoke-MenuItemClick "MenuToolsLdifStudio"
    $p = Get-ActivePanelName
    if ($p -ne "LdifStudio") { throw "Panel did not switch to LdifStudio! Current: $p" }
}

Assert-TestAction "MenuSecAclBrowser" "Security -> 6-Way Effective Rights & ACL Suite" {
    Invoke-MenuItemClick "MenuSecAclBrowser"
    $p = Get-ActivePanelName
    if ($p -ne "SecurityAcl") { throw "Panel did not switch to SecurityAcl! Current: $p" }
}

Assert-TestAction "MenuReplTopology" "Replication -> Forest Topology & Latency Matrix" {
    Invoke-MenuItemClick "MenuReplTopology"
    $p = Get-ActivePanelName
    if ($p -ne "ReplicationSuite") { throw "Panel did not switch to ReplicationSuite! Current: $p" }
}

Assert-TestAction "MenuDiagGroupLoops" "Diagnostics -> Circular Group Membership Loop Detector" {
    Invoke-MenuItemClick "MenuDiagGroupLoops"
    $p = Get-ActivePanelName
    if ($p -ne "DiagnosticsToolbox") { throw "Panel did not switch to DiagnosticsToolbox! Current: $p" }
}

Assert-TestAction "MenuToolsAuditReports" "Tools -> 48 Security & Hygiene Audit Reports" {
    Invoke-MenuItemClick "MenuToolsAuditReports"
    $p = Get-ActivePanelName
    if ($p -ne "AuditReports") { throw "Panel did not switch to AuditReports! Current: $p" }
}

Assert-TestAction "MenuSecDelegation" "Security -> AD Delegation Matrix Report" {
    Invoke-MenuItemClick "MenuSecDelegation"
    $p = Get-ActivePanelName
    if ($p -ne "SecurityAcl") { throw "Panel did not switch to SecurityAcl! Current: $p" }
}

Assert-TestAction "MenuThemeModes" "View -> Theme Mode Checkmark Toggles" {
    Invoke-MenuItemClick "MenuThemeLight"
    if ($state.CurrentTheme -ne "Light") { throw "Theme did not change to Light! Current: $($state.CurrentTheme)" }
    Invoke-MenuItemClick "MenuThemeDark"
    if ($state.CurrentTheme -ne "Dark") { throw "Theme did not change back to Dark! Current: $($state.CurrentTheme)" }
}

Assert-TestAction "MenuReplTrusts" "Replication -> Active Directory Trusts & Domains Dialog" {
    Invoke-MenuItemClick "MenuReplTrusts"
}

Assert-TestAction "MenuDiagErrorCodeLookup" "Diagnostics -> Win32, LSA & LDAP Error Code Lookup Dialog" {
    Invoke-MenuItemClick "MenuDiagErrorCodeLookup"
}

Assert-TestAction "MenuDiagOrgStructure" "Diagnostics -> Org Structure Hierarchy Dialog" {
    Invoke-MenuItemClick "MenuDiagOrgStructure"
}

Assert-TestAction "MenuHelpAbout" "Help -> About Directory Management Studio" {
    Invoke-MenuItemClick "MenuHelpAbout"
}

# 3. Test High-Value Competitor Engine Integrations
Write-TestLog "`n--- [Competitor Engine Testing] Extended LDAP-SQL, ModLogs, NetTools ---" "Cyan"

Assert-TestAction "LdapSql-ExtendedGrammar" "Extended LDAP-SQL (MODDN, COPY, INTERVAL)" {
    $sqlModDn = "MODDN 'CN=Test,OU=Source,DC=test,DC=local' TO 'OU=Target,DC=test,DC=local'"
    $resModDn = Invoke-ADSqlExtendedQuery -Query $sqlModDn
    if (-not $resModDn.Success) { throw "MODDN query failed: $($resModDn.Message)" }

    $sqlCopy = "COPY 'CN=Test,OU=Source,DC=test,DC=local' TO 'OU=Target,DC=test,DC=local'"
    $resCopy = Invoke-ADSqlExtendedQuery -Query $sqlCopy
    if (-not $resCopy.Success) { throw "COPY query failed: $($resCopy.Message)" }

    $sqlInterval = "SELECT sAMAccountName FROM 'DC=test,DC=local' WHERE whenCreated > CURRENT_DATE - INTERVAL '30 DAYS'"
    $resInterval = Invoke-ADSqlExtendedQuery -Query $sqlInterval
    if (-not $resInterval.Success) { throw "Interval query failed: $($resInterval.Message)" }
}

Assert-TestAction "ModLogs-InverseRollback" "RFC 2849 Modification Logs & Inverse LDIF Rollback" {
    Register-DirectoryMutationLog -Operation "modify" -DistinguishedName "CN=TestUser,DC=test,DC=local" -AttributeChanges "mail: old@test.local -> new@test.local" -InverseLdif "dn: CN=TestUser,DC=test,DC=local`r`nchangetype: modify`r`nreplace: mail`r`nmail: old@test.local`r`n-" -StatusBadge "Success"
    $logs = Get-DirectoryMutationLogs
    if ($logs.Count -eq 0) { throw "Modification log was not recorded!" }
    $lastLog = $logs[0]
    if ($lastLog.InverseLdif -notlike "*replace: mail*") { throw "Inverse LDIF rollback script is missing or invalid!" }
}

Assert-TestAction "NetTools-ErrorLookup" "Win32 / LSA / LDAP Error Code Resolver" {
    $resAccessDenied = Resolve-ADErrorCode -ErrorCode "0x80070005"
    if ($resAccessDenied.SymbolicName -notlike "*ACCESS*DENIED*") { throw "Failed to resolve 0x80070005: $($resAccessDenied.SymbolicName)" }
    $resLdap = Resolve-ADErrorCode -ErrorCode "49"
    if ($resLdap.SymbolicName -notlike "*INVALID_CREDENTIALS*") { throw "Failed to resolve LDAP 49: $($resLdap.SymbolicName)" }
}

Write-TestLog "`n======================================================================" "Cyan"
Write-TestLog "Test Suite Completed: $passedOperations / $totalOperations Operations Passed." "Cyan"
if ($recordedErrors.Count -gt 0) {
    Write-TestLog "Recorded Errors: $($recordedErrors.Count)" "Red"
    foreach ($err in $recordedErrors) {
        Write-TestLog "  - $err" "Red"
    }
    exit 1
} else {
    Write-TestLog "ALL TESTS PASSED WITH 0 ERRORS!" "Green"
    exit 0
}
