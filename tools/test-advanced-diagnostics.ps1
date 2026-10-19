[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidGlobalVars', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingEmptyCatchBlock', '')]
[CmdletBinding()]
param()

$projectRoot = (Get-Location).Path
$logOutput = [System.Collections.Generic.List[string]]::new()
$recordedErrors = [System.Collections.Generic.List[string]]::new()

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
    $null = $title
    $null = $icon
    $null = $text
    Write-TestLog "  [MOCK-MSG] $($title): $text" "DarkGray"
    if ($button -eq [System.Windows.MessageBoxButton]::YesNo -or $button -eq [System.Windows.MessageBoxButton]::YesNoCancel) {
        if ("$title $text" -match 'Delete|Clear|Remove|Purge|Break') {
            return [System.Windows.MessageBoxResult]::No
        }
        return [System.Windows.MessageBoxResult]::Yes
    }
    return [System.Windows.MessageBoxResult]::OK
}

function Invoke-MockInputBox {
    param($prompt, $title, $default)
    $null = $prompt
    $null = $title
    Write-TestLog "  [MOCK-INPUT] $title -> returning: $default" "DarkGray"
    return $default
}

Write-TestLog "======================================================================" "Cyan"
Write-TestLog "Starting Advanced Diagnostics & Panels 13-24 Automated Test Suite" "Cyan"
Write-TestLog "======================================================================" "Cyan"

# Load application modules
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

# Prepare main.ps1 offscreen with neutralized dialog blockers
$mainScript = Get-Content (Join-Path $projectRoot "main.ps1") -Raw -Encoding utf8

$offscreenReplacement = @'
$window.WindowStartupLocation = [System.Windows.WindowStartupLocation]::Manual
$window.Left = -32000
$window.Top = -32000
$window.Show()
'@

$mainScriptOffscreen = $mainScript -replace '\[void\]\$window\.ShowDialog\(\)', $offscreenReplacement
$mainScriptOffscreen = $mainScriptOffscreen -replace '\[System\.Windows\.MessageBox\]::Show', 'Invoke-MockMessageBoxShow'
$mainScriptOffscreen = $mainScriptOffscreen -replace '\[Microsoft\.VisualBasic\.Interaction\]::InputBox', 'Invoke-MockInputBox'

# Neutralize modal dialog windows so they close immediately
$neutralizeDialogs = @'
$dlg.WindowStartupLocation = [System.Windows.WindowStartupLocation]::Manual
$dlg.Left = -32000
$dlg.Top = -32000
$dlg.Show()
try {
    [void][System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([System.Windows.Threading.DispatcherPriority]::Normal, [System.TimeSpan]::FromMilliseconds(50), [Action]{})
} catch { }
$dlg.Close()
'@

$mainScriptOffscreen = $mainScriptOffscreen -replace '\[void\]\$dlg\.ShowDialog\(\)', $neutralizeDialogs
$mainScriptOffscreen = $mainScriptOffscreen -replace '\[void\]\$win\.ShowDialog\(\)', '$win.Close()'
$mainScriptOffscreen = $mainScriptOffscreen -replace '\$dialogRes = \$win\.ShowDialog\(\)', '$win.Close(); $dialogRes = $true'

# File dialog bypasses: mock safe file paths
$tempDir = [System.IO.Path]::GetTempPath()
$tempExportCsv = Join-Path $tempDir "temp_test_export.csv"
$tempImportCsv = Join-Path $tempDir "temp_test_import.csv"
"sAMAccountName,operation,attribute,value`r`njdoe,Set Attribute,title,Senior Architect" | Out-File -FilePath $tempImportCsv -Encoding utf8

$mainScriptOffscreen = $mainScriptOffscreen -replace 'if \(\$saveDlg\.ShowDialog\(\) -eq \[System\.Windows\.Forms\.DialogResult\]::OK\)', "`$saveDlg.FileName = '$tempExportCsv'; if (`$true)"
$mainScriptOffscreen = $mainScriptOffscreen -replace 'if \(\$sfd\.ShowDialog\(\) -eq \[System\.Windows\.Forms\.DialogResult\]::OK\)', "`$sfd.FileName = '$tempExportCsv'; if (`$true)"
$mainScriptOffscreen = $mainScriptOffscreen -replace 'if \(\$sfd\.ShowDialog\(\)\)', "`$sfd.FileName = '$tempExportCsv'; if (`$true)"
$mainScriptOffscreen = $mainScriptOffscreen -replace 'if \(\$dlg\.ShowDialog\(\) -eq \[System\.Windows\.Forms\.DialogResult\]::OK\)', "`$dlg.FileName = '$tempImportCsv'; if (`$true)"
$mainScriptOffscreen = $mainScriptOffscreen -replace 'if \(\$ofd\.ShowDialog\(\)\)', "`$ofd.FileName = '$tempImportCsv'; if (`$true)"
$mainScriptOffscreen = $mainScriptOffscreen -replace 'if \(\$ofd\.ShowDialog\(\) -eq \$true\)', "`$ofd.FileName = '$tempImportCsv'; if (`$true)"
$mainScriptOffscreen = $mainScriptOffscreen -replace 'if \(\$sfd\.ShowDialog\(\) -eq \$true\)', "`$sfd.FileName = '$tempExportCsv'; if (`$true)"

function Assert-ControlAction {
    param (
        [string]$ControlName,
        [string]$Description,
        [scriptblock]$Action
    )
    $beforeErrCount = $global:Error.Count
    Write-TestLog "Testing [$ControlName]: $Description" "Gray"
    try {
        & $Action
        Invoke-DispatcherPump
        $newErrors = $global:Error.Count - $beforeErrCount
        if ($newErrors -gt 0) {
            $latestErr = $global:Error[0]
            Write-TestLog "  -> ERROR in [$ControlName]: $latestErr" "Red"
            $recordedErrors.Add("[$ControlName] $latestErr")
        } else {
            Write-TestLog "  -> PASS [$ControlName]" "Green"
        }
    } catch {
        Write-TestLog "  -> EXCEPTION in [$ControlName]: $_" "Red"
        $recordedErrors.Add("[$ControlName] $_")
    }
}

try {
    # Execute main.ps1 offscreen
    . ([scriptblock]::Create($mainScriptOffscreen))
    Invoke-DispatcherPump

    Write-TestLog "Offscreen MainWindow initialized successfully." "Green"

    # =========================================================================
    # 13. SCHEMA BROWSER PANEL
    # =========================================================================
    Write-TestLog "`n--- [Panel 13] Schema Browser ---" "Cyan"
    Show-Panel "SchemaBrowser"
    Invoke-DispatcherPump

    Assert-ControlAction "TxtSearchSchema" "Filter schema items" {
        $controls['TxtSearchSchema'].Text = "user"
    }

    Assert-ControlAction "BtnRefreshSchema" "Load schema catalog" {
        $controls['BtnRefreshSchema'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Assert-ControlAction "RadioSchemaClasses" "Switch to Object Classes mode" {
        $controls['RadioSchemaClasses'].IsChecked = $true
    }

    Assert-ControlAction "RadioSchemaAttributes" "Switch to Attribute Types mode" {
        $controls['RadioSchemaAttributes'].IsChecked = $true
    }

    Assert-ControlAction "GridSchema" "Select schema item and update details" {
        if ($controls['GridSchema'].Items.Count -gt 0) {
            $controls['GridSchema'].SelectedIndex = 0
        }
    }

    Assert-ControlAction "BtnRunSchemaAudit" "Execute schema integrity audit" {
        $controls['BtnRunSchemaAudit'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Assert-ControlAction "BtnExportSchemaOpenLdap" "Export schema to OpenLDAP" {
        $controls['BtnExportSchemaOpenLdap'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Assert-ControlAction "BtnExportSchemaLdif" "Export schema to LDIF" {
        $controls['BtnExportSchemaLdif'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    # =========================================================================
    # 14. BULK EDITOR PANEL
    # =========================================================================
    Write-TestLog "`n--- [Panel 14] Bulk Editor ---" "Cyan"
    Show-Panel "BulkEditor"
    Invoke-DispatcherPump

    Assert-ControlAction "TxtBulkCsvPath" "Set CSV path" {
        $controls['TxtBulkCsvPath'].Text = $tempImportCsv
    }

    Assert-ControlAction "BtnBrowseBulkCsv" "Browse for CSV" {
        $controls['BtnBrowseBulkCsv'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Assert-ControlAction "BtnValidateBulk" "Validate CSV Batch data" {
        $controls['BtnValidateBulk'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Assert-ControlAction "BtnExportBulkTemplate" "Export standard CSV Template" {
        $controls['BtnExportBulkTemplate'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Assert-ControlAction "BtnExecuteBulk" "Execute bulk CSV batch operations" {
        $controls['BtnExecuteBulk'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    # =========================================================================
    # 15. BASKET PANEL
    # =========================================================================
    Write-TestLog "`n--- [Panel 15] Directory Basket ---" "Cyan"
    Show-Panel "Basket"
    Invoke-DispatcherPump

    Assert-ControlAction "ListBasketItems" "Inspect staged basket items" {
        if (-not $state.BasketItems) {
            $state.BasketItems = [System.Collections.ObjectModel.ObservableCollection[psobject]]::new()
        }
        $state.BasketItems.Add([PSCustomObject]@{
            Class = "user"; Name = "Jane Doe"; SamAccountName = "jdoe"; Status = "Active"; OUPath = "OU=Staff,DC=corp,DC=local"; DistinguishedName = "CN=Jane Doe,OU=Staff,DC=corp,DC=local"
        })
        $controls['GridBasket'].ItemsSource = $state.BasketItems
    }

    Assert-ControlAction "BtnBulkActionExecute" "Execute bulk basket modification" {
        $controls['BtnBulkActionExecute'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Assert-ControlAction "BtnExportBasket" "Export staged basket items to CSV" {
        $controls['BtnExportBasket'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Assert-ControlAction "BtnRemoveFromBasket" "Remove selected item from basket" {
        if ($controls['GridBasket'].Items.Count -gt 0) {
            $controls['GridBasket'].SelectedIndex = 0
            $controls['BtnRemoveFromBasket'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
        }
    }

    Assert-ControlAction "BtnClearBasket" "Clear entire directory basket" {
        $controls['BtnClearBasket'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    # =========================================================================
    # 16. REQUEST LOG PANEL
    # =========================================================================
    Write-TestLog "`n--- [Panel 16] Request Log ---" "Cyan"
    Show-Panel "RequestLog"
    Invoke-DispatcherPump

    Assert-ControlAction "GridRequestLog" "Log dummy request and check items" {
        Log-LdapRequest -Operation "SEARCH" -TargetDN "DC=corp,DC=local" -FilterOrPayload "(objectClass=user)" -DurationMs 12 -Status "SUCCESS" -Details "Query completed"
        Invoke-DispatcherPump
    }

    Assert-ControlAction "CmbFilterRequestLog" "Filter request log by operation type" {
        if ($controls['CmbFilterRequestLog'].Items.Count -gt 1) {
            $controls['CmbFilterRequestLog'].SelectedIndex = 1 # SEARCH
            Invoke-DispatcherPump
            $controls['CmbFilterRequestLog'].SelectedIndex = 0 # All Operations
        }
    }

    Assert-ControlAction "BtnExportRequestLog" "Export request log entries" {
        $controls['BtnExportRequestLog'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Assert-ControlAction "BtnClearRequestLog" "Clear wire request log" {
        $controls['BtnClearRequestLog'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    # =========================================================================
    # 17. CONNECTIONS PANEL
    # =========================================================================
    Write-TestLog "`n--- [Panel 17] Connection Profiles ---" "Cyan"
    Show-Panel "Connections"
    Invoke-DispatcherPump

    Assert-ControlAction "BtnAutoDetectConnections" "Auto-detect Active Directory connections and probe latency" {
        $controls['BtnAutoDetectConnections'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Assert-ControlAction "BtnSortPingAsc" "Sort AD connections by ping latency ascending" {
        $controls['BtnSortPingAsc'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Assert-ControlAction "BtnSortPingDesc" "Sort AD connections by ping latency descending" {
        $controls['BtnSortPingDesc'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Assert-ControlAction "GridActiveConnections" "Select connection from active connections grid" {
        if ($controls['GridActiveConnections'] -and $controls['GridActiveConnections'].Items.Count -gt 0) {
            $controls['GridActiveConnections'].SelectedIndex = 0
        }
    }

    Assert-ControlAction "ListSavedProfiles" "View saved connection profiles" {
        if ($controls['ListProfiles'].Items.Count -gt 0) {
            $controls['ListProfiles'].SelectedIndex = 0
        }
    }

    Assert-ControlAction "BtnNewProfile" "Launch New Profile Dialog" {
        $controls['BtnNewProfile'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Assert-ControlAction "BtnTestConnection" "Test Active Directory connection" {
        $controls['BtnTestConnection'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Assert-ControlAction "BtnConnectProfile" "Connect to active profile" {
        $controls['BtnConnectProfile'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Assert-ControlAction "BtnSaveProfile" "Save connection profiles" {
        $controls['BtnSaveProfile'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Assert-ControlAction "BtnDeleteProfile" "Delete profile safely" {
        $controls['BtnDeleteProfile'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    # =========================================================================
    # 18. SETTINGS PANEL
    # =========================================================================
    Write-TestLog "`n--- [Panel 18] Settings & Preferences ---" "Cyan"
    Show-Panel "Settings"
    Invoke-DispatcherPump

    Assert-ControlAction "CmbThemeMode" "Toggle interface theme mode" {
        $controls['CmbThemeMode'].SelectedIndex = 1
        $controls['CmbThemeMode'].SelectedIndex = 0
    }

    Assert-ControlAction "CmbAccentTone" "Change accent tone color" {
        $controls['CmbAccentTone'].SelectedIndex = 2
        $controls['CmbAccentTone'].SelectedIndex = 0
    }

    Assert-ControlAction "CmbExportDelimiter" "Switch CSV delimiter" {
        $controls['CmbExportDelimiter'].SelectedIndex = 1
        $controls['CmbExportDelimiter'].SelectedIndex = 0
    }

    Assert-ControlAction "CmbUsernameFormat" "Switch username format" {
        $controls['CmbUsernameFormat'].SelectedIndex = 1
        $controls['CmbUsernameFormat'].SelectedIndex = 0
    }

    Assert-ControlAction "ChkCfgRequirePwChange" "Toggle require password change" {
        $controls['ChkCfgRequirePwChange'].IsChecked = $false
        $controls['ChkCfgRequirePwChange'].IsChecked = $true
    }

    Assert-ControlAction "ChkThemeAutoSync" "Toggle HTML theme auto-sync" {
        $controls['ChkThemeAutoSync'].IsChecked = $false
        $controls['ChkThemeAutoSync'].IsChecked = $true
    }

    Assert-ControlAction "BtnSaveSettings" "Save application settings" {
        $controls['BtnSaveSettings'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Assert-ControlAction "BtnResetSettings" "Reset settings to defaults" {
        $controls['BtnResetSettings'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    # =========================================================================
    # 19. RECYCLE BIN PANEL
    # =========================================================================
    Write-TestLog "`n--- [Panel 19] Recycle Bin & Tombstones ---" "Cyan"
    Show-Panel "RecycleBin"
    Invoke-DispatcherPump

    Assert-ControlAction "BtnLoadRecycleBin" "Query deleted tombstone objects" {
        $controls['BtnLoadRecycleBin'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Assert-ControlAction "GridRecycleBin" "Select deleted tombstone object" {
        if ($controls['GridRecycleBin'].Items.Count -gt 0) {
            $controls['GridRecycleBin'].SelectedIndex = 0
        }
    }

    Assert-ControlAction "BtnRestoreObject" "Restore tombstone object" {
        $controls['BtnRestoreObject'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Assert-ControlAction "BtnPurgeObject" "Purge deleted object permanently" {
        $controls['BtnPurgeObject'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    # =========================================================================
    # 20. SERVER MONITOR PANEL
    # =========================================================================
    Write-TestLog "`n--- [Panel 20] Server Monitor ---" "Cyan"
    Show-Panel "ServerMonitor"
    Invoke-DispatcherPump

    Assert-ControlAction "BtnRefreshServerMonitor" "Refresh server telemetry and RootDSE" {
        $controls['BtnRefreshServerMonitor'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Assert-ControlAction "BtnRefreshDcHealth" "Refresh multi-DC health diagnostic matrix" {
        $controls['BtnRefreshDcHealth'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Assert-ControlAction "GridDcHealth" "Verify DC health matrix data" {
        if ($controls['GridDcHealth'].Items.Count -gt 0) {
            $controls['GridDcHealth'].SelectedIndex = 0
        }
    }

    Assert-ControlAction "BtnPingAllDcs" "Ping all domain controllers" {
        $controls['BtnPingAllDcs'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Assert-ControlAction "BtnCheckDnsReplication" "Check DNS partition replication" {
        $controls['BtnCheckDnsReplication'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    # =========================================================================
    # 21. SECURITY ACL PANEL
    # =========================================================================
    Write-TestLog "`n--- [Panel 21] Security & ACL Suite ---" "Cyan"
    Show-Panel "SecurityAcl"
    Invoke-DispatcherPump

    Assert-ControlAction "TxtAclTargetDN" "Set ACL Target DN" {
        $controls['TxtAclTargetDN'].Text = if ($adContext.DefaultNamingContext) { $adContext.DefaultNamingContext } else { "DC=corp,DC=local" }
    }

    Assert-ControlAction "BtnAclLoad" "Load and inspect object ACL" {
        $controls['BtnAclLoad'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Assert-ControlAction "BtnAclCopySddl" "Copy SDDL string to clipboard" {
        $controls['BtnAclCopySddl'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Assert-ControlAction "GridAclAces" "Select ACE in DataGrid" {
        if ($controls['GridAclAces'].Items.Count -gt 0) {
            $controls['GridAclAces'].SelectedIndex = 0
        }
    }

    Assert-ControlAction "TxtAclTrustee" "Set trustee for effective rights calculation" {
        $controls['TxtAclTrustee'].Text = "Domain Admins"
    }

    Assert-ControlAction "BtnAclCalcEffective" "Calculate effective permissions" {
        $controls['BtnAclCalcEffective'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Assert-ControlAction "RadEffFilterAll" "Filter effective permissions: All" {
        $controls['RadEffFilterAll'].IsChecked = $true
    }

    Assert-ControlAction "RadEffFilterAllowed" "Filter effective permissions: Allowed" {
        $controls['RadEffFilterAllowed'].IsChecked = $true
    }

    Assert-ControlAction "RadEffFilterDenied" "Filter effective permissions: Denied" {
        $controls['RadEffFilterDenied'].IsChecked = $true
    }

    Assert-ControlAction "RadEffFilterWrite" "Filter effective permissions: Write" {
        $controls['RadEffFilterWrite'].IsChecked = $true
        $controls['RadEffFilterAll'].IsChecked = $true
    }

    Assert-ControlAction "BtnAclResetTraceFilter" "Reset effective rights filter" {
        $controls['BtnAclResetTraceFilter'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Assert-ControlAction "BtnAclListUsers" "List recursive trustee members" {
        $controls['BtnAclListUsers'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Assert-ControlAction "BtnScanAdminSdHolder" "Scan AdminSDHolder orphan accounts" {
        $controls['BtnScanAdminSdHolder'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Assert-ControlAction "GridAdminSdOrphans" "Select AdminSDHolder orphan entry" {
        if ($controls['GridAdminSdOrphans'].Items.Count -gt 0) {
            $controls['GridAdminSdOrphans'].SelectedIndex = 0
        }
    }

    Assert-ControlAction "BtnFixAdminSdHolder" "Remediate selected AdminSDHolder orphan" {
        $controls['BtnFixAdminSdHolder'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Assert-ControlAction "BtnFixAllAdminSdHolder" "Batch remediate all AdminSDHolder orphans" {
        $controls['BtnFixAllAdminSdHolder'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Assert-ControlAction "BtnTriggerSdProp" "Trigger SDProp propagation task on PDC" {
        $controls['BtnTriggerSdProp'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Assert-ControlAction "CmbDelegationScope" "Set delegation report scope" {
        if ($controls['CmbDelegationScope'].Items.Count -gt 0) {
            $controls['CmbDelegationScope'].SelectedIndex = 0
        }
    }

    Assert-ControlAction "BtnRunDelegationReport" "Run domain delegation security audit" {
        $controls['BtnRunDelegationReport'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Assert-ControlAction "BtnExportDelegationReport" "Export delegation security audit report" {
        $controls['BtnExportDelegationReport'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Assert-ControlAction "TxtAclCompareObjA" "Configure ACL comparison targets" {
        $domainNC = if ($adContext.DefaultNamingContext) { $adContext.DefaultNamingContext } else { "DC=corp,DC=local" }
        $controls['TxtAclCompareObjA'].Text = "CN=Administrator,CN=Users,$domainNC"
        $controls['TxtAclCompareObjB'].Text = "CN=Guest,CN=Users,$domainNC"
    }

    Assert-ControlAction "BtnRunAclCompare" "Execute side-by-side ACL comparison" {
        $controls['BtnRunAclCompare'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Assert-ControlAction "BtnLoadExtRights" "Query extended rights catalog" {
        $controls['BtnLoadExtRights'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Assert-ControlAction "TxtPropSetFilter" "Set property sets query filter" {
        $controls['TxtPropSetFilter'].Text = "Phone"
    }

    Assert-ControlAction "BtnSearchPropSets" "Search property sets in schema" {
        $controls['BtnSearchPropSets'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Assert-ControlAction "TxtAclFindTrusteeInput" "Set trustee for domain rights search" {
        $controls['TxtAclFindTrusteeInput'].Text = "Domain Admins"
    }

    Assert-ControlAction "BtnAclFindTrusteeAssignments" "Scan domain objects for trustee rights" {
        $controls['BtnAclFindTrusteeAssignments'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Assert-ControlAction "BtnExportTrusteeAssignments" "Export trustee rights report" {
        $controls['BtnExportTrusteeAssignments'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    # =========================================================================
    # 22. KERBEROS SUITE PANEL
    # =========================================================================
    Write-TestLog "`n--- [Panel 22] Kerberos & Authentication Suite ---" "Cyan"
    Show-Panel "KerberosSuite"
    Invoke-DispatcherPump

    Assert-ControlAction "BtnRefreshTickets" "Query cached Kerberos tickets via klist" {
        $controls['BtnRefreshTickets'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Assert-ControlAction "BtnPurgeTickets" "Purge ticket cache via klist purge" {
        $controls['BtnPurgeTickets'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Assert-ControlAction "TxtTestSpn" "Specify SPN target" {
        $controls['TxtTestSpn'].Text = "HOST/dc01.corp.local"
    }

    Assert-ControlAction "BtnTestSpnTicket" "Request Kerberos TGS ticket for SPN" {
        $controls['BtnTestSpnTicket'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Assert-ControlAction "TxtTokenUser" "Specify user for token size calculation" {
        $controls['TxtTokenUser'].Text = "Administrator"
    }

    Assert-ControlAction "BtnCalcTokenSize" "Calculate Kerberos MaxTokenSize & token groups" {
        $controls['BtnCalcTokenSize'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Assert-ControlAction "GridTokenGroups" "Inspect calculated token groups" {
        if ($controls['GridTokenGroups'].Items.Count -gt 0) {
            $controls['GridTokenGroups'].SelectedIndex = 0
        }
    }

    Assert-ControlAction "BtnRefreshRidPool" "Query domain RID pool allocation" {
        $controls['BtnRefreshRidPool'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    # =========================================================================
    # 23. REPLICATION SUITE PANEL
    # =========================================================================
    Write-TestLog "`n--- [Panel 23] Replication & Multi-DC Suite ---" "Cyan"
    Show-Panel "ReplicationSuite"
    Invoke-DispatcherPump

    Assert-ControlAction "BtnRefreshReplicationSuite" "Refresh replication topology" {
        $controls['BtnRefreshReplicationSuite'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Assert-ControlAction "TxtMultiDcTarget" "Configure target user for multi-DC query" {
        $controls['TxtMultiDcTarget'].Text = "Administrator"
    }

    Assert-ControlAction "BtnScanMultiDcLogon" "Query real-time logon timestamps across all DCs" {
        $controls['BtnScanMultiDcLogon'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Assert-ControlAction "BtnScanSubnetOverlaps" "Audit subnet site coverage and overlaps" {
        $controls['BtnScanSubnetOverlaps'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Assert-ControlAction "BtnExportSubnets" "Export subnet audit to CSV" {
        $controls['BtnExportSubnets'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Assert-ControlAction "BtnCheckGpoSync" "Audit Group Policy consistency and sysvol replication" {
        $controls['BtnCheckGpoSync'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Assert-ControlAction "TxtReplMetaTarget" "Set target object for attribute replication metadata" {
        $domainNC = if ($adContext.DefaultNamingContext) { $adContext.DefaultNamingContext } else { "DC=corp,DC=local" }
        $controls['TxtReplMetaTarget'].Text = "CN=Administrator,CN=Users,$domainNC"
    }

    Assert-ControlAction "BtnGetReplMetadata" "Query msDS-ReplAttributeMetaData" {
        $controls['BtnGetReplMetadata'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Assert-ControlAction "BtnLoadSiteBrowser" "Query Active Directory Sites and Topology" {
        $controls['BtnLoadSiteBrowser'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Assert-ControlAction "BtnRunLatencyProbe" "Measure inter-DC replication latency" {
        $controls['BtnRunLatencyProbe'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Assert-ControlAction "BtnLoadSchemaMatrix" "Query schema convergence matrix" {
        $controls['BtnLoadSchemaMatrix'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    # =========================================================================
    # 24. DIAGNOSTICS TOOLBOX & NETWORK DIAGNOSTICS
    # =========================================================================
    Write-TestLog "`n--- [Panel 24] Diagnostics Toolbox & Network Diagnostics ---" "Cyan"
    Show-Panel "DiagnosticsToolbox"
    Invoke-DispatcherPump

    Assert-ControlAction "BtnScanGroupCycles" "Scan domain group nesting loops" {
        $controls['BtnScanGroupCycles'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Assert-ControlAction "BtnBreakLoop" "Remediate circular group loop" {
        $controls['BtnBreakLoop'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Assert-ControlAction "BtnDiagOpenResolver" "Open Resolver scratchpad" {
        $controls['BtnDiagOpenResolver'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Show-Panel "NetworkDiagnostics"
    Invoke-DispatcherPump

    Assert-ControlAction "TxtNetDiagTargetHost" "Set target host for network scan" {
        $controls['TxtNetDiagTargetHost'].Text = "dc01.corp.local"
    }

    Assert-ControlAction "BtnTestAllPorts" "Scan Active Directory service ports" {
        $controls['BtnTestAllPorts'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Assert-ControlAction "BtnTestPing" "Ping target domain controller" {
        $controls['BtnTestPing'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Assert-ControlAction "BtnTestDns" "Resolve DNS for target host" {
        $controls['BtnTestDns'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Assert-ControlAction "TxtTestUncPath" "Set target UNC share path" {
        $controls['TxtTestUncPath'].Text = "\\dc01.corp.local\SYSVOL"
    }

    Assert-ControlAction "BtnTestUnc7Tier" "Execute 7-Step UNC accessibility test" {
        $controls['BtnTestUnc7Tier'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    # =========================================================================
    # 25. GLOBAL HEADER CONTROLS
    # =========================================================================
    Write-TestLog "`n--- [Header] Global Header Controls & Quick Launchers ---" "Cyan"

    Assert-ControlAction "TxtGlobalSearch" "Quick search autocomplete" {
        $controls['TxtGlobalSearch'].Text = "admin"
    }

    Assert-ControlAction "PopupGlobalSearch" "Verify popup display" {
        $null = $controls['PopupGlobalSearch'].IsOpen
    }

    Assert-ControlAction "BtnHeaderQuickTools" "Open Quick Tools Dropdown Menu" {
        $controls['BtnHeaderQuickTools'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Assert-ControlAction "MenuToolsResolver" "Launch Resolver Scratchpad via Menu" {
        $controls['MenuToolsResolver'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.MenuItem]::ClickEvent))
    }

    Assert-ControlAction "MenuToolsGpoExplorer" "Launch GPO Explorer via Menu" {
        $controls['MenuToolsGpoExplorer'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.MenuItem]::ClickEvent))
    }

    Assert-ControlAction "MenuToolsAsn1Viewer" "Launch ASN.1 Viewer via Menu" {
        $controls['MenuToolsAsn1Viewer'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.MenuItem]::ClickEvent))
    }

    Assert-ControlAction "MenuToolsDiffViewer" "Launch Side-by-Side Diff Viewer via Menu" {
        $controls['MenuToolsDiffViewer'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.MenuItem]::ClickEvent))
    }

    Assert-ControlAction "BtnHeaderResolver" "Launch Resolver Scratchpad" {
        $controls['BtnHeaderResolver'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Assert-ControlAction "BtnHeaderLockout" "Launch Lockout Investigator" {
        $controls['BtnHeaderLockout'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Assert-ControlAction "BtnHeaderGpoExplorer" "Launch GPO Explorer" {
        $controls['BtnHeaderGpoExplorer'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Assert-ControlAction "BtnHeaderAsn1Viewer" "Launch ASN.1 Viewer" {
        $controls['BtnHeaderAsn1Viewer'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Assert-ControlAction "BtnHeaderDiffViewer" "Launch Side-by-Side Diff Viewer" {
        $controls['BtnHeaderDiffViewer'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Assert-ControlAction "BtnThemeToggle" "Toggle Dark / Light theme" {
        $controls['BtnThemeToggle'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
        $controls['BtnThemeToggle'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Assert-ControlAction "BtnWorkspaceNewTab" "Create new workspace tab" {
        $controls['BtnWorkspaceNewTab'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Assert-ControlAction "BtnWorkspaceDetachCurrent" "Detach current tab to window" {
        $controls['BtnWorkspaceDetachCurrent'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    Assert-ControlAction "BtnWorkspaceDockAll" "Dock all detached windows" {
        $controls['BtnWorkspaceDockAll'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }

    # Clean up temporary test files
    if (Test-Path $tempExportCsv) { Remove-Item $tempExportCsv -Force -ErrorAction SilentlyContinue }
    if (Test-Path $tempImportCsv) { Remove-Item $tempImportCsv -Force -ErrorAction SilentlyContinue }

    # Close offscreen window safely
    $window.Close()
    Invoke-DispatcherPump

} catch {
    Write-TestLog "FATAL TEST HARNESS ERROR: $_" "Red"
    $recordedErrors.Add("FATAL: $_")
}

Write-TestLog "`n======================================================================" "Cyan"
Write-TestLog "DIAGNOSTIC TEST SUMMARY REPORT" "Cyan"
Write-TestLog "======================================================================" "Cyan"
Write-TestLog "Total Errors Encountered: $($recordedErrors.Count)" $(if ($recordedErrors.Count -eq 0) { "Green" } else { "Red" })

if ($recordedErrors.Count -gt 0) {
    Write-TestLog "Errors detail:" "Red"
    foreach ($err in $recordedErrors) {
        Write-TestLog "  - $err" "Red"
    }
    exit 1
} else {
    Write-TestLog "ALL PANELS (13-24) AND GLOBAL CONTROLS PASSED WITH 0 ERRORS!" "Green"
    exit 0
}
