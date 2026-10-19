[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidGlobalVars', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingEmptyCatchBlock', '')]
[CmdletBinding()]
param()

$projectRoot = (Get-Location).Path

# Ensure STA apartment mode if invoked directly with pwsh -STA

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
    if ($text -is [System.Array] -and $null -eq $title -and $null -eq $button) {
        $arr = $text
        $text = if ($arr.Count -gt 0) { $arr[0] } else { "" }
        $title = if ($arr.Count -gt 1) { $arr[1] } else { "" }
        $button = if ($arr.Count -gt 2) { $arr[2] } else { $null }
        $icon = if ($arr.Count -gt 3) { $arr[3] } else { $null }
    }
    $null = $icon
    Write-TestLog "  [MOCK-MSG] $($title): $text" "DarkGray"
    if ($button -eq [System.Windows.MessageBoxButton]::YesNo -or $button -eq [System.Windows.MessageBoxButton]::YesNoCancel -or "$button" -match "YesNo") {
        if ("$title $text" -match 'Delete|Clear|Remove|Purge|Break|Status|Change|Enable|Disable|Toggle') {
            return [System.Windows.MessageBoxResult]::No
        }
        return [System.Windows.MessageBoxResult]::Yes
    }
    return [System.Windows.MessageBoxResult]::OK
}

function Invoke-MockInputBox {
    param($prompt, $title, $default)
    if ($prompt -is [System.Array] -and $null -eq $title) {
        $arr = $prompt
        $prompt = if ($arr.Count -gt 0) { $arr[0] } else { "" }
        $title = if ($arr.Count -gt 1) { $arr[1] } else { "" }
        $default = if ($arr.Count -gt 2) { $arr[2] } else { "" }
    }
    $null = $prompt
    Write-TestLog "  [MOCK-INPUT] $title -> returning: $default" "DarkGray"
    return $default
}

function Invoke-MockClipboardSet {
    param($data, $arg2)
    $null = $arg2
    if ($data -is [System.Array]) { $data = $data[0] }
    Write-TestLog "  [MOCK-CLIPBOARD] Content copied ($([string]$data).Length chars)" "DarkGray"
}

function Invoke-ControlClick {
    param ($Control)
    if ($Control) {
        $Control.RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }
}

function Invoke-CardMouseDown {
    param ($Control)
    if ($Control) {
        try {
            $mouseArgs = [System.Windows.Input.MouseButtonEventArgs]::new([System.Windows.Input.Mouse]::PrimaryDevice, 0, [System.Windows.Input.MouseButton]::Left)
            $mouseArgs.RoutedEvent = [System.Windows.UIElement]::MouseDownEvent
            $Control.RaiseEvent($mouseArgs)
        } catch {
            $null = $_
        }
    }
}

function Invoke-TextBoxEnter {
    param ($TextBox, [scriptblock]$FallbackAction)
    if ($TextBox) {
        $handled = $false
        try {
            $src = [System.Windows.PresentationSource]::FromVisual($window)
            if ($src) {
                $keyArgs = [System.Windows.Input.KeyEventArgs]::new([System.Windows.Input.Keyboard]::PrimaryDevice, $src, 0, [System.Windows.Input.Key]::Enter)
                $keyArgs.RoutedEvent = [System.Windows.UIElement]::KeyDownEvent
                $TextBox.RaiseEvent($keyArgs)
                $handled = $true
            }
        } catch {
            $handled = $false
        }
        if (-not $handled -and $FallbackAction) {
            & $FallbackAction
        }
    }
}

function Assert-ControlAction {
    param (
        [string]$ControlName,
        [string]$Description,
        [scriptblock]$Action
    )
    $script:totalOperations++
    $beforeErrCount = $global:Error.Count
    Write-TestLog "Testing [$ControlName]: $Description" "Gray"
    try {
        & $Action
        Write-TestLog "  [ACTION-DONE] [$ControlName]" "DarkGray"
        Invoke-DispatcherPump
        Write-TestLog "  [PUMP-DONE] [$ControlName]" "DarkGray"
        $newErrors = $global:Error.Count - $beforeErrCount
        if ($newErrors -gt 0) {
            $latestErr = $global:Error[0]
            Write-TestLog "  -> ERROR in [$ControlName]: $latestErr" "Red"
            $recordedErrors.Add("[$ControlName] $latestErr")
        } else {
            $script:passedOperations++
            Write-TestLog "  -> PASS [$ControlName]" "Green"
        }
    } catch {
        Write-TestLog "  -> EXCEPTION in [$ControlName]: $_" "Red"
        $recordedErrors.Add("[$ControlName] $_")
    }
}

Write-TestLog "======================================================================" "Cyan"
Write-TestLog "Starting Core Operations Test Suite: Panels 1 - 12 (Programmatic UI)" "Cyan"
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
$mainScriptOffscreen = $mainScriptOffscreen.Replace('[System.Windows.Clipboard]::SetDataObject(', 'Invoke-MockClipboardSet(')
$mainScriptOffscreen = $mainScriptOffscreen.Replace('[System.Windows.Clipboard]::SetText(', 'Invoke-MockClipboardSet(')
$mainScriptOffscreen = $mainScriptOffscreen.Replace('Start-Process $tempPath', 'Write-Host "  [MOCK-BROWSER] External browser launch bypassed"')

$mainScriptOffscreen = $mainScriptOffscreen.Replace('[void]$dlg.ShowDialog()', $neutralizeDialogs)
$mainScriptOffscreen = $mainScriptOffscreen.Replace('[void]$win.ShowDialog()', '$win.Close()')
$mainScriptOffscreen = $mainScriptOffscreen.Replace('$dialogRes = $win.ShowDialog()', '$win.Close(); $dialogRes = $true')

# File dialog bypasses: mock safe file paths
$tempDir = [System.IO.Path]::GetTempPath()
$tempExportCsv = Join-Path $tempDir "temp_test_core_export.csv"
$tempImportCsv = Join-Path $tempDir "temp_test_core_import.csv"
"sAMAccountName,operation,attribute,value`r`njdoe,Set Attribute,title,Senior Architect" | Out-File -FilePath $tempImportCsv -Encoding utf8

$mainScriptOffscreen = $mainScriptOffscreen.Replace('if ($saveDlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK)', "`$saveDlg.FileName = '$tempExportCsv'; if (`$true)")
$mainScriptOffscreen = $mainScriptOffscreen.Replace('if ($sfd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK)', "`$sfd.FileName = '$tempExportCsv'; if (`$true)")
$mainScriptOffscreen = $mainScriptOffscreen.Replace('if ($sfd.ShowDialog())', "`$sfd.FileName = '$tempExportCsv'; if (`$true)")
$mainScriptOffscreen = $mainScriptOffscreen.Replace('if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK)', "`$dlg.FileName = '$tempImportCsv'; if (`$true)")
$mainScriptOffscreen = $mainScriptOffscreen.Replace('if ($ofd.ShowDialog())', "`$ofd.FileName = '$tempImportCsv'; if (`$true)")
$mainScriptOffscreen = $mainScriptOffscreen.Replace('if ($ofd.ShowDialog() -eq $true)', "`$ofd.FileName = '$tempImportCsv'; if (`$true)")
$mainScriptOffscreen = $mainScriptOffscreen.Replace('if ($sfd.ShowDialog() -eq $true)', "`$sfd.FileName = '$tempExportCsv'; if (`$true)")

try {
    # Execute main.ps1 offscreen
    . ([scriptblock]::Create($mainScriptOffscreen))
    Invoke-DispatcherPump

    Write-TestLog "Offscreen MainWindow initialized successfully." "Green"

    # =========================================================================
    # 1. DASHBOARD PANEL
    # =========================================================================
    Write-TestLog "`n--- [Panel 1] Dashboard ---" "Cyan"
    Show-Panel "Dashboard"
    Invoke-DispatcherPump

    Assert-ControlAction "Refresh-Dashboard" "Refresh dashboard statistics" {
        Refresh-Dashboard
    }

    Assert-ControlAction "CardBtnActiveUsers" "Card button drill down to Active Users" {
        Invoke-CardMouseDown $controls['CardBtnActiveUsers']
    }

    Assert-ControlAction "CardBtnDisabledUsers" "Card button drill down to Disabled Users" {
        Invoke-CardMouseDown $controls['CardBtnDisabledUsers']
    }

    Assert-ControlAction "CardBtnLockedUsers" "Card button drill down to Locked Users" {
        Invoke-CardMouseDown $controls['CardBtnLockedUsers']
    }

    Assert-ControlAction "CardBtnGroups" "Card button drill down to Groups" {
        Invoke-CardMouseDown $controls['CardBtnGroups']
    }

    Assert-ControlAction "CardBtnOUs" "Card button drill down to OUs" {
        Invoke-CardMouseDown $controls['CardBtnOUs']
    }

    Assert-ControlAction "BtnDashSearch" "Dashboard quick launcher for Directory Search" {
        Invoke-ControlClick $controls['BtnDashSearch']
    }

    Assert-ControlAction "BtnDashSql" "Dashboard quick launcher for LDAP-SQL" {
        Invoke-ControlClick $controls['BtnDashSql']
    }

    Assert-ControlAction "BtnDashAttributes" "Dashboard quick launcher for Attribute Editor" {
        Invoke-ControlClick $controls['BtnDashAttributes']
    }

    Assert-ControlAction "BtnDashAudits" "Dashboard quick launcher for Security Audits" {
        Invoke-ControlClick $controls['BtnDashAudits']
    }

    Assert-ControlAction "BtnDashTestConn" "Dashboard quick launcher for Connection Test" {
        Invoke-ControlClick $controls['BtnDashTestConn']
    }

    Assert-ControlAction "BtnDiagnostics" "Diagnostics button launcher" {
        Invoke-ControlClick $controls['BtnDiagnostics']
    }

    # =========================================================================
    # 2. USERS PANEL
    # =========================================================================
    Write-TestLog "`n--- [Panel 2] Users ---" "Cyan"
    Show-Panel "Users"
    Invoke-DispatcherPump

    Assert-ControlAction "TxtSearchUsers" "Type search query and trigger live filter" {
        $controls['TxtSearchUsers'].Text = "admin"
        Invoke-TextBoxEnter $controls['TxtSearchUsers'] { Refresh-Users }
    }

    Assert-ControlAction "BtnSearchUsers" "Click search users button" {
        Invoke-ControlClick $controls['BtnSearchUsers']
    }

    Assert-ControlAction "BtnClearSearchUsers" "Clear search users input" {
        Invoke-ControlClick $controls['BtnClearSearchUsers']
    }

    Assert-ControlAction "FilterUserActive" "Switch user filter to Active" {
        $controls['FilterUserActive'].IsChecked = $true
    }

    Assert-ControlAction "FilterUserDisabled" "Switch user filter to Disabled" {
        $controls['FilterUserDisabled'].IsChecked = $true
    }

    Assert-ControlAction "FilterUserLocked" "Switch user filter to Locked" {
        $controls['FilterUserLocked'].IsChecked = $true
    }

    Assert-ControlAction "FilterUserAll" "Switch user filter to All" {
        $controls['FilterUserAll'].IsChecked = $true
    }

    Assert-ControlAction "CmbUserOUFilter" "Select OU filter dropdown item" {
        if ($controls['CmbUserOUFilter'].Items.Count -gt 0) {
            $controls['CmbUserOUFilter'].SelectedIndex = 0
        }
    }

    Assert-ControlAction "BtnNewUser" "Open New User dialog and save/cancel" {
        Invoke-ControlClick $controls['BtnNewUser']
    }

    Assert-ControlAction "BtnEditUser" "Open Edit User dialog for selected user" {
        if ($controls['GridUsers'].Items.Count -gt 0) {
            $controls['GridUsers'].SelectedIndex = 0
            Invoke-ControlClick $controls['BtnEditUser']
        }
    }

    Assert-ControlAction "BtnResetPassword" "Trigger password reset for selected user" {
        if ($controls['GridUsers'].Items.Count -gt 0) {
            $controls['GridUsers'].SelectedIndex = 0
            Invoke-ControlClick $controls['BtnResetPassword']
        }
    }

    Assert-ControlAction "BtnToggleUserStatus" "Toggle user account status (enable/disable)" {
        if ($controls['GridUsers'].Items.Count -gt 0) {
            $controls['GridUsers'].SelectedIndex = 0
            Invoke-ControlClick $controls['BtnToggleUserStatus']
        }
    }

    Assert-ControlAction "BtnDeleteUser" "Trigger user delete confirmation" {
        if ($controls['GridUsers'].Items.Count -gt 0) {
            $controls['GridUsers'].SelectedIndex = 0
            Invoke-ControlClick $controls['BtnDeleteUser']
        }
    }

    Assert-ControlAction "BtnExportUsers" "Export users list to CSV" {
        Invoke-ControlClick $controls['BtnExportUsers']
    }

    Assert-ControlAction "CtxUserDelete" "Context menu user delete action" {
        if ($controls['CtxUserDelete']) {
            if ($controls['GridUsers'].Items.Count -gt 0) {
                $controls['GridUsers'].SelectedIndex = 0
                $controls['CtxUserDelete'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.MenuItem]::ClickEvent))
            }
        }
    }

    # =========================================================================
    # 3. GROUPS PANEL
    # =========================================================================
    Write-TestLog "`n--- [Panel 3] Groups ---" "Cyan"
    Show-Panel "Groups"
    Invoke-DispatcherPump

    Assert-ControlAction "TxtSearchGroups" "Type search query and trigger live group search" {
        $controls['TxtSearchGroups'].Text = "admin"
        Invoke-TextBoxEnter $controls['TxtSearchGroups'] { Refresh-Groups }
    }

    Assert-ControlAction "BtnSearchGroups" "Click search groups button" {
        Invoke-ControlClick $controls['BtnSearchGroups']
    }

    Assert-ControlAction "BtnClearSearchGroups" "Clear search groups input" {
        Invoke-ControlClick $controls['BtnClearSearchGroups']
    }

    Assert-ControlAction "FilterGroupSec" "Switch group filter to Security" {
        $controls['FilterGroupSec'].IsChecked = $true
    }

    Assert-ControlAction "FilterGroupDist" "Switch group filter to Distribution" {
        $controls['FilterGroupDist'].IsChecked = $true
    }

    Assert-ControlAction "FilterGroupAll" "Switch group filter to All" {
        $controls['FilterGroupAll'].IsChecked = $true
    }

    Assert-ControlAction "BtnNewGroup" "Open New Group dialog" {
        Invoke-ControlClick $controls['BtnNewGroup']
    }

    Assert-ControlAction "BtnEditGroup" "Open Edit Group dialog for selected group" {
        if ($controls['GridGroups'].Items.Count -gt 0) {
            $controls['GridGroups'].SelectedIndex = 0
            Invoke-ControlClick $controls['BtnEditGroup']
        }
    }

    Assert-ControlAction "BtnDeleteGroup" "Trigger group delete action" {
        if ($controls['GridGroups'].Items.Count -gt 0) {
            $controls['GridGroups'].SelectedIndex = 0
            Invoke-ControlClick $controls['BtnDeleteGroup']
        }
    }

    Assert-ControlAction "Open-MemberDialog" "Open Member Dialog and exercise Search, Add, Remove, Transitive" {
        if ($controls['GridGroups'].Items.Count -gt 0) {
            $selG = $controls['GridGroups'].Items[0]
            Open-MemberDialog -Group $selG
        }
    }

    Assert-ControlAction "Export-GroupsAction" "Export groups to CSV" {
        Invoke-ControlClick $controls['BtnExportGroups']
    }

    # =========================================================================
    # 4. COMPUTERS PANEL
    # =========================================================================
    Write-TestLog "`n--- [Panel 4] Computers ---" "Cyan"
    Show-Panel "Computers"
    Invoke-DispatcherPump

    Assert-ControlAction "TxtSearchComputers" "Type search query and trigger live computer search" {
        $controls['TxtSearchComputers'].Text = "dc"
        Invoke-TextBoxEnter $controls['TxtSearchComputers'] { Refresh-Computers }
    }

    Assert-ControlAction "BtnSearchComputers" "Click search computers button" {
        Invoke-ControlClick $controls['BtnSearchComputers']
    }

    Assert-ControlAction "BtnClearSearchComputers" "Clear search computers input" {
        Invoke-ControlClick $controls['BtnClearSearchComputers']
    }

    Assert-ControlAction "FilterCompEnabled" "Switch computer filter to Enabled" {
        $controls['FilterCompEnabled'].IsChecked = $true
    }

    Assert-ControlAction "FilterCompDisabled" "Switch computer filter to Disabled" {
        $controls['FilterCompDisabled'].IsChecked = $true
    }

    Assert-ControlAction "FilterCompAll" "Switch computer filter to All" {
        $controls['FilterCompAll'].IsChecked = $true
    }

    Assert-ControlAction "BtnToggleCompStatus" "Toggle computer status (enable/disable)" {
        if ($controls['GridComputers'].Items.Count -gt 0) {
            $controls['GridComputers'].SelectedIndex = 0
            Invoke-ControlClick $controls['BtnToggleCompStatus']
        }
    }

    Assert-ControlAction "BtnExportComputers" "Export computers to CSV" {
        Invoke-ControlClick $controls['BtnExportComputers']
    }

    # =========================================================================
    # 5. OUS PANEL
    # =========================================================================
    Write-TestLog "`n--- [Panel 5] Organizational Units ---" "Cyan"
    Show-Panel "OUs"
    Invoke-DispatcherPump

    Assert-ControlAction "TreeOUs" "Navigate OU Tree and select node" {
        if ($controls['TreeOUs'] -and $controls['TreeOUs'].Items.Count -gt 0) {
            $firstNode = $controls['TreeOUs'].Items[0]
            if ($controls['TreeOUs'].ItemContainerGenerator) {
                $container = $controls['TreeOUs'].ItemContainerGenerator.ContainerFromItem($firstNode)
                if ($container -and ($container -is [System.Windows.Controls.TreeViewItem])) {
                    $container.IsSelected = $true
                }
            }
            if ($firstNode -is [System.Windows.Controls.TreeViewItem]) {
                $firstNode.IsSelected = $true
            }
        }
    }

    Assert-ControlAction "BtnRefreshOUs" "Refresh OU hierarchy tree" {
        Invoke-ControlClick $controls['BtnRefreshOUs']
    }

    Assert-ControlAction "BtnRefreshOUObjects" "Refresh objects within selected OU" {
        Invoke-ControlClick $controls['BtnRefreshOUObjects']
    }

    Assert-ControlAction "BtnNewOU" "Open New OU creation dialog" {
        Invoke-ControlClick $controls['BtnNewOU']
    }

    Assert-ControlAction "BtnDeleteOU" "Trigger OU delete confirmation" {
        Invoke-ControlClick $controls['BtnDeleteOU']
    }

    # =========================================================================
    # 6. DIRECTORY SEARCH PANEL
    # =========================================================================
    Write-TestLog "`n--- [Panel 6] Directory Search ---" "Cyan"
    Show-Panel "DirectorySearch"
    Invoke-DispatcherPump

    Assert-ControlAction "TxtRawLdapFilter" "Set raw LDAP filter string" {
        $controls['TxtRawLdapFilter'].Text = "(&(objectClass=user)(sAMAccountName=*admin*))"
    }

    Assert-ControlAction "CmbSearchScope" "Set LDAP search scope" {
        if ($controls['CmbSearchScope'].Items.Count -gt 0) {
            $controls['CmbSearchScope'].SelectedIndex = 0
        }
    }

    Assert-ControlAction "TxtSearchBaseDn" "Set search base DN" {
        $controls['TxtSearchBaseDn'].Text = if ($adContext.DefaultNamingContext) { $adContext.DefaultNamingContext } else { "" }
    }

    Assert-ControlAction "BtnRunLdapSearch" "Execute LDAP filter search" {
        Invoke-ControlClick $controls['BtnRunLdapSearch']
    }

    Assert-ControlAction "BtnVerifyFilterSyntax" "Verify filter syntax" {
        Invoke-ControlClick $controls['BtnVerifyFilterSyntax']
    }

    Assert-ControlAction "BtnNormalizeFilter" "Normalize LDAP filter syntax" {
        Invoke-ControlClick $controls['BtnNormalizeFilter']
    }

    Assert-ControlAction "BtnConvertScim" "Convert LDAP filter to SCIM 2.0" {
        Invoke-ControlClick $controls['BtnConvertScim']
    }

    Assert-ControlAction "CmbSearchPageSize" "Change search pagination size" {
        if ($controls['CmbSearchPageSize'] -and $controls['CmbSearchPageSize'].Items.Count -gt 0) {
            $controls['CmbSearchPageSize'].SelectedIndex = 0
        }
    }

    Assert-ControlAction "BtnSearchPageNext" "Navigate to next search results page" {
        if ($controls['BtnSearchPageNext']) {
            Invoke-ControlClick $controls['BtnSearchPageNext']
        }
    }

    Assert-ControlAction "BtnSearchPagePrev" "Navigate to previous search results page" {
        if ($controls['BtnSearchPagePrev']) {
            Invoke-ControlClick $controls['BtnSearchPagePrev']
        }
    }

    Assert-ControlAction "ChkUseRegexFilter" "Enable RegEx secondary filtering" {
        $controls['ChkUseRegexFilter'].IsChecked = $true
    }

    Assert-ControlAction "TxtRegexPattern" "Set RegEx filter pattern" {
        $controls['TxtRegexPattern'].Text = "^[a-zA-Z0-9]+$"
    }

    Assert-ControlAction "CmbRegexTargetAttr" "Select RegEx target attribute" {
        if ($controls['CmbRegexTargetAttr'] -and $controls['CmbRegexTargetAttr'].Items.Count -gt 0) {
            $controls['CmbRegexTargetAttr'].SelectedIndex = 0
        }
    }

    Assert-ControlAction "BtnExportSearchResults" "Export search results to CSV" {
        Invoke-ControlClick $controls['BtnExportSearchResults']
    }

    # =========================================================================
    # 7. LDAP-SQL PANEL
    # =========================================================================
    Write-TestLog "`n--- [Panel 7] LDAP-SQL Console ---" "Cyan"
    Show-Panel "LdapSql"
    Invoke-DispatcherPump

    Assert-ControlAction "TxtSqlQuery" "Enter LDAP SQL SELECT statement" {
        $controls['TxtSqlQuery'].Text = "SELECT sAMAccountName, displayName, mail FROM SUBTREE WHERE objectClass = 'user'"
    }

    Assert-ControlAction "BtnSqlExplain" "Explain query execution plan" {
        Invoke-ControlClick $controls['BtnSqlExplain']
    }

    Assert-ControlAction "BtnExecuteSql" "Execute LDAP SQL query" {
        Invoke-ControlClick $controls['BtnExecuteSql']
    }

    Assert-ControlAction "BtnExportSqlResults" "Export SQL query results to CSV" {
        Invoke-ControlClick $controls['BtnExportSqlResults']
    }

    Assert-ControlAction "BtnClearSql" "Clear SQL input query" {
        Invoke-ControlClick $controls['BtnClearSql']
    }

    # =========================================================================
    # 8. ATTRIBUTE EDITOR PANEL
    # =========================================================================
    Write-TestLog "`n--- [Panel 8] Attribute Editor ---" "Cyan"
    Show-Panel "AttributeEditor"
    Invoke-DispatcherPump

    $testUserDN = if ($state.CachedUsers -and $state.CachedUsers.Count -gt 0) {
        $state.CachedUsers[0].DistinguishedName
    } elseif ($adContext.DefaultNamingContext) {
        $adContext.DefaultNamingContext
    } else {
        "DC=corp,DC=example,DC=com"
    }

    Assert-ControlAction "TxtAttrEditorDN" "Set target Distinguished Name" {
        $controls['TxtAttrEditorDN'].Text = $testUserDN
    }

    Assert-ControlAction "ChkShowOperationalAttributes" "Toggle show operational attributes" {
        $controls['ChkShowOperationalAttributes'].IsChecked = $true
    }

    Assert-ControlAction "BtnLoadRawAttributes" "Load raw directory attributes" {
        Invoke-ControlClick $controls['BtnLoadRawAttributes']
    }

    Assert-ControlAction "TxtSearchAttributes" "Filter loaded attributes" {
        $controls['TxtSearchAttributes'].Text = "name"
    }

    Assert-ControlAction "CmbFilterAttr" "Select schema filter attribute" {
        if ($controls['CmbFilterAttr'] -and $controls['CmbFilterAttr'].Items.Count -gt 0) {
            $controls['CmbFilterAttr'].SelectedIndex = 0
        }
    }

    Assert-ControlAction "BtnEditAttribute" "Open Attribute Editor Dialog for selected attribute" {
        if ($controls['GridRawAttributes'].Items.Count -gt 0) {
            $controls['GridRawAttributes'].SelectedIndex = 0
            Invoke-ControlClick $controls['BtnEditAttribute']
        }
    }

    Assert-ControlAction "BtnAddAttribute" "Open Add Attribute prompt dialog" {
        Invoke-ControlClick $controls['BtnAddAttribute']
    }

    Assert-ControlAction "BtnDeleteAttribute" "Delete / clear selected attribute" {
        if ($controls['GridRawAttributes'].Items.Count -gt 0) {
            $controls['GridRawAttributes'].SelectedIndex = 0
            Invoke-ControlClick $controls['BtnDeleteAttribute']
        }
    }

    # =========================================================================
    # 9. HTML VIEW PANEL
    # =========================================================================
    Write-TestLog "`n--- [Panel 9] In-App HTML Dossier View ---" "Cyan"
    Show-Panel "HtmlView"
    Invoke-DispatcherPump

    Assert-ControlAction "TxtHtmlViewDN" "Enter target identity for HTML Dossier" {
        $controls['TxtHtmlViewDN'].Text = $testUserDN
    }

    Assert-ControlAction "BtnHtmlViewGo" "Generate and render HTML Dossier" {
        Invoke-ControlClick $controls['BtnHtmlViewGo']
    }

    Assert-ControlAction "CmbHtmlViewTemplate" "Switch HTML dossier template" {
        if ($controls['CmbHtmlViewTemplate'].Items.Count -gt 1) {
            $controls['CmbHtmlViewTemplate'].SelectedIndex = 1
        }
    }

    Assert-ControlAction "BtnHtmlViewRefresh" "Refresh HTML dossier rendering" {
        Invoke-ControlClick $controls['BtnHtmlViewRefresh']
    }

    Assert-ControlAction "BtnHtmlViewCopyHtml" "Copy generated HTML markup to clipboard" {
        Invoke-ControlClick $controls['BtnHtmlViewCopyHtml']
    }

    Assert-ControlAction "BtnHtmlViewPrint" "Print HTML dossier view" {
        Invoke-ControlClick $controls['BtnHtmlViewPrint']
    }

    Assert-ControlAction "BtnHtmlViewOpenBrowser" "Open HTML dossier in external browser" {
        Invoke-ControlClick $controls['BtnHtmlViewOpenBrowser']
    }

    # =========================================================================
    # 10. OBJECT COMPARE PANEL
    # =========================================================================
    Write-TestLog "`n--- [Panel 10] Object Compare & Diff ---" "Cyan"
    Show-Panel "ObjectCompare"
    Invoke-DispatcherPump

    $defaultDN = if ($adContext.DefaultNamingContext) { $adContext.DefaultNamingContext } else { "DC=vielcahp,DC=com" }
    $obj1DN = if ($state.CachedUsers -and $state.CachedUsers.Count -gt 0) {
        $state.CachedUsers[0].DistinguishedName
    } elseif ($state.AllScopeUsers -and $state.AllScopeUsers.Count -gt 0) {
        $state.AllScopeUsers[0].DistinguishedName
    } elseif ($controls['GridUsers'] -and $controls['GridUsers'].Items.Count -gt 0) {
        $controls['GridUsers'].Items[0].DistinguishedName
    } else {
        "CN=Administrador,CN=Users,$defaultDN"
    }
    $obj2DN = if ($state.CachedUsers -and $state.CachedUsers.Count -gt 1) {
        $state.CachedUsers[1].DistinguishedName
    } elseif ($state.AllScopeUsers -and $state.AllScopeUsers.Count -gt 1) {
        $state.AllScopeUsers[1].DistinguishedName
    } elseif ($controls['GridUsers'] -and $controls['GridUsers'].Items.Count -gt 1) {
        $controls['GridUsers'].Items[1].DistinguishedName
    } else {
        "CN=Invitado,CN=Users,$defaultDN"
    }

    Write-TestLog "Compare Objects: '$obj1DN' vs '$obj2DN'" "DarkGray"

    Assert-ControlAction "TxtCompareDN1" "Set Object 1 DN" {
        if ($controls['TxtCompareDN1']) { $controls['TxtCompareDN1'].Text = $obj1DN }
        if ($controls['TxtCompareObjectA']) { $controls['TxtCompareObjectA'].Text = $obj1DN }
    }

    Assert-ControlAction "TxtCompareDN2" "Set Object 2 DN" {
        if ($controls['TxtCompareDN2']) { $controls['TxtCompareDN2'].Text = $obj2DN }
        if ($controls['TxtCompareObjectB']) { $controls['TxtCompareObjectB'].Text = $obj2DN }
    }

    Assert-ControlAction "BtnRunCompare" "Execute object comparison" {
        Invoke-ControlClick $controls['BtnRunCompare']
    }

    Assert-ControlAction "BtnSwapCompare" "Swap Object 1 and Object 2 DNs" {
        Invoke-ControlClick $controls['BtnSwapCompare']
    }

    Assert-ControlAction "ChkShowDifferencesOnly" "Toggle show differences only filter" {
        if ($controls['ChkShowDifferencesOnly']) {
            $controls['ChkShowDifferencesOnly'].IsChecked = $true
            $controls['ChkShowDifferencesOnly'].IsChecked = $false
        }
        if ($controls['ChkCompareDiffsOnly'] -and $controls['ChkCompareDiffsOnly'] -ne $controls['ChkShowDifferencesOnly']) {
            $controls['ChkCompareDiffsOnly'].IsChecked = $true
            $controls['ChkCompareDiffsOnly'].IsChecked = $false
        }
    }

    # =========================================================================
    # 11. LDIF STUDIO PANEL
    # =========================================================================
    Write-TestLog "`n--- [Panel 11] LDIF Studio ---" "Cyan"
    Show-Panel "LdifStudio"
    Invoke-DispatcherPump

    $testLdif = @"
dn: CN=Test Object,CN=Users,$defaultDN
changetype: modify
replace: description
description: Validated via automated test harness
-
"@

    Assert-ControlAction "TxtLdifInput" "Enter LDIF content into editor" {
        $controls['TxtLdifInput'].Text = $testLdif
    }

    Assert-ControlAction "BtnParseLdif" "Parse and validate LDIF syntax" {
        Invoke-ControlClick $controls['BtnParseLdif']
    }

    Assert-ControlAction "BtnExportLdif" "Export LDIF to file" {
        Invoke-ControlClick $controls['BtnExportLdif']
    }

    Assert-ControlAction "BtnClearLdif" "Clear LDIF editor contents" {
        Invoke-ControlClick $controls['BtnClearLdif']
    }

    # =========================================================================
    # 12. AUDIT REPORTS PANEL
    # =========================================================================
    Write-TestLog "`n--- [Panel 12] Audit Reports ---" "Cyan"
    Show-Panel "AuditReports"
    Invoke-DispatcherPump

    Assert-ControlAction "ListAuditCategories" "Select audit category" {
        if ($controls['ListAuditCategories'].Items.Count -gt 0) {
            $controls['ListAuditCategories'].SelectedIndex = 0
        }
    }

    Assert-ControlAction "ListAuditReports" "Select custom audit report" {
        if ($controls['ListAuditReports'].Items.Count -gt 0) {
            $controls['ListAuditReports'].SelectedIndex = 0
        }
    }

    Assert-ControlAction "BtnRunAuditReport" "Run selected security audit report" {
        Invoke-ControlClick $controls['BtnRunAuditReport']
    }

    Assert-ControlAction "BtnExportAuditReport" "Export audit report findings to CSV" {
        Invoke-ControlClick $controls['BtnExportAuditReport']
    }

} finally {
    if ($window) {
        $window.Close()
        Write-TestLog "Closed offscreen MainWindow." "DarkGray"
    }

    # Cleanup temporary test files
    if (Test-Path $tempExportCsv) { Remove-Item $tempExportCsv -Force -ErrorAction SilentlyContinue }
    if (Test-Path $tempImportCsv) { Remove-Item $tempImportCsv -Force -ErrorAction SilentlyContinue }
}

Write-TestLog "`n======================================================================" "Cyan"
Write-TestLog "Core Operations Test Suite Completed!" "Cyan"
Write-TestLog "Total operations executed : $totalOperations" "White"
Write-TestLog "Passed operations           : $passedOperations" "Green"
Write-TestLog "Failed operations           : $($recordedErrors.Count)" $(if ($recordedErrors.Count -eq 0) { "Green" } else { "Red" })
Write-TestLog "======================================================================" "Cyan"

if ($recordedErrors.Count -gt 0) {
    Write-TestLog "`nErrors detected during execution:" "Red"
    foreach ($err in $recordedErrors) {
        Write-TestLog "  - $err" "Red"
    }
    exit 1
} else {
    Write-TestLog "`nAll core controls, search bars, filters, executors, and dialogs passed cleanly with 0 errors!" "Green"
    exit 0
}
