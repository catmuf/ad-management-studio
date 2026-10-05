<#
.SYNOPSIS
    Active Directory Management Studio - Modern Windows Server Administration Suite
.DESCRIPTION
    Professional WPF/XAML Active Directory & LDAP Administration Suite featuring
    Visual LDAP Filter Builder, Raw Attribute Editor & UAC Bitmask Decoder, LDAP-SQL Console,
    RFC 2849 LDIF Studio, Object Compare & Diff, Security Audits & Executive Reports,
    AD Schema Browser, Bulk Operations Engine, and Connection Profiles with Diagnostics.
#>

# Ensure script runs in Single Thread Apartment (STA) mode for WPF
if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne [System.Threading.ApartmentState]::STA) {
    Write-Host "Restarting Active Directory Studio in STA mode..." -ForegroundColor Cyan
    $powershellExe = (Get-Process -Id $PID).Path
    Start-Process -FilePath $powershellExe -ArgumentList "-STA -NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}

# Required .NET Assemblies for WPF & Dialogs
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Drawing, System.Windows.Forms

# Application Root Path
$appRoot = if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) { $PSScriptRoot } else { (Get-Location).Path }
$modulesPath = Join-Path $appRoot "Modules"
$viewsPath   = Join-Path $appRoot "Views"

# Import Core Services
Import-Module (Join-Path $modulesPath "ConfigService.psm1") -Force
Import-Module (Join-Path $modulesPath "ValidationService.psm1") -Force
Import-Module (Join-Path $modulesPath "ExportService.psm1") -Force
Import-Module (Join-Path $modulesPath "ADService.psm1") -Force

# Load App Settings & AD Context
$appConfig = Get-AppSettings
$adContext = Get-ADEnvironmentContext -Config $appConfig

# Helper function to load and parse XAML files
function Load-XamlWindow {
    param ([string]$XamlPath)
    if (-not (Test-Path $XamlPath)) {
        throw "XAML file not found at: $XamlPath"
    }
    $rawXaml = Get-Content -Path $XamlPath -Raw -Encoding UTF8
    [xml]$xmlDoc = $rawXaml
    $reader = New-Object System.Xml.XmlNodeReader $xmlDoc
    return [System.Windows.Markup.XamlReader]::Load($reader)
}

# Load Main Window
$mainWindowXamlPath = Join-Path $viewsPath "MainWindow.xaml"
$window = Load-XamlWindow -XamlPath $mainWindowXamlPath

# Extract all controls by Name
$controls = @{}
$reader = [System.Xml.XmlReader]::Create([System.IO.StringReader](Get-Content $mainWindowXamlPath -Raw))
while ($reader.Read()) {
    if ($reader.NodeType -eq [System.Xml.XmlNodeType]::Element) {
        $name = $reader.GetAttribute("Name")
        if ($name) {
            $controls[$name] = $window.FindName($name)
        }
    }
}
$reader.Close()

# Global UI State
$state = [PSCustomObject]@{
    CachedUsers            = @()
    CachedGroups           = @()
    CachedOUs              = @()
    CachedComputers        = @()
    CachedSchema           = @()
    CurrentSearchResults   = @()
    CurrentSqlResults      = @()
    CurrentRawAttributes   = @()
    CurrentRawDN           = ""
    CurrentCompare         = $null
    CurrentAuditReport     = $null
    SelectedOU             = ""
    DomainName             = $adContext.DomainName
    UPNSuffix              = if ($adContext.DomainName) { "@$($adContext.DomainName)" } else { "" }
    MasterAttributeList    = [System.Collections.Generic.List[string]]::new()
    SearchAttributesLoaded = $false
    IsFilteringAttributes  = $false
}

# Update Top Header Ribbon
if ($adContext.IsConnected) {
    if ($controls['TxtDomainBadge'])  { $controls['TxtDomainBadge'].Text = "Connected: $($adContext.DomainName)" }
    if ($controls['TxtDCBadge'])      { $controls['TxtDCBadge'].Text     = if ($adContext.PDCEmulator) { $adContext.PDCEmulator } else { "Local DC" } }
    if ($controls['TxtLatencyBadge']) { $controls['TxtLatencyBadge'].Text = "$($adContext.LatencyMs) ms" }
    if ($controls['StatusDot'])       { $controls['StatusDot'].Fill      = [System.Windows.Media.Brushes]::LimeGreen }
} else {
    if ($controls['TxtDomainBadge'])  { $controls['TxtDomainBadge'].Text = "Not Connected to AD" }
    if ($controls['TxtDCBadge'])      { $controls['TxtDCBadge'].Text     = $adContext.ErrorMessage }
    if ($controls['TxtLatencyBadge']) { $controls['TxtLatencyBadge'].Text = "--" }
    if ($controls['StatusDot'])       { $controls['StatusDot'].Fill      = [System.Windows.Media.Brushes]::Red }
}

function Set-Status {
    param ([string]$Message, [string]$Count = "")
    if ($controls['TxtStatusMessage']) {
        $controls['TxtStatusMessage'].Text = $Message
    }
    if ($controls['TxtScopeMessage']) {
        if ($Count) {
            $controls['TxtScopeMessage'].Text = $Count
        } else {
            $controls['TxtScopeMessage'].Text = if ($adContext.IsConnected) { "Connected: $($adContext.DomainName)" } else { "Offline / Disconnected" }
        }
    }
}

#region Panel Switching & Navigation
function Show-Panel {
    param ([string]$PanelName)
    $panels = @(
        'PanelDashboard', 'PanelUsers', 'PanelGroups', 'PanelOUs', 'PanelComputers',
        'PanelDirectorySearch', 'PanelLdapSql', 'PanelAttributeEditor', 'PanelObjectCompare',
        'PanelLdifStudio', 'PanelAuditReports', 'PanelSchemaBrowser', 'PanelBulkEditor',
        'PanelConnections', 'PanelSettings'
    )
    $targetName = "Panel$PanelName"
    foreach ($p in $panels) {
        if ($controls[$p]) {
            $controls[$p].Visibility = if ($p -eq $targetName) { [System.Windows.Visibility]::Visible } else { [System.Windows.Visibility]::Collapsed }
        }
    }
}

# Wire Sidebar Navigation RadioButtons
if ($controls['NavDashboard'])       { $controls['NavDashboard'].Add_Checked({ Show-Panel "Dashboard"; Refresh-Dashboard }) }
if ($controls['NavUsers'])           { $controls['NavUsers'].Add_Checked({ Show-Panel "Users"; Refresh-Users }) }
if ($controls['NavGroups'])          { $controls['NavGroups'].Add_Checked({ Show-Panel "Groups"; Refresh-Groups }) }
if ($controls['NavOUs'])             { $controls['NavOUs'].Add_Checked({ Show-Panel "OUs"; Refresh-OUs }) }
if ($controls['NavComputers'])       { $controls['NavComputers'].Add_Checked({ Show-Panel "Computers"; Refresh-Computers }) }
if ($controls['NavDirectorySearch']) { $controls['NavDirectorySearch'].Add_Checked({ Show-Panel "DirectorySearch"; Init-DirectorySearch }) }
if ($controls['NavLdapSql'])         { $controls['NavLdapSql'].Add_Checked({ Show-Panel "LdapSql" }) }
if ($controls['NavAttributeEditor']) { $controls['NavAttributeEditor'].Add_Checked({ Show-Panel "AttributeEditor" }) }
if ($controls['NavObjectCompare'])   { $controls['NavObjectCompare'].Add_Checked({ Show-Panel "ObjectCompare" }) }
if ($controls['NavLdifStudio'])      { $controls['NavLdifStudio'].Add_Checked({ Show-Panel "LdifStudio"; Init-LdifStudio }) }
if ($controls['NavAuditReports'])    { $controls['NavAuditReports'].Add_Checked({ Show-Panel "AuditReports" }) }
if ($controls['NavSchemaBrowser'])   { $controls['NavSchemaBrowser'].Add_Checked({ Show-Panel "SchemaBrowser"; Refresh-Schema }) }
if ($controls['NavBulkEditor'])      { $controls['NavBulkEditor'].Add_Checked({ Show-Panel "BulkEditor" }) }
if ($controls['NavConnections'])     { $controls['NavConnections'].Add_Checked({ Show-Panel "Connections"; Refresh-Connections }) }
if ($controls['NavSettings'])        { $controls['NavSettings'].Add_Checked({ Show-Panel "Settings"; Load-SettingsPanel }) }
#endregion

#region 1. Dashboard Functions
function Refresh-Dashboard {
    Set-Status -Message "Fetching directory health metrics..."
    $stats = Get-ADDashboardStats
    if ($controls['CardTotalUsers'])    { $controls['CardTotalUsers'].Text    = $stats.TotalUsers.ToString() }
    if ($controls['CardActiveUsers'])   { $controls['CardActiveUsers'].Text   = $stats.ActiveUsers.ToString() }
    if ($controls['CardDisabledUsers']) { $controls['CardDisabledUsers'].Text = $stats.DisabledUsers.ToString() }
    if ($controls['CardLockedUsers'])   { $controls['CardLockedUsers'].Text   = $stats.LockedUsers.ToString() }
    if ($controls['CardTotalGroups'])   { $controls['CardTotalGroups'].Text   = $stats.TotalGroups.ToString() }
    if ($controls['CardTotalOUs'])      { $controls['CardTotalOUs'].Text      = $stats.TotalOUs.ToString() }

    # Telemetry cards on dashboard
    if ($controls['TxtDashPdc']) { $controls['TxtDashPdc'].Text = if ($adContext.PDCEmulator) { $adContext.PDCEmulator } else { "Local DC" } }
    if ($controls['TxtDashDefaultNC']) { $controls['TxtDashDefaultNC'].Text = if ($adContext.DefaultNamingContext) { $adContext.DefaultNamingContext } else { "--" } }
    if ($controls['TxtDashModuleStatus']) {
        $controls['TxtDashModuleStatus'].Text = if ($adContext.IsRSAT) { "RSAT (ActiveDirectory) Module Active" } else { "ADSI / .NET Fallback Mode Active" }
    }

    Set-Status -Message "Dashboard metrics updated." -Count "$($stats.TotalUsers) Users | $($stats.TotalGroups) Groups | $($stats.TotalOUs) OUs"
}

# Interactive Drill-downs
if ($controls['CardBtnActiveUsers']) {
    $controls['CardBtnActiveUsers'].Add_MouseDown({
        $controls['NavUsers'].IsChecked = $true
        Show-Panel "Users"
        if ($controls['FilterUserActive']) { $controls['FilterUserActive'].IsChecked = $true }
        Refresh-Users
    })
}

if ($controls['CardBtnDisabledUsers']) {
    $controls['CardBtnDisabledUsers'].Add_MouseDown({
        $controls['NavUsers'].IsChecked = $true
        Show-Panel "Users"
        if ($controls['FilterUserDisabled']) { $controls['FilterUserDisabled'].IsChecked = $true }
        Refresh-Users
    })
}

if ($controls['CardBtnLockedUsers']) {
    $controls['CardBtnLockedUsers'].Add_MouseDown({
        $controls['NavUsers'].IsChecked = $true
        Show-Panel "Users"
        if ($controls['FilterUserLocked']) { $controls['FilterUserLocked'].IsChecked = $true }
        Refresh-Users
    })
}

if ($controls['CardBtnGroups']) {
    $controls['CardBtnGroups'].Add_MouseDown({
        $controls['NavGroups'].IsChecked = $true
        Show-Panel "Groups"
        Refresh-Groups
    })
}

if ($controls['CardBtnOUs']) {
    $controls['CardBtnOUs'].Add_MouseDown({
        $controls['NavOUs'].IsChecked = $true
        Show-Panel "OUs"
        Refresh-OUs
    })
}

# Dashboard Feature Launchers
if ($controls['BtnDashSearch']) {
    $controls['BtnDashSearch'].Add_Click({
        $controls['NavDirectorySearch'].IsChecked = $true
        Show-Panel "DirectorySearch"
        Init-DirectorySearch
    })
}
if ($controls['BtnDashSql']) {
    $controls['BtnDashSql'].Add_Click({
        $controls['NavLdapSql'].IsChecked = $true
        Show-Panel "LdapSql"
    })
}
if ($controls['BtnDashAttributes']) {
    $controls['BtnDashAttributes'].Add_Click({
        $controls['NavAttributeEditor'].IsChecked = $true
        Show-Panel "AttributeEditor"
    })
}
if ($controls['BtnDashAudits']) {
    $controls['BtnDashAudits'].Add_Click({
        $controls['NavAuditReports'].IsChecked = $true
        Show-Panel "AuditReports"
    })
}
if ($controls['BtnDashTestConn']) {
    $controls['BtnDashTestConn'].Add_Click({
        $controls['NavConnections'].IsChecked = $true
        Show-Panel "Connections"
        Run-ConnectionDiagnostics
    })
}

if ($controls['BtnDiagnostics']) {
    $controls['BtnDiagnostics'].Add_Click({
        if ($controls['NavConnections']) {
            $controls['NavConnections'].IsChecked = $true
        } else {
            Show-Panel "Connections"
            Refresh-Connections
        }
        Run-ConnectionDiagnostics
    })
}

if ($controls['BtnGlobalRefresh']) {
    $controls['BtnGlobalRefresh'].Add_Click({ Refresh-All })
}
#endregion

#region 2. Users Management Logic
function Refresh-Users {
    Set-Status -Message "Loading users from Active Directory..."
    $searchText = if ($controls['TxtSearchUsers']) { $controls['TxtSearchUsers'].Text.Trim() } else { "" }
    
    $statusFilter = "All"
    if ($controls['FilterUserActive'] -and $controls['FilterUserActive'].IsChecked)         { $statusFilter = "Active" }
    elseif ($controls['FilterUserDisabled'] -and $controls['FilterUserDisabled'].IsChecked) { $statusFilter = "Disabled" }
    elseif ($controls['FilterUserLocked'] -and $controls['FilterUserLocked'].IsChecked)     { $statusFilter = "Locked" }

    $searchBase = ""
    if ($controls['CmbUserOUFilter'] -and $controls['CmbUserOUFilter'].SelectedItem -and $controls['CmbUserOUFilter'].SelectedIndex -gt 0) {
        $selectedOUItem = $controls['CmbUserOUFilter'].SelectedItem
        if ($selectedOUItem.Tag) {
            $searchBase = $selectedOUItem.Tag
        }
    }

    $users = Get-ADUsersList -SearchText $searchText -StatusFilter $statusFilter -SearchBase $searchBase -Limit ($appConfig.UI.PageSize)
    $state.CachedUsers = $users
    if ($controls['GridUsers']) {
        $controls['GridUsers'].ItemsSource = $users
    }
    Set-Status -Message "Loaded $($users.Count) user(s)." -Count "$($users.Count) users displayed"
}

function Open-UserDialog {
    param (
        [string]$Mode = "Create",
        $UserToEdit = $null
    )

    $dlgPath = Join-Path $viewsPath "UserDialog.xaml"
    $dlg = Load-XamlWindow -XamlPath $dlgPath
    $dlg.Owner = $window

    $dControls = @{}
    $dReader = [System.Xml.XmlReader]::Create([System.IO.StringReader](Get-Content $dlgPath -Raw))
    while ($dReader.Read()) {
        if ($dReader.NodeType -eq [System.Xml.XmlNodeType]::Element) {
            $dName = $dReader.GetAttribute("Name")
            if ($dName) { $dControls[$dName] = $dlg.FindName($dName) }
        }
    }
    $dReader.Close()

    # Populate OU List in dialog
    $dControls['CmbTargetOU'].Items.Clear()
    foreach ($ou in $state.CachedOUs) {
        $item = New-Object System.Windows.Controls.ComboBoxItem
        $item.Content = $ou.DisplayName
        $item.Tag = $ou.DistinguishedName
        [void]$dControls['CmbTargetOU'].Items.Add($item)
    }

    if ($dControls['CmbTargetOU'].Items.Count -gt 0) {
        $dControls['CmbTargetOU'].SelectedIndex = 0
        $dControls['TxtSelectedOUDN'].Text = $dControls['CmbTargetOU'].SelectedItem.Tag
    }

    $dControls['CmbTargetOU'].Add_SelectionChanged({
        if ($dControls['CmbTargetOU'].SelectedItem) {
            $dControls['TxtSelectedOUDN'].Text = $dControls['CmbTargetOU'].SelectedItem.Tag
        }
    })

    # Auto suggest username
    $dControls['BtnSuggestUsername'].Add_Click({
        $fn = $dControls['TxtFirstName'].Text
        $ln = $dControls['TxtLastName'].Text
        $suggested = Get-SuggestedUsername -FirstName $fn -LastName $ln -Format ($appConfig.Defaults.UsernameFormat)
        $dControls['TxtUsername'].Text = $suggested
        $dControls['TxtUPN'].Text = if ($suggested) { "$suggested$($state.UPNSuffix)" } else { "" }
        if (-not $dControls['TxtDisplayName'].Text) {
            $dControls['TxtDisplayName'].Text = "$fn $ln".Trim()
        }
    })

    # Generate password button
    $dControls['BtnGeneratePassword'].Add_Click({
        $pw = New-SecurePassword -Length ($appConfig.Defaults.PasswordLength)
        $dControls['TxtPassword'].Text = $pw
    })

    if ($Mode -eq "Edit" -and $UserToEdit) {
        $dlg.Title = "Edit User - $($UserToEdit.DisplayName)"
        $dControls['TxtDialogTitle'].Text = "Edit User: $($UserToEdit.DisplayName)"
        $dControls['TxtDialogSubtitle'].Text = "Update account properties, organizational roles, and contact details."
        $dControls['BtnSaveUser'].Content = "Save Changes"

        $dControls['TxtFirstName'].Text   = $UserToEdit.GivenName
        $dControls['TxtLastName'].Text    = $UserToEdit.Surname
        $dControls['TxtDisplayName'].Text = $UserToEdit.DisplayName
        $dControls['TxtUsername'].Text    = $UserToEdit.SamAccountName
        $dControls['TxtUsername'].IsEnabled = $false
        $dControls['TxtUPN'].Text         = $UserToEdit.UserPrincipalName
        $dControls['TxtEmail'].Text       = $UserToEdit.Mail
        $dControls['TxtEmployeeID'].Text  = $UserToEdit.EmployeeID
        $dControls['TxtDescription'].Text = $UserToEdit.Description
        $dControls['TxtJobTitle'].Text    = $UserToEdit.Title
        $dControls['TxtDepartment'].Text  = $UserToEdit.Department
        $dControls['TxtCompany'].Text     = $UserToEdit.Company
        $dControls['TxtOffice'].Text      = $UserToEdit.Office

        $dControls['TabCredentials'].Visibility = [System.Windows.Visibility]::Collapsed
    } else {
        $dControls['TxtPassword'].Text = New-SecurePassword -Length ($appConfig.Defaults.PasswordLength)
    }

    $dControls['BtnCancel'].Add_Click({ $dlg.Close() })

    $dControls['BtnSaveUser'].Add_Click({
        $fn  = $dControls['TxtFirstName'].Text.Trim()
        $ln  = $dControls['TxtLastName'].Text.Trim()
        $dn  = $dControls['TxtDisplayName'].Text.Trim()
        $sam = $dControls['TxtUsername'].Text.Trim()
        $upn = $dControls['TxtUPN'].Text.Trim()
        $em  = $dControls['TxtEmail'].Text.Trim()
        $eid = $dControls['TxtEmployeeID'].Text.Trim()
        $desc = $dControls['TxtDescription'].Text.Trim()
        $title = $dControls['TxtJobTitle'].Text.Trim()
        $dept = $dControls['TxtDepartment'].Text.Trim()
        $comp = $dControls['TxtCompany'].Text.Trim()
        $off  = $dControls['TxtOffice'].Text.Trim()
        $script = $dControls['TxtScriptPath'].Text.Trim()

        if ([string]::IsNullOrWhiteSpace($fn) -or [string]::IsNullOrWhiteSpace($ln)) {
            $dControls['TxtDialogError'].Text = "First name and last name are required."
            return
        }

        if ([string]::IsNullOrWhiteSpace($sam)) {
            $dControls['TxtDialogError'].Text = "Username is required."
            return
        }

        if ($Mode -eq "Create") {
            if (Test-ADUsernameExists -SamAccountName $sam) {
                $dControls['TxtDialogError'].Text = "Username '$sam' already exists in Active Directory."
                return
            }

            $plainPw = $dControls['TxtPassword'].Text
            $pwComp = Test-PasswordComplexity -Password $plainPw
            if (-not $pwComp.IsValid) {
                $dControls['TxtDialogError'].Text = $pwComp.Message
                return
            }

            $targetOU = $dControls['CmbTargetOU'].SelectedItem.Tag
            if (-not $targetOU) {
                $dControls['TxtDialogError'].Text = "Please select a target OU."
                return
            }

            $secPw = ConvertTo-SecureString $plainPw -AsPlainText -Force
            $res = New-ADUserItem `
                -FirstName $fn -LastName $ln -DisplayName $dn -SamAccountName $sam `
                -UserPrincipalName $upn -Password $secPw -Path $targetOU `
                -Email $em -EmployeeID $eid -Description $desc -Title $title `
                -Department $dept -Company $comp -Office $off -ScriptPath $script `
                -Enabled ([bool]$dControls['ChkAccountEnabled'].IsChecked) `
                -MustChangePassword ([bool]$dControls['ChkMustChangePassword'].IsChecked) `
                -PasswordNeverExpires ([bool]$dControls['ChkPasswordNeverExpires'].IsChecked)

            if ($res.Success) {
                [System.Windows.MessageBox]::Show($res.Message, "User Created", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
                $dlg.Close()
                Refresh-Users
                Refresh-Dashboard
            } else {
                $dControls['TxtDialogError'].Text = $res.Message
            }
        } else {
            $res = Set-ADUserItem `
                -Identity $UserToEdit.DistinguishedName `
                -FirstName $fn -LastName $ln -DisplayName $dn `
                -Email $em -EmployeeID $eid -Description $desc `
                -Title $title -Department $dept -Company $comp -Office $off

            if ($res.Success) {
                [System.Windows.MessageBox]::Show($res.Message, "User Updated", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
                $dlg.Close()
                Refresh-Users
            } else {
                $dControls['TxtDialogError'].Text = $res.Message
            }
        }
    })

    [void]$dlg.ShowDialog()
}

function Open-PasswordDialog {
    param ($User)
    if (-not $User) { return }

    $dlgPath = Join-Path $viewsPath "PasswordDialog.xaml"
    $dlg = Load-XamlWindow -XamlPath $dlgPath
    $dlg.Owner = $window

    $dControls = @{}
    $dReader = [System.Xml.XmlReader]::Create([System.IO.StringReader](Get-Content $dlgPath -Raw))
    while ($dReader.Read()) {
        if ($dReader.NodeType -eq [System.Xml.XmlNodeType]::Element) {
            $dName = $dReader.GetAttribute("Name")
            if ($dName) { $dControls[$dName] = $dlg.FindName($dName) }
        }
    }
    $dReader.Close()

    $dControls['TxtTargetUser'].Text = "Target: $($User.DisplayName) ($($User.SamAccountName))"
    $dControls['TxtNewPassword'].Text = New-SecurePassword -Length ($appConfig.Defaults.PasswordLength)

    $updatePwStatus = {
        $p = $dControls['TxtNewPassword'].Text
        if ($dControls['TxtPasswordStatus']) {
            $chk = Test-PasswordComplexity -Password $p
            if ($chk.IsValid) {
                $dControls['TxtPasswordStatus'].Text = "Password meets domain complexity requirements."
                $dControls['TxtPasswordStatus'].Foreground = [System.Windows.Media.Brushes]::LimeGreen
            } else {
                $dControls['TxtPasswordStatus'].Text = $chk.Message
                $dControls['TxtPasswordStatus'].Foreground = [System.Windows.Media.Brushes]::Gold
            }
        }
    }
    $dControls['TxtNewPassword'].Add_TextChanged({ & $updatePwStatus })
    & $updatePwStatus

    $dControls['BtnGeneratePassword'].Add_Click({
        $dControls['TxtNewPassword'].Text = New-SecurePassword -Length ($appConfig.Defaults.PasswordLength)
    })

    $dControls['BtnCancel'].Add_Click({ $dlg.Close() })

    $dControls['BtnConfirmReset'].Add_Click({
        $plainPw = $dControls['TxtNewPassword'].Text
        $pwComp = Test-PasswordComplexity -Password $plainPw
        if (-not $pwComp.IsValid) {
            $dControls['TxtDialogError'].Text = $pwComp.Message
            return
        }

        $secPw = ConvertTo-SecureString $plainPw -AsPlainText -Force
        $res = Set-ADUserPassword `
            -Identity $User.DistinguishedName `
            -NewPassword $secPw `
            -MustChangePassword ([bool]$dControls['ChkMustChange'].IsChecked) `
            -Unlock ([bool]$dControls['ChkUnlockAccount'].IsChecked)

        if ($res.Success) {
            [System.Windows.MessageBox]::Show($res.Message, "Password Reset", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            $dlg.Close()
            Refresh-Users
        } else {
            $dControls['TxtDialogError'].Text = $res.Message
        }
    })

    [void]$dlg.ShowDialog()
}

function Open-UserDetailDialog {
    param ($User)
    if (-not $User) { return }

    $detail = Get-ADUserDetail -Identity $User.DistinguishedName
    if (-not $detail) { return }

    $dlgPath = Join-Path $viewsPath "UserDetailDialog.xaml"
    $dlg = Load-XamlWindow -XamlPath $dlgPath
    $dlg.Owner = $window

    $dControls = @{}
    $dReader = [System.Xml.XmlReader]::Create([System.IO.StringReader](Get-Content $dlgPath -Raw))
    while ($dReader.Read()) {
        if ($dReader.NodeType -eq [System.Xml.XmlNodeType]::Element) {
            $dName = $dReader.GetAttribute("Name")
            if ($dName) { $dControls[$dName] = $dlg.FindName($dName) }
        }
    }
    $dReader.Close()

    $u = $detail.User
    $dControls['TxtHeaderDisplayName'].Text = $u.DisplayName
    $dControls['TxtHeaderUPN'].Text         = if ($u.UserPrincipalName) { $u.UserPrincipalName } else { $u.SamAccountName }
    $dControls['TxtStatusBadge'].Text       = $u.StatusBadge
    $dControls['BorderStatus'].Background   = (New-Object System.Windows.Media.BrushConverter).ConvertFromString($u.StatusColor)

    $dControls['ValUsername'].Text       = $u.SamAccountName
    $dControls['ValEmail'].Text          = if ($u.Mail) { $u.Mail } else { "--" }
    $dControls['ValEmployeeID'].Text     = if ($u.EmployeeID) { $u.EmployeeID } else { "--" }
    $dControls['ValTitle'].Text          = if ($u.Title) { $u.Title } else { "--" }
    $dControls['ValDepartment'].Text     = if ($u.Department) { $u.Department } else { "--" }
    $dControls['ValOffice'].Text         = if ($u.Office) { $u.Office } else { "--" }
    $dControls['ValCompany'].Text        = if ($u.Company) { $u.Company } else { "--" }
    $dControls['ValDescription'].Text    = if ($u.Description) { $u.Description } else { "--" }

    $dControls['ValAccountEnabled'].Text = if ($u.Enabled) { "Enabled" } else { "Disabled" }
    $dControls['ValLockedOut'].Text      = if ($u.LockedOut) { "Yes (Locked)" } else { "No" }
    $dControls['ValLastLogon'].Text      = $u.LastLogonDate
    $dControls['ValPasswordLastSet'].Text = $u.PasswordLastSet
    $dControls['ValWhenCreated'].Text    = $u.WhenCreated
    $dControls['ValSID'].Text            = $u.SID
    $dControls['ValDN'].Text             = $u.DistinguishedName

    $dControls['ListGroups'].ItemsSource = $detail.Groups

    $dControls['BtnClose'].Add_Click({ $dlg.Close() })
    [void]$dlg.ShowDialog()
}

function Open-MoveDialog {
    param ($Principal, [string]$Type = "User")
    if (-not $Principal) { return }

    $dlgPath = Join-Path $viewsPath "MoveDialog.xaml"
    $dlg = Load-XamlWindow -XamlPath $dlgPath
    $dlg.Owner = $window

    $dControls = @{}
    $dReader = [System.Xml.XmlReader]::Create([System.IO.StringReader](Get-Content $dlgPath -Raw))
    while ($dReader.Read()) {
        if ($dReader.NodeType -eq [System.Xml.XmlNodeType]::Element) {
            $dName = $dReader.GetAttribute("Name")
            if ($dName) { $dControls[$dName] = $dlg.FindName($dName) }
        }
    }
    $dReader.Close()

    $dControls['TxtObjectName'].Text = "$($Type): $($Principal.DisplayName) (Currently in: $($Principal.OUPath))"

    $dControls['CmbTargetOU'].Items.Clear()
    foreach ($ou in $state.CachedOUs) {
        $item = New-Object System.Windows.Controls.ComboBoxItem
        $item.Content = $ou.DisplayName
        $item.Tag = $ou.DistinguishedName
        [void]$dControls['CmbTargetOU'].Items.Add($item)
    }

    if ($dControls['CmbTargetOU'].Items.Count -gt 0) {
        $dControls['CmbTargetOU'].SelectedIndex = 0
        $dControls['TxtSelectedOUDN'].Text = $dControls['CmbTargetOU'].SelectedItem.Tag
    }

    $dControls['CmbTargetOU'].Add_SelectionChanged({
        if ($dControls['CmbTargetOU'].SelectedItem) {
            $dControls['TxtSelectedOUDN'].Text = $dControls['CmbTargetOU'].SelectedItem.Tag
        }
    })

    $dControls['BtnCancel'].Add_Click({ $dlg.Close() })

    $dControls['BtnConfirmMove'].Add_Click({
        $targetDN = $dControls['CmbTargetOU'].SelectedItem.Tag
        if (-not $targetDN) { return }

        $res = Move-ADPrincipal -Identity $Principal.DistinguishedName -TargetPath $targetDN
        if ($res.Success) {
            [System.Windows.MessageBox]::Show($res.Message, "Object Moved", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            $dlg.Close()
            if ($Type -eq "User") { Refresh-Users } else { Refresh-Groups }
        } else {
            $dControls['TxtDialogError'].Text = $res.Message
        }
    })

    [void]$dlg.ShowDialog()
}

function Delete-UserAction {
    $selUser = if ($controls['GridUsers']) { $controls['GridUsers'].SelectedItem } else { $null }
    if (-not $selUser) {
        [System.Windows.MessageBox]::Show("Please select a user from the list first.", "No Selection", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        return
    }

    $confirm = [System.Windows.MessageBox]::Show(
        "Are you sure you want to permanently delete user:`n`n$($selUser.DisplayName) ($($selUser.SamAccountName))`nDN: $($selUser.DistinguishedName)`n`nThis action cannot be undone.",
        "Confirm Delete User",
        [System.Windows.MessageBoxButton]::YesNo,
        [System.Windows.MessageBoxImage]::Warning
    )

    if ($confirm -eq [System.Windows.MessageBoxResult]::Yes) {
        $res = Remove-ADUserItem -Identity $selUser.DistinguishedName
        if ($res.Success) {
            [System.Windows.MessageBox]::Show($res.Message, "User Deleted", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            Refresh-Users
            Refresh-Dashboard
        } else {
            [System.Windows.MessageBox]::Show($res.Message, "Error Deleting User", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        }
    }
}

function Toggle-UserStatusAction {
    $selUser = if ($controls['GridUsers']) { $controls['GridUsers'].SelectedItem } else { $null }
    if (-not $selUser) { return }

    $targetEnable = -not $selUser.Enabled
    $actionName   = if ($targetEnable) { "Enable" } else { "Disable" }

    $confirm = [System.Windows.MessageBox]::Show(
        "Are you sure you want to $actionName user '$($selUser.DisplayName)' ($($selUser.SamAccountName))?",
        "Confirm $actionName Account",
        [System.Windows.MessageBoxButton]::YesNo,
        [System.Windows.MessageBoxImage]::Question
    )

    if ($confirm -eq [System.Windows.MessageBoxResult]::Yes) {
        $res = Set-ADUserStatus -Identity $selUser.DistinguishedName -Enable $targetEnable
        if ($res.Success) {
            Refresh-Users
            Refresh-Dashboard
        } else {
            [System.Windows.MessageBox]::Show($res.Message, "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        }
    }
}

function Export-UsersAction {
    $saveDlg = New-Object System.Windows.Forms.SaveFileDialog
    $dateStr = (Get-Date).ToString("yyyyMMdd_HHmm")
    $saveDlg.FileName = "AD_Users_$dateStr.csv"
    $saveDlg.Filter = "CSV files (*.csv)|*.csv|All files (*.*)|*.*"
    
    if ($saveDlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $usersToExport = if ($state.CachedUsers.Count -gt 0) { $state.CachedUsers } else { Get-ADUsersList }
        $res = Export-ADDataToCsv -Data $usersToExport -FilePath $saveDlg.FileName -Delimiter ($appConfig.Defaults.ExportDelimiter) `
            -PropertiesToExport @('SamAccountName', 'DisplayName', 'UserPrincipalName', 'Mail', 'Title', 'Department', 'Office', 'Company', 'EmployeeID', 'Enabled', 'LockedOut', 'OUPath', 'LastLogonDate', 'DistinguishedName')

        if ($res.Success) {
            [System.Windows.MessageBox]::Show($res.Message, "Export Successful", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        } else {
            [System.Windows.MessageBox]::Show($res.Message, "Export Failed", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        }
    }
}

# User Actions Wiring
if ($controls['BtnSearchUsers']) { $controls['BtnSearchUsers'].Add_Click({ Refresh-Users }) }
if ($controls['TxtSearchUsers']) {
    $controls['TxtSearchUsers'].Add_KeyDown({
        if ($_.Key -eq [System.Windows.Input.Key]::Enter) { Refresh-Users }
    })
}
if ($controls['FilterUserAll'])      { $controls['FilterUserAll'].Add_Checked({ Refresh-Users }) }
if ($controls['FilterUserActive'])   { $controls['FilterUserActive'].Add_Checked({ Refresh-Users }) }
if ($controls['FilterUserDisabled']) { $controls['FilterUserDisabled'].Add_Checked({ Refresh-Users }) }
if ($controls['FilterUserLocked'])   { $controls['FilterUserLocked'].Add_Checked({ Refresh-Users }) }
if ($controls['CmbUserOUFilter'])    { $controls['CmbUserOUFilter'].Add_SelectionChanged({ Refresh-Users }) }

if ($controls['BtnNewUser']) { $controls['BtnNewUser'].Add_Click({ Open-UserDialog -Mode "Create" }) }
if ($controls['BtnEditUser']) {
    $controls['BtnEditUser'].Add_Click({
        $u = $controls['GridUsers'].SelectedItem
        if ($u) { Open-UserDialog -Mode "Edit" -UserToEdit $u }
    })
}
if ($controls['BtnViewUser']) {
    $controls['BtnViewUser'].Add_Click({
        $u = $controls['GridUsers'].SelectedItem
        if ($u) { Open-UserDetailDialog -User $u }
    })
}
if ($controls['BtnResetPassword']) {
    $controls['BtnResetPassword'].Add_Click({
        $u = $controls['GridUsers'].SelectedItem
        if ($u) { Open-PasswordDialog -User $u }
    })
}
if ($controls['BtnToggleStatus']) { $controls['BtnToggleStatus'].Add_Click({ Toggle-UserStatusAction }) }
if ($controls['BtnMoveUser']) {
    $controls['BtnMoveUser'].Add_Click({
        $u = $controls['GridUsers'].SelectedItem
        if ($u) { Open-MoveDialog -Principal $u -Type "User" }
    })
}
if ($controls['BtnDeleteUser']) { $controls['BtnDeleteUser'].Add_Click({ Delete-UserAction }) }
if ($controls['BtnExportUsers']) { $controls['BtnExportUsers'].Add_Click({ Export-UsersAction }) }

# User Cross-Links to Softerra Tools
if ($controls['BtnUserRawAttributes']) {
    $controls['BtnUserRawAttributes'].Add_Click({
        $u = $controls['GridUsers'].SelectedItem
        if ($u) {
            $controls['NavAttributeEditor'].IsChecked = $true
            Show-Panel "AttributeEditor"
            $controls['TxtAttrEditorDN'].Text = $u.DistinguishedName
            Load-RawAttributesUI -TargetDN $u.DistinguishedName
        } else {
            [System.Windows.MessageBox]::Show("Please select a user first.", "Selection Required", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        }
    })
}

if ($controls['BtnUserCompare']) {
    $controls['BtnUserCompare'].Add_Click({
        $u = $controls['GridUsers'].SelectedItem
        if ($u) {
            $controls['NavObjectCompare'].IsChecked = $true
            Show-Panel "ObjectCompare"
            $controls['TxtCompareObjectA'].Text = $u.DistinguishedName
        } else {
            [System.Windows.MessageBox]::Show("Please select a user first.", "Selection Required", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        }
    })
}

if ($controls['GridUsers']) {
    $controls['GridUsers'].Add_MouseDoubleClick({
        $u = $controls['GridUsers'].SelectedItem
        if ($u) { Open-UserDetailDialog -User $u }
    })
}
#endregion

#region 3. Groups Management Logic
function Refresh-Groups {
    Set-Status -Message "Loading groups from Active Directory..."
    $searchText = if ($controls['TxtSearchGroups']) { $controls['TxtSearchGroups'].Text.Trim() } else { "" }
    
    $catFilter = "All"
    if ($controls['CmbGroupCategoryFilter'] -and $controls['CmbGroupCategoryFilter'].SelectedItem) {
        $catText = $controls['CmbGroupCategoryFilter'].SelectedItem.Content.ToString()
        if ($catText -match "Security|Distribution") { $catFilter = $catText }
    }

    $scopeFilter = "All"
    if ($controls['CmbGroupScopeFilter'] -and $controls['CmbGroupScopeFilter'].SelectedItem) {
        $scopeText = $controls['CmbGroupScopeFilter'].SelectedItem.Content.ToString()
        if ($scopeText -notmatch "All Scopes") { $scopeFilter = $scopeText }
    }

    $groups = Get-ADGroupsList -SearchText $searchText -CategoryFilter $catFilter -ScopeFilter $scopeFilter -Limit ($appConfig.UI.PageSize)
    $state.CachedGroups = $groups
    if ($controls['GridGroups']) {
        $controls['GridGroups'].ItemsSource = $groups
    }
    Set-Status -Message "Loaded $($groups.Count) group(s)." -Count "$($groups.Count) groups displayed"
}

function Open-GroupDialog {
    $dlgPath = Join-Path $viewsPath "GroupDialog.xaml"
    $dlg = Load-XamlWindow -XamlPath $dlgPath
    $dlg.Owner = $window

    $dControls = @{}
    $dReader = [System.Xml.XmlReader]::Create([System.IO.StringReader](Get-Content $dlgPath -Raw))
    while ($dReader.Read()) {
        if ($dReader.NodeType -eq [System.Xml.XmlNodeType]::Element) {
            $dName = $dReader.GetAttribute("Name")
            if ($dName) { $dControls[$dName] = $dlg.FindName($dName) }
        }
    }
    $dReader.Close()

    foreach ($ou in $state.CachedOUs) {
        $item = New-Object System.Windows.Controls.ComboBoxItem
        $item.Content = $ou.DisplayName
        $item.Tag = $ou.DistinguishedName
        [void]$dControls['CmbGroupOU'].Items.Add($item)
    }
    if ($dControls['CmbGroupOU'].Items.Count -gt 0) {
        $dControls['CmbGroupOU'].SelectedIndex = 0
    }

    $dControls['TxtGroupName'].Add_TextChanged({
        if (-not $dControls['TxtGroupSam'].Text) {
            $dControls['TxtGroupSam'].Text = $dControls['TxtGroupName'].Text
        }
    })

    $dControls['BtnCancel'].Add_Click({ $dlg.Close() })

    $dControls['BtnSaveGroup'].Add_Click({
        $name = $dControls['TxtGroupName'].Text.Trim()
        $sam  = $dControls['TxtGroupSam'].Text.Trim()
        $desc = $dControls['TxtGroupDescription'].Text.Trim()
        $ou   = $dControls['CmbGroupOU'].SelectedItem.Tag

        if ([string]::IsNullOrWhiteSpace($name) -or [string]::IsNullOrWhiteSpace($sam)) {
            $dControls['TxtDialogError'].Text = "Group name is required."
            return
        }

        $scope = "Global"
        if ($dControls['RadScopeUniversal'].IsChecked)   { $scope = "Universal" }
        if ($dControls['RadScopeDomainLocal'].IsChecked) { $scope = "DomainLocal" }

        $cat = if ($dControls['RadCatDistribution'].IsChecked) { "Distribution" } else { "Security" }

        $res = New-ADGroupItem -Name $name -SamAccountName $sam -Path $ou -GroupScope $scope -GroupCategory $cat -Description $desc
        if ($res.Success) {
            [System.Windows.MessageBox]::Show($res.Message, "Group Created", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            $dlg.Close()
            Refresh-Groups
            Refresh-Dashboard
        } else {
            $dControls['TxtDialogError'].Text = $res.Message
        }
    })

    [void]$dlg.ShowDialog()
}

function Open-MemberDialog {
    param ($Group)
    if (-not $Group) { return }

    $dlgPath = Join-Path $viewsPath "MemberDialog.xaml"
    $dlg = Load-XamlWindow -XamlPath $dlgPath
    $dlg.Owner = $window

    $dControls = @{}
    $dReader = [System.Xml.XmlReader]::Create([System.IO.StringReader](Get-Content $dlgPath -Raw))
    while ($dReader.Read()) {
        if ($dReader.NodeType -eq [System.Xml.XmlNodeType]::Element) {
            $dName = $dReader.GetAttribute("Name")
            if ($dName) { $dControls[$dName] = $dlg.FindName($dName) }
        }
    }
    $dReader.Close()

    $dControls['TxtGroupNameHeader'].Text = "Group: $($Group.Name)"

    $ReloadMembers = {
        $m = Get-ADGroupMembersList -Identity $Group.DistinguishedName
        $dControls['ListCurrentMembers'].ItemsSource = $m
        $dControls['TxtMemberCount'].Text = "$($m.Count) members"
    }
    & $ReloadMembers

    $dControls['BtnSearchMembers'].Add_Click({
        $st = $dControls['TxtMemberSearch'].Text.Trim()
        if ($st) {
            $foundUsers = Get-ADUsersList -SearchText $st -Limit 50
            $dControls['ListAvailableUsers'].ItemsSource = $foundUsers
        }
    })

    $dControls['TxtMemberSearch'].Add_KeyDown({
        if ($_.Key -eq [System.Windows.Input.Key]::Enter) {
            $dControls['BtnSearchMembers'].RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Button]::ClickEvent)))
        }
    })

    $dControls['BtnAddMember'].Add_Click({
        $sel = $dControls['ListAvailableUsers'].SelectedItem
        if ($sel) {
            $res = Add-ADPrincipalToGroup -GroupIdentity $Group.DistinguishedName -MemberIdentity $sel.SamAccountName
            if ($res.Success) {
                $dControls['TxtDialogStatus'].Text = "Added '$($sel.DisplayName)'."
                & $ReloadMembers
            } else {
                $dControls['TxtDialogStatus'].Text = $res.Message
            }
        }
    })

    $dControls['BtnRemoveMember'].Add_Click({
        $selMember = $dControls['ListCurrentMembers'].SelectedItem
        if ($selMember) {
            $confirm = [System.Windows.MessageBox]::Show(
                "Remove member '$($selMember.Name)' from group '$($Group.Name)'?",
                "Confirm Remove Member",
                [System.Windows.MessageBoxButton]::YesNo,
                [System.Windows.MessageBoxImage]::Question
            )
            if ($confirm -eq [System.Windows.MessageBoxResult]::Yes) {
                $res = Remove-ADPrincipalFromGroup -GroupIdentity $Group.DistinguishedName -MemberIdentity $selMember.DistinguishedName
                if ($res.Success) {
                    $dControls['TxtDialogStatus'].Text = "Removed '$($selMember.Name)'."
                    & $ReloadMembers
                }
            }
        }
    })

    $dControls['BtnClose'].Add_Click({ $dlg.Close() })
    [void]$dlg.ShowDialog()
}

function Delete-GroupAction {
    $selGroup = if ($controls['GridGroups']) { $controls['GridGroups'].SelectedItem } else { $null }
    if (-not $selGroup) { return }

    $confirm = [System.Windows.MessageBox]::Show(
        "Are you sure you want to permanently delete group '$($selGroup.Name)'?`nDN: $($selGroup.DistinguishedName)",
        "Confirm Delete Group",
        [System.Windows.MessageBoxButton]::YesNo,
        [System.Windows.MessageBoxImage]::Warning
    )

    if ($confirm -eq [System.Windows.MessageBoxResult]::Yes) {
        $res = Remove-ADGroupItem -Identity $selGroup.DistinguishedName
        if ($res.Success) {
            [System.Windows.MessageBox]::Show($res.Message, "Group Deleted", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            Refresh-Groups
            Refresh-Dashboard
        } else {
            [System.Windows.MessageBox]::Show($res.Message, "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        }
    }
}

function Export-GroupsAction {
    $saveDlg = New-Object System.Windows.Forms.SaveFileDialog
    $dateStr = (Get-Date).ToString("yyyyMMdd_HHmm")
    $saveDlg.FileName = "AD_Groups_$dateStr.csv"
    $saveDlg.Filter = "CSV files (*.csv)|*.csv|All files (*.*)|*.*"
    
    if ($saveDlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $groupsToExport = if ($state.CachedGroups.Count -gt 0) { $state.CachedGroups } else { Get-ADGroupsList }
        $res = Export-ADDataToCsv -Data $groupsToExport -FilePath $saveDlg.FileName -Delimiter ($appConfig.Defaults.ExportDelimiter) `
            -PropertiesToExport @('Name', 'SamAccountName', 'GroupCategory', 'GroupScope', 'MemberCount', 'Description', 'OUPath', 'DistinguishedName')

        if ($res.Success) {
            [System.Windows.MessageBox]::Show($res.Message, "Export Successful", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        }
    }
}

if ($controls['BtnSearchGroups']) { $controls['BtnSearchGroups'].Add_Click({ Refresh-Groups }) }
if ($controls['TxtSearchGroups']) {
    $controls['TxtSearchGroups'].Add_KeyDown({
        if ($_.Key -eq [System.Windows.Input.Key]::Enter) { Refresh-Groups }
    })
}
if ($controls['CmbGroupScopeFilter'])    { $controls['CmbGroupScopeFilter'].Add_SelectionChanged({ Refresh-Groups }) }
if ($controls['CmbGroupCategoryFilter']) { $controls['CmbGroupCategoryFilter'].Add_SelectionChanged({ Refresh-Groups }) }

if ($controls['BtnNewGroup'])      { $controls['BtnNewGroup'].Add_Click({ Open-GroupDialog }) }
if ($controls['BtnDeleteGroup'])   { $controls['BtnDeleteGroup'].Add_Click({ Delete-GroupAction }) }
if ($controls['BtnExportGroups'])  { $controls['BtnExportGroups'].Add_Click({ Export-GroupsAction }) }
if ($controls['BtnManageMembers']) {
    $controls['BtnManageMembers'].Add_Click({
        $g = $controls['GridGroups'].SelectedItem
        if ($g) { Open-MemberDialog -Group $g }
    })
}
if ($controls['BtnGroupRawAttributes']) {
    $controls['BtnGroupRawAttributes'].Add_Click({
        $g = $controls['GridGroups'].SelectedItem
        if ($g) {
            $controls['NavAttributeEditor'].IsChecked = $true
            Show-Panel "AttributeEditor"
            $controls['TxtAttrEditorDN'].Text = $g.DistinguishedName
            Load-RawAttributesUI -TargetDN $g.DistinguishedName
        } else {
            [System.Windows.MessageBox]::Show("Please select a group first.", "Selection Required", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        }
    })
}
#endregion

#region 4. Organizational Units (OUs) Management Logic
function Refresh-OUs {
    Set-Status -Message "Building Organizational Unit hierarchy..."
    $ouTree = Get-ADOUTree
    if ($ouTree -and $controls['TreeOUs']) {
        $controls['TreeOUs'].ItemsSource = @($ouTree)
    }

    # Populate OU filter dropdowns
    $ouFlatList = Get-ADOUFlatList
    $state.CachedOUs = $ouFlatList

    if ($controls['CmbUserOUFilter']) {
        $controls['CmbUserOUFilter'].Items.Clear()
        $domainRootItem = New-Object System.Windows.Controls.ComboBoxItem
        $domainRootItem.Content = "Entire Domain (All OUs)"
        $domainRootItem.Tag = ""
        [void]$controls['CmbUserOUFilter'].Items.Add($domainRootItem)
        $controls['CmbUserOUFilter'].SelectedIndex = 0

        foreach ($ou in $ouFlatList) {
            $item = New-Object System.Windows.Controls.ComboBoxItem
            $item.Content = $ou.DisplayName
            $item.Tag = $ou.DistinguishedName
            [void]$controls['CmbUserOUFilter'].Items.Add($item)
        }
    }

    Set-Status -Message "OU hierarchy loaded ($($ouFlatList.Count) OUs)." -Count "$($ouFlatList.Count) OUs"
}

function Open-OUDialog {
    $dlgPath = Join-Path $viewsPath "OUDialog.xaml"
    $dlg = Load-XamlWindow -XamlPath $dlgPath
    $dlg.Owner = $window

    $dControls = @{}
    $dReader = [System.Xml.XmlReader]::Create([System.IO.StringReader](Get-Content $dlgPath -Raw))
    while ($dReader.Read()) {
        if ($dReader.NodeType -eq [System.Xml.XmlNodeType]::Element) {
            $dName = $dReader.GetAttribute("Name")
            if ($dName) { $dControls[$dName] = $dlg.FindName($dName) }
        }
    }
    $dReader.Close()

    $rootItem = New-Object System.Windows.Controls.ComboBoxItem
    $rootItem.Content = "Domain Root ($($adContext.DomainName))"
    $rootItem.Tag = $adContext.DefaultNamingContext
    [void]$dControls['CmbParentOU'].Items.Add($rootItem)

    foreach ($ou in $state.CachedOUs) {
        $item = New-Object System.Windows.Controls.ComboBoxItem
        $item.Content = $ou.DisplayName
        $item.Tag = $ou.DistinguishedName
        [void]$dControls['CmbParentOU'].Items.Add($item)
    }
    $dControls['CmbParentOU'].SelectedIndex = 0

    $dControls['BtnCancel'].Add_Click({ $dlg.Close() })

    $dControls['BtnSaveOU'].Add_Click({
        $name = $dControls['TxtOUName'].Text.Trim()
        $desc = $dControls['TxtOUDescription'].Text.Trim()
        $parentPath = $dControls['CmbParentOU'].SelectedItem.Tag
        $isProtected = [bool]$dControls['ChkProtected'].IsChecked

        if ([string]::IsNullOrWhiteSpace($name)) {
            $dControls['TxtDialogError'].Text = "OU Name is required."
            return
        }

        $res = New-ADOrganizationalUnitItem -Name $name -Path $parentPath -Description $desc -Protected $isProtected
        if ($res.Success) {
            [System.Windows.MessageBox]::Show($res.Message, "OU Created", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            $dlg.Close()
            Refresh-OUs
            Refresh-Dashboard
        } else {
            $dControls['TxtDialogError'].Text = $res.Message
        }
    })

    [void]$dlg.ShowDialog()
}

if ($controls['BtnNewOU']) { $controls['BtnNewOU'].Add_Click({ Open-OUDialog }) }

function Load-OUObjectsUI {
    $selectedNode = if ($controls['TreeOUs']) { $controls['TreeOUs'].SelectedItem } else { $null }
    if (-not $selectedNode) { return }

    if ($controls['TxtSelectedOUName']) { $controls['TxtSelectedOUName'].Text = $selectedNode.Name }
    if ($controls['TxtSelectedOUDN'])   { $controls['TxtSelectedOUDN'].Text   = $selectedNode.DistinguishedName }

    $scope = "OneLevel"
    if ($controls['CmbOUSearchScope'] -and $controls['CmbOUSearchScope'].SelectedItem) {
        $scope = $controls['CmbOUSearchScope'].SelectedItem.Content.ToString()
    }

    try {
        Set-Status -Message "Fetching directory objects in $($selectedNode.Name)..."
        $rawItems = Get-ADObjectsInOU -SearchBase $selectedNode.DistinguishedName -SearchScope $scope
        if ($controls['GridOUObjects']) {
            $controls['GridOUObjects'].ItemsSource = $rawItems
        }
        if ($controls['TxtSelectedOUObjectsCount']) {
            $count = if ($rawItems) { $rawItems.Count } else { 0 }
            $controls['TxtSelectedOUObjectsCount'].Text = "$count object(s)"
        }
        Set-Status -Message "Loaded $($rawItems.Count) object(s) in $($selectedNode.Name)."
    } catch {
        if ($controls['GridOUObjects']) { $controls['GridOUObjects'].ItemsSource = @() }
        if ($controls['TxtSelectedOUObjectsCount']) { $controls['TxtSelectedOUObjectsCount'].Text = "0 objects" }
        Set-Status -Message "Error querying OU objects: $($_.Exception.Message)"
    }
}

if ($controls['TreeOUs']) {
    $controls['TreeOUs'].Add_SelectedItemChanged({ Load-OUObjectsUI })
}

if ($controls['CmbOUSearchScope']) {
    $controls['CmbOUSearchScope'].Add_SelectionChanged({ Load-OUObjectsUI })
}

if ($controls['BtnRefreshOUObjects']) {
    $controls['BtnRefreshOUObjects'].Add_Click({ Load-OUObjectsUI })
}

if ($controls['GridOUObjects']) {
    $controls['GridOUObjects'].Add_MouseDoubleClick({
        $item = $controls['GridOUObjects'].SelectedItem
        if ($item -and $item.DistinguishedName) {
            $controls['NavAttributeEditor'].IsChecked = $true
            Show-Panel "AttributeEditor"
            $controls['TxtAttrEditorDN'].Text = $item.DistinguishedName
            Load-RawAttributesUI -TargetDN $item.DistinguishedName
        }
    })
}

if ($controls['BtnOURawAttributes']) {
    $controls['BtnOURawAttributes'].Add_Click({
        $selectedNode = if ($controls['TreeOUs']) { $controls['TreeOUs'].SelectedItem } else { $null }
        if ($selectedNode) {
            $controls['NavAttributeEditor'].IsChecked = $true
            Show-Panel "AttributeEditor"
            $controls['TxtAttrEditorDN'].Text = $selectedNode.DistinguishedName
            Load-RawAttributesUI -TargetDN $selectedNode.DistinguishedName
        } else {
            [System.Windows.MessageBox]::Show("Please select an OU from the tree first.", "Selection Required", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        }
    })
}

if ($controls['BtnDeleteOU']) {
    $controls['BtnDeleteOU'].Add_Click({
        $selectedNode = if ($controls['TreeOUs']) { $controls['TreeOUs'].SelectedItem } else { $null }
        if (-not $selectedNode -or $selectedNode.DistinguishedName -eq $adContext.DefaultNamingContext) {
            [System.Windows.MessageBox]::Show("Cannot delete the domain root or no OU is selected.", "Notice", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            return
        }

        $confirm = [System.Windows.MessageBox]::Show(
            "Are you sure you want to delete Organizational Unit:`n`n$($selectedNode.Name)`nDN: $($selectedNode.DistinguishedName)`n`nWARNING: All objects within this OU may be deleted!",
            "Confirm Delete OU",
            [System.Windows.MessageBoxButton]::YesNo,
            [System.Windows.MessageBoxImage]::Warning
        )

        if ($confirm -eq [System.Windows.MessageBoxResult]::Yes) {
            $res = Remove-ADOrganizationalUnitItem -Identity $selectedNode.DistinguishedName -UnprotectFirst $true
            if ($res.Success) {
                [System.Windows.MessageBox]::Show($res.Message, "OU Deleted", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
                Refresh-OUs
                Refresh-Dashboard
            } else {
                [System.Windows.MessageBox]::Show($res.Message, "Error Deleting OU", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
            }
        }
    })
}
#endregion

#region 5. Computers Inventory Logic
function Refresh-Computers {
    Set-Status -Message "Loading domain computers..."
    $search = if ($controls['TxtSearchComputers']) { $controls['TxtSearchComputers'].Text.Trim() } else { "" }
    $computers = Get-ADComputersList -SearchText $search -Limit ($appConfig.UI.PageSize)
    $state.CachedComputers = $computers
    if ($controls['GridComputers']) {
        $controls['GridComputers'].ItemsSource = $computers
    }
    Set-Status -Message "Loaded $($computers.Count) computer(s)." -Count "$($computers.Count) computers displayed"
}

if ($controls['BtnSearchComputers']) { $controls['BtnSearchComputers'].Add_Click({ Refresh-Computers }) }
if ($controls['TxtSearchComputers']) {
    $controls['TxtSearchComputers'].Add_KeyDown({
        if ($_.Key -eq [System.Windows.Input.Key]::Enter) { Refresh-Computers }
    })
}

if ($controls['BtnComputerRawAttributes']) {
    $controls['BtnComputerRawAttributes'].Add_Click({
        $c = if ($controls['GridComputers']) { $controls['GridComputers'].SelectedItem } else { $null }
        if ($c) {
            $controls['NavAttributeEditor'].IsChecked = $true
            Show-Panel "AttributeEditor"
            $controls['TxtAttrEditorDN'].Text = $c.DistinguishedName
            Load-RawAttributesUI -TargetDN $c.DistinguishedName
        } else {
            [System.Windows.MessageBox]::Show("Please select a computer first.", "Selection Required", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        }
    })
}

if ($controls['BtnComputerCompare']) {
    $controls['BtnComputerCompare'].Add_Click({
        $c = if ($controls['GridComputers']) { $controls['GridComputers'].SelectedItem } else { $null }
        if ($c) {
            $controls['NavObjectCompare'].IsChecked = $true
            Show-Panel "ObjectCompare"
            $controls['TxtCompareObjectA'].Text = $c.DistinguishedName
        } else {
            [System.Windows.MessageBox]::Show("Please select a computer first.", "Selection Required", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        }
    })
}

if ($controls['BtnExportComputers']) {
    $controls['BtnExportComputers'].Add_Click({
        $saveDlg = New-Object System.Windows.Forms.SaveFileDialog
        $dateStr = (Get-Date).ToString("yyyyMMdd_HHmm")
        $saveDlg.FileName = "AD_Computers_$dateStr.csv"
        $saveDlg.Filter = "CSV files (*.csv)|*.csv|All files (*.*)|*.*"
        
        if ($saveDlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $computersToExport = if ($state.CachedComputers.Count -gt 0) { $state.CachedComputers } else { Get-ADComputersList }
            $res = Export-ADDataToCsv -Data $computersToExport -FilePath $saveDlg.FileName -Delimiter ($appConfig.Defaults.ExportDelimiter) `
                -PropertiesToExport @('Name', 'DNSHostName', 'OperatingSystem', 'OSVersion', 'Status', 'LastLogon', 'OUPath', 'DistinguishedName')

            if ($res.Success) {
                [System.Windows.MessageBox]::Show($res.Message, "Export Successful", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            }
        }
    })
}
#endregion

#region 6. Directory Search (Visual LDAP Filter Builder)
function Attach-SearchableAttributeDropdown {
    param(
        [System.Windows.Controls.ComboBox]$Combo,
        [System.Collections.Generic.List[string]]$MasterList,
        [System.Windows.Controls.TextBlock]$OutcomeText,
        [System.Windows.Controls.Border]$OutcomeBorder,
        [System.Windows.Controls.TextBox]$SyncSearchBox = $null,
        [bool]$IncludeAnyOption = $false
    )

    if (-not $Combo -or -not $MasterList -or $MasterList.Count -eq 0) { return }

    $Combo.IsEditable = $true
    $Combo.IsTextSearchEnabled = $false
    $Combo.StaysOpenOnEdit = $true
    $Combo.MaxDropDownHeight = 320

    $Combo.ApplyTemplate()
    $editBox = $Combo.Template.FindName("PART_EditableTextBox", $Combo)
    if (-not $editBox) { return }

    # When dropdown receives focus: select all text so typing immediately starts a new query
    $editBox.Add_GotFocus({
        $editBox.SelectAll()
        $Combo.IsDropDownOpen = $true
    })

    # DropDownOpened: when user clicks the toggle arrow, ensure the list is ready
    $Combo.Add_DropDownOpened({
        if ($state.IsFilteringAttributes) { return }
        $currentText = if ($editBox.Text) { $editBox.Text.Trim() } else { "" }
        $selectedText = if ($Combo.SelectedItem) {
            if ($Combo.SelectedItem -is [System.Windows.Controls.ComboBoxItem]) { $Combo.SelectedItem.Content.ToString() } else { $Combo.SelectedItem.ToString() }
        } else { "" }

        if ([string]::IsNullOrWhiteSpace($currentText) -or ($selectedText -and $currentText -eq $selectedText)) {
            $fullList = [System.Collections.Generic.List[string]]::new()
            if ($IncludeAnyOption) { [void]$fullList.Add("Any Attribute") }
            foreach ($item in $MasterList) { [void]$fullList.Add($item) }
            $Combo.ItemsSource = @($fullList)
            if ($selectedText) { $Combo.SelectedItem = $selectedText }
        }
    })

    # Keyboard navigation: Down/Up to browse, Enter to confirm, Escape to cancel
    $editBox.Add_PreviewKeyDown({
        param($s, $e)
        if ($e.Key -eq [System.Windows.Input.Key]::Down) {
            if (-not $Combo.IsDropDownOpen) {
                $Combo.IsDropDownOpen = $true
                $e.Handled = $true
            }
        } elseif ($e.Key -eq [System.Windows.Input.Key]::Enter) {
            $Combo.IsDropDownOpen = $false
            $e.Handled = $true
            if ($controls['TxtFilterVal']) {
                $controls['TxtFilterVal'].Focus()
                $controls['TxtFilterVal'].SelectAll()
            }
        } elseif ($e.Key -eq [System.Windows.Input.Key]::Escape) {
            $fullList = [System.Collections.Generic.List[string]]::new()
            if ($IncludeAnyOption) { [void]$fullList.Add("Any Attribute") }
            foreach ($item in $MasterList) { [void]$fullList.Add($item) }
            $Combo.ItemsSource = @($fullList)
            $Combo.IsDropDownOpen = $false
            $e.Handled = $true
        }
    })

    # Live Real-Time Filtering as user types directly in the dropdown
    $FilterCombo = {
        param([string]$query)
        if ($state.IsFilteringAttributes) { return }
        $state.IsFilteringAttributes = $true
        try {
            $caret = $editBox.CaretIndex
            $trimmed = if ($query) { $query.Trim() } else { "" }

            if ($SyncSearchBox -and $SyncSearchBox.Text -ne $trimmed) {
                $SyncSearchBox.Text = $trimmed
            }

            if ([string]::IsNullOrWhiteSpace($trimmed)) {
                $fullList = [System.Collections.Generic.List[string]]::new()
                if ($IncludeAnyOption) { [void]$fullList.Add("Any Attribute") }
                foreach ($item in $MasterList) { [void]$fullList.Add($item) }
                $Combo.ItemsSource = @($fullList)
                $Combo.IsDropDownOpen = $true
                $editBox.Text = ""
                $editBox.CaretIndex = 0

                if ($OutcomeText) {
                    $OutcomeText.Text = "Displaying all $($fullList.Count) attributes (type directly in dropdown to search)"
                    $OutcomeText.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#38BDF8")
                }
                if ($OutcomeBorder) {
                    $OutcomeBorder.Background = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#1E293B")
                }
                return
            }

            $matched = [System.Collections.Generic.List[string]]::new()
            if ($IncludeAnyOption -and "Any Attribute".IndexOf($trimmed, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                [void]$matched.Add("Any Attribute")
            }
            foreach ($attr in $MasterList) {
                if ($attr.IndexOf($trimmed, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                    [void]$matched.Add($attr)
                }
            }

            if ($matched.Count -gt 0) {
                $Combo.ItemsSource = @($matched)
                $Combo.IsDropDownOpen = $true
                $editBox.Text = $query
                $editBox.CaretIndex = $caret

                if ($OutcomeText) {
                    $plural = if ($matched.Count -eq 1) { "attribute" } else { "attributes" }
                    $preview = if ($matched.Count -le 3) {
                        " ($([string]::Join(', ', $matched)))"
                    } else {
                        " (e.g. $($matched[0]), $($matched[1]), $($matched[2])...)"
                    }
                    $OutcomeText.Text = "Found $($matched.Count) matching $plural for '$trimmed'$preview"
                    $OutcomeText.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#4ADE80")
                }
                if ($OutcomeBorder) {
                    $OutcomeBorder.Background = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#064E3B")
                }
            } else {
                $Combo.ItemsSource = @()
                $Combo.Text = $trimmed

                if ($OutcomeText) {
                    $OutcomeText.Text = "No attributes matched '$trimmed' (custom attribute allowed)"
                    $OutcomeText.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#FBBF24")
                }
                if ($OutcomeBorder) {
                    $OutcomeBorder.Background = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#451A03")
                }
            }
        }
        finally {
            $state.IsFilteringAttributes = $false
        }
    }

    $editBox.Add_TextChanged({
        if ($state.IsFilteringAttributes) { return }
        if (-not $editBox.IsKeyboardFocused) { return }
        $selectedText = if ($Combo.SelectedItem) {
            if ($Combo.SelectedItem -is [System.Windows.Controls.ComboBoxItem]) { $Combo.SelectedItem.Content.ToString() } else { $Combo.SelectedItem.ToString() }
        } else { "" }
        if ($selectedText -and $editBox.Text -eq $selectedText) { return }

        & $FilterCombo -query $editBox.Text
    })

    $Combo.Add_SelectionChanged({
        if ($state.IsFilteringAttributes) { return }
        if (-not $Combo.SelectedItem) { return }

        $sel = if ($Combo.SelectedItem -is [System.Windows.Controls.ComboBoxItem]) {
            $Combo.SelectedItem.Content.ToString()
        } else {
            $Combo.SelectedItem.ToString()
        }

        if (-not [string]::IsNullOrWhiteSpace($sel)) {
            $Combo.IsDropDownOpen = $false
            if ($OutcomeText) {
                $OutcomeText.Text = "Selected attribute: $sel (Ready to insert condition)"
                $OutcomeText.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#38BDF8")
            }
            if ($OutcomeBorder) {
                $OutcomeBorder.Background = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#1E293B")
            }
        }
    })
}

function Populate-SearchAttributeDropdowns {
    if ($state.SearchAttributesLoaded) { return }

    # Core high-priority attributes to keep at the top for quick access
    $priorityAttrs = @(
        'sAMAccountName', 'userPrincipalName', 'displayName', 'givenName', 'sn', 'cn', 'name', 'mail',
        'distinguishedName', 'objectClass', 'objectCategory', 'userAccountControl', 'department', 'title',
        'company', 'manager', 'telephoneNumber', 'mobile', 'memberOf', 'member', 'primaryGroupID',
        'groupType', 'managedBy', 'pwdLastSet', 'lockoutTime', 'badPwdCount', 'accountExpires', 'adminCount',
        'description', 'comment', 'whenCreated', 'whenChanged', 'lastLogon', 'lastLogonTimestamp',
        'operatingSystem', 'operatingSystemVersion', 'operatingSystemServicePack', 'dNSHostName',
        'servicePrincipalName', 'employeeID', 'employeeNumber', 'employeeType', 'physicalDeliveryOfficeName',
        'streetAddress', 'l', 'st', 'postalCode', 'c', 'co', 'countryCode', 'postOfficeBox',
        'proxyAddresses', 'targetAddress', 'mailNickname', 'homeDirectory', 'homeDrive', 'scriptPath',
        'profilePath', 'userWorkstations', 'logonHours', 'initials', 'middleName', 'directReports',
        'division', 'organization', 'wWWHomePage', 'url', 'facsimileTelephoneNumber', 'ipPhone',
        'pager', 'homePhone', 'canonicalName', 'objectGUID', 'objectSid', 'sIDHistory', 'tokenGroups',
        'msDS-UserPasswordExpiryTimeComputed', 'msDS-User-Account-Control-Computed', 'msDS-ResultantPSO',
        'ms-Mcs-AdmPwd', 'isCriticalSystemObject', 'showInAdvancedViewOnly', 'uSNCreated', 'uSNChanged'
    )

    $allAttrNames = [System.Collections.Generic.List[string]]::new()
    foreach ($p in $priorityAttrs) {
        if (-not $allAttrNames.Contains($p)) { [void]$allAttrNames.Add($p) }
    }

    try {
        $schemaAttrs = Get-ADSchemaAttributes
        if ($schemaAttrs -and $schemaAttrs.Count -gt 0) {
            $otherAttrs = $schemaAttrs | Select-Object -ExpandProperty Name | Sort-Object
            foreach ($attr in $otherAttrs) {
                if (-not $allAttrNames.Contains($attr)) {
                    [void]$allAttrNames.Add($attr)
                }
            }
        }
    }
    catch {
        Write-Warning "Could not load schema attributes: $_"
    }

    $state.MasterAttributeList = $allAttrNames
    $state.SearchAttributesLoaded = $true

    $state.IsFilteringAttributes = $true
    try {
        if ($controls['CmbFilterAttr']) {
            $cur = ""
            if ($controls['CmbFilterAttr'].SelectedItem) {
                $cur = if ($controls['CmbFilterAttr'].SelectedItem -is [System.Windows.Controls.ComboBoxItem]) {
                    $controls['CmbFilterAttr'].SelectedItem.Content.ToString()
                } else {
                    $controls['CmbFilterAttr'].SelectedItem.ToString()
                }
            } elseif (-not [string]::IsNullOrWhiteSpace($controls['CmbFilterAttr'].Text)) {
                $cur = $controls['CmbFilterAttr'].Text.Trim()
            }
            if ([string]::IsNullOrWhiteSpace($cur)) { $cur = "sAMAccountName" }

            $controls['CmbFilterAttr'].Items.Clear()
            $controls['CmbFilterAttr'].ItemsSource = @($allAttrNames)
            $controls['CmbFilterAttr'].SelectedItem = if ($allAttrNames.Contains($cur)) { $cur } else { "sAMAccountName" }

            Attach-SearchableAttributeDropdown -Combo $controls['CmbFilterAttr'] `
                -MasterList $state.MasterAttributeList `
                -OutcomeText $controls['TxtSearchAttrOutcome'] `
                -OutcomeBorder $controls['BorderSearchAttrOutcome'] `
                -SyncSearchBox $controls['TxtSearchAttrFilter'] `
                -IncludeAnyOption $false
        }

        if ($controls['CmbRegexTargetAttr']) {
            $curRegex = ""
            if ($controls['CmbRegexTargetAttr'].SelectedItem) {
                $curRegex = if ($controls['CmbRegexTargetAttr'].SelectedItem -is [System.Windows.Controls.ComboBoxItem]) {
                    $controls['CmbRegexTargetAttr'].SelectedItem.Content.ToString()
                } else {
                    $controls['CmbRegexTargetAttr'].SelectedItem.ToString()
                }
            } elseif (-not [string]::IsNullOrWhiteSpace($controls['CmbRegexTargetAttr'].Text)) {
                $curRegex = $controls['CmbRegexTargetAttr'].Text.Trim()
            }
            if ([string]::IsNullOrWhiteSpace($curRegex)) { $curRegex = "Any Attribute" }

            $regexAttrs = [System.Collections.Generic.List[string]]::new()
            [void]$regexAttrs.Add("Any Attribute")
            foreach ($a in $allAttrNames) {
                [void]$regexAttrs.Add($a)
            }

            $controls['CmbRegexTargetAttr'].Items.Clear()
            $controls['CmbRegexTargetAttr'].ItemsSource = @($regexAttrs)
            $controls['CmbRegexTargetAttr'].SelectedItem = if ($regexAttrs.Contains($curRegex)) { $curRegex } else { "Any Attribute" }

            Attach-SearchableAttributeDropdown -Combo $controls['CmbRegexTargetAttr'] `
                -MasterList $state.MasterAttributeList `
                -OutcomeText $null `
                -OutcomeBorder $null `
                -SyncSearchBox $null `
                -IncludeAnyOption $true
        }

        if ($controls['TxtSearchAttrOutcome']) {
            $controls['TxtSearchAttrOutcome'].Text = "Displaying all $($allAttrNames.Count) attributes (type directly in dropdown to search)"
            $controls['TxtSearchAttrOutcome'].Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#38BDF8")
        }
        if ($controls['BorderSearchAttrOutcome']) {
            $controls['BorderSearchAttrOutcome'].Background = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#1E293B")
        }
    }
    finally {
        $state.IsFilteringAttributes = $false
    }
}

function Filter-SearchAttributes {
    if (-not $state.SearchAttributesLoaded -or -not $state.MasterAttributeList -or $state.MasterAttributeList.Count -eq 0) {
        Populate-SearchAttributeDropdowns
    }

    $query = ""
    if ($controls['TxtSearchAttrFilter']) {
        $query = $controls['TxtSearchAttrFilter'].Text
        if ($null -eq $query) { $query = "" }
        $query = $query.Trim()
    }

    if ($controls['TxtSearchAttrPlaceholder']) {
        $controls['TxtSearchAttrPlaceholder'].Visibility = if ([string]::IsNullOrEmpty($query)) {
            [System.Windows.Visibility]::Visible
        } else {
            [System.Windows.Visibility]::Collapsed
        }
    }

    $state.IsFilteringAttributes = $true
    try {
        if ([string]::IsNullOrWhiteSpace($query)) {
            if ($controls['CmbFilterAttr']) {
                $cur = $controls['CmbFilterAttr'].SelectedItem
                $controls['CmbFilterAttr'].ItemsSource = @($state.MasterAttributeList)
                if ($cur -and $state.MasterAttributeList.Contains($cur)) {
                    $controls['CmbFilterAttr'].SelectedItem = $cur
                } else {
                    $controls['CmbFilterAttr'].SelectedItem = "sAMAccountName"
                }
            }

            if ($controls['CmbRegexTargetAttr']) {
                $regexList = [System.Collections.Generic.List[string]]::new()
                [void]$regexList.Add("Any Attribute")
                foreach ($a in $state.MasterAttributeList) { [void]$regexList.Add($a) }
                $controls['CmbRegexTargetAttr'].ItemsSource = @($regexList)
                if (-not $controls['CmbRegexTargetAttr'].SelectedItem) {
                    $controls['CmbRegexTargetAttr'].SelectedItem = "Any Attribute"
                }
            }

            if ($controls['TxtSearchAttrOutcome']) {
                $controls['TxtSearchAttrOutcome'].Text = "Displaying all $($state.MasterAttributeList.Count) attributes (type directly in dropdown to search)"
                $controls['TxtSearchAttrOutcome'].Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#38BDF8")
            }
            if ($controls['BorderSearchAttrOutcome']) {
                $controls['BorderSearchAttrOutcome'].Background = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#1E293B")
            }
            return
        }

        # Filter attributes matching query (case-insensitive substring)
        $filtered = [System.Collections.Generic.List[string]]::new()
        foreach ($attr in $state.MasterAttributeList) {
            if ($attr.IndexOf($query, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                [void]$filtered.Add($attr)
            }
        }

        if ($filtered.Count -gt 0) {
            if ($controls['CmbFilterAttr']) {
                $controls['CmbFilterAttr'].ItemsSource = @($filtered)
                $controls['CmbFilterAttr'].SelectedItem = $filtered[0]
                $controls['CmbFilterAttr'].IsDropDownOpen = $true
            }

            if ($controls['CmbRegexTargetAttr']) {
                $regexFiltered = [System.Collections.Generic.List[string]]::new()
                [void]$regexFiltered.Add("Any Attribute")
                foreach ($a in $filtered) { [void]$regexFiltered.Add($a) }
                $controls['CmbRegexTargetAttr'].ItemsSource = @($regexFiltered)
            }

            if ($controls['TxtSearchAttrOutcome']) {
                $plural = if ($filtered.Count -eq 1) { "attribute" } else { "attributes" }
                $preview = if ($filtered.Count -le 3) {
                    " ($([string]::Join(', ', $filtered)))"
                } else {
                    " (e.g. $($filtered[0]), $($filtered[1]), $($filtered[2])...)"
                }
                $controls['TxtSearchAttrOutcome'].Text = "Found $($filtered.Count) matching $plural for '$query'$preview"
                $controls['TxtSearchAttrOutcome'].Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#4ADE80")
            }
            if ($controls['BorderSearchAttrOutcome']) {
                $controls['BorderSearchAttrOutcome'].Background = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#064E3B")
            }
        } else {
            if ($controls['CmbFilterAttr']) {
                $controls['CmbFilterAttr'].ItemsSource = @()
                $controls['CmbFilterAttr'].Text = $query
            }

            if ($controls['CmbRegexTargetAttr']) {
                $controls['CmbRegexTargetAttr'].ItemsSource = @("Any Attribute")
            }

            if ($controls['TxtSearchAttrOutcome']) {
                $controls['TxtSearchAttrOutcome'].Text = "No attributes matched '$query' (custom attribute allowed)"
                $controls['TxtSearchAttrOutcome'].Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#FBBF24")
            }
            if ($controls['BorderSearchAttrOutcome']) {
                $controls['BorderSearchAttrOutcome'].Background = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#451A03")
            }
        }
    }
    finally {
        $state.IsFilteringAttributes = $false
    }
}

function Init-DirectorySearch {
    if ($controls['TxtSearchBaseDn'] -and [string]::IsNullOrEmpty($controls['TxtSearchBaseDn'].Text)) {
        $controls['TxtSearchBaseDn'].Text = $adContext.DefaultNamingContext
    }
    Populate-SearchAttributeDropdowns
}

# Live Attribute Search & Outcome Event Listeners for Quick Search Bar
if ($controls['TxtSearchAttrFilter']) {
    $controls['TxtSearchAttrFilter'].Add_TextChanged({
        Filter-SearchAttributes
    })
    $controls['TxtSearchAttrFilter'].Add_KeyDown({
        param($s, $e)
        if ($e.Key -eq [System.Windows.Input.Key]::Enter) {
            $e.Handled = $true
            if ($controls['CmbFilterAttr']) {
                $controls['CmbFilterAttr'].Focus()
                $controls['CmbFilterAttr'].IsDropDownOpen = $true
            }
        } elseif ($e.Key -eq [System.Windows.Input.Key]::Escape) {
            $e.Handled = $true
            if ($controls['TxtSearchAttrFilter']) {
                $controls['TxtSearchAttrFilter'].Text = ""
            }
            Filter-SearchAttributes
        }
    })
}

if ($controls['BtnClearAttrFilter']) {
    $controls['BtnClearAttrFilter'].Add_Click({
        if ($controls['TxtSearchAttrFilter']) {
            $controls['TxtSearchAttrFilter'].Text = ""
            $controls['TxtSearchAttrFilter'].Focus()
        }
        Filter-SearchAttributes
    })
}

if ($controls['CmbSearchPresets']) {
    $controls['CmbSearchPresets'].Add_SelectionChanged({
        if (-not $controls['CmbSearchPresets'].SelectedItem) { return }
        $selText = $controls['CmbSearchPresets'].SelectedItem.Content.ToString()
        $filter = switch ($selText) {
            "All Users"                        { "(objectClass=user)" }
            "Locked Out Accounts"              { "(&(objectCategory=person)(objectClass=user)(lockoutTime>=1))" }
            "Disabled Accounts"                { "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))" }
            "Passwords Never Expire"           { "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))" }
            "Empty Groups"                     { "(&(objectCategory=group)(!member=*))" }
            "Privileged Accounts (adminCount=1)" { "(&(objectCategory=person)(adminCount=1))" }
            "Service Accounts (SPNs)"          { "(&(servicePrincipalName=*)(!(objectClass=computer)))" }
            "All Computers"                    { "(objectCategory=computer)" }
            "Domain Controllers"               { "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))" }
            default                            { "" }
        }
        if ($filter -and $controls['TxtRawLdapFilter']) {
            $controls['TxtRawLdapFilter'].Text = $filter
        }
    })
}

if ($controls['BtnInsertCondition']) {
    $controls['BtnInsertCondition'].Add_Click({
        $attr = ""
        if ($controls['CmbFilterAttr'].SelectedItem) {
            $attr = if ($controls['CmbFilterAttr'].SelectedItem -is [System.Windows.Controls.ComboBoxItem]) {
                $controls['CmbFilterAttr'].SelectedItem.Content.ToString()
            } else {
                $controls['CmbFilterAttr'].SelectedItem.ToString()
            }
        } elseif (-not [string]::IsNullOrWhiteSpace($controls['CmbFilterAttr'].Text)) {
            $attr = $controls['CmbFilterAttr'].Text.Trim()
        }
        if ([string]::IsNullOrWhiteSpace($attr)) { $attr = "sAMAccountName" }

        $op = if ($controls['CmbFilterOp'].SelectedItem) {
            if ($controls['CmbFilterOp'].SelectedItem -is [System.Windows.Controls.ComboBoxItem]) {
                $controls['CmbFilterOp'].SelectedItem.Content.ToString()
            } else {
                $controls['CmbFilterOp'].SelectedItem.ToString()
            }
        } else { "=" }
        $val = if ($controls['TxtFilterVal']) { $controls['TxtFilterVal'].Text.Trim() } else { "*" }

        $condition = switch ($op) {
            "="            { "($attr=$val)" }
            "starts with"  { "($attr=$val*)" }
            "ends with"    { "($attr=*$val)" }
            "contains"     { "($attr=*$val*)" }
            "* is present" { "($attr=*)" }
            "!="           { "(!($attr=$val))" }
            ">="           { "($attr>=$val)" }
            "<="           { "($attr<=$val)" }
            default        { "($attr=$val)" }
        }

        $existing = if ($controls['TxtRawLdapFilter']) { $controls['TxtRawLdapFilter'].Text.Trim() } else { "" }
        if ([string]::IsNullOrWhiteSpace($existing) -or $existing -eq "(objectClass=*)" -or $existing -eq "(objectClass=user)") {
            $controls['TxtRawLdapFilter'].Text = "(&(objectClass=user)$condition)"
        } else {
            $controls['TxtRawLdapFilter'].Text = "(&$existing$condition)"
        }
    })
}

function Invoke-LdapSearchUI {
    $filter = if ($controls['TxtRawLdapFilter']) { $controls['TxtRawLdapFilter'].Text.Trim() } else { "(objectClass=*)" }
    $baseDn = if ($controls['TxtSearchBaseDn'] -and -not [string]::IsNullOrWhiteSpace($controls['TxtSearchBaseDn'].Text)) {
        $controls['TxtSearchBaseDn'].Text.Trim()
    } else {
        $adContext.DefaultNamingContext
    }
    $scopeItem = if ($controls['CmbSearchScope'] -and $controls['CmbSearchScope'].SelectedItem) {
        $controls['CmbSearchScope'].SelectedItem.Content.ToString()
    } else { "Subtree" }

    Set-Status -Message "Executing LDAP filter search: $filter ..."
    $controls['TxtSearchStatus'].Text = "Executing LDAP search on $scopeItem scope..."
    $res = Invoke-LdapQuery -Filter $filter -SearchBase $baseDn -SearchScope $scopeItem -PageSize 1000

    if ($res.Success) {
        $rawResults = $res.Results
        $finalResults = $rawResults

        # Advanced RegEx Filtering Suite (Softerra LDAP Administrator 2026 Parity)
        $isRegexEnabled = if ($controls['ChkUseRegexFilter']) { [bool]$controls['ChkUseRegexFilter'].IsChecked } else { $false }
        $regexPattern = if ($controls['TxtRegexPattern']) { $controls['TxtRegexPattern'].Text.Trim() } else { "" }

        if ($isRegexEnabled -and -not [string]::IsNullOrEmpty($regexPattern)) {
            $ignoreCase = if ($controls['ChkRegexIgnoreCase']) { [bool]$controls['ChkRegexIgnoreCase'].IsChecked } else { $true }
            $invertMatch = if ($controls['ChkRegexInvert']) { [bool]$controls['ChkRegexInvert'].IsChecked } else { $false }
            $targetAttr = "Any Attribute"
            if ($controls['CmbRegexTargetAttr'] -and $controls['CmbRegexTargetAttr'].SelectedItem) {
                $targetAttr = if ($controls['CmbRegexTargetAttr'].SelectedItem -is [System.Windows.Controls.ComboBoxItem]) {
                    $controls['CmbRegexTargetAttr'].SelectedItem.Content.ToString()
                } else {
                    $controls['CmbRegexTargetAttr'].SelectedItem.ToString()
                }
            } elseif ($controls['CmbRegexTargetAttr'] -and -not [string]::IsNullOrWhiteSpace($controls['CmbRegexTargetAttr'].Text)) {
                $targetAttr = $controls['CmbRegexTargetAttr'].Text.Trim()
            }

            $regexOptions = [System.Text.RegularExpressions.RegexOptions]::None
            if ($ignoreCase) {
                $regexOptions = $regexOptions -bor [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
            }

            try {
                $rx = [System.Text.RegularExpressions.Regex]::new($regexPattern, $regexOptions)

                $filteredList = [System.Collections.Generic.List[PSCustomObject]]::new()
                foreach ($item in $rawResults) {
                    $matched = $false
                    if ($targetAttr -eq "Any Attribute") {
                        foreach ($prop in $item.PSObject.Properties) {
                            if ($prop.Value) {
                                $valStr = if ($prop.Value -is [array]) { $prop.Value -join " " } else { $prop.Value.ToString() }
                                if ($rx.IsMatch($valStr)) {
                                    $matched = $true
                                    break
                                }
                            }
                        }
                    } else {
                        $prop = $item.PSObject.Properties[$targetAttr]
                        if (-not $prop) {
                            $prop = $item.PSObject.Properties[$targetAttr.ToLower()]
                        }
                        if ($prop -and $prop.Value) {
                            $valStr = if ($prop.Value -is [array]) { $prop.Value -join " " } else { $prop.Value.ToString() }
                            if ($rx.IsMatch($valStr)) {
                                $matched = $true
                            }
                        }
                    }

                    if ($invertMatch) {
                        $matched = -not $matched
                    }

                    if ($matched) {
                        $filteredList.Add($item)
                    }
                }

                $finalResults = @($filteredList)
                $msg = "Search completed in $($res.ElapsedMilliseconds) ms. $($rawResults.Count) LDAP objects found -> $($finalResults.Count) matched RegEx '/$regexPattern/'."
                $controls['TxtSearchStatus'].Text = $msg
                Set-Status -Message $msg -Count "$($finalResults.Count) regex matches"
            }
            catch {
                $controls['TxtSearchStatus'].Text = "RegEx Error: $($_.Exception.Message)"
                [System.Windows.MessageBox]::Show("Invalid Regular Expression: `n$($_.Exception.Message)", "RegEx Syntax Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
                $finalResults = $rawResults
            }
        } else {
            $msg = "Search completed in $($res.ElapsedMilliseconds) ms. Found $($res.Count) object(s)."
            $controls['TxtSearchStatus'].Text = $msg
            Set-Status -Message $msg -Count "$($res.Count) results"
        }

        $state.CurrentSearchResults = $finalResults
        $controls['GridSearchResults'].ItemsSource = $finalResults
    } else {
        $controls['TxtSearchStatus'].Text = "Error: $($res.Error)"
        [System.Windows.MessageBox]::Show("LDAP Search Failed: `n$($res.Error)", "Search Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
    }
}

if ($controls['BtnRunLdapSearch']) { $controls['BtnRunLdapSearch'].Add_Click({ Invoke-LdapSearchUI }) }
if ($controls['TxtRawLdapFilter']) {
    $controls['TxtRawLdapFilter'].Add_KeyDown({
        if ($_.Key -eq [System.Windows.Input.Key]::Enter) { Invoke-LdapSearchUI }
    })
}

if ($controls['TxtRegexPattern']) {
    $controls['TxtRegexPattern'].Add_TextChanged({
        $pat = $controls['TxtRegexPattern'].Text.Trim()
        if ([string]::IsNullOrEmpty($pat)) {
            if ($controls['TxtRegexStatus']) {
                $controls['TxtRegexStatus'].Text = "RegEx: Ready"
                $controls['TxtRegexStatus'].Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#38BDF8")
            }
            if ($controls['BorderRegexStatus']) {
                $controls['BorderRegexStatus'].Background = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#1E293B")
            }
            return
        }

        try {
            [void][System.Text.RegularExpressions.Regex]::new($pat)
            if ($controls['TxtRegexStatus']) {
                $controls['TxtRegexStatus'].Text = "RegEx: Valid"
                $controls['TxtRegexStatus'].Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#4ADE80")
            }
            if ($controls['BorderRegexStatus']) {
                $controls['BorderRegexStatus'].Background = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#064E3B")
            }
        } catch {
            if ($controls['TxtRegexStatus']) {
                $controls['TxtRegexStatus'].Text = "RegEx: Invalid"
                $controls['TxtRegexStatus'].Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#F87171")
            }
            if ($controls['BorderRegexStatus']) {
                $controls['BorderRegexStatus'].Background = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#7F1D1D")
            }
        }
    })

    $controls['TxtRegexPattern'].Add_KeyDown({
        if ($_.Key -eq [System.Windows.Input.Key]::Enter) {
            Invoke-LdapSearchUI
        }
    })
}

if ($controls['ChkUseRegexFilter']) {
    $controls['ChkUseRegexFilter'].Add_Checked({
        if ($controls['TxtRegexPattern'] -and [string]::IsNullOrWhiteSpace($controls['TxtRegexPattern'].Text)) {
            $controls['TxtRegexPattern'].Focus()
        }
    })
}

if ($controls['BtnSearchInspectAttr']) {
    $controls['BtnSearchInspectAttr'].Add_Click({
        $res = if ($controls['GridSearchResults']) { $controls['GridSearchResults'].SelectedItem } else { $null }
        if ($res) {
            $controls['NavAttributeEditor'].IsChecked = $true
            Show-Panel "AttributeEditor"
            $controls['TxtAttrEditorDN'].Text = $res.DistinguishedName
            Load-RawAttributesUI -TargetDN $res.DistinguishedName
        } else {
            [System.Windows.MessageBox]::Show("Please select a search result first.", "Selection Required", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        }
    })
}

if ($controls['BtnSearchExportCsv']) {
    $controls['BtnSearchExportCsv'].Add_Click({
        if (-not $state.CurrentSearchResults -or $state.CurrentSearchResults.Count -eq 0) {
            [System.Windows.MessageBox]::Show("No search results to export.", "Notice", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            return
        }
        $saveDlg = New-Object System.Windows.Forms.SaveFileDialog
        $saveDlg.FileName = "LDAP_Search_$(Get-Date -Format 'yyyyMMdd_HHmm').csv"
        $saveDlg.Filter = "CSV files (*.csv)|*.csv|All files (*.*)|*.*"
        if ($saveDlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $res = Export-ADDataToCsv -Data $state.CurrentSearchResults -FilePath $saveDlg.FileName -Delimiter ($appConfig.Defaults.ExportDelimiter)
            if ($res.Success) {
                [System.Windows.MessageBox]::Show($res.Message, "Export Successful", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            }
        }
    })
}

if ($controls['BtnSearchExportLdif']) {
    $controls['BtnSearchExportLdif'].Add_Click({
        if (-not $state.CurrentSearchResults -or $state.CurrentSearchResults.Count -eq 0) {
            [System.Windows.MessageBox]::Show("No search results to export.", "Notice", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            return
        }
        $saveDlg = New-Object System.Windows.Forms.SaveFileDialog
        $saveDlg.FileName = "LDAP_Search_$(Get-Date -Format 'yyyyMMdd_HHmm').ldif"
        $saveDlg.Filter = "LDIF files (*.ldif)|*.ldif|All files (*.*)|*.*"
        if ($saveDlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $res = Export-ADDataToLdif -Data $state.CurrentSearchResults -FilePath $saveDlg.FileName
            if ($res.Success) {
                [System.Windows.MessageBox]::Show($res.Message, "LDIF Export Successful", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            }
        }
    })
}

if ($controls['BtnSearchExportJson']) {
    $controls['BtnSearchExportJson'].Add_Click({
        if (-not $state.CurrentSearchResults -or $state.CurrentSearchResults.Count -eq 0) {
            [System.Windows.MessageBox]::Show("No search results to export.", "Notice", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            return
        }
        $saveDlg = New-Object System.Windows.Forms.SaveFileDialog
        $saveDlg.FileName = "LDAP_Search_$(Get-Date -Format 'yyyyMMdd_HHmm').json"
        $saveDlg.Filter = "JSON files (*.json)|*.json|All files (*.*)|*.*"
        if ($saveDlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $res = Export-ADDataToJson -Data $state.CurrentSearchResults -FilePath $saveDlg.FileName
            if ($res.Success) {
                [System.Windows.MessageBox]::Show($res.Message, "JSON Export Successful", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            }
        }
    })
}
#endregion

#region 7. LDAP-SQL Console Logic
if ($controls['CmbSqlTemplates']) {
    $controls['CmbSqlTemplates'].Add_SelectionChanged({
        if (-not $controls['CmbSqlTemplates'].SelectedItem) { return }
        $selText = $controls['CmbSqlTemplates'].SelectedItem.Content.ToString()
        $sql = switch ($selText) {
            "Select All Users"           { "SELECT sAMAccountName, displayName, mail, department FROM SUBTREE WHERE objectClass = 'user'" }
            "Select Users with Email"    { "SELECT sAMAccountName, displayName, mail FROM SUBTREE WHERE mail = '*'" }
            "Select Disabled Accounts"   { "SELECT sAMAccountName, displayName, userAccountControl FROM SUBTREE WHERE userAccountControl = '514'" }
            "Select Computers"           { "SELECT name, dNSHostName, operatingSystem FROM SUBTREE WHERE objectClass = 'computer'" }
            "Select Groups"              { "SELECT name, sAMAccountName, groupType FROM SUBTREE WHERE objectClass = 'group'" }
            default                      { "" }
        }
        if ($sql -and $controls['TxtSqlQuery']) {
            $controls['TxtSqlQuery'].Text = $sql
        }
    })
}

if ($controls['BtnClearSql']) {
    $controls['BtnClearSql'].Add_Click({
        if ($controls['TxtSqlQuery']) { $controls['TxtSqlQuery'].Clear() }
    })
}

function Invoke-LdapSqlUI {
    $query = if ($controls['TxtSqlQuery']) { $controls['TxtSqlQuery'].Text.Trim() } else { "" }
    if ([string]::IsNullOrWhiteSpace($query)) {
        $controls['TxtSqlStatus'].Text = "Please enter an LDAP SQL query."
        return
    }

    $controls['TxtSqlStatus'].Text = "Parsing and executing SQL query..."
    $res = Invoke-LdapSqlQuery -Query $query
    if ($res.Success) {
        $state.CurrentSqlResults = $res.Results
        $controls['GridSqlResults'].ItemsSource = $res.Results
        $msg = "SQL query completed in $($res.ElapsedMilliseconds) ms. Returned $($res.Count) record(s)."
        $controls['TxtSqlStatus'].Text = $msg
        Set-Status -Message $msg -Count "$($res.Count) records"
    } else {
        $controls['TxtSqlStatus'].Text = "SQL Error: $($res.Error)"
        [System.Windows.MessageBox]::Show("LDAP SQL Execution Error: `n$($res.Error)", "SQL Query Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
    }
}

if ($controls['BtnExecuteSql']) { $controls['BtnExecuteSql'].Add_Click({ Invoke-LdapSqlUI }) }
if ($controls['TxtSqlQuery']) {
    $controls['TxtSqlQuery'].Add_KeyDown({
        if ($_.Key -eq [System.Windows.Input.Key]::F5) { Invoke-LdapSqlUI }
    })
}

if ($controls['BtnSqlExportCsv']) {
    $controls['BtnSqlExportCsv'].Add_Click({
        if (-not $state.CurrentSqlResults -or $state.CurrentSqlResults.Count -eq 0) {
            [System.Windows.MessageBox]::Show("No SQL results to export.", "Notice", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            return
        }
        $saveDlg = New-Object System.Windows.Forms.SaveFileDialog
        $saveDlg.FileName = "LDAP_SQL_$(Get-Date -Format 'yyyyMMdd_HHmm').csv"
        $saveDlg.Filter = "CSV files (*.csv)|*.csv|All files (*.*)|*.*"
        if ($saveDlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $res = Export-ADDataToCsv -Data $state.CurrentSqlResults -FilePath $saveDlg.FileName -Delimiter ($appConfig.Defaults.ExportDelimiter)
            if ($res.Success) {
                [System.Windows.MessageBox]::Show($res.Message, "Export Successful", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            }
        }
    })
}

if ($controls['BtnSqlExportJson']) {
    $controls['BtnSqlExportJson'].Add_Click({
        if (-not $state.CurrentSqlResults -or $state.CurrentSqlResults.Count -eq 0) { return }
        $saveDlg = New-Object System.Windows.Forms.SaveFileDialog
        $saveDlg.FileName = "LDAP_SQL_$(Get-Date -Format 'yyyyMMdd_HHmm').json"
        $saveDlg.Filter = "JSON files (*.json)|*.json|All files (*.*)|*.*"
        if ($saveDlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $res = Export-ADDataToJson -Data $state.CurrentSqlResults -FilePath $saveDlg.FileName
            if ($res.Success) {
                [System.Windows.MessageBox]::Show($res.Message, "JSON Export Successful", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            }
        }
    })
}

if ($controls['BtnSqlExportLdif']) {
    $controls['BtnSqlExportLdif'].Add_Click({
        if (-not $state.CurrentSqlResults -or $state.CurrentSqlResults.Count -eq 0) { return }
        $saveDlg = New-Object System.Windows.Forms.SaveFileDialog
        $saveDlg.FileName = "LDAP_SQL_$(Get-Date -Format 'yyyyMMdd_HHmm').ldif"
        $saveDlg.Filter = "LDIF files (*.ldif)|*.ldif|All files (*.*)|*.*"
        if ($saveDlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $res = Export-ADDataToLdif -Data $state.CurrentSqlResults -FilePath $saveDlg.FileName
            if ($res.Success) {
                [System.Windows.MessageBox]::Show($res.Message, "LDIF Export Successful", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            }
        }
    })
}
#endregion

#region 8. Raw Attribute Editor Logic
function Load-RawAttributesUI {
    param ([string]$TargetDN = "")
    if (-not $TargetDN -and $controls['TxtAttrEditorDN']) {
        $TargetDN = $controls['TxtAttrEditorDN'].Text.Trim()
    }
    if ([string]::IsNullOrWhiteSpace($TargetDN)) {
        [System.Windows.MessageBox]::Show("Please enter an object Distinguished Name (DN) or SamAccountName.", "Input Required", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        return
    }

    Set-Status -Message "Fetching raw directory attributes for: $TargetDN..."
    $attrs = Get-ADObjectRawAttributes -DistinguishedName $TargetDN
    if ($attrs -and $attrs.Count -gt 0) {
        $state.CurrentRawAttributes = $attrs
        $state.CurrentRawDN = $attrs[0].RawDN
        if ($controls['TxtAttrEditorDN']) { $controls['TxtAttrEditorDN'].Text = $state.CurrentRawDN }
        if ($controls['GridRawAttributes']) { $controls['GridRawAttributes'].ItemsSource = $attrs }
        if ($controls['TxtAttrCount']) { $controls['TxtAttrCount'].Text = "$($attrs.Count) attributes loaded" }
        Set-Status -Message "Loaded $($attrs.Count) attributes for '$($attrs[0].RawDN)'." -Count "$($attrs.Count) attributes"
    } else {
        [System.Windows.MessageBox]::Show("No attributes found or object could not be resolved: $TargetDN", "Object Not Found", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
    }
}

if ($controls['BtnLoadRawAttributes']) { $controls['BtnLoadRawAttributes'].Add_Click({ Load-RawAttributesUI }) }
if ($controls['TxtAttrEditorDN']) {
    $controls['TxtAttrEditorDN'].Add_KeyDown({
        if ($_.Key -eq [System.Windows.Input.Key]::Enter) { Load-RawAttributesUI }
    })
}

if ($controls['TxtSearchAttributes']) {
    $controls['TxtSearchAttributes'].Add_TextChanged({
        $filter = $controls['TxtSearchAttributes'].Text.Trim()
        if ([string]::IsNullOrWhiteSpace($filter)) {
            $controls['GridRawAttributes'].ItemsSource = $state.CurrentRawAttributes
        } else {
            $filtered = $state.CurrentRawAttributes | Where-Object {
                $_.Name -match [regex]::Escape($filter) -or [string]$_.Value -match [regex]::Escape($filter)
            }
            $controls['GridRawAttributes'].ItemsSource = @($filtered)
        }
    })
}

function Open-AttributeEditDialog {
    $selAttr = if ($controls['GridRawAttributes']) { $controls['GridRawAttributes'].SelectedItem } else { $null }
    if (-not $selAttr) {
        [System.Windows.MessageBox]::Show("Please select an attribute to edit.", "Selection Required", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        return
    }

    $dlgPath = Join-Path $viewsPath "AttributeEditDialog.xaml"
    $dlg = Load-XamlWindow -XamlPath $dlgPath
    $dlg.Owner = $window

    $dControls = @{}
    $dReader = [System.Xml.XmlReader]::Create([System.IO.StringReader](Get-Content $dlgPath -Raw))
    while ($dReader.Read()) {
        if ($dReader.NodeType -eq [System.Xml.XmlNodeType]::Element) {
            $dName = $dReader.GetAttribute("Name")
            if ($dName) { $dControls[$dName] = $dlg.FindName($dName) }
        }
    }
    $dReader.Close()

    $dControls['TxtHeaderAttrName'].Text = $selAttr.Name
    $dControls['TxtHeaderType'].Text = "Syntax: $($selAttr.Type) | Count: $($selAttr.Count)"
    $dControls['TxtHeaderDN'].Text = $selAttr.RawDN

    $isUac = ($selAttr.Name -ieq "userAccountControl")
    $isMulti = ($selAttr.IsMultiValued -or $selAttr.Count -gt 1 -or $selAttr.Type -match "MultiValued")

    if ($isUac) {
        $dControls['ModeStringEditor'].Visibility = [System.Windows.Visibility]::Collapsed
        $dControls['ModeMultiValueEditor'].Visibility = [System.Windows.Visibility]::Collapsed
        $dControls['ModeUacEditor'].Visibility = [System.Windows.Visibility]::Visible

        $intVal = 512
        [void][int]::TryParse($selAttr.Value, [ref]$intVal)
        $parsedFlags = ConvertFrom-UACFlags -UACValue $intVal

        $flagItems = New-Object System.Collections.ObjectModel.ObservableCollection[System.Object]
        foreach ($f in $parsedFlags.AllFlags) {
            $flagItems.Add([PSCustomObject]@{
                FlagName  = $f.Name
                HexValue  = $f.Hex
                IsChecked = $f.Enabled
                Value     = $f.Value
            })
        }
        $dControls['ItemsUacFlags'].ItemsSource = $flagItems
        $dControls['TxtUacComputed'].Text = "Current Value: $intVal (0x{0:X4})" -f $intVal

        $ComputeUac = {
            $sum = 0
            foreach ($item in $flagItems) {
                if ($item.IsChecked) {
                    $sum = $sum -bor $item.Value
                }
            }
            $dControls['TxtUacComputed'].Text = "Computed Value: $sum (0x{0:X4})" -f $sum
            return $sum
        }

        $dControls['BtnPresetNormalUser'].Add_Click({
            foreach ($item in $flagItems) {
                $item.IsChecked = ($item.FlagName -eq "NORMAL_ACCOUNT")
            }
            $dControls['ItemsUacFlags'].ItemsSource = $null
            $dControls['ItemsUacFlags'].ItemsSource = $flagItems
            & $ComputeUac
        })

        $dControls['BtnPresetDisabledUser'].Add_Click({
            foreach ($item in $flagItems) {
                $item.IsChecked = ($item.FlagName -eq "NORMAL_ACCOUNT" -or $item.FlagName -eq "ACCOUNTDISABLE")
            }
            $dControls['ItemsUacFlags'].ItemsSource = $null
            $dControls['ItemsUacFlags'].ItemsSource = $flagItems
            & $ComputeUac
        })

        $dControls['BtnPresetPwdNeverExpire'].Add_Click({
            foreach ($item in $flagItems) {
                if ($item.FlagName -eq "DONT_EXPIRE_PASSWORD") {
                    $item.IsChecked = -not $item.IsChecked
                }
            }
            $dControls['ItemsUacFlags'].ItemsSource = $null
            $dControls['ItemsUacFlags'].ItemsSource = $flagItems
            & $ComputeUac
        })

    } elseif ($isMulti) {
        $dControls['ModeStringEditor'].Visibility = [System.Windows.Visibility]::Collapsed
        $dControls['ModeMultiValueEditor'].Visibility = [System.Windows.Visibility]::Visible
        $dControls['ModeUacEditor'].Visibility = [System.Windows.Visibility]::Collapsed

        $multiItems = New-Object System.Collections.ObjectModel.ObservableCollection[System.String]
        if ($selAttr.RawValues -is [System.Collections.IEnumerable] -and $selAttr.RawValues -isnot [string]) {
            foreach ($v in $selAttr.RawValues) {
                [void]$multiItems.Add([string]$v)
            }
        } elseif (-not [string]::IsNullOrWhiteSpace($selAttr.Value)) {
            $splitVals = $selAttr.Value -split " ;\s*"
            foreach ($v in $splitVals) {
                if (-not [string]::IsNullOrWhiteSpace($v)) { [void]$multiItems.Add($v.Trim()) }
            }
        }
        $dControls['ListMultiValues'].ItemsSource = $multiItems
        $dControls['TxtMultiCount'].Text = "$($multiItems.Count) values"

        $dControls['BtnAddMultiValue'].Add_Click({
            $newV = $dControls['TxtNewMultiValue'].Text.Trim()
            if (-not [string]::IsNullOrWhiteSpace($newV)) {
                $multiItems.Add($newV)
                $dControls['TxtNewMultiValue'].Clear()
                $dControls['TxtMultiCount'].Text = "$($multiItems.Count) values"
            }
        })

        $dControls['BtnRemoveMultiValue'].Add_Click({
            $selectedItem = $dControls['ListMultiValues'].SelectedItem
            if ($selectedItem) {
                [void]$multiItems.Remove($selectedItem)
                $dControls['TxtMultiCount'].Text = "$($multiItems.Count) values"
            }
        })

    } else {
        $dControls['ModeStringEditor'].Visibility = [System.Windows.Visibility]::Visible
        $dControls['ModeMultiValueEditor'].Visibility = [System.Windows.Visibility]::Collapsed
        $dControls['ModeUacEditor'].Visibility = [System.Windows.Visibility]::Collapsed

        $dControls['TxtStringValue'].Text = [string]$selAttr.Value

        $dControls['BtnClearValue'].Add_Click({
            $dControls['TxtStringValue'].Text = ""
        })

        if ($dControls['BtnSetNever']) {
            if ($selAttr.Name -in @('accountExpires', 'pwdLastSet', 'lockoutTime')) {
                $dControls['BtnSetNever'].Visibility = [System.Windows.Visibility]::Visible
                $dControls['BtnSetNever'].Add_Click({
                    $dControls['TxtStringValue'].Text = "0"
                })
            } else {
                $dControls['BtnSetNever'].Visibility = [System.Windows.Visibility]::Collapsed
            }
        }
    }

    $dControls['BtnCancel'].Add_Click({ $dlg.Close() })

    $dControls['BtnSaveAttribute'].Add_Click({
        try {
            if ($isUac) {
                $newUac = & $ComputeUac
                $setRes = Set-ADObjectRawAttribute -DistinguishedName $selAttr.RawDN -AttributeName "userAccountControl" -NewValue $newUac
            } elseif ($isMulti) {
                $newVals = @($multiItems)
                $setRes = Set-ADObjectRawAttribute -DistinguishedName $selAttr.RawDN -AttributeName $selAttr.Name -NewValue $newVals
            } else {
                $newStr = $dControls['TxtStringValue'].Text
                $setRes = Set-ADObjectRawAttribute -DistinguishedName $selAttr.RawDN -AttributeName $selAttr.Name -NewValue $newStr
            }

            if ($setRes.Success) {
                [System.Windows.MessageBox]::Show($setRes.Message, "Attribute Saved", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
                $dlg.Close()
                Load-RawAttributesUI -TargetDN $selAttr.RawDN
            } else {
                $dControls['TxtEditorStatus'].Text = $setRes.Error
                $dControls['TxtEditorStatus'].Foreground = [System.Windows.Media.Brushes]::Red
            }
        }
        catch {
            $dControls['TxtEditorStatus'].Text = $_.Exception.Message
            $dControls['TxtEditorStatus'].Foreground = [System.Windows.Media.Brushes]::Red
        }
    })

    [void]$dlg.ShowDialog()
}

if ($controls['BtnEditAttrValue']) { $controls['BtnEditAttrValue'].Add_Click({ Open-AttributeEditDialog }) }
if ($controls['GridRawAttributes']) {
    $controls['GridRawAttributes'].Add_MouseDoubleClick({ Open-AttributeEditDialog })
}

if ($controls['BtnClearAttrValue']) {
    $controls['BtnClearAttrValue'].Add_Click({
        $selAttr = if ($controls['GridRawAttributes']) { $controls['GridRawAttributes'].SelectedItem } else { $null }
        if (-not $selAttr) { return }

        $confirm = [System.Windows.MessageBox]::Show(
            "Are you sure you want to clear attribute '$($selAttr.Name)' on object '$($selAttr.RawDN)'?",
            "Confirm Clear Attribute",
            [System.Windows.MessageBoxButton]::YesNo,
            [System.Windows.MessageBoxImage]::Warning
        )

        if ($confirm -eq [System.Windows.MessageBoxResult]::Yes) {
            $res = Clear-ADObjectRawAttribute -DistinguishedName $selAttr.RawDN -AttributeName $selAttr.Name
            if ($res.Success) {
                Load-RawAttributesUI -TargetDN $selAttr.RawDN
            } else {
                [System.Windows.MessageBox]::Show($res.Error, "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
            }
        }
    })
}

if ($controls['BtnCopyAttrValue']) {
    $controls['BtnCopyAttrValue'].Add_Click({
        $selAttr = if ($controls['GridRawAttributes']) { $controls['GridRawAttributes'].SelectedItem } else { $null }
        if ($selAttr -and $selAttr.Value) {
            [System.Windows.Clipboard]::SetText([string]$selAttr.Value)
            Set-Status -Message "Copied '$($selAttr.Name)' value to clipboard."
        }
    })
}

if ($controls['BtnExportObjectLdif']) {
    $controls['BtnExportObjectLdif'].Add_Click({
        if (-not $state.CurrentRawAttributes -or $state.CurrentRawAttributes.Count -eq 0) { return }
        $saveDlg = New-Object System.Windows.Forms.SaveFileDialog
        $saveDlg.FileName = "AD_Object_$(Get-Date -Format 'yyyyMMdd_HHmm').ldif"
        $saveDlg.Filter = "LDIF files (*.ldif)|*.ldif|All files (*.*)|*.*"
        if ($saveDlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $dn = $state.CurrentRawDN
            $ldifText = "dn: $dn`r`nchangetype: add`r`n"
            foreach ($attr in $state.CurrentRawAttributes) {
                if (-not $attr.IsOperational -and $attr.Value) {
                    $ldifText += "$($attr.Name): $($attr.Value)`r`n"
                }
            }
            [System.IO.File]::WriteAllText($saveDlg.FileName, $ldifText, [System.Text.Encoding]::UTF8)
            [System.Windows.MessageBox]::Show("Object LDIF exported to $($saveDlg.FileName).", "Export Successful", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        }
    })
}
#endregion

#region 9. Object Compare & Diff Logic
function Run-ObjectCompareUI {
    $objA = if ($controls['TxtCompareObjectA']) { $controls['TxtCompareObjectA'].Text.Trim() } else { "" }
    $objB = if ($controls['TxtCompareObjectB']) { $controls['TxtCompareObjectB'].Text.Trim() } else { "" }

    if ([string]::IsNullOrWhiteSpace($objA) -or [string]::IsNullOrWhiteSpace($objB)) {
        [System.Windows.MessageBox]::Show("Please enter both Object A and Object B Distinguished Names or SamAccountNames to compare.", "Input Required", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        return
    }

    Set-Status -Message "Comparing directory objects: '$objA' vs '$objB'..."
    $cmp = Compare-ADObjects -ObjectA $objA -ObjectB $objB
    $state.CurrentCompare = $cmp

    if ($cmp.Success) {
        $summary = "$($cmp.DifferencesCount) differences detected out of $($cmp.TotalAttributesCompared) total attributes compared."
        if ($controls['TxtCompareSummary']) {
            $controls['TxtCompareSummary'].Text = $summary
            $controls['TxtCompareSummary'].Foreground = if ($cmp.DifferencesCount -gt 0) { [System.Windows.Media.Brushes]::Orange } else { [System.Windows.Media.Brushes]::LimeGreen }
        }

        Update-CompareGridDisplay
        Set-Status -Message "Comparison complete: $summary" -Count "$($cmp.DifferencesCount) diffs"
    } else {
        [System.Windows.MessageBox]::Show("Object Comparison Failed: `n$($cmp.Error)", "Compare Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
    }
}

function Update-CompareGridDisplay {
    if (-not $state.CurrentCompare -or -not $state.CurrentCompare.Comparisons) { return }
    $diffOnly = if ($controls['ChkCompareDiffsOnly']) { [bool]$controls['ChkCompareDiffsOnly'].IsChecked } else { $false }
    $items = if ($diffOnly) {
        $state.CurrentCompare.Comparisons | Where-Object { $_.IsDifferent }
    } else {
        $state.CurrentCompare.Comparisons
    }
    if ($controls['GridCompareResults']) {
        $controls['GridCompareResults'].ItemsSource = @($items)
    }
}

if ($controls['BtnExecuteCompare']) { $controls['BtnExecuteCompare'].Add_Click({ Run-ObjectCompareUI }) }
if ($controls['ChkCompareDiffsOnly']) {
    $controls['ChkCompareDiffsOnly'].Add_Checked({ Update-CompareGridDisplay })
    $controls['ChkCompareDiffsOnly'].Add_Unchecked({ Update-CompareGridDisplay })
}

if ($controls['BtnCompareExportCsv']) {
    $controls['BtnCompareExportCsv'].Add_Click({
        if (-not $state.CurrentCompare -or -not $state.CurrentCompare.Comparisons) { return }
        $saveDlg = New-Object System.Windows.Forms.SaveFileDialog
        $saveDlg.FileName = "AD_ObjectDiff_$(Get-Date -Format 'yyyyMMdd_HHmm').csv"
        $saveDlg.Filter = "CSV files (*.csv)|*.csv|All files (*.*)|*.*"
        if ($saveDlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $res = Export-ADDataToCsv -Data $state.CurrentCompare.Comparisons -FilePath $saveDlg.FileName -Delimiter ($appConfig.Defaults.ExportDelimiter)
            if ($res.Success) {
                [System.Windows.MessageBox]::Show($res.Message, "Diff Export Successful", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            }
        }
    })
}
#endregion

#region 10. RFC 2849 LDIF Studio Logic
function Init-LdifStudio {
    if ($controls['TxtLdifEditor'] -and [string]::IsNullOrWhiteSpace($controls['TxtLdifEditor'].Text)) {
        $domainNC = if ($adContext.DefaultNamingContext) { $adContext.DefaultNamingContext } else { "DC=corp,DC=example,DC=com" }
        $controls['TxtLdifEditor'].Text = @"
dn: CN=Test User,CN=Users,$domainNC
changetype: modify
replace: department
department: Information Technology
-
replace: title
title: Senior Systems Administrator
-
"@
    }
}

if ($controls['CmbLdifTemplates']) {
    $controls['CmbLdifTemplates'].Add_SelectionChanged({
        if (-not $controls['CmbLdifTemplates'].SelectedItem) { return }
        $selText = $controls['CmbLdifTemplates'].SelectedItem.Content.ToString()
        $domainNC = if ($adContext.DefaultNamingContext) { $adContext.DefaultNamingContext } else { "DC=corp,DC=example,DC=com" }
        $ldif = switch ($selText) {
            "Template: Modify Attribute" {
@"
dn: CN=Test User,CN=Users,$domainNC
changetype: modify
replace: department
department: Information Technology
-
replace: title
title: Senior Systems Administrator
-
"@
            }
            "Template: Add New User" {
@"
dn: CN=Jane Doe,OU=Standard Users,$domainNC
changetype: add
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Jane Doe
givenName: Jane
sn: Doe
displayName: Jane Doe
sAMAccountName: jane.doe
userPrincipalName: jane.doe@$($adContext.DomainName)
mail: jane.doe@$($adContext.DomainName)
userAccountControl: 512
"@
            }
            "Template: Delete Object" {
@"
dn: CN=Temp Account,OU=Staging,$domainNC
changetype: delete
"@
            }
            default { "" }
        }
        if ($ldif -and $controls['TxtLdifEditor']) {
            $controls['TxtLdifEditor'].Text = $ldif
        }
    })
}

function Validate-LdifUI {
    $content = if ($controls['TxtLdifEditor']) { $controls['TxtLdifEditor'].Text } else { "" }
    if ([string]::IsNullOrWhiteSpace($content)) {
        [System.Windows.MessageBox]::Show("Please enter LDIF content to validate.", "Empty LDIF", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        return
    }

    $syntax = Test-LdifSyntax -LdifContent $content
    $dryRun = Invoke-LdifImport -LdifContent $content -DryRun

    $log = @"
[$(Get-Date -Format 'HH:mm:ss')] LDIF SYNTAX & DRY-RUN VALIDATION REPORT
======================================================================
Syntax Valid: $($syntax.IsValid)
Total Records Detected: $($syntax.EntryCount)
$(if ($syntax.Errors.Count -gt 0) { "Syntax Errors:`n" + ($syntax.Errors -join "`n") } else { "No syntax errors found." })

DRY-RUN SIMULATION RESULTS:
Processed Entries: $($dryRun.TotalProcessed)
Successful Simulation: $($dryRun.SuccessCount)
Simulation Failures: $($dryRun.FailureCount)

LOG DETAILS:
$($dryRun.Log -join "`r`n")
"@
    if ($controls['TxtLdifLog']) { $controls['TxtLdifLog'].Text = $log }
}

function Execute-LdifUI {
    $content = if ($controls['TxtLdifEditor']) { $controls['TxtLdifEditor'].Text } else { "" }
    if ([string]::IsNullOrWhiteSpace($content)) {
        [System.Windows.MessageBox]::Show("Please enter LDIF content to execute.", "Empty LDIF", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        return
    }

    $confirm = [System.Windows.MessageBox]::Show(
        "WARNING: You are about to execute live LDIF modifications directly against Active Directory.`n`nAre you sure you want to proceed?",
        "Confirm Live LDIF Execution",
        [System.Windows.MessageBoxButton]::YesNo,
        [System.Windows.MessageBoxImage]::Warning
    )

    if ($confirm -eq [System.Windows.MessageBoxResult]::Yes) {
        $res = Invoke-LdifImport -LdifContent $content -DryRun:$false
        $log = @"
[$(Get-Date -Format 'HH:mm:ss')] LIVE LDIF EXECUTION REPORT
======================================================================
Overall Success: $($res.Success)
Entries Processed: $($res.TotalProcessed)
Successful Operations: $($res.SuccessCount)
Failed Operations: $($res.FailureCount)

EXECUTION LOG:
$($res.Log -join "`r`n")
"@
        if ($controls['TxtLdifLog']) { $controls['TxtLdifLog'].Text = $log }
        Set-Status -Message "LDIF execution finished: $($res.SuccessCount) succeeded, $($res.FailureCount) failed."
    }
}

if ($controls['BtnLdifValidate']) { $controls['BtnLdifValidate'].Add_Click({ Validate-LdifUI }) }
if ($controls['BtnLdifExecute'])  { $controls['BtnLdifExecute'].Add_Click({ Execute-LdifUI }) }

if ($controls['BtnLdifExport']) {
    $controls['BtnLdifExport'].Add_Click({
        $content = if ($controls['TxtLdifEditor']) { $controls['TxtLdifEditor'].Text } else { "" }
        if ([string]::IsNullOrWhiteSpace($content)) { return }
        $saveDlg = New-Object System.Windows.Forms.SaveFileDialog
        $saveDlg.FileName = "Script_$(Get-Date -Format 'yyyyMMdd_HHmm').ldif"
        $saveDlg.Filter = "LDIF files (*.ldif)|*.ldif|All files (*.*)|*.*"
        if ($saveDlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            [System.IO.File]::WriteAllText($saveDlg.FileName, $content, [System.Text.Encoding]::UTF8)
            [System.Windows.MessageBox]::Show("Saved LDIF script to $($saveDlg.FileName).", "File Saved", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        }
    })
}
#endregion

#region 11. Security & Audit Reports Logic
function Run-AuditReportsUI {
    $catItem = if ($controls['CmbAuditCategory'].SelectedItem) { $controls['CmbAuditCategory'].SelectedItem.Content.ToString() } else { "Inactive Users" }
    $daysItem = if ($controls['CmbAuditDays'].SelectedItem) { [int]$controls['CmbAuditDays'].SelectedItem.Content.ToString() } else { 90 }

    $auditType = switch -Wildcard ($catItem) {
        "*Inactive Users*"          { "InactiveUsers" }
        "*Passwords Never Expire*"  { "PasswordsNeverExpire" }
        "*Locked Out*"              { "LockedOutUsers" }
        "*Privileged*"              { "PrivilegedAccounts" }
        "*Empty Groups*"            { "EmptyGroups" }
        "*Unprotected OUs*"         { "UnprotectedOUs" }
        "*Service Accounts*"        { "ServiceAccounts" }
        "*Inactive Computers*"      { "InactiveComputers" }
        default                     { "InactiveUsers" }
    }

    Set-Status -Message "Running security audit: $catItem ($daysItem days threshold)..."
    $report = Get-ADSecurityAuditReport -AuditType $auditType -InactiveDays $daysItem
    $state.CurrentAuditReport = $report

    if ($controls['TxtAuditSummary']) { $controls['TxtAuditSummary'].Text = "$($report.Title) - $($report.Description)" }
    if ($controls['TxtAuditCount']) { $controls['TxtAuditCount'].Text = "$($report.Count) Findings" }
    if ($controls['GridAuditResults']) { $controls['GridAuditResults'].ItemsSource = $report.Findings }

    Set-Status -Message "Security audit finished. Found $($report.Count) item(s)." -Count "$($report.Count) findings"
}

if ($controls['BtnRunAudit']) { $controls['BtnRunAudit'].Add_Click({ Run-AuditReportsUI }) }

if ($controls['BtnExportAuditHtml']) {
    $controls['BtnExportAuditHtml'].Add_Click({
        if (-not $state.CurrentAuditReport -or -not $state.CurrentAuditReport.Findings) {
            [System.Windows.MessageBox]::Show("Please run an audit report first before exporting.", "No Report", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            return
        }

        $saveDlg = New-Object System.Windows.Forms.SaveFileDialog
        $dateStr = (Get-Date).ToString("yyyyMMdd_HHmm")
        $saveDlg.FileName = "AD_SecurityAudit_$($state.CurrentAuditReport.AuditType)_$dateStr.html"
        $saveDlg.Filter = "HTML Report (*.html)|*.html|All files (*.*)|*.*"

        if ($saveDlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $expRes = Export-ADSecurityAuditToHtml -AuditReport $state.CurrentAuditReport -FilePath $saveDlg.FileName
            if ($expRes.Success) {
                $open = [System.Windows.MessageBox]::Show("Audit report successfully saved to:`n$($saveDlg.FileName)`n`nWould you like to open it now in your browser?", "Export Successful", [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Information)
                if ($open -eq [System.Windows.MessageBoxResult]::Yes) {
                    Start-Process $saveDlg.FileName
                }
            } else {
                [System.Windows.MessageBox]::Show("Export failed: $($expRes.Error)", "Export Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
            }
        }
    })
}

if ($controls['BtnExportAuditCsv']) {
    $controls['BtnExportAuditCsv'].Add_Click({
        if (-not $state.CurrentAuditReport -or -not $state.CurrentAuditReport.Findings) { return }
        $saveDlg = New-Object System.Windows.Forms.SaveFileDialog
        $saveDlg.FileName = "AD_SecurityAudit_$($state.CurrentAuditReport.AuditType)_$(Get-Date -Format 'yyyyMMdd_HHmm').csv"
        $saveDlg.Filter = "CSV files (*.csv)|*.csv|All files (*.*)|*.*"
        if ($saveDlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $res = Export-ADDataToCsv -Data $state.CurrentAuditReport.Findings -FilePath $saveDlg.FileName -Delimiter ($appConfig.Defaults.ExportDelimiter)
            if ($res.Success) {
                [System.Windows.MessageBox]::Show($res.Message, "CSV Export Successful", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            }
        }
    })
}
#endregion

#region 12. Schema Browser Logic
function Refresh-Schema {
    $isClasses = if ($controls['RadioSchemaClasses']) { [bool]$controls['RadioSchemaClasses'].IsChecked } else { $true }
    $filterText = if ($controls['TxtSearchSchema']) { $controls['TxtSearchSchema'].Text.Trim() } else { "" }

    Set-Status -Message "Reading Active Directory Schema definitions..."
    if ($isClasses) {
        $items = Get-ADSchemaClasses -FilterText $filterText
    } else {
        $items = Get-ADSchemaAttributes -FilterText $filterText
    }

    $state.CachedSchema = $items
    if ($controls['GridSchema']) { $controls['GridSchema'].ItemsSource = $items }
    Set-Status -Message "Schema loaded: $($items.Count) definition(s) displayed." -Count "$($items.Count) schema items"
}

if ($controls['BtnRefreshSchema']) { $controls['BtnRefreshSchema'].Add_Click({ Refresh-Schema }) }
if ($controls['RadioSchemaClasses'])    { $controls['RadioSchemaClasses'].Add_Checked({ Refresh-Schema }) }
if ($controls['RadioSchemaAttributes']) { $controls['RadioSchemaAttributes'].Add_Checked({ Refresh-Schema }) }
if ($controls['TxtSearchSchema']) {
    $controls['TxtSearchSchema'].Add_KeyDown({
        if ($_.Key -eq [System.Windows.Input.Key]::Enter) { Refresh-Schema }
    })
}
#endregion

#region 13. Bulk Operations Engine Logic
if ($controls['BtnExecuteBulk']) {
    $controls['BtnExecuteBulk'].Add_Click({
        $op = if ($controls['CmbBulkOperation'].SelectedItem) { $controls['CmbBulkOperation'].SelectedItem.Content.ToString() } else { "Set Attribute" }
        $attrName = if ($controls['TxtBulkAttrName']) { $controls['TxtBulkAttrName'].Text.Trim() } else { "" }
        $newVal = if ($controls['TxtBulkNewValue']) { $controls['TxtBulkNewValue'].Text.Trim() } else { "" }

        $targetObjects = @()
        if ($state.CurrentSearchResults -and $state.CurrentSearchResults.Count -gt 0) {
            $targetObjects = $state.CurrentSearchResults
        } elseif ($state.CachedUsers -and $state.CachedUsers.Count -gt 0) {
            $targetObjects = $state.CachedUsers
        }

        if ($targetObjects.Count -eq 0) {
            [System.Windows.MessageBox]::Show("No target objects loaded. Please run a search or load users first.", "No Target Objects", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            return
        }

        $confirm = [System.Windows.MessageBox]::Show(
            "Are you sure you want to perform bulk operation '$op' on $($targetObjects.Count) object(s)?`n`nOperation: $op`nAttribute: $attrName`nValue: $newVal",
            "Confirm Bulk Operation",
            [System.Windows.MessageBoxButton]::YesNo,
            [System.Windows.MessageBoxImage]::Warning
        )

        if ($confirm -eq [System.Windows.MessageBoxResult]::Yes) {
            Set-Status -Message "Executing bulk operation '$op' on $($targetObjects.Count) objects..."
            $bulkRes = Invoke-ADBulkUpdate -Objects $targetObjects -Operation $op -AttributeName $attrName -NewValue $newVal

            $log = @"
[$(Get-Date -Format 'HH:mm:ss')] BULK OPERATION REPORT
======================================================================
Operation: $op
Total Objects: $($bulkRes.Total)
Succeeded: $($bulkRes.SuccessCount)
Failed: $($bulkRes.FailureCount)

LOG DETAILS:
$($bulkRes.Log -join "`r`n")
"@
            if ($controls['TxtBulkLog']) { $controls['TxtBulkLog'].Text = $log }
            Set-Status -Message "Bulk operation completed: $($bulkRes.SuccessCount) succeeded, $($bulkRes.FailureCount) failed." -Count "$($bulkRes.SuccessCount)/$($bulkRes.Total)"
        }
    })
}
#endregion

#region 14. Connection Profiles & Diagnostics Logic
function Open-ConnectionDialog {
    $dlgPath = Join-Path $viewsPath "ConnectionDialog.xaml"
    $dlg = Load-XamlWindow -XamlPath $dlgPath
    $dlg.Owner = $window

    $dControls = @{}
    $dReader = [System.Xml.XmlReader]::Create([System.IO.StringReader](Get-Content $dlgPath -Raw))
    while ($dReader.Read()) {
        if ($dReader.NodeType -eq [System.Xml.XmlNodeType]::Element) {
            $dName = $dReader.GetAttribute("Name")
            if ($dName) { $dControls[$dName] = $dlg.FindName($dName) }
        }
    }
    $dReader.Close()

    $dControls['TxtServerHost'].Text = if ($adContext.PDCEmulator) { $adContext.PDCEmulator } else { $adContext.DomainName }
    $dControls['TxtSearchBase'].Text = $adContext.DefaultNamingContext

    $dControls['ChkCurrentCredentials'].Add_Checked({
        $dControls['PanelCustomCredentials'].Visibility = [System.Windows.Visibility]::Collapsed
    })
    $dControls['ChkCurrentCredentials'].Add_Unchecked({
        $dControls['PanelCustomCredentials'].Visibility = [System.Windows.Visibility]::Visible
    })

    $dControls['BtnTestConnection'].Add_Click({
        $hostName = $dControls['TxtServerHost'].Text.Trim()
        $portNum = 389
        [void][int]::TryParse($dControls['TxtPort'].Text.Trim(), [ref]$portNum)
        $dControls['TxtDiagStatus'].Text = "Testing connection to ${hostName}:$portNum..."
        $dControls['TxtDiagStatus'].Foreground = [System.Windows.Media.Brushes]::Yellow

        $diag = Test-ADConnectionDiagnostic -Server $hostName -Port $portNum
        if ($diag.Success) {
            $dControls['TxtDiagStatus'].Text = "Connected Successfully ($($diag.LatencyMs) ms)"
            $dControls['TxtDiagStatus'].Foreground = [System.Windows.Media.Brushes]::LimeGreen
            $dControls['TxtDiagDetails'].Text = "IP: $($diag.IPAddress) | DefaultNC: $($diag.DefaultNamingContext)"
        } else {
            $dControls['TxtDiagStatus'].Text = "Connection Failed"
            $dControls['TxtDiagStatus'].Foreground = [System.Windows.Media.Brushes]::Red
            $dControls['TxtDiagDetails'].Text = $diag.ErrorMessage
        }
    })

    $dControls['BtnCancel'].Add_Click({ $dlg.Close() })

    $dControls['BtnSaveProfile'].Add_Click({
        $pName = $dControls['TxtProfileName'].Text.Trim()
        if ([string]::IsNullOrWhiteSpace($pName)) { $pName = "Profile $(([DateTime]::Now).ToString('HHmm'))" }
        $hostName = $dControls['TxtServerHost'].Text.Trim()
        $portNum = 389
        [void][int]::TryParse($dControls['TxtPort'].Text.Trim(), [ref]$portNum)
        $useSsl = [bool]$dControls['ChkUseSSL'].IsChecked
        $searchBase = $dControls['TxtSearchBase'].Text.Trim()

        $newProf = @{
            Name = $pName
            Server = $hostName
            Port = $portNum
            UseSSL = $useSsl
            SearchBase = $searchBase
        }

        if (-not $appConfig.Profiles) {
            $appConfig | Add-Member -MemberType NoteProperty -Name "Profiles" -Value @() -Force
        }
        $existingProfiles = @($appConfig.Profiles) + @($newProf)
        $appConfig.Profiles = $existingProfiles
        Save-AppSettings -Config $appConfig

        [System.Windows.MessageBox]::Show("Connection profile '$pName' saved successfully.", "Profile Saved", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        $dlg.Close()
        Refresh-Connections
    })

    [void]$dlg.ShowDialog()
}

function Refresh-Connections {
    if ($controls['ListProfiles']) {
        $controls['ListProfiles'].Items.Clear()
        $profiles = @($appConfig.Profiles)
        if ($profiles.Count -eq 0) {
            $defaultServer = if ($adContext.PDCEmulator) { $adContext.PDCEmulator } else { $adContext.DomainName }
            $controls['ListProfiles'].Items.Add("Default: Production Domain [$($defaultServer):389]")
        } else {
            foreach ($p in $profiles) {
                [void]$controls['ListProfiles'].Items.Add("$($p.Name) [$($p.Server):$($p.Port)]")
            }
        }
    }

    if ($controls['CmbActiveProfile']) {
        $controls['CmbActiveProfile'].Items.Clear()
        $defaultServer = if ($adContext.PDCEmulator) { $adContext.PDCEmulator } else { $adContext.DomainName }
        [void]$controls['CmbActiveProfile'].Items.Add("Default ($defaultServer)")
        if ($appConfig.Profiles) {
            foreach ($p in $appConfig.Profiles) {
                [void]$controls['CmbActiveProfile'].Items.Add("$($p.Name)")
            }
        }
        $controls['CmbActiveProfile'].SelectedIndex = 0
    }
}

function Run-ConnectionDiagnostics {
    Set-Status -Message "Running full Active Directory connection diagnostics..."
    $server = if ($adContext.PDCEmulator) { $adContext.PDCEmulator } else { $adContext.DomainName }
    $diag = Test-ADConnectionDiagnostic -Server $server -Port 389

    if ($controls['TxtDiagServer']) { $controls['TxtDiagServer'].Text = $server }
    if ($controls['TxtDiagIp']) { $controls['TxtDiagIp'].Text = if ($diag.IPAddress) { $diag.IPAddress } else { "--" } }
    if ($controls['TxtDiagPortStatus']) {
        $controls['TxtDiagPortStatus'].Text = if ($diag.PortOpen) { "OPEN (Port 389 Active)" } else { "CLOSED / FILTERED" }
        $controls['TxtDiagPortStatus'].Foreground = if ($diag.PortOpen) { [System.Windows.Media.Brushes]::LimeGreen } else { [System.Windows.Media.Brushes]::Red }
    }
    if ($controls['TxtDiagLatency']) {
        $controls['TxtDiagLatency'].Text = "$($diag.LatencyMs) ms"
        if ($controls['TxtLatencyBadge']) { $controls['TxtLatencyBadge'].Text = "$($diag.LatencyMs) ms" }
    }
    if ($controls['TxtDiagDefaultNC']) { $controls['TxtDiagDefaultNC'].Text = if ($diag.DefaultNamingContext) { $diag.DefaultNamingContext } else { "--" } }
    if ($controls['TxtDiagMessage']) {
        $controls['TxtDiagMessage'].Text = if ($diag.Success) {
            "Diagnostic passed at $(Get-Date -Format 'HH:mm:ss'). RootDSE naming context verified."
        } else {
            "Diagnostic failed: $($diag.ErrorMessage)"
        }
    }
    Set-Status -Message "Diagnostic check complete." -Count "$($diag.LatencyMs) ms latency"
}

if ($controls['BtnNewProfile'])    { $controls['BtnNewProfile'].Add_Click({ Open-ConnectionDialog }) }
if ($controls['BtnRunDiagFull'])   { $controls['BtnRunDiagFull'].Add_Click({ Run-ConnectionDiagnostics }) }
if ($controls['BtnDeleteProfile']) {
    $controls['BtnDeleteProfile'].Add_Click({
        $selIdx = $controls['ListProfiles'].SelectedIndex
        if ($selIdx -ge 0 -and $appConfig.Profiles -and $selIdx -lt $appConfig.Profiles.Count) {
            $updated = @($appConfig.Profiles)
            $updated = $updated[0..($selIdx - 1)] + $updated[($selIdx + 1)..($updated.Count - 1)]
            $appConfig.Profiles = $updated
            Save-AppSettings -Config $appConfig
            Refresh-Connections
        }
    })
}
#endregion

#region 15. Settings Panel Logic
function Load-SettingsPanel {
    if ($controls['ChkAutoDetect']) { $controls['ChkAutoDetect'].IsChecked = $true }
    if ($controls['TxtCfgSearchBase']) { $controls['TxtCfgSearchBase'].Text = $appConfig.Domain.SearchBase }
    if ($controls['TxtCfgPasswordLength']) { $controls['TxtCfgPasswordLength'].Text = $appConfig.Defaults.PasswordLength.ToString() }
    if ($controls['ChkCfgRequirePwChange']) { $controls['ChkCfgRequirePwChange'].IsChecked = $appConfig.Defaults.RequirePasswordChange }
    if ($controls['CmbUsernameFormat']) {
        $fmt = if ($appConfig.Defaults.UsernameFormat) { $appConfig.Defaults.UsernameFormat } else { "first.last" }
        $controls['CmbUsernameFormat'].SelectedIndex = if ($fmt -eq "flast") { 1 } else { 0 }
    }
    if ($controls['CmbExportDelimiter']) {
        $delim = if ($appConfig.Defaults.ExportDelimiter) { $appConfig.Defaults.ExportDelimiter } else { ";" }
        $controls['CmbExportDelimiter'].SelectedIndex = if ($delim -eq ",") { 1 } else { 0 }
    }
}

if ($controls['BtnSaveSettings']) {
    $controls['BtnSaveSettings'].Add_Click({
        $appConfig.Domain.SearchBase = if ($controls['TxtCfgSearchBase']) { $controls['TxtCfgSearchBase'].Text.Trim() } else { "" }
        
        $pwLen = 16
        if ($controls['TxtCfgPasswordLength'] -and [int]::TryParse($controls['TxtCfgPasswordLength'].Text, [ref]$pwLen)) {
            $appConfig.Defaults.PasswordLength = $pwLen
        }

        if ($controls['ChkCfgRequirePwChange']) {
            $appConfig.Defaults.RequirePasswordChange = [bool]$controls['ChkCfgRequirePwChange'].IsChecked
        }

        if ($controls['CmbUsernameFormat']) {
            $appConfig.Defaults.UsernameFormat = if ($controls['CmbUsernameFormat'].SelectedIndex -eq 1) { "flast" } else { "first.last" }
        }

        if ($controls['CmbExportDelimiter']) {
            $appConfig.Defaults.ExportDelimiter = if ($controls['CmbExportDelimiter'].SelectedIndex -eq 1) { "," } else { ";" }
        }

        $saved = Save-AppSettings -Config $appConfig
        if ($saved) {
            [System.Windows.MessageBox]::Show("Settings saved successfully.", "Settings Saved", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            Set-Status -Message "Settings updated."
        }
    })
}
#endregion

function Refresh-All {
    Refresh-Dashboard
    Refresh-OUs
    if ($controls['NavUsers'] -and $controls['NavUsers'].IsChecked)         { Refresh-Users }
    if ($controls['NavGroups'] -and $controls['NavGroups'].IsChecked)       { Refresh-Groups }
    if ($controls['NavComputers'] -and $controls['NavComputers'].IsChecked) { Refresh-Computers }
}

# Initial Window Launch
$window.Add_Loaded({
    Refresh-All
    Refresh-Connections
})

# Show Main Window
[void]$window.ShowDialog()