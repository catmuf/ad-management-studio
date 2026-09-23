<#
.SYNOPSIS
    Active Directory Management Studio - Modern Windows Server Administration Suite
.DESCRIPTION
    A modern WPF/XAML application for managing Active Directory Users, Groups, and Organizational Units.
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
$appRoot = $PSScriptRoot
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

# Helper to find named elements in a Window
function Get-NamedElements {
    param ([System.Windows.FrameworkElement]$Window)
    $elements = @{}
    $xmlDoc = [xml](Get-Content -Path (Join-Path $viewsPath "$($Window.GetType().Name).xaml") -Raw -ErrorAction SilentlyContinue)
    # Recursively find elements by Name
    function Find-Controls ($parent) {
        if ($parent -is [System.Windows.FrameworkElement] -and -not [string]::IsNullOrEmpty($parent.Name)) {
            $elements[$parent.Name] = $parent
        }
        $count = [System.Windows.Media.VisualTreeHelper]::GetChildrenCount($parent)
        for ($i = 0; $i -lt $count; $i++) {
            $child = [System.Windows.Media.VisualTreeHelper]::GetChild($parent, $i)
            Find-Controls $child
        }
    }
    return $elements
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
    CachedUsers  = @()
    CachedGroups = @()
    CachedOUs    = @()
    SelectedOU   = ""
    DomainName   = $adContext.DomainName
    UPNSuffix    = if ($adContext.DomainName) { "@$($adContext.DomainName)" } else { "" }
}

# Update Top Header
if ($adContext.IsConnected) {
    $controls['TxtDomainBadge'].Text = "Connected: $($adContext.DomainName)"
    $controls['TxtDCBadge'].Text     = if ($adContext.PDCEmulator) { $adContext.PDCEmulator } else { "Local DC" }
    $controls['StatusDot'].Fill      = [System.Windows.Media.Brushes]::Green
} else {
    $controls['TxtDomainBadge'].Text = "Not Connected to AD"
    $controls['TxtDCBadge'].Text     = $adContext.ErrorMessage
    $controls['StatusDot'].Fill      = [System.Windows.Media.Brushes]::Red
    [System.Windows.MessageBox]::Show(
        "Active Directory connection error: `n$($adContext.ErrorMessage)`n`nPlease ensure your computer is joined to a domain or check your RSAT credentials.",
        "AD Connection Warning",
        [System.Windows.MessageBoxButton]::OK,
        [System.Windows.MessageBoxImage]::Warning
    )
}

function Set-Status {
    param ([string]$Message, [string]$Count = "")
    $controls['TxtStatusBarMessage'].Text = $Message
    if ($Count) {
        $controls['TxtStatusBarCounter'].Text = $Count
    }
}

#region Refresh & Load Functions
function Refresh-Dashboard {
    Set-Status -Message "Fetching directory health metrics..."
    $stats = Get-ADDashboardStats
    $controls['CardTotalUsers'].Text    = $stats.TotalUsers.ToString()
    $controls['CardActiveUsers'].Text   = $stats.ActiveUsers.ToString()
    $controls['CardDisabledUsers'].Text = $stats.DisabledUsers.ToString()
    $controls['CardLockedUsers'].Text   = $stats.LockedUsers.ToString()
    $controls['CardTotalGroups'].Text   = $stats.TotalGroups.ToString()
    $controls['CardTotalOUs'].Text      = $stats.TotalOUs.ToString()
    Set-Status -Message "Dashboard metrics updated." -Count "$($stats.TotalUsers) Users | $($stats.TotalGroups) Groups | $($stats.TotalOUs) OUs"
}

function Refresh-Users {
    Set-Status -Message "Loading users from Active Directory..."
    $searchText = $controls['TxtUserSearch'].Text
    
    $statusFilter = "All"
    if ($controls['CmbUserStatus'].SelectedItem) {
        $statusText = $controls['CmbUserStatus'].SelectedItem.Content.ToString()
        if ($statusText -match "Active")   { $statusFilter = "Active" }
        if ($statusText -match "Disabled") { $statusFilter = "Disabled" }
        if ($statusText -match "Locked")   { $statusFilter = "Locked" }
    }

    $searchBase = ""
    if ($controls['CmbUserOU'].SelectedItem -and $controls['CmbUserOU'].SelectedIndex -gt 0) {
        $selectedOUItem = $controls['CmbUserOU'].SelectedItem
        if ($selectedOUItem.Tag) {
            $searchBase = $selectedOUItem.Tag
        }
    }

    $users = Get-ADUsersList -SearchText $searchText -StatusFilter $statusFilter -SearchBase $searchBase -Limit ($appConfig.UI.PageSize)
    $state.CachedUsers = $users
    $controls['GridUsers'].ItemsSource = $users
    Set-Status -Message "Loaded $($users.Count) user(s)." -Count "$($users.Count) users displayed"
}

function Refresh-Groups {
    Set-Status -Message "Loading groups from Active Directory..."
    $searchText = $controls['TxtGroupSearch'].Text
    
    $catFilter = "All"
    if ($controls['CmbGroupCategory'].SelectedItem) {
        $catText = $controls['CmbGroupCategory'].SelectedItem.Content.ToString()
        if ($catText -eq "Security" -or $catText -eq "Distribution") { $catFilter = $catText }
    }

    $scopeFilter = "All"
    if ($controls['CmbGroupScope'].SelectedItem) {
        $scopeText = $controls['CmbGroupScope'].SelectedItem.Content.ToString()
        if ($scopeText -ne "All Scopes") { $scopeFilter = $scopeText }
    }

    $groups = Get-ADGroupsList -SearchText $searchText -CategoryFilter $catFilter -ScopeFilter $scopeFilter -Limit ($appConfig.UI.PageSize)
    $state.CachedGroups = $groups
    $controls['GridGroups'].ItemsSource = $groups
    Set-Status -Message "Loaded $($groups.Count) group(s)." -Count "$($groups.Count) groups displayed"
}

function Refresh-OUs {
    Set-Status -Message "Building Organizational Unit hierarchy..."
    $ouTree = Get-ADOUTree
    if ($ouTree) {
        $controls['TreeOUs'].ItemsSource = @($ouTree)
    }

    # Populate OU filter dropdowns
    $ouFlatList = Get-ADOUFlatList
    $state.CachedOUs = $ouFlatList

    $controls['CmbUserOU'].Items.Clear()
    $domainRootItem = New-Object System.Windows.Controls.ComboBoxItem
    $domainRootItem.Content = "Entire Domain (All OUs)"
    $domainRootItem.Tag = ""
    [void]$controls['CmbUserOU'].Items.Add($domainRootItem)
    $controls['CmbUserOU'].SelectedIndex = 0

    foreach ($ou in $ouFlatList) {
        $item = New-Object System.Windows.Controls.ComboBoxItem
        $item.Content = $ou.DisplayName
        $item.Tag = $ou.DistinguishedName
        [void]$controls['CmbUserOU'].Items.Add($item)
    }

    Set-Status -Message "OU hierarchy loaded ($($ouFlatList.Count) OUs)." -Count "$($ouFlatList.Count) OUs"
}

function Refresh-All {
    Refresh-Dashboard
    Refresh-OUs
    if ($controls['NavUsers'].IsChecked)  { Refresh-Users }
    if ($controls['NavGroups'].IsChecked) { Refresh-Groups }
}
#endregion

#region Navigation Tab Switching
function Show-Panel {
    param ([string]$PanelName)
    $controls['PanelDashboard'].Visibility = if ($PanelName -eq "Dashboard") { [System.Windows.Visibility]::Visible } else { [System.Windows.Visibility]::Collapsed }
    $controls['PanelUsers'].Visibility     = if ($PanelName -eq "Users")     { [System.Windows.Visibility]::Visible } else { [System.Windows.Visibility]::Collapsed }
    $controls['PanelGroups'].Visibility    = if ($PanelName -eq "Groups")    { [System.Windows.Visibility]::Visible } else { [System.Windows.Visibility]::Collapsed }
    $controls['PanelOUs'].Visibility       = if ($PanelName -eq "OUs")       { [System.Windows.Visibility]::Visible } else { [System.Windows.Visibility]::Collapsed }
    $controls['PanelSettings'].Visibility  = if ($PanelName -eq "Settings")  { [System.Windows.Visibility]::Visible } else { [System.Windows.Visibility]::Collapsed }
}

$controls['NavDashboard'].Add_Checked({ Show-Panel "Dashboard"; Refresh-Dashboard })
$controls['NavUsers'].Add_Checked({ Show-Panel "Users"; Refresh-Users })
$controls['NavGroups'].Add_Checked({ Show-Panel "Groups"; Refresh-Groups })
$controls['NavOUs'].Add_Checked({ Show-Panel "OUs"; Refresh-OUs })
$controls['NavSettings'].Add_Checked({ Show-Panel "Settings"; Load-SettingsPanel })

# Dashboard KPI Card Click Handlers (Interactive Drill-Down!)
$controls['CardBtnActiveUsers'].Add_MouseDown({
    $controls['NavUsers'].IsChecked = $true
    $controls['CmbUserStatus'].SelectedIndex = 1 # Active Only
    Refresh-Users
})

$controls['CardBtnDisabledUsers'].Add_MouseDown({
    $controls['NavUsers'].IsChecked = $true
    $controls['CmbUserStatus'].SelectedIndex = 2 # Disabled Only
    Refresh-Users
})

$controls['CardBtnLockedUsers'].Add_MouseDown({
    $controls['NavUsers'].IsChecked = $true
    $controls['CmbUserStatus'].SelectedIndex = 3 # Locked Only
    Refresh-Users
})

$controls['CardBtnGroups'].Add_MouseDown({
    $controls['NavGroups'].IsChecked = $true
    Refresh-Groups
})

$controls['CardBtnOUs'].Add_MouseDown({
    $controls['NavOUs'].IsChecked = $true
    Refresh-OUs
})

# Quick Actions on Dashboard
$controls['QuickBtnNewUser'].Add_Click({ Open-UserDialog -Mode "Create" })
$controls['QuickBtnNewGroup'].Add_Click({ Open-GroupDialog })
$controls['QuickBtnNewOU'].Add_Click({ Open-OUDialog })
$controls['QuickBtnExportAll'].Add_Click({ Export-UsersAction })
$controls['BtnGlobalRefresh'].Add_Click({ Refresh-All })
#endregion

#region User Management Actions & Dialogs
function Open-UserDialog {
    param (
        [string]$Mode = "Create", # "Create" or "Edit"
        $UserToEdit = $null
    )

    $dlgPath = Join-Path $viewsPath "UserDialog.xaml"
    $dlg = Load-XamlWindow -XamlPath $dlgPath
    $dlg.Owner = $window

    # Extract dialog controls
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

        # Populate existing values
        $dControls['TxtFirstName'].Text   = $UserToEdit.GivenName
        $dControls['TxtLastName'].Text    = $UserToEdit.Surname
        $dControls['TxtDisplayName'].Text = $UserToEdit.DisplayName
        $dControls['TxtUsername'].Text    = $UserToEdit.SamAccountName
        $dControls['TxtUsername'].IsEnabled = $false # SamAccountName shouldn't be casually renamed here
        $dControls['TxtUPN'].Text         = $UserToEdit.UserPrincipalName
        $dControls['TxtEmail'].Text       = $UserToEdit.Mail
        $dControls['TxtEmployeeID'].Text  = $UserToEdit.EmployeeID
        $dControls['TxtDescription'].Text = $UserToEdit.Description
        $dControls['TxtJobTitle'].Text    = $UserToEdit.Title
        $dControls['TxtDepartment'].Text  = $UserToEdit.Department
        $dControls['TxtCompany'].Text     = $UserToEdit.Company
        $dControls['TxtOffice'].Text      = $UserToEdit.Office

        # Disable credentials tab in edit mode (use Reset Password dialog instead)
        $dControls['TabCredentials'].Visibility = [System.Windows.Visibility]::Collapsed
    }
    else {
        # Default for new user
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
        }
        else {
            # Update existing user
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
    $selUser = $controls['GridUsers'].SelectedItem
    if (-not $selUser) {
        [System.Windows.MessageBox]::Show("Please select a user from the list first.", "No Selection", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        return
    }

    $confirm = [System.Windows.MessageBox]::Show(
        "Are you sure you want to permanently delete user:`n`n$($selUser.DisplayName) ($($selUser.SamAccountName))`nDN: $($selUser.DistinguishedName)`n`nThis will remove the account from Active Directory. This action cannot be undone.",
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
    $selUser = $controls['GridUsers'].SelectedItem
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

function Unlock-UserAction {
    $selUser = $controls['GridUsers'].SelectedItem
    if (-not $selUser) { return }

    $res = Unlock-ADUserAccount -Identity $selUser.DistinguishedName
    if ($res.Success) {
        [System.Windows.MessageBox]::Show($res.Message, "Account Unlocked", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        Refresh-Users
        Refresh-Dashboard
    } else {
        [System.Windows.MessageBox]::Show($res.Message, "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
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

# User Toolbar & Grid Event Wiring
$controls['BtnUserSearch'].Add_Click({ Refresh-Users })
$controls['TxtUserSearch'].Add_KeyDown({
    if ($_.Key -eq [System.Windows.Input.Key]::Enter) { Refresh-Users }
})
$controls['CmbUserStatus'].Add_SelectionChanged({ Refresh-Users })
$controls['CmbUserOU'].Add_SelectionChanged({ Refresh-Users })

$controls['BtnUserNew'].Add_Click({ Open-UserDialog -Mode "Create" })
$controls['BtnUserEdit'].Add_Click({
    $u = $controls['GridUsers'].SelectedItem
    if ($u) { Open-UserDialog -Mode "Edit" -UserToEdit $u }
})
$controls['BtnUserView'].Add_Click({
    $u = $controls['GridUsers'].SelectedItem
    if ($u) { Open-UserDetailDialog -User $u }
})
$controls['BtnUserPassword'].Add_Click({
    $u = $controls['GridUsers'].SelectedItem
    if ($u) { Open-PasswordDialog -User $u }
})
$controls['BtnUserToggleStatus'].Add_Click({ Toggle-UserStatusAction })
$controls['BtnUserUnlock'].Add_Click({ Unlock-UserAction })
$controls['BtnUserMove'].Add_Click({
    $u = $controls['GridUsers'].SelectedItem
    if ($u) { Open-MoveDialog -Principal $u -Type "User" }
})
$controls['BtnUserDelete'].Add_Click({ Delete-UserAction })
$controls['BtnUserExport'].Add_Click({ Export-UsersAction })

# Double Click on DataGrid row to view details
$controls['GridUsers'].Add_MouseDoubleClick({
    $u = $controls['GridUsers'].SelectedItem
    if ($u) { Open-UserDetailDialog -User $u }
})

# User Context Menu Wiring
$controls['CtxUserView'].Add_Click({
    $u = $controls['GridUsers'].SelectedItem
    if ($u) { Open-UserDetailDialog -User $u }
})
$controls['CtxUserEdit'].Add_Click({
    $u = $controls['GridUsers'].SelectedItem
    if ($u) { Open-UserDialog -Mode "Edit" -UserToEdit $u }
})
$controls['CtxUserPassword'].Add_Click({
    $u = $controls['GridUsers'].SelectedItem
    if ($u) { Open-PasswordDialog -User $u }
})
$controls['CtxUserUnlock'].Add_Click({ Unlock-UserAction })
$controls['CtxUserToggle'].Add_Click({ Toggle-UserStatusAction })
$controls['CtxUserMove'].Add_Click({
    $u = $controls['GridUsers'].SelectedItem
    if ($u) { Open-MoveDialog -Principal $u -Type "User" }
})
$controls['CtxUserCopyUser'].Add_Click({
    $u = $controls['GridUsers'].SelectedItem
    if ($u) { [System.Windows.Clipboard]::SetText($u.SamAccountName) }
})
$controls['CtxUserDelete'].Add_Click({ Delete-UserAction })
#endregion

#region Group Management Actions & Dialogs
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

    function Reload-Members {
        $m = Get-ADGroupMembersList -Identity $Group.DistinguishedName
        $dControls['ListCurrentMembers'].ItemsSource = $m
        $dControls['TxtMemberCount'].Text = "$($m.Count) members"
    }
    Reload-Members

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
                Reload-Members
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
                    Reload-Members
                }
            }
        }
    })

    $dControls['BtnClose'].Add_Click({ $dlg.Close() })
    [void]$dlg.ShowDialog()
}

function Delete-GroupAction {
    $selGroup = $controls['GridGroups'].SelectedItem
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

$controls['BtnGroupSearch'].Add_Click({ Refresh-Groups })
$controls['TxtGroupSearch'].Add_KeyDown({
    if ($_.Key -eq [System.Windows.Input.Key]::Enter) { Refresh-Groups }
})
$controls['CmbGroupCategory'].Add_SelectionChanged({ Refresh-Groups })
$controls['CmbGroupScope'].Add_SelectionChanged({ Refresh-Groups })
$controls['BtnGroupNew'].Add_Click({ Open-GroupDialog })
$controls['BtnGroupMembers'].Add_Click({
    $g = $controls['GridGroups'].SelectedItem
    if ($g) { Open-MemberDialog -Group $g }
})
$controls['BtnGroupDelete'].Add_Click({ Delete-GroupAction })
$controls['BtnGroupExport'].Add_Click({ Export-GroupsAction })
#endregion

#region Organizational Unit (OU) Management Actions
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

    # Domain Root as default parent option
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

$controls['BtnOUNew'].Add_Click({ Open-OUDialog })
$controls['BtnOURefresh'].Add_Click({ Refresh-OUs })

# Tree View Selection Changed: load objects in selected OU
$controls['TreeOUs'].Add_SelectedItemChanged({
    $selectedNode = $controls['TreeOUs'].SelectedItem
    if ($selectedNode) {
        $controls['TxtOUDetailName'].Text = $selectedNode.Name
        $controls['TxtOUDetailDN'].Text   = $selectedNode.DistinguishedName
        $controls['TxtOUDescription'].Text = if ($selectedNode.Description) { $selectedNode.Description } else { "(None)" }
        $controls['TxtOUProtection'].Text  = if ($selectedNode.IsProtected) { "Protected from accidental deletion" } else { "Unprotected" }
        $controls['TxtOUProtection'].Foreground = if ($selectedNode.IsProtected) { [System.Windows.Media.Brushes]::Green } else { [System.Windows.Media.Brushes]::Orange }

        # Query items inside this OU
        try {
            $usersInOU = Get-ADUser -Filter * -SearchBase $selectedNode.DistinguishedName -SearchScope OneLevel -Properties DisplayName, SamAccountName, DistinguishedName |
                         Select-Object @{N='ObjectClass'; E={'User'}}, @{N='Name'; E={$_.DisplayName}}, SamAccountName, DistinguishedName

            $groupsInOU = Get-ADGroup -Filter * -SearchBase $selectedNode.DistinguishedName -SearchScope OneLevel -Properties Name, SamAccountName, DistinguishedName |
                          Select-Object @{N='ObjectClass'; E={'Group'}}, Name, SamAccountName, DistinguishedName

            $allObjects = @($usersInOU) + @($groupsInOU)
            $controls['GridOUObjects'].ItemsSource = $allObjects
        }
        catch {
            $controls['GridOUObjects'].ItemsSource = @()
        }
    }
})

$controls['BtnOUDelete'].Add_Click({
    $selectedNode = $controls['TreeOUs'].SelectedItem
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
#endregion

#region Settings Panel Logic
function Load-SettingsPanel {
    $controls['SettingDomainName'].Text = $appConfig.Domain.DomainName
    $controls['SettingDC'].Text         = $appConfig.Domain.DomainController
    $controls['SettingSearchBase'].Text = $appConfig.Domain.SearchBase
    $controls['SettingPasswordLength'].Text = $appConfig.Defaults.PasswordLength.ToString()
}

$controls['BtnSaveSettings'].Add_Click({
    $appConfig.Domain.DomainName       = $controls['SettingDomainName'].Text.Trim()
    $appConfig.Domain.DomainController = $controls['SettingDC'].Text.Trim()
    $appConfig.Domain.SearchBase       = $controls['SettingSearchBase'].Text.Trim()
    
    $pwLen = 16
    if ([int]::TryParse($controls['SettingPasswordLength'].Text, [ref]$pwLen)) {
        $appConfig.Defaults.PasswordLength = $pwLen
    }

    $saved = Save-AppSettings -Config $appConfig
    if ($saved) {
        [System.Windows.MessageBox]::Show("Settings saved successfully.", "Settings Saved", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        Set-Status -Message "Settings updated."
    }
})
#endregion

# Initial Launch Logic
$window.Add_Loaded({
    Refresh-All
})

# Show Main Window
[void]$window.ShowDialog()