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
    AllScopeUsers          = @()
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

#region Dynamic Table Column Customization Engine
$tableColumnCatalog = @{
    Users = @{
        GridControl = 'GridUsers'
        FriendlyName = 'Users'
        DefaultColumns = @(
            @{ Header = "Status"; Property = "StatusBadge"; Width = 90 }
            @{ Header = "Display Name"; Property = "DisplayName"; Width = 160 }
            @{ Header = "Username"; Property = "SamAccountName"; Width = 120 }
            @{ Header = "Email"; Property = "Email"; Width = 180 }
            @{ Header = "Department"; Property = "Department"; Width = 140 }
            @{ Header = "Title"; Property = "Title"; Width = 140 }
            @{ Header = "OU Location"; Property = "OUPath"; Width = "*" }
        )
        AvailableAttributes = @(
            @{ Header = "Status"; PropertyKey = "StatusBadge"; Category = "Status"; Description = "Active, Disabled, or Locked account status" }
            @{ Header = "Display Name"; PropertyKey = "DisplayName"; Category = "Standard"; Description = "Full display name of user" }
            @{ Header = "Username"; PropertyKey = "SamAccountName"; Category = "Standard"; Description = "Logon user account name (sAMAccountName)" }
            @{ Header = "Email"; PropertyKey = "Email"; Category = "Contact"; Description = "Primary email or UPN email address" }
            @{ Header = "Department"; PropertyKey = "Department"; Category = "Organization"; Description = "Department within organization" }
            @{ Header = "Title"; PropertyKey = "Title"; Category = "Organization"; Description = "Job or business title" }
            @{ Header = "OU Location"; PropertyKey = "OUPath"; Category = "Location"; Description = "Canonical Organizational Unit path" }
            @{ Header = "First Name"; PropertyKey = "GivenName"; Category = "Standard"; Description = "First or given name (givenName)" }
            @{ Header = "Last Name"; PropertyKey = "Surname"; Category = "Standard"; Description = "Last or surname (sn)" }
            @{ Header = "User Principal Name"; PropertyKey = "UserPrincipalName"; Category = "Standard"; Description = "UPN (user@domain.com)" }
            @{ Header = "Telephone"; PropertyKey = "TelephoneNumber"; Category = "Contact"; Description = "Primary telephone number (telephoneNumber)" }
            @{ Header = "Mobile"; PropertyKey = "Mobile"; Category = "Contact"; Description = "Mobile phone number (mobile)" }
            @{ Header = "Office"; PropertyKey = "Office"; Category = "Location"; Description = "Office room or building (physicalDeliveryOfficeName)" }
            @{ Header = "Company"; PropertyKey = "Company"; Category = "Organization"; Description = "Company or business entity (company)" }
            @{ Header = "Manager"; PropertyKey = "Manager"; Category = "Organization"; Description = "Reporting manager name (manager)" }
            @{ Header = "Employee ID"; PropertyKey = "EmployeeID"; Category = "Organization"; Description = "Corporate employee number (employeeID)" }
            @{ Header = "Description"; PropertyKey = "Description"; Category = "Standard"; Description = "Account description" }
            @{ Header = "Street Address"; PropertyKey = "StreetAddress"; Category = "Location"; Description = "Street address (streetAddress)" }
            @{ Header = "City"; PropertyKey = "City"; Category = "Location"; Description = "City locality (l)" }
            @{ Header = "State / Province"; PropertyKey = "State"; Category = "Location"; Description = "State or province (st)" }
            @{ Header = "Postal Code"; PropertyKey = "PostalCode"; Category = "Location"; Description = "Postal or ZIP code (postalCode)" }
            @{ Header = "Country"; PropertyKey = "Country"; Category = "Location"; Description = "Country name or code (co)" }
            @{ Header = "When Created"; PropertyKey = "WhenCreated"; Category = "System"; Description = "Account creation timestamp" }
            @{ Header = "When Changed"; PropertyKey = "WhenChanged"; Category = "System"; Description = "Last modification timestamp" }
            @{ Header = "Last Logon"; PropertyKey = "LastLogonDate"; Category = "System"; Description = "Last logon timestamp" }
            @{ Header = "Password Last Set"; PropertyKey = "PasswordLastSet"; Category = "Security"; Description = "Date password was last changed" }
            @{ Header = "Object SID"; PropertyKey = "SID"; Category = "Security"; Description = "Security Identifier (objectSid)" }
            @{ Header = "Object GUID"; PropertyKey = "ObjectGUID"; Category = "System"; Description = "Unique GUID identifier" }
            @{ Header = "Distinguished Name"; PropertyKey = "DistinguishedName"; Category = "System"; Description = "Full LDAP X.500 distinguished name" }
        )
    }
    Groups = @{
        GridControl = 'GridGroups'
        FriendlyName = 'Groups'
        DefaultColumns = @(
            @{ Header = "Group Name"; Property = "Name"; Width = 200 }
            @{ Header = "SamAccountName"; Property = "SamAccountName"; Width = 160 }
            @{ Header = "Scope"; Property = "GroupScope"; Width = 110 }
            @{ Header = "Category"; Property = "GroupCategory"; Width = 110 }
            @{ Header = "OU Location"; Property = "OUPath"; Width = "*" }
        )
        AvailableAttributes = @(
            @{ Header = "Group Name"; PropertyKey = "Name"; Category = "Standard"; Description = "Friendly group display name" }
            @{ Header = "SamAccountName"; PropertyKey = "SamAccountName"; Category = "Standard"; Description = "Pre-Windows 2000 group logon name" }
            @{ Header = "Scope"; PropertyKey = "GroupScope"; Category = "Scope"; Description = "Group scope: Global, Universal, or DomainLocal" }
            @{ Header = "Category"; PropertyKey = "GroupCategory"; Category = "Category"; Description = "Group category: Security or Distribution" }
            @{ Header = "OU Location"; PropertyKey = "OUPath"; Category = "Location"; Description = "Parent Organizational Unit path" }
            @{ Header = "Description"; PropertyKey = "Description"; Category = "Standard"; Description = "Group description or purpose" }
            @{ Header = "Member Count"; PropertyKey = "MemberCount"; Category = "Membership"; Description = "Count of direct members in group" }
            @{ Header = "E-mail"; PropertyKey = "Mail"; Category = "Contact"; Description = "Group email address (mail)" }
            @{ Header = "Managed By"; PropertyKey = "ManagedBy"; Category = "Organization"; Description = "Group owner / manager (managedBy)" }
            @{ Header = "When Created"; PropertyKey = "WhenCreated"; Category = "System"; Description = "Group creation timestamp" }
            @{ Header = "When Changed"; PropertyKey = "WhenChanged"; Category = "System"; Description = "Group last modified timestamp" }
            @{ Header = "Object SID"; PropertyKey = "SID"; Category = "Security"; Description = "Security Identifier (objectSid)" }
            @{ Header = "Object GUID"; PropertyKey = "ObjectGUID"; Category = "System"; Description = "Unique group GUID" }
            @{ Header = "Notes / Info"; PropertyKey = "Info"; Category = "Standard"; Description = "Administrative notes (info)" }
            @{ Header = "Distinguished Name"; PropertyKey = "DistinguishedName"; Category = "System"; Description = "Full group LDAP distinguished name" }
        )
    }
    Computers = @{
        GridControl = 'GridComputers'
        FriendlyName = 'Computers'
        DefaultColumns = @(
            @{ Header = "Computer Name"; Property = "Name"; Width = 150 }
            @{ Header = "DNS Hostname"; Property = "DNSHostName"; Width = 190 }
            @{ Header = "Operating System"; Property = "OperatingSystem"; Width = 180 }
            @{ Header = "Version"; Property = "OSVersion"; Width = 100 }
            @{ Header = "Status"; Property = "Status"; Width = 90 }
            @{ Header = "Last Logon"; Property = "LastLogon"; Width = 140 }
            @{ Header = "OU Location"; Property = "OUPath"; Width = "*" }
        )
        AvailableAttributes = @(
            @{ Header = "Computer Name"; PropertyKey = "Name"; Category = "Standard"; Description = "NetBIOS computer name" }
            @{ Header = "DNS Hostname"; PropertyKey = "DNSHostName"; Category = "Network"; Description = "Fully qualified DNS host name (dNSHostName)" }
            @{ Header = "Operating System"; PropertyKey = "OperatingSystem"; Category = "OS"; Description = "Operating System name (operatingSystem)" }
            @{ Header = "Version"; PropertyKey = "OSVersion"; Category = "OS"; Description = "Operating System build version (operatingSystemVersion)" }
            @{ Header = "Status"; PropertyKey = "Status"; Category = "Status"; Description = "Computer account enabled or disabled" }
            @{ Header = "Last Logon"; PropertyKey = "LastLogon"; Category = "System"; Description = "Last computer logon timestamp" }
            @{ Header = "OU Location"; PropertyKey = "OUPath"; Category = "Location"; Description = "Parent OU path" }
            @{ Header = "Description"; PropertyKey = "Description"; Category = "Standard"; Description = "Computer description or role" }
            @{ Header = "IPv4 Address"; PropertyKey = "IPv4Address"; Category = "Network"; Description = "Registered IPv4 address (ipv4Address)" }
            @{ Header = "SamAccountName"; PropertyKey = "SamAccountName"; Category = "Standard"; Description = "Computer sAMAccountName (e.g. WS01$)" }
            @{ Header = "When Created"; PropertyKey = "WhenCreated"; Category = "System"; Description = "Domain join creation timestamp" }
            @{ Header = "When Changed"; PropertyKey = "WhenChanged"; Category = "System"; Description = "Last modification timestamp" }
            @{ Header = "Distinguished Name"; PropertyKey = "DistinguishedName"; Category = "System"; Description = "Full computer LDAP DN" }
        )
    }
    OUObjects = @{
        GridControl = 'GridOUObjects'
        FriendlyName = 'OU Objects'
        DefaultColumns = @(
            @{ Header = "Type"; Property = "ObjectClass"; Width = 80 }
            @{ Header = "Name"; Property = "Name"; Width = 180 }
            @{ Header = "SamAccountName"; Property = "SamAccountName"; Width = 140 }
            @{ Header = "Status"; Property = "Status"; Width = 100 }
            @{ Header = "Distinguished Name"; Property = "DistinguishedName"; Width = "*" }
        )
        AvailableAttributes = @(
            @{ Header = "Type"; PropertyKey = "ObjectClass"; Category = "Standard"; Description = "Object class (User, Group, Computer, OU)" }
            @{ Header = "Name"; PropertyKey = "Name"; Category = "Standard"; Description = "Object name (cn or ou)" }
            @{ Header = "SamAccountName"; PropertyKey = "SamAccountName"; Category = "Standard"; Description = "Account logon name (sAMAccountName)" }
            @{ Header = "Status"; PropertyKey = "Status"; Category = "Status"; Description = "Account or object status" }
            @{ Header = "Distinguished Name"; PropertyKey = "DistinguishedName"; Category = "System"; Description = "Full LDAP Distinguished Name" }
            @{ Header = "Description"; PropertyKey = "Description"; Category = "Standard"; Description = "Object description" }
            @{ Header = "E-mail"; PropertyKey = "Mail"; Category = "Contact"; Description = "Object email address (mail)" }
            @{ Header = "When Created"; PropertyKey = "WhenCreated"; Category = "System"; Description = "Creation timestamp" }
            @{ Header = "When Changed"; PropertyKey = "WhenChanged"; Category = "System"; Description = "Last modification timestamp" }
        )
    }
    Search = @{
        GridControl = 'GridSearchResults'
        FriendlyName = 'Directory Search'
        DefaultColumns = @(
            @{ Header = "Class"; Property = "ObjectClass"; Width = 90 }
            @{ Header = "SamAccountName"; Property = "SamAccountName"; Width = 150 }
            @{ Header = "Display Name"; Property = "DisplayName"; Width = 180 }
            @{ Header = "Distinguished Name"; Property = "DistinguishedName"; Width = "*" }
        )
        AvailableAttributes = @(
            @{ Header = "Class"; PropertyKey = "ObjectClass"; Category = "Standard"; Description = "LDAP Object class" }
            @{ Header = "SamAccountName"; PropertyKey = "SamAccountName"; Category = "Standard"; Description = "User/Group/Computer logon name" }
            @{ Header = "Display Name"; PropertyKey = "DisplayName"; Category = "Standard"; Description = "Full display name" }
            @{ Header = "Distinguished Name"; PropertyKey = "DistinguishedName"; Category = "System"; Description = "Full LDAP Distinguished Name" }
            @{ Header = "Description"; PropertyKey = "description"; Category = "Standard"; Description = "Object description (description)" }
            @{ Header = "Email / Mail"; PropertyKey = "mail"; Category = "Contact"; Description = "Email address (mail)" }
            @{ Header = "Department"; PropertyKey = "department"; Category = "Organization"; Description = "Department (department)" }
            @{ Header = "Title"; PropertyKey = "title"; Category = "Organization"; Description = "Job title (title)" }
            @{ Header = "Telephone"; PropertyKey = "telephoneNumber"; Category = "Contact"; Description = "Telephone number (telephoneNumber)" }
            @{ Header = "When Created"; PropertyKey = "whenCreated"; Category = "System"; Description = "Creation date (whenCreated)" }
            @{ Header = "When Changed"; PropertyKey = "whenChanged"; Category = "System"; Description = "Modification date (whenChanged)" }
            @{ Header = "User Account Control"; PropertyKey = "userAccountControl"; Category = "Security"; Description = "UAC bitmask flags (userAccountControl)" }
            @{ Header = "Object SID"; PropertyKey = "objectsid"; Category = "Security"; Description = "Security Identifier (objectSid)" }
        )
    }
}

function Populate-MissingAttributeInItemsSource {
    param (
        [System.Windows.Controls.DataGrid]$DataGrid,
        [string]$PropertyKey
    )
    if (-not $DataGrid -or -not $DataGrid.ItemsSource) { return }

    foreach ($item in $DataGrid.ItemsSource) {
        if ($null -eq $item -or $item -isnot [System.Management.Automation.PSCustomObject]) { continue }
        $existingProp = $item.PSObject.Properties[$PropertyKey]
        if (-not $existingProp) {
            $val = ""
            if ($item.RawUser -and $item.RawUser.$PropertyKey) {
                $val = $item.RawUser.$PropertyKey.ToString()
            } elseif ($item.RawGroup -and $item.RawGroup.$PropertyKey) {
                $val = $item.RawGroup.$PropertyKey.ToString()
            } elseif ($item.RawComputer -and $item.RawComputer.$PropertyKey) {
                $val = $item.RawComputer.$PropertyKey.ToString()
            } elseif ($item.RawObject -and $item.RawObject.$PropertyKey) {
                $val = $item.RawObject.$PropertyKey.ToString()
            } elseif ($item.DistinguishedName) {
                try {
                    $entry = [System.DirectoryServices.DirectoryEntry]"LDAP://$($item.DistinguishedName)"
                    if ($entry.Properties.Contains($PropertyKey)) {
                        $propVals = $entry.Properties[$PropertyKey]
                        $val = if ($propVals.Count -gt 1) { ($propVals | ForEach-Object { "$_" }) -join "; " } else { "$($propVals.Value)" }
                    }
                } catch {}
            }
            $item | Add-Member -NotePropertyName $PropertyKey -NotePropertyValue $val -Force
        }
    }
}

function Sync-DataGridColumnsProperties {
    param (
        [System.Windows.Controls.DataGrid]$DataGrid
    )
    if (-not $DataGrid -or -not $DataGrid.ItemsSource) { return }
    foreach ($col in $DataGrid.Columns) {
        if ($col -is [System.Windows.Controls.DataGridBoundColumn] -and $col.Binding -is [System.Windows.Data.Binding]) {
            $propKey = $col.Binding.Path.Path
            Populate-MissingAttributeInItemsSource -DataGrid $DataGrid -PropertyKey $propKey
        }
    }
}

function Show-ColumnChooser {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("Users", "Groups", "Computers", "OUObjects", "Search")]
        [string]$TableName
    )

    $config = $tableColumnCatalog[$TableName]
    if (-not $config) { return }

    $grid = $controls[$config.GridControl]
    if (-not $grid) { return }

    $dlgPath = Join-Path $viewsPath "ColumnChooserDialog.xaml"
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

    # Title & Subtitle
    if ($dControls['TxtDialogTitle']) {
        $dControls['TxtDialogTitle'].Text = "Customize Columns: $($config.FriendlyName)"
    }

    # Get currently visible columns
    $currentBindingKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($col in $grid.Columns) {
        if ($col -is [System.Windows.Controls.DataGridBoundColumn] -and $col.Binding -is [System.Windows.Data.Binding]) {
            [void]$currentBindingKeys.Add($col.Binding.Path.Path)
        } else {
            [void]$currentBindingKeys.Add($col.Header.ToString())
        }
    }

    # Build selectable list of attributes
    $attrObservableList = [System.Collections.ObjectModel.ObservableCollection[PSCustomObject]]::new()
    $seenKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($attr in $config.AvailableAttributes) {
        [void]$seenKeys.Add($attr.PropertyKey)
        $isSelected = $currentBindingKeys.Contains($attr.PropertyKey) -or $currentBindingKeys.Contains($attr.Header)
        $attrObservableList.Add([PSCustomObject]@{
            Header      = $attr.Header
            PropertyKey = $attr.PropertyKey
            Category    = $attr.Category
            Description = $attr.Description
            IsSelected  = [bool]$isSelected
        })
    }

    # Include any custom columns currently present on grid
    foreach ($col in $grid.Columns) {
        $pKey = if ($col -is [System.Windows.Controls.DataGridBoundColumn] -and $col.Binding -is [System.Windows.Data.Binding]) {
            $col.Binding.Path.Path
        } else { $col.Header.ToString() }
        if (-not $seenKeys.Contains($pKey)) {
            [void]$seenKeys.Add($pKey)
            $attrObservableList.Add([PSCustomObject]@{
                Header      = $col.Header.ToString()
                PropertyKey = $pKey
                Category    = "Custom"
                Description = "Custom column attribute"
                IsSelected  = $true
            })
        }
    }

    $dControls['LstAttributes'].ItemsSource = $attrObservableList

    $updateCountBadge = {
        $selectedCount = ($attrObservableList | Where-Object { $_.IsSelected }).Count
        if ($dControls['TxtActiveColumnsCount']) {
            $dControls['TxtActiveColumnsCount'].Text = "$selectedCount columns active"
        }
    }
    & $updateCountBadge

    if ($dControls['LstAttributes']) {
        $dControls['LstAttributes'].Add_PreviewMouseLeftButtonUp({
            $dlg.Dispatcher.BeginInvoke([System.Action]{
                & $updateCountBadge
            })
        })
    }

    # Search / Filter
    $filterAttrs = {
        $q = if ($dControls['TxtFilterColumns']) { $dControls['TxtFilterColumns'].Text.Trim() } else { "" }
        if ($dControls['TxtFilterPlaceholder']) {
            $dControls['TxtFilterPlaceholder'].Visibility = if ([string]::IsNullOrEmpty($q)) { [System.Windows.Visibility]::Visible } else { [System.Windows.Visibility]::Collapsed }
        }
        if ($dControls['BtnClearFilter']) {
            $dControls['BtnClearFilter'].Visibility = if ([string]::IsNullOrEmpty($q)) { [System.Windows.Visibility]::Collapsed } else { [System.Windows.Visibility]::Visible }
        }

        $view = [System.Windows.Data.CollectionViewSource]::GetDefaultView($dControls['LstAttributes'].ItemsSource)
        if ($view) {
            if ([string]::IsNullOrWhiteSpace($q)) {
                $view.Filter = $null
            } else {
                $view.Filter = [System.Predicate[object]]{
                    param($item)
                    if (-not $item) { return $false }
                    return ($item.Header -like "*$q*" -or $item.PropertyKey -like "*$q*" -or $item.Description -like "*$q*" -or $item.Category -like "*$q*")
                }
            }
        }
    }

    if ($dControls['TxtFilterColumns']) {
        $dControls['TxtFilterColumns'].Add_TextChanged({ & $filterAttrs })
    }
    if ($dControls['BtnClearFilter']) {
        $dControls['BtnClearFilter'].Add_Click({
            $dControls['TxtFilterColumns'].Text = ""
            $dControls['TxtFilterColumns'].Focus()
        })
    }

    # Select All / Clear All
    if ($dControls['BtnSelectAll']) {
        $dControls['BtnSelectAll'].Add_Click({
            foreach ($item in $attrObservableList) { $item.IsSelected = $true }
            & $updateCountBadge
            try { $dControls['LstAttributes'].Items.Refresh() } catch {}
        })
    }
    if ($dControls['BtnDeselectAll']) {
        $dControls['BtnDeselectAll'].Add_Click({
            foreach ($item in $attrObservableList) { $item.IsSelected = $false }
            & $updateCountBadge
            try { $dControls['LstAttributes'].Items.Refresh() } catch {}
        })
    }

    # Custom Attribute Adder
    $addCustomAttr = {
        $customName = if ($dControls['TxtCustomAttribute']) { $dControls['TxtCustomAttribute'].Text.Trim() } else { "" }
        if ([string]::IsNullOrWhiteSpace($customName)) { return }

        $existing = $attrObservableList | Where-Object { $_.PropertyKey -ieq $customName -or $_.Header -ieq $customName }
        if ($existing) {
            $existing.IsSelected = $true
        } else {
            $newItem = [PSCustomObject]@{
                Header      = $customName
                PropertyKey = $customName
                Category    = "Custom"
                Description = "Custom AD schema attribute: $customName"
                IsSelected  = $true
            }
            $attrObservableList.Add($newItem)
        }
        $dControls['TxtCustomAttribute'].Text = ""
        & $updateCountBadge
        try { $dControls['LstAttributes'].Items.Refresh() } catch {}
    }

    if ($dControls['BtnAddCustomAttribute']) {
        $dControls['BtnAddCustomAttribute'].Add_Click({ & $addCustomAttr })
    }
    if ($dControls['TxtCustomAttribute']) {
        $dControls['TxtCustomAttribute'].Add_KeyDown({
            if ($_.Key -eq [System.Windows.Input.Key]::Enter) { & $addCustomAttr }
        })
    }

    # Reset Defaults inside dialog
    if ($dControls['BtnResetDefaults']) {
        $dControls['BtnResetDefaults'].Add_Click({
            $defaultKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($dc in $config.DefaultColumns) {
                [void]$defaultKeys.Add($dc.Property)
                [void]$defaultKeys.Add($dc.Header)
            }
            foreach ($item in $attrObservableList) {
                $item.IsSelected = $defaultKeys.Contains($item.PropertyKey) -or $defaultKeys.Contains($item.Header)
            }
            & $updateCountBadge
            try { $dControls['LstAttributes'].Items.Refresh() } catch {}
        })
    }

    # Cancel
    if ($dControls['BtnCancel']) {
        $dControls['BtnCancel'].Add_Click({ $dlg.Close() })
    }

    # Apply
    if ($dControls['BtnApply']) {
        $dControls['BtnApply'].Add_Click({
            $selectedItems = @($attrObservableList | Where-Object { $_.IsSelected })
            if ($selectedItems.Count -eq 0) {
                [System.Windows.MessageBox]::Show("Please select at least one column to display in the table.", "No Columns Selected", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
                return
            }

            $grid.Columns.Clear()
            foreach ($item in $selectedItems) {
                $col = New-Object System.Windows.Controls.DataGridTextColumn
                $col.Header = $item.Header
                $col.Binding = New-Object System.Windows.Data.Binding($item.PropertyKey)
                
                $defMatch = $config.DefaultColumns | Where-Object { $_.Property -ieq $item.PropertyKey -or $_.Header -ieq $item.Header }
                if ($defMatch) {
                    if ($defMatch.Width -eq "*") {
                        $col.Width = New-Object System.Windows.Controls.DataGridLength(1, [System.Windows.Controls.DataGridLengthUnitType]::Star)
                    } else {
                        $col.Width = New-Object System.Windows.Controls.DataGridLength([double]$defMatch.Width)
                    }
                } else {
                    $col.Width = New-Object System.Windows.Controls.DataGridLength(140)
                }
                [void]$grid.Columns.Add($col)
            }

            Sync-DataGridColumnsProperties -DataGrid $grid
            try { $grid.Items.Refresh() } catch {}
            $dlg.Close()
            Set-Status -Message "Updated columns for $($config.FriendlyName) table ($($grid.Columns.Count) columns active)."
        })
    }

    [void]$dlg.ShowDialog()
}

function Reset-TableColumns {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("Users", "Groups", "Computers", "OUObjects", "Search")]
        [string]$TableName
    )

    $config = $tableColumnCatalog[$TableName]
    if (-not $config) { return }

    $grid = $controls[$config.GridControl]
    if (-not $grid) { return }

    $grid.Columns.Clear()
    foreach ($colDef in $config.DefaultColumns) {
        $col = New-Object System.Windows.Controls.DataGridTextColumn
        $col.Header = $colDef.Header
        $col.Binding = New-Object System.Windows.Data.Binding($colDef.Property)
        if ($colDef.Width -eq "*") {
            $col.Width = New-Object System.Windows.Controls.DataGridLength(1, [System.Windows.Controls.DataGridLengthUnitType]::Star)
        } else {
            $col.Width = New-Object System.Windows.Controls.DataGridLength([double]$colDef.Width)
        }
        [void]$grid.Columns.Add($col)
    }

    Sync-DataGridColumnsProperties -DataGrid $grid
    try { $grid.Items.Refresh() } catch {}
    Set-Status -Message "Reset $($config.FriendlyName) table columns to defaults."
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

    $rawUsers = Get-ADUsersList -SearchText $searchText -StatusFilter $statusFilter -SearchBase $searchBase -Limit ($appConfig.UI.PageSize)
    $users = @($rawUsers | ForEach-Object { $_ })
    $state.CachedUsers = $users
    if ([string]::IsNullOrWhiteSpace($searchText)) {
        $state.AllScopeUsers = $users
    }

    if ($controls['GridUsers']) {
        $controls['GridUsers'].ItemsSource = $users
        Sync-DataGridColumnsProperties -DataGrid $controls['GridUsers']
    }

    $countMsg = if ([string]::IsNullOrWhiteSpace($searchText)) {
        "$($users.Count) users displayed"
    } else {
        "$($users.Count) user(s) matching '$searchText'"
    }

    if ($controls['TxtUsersCountBadge']) {
        $controls['TxtUsersCountBadge'].Text = $countMsg
        $controls['TxtUsersCountBadge'].Foreground = if ($users.Count -gt 0) {
            [System.Windows.Media.BrushConverter]::new().ConvertFromString("#38BDF8")
        } else {
            [System.Windows.Media.BrushConverter]::new().ConvertFromString("#F87171")
        }
    }

    Set-Status -Message "Loaded $($users.Count) user(s)." -Count "$($users.Count) users displayed"
}

function Filter-UsersLive {
    $query = if ($controls['TxtSearchUsers']) { $controls['TxtSearchUsers'].Text.Trim() } else { "" }
    if ([string]::IsNullOrWhiteSpace($query)) {
        if ($state.AllScopeUsers) {
            $allUsers = @($state.AllScopeUsers | ForEach-Object { $_ })
            if ($controls['GridUsers']) {
                $controls['GridUsers'].ItemsSource = $allUsers
                Sync-DataGridColumnsProperties -DataGrid $controls['GridUsers']
            }
            if ($controls['TxtUsersCountBadge']) {
                $controls['TxtUsersCountBadge'].Text = "$($allUsers.Count) users displayed"
                $controls['TxtUsersCountBadge'].Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#9CA3AF")
            }
        }
        return
    }

    $sourceList = if ($state.AllScopeUsers -and $state.AllScopeUsers.Count -gt 0) {
        @($state.AllScopeUsers | ForEach-Object { $_ })
    } elseif ($state.CachedUsers) {
        @($state.CachedUsers | ForEach-Object { $_ })
    } else {
        @()
    }

    $cleanQuery = $query.Trim()
    $asciiQuery = Remove-DiacriticsText $cleanQuery
    $terms = @($cleanQuery)
    if ($asciiQuery -and $asciiQuery -ne $cleanQuery) {
        $terms += $asciiQuery
    }
    $words = $cleanQuery -split '\s+' | Where-Object { $_ }

    $filtered = @($sourceList | Where-Object {
        $u = $_
        $matched = $false

        $composite = "$($u.DisplayName) $($u.GivenName) $($u.Surname) $($u.SamAccountName) $($u.Department) $($u.Title) $($u.Office) $($u.Description) $($u.Mail) $($u.Email) $($u.EmployeeID)"
        $asciiComp = Remove-DiacriticsText $composite

        foreach ($t in $terms) {
            if ($composite -match [regex]::Escape($t) -or $asciiComp -match [regex]::Escape($t)) {
                $matched = $true
                break
            }
        }

        if (-not $matched -and $words.Count -ge 2) {
            $allWords = $true
            foreach ($w in $words) {
                $wAscii = Remove-DiacriticsText $w
                if ($composite -notmatch [regex]::Escape($w) -and $asciiComp -notmatch [regex]::Escape($wAscii)) {
                    $allWords = $false
                    break
                }
            }
            if ($allWords) { $matched = $true }
        }

        $matched
    })

    if ($controls['GridUsers']) {
        $controls['GridUsers'].ItemsSource = @($filtered)
    }

    if ($controls['TxtUsersCountBadge']) {
        $controls['TxtUsersCountBadge'].Text = "$($filtered.Count) user(s) found"
        $controls['TxtUsersCountBadge'].Foreground = if ($filtered.Count -gt 0) {
            [System.Windows.Media.BrushConverter]::new().ConvertFromString("#38BDF8")
        } else {
            [System.Windows.Media.BrushConverter]::new().ConvertFromString("#F87171")
        }
    }

    Set-Status -Message "Found $($filtered.Count) user(s) matching '$query'." -Count "$($filtered.Count) users displayed"
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
        $usersToExport = if ($state.CachedUsers.Count -gt 0) { $state.CachedUsers } else { @(Get-ADUsersList | ForEach-Object { $_ }) }
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
    $controls['TxtSearchUsers'].Add_TextChanged({
        $hasText = -not [string]::IsNullOrEmpty($controls['TxtSearchUsers'].Text)
        if ($controls['TxtSearchUsersPlaceholder']) {
            $controls['TxtSearchUsersPlaceholder'].Visibility = if ($hasText) { 'Collapsed' } else { 'Visible' }
        }
        if ($controls['BtnClearSearchUsers']) {
            $controls['BtnClearSearchUsers'].Visibility = if ($hasText) { 'Visible' } else { 'Collapsed' }
        }

        if (-not $hasText) {
            if ($state.AllScopeUsers) {
                if ($controls['GridUsers']) { $controls['GridUsers'].ItemsSource = @($state.AllScopeUsers) }
                if ($controls['TxtUsersCountBadge']) {
                    $controls['TxtUsersCountBadge'].Text = "$($state.AllScopeUsers.Count) users displayed"
                    $controls['TxtUsersCountBadge'].Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#9CA3AF")
                }
            } else {
                Refresh-Users
            }
        } else {
            Filter-UsersLive
        }
    })

    $controls['TxtSearchUsers'].Add_KeyDown({
        if ($_.Key -eq [System.Windows.Input.Key]::Enter) { Refresh-Users }
    })
}

if ($controls['BtnClearSearchUsers']) {
    $controls['BtnClearSearchUsers'].Add_Click({
        if ($controls['TxtSearchUsers']) {
            $controls['TxtSearchUsers'].Text = ""
            $controls['TxtSearchUsers'].Focus()
        }
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
if ($controls['BtnUserAddColumn']) { $controls['BtnUserAddColumn'].Add_Click({ Show-ColumnChooser -TableName "Users" }) }
if ($controls['BtnUserResetColumns']) { $controls['BtnUserResetColumns'].Add_Click({ Reset-TableColumns -TableName "Users" }) }

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
        if ($_.OriginalSource) {
            try {
                $dep = $_.OriginalSource
                while ($dep -and $dep -isnot [System.Windows.Controls.DataGridRow] -and $dep -isnot [System.Windows.Controls.Primitives.DataGridColumnHeader]) {
                    if ($dep -is [System.Windows.Controls.Primitives.ScrollBar] -or $dep -is [System.Windows.Controls.Primitives.Thumb]) { return }
                    if ($dep -is [System.Windows.Media.Visual] -or $dep -is [System.Windows.Media.Media3D.Visual3D]) {
                        $dep = [System.Windows.Media.VisualTreeHelper]::GetParent($dep)
                    } else {
                        $dep = [System.Windows.LogicalTreeHelper]::GetParent($dep)
                    }
                }
                if ($dep -is [System.Windows.Controls.Primitives.DataGridColumnHeader]) { return }
            } catch {}
        }
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
        $catItem = $controls['CmbGroupCategoryFilter'].SelectedItem
        $catText = if ($catItem -is [System.Windows.Controls.ComboBoxItem]) { $catItem.Content.ToString() } else { "$catItem" }
        if ($catText -match "Security|Distribution") { $catFilter = $catText }
    }

    $scopeFilter = "All"
    if ($controls['CmbGroupScopeFilter'] -and $controls['CmbGroupScopeFilter'].SelectedItem) {
        $scopeItem = $controls['CmbGroupScopeFilter'].SelectedItem
        $scopeText = if ($scopeItem -is [System.Windows.Controls.ComboBoxItem]) { $scopeItem.Content.ToString() } else { "$scopeItem" }
        if ($scopeText -notmatch "All Scopes") { $scopeFilter = $scopeText }
    }

    $rawGroups = Get-ADGroupsList -SearchText $searchText -CategoryFilter $catFilter -ScopeFilter $scopeFilter -Limit ($appConfig.UI.PageSize)
    $groups = @($rawGroups | ForEach-Object { $_ })
    $state.CachedGroups = $groups
    if ($controls['GridGroups']) {
        $controls['GridGroups'].ItemsSource = $groups
        Sync-DataGridColumnsProperties -DataGrid $controls['GridGroups']
    }
    if ($controls['TxtGroupsCountBadge']) {
        $controls['TxtGroupsCountBadge'].Text = "$($groups.Count) groups displayed"
    }
    Set-Status -Message "Loaded $($groups.Count) group(s)." -Count "$($groups.Count) groups displayed"
}

function Filter-GroupsLive {
    $query = if ($controls['TxtSearchGroups']) { $controls['TxtSearchGroups'].Text.Trim() } else { "" }
    
    if ($controls['TxtSearchGroupsPlaceholder']) {
        $controls['TxtSearchGroupsPlaceholder'].Visibility = if ([string]::IsNullOrWhiteSpace($query)) {
            [System.Windows.Visibility]::Visible
        } else {
            [System.Windows.Visibility]::Collapsed
        }
    }
    if ($controls['BtnClearSearchGroups']) {
        $controls['BtnClearSearchGroups'].Visibility = if ([string]::IsNullOrWhiteSpace($query)) {
            [System.Windows.Visibility]::Collapsed
        } else {
            [System.Windows.Visibility]::Visible
        }
    }

    $sourceList = if ($state.CachedGroups) { @($state.CachedGroups | ForEach-Object { $_ }) } else { @() }
    if ($sourceList.Count -eq 0) { return }

    $catFilter = "All"
    if ($controls['CmbGroupCategoryFilter'] -and $controls['CmbGroupCategoryFilter'].SelectedItem) {
        $catItem = $controls['CmbGroupCategoryFilter'].SelectedItem
        $catText = if ($catItem -is [System.Windows.Controls.ComboBoxItem]) { $catItem.Content.ToString() } else { "$catItem" }
        if ($catText -match "Security|Distribution") { $catFilter = $catText }
    }

    $scopeFilter = "All"
    if ($controls['CmbGroupScopeFilter'] -and $controls['CmbGroupScopeFilter'].SelectedItem) {
        $scopeItem = $controls['CmbGroupScopeFilter'].SelectedItem
        $scopeText = if ($scopeItem -is [System.Windows.Controls.ComboBoxItem]) { $scopeItem.Content.ToString() } else { "$scopeItem" }
        if ($scopeText -notmatch "All Scopes") { $scopeFilter = $scopeText }
    }

    $filtered = [System.Collections.Generic.List[PSCustomObject]]::new()
    $cleanAscii = Remove-DiacriticsText $query

    foreach ($g in $sourceList) {
        $include = $true
        if ($catFilter -ne "All" -and $g.GroupCategory -ne $catFilter) {
            $include = $false
        }
        if ($scopeFilter -ne "All" -and $g.GroupScope -ne $scopeFilter) {
            $include = $false
        }
        if ($include -and -not [string]::IsNullOrWhiteSpace($query)) {
            $comp = "$($g.Name) $($g.SamAccountName) $($g.Description) $($g.OUPath)"
            $asciiComp = Remove-DiacriticsText $comp
            if ($comp -notmatch [regex]::Escape($query) -and $asciiComp -notmatch [regex]::Escape($cleanAscii)) {
                $include = $false
            }
        }
        if ($include) {
            $filtered.Add($g)
        }
    }

    $finalArr = @($filtered)
    if ($controls['GridGroups']) {
        $controls['GridGroups'].ItemsSource = $finalArr
        Sync-DataGridColumnsProperties -DataGrid $controls['GridGroups']
    }
    if ($controls['TxtGroupsCountBadge']) {
        $controls['TxtGroupsCountBadge'].Text = "$($finalArr.Count) groups displayed"
    }
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
        $rawM = Get-ADGroupMembersList -Identity $Group.DistinguishedName
        $m = @($rawM | ForEach-Object { $_ })
        $dControls['ListCurrentMembers'].ItemsSource = $m
        $dControls['TxtMemberCount'].Text = "$($m.Count) members"
    }
    & $ReloadMembers

    $SearchUsersAction = {
        $st = if ($dControls['TxtMemberSearch']) { $dControls['TxtMemberSearch'].Text.Trim() } else { "" }
        $rawUsers = if ([string]::IsNullOrWhiteSpace($st)) {
            Get-ADUsersList -Limit 50
        } else {
            Get-ADUsersList -SearchText $st -Limit 50
        }
        $foundUsers = @($rawUsers | ForEach-Object { $_ })
        if ($dControls['ListAvailableUsers']) {
            $dControls['ListAvailableUsers'].ItemsSource = $foundUsers
        }
        if ($dControls['TxtDialogStatus']) {
            if ($foundUsers.Count -eq 0) {
                $dControls['TxtDialogStatus'].Text = if ([string]::IsNullOrWhiteSpace($st)) { "No users found." } else { "No users found matching '$st'." }
            } else {
                $dControls['TxtDialogStatus'].Text = "Found $($foundUsers.Count) user(s)."
            }
        }
    }

    if ($dControls['TxtMemberSearch']) {
        $dControls['TxtMemberSearch'].Add_TextChanged({
            $q = $dControls['TxtMemberSearch'].Text.Trim()
            if ($dControls['TxtMemberSearchPlaceholder']) {
                $dControls['TxtMemberSearchPlaceholder'].Visibility = if ([string]::IsNullOrWhiteSpace($q)) {
                    [System.Windows.Visibility]::Visible
                } else {
                    [System.Windows.Visibility]::Collapsed
                }
            }
            if ($dControls['BtnClearMemberSearch']) {
                $dControls['BtnClearMemberSearch'].Visibility = if ([string]::IsNullOrWhiteSpace($q)) {
                    [System.Windows.Visibility]::Collapsed
                } else {
                    [System.Windows.Visibility]::Visible
                }
            }
        })

        $dControls['TxtMemberSearch'].Add_KeyDown({
            if ($_.Key -eq [System.Windows.Input.Key]::Enter) {
                & $SearchUsersAction
            }
        })
    }

    if ($dControls['BtnClearMemberSearch']) {
        $dControls['BtnClearMemberSearch'].Add_Click({
            if ($dControls['TxtMemberSearch']) {
                $dControls['TxtMemberSearch'].Text = ""
                $dControls['TxtMemberSearch'].Focus()
            }
            if ($dControls['ListAvailableUsers']) {
                $dControls['ListAvailableUsers'].ItemsSource = @()
            }
            if ($dControls['TxtDialogStatus']) {
                $dControls['TxtDialogStatus'].Text = ""
            }
        })
    }

    if ($dControls['BtnSearchMembers']) {
        $dControls['BtnSearchMembers'].Add_Click({ & $SearchUsersAction })
    }

    $AddMemberAction = {
        $sel = if ($dControls['ListAvailableUsers']) { $dControls['ListAvailableUsers'].SelectedItem } else { $null }
        if ($sel) {
            $nameToShow = if ($sel.DisplayName) { $sel.DisplayName } else { $sel.SamAccountName }
            $res = Add-ADPrincipalToGroup -GroupIdentity $Group.DistinguishedName -MemberIdentity $sel.SamAccountName
            if ($res.Success) {
                $dControls['TxtDialogStatus'].Text = "Added '$nameToShow'."
                & $ReloadMembers
            } else {
                $dControls['TxtDialogStatus'].Text = $res.Message
            }
        }
    }

    if ($dControls['BtnAddMember']) {
        $dControls['BtnAddMember'].Add_Click({ & $AddMemberAction })
    }
    if ($dControls['ListAvailableUsers']) {
        $dControls['ListAvailableUsers'].Add_MouseDoubleClick({ & $AddMemberAction })
    }

    $RemoveMemberAction = {
        $selMember = if ($dControls['ListCurrentMembers']) { $dControls['ListCurrentMembers'].SelectedItem } else { $null }
        if ($selMember) {
            $nameToShow = if ($selMember.Name) { $selMember.Name } else { $selMember.SamAccountName }
            $confirm = [System.Windows.MessageBox]::Show(
                "Remove member '$nameToShow' from group '$($Group.Name)'?",
                "Confirm Remove Member",
                [System.Windows.MessageBoxButton]::YesNo,
                [System.Windows.MessageBoxImage]::Question
            )
            if ($confirm -eq [System.Windows.MessageBoxResult]::Yes) {
                $res = Remove-ADPrincipalFromGroup -GroupIdentity $Group.DistinguishedName -MemberIdentity $selMember.DistinguishedName
                if ($res.Success) {
                    $dControls['TxtDialogStatus'].Text = "Removed '$nameToShow'."
                    & $ReloadMembers
                } else {
                    $dControls['TxtDialogStatus'].Text = $res.Message
                }
            }
        }
    }

    if ($dControls['BtnRemoveMember']) {
        $dControls['BtnRemoveMember'].Add_Click({ & $RemoveMemberAction })
    }
    if ($dControls['ListCurrentMembers']) {
        $dControls['ListCurrentMembers'].Add_MouseDoubleClick({ & $RemoveMemberAction })
    }

    if ($dControls['BtnClose']) {
        $dControls['BtnClose'].Add_Click({ $dlg.Close() })
    }
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
        $groupsToExport = if ($state.CachedGroups.Count -gt 0) { $state.CachedGroups } else { @(Get-ADGroupsList | ForEach-Object { $_ }) }
        $res = Export-ADDataToCsv -Data $groupsToExport -FilePath $saveDlg.FileName -Delimiter ($appConfig.Defaults.ExportDelimiter) `
            -PropertiesToExport @('Name', 'SamAccountName', 'GroupCategory', 'GroupScope', 'MemberCount', 'Description', 'OUPath', 'DistinguishedName')

        if ($res.Success) {
            [System.Windows.MessageBox]::Show($res.Message, "Export Successful", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        }
    }
}

if ($controls['BtnSearchGroups']) { $controls['BtnSearchGroups'].Add_Click({ Refresh-Groups }) }
if ($controls['TxtSearchGroups']) {
    $controls['TxtSearchGroups'].Add_TextChanged({ Filter-GroupsLive })
    $controls['TxtSearchGroups'].Add_KeyDown({
        if ($_.Key -eq [System.Windows.Input.Key]::Enter) { Refresh-Groups }
    })
}
if ($controls['BtnClearSearchGroups']) {
    $controls['BtnClearSearchGroups'].Add_Click({
        if ($controls['TxtSearchGroups']) {
            $controls['TxtSearchGroups'].Text = ""
            $controls['TxtSearchGroups'].Focus()
        }
    })
}
if ($controls['CmbGroupScopeFilter'])    { $controls['CmbGroupScopeFilter'].Add_SelectionChanged({ Refresh-Groups }) }
if ($controls['CmbGroupCategoryFilter']) { $controls['CmbGroupCategoryFilter'].Add_SelectionChanged({ Refresh-Groups }) }

if ($controls['BtnNewGroup'])      { $controls['BtnNewGroup'].Add_Click({ Open-GroupDialog }) }
if ($controls['BtnDeleteGroup'])   { $controls['BtnDeleteGroup'].Add_Click({ Delete-GroupAction }) }
if ($controls['BtnExportGroups'])  { $controls['BtnExportGroups'].Add_Click({ Export-GroupsAction }) }
if ($controls['BtnGroupAddColumn']) { $controls['BtnGroupAddColumn'].Add_Click({ Show-ColumnChooser -TableName "Groups" }) }
if ($controls['BtnGroupResetColumns']) { $controls['BtnGroupResetColumns'].Add_Click({ Reset-TableColumns -TableName "Groups" }) }
if ($controls['BtnManageMembers']) {
    $controls['BtnManageMembers'].Add_Click({
        $g = $controls['GridGroups'].SelectedItem
        if ($g) { Open-MemberDialog -Group $g }
    })
}
if ($controls['GridGroups']) {
    $controls['GridGroups'].Add_MouseDoubleClick({
        if ($_.OriginalSource) {
            try {
                $dep = $_.OriginalSource
                while ($dep -and $dep -isnot [System.Windows.Controls.DataGridRow] -and $dep -isnot [System.Windows.Controls.Primitives.DataGridColumnHeader]) {
                    if ($dep -is [System.Windows.Controls.Primitives.ScrollBar] -or $dep -is [System.Windows.Controls.Primitives.Thumb]) { return }
                    if ($dep -is [System.Windows.Media.Visual] -or $dep -is [System.Windows.Media.Media3D.Visual3D]) {
                        $dep = [System.Windows.Media.VisualTreeHelper]::GetParent($dep)
                    } else {
                        $dep = [System.Windows.LogicalTreeHelper]::GetParent($dep)
                    }
                }
                if ($dep -is [System.Windows.Controls.Primitives.DataGridColumnHeader]) { return }
            } catch {}
        }
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
        $flatItems = @($rawItems | ForEach-Object { $_ })
        if ($controls['GridOUObjects']) {
            $controls['GridOUObjects'].ItemsSource = $flatItems
            Sync-DataGridColumnsProperties -DataGrid $controls['GridOUObjects']
        }
        if ($controls['TxtSelectedOUObjectsCount']) {
            $controls['TxtSelectedOUObjectsCount'].Text = "$($flatItems.Count) object(s)"
        }
        Set-Status -Message "Loaded $($flatItems.Count) object(s) in $($selectedNode.Name)."
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

if ($controls['BtnOUAddColumn']) { $controls['BtnOUAddColumn'].Add_Click({ Show-ColumnChooser -TableName "OUObjects" }) }
if ($controls['BtnOUResetColumns']) { $controls['BtnOUResetColumns'].Add_Click({ Reset-TableColumns -TableName "OUObjects" }) }

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
    $rawComputers = Get-ADComputersList -SearchText $search -Limit ($appConfig.UI.PageSize)
    $computers = @($rawComputers | ForEach-Object { $_ })
    $state.CachedComputers = $computers
    if ($controls['GridComputers']) {
        $controls['GridComputers'].ItemsSource = $computers
        Sync-DataGridColumnsProperties -DataGrid $controls['GridComputers']
    }
    if ($controls['TxtComputersCountBadge']) {
        $controls['TxtComputersCountBadge'].Text = "$($computers.Count) computers displayed"
    }
    Set-Status -Message "Loaded $($computers.Count) computer(s)." -Count "$($computers.Count) computers displayed"
}

function Filter-ComputersLive {
    $query = if ($controls['TxtSearchComputers']) { $controls['TxtSearchComputers'].Text.Trim() } else { "" }

    if ($controls['TxtSearchComputersPlaceholder']) {
        $controls['TxtSearchComputersPlaceholder'].Visibility = if ([string]::IsNullOrWhiteSpace($query)) {
            [System.Windows.Visibility]::Visible
        } else {
            [System.Windows.Visibility]::Collapsed
        }
    }
    if ($controls['BtnClearSearchComputers']) {
        $controls['BtnClearSearchComputers'].Visibility = if ([string]::IsNullOrWhiteSpace($query)) {
            [System.Windows.Visibility]::Collapsed
        } else {
            [System.Windows.Visibility]::Visible
        }
    }

    $sourceList = if ($state.CachedComputers) { @($state.CachedComputers | ForEach-Object { $_ }) } else { @() }
    if ($sourceList.Count -eq 0) { return }

    if ([string]::IsNullOrWhiteSpace($query)) {
        if ($controls['GridComputers']) {
            $controls['GridComputers'].ItemsSource = $sourceList
            Sync-DataGridColumnsProperties -DataGrid $controls['GridComputers']
        }
        if ($controls['TxtComputersCountBadge']) {
            $controls['TxtComputersCountBadge'].Text = "$($sourceList.Count) computers displayed"
        }
        return
    }

    $filtered = [System.Collections.Generic.List[PSCustomObject]]::new()
    $cleanAscii = Remove-DiacriticsText $query

    foreach ($c in $sourceList) {
        $comp = "$($c.Name) $($c.DNSHostName) $($c.OperatingSystem) $($c.Description) $($c.OUPath) $($c.SamAccountName)"
        $asciiComp = Remove-DiacriticsText $comp
        if ($comp -match [regex]::Escape($query) -or $asciiComp -match [regex]::Escape($cleanAscii)) {
            $filtered.Add($c)
        }
    }

    $finalArr = @($filtered)
    if ($controls['GridComputers']) {
        $controls['GridComputers'].ItemsSource = $finalArr
        Sync-DataGridColumnsProperties -DataGrid $controls['GridComputers']
    }
    if ($controls['TxtComputersCountBadge']) {
        $controls['TxtComputersCountBadge'].Text = "$($finalArr.Count) computers displayed"
    }
}

if ($controls['BtnSearchComputers']) { $controls['BtnSearchComputers'].Add_Click({ Refresh-Computers }) }
if ($controls['TxtSearchComputers']) {
    $controls['TxtSearchComputers'].Add_TextChanged({ Filter-ComputersLive })
    $controls['TxtSearchComputers'].Add_KeyDown({
        if ($_.Key -eq [System.Windows.Input.Key]::Enter) { Refresh-Computers }
    })
}
if ($controls['BtnClearSearchComputers']) {
    $controls['BtnClearSearchComputers'].Add_Click({
        if ($controls['TxtSearchComputers']) {
            $controls['TxtSearchComputers'].Text = ""
            $controls['TxtSearchComputers'].Focus()
        }
    })
}
if ($controls['BtnComputerAddColumn']) { $controls['BtnComputerAddColumn'].Add_Click({ Show-ColumnChooser -TableName "Computers" }) }
if ($controls['BtnComputerResetColumns']) { $controls['BtnComputerResetColumns'].Add_Click({ Reset-TableColumns -TableName "Computers" }) }

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
            $computersToExport = if ($state.CachedComputers.Count -gt 0) { $state.CachedComputers } else { @(Get-ADComputersList | ForEach-Object { $_ }) }
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
function Filter-ComboAttributes {
    param(
        [System.Windows.Controls.ComboBox]$Combo,
        [string]$Query,
        [bool]$IncludeAny = $false,
        [System.Windows.Controls.TextBlock]$OutcomeText = $null,
        [System.Windows.Controls.Border]$OutcomeBorder = $null,
        [System.Windows.Controls.TextBox]$SyncSearchBox = $null,
        [bool]$OpenDropDown = $true
    )

    if ($state.IsFilteringAttributes -or -not $Combo) { return }
    $state.IsFilteringAttributes = $true
    try {
        $editBox = $Combo.Template.FindName("PART_EditableTextBox", $Combo)
        $caret = if ($editBox) { $editBox.CaretIndex } else { 0 }
        $trimmed = if ($Query) { $Query.Trim() } else { "" }

        $allList = if ($state.MasterAttributeList -and $state.MasterAttributeList.Count -gt 0) {
            $state.MasterAttributeList
        } else {
            [System.Collections.Generic.List[string]]::new()
        }

        if ([string]::IsNullOrWhiteSpace($trimmed)) {
            $fullList = [System.Collections.Generic.List[string]]::new()
            if ($IncludeAny) { [void]$fullList.Add("Any Attribute") }
            foreach ($item in $allList) { [void]$fullList.Add($item) }

            if ($null -eq $Combo.ItemsSource -and $Combo.Items.Count -gt 0) {
                $Combo.Items.Clear()
            }
            $Combo.ItemsSource = @($fullList)
            if ($OpenDropDown) {
                $Combo.IsDropDownOpen = $true
            }
            if ($editBox) {
                $editBox.Text = ""
                $editBox.CaretIndex = 0
            }

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
        if ($IncludeAny -and "Any Attribute".IndexOf($trimmed, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
            [void]$matched.Add("Any Attribute")
        }
        foreach ($attr in $allList) {
            if ($attr.IndexOf($trimmed, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                [void]$matched.Add($attr)
            }
        }

        if ($matched.Count -gt 0) {
            if ($null -eq $Combo.ItemsSource -and $Combo.Items.Count -gt 0) {
                $Combo.Items.Clear()
            }
            $Combo.ItemsSource = @($matched)
            if ($OpenDropDown) {
                $Combo.IsDropDownOpen = $true
            }

            # Select exact match or first match so user has an active, visible selection in the popup
            $exact = $matched | Where-Object { $_ -eq $trimmed } | Select-Object -First 1
            $selected = if ($exact) { $exact } else { $matched[0] }
            $Combo.SelectedItem = $selected

            if ($editBox) {
                $editBox.Text = $Query
                $editBox.CaretIndex = [Math]::Min($caret, $Query.Length)
            }

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
            if ($null -eq $Combo.ItemsSource -and $Combo.Items.Count -gt 0) {
                $Combo.Items.Clear()
            }
            $Combo.ItemsSource = @()
            $Combo.SelectedItem = $null
            $Combo.Text = $trimmed
            if ($editBox) {
                $editBox.Text = $Query
                $editBox.CaretIndex = [Math]::Min($caret, $Query.Length)
            }

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

function Attach-SearchableAttributeDropdown {
    param(
        [System.Windows.Controls.ComboBox]$Combo,
        [System.Collections.Generic.List[string]]$MasterList,
        [System.Windows.Controls.TextBlock]$OutcomeText,
        [System.Windows.Controls.Border]$OutcomeBorder,
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
    }.GetNewClosure())

    # Direct click on edit box: focus, select all, and ensure dropdown is visible
    $editBox.Add_PreviewMouseLeftButtonDown({
        param($s, $e)
        if (-not $editBox.IsKeyboardFocused) {
            $editBox.Focus()
            $editBox.SelectAll()
            $Combo.IsDropDownOpen = $true
            $e.Handled = $true
        }
    }.GetNewClosure())

    # DropDownOpened: when user clicks the toggle arrow, display full list if blank, or filtered list if text entered
    $Combo.Add_DropDownOpened({
        if ($state.IsFilteringAttributes) { return }
        $currentText = if ($editBox.Text) { $editBox.Text.Trim() } else { "" }
        $selectedText = if ($Combo.SelectedItem) {
            if ($Combo.SelectedItem -is [System.Windows.Controls.ComboBoxItem]) { $Combo.SelectedItem.Content.ToString() } else { $Combo.SelectedItem.ToString() }
        } else { "" }

        if ([string]::IsNullOrWhiteSpace($currentText)) {
            $fullList = [System.Collections.Generic.List[string]]::new()
            if ($IncludeAnyOption) { [void]$fullList.Add("Any Attribute") }
            foreach ($item in $MasterList) { [void]$fullList.Add($item) }
            $state.IsFilteringAttributes = $true
            try {
                if ($null -eq $Combo.ItemsSource -and $Combo.Items.Count -gt 0) {
                    $Combo.Items.Clear()
                }
                $Combo.ItemsSource = @($fullList)
                if ($selectedText) { $Combo.SelectedItem = $selectedText }
            }
            finally {
                $state.IsFilteringAttributes = $false
            }
        } else {
            Filter-ComboAttributes -Combo $Combo -Query $currentText -IncludeAny $IncludeAnyOption `
                -OutcomeText $OutcomeText -OutcomeBorder $OutcomeBorder -OpenDropDown $true
        }
    }.GetNewClosure())

    # Keyboard navigation: Down/Up to browse, Enter to confirm, Escape to cancel
    $editBox.Add_PreviewKeyDown({
        param($s, $e)
        if ($e.Key -eq [System.Windows.Input.Key]::Down) {
            if (-not $Combo.IsDropDownOpen) {
                $Combo.IsDropDownOpen = $true
                $e.Handled = $true
            }
        } elseif ($e.Key -eq [System.Windows.Input.Key]::Enter) {
            if (-not $Combo.SelectedItem -and $Combo.Items.Count -gt 0) {
                $Combo.SelectedItem = $Combo.Items[0]
            }
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
            $state.IsFilteringAttributes = $true
            try {
                if ($null -eq $Combo.ItemsSource -and $Combo.Items.Count -gt 0) {
                    $Combo.Items.Clear()
                }
                $Combo.ItemsSource = @($fullList)
            } finally {
                $state.IsFilteringAttributes = $false
            }
            $Combo.IsDropDownOpen = $false
            $e.Handled = $true
        }
    }.GetNewClosure())

    # Real-time filtering when user types directly in the dropdown text box
    $editBox.Add_TextChanged({
        if ($state.IsFilteringAttributes) { return }
        $selectedText = if ($Combo.SelectedItem) {
            if ($Combo.SelectedItem -is [System.Windows.Controls.ComboBoxItem]) { $Combo.SelectedItem.Content.ToString() } else { $Combo.SelectedItem.ToString() }
        } else { "" }
        if ($selectedText -and $editBox.Text -eq $selectedText) { return }

        Filter-ComboAttributes -Combo $Combo -Query $editBox.Text -IncludeAny $IncludeAnyOption `
            -OutcomeText $OutcomeText -OutcomeBorder $OutcomeBorder -OpenDropDown $true
    }.GetNewClosure())

    # Selection change: close dropdown and show confirmation badge
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
    }.GetNewClosure())
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

            if ($null -eq $controls['CmbFilterAttr'].ItemsSource -and $controls['CmbFilterAttr'].Items.Count -gt 0) {
                $controls['CmbFilterAttr'].Items.Clear()
            }
            $controls['CmbFilterAttr'].ItemsSource = @($allAttrNames)
            $controls['CmbFilterAttr'].SelectedItem = if ($allAttrNames.Contains($cur)) { $cur } else { "sAMAccountName" }

            Attach-SearchableAttributeDropdown -Combo $controls['CmbFilterAttr'] `
                -MasterList $state.MasterAttributeList `
                -OutcomeText $controls['TxtSearchAttrOutcome'] `
                -OutcomeBorder $controls['BorderSearchAttrOutcome'] `
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

            if ($null -eq $controls['CmbRegexTargetAttr'].ItemsSource -and $controls['CmbRegexTargetAttr'].Items.Count -gt 0) {
                $controls['CmbRegexTargetAttr'].Items.Clear()
            }
            $controls['CmbRegexTargetAttr'].ItemsSource = @($regexAttrs)
            $controls['CmbRegexTargetAttr'].SelectedItem = if ($regexAttrs.Contains($curRegex)) { $curRegex } else { "Any Attribute" }

            Attach-SearchableAttributeDropdown -Combo $controls['CmbRegexTargetAttr'] `
                -MasterList $state.MasterAttributeList `
                -OutcomeText $null `
                -OutcomeBorder $null `
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

    if ($state.IsFilteringAttributes) { return }

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

    if ($controls['CmbFilterAttr']) {
        Filter-ComboAttributes -Combo $controls['CmbFilterAttr'] -Query $query -IncludeAny $false `
            -OutcomeText $controls['TxtSearchAttrOutcome'] -OutcomeBorder $controls['BorderSearchAttrOutcome'] `
            -OpenDropDown $true
    }
    if ($controls['CmbRegexTargetAttr']) {
        Filter-ComboAttributes -Combo $controls['CmbRegexTargetAttr'] -Query $query -IncludeAny $true `
            -OpenDropDown $false
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
        Sync-DataGridColumnsProperties -DataGrid $controls['GridSearchResults']
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

if ($controls['BtnSearchAddColumn']) { $controls['BtnSearchAddColumn'].Add_Click({ Show-ColumnChooser -TableName "Search" }) }
if ($controls['BtnSearchResetColumns']) { $controls['BtnSearchResetColumns'].Add_Click({ Reset-TableColumns -TableName "Search" }) }
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
        # Determine column list in the order specified by the user's SELECT statement
        $cols = [System.Collections.Generic.List[string]]::new()
        if ($res.PropertiesLoaded -and $res.PropertiesLoaded -ne "*") {
            foreach ($c in ($res.PropertiesLoaded -split ',')) {
                $trimmedCol = $c.Trim()
                if ($trimmedCol -and -not $cols.Contains($trimmedCol)) {
                    [void]$cols.Add($trimmedCol)
                }
            }
        } else {
            # Collect all distinct property names across returned items
            $seenProps = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($r in $res.Results) {
                foreach ($p in $r.PSObject.Properties) {
                    if (-not $seenProps.Contains($p.Name)) {
                        [void]$seenProps.Add($p.Name)
                        [void]$cols.Add($p.Name)
                    }
                }
            }
        }

        # Ensure DistinguishedName is included for complete directory object tracking
        if (-not ($cols | Where-Object { $_ -eq "DistinguishedName" })) {
            [void]$cols.Add("DistinguishedName")
        }

        # Build dynamic DataTable for reliable WPF DataGrid binding and row representation
        $dt = New-Object System.Data.DataTable
        foreach ($c in $cols) {
            [void]$dt.Columns.Add($c, [string])
        }

        $uniformList = New-Object System.Collections.Generic.List[PSCustomObject]
        foreach ($r in $res.Results) {
            $row = $dt.NewRow()
            $h = [ordered]@{}
            foreach ($c in $cols) {
                $prop = $r.PSObject.Properties[$c]
                $valStr = ""
                if ($null -ne $prop -and $null -ne $prop.Value) {
                    $val = $prop.Value
                    if ($val -is [System.Collections.IEnumerable] -and $val -isnot [string]) {
                        $valStr = ($val -join "; ")
                    } else {
                        $valStr = [string]$val
                    }
                }
                $row[$c] = $valStr
                $h[$c] = $valStr
            }
            $dt.Rows.Add($row)
            $uniformList.Add([PSCustomObject]$h)
        }

        # Save both uniform list for exports and data table for grid
        $state.CurrentSqlResults = $uniformList

        if ($controls['GridSqlResults']) {
            $controls['GridSqlResults'].Columns.Clear()
            foreach ($col in $dt.Columns) {
                $dgCol = New-Object System.Windows.Controls.DataGridTextColumn
                $dgCol.Header = $col.ColumnName
                $dgCol.Binding = New-Object System.Windows.Data.Binding($col.ColumnName)
                $dgCol.CanUserSort = $true
                if ($col.ColumnName -eq "DistinguishedName") {
                    $dgCol.Width = New-Object System.Windows.Controls.DataGridLength(1, [System.Windows.Controls.DataGridLengthUnitType]::Star)
                } else {
                    $dgCol.Width = New-Object System.Windows.Controls.DataGridLength(150, [System.Windows.Controls.DataGridLengthUnitType]::Pixel)
                }
                $controls['GridSqlResults'].Columns.Add($dgCol)
            }
            $controls['GridSqlResults'].ItemsSource = $dt.DefaultView
        }

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

    $rawItems = if ($isClasses) { Get-ADSchemaClasses } else { Get-ADSchemaAttributes }
    $items = if ([string]::IsNullOrWhiteSpace($filterText)) {
        $rawItems
    } else {
        @($rawItems | Where-Object { $_.Name -match [regex]::Escape($filterText) })
    }

    $state.CachedSchema = $items
    if ($controls['GridSchema']) {
        $controls['GridSchema'].Columns.Clear()
        if ($isClasses) {
            $colDefs = @(
                @{ Header = "Class Name"; Binding = "Name"; Width = 190 },
                @{ Header = "Subclass Of"; Binding = "SubClassOf"; Width = 140 },
                @{ Header = "OID (governsID)"; Binding = "OID"; Width = 200 },
                @{ Header = "Mandatory"; Binding = "MandatoryCount"; Width = 90 },
                @{ Header = "Optional"; Binding = "OptionalCount"; Width = 90 },
                @{ Header = "Distinguished Name"; Binding = "DistinguishedName"; Width = 1 }
            )
        } else {
            $colDefs = @(
                @{ Header = "Attribute Name"; Binding = "Name"; Width = 190 },
                @{ Header = "OID (attributeID)"; Binding = "OID"; Width = 200 },
                @{ Header = "Syntax OID"; Binding = "Syntax"; Width = 180 },
                @{ Header = "Single-Valued"; Binding = "IsSingleValued"; Width = 100 },
                @{ Header = "In Global Catalog"; Binding = "InGlobalCatalog"; Width = 130 },
                @{ Header = "Distinguished Name"; Binding = "DistinguishedName"; Width = 1 }
            )
        }
        foreach ($cd in $colDefs) {
            $col = New-Object System.Windows.Controls.DataGridTextColumn
            $col.Header = $cd.Header
            $col.Binding = New-Object System.Windows.Data.Binding($cd.Binding)
            $col.CanUserSort = $true
            if ($cd.Width -eq 1) {
                $col.Width = New-Object System.Windows.Controls.DataGridLength(1, [System.Windows.Controls.DataGridLengthUnitType]::Star)
            } else {
                $col.Width = New-Object System.Windows.Controls.DataGridLength($cd.Width, [System.Windows.Controls.DataGridLengthUnitType]::Pixel)
            }
            $controls['GridSchema'].Columns.Add($col)
        }
        $controls['GridSchema'].ItemsSource = $items
    }
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
        $defaultLabel = "Default ($defaultServer)"
        [void]$controls['CmbActiveProfile'].Items.Add($defaultLabel)
        if ($appConfig.Profiles) {
            foreach ($p in $appConfig.Profiles) {
                [void]$controls['CmbActiveProfile'].Items.Add("$($p.Name)")
            }
        }
        $controls['CmbActiveProfile'].SelectedIndex = 0
        $controls['CmbActiveProfile'].ToolTip = "Active Directory Profile / Server: $defaultLabel"

        if (-not $controls['CmbActiveProfile'].Tag) {
            $controls['CmbActiveProfile'].Tag = "Initialized"
            $controls['CmbActiveProfile'].Add_SelectionChanged({
                if ($controls['CmbActiveProfile'].SelectedItem) {
                    $sel = [string]$controls['CmbActiveProfile'].SelectedItem
                    $controls['CmbActiveProfile'].ToolTip = "Active Directory Profile / Server: $sel"
                }
            })
        }
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
    Populate-SearchAttributeDropdowns
})

# Show Main Window
[void]$window.ShowDialog()