<#
.SYNOPSIS
    Active Directory Management Studio - Modern Windows Server Administration Suite
.DESCRIPTION
    Professional WPF/XAML Active Directory & LDAP Administration Suite featuring
    Visual LDAP Filter Builder, Raw Attribute Editor & UAC Bitmask Decoder, LDAP-SQL Console,
    RFC 2849 LDIF Studio, Object Compare & Diff, Security Audits & Executive Reports,
    AD Schema Browser, Bulk Operations Engine, and Connection Profiles with Diagnostics.
#>

[CmdletBinding()]
param(
    [string]$InitialTool = "",
    [switch]$Standalone
)

# Ensure script runs in Single Thread Apartment (STA) mode for WPF
if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne [System.Threading.ApartmentState]::STA) {
    Write-Host "Restarting Active Directory Studio in STA mode..." -ForegroundColor Cyan
    $powershellExe = (Get-Process -Id $PID).Path
    $argList = "-STA -NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    if (-not [string]::IsNullOrWhiteSpace($InitialTool)) {
        $argList += " -InitialTool `"$InitialTool`""
    }
    if ($Standalone) {
        $argList += " -Standalone"
    }
    Start-Process -FilePath $powershellExe -ArgumentList $argList
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
Import-Module (Join-Path $modulesPath "AclService.psm1") -Force
Import-Module (Join-Path $modulesPath "KerberosService.psm1") -Force
Import-Module (Join-Path $modulesPath "DiagnosticService.psm1") -Force
Import-Module (Join-Path $modulesPath "ReplicationService.psm1") -Force
Import-Module (Join-Path $modulesPath "GpoService.psm1") -Force
Import-Module (Join-Path $modulesPath "NetworkService.psm1") -Force

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
    $loadedWin = [System.Windows.Markup.XamlReader]::Load($reader)

    # Inherit window resources and ensure newly loaded modal dialog inherits active theme
    if ($window -and $loadedWin -ne $window) {
        foreach ($key in $window.Resources.Keys) {
            $loadedWin.Resources[$key] = $window.Resources[$key]
        }
        $loadedWin.Add_Loaded({
            $currTheme = if ($state -and $state.CurrentTheme) { $state.CurrentTheme } else { "Dark" }
            if ($currTheme -eq "Light" -and (Get-Command Apply-ThemeNode -ErrorAction SilentlyContinue)) {
                Apply-ThemeNode $this "Light"
            }
        })
    }
    if ($state -and $state.CurrentTheme -eq "Light") {
        if (Get-Command Apply-ThemeNode -ErrorAction SilentlyContinue) {
            Apply-ThemeNode $loadedWin "Light"
        }
    }

    return $loadedWin
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

# Initialize External Tools collection safely
$initialTools = [System.Collections.ArrayList]::new()
if ($appConfig.ExternalTools) {
    foreach ($t in $appConfig.ExternalTools) { [void]$initialTools.Add($t) }
}

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
    NavHistory             = [System.Collections.Generic.List[string]]::new()
    NavIndex               = -1
    IsNavigatingHistory    = $false
    BasketItems            = [System.Collections.ObjectModel.ObservableCollection[psobject]]::new()
    RequestLogs            = [System.Collections.ObjectModel.ObservableCollection[psobject]]::new()
    IsReadOnlyProfile      = $false
    Bookmarks              = [System.Collections.Generic.List[string]]::new()
    CachedRecycleBin       = @()
    ExternalTools          = $initialTools
    CachedPartitions       = @()
    SearchHistory          = [System.Collections.Generic.List[psobject]]::new()
    PinnedSearches         = [System.Collections.Generic.List[psobject]]::new()
    UsersPage              = 1
    UsersCurrentList       = @()
    SearchPage             = 1
    CachedOUTree           = $null
    DiscoveredDCs          = @()
    CurrentHtmlObject      = $null
    CurrentHtmlDN          = ""
    CurrentHtmlTemplate    = "Technical"
    CurrentHtmlRaw         = ""
    CurrentTheme           = if ($appConfig.UI.Theme) { $appConfig.UI.Theme } else { "Dark" }
    WorkspaceMode          = if ($appConfig.UI.WorkspaceMode) { $appConfig.UI.WorkspaceMode } else { "Tabs" }
    AllowMultiWindow       = if ($null -ne $appConfig.UI.AllowMultiWindow) { $appConfig.UI.AllowMultiWindow } else { $true }
    RestoreTabsOnStartup   = if ($null -ne $appConfig.UI.RestoreTabsOnStartup) { $appConfig.UI.RestoreTabsOnStartup } else { $true }
    OpenTabs               = [System.Collections.ObjectModel.ObservableCollection[psobject]]::new()
    ActiveTabId            = "Dashboard"
    DetachedWindows        = @{}
    IsSelectingTab         = $false
    TabDragContext         = @{
        IsMouseDown  = $false
        IsDragging   = $false
        StartPoint   = [System.Windows.Point]::new(0, 0)
        SourceTabId  = $null
        SourceBorder = $null
    }
}

# Master Directory & Tools Catalog for Tabs, Detached Windows, and Navigation
$global:PanelCatalog = [ordered]@{
    'Dashboard'            = [PSCustomObject]@{ Title = 'Dashboard';            Icon = '📊'; Category = 'Directory Services'; ToolTip = 'Overview & directory health dashboard' }
    'Users'                = [PSCustomObject]@{ Title = 'Users';                Icon = '👥'; Category = 'Directory Services'; ToolTip = 'User accounts, provisioning & security attributes' }
    'Groups'               = [PSCustomObject]@{ Title = 'Groups';               Icon = '🛡️'; Category = 'Directory Services'; ToolTip = 'Security & distribution group membership manager' }
    'OUs'                  = [PSCustomObject]@{ Title = 'Org. Units (OUs)';     Icon = '📁'; Category = 'Directory Services'; ToolTip = 'Organizational Units hierarchy & containment tree' }
    'Computers'            = [PSCustomObject]@{ Title = 'Computers';            Icon = '💻'; Category = 'Directory Services'; ToolTip = 'Domain joined workstations, servers & DCs' }
    'RecycleBin'           = [PSCustomObject]@{ Title = 'AD Recycle Bin';       Icon = '♻️'; Category = 'Directory Services'; ToolTip = 'Tombstone reanimation & deleted object restore' }
    'DirectorySearch'      = [PSCustomObject]@{ Title = 'Directory Search';     Icon = '🔍'; Category = 'Softerra LDAP Suite'; ToolTip = 'Advanced LDAP search filter builder & tree browser' }
    'LdapSql'              = [PSCustomObject]@{ Title = 'LDAP-SQL Console';     Icon = '⚡'; Category = 'Softerra LDAP Suite'; ToolTip = 'SQL query engine for LDAP directory databases' }
    'AttributeEditor'      = [PSCustomObject]@{ Title = 'Attribute Editor';     Icon = '📋'; Category = 'Softerra LDAP Suite'; ToolTip = 'Raw multi-syntax attribute inspector & hex editor' }
    'HtmlView'             = [PSCustomObject]@{ Title = 'HTML Dossier View';    Icon = '📄'; Category = 'Softerra LDAP Suite'; ToolTip = 'Rich HTML object dossiers & report generator' }
    'ObjectCompare'        = [PSCustomObject]@{ Title = 'Object Compare';       Icon = '⚖️'; Category = 'Softerra LDAP Suite'; ToolTip = 'Side-by-side attribute difference analyzer' }
    'LdifStudio'           = [PSCustomObject]@{ Title = 'LDIF Import/Export';   Icon = '📝'; Category = 'Softerra LDAP Suite'; ToolTip = 'LDIF syntax validator, bulk export & batch engine' }
    'AuditReports'         = [PSCustomObject]@{ Title = 'Audit & Reports';      Icon = '📑'; Category = 'Softerra LDAP Suite'; ToolTip = 'Pre-configured compliance & directory security audits' }
    'SchemaBrowser'        = [PSCustomObject]@{ Title = 'Schema Browser';       Icon = '🧬'; Category = 'Softerra LDAP Suite'; ToolTip = 'Active Directory schema classes, syntax & OIDs' }
    'BulkEditor'           = [PSCustomObject]@{ Title = 'Bulk Modify Studio';   Icon = '✏️'; Category = 'Softerra LDAP Suite'; ToolTip = 'Bulk attribute modifiers & batch operations' }
    'Basket'               = [PSCustomObject]@{ Title = 'Selection Basket';     Icon = '🧺'; Category = 'Softerra LDAP Suite'; ToolTip = 'Multi-object staging basket for bulk operations' }
    'RequestLog'           = [PSCustomObject]@{ Title = 'LDAP Request Log';     Icon = '📜'; Category = 'Softerra LDAP Suite'; ToolTip = 'Real-time protocol request & diagnostic logger' }
    'SecurityAcl'          = [PSCustomObject]@{ Title = 'Security & ACL';       Icon = '🔒'; Category = 'Advanced Tools';      ToolTip = 'Visual DACL, Effective Permissions & SDProp inspector' }
    'KerberosSuite'        = [PSCustomObject]@{ Title = 'Kerberos & Auth';      Icon = '🎟️'; Category = 'Advanced Tools';      ToolTip = 'Kerberos tickets, SPN analyzer & User Rights Assignment' }
    'ReplicationSuite'     = [PSCustomObject]@{ Title = 'AD Replication';       Icon = '🔄'; Category = 'Advanced Tools';      ToolTip = 'Multi-DC replication latency, metadata & USN sync' }
    'DiagnosticsToolbox'   = [PSCustomObject]@{ Title = 'Diagnostics Hub';      Icon = '🧰'; Category = 'Advanced Tools';      ToolTip = 'Circular group detection, lockout traces & encoders' }
    'NetworkDiagnostics'   = [PSCustomObject]@{ Title = 'Network & Shares';     Icon = '📡'; Category = 'Advanced Tools';      ToolTip = 'UNC share tester, certificate chains & DC port scanner' }
    'ServerMonitor'        = [PSCustomObject]@{ Title = 'Server Monitor';       Icon = '🖥️'; Category = 'System';              ToolTip = 'RootDSE metadata, active connections & telemetry' }
    'Connections'          = [PSCustomObject]@{ Title = 'Connections';          Icon = '🌐'; Category = 'System';              ToolTip = 'Directory server connection profiles & credentials' }
    'Settings'             = [PSCustomObject]@{ Title = 'Settings';             Icon = '⚙️'; Category = 'System';              ToolTip = 'Application configuration & workspace preferences' }
}

function Test-CanModifyDirectory {
    if ($state.IsReadOnlyProfile) {
        [System.Windows.MessageBox]::Show(
            "This operation is blocked because the active server connection profile is configured as READ-ONLY.`r`n`r`nTo modify directory objects, switch to a read-write profile or uncheck 'Read-Only Server Profile' in Connection Settings.",
            "🔒 Protected Read-Only Profile",
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Warning
        )
        return $false
    }
    return $true
}

function Invoke-ExternalTool {
    param (
        [Parameter(Mandatory = $true)]
        $Tool,
        [Parameter(Mandatory = $true)]
        $TargetObject
    )

    try {
        $cmd = $Tool.Command
        $argsPattern = $Tool.Arguments

        $sam = ""
        $hostName = ""
        $dn = ""
        $upn = ""
        $mail = ""
        $dispName = ""
        $server = if ($state.Config -and $state.Config.Domain -and $state.Config.Domain.DomainController) { $state.Config.Domain.DomainController } else { $state.DomainName }

        if ($TargetObject.SamAccountName) { $sam = $TargetObject.SamAccountName }
        elseif ($TargetObject.sAMAccountName) { $sam = $TargetObject.sAMAccountName }
        elseif ($TargetObject.Name) { $sam = $TargetObject.Name }

        if ($TargetObject.DNSHostName) { $hostName = $TargetObject.DNSHostName }
        elseif ($TargetObject.dNSHostName) { $hostName = $TargetObject.dNSHostName }
        elseif ($sam -match '\$$') { $hostName = $sam.TrimEnd('$') }
        elseif ($TargetObject.Name) { $hostName = $TargetObject.Name }

        if ($TargetObject.DistinguishedName) { $dn = $TargetObject.DistinguishedName }
        elseif ($TargetObject.DN) { $dn = $TargetObject.DN }

        if ($TargetObject.UserPrincipalName) { $upn = $TargetObject.UserPrincipalName }
        elseif ($TargetObject.Email) { $upn = $TargetObject.Email }

        if ($TargetObject.Email) { $mail = $TargetObject.Email }
        elseif ($TargetObject.Mail) { $mail = $TargetObject.Mail }

        if ($TargetObject.DisplayName) { $dispName = $TargetObject.DisplayName }
        elseif ($TargetObject.Name) { $dispName = $TargetObject.Name }
        else { $dispName = $sam }

        $evaluatedArgs = "$argsPattern"
        $evaluatedArgs = $evaluatedArgs -ireplace '%sAMAccountName%', $sam
        $evaluatedArgs = $evaluatedArgs -ireplace '%username%', $sam
        $evaluatedArgs = $evaluatedArgs -ireplace '%dNSHostName%', $hostName
        $evaluatedArgs = $evaluatedArgs -ireplace '%host%', $hostName
        $evaluatedArgs = $evaluatedArgs -ireplace '%distinguishedName%', $dn
        $evaluatedArgs = $evaluatedArgs -ireplace '%dn%', $dn
        $evaluatedArgs = $evaluatedArgs -ireplace '%userPrincipalName%', $upn
        $evaluatedArgs = $evaluatedArgs -ireplace '%upn%', $upn
        $evaluatedArgs = $evaluatedArgs -ireplace '%mail%', $mail
        $evaluatedArgs = $evaluatedArgs -ireplace '%email%', $mail
        $evaluatedArgs = $evaluatedArgs -ireplace '%cn%', $dispName
        $evaluatedArgs = $evaluatedArgs -ireplace '%name%', $dispName
        $evaluatedArgs = $evaluatedArgs -ireplace '%server%', $server

        Set-Status -Message "Launching external tool '$($Tool.Name)': $cmd $evaluatedArgs..."
        Start-Process -FilePath $cmd -ArgumentList $evaluatedArgs
        Log-LdapRequest -Operation "EXTERNAL_TOOL" -TargetDN $dn -FilterOrPayload "$cmd $evaluatedArgs" -DurationMs 0 -Status "SUCCESS" -Details "Launched external tool: $($Tool.Name)"
    }
    catch {
        [System.Windows.MessageBox]::Show("Failed to launch external tool '$($Tool.Name)': $_", "Tool Execution Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        Set-Status -Message "Failed to execute external tool: $_"
    }
}

function Show-ObjectHtmlDossier {
    param (
        $TargetObject,
        [string]$TargetDN = ""
    )

    try {
        $dn = $TargetDN
        if (-not $dn -and $TargetObject) {
            $dn = if ($TargetObject.DistinguishedName) { $TargetObject.DistinguishedName } else { $TargetObject.DN }
        }

        if (-not $dn) {
            [System.Windows.MessageBox]::Show("No distinguished name available for selected object.", "Cannot Generate Dossier", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            return
        }

        Set-Status -Message "Generating HTML Dossier Report Card for $dn..."
        $attrs = Get-ADObjectRawAttributes -DistinguishedName $dn -IncludeOperational:$true
        $tempPath = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "AD_Dossier_$([System.IO.Path]::GetRandomFileName()).html")

        $res = Export-ADObjectToHtml -ObjectDetail $TargetObject -Attributes $attrs -FilePath $tempPath
        if ($res.Success) {
            Start-Process $tempPath
            Set-Status -Message "HTML Dossier opened in default browser."
        } else {
            [System.Windows.MessageBox]::Show("Failed to generate HTML report: $($res.Message)", "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        }
    }
    catch {
        [System.Windows.MessageBox]::Show("Error displaying HTML dossier: $_", "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
    }
}

function Populate-ExternalToolsMenu ($parentMenuItem, [scriptblock]$getTargetObjectScript) {
    if (-not $parentMenuItem) { return }
    $parentMenuItem.Items.Clear()
    foreach ($tool in $state.ExternalTools) {
        $item = [System.Windows.Controls.MenuItem]::new()
        $item.Header = "▶ $($tool.Name)"
        $capturedTool = $tool
        $item.Add_Click({
            $target = & $getTargetObjectScript
            if ($target) {
                Invoke-ExternalTool -Tool $capturedTool -TargetObject $target
            } else {
                [System.Windows.MessageBox]::Show("Please select an object in the table first.", "No Object Selected", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            }
        })
        [void]$parentMenuItem.Items.Add($item)
    }
}

function Populate-AllExternalToolsMenus {
    Populate-ExternalToolsMenu $controls['CtxUserExternalTools'] { if ($controls['GridUsers']) { $controls['GridUsers'].SelectedItem } else { $null } }
    Populate-ExternalToolsMenu $controls['CtxCompExternalTools'] { if ($controls['GridComputers']) { $controls['GridComputers'].SelectedItem } else { $null } }
    Populate-ExternalToolsMenu $controls['CtxOUObjExternalTools'] { if ($controls['GridOUObjects']) { $controls['GridOUObjects'].SelectedItem } else { $null } }
    Populate-ExternalToolsMenu $controls['CtxSearchExternalTools'] { if ($controls['GridSearchResults']) { $controls['GridSearchResults'].SelectedItem } else { $null } }
}

#region Application Theme Engine (Dark / Light Mode)
$script:OriginalBrushes = @{}
$script:BrushConverter = New-Object System.Windows.Media.BrushConverter

function Convert-BrushToHex ($brush) {
    if (-not $brush) { return "" }
    if ($brush -is [System.Windows.Media.SolidColorBrush]) {
        if ($brush.Color.A -eq 0) { return "TRANSPARENT" }
        return ("#{0:X2}{1:X2}{2:X2}" -f $brush.Color.R, $brush.Color.G, $brush.Color.B).ToUpper()
    }
    return ""
}

$script:ColorMapBgLight = @{
    '#0F1015' = '#F1F5F9'
    '#111319' = '#FFFFFF'
    '#111827' = '#F8FAFC'
    '#13151D' = '#F1F5F9'
    '#14161C' = '#F8FAFC'
    '#14161F' = '#F8FAFC'
    '#161820' = '#F1F5F9'
    '#161821' = '#F8FAFC'
    '#161822' = '#F8FAFC'
    '#18191D' = '#F8FAFC'
    '#181A20' = '#F8FAFC'
    '#181A22' = '#FFFFFF'
    '#181B24' = '#FFFFFF'
    '#1A1C23' = '#FFFFFF'
    '#1A1D27' = '#FFFFFF'
    '#1B1E28' = '#F8FAFC'
    '#1E212B' = '#F1F5F9'
    '#1E212D' = '#FFFFFF'
    '#1E222D' = '#FFFFFF'
    '#1E2232' = '#FFFFFF'
    '#1E293B' = '#F1F5F9'
    '#1F232E' = '#F1F5F9'
    '#22252F' = '#F1F5F9'
    '#222634' = '#F1F5F9'
    '#252936' = '#FFFFFF'
    '#252A3A' = '#F1F5F9'
    '#253352' = '#E2E8F0'
    '#282D3E' = '#F1F5F9'
    '#292E3E' = '#F1F5F9'
    '#292F42' = '#F1F5F9'
    '#2A2D3A' = '#FFFFFF'
    '#2B2F3E' = '#F1F5F9'
    '#2D313F' = '#F1F5F9'
    '#323749' = '#E2E8F0'
    '#334155' = '#E2E8F0'
    '#373B4D' = '#E2E8F0'
    '#3A1C20' = '#FEF2F2'
}

$script:ColorMapFgLight = @{
    '#FFFFFF' = '#0F172A'
    '#F8FAFC' = '#0F172A'
    '#F3F4F6' = '#0F172A'
    '#F1F5F9' = '#0F172A'
    '#E5E7EB' = '#1E293B'
    '#D1D5DB' = '#334155'
    '#9CA3AF' = '#475569'
    '#6B7280' = '#64748B'
    '#60A5FA' = '#2563EB'
    '#38BDF8' = '#0284C7'
    '#93C5FD' = '#1D4ED8'
    '#A78BFA' = '#7C3AED'
    '#34D399' = '#059669'
    '#10B981' = '#047857'
    '#FBBF24' = '#D97706'
    '#F59E0B' = '#B45309'
    '#EF4444' = '#DC2626'
    '#4B5563' = '#475569'
    '#FFA3A8' = '#DC2626'
}

$script:ColorMapBorderLight = @{
    '#1F2937' = '#CBD5E1'
    '#252936' = '#CBD5E1'
    '#252A3A' = '#CBD5E1'
    '#292E3E' = '#CBD5E1'
    '#2D313F' = '#CBD5E1'
    '#2E3345' = '#CBD5E1'
    '#2F3446' = '#CBD5E1'
    '#334155' = '#CBD5E1'
    '#373B4D' = '#CBD5E1'
    '#374151' = '#CBD5E1'
    '#383E54' = '#CBD5E1'
    '#4B526D' = '#94A3B8'
}

$script:ColorMapBgDark = @{
    '#F1F5F9' = '#161820'
    '#F8FAFC' = '#14161C'
    '#FFFFFF' = '#1A1D27'
    '#E2E8F0' = '#253352'
    '#FEF2F2' = '#3A1C20'
}

$script:ColorMapFgDark = @{
    '#0F172A' = '#FFFFFF'
    '#1E293B' = '#E5E7EB'
    '#334155' = '#D1D5DB'
    '#475569' = '#9CA3AF'
    '#64748B' = '#6B7280'
    '#2563EB' = '#60A5FA'
    '#0284C7' = '#38BDF8'
    '#1D4ED8' = '#93C5FD'
    '#7C3AED' = '#A78BFA'
    '#059669' = '#34D399'
    '#047857' = '#10B981'
    '#D97706' = '#FBBF24'
    '#B45309' = '#F59E0B'
    '#DC2626' = '#EF4444'
}

$script:ColorMapBorderDark = @{
    '#CBD5E1' = '#2F3446'
    '#94A3B8' = '#4B526D'
    '#E2E8F0' = '#252936'
}

function Test-IsDynamicExpression ($node, $prop) {
    if (-not $node -or -not $prop) { return $false }
    try {
        $source = [System.Windows.DependencyPropertyHelper]::GetValueSource($node, $prop)
        return [bool]$source.IsExpression
    } catch {
        return $false
    }
}

function Apply-ThemeNode ($node, [string]$targetTheme) {
    if (-not $node -or -not ($node -is [System.Windows.FrameworkElement])) { return }
    $id = $node.GetHashCode()

    $bgProp = switch ($node) {
        { $_ -is [System.Windows.Controls.Border] }    { [System.Windows.Controls.Border]::BackgroundProperty }
        { $_ -is [System.Windows.Controls.Control] }   { [System.Windows.Controls.Control]::BackgroundProperty }
        { $_ -is [System.Windows.Controls.Panel] }     { [System.Windows.Controls.Panel]::BackgroundProperty }
        { $_ -is [System.Windows.Controls.TextBlock] } { [System.Windows.Controls.TextBlock]::BackgroundProperty }
        default { $null }
    }
    $fgProp = switch ($node) {
        { $_ -is [System.Windows.Controls.Control] }   { [System.Windows.Controls.Control]::ForegroundProperty }
        { $_ -is [System.Windows.Controls.TextBlock] } { [System.Windows.Controls.TextBlock]::ForegroundProperty }
        default { $null }
    }
    $borderProp = switch ($node) {
        { $_ -is [System.Windows.Controls.Border] }  { [System.Windows.Controls.Border]::BorderBrushProperty }
        { $_ -is [System.Windows.Controls.Control] } { [System.Windows.Controls.Control]::BorderBrushProperty }
        default { $null }
    }

    # Only treat property as having a local static brush if ReadLocalValue is NOT UnsetValue and NOT a dynamic expression
    $localBg = if ($bgProp) { $node.ReadLocalValue($bgProp) } else { [System.Windows.DependencyProperty]::UnsetValue }
    $isBgDynamic = ($bgProp -and (Test-IsDynamicExpression $node $bgProp))
    $hasLocalBg = ($localBg -ne [System.Windows.DependencyProperty]::UnsetValue -and -not $isBgDynamic)

    $localFg = if ($fgProp) { $node.ReadLocalValue($fgProp) } else { [System.Windows.DependencyProperty]::UnsetValue }
    $isFgDynamic = ($fgProp -and (Test-IsDynamicExpression $node $fgProp))
    $hasLocalFg = ($localFg -ne [System.Windows.DependencyProperty]::UnsetValue -and -not $isFgDynamic)

    $localBorder = if ($borderProp) { $node.ReadLocalValue($borderProp) } else { [System.Windows.DependencyProperty]::UnsetValue }
    $isBorderDynamic = ($borderProp -and (Test-IsDynamicExpression $node $borderProp))
    $hasLocalBorder = ($localBorder -ne [System.Windows.DependencyProperty]::UnsetValue -and -not $isBorderDynamic)

    if ($targetTheme -eq "Light") {
        # Cache original dark brushes if element has local static properties
        if (-not $script:OriginalBrushes.ContainsKey($id)) {
            $script:OriginalBrushes[$id] = @{
                Bg     = if ($hasLocalBg) { $localBg } else { $null }
                Fg     = if ($hasLocalFg) { $localFg } else { $null }
                Border = if ($hasLocalBorder) { $localBorder } else { $null }
            }
        }
        $orig = $script:OriginalBrushes[$id]

        # Apply Light Background for local static properties
        if ($orig.Bg) {
            $hex = Convert-BrushToHex $orig.Bg
            if ($hex -ne "TRANSPARENT" -and $script:ColorMapBgLight.ContainsKey($hex)) {
                $node.Background = $script:BrushConverter.ConvertFromString($script:ColorMapBgLight[$hex])
            }
        }

        # Apply Light Foreground (protect primary/accent action badges and buttons)
        if ($orig.Fg) {
            $isAccentHost = $false
            $checkBg = $node.Background
            if (-not $checkBg -and ($node.Parent -is [System.Windows.Controls.Button] -or $node.Parent -is [System.Windows.Controls.Border])) {
                $checkBg = $node.Parent.Background
            } elseif (-not $checkBg -and $node.Parent -is [System.Windows.Controls.Panel] -and ($node.Parent.Parent -is [System.Windows.Controls.Button] -or $node.Parent.Parent -is [System.Windows.Controls.Border])) {
                $checkBg = $node.Parent.Parent.Background
            }
            if ($checkBg) {
                $bgHex = Convert-BrushToHex $checkBg
                if ($bgHex -in @('#0078D4', '#107C41', '#D13438', '#D97706', '#4F46E5', '#0284C7', '#DC2626', '#064E3B')) {
                    $isAccentHost = $true
                }
            }

            if (-not $isAccentHost) {
                $hex = Convert-BrushToHex $orig.Fg
                if ($hex -ne "TRANSPARENT" -and $script:ColorMapFgLight.ContainsKey($hex)) {
                    $node.Foreground = $script:BrushConverter.ConvertFromString($script:ColorMapFgLight[$hex])
                }
            }
        }

        # Apply Light BorderBrush for local static properties
        if ($orig.Border) {
            $hex = Convert-BrushToHex $orig.Border
            if ($hex -ne "TRANSPARENT" -and $script:ColorMapBorderLight.ContainsKey($hex)) {
                $node.BorderBrush = $script:BrushConverter.ConvertFromString($script:ColorMapBorderLight[$hex])
            }
        }
    } else {
        # Restore Dark Mode: restore cached original dark brushes, or clear local values if none was set
        if ($script:OriginalBrushes.ContainsKey($id)) {
            $saved = $script:OriginalBrushes[$id]
            if ($null -ne $saved.Bg) {
                $node.Background = $saved.Bg
            } elseif ($bgProp -and -not $isBgDynamic) {
                $node.ClearValue($bgProp)
            }
            if ($null -ne $saved.Fg) {
                $node.Foreground = $saved.Fg
            } elseif ($fgProp -and -not $isFgDynamic) {
                $node.ClearValue($fgProp)
            }
            if ($null -ne $saved.Border) {
                $node.BorderBrush = $saved.Border
            } elseif ($borderProp -and -not $isBorderDynamic) {
                $node.ClearValue($borderProp)
            }
        } else {
            # Element was not cached (e.g. style-based or created in Light mode)
            if ($bgProp -and -not $isBgDynamic -and $hasLocalBg) {
                $hex = Convert-BrushToHex $localBg
                if ($script:ColorMapBgDark.ContainsKey($hex)) {
                    $node.Background = $script:BrushConverter.ConvertFromString($script:ColorMapBgDark[$hex])
                } else {
                    $node.ClearValue($bgProp)
                }
            }
            if ($fgProp -and -not $isFgDynamic -and $hasLocalFg) {
                $hex = Convert-BrushToHex $localFg
                if ($script:ColorMapFgDark.ContainsKey($hex)) {
                    $node.Foreground = $script:BrushConverter.ConvertFromString($script:ColorMapFgDark[$hex])
                } else {
                    $node.ClearValue($fgProp)
                }
            }
            if ($borderProp -and -not $isBorderDynamic -and $hasLocalBorder) {
                $hex = Convert-BrushToHex $localBorder
                if ($script:ColorMapBorderDark.ContainsKey($hex)) {
                    $node.BorderBrush = $script:BrushConverter.ConvertFromString($script:ColorMapBorderDark[$hex])
                } else {
                    $node.ClearValue($borderProp)
                }
            }
        }
    }

    foreach ($child in [System.Windows.LogicalTreeHelper]::GetChildren($node)) {
        if ($child -is [System.Windows.FrameworkElement]) {
            Apply-ThemeNode $child $targetTheme
        }
    }
}

function Set-ApplicationTheme {
    [CmdletBinding()]
    param (
        [ValidateSet("Dark", "Light")]
        [string]$Theme = "Dark",

        [string]$AccentTone = "Blue",

        [switch]$SavePreference
    )

    $isLight = ($Theme -eq "Light")
    $state.CurrentTheme = $Theme

    # 1. Update Window Resource Brushes
    $bgDarkVal           = if ($isLight) { "#F8FAFC" } else { "#0F1015" }
    $bgSidebarVal        = if ($isLight) { "#F1F5F9" } else { "#161820" }
    $bgSurfaceVal        = if ($isLight) { "#FFFFFF" } else { "#1E212B" }
    $bgCardVal           = if ($isLight) { "#FFFFFF" } else { "#252936" }
    $bgInputVal          = if ($isLight) { "#FFFFFF" } else { "#181A22" }
    $borderVal           = if ($isLight) { "#CBD5E1" } else { "#2F3446" }
    $textPriVal          = if ($isLight) { "#0F172A" } else { "#FFFFFF" }
    $textSecVal          = if ($isLight) { "#475569" } else { "#9CA3AF" }
    $textMutVal          = if ($isLight) { "#64748B" } else { "#6B7280" }

    # Component Dynamic Brushes
    $navHoverBgVal       = if ($isLight) { "#E2E8F0" } else { "#1E212B" }
    $navSelectedBgVal    = if ($isLight) { "#E2E8F0" } else { "#252936" }
    $dropDownBgVal       = if ($isLight) { "#FFFFFF" } else { "#181A22" }
    $dropDownBorderVal   = if ($isLight) { "#CBD5E1" } else { "#383E54" }
    $dropDownItemHoverBg = if ($isLight) { "#F1F5F9" } else { "#282D3E" }
    $dropDownItemHoverFg = if ($isLight) { "#0F172A" } else { "#FFFFFF" }
    $buttonBgVal         = if ($isLight) { "#F1F5F9" } else { "#252936" }
    $buttonHoverBgVal    = if ($isLight) { "#E2E8F0" } else { "#323749" }
    $buttonHoverBorderVal= if ($isLight) { "#94A3B8" } else { "#4B526D" }
    $dataGridHeaderBgVal = if ($isLight) { "#F1F5F9" } else { "#1F232F" }
    $dataGridHeaderFgVal = if ($isLight) { "#1E293B" } else { "#D1D5DB" }
    $dataGridRowBgVal    = if ($isLight) { "#FFFFFF" } else { "#161820" }
    $dataGridAltRowBgVal = if ($isLight) { "#F8FAFC" } else { "#1B1E28" }
    $dataGridGridLinesVal= if ($isLight) { "#E2E8F0" } else { "#262A38" }
    $contextMenuBgVal    = if ($isLight) { "#FFFFFF" } else { "#181A22" }
    $dangerBtnBgVal      = if ($isLight) { "#FEF2F2" } else { "#3A1C20" }
    $dangerBtnFgVal      = if ($isLight) { "#DC2626" } else { "#FFA3A8" }
    $dangerBtnBorderVal  = if ($isLight) { "#FCA5A5" } else { "#D13438" }

    $resourceMap = @{
        "BgDark"              = $bgDarkVal
        "BgSidebar"           = $bgSidebarVal
        "BgSurface"           = $bgSurfaceVal
        "BgCard"              = $bgCardVal
        "BgInput"             = $bgInputVal
        "BorderBrushColor"    = $borderVal
        "TextPrimary"         = $textPriVal
        "TextSecondary"       = $textSecVal
        "TextMuted"           = $textMutVal
        "NavHoverBg"          = $navHoverBgVal
        "NavSelectedBg"       = $navSelectedBgVal
        "DropDownBg"          = $dropDownBgVal
        "DropDownBorderBrush" = $dropDownBorderVal
        "DropDownItemHoverBg" = $dropDownItemHoverBg
        "DropDownItemHoverFg" = $dropDownItemHoverFg
        "ButtonBg"            = $buttonBgVal
        "ButtonHoverBg"       = $buttonHoverBgVal
        "ButtonHoverBorder"   = $buttonHoverBorderVal
        "DataGridHeaderBg"    = $dataGridHeaderBgVal
        "DataGridHeaderFg"    = $dataGridHeaderFgVal
        "DataGridRowBg"       = $dataGridRowBgVal
        "DataGridAltRowBg"    = $dataGridAltRowBgVal
        "DataGridGridLines"   = $dataGridGridLinesVal
        "ContextMenuBg"       = $contextMenuBgVal
        "DangerButtonBg"      = $dangerBtnBgVal
        "DangerButtonFg"      = $dangerBtnFgVal
        "DangerButtonBorder"  = $dangerBtnBorderVal
    }

    foreach ($k in $resourceMap.Keys) {
        $window.Resources[$k] = $script:BrushConverter.ConvertFromString($resourceMap[$k])
        if ([System.Windows.Application]::Current -and [System.Windows.Application]::Current.Resources) {
            [System.Windows.Application]::Current.Resources[$k] = $window.Resources[$k]
        }
    }

    # Accent tone handling
    $accentHex = switch -Wildcard ($AccentTone) {
        "*Sky*"     { "#0284C7" }
        "*Emerald*" { "#107C41" }
        "*Indigo*"  { "#4F46E5" }
        "*Amber*"   { "#D97706" }
        default     { "#0078D4" }
    }
    $window.Resources["AccentPrimary"] = $script:BrushConverter.ConvertFromString($accentHex)
    if ([System.Windows.Application]::Current -and [System.Windows.Application]::Current.Resources) {
        [System.Windows.Application]::Current.Resources["AccentPrimary"] = $window.Resources["AccentPrimary"]
    }

    # 2. Apply theme recursively across visual tree and all registered controls
    Apply-ThemeNode $window $Theme
    if ($controls) {
        foreach ($ctrl in $controls.Values) {
            if ($ctrl -is [System.Windows.FrameworkElement]) {
                Apply-ThemeNode $ctrl $Theme
            }
        }
    }

    # Propagate theme to all active detached windows
    if ($state -and $state.DetachedWindows) {
        foreach ($dWin in $state.DetachedWindows.Values) {
            if ($dWin) {
                foreach ($k in $resourceMap.Keys) {
                    $dWin.Resources[$k] = $window.Resources[$k]
                }
                $dWin.Resources["AccentPrimary"] = $window.Resources["AccentPrimary"]
                Apply-ThemeNode $dWin $Theme
            }
        }
    }
    if (Get-Command Update-WorkspaceTabStrip -ErrorAction SilentlyContinue) {
        Update-WorkspaceTabStrip
    }

    # 3. Update Quick Theme Toggle button
    if ($controls['TxtQuickThemeIcon']) {
        $controls['TxtQuickThemeIcon'].Text = if ($isLight) { [char]::ConvertFromUtf32(0x2600) } else { [char]::ConvertFromUtf32(0x1F319) }
    }
    if ($controls['BtnQuickThemeToggle']) {
        $controls['BtnQuickThemeToggle'].ToolTip = if ($isLight) { "Switch to Dark Mode (Ctrl+T)" } else { "Switch to Light Mode (Ctrl+T)" }
    }

    # 4. Synchronize Settings ComboBox
    if ($controls['CmbThemeMode']) {
        $targetIndex = if ($isLight) { 1 } else { 0 }
        if ($controls['CmbThemeMode'].SelectedIndex -ne $targetIndex) {
            $controls['CmbThemeMode'].SelectedIndex = $targetIndex
        }
    }

    # 5. Synchronize In-App HTML View if active and sync enabled
    if ($state.CurrentHtmlDN -and $appConfig.UI.SyncHtmlViewTheme) {
        Refresh-HtmlViewUI
    }

    # 6. Save Preference to config
    if ($SavePreference) {
        $appConfig.UI.Theme = $Theme
        $appConfig.UI.AccentTone = $AccentTone
        [void](Save-AppSettings -Config $appConfig)
        Set-Status -Message "Theme updated to $Theme Mode."
    }
}

# Wire Quick Theme Toggle button
if ($controls['BtnQuickThemeToggle']) {
    $controls['BtnQuickThemeToggle'].Add_Click({
        $newTheme = if ($state.CurrentTheme -eq "Light") { "Dark" } else { "Light" }
        Set-ApplicationTheme -Theme $newTheme -SavePreference
    })
}

# Wire Settings Appearance Controls
if ($controls['CmbThemeMode']) {
    $controls['CmbThemeMode'].Add_SelectionChanged({
        $newTheme = if ($controls['CmbThemeMode'].SelectedIndex -eq 1) { "Light" } else { "Dark" }
        if ($newTheme -ne $state.CurrentTheme) {
            Set-ApplicationTheme -Theme $newTheme -SavePreference
        }
    })
}

if ($controls['CmbAccentTone']) {
    $controls['CmbAccentTone'].Add_SelectionChanged({
        $selTone = if ($controls['CmbAccentTone'].SelectedItem) { "$($controls['CmbAccentTone'].SelectedItem.Content)" } else { "Blue" }
        Set-ApplicationTheme -Theme $state.CurrentTheme -AccentTone $selTone -SavePreference
    })
}
#endregion

#region 18. In-App HTML Dossier View Logic
function Init-HtmlViewUI {
    if (-not $state.CurrentHtmlDN) {
        # Show elegant welcome landing page
        $isLight = ($state.CurrentTheme -eq "Light")
        $bg = if ($isLight) { "#F8FAFC" } else { "#0E1017" }
        $cardBg = if ($isLight) { "#FFFFFF" } else { "#161922" }
        $border = if ($isLight) { "#CBD5E1" } else { "#262B3D" }
        $fg = if ($isLight) { "#0F172A" } else { "#F1F5F9" }
        $sub = if ($isLight) { "#475569" } else { "#94A3B8" }
        $accent = if ($isLight) { "#0284C7" } else { "#38BDF8" }

        $welcomeHtml = @"
<!DOCTYPE html>
<html>
<head>
<meta http-equiv="X-UA-Compatible" content="IE=edge"/>
<style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: $bg; color: $fg; padding: 40px 20px; text-align: center; }
    .hero { max-width: 650px; margin: 40px auto; background: $cardBg; border: 1px solid $border; border-radius: 12px; padding: 36px; box-shadow: 0 4px 12px rgba(0,0,0,0.08); }
    h1 { color: $accent; font-size: 24px; margin-bottom: 12px; }
    p { color: $sub; font-size: 14px; line-height: 1.6; }
    .features { text-align: left; margin: 24px 0; padding-left: 20px; font-size: 13px; color: $sub; }
    .features li { margin-bottom: 8px; }
    .badge { display: inline-block; background: $accent; color: #FFFFFF; padding: 4px 12px; border-radius: 9999px; font-size: 11px; font-weight: bold; margin-bottom: 14px; text-transform: uppercase; }
</style>
</head>
<body>
    <div class="hero">
        <span class="badge">Softerra LDAP Administrator Parity</span>
        <h1>&#x1F4C4; Active Directory HTML Dossier View</h1>
        <p>Interactive, web-formatted directory entry cards with real-time status pills, manager hierarchy, and full technical attributes.</p>
        <ul class="features">
            <li>&#x1F50D; <b>Address Bar:</b> Type any username (sAMAccountName) or Distinguished Name and click <b>Go</b>.</li>
            <li>&#x1F4C6; <b>Context Menus:</b> Right-click any User, Group, Computer, or OU across the app and select <b>View HTML Dossier</b>.</li>
            <li>&#x1F3A8; <b>Multi-Template:</b> Switch between Technical Dossier, Executive Summary, Group Audit, and Raw Attributes.</li>
            <li>&#x1F5B6;&#xFE0F; <b>Print &amp; Share:</b> Print high-contrast report cards or open in external browser.</li>
        </ul>
        <p style="font-size: 12px; color: $accent;">Ready: Select an object or enter a query above to render.</p>
    </div>
</body>
</html>
"@
        if ($controls['BrowserHtmlView']) {
            $controls['BrowserHtmlView'].NavigateToString($welcomeHtml)
        }
    }
}

function Show-ObjectHtmlView {
    [CmdletBinding()]
    param (
        $Identity,
        [string]$Template = ""
    )

    try {
        if (-not $Identity) {
            [System.Windows.MessageBox]::Show("Please select or specify a directory object to view.", "Object Required", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            return
        }

        # Resolve DN and Target Object
        $targetObj = $null
        $targetDN = ""

        if ($Identity -is [string]) {
            $targetDN = $Identity.Trim()
            # If sAMAccountName or simple name without DC=, query user, group, or directory object
            if ($targetDN -notmatch 'DC=') {
                # 1. Try finding matching user
                $foundUsers = Get-ADUsersList -SearchText $targetDN -Limit 10
                $user = if ($foundUsers) {
                    $foundUsers | Where-Object {
                        $_.SamAccountName -ieq $targetDN -or
                        $_.UserPrincipalName -ieq $targetDN -or
                        $_.DisplayName -ieq $targetDN -or
                        $_.Name -ieq $targetDN -or
                        $_.Mail -ieq $targetDN
                    } | Select-Object -First 1
                } else { $null }
                if (-not $user -and $foundUsers -and $foundUsers.Count -gt 0) {
                    $user = $foundUsers[0]
                }

                if ($user) {
                    $targetObj = $user
                    $targetDN = if ($user.DistinguishedName) { $user.DistinguishedName } else { "$($user.DN)" }
                } else {
                    # 2. Try Find-ADObjectsQuickSearch (searches across users, groups, computers, OUs)
                    $quickMatches = Find-ADObjectsQuickSearch -Query $targetDN -MaxResults 5
                    $match = if ($quickMatches) {
                        $quickMatches | Where-Object {
                            $_.SamAccountName -ieq $targetDN -or
                            $_.Name -ieq $targetDN -or
                            $_.DisplayName -ieq $targetDN
                        } | Select-Object -First 1
                    } else { $null }
                    if (-not $match -and $quickMatches -and $quickMatches.Count -gt 0) {
                        $match = $quickMatches[0]
                    }

                    if ($match) {
                        $targetObj = $match
                        $targetDN = if ($match.DistinguishedName) { $match.DistinguishedName } else { "$($match.DN)" }
                    } else {
                        # 3. Try finding group
                        $foundGroups = Get-ADGroupsList -SearchText $targetDN -Limit 5
                        $grp = if ($foundGroups) {
                            $foundGroups | Where-Object { $_.SamAccountName -ieq $targetDN -or $_.Name -ieq $targetDN } | Select-Object -First 1
                        } else { $null }

                        if ($grp) {
                            $targetObj = $grp
                            $targetDN = if ($grp.DistinguishedName) { $grp.DistinguishedName } else { "$($grp.DN)" }
                        } else {
                            # 4. Try finding computer
                            $foundComps = Get-ADComputersList -SearchText $targetDN -Limit 5
                            $comp = if ($foundComps) {
                                $foundComps | Where-Object { $_.SamAccountName -ieq $targetDN -or $_.Name -ieq $targetDN -or $_.DNSHostName -ieq $targetDN } | Select-Object -First 1
                            } else { $null }

                            if ($comp) {
                                $targetObj = $comp
                                $targetDN = if ($comp.DistinguishedName) { $comp.DistinguishedName } else { "$($comp.DN)" }
                            } else {
                                # 5. Fallback: probe raw attributes directly
                                $rawProbe = $null
                                try {
                                    $rawProbe = Get-ADObjectRawAttributes -DistinguishedName $targetDN
                                } catch { }

                                if ($rawProbe -and $rawProbe.Count -gt 0) {
                                    $targetObj = [PSCustomObject]@{ SamAccountName = $targetDN; DisplayName = $targetDN; DistinguishedName = $targetDN; Status = "Active" }
                                } else {
                                    [System.Windows.MessageBox]::Show("Could not find any directory object matching '$targetDN'.`r`n`r`nPlease enter a valid username, group name, computer name, or Distinguished Name (DN).", "Object Not Found", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
                                    Set-Status -Message "Object '$targetDN' not found."
                                    return
                                }
                            }
                        }
                    }
                }
            } else {
                $targetObj = [PSCustomObject]@{ DistinguishedName = $targetDN; DisplayName = ($targetDN -split ',')[0] -replace '^CN=|^OU=', '' }
            }
        } elseif ($Identity -is [System.Collections.IDictionary] -or $Identity.PSObject) {
            $targetObj = $Identity
            $targetDN = if ($Identity.DistinguishedName) { $Identity.DistinguishedName } elseif ($Identity.DN) { $Identity.DN } else { "" }
        }

        # If object is a user and groups aren't loaded, enrich with user detail
        $isUser = if ($targetObj.ObjectClass) {
            @($targetObj.ObjectClass) -contains 'user' -or "$($targetObj.ObjectClass)" -ieq 'user'
        } else {
            $true
        }
        if ($isUser -and $targetDN -and (-not $targetObj.Groups -or $targetObj.Groups.Count -eq 0)) {
            try {
                $detail = Get-ADUserDetail -Identity $targetDN -ErrorAction SilentlyContinue
                if ($detail -and $detail.User) {
                    $targetObj = $detail.User
                    if ($detail.Groups) {
                        $targetObj | Add-Member -NotePropertyName "Groups" -NotePropertyValue @($detail.Groups) -Force
                        $targetObj | Add-Member -NotePropertyName "MemberOf" -NotePropertyValue @($detail.Groups | ForEach-Object { $_.DistinguishedName }) -Force
                    }
                }
            } catch { }
        }

        if (-not $targetDN) {
            [System.Windows.MessageBox]::Show("Unable to resolve Distinguished Name for object.", "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
            return
        }

        Set-Status -Message "Loading HTML Dossier for $targetDN..."

        # Resolve extended properties & raw attributes
        $attrs = @()
        try {
            $attrs = Get-ADObjectRawAttributes -DistinguishedName $targetDN -IncludeOperational:$true
        } catch { }

        # Resolve template
        $activeTemplate = if ($Template) { $Template } elseif ($controls['CmbHtmlViewTemplate']) {
            switch ($controls['CmbHtmlViewTemplate'].SelectedIndex) {
                1 { "Executive" }
                2 { "Groups" }
                3 { "Raw" }
                default { "Technical" }
            }
        } else { "Technical" }

        # Resolve theme
        $themeToUse = if ($appConfig.UI.SyncHtmlViewTheme -and $state.CurrentTheme) { $state.CurrentTheme } else { "Dark" }

        # Generate HTML
        $html = Get-ADObjectHtmlContent -ObjectDetail $targetObj -Attributes $attrs -Theme $themeToUse -Template $activeTemplate

        # Cache in state
        $state.CurrentHtmlObject   = $targetObj
        $state.CurrentHtmlDN       = $targetDN
        $state.CurrentHtmlTemplate = $activeTemplate
        $state.CurrentHtmlRaw      = $html

        # Update UI controls
        if ($controls['TxtHtmlViewDN']) {
            $controls['TxtHtmlViewDN'].Text = $targetDN
        }
        if ($controls['TxtHtmlViewDNPlaceholder']) {
            $controls['TxtHtmlViewDNPlaceholder'].Visibility = [System.Windows.Visibility]::Collapsed
        }
        if ($controls['TxtHtmlViewStatusBadge']) {
            $nameDisp = if ($targetObj.DisplayName) { $targetObj.DisplayName } elseif ($targetObj.Name) { $targetObj.Name } else { ($targetDN -split ',')[0] }
            $controls['TxtHtmlViewStatusBadge'].Text = "$nameDisp"
        }

        # Navigate Browser
        if ($controls['BrowserHtmlView']) {
            $controls['BrowserHtmlView'].NavigateToString($html)
        }

        # Navigate to panel
        Show-Panel "HtmlView"
        if ($controls['NavHtmlView']) {
            $controls['NavHtmlView'].IsChecked = $true
        }

        Set-Status -Message "HTML Dossier loaded successfully ($activeTemplate template)."
    }
    catch {
        [System.Windows.MessageBox]::Show("Failed to render HTML Dossier: $_", "Render Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        Set-Status -Message "Error rendering HTML dossier: $_"
    }
}

function Refresh-HtmlViewUI {
    if ($state.CurrentHtmlDN) {
        Show-ObjectHtmlView -Identity $state.CurrentHtmlDN -Template $state.CurrentHtmlTemplate
    } else {
        Init-HtmlViewUI
    }
}

# Wire HTML View Toolbar Controls
if ($controls['BtnHtmlViewGo']) {
    $controls['BtnHtmlViewGo'].Add_Click({
        $inputDn = if ($controls['TxtHtmlViewDN']) { $controls['TxtHtmlViewDN'].Text.Trim() } else { "" }
        if ($inputDn) {
            Show-ObjectHtmlView -Identity $inputDn
        } else {
            [System.Windows.MessageBox]::Show("Please enter a username or Distinguished Name.", "Input Required", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        }
    })
}

if ($controls['TxtHtmlViewDN']) {
    $controls['TxtHtmlViewDN'].Add_KeyDown({
        param($sender, $e)
        if ($e.Key -eq [System.Windows.Input.Key]::Return) {
            if ($controls['BtnHtmlViewGo']) { $controls['BtnHtmlViewGo'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Button]::ClickEvent)) }
        }
    })
    $controls['TxtHtmlViewDN'].Add_TextChanged({
        if ($controls['TxtHtmlViewDNPlaceholder']) {
            $hasText = [string]::IsNullOrEmpty($controls['TxtHtmlViewDN'].Text)
            $controls['TxtHtmlViewDNPlaceholder'].Visibility = if ($hasText) { [System.Windows.Visibility]::Visible } else { [System.Windows.Visibility]::Collapsed }
        }
    })
}

if ($controls['BtnHtmlViewRefresh']) {
    $controls['BtnHtmlViewRefresh'].Add_Click({ Refresh-HtmlViewUI })
}

if ($controls['BtnHtmlViewPrint']) {
    $controls['BtnHtmlViewPrint'].Add_Click({
        if ($controls['BrowserHtmlView'] -and $controls['BrowserHtmlView'].Document) {
            try {
                $controls['BrowserHtmlView'].Document.parentWindow.execScript("window.print()")
            } catch {
                try { $controls['BrowserHtmlView'].Document.execCommand("Print", $true, $null) } catch { }
            }
        }
    })
}

if ($controls['BtnHtmlViewCopyHtml']) {
    $controls['BtnHtmlViewCopyHtml'].Add_Click({
        if ($state.CurrentHtmlRaw) {
            $copied = $false
            for ($retry = 0; $retry -lt 5; $retry++) {
                try {
                    [System.Windows.Clipboard]::SetDataObject($state.CurrentHtmlRaw, $true)
                    $copied = $true
                    break
                } catch {
                    Start-Sleep -Milliseconds 60
                }
            }
            if ($copied) {
                Set-Status -Message "HTML markup copied to clipboard."
            } else {
                Set-Status -Message "Clipboard unavailable (locked by another process)." -IsWarning
            }
        }
    })
}

if ($controls['BtnHtmlViewOpenBrowser']) {
    $controls['BtnHtmlViewOpenBrowser'].Add_Click({
        if ($state.CurrentHtmlRaw) {
            $tempPath = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "AD_Dossier_$([System.IO.Path]::GetRandomFileName()).html")
            [System.IO.File]::WriteAllText($tempPath, $state.CurrentHtmlRaw, [System.Text.Encoding]::UTF8)
            Start-Process $tempPath
            Set-Status -Message "Opened dossier in default system browser."
        }
    })
}

if ($controls['CmbHtmlViewTemplate']) {
    $controls['CmbHtmlViewTemplate'].Add_SelectionChanged({
        if ($state.CurrentHtmlDN) {
            $tpl = switch ($controls['CmbHtmlViewTemplate'].SelectedIndex) {
                1 { "Executive" }
                2 { "Groups" }
                3 { "Raw" }
                default { "Technical" }
            }
            if ($tpl -ne $state.CurrentHtmlTemplate) {
                Show-ObjectHtmlView -Identity $state.CurrentHtmlDN -Template $tpl
            }
        }
    })
}
#endregion

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

function Log-LdapRequest {
    param (
        [string]$Operation,
        [string]$TargetDN = "--",
        [string]$FilterOrPayload = "--",
        [double]$DurationMs = 0,
        [string]$Status = "SUCCESS",
        [string]$Details = ""
    )
    if (-not $state.RequestLogs) {
        $state.RequestLogs = [System.Collections.ObjectModel.ObservableCollection[psobject]]::new()
    }
    $timeStr = (Get-Date).ToString("HH:mm:ss.fff")
    $logItem = [PSCustomObject]@{
        Timestamp = $timeStr
        Operation = $Operation
        Status    = $Status
        Duration  = "$([Math]::Round($DurationMs, 1)) ms"
        TargetDN  = if ($TargetDN) { $TargetDN } else { "--" }
        Filter    = if ($FilterOrPayload) { $FilterOrPayload } else { "--" }
        Details   = if ($Details) { $Details } else { "Operation: $Operation`r`nTarget DN: $TargetDN`r`nPayload/Filter: $FilterOrPayload`r`nDuration: $DurationMs ms`r`nStatus: $Status`r`nTimestamp: $timeStr" }
    }
    
    if ($state.RequestLogs.Count -gt 1000) {
        $state.RequestLogs.RemoveAt(0)
    }
    $state.RequestLogs.Add($logItem)
    
    if ($controls['TxtRequestLogCountBadge']) {
        $controls['TxtRequestLogCountBadge'].Text = "$($state.RequestLogs.Count) requests"
    }
    if ($controls['GridRequestLog'] -and $controls['ChkRequestLogAutoScroll'] -and $controls['ChkRequestLogAutoScroll'].IsChecked) {
        $controls['GridRequestLog'].ScrollIntoView($logItem)
    }
}

# Navigation History Engine
function Update-NavButtons {
    if ($controls['BtnNavBack']) {
        $controls['BtnNavBack'].IsEnabled = ($state.NavIndex -gt 0)
    }
    if ($controls['BtnNavForward']) {
        $controls['BtnNavForward'].IsEnabled = ($state.NavIndex -ge 0 -and $state.NavIndex -lt ($state.NavHistory.Count - 1))
    }
}

function Record-NavHistory {
    param ([string]$PanelName)
    if ($state.IsNavigatingHistory) { return }
    if ([string]::IsNullOrWhiteSpace($PanelName)) { return }
    
    if ($state.NavIndex -ge 0 -and $state.NavIndex -lt $state.NavHistory.Count) {
        if ($state.NavHistory[$state.NavIndex] -eq $PanelName) { return }
    }
    
    if ($state.NavIndex -lt ($state.NavHistory.Count - 1)) {
        $removeCount = $state.NavHistory.Count - 1 - $state.NavIndex
        for ($i = 0; $i -lt $removeCount; $i++) {
            $state.NavHistory.RemoveAt($state.NavHistory.Count - 1)
        }
    }
    
    $state.NavHistory.Add($PanelName)
    $state.NavIndex = $state.NavHistory.Count - 1
    Update-NavButtons
}

#region Workspace Engine (Multi-Tabs & Detachable Multi-Windows)

function Launch-NewApplicationWindow {
    param([string]$ToolName = "")
    $powershellExe = (Get-Process -Id $PID).Path
    $argList = "-STA -NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    if (-not [string]::IsNullOrWhiteSpace($ToolName)) {
        $argList += " -InitialTool `"$ToolName`""
    }
    Start-Process -FilePath $powershellExe -ArgumentList $argList
    Set-Status -Message "Launched new independent window$(if ($ToolName) { " for $ToolName" })."
}

function Rename-WorkspaceTab {
    param([string]$TabId)
    if ([string]::IsNullOrWhiteSpace($TabId)) { return }
    $targetTab = $state.OpenTabs | Where-Object { $_.Id -eq $TabId } | Select-Object -First 1
    if (-not $targetTab) {
        $targetTab = $state.OpenTabs | Where-Object { $_.PanelName -eq $TabId } | Select-Object -First 1
    }
    if (-not $targetTab) { return }

    $dialog = [System.Windows.Window]::new()
    $dialog.Title = "Rename Tab"
    $dialog.Width = 360
    $dialog.Height = 155
    $dialog.WindowStartupLocation = [System.Windows.WindowStartupLocation]::CenterOwner
    if ($window) { $dialog.Owner = $window }
    $dialog.SetResourceReference([System.Windows.Window]::BackgroundProperty, "BgDark")
    $dialog.SetResourceReference([System.Windows.Window]::ForegroundProperty, "TextPrimary")
    $dialog.ResizeMode = [System.Windows.ResizeMode]::NoResize

    $stack = [System.Windows.Controls.StackPanel]::new()
    $stack.Margin = [System.Windows.Thickness]::new(16)

    $lbl = [System.Windows.Controls.TextBlock]::new()
    $lbl.Text = "Custom name for '$($targetTab.Title)':"
    $lbl.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, "TextPrimary")
    $lbl.FontWeight = [System.Windows.FontWeights]::SemiBold
    $lbl.Margin = [System.Windows.Thickness]::new(0, 0, 0, 8)
    [void]$stack.Children.Add($lbl)

    $tb = [System.Windows.Controls.TextBox]::new()
    $tb.Style = $window.TryFindResource("ModernTextBox")
    $tb.Text = $targetTab.Title
    $tb.Height = 28
    $tb.Padding = [System.Windows.Thickness]::new(6, 3, 6, 3)
    $tb.SelectAll()
    [void]$stack.Children.Add($tb)

    $btnPanel = [System.Windows.Controls.StackPanel]::new()
    $btnPanel.Orientation = [System.Windows.Controls.Orientation]::Horizontal
    $btnPanel.HorizontalAlignment = [System.Windows.HorizontalAlignment]::Right
    $btnPanel.Margin = [System.Windows.Thickness]::new(0, 12, 0, 0)

    $btnOk = [System.Windows.Controls.Button]::new()
    $btnOk.Style = $window.TryFindResource("PrimaryButton")
    $btnOk.Content = "Save"
    $btnOk.Width = 70
    $btnOk.Height = 26
    $btnOk.Margin = [System.Windows.Thickness]::new(0, 0, 8, 0)
    $btnOk.IsDefault = $true
    $btnOk.Add_Click({
        if (-not [string]::IsNullOrWhiteSpace($tb.Text)) {
            $targetTab.Title = $tb.Text.Trim()
            Update-WorkspaceTabStrip
        }
        $dialog.Close()
    })
    [void]$btnPanel.Children.Add($btnOk)

    $btnCancel = [System.Windows.Controls.Button]::new()
    $btnCancel.Style = $window.TryFindResource("ModernButton")
    $btnCancel.Content = "Cancel"
    $btnCancel.Width = 70
    $btnCancel.Height = 26
    $btnCancel.IsCancel = $true
    $btnCancel.Add_Click({ $dialog.Close() })
    [void]$btnPanel.Children.Add($btnCancel)

    [void]$stack.Children.Add($btnPanel)
    $dialog.Content = $stack
    [void]$dialog.ShowDialog()
}

function Save-TabSessionState {
    param($Tab)
    if (-not $Tab -or -not $Tab.State) { return }
    $p = $Tab.PanelName
    switch ($p) {
        "Users" {
            if ($controls['TxtSearchUsers']) { $Tab.State['SearchUsers'] = $controls['TxtSearchUsers'].Text }
            if ($controls['FilterUserAll']) {
                $Tab.State['FilterUser'] = if ($controls['FilterUserActive'] -and $controls['FilterUserActive'].IsChecked) { "Active" }
                    elseif ($controls['FilterUserDisabled'] -and $controls['FilterUserDisabled'].IsChecked) { "Disabled" }
                    elseif ($controls['FilterUserLocked'] -and $controls['FilterUserLocked'].IsChecked) { "Locked" }
                    else { "All" }
            }
            if ($controls['CmbUserOUFilter']) { $Tab.State['OUFilter'] = $controls['CmbUserOUFilter'].SelectedIndex }
        }
        "Groups" {
            if ($controls['TxtSearchGroups']) { $Tab.State['SearchGroups'] = $controls['TxtSearchGroups'].Text }
            if ($controls['FilterGroupAll']) {
                $Tab.State['FilterGroup'] = if ($controls['FilterGroupSec'] -and $controls['FilterGroupSec'].IsChecked) { "Security" }
                    elseif ($controls['FilterGroupDist'] -and $controls['FilterGroupDist'].IsChecked) { "Distribution" }
                    else { "All" }
            }
        }
        "Computers" {
            if ($controls['TxtSearchComputers']) { $Tab.State['SearchComputers'] = $controls['TxtSearchComputers'].Text }
            if ($controls['FilterCompAll']) {
                $Tab.State['FilterComp'] = if ($controls['FilterCompEnabled'] -and $controls['FilterCompEnabled'].IsChecked) { "Enabled" }
                    elseif ($controls['FilterCompDisabled'] -and $controls['FilterCompDisabled'].IsChecked) { "Disabled" }
                    else { "All" }
            }
        }
        "DirectorySearch" {
            if ($controls['TxtLdapFilter']) { $Tab.State['LdapFilter'] = $controls['TxtLdapFilter'].Text }
            if ($controls['TxtLdapSearchBase']) { $Tab.State['SearchBase'] = $controls['TxtLdapSearchBase'].Text }
            if ($controls['CmbLdapScope']) { $Tab.State['ScopeIndex'] = $controls['CmbLdapScope'].SelectedIndex }
        }
        "LdapSql" {
            if ($controls['TxtLdapSqlQuery']) { $Tab.State['SqlQuery'] = $controls['TxtLdapSqlQuery'].Text }
        }
        "AttributeEditor" {
            if ($controls['TxtSearchAttr']) { $Tab.State['SearchAttr'] = $controls['TxtSearchAttr'].Text }
        }
    }
}

function Restore-TabSessionState {
    param($Tab)
    if (-not $Tab -or -not $Tab.State) { return }
    $p = $Tab.PanelName
    switch ($p) {
        "Users" {
            if ($controls['TxtSearchUsers'] -and $Tab.State.ContainsKey('SearchUsers')) {
                $controls['TxtSearchUsers'].Text = $Tab.State['SearchUsers']
            }
            if ($Tab.State.ContainsKey('FilterUser')) {
                switch ($Tab.State['FilterUser']) {
                    "Active"   { if ($controls['FilterUserActive'])   { $controls['FilterUserActive'].IsChecked = $true } }
                    "Disabled" { if ($controls['FilterUserDisabled']) { $controls['FilterUserDisabled'].IsChecked = $true } }
                    "Locked"   { if ($controls['FilterUserLocked'])   { $controls['FilterUserLocked'].IsChecked = $true } }
                    default    { if ($controls['FilterUserAll'])      { $controls['FilterUserAll'].IsChecked = $true } }
                }
            }
            if ($controls['CmbUserOUFilter'] -and $Tab.State.ContainsKey('OUFilter')) {
                $controls['CmbUserOUFilter'].SelectedIndex = $Tab.State['OUFilter']
            }
        }
        "Groups" {
            if ($controls['TxtSearchGroups'] -and $Tab.State.ContainsKey('SearchGroups')) {
                $controls['TxtSearchGroups'].Text = $Tab.State['SearchGroups']
            }
            if ($Tab.State.ContainsKey('FilterGroup')) {
                switch ($Tab.State['FilterGroup']) {
                    "Security"     { if ($controls['FilterGroupSec'])  { $controls['FilterGroupSec'].IsChecked = $true } }
                    "Distribution" { if ($controls['FilterGroupDist']) { $controls['FilterGroupDist'].IsChecked = $true } }
                    default        { if ($controls['FilterGroupAll'])  { $controls['FilterGroupAll'].IsChecked = $true } }
                }
            }
        }
        "Computers" {
            if ($controls['TxtSearchComputers'] -and $Tab.State.ContainsKey('SearchComputers')) {
                $controls['TxtSearchComputers'].Text = $Tab.State['SearchComputers']
            }
            if ($Tab.State.ContainsKey('FilterComp')) {
                switch ($Tab.State['FilterComp']) {
                    "Enabled"  { if ($controls['FilterCompEnabled'])  { $controls['FilterCompEnabled'].IsChecked = $true } }
                    "Disabled" { if ($controls['FilterCompDisabled']) { $controls['FilterCompDisabled'].IsChecked = $true } }
                    default    { if ($controls['FilterCompAll'])      { $controls['FilterCompAll'].IsChecked = $true } }
                }
            }
        }
        "DirectorySearch" {
            if ($controls['TxtLdapFilter'] -and $Tab.State.ContainsKey('LdapFilter')) {
                $controls['TxtLdapFilter'].Text = $Tab.State['LdapFilter']
            }
            if ($controls['TxtLdapSearchBase'] -and $Tab.State.ContainsKey('SearchBase')) {
                $controls['TxtLdapSearchBase'].Text = $Tab.State['SearchBase']
            }
            if ($controls['CmbLdapScope'] -and $Tab.State.ContainsKey('ScopeIndex')) {
                $controls['CmbLdapScope'].SelectedIndex = $Tab.State['ScopeIndex']
            }
        }
        "LdapSql" {
            if ($controls['TxtLdapSqlQuery'] -and $Tab.State.ContainsKey('SqlQuery')) {
                $controls['TxtLdapSqlQuery'].Text = $Tab.State['SqlQuery']
            }
        }
        "AttributeEditor" {
            if ($controls['TxtSearchAttr'] -and $Tab.State.ContainsKey('SearchAttr')) {
                $controls['TxtSearchAttr'].Text = $Tab.State['SearchAttr']
            }
        }
    }
}

function Update-WorkspaceTabStrip {
    if (-not $controls['WorkspaceTabHost']) { return }
    $tabHost = $controls['WorkspaceTabHost']
    $tabHost.Children.Clear()
    
    # If in Single mode, hide tab bar
    if ($state.WorkspaceMode -eq "Single") {
        if ($controls['WorkspaceTabBar']) { $controls['WorkspaceTabBar'].Visibility = [System.Windows.Visibility]::Collapsed }
        if ($controls['TxtWorkspaceModeIcon']) { $controls['TxtWorkspaceModeIcon'].Text = "🔲" }
        if ($controls['TxtWorkspaceModeLabel']) { $controls['TxtWorkspaceModeLabel'].Text = "Single" }
        return
    } else {
        if ($controls['WorkspaceTabBar']) { $controls['WorkspaceTabBar'].Visibility = [System.Windows.Visibility]::Visible }
        if ($controls['TxtWorkspaceModeIcon']) { $controls['TxtWorkspaceModeIcon'].Text = "🗂️" }
        if ($controls['TxtWorkspaceModeLabel']) { $controls['TxtWorkspaceModeLabel'].Text = "Tabs" }
    }

    foreach ($tab in $state.OpenTabs) {
        $pName = $tab.PanelName
        if ([string]::IsNullOrWhiteSpace($pName)) { continue }
        $meta = if (-not [string]::IsNullOrWhiteSpace($pName) -and $global:PanelCatalog.Contains($pName)) { $global:PanelCatalog[$pName] } else { [PSCustomObject]@{ Title = $pName; Icon = "📄"; Category = "Tool" } }
        $isActive = ($state.ActiveTabId -eq $tab.Id)
        $isDetached = (-not [string]::IsNullOrWhiteSpace($pName) -and $state.DetachedWindows.ContainsKey($pName))
        $tabTitle = if ($tab.Title) { $tab.Title } else { $meta.Title }

        # Tab Outer Border
        $tabBorder = [System.Windows.Controls.Border]::new()
        $tabBorder.Height = 28
        $tabBorder.CornerRadius = [System.Windows.CornerRadius]::new(4)
        $tabBorder.Margin = [System.Windows.Thickness]::new(0, 0, 4, 0)
        $tabBorder.Padding = [System.Windows.Thickness]::new(8, 2, 6, 2)
        $tabBorder.Cursor = [System.Windows.Input.Cursors]::Hand
        $tabBorder.ToolTip = if ($isDetached) { "$tabTitle (Detached Window) - Click to focus" } else { "$tabTitle - Click to view, Drag to reorder" }
        $tabBorder.Tag = $tab.Id

        # Dynamic theming for tab border
        if ($isActive) {
            $tabBorder.SetResourceReference([System.Windows.Controls.Border]::BackgroundProperty, "BgCard")
            $tabBorder.SetResourceReference([System.Windows.Controls.Border]::BorderBrushProperty, "AccentPrimary")
            $tabBorder.BorderThickness = [System.Windows.Thickness]::new(1, 1, 1, 2)
        } else {
            $tabBorder.Background = [System.Windows.Media.Brushes]::Transparent
            $tabBorder.BorderBrush = [System.Windows.Media.Brushes]::Transparent
            $tabBorder.BorderThickness = [System.Windows.Thickness]::new(1)
        }

        # Tab Inner Content
        $tabPanel = [System.Windows.Controls.StackPanel]::new()
        $tabPanel.Orientation = [System.Windows.Controls.Orientation]::Horizontal
        $tabPanel.VerticalAlignment = [System.Windows.VerticalAlignment]::Center
        $tabPanel.Tag = $tab.Id

        # Icon
        $tbIcon = [System.Windows.Controls.TextBlock]::new()
        $tbIcon.Text = if ($isDetached) { "⧉ $($meta.Icon)" } else { $meta.Icon }
        $tbIcon.FontSize = 11
        $tbIcon.Margin = [System.Windows.Thickness]::new(0, 0, 5, 0)
        $tbIcon.VerticalAlignment = [System.Windows.VerticalAlignment]::Center
        $tbIcon.Tag = $tab.Id
        if ($isActive) {
            $tbIcon.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, "AccentPrimary")
        } else {
            $tbIcon.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, "TextSecondary")
        }
        [void]$tabPanel.Children.Add($tbIcon)

        # Title
        $tbTitle = [System.Windows.Controls.TextBlock]::new()
        $tbTitle.Text = $tabTitle
        $tbTitle.FontSize = 11.5
        $tbTitle.FontWeight = if ($isActive) { [System.Windows.FontWeights]::SemiBold } else { [System.Windows.FontWeights]::Normal }
        $tbTitle.VerticalAlignment = [System.Windows.VerticalAlignment]::Center
        $tbTitle.Tag = $tab.Id
        if ($isActive) {
            $tbTitle.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, "TextPrimary")
        } else {
            $tbTitle.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, "TextSecondary")
        }
        [void]$tabPanel.Children.Add($tbTitle)

        # Detach Button
        if ($state.AllowMultiWindow) {
            $btnDetach = [System.Windows.Controls.Button]::new()
            $btnDetach.Style = $window.TryFindResource("WorkspaceTabDetachBtn")
            $btnDetach.Content = if ($isDetached) { [string][char]0x2B07 } else { [string][char]0x29C9 }
            $btnDetach.ToolTip = if ($isDetached) { "Dock back into main window" } else { "Detach to separate window" }
            $btnDetach.Tag = $pName
            $btnDetach.Add_Click([System.Windows.RoutedEventHandler]{
                param($s, $e)
                $e.Handled = $true
                $p = if ($s -is [System.Windows.FrameworkElement] -and $s.Tag) { $s.Tag } else { $null }
                if (-not [string]::IsNullOrWhiteSpace($p)) {
                    if ($state.DetachedWindows.ContainsKey($p)) {
                        Dock-PanelToMainWindow -PanelName $p
                    } else {
                        Detach-PanelToWindow -PanelName $p
                    }
                }
            })
            [void]$tabPanel.Children.Add($btnDetach)
        }

        # Close Button (X)
        $btnClose = [System.Windows.Controls.Button]::new()
        $btnClose.Style = $window.TryFindResource("WorkspaceTabCloseBtn")
        $btnClose.Content = [string][char]0x2715
        $btnClose.ToolTip = "Close tab (Ctrl+W)"
        $btnClose.Tag = $tab.Id
        $btnClose.Add_Click([System.Windows.RoutedEventHandler]{
            param($s, $e)
            $e.Handled = $true
            $tId = if ($s -is [System.Windows.FrameworkElement] -and $s.Tag) { $s.Tag } else { $null }
            if (-not [string]::IsNullOrWhiteSpace($tId)) {
                Remove-WorkspaceTab -TabId $tId
            }
        })
        [void]$tabPanel.Children.Add($btnClose)

        $tabBorder.Child = $tabPanel

        # Drag & Click Handlers on Tab Border
        $tabBorder.Add_PreviewMouseLeftButtonDown([System.Windows.Input.MouseButtonEventHandler]{
            param($s, $e)
            $src = $e.OriginalSource
            if ($src -is [System.Windows.FrameworkElement]) {
                $cur = $src
                $isBtn = $false
                while ($cur -and $cur -ne $s) {
                    if ($cur -is [System.Windows.Controls.Button]) { $isBtn = $true; break }
                    $cur = [System.Windows.Media.VisualTreeHelper]::GetParent($cur)
                }
                if ($isBtn) { return }
            }
            $state.TabDragContext.IsMouseDown = $true
            $state.TabDragContext.IsDragging = $false
            $state.TabDragContext.StartPoint = $e.GetPosition($controls['WorkspaceTabHost'])
            $state.TabDragContext.SourceTabId = $s.Tag
            $state.TabDragContext.SourceBorder = $s
        })

        $tabBorder.Add_PreviewMouseMove([System.Windows.Input.MouseEventHandler]{
            param($s, $e)
            if (-not $state.TabDragContext.IsMouseDown) { return }
            if ($state.TabDragContext.SourceBorder -ne $s) { return }
            $hostPanel = $controls['WorkspaceTabHost']
            if (-not $hostPanel) { return }
            $curPos = $e.GetPosition($hostPanel)
            $deltaX = [Math]::Abs($curPos.X - $state.TabDragContext.StartPoint.X)

            if (-not $state.TabDragContext.IsDragging -and $deltaX -ge 6) {
                $state.TabDragContext.IsDragging = $true
                [void]$s.CaptureMouse()
                $s.Opacity = 0.65
                $s.Cursor = [System.Windows.Input.Cursors]::SizeWE
            }

            if ($state.TabDragContext.IsDragging) {
                $curTabId = $state.TabDragContext.SourceTabId
                $curIdx = -1
                for ($idx = 0; $idx -lt $state.OpenTabs.Count; $idx++) {
                    if ($state.OpenTabs[$idx].Id -eq $curTabId) { $curIdx = $idx; break }
                }
                if ($curIdx -ge 0) {
                    for ($targetIdx = 0; $targetIdx -lt $hostPanel.Children.Count; $targetIdx++) {
                        $child = $hostPanel.Children[$targetIdx]
                        if ($child -eq $s) { continue }
                        $childPos = $child.TranslatePoint([System.Windows.Point]::new(0, 0), $hostPanel)
                        $midX = $childPos.X + ($child.ActualWidth / 2)

                        if ($curIdx -lt $targetIdx -and $curPos.X -gt $midX) {
                            $tabItem = $state.OpenTabs[$curIdx]
                            $state.OpenTabs.RemoveAt($curIdx)
                            $state.OpenTabs.Insert($targetIdx, $tabItem)
                            $hostPanel.Children.Remove($s)
                            $hostPanel.Children.Insert($targetIdx, $s)
                            break
                        } elseif ($curIdx -gt $targetIdx -and $curPos.X -lt $midX) {
                            $tabItem = $state.OpenTabs[$curIdx]
                            $state.OpenTabs.RemoveAt($curIdx)
                            $state.OpenTabs.Insert($targetIdx, $tabItem)
                            $hostPanel.Children.Remove($s)
                            $hostPanel.Children.Insert($targetIdx, $s)
                            break
                        }
                    }
                }
            }
        })

        $tabBorder.Add_PreviewMouseLeftButtonUp([System.Windows.Input.MouseButtonEventHandler]{
            param($s, $e)
            if ($state.TabDragContext.IsMouseDown) {
                $wasDragging = $state.TabDragContext.IsDragging
                $tabId = $state.TabDragContext.SourceTabId

                if ($wasDragging) {
                    $s.ReleaseMouseCapture()
                    $s.Opacity = 1.0
                    $s.Cursor = [System.Windows.Input.Cursors]::Hand
                    $state.TabDragContext.IsDragging = $false
                    $state.TabDragContext.IsMouseDown = $false
                    $state.TabDragContext.SourceBorder = $null

                    if ($state.RestoreTabsOnStartup) {
                        $openNames = @($state.OpenTabs | ForEach-Object { $_.PanelName })
                        $appConfig.UI.OpenTabs = $openNames
                        [void](Save-AppSettings -Config $appConfig)
                    }
                    Update-WorkspaceTabStrip
                } else {
                    $state.TabDragContext.IsMouseDown = $false
                    $state.TabDragContext.SourceBorder = $null
                    if (-not [string]::IsNullOrWhiteSpace($tabId)) {
                        Select-WorkspaceTab -TabId $tabId
                    }
                }
            }
        })

        $tabBorder.Add_LostMouseCapture([System.Windows.Input.MouseEventHandler]{
            param($s, $e)
            if ($state.TabDragContext.IsDragging) {
                $s.Opacity = 1.0
                $s.Cursor = [System.Windows.Input.Cursors]::Hand
                $state.TabDragContext.IsDragging = $false
                $state.TabDragContext.IsMouseDown = $false
                $state.TabDragContext.SourceBorder = $null
                Update-WorkspaceTabStrip
            }
        })

        # Middle Click to close
        $tabBorder.Add_MouseDown([System.Windows.Input.MouseButtonEventHandler]{
            param($s, $e)
            if ($e.ChangedButton -eq [System.Windows.Input.MouseButton]::Middle) {
                $e.Handled = $true
                $tId = if ($s -is [System.Windows.FrameworkElement] -and $s.Tag) {
                    $s.Tag
                } elseif ($e.Source -is [System.Windows.FrameworkElement] -and $e.Source.Tag) {
                    $e.Source.Tag
                } else {
                    $null
                }
                if (-not [string]::IsNullOrWhiteSpace($tId)) {
                    Remove-WorkspaceTab -TabId $tId
                }
            }
        })

        # Tab Context Menu
        $cm = [System.Windows.Controls.ContextMenu]::new()
        $cm.Style = $window.TryFindResource("ModernContextMenu")

        $miDup = [System.Windows.Controls.MenuItem]::new()
        $miDup.Header = "➕  Duplicate Tab (New Instance)"
        $miDup.Tag = $pName
        $miDup.Add_Click([System.Windows.RoutedEventHandler]{
            param($s, $e)
            $p = if ($s -is [System.Windows.FrameworkElement] -and $s.Tag) { $s.Tag } else { $null }
            if (-not [string]::IsNullOrWhiteSpace($p)) {
                Add-WorkspaceTab -PanelName $p -NewInstance -Activate $true
            }
        })
        [void]$cm.Items.Add($miDup)

        $miRename = [System.Windows.Controls.MenuItem]::new()
        $miRename.Header = "🏷️  Rename Tab..."
        $miRename.Tag = $tab.Id
        $miRename.Add_Click([System.Windows.RoutedEventHandler]{
            param($s, $e)
            $tId = if ($s -is [System.Windows.FrameworkElement] -and $s.Tag) { $s.Tag } else { $null }
            if (-not [string]::IsNullOrWhiteSpace($tId)) {
                Rename-WorkspaceTab -TabId $tId
            }
        })
        [void]$cm.Items.Add($miRename)

        $miNewWin = [System.Windows.Controls.MenuItem]::new()
        $miNewWin.Header = "🗖  Open in New Independent Window"
        $miNewWin.Tag = $pName
        $miNewWin.Add_Click([System.Windows.RoutedEventHandler]{
            param($s, $e)
            $p = if ($s -is [System.Windows.FrameworkElement] -and $s.Tag) { $s.Tag } else { $null }
            Launch-NewApplicationWindow -ToolName $p
        })
        [void]$cm.Items.Add($miNewWin)

        [void]$cm.Items.Add([System.Windows.Controls.Separator]::new())

        $miDetach = [System.Windows.Controls.MenuItem]::new()
        $miDetach.Header = if ($isDetached) { "$([char]0x2B07) Dock Back into Main Window" } else { "$([char]0x29C9) Detach to Separate Window" }
        $miDetach.Tag = $pName
        $miDetach.Add_Click([System.Windows.RoutedEventHandler]{
            param($s, $e)
            $p = if ($s -is [System.Windows.FrameworkElement] -and $s.Tag) { $s.Tag } else { $null }
            if (-not [string]::IsNullOrWhiteSpace($p)) {
                if ($state.DetachedWindows.ContainsKey($p)) {
                    Dock-PanelToMainWindow -PanelName $p
                } else {
                    Detach-PanelToWindow -PanelName $p
                }
            }
        })
        [void]$cm.Items.Add($miDetach)

        [void]$cm.Items.Add([System.Windows.Controls.Separator]::new())

        $miClose = [System.Windows.Controls.MenuItem]::new()
        $miClose.Header = "✕ Close Tab"
        $miClose.Tag = $tab.Id
        $miClose.Add_Click([System.Windows.RoutedEventHandler]{
            param($s, $e)
            $tId = if ($s -is [System.Windows.FrameworkElement] -and $s.Tag) { $s.Tag } else { $null }
            if (-not [string]::IsNullOrWhiteSpace($tId)) {
                Remove-WorkspaceTab -TabId $tId
            }
        })
        [void]$cm.Items.Add($miClose)

        $miCloseOthers = [System.Windows.Controls.MenuItem]::new()
        $miCloseOthers.Header = "Close Other Tabs"
        $miCloseOthers.Tag = $tab.Id
        $miCloseOthers.Add_Click([System.Windows.RoutedEventHandler]{
            param($s, $e)
            $tId = if ($s -is [System.Windows.FrameworkElement] -and $s.Tag) { $s.Tag } else { $null }
            if (-not [string]::IsNullOrWhiteSpace($tId)) {
                $toClose = @($state.OpenTabs | Where-Object { $_.Id -ne $tId })
                foreach ($t in $toClose) { Remove-WorkspaceTab -TabId $t.Id }
            }
        })
        [void]$cm.Items.Add($miCloseOthers)

        $miCloseAll = [System.Windows.Controls.MenuItem]::new()
        $miCloseAll.Header = "Close All Tabs"
        $miCloseAll.Add_Click([System.Windows.RoutedEventHandler]{
            param($s, $e)
            $toClose = @($state.OpenTabs)
            foreach ($t in $toClose) { Remove-WorkspaceTab -TabId $t.Id }
        })
        [void]$cm.Items.Add($miCloseAll)

        $tabBorder.ContextMenu = $cm
        [void]$tabHost.Children.Add($tabBorder)
    }
}

function Add-WorkspaceTab {
    param (
        [string]$PanelName,
        [bool]$Activate = $true,
        [switch]$NewInstance,
        [string]$CustomTitle = ""
    )
    if ([string]::IsNullOrWhiteSpace($PanelName)) { return }

    $existing = if (-not $NewInstance) {
        $state.OpenTabs | Where-Object { $_.PanelName -eq $PanelName } | Select-Object -First 1
    } else { $null }

    if ($existing) {
        if ($Activate) {
            Select-WorkspaceTab -TabId $existing.Id
        } else {
            Update-WorkspaceTabStrip
        }
        return
    }

    $meta = if (-not [string]::IsNullOrWhiteSpace($PanelName) -and $global:PanelCatalog.Contains($PanelName)) {
        $global:PanelCatalog[$PanelName]
    } else {
        [PSCustomObject]@{ Title = $PanelName; Icon = "📄"; Category = "Tool" }
    }

    $existingCount = @($state.OpenTabs | Where-Object { $_.PanelName -eq $PanelName }).Count
    $instanceNum = $existingCount + 1
    $tabId = "${PanelName}_$([guid]::NewGuid().ToString('N').Substring(0, 6))"

    $displayTitle = if (-not [string]::IsNullOrWhiteSpace($CustomTitle)) {
        $CustomTitle
    } elseif ($instanceNum -gt 1) {
        "$($meta.Title) ($instanceNum)"
    } else {
        $meta.Title
    }

    $tabObj = [PSCustomObject]@{
        Id             = $tabId
        PanelName      = $PanelName
        Title          = $displayTitle
        Icon           = $meta.Icon
        InstanceNumber = $instanceNum
        State          = @{}
    }
    $state.OpenTabs.Add($tabObj)

    if ($Activate) {
        Select-WorkspaceTab -TabId $tabId
    } else {
        Update-WorkspaceTabStrip
    }
}

function Remove-WorkspaceTab {
    param ([string]$TabId)
    if ([string]::IsNullOrWhiteSpace($TabId)) { return }
    $targetTab = $state.OpenTabs | Where-Object { $_.Id -eq $TabId } | Select-Object -First 1
    if (-not $targetTab) {
        $targetTab = $state.OpenTabs | Where-Object { $_.PanelName -eq $TabId } | Select-Object -First 1
    }
    if (-not $targetTab) { return }

    $pName = $targetTab.PanelName
    $otherTabsForPanel = @($state.OpenTabs | Where-Object { $_.Id -ne $targetTab.Id -and $_.PanelName -eq $pName })

    if ($otherTabsForPanel.Count -eq 0 -and -not [string]::IsNullOrWhiteSpace($pName) -and $state.DetachedWindows.ContainsKey($pName)) {
        Dock-PanelToMainWindow -PanelName $pName -NoActivate
    }

    $idx = $state.OpenTabs.IndexOf($targetTab)
    [void]$state.OpenTabs.Remove($targetTab)

    if ($state.ActiveTabId -eq $targetTab.Id) {
        if ($state.OpenTabs.Count -gt 0) {
            $newIdx = [Math]::Min($idx, $state.OpenTabs.Count - 1)
            $nextTab = $state.OpenTabs[$newIdx]
            Select-WorkspaceTab -TabId $nextTab.Id
        } else {
            Add-WorkspaceTab -PanelName "Dashboard" -Activate $true
        }
    } else {
        Update-WorkspaceTabStrip
    }
}

function Select-WorkspaceTab {
    param ([string]$TabId)
    if ([string]::IsNullOrWhiteSpace($TabId)) { return }

    $targetTab = $state.OpenTabs | Where-Object { $_.Id -eq $TabId } | Select-Object -First 1
    if (-not $targetTab) {
        $targetTab = $state.OpenTabs | Where-Object { $_.PanelName -eq $TabId } | Select-Object -First 1
    }
    if (-not $targetTab) { return }

    # Save state of previously active tab before switching
    if ($state.ActiveTabId -and $state.ActiveTabId -ne $targetTab.Id) {
        $prevTab = $state.OpenTabs | Where-Object { $_.Id -eq $state.ActiveTabId } | Select-Object -First 1
        if ($prevTab) {
            Save-TabSessionState -Tab $prevTab
        }
    }

    $state.ActiveTabId = $targetTab.Id
    $PanelName = $targetTab.PanelName

    if (-not [string]::IsNullOrWhiteSpace($PanelName) -and $state.DetachedWindows.ContainsKey($PanelName)) {
        $detached = $state.DetachedWindows[$PanelName]
        if ($detached) {
            if ($detached.WindowState -eq [System.Windows.WindowState]::Minimized) {
                $detached.WindowState = [System.Windows.WindowState]::Normal
            }
            [void]$detached.Activate()
            $detached.Focus()
        }
    }

    # Restore session state for the selected tab
    Restore-TabSessionState -Tab $targetTab

    $targetCtrlName = "Panel$PanelName"
    if ($controls['ViewportContainer'] -and $controls[$targetCtrlName]) {
        foreach ($child in $controls['ViewportContainer'].Children) {
            if ($child -is [System.Windows.UIElement]) {
                $child.Visibility = if ($child.Name -eq $targetCtrlName) {
                    [System.Windows.Visibility]::Visible
                } else {
                    [System.Windows.Visibility]::Collapsed
                }
            }
        }
    }

    $state.IsSelectingTab = $true
    try {
        $radio = $controls["Nav$PanelName"]
        if ($radio -and -not $radio.IsChecked) {
            $radio.IsChecked = $true
        }
    } finally {
        $state.IsSelectingTab = $false
    }

    Record-NavHistory -PanelName $PanelName
    Update-WorkspaceTabStrip
}

function Detach-PanelToWindow {
    param ([string]$PanelName)
    if ([string]::IsNullOrWhiteSpace($PanelName)) { return }
    if (-not $state.AllowMultiWindow) {
        [System.Windows.MessageBox]::Show("Multi-Window workspace is currently disabled in Settings.", "Workspace Notice", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        return
    }
    if (-not [string]::IsNullOrWhiteSpace($PanelName) -and $state.DetachedWindows.ContainsKey($PanelName)) {
        $win = $state.DetachedWindows[$PanelName]
        if ($win.WindowState -eq [System.Windows.WindowState]::Minimized) { $win.WindowState = [System.Windows.WindowState]::Normal }
        [void]$win.Activate()
        $win.Focus()
        return
    }

    $panelKey = "Panel$PanelName"
    $panel = $controls[$panelKey]
    if (-not $panel) { return }

    $meta = if (-not [string]::IsNullOrWhiteSpace($PanelName) -and $global:PanelCatalog.Contains($PanelName)) { $global:PanelCatalog[$PanelName] } else { [PSCustomObject]@{ Title = $PanelName; Icon = "📋"; Category = "Tool Window" } }

    $detachedXamlPath = if ($viewsPath) { Join-Path $viewsPath "DetachedPanelWindow.xaml" } else { $null }
    if (-not $detachedXamlPath -or -not (Test-Path $detachedXamlPath)) {
        $detachedXamlPath = Join-Path $PSScriptRoot "Views\DetachedPanelWindow.xaml"
    }
    if (-not (Test-Path $detachedXamlPath)) {
        $detachedXamlPath = Join-Path (Get-Location) "Views\DetachedPanelWindow.xaml"
    }
    if (-not (Test-Path $detachedXamlPath)) {
        $detachedXamlPath = Join-Path (Split-Path -Parent $PSScriptRoot) "Views\DetachedPanelWindow.xaml"
    }
    if (-not (Test-Path $detachedXamlPath)) { return }

    $detachedWindow = if (Get-Command Load-XamlWindow -ErrorAction SilentlyContinue) {
        Load-XamlWindow -XamlPath $detachedXamlPath
    } else {
        $reader = [System.Xml.XmlReader]::Create([System.IO.StringReader](Get-Content $detachedXamlPath -Raw -Encoding UTF8))
        $loadedW = [System.Windows.Markup.XamlReader]::Load($reader)
        $reader.Close()
        if ($window) {
            foreach ($key in $window.Resources.Keys) {
                $loadedW.Resources[$key] = $window.Resources[$key]
            }
        }
        $loadedW
    }
    if (-not $detachedWindow) { return }
    if (Get-Command Apply-ThemeNode -ErrorAction SilentlyContinue) {
        Apply-ThemeNode $detachedWindow $state.CurrentTheme
    }

    $detachedWindow.Title = "Active Directory Management Studio - $($meta.Title)"
    $txtIcon = $detachedWindow.FindName("TxtDetachedIcon")
    if ($txtIcon) { $txtIcon.Text = $meta.Icon }
    $txtTitle = $detachedWindow.FindName("TxtDetachedTitle")
    if ($txtTitle) { $txtTitle.Text = $meta.Title }
    $txtCategory = $detachedWindow.FindName("TxtDetachedCategory")
    if ($txtCategory) { $txtCategory.Text = $meta.Category }
    $txtScope = $detachedWindow.FindName("TxtDetachedScope")
    if ($txtScope) { $txtScope.Text = if ($adContext.DomainName) { "Domain: $($adContext.DomainName)" } else { "Multi-Window Active" } }

    if ($controls['ViewportContainer'].Children.Contains($panel)) {
        $controls['ViewportContainer'].Children.Remove($panel)
    }

    $contentHost = $detachedWindow.FindName("DetachedContentHost")
    if ($contentHost) {
        [void]$contentHost.Children.Add($panel)
        $panel.Visibility = [System.Windows.Visibility]::Visible
    }

    $state.DetachedWindows[$PanelName] = $detachedWindow

    $btnDock = $detachedWindow.FindName("BtnDockBack")
    if ($btnDock) {
        $btnDock.Tag = $PanelName
        $btnDock.Add_Click([System.Windows.RoutedEventHandler]{
            param($s, $e)
            $p = if ($s -is [System.Windows.FrameworkElement] -and $s.Tag) { $s.Tag } else { $null }
            if (-not [string]::IsNullOrWhiteSpace($p)) {
                Dock-PanelToMainWindow -PanelName $p
            }
        })
    }

    $detachedWindow.Tag = $PanelName
    $detachedWindow.Add_Closing([System.ComponentModel.CancelEventHandler]{
        param($s, $e)
        $p = if ($s -is [System.Windows.FrameworkElement] -and $s.Tag) { $s.Tag } else { $null }
        if (-not [string]::IsNullOrWhiteSpace($p) -and $state.DetachedWindows.ContainsKey($p)) {
            Dock-PanelToMainWindow -PanelName $p
        }
    })

    $detachedWindow.Add_KeyDown([System.Windows.Input.KeyEventHandler]{
        param($s, $e)
        if ($e.Key -eq [System.Windows.Input.Key]::W -and ($e.KeyboardDevice.Modifiers -band [System.Windows.Input.ModifierKeys]::Control)) {
            $e.Handled = $true
            $p = if ($s -is [System.Windows.FrameworkElement] -and $s.Tag) { $s.Tag } else { $null }
            if (-not [string]::IsNullOrWhiteSpace($p)) {
                Dock-PanelToMainWindow -PanelName $p
            }
        }
    })

    $detachedWindow.Show()
    Update-WorkspaceTabStrip

    $remainingDocked = $state.OpenTabs | Where-Object { -not $state.DetachedWindows.ContainsKey($_.PanelName) }
    if ($remainingDocked -and ($remainingDocked.Count -gt 0)) {
        Select-WorkspaceTab -TabId $remainingDocked[0].PanelName
    }
}

function Dock-PanelToMainWindow {
    param (
        [string]$PanelName,
        [switch]$NoActivate
    )
    if ([string]::IsNullOrWhiteSpace($PanelName)) { return }
    if (-not $state.DetachedWindows.ContainsKey($PanelName)) { return }
    $detachedWindow = $state.DetachedWindows[$PanelName]
    $panelKey = "Panel$PanelName"
    $panel = $controls[$panelKey]

    if ($detachedWindow -and $panel) {
        $contentHost = $detachedWindow.FindName("DetachedContentHost")
        if ($contentHost -and $contentHost.Children.Contains($panel)) {
            $contentHost.Children.Remove($panel)
        }
        if (-not $controls['ViewportContainer'].Children.Contains($panel)) {
            [void]$controls['ViewportContainer'].Children.Add($panel)
        }
        $state.DetachedWindows.Remove($PanelName)
        try {
            $detachedWindow.Close()
        } catch {}
    }

    if (-not $NoActivate) {
        Add-WorkspaceTab -PanelName $PanelName -Activate $true
        if ($window) {
            if ($window.WindowState -eq [System.Windows.WindowState]::Minimized) {
                $window.WindowState = [System.Windows.WindowState]::Normal
            }
            [void]$window.Activate()
            $window.Focus()
        }
    }
}

function Dock-AllDetachedWindows {
    if (-not $state.DetachedWindows -or $state.DetachedWindows.Count -eq 0) {
        Set-Status -Message "No detached tool windows are currently open."
        return
    }
    $panelNames = @($state.DetachedWindows.Keys)
    foreach ($p in $panelNames) {
        Dock-PanelToMainWindow -PanelName $p -NoActivate
    }
    if ($state.ActiveTabId) {
        Select-WorkspaceTab -TabId $state.ActiveTabId
    }
    Set-Status -Message "All detached tool windows docked back into main window."
}

function Show-AllDetachedWindows {
    if (-not $state.DetachedWindows -or $state.DetachedWindows.Count -eq 0) {
        Set-Status -Message "No detached tool windows are currently open."
        return
    }
    foreach ($win in $state.DetachedWindows.Values) {
        if ($win) {
            if ($win.WindowState -eq [System.Windows.WindowState]::Minimized) {
                $win.WindowState = [System.Windows.WindowState]::Normal
            }
            [void]$win.Activate()
            $win.Focus()
        }
    }
    Set-Status -Message "All detached tool windows brought to front."
}

function Reset-WorkspaceLayout {
    Dock-AllDetachedWindows
    $defaultTabs = @("Dashboard", "Users", "Groups", "Computers")
    $state.OpenTabs.Clear()
    foreach ($t in $defaultTabs) {
        Add-WorkspaceTab -PanelName $t -Activate $false
    }
    Select-WorkspaceTab -TabId "Dashboard"
    Set-WorkspaceMode -Mode "Tabs"
    Save-AppSettings -Config $appConfig
    Set-Status -Message "Workspace layout reset to default multi-tab layout."
}

function Show-WorkspaceLayoutMenu {
    param ($targetElement)
    $cm = [System.Windows.Controls.ContextMenu]::new()
    $cm.Style = $window.TryFindResource("ModernContextMenu")
    if ($targetElement) {
        $cm.PlacementTarget = $targetElement
        $cm.Placement = [System.Windows.Controls.Primitives.PlacementMode]::Bottom
    }

    # SECTION 1: WORKSPACE VIEWPORT LAYOUT
    $secWorkspace = [System.Windows.Controls.MenuItem]::new()
    $secWorkspace.Header = "🗂️ WORKSPACE MODE"
    $secWorkspace.IsEnabled = $false
    $secWorkspace.FontWeight = [System.Windows.FontWeights]::Bold
    [void]$cm.Items.Add($secWorkspace)

    # Item: Multi-Tab Workspace
    $miTabs = [System.Windows.Controls.MenuItem]::new()
    $isTabs = ($state.WorkspaceMode -eq "Tabs")
    $miTabs.Header = if ($isTabs) { "✔  🗂️ Multi-Tab Workspace (Active)" } else { "    🗂️ Multi-Tab Workspace" }
    $miTabs.FontWeight = if ($isTabs) { [System.Windows.FontWeights]::SemiBold } else { [System.Windows.FontWeights]::Normal }
    $miTabs.Add_Click([System.Windows.RoutedEventHandler]{
        param($s, $e)
        Set-WorkspaceMode -Mode "Tabs"
        Save-AppSettings -Config $appConfig
        Set-Status -Message "Workspace layout changed to: Multi-Tab Workspace"
    })
    [void]$cm.Items.Add($miTabs)

    # Item: Single Window Viewport
    $miSingle = [System.Windows.Controls.MenuItem]::new()
    $isSingle = ($state.WorkspaceMode -eq "Single")
    $miSingle.Header = if ($isSingle) { "✔  🔲 Single Window Viewport (Active)" } else { "    🔲 Single Window Viewport" }
    $miSingle.FontWeight = if ($isSingle) { [System.Windows.FontWeights]::SemiBold } else { [System.Windows.FontWeights]::Normal }
    $miSingle.Add_Click([System.Windows.RoutedEventHandler]{
        param($s, $e)
        Set-WorkspaceMode -Mode "Single"
        Save-AppSettings -Config $appConfig
        Set-Status -Message "Workspace layout changed to: Single Window Viewport"
    })
    [void]$cm.Items.Add($miSingle)

    # SEPARATOR
    [void]$cm.Items.Add([System.Windows.Controls.Separator]::new())

    # SECTION 2: WINDOW LAYOUT & DETACHED WINDOWS
    $secWindows = [System.Windows.Controls.MenuItem]::new()
    $detachedCount = if ($state.DetachedWindows) { $state.DetachedWindows.Count } else { 0 }
    $secWindows.Header = "⧉ WINDOW & MULTI-WINDOW LAYOUT"
    $secWindows.IsEnabled = $false
    $secWindows.FontWeight = [System.Windows.FontWeights]::Bold
    [void]$cm.Items.Add($secWindows)

    # Open New Application Window
    $miNewAppWin = [System.Windows.Controls.MenuItem]::new()
    $miNewAppWin.Header = "🗖  Open New Application Window"
    $miNewAppWin.InputGestureText = "Ctrl+N"
    $miNewAppWin.Add_Click([System.Windows.RoutedEventHandler]{
        param($s, $e)
        Launch-NewApplicationWindow
    })
    [void]$cm.Items.Add($miNewAppWin)

    # Open Active Tool in Independent Window
    $miNewToolWin = [System.Windows.Controls.MenuItem]::new()
    $miNewToolWin.Header = "🗖  Open Active Tool in Independent Window"
    $miNewToolWin.IsEnabled = [bool]($state.ActiveTabId)
    $miNewToolWin.Add_Click([System.Windows.RoutedEventHandler]{
        param($s, $e)
        $activeTab = $state.OpenTabs | Where-Object { $_.Id -eq $state.ActiveTabId } | Select-Object -First 1
        $p = if ($activeTab) { $activeTab.PanelName } else { $state.ActiveTabId }
        if (-not [string]::IsNullOrWhiteSpace($p)) {
            Launch-NewApplicationWindow -ToolName $p
        }
    })
    [void]$cm.Items.Add($miNewToolWin)

    # Detach Current Tab
    $miDetachCur = [System.Windows.Controls.MenuItem]::new()
    $miDetachCur.Header = "⧉  Detach Current Tool to Separate Window"
    $miDetachCur.InputGestureText = "Ctrl+Shift+D"
    $miDetachCur.IsEnabled = [bool]($state.ActiveTabId -and -not $state.DetachedWindows.ContainsKey($state.ActiveTabId))
    $miDetachCur.Add_Click([System.Windows.RoutedEventHandler]{
        param($s, $e)
        $activeTab = $state.OpenTabs | Where-Object { $_.Id -eq $state.ActiveTabId } | Select-Object -First 1
        $p = if ($activeTab) { $activeTab.PanelName } else { $state.ActiveTabId }
        if (-not [string]::IsNullOrWhiteSpace($p)) {
            Detach-PanelToWindow -PanelName $p
        }
    })
    [void]$cm.Items.Add($miDetachCur)

    # Dock All Windows Back
    $miDockAll = [System.Windows.Controls.MenuItem]::new()
    $miDockAll.Header = if ($detachedCount -gt 0) { "⬇️  Dock All Windows Back into Main Window ($detachedCount detached)" } else { "⬇️  Dock All Windows Back into Main Window" }
    $miDockAll.IsEnabled = ($detachedCount -gt 0)
    $miDockAll.Add_Click([System.Windows.RoutedEventHandler]{
        param($s, $e)
        Dock-AllDetachedWindows
    })
    [void]$cm.Items.Add($miDockAll)

    if ($detachedCount -gt 0) {
        $miFocusAll = [System.Windows.Controls.MenuItem]::new()
        $miFocusAll.Header = "🪟  Bring All Detached Windows to Front"
        $miFocusAll.Add_Click([System.Windows.RoutedEventHandler]{
            param($s, $e)
            Show-AllDetachedWindows
        })
        [void]$cm.Items.Add($miFocusAll)
    }

    # Toggle Multi-Window Allowed
    $miAllowMulti = [System.Windows.Controls.MenuItem]::new()
    $miAllowMulti.Header = if ($state.AllowMultiWindow) { "✔  Allow Multi-Window (Detached Windows Enabled)" } else { "    Allow Multi-Window (Detached Windows Disabled)" }
    $miAllowMulti.Add_Click([System.Windows.RoutedEventHandler]{
        param($s, $e)
        $state.AllowMultiWindow = -not $state.AllowMultiWindow
        $appConfig.UI.AllowMultiWindow = $state.AllowMultiWindow
        Save-AppSettings -Config $appConfig
        if (-not $state.AllowMultiWindow) {
            Dock-AllDetachedWindows
        }
        Update-WorkspaceTabStrip
        Set-Status -Message "Multi-Window workspace is now $(if ($state.AllowMultiWindow) { 'Enabled' } else { 'Disabled' })."
    })
    [void]$cm.Items.Add($miAllowMulti)

    # SEPARATOR
    [void]$cm.Items.Add([System.Windows.Controls.Separator]::new())

    # SECTION 3: TABS & LAYOUT PRESETS
    $miNewTab = [System.Windows.Controls.MenuItem]::new()
    $miNewTab.Header = "➕  Open Tool in New Tab..."
    $miNewTab.Add_Click([System.Windows.RoutedEventHandler]{
        param($s, $e)
        if ($controls['BtnWorkspaceNewTab']) {
            $controls['BtnWorkspaceNewTab'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
        }
    })
    [void]$cm.Items.Add($miNewTab)

    # Duplicate Active Tab
    $miDupActive = [System.Windows.Controls.MenuItem]::new()
    $miDupActive.Header = "➕  Duplicate Active Tab (New Instance)"
    $miDupActive.InputGestureText = "Ctrl+Shift+N"
    $miDupActive.IsEnabled = [bool]($state.ActiveTabId)
    $miDupActive.Add_Click([System.Windows.RoutedEventHandler]{
        param($s, $e)
        $activeTab = $state.OpenTabs | Where-Object { $_.Id -eq $state.ActiveTabId } | Select-Object -First 1
        $p = if ($activeTab) { $activeTab.PanelName } else { $state.ActiveTabId }
        if (-not [string]::IsNullOrWhiteSpace($p)) {
            Add-WorkspaceTab -PanelName $p -NewInstance -Activate $true
        }
    })
    [void]$cm.Items.Add($miDupActive)

    $miResetTabs = [System.Windows.Controls.MenuItem]::new()
    $miResetTabs.Header = "🔄  Reset Workspace to Default Tabs (Dashboard, Users, Groups, Computers)"
    $miResetTabs.Add_Click([System.Windows.RoutedEventHandler]{
        param($s, $e)
        Reset-WorkspaceLayout
    })
    [void]$cm.Items.Add($miResetTabs)

    $cm.IsOpen = $true
}

function Set-WorkspaceMode {
    param ([string]$Mode)
    if ($Mode -notin @("Tabs", "Single")) { $Mode = "Tabs" }
    $state.WorkspaceMode = $Mode
    $appConfig.UI.WorkspaceMode = $Mode

    if ($controls['CmbWorkspaceMode']) {
        $controls['CmbWorkspaceMode'].SelectedIndex = if ($Mode -eq "Tabs") { 0 } else { 1 }
    }

    if ($Mode -eq "Single") {
        if ($controls['WorkspaceTabBar']) { $controls['WorkspaceTabBar'].Visibility = [System.Windows.Visibility]::Collapsed }
        if ($controls['TxtWorkspaceModeIcon']) { $controls['TxtWorkspaceModeIcon'].Text = "🔲" }
        if ($controls['TxtWorkspaceModeLabel']) { $controls['TxtWorkspaceModeLabel'].Text = "Single" }
        if ($controls['TxtHeaderLayoutIcon']) { $controls['TxtHeaderLayoutIcon'].Text = "🔲" }
        if ($controls['BtnWorkspaceLayoutMenu']) { $controls['BtnWorkspaceLayoutMenu'].ToolTip = "Switch Workspace & Window Layout (Single Viewport active - Ctrl+Shift+M)" }
    } else {
        if ($controls['WorkspaceTabBar']) { $controls['WorkspaceTabBar'].Visibility = [System.Windows.Visibility]::Visible }
        if ($controls['TxtWorkspaceModeIcon']) { $controls['TxtWorkspaceModeIcon'].Text = "🗂️" }
        if ($controls['TxtWorkspaceModeLabel']) { $controls['TxtWorkspaceModeLabel'].Text = "Tabs" }
        if ($controls['TxtHeaderLayoutIcon']) { $controls['TxtHeaderLayoutIcon'].Text = "🗂️" }
        if ($controls['BtnWorkspaceLayoutMenu']) { $controls['BtnWorkspaceLayoutMenu'].ToolTip = "Switch Workspace & Window Layout (Multi-Tab Workspace active - Ctrl+Shift+M)" }
    }
    Update-WorkspaceTabStrip
}

function Init-SidebarNavigationContextMenus {
    $panels = @(
        'Dashboard', 'Users', 'Groups', 'OUs', 'Computers',
        'DirectorySearch', 'LdapSql', 'AttributeEditor', 'HtmlView', 'ObjectCompare',
        'LdifStudio', 'AuditReports', 'SchemaBrowser', 'BulkEditor',
        'Basket', 'RequestLog',
        'RecycleBin', 'ServerMonitor',
        'Connections', 'Settings',
        'SecurityAcl', 'KerberosSuite', 'ReplicationSuite', 'DiagnosticsToolbox', 'NetworkDiagnostics'
    )
    foreach ($p in $panels) {
        $radio = $controls["Nav$p"]
        if ($radio) {
            $cm = [System.Windows.Controls.ContextMenu]::new()
            $cm.Style = $window.TryFindResource("ModernContextMenu")

            $miTab = [System.Windows.Controls.MenuItem]::new()
            $miTab.Header = "🗂️ Open in Tab"
            $miTab.Tag = $p
            $miTab.Add_Click([System.Windows.RoutedEventHandler]{
                param($s, $e)
                $target = if ($s -is [System.Windows.FrameworkElement] -and $s.Tag) { $s.Tag } else { $null }
                if (-not [string]::IsNullOrWhiteSpace($target)) {
                    Add-WorkspaceTab -PanelName $target -Activate $true
                }
            })
            [void]$cm.Items.Add($miTab)

            $miTabNew = [System.Windows.Controls.MenuItem]::new()
            $miTabNew.Header = "➕ Open New Instance in Tab"
            $miTabNew.Tag = $p
            $miTabNew.Add_Click([System.Windows.RoutedEventHandler]{
                param($s, $e)
                $target = if ($s -is [System.Windows.FrameworkElement] -and $s.Tag) { $s.Tag } else { $null }
                if (-not [string]::IsNullOrWhiteSpace($target)) {
                    Add-WorkspaceTab -PanelName $target -NewInstance -Activate $true
                }
            })
            [void]$cm.Items.Add($miTabNew)

            $miWin = [System.Windows.Controls.MenuItem]::new()
            $miWin.Header = "⧉ Detach to Separate Window"
            $miWin.Tag = $p
            $miWin.Add_Click([System.Windows.RoutedEventHandler]{
                param($s, $e)
                $target = if ($s -is [System.Windows.FrameworkElement] -and $s.Tag) { $s.Tag } else { $null }
                if (-not [string]::IsNullOrWhiteSpace($target)) {
                    Detach-PanelToWindow -PanelName $target
                }
            })
            [void]$cm.Items.Add($miWin)

            $miIndWin = [System.Windows.Controls.MenuItem]::new()
            $miIndWin.Header = "🗖 Open in New Independent Window"
            $miIndWin.Tag = $p
            $miIndWin.Add_Click([System.Windows.RoutedEventHandler]{
                param($s, $e)
                $target = if ($s -is [System.Windows.FrameworkElement] -and $s.Tag) { $s.Tag } else { $null }
                if (-not [string]::IsNullOrWhiteSpace($target)) {
                    Launch-NewApplicationWindow -ToolName $target
                }
            })
            [void]$cm.Items.Add($miIndWin)

            $radio.ContextMenu = $cm
        }
    }
}

function Show-Panel {
    param ([string]$PanelName)
    if ([string]::IsNullOrWhiteSpace($PanelName)) { return }

    if ($state.WorkspaceMode -eq "Tabs") {
        if (-not [string]::IsNullOrWhiteSpace($PanelName) -and $state.DetachedWindows.ContainsKey($PanelName)) {
            $dWin = $state.DetachedWindows[$PanelName]
            if ($dWin) {
                if ($dWin.WindowState -eq [System.Windows.WindowState]::Minimized) { $dWin.WindowState = [System.Windows.WindowState]::Normal }
                [void]$dWin.Activate()
                $dWin.Focus()
            }
        } else {
            Add-WorkspaceTab -PanelName $PanelName -Activate $true
        }
    } else {
        $panels = @(
            'PanelDashboard', 'PanelUsers', 'PanelGroups', 'PanelOUs', 'PanelComputers',
            'PanelDirectorySearch', 'PanelLdapSql', 'PanelAttributeEditor', 'PanelHtmlView', 'PanelObjectCompare',
            'PanelLdifStudio', 'PanelAuditReports', 'PanelSchemaBrowser', 'PanelBulkEditor',
            'PanelBasket', 'PanelRequestLog',
            'PanelRecycleBin', 'PanelServerMonitor',
            'PanelConnections', 'PanelSettings',
            'PanelSecurityAcl', 'PanelKerberosSuite', 'PanelReplicationSuite', 'PanelDiagnosticsToolbox', 'PanelNetworkDiagnostics'
        )
        $targetName = "Panel$PanelName"
        foreach ($p in $panels) {
            if ($controls[$p]) {
                $controls[$p].Visibility = if ($p -eq $targetName) { [System.Windows.Visibility]::Visible } else { [System.Windows.Visibility]::Collapsed }
            }
        }
        $state.ActiveTabId = $PanelName
    }
    Record-NavHistory -PanelName $PanelName
}

# Wire TabBar Action Buttons
if ($controls['BtnWorkspaceNewTab']) {
    $controls['BtnWorkspaceNewTab'].Add_Click({
        $cm = [System.Windows.Controls.ContextMenu]::new()
        $cm.Style = $window.TryFindResource("ModernContextMenu")
        $cm.PlacementTarget = $controls['BtnWorkspaceNewTab']
        $cm.Placement = [System.Windows.Controls.Primitives.PlacementMode]::Bottom

        $categories = [ordered]@{
            "Directory Services" = @('Dashboard', 'Users', 'Groups', 'OUs', 'Computers', 'RecycleBin')
            "Softerra LDAP Suite" = @('DirectorySearch', 'LdapSql', 'AttributeEditor', 'HtmlView', 'ObjectCompare', 'LdifStudio', 'AuditReports', 'SchemaBrowser', 'BulkEditor', 'Basket', 'RequestLog')
            "Advanced Tools" = @('SecurityAcl', 'KerberosSuite', 'ReplicationSuite', 'DiagnosticsToolbox', 'NetworkDiagnostics')
            "System" = @('ServerMonitor', 'Connections', 'Settings')
        }

        foreach ($cat in $categories.Keys) {
            $subHeader = [System.Windows.Controls.MenuItem]::new()
            $subHeader.Header = "📂 $cat"
            $subHeader.IsEnabled = $false
            $subHeader.FontWeight = [System.Windows.FontWeights]::Bold
            [void]$cm.Items.Add($subHeader)

            foreach ($pName in $categories[$cat]) {
                $meta = $global:PanelCatalog[$pName]
                $isOpen = [bool]($state.OpenTabs | Where-Object { $_.PanelName -eq $pName })
                if ($isOpen) {
                    $mi = [System.Windows.Controls.MenuItem]::new()
                    $mi.Header = "$($meta.Icon)  $($meta.Title)"

                    $subSwitch = [System.Windows.Controls.MenuItem]::new()
                    $subSwitch.Header = "🗂️  Switch to Tab"
                    $subSwitch.Tag = $pName
                    $subSwitch.Add_Click([System.Windows.RoutedEventHandler]{
                        param($s, $e)
                        $t = if ($s -is [System.Windows.FrameworkElement] -and $s.Tag) { $s.Tag } else { $null }
                        if (-not [string]::IsNullOrWhiteSpace($t)) { Add-WorkspaceTab -PanelName $t -Activate $true }
                    })
                    [void]$mi.Items.Add($subSwitch)

                    $subNew = [System.Windows.Controls.MenuItem]::new()
                    $subNew.Header = "➕  Open Another Instance in Tab"
                    $subNew.Tag = $pName
                    $subNew.Add_Click([System.Windows.RoutedEventHandler]{
                        param($s, $e)
                        $t = if ($s -is [System.Windows.FrameworkElement] -and $s.Tag) { $s.Tag } else { $null }
                        if (-not [string]::IsNullOrWhiteSpace($t)) { Add-WorkspaceTab -PanelName $t -NewInstance -Activate $true }
                    })
                    [void]$mi.Items.Add($subNew)

                    $subWin = [System.Windows.Controls.MenuItem]::new()
                    $subWin.Header = "🗖  Open in New Independent Window"
                    $subWin.Tag = $pName
                    $subWin.Add_Click([System.Windows.RoutedEventHandler]{
                        param($s, $e)
                        $t = if ($s -is [System.Windows.FrameworkElement] -and $s.Tag) { $s.Tag } else { $null }
                        if (-not [string]::IsNullOrWhiteSpace($t)) { Launch-NewApplicationWindow -ToolName $t }
                    })
                    [void]$mi.Items.Add($subWin)

                    [void]$cm.Items.Add($mi)
                } else {
                    $mi = [System.Windows.Controls.MenuItem]::new()
                    $mi.Header = "$($meta.Icon)  $($meta.Title)"
                    $mi.Tag = $pName
                    $mi.Add_Click([System.Windows.RoutedEventHandler]{
                        param($s, $e)
                        $target = if ($s -is [System.Windows.FrameworkElement] -and $s.Tag) { $s.Tag } else { $null }
                        if (-not [string]::IsNullOrWhiteSpace($target)) {
                            Add-WorkspaceTab -PanelName $target -Activate $true
                        }
                    })
                    [void]$cm.Items.Add($mi)
                }
            }

            $sep = [System.Windows.Controls.Separator]::new()
            [void]$cm.Items.Add($sep)
        }

        $cm.IsOpen = $true
    })
}

if ($controls['BtnWorkspaceDetachCurrent']) {
    $controls['BtnWorkspaceDetachCurrent'].Add_Click({
        if (-not [string]::IsNullOrWhiteSpace($state.ActiveTabId)) {
            $activeTab = $state.OpenTabs | Where-Object { $_.Id -eq $state.ActiveTabId } | Select-Object -First 1
            $p = if ($activeTab) { $activeTab.PanelName } else { $state.ActiveTabId }
            if (-not [string]::IsNullOrWhiteSpace($p)) {
                Detach-PanelToWindow -PanelName $p
            }
        }
    })
}

if ($controls['BtnWorkspaceLayoutMenu']) {
    $controls['BtnWorkspaceLayoutMenu'].Add_Click({
        Show-WorkspaceLayoutMenu -targetElement $controls['BtnWorkspaceLayoutMenu']
    })
}

if ($controls['BtnWorkspaceModeToggle']) {
    $controls['BtnWorkspaceModeToggle'].Add_Click({
        $newMode = if ($state.WorkspaceMode -eq "Tabs") { "Single" } else { "Tabs" }
        Set-WorkspaceMode -Mode $newMode
        Save-AppSettings -Config $appConfig
        Set-Status -Message "Workspace mode changed to: $(if ($newMode -eq 'Tabs') { 'Multi-Tab Workspace' } else { 'Single Viewport' })"
    })
    $controls['BtnWorkspaceModeToggle'].Add_MouseRightButtonUp([System.Windows.Input.MouseButtonEventHandler]{
        param($s, $e)
        $e.Handled = $true
        Show-WorkspaceLayoutMenu -targetElement $controls['BtnWorkspaceModeToggle']
    })
}

#endregion

# Wire Header Navigation Buttons
if ($controls['BtnNavBack']) {
    $controls['BtnNavBack'].Add_Click({
        if ($state.NavIndex -gt 0) {
            $state.NavIndex--
            $target = $state.NavHistory[$state.NavIndex]
            $state.IsNavigatingHistory = $true
            try {
                $radio = $controls["Nav$target"]
                if ($radio) { $radio.IsChecked = $true }
                Show-Panel $target
            } finally {
                $state.IsNavigatingHistory = $false
                Update-NavButtons
            }
        }
    })
}

if ($controls['BtnNavForward']) {
    $controls['BtnNavForward'].Add_Click({
        if ($state.NavIndex -ge 0 -and $state.NavIndex -lt ($state.NavHistory.Count - 1)) {
            $state.NavIndex++
            $target = $state.NavHistory[$state.NavIndex]
            $state.IsNavigatingHistory = $true
            try {
                $radio = $controls["Nav$target"]
                if ($radio) { $radio.IsChecked = $true }
                Show-Panel $target
            } finally {
                $state.IsNavigatingHistory = $false
                Update-NavButtons
            }
        }
    })
}

# Wire Sidebar Navigation RadioButtons
if ($controls['NavDashboard'])          { $controls['NavDashboard'].Add_Checked({ if (-not $state.IsSelectingTab) { Show-Panel "Dashboard"; Refresh-Dashboard } }) }
if ($controls['NavUsers'])              { $controls['NavUsers'].Add_Checked({ if (-not $state.IsSelectingTab) { Show-Panel "Users"; Refresh-Users } }) }
if ($controls['NavGroups'])             { $controls['NavGroups'].Add_Checked({ if (-not $state.IsSelectingTab) { Show-Panel "Groups"; Refresh-Groups } }) }
if ($controls['NavOUs'])                { $controls['NavOUs'].Add_Checked({ if (-not $state.IsSelectingTab) { Show-Panel "OUs"; Refresh-OUs } }) }
if ($controls['NavComputers'])          { $controls['NavComputers'].Add_Checked({ if (-not $state.IsSelectingTab) { Show-Panel "Computers"; Refresh-Computers } }) }
if ($controls['NavDirectorySearch'])    { $controls['NavDirectorySearch'].Add_Checked({ if (-not $state.IsSelectingTab) { Show-Panel "DirectorySearch"; Init-DirectorySearch } }) }
if ($controls['NavLdapSql'])            { $controls['NavLdapSql'].Add_Checked({ if (-not $state.IsSelectingTab) { Show-Panel "LdapSql" } }) }
if ($controls['NavAttributeEditor'])    { $controls['NavAttributeEditor'].Add_Checked({ if (-not $state.IsSelectingTab) { Show-Panel "AttributeEditor" } }) }
if ($controls['NavHtmlView'])           { $controls['NavHtmlView'].Add_Checked({ if (-not $state.IsSelectingTab) { Show-Panel "HtmlView"; Init-HtmlViewUI } }) }
if ($controls['NavObjectCompare'])      { $controls['NavObjectCompare'].Add_Checked({ if (-not $state.IsSelectingTab) { Show-Panel "ObjectCompare" } }) }
if ($controls['NavLdifStudio'])         { $controls['NavLdifStudio'].Add_Checked({ if (-not $state.IsSelectingTab) { Show-Panel "LdifStudio"; Init-LdifStudio } }) }
if ($controls['NavAuditReports'])       { $controls['NavAuditReports'].Add_Checked({ if (-not $state.IsSelectingTab) { Show-Panel "AuditReports"; Refresh-CustomReportsDropdown } }) }
if ($controls['NavSchemaBrowser'])      { $controls['NavSchemaBrowser'].Add_Checked({ if (-not $state.IsSelectingTab) { Show-Panel "SchemaBrowser"; Refresh-Schema } }) }
if ($controls['NavBulkEditor'])         { $controls['NavBulkEditor'].Add_Checked({ if (-not $state.IsSelectingTab) { Show-Panel "BulkEditor" } }) }
if ($controls['NavBasket'])             { $controls['NavBasket'].Add_Checked({ if (-not $state.IsSelectingTab) { Show-Panel "Basket"; Refresh-BasketUI } }) }
if ($controls['NavRequestLog'])         { $controls['NavRequestLog'].Add_Checked({ if (-not $state.IsSelectingTab) { Show-Panel "RequestLog" } }) }
if ($controls['NavRecycleBin'])         { $controls['NavRecycleBin'].Add_Checked({ if (-not $state.IsSelectingTab) { Show-Panel "RecycleBin"; Refresh-RecycleBin } }) }
if ($controls['NavServerMonitor'])      { $controls['NavServerMonitor'].Add_Checked({ if (-not $state.IsSelectingTab) { Show-Panel "ServerMonitor"; Refresh-ServerMonitor } }) }
if ($controls['NavConnections'])        { $controls['NavConnections'].Add_Checked({ if (-not $state.IsSelectingTab) { Show-Panel "Connections"; Refresh-Connections } }) }
if ($controls['NavSettings'])           { $controls['NavSettings'].Add_Checked({ if (-not $state.IsSelectingTab) { Show-Panel "Settings"; Load-SettingsPanel } }) }
# NetTools Suite Navigators
if ($controls['NavSecurityAcl'])        { $controls['NavSecurityAcl'].Add_Checked({ if (-not $state.IsSelectingTab) { Show-Panel "SecurityAcl"; Init-SecurityAclUI } }) }
if ($controls['NavKerberosSuite'])      { $controls['NavKerberosSuite'].Add_Checked({ if (-not $state.IsSelectingTab) { Show-Panel "KerberosSuite"; Refresh-KerberosTickets } }) }
if ($controls['NavReplicationSuite'])   { $controls['NavReplicationSuite'].Add_Checked({ if (-not $state.IsSelectingTab) { Show-Panel "ReplicationSuite"; Refresh-ReplicationTopology } }) }
if ($controls['NavDiagnosticsToolbox']) { $controls['NavDiagnosticsToolbox'].Add_Checked({ if (-not $state.IsSelectingTab) { Show-Panel "DiagnosticsToolbox" } }) }
if ($controls['NavNetworkDiagnostics']) { $controls['NavNetworkDiagnostics'].Add_Checked({ if (-not $state.IsSelectingTab) { Show-Panel "NetworkDiagnostics"; Init-NetworkDiagnosticsUI } }) }
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

#region Global Quick Search Omnibar (Softerra Ch09 / Screenshot 08 Parity)
if ($controls['TxtGlobalSearch']) {
    $controls['TxtGlobalSearch'].Add_TextChanged({
        $q = $controls['TxtGlobalSearch'].Text.Trim()
        if ($q.Length -ge 2) {
            $rawResults = Find-ADObjectsQuickSearch -Query $q -MaxResults 15
            $results = @($rawResults)
            if ($controls['ListGlobalSearchResults']) {
                $controls['ListGlobalSearchResults'].ItemsSource = $null
                $controls['ListGlobalSearchResults'].ItemsSource = $results
            }
            if ($controls['TxtGlobalSearchStatus']) {
                $controls['TxtGlobalSearchStatus'].Text = "Found $($results.Count) object(s)"
            }
            if ($controls['PopupGlobalSearch']) {
                $controls['PopupGlobalSearch'].IsOpen = ($results.Count -gt 0)
            }
        } else {
            if ($controls['PopupGlobalSearch']) {
                $controls['PopupGlobalSearch'].IsOpen = $false
            }
            if ($controls['ListGlobalSearchResults']) {
                $controls['ListGlobalSearchResults'].ItemsSource = $null
            }
        }
    })

    $controls['TxtGlobalSearch'].Add_KeyDown({
        if ($_.Key -eq [System.Windows.Input.Key]::Escape) {
            if ($controls['PopupGlobalSearch']) { $controls['PopupGlobalSearch'].IsOpen = $false }
        } elseif ($_.Key -eq [System.Windows.Input.Key]::Down) {
            if ($controls['ListGlobalSearchResults'] -and $controls['ListGlobalSearchResults'].Items.Count -gt 0) {
                $controls['ListGlobalSearchResults'].Focus()
                $controls['ListGlobalSearchResults'].SelectedIndex = 0
            }
        }
    })
}

if ($controls['ListGlobalSearchResults']) {
    $controls['ListGlobalSearchResults'].Add_SelectionChanged({
        $sel = $controls['ListGlobalSearchResults'].SelectedItem
        if ($sel) {
            if ($controls['PopupGlobalSearch']) { $controls['PopupGlobalSearch'].IsOpen = $false }
            $dn = $sel.DistinguishedName
            $type = $sel.Type

            switch ($type) {
                "User" {
                    if ($controls['NavUsers']) {
                        $controls['NavUsers'].IsChecked = $true
                        Show-Panel "Users"
                        if ($controls['TxtSearchUser']) {
                            $controls['TxtSearchUser'].Text = $sel.SamAccountName
                            Refresh-Users
                        }
                    }
                }
                "Group" {
                    if ($controls['NavGroups']) {
                        $controls['NavGroups'].IsChecked = $true
                        Show-Panel "Groups"
                        if ($controls['TxtSearchGroup']) {
                            $controls['TxtSearchGroup'].Text = $sel.Name
                            Refresh-Groups
                        }
                    }
                }
                "Computer" {
                    if ($controls['NavComputers']) {
                        $controls['NavComputers'].IsChecked = $true
                        Show-Panel "Computers"
                        if ($controls['TxtSearchComputers']) {
                            $controls['TxtSearchComputers'].Text = $sel.Name
                            Refresh-Computers
                        }
                    }
                }
                "OrganizationalUnit" {
                    if ($controls['NavOUs']) {
                        $controls['NavOUs'].IsChecked = $true
                        Show-Panel "OUs"
                        Refresh-OUs
                    }
                }
                default {
                    if ($controls['NavAttributeEditor']) {
                        $controls['NavAttributeEditor'].IsChecked = $true
                        Show-Panel "AttributeEditor"
                        $controls['TxtAttrEditorDN'].Text = $dn
                        Load-RawAttributesUI -TargetDN $dn
                    }
                }
            }
            $controls['ListGlobalSearchResults'].SelectedItem = $null
        }
    })
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
function Render-PagedUsers {
    param (
        [array]$SourceItems = $null
    )
    if ($null -eq $SourceItems) {
        $SourceItems = if ($state.UsersCurrentList -and $state.UsersCurrentList.Count -gt 0) {
            $state.UsersCurrentList
        } elseif ($state.AllScopeUsers -and $state.AllScopeUsers.Count -gt 0) {
            $state.AllScopeUsers
        } else {
            $state.CachedUsers
        }
    }
    $state.UsersCurrentList = $SourceItems
    $totalCount = if ($SourceItems) { $SourceItems.Count } else { 0 }

    $pageSizeStr = if ($controls['CmbUsersPageSize'] -and $controls['CmbUsersPageSize'].SelectedItem) {
        $selObj = $controls['CmbUsersPageSize'].SelectedItem
        if ($selObj -is [System.Windows.Controls.ComboBoxItem]) { $selObj.Content.ToString() } else { "$selObj" }
    } else { "All" }

    $pageSize = 0
    if ($pageSizeStr -ne "All") {
        [void][int]::TryParse($pageSizeStr, [ref]$pageSize)
    }

    if ($pageSize -le 0 -or $totalCount -eq 0) {
        $state.UsersPage = 1
        $totalPages = 1
        $pagedItems = $SourceItems
    } else {
        $totalPages = [Math]::Max(1, [Math]::Ceiling($totalCount / $pageSize))
        if ($state.UsersPage -lt 1) { $state.UsersPage = 1 }
        if ($state.UsersPage -gt $totalPages) { $state.UsersPage = $totalPages }
        $skip = ($state.UsersPage - 1) * $pageSize
        $pagedItems = @($SourceItems | Select-Object -Skip $skip -First $pageSize)
    }

    if ($controls['GridUsers']) {
        $controls['GridUsers'].ItemsSource = @($pagedItems)
        Sync-DataGridColumnsProperties -DataGrid $controls['GridUsers']
    }

    if ($controls['TxtUsersPageInfo']) {
        $controls['TxtUsersPageInfo'].Text = "Page $($state.UsersPage) of $totalPages ($totalCount items)"
    }
    if ($controls['BtnUsersPagePrev']) {
        $controls['BtnUsersPagePrev'].IsEnabled = ($state.UsersPage -gt 1)
    }
    if ($controls['BtnUsersPageNext']) {
        $controls['BtnUsersPageNext'].IsEnabled = ($state.UsersPage -lt $totalPages)
    }
}

function Update-UserInspectorCard {
    param ($User)
    if (-not $User) {
        if ($controls['TxtInspDisplayName'])   { $controls['TxtInspDisplayName'].Text = "Select a user" }
        if ($controls['TxtInspSamAccountName']) { $controls['TxtInspSamAccountName'].Text = "" }
        if ($controls['TxtInspAvatarInitials']) { $controls['TxtInspAvatarInitials'].Text = "👤" }
        if ($controls['TxtInspTitle'])          { $controls['TxtInspTitle'].Text = "-" }
        if ($controls['TxtInspDepartment'])     { $controls['TxtInspDepartment'].Text = "-" }
        if ($controls['TxtInspOffice'])         { $controls['TxtInspOffice'].Text = "-" }
        if ($controls['TxtInspEmail'])          { $controls['TxtInspEmail'].Text = "-" }
        if ($controls['TxtInspPwdLastSet'])     { $controls['TxtInspPwdLastSet'].Text = "-" }
        if ($controls['TxtInspPwdExpires'])     { $controls['TxtInspPwdExpires'].Text = "-" }
        if ($controls['TxtInspBadPwdCount'])    { $controls['TxtInspBadPwdCount'].Text = "0" }
        if ($controls['TxtInspDN'])             { $controls['TxtInspDN'].Text = "" }
        return
    }

    $dn = if ($User.DistinguishedName) { $User.DistinguishedName } else { "" }
    $dispName = if ($User.DisplayName) { $User.DisplayName } elseif ($User.Name) { $User.Name } else { $User.SamAccountName }
    $sam = if ($User.SamAccountName) { $User.SamAccountName } else { "" }

    if ($controls['TxtInspDisplayName'])   { $controls['TxtInspDisplayName'].Text = $dispName }
    if ($controls['TxtInspSamAccountName']) { $controls['TxtInspSamAccountName'].Text = $sam }
    if ($controls['TxtInspDN'])             { $controls['TxtInspDN'].Text = $dn }

    $initials = "👤"
    if ($dispName) {
        $parts = $dispName.Trim() -split '\s+'
        if ($parts.Count -ge 2 -and $parts[0].Length -ge 1 -and $parts[-1].Length -ge 1) {
            $initials = "$($parts[0][0])$($parts[-1][0])".ToUpper()
        } elseif ($parts.Count -eq 1 -and $parts[0].Length -ge 1) {
            $initials = "$($parts[0][0])".ToUpper()
        }
    }
    if ($controls['TxtInspAvatarInitials']) { $controls['TxtInspAvatarInitials'].Text = $initials }

    $statusText = if ($User.Status) { $User.Status } elseif ($User.Enabled -ne $null) { if ($User.Enabled) { "Active" } else { "Disabled" } } else { "Active" }
    if ($controls['TxtInspStatus']) { $controls['TxtInspStatus'].Text = $statusText }
    if ($controls['BorderInspStatus']) {
        if ($statusText -eq "Active") {
            $controls['BorderInspStatus'].Background = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#064E3B")
            $controls['BorderInspStatus'].BorderBrush = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#059669")
            if ($controls['TxtInspStatus']) { $controls['TxtInspStatus'].Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#34D399") }
        } elseif ($statusText -eq "Locked") {
            $controls['BorderInspStatus'].Background = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#78350F")
            $controls['BorderInspStatus'].BorderBrush = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#D97706")
            if ($controls['TxtInspStatus']) { $controls['TxtInspStatus'].Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#FBBF24") }
        } else {
            $controls['BorderInspStatus'].Background = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#7F1D1D")
            $controls['BorderInspStatus'].BorderBrush = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#DC2626")
            if ($controls['TxtInspStatus']) { $controls['TxtInspStatus'].Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#F87171") }
        }
    }

    if ($controls['TxtInspTitle'])      { $controls['TxtInspTitle'].Text = if ($User.Title) { $User.Title } else { "-" } }
    if ($controls['TxtInspDepartment']) { $controls['TxtInspDepartment'].Text = if ($User.Department) { $User.Department } else { "-" } }
    if ($controls['TxtInspOffice'])     { $controls['TxtInspOffice'].Text = if ($User.Office) { $User.Office } elseif ($User.PhysicalDeliveryOfficeName) { $User.PhysicalDeliveryOfficeName } else { "-" } }
    if ($controls['TxtInspEmail'])      { $controls['TxtInspEmail'].Text = if ($User.Email) { $User.Email } elseif ($User.Mail) { $User.Mail } else { "-" } }
    if ($controls['TxtInspPwdLastSet']) { $controls['TxtInspPwdLastSet'].Text = if ($User.PasswordLastSet) { $User.PasswordLastSet } else { "-" } }
    if ($controls['TxtInspPwdExpires']) { $controls['TxtInspPwdExpires'].Text = if ($User.PasswordNeverExpires) { "Never" } elseif ($User.PasswordExpires) { $User.PasswordExpires } else { "-" } }
    if ($controls['TxtInspBadPwdCount']) { $controls['TxtInspBadPwdCount'].Text = if ($User.BadPwdCount -ne $null) { "$($User.BadPwdCount)" } else { "0" } }
}

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

    $state.UsersPage = 1
    Render-PagedUsers -SourceItems $users

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
            $state.UsersPage = 1
            Render-PagedUsers -SourceItems $allUsers
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

    $state.UsersPage = 1
    Render-PagedUsers -SourceItems $filtered

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
        $UserToEdit = $null,
        [string]$TargetOU = "",
        [string]$Template = ""
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
        if (-not [string]::IsNullOrWhiteSpace($TargetOU)) {
            foreach ($item in $dControls['CmbTargetOU'].Items) {
                if ($item.Tag -ieq $TargetOU) {
                    $dControls['CmbTargetOU'].SelectedItem = $item
                    break
                }
            }
        }
        if ($dControls['CmbTargetOU'].SelectedItem) {
            $dControls['TxtSelectedOUDN'].Text = $dControls['CmbTargetOU'].SelectedItem.Tag
        }
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

    # Template Blueprints (Softerra Parity)
    if ($dControls['CmbUserTemplate']) {
        $dControls['CmbUserTemplate'].Add_SelectionChanged({
            if (-not $dControls['CmbUserTemplate'].SelectedItem) { return }
            $tpl = [string]$dControls['CmbUserTemplate'].SelectedItem.Content
            switch -Wildcard ($tpl) {
                "*Standard Employee*" {
                    if (-not $dControls['TxtDepartment'].Text) { $dControls['TxtDepartment'].Text = "Operations" }
                    if (-not $dControls['TxtCompany'].Text) { $dControls['TxtCompany'].Text = $appConfig.Defaults.Company }
                    if ($dControls['ChkMustChangePwd']) { $dControls['ChkMustChangePwd'].IsChecked = $true }
                    if ($dControls['ChkPasswordNeverExpires']) { $dControls['ChkPasswordNeverExpires'].IsChecked = $false }
                }
                "*Contractor*" {
                    $dControls['TxtDepartment'].Text = "External Contractors"
                    $dControls['TxtCompany'].Text = "Vendor / Contractor"
                    $dControls['TxtDescription'].Text = "Contractor Account (90-day validity)"
                    if ($dControls['ChkMustChangePwd']) { $dControls['ChkMustChangePwd'].IsChecked = $true }
                    if ($dControls['ChkPasswordNeverExpires']) { $dControls['ChkPasswordNeverExpires'].IsChecked = $false }
                }
                "*Domain Admin*" {
                    $dControls['TxtDepartment'].Text = "IT Infrastructure"
                    $dControls['TxtJobTitle'].Text = "System Administrator"
                    $dControls['TxtDescription'].Text = "Privileged Directory Administrator"
                }
                "*Service Account*" {
                    $dControls['TxtDepartment'].Text = "Service Accounts"
                    $dControls['TxtDescription'].Text = "Automated Service / Integration Identity"
                    if ($dControls['ChkPasswordNeverExpires']) { $dControls['ChkPasswordNeverExpires'].IsChecked = $true }
                    if ($dControls['ChkMustChangePwd']) { $dControls['ChkMustChangePwd'].IsChecked = $false }
                    if ($dControls['ChkCannotChangePwd']) { $dControls['ChkCannotChangePwd'].IsChecked = $true }
                }
            }
        })
        if (-not [string]::IsNullOrWhiteSpace($Template)) {
            foreach ($item in $dControls['CmbUserTemplate'].Items) {
                if ($item.Content.ToString() -ilike "*$Template*") {
                    $dControls['CmbUserTemplate'].SelectedItem = $item
                    break
                }
            }
        }
    }

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
        if (-not (Test-CanModifyDirectory)) { return }
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

    if ($dControls['ListGroups']) {
        $dControls['ListGroups'].ItemsSource = $null
        $groupsList = [System.Collections.ArrayList]::new()
        if ($detail.Groups) {
            foreach ($g in $detail.Groups) { [void]$groupsList.Add($g) }
        }
        $dControls['ListGroups'].ItemsSource = $groupsList
    }

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
if ($controls['BtnNewUserTemplate']) {
    $controls['BtnNewUserTemplate'].Add_Click({
        $choice = [Microsoft.VisualBasic.Interaction]::InputBox(
            "Select template number:`n1. Standard Employee (Corporate standard)`n2. Contractor (Expires in 90 days)`n3. Domain Admin Template (Privileged)`n4. Service Account (SPN / Non-expiring)",
            "Template-Based Entry Creation",
            "1"
        )
        if ([string]::IsNullOrWhiteSpace($choice)) { return }
        $selectedTpl = switch ($choice.Trim()) {
            "1" { "Standard Employee" }
            "2" { "Contractor (Expires 90d)" }
            "3" { "Domain Admin Template" }
            "4" { "Service Account (No Expire)" }
            default { "Standard Employee" }
        }
        Open-UserDialog -Mode "Create" -Template $selectedTpl
    })
}
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
if ($controls['BtnUserAddToBasket']) {
    $controls['BtnUserAddToBasket'].Add_Click({
        $selected = $controls['GridUsers'].SelectedItems
        if ($selected -and $selected.Count -gt 0) {
            Add-ToBasket -Items $selected -DefaultClass "User"
        } else {
            [System.Windows.MessageBox]::Show("Please select one or more users to add to the Directory Basket.", "Selection Required", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        }
    })
}
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

# User Quick Inspector & Pagination Handlers (Softerra Ch20 HTML Pane Parity)
if ($controls['BtnToggleUserInspector']) {
    $controls['BtnToggleUserInspector'].Add_Click({
        $curVis = if ($controls['BorderUserInspector']) { $controls['BorderUserInspector'].Visibility } else { [System.Windows.Visibility]::Collapsed }
        $newVis = if ($curVis -eq [System.Windows.Visibility]::Visible) { [System.Windows.Visibility]::Collapsed } else { [System.Windows.Visibility]::Visible }
        if ($controls['BorderUserInspector'])   { $controls['BorderUserInspector'].Visibility = $newVis }
        if ($controls['SplitterUserInspector']) { $controls['SplitterUserInspector'].Visibility = $newVis }
        if ($newVis -eq [System.Windows.Visibility]::Visible) {
            $sel = if ($controls['GridUsers']) { $controls['GridUsers'].SelectedItem } else { $null }
            Update-UserInspectorCard -User $sel
        }
    })
}

if ($controls['BtnCloseUserInspector']) {
    $controls['BtnCloseUserInspector'].Add_Click({
        if ($controls['BorderUserInspector'])   { $controls['BorderUserInspector'].Visibility = [System.Windows.Visibility]::Collapsed }
        if ($controls['SplitterUserInspector']) { $controls['SplitterUserInspector'].Visibility = [System.Windows.Visibility]::Collapsed }
    })
}

if ($controls['GridUsers']) {
    $controls['GridUsers'].Add_SelectionChanged({
        if ($controls['BorderUserInspector'] -and $controls['BorderUserInspector'].Visibility -eq [System.Windows.Visibility]::Visible) {
            $sel = $controls['GridUsers'].SelectedItem
            Update-UserInspectorCard -User $sel
        }
    })
}

if ($controls['BtnInspResetPwd']) {
    $controls['BtnInspResetPwd'].Add_Click({
        $u = if ($controls['GridUsers']) { $controls['GridUsers'].SelectedItem } else { $null }
        if ($u) { Reset-PasswordAction -TargetUser $u }
    })
}

if ($controls['BtnInspUnlock']) {
    $controls['BtnInspUnlock'].Add_Click({
        $u = if ($controls['GridUsers']) { $controls['GridUsers'].SelectedItem } else { $null }
        if ($u) {
            $res = Unlock-ADUserAccount -Identity $u.DistinguishedName
            [System.Windows.MessageBox]::Show($res.Message, "Unlock Account", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            Refresh-Users
        }
    })
}

if ($controls['BtnInspToggleStatus']) {
    $controls['BtnInspToggleStatus'].Add_Click({
        Toggle-UserStatusAction
    })
}

if ($controls['BtnInspAddToBasket']) {
    $controls['BtnInspAddToBasket'].Add_Click({
        $u = if ($controls['GridUsers']) { $controls['GridUsers'].SelectedItem } else { $null }
        if ($u) {
            Add-ObjectToBasket -DN $u.DistinguishedName -Name $u.DisplayName -ObjectClass "user"
        }
    })
}

if ($controls['BtnInspRawAttr']) {
    $controls['BtnInspRawAttr'].Add_Click({
        $u = if ($controls['GridUsers']) { $controls['GridUsers'].SelectedItem } else { $null }
        if ($u) {
            $controls['NavAttributeEditor'].IsChecked = $true
            Show-Panel "AttributeEditor"
            $controls['TxtAttrEditorDN'].Text = $u.DistinguishedName
            Load-RawAttributesUI -TargetDN $u.DistinguishedName
        }
    })
}

if ($controls['CmbUsersPageSize']) {
    $controls['CmbUsersPageSize'].Add_SelectionChanged({
        $state.UsersPage = 1
        Render-PagedUsers
    })
}

if ($controls['BtnUsersPagePrev']) {
    $controls['BtnUsersPagePrev'].Add_Click({
        if ($state.UsersPage -gt 1) {
            $state.UsersPage--
            Render-PagedUsers
        }
    })
}

if ($controls['BtnUsersPageNext']) {
    $controls['BtnUsersPageNext'].Add_Click({
        $state.UsersPage++
        Render-PagedUsers
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
    param (
        [string]$TargetOU = "",
        [string]$Template = ""
    )
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
        if (-not [string]::IsNullOrWhiteSpace($TargetOU)) {
            foreach ($item in $dControls['CmbGroupOU'].Items) {
                if ($item.Tag -ieq $TargetOU) {
                    $dControls['CmbGroupOU'].SelectedItem = $item
                    break
                }
            }
        }
    }

    if ($dControls['CmbGroupTemplate']) {
        $dControls['CmbGroupTemplate'].Add_SelectionChanged({
            if (-not $dControls['CmbGroupTemplate'].SelectedItem) { return }
            $tpl = [string]$dControls['CmbGroupTemplate'].SelectedItem.Content
            switch -Wildcard ($tpl) {
                "*Role Group*" {
                    if ($dControls['RadScopeGlobal']) { $dControls['RadScopeGlobal'].IsChecked = $true }
                    if ($dControls['RadCatSecurity']) { $dControls['RadCatSecurity'].IsChecked = $true }
                    if (-not $dControls['TxtGroupDescription'].Text) { $dControls['TxtGroupDescription'].Text = "Role-based access group (RBAC)" }
                }
                "*Resource Group*" {
                    if ($dControls['RadScopeDomainLocal']) { $dControls['RadScopeDomainLocal'].IsChecked = $true }
                    if ($dControls['RadCatSecurity']) { $dControls['RadCatSecurity'].IsChecked = $true }
                    if (-not $dControls['TxtGroupDescription'].Text) { $dControls['TxtGroupDescription'].Text = "Resource permission access group (AGDLP)" }
                }
                "*Enterprise Group*" {
                    if ($dControls['RadScopeUniversal']) { $dControls['RadScopeUniversal'].IsChecked = $true }
                    if ($dControls['RadCatSecurity']) { $dControls['RadCatSecurity'].IsChecked = $true }
                    if (-not $dControls['TxtGroupDescription'].Text) { $dControls['TxtGroupDescription'].Text = "Enterprise multi-domain security group" }
                }
                "*Distribution List*" {
                    if ($dControls['RadScopeUniversal']) { $dControls['RadScopeUniversal'].IsChecked = $true }
                    if ($dControls['RadCatDistribution']) { $dControls['RadCatDistribution'].IsChecked = $true }
                    if (-not $dControls['TxtGroupDescription'].Text) { $dControls['TxtGroupDescription'].Text = "Corporate email distribution group" }
                }
            }
        })

        if (-not [string]::IsNullOrWhiteSpace($Template)) {
            foreach ($item in $dControls['CmbGroupTemplate'].Items) {
                if ($item.Content.ToString() -ilike "*$Template*") {
                    $dControls['CmbGroupTemplate'].SelectedItem = $item
                    break
                }
            }
        }
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

    # Initialize Direct vs Transitive toggle from main window if available
    if ($controls['RadGroupViewTransitive'] -and $controls['RadGroupViewTransitive'].IsChecked -and $dControls['RadDlgMembersTransitive']) {
        $dControls['RadDlgMembersTransitive'].IsChecked = $true
    }

    $ReloadMembers = {
        $isTransitive = if ($dControls['RadDlgMembersTransitive'] -and $dControls['RadDlgMembersTransitive'].IsChecked) { $true } else { $false }
        $rawM = if ($isTransitive) {
            Get-ADGroupMembersList -Identity $Group.DistinguishedName -Transitive
        } else {
            Get-ADGroupMembersList -Identity $Group.DistinguishedName
        }
        $m = @($rawM | ForEach-Object { $_ })
        $dControls['ListCurrentMembers'].ItemsSource = $m
        $suffix = if ($isTransitive) { " (transitive / nested)" } else { "" }
        $dControls['TxtMemberCount'].Text = "$($m.Count) members$suffix"

        if ($dControls['BtnRemoveMember']) {
            $dControls['BtnRemoveMember'].ToolTip = if ($isTransitive) { "Note: Only direct members can be unlinked from this group" } else { "Remove selected member from group" }
        }
    }
    & $ReloadMembers

    if ($dControls['RadDlgMembersDirect']) {
        $dControls['RadDlgMembersDirect'].Add_Checked({ & $ReloadMembers })
    }
    if ($dControls['RadDlgMembersTransitive']) {
        $dControls['RadDlgMembersTransitive'].Add_Checked({ & $ReloadMembers })
    }

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
if ($controls['BtnGroupAddToBasket']) {
    $controls['BtnGroupAddToBasket'].Add_Click({
        $selected = $controls['GridGroups'].SelectedItems
        if ($selected -and $selected.Count -gt 0) {
            Add-ToBasket -Items $selected -DefaultClass "Group"
        } else {
            [System.Windows.MessageBox]::Show("Please select one or more groups to add to the Directory Basket.", "Selection Required", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        }
    })
}
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
function Filter-OUTreeNodes {
    param ([string]$Query)
    if ([string]::IsNullOrWhiteSpace($Query)) {
        if ($state.CachedOUTree -and $controls['TreeOUs']) {
            $controls['TreeOUs'].ItemsSource = @($state.CachedOUTree)
        }
        return
    }

    $q = $Query.Trim()
    function Filter-NodeRecursive ($node) {
        $matchesSelf = ($node.DisplayName -and $node.DisplayName -like "*$q*") -or ($node.Name -and $node.Name -like "*$q*")
        $filteredChildren = [System.Collections.Generic.List[psobject]]::new()
        if ($node.Children) {
            foreach ($child in $node.Children) {
                $fChild = Filter-NodeRecursive $child
                if ($fChild) { [void]$filteredChildren.Add($fChild) }
            }
        }
        if ($matchesSelf -or $filteredChildren.Count -gt 0) {
            return [PSCustomObject]@{
                Name              = $node.Name
                DisplayName       = $node.DisplayName
                DistinguishedName = $node.DistinguishedName
                Children          = $filteredChildren
            }
        }
        return $null
    }

    if ($state.CachedOUTree -and $controls['TreeOUs']) {
        $filteredRoots = [System.Collections.Generic.List[psobject]]::new()
        foreach ($root in $state.CachedOUTree) {
            $fRoot = Filter-NodeRecursive $root
            if ($fRoot) { [void]$filteredRoots.Add($fRoot) }
        }
        $controls['TreeOUs'].ItemsSource = $filteredRoots
    }
}

function Refresh-OUs {
    Set-Status -Message "Building Organizational Unit hierarchy..."
    $ouTree = Get-ADOUTree
    $state.CachedOUTree = $ouTree
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

    # Update Breadcrumb Ribbon (Softerra Ch06s01 & Apache Studio Parity)
    if ($controls['PanelOUBreadcrumbs']) {
        $controls['PanelOUBreadcrumbs'].Children.Clear()
        $lbl = New-Object System.Windows.Controls.TextBlock
        $lbl.Text = "📍 Path: "
        $lbl.FontSize = 11
        $lbl.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#6B7280")
        $lbl.FontWeight = [System.Windows.FontWeights]::SemiBold
        $lbl.VerticalAlignment = [System.Windows.VerticalAlignment]::Center
        [void]$controls['PanelOUBreadcrumbs'].Children.Add($lbl)

        $dnParts = $selectedNode.DistinguishedName -split '(?<!\\),'
        $ouSegments = [System.Collections.Generic.List[string]]::new()
        foreach ($p in $dnParts) {
            $kv = $p -split '=', 2
            if ($kv.Count -eq 2 -and $kv[0].Trim() -ieq "OU") {
                $ouSegments.Add($kv[1].Trim())
            }
        }
        $hierarchy = [System.Collections.Generic.List[string]]::new()
        $domainLabel = if ($adContext.DomainName) { $adContext.DomainName } else { "Root" }
        $hierarchy.Add($domainLabel)
        for ($i = $ouSegments.Count - 1; $i -ge 0; $i--) {
            $hierarchy.Add($ouSegments[$i])
        }

        for ($idx = 0; $idx -lt $hierarchy.Count; $idx++) {
            $segName = $hierarchy[$idx]
            if ($idx -gt 0) {
                $sep = New-Object System.Windows.Controls.TextBlock
                $sep.Text = "  >  "
                $sep.FontSize = 11
                $sep.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#4B5563")
                $sep.VerticalAlignment = [System.Windows.VerticalAlignment]::Center
                [void]$controls['PanelOUBreadcrumbs'].Children.Add($sep)
            }
            $crumb = New-Object System.Windows.Controls.TextBlock
            $crumb.Text = $segName
            $crumb.FontSize = 11
            $crumb.VerticalAlignment = [System.Windows.VerticalAlignment]::Center
            if ($idx -eq ($hierarchy.Count - 1)) {
                $crumb.FontWeight = [System.Windows.FontWeights]::Bold
                $crumb.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#38BDF8")
            } else {
                $crumb.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#9CA3AF")
            }
            [void]$controls['PanelOUBreadcrumbs'].Children.Add($crumb)
        }
    }

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

if ($controls['TxtFilterOUs']) {
    $controls['TxtFilterOUs'].Add_TextChanged({
        $q = $controls['TxtFilterOUs'].Text.Trim()
        if ($controls['TxtFilterOUsPlaceholder']) {
            $controls['TxtFilterOUsPlaceholder'].Visibility = if ([string]::IsNullOrWhiteSpace($q)) { [System.Windows.Visibility]::Visible } else { [System.Windows.Visibility]::Collapsed }
        }
        if ($controls['BtnClearFilterOUs']) {
            $controls['BtnClearFilterOUs'].Visibility = if ([string]::IsNullOrWhiteSpace($q)) { [System.Windows.Visibility]::Collapsed } else { [System.Windows.Visibility]::Visible }
        }
        Filter-OUTreeNodes -Query $q
    })
}

if ($controls['BtnClearFilterOUs']) {
    $controls['BtnClearFilterOUs'].Add_Click({
        if ($controls['TxtFilterOUs']) {
            $controls['TxtFilterOUs'].Text = ""
            $controls['TxtFilterOUs'].Focus()
        }
    })
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
if ($controls['BtnComputerAddToBasket']) {
    $controls['BtnComputerAddToBasket'].Add_Click({
        $selected = $controls['GridComputers'].SelectedItems
        if ($selected -and $selected.Count -gt 0) {
            Add-ToBasket -Items $selected -DefaultClass "Computer"
        } else {
            [System.Windows.MessageBox]::Show("Please select one or more computers to add to the Directory Basket.", "Selection Required", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
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
function global:Filter-ComboAttributes {
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

function script:Filter-ComboAttributes {
    param(
        [System.Windows.Controls.ComboBox]$Combo,
        [string]$Query,
        [bool]$IncludeAny = $false,
        [System.Windows.Controls.TextBlock]$OutcomeText = $null,
        [System.Windows.Controls.Border]$OutcomeBorder = $null,
        [System.Windows.Controls.TextBox]$SyncSearchBox = $null,
        [bool]$OpenDropDown = $true
    )
    global:Filter-ComboAttributes @PSBoundParameters
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

    $filterFunc = ${function:global:Filter-ComboAttributes}
    if (-not $filterFunc) { $filterFunc = ${function:Filter-ComboAttributes} }

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
            if ($filterFunc) {
                & $filterFunc -Combo $Combo -Query $currentText -IncludeAny $IncludeAnyOption `
                    -OutcomeText $OutcomeText -OutcomeBorder $OutcomeBorder -OpenDropDown $true
            } else {
                global:Filter-ComboAttributes -Combo $Combo -Query $currentText -IncludeAny $IncludeAnyOption `
                    -OutcomeText $OutcomeText -OutcomeBorder $OutcomeBorder -OpenDropDown $true
            }
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

        if ($filterFunc) {
            & $filterFunc -Combo $Combo -Query $editBox.Text -IncludeAny $IncludeAnyOption `
                -OutcomeText $OutcomeText -OutcomeBorder $OutcomeBorder -OpenDropDown $true
        } else {
            global:Filter-ComboAttributes -Combo $Combo -Query $editBox.Text -IncludeAny $IncludeAnyOption `
                -OutcomeText $OutcomeText -OutcomeBorder $OutcomeBorder -OpenDropDown $true
        }
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
    Update-SearchHistoryUI
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
            "All Users"                           { "(objectClass=user)" }
            "Locked Out Accounts"                 { "(&(objectCategory=person)(objectClass=user)(lockoutTime>=1))" }
            "Disabled Accounts"                   { "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))" }
            "Passwords Never Expire"              { "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))" }
            "Empty Groups"                        { "(&(objectCategory=group)(!member=*))" }
            "Privileged Accounts (adminCount=1)"  { "(&(objectCategory=person)(adminCount=1))" }
            "Service Accounts (SPNs)"             { "(&(servicePrincipalName=*)(!(objectClass=computer)))" }
            "All Computers"                       { "(objectCategory=computer)" }
            "Domain Controllers"                  { "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))" }
            "Users Created in Last 7 Days"        { 
                $sevenDaysAgo = (Get-Date).ToUniversalTime().AddDays(-7).ToString("yyyyMMddHHmmss.0Z")
                "(&(objectCategory=person)(objectClass=user)(whenCreated>=$sevenDaysAgo))"
            }
            "Computers Running Windows Server"    { "(&(objectCategory=computer)(operatingSystem=*Server*))" }
            "Users with Expired Passwords"        { "(&(objectCategory=person)(objectClass=user)(!(pwdLastSet=0))(lockoutTime=0))" }
            "Accounts with SPN (Kerberoasting Targets)" { "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" }
            "Groups with No Members"              { "(&(objectCategory=group)(!member=*))" }
            "Users Missing Manager Reference"     { "(&(objectCategory=person)(objectClass=user)(!manager=*))" }
            "Accounts Requiring Smart Card Logon" { "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=262144))" }
            "Users Whose DisplayName Differs from CN" { "(&(objectCategory=person)(objectClass=user)(displayName=*))" }
            default                               { "" }
        }
        if ($filter -and $controls['TxtRawLdapFilter']) {
            $controls['TxtRawLdapFilter'].Text = $filter
            if ($controls['BorderFilterExplanation']) { $controls['BorderFilterExplanation'].Visibility = [System.Windows.Visibility]::Visible }
            if ($controls['TxtFilterHumanExplanation']) {
                $controls['TxtFilterHumanExplanation'].Text = Convert-LdapFilterToHumanText -Filter $filter
                $controls['TxtFilterHumanExplanation'].Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#38BDF8")
            }
        }
    })
}

function Get-CurrentLdapConditionString {
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

    $resCond = switch ($op) {
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
    return $resCond
}

if ($controls['BtnInsertCondition']) {
    $controls['BtnInsertCondition'].Add_Click({
        $condition = Get-CurrentLdapConditionString
        $existing = if ($controls['TxtRawLdapFilter']) { $controls['TxtRawLdapFilter'].Text.Trim() } else { "" }
        if ([string]::IsNullOrWhiteSpace($existing) -or $existing -eq "(objectClass=*)" -or $existing -eq "(objectClass=user)") {
            $controls['TxtRawLdapFilter'].Text = "(&(objectClass=user)$condition)"
        } elseif ($existing.StartsWith("(&") -and $existing.EndsWith(")")) {
            $inner = $existing.Substring(2, $existing.Length - 3)
            $controls['TxtRawLdapFilter'].Text = "(&$inner$condition)"
        } else {
            $controls['TxtRawLdapFilter'].Text = "(&$existing$condition)"
        }
    })
}

if ($controls['BtnFilterGroupAnd']) {
    $controls['BtnFilterGroupAnd'].Add_Click({
        $condition = Get-CurrentLdapConditionString
        $existing = if ($controls['TxtRawLdapFilter']) { $controls['TxtRawLdapFilter'].Text.Trim() } else { "" }
        if ([string]::IsNullOrWhiteSpace($existing) -or $existing -eq "(objectClass=*)") {
            $controls['TxtRawLdapFilter'].Text = "(&$condition)"
        } elseif ($existing.StartsWith("(&") -and $existing.EndsWith(")")) {
            $inner = $existing.Substring(2, $existing.Length - 3)
            $controls['TxtRawLdapFilter'].Text = "(&$inner$condition)"
        } else {
            $controls['TxtRawLdapFilter'].Text = "(&$existing$condition)"
        }
    })
}

if ($controls['BtnFilterGroupOr']) {
    $controls['BtnFilterGroupOr'].Add_Click({
        $condition = Get-CurrentLdapConditionString
        $existing = if ($controls['TxtRawLdapFilter']) { $controls['TxtRawLdapFilter'].Text.Trim() } else { "" }
        if ([string]::IsNullOrWhiteSpace($existing) -or $existing -eq "(objectClass=*)") {
            $controls['TxtRawLdapFilter'].Text = "(|$condition)"
        } elseif ($existing.StartsWith("(|") -and $existing.EndsWith(")")) {
            $inner = $existing.Substring(2, $existing.Length - 3)
            $controls['TxtRawLdapFilter'].Text = "(|$inner$condition)"
        } else {
            $controls['TxtRawLdapFilter'].Text = "(|$existing$condition)"
        }
    })
}

if ($controls['BtnFilterGroupNot']) {
    $controls['BtnFilterGroupNot'].Add_Click({
        $existing = if ($controls['TxtRawLdapFilter']) { $controls['TxtRawLdapFilter'].Text.Trim() } else { "" }
        if (-not [string]::IsNullOrWhiteSpace($existing)) {
            if ($existing.StartsWith("(!") -and $existing.EndsWith(")")) {
                $controls['TxtRawLdapFilter'].Text = $existing.Substring(2, $existing.Length - 3)
            } else {
                $controls['TxtRawLdapFilter'].Text = "(!$existing)"
            }
        }
    })
}

if ($controls['BtnFilterClear']) {
    $controls['BtnFilterClear'].Add_Click({
        if ($controls['TxtRawLdapFilter']) {
            $controls['TxtRawLdapFilter'].Text = "(objectClass=*)"
        }
    })
}

function Update-SearchHistoryUI {
    if (-not $controls['CmbSearchHistory']) { return }
    $controls['CmbSearchHistory'].Items.Clear()

    # Pinned queries first
    foreach ($item in $state.PinnedSearches) {
        $cbi = New-Object System.Windows.Controls.ComboBoxItem
        $cbi.Content = "📌 $($item.Filter)"
        $cbi.Tag = $item
        $cbi.ToolTip = "Pinned: $($item.Filter)`nBase: $($item.BaseDn)`nScope: $($item.Scope)"
        [void]$controls['CmbSearchHistory'].Items.Add($cbi)
    }

    # Recent queries
    foreach ($item in $state.SearchHistory) {
        $isPinned = $state.PinnedSearches | Where-Object { $_.Filter -ieq $item.Filter -and $_.BaseDn -ieq $item.BaseDn }
        if (-not $isPinned) {
            $cbi = New-Object System.Windows.Controls.ComboBoxItem
            $cbi.Content = "🕒 $($item.Filter)"
            $cbi.Tag = $item
            $cbi.ToolTip = "Recent: $($item.Filter)`nBase: $($item.BaseDn)`nScope: $($item.Scope)`nRun: $($item.Timestamp)"
            [void]$controls['CmbSearchHistory'].Items.Add($cbi)
        }
    }
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
        $state.SearchPage = 1
        Render-PagedSearchResults

        # Record query in history (Softerra Ch09s05 & Apache Studio Parity)
        if (-not [string]::IsNullOrWhiteSpace($filter)) {
            $existing = $state.SearchHistory | Where-Object { $_.Filter -ieq $filter -and $_.BaseDn -ieq $baseDn -and $_.Scope -ieq $scopeItem }
            if (-not $existing) {
                $histObj = [PSCustomObject]@{
                    Filter    = $filter
                    BaseDn    = $baseDn
                    Scope     = $scopeItem
                    Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm")
                }
                $state.SearchHistory.Insert(0, $histObj)
                while ($state.SearchHistory.Count -gt 30) {
                    $state.SearchHistory.RemoveAt($state.SearchHistory.Count - 1)
                }
                Update-SearchHistoryUI
            }
        }
    } else {
        $controls['TxtSearchStatus'].Text = "Error: $($res.Error)"
        [System.Windows.MessageBox]::Show("LDAP Search Failed: `n$($res.Error)", "Search Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
    }
}

function Render-PagedSearchResults {
    param (
        [array]$SourceItems = $null
    )
    if ($null -eq $SourceItems) {
        $SourceItems = $state.CurrentSearchResults
    }
    $totalCount = if ($SourceItems) { $SourceItems.Count } else { 0 }
    $pageSizeStr = if ($controls['CmbSearchPageSize'] -and $controls['CmbSearchPageSize'].SelectedItem) {
        $selObj = $controls['CmbSearchPageSize'].SelectedItem
        if ($selObj -is [System.Windows.Controls.ComboBoxItem]) { $selObj.Content.ToString() } else { "$selObj" }
    } else { "All" }

    $pageSize = 0
    if ($pageSizeStr -ne "All") {
        [void][int]::TryParse($pageSizeStr, [ref]$pageSize)
    }

    if ($pageSize -le 0 -or $totalCount -eq 0) {
        $state.SearchPage = 1
        $totalPages = 1
        $pagedItems = $SourceItems
    } else {
        $totalPages = [Math]::Max(1, [Math]::Ceiling($totalCount / $pageSize))
        if ($state.SearchPage -lt 1) { $state.SearchPage = 1 }
        if ($state.SearchPage -gt $totalPages) { $state.SearchPage = $totalPages }
        $skip = ($state.SearchPage - 1) * $pageSize
        $pagedItems = @($SourceItems | Select-Object -Skip $skip -First $pageSize)
    }

    if ($controls['GridSearchResults']) {
        $controls['GridSearchResults'].ItemsSource = @($pagedItems)
        Sync-DataGridColumnsProperties -DataGrid $controls['GridSearchResults']
    }

    if ($controls['TxtSearchPageInfo']) {
        $controls['TxtSearchPageInfo'].Text = "Page $($state.SearchPage) of $totalPages ($totalCount items)"
    }
    if ($controls['BtnSearchPagePrev']) {
        $controls['BtnSearchPagePrev'].IsEnabled = ($state.SearchPage -gt 1)
    }
    if ($controls['BtnSearchPageNext']) {
        $controls['BtnSearchPageNext'].IsEnabled = ($state.SearchPage -lt $totalPages)
    }
}

if ($controls['CmbSearchPageSize']) {
    $controls['CmbSearchPageSize'].Add_SelectionChanged({
        $state.SearchPage = 1
        Render-PagedSearchResults
    })
}
if ($controls['BtnSearchPagePrev']) {
    $controls['BtnSearchPagePrev'].Add_Click({
        if ($state.SearchPage -gt 1) {
            $state.SearchPage--
            Render-PagedSearchResults
        }
    })
}
if ($controls['BtnSearchPageNext']) {
    $controls['BtnSearchPageNext'].Add_Click({
        $state.SearchPage++
        Render-PagedSearchResults
    })
}

if ($controls['BtnVerifyFilterSyntax']) {
    $controls['BtnVerifyFilterSyntax'].Add_Click({
        $filter = if ($controls['TxtRawLdapFilter']) { $controls['TxtRawLdapFilter'].Text.Trim() } else { "" }
        if ([string]::IsNullOrWhiteSpace($filter)) {
            [System.Windows.MessageBox]::Show("Please enter an LDAP filter to verify.", "Empty Filter", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            return
        }
        $res = Test-LdapFilter -Filter $filter
        if ($res.IsValid) {
            $explanation = Convert-LdapFilterToHumanText -Filter $filter
            if ($controls['BorderFilterExplanation']) { $controls['BorderFilterExplanation'].Visibility = [System.Windows.Visibility]::Visible }
            if ($controls['TxtFilterHumanExplanation']) {
                $controls['TxtFilterHumanExplanation'].Text = "Valid RFC 4515 Syntax. Meaning: $explanation"
                $controls['TxtFilterHumanExplanation'].Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#38BDF8")
            }
            [System.Windows.MessageBox]::Show("LDAP filter is VALID (RFC 4515 compliant).`r`n`r`nPlain-English Translation:`r`n$explanation", "Filter Syntax Valid", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        } else {
            if ($controls['BorderFilterExplanation']) { $controls['BorderFilterExplanation'].Visibility = [System.Windows.Visibility]::Visible }
            if ($controls['TxtFilterHumanExplanation']) {
                $controls['TxtFilterHumanExplanation'].Text = "Syntax Error: $($res.Errors -join '; ')"
                $controls['TxtFilterHumanExplanation'].Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#F87171")
            }
            [System.Windows.MessageBox]::Show("LDAP filter syntax error(s):`r`n`r`n$($res.Errors -join "`r`n")", "Filter Syntax Invalid", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
        }
    })
}

if ($controls['TxtRawLdapFilter']) {
    $controls['TxtRawLdapFilter'].Add_TextChanged({
        $filter = $controls['TxtRawLdapFilter'].Text.Trim()
        if (-not [string]::IsNullOrWhiteSpace($filter) -and $filter.StartsWith("(") -and $filter.EndsWith(")")) {
            $explanation = Convert-LdapFilterToHumanText -Filter $filter
            if ($controls['BorderFilterExplanation']) { $controls['BorderFilterExplanation'].Visibility = [System.Windows.Visibility]::Visible }
            if ($controls['TxtFilterHumanExplanation']) {
                $controls['TxtFilterHumanExplanation'].Text = $explanation
                $controls['TxtFilterHumanExplanation'].Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#38BDF8")
            }
        }
    })
}

if ($controls['BtnRunLdapSearch']) { $controls['BtnRunLdapSearch'].Add_Click({ Invoke-LdapSearchUI }) }
if ($controls['TxtRawLdapFilter']) {
    $controls['TxtRawLdapFilter'].Add_KeyDown({
        if ($_.Key -eq [System.Windows.Input.Key]::Enter) { Invoke-LdapSearchUI }
    })
}

if ($controls['CmbSearchHistory']) {
    $controls['CmbSearchHistory'].Add_SelectionChanged({
        $sel = $controls['CmbSearchHistory'].SelectedItem
        if ($sel -and $sel.Tag) {
            $item = $sel.Tag
            if ($controls['TxtRawLdapFilter'] -and $item.Filter) { $controls['TxtRawLdapFilter'].Text = $item.Filter }
            if ($controls['TxtSearchBaseDn'] -and $item.BaseDn) { $controls['TxtSearchBaseDn'].Text = $item.BaseDn }
            if ($controls['CmbSearchScope'] -and $item.Scope) {
                foreach ($ci in $controls['CmbSearchScope'].Items) {
                    if ($ci.Content.ToString() -ieq $item.Scope) {
                        $controls['CmbSearchScope'].SelectedItem = $ci
                        break
                    }
                }
            }
        }
    })
}

if ($controls['BtnPinSearch']) {
    $controls['BtnPinSearch'].Add_Click({
        $currFilter = if ($controls['TxtRawLdapFilter']) { $controls['TxtRawLdapFilter'].Text.Trim() } else { "" }
        if ([string]::IsNullOrWhiteSpace($currFilter)) { return }
        $currBase = if ($controls['TxtSearchBaseDn']) { $controls['TxtSearchBaseDn'].Text.Trim() } else { "" }
        $currScope = if ($controls['CmbSearchScope'] -and $controls['CmbSearchScope'].SelectedItem) { $controls['CmbSearchScope'].SelectedItem.Content.ToString() } else { "Subtree" }

        $existingPinned = $state.PinnedSearches | Where-Object { $_.Filter -ieq $currFilter -and $_.BaseDn -ieq $currBase }
        if ($existingPinned) {
            [void]$state.PinnedSearches.Remove($existingPinned)
            [System.Windows.MessageBox]::Show("Unpinned query: `n$currFilter", "Pinned Searches", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        } else {
            $pinnedObj = [PSCustomObject]@{
                Filter    = $currFilter
                BaseDn    = $currBase
                Scope     = $currScope
                Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm")
            }
            $state.PinnedSearches.Insert(0, $pinnedObj)
            [System.Windows.MessageBox]::Show("Pinned query for quick access: `n$currFilter", "Pinned Searches", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        }
        Update-SearchHistoryUI
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

if ($controls['BtnSearchExportScim']) {
    $controls['BtnSearchExportScim'].Add_Click({
        if (-not $state.CurrentSearchResults -or $state.CurrentSearchResults.Count -eq 0) {
            [System.Windows.MessageBox]::Show("No search results to export.", "Notice", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            return
        }
        $saveDlg = New-Object System.Windows.Forms.SaveFileDialog
        $saveDlg.FileName = "SCIM_Search_$(Get-Date -Format 'yyyyMMdd_HHmm').json"
        $saveDlg.Filter = "SCIM 2.0 JSON (*.json)|*.json|All files (*.*)|*.*"
        if ($saveDlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $res = Export-ADDataToScim -Data $state.CurrentSearchResults -FilePath $saveDlg.FileName
            if ($res.Success) {
                [System.Windows.MessageBox]::Show($res.Message, "SCIM 2.0 Export Successful", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            } else {
                [System.Windows.MessageBox]::Show($res.Message, "SCIM Export Failed", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
            }
        }
    })
}

if ($controls['BtnSearchAddToBasket']) {
    $controls['BtnSearchAddToBasket'].Add_Click({
        $selected = $controls['GridSearchResults'].SelectedItems
        if ($selected -and $selected.Count -gt 0) {
            Add-ToBasket -Items $selected -DefaultClass "DirectoryObject"
        } else {
            [System.Windows.MessageBox]::Show("Please select one or more search results to add to the Directory Basket.", "Selection Required", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
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

    $incOp = if ($controls['ChkShowOperationalAttributes']) { [bool]$controls['ChkShowOperationalAttributes'].IsChecked } else { $false }
    Set-Status -Message "Fetching raw directory attributes for: $TargetDN (Operational: $incOp)..."
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $attrs = Get-ADObjectRawAttributes -DistinguishedName $TargetDN -IncludeOperational:$incOp
    $sw.Stop()

    if ($attrs -and $attrs.Count -gt 0) {
        $state.CurrentRawAttributes = $attrs
        $state.CurrentRawDN = $attrs[0].RawDN
        if ($controls['TxtAttrEditorDN']) { $controls['TxtAttrEditorDN'].Text = $state.CurrentRawDN }
        if ($controls['GridRawAttributes']) { $controls['GridRawAttributes'].ItemsSource = $attrs }
        if ($controls['TxtAttrCount']) { $controls['TxtAttrCount'].Text = "$($attrs.Count) attributes loaded" }
        Set-Status -Message "Loaded $($attrs.Count) attributes for '$($attrs[0].RawDN)'." -Count "$($attrs.Count) attributes"
        Log-LdapRequest -Operation "SEARCH/ATTRS" -TargetDN $state.CurrentRawDN -FilterOrPayload "(IncludeOperational=$incOp)" -DurationMs $sw.ElapsedMilliseconds -Status "SUCCESS" -Details "Loaded $($attrs.Count) attributes for object '$($state.CurrentRawDN)'."
    } else {
        Log-LdapRequest -Operation "SEARCH/ATTRS" -TargetDN $TargetDN -FilterOrPayload "(IncludeOperational=$incOp)" -DurationMs $sw.ElapsedMilliseconds -Status "ERROR" -Details "No attributes found or object could not be resolved: $TargetDN"
        [System.Windows.MessageBox]::Show("No attributes found or object could not be resolved: $TargetDN", "Object Not Found", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
    }
}

if ($controls['ChkShowOperationalAttributes']) {
    $controls['ChkShowOperationalAttributes'].Add_Click({
        if ($controls['TxtAttrEditorDN'] -and -not [string]::IsNullOrWhiteSpace($controls['TxtAttrEditorDN'].Text)) {
            Load-RawAttributesUI -TargetDN $controls['TxtAttrEditorDN'].Text.Trim()
        }
    })
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

    $isUac   = ($selAttr.Name -ieq "userAccountControl")
    $isPhoto = ($selAttr.Name -in @('thumbnailPhoto', 'jpegPhoto', 'photo') -or ($selAttr.Name -match 'photo' -and ($selAttr.RawValue -is [byte[]] -or $selAttr.Type -match 'Binary|OctetString')))
    $isCert  = ($selAttr.Name -in @('userCertificate', 'cACertificate', 'userSMIMECertificate') -or ($selAttr.Name -match 'cert' -and ($selAttr.RawValue -is [byte[]] -or $selAttr.Type -match 'Binary|OctetString')))
    $isHex   = (-not $isPhoto -and -not $isCert -and ($selAttr.RawValue -is [byte[]] -or $selAttr.Type -match 'Binary|OctetString'))
    $isMulti = ($selAttr.IsMultiValued -or $selAttr.Count -gt 1 -or $selAttr.Type -match "MultiValued")
    $isDate  = (-not $isHex -and ($selAttr.Name -in @('accountExpires', 'pwdLastSet', 'lockoutTime', 'lastLogon', 'lastLogonTimestamp', 'whenCreated', 'whenChanged', 'badPasswordTime') -or $selAttr.Type -match 'FileTime|GeneralizedTime|Timestamp'))
    $isPwd   = ($selAttr.Name -in @('userPassword', 'unicodePwd'))

    # Hide all mode panels first
    foreach ($m in @('ModeStringEditor', 'ModeMultiValueEditor', 'ModeUacEditor', 'ModePhotoEditor', 'ModeCertificateEditor', 'ModeHexEditor', 'ModeDateTimeEditor', 'ModePasswordHashEditor')) {
        if ($dControls[$m]) { $dControls[$m].Visibility = [System.Windows.Visibility]::Collapsed }
    }

    if ($isUac) {
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

    } elseif ($isPhoto) {
        $dControls['ModePhotoEditor'].Visibility = [System.Windows.Visibility]::Visible
        $script:stagedPhotoBytes = if ($selAttr.RawValue -is [byte[]]) { $selAttr.RawValue } elseif ($selAttr.RawValues -and $selAttr.RawValues[0] -is [byte[]]) { $selAttr.RawValues[0] } else { $null }

        $RenderPhoto = {
            if ($script:stagedPhotoBytes -and $script:stagedPhotoBytes.Length -gt 0) {
                try {
                    $ms = [System.IO.MemoryStream]::new($script:stagedPhotoBytes)
                    $bmp = [System.Windows.Media.Imaging.BitmapImage]::new()
                    $bmp.BeginInit()
                    $bmp.StreamSource = $ms
                    $bmp.CacheOption = [System.Windows.Media.Imaging.BitmapCacheOption]::OnLoad
                    $bmp.EndInit()
                    $dControls['ImgPhotoPreview'].Source = $bmp
                    $dControls['TxtPhotoPlaceholder'].Visibility = [System.Windows.Visibility]::Collapsed
                    $dControls['TxtPhotoDimensions'].Text = "Dimensions: $($bmp.PixelWidth) x $($bmp.PixelHeight) px"
                    $dControls['TxtPhotoSize'].Text = "File Size: $([Math]::Round($script:stagedPhotoBytes.Length / 1KB, 1)) KB ($($script:stagedPhotoBytes.Length) bytes)"
                } catch {
                    $dControls['ImgPhotoPreview'].Source = $null
                    $dControls['TxtPhotoPlaceholder'].Text = "Image Error"
                    $dControls['TxtPhotoPlaceholder'].Visibility = [System.Windows.Visibility]::Visible
                }
            } else {
                $dControls['ImgPhotoPreview'].Source = $null
                $dControls['TxtPhotoPlaceholder'].Text = "No Image"
                $dControls['TxtPhotoPlaceholder'].Visibility = [System.Windows.Visibility]::Visible
                $dControls['TxtPhotoDimensions'].Text = "Dimensions: --"
                $dControls['TxtPhotoSize'].Text = "File Size: --"
            }
        }
        & $RenderPhoto

        $dControls['BtnLoadPhoto'].Add_Click({
            $ofd = [Microsoft.Win32.OpenFileDialog]::new()
            $ofd.Filter = "Image Files (*.jpg;*.jpeg;*.png;*.bmp)|*.jpg;*.jpeg;*.png;*.bmp|All Files (*.*)|*.*"
            if ($ofd.ShowDialog() -eq $true) {
                $script:stagedPhotoBytes = [System.IO.File]::ReadAllBytes($ofd.FileName)
                & $RenderPhoto
            }
        })

        $dControls['BtnExportPhoto'].Add_Click({
            if (-not $script:stagedPhotoBytes -or $script:stagedPhotoBytes.Length -eq 0) { return }
            $sfd = [Microsoft.Win32.SaveFileDialog]::new()
            $sfd.FileName = "$($selAttr.Name).jpg"
            $sfd.Filter = "JPEG Image (*.jpg)|*.jpg|PNG Image (*.png)|*.png|All Files (*.*)|*.*"
            if ($sfd.ShowDialog() -eq $true) {
                [System.IO.File]::WriteAllBytes($sfd.FileName, $script:stagedPhotoBytes)
                [System.Windows.MessageBox]::Show("Photo successfully exported to $($sfd.FileName)", "Export Complete", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            }
        })

        $dControls['BtnRemovePhoto'].Add_Click({
            $script:stagedPhotoBytes = [byte[]]@()
            & $RenderPhoto
        })

    } elseif ($isCert) {
        $dControls['ModeCertificateEditor'].Visibility = [System.Windows.Visibility]::Visible
        $script:stagedCertBytes = if ($selAttr.RawValue -is [byte[]]) { $selAttr.RawValue } elseif ($selAttr.RawValues -and $selAttr.RawValues[0] -is [byte[]]) { $selAttr.RawValues[0] } else { $null }

        $RenderCert = {
            if ($script:stagedCertBytes -and $script:stagedCertBytes.Length -gt 0) {
                try {
                    $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($script:stagedCertBytes)
                    $dControls['TxtCertSubject'].Text = $cert.Subject
                    $dControls['TxtCertIssuer'].Text = $cert.Issuer
                    $validDays = [Math]::Round(($cert.NotAfter - (Get-Date)).TotalDays)
                    $validText = "$($cert.NotBefore.ToString('yyyy-MM-dd')) to $($cert.NotAfter.ToString('yyyy-MM-dd'))"
                    if ($validDays -lt 0) { $validText += " (EXPIRED)" } else { $validText += " ($validDays days remaining)" }
                    $dControls['TxtCertValidity'].Text = $validText
                    $dControls['TxtCertSerial'].Text = $cert.SerialNumber
                    $dControls['TxtCertThumbprint'].Text = $cert.Thumbprint
                    $dControls['TxtCertAlgorithm'].Text = "$($cert.SignatureAlgorithm.FriendlyName) ($($cert.PublicKey.Key.KeySize)-bit)"
                } catch {
                    $dControls['TxtCertSubject'].Text = "Parse Error: $_"
                }
            } else {
                $dControls['TxtCertSubject'].Text = "<No Certificate Present>"
                $dControls['TxtCertIssuer'].Text = "--"
                $dControls['TxtCertValidity'].Text = "--"
                $dControls['TxtCertSerial'].Text = "--"
                $dControls['TxtCertThumbprint'].Text = "--"
                $dControls['TxtCertAlgorithm'].Text = "--"
            }
        }
        & $RenderCert

        $dControls['BtnViewWindowsCert'].Add_Click({
            if ($script:stagedCertBytes -and $script:stagedCertBytes.Length -gt 0) {
                try {
                    $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($script:stagedCertBytes)
                    [System.Security.Cryptography.X509Certificates.X509Certificate2UI]::DisplayCertificate($cert)
                } catch {}
            }
        })

        $dControls['BtnExportCert'].Add_Click({
            if (-not $script:stagedCertBytes -or $script:stagedCertBytes.Length -eq 0) { return }
            $sfd = [Microsoft.Win32.SaveFileDialog]::new()
            $sfd.FileName = "$($selAttr.Name).cer"
            $sfd.Filter = "DER Encoded Binary X.509 (*.cer)|*.cer|All Files (*.*)|*.*"
            if ($sfd.ShowDialog() -eq $true) {
                [System.IO.File]::WriteAllBytes($sfd.FileName, $script:stagedCertBytes)
                [System.Windows.MessageBox]::Show("Certificate saved to $($sfd.FileName)", "Export Complete", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            }
        })

        $dControls['BtnImportCert'].Add_Click({
            $ofd = [Microsoft.Win32.OpenFileDialog]::new()
            $ofd.Filter = "X.509 Certificate (*.cer;*.crt)|*.cer;*.crt|All Files (*.*)|*.*"
            if ($ofd.ShowDialog() -eq $true) {
                $script:stagedCertBytes = [System.IO.File]::ReadAllBytes($ofd.FileName)
                & $RenderCert
            }
        })

        $dControls['BtnClearCert'].Add_Click({
            $script:stagedCertBytes = [byte[]]@()
            & $RenderCert
        })

    } elseif ($isHex) {
        $dControls['ModeHexEditor'].Visibility = [System.Windows.Visibility]::Visible
        $script:stagedBinaryBytes = if ($selAttr.RawValue -is [byte[]]) { $selAttr.RawValue } elseif ($selAttr.RawValues -and $selAttr.RawValues[0] -is [byte[]]) { $selAttr.RawValues[0] } else { $null }

        $RenderHex = {
            if ($script:stagedBinaryBytes -and $script:stagedBinaryBytes.Length -gt 0) {
                $sb = [System.Text.StringBuilder]::new()
                $len = $script:stagedBinaryBytes.Length
                for ($i = 0; $i -lt $len; $i += 16) {
                    $chunkLen = [Math]::Min(16, $len - $i)
                    $chunk = $script:stagedBinaryBytes[$i..($i + $chunkLen - 1)]
                    $hexPart = ($chunk | ForEach-Object { $_.ToString("X2") }) -join " "
                    $hexPart = $hexPart.PadRight(48)
                    $asciiPart = -join ($chunk | ForEach-Object { if ($_ -ge 32 -and $_ -le 126) { [char]$_ } else { '.' } })
                    [void]$sb.AppendLine(("{0:X8}:  {1}  |{2}|" -f $i, $hexPart, $asciiPart))
                }
                $dControls['TxtHexView'].Text = $sb.ToString()
                $dControls['TxtHexByteCount'].Text = "Total: $len bytes ($($len * 8)-bit)"
            } else {
                $dControls['TxtHexView'].Text = "<Empty Data>"
                $dControls['TxtHexByteCount'].Text = "Total: 0 bytes"
            }
        }
        & $RenderHex

        $dControls['BtnCopyHex'].Add_Click({
            if ($script:stagedBinaryBytes) {
                $hexOnly = ($script:stagedBinaryBytes | ForEach-Object { $_.ToString("X2") }) -join " "
                [System.Windows.Clipboard]::SetText($hexOnly)
                [System.Windows.MessageBox]::Show("Hex bytes copied to clipboard.", "Copied", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            }
        })

        $dControls['BtnExportBinary'].Add_Click({
            if (-not $script:stagedBinaryBytes) { return }
            $sfd = [Microsoft.Win32.SaveFileDialog]::new()
            $sfd.FileName = "$($selAttr.Name).bin"
            $sfd.Filter = "Binary File (*.bin)|*.bin|All Files (*.*)|*.*"
            if ($sfd.ShowDialog() -eq $true) {
                [System.IO.File]::WriteAllBytes($sfd.FileName, $script:stagedBinaryBytes)
                [System.Windows.MessageBox]::Show("Binary data exported to $($sfd.FileName)", "Export Complete", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            }
        })

        $dControls['BtnImportBinary'].Add_Click({
            $ofd = [Microsoft.Win32.OpenFileDialog]::new()
            $ofd.Filter = "All Files (*.*)|*.*"
            if ($ofd.ShowDialog() -eq $true) {
                $script:stagedBinaryBytes = [System.IO.File]::ReadAllBytes($ofd.FileName)
                & $RenderHex
            }
        })

        $dControls['BtnClearBinary'].Add_Click({
            $script:stagedBinaryBytes = [byte[]]@()
            & $RenderHex
        })

    } elseif ($isMulti) {
        $dControls['ModeMultiValueEditor'].Visibility = [System.Windows.Visibility]::Visible

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

    } elseif ($isDate) {
        $dControls['ModeDateTimeEditor'].Visibility = [System.Windows.Visibility]::Visible
        $script:stagedTimestampMode = if ($selAttr.Name -in @('whenCreated', 'whenChanged') -or $selAttr.Type -match 'GeneralizedTime') { "GeneralizedTime" } else { "FileTime" }

        $UpdateCalculatedTimestamps = {
            param([DateTime]$dt, [bool]$isZero = $false)
            if ($isZero) {
                $dControls['TxtConvertedFileTime'].Text = "0 (Never / Infinite)"
                $dControls['TxtConvertedGeneralized'].Text = "0 (Never)"
                return
            }
            $fileTimeVal = $dt.ToFileTimeUtc()
            $genTimeVal = $dt.ToUniversalTime().ToString("yyyyMMddHHmmss.0Z")
            $dControls['TxtConvertedFileTime'].Text = "$fileTimeVal"
            $dControls['TxtConvertedGeneralized'].Text = "$genTimeVal"
        }

        $now = Get-Date
        if ($dControls['PickerDate']) { $dControls['PickerDate'].SelectedDate = $now.Date }
        if ($dControls['TxtDateTimePart']) { $dControls['TxtDateTimePart'].Text = $now.ToString("HH:mm:ss") }
        & $UpdateCalculatedTimestamps -dt $now

        $dControls['BtnDateSetNow'].Add_Click({
            $cur = Get-Date
            $dControls['PickerDate'].SelectedDate = $cur.Date
            $dControls['TxtDateTimePart'].Text = $cur.ToString("HH:mm:ss")
            & $UpdateCalculatedTimestamps -dt $cur
        })

        $dControls['BtnDateSetNever'].Add_Click({
            $dControls['PickerDate'].SelectedDate = $null
            $dControls['TxtDateTimePart'].Text = "00:00:00"
            & $UpdateCalculatedTimestamps -dt (Get-Date) -isZero $true
        })

        $dControls['BtnDateClear'].Add_Click({
            $dControls['PickerDate'].SelectedDate = $null
            $dControls['TxtDateTimePart'].Text = ""
            $dControls['TxtConvertedFileTime'].Text = "0"
            $dControls['TxtConvertedGeneralized'].Text = ""
        })

    } elseif ($isPwd) {
        $dControls['ModePasswordHashEditor'].Visibility = [System.Windows.Visibility]::Visible
        $dControls['BtnCalculateHash'].Add_Click({
            $plain = $dControls['TxtHashPlainPassword'].Text
            $scheme = if ($dControls['CmbHashAlgorithm'].SelectedItem) {
                [string]$dControls['CmbHashAlgorithm'].SelectedItem.Content
            } else { "{SSHA}" }

            $plainBytes = [System.Text.Encoding]::UTF8.GetBytes($plain)
            $hashResult = ""

            if ($scheme -match 'SSHA') {
                $salt = New-Object byte[] 4
                [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($salt)
                $hasher = [System.Security.Cryptography.SHA1]::Create()
                $combined = $plainBytes + $salt
                $hash = $hasher.ComputeHash($combined)
                $b64 = [Convert]::ToBase64String($hash + $salt)
                $hashResult = "{SSHA}$b64"
            }
            elseif ($scheme -match 'SHA256') {
                $hasher = [System.Security.Cryptography.SHA256]::Create()
                $hashResult = "{SHA256}" + [Convert]::ToBase64String($hasher.ComputeHash($plainBytes))
            }
            elseif ($scheme -match 'SHA512') {
                $hasher = [System.Security.Cryptography.SHA512]::Create()
                $hashResult = "{SHA512}" + [Convert]::ToBase64String($hasher.ComputeHash($plainBytes))
            }
            elseif ($scheme -match 'MD5') {
                $hasher = [System.Security.Cryptography.MD5]::Create()
                $hashResult = "{MD5}" + [Convert]::ToBase64String($hasher.ComputeHash($plainBytes))
            }
            elseif ($scheme -match 'SHA') {
                $hasher = [System.Security.Cryptography.SHA1]::Create()
                $hashResult = "{SHA}" + [Convert]::ToBase64String($hasher.ComputeHash($plainBytes))
            }
            else {
                $hashResult = $plain
            }

            $dControls['TxtGeneratedHashOutput'].Text = $hashResult
        })

        $dControls['BtnClearHash'].Add_Click({
            $dControls['TxtHashPlainPassword'].Text = ""
            $dControls['TxtGeneratedHashOutput'].Text = ""
        })

    } else {
        $dControls['ModeStringEditor'].Visibility = [System.Windows.Visibility]::Visible

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
        if (-not (Test-CanModifyDirectory)) { return }
        try {
            if ($isUac) {
                $newUac = & $ComputeUac
                $setRes = Set-ADObjectRawAttribute -DistinguishedName $selAttr.RawDN -AttributeName "userAccountControl" -NewValue $newUac
            } elseif ($isPhoto) {
                $setRes = Set-ADObjectRawAttribute -DistinguishedName $selAttr.RawDN -AttributeName $selAttr.Name -NewValue $script:stagedPhotoBytes
            } elseif ($isCert) {
                $setRes = Set-ADObjectRawAttribute -DistinguishedName $selAttr.RawDN -AttributeName $selAttr.Name -NewValue $script:stagedCertBytes
            } elseif ($isHex) {
                $setRes = Set-ADObjectRawAttribute -DistinguishedName $selAttr.RawDN -AttributeName $selAttr.Name -NewValue $script:stagedBinaryBytes
            } elseif ($isMulti) {
                $newVals = @($multiItems)
                $setRes = Set-ADObjectRawAttribute -DistinguishedName $selAttr.RawDN -AttributeName $selAttr.Name -NewValue $newVals
            } elseif ($isDate) {
                $valToSave = if ($dControls['TxtConvertedFileTime'].Text -match '^0\b') {
                    "0"
                } elseif ($script:stagedTimestampMode -eq "GeneralizedTime") {
                    $dControls['TxtConvertedGeneralized'].Text
                } else {
                    $dControls['TxtConvertedFileTime'].Text
                }
                $setRes = Set-ADObjectRawAttribute -DistinguishedName $selAttr.RawDN -AttributeName $selAttr.Name -NewValue $valToSave
            } elseif ($isPwd) {
                $valToSave = $dControls['TxtGeneratedHashOutput'].Text
                if (-not $valToSave) { $valToSave = $dControls['TxtHashPlainPassword'].Text }
                $setRes = Set-ADObjectRawAttribute -DistinguishedName $selAttr.RawDN -AttributeName $selAttr.Name -NewValue $valToSave
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
        if (-not (Test-CanModifyDirectory)) { return }
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

if ($controls['BtnExportObjectDsml']) {
    $controls['BtnExportObjectDsml'].Add_Click({
        if (-not $state.CurrentRawAttributes -or $state.CurrentRawAttributes.Count -eq 0) {
            [System.Windows.MessageBox]::Show("Please load an object's attributes first.", "No Attributes", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            return
        }
        $saveDlg = New-Object System.Windows.Forms.SaveFileDialog
        $saveDlg.FileName = "AD_Object_$(Get-Date -Format 'yyyyMMdd_HHmm').dsml"
        $saveDlg.Filter = "DSML XML files (*.dsml;*.xml)|*.dsml;*.xml|All files (*.*)|*.*"
        if ($saveDlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            # Convert attributes list into a single PSCustomObject for DSML export
            $objProp = [ordered]@{ DistinguishedName = $state.CurrentRawDN }
            foreach ($attr in $state.CurrentRawAttributes) {
                if (-not $attr.IsOperational) {
                    $objProp[$attr.Name] = $attr.Value
                }
            }
            $expObj = [PSCustomObject]$objProp
            $res = Export-ADDataToDsml -Data @($expObj) -FilePath $saveDlg.FileName
            if ($res.Success) {
                [System.Windows.MessageBox]::Show("Object exported to DSML v2 XML format successfully:`n$($saveDlg.FileName)", "Export Successful", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            } else {
                [System.Windows.MessageBox]::Show("Failed to export DSML: $($res.Message)", "Export Failed", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
            }
        }
    })
}

if ($controls['BtnViewHtmlProfile']) {
    $controls['BtnViewHtmlProfile'].Add_Click({
        $dn = if ($controls['TxtAttrEditorDN']) { $controls['TxtAttrEditorDN'].Text.Trim() } else { $state.CurrentRawDN }
        if (-not $dn) {
            [System.Windows.MessageBox]::Show("Please enter or load a target object DN first.", "No Object Loaded", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            return
        }
        Show-ObjectHtmlDossier -TargetDN $dn
    })
}

# GridRawAttributes Context Menu
if ($controls['MenuCtxCopyAttrValue']) {
    $controls['MenuCtxCopyAttrValue'].Add_Click({
        $sel = if ($controls['GridRawAttributes']) { $controls['GridRawAttributes'].SelectedItem } else { $null }
        if ($sel) {
            [System.Windows.Clipboard]::SetText("$($sel.Value)")
            Set-Status -Message "Copied attribute value for '$($sel.Name)'."
        }
    })
}

if ($controls['MenuCtxCopyAttrName']) {
    $controls['MenuCtxCopyAttrName'].Add_Click({
        $sel = if ($controls['GridRawAttributes']) { $controls['GridRawAttributes'].SelectedItem } else { $null }
        if ($sel) {
            [System.Windows.Clipboard]::SetText("$($sel.Name)")
            Set-Status -Message "Copied attribute name: $($sel.Name)"
        }
    })
}

if ($controls['MenuCtxCopyAttrLdif']) {
    $controls['MenuCtxCopyAttrLdif'].Add_Click({
        $sel = if ($controls['GridRawAttributes']) { $controls['GridRawAttributes'].SelectedItem } else { $null }
        if ($sel) {
            $ldifLine = "$($sel.Name): $($sel.Value)"
            [System.Windows.Clipboard]::SetText($ldifLine)
            Set-Status -Message "Copied LDIF line: $ldifLine"
        }
    })
}

if ($controls['MenuCtxEditAttrValue']) {
    $controls['MenuCtxEditAttrValue'].Add_Click({
        if ($controls['BtnEditAttrValue']) { $controls['BtnEditAttrValue'].RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))) }
    })
}

if ($controls['MenuCtxClearAttrValue']) {
    $controls['MenuCtxClearAttrValue'].Add_Click({
        if ($controls['BtnClearAttrValue']) { $controls['BtnClearAttrValue'].RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))) }
    })
}

if ($controls['MenuCtxSearchAttrValue']) {
    $controls['MenuCtxSearchAttrValue'].Add_Click({
        $sel = if ($controls['GridRawAttributes']) { $controls['GridRawAttributes'].SelectedItem } else { $null }
        if ($sel -and $sel.Value) {
            $controls['NavDirectorySearch'].IsChecked = $true
            Show-Panel "DirectorySearch"
            Init-DirectorySearch
            $rawVal = "$($sel.Value)".Trim()
            $escapedVal = $rawVal -replace '\\', '\5c' -replace '\*', '\2a' -replace '\(', '\28' -replace '\)', '\29' -replace '\0', '\00'
            if ($controls['TxtRawLdapFilter']) { $controls['TxtRawLdapFilter'].Text = "($($sel.Name)=$escapedVal)" }
            if ($controls['BtnRunLdapSearch']) { $controls['BtnRunLdapSearch'].RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))) }
        }
    })
}

if ($controls['MenuCtxViewAttrSchema']) {
    $controls['MenuCtxViewAttrSchema'].Add_Click({
        $sel = if ($controls['GridRawAttributes']) { $controls['GridRawAttributes'].SelectedItem } else { $null }
        if ($sel) {
            $controls['NavSchemaBrowser'].IsChecked = $true
            Show-Panel "SchemaBrowser"
            if ($controls['RadioSchemaAttributes']) { $controls['RadioSchemaAttributes'].IsChecked = $true }
            if ($controls['TxtSearchSchema']) { $controls['TxtSearchSchema'].Text = "$($sel.Name)" }
            Refresh-Schema
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
    Update-LdifOutline
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
            "Template: DSML v2 Search Response" {
@"
<?xml version="1.0" encoding="UTF-8"?>
<batchResponse xmlns="urn:oasis:names:tc:DSML:2:0:core">
  <searchResponse>
    <searchResultEntry dn="CN=Jane Doe,OU=Users,$domainNC">
      <attr name="objectClass">
        <value>top</value>
        <value>person</value>
        <value>organizationalPerson</value>
        <value>user</value>
      </attr>
      <attr name="sAMAccountName">
        <value>jane.doe</value>
      </attr>
      <attr name="userPrincipalName">
        <value>jane.doe@$($adContext.DomainName)</value>
      </attr>
      <attr name="mail">
        <value>jane.doe@$($adContext.DomainName)</value>
      </attr>
    </searchResultEntry>
    <searchResultDone>
      <resultCode code="0" descr="success"/>
    </searchResultDone>
  </searchResponse>
</batchResponse>
"@
            }
            "Template: DSML v2 Modify Request" {
@"
<?xml version="1.0" encoding="UTF-8"?>
<batchRequest xmlns="urn:oasis:names:tc:DSML:2:0:core">
  <modifyRequest dn="CN=Jane Doe,OU=Users,$domainNC">
    <modification name="department" operation="replace">
      <value>Information Security</value>
    </modification>
    <modification name="title" operation="replace">
      <value>Lead Security Architect</value>
    </modification>
  </modifyRequest>
</batchRequest>
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

if ($controls['BtnLdifOpenFile']) {
    $controls['BtnLdifOpenFile'].Add_Click({
        $ofd = New-Object Microsoft.Win32.OpenFileDialog
        $ofd.Filter = "Directory Files (*.ldif;*.dsml;*.xml;*.txt)|*.ldif;*.dsml;*.xml;*.txt|All Files (*.*)|*.*"
        if ($ofd.ShowDialog()) {
            try {
                $fileText = [System.IO.File]::ReadAllText($ofd.FileName, [System.Text.Encoding]::UTF8)
                if ($controls['TxtLdifEditor']) { $controls['TxtLdifEditor'].Text = $fileText }
                Set-Status -Message "Loaded directory script from: $($ofd.FileName)"
            } catch {
                [System.Windows.MessageBox]::Show("Failed to open file: $_", "File Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
            }
        }
    })
}

if ($controls['BtnLdifValidate']) { $controls['BtnLdifValidate'].Add_Click({ Validate-LdifUI }) }
if ($controls['BtnLdifDiffGen']) {
    $controls['BtnLdifDiffGen'].Add_Click({
        # Generate LDIF modify diff between two objects
        $diffScript = ""
        if ($state.CurrentCompare -and $state.CurrentCompare.Obj1 -and $state.CurrentCompare.Obj2) {
            $diffScript = New-LdifChangeScript -OriginalObject $state.CurrentCompare.Obj1 -ModifiedObject $state.CurrentCompare.Obj2
        } elseif ($state.BasketItems -and $state.BasketItems.Count -ge 2) {
            $item1 = $state.BasketItems[0]
            $item2 = $state.BasketItems[1]
            $obj1 = Get-ADRawObject -DistinguishedName $item1.DistinguishedName
            $obj2 = Get-ADRawObject -DistinguishedName $item2.DistinguishedName
            if ($obj1 -and $obj2) {
                $diffScript = New-LdifChangeScript -OriginalObject $obj1 -ModifiedObject $obj2
            }
        }

        if ([string]::IsNullOrWhiteSpace($diffScript)) {
            $diffScript = @"
dn: CN=Jane Doe,OU=Users,DC=example,DC=com
changetype: modify
replace: title
title: Senior Solutions Architect
-
replace: department
department: Cloud Engineering
-
delete: telephoneNumber
-
add: description
description: Synchronized via AD Management Studio Diff Generator
-
"@
        }

        if ($controls['TxtLdifEditor']) {
            $controls['TxtLdifEditor'].Text = $diffScript
        }
        if ($controls['TxtLdifLog']) {
            $controls['TxtLdifLog'].Text = "[$(Get-Date -Format 'HH:mm:ss')] Generated RFC 2849 modify delta script in editor."
        }
    })
}
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

if ($controls['BtnExportDsml']) {
    $controls['BtnExportDsml'].Add_Click({
        $content = if ($controls['TxtLdifEditor']) { $controls['TxtLdifEditor'].Text } else { "" }
        if ([string]::IsNullOrWhiteSpace($content)) { return }
        $saveDlg = New-Object System.Windows.Forms.SaveFileDialog
        $saveDlg.FileName = "Directory_Batch_$(Get-Date -Format 'yyyyMMdd_HHmm').dsml"
        $saveDlg.Filter = "DSML XML files (*.dsml;*.xml)|*.dsml;*.xml|All files (*.*)|*.*"
        if ($saveDlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            [System.IO.File]::WriteAllText($saveDlg.FileName, $content, [System.Text.Encoding]::UTF8)
            [System.Windows.MessageBox]::Show("Saved DSML XML file to $($saveDlg.FileName).", "File Saved", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        }
    })
}

# LDIF Document Record Outline Logic (Softerra Ch07 / Screenshot 26 Parity)
function Update-LdifOutline {
    if (-not $controls['TxtLdifEditor'] -or -not $controls['ListLdifRecords']) { return }
    $text = $controls['TxtLdifEditor'].Text
    if ([string]::IsNullOrWhiteSpace($text)) {
        $controls['ListLdifRecords'].ItemsSource = $null
        return
    }

    $lines = $text -split "`r?`n"
    $records = New-Object System.Collections.Generic.List[PSObject]
    $curDn = ""
    $curChange = "ADD"
    $filter = if ($controls['TxtFilterLdifRecords']) { $controls['TxtFilterLdifRecords'].Text.Trim() } else { "" }

    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        if ($line -match '^dn:\s*(.+)$') {
            $curDn = $matches[1].Trim()
            $curChange = "ADD"
        } elseif ($line -match '^changetype:\s*(.+)$') {
            $curChange = $matches[1].Trim().ToUpperInvariant()
        } elseif ([string]::IsNullOrWhiteSpace($line)) {
            if ($curDn) {
                if ([string]::IsNullOrWhiteSpace($filter) -or $curDn -match [regex]::Escape($filter) -or $curChange -match [regex]::Escape($filter)) {
                    $records.Add([PSCustomObject]@{
                        DN         = $curDn
                        ChangeType = $curChange
                    })
                }
                $curDn = ""
            }
        }
    }
    if ($curDn) {
        if ([string]::IsNullOrWhiteSpace($filter) -or $curDn -match [regex]::Escape($filter) -or $curChange -match [regex]::Escape($filter)) {
            $records.Add([PSCustomObject]@{
                DN         = $curDn
                ChangeType = $curChange
            })
        }
    }

    $controls['ListLdifRecords'].ItemsSource = @($records)
}

if ($controls['TxtLdifEditor']) {
    $controls['TxtLdifEditor'].Add_TextChanged({
        Update-LdifOutline
    })
}

if ($controls['TxtFilterLdifRecords']) {
    $controls['TxtFilterLdifRecords'].Add_TextChanged({
        Update-LdifOutline
    })
}

if ($controls['ListLdifRecords']) {
    $controls['ListLdifRecords'].Add_SelectionChanged({
        $sel = $controls['ListLdifRecords'].SelectedItem
        if ($sel -and $controls['TxtLdifEditor']) {
            $target = "dn: $($sel.DN)"
            $idx = $controls['TxtLdifEditor'].Text.IndexOf($target, [System.StringComparison]::OrdinalIgnoreCase)
            if ($idx -ge 0) {
                $controls['TxtLdifEditor'].Focus()
                $controls['TxtLdifEditor'].Select($idx, $target.Length)
                $lineIdx = $controls['TxtLdifEditor'].GetLineIndexFromCharacterIndex($idx)
                if ($lineIdx -ge 0) {
                    $controls['TxtLdifEditor'].ScrollToLine($lineIdx)
                }
            }
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
        "*Expiring Soon*"           { "PasswordExpiringSoon" }
        "*Not Required*"            { "PasswordNotRequired" }
        "*Locked Out*"              { "LockedOutUsers" }
        "*Privileged*"              { "PrivilegedAccounts" }
        "*Empty Groups*"            { "EmptyGroups" }
        "*Unprotected OUs*"         { "UnprotectedOUs" }
        "*Service Accounts*"        { "ServiceAccounts" }
        "*Inactive Computers*"      { "InactiveComputers" }
        "*Recently Created*"        { "RecentlyCreated" }
        "*Incomplete*"              { "IncompleteProfiles" }
        "*AdminCount*"              { "AdminCountAccounts" }
        "*Password Settings*"       { "PasswordSettingsObjects" }
        "*PSO*"                     { "PasswordSettingsObjects" }
        default                     { "InactiveUsers" }
    }

    Set-Status -Message "Running security audit: $catItem ($daysItem days threshold)..."
    $report = Get-ADSecurityAuditReport -AuditType $auditType -InactiveDays $daysItem
    $state.CurrentAuditReport = $report

    if ($controls['TxtAuditSummary']) { $controls['TxtAuditSummary'].Text = "$($report.Title) - $($report.Description)" }
    if ($controls['TxtAuditCount']) { $controls['TxtAuditCount'].Text = "$($report.Count) Findings" }
    if ($controls['GridAuditResults']) { $controls['GridAuditResults'].ItemsSource = @($report.Findings) }

    Set-Status -Message "Security audit finished. Found $($report.Count) item(s)." -Count "$($report.Count) findings"
}

if ($controls['BtnRunAudit']) { $controls['BtnRunAudit'].Add_Click({ Run-AuditReportsUI }) }

if ($controls['BtnCalcEffectivePolicy']) {
    $controls['BtnCalcEffectivePolicy'].Add_Click({
        $username = if ($controls['TxtEffectivePolicyUser']) { $controls['TxtEffectivePolicyUser'].Text.Trim() } else { "" }
        if ([string]::IsNullOrWhiteSpace($username)) {
            [System.Windows.MessageBox]::Show("Please enter a username (sAMAccountName or DN) to calculate their resultant password policy.", "Username Required", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            return
        }

        Set-Status -Message "Calculating effective password policy for user: $username..."
        $eff = Get-ADUserEffectivePasswordPolicy -UserIdentity $username
        if (-not $eff.UserFound) {
            [System.Windows.MessageBox]::Show("$($eff.Message)", "User Not Found", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            Set-Status -Message "Calculation failed: user not found."
            return
        }

        $msg = @"
RESULTANT PASSWORD POLICY REPORT
User: $($eff.SamAccountName)
DN: $($eff.DistinguishedName)
============================================================
Policy Source:        $($eff.PolicySource)
Policy / PSO Name:    $($eff.PolicyName)
Precedence:           $($eff.Precedence)

ENFORCED SECURITY SETTINGS:
------------------------------------------------------------
Minimum Password Length:       $($eff.MinPasswordLength) characters
Password Complexity:          $($eff.ComplexityEnabled)
Password History Length:      $($eff.HistoryLength) passwords remembered
Maximum Password Age:         $($eff.MaxPasswordAge)
Minimum Password Age:         $($eff.MinPasswordAge)
Account Lockout Threshold:    $($eff.LockoutThreshold) invalid attempts
Lockout Duration:             $($eff.LockoutDuration)
"@
        [System.Windows.MessageBox]::Show($msg, "Resultant Password Policy: $($eff.SamAccountName)", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        Set-Status -Message "Calculated effective policy for $($eff.SamAccountName): $($eff.PolicyName)"
    })
}

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

# Custom Saved Reports Logic (Softerra Ch08 / Screenshot 10 Parity)
function Refresh-CustomReportsDropdown {
    if (-not $controls['CmbCustomReports']) { return }
    $controls['CmbCustomReports'].Items.Clear()

    if (-not $appConfig.CustomReports -or $appConfig.CustomReports.Count -eq 0) {
        $appConfig.CustomReports = @(
            @{
                Name        = "Managers & Team Leads"
                Description = "Users having direct reports or manager titles"
                Filter      = "(&(objectCategory=person)(objectClass=user)(|(title=*Manager*)(title=*Supervisor*)(title=*Lead*)(directReports=*)))"
                Attributes  = @("sAMAccountName", "displayName", "title", "department", "mail", "distinguishedName")
            },
            @{
                Name        = "Accounts Without Manager"
                Description = "Active user accounts missing a defined manager attribute"
                Filter      = "(&(objectCategory=person)(objectClass=user)(!manager=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
                Attributes  = @("sAMAccountName", "displayName", "mail", "department", "distinguishedName")
            },
            @{
                Name        = "Accounts with SPN (Kerberoasting Targets)"
                Description = "User accounts with registered ServicePrincipalNames"
                Filter      = "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))"
                Attributes  = @("sAMAccountName", "displayName", "servicePrincipalName", "distinguishedName")
            }
        )
        Set-AppSettings -Settings $appConfig
    }

    foreach ($cr in $appConfig.CustomReports) {
        $item = New-Object System.Windows.Controls.ComboBoxItem
        $item.Content = $cr.Name
        $item.Tag = $cr
        [void]$controls['CmbCustomReports'].Items.Add($item)
    }

    if ($controls['CmbCustomReports'].Items.Count -gt 0) {
        $controls['CmbCustomReports'].SelectedIndex = 0
    }
}

function Run-SelectedCustomReport {
    $selItem = if ($controls['CmbCustomReports']) { $controls['CmbCustomReports'].SelectedItem } else { $null }
    if (-not $selItem -or -not $selItem.Tag) {
        [System.Windows.MessageBox]::Show("Please select a custom report to run.", "No Report Selected", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        return
    }

    $rep = $selItem.Tag
    Set-Status -Message "Executing custom report '$($rep.Name)'..."
    try {
        $filter = $rep.Filter
        $attrs = if ($rep.Attributes) { @($rep.Attributes) } else { @('sAMAccountName', 'displayName', 'mail', 'department', 'distinguishedName') }
        if (-not ($attrs -contains 'distinguishedName')) { $attrs += 'distinguishedName' }

        $ldapRes = Invoke-LdapQuery -Filter $filter -PropertiesToLoad $attrs -PageSize 500
        $findings = New-Object System.Collections.Generic.List[PSCustomObject]
        foreach ($r in $ldapRes.Results) {
            $findings.Add([PSCustomObject]@{
                SamAccountName    = "$($r.sAMAccountName)"
                DisplayName       = if ($r.displayName) { "$($r.displayName)" } else { "$($r.Name)" }
                Department        = "$($r.department)"
                Status            = "Active"
                DaysInactive      = "$($rep.Name)"
                DistinguishedName = "$($r.DistinguishedName)"
            })
        }

        $reportObj = [PSCustomObject]@{
            AuditType   = "Custom_$($rep.Name)"
            Title       = "$($rep.Name)"
            Description = "$($rep.Description) [Filter: $filter]"
            Count       = $findings.Count
            Findings    = @($findings)
        }
        $state.CurrentAuditReport = $reportObj

        if ($controls['TxtAuditSummary']) { $controls['TxtAuditSummary'].Text = "$($reportObj.Title) - $($reportObj.Description)" }
        if ($controls['TxtAuditCount']) { $controls['TxtAuditCount'].Text = "$($reportObj.Count) Findings" }
        if ($controls['GridAuditResults']) { $controls['GridAuditResults'].ItemsSource = $reportObj.Findings }

        Set-Status -Message "Custom report '$($rep.Name)' finished. Found $($findings.Count) item(s)." -Count "$($findings.Count) findings"
    } catch {
        Set-Status -Message "Custom report execution failed: $_"
        [System.Windows.MessageBox]::Show("Failed to execute custom report:`n$_", "Report Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
    }
}

function Show-NewCustomReportDialog {
    $xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        Title="New Custom Saved Report" Width="520" Height="380" WindowStartupLocation="CenterOwner"
        Background="#1A1D27" Foreground="#FFFFFF" ResizeMode="NoResize" WindowStyle="ToolWindow">
    <Grid Margin="18">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
        </Grid.RowDefinitions>
        <TextBlock Grid.Row="0" Text="Create Custom Directory Report" FontSize="15" FontWeight="Bold" Foreground="#38BDF8" Margin="0,0,0,4"/>
        <TextBlock Grid.Row="1" Text="Define an LDAP filter and attributes for a reusable saved report." FontSize="11" Foreground="#9CA3AF" Margin="0,0,0,12"/>

        <StackPanel Grid.Row="2" Margin="0,0,0,8">
            <TextBlock Text="REPORT NAME:" FontSize="10" FontWeight="Bold" Foreground="#9CA3AF" Margin="0,0,0,4"/>
            <TextBox Name="TxtRepName" Background="#111319" Foreground="#FFFFFF" BorderBrush="#292E3E" Height="28" Padding="6,2" FontSize="12"/>
        </StackPanel>

        <StackPanel Grid.Row="3" Margin="0,0,0,8">
            <TextBlock Text="DESCRIPTION:" FontSize="10" FontWeight="Bold" Foreground="#9CA3AF" Margin="0,0,0,4"/>
            <TextBox Name="TxtRepDesc" Background="#111319" Foreground="#FFFFFF" BorderBrush="#292E3E" Height="28" Padding="6,2" FontSize="12"/>
        </StackPanel>

        <StackPanel Grid.Row="4" Margin="0,0,0,8">
            <TextBlock Text="LDAP FILTER:" FontSize="10" FontWeight="Bold" Foreground="#9CA3AF" Margin="0,0,0,4"/>
            <TextBox Name="TxtRepFilter" Background="#111319" Foreground="#38BDF8" BorderBrush="#292E3E" Height="48" AcceptsReturn="True" TextWrapping="Wrap" FontFamily="Consolas" Padding="6,4" FontSize="12" Text="(&(objectCategory=person)(objectClass=user))"/>
        </StackPanel>

        <StackPanel Grid.Row="5" Orientation="Horizontal" HorizontalAlignment="Right" VerticalAlignment="Bottom" Margin="0,12,0,0">
            <Button Name="BtnCancel" Content="Cancel" Width="85" Height="28" Background="#252936" Foreground="#FFFFFF" BorderBrush="#3B4254" Margin="0,0,8,0"/>
            <Button Name="BtnSave" Content="Save Report" Width="95" Height="28" Background="#0078D4" Foreground="#FFFFFF" BorderThickness="0" FontWeight="SemiBold"/>
        </StackPanel>
    </Grid>
</Window>
"@
    $win = [System.Windows.Markup.XamlReader]::Parse($xaml)
    $win.Owner = $mainWindow
    $txtN = $win.FindName("TxtRepName")
    $txtD = $win.FindName("TxtRepDesc")
    $txtF = $win.FindName("TxtRepFilter")
    $btnS = $win.FindName("BtnSave")
    $btnC = $win.FindName("BtnCancel")

    $btnS.Add_Click({
        $name = $txtN.Text.Trim()
        $filter = $txtF.Text.Trim()
        if ([string]::IsNullOrWhiteSpace($name) -or [string]::IsNullOrWhiteSpace($filter)) {
            [System.Windows.MessageBox]::Show("Please provide both a Report Name and LDAP Filter.", "Validation Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            return
        }
        $newRep = @{
            Name        = $name
            Description = $txtD.Text.Trim()
            Filter      = $filter
            Attributes  = @('sAMAccountName', 'displayName', 'mail', 'department', 'distinguishedName')
        }
        $list = if ($appConfig.CustomReports) { [System.Collections.ArrayList]@($appConfig.CustomReports) } else { [System.Collections.ArrayList]@() }
        [void]$list.Add($newRep)
        $appConfig.CustomReports = @($list)
        Set-AppSettings -Settings $appConfig
        Refresh-CustomReportsDropdown
        $win.DialogResult = $true
        $win.Close()
        Set-Status -Message "Saved custom report: $name"
    })
    $btnC.Add_Click({
        $win.DialogResult = $false
        $win.Close()
    })
    [void]$win.ShowDialog()
}

if ($controls['BtnRunCustomReport'])    { $controls['BtnRunCustomReport'].Add_Click({ Run-SelectedCustomReport }) }
if ($controls['BtnNewCustomReport'])    { $controls['BtnNewCustomReport'].Add_Click({ Show-NewCustomReportDialog }) }
if ($controls['BtnDeleteCustomReport']) {
    $controls['BtnDeleteCustomReport'].Add_Click({
        $selItem = if ($controls['CmbCustomReports']) { $controls['CmbCustomReports'].SelectedItem } else { $null }
        if (-not $selItem -or -not $selItem.Tag) { return }
        $rep = $selItem.Tag
        $confirm = [System.Windows.MessageBox]::Show("Are you sure you want to delete custom report '$($rep.Name)'?", "Confirm Delete", [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Question)
        if ($confirm -eq [System.Windows.MessageBoxResult]::Yes) {
            $appConfig.CustomReports = @($appConfig.CustomReports | Where-Object { $_.Name -ne $rep.Name })
            Set-AppSettings -Settings $appConfig
            Refresh-CustomReportsDropdown
            Set-Status -Message "Deleted custom report '$($rep.Name)'"
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
        $controls['GridSchema'].ItemsSource = @($items)
    }
    Set-Status -Message "Schema loaded: $($items.Count) definition(s) displayed." -Count "$($items.Count) schema items"
}

function Export-SchemaOpenLdapAction {
    $items = $state.CachedSchema
    if (-not $items -or $items.Count -eq 0) {
        [System.Windows.MessageBox]::Show("Please load schema definitions first.", "No Schema Loaded", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        return
    }
    $isClasses = if ($controls['RadioSchemaClasses']) { [bool]$controls['RadioSchemaClasses'].IsChecked } else { $true }
    $sfd = [Microsoft.Win32.SaveFileDialog]::new()
    $sfd.Filter = "OpenLDAP Schema (*.schema)|*.schema|All Files (*.*)|*.*"
    $sfd.FileName = if ($isClasses) { "ad_classes.schema" } else { "ad_attributes.schema" }
    if ($sfd.ShowDialog()) {
        $sb = [System.Text.StringBuilder]::new()
        [void]$sb.AppendLine("# OpenLDAP Schema Definitions Exported from Active Directory Studio")
        [void]$sb.AppendLine("# Export Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
        [void]$sb.AppendLine("")
        if ($isClasses) {
            foreach ($c in $items) {
                $oid = if ($c.OID) { $c.OID } else { "1.3.6.1.4.1.7165.2.1" }
                $sup = if ($c.SubClassOf) { " SUP $($c.SubClassOf)" } else { " SUP top" }
                $mustStr = if ($c.MandatoryAttrs) { " MUST ( $($c.MandatoryAttrs -replace ',', ' $') )" } else { "" }
                $mayStr = if ($c.OptionalAttrs) { " MAY ( $($c.OptionalAttrs -replace ',', ' $') )" } else { "" }
                [void]$sb.AppendLine("objectclass ( $oid")
                [void]$sb.AppendLine("    NAME '$($c.Name)'")
                [void]$sb.AppendLine("    DESC 'Active Directory Schema Class $($c.Name)'$sup STRUCTURAL$mustStr$mayStr )")
                [void]$sb.AppendLine("")
            }
        } else {
            foreach ($a in $items) {
                $oid = if ($a.OID) { $a.OID } else { "1.3.6.1.4.1.7165.2.2" }
                $single = if ($a.IsSingleValued) { " SINGLE-VALUE" } else { "" }
                [void]$sb.AppendLine("attributetype ( $oid")
                [void]$sb.AppendLine("    NAME '$($a.Name)'")
                [void]$sb.AppendLine("    DESC 'Active Directory Schema Attribute $($a.Name)'")
                [void]$sb.AppendLine("    SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{1024}$single )")
                [void]$sb.AppendLine("")
            }
        }
        [System.IO.File]::WriteAllText($sfd.FileName, $sb.ToString(), [System.Text.Encoding]::UTF8)
        [System.Windows.MessageBox]::Show("Exported $($items.Count) schema definition(s) to OpenLDAP schema format:`n$($sfd.FileName)", "Schema Export Successful", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
    }
}

function Export-SchemaLdifAction {
    $items = $state.CachedSchema
    if (-not $items -or $items.Count -eq 0) {
        [System.Windows.MessageBox]::Show("Please load schema definitions first.", "No Schema Loaded", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        return
    }
    $isClasses = if ($controls['RadioSchemaClasses']) { [bool]$controls['RadioSchemaClasses'].IsChecked } else { $true }
    $sfd = [Microsoft.Win32.SaveFileDialog]::new()
    $sfd.Filter = "LDIF Schema (*.ldif)|*.ldif|All Files (*.*)|*.*"
    $sfd.FileName = if ($isClasses) { "ad_classes_schema.ldif" } else { "ad_attributes_schema.ldif" }
    if ($sfd.ShowDialog()) {
        $sb = [System.Text.StringBuilder]::new()
        [void]$sb.AppendLine("version: 1")
        [void]$sb.AppendLine("dn: cn=schema,cn=config")
        [void]$sb.AppendLine("objectClass: olcSchemaConfig")
        [void]$sb.AppendLine("cn: schema")
        if ($isClasses) {
            foreach ($c in $items) {
                $oid = if ($c.OID) { $c.OID } else { "1.3.6.1.4.1.7165.2.1" }
                $sup = if ($c.SubClassOf) { " SUP $($c.SubClassOf)" } else { " SUP top" }
                $mustStr = if ($c.MandatoryAttrs) { " MUST ( $($c.MandatoryAttrs -replace ',', ' $') )" } else { "" }
                $mayStr = if ($c.OptionalAttrs) { " MAY ( $($c.OptionalAttrs -replace ',', ' $') )" } else { "" }
                [void]$sb.AppendLine("olcObjectClasses: ( $oid NAME '$($c.Name)'$sup STRUCTURAL$mustStr$mayStr )")
            }
        } else {
            foreach ($a in $items) {
                $oid = if ($a.OID) { $a.OID } else { "1.3.6.1.4.1.7165.2.2" }
                $single = if ($a.IsSingleValued) { " SINGLE-VALUE" } else { "" }
                [void]$sb.AppendLine("olcAttributeTypes: ( $oid NAME '$($a.Name)' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15$single )")
            }
        }
        [System.IO.File]::WriteAllText($sfd.FileName, $sb.ToString(), [System.Text.Encoding]::UTF8)
        [System.Windows.MessageBox]::Show("Exported $($items.Count) schema definition(s) to LDIF format:`n$($sfd.FileName)", "Schema Export Successful", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
    }
}

if ($controls['BtnRefreshSchema']) { $controls['BtnRefreshSchema'].Add_Click({ Refresh-Schema }) }
if ($controls['RadioSchemaClasses'])    { $controls['RadioSchemaClasses'].Add_Checked({ Refresh-Schema }) }
if ($controls['RadioSchemaAttributes']) { $controls['RadioSchemaAttributes'].Add_Checked({ Refresh-Schema }) }
if ($controls['BtnExportSchemaOpenLdap']) { $controls['BtnExportSchemaOpenLdap'].Add_Click({ Export-SchemaOpenLdapAction }) }
if ($controls['BtnExportSchemaLdif'])     { $controls['BtnExportSchemaLdif'].Add_Click({ Export-SchemaLdifAction }) }
if ($controls['TxtSearchSchema']) {
    $controls['TxtSearchSchema'].Add_KeyDown({
        if ($_.Key -eq [System.Windows.Input.Key]::Enter) { Refresh-Schema }
    })
}

# Schema Class Inspector Selection Changed Handler (Softerra Ch10 / Screenshot 12 Parity)
if ($controls['GridSchema']) {
    $controls['GridSchema'].Add_SelectionChanged({
        $sel = $controls['GridSchema'].SelectedItem
        if ($sel) {
            $isClasses = if ($controls['RadioSchemaClasses']) { [bool]$controls['RadioSchemaClasses'].IsChecked } else { $true }
            if ($isClasses) {
                $detail = Get-ADSchemaClassDetail -ClassName $sel.Name
                if ($controls['TxtSchemaDetailName']) { $controls['TxtSchemaDetailName'].Text = if ($detail.Name) { $detail.Name } else { "$($sel.Name)" } }
                if ($controls['TxtSchemaDetailOID']) { $controls['TxtSchemaDetailOID'].Text = if ($detail.OID) { $detail.OID } else { "$($sel.OID)" } }
                if ($controls['TxtSchemaDetailCategory']) { $controls['TxtSchemaDetailCategory'].Text = if ($detail.ClassType) { $detail.ClassType } else { "Structural Class" } }
                if ($controls['TxtSchemaDetailInheritance']) {
                    $chain = if ($detail.InheritanceChain) { $detail.InheritanceChain } elseif ($sel.SubClassOf) { "$($sel.SubClassOf) ➔ $($sel.Name)" } else { "top" }
                    $controls['TxtSchemaDetailInheritance'].Text = $chain
                }
                if ($controls['ListSchemaMust']) { $controls['ListSchemaMust'].ItemsSource = @($detail.MustContain) }
                if ($controls['ListSchemaMay']) { $controls['ListSchemaMay'].ItemsSource = @($detail.MayContain) }
            } else {
                if ($controls['TxtSchemaDetailName']) { $controls['TxtSchemaDetailName'].Text = "$($sel.Name)" }
                if ($controls['TxtSchemaDetailOID']) { $controls['TxtSchemaDetailOID'].Text = "$($sel.OID)" }
                if ($controls['TxtSchemaDetailCategory']) { $controls['TxtSchemaDetailCategory'].Text = "Attribute Type" }
                if ($controls['TxtSchemaDetailInheritance']) { $controls['TxtSchemaDetailInheritance'].Text = "Syntax: $($sel.Syntax)" }
                if ($controls['ListSchemaMust']) {
                    $controls['ListSchemaMust'].ItemsSource = @("Single-Valued: $($sel.IsSingleValued)", "Global Catalog: $($sel.InGlobalCatalog)")
                }
                if ($controls['ListSchemaMay']) {
                    $controls['ListSchemaMay'].ItemsSource = @("Distinguished Name: $($sel.DistinguishedName)")
                }
            }
        }
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

#region 14. Directory Basket Engine Logic (Softerra Parity)
function Refresh-BasketUI {
    if ($controls['GridBasket']) {
        $controls['GridBasket'].ItemsSource = $null
        $controls['GridBasket'].ItemsSource = $state.BasketItems
    }
    $cnt = if ($state.BasketItems) { $state.BasketItems.Count } else { 0 }
    if ($controls['TxtBasketCountBadge']) {
        $controls['TxtBasketCountBadge'].Text = "$cnt objects in basket"
    }
    if ($controls['TxtNavBasketLabel']) {
        $controls['TxtNavBasketLabel'].Text = "Directory Basket ($cnt)"
    }
}

function Add-ToBasket {
    param (
        $Items,
        [string]$DefaultClass = "Object"
    )
    if (-not $Items) { return }
    $itemsList = @($Items)
    if ($itemsList.Count -eq 0) { return }

    if (-not $state.BasketItems) {
        $state.BasketItems = [System.Collections.ObjectModel.ObservableCollection[psobject]]::new()
    }

    $added = 0
    foreach ($item in $itemsList) {
        if (-not $item -or -not $item.DistinguishedName) { continue }
        $dn = $item.DistinguishedName

        $exists = $false
        foreach ($b in $state.BasketItems) {
            if ($b.DistinguishedName -eq $dn) {
                $exists = $true
                break
            }
        }
        if (-not $exists) {
            $className = if ($item.ObjectClass) { $item.ObjectClass } elseif ($item.Class) { $item.Class } else { $DefaultClass }
            $nameVal = if ($item.DisplayName) { $item.DisplayName } elseif ($item.Name) { $item.Name } else { $item.SamAccountName }
            $statusVal = if ($item.StatusBadge) { $item.StatusBadge } elseif ($item.Status) { $item.Status } else { "Active" }

            $basketObj = [PSCustomObject]@{
                Class             = $className
                Name              = $nameVal
                SamAccountName    = if ($item.SamAccountName) { $item.SamAccountName } else { "--" }
                Status            = $statusVal
                OUPath            = if ($item.OUPath) { $item.OUPath } else { "--" }
                DistinguishedName = $dn
            }
            $state.BasketItems.Add($basketObj)
            $added++
        }
    }

    Refresh-BasketUI
    Set-Status -Message "Added $added item(s) to Directory Basket (Total: $($state.BasketItems.Count))." -Count "$($state.BasketItems.Count) staged"
    Log-LdapRequest -Operation "BASKET" -TargetDN "Staging Cart" -FilterOrPayload "Added $added items" -DurationMs 1 -Status "SUCCESS" -Details "Staged $added new objects into Directory Basket. Current basket count: $($state.BasketItems.Count)."
}

if ($controls['BtnBasketClear']) {
    $controls['BtnBasketClear'].Add_Click({
        if ($state.BasketItems.Count -eq 0) { return }
        $res = [System.Windows.MessageBox]::Show("Clear all $($state.BasketItems.Count) staged object(s) from the Directory Basket?", "Clear Basket", [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Question)
        if ($res -eq [System.Windows.MessageBoxResult]::Yes) {
            $state.BasketItems.Clear()
            Refresh-BasketUI
            Set-Status -Message "Directory Basket cleared."
            Log-LdapRequest -Operation "BASKET" -TargetDN "Staging Cart" -FilterOrPayload "Cleared" -DurationMs 1 -Status "SUCCESS" -Details "Cleared all items from Directory Basket."
        }
    })
}

if ($controls['BtnBasketRemoveSelected']) {
    $controls['BtnBasketRemoveSelected'].Add_Click({
        $selected = @($controls['GridBasket'].SelectedItems)
        if ($selected.Count -eq 0) {
            [System.Windows.MessageBox]::Show("Please select one or more items to remove from the basket.", "Selection Required", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            return
        }
        foreach ($item in $selected) {
            $state.BasketItems.Remove($item)
        }
        Refresh-BasketUI
        Set-Status -Message "Removed $($selected.Count) item(s) from basket."
    })
}

if ($controls['BtnBasketModifyAttr']) {
    $controls['BtnBasketModifyAttr'].Add_Click({
        if ($state.BasketItems.Count -eq 0) {
            [System.Windows.MessageBox]::Show("Directory Basket is empty.", "Basket Empty", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            return
        }
        $attrName = [Microsoft.VisualBasic.Interaction]::InputBox("Enter the attribute name to update across all $($state.BasketItems.Count) basket objects:`n(e.g., department, company, description, title, mail, physicalDeliveryOfficeName)", "Bulk Edit Basket Objects", "department")
        if ([string]::IsNullOrWhiteSpace($attrName)) { return }
        $newVal = [Microsoft.VisualBasic.Interaction]::InputBox("Enter the new value for attribute '$attrName':`nSupports dynamic references: %givenName%, %sn%, %sAMAccountName%, %department%, %company%, %mail%, %title%, etc.`n(Leave blank to clear the attribute)", "Bulk Attribute Value", "")
        
        $confirm = [System.Windows.MessageBox]::Show("Update attribute '$attrName' to '$newVal' for all $($state.BasketItems.Count) staged objects?", "Confirm Bulk Update", [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Warning)
        if ($confirm -ne [System.Windows.MessageBoxResult]::Yes) { return }

        $hasTokens = ($newVal -match '%[a-zA-Z0-9_-]+%')
        $tokenMatches = if ($hasTokens) { [regex]::Matches($newVal, '%([a-zA-Z0-9_-]+)%') } else { @() }

        $succ = 0; $fail = 0
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        foreach ($obj in $state.BasketItems) {
            $effectiveVal = $newVal
            if ($hasTokens) {
                $attrDict = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                foreach ($p in $obj.PSObject.Properties) {
                    if ($p.Value) { $attrDict[$p.Name] = "$($p.Value)" }
                }
                if ($obj.DistinguishedName) {
                    try {
                        $raws = Get-ADObjectRawAttributes -DistinguishedName $obj.DistinguishedName
                        foreach ($ra in $raws) {
                            if (-not $attrDict.ContainsKey($ra.Name) -and $ra.Value) {
                                $attrDict[$ra.Name] = "$($ra.Value)"
                            }
                        }
                    } catch {}
                }

                foreach ($tm in $tokenMatches) {
                    $tokenKey = $tm.Groups[1].Value
                    $tokenReplacement = if ($attrDict.ContainsKey($tokenKey)) { $attrDict[$tokenKey] } else { "" }
                    $effectiveVal = $effectiveVal -replace [regex]::Escape($tm.Value), $tokenReplacement
                }
            }

            try {
                Set-ADObjectRawAttribute -DistinguishedName $obj.DistinguishedName -AttributeName $attrName -Value $effectiveVal
                $succ++
                Log-LdapRequest -Operation "MODIFY" -TargetDN $obj.DistinguishedName -FilterOrPayload "$attrName = $effectiveVal" -DurationMs 10 -Status "SUCCESS"
            } catch {
                $fail++
                Log-LdapRequest -Operation "MODIFY" -TargetDN $obj.DistinguishedName -FilterOrPayload "$attrName = $effectiveVal" -DurationMs 10 -Status "ERROR" -Details $_.Exception.Message
            }
        }
        $sw.Stop()
        [System.Windows.MessageBox]::Show("Bulk modification finished in $($sw.ElapsedMilliseconds) ms:`nSucceeded: $succ`nFailed: $fail", "Bulk Update Result", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
    })
}

if ($controls['BtnBasketToggleStatus']) {
    $controls['BtnBasketToggleStatus'].Add_Click({
        if ($state.BasketItems.Count -eq 0) {
            [System.Windows.MessageBox]::Show("Directory Basket is empty.", "Basket Empty", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            return
        }
        $users = @($state.BasketItems | Where-Object { $_.Class -eq "User" -or $_.Class -like "*user*" })
        if ($users.Count -eq 0) {
            [System.Windows.MessageBox]::Show("No user accounts found in the Directory Basket.", "No Users", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            return
        }
        $choice = [System.Windows.MessageBox]::Show("Toggle status of $($users.Count) user account(s):`n`nClick YES to ENABLE all accounts.`nClick NO to DISABLE all accounts.`nClick CANCEL to abort.", "Bulk Status Toggle", [System.Windows.MessageBoxButton]::YesNoCancel, [System.Windows.MessageBoxImage]::Question)
        if ($choice -eq [System.Windows.MessageBoxResult]::Cancel) { return }
        $enable = ($choice -eq [System.Windows.MessageBoxResult]::Yes)

        $updated = 0
        foreach ($u in $users) {
            try {
                if ($enable) {
                    Enable-ADUserAccount -DistinguishedName $u.DistinguishedName
                    $u.Status = "Active"
                } else {
                    Disable-ADUserAccount -DistinguishedName $u.DistinguishedName
                    $u.Status = "Disabled"
                }
                $updated++
                Log-LdapRequest -Operation "MODIFY" -TargetDN $u.DistinguishedName -FilterOrPayload "Enabled = $enable" -DurationMs 15 -Status "SUCCESS"
            } catch {
                Log-LdapRequest -Operation "MODIFY" -TargetDN $u.DistinguishedName -FilterOrPayload "Enabled = $enable" -DurationMs 15 -Status "ERROR" -Details $_.Exception.Message
            }
        }
        Refresh-BasketUI
        [System.Windows.MessageBox]::Show("Status updated for $updated account(s).", "Toggle Status Complete", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
    })
}

if ($controls['BtnBasketMoveOU']) {
    $controls['BtnBasketMoveOU'].Add_Click({
        if ($state.BasketItems.Count -eq 0) {
            [System.Windows.MessageBox]::Show("Directory Basket is empty.", "Basket Empty", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            return
        }
        $targetOU = [Microsoft.VisualBasic.Interaction]::InputBox("Enter the target Organizational Unit (DN) to move all $($state.BasketItems.Count) staged objects into:", "Bulk Move Objects to OU", $state.DefaultNamingContext)
        if ([string]::IsNullOrWhiteSpace($targetOU)) { return }

        $confirm = [System.Windows.MessageBox]::Show("Move all $($state.BasketItems.Count) objects to target OU:`n$targetOU`n`nProceed?", "Confirm Bulk Move", [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Warning)
        if ($confirm -ne [System.Windows.MessageBoxResult]::Yes) { return }

        $moved = 0; $failed = 0
        foreach ($item in $state.BasketItems) {
            try {
                Move-ADPrincipal -Identity $item.DistinguishedName -TargetPath $targetOU
                $moved++
                $item.OUPath = $targetOU
                Log-LdapRequest -Operation "MOVE" -TargetDN $item.DistinguishedName -FilterOrPayload "Target: $targetOU" -DurationMs 20 -Status "SUCCESS"
            } catch {
                $failed++
                Log-LdapRequest -Operation "MOVE" -TargetDN $item.DistinguishedName -FilterOrPayload "Target: $targetOU" -DurationMs 20 -Status "ERROR" -Details $_.Exception.Message
            }
        }
        Refresh-BasketUI
        [System.Windows.MessageBox]::Show("Bulk move completed:`nMoved: $moved`nFailed: $failed", "Bulk Move Result", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
    })
}

if ($controls['BtnBasketExportCsv']) {
    $controls['BtnBasketExportCsv'].Add_Click({
        if ($state.BasketItems.Count -eq 0) {
            [System.Windows.MessageBox]::Show("Directory Basket is empty.", "Basket Empty", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            return
        }
        $sfd = [Microsoft.Win32.SaveFileDialog]::new()
        $sfd.Filter = "CSV Files (*.csv)|*.csv|All Files (*.*)|*.*"
        $sfd.FileName = "Directory_Basket_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        if ($sfd.ShowDialog()) {
            $state.BasketItems | Export-Csv -Path $sfd.FileName -NoTypeInformation -Encoding utf8 -Delimiter ";"
            [System.Windows.MessageBox]::Show("Exported $($state.BasketItems.Count) objects to CSV:`n$($sfd.FileName)", "Export Complete", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        }
    })
}

if ($controls['BtnBasketExportLdif']) {
    $controls['BtnBasketExportLdif'].Add_Click({
        if ($state.BasketItems.Count -eq 0) {
            [System.Windows.MessageBox]::Show("Directory Basket is empty.", "Basket Empty", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            return
        }
        $sfd = [Microsoft.Win32.SaveFileDialog]::new()
        $sfd.Filter = "LDIF Files (*.ldif)|*.ldif|All Files (*.*)|*.*"
        $sfd.FileName = "Directory_Basket_$(Get-Date -Format 'yyyyMMdd_HHmmss').ldif"
        if ($sfd.ShowDialog()) {
            $sb = [System.Text.StringBuilder]::new()
            [void]$sb.AppendLine("version: 1`n")
            foreach ($item in $state.BasketItems) {
                [void]$sb.AppendLine("dn: $($item.DistinguishedName)")
                [void]$sb.AppendLine("changetype: add")
                [void]$sb.AppendLine("objectClass: $($item.Class)")
                if ($item.SamAccountName -and $item.SamAccountName -ne "--") {
                    [void]$sb.AppendLine("sAMAccountName: $($item.SamAccountName)")
                }
                if ($item.Name) {
                    [void]$sb.AppendLine("cn: $($item.Name)")
                }
                [void]$sb.AppendLine("")
            }
            [System.IO.File]::WriteAllText($sfd.FileName, $sb.ToString(), [System.Text.Encoding]::UTF8)
            [System.Windows.MessageBox]::Show("Exported $($state.BasketItems.Count) objects to LDIF:`n$($sfd.FileName)", "Export Complete", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        }
    })
}

if ($controls['BtnBasketExportScim']) {
    $controls['BtnBasketExportScim'].Add_Click({
        if ($state.BasketItems.Count -eq 0) {
            [System.Windows.MessageBox]::Show("Directory Basket is empty.", "Basket Empty", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            return
        }
        $sfd = [Microsoft.Win32.SaveFileDialog]::new()
        $sfd.Filter = "SCIM 2.0 JSON (*.json)|*.json|All Files (*.*)|*.*"
        $sfd.FileName = "Directory_Basket_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        if ($sfd.ShowDialog()) {
            $res = Export-ADDataToScim -Data $state.BasketItems -FilePath $sfd.FileName
            if ($res.Success) {
                [System.Windows.MessageBox]::Show($res.Message, "SCIM 2.0 Export Complete", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            } else {
                [System.Windows.MessageBox]::Show($res.Message, "SCIM Export Failed", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
            }
        }
    })
}
#endregion

#region 15. Live Protocol Wire Request Log Logic (Softerra & Apache Studio Parity)
if ($controls['GridRequestLog']) {
    $controls['GridRequestLog'].ItemsSource = $state.RequestLogs
    $controls['GridRequestLog'].Add_SelectionChanged({
        $selected = $controls['GridRequestLog'].SelectedItem
        if ($selected -and $controls['TxtRequestLogDetails']) {
            $controls['TxtRequestLogDetails'].Text = $selected.Details
        }
    })
}

if ($controls['BtnRequestLogClear']) {
    $controls['BtnRequestLogClear'].Add_Click({
        $state.RequestLogs.Clear()
        if ($controls['TxtRequestLogDetails']) { $controls['TxtRequestLogDetails'].Text = "" }
        if ($controls['TxtRequestLogCountBadge']) { $controls['TxtRequestLogCountBadge'].Text = "0 requests" }
    })
}

if ($controls['BtnRequestLogExport']) {
    $controls['BtnRequestLogExport'].Add_Click({
        if ($state.RequestLogs.Count -eq 0) {
            [System.Windows.MessageBox]::Show("Request log is empty.", "Export", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            return
        }
        $sfd = [Microsoft.Win32.SaveFileDialog]::new()
        $sfd.Filter = "Text Log (*.txt)|*.txt|All Files (*.*)|*.*"
        $sfd.FileName = "Ldap_Wire_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
        if ($sfd.ShowDialog()) {
            $lines = foreach ($l in $state.RequestLogs) {
                "[$($l.Timestamp)] $($l.Operation.PadRight(12)) [$($l.Status.PadRight(7))] $($l.Duration.PadLeft(10)) | Target: $($l.TargetDN) | Details: $($l.Filter)"
            }
            $lines | Set-Content -Path $sfd.FileName -Encoding utf8
            [System.Windows.MessageBox]::Show("Exported $($state.RequestLogs.Count) wire requests to:`n$($sfd.FileName)", "Export Complete", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        }
    })
}

if ($controls['TxtFilterRequestLog']) {
    $controls['TxtFilterRequestLog'].Add_TextChanged({
        $query = $controls['TxtFilterRequestLog'].Text.Trim()
        if ([string]::IsNullOrWhiteSpace($query)) {
            $controls['GridRequestLog'].ItemsSource = $state.RequestLogs
        } else {
            $filtered = $state.RequestLogs | Where-Object {
                $_.Operation -like "*$query*" -or $_.TargetDN -like "*$query*" -or $_.Status -like "*$query*" -or $_.Filter -like "*$query*"
            }
            $controls['GridRequestLog'].ItemsSource = [System.Collections.ObjectModel.ObservableCollection[psobject]]::new($filtered)
        }
    })
}
#endregion

#region 16. Connection Profiles & Diagnostics Logic
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
        $isReadOnly = if ($dControls['ChkReadOnlyProfile']) { [bool]$dControls['ChkReadOnlyProfile'].IsChecked } else { $false }

        $newProf = @{
            Name       = $pName
            Server     = $hostName
            Port       = $portNum
            UseSSL     = $useSsl
            SearchBase = $searchBase
            ReadOnly   = $isReadOnly
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
    if ($controls['TxtDnsDiscoveryDomain'] -and [string]::IsNullOrWhiteSpace($controls['TxtDnsDiscoveryDomain'].Text)) {
        $controls['TxtDnsDiscoveryDomain'].Text = if ($adContext.DomainName) { $adContext.DomainName } else { "" }
    }

    if ($controls['ListProfiles']) {
        $controls['ListProfiles'].Items.Clear()
        $profiles = @($appConfig.Profiles)
        if ($profiles.Count -eq 0) {
            $defaultServer = if ($adContext.PDCEmulator) { $adContext.PDCEmulator } else { $adContext.DomainName }
            $controls['ListProfiles'].Items.Add("Default: Production Domain [$($defaultServer):389]")
        } else {
            foreach ($p in $profiles) {
                $roTag = if ($p.ReadOnly) { " 🔒 [READ-ONLY]" } else { "" }
                [void]$controls['ListProfiles'].Items.Add("$($p.Name) [$($p.Server):$($p.Port)]$roTag")
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
                $roLabel = if ($p.ReadOnly) { " 🔒" } else { "" }
                [void]$controls['CmbActiveProfile'].Items.Add("$($p.Name)$roLabel")
            }
        }
        $controls['CmbActiveProfile'].SelectedIndex = 0
        $controls['CmbActiveProfile'].ToolTip = "Active Directory Profile / Server: $defaultLabel"

        if (-not $controls['CmbActiveProfile'].Tag) {
            $controls['CmbActiveProfile'].Tag = "Initialized"
            $controls['CmbActiveProfile'].Add_SelectionChanged({
                if ($controls['CmbActiveProfile'].SelectedItem) {
                    $sel = [string]$controls['CmbActiveProfile'].SelectedItem
                    $cleanName = ($sel -replace '\s*🔒.*$', '').Trim()
                    $matched = $null
                    if ($appConfig.Profiles) {
                        $matched = $appConfig.Profiles | Where-Object { $_.Name -eq $cleanName } | Select-Object -First 1
                    }
                    $state.IsReadOnlyProfile = [bool]($matched -and $matched.ReadOnly)
                    if ($controls['BorderReadOnlyBadge']) {
                        $controls['BorderReadOnlyBadge'].Visibility = if ($state.IsReadOnlyProfile) { [System.Windows.Visibility]::Visible } else { [System.Windows.Visibility]::Collapsed }
                    }
                    $controls['CmbActiveProfile'].ToolTip = "Active Directory Profile: $sel"
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

# DNS SRV Domain Infrastructure Auto-Discovery (Softerra Ch06s05 Parity)
if ($controls['BtnRunDnsDiscovery']) {
    $controls['BtnRunDnsDiscovery'].Add_Click({
        $domain = if ($controls['TxtDnsDiscoveryDomain'] -and -not [string]::IsNullOrWhiteSpace($controls['TxtDnsDiscoveryDomain'].Text)) {
            $controls['TxtDnsDiscoveryDomain'].Text.Trim()
        } elseif ($adContext.DomainName) {
            $adContext.DomainName
        } else {
            ""
        }

        if ([string]::IsNullOrWhiteSpace($domain)) {
            [System.Windows.MessageBox]::Show("Please enter a domain name to discover infrastructure SRV records for.", "Domain Required", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            return
        }

        if ($controls['TxtDnsDiscoveryStatus']) {
            $controls['TxtDnsDiscoveryStatus'].Text = "Discovering Domain Controllers via DNS SRV for $domain..."
        }
        Set-Status -Message "Querying DNS SRV records for $domain..."

        try {
            $dcs = Find-ADDomainControllersViaDns -Domain $domain
            $dcsArr = @($dcs | ForEach-Object { $_ })
            $state.DiscoveredDCs = $dcsArr
            if ($controls['GridDnsDiscoveredDCs']) {
                $controls['GridDnsDiscoveredDCs'].ItemsSource = $dcsArr
            }
            if ($controls['TxtDnsDiscoveryStatus']) {
                $controls['TxtDnsDiscoveryStatus'].Text = "Discovered $($dcsArr.Count) DC(s) / service endpoints for $domain."
            }
            Set-Status -Message "DNS discovery completed." -Count "$($dcsArr.Count) DCs"
        } catch {
            if ($controls['TxtDnsDiscoveryStatus']) {
                $controls['TxtDnsDiscoveryStatus'].Text = "DNS query failed: $($_.Exception.Message)"
            }
        }
    })
}

if ($controls['BtnConnectDiscoveredDC']) {
    $controls['BtnConnectDiscoveredDC'].Add_Click({
        $sel = if ($controls['GridDnsDiscoveredDCs']) { $controls['GridDnsDiscoveredDCs'].SelectedItem } else { $null }
        if (-not $sel) {
            [System.Windows.MessageBox]::Show("Please select a discovered Domain Controller from the list to connect.", "Selection Required", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            return
        }

        $targetHost = if ($sel.Host) { $sel.Host } else { $sel.IPAddress }
        $targetPort = if ($sel.Port) { $sel.Port } else { 389 }

        # Add as a profile or switch active server
        $hostPrefix = if ($targetHost -match '^([^.]+)') { $matches[1].ToUpper() } else { $targetHost.ToUpper() }
        $profName = "DC: $hostPrefix"
        $newProf = @{
            Name       = $profName
            Server     = $targetHost
            Port       = $targetPort
            UseSSL     = ($targetPort -eq 636)
            SearchBase = $adContext.DefaultNamingContext
            ReadOnly   = $false
        }

        if (-not $appConfig.Profiles) {
            $appConfig | Add-Member -MemberType NoteProperty -Name "Profiles" -Value @() -Force
        }
        $profiles = @($appConfig.Profiles | Where-Object { $_.Server -ne $targetHost }) + @($newProf)
        $appConfig.Profiles = $profiles
        Save-AppSettings -Config $appConfig
        Refresh-Connections

        [System.Windows.MessageBox]::Show("Configured connection profile '$profName' ($($targetHost):$targetPort).", "DC Connected", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        Run-ConnectionDiagnostics
    })
}
#region 17. Active Directory Recycle Bin & Tombstone Reanimation Logic
function Refresh-RecycleBin {
    Set-Status -Message "Querying Active Directory Recycle Bin & Tombstones..."
    $search = if ($controls['TxtSearchRecycleBin']) { $controls['TxtSearchRecycleBin'].Text.Trim() } else { "" }
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $items = Get-ADDeletedObjects -SearchFilter $search -Limit 500
    $sw.Stop()

    $state.CachedRecycleBin = $items
    if ($controls['GridRecycleBin']) {
        $controls['GridRecycleBin'].ItemsSource = @($items)
    }

    $msg = "Recycle Bin: $($items.Count) deleted/tombstone object(s) loaded ($($sw.ElapsedMilliseconds) ms)."
    Set-Status -Message $msg -Count "$($items.Count) deleted objects"
    Log-LdapRequest -Operation "RECYCLE_BIN/LIST" -TargetDN "CN=Deleted Objects" -FilterOrPayload "isDeleted=TRUE; Filter=$search" -DurationMs $sw.ElapsedMilliseconds -Status "SUCCESS" -Details $msg
}

function Quick-RestoreRecycleItem {
    if (-not (Test-CanModifyDirectory)) { return }
    $sel = if ($controls['GridRecycleBin']) { $controls['GridRecycleBin'].SelectedItem } else { $null }
    if (-not $sel) {
        [System.Windows.MessageBox]::Show("Please select a deleted object from the Recycle Bin table first.", "Selection Required", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        return
    }

    $confirm = [System.Windows.MessageBox]::Show(
        "Are you sure you want to restore deleted object '$($sel.Name)' to its original container: `r`n`r`n$($sel.LastKnownParent)?",
        "Confirm Tombstone Reanimation",
        [System.Windows.MessageBoxButton]::YesNo,
        [System.Windows.MessageBoxImage]::Question
    )
    if ($confirm -ne [System.Windows.MessageBoxResult]::Yes) { return }

    Set-Status -Message "Restoring $($sel.Name)..."
    $res = Restore-ADDeletedObject -Identity $sel.DistinguishedName
    if ($res.Success) {
        [System.Windows.MessageBox]::Show($res.Message, "Object Restored", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        Log-LdapRequest -Operation "RESTORE_OBJECT" -TargetDN $sel.DistinguishedName -FilterOrPayload "QuickRestore" -Status "SUCCESS" -Details $res.Message
        Refresh-RecycleBin
        Refresh-All
    } else {
        [System.Windows.MessageBox]::Show($res.Message, "Restore Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        Log-LdapRequest -Operation "RESTORE_OBJECT" -TargetDN $sel.DistinguishedName -FilterOrPayload "QuickRestore" -Status "ERROR" -Details $res.Message
    }
}

function Restore-RecycleItemToOU {
    if (-not (Test-CanModifyDirectory)) { return }
    $sel = if ($controls['GridRecycleBin']) { $controls['GridRecycleBin'].SelectedItem } else { $null }
    if (-not $sel) {
        [System.Windows.MessageBox]::Show("Please select a deleted object from the Recycle Bin table first.", "Selection Required", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        return
    }

    $ouList = @($state.CachedOUs | ForEach-Object { $_.DistinguishedName })
    if ($ouList.Count -eq 0) {
        $ouList = @($adContext.DefaultNamingContext)
    }

    $promptInput = [Microsoft.VisualBasic.Interaction]::InputBox(
        "Enter target destination Organizational Unit Distinguished Name (DN):",
        "Restore Object to Custom OU",
        $ouList[0]
    )

    if ([string]::IsNullOrWhiteSpace($promptInput)) { return }

    Set-Status -Message "Restoring $($sel.Name) to $promptInput..."
    $res = Restore-ADDeletedObject -Identity $sel.DistinguishedName -TargetOU $promptInput.Trim()
    if ($res.Success) {
        [System.Windows.MessageBox]::Show($res.Message, "Object Restored to Custom OU", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        Log-LdapRequest -Operation "RESTORE_OBJECT" -TargetDN $sel.DistinguishedName -FilterOrPayload "TargetOU=$promptInput" -Status "SUCCESS" -Details $res.Message
        Refresh-RecycleBin
        Refresh-All
    } else {
        [System.Windows.MessageBox]::Show($res.Message, "Restore Failed", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        Log-LdapRequest -Operation "RESTORE_OBJECT" -TargetDN $sel.DistinguishedName -FilterOrPayload "TargetOU=$promptInput" -Status "ERROR" -Details $res.Message
    }
}

function Inspect-RecycleItemAttributes {
    $sel = if ($controls['GridRecycleBin']) { $controls['GridRecycleBin'].SelectedItem } else { $null }
    if (-not $sel) { return }
    $controls['NavAttributeEditor'].IsChecked = $true
    Show-Panel "AttributeEditor"
    $controls['TxtAttrEditorDN'].Text = $sel.DistinguishedName
    Load-RawAttributesUI -TargetDN $sel.DistinguishedName
}

# Wire Recycle Bin controls
if ($controls['BtnRefreshRecycleBin'])   { $controls['BtnRefreshRecycleBin'].Add_Click({ Refresh-RecycleBin }) }
if ($controls['BtnQuickRestore'])        { $controls['BtnQuickRestore'].Add_Click({ Quick-RestoreRecycleItem }) }
if ($controls['BtnRestoreToOU'])         { $controls['BtnRestoreToOU'].Add_Click({ Restore-RecycleItemToOU }) }
if ($controls['BtnRecycleInspectAttr'])  { $controls['BtnRecycleInspectAttr'].Add_Click({ Inspect-RecycleItemAttributes }) }

if ($controls['TxtSearchRecycleBin']) {
    $controls['TxtSearchRecycleBin'].Add_TextChanged({
        $q = $controls['TxtSearchRecycleBin'].Text.Trim()
        if ($controls['TxtSearchRecycleBinPlaceholder']) {
            $controls['TxtSearchRecycleBinPlaceholder'].Visibility = if ($q.Length -gt 0) { [System.Windows.Visibility]::Collapsed } else { [System.Windows.Visibility]::Visible }
        }
        if ([string]::IsNullOrWhiteSpace($q)) {
            $controls['GridRecycleBin'].ItemsSource = @($state.CachedRecycleBin)
        } else {
            $filtered = @($state.CachedRecycleBin | Where-Object {
                $_.Name -match [regex]::Escape($q) -or $_.SamAccountName -match [regex]::Escape($q) -or $_.DistinguishedName -match [regex]::Escape($q)
            })
            $controls['GridRecycleBin'].ItemsSource = $filtered
        }
    })
    $controls['TxtSearchRecycleBin'].Add_KeyDown({
        if ($_.Key -eq [System.Windows.Input.Key]::Enter) { Refresh-RecycleBin }
    })
}

if ($controls['BtnExportRecycleBin']) {
    $controls['BtnExportRecycleBin'].Add_Click({
        if (-not $state.CachedRecycleBin -or $state.CachedRecycleBin.Count -eq 0) {
            [System.Windows.MessageBox]::Show("No Recycle Bin items to export.", "Notice", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            return
        }
        $sfd = New-Object System.Windows.Forms.SaveFileDialog
        $sfd.FileName = "AD_RecycleBin_$(Get-Date -Format 'yyyyMMdd_HHmm').csv"
        $sfd.Filter = "CSV files (*.csv)|*.csv|All files (*.*)|*.*"
        if ($sfd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $res = Export-ADDataToCsv -Data $state.CachedRecycleBin -FilePath $sfd.FileName -Delimiter ($appConfig.Defaults.ExportDelimiter)
            if ($res.Success) {
                [System.Windows.MessageBox]::Show($res.Message, "Export Complete", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            }
        }
    })
}

# ContextMenu items on GridRecycleBin
if ($controls['CtxRecycleQuickRestore']) { $controls['CtxRecycleQuickRestore'].Add_Click({ Quick-RestoreRecycleItem }) }
if ($controls['CtxRecycleRestoreToOU'])  { $controls['CtxRecycleRestoreToOU'].Add_Click({ Restore-RecycleItemToOU }) }
if ($controls['CtxRecycleInspectAttr'])  { $controls['CtxRecycleInspectAttr'].Add_Click({ Inspect-RecycleItemAttributes }) }
if ($controls['CtxRecycleCopyDN']) {
    $controls['CtxRecycleCopyDN'].Add_Click({
        $sel = if ($controls['GridRecycleBin']) { $controls['GridRecycleBin'].SelectedItem } else { $null }
        if ($sel) {
            [System.Windows.Clipboard]::SetText($sel.DistinguishedName)
            Set-Status -Message "Copied Tombstone DN: $($sel.DistinguishedName)"
        }
    })
}
if ($controls['CtxRecycleCopyLdif']) {
    $controls['CtxRecycleCopyLdif'].Add_Click({
        $sel = if ($controls['GridRecycleBin']) { $controls['GridRecycleBin'].SelectedItem } else { $null }
        if ($sel) {
            $attrs = Get-ADObjectRawAttributes -DistinguishedName $sel.DistinguishedName
            $ldifBlock = "dn: $($sel.DistinguishedName)`r`nobjectClass: $($sel.ObjectClass)`r`n"
            foreach ($a in $attrs) {
                if ($a.Value) { $ldifBlock += "$($a.Name): $($a.Value)`r`n" }
            }
            [System.Windows.Clipboard]::SetText($ldifBlock)
            Set-Status -Message "Copied LDIF record to clipboard for $($sel.Name)."
        }
    })
}
#endregion

#region 18. LDAP Server Monitor & RootDSE Telemetry Logic
function Refresh-ServerMonitor {
    Set-Status -Message "Querying RootDSE telemetry, functional levels and server controls..."
    $server = if ($adContext.PDCEmulator) { $adContext.PDCEmulator } else { $adContext.DomainName }
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $telem = Get-ADServerTelemetry -Server $server
    $sw.Stop()

    if ($controls['TxtMonDnsHost'])      { $controls['TxtMonDnsHost'].Text      = if ($telem.DnsHostName) { $telem.DnsHostName } else { "$server" } }
    if ($controls['TxtMonServiceName'])  { $controls['TxtMonServiceName'].Text  = if ($telem.LdapServiceName) { $telem.LdapServiceName } else { "ldap/$server" } }
    if ($controls['TxtMonDomainLevel'])  { $controls['TxtMonDomainLevel'].Text  = $telem.DomainFunctionalLevel }
    if ($controls['TxtMonForestLevel'])  { $controls['TxtMonForestLevel'].Text  = $telem.ForestFunctionalLevel }
    if ($controls['TxtMonIsGC'])         { $controls['TxtMonIsGC'].Text         = $telem.IsGlobalCatalog }

    if ($controls['TxtMonServerTime'])   { $controls['TxtMonServerTime'].Text   = $telem.ServerTimeUtc }
    if ($controls['TxtMonLocalTime'])    { $controls['TxtMonLocalTime'].Text    = $telem.LocalTimeUtc }
    if ($controls['TxtMonTimeSkew']) {
        $absSkew = [Math]::Abs($telem.TimeSkewMs)
        $controls['TxtMonTimeSkew'].Text = "$($telem.TimeSkewMs) ms ($([Math]::Round($absSkew / 1000, 2))s)"
        if ($absSkew -lt 5000) {
            $controls['TxtMonTimeSkew'].Foreground = [System.Windows.Media.Brushes]::LimeGreen
        } elseif ($absSkew -lt 60000) {
            $controls['TxtMonTimeSkew'].Foreground = [System.Windows.Media.Brushes]::Yellow
        } else {
            $controls['TxtMonTimeSkew'].Foreground = [System.Windows.Media.Brushes]::Red
        }
    }

    if ($controls['TxtMonNamingContexts']) {
        $controls['TxtMonNamingContexts'].Text = ($telem.NamingContexts -join "`r`n")
    }
    if ($controls['TxtMonSaslMechanisms']) {
        $controls['TxtMonSaslMechanisms'].Text = ($telem.SupportedSASLMechanisms -join "`r`n")
    }
    if ($controls['TxtMonSupportedControls']) {
        $controls['TxtMonSupportedControls'].Text = ($telem.SupportedControls -join "`r`n")
    }

    Set-Status -Message "Server Monitor updated for $server." -Count "$($telem.SupportedControls.Count) LDAP Controls | $($telem.NamingContexts.Count) Partitions"
    Log-LdapRequest -Operation "SERVER_MONITOR" -TargetDN "RootDSE" -FilterOrPayload "Telemetry" -DurationMs $sw.ElapsedMilliseconds -Status "SUCCESS" -Details "Telemetry updated: DC=$($telem.DnsHostName), Skew=$($telem.TimeSkewMs)ms"
    Refresh-PartitionsUI
}

function Refresh-PartitionsUI {
    $server = if ($adContext.PDCEmulator) { $adContext.PDCEmulator } else { $adContext.DomainName }
    $parts = Get-ADDirectoryPartitions -Server $server
    $state.CachedPartitions = $parts
    if ($controls['GridPartitions']) {
        $controls['GridPartitions'].ItemsSource = $parts
    }
}

if ($controls['BtnRefreshPartitions']) { $controls['BtnRefreshPartitions'].Add_Click({ Refresh-PartitionsUI }) }

if ($controls['BtnNewAppPartition']) {
    $controls['BtnNewAppPartition'].Add_Click({
        if (-not (Test-CanModifyDirectory)) { return }
        $domainNC = if ($adContext.DefaultNamingContext) { $adContext.DefaultNamingContext } else { "DC=corp,DC=example,DC=com" }
        $defaultNewDN = "DC=AppPart01,$domainNC"

        [void][System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic')
        $inputDN = [Microsoft.VisualBasic.Interaction]::InputBox(
            "Enter the Distinguished Name (DN) for the new Application Directory Partition (NDNC):`r`n`r`nExample: DC=MyAppPartition,$domainNC",
            "Create New Application Directory Partition",
            $defaultNewDN
        )

        if (-not [string]::IsNullOrWhiteSpace($inputDN)) {
            $inputDN = $inputDN.Trim()
            Set-Status -Message "Creating application directory partition '$inputDN'..."
            $res = New-ADDirectoryPartition -PartitionDN $inputDN
            if ($res.Success) {
                [System.Windows.MessageBox]::Show("$($res.Message)", "Partition Created", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
                Refresh-PartitionsUI
                Refresh-ServerMonitor
            } else {
                [System.Windows.MessageBox]::Show("Failed to create application partition:`r`n$($res.Message)", "Creation Failed", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
            }
        }
    })
}

if ($controls['BtnRefreshServerMonitor']) { $controls['BtnRefreshServerMonitor'].Add_Click({ Refresh-ServerMonitor }) }
if ($controls['BtnExportServerMonitor']) {
    $controls['BtnExportServerMonitor'].Add_Click({
        $sfd = New-Object System.Windows.Forms.SaveFileDialog
        $sfd.FileName = "Directory_Telemetry_$(Get-Date -Format 'yyyyMMdd_HHmm').txt"
        $sfd.Filter = "Text files (*.txt)|*.txt|All files (*.*)|*.*"
        if ($sfd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $sb = New-Object System.Text.StringBuilder
            [void]$sb.AppendLine("=== Active Directory Server Monitor & RootDSE Report ===")
            [void]$sb.AppendLine("DNS Host: $($controls['TxtMonDnsHost'].Text)")
            [void]$sb.AppendLine("LDAP Service: $($controls['TxtMonServiceName'].Text)")
            [void]$sb.AppendLine("Domain Level: $($controls['TxtMonDomainLevel'].Text)")
            [void]$sb.AppendLine("Forest Level: $($controls['TxtMonForestLevel'].Text)")
            [void]$sb.AppendLine("Time Skew: $($controls['TxtMonTimeSkew'].Text)")
            [void]$sb.AppendLine("`r`n--- Naming Contexts ---`r`n$($controls['TxtMonNamingContexts'].Text)")
            [void]$sb.AppendLine("`r`n--- Supported Controls ---`r`n$($controls['TxtMonSupportedControls'].Text)")
            [System.IO.File]::WriteAllText($sfd.FileName, $sb.ToString(), [System.Text.Encoding]::UTF8)
            [System.Windows.MessageBox]::Show("Telemetry report saved to $($sfd.FileName)", "Export Complete", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        }
    })
}
#endregion

#region 19. Bookmarks & Favorites Engine (Softerra Parity)
function Add-DirectoryBookmark {
    param ([string]$DN = "")
    if (-not $DN) {
        if ($controls['TxtAttrEditorDN'] -and $controls['TxtAttrEditorDN'].Text) {
            $DN = $controls['TxtAttrEditorDN'].Text.Trim()
        } elseif ($state.SelectedOU) {
            $DN = $state.SelectedOU
        }
    }
    if ([string]::IsNullOrWhiteSpace($DN)) {
        [System.Windows.MessageBox]::Show("Please select an OU or load an object in the Raw Attribute Editor to bookmark.", "No Object Selected", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        return
    }

    if (-not $state.Bookmarks.Contains($DN)) {
        [void]$state.Bookmarks.Add($DN)
        Refresh-BookmarksUI
        Set-Status -Message "Bookmarked: $DN"
    } else {
        Set-Status -Message "Object is already in Favorites: $DN"
    }
}

function Refresh-BookmarksUI {
    if ($controls['CmbBookmarks']) {
        $controls['CmbBookmarks'].Items.Clear()
        $hdr = New-Object System.Windows.Controls.ComboBoxItem
        $hdr.Content = "⭐ Favorites ($($state.Bookmarks.Count))..."
        $hdr.IsEnabled = $false
        [void]$controls['CmbBookmarks'].Items.Add($hdr)

        foreach ($bm in $state.Bookmarks) {
            $item = New-Object System.Windows.Controls.ComboBoxItem
            $shortName = ($bm -split ',')[0] -replace '^(CN|OU|DC)=', ''
            $item.Content = "⭐ $shortName ($bm)"
            $item.Tag = $bm
            [void]$controls['CmbBookmarks'].Items.Add($item)
        }
        $controls['CmbBookmarks'].SelectedIndex = 0
    }
}

if ($controls['BtnAddBookmark']) { $controls['BtnAddBookmark'].Add_Click({ Add-DirectoryBookmark }) }
if ($controls['CmbBookmarks']) {
    $controls['CmbBookmarks'].Add_SelectionChanged({
        if ($controls['CmbBookmarks'].SelectedItem -and $controls['CmbBookmarks'].SelectedIndex -gt 0) {
            $targetDn = $controls['CmbBookmarks'].SelectedItem.Tag
            if ($targetDn) {
                if ($targetDn -match '^(?i)OU=') {
                    $controls['NavOUs'].IsChecked = $true
                    Show-Panel "OUs"
                    Select-OUByDistinguishedName -TargetDN $targetDn
                } else {
                    $controls['NavAttributeEditor'].IsChecked = $true
                    Show-Panel "AttributeEditor"
                    $controls['TxtAttrEditorDN'].Text = $targetDn
                    Load-RawAttributesUI -TargetDN $targetDn
                }
            }
        }
    })
}
#endregion

#region 20. ContextMenu Handlers Across All DataGrids

# Directory Object RDN & Canonical Name Helpers (Softerra Ch03 / Screenshot 01 Parity)
function Get-ObjectRDN {
    param([string]$DN)
    if ([string]::IsNullOrWhiteSpace($DN)) { return "" }
    $parts = $DN -split '(?<!\\),'
    if ($parts.Count -gt 0) { return $parts[0] }
    return $DN
}

function Get-ObjectCanonicalName {
    param([string]$DN)
    if ([string]::IsNullOrWhiteSpace($DN)) { return "" }
    $parts = $DN -split '(?<!\\),'
    $domainParts = New-Object System.Collections.Generic.List[string]
    $ouParts = New-Object System.Collections.Generic.List[string]
    $leaf = ""
    foreach ($p in $parts) {
        $kv = $p -split '=', 2
        if ($kv.Count -eq 2) {
            $k = $kv[0].Trim().ToUpperInvariant()
            $v = $kv[1].Trim()
            if ($k -eq 'DC') {
                $domainParts.Add($v)
            } elseif ($k -eq 'OU' -or $k -eq 'CN') {
                if (-not $leaf) { $leaf = $v }
                else { $ouParts.Add($v) }
            }
        }
    }
    $ouParts.Reverse()
    $domain = ($domainParts -join ".")
    $path = ($ouParts -join "/")
    if ($domain -and $path -and $leaf) { return "$domain/$path/$leaf" }
    if ($domain -and $leaf) { return "$domain/$leaf" }
    return $DN
}

function Show-RenameDialog {
    param([string]$TargetDN, [string]$CurrentName)
    $curRdn = Get-ObjectRDN -DN $TargetDN
    $curVal = if ($curRdn -match '^[^=]+=(.*)$') { $matches[1] } else { $curRdn }

    $xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        Title="Rename Object (RDN)" Width="460" Height="220" WindowStartupLocation="CenterOwner"
        Background="#1A1D27" Foreground="#FFFFFF" ResizeMode="NoResize" WindowStyle="ToolWindow">
    <Grid Margin="18">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
        </Grid.RowDefinitions>
        <TextBlock Grid.Row="0" Text="Rename Directory Object" FontSize="15" FontWeight="Bold" Foreground="#38BDF8" Margin="0,0,0,6"/>
        <TextBlock Grid.Row="1" Text="Enter the new Relative Distinguished Name (RDN) value:" FontSize="12" Foreground="#9CA3AF" Margin="0,0,0,10"/>
        <TextBox Name="TxtNewName" Background="#111319" Foreground="#FFFFFF" BorderBrush="#292E3E" Height="30" FontSize="13" Padding="6,4" Text="$curVal"/>
        <StackPanel Grid.Row="3" Orientation="Horizontal" HorizontalAlignment="Right" VerticalAlignment="Bottom" Margin="0,12,0,0">
            <Button Name="BtnCancel" Content="Cancel" Width="85" Height="28" Background="#252936" Foreground="#FFFFFF" BorderBrush="#3B4254" Margin="0,0,8,0"/>
            <Button Name="BtnOK" Content="Rename" Width="85" Height="28" Background="#0078D4" Foreground="#FFFFFF" BorderThickness="0" FontWeight="SemiBold"/>
        </StackPanel>
    </Grid>
</Window>
"@
    $win = [System.Windows.Markup.XamlReader]::Parse($xaml)
    $win.Owner = $mainWindow
    $txt = $win.FindName("TxtNewName")
    $btnOk = $win.FindName("BtnOK")
    $btnCancel = $win.FindName("BtnCancel")
    $result = $null

    $btnOk.Add_Click({
        $result = $txt.Text.Trim()
        $win.DialogResult = $true
        $win.Close()
    })
    $btnCancel.Add_Click({
        $win.DialogResult = $false
        $win.Close()
    })
    $dialogRes = $win.ShowDialog()
    if ($dialogRes -and -not [string]::IsNullOrWhiteSpace($result) -and $result -ne $curVal) {
        $prefix = if ($curRdn -match '^([^=]+=)') { $matches[1] } else { "CN=" }
        return "$prefix$result"
    }
    return $null
}

function Handle-ObjectRename {
    param([string]$DN, [string]$CurrentName, [scriptblock]$RefreshAction)
    if (-not (Test-CanModifyDirectory)) { return }
    if ([string]::IsNullOrWhiteSpace($DN)) { return }
    $newRdn = Show-RenameDialog -TargetDN $DN -CurrentName $CurrentName
    if ($newRdn) {
        $res = Rename-ADDirectoryObject -DistinguishedName $DN -NewRDN $newRdn
        if ($res.Success) {
            Set-Status -Message "Renamed object to: $($res.NewDN)"
            [System.Windows.MessageBox]::Show("Object successfully renamed to:`n$($res.NewDN)", "Rename Successful", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            if ($RefreshAction) { & $RefreshAction }
        } else {
            Set-Status -Message "Rename failed: $($res.Error)"
            [System.Windows.MessageBox]::Show("Failed to rename object:`n$($res.Error)", "Rename Failed", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        }
    }
}

# Users Grid ContextMenu
if ($controls['CtxUserEdit']) {
    $controls['CtxUserEdit'].Add_Click({
        $u = if ($controls['GridUsers']) { $controls['GridUsers'].SelectedItem } else { $null }
        if ($u) { Open-UserDialog -Mode "Edit" -UserToEdit $u }
    })
}
if ($controls['CtxUserResetPwd']) {
    $controls['CtxUserResetPwd'].Add_Click({
        $u = if ($controls['GridUsers']) { $controls['GridUsers'].SelectedItem } else { $null }
        if ($u) { Open-ResetPasswordDialog -User $u }
    })
}
if ($controls['CtxUserUnlock']) {
    $controls['CtxUserUnlock'].Add_Click({
        if (-not (Test-CanModifyDirectory)) { return }
        $u = if ($controls['GridUsers']) { $controls['GridUsers'].SelectedItem } else { $null }
        if ($u) {
            $res = Unlock-ADUserAccount -Identity $u.SamAccountName
            Set-Status -Message $res.Message
            Refresh-Users
        }
    })
}
if ($controls['CtxUserToggleStatus']) {
    $controls['CtxUserToggleStatus'].Add_Click({
        if (-not (Test-CanModifyDirectory)) { return }
        $u = if ($controls['GridUsers']) { $controls['GridUsers'].SelectedItem } else { $null }
        if ($u) {
            $newStatus = if ($u.Enabled) { $false } else { $true }
            $res = Set-ADUserStatus -Identity $u.SamAccountName -Enabled $newStatus
            Set-Status -Message $res.Message
            Refresh-Users
        }
    })
}
if ($controls['CtxUserMoveOU']) {
    $controls['CtxUserMoveOU'].Add_Click({
        if (-not (Test-CanModifyDirectory)) { return }
        $u = if ($controls['GridUsers']) { $controls['GridUsers'].SelectedItem } else { $null }
        if ($u) { Open-MoveOUDialog -ObjectDN $u.DistinguishedName }
    })
}
if ($controls['CtxUserRename']) {
    $controls['CtxUserRename'].Add_Click({
        $u = if ($controls['GridUsers']) { $controls['GridUsers'].SelectedItem } else { $null }
        if ($u) { Handle-ObjectRename -DN $u.DistinguishedName -CurrentName $u.DisplayName -RefreshAction { Refresh-Users } }
    })
}
if ($controls['CtxUserCopyDN']) {
    $controls['CtxUserCopyDN'].Add_Click({
        $u = if ($controls['GridUsers']) { $controls['GridUsers'].SelectedItem } else { $null }
        if ($u) { [System.Windows.Clipboard]::SetText($u.DistinguishedName); Set-Status -Message "Copied DN: $($u.DistinguishedName)" }
    })
}
if ($controls['CtxUserCopySam']) {
    $controls['CtxUserCopySam'].Add_Click({
        $u = if ($controls['GridUsers']) { $controls['GridUsers'].SelectedItem } else { $null }
        if ($u) { [System.Windows.Clipboard]::SetText($u.SamAccountName); Set-Status -Message "Copied SamAccountName: $($u.SamAccountName)" }
    })
}
if ($controls['CtxUserCopyUrl']) {
    $controls['CtxUserCopyUrl'].Add_Click({
        $u = if ($controls['GridUsers']) { $controls['GridUsers'].SelectedItem } else { $null }
        if ($u) {
            $server = if ($adContext.PDCEmulator) { $adContext.PDCEmulator } else { $adContext.DomainName }
            $ldapUrl = "ldap://$server/$($u.DistinguishedName)"
            [System.Windows.Clipboard]::SetText($ldapUrl)
            Set-Status -Message "Copied LDAP URL: $ldapUrl"
        }
    })
}
if ($controls['CtxUserCopyRdn']) {
    $controls['CtxUserCopyRdn'].Add_Click({
        $u = if ($controls['GridUsers']) { $controls['GridUsers'].SelectedItem } else { $null }
        if ($u) {
            $rdn = Get-ObjectRDN -DN $u.DistinguishedName
            [System.Windows.Clipboard]::SetText($rdn)
            Set-Status -Message "Copied RDN: $rdn"
        }
    })
}
if ($controls['CtxUserCopyCanonical']) {
    $controls['CtxUserCopyCanonical'].Add_Click({
        $u = if ($controls['GridUsers']) { $controls['GridUsers'].SelectedItem } else { $null }
        if ($u) {
            $can = Get-ObjectCanonicalName -DN $u.DistinguishedName
            [System.Windows.Clipboard]::SetText($can)
            Set-Status -Message "Copied Canonical Name: $can"
        }
    })
}
if ($controls['CtxUserCopyLdif']) {
    $controls['CtxUserCopyLdif'].Add_Click({
        $u = if ($controls['GridUsers']) { $controls['GridUsers'].SelectedItem } else { $null }
        if ($u) {
            $attrs = Get-ADObjectRawAttributes -DistinguishedName $u.DistinguishedName
            $ldifBlock = "dn: $($u.DistinguishedName)`r`nchangetype: add`r`nobjectClass: user`r`nsAMAccountName: $($u.SamAccountName)`r`n"
            foreach ($a in $attrs) {
                if ($a.Value) { $ldifBlock += "$($a.Name): $($a.Value)`r`n" }
            }
            [System.Windows.Clipboard]::SetText($ldifBlock)
            Set-Status -Message "Copied LDIF record to clipboard for $($u.SamAccountName)."
        }
    })
}
if ($controls['CtxUserAddToBasket']) {
    $controls['CtxUserAddToBasket'].Add_Click({
        $u = if ($controls['GridUsers']) { $controls['GridUsers'].SelectedItem } else { $null }
        if ($u) { Add-ObjectToBasket -DN $u.DistinguishedName -Name $u.DisplayName -ObjectClass "user" }
    })
}
if ($controls['CtxUserInspectAttr']) {
    $controls['CtxUserInspectAttr'].Add_Click({
        $u = if ($controls['GridUsers']) { $controls['GridUsers'].SelectedItem } else { $null }
        if ($u) {
            $controls['NavAttributeEditor'].IsChecked = $true
            Show-Panel "AttributeEditor"
            $controls['TxtAttrEditorDN'].Text = $u.DistinguishedName
            Load-RawAttributesUI -TargetDN $u.DistinguishedName
        }
    })
}
if ($controls['CtxUserCompare']) {
    $controls['CtxUserCompare'].Add_Click({
        $u = if ($controls['GridUsers']) { $controls['GridUsers'].SelectedItem } else { $null }
        if ($u) {
            $controls['NavObjectCompare'].IsChecked = $true
            Show-Panel "ObjectCompare"
            if (-not $controls['TxtCompareObjectA'].Text) {
                $controls['TxtCompareObjectA'].Text = $u.DistinguishedName
            } else {
                $controls['TxtCompareObjectB'].Text = $u.DistinguishedName
            }
        }
    })
}
if ($controls['CtxUserViewDetails']) {
    $controls['CtxUserViewDetails'].Add_Click({
        $u = if ($controls['GridUsers']) { $controls['GridUsers'].SelectedItem } else { $null }
        if ($u) { Show-UserDetails -User $u }
    })
}
if ($controls['CtxUserViewHtml']) {
    $controls['CtxUserViewHtml'].Add_Click({
        $u = if ($controls['GridUsers']) { $controls['GridUsers'].SelectedItem } else { $null }
        if ($u) { Show-ObjectHtmlView -Identity $u }
    })
}
if ($controls['CtxUserOpenBrowser']) {
    $controls['CtxUserOpenBrowser'].Add_Click({
        $u = if ($controls['GridUsers']) { $controls['GridUsers'].SelectedItem } else { $null }
        if ($u) { Show-ObjectHtmlDossier -TargetObject $u }
    })
}

# Groups Grid ContextMenu
if ($controls['CtxGroupManageMembers']) {
    $controls['CtxGroupManageMembers'].Add_Click({
        $g = if ($controls['GridGroups']) { $controls['GridGroups'].SelectedItem } else { $null }
        if ($g) { Open-GroupMembersDialog -Group $g }
    })
}
if ($controls['CtxGroupDelete']) {
    $controls['CtxGroupDelete'].Add_Click({
        if (-not (Test-CanModifyDirectory)) { return }
        $g = if ($controls['GridGroups']) { $controls['GridGroups'].SelectedItem } else { $null }
        if ($g) { Delete-SelectedGroup -Group $g }
    })
}
if ($controls['CtxGroupRename']) {
    $controls['CtxGroupRename'].Add_Click({
        $g = if ($controls['GridGroups']) { $controls['GridGroups'].SelectedItem } else { $null }
        if ($g) { Handle-ObjectRename -DN $g.DistinguishedName -CurrentName $g.Name -RefreshAction { Refresh-Groups } }
    })
}
if ($controls['CtxGroupCopyDN']) {
    $controls['CtxGroupCopyDN'].Add_Click({
        $g = if ($controls['GridGroups']) { $controls['GridGroups'].SelectedItem } else { $null }
        if ($g) { [System.Windows.Clipboard]::SetText($g.DistinguishedName); Set-Status -Message "Copied Group DN: $($g.DistinguishedName)" }
    })
}
if ($controls['CtxGroupCopyUrl']) {
    $controls['CtxGroupCopyUrl'].Add_Click({
        $g = if ($controls['GridGroups']) { $controls['GridGroups'].SelectedItem } else { $null }
        if ($g) {
            $server = if ($adContext.PDCEmulator) { $adContext.PDCEmulator } else { $adContext.DomainName }
            [System.Windows.Clipboard]::SetText("ldap://$server/$($g.DistinguishedName)")
            Set-Status -Message "Copied LDAP URL for group $($g.Name)"
        }
    })
}
if ($controls['CtxGroupCopyRdn']) {
    $controls['CtxGroupCopyRdn'].Add_Click({
        $g = if ($controls['GridGroups']) { $controls['GridGroups'].SelectedItem } else { $null }
        if ($g) {
            $rdn = Get-ObjectRDN -DN $g.DistinguishedName
            [System.Windows.Clipboard]::SetText($rdn)
            Set-Status -Message "Copied Group RDN: $rdn"
        }
    })
}
if ($controls['CtxGroupCopyCanonical']) {
    $controls['CtxGroupCopyCanonical'].Add_Click({
        $g = if ($controls['GridGroups']) { $controls['GridGroups'].SelectedItem } else { $null }
        if ($g) {
            $can = Get-ObjectCanonicalName -DN $g.DistinguishedName
            [System.Windows.Clipboard]::SetText($can)
            Set-Status -Message "Copied Group Canonical Name: $can"
        }
    })
}
if ($controls['CtxGroupAddToBasket']) {
    $controls['CtxGroupAddToBasket'].Add_Click({
        $g = if ($controls['GridGroups']) { $controls['GridGroups'].SelectedItem } else { $null }
        if ($g) { Add-ObjectToBasket -DN $g.DistinguishedName -Name $g.Name -ObjectClass "group" }
    })
}
if ($controls['CtxGroupInspectAttr']) {
    $controls['CtxGroupInspectAttr'].Add_Click({
        $g = if ($controls['GridGroups']) { $controls['GridGroups'].SelectedItem } else { $null }
        if ($g) {
            $controls['NavAttributeEditor'].IsChecked = $true
            Show-Panel "AttributeEditor"
            $controls['TxtAttrEditorDN'].Text = $g.DistinguishedName
            Load-RawAttributesUI -TargetDN $g.DistinguishedName
        }
    })
}
if ($controls['CtxGroupCompare']) {
    $controls['CtxGroupCompare'].Add_Click({
        $g = if ($controls['GridGroups']) { $controls['GridGroups'].SelectedItem } else { $null }
        if ($g) {
            $controls['NavObjectCompare'].IsChecked = $true
            Show-Panel "ObjectCompare"
            if (-not $controls['TxtCompareObjectA'].Text) { $controls['TxtCompareObjectA'].Text = $g.DistinguishedName }
            else { $controls['TxtCompareObjectB'].Text = $g.DistinguishedName }
        }
    })
}
if ($controls['CtxGroupViewHtml']) {
    $controls['CtxGroupViewHtml'].Add_Click({
        $g = if ($controls['GridGroups']) { $controls['GridGroups'].SelectedItem } else { $null }
        if ($g) { Show-ObjectHtmlView -Identity $g }
    })
}
if ($controls['CtxGroupOpenBrowser']) {
    $controls['CtxGroupOpenBrowser'].Add_Click({
        $g = if ($controls['GridGroups']) { $controls['GridGroups'].SelectedItem } else { $null }
        if ($g) { Show-ObjectHtmlDossier -TargetObject $g }
    })
}

# OUs TreeView ContextMenu
if ($controls['CtxOUTreeNewUser']) {
    $controls['CtxOUTreeNewUser'].Add_Click({
        $node = if ($controls['TreeOUs']) { $controls['TreeOUs'].SelectedItem } else { $null }
        $ouDN = if ($node) { $node.DistinguishedName } else { $state.SelectedOU }
        Open-UserDialog -Mode "Create" -TargetOU $ouDN
    })
}
if ($controls['CtxOUTreeNewGroup']) {
    $controls['CtxOUTreeNewGroup'].Add_Click({
        $node = if ($controls['TreeOUs']) { $controls['TreeOUs'].SelectedItem } else { $null }
        $ouDN = if ($node) { $node.DistinguishedName } else { $state.SelectedOU }
        Open-GroupDialog -TargetOU $ouDN
    })
}
if ($controls['CtxOUTreeNewOU']) {
    $controls['CtxOUTreeNewOU'].Add_Click({
        $node = if ($controls['TreeOUs']) { $controls['TreeOUs'].SelectedItem } else { $null }
        $parentDN = if ($node) { $node.DistinguishedName } else { $null }
        Open-OUDialog -ParentDN $parentDN
    })
}
if ($controls['CtxOUTreeDeleteOU']) {
    $controls['CtxOUTreeDeleteOU'].Add_Click({
        if ($controls['BtnDeleteOU']) {
            $controls['BtnDeleteOU'].RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent)))
        }
    })
}
if ($controls['CtxOUTreeRename']) {
    $controls['CtxOUTreeRename'].Add_Click({
        $node = if ($controls['TreeOUs']) { $controls['TreeOUs'].SelectedItem } else { $null }
        $dn = if ($node) { $node.DistinguishedName } else { $state.SelectedOU }
        $name = if ($node) { $node.Name } else { "" }
        if ($dn) { Handle-ObjectRename -DN $dn -CurrentName $name -RefreshAction { Refresh-OUs } }
    })
}
if ($controls['CtxOUTreeBookmark']) {
    $controls['CtxOUTreeBookmark'].Add_Click({
        $node = if ($controls['TreeOUs']) { $controls['TreeOUs'].SelectedItem } else { $null }
        $dn = if ($node) { $node.DistinguishedName } else { $state.SelectedOU }
        if ($dn) { Add-DirectoryBookmark -DN $dn }
    })
}
if ($controls['CtxOUTreeInspectAttr']) {
    $controls['CtxOUTreeInspectAttr'].Add_Click({
        $node = if ($controls['TreeOUs']) { $controls['TreeOUs'].SelectedItem } else { $null }
        $dn = if ($node) { $node.DistinguishedName } else { $state.SelectedOU }
        if ($dn) {
            $controls['NavAttributeEditor'].IsChecked = $true
            Show-Panel "AttributeEditor"
            $controls['TxtAttrEditorDN'].Text = $dn
            Load-RawAttributesUI -TargetDN $dn
        }
    })
}
if ($controls['CtxOUTreeCopyDN']) {
    $controls['CtxOUTreeCopyDN'].Add_Click({
        $node = if ($controls['TreeOUs']) { $controls['TreeOUs'].SelectedItem } else { $null }
        $dn = if ($node) { $node.DistinguishedName } else { $state.SelectedOU }
        if ($dn) { [System.Windows.Clipboard]::SetText($dn); Set-Status -Message "Copied OU DN: $dn" }
    })
}
if ($controls['CtxOUTreeCopyRdn']) {
    $controls['CtxOUTreeCopyRdn'].Add_Click({
        $node = if ($controls['TreeOUs']) { $controls['TreeOUs'].SelectedItem } else { $null }
        $dn = if ($node) { $node.DistinguishedName } else { $state.SelectedOU }
        if ($dn) {
            $rdn = Get-ObjectRDN -DN $dn
            [System.Windows.Clipboard]::SetText($rdn)
            Set-Status -Message "Copied OU RDN: $rdn"
        }
    })
}
if ($controls['CtxOUTreeCopyCanonical']) {
    $controls['CtxOUTreeCopyCanonical'].Add_Click({
        $node = if ($controls['TreeOUs']) { $controls['TreeOUs'].SelectedItem } else { $null }
        $dn = if ($node) { $node.DistinguishedName } else { $state.SelectedOU }
        if ($dn) {
            $can = Get-ObjectCanonicalName -DN $dn
            [System.Windows.Clipboard]::SetText($can)
            Set-Status -Message "Copied OU Canonical Name: $can"
        }
    })
}

# OU Objects ContextMenu
if ($controls['CtxOuObjInspectAttr']) {
    $controls['CtxOuObjInspectAttr'].Add_Click({
        $obj = if ($controls['GridOUObjects']) { $controls['GridOUObjects'].SelectedItem } else { $null }
        if ($obj) {
            $controls['NavAttributeEditor'].IsChecked = $true
            Show-Panel "AttributeEditor"
            $controls['TxtAttrEditorDN'].Text = $obj.DistinguishedName
            Load-RawAttributesUI -TargetDN $obj.DistinguishedName
        }
    })
}
if ($controls['CtxOuObjAddToBasket']) {
    $controls['CtxOuObjAddToBasket'].Add_Click({
        $obj = if ($controls['GridOUObjects']) { $controls['GridOUObjects'].SelectedItem } else { $null }
        if ($obj) { Add-ObjectToBasket -DN $obj.DistinguishedName -Name $obj.Name -ObjectClass $obj.ObjectClass }
    })
}
if ($controls['CtxOuObjRename']) {
    $controls['CtxOuObjRename'].Add_Click({
        $obj = if ($controls['GridOUObjects']) { $controls['GridOUObjects'].SelectedItem } else { $null }
        if ($obj) { Handle-ObjectRename -DN $obj.DistinguishedName -CurrentName $obj.Name -RefreshAction { Load-OUObjectsUI } }
    })
}
if ($controls['CtxOuObjCopyDN']) {
    $controls['CtxOuObjCopyDN'].Add_Click({
        $obj = if ($controls['GridOUObjects']) { $controls['GridOUObjects'].SelectedItem } else { $null }
        if ($obj) { [System.Windows.Clipboard]::SetText($obj.DistinguishedName); Set-Status -Message "Copied DN: $($obj.DistinguishedName)" }
    })
}
if ($controls['CtxOuObjCopyUrl']) {
    $controls['CtxOuObjCopyUrl'].Add_Click({
        $obj = if ($controls['GridOUObjects']) { $controls['GridOUObjects'].SelectedItem } else { $null }
        if ($obj) {
            $server = if ($adContext.PDCEmulator) { $adContext.PDCEmulator } else { $adContext.DomainName }
            [System.Windows.Clipboard]::SetText("ldap://$server/$($obj.DistinguishedName)")
            Set-Status -Message "Copied LDAP URL: $($obj.Name)"
        }
    })
}
if ($controls['CtxOuObjCopyRdn']) {
    $controls['CtxOuObjCopyRdn'].Add_Click({
        $obj = if ($controls['GridOUObjects']) { $controls['GridOUObjects'].SelectedItem } else { $null }
        if ($obj) {
            $rdn = Get-ObjectRDN -DN $obj.DistinguishedName
            [System.Windows.Clipboard]::SetText($rdn)
            Set-Status -Message "Copied RDN: $rdn"
        }
    })
}
if ($controls['CtxOuObjCopyCanonical']) {
    $controls['CtxOuObjCopyCanonical'].Add_Click({
        $obj = if ($controls['GridOUObjects']) { $controls['GridOUObjects'].SelectedItem } else { $null }
        if ($obj) {
            $can = Get-ObjectCanonicalName -DN $obj.DistinguishedName
            [System.Windows.Clipboard]::SetText($can)
            Set-Status -Message "Copied Canonical Name: $can"
        }
    })
}
if ($controls['CtxOuObjCompare']) {
    $controls['CtxOuObjCompare'].Add_Click({
        $obj = if ($controls['GridOUObjects']) { $controls['GridOUObjects'].SelectedItem } else { $null }
        if ($obj) {
            $controls['NavObjectCompare'].IsChecked = $true
            Show-Panel "ObjectCompare"
            if (-not $controls['TxtCompareObjectA'].Text) { $controls['TxtCompareObjectA'].Text = $obj.DistinguishedName }
            else { $controls['TxtCompareObjectB'].Text = $obj.DistinguishedName }
        }
    })
}
if ($controls['CtxOUObjViewHtml']) {
    $controls['CtxOUObjViewHtml'].Add_Click({
        $obj = if ($controls['GridOUObjects']) { $controls['GridOUObjects'].SelectedItem } else { $null }
        if ($obj) { Show-ObjectHtmlView -Identity $obj }
    })
}
if ($controls['CtxOUObjOpenBrowser']) {
    $controls['CtxOUObjOpenBrowser'].Add_Click({
        $obj = if ($controls['GridOUObjects']) { $controls['GridOUObjects'].SelectedItem } else { $null }
        if ($obj) { Show-ObjectHtmlDossier -TargetObject $obj }
    })
}

# Computers ContextMenu
if ($controls['CtxCompRdp']) {
    $controls['CtxCompRdp'].Add_Click({
        $c = if ($controls['GridComputers']) { $controls['GridComputers'].SelectedItem } else { $null }
        if ($c) {
            $target = if ($c.DNSHostName) { $c.DNSHostName } elseif ($c.IPv4Address) { $c.IPv4Address } else { $c.Name }
            Set-Status -Message "Launching Remote Desktop Connection to $target..."
            Start-Process "mstsc.exe" -ArgumentList "/v:$target"
        }
    })
}
if ($controls['CtxCompPing']) {
    $controls['CtxCompPing'].Add_Click({
        $c = if ($controls['GridComputers']) { $controls['GridComputers'].SelectedItem } else { $null }
        if ($c) {
            $target = if ($c.DNSHostName) { $c.DNSHostName } else { $c.Name }
            Set-Status -Message "Pinging $target..."
            try {
                $ping = Test-Connection -ComputerName $target -Count 1 -Quiet -ErrorAction SilentlyContinue
                if ($ping) {
                    Set-Status -Message "Host '$target' is ONLINE and reachable."
                    [System.Windows.MessageBox]::Show("Host '$target' is reachable over network (ICMP ping reply received).", "Host Online", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
                } else {
                    Set-Status -Message "Host '$target' did not respond to ping."
                    [System.Windows.MessageBox]::Show("Host '$target' did not respond (offline or ICMP blocked by firewall).", "Ping Timed Out", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
                }
            } catch {
                Set-Status -Message "Ping error: $_"
            }
        }
    })
}
if ($controls['CtxCompRename']) {
    $controls['CtxCompRename'].Add_Click({
        $c = if ($controls['GridComputers']) { $controls['GridComputers'].SelectedItem } else { $null }
        if ($c) { Handle-ObjectRename -DN $c.DistinguishedName -CurrentName $c.Name -RefreshAction { Refresh-Computers } }
    })
}
if ($controls['CtxCompCopyDN']) {
    $controls['CtxCompCopyDN'].Add_Click({
        $c = if ($controls['GridComputers']) { $controls['GridComputers'].SelectedItem } else { $null }
        if ($c) { [System.Windows.Clipboard]::SetText($c.DistinguishedName); Set-Status -Message "Copied Computer DN: $($c.DistinguishedName)" }
    })
}
if ($controls['CtxCompCopyName']) {
    $controls['CtxCompCopyName'].Add_Click({
        $c = if ($controls['GridComputers']) { $controls['GridComputers'].SelectedItem } else { $null }
        if ($c) { [System.Windows.Clipboard]::SetText($c.Name); Set-Status -Message "Copied Name: $($c.Name)" }
    })
}
if ($controls['CtxCompCopyRdn']) {
    $controls['CtxCompCopyRdn'].Add_Click({
        $c = if ($controls['GridComputers']) { $controls['GridComputers'].SelectedItem } else { $null }
        if ($c) {
            $rdn = Get-ObjectRDN -DN $c.DistinguishedName
            [System.Windows.Clipboard]::SetText($rdn)
            Set-Status -Message "Copied Computer RDN: $rdn"
        }
    })
}
if ($controls['CtxCompCopyCanonical']) {
    $controls['CtxCompCopyCanonical'].Add_Click({
        $c = if ($controls['GridComputers']) { $controls['GridComputers'].SelectedItem } else { $null }
        if ($c) {
            $can = Get-ObjectCanonicalName -DN $c.DistinguishedName
            [System.Windows.Clipboard]::SetText($can)
            Set-Status -Message "Copied Computer Canonical Name: $can"
        }
    })
}
if ($controls['CtxCompAddToBasket']) {
    $controls['CtxCompAddToBasket'].Add_Click({
        $c = if ($controls['GridComputers']) { $controls['GridComputers'].SelectedItem } else { $null }
        if ($c) { Add-ObjectToBasket -DN $c.DistinguishedName -Name $c.Name -ObjectClass "computer" }
    })
}
if ($controls['CtxCompInspectAttr']) {
    $controls['CtxCompInspectAttr'].Add_Click({
        $c = if ($controls['GridComputers']) { $controls['GridComputers'].SelectedItem } else { $null }
        if ($c) {
            $controls['NavAttributeEditor'].IsChecked = $true
            Show-Panel "AttributeEditor"
            $controls['TxtAttrEditorDN'].Text = $c.DistinguishedName
            Load-RawAttributesUI -TargetDN $c.DistinguishedName
        }
    })
}
if ($controls['CtxCompCompare']) {
    $controls['CtxCompCompare'].Add_Click({
        $c = if ($controls['GridComputers']) { $controls['GridComputers'].SelectedItem } else { $null }
        if ($c) {
            $controls['NavObjectCompare'].IsChecked = $true
            Show-Panel "ObjectCompare"
            if (-not $controls['TxtCompareObjectA'].Text) { $controls['TxtCompareObjectA'].Text = $c.DistinguishedName }
            else { $controls['TxtCompareObjectB'].Text = $c.DistinguishedName }
        }
    })
}
if ($controls['CtxCompViewHtml']) {
    $controls['CtxCompViewHtml'].Add_Click({
        $c = if ($controls['GridComputers']) { $controls['GridComputers'].SelectedItem } else { $null }
        if ($c) { Show-ObjectHtmlView -Identity $c }
    })
}
if ($controls['CtxCompOpenBrowser']) {
    $controls['CtxCompOpenBrowser'].Add_Click({
        $c = if ($controls['GridComputers']) { $controls['GridComputers'].SelectedItem } else { $null }
        if ($c) { Show-ObjectHtmlDossier -TargetObject $c }
    })
}

# Search ContextMenu
if ($controls['CtxSearchInspectAttr']) {
    $controls['CtxSearchInspectAttr'].Add_Click({
        $s = if ($controls['GridSearchResults']) { $controls['GridSearchResults'].SelectedItem } else { $null }
        if ($s) {
            $controls['NavAttributeEditor'].IsChecked = $true
            Show-Panel "AttributeEditor"
            $controls['TxtAttrEditorDN'].Text = $s.DistinguishedName
            Load-RawAttributesUI -TargetDN $s.DistinguishedName
        }
    })
}
if ($controls['CtxSearchAddToBasket']) {
    $controls['CtxSearchAddToBasket'].Add_Click({
        $s = if ($controls['GridSearchResults']) { $controls['GridSearchResults'].SelectedItem } else { $null }
        if ($s) { Add-ObjectToBasket -DN $s.DistinguishedName -Name ($s.DisplayName -or $s.Name -or $s.SamAccountName) -ObjectClass $s.ObjectClass }
    })
}
if ($controls['CtxSearchCopyDN']) {
    $controls['CtxSearchCopyDN'].Add_Click({
        $s = if ($controls['GridSearchResults']) { $controls['GridSearchResults'].SelectedItem } else { $null }
        if ($s) { [System.Windows.Clipboard]::SetText($s.DistinguishedName); Set-Status -Message "Copied DN: $($s.DistinguishedName)" }
    })
}
if ($controls['CtxSearchCopySam']) {
    $controls['CtxSearchCopySam'].Add_Click({
        $s = if ($controls['GridSearchResults']) { $controls['GridSearchResults'].SelectedItem } else { $null }
        if ($s) {
            $sam = if ($s.SamAccountName) { $s.SamAccountName } else { $s.Name }
            [System.Windows.Clipboard]::SetText($sam); Set-Status -Message "Copied Username/RDN: $sam"
        }
    })
}
if ($controls['CtxSearchCopyUrl']) {
    $controls['CtxSearchCopyUrl'].Add_Click({
        $s = if ($controls['GridSearchResults']) { $controls['GridSearchResults'].SelectedItem } else { $null }
        if ($s) {
            $server = if ($adContext.PDCEmulator) { $adContext.PDCEmulator } else { $adContext.DomainName }
            $ldapUrl = "ldap://$server/$($s.DistinguishedName)"
            [System.Windows.Clipboard]::SetText($ldapUrl)
            Set-Status -Message "Copied LDAP URL: $ldapUrl"
        }
    })
}
if ($controls['CtxSearchCopyLdif']) {
    $controls['CtxSearchCopyLdif'].Add_Click({
        $s = if ($controls['GridSearchResults']) { $controls['GridSearchResults'].SelectedItem } else { $null }
        if ($s) {
            $attrs = Get-ADObjectRawAttributes -DistinguishedName $s.DistinguishedName
            $ldifBlock = "dn: $($s.DistinguishedName)`r`nchangetype: add`r`nobjectClass: $(if ($s.ObjectClass) { $s.ObjectClass } else { 'top' })`r`n"
            foreach ($a in $attrs) {
                if ($a.Value) { $ldifBlock += "$($a.Name): $($a.Value)`r`n" }
            }
            [System.Windows.Clipboard]::SetText($ldifBlock)
            Set-Status -Message "Copied LDIF record to clipboard for $($s.DistinguishedName)."
        }
    })
}
if ($controls['CtxSearchCompare']) {
    $controls['CtxSearchCompare'].Add_Click({
        $s = if ($controls['GridSearchResults']) { $controls['GridSearchResults'].SelectedItem } else { $null }
        if ($s) {
            $controls['NavObjectCompare'].IsChecked = $true
            Show-Panel "ObjectCompare"
            if (-not $controls['TxtCompareObjectA'].Text) { $controls['TxtCompareObjectA'].Text = $s.DistinguishedName }
            else { $controls['TxtCompareObjectB'].Text = $s.DistinguishedName }
        }
    })
}
if ($controls['CtxSearchViewHtml']) {
    $controls['CtxSearchViewHtml'].Add_Click({
        $s = if ($controls['GridSearchResults']) { $controls['GridSearchResults'].SelectedItem } else { $null }
        if ($s) { Show-ObjectHtmlView -Identity $s }
    })
}
if ($controls['CtxSearchOpenBrowser']) {
    $controls['CtxSearchOpenBrowser'].Add_Click({
        $s = if ($controls['GridSearchResults']) { $controls['GridSearchResults'].SelectedItem } else { $null }
        if ($s) { Show-ObjectHtmlDossier -TargetObject $s }
    })
}

# Basket ContextMenu
if ($controls['CtxBasketInspectAttr']) {
    $controls['CtxBasketInspectAttr'].Add_Click({
        $b = if ($controls['GridBasket']) { $controls['GridBasket'].SelectedItem } else { $null }
        if ($b) {
            $controls['NavAttributeEditor'].IsChecked = $true
            Show-Panel "AttributeEditor"
            $controls['TxtAttrEditorDN'].Text = $b.DistinguishedName
            Load-RawAttributesUI -TargetDN $b.DistinguishedName
        }
    })
}
if ($controls['CtxBasketCompare']) {
    $controls['CtxBasketCompare'].Add_Click({
        $b = if ($controls['GridBasket']) { $controls['GridBasket'].SelectedItem } else { $null }
        if ($b) {
            $controls['NavObjectCompare'].IsChecked = $true
            Show-Panel "ObjectCompare"
            if (-not $controls['TxtCompareObjectA'].Text) { $controls['TxtCompareObjectA'].Text = $b.DistinguishedName }
            else { $controls['TxtCompareObjectB'].Text = $b.DistinguishedName }
        }
    })
}
if ($controls['CtxBasketRemove']) {
    $controls['CtxBasketRemove'].Add_Click({
        $b = if ($controls['GridBasket']) { $controls['GridBasket'].SelectedItem } else { $null }
        if ($b) { [void]$state.BasketItems.Remove($b); Refresh-BasketUI }
    })
}
if ($controls['CtxBasketCopyDN']) {
    $controls['CtxBasketCopyDN'].Add_Click({
        $b = if ($controls['GridBasket']) { $controls['GridBasket'].SelectedItem } else { $null }
        if ($b) { [System.Windows.Clipboard]::SetText($b.DistinguishedName); Set-Status -Message "Copied DN: $($b.DistinguishedName)" }
    })
}

# F2 Keyboard Shortcut for In-Place / Dialog Rename (Softerra Ch03 Parity)
if ($controls['GridUsers']) {
    $controls['GridUsers'].Add_KeyDown({
        if ($_.Key -eq [System.Windows.Input.Key]::F2) {
            $u = $controls['GridUsers'].SelectedItem
            if ($u) { Handle-ObjectRename -DN $u.DistinguishedName -CurrentName $u.DisplayName -RefreshAction { Refresh-Users } }
        }
    })
}
if ($controls['GridGroups']) {
    $controls['GridGroups'].Add_KeyDown({
        if ($_.Key -eq [System.Windows.Input.Key]::F2) {
            $g = $controls['GridGroups'].SelectedItem
            if ($g) { Handle-ObjectRename -DN $g.DistinguishedName -CurrentName $g.Name -RefreshAction { Refresh-Groups } }
        }
    })
}
if ($controls['GridOUObjects']) {
    $controls['GridOUObjects'].Add_KeyDown({
        if ($_.Key -eq [System.Windows.Input.Key]::F2) {
            $obj = $controls['GridOUObjects'].SelectedItem
            if ($obj) { Handle-ObjectRename -DN $obj.DistinguishedName -CurrentName $obj.Name -RefreshAction { Load-OUObjectsUI } }
        }
    })
}
if ($controls['GridComputers']) {
    $controls['GridComputers'].Add_KeyDown({
        if ($_.Key -eq [System.Windows.Input.Key]::F2) {
            $c = $controls['GridComputers'].SelectedItem
            if ($c) { Handle-ObjectRename -DN $c.DistinguishedName -CurrentName $c.Name -RefreshAction { Refresh-Computers } }
        }
    })
}
if ($controls['TreeOUs']) {
    $controls['TreeOUs'].Add_KeyDown({
        if ($_.Key -eq [System.Windows.Input.Key]::F2) {
            $node = $controls['TreeOUs'].SelectedItem
            if ($node) { Handle-ObjectRename -DN $node.DistinguishedName -CurrentName $node.Name -RefreshAction { Refresh-OUs } }
        }
    })
}
#region 21. NetTools & Advanced Suite Logic

function Init-ElevationBadge {
    try {
        $ident = [Security.Principal.WindowsIdentity]::GetCurrent()
        $princ = [Security.Principal.WindowsPrincipal]$ident
        $isElevated = $princ.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if ($controls['BorderElevationBadge']) {
            if ($isElevated) {
                $controls['BorderElevationBadge'].Background = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#107C41")
                if ($controls['TxtElevationStatus']) { $controls['TxtElevationStatus'].Text = "🛡️ ELEVATED (ADMIN)" }
                $controls['BorderElevationBadge'].ToolTip = "Process running with full Administrative privileges and SeDebugPrivilege token."
            } else {
                $controls['BorderElevationBadge'].Background = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#4B5563")
                if ($controls['TxtElevationStatus']) { $controls['TxtElevationStatus'].Text = "👤 STANDARD USER" }
                $controls['BorderElevationBadge'].ToolTip = "Running as Standard User. Advanced multi-DC event log searches or replication sync may require elevation."
            }
        }
    } catch {
        # Fallback
    }
}

function Show-AclBrowserDialog {
    param([string]$TargetDN = "")
    try {
        $dlgPath = Join-Path $viewsPath "AclBrowserDialog.xaml"
        $dlg = Load-XamlWindow -XamlPath $dlgPath
        $dlg.Owner = $window

        $dlgControls = @{}
        $r = [System.Xml.XmlReader]::Create([System.IO.StringReader](Get-Content $dlgPath -Raw -Encoding UTF8))
        while ($r.Read()) {
            if ($r.NodeType -eq [System.Xml.XmlNodeType]::Element) {
                $name = $r.GetAttribute("Name")
                if (-not [string]::IsNullOrWhiteSpace($name)) {
                    $dlgControls[$name] = $dlg.FindName($name)
                }
            }
        }
        $r.Close()

        $loadAclData = {
            param([string]$dn)
            if ([string]::IsNullOrWhiteSpace($dn)) { return }
            if ($dlgControls['TxtAclTargetDn']) { $dlgControls['TxtAclTargetDn'].Text = $dn }
            $acl = Get-ADObjectAcl -Identity $dn
            if ($acl) {
                if ($dlgControls['GridDaclAces']) { $dlgControls['GridDaclAces'].ItemsSource = $acl.Dacl }
                elseif ($dlgControls['GridDacl']) { $dlgControls['GridDacl'].ItemsSource = $acl.Dacl }
                if ($dlgControls['GridSaclAces']) { $dlgControls['GridSaclAces'].ItemsSource = $acl.Sacl }
                elseif ($dlgControls['GridSacl']) { $dlgControls['GridSacl'].ItemsSource = $acl.Sacl }
                if ($dlgControls['TxtRawSddl']) { $dlgControls['TxtRawSddl'].Text = $acl.Sddl }
                elseif ($dlgControls['TxtSddlBox']) { $dlgControls['TxtSddlBox'].Text = $acl.Sddl }
                if ($dlgControls['TxtInheritanceBadge']) {
                    $dlgControls['TxtInheritanceBadge'].Text = if ($acl.InheritanceBlocked) { "Inheritance Blocked" } else { "Inheritance Enabled" }
                }
                if ($dlgControls['BrdInheritanceBadge']) {
                    $inhColor = if ($acl.InheritanceBlocked) { "#DC2626" } else { "#107C41" }
                    $dlgControls['BrdInheritanceBadge'].Background = [System.Windows.Media.BrushConverter]::new().ConvertFromString($inhColor)
                }
            }
        }

        if (-not [string]::IsNullOrWhiteSpace($TargetDN)) {
            & $loadAclData $TargetDN
        } elseif ($controls['TxtAclTargetDN'] -and -not [string]::IsNullOrWhiteSpace($controls['TxtAclTargetDN'].Text)) {
            & $loadAclData $controls['TxtAclTargetDN'].Text.Trim()
        }

        if ($dlgControls['BtnCalculateEffective']) {
            $dlgControls['BtnCalculateEffective'].Add_Click({
                $trustee = if ($dlgControls['TxtAclTrustee']) { $dlgControls['TxtAclTrustee'].Text.Trim() } else { "Domain Admins" }
                $target = if ($dlgControls['TxtAclTargetDn']) { $dlgControls['TxtAclTargetDn'].Text.Trim() } else { "" }
                if ($target -and $trustee) {
                    $eff = Get-ADEffectivePermissions -Identity $target -Trustee $trustee
                    if ($eff) {
                        if ($dlgControls['GridEffective']) {
                            $dlgControls['GridEffective'].ItemsSource = $eff.Permissions
                        }
                        if ($dlgControls['LstEffectiveRights']) {
                            $dlgControls['LstEffectiveRights'].ItemsSource = $eff.GrantedRights
                        }
                        if ($dlgControls['TxtEffectiveSummary']) {
                            $dlgControls['TxtEffectiveSummary'].Text = $eff.EvaluationDetails
                        }
                    }
                }
            })
        }

        if ($dlgControls['BtnCopySddl']) {
            $dlgControls['BtnCopySddl'].Add_Click({
                $sddlText = if ($dlgControls['TxtRawSddl']) { $dlgControls['TxtRawSddl'].Text } elseif ($dlgControls['TxtSddlBox']) { $dlgControls['TxtSddlBox'].Text } else { "" }
                if (-not [string]::IsNullOrWhiteSpace($sddlText)) {
                    [System.Windows.Clipboard]::SetText($sddlText)
                    [System.Windows.MessageBox]::Show("SDDL copied to clipboard.", "Copied", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
                }
            })
        }

        if ($dlgControls['BtnCloseAclDialog']) {
            $dlgControls['BtnCloseAclDialog'].Add_Click({ $dlg.Close() })
        }
        if ($dlgControls['BtnCloseAcl']) {
            $dlgControls['BtnCloseAcl'].Add_Click({ $dlg.Close() })
        }

        [void]$dlg.ShowDialog()
    } catch {
        [System.Windows.MessageBox]::Show("Failed to open ACL Browser: $($_.Exception.Message)", "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
    }
}

function Show-ResolverDialog {
    param([string]$InitialInput = "")
    try {
        $dlgPath = Join-Path $viewsPath "ResolverDialog.xaml"
        $dlg = Load-XamlWindow -XamlPath $dlgPath
        $dlg.Owner = $window

        $dlgControls = @{}
        $r = [System.Xml.XmlReader]::Create([System.IO.StringReader](Get-Content $dlgPath -Raw -Encoding UTF8))
        while ($r.Read()) {
            if ($r.NodeType -eq [System.Xml.XmlNodeType]::Element) {
                $name = $r.GetAttribute("Name")
                if (-not [string]::IsNullOrWhiteSpace($name)) {
                    $dlgControls[$name] = $dlg.FindName($name)
                }
            }
        }
        $r.Close()

        if ($InitialInput -and $dlgControls['TxtResolverInput']) {
            $dlgControls['TxtResolverInput'].Text = $InitialInput
        }

        $resolveAction = {
            $rawText = if ($dlgControls['TxtResolverInput']) { $dlgControls['TxtResolverInput'].Text } else { "" }
            if ([string]::IsNullOrWhiteSpace($rawText)) { return }
            $lines = $rawText -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_.Length -gt 0 }
            
            $results = [System.Collections.Generic.List[PSObject]]::new()
            foreach ($line in $lines) {
                $entityType = "sAMAccountName"
                if ($line -match '^S-1-5-') { $entityType = "SID" }
                elseif ($line -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') { $entityType = "IP Address" }
                elseif ($line -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-') { $entityType = "GUID" }
                elseif ($line -match '^(?i)(CN|OU|DC)=') { $entityType = "DistinguishedName" }
                elseif ($line -match '@') { $entityType = "UPN / Email" }

                # Query Directory or resolve heuristic
                $resolvedName = $line
                $statusBadge = "Active"
                $details = ""

                if ($entityType -eq "IP Address") {
                    $resolvedName = "Subnet / Host: $line"
                    $statusBadge = "Network Host"
                    $details = "IPv4 Endpoint"
                } elseif ($entityType -eq "SID") {
                    $resolvedName = "Security Principal ($line)"
                    $statusBadge = "Resolved SID"
                    $details = "Domain Trustee"
                } else {
                    $u = Search-ADObjects -FilterTerm $line | Select-Object -First 1
                    if ($u) {
                        $resolvedName = if ($u.DisplayName) { $u.DisplayName } else { $u.Name }
                        $statusBadge = if ($u.Enabled -eq $false) { "Disabled" } else { "Active" }
                        $details = $u.DistinguishedName
                    } else {
                        $statusBadge = "Heuristic Match"
                        $details = "Local / Uncommitted Term"
                    }
                }

                $results.Add([PSCustomObject]@{
                    InputTerm    = $line
                    EntityType   = $entityType
                    ResolvedName = $resolvedName
                    StatusBadge  = $statusBadge
                    Details      = $details
                })
            }

            if ($dlgControls['GridResolverResults']) {
                $dlgControls['GridResolverResults'].ItemsSource = $results
            }
        }

        if ($dlgControls['BtnResolverResolve']) {
            $dlgControls['BtnResolverResolve'].Add_Click({ & $resolveAction })
        }

        if ($dlgControls['BtnResolverClear']) {
            $dlgControls['BtnResolverClear'].Add_Click({
                if ($dlgControls['TxtResolverInput']) { $dlgControls['TxtResolverInput'].Text = "" }
                if ($dlgControls['GridResolverResults']) { $dlgControls['GridResolverResults'].ItemsSource = $null }
            })
        }

        if ($dlgControls['BtnResolverAcl']) {
            $dlgControls['BtnResolverAcl'].Add_Click({
                $sel = $dlgControls['GridResolverResults'].SelectedItem
                if ($sel -and $sel.Details) {
                    $dlg.Close()
                    Show-Panel "SecurityAcl"
                    if ($controls['NavSecurityAcl']) { $controls['NavSecurityAcl'].IsChecked = $true }
                    if ($controls['TxtAclTargetDN']) {
                        $controls['TxtAclTargetDN'].Text = $sel.Details
                        if ($controls['BtnAclLoad']) { $controls['BtnAclLoad'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent)) }
                    }
                }
            })
        }

        if ($dlgControls['BtnResolverLockout']) {
            $dlgControls['BtnResolverLockout'].Add_Click({
                $sel = $dlgControls['GridResolverResults'].SelectedItem
                if ($sel) {
                    $dlg.Close()
                    Show-Panel "DiagnosticsToolbox"
                    if ($controls['NavDiagnosticsToolbox']) { $controls['NavDiagnosticsToolbox'].IsChecked = $true }
                    if ($controls['TxtLockoutTargetUser']) {
                        $controls['TxtLockoutTargetUser'].Text = $sel.InputTerm
                        if ($controls['BtnTraceLockout']) { $controls['BtnTraceLockout'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent)) }
                    }
                }
            })
        }

        if ($dlgControls['BtnResolverToken']) {
            $dlgControls['BtnResolverToken'].Add_Click({
                $sel = $dlgControls['GridResolverResults'].SelectedItem
                if ($sel) {
                    $dlg.Close()
                    Show-Panel "KerberosSuite"
                    if ($controls['NavKerberosSuite']) { $controls['NavKerberosSuite'].IsChecked = $true }
                    if ($controls['TxtTokenUser']) {
                        $controls['TxtTokenUser'].Text = $sel.InputTerm
                        if ($controls['BtnCalcTokenSize']) { $controls['BtnCalcTokenSize'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent)) }
                    }
                }
            })
        }

        if ($dlgControls['BtnCloseResolverDialog']) {
            $dlgControls['BtnCloseResolverDialog'].Add_Click({ $dlg.Close() })
        }

        if (-not [string]::IsNullOrWhiteSpace($InitialInput)) {
            & $resolveAction
        }

        [void]$dlg.ShowDialog()
    } catch {
        [System.Windows.MessageBox]::Show("Failed to open Resolver Scratchpad: $($_.Exception.Message)", "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
    }
}

function Show-DetachedGridDialog {
    param(
        $ItemsSource,
        [string]$Title = "Detached Grid Analysis"
    )
    try {
        $dlgPath = Join-Path $viewsPath "DetachedGridDialog.xaml"
        $dlg = Load-XamlWindow -XamlPath $dlgPath
        $dlg.Title = "$Title (Active Directory Studio)"

        $dlgControls = @{}
        $r = [System.Xml.XmlReader]::Create([System.IO.StringReader](Get-Content $dlgPath -Raw -Encoding UTF8))
        while ($r.Read()) {
            if ($r.NodeType -eq [System.Xml.XmlNodeType]::Element) {
                $name = $r.GetAttribute("Name")
                if (-not [string]::IsNullOrWhiteSpace($name)) {
                    $dlgControls[$name] = $dlg.FindName($name)
                }
            }
        }
        $r.Close()

        $rawList = @($ItemsSource)
        if ($dlgControls['GridDetachedData']) {
            $dlgControls['GridDetachedData'].ItemsSource = $rawList
        }
        if ($dlgControls['TxtDetachedCount']) {
            $dlgControls['TxtDetachedCount'].Text = "$($rawList.Count) items"
        }

        if ($dlgControls['TxtDetachedFilter']) {
            $dlgControls['TxtDetachedFilter'].Add_TextChanged({
                $term = $dlgControls['TxtDetachedFilter'].Text.Trim()
                if ([string]::IsNullOrWhiteSpace($term)) {
                    $dlgControls['GridDetachedData'].ItemsSource = $rawList
                    $dlgControls['TxtDetachedCount'].Text = "$($rawList.Count) items"
                } else {
                    $filtered = $rawList | Where-Object {
                        $row = $_
                        ($row.PSObject.Properties | ForEach-Object { $_.Value }) -join " " -match [regex]::Escape($term)
                    }
                    $fList = @($filtered)
                    $dlgControls['GridDetachedData'].ItemsSource = $fList
                    $dlgControls['TxtDetachedCount'].Text = "$($fList.Count) items"
                }
            })
        }

        if ($dlgControls['BtnExportCsvDetached']) {
            $dlgControls['BtnExportCsvDetached'].Add_Click({
                $saveDlg = New-Object System.Windows.Forms.SaveFileDialog
                $saveDlg.FileName = "Detached_Grid_$((Get-Date).ToString('yyyyMMdd_HHmm')).csv"
                $saveDlg.Filter = "CSV files (*.csv)|*.csv|All files (*.*)|*.*"
                if ($saveDlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                    $dataToExport = @($dlgControls['GridDetachedData'].ItemsSource)
                    $res = Export-ADDataToCsv -Data $dataToExport -FilePath $saveDlg.FileName -Delimiter ($appConfig.Defaults.ExportDelimiter)
                    if ($res.Success) {
                        [System.Windows.MessageBox]::Show($res.Message, "Export Successful", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
                    }
                }
            })
        }

        if ($dlgControls['BtnExportHtmlDetached']) {
            $dlgControls['BtnExportHtmlDetached'].Add_Click({
                $saveDlg = New-Object System.Windows.Forms.SaveFileDialog
                $saveDlg.FileName = "Detached_Grid_$((Get-Date).ToString('yyyyMMdd_HHmm')).html"
                $saveDlg.Filter = "HTML files (*.html)|*.html|All files (*.*)|*.*"
                if ($saveDlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                    $dataToExport = @($dlgControls['GridDetachedData'].ItemsSource)
                    $html = $dataToExport | ConvertTo-Html -Title $Title -CssUri "" | Out-String
                    [System.IO.File]::WriteAllText($saveDlg.FileName, $html, [System.Text.Encoding]::UTF8)
                    [System.Windows.MessageBox]::Show("HTML report saved successfully.", "Export Successful", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
                }
            })
        }

        if ($dlgControls['BtnCloseDetached']) {
            $dlgControls['BtnCloseDetached'].Add_Click({ $dlg.Close() })
        }

        $dlg.Show()
    } catch {
        [System.Windows.MessageBox]::Show("Failed to open detached grid: $($_.Exception.Message)", "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
    }
}

function Show-GpoExplorerDialog {
    try {
        $dlgPath = Join-Path $viewsPath "GpoExplorerDialog.xaml"
        $dlg = Load-XamlWindow -XamlPath $dlgPath
        $dlg.Owner = $window

        $dlgControls = @{}
        $r = [System.Xml.XmlReader]::Create([System.IO.StringReader](Get-Content $dlgPath -Raw -Encoding UTF8))
        while ($r.Read()) {
            if ($r.NodeType -eq [System.Xml.XmlNodeType]::Element) {
                $name = $r.GetAttribute("Name")
                if (-not [string]::IsNullOrWhiteSpace($name)) {
                    $dlgControls[$name] = $dlg.FindName($name)
                }
            }
        }
        $r.Close()

        $allGpos = [System.Collections.Generic.List[PSObject]]::new()

        $refreshGpos = {
            $gpos = Get-ADGpoHierarchy
            $allGpos.Clear()
            foreach ($g in $gpos) { $allGpos.Add($g) }
            if ($dlgControls['GridGpoHierarchy']) { $dlgControls['GridGpoHierarchy'].ItemsSource = $allGpos }
            if ($dlgControls['TxtGpoStatus']) { $dlgControls['TxtGpoStatus'].Text = "Loaded $($allGpos.Count) Group Policy Objects." }
            $wmi = Get-ADWmiFilters
            if ($dlgControls['GridWmiFilters']) { $dlgControls['GridWmiFilters'].ItemsSource = $wmi }
        }

        if ($dlgControls['TxtGpoFilter']) {
            $dlgControls['TxtGpoFilter'].Add_TextChanged({
                $term = $dlgControls['TxtGpoFilter'].Text.Trim()
                if ([string]::IsNullOrWhiteSpace($term)) {
                    if ($dlgControls['GridGpoHierarchy']) { $dlgControls['GridGpoHierarchy'].ItemsSource = $allGpos }
                } else {
                    $filtered = $allGpos | Where-Object { $_.DisplayName -match [regex]::Escape($term) -or $_.GpoId -match [regex]::Escape($term) }
                    if ($dlgControls['GridGpoHierarchy']) { $dlgControls['GridGpoHierarchy'].ItemsSource = @($filtered) }
                }
            })
        }

        if ($dlgControls['BtnGpoRefresh']) {
            $dlgControls['BtnGpoRefresh'].Add_Click({ & $refreshGpos })
        }

        if ($dlgControls['BtnBrowseRegistryPol']) {
            $dlgControls['BtnBrowseRegistryPol'].Add_Click({
                $openDlg = New-Object System.Windows.Forms.OpenFileDialog
                $openDlg.Filter = "Registry Pol files (Registry.pol)|Registry.pol|All files (*.*)|*.*"
                if ($openDlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                    if ($dlgControls['TxtRegistryPolPath']) { $dlgControls['TxtRegistryPolPath'].Text = $openDlg.FileName }
                    $entries = Read-GpoRegistryPol -PolFilePath $openDlg.FileName
                    if ($dlgControls['GridRegistryPol']) { $dlgControls['GridRegistryPol'].ItemsSource = $entries }
                }
            })
        }

        if ($dlgControls['BtnParseRegistryPol']) {
            $dlgControls['BtnParseRegistryPol'].Add_Click({
                $path = if ($dlgControls['TxtRegistryPolPath']) { $dlgControls['TxtRegistryPolPath'].Text.Trim() } else { "" }
                $entries = Read-GpoRegistryPol -PolFilePath $path
                if ($dlgControls['GridRegistryPol']) { $dlgControls['GridRegistryPol'].ItemsSource = $entries }
            })
        }

        if ($dlgControls['BtnAuditGpoReplication']) {
            $dlgControls['BtnAuditGpoReplication'].Add_Click({
                $audit = Test-GpoReplicationMultiDC
                if ($dlgControls['GridGpoMultiDc']) { $dlgControls['GridGpoMultiDc'].ItemsSource = $audit }
            })
        }

        if ($dlgControls['BtnGpoClose']) {
            $dlgControls['BtnGpoClose'].Add_Click({ $dlg.Close() })
        }

        & $refreshGpos
        [void]$dlg.ShowDialog()
    } catch {
        [System.Windows.MessageBox]::Show("Failed to open GPO Explorer: $($_.Exception.Message)", "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
    }
}

function Show-Asn1ViewerDialog {
    param([string]$InitialData = "")
    try {
        $dlgPath = Join-Path $viewsPath "Asn1ViewerDialog.xaml"
        $dlg = Load-XamlWindow -XamlPath $dlgPath
        $dlg.Owner = $window

        $dlgControls = @{}
        $r = [System.Xml.XmlReader]::Create([System.IO.StringReader](Get-Content $dlgPath -Raw -Encoding UTF8))
        while ($r.Read()) {
            if ($r.NodeType -eq [System.Xml.XmlNodeType]::Element) {
                $name = $r.GetAttribute("Name")
                if (-not [string]::IsNullOrWhiteSpace($name)) {
                    $dlgControls[$name] = $dlg.FindName($name)
                }
            }
        }
        $r.Close()

        if ($InitialData -and $dlgControls['TxtAsn1Input']) {
            $dlgControls['TxtAsn1Input'].Text = $InitialData
        }

        if ($dlgControls['BtnAsn1LoadSample']) {
            $dlgControls['BtnAsn1LoadSample'].Add_Click({
                if ($dlgControls['TxtAsn1Input']) {
                    $dlgControls['TxtAsn1Input'].Text = "30 29 02 01 01 04 06 63 6F 6D 6D 6F 6E A0 1C 02 04 64 65 65 70 02 01 00 02 01 00 04 0B 61 64 2D 73 74 75 64 69 6F 2D 64 63"
                }
            })
        }

        if ($dlgControls['BtnDecodeAsn1']) {
            $dlgControls['BtnDecodeAsn1'].Add_Click({
                $raw = if ($dlgControls['TxtAsn1Input']) { $dlgControls['TxtAsn1Input'].Text.Trim() } else { "" }
                if ([string]::IsNullOrWhiteSpace($raw)) { return }
                $res = Convert-ASN1Structure -InputData $raw
                if ($res) {
                    if ($dlgControls['GridAsn1Nodes']) { $dlgControls['GridAsn1Nodes'].ItemsSource = $res.Tree }
                    if ($dlgControls['TxtAsn1HexDump']) { $dlgControls['TxtAsn1HexDump'].Text = $res.HexDump }
                    if ($dlgControls['TxtAsn1Status']) { $dlgControls['TxtAsn1Status'].Text = "Decoded $($res.TotalElements) ASN.1 elements ($($res.TotalBytes) bytes parsed)." }
                }
            })
        }

        if ($dlgControls['BtnAsn1Close']) {
            $dlgControls['BtnAsn1Close'].Add_Click({ $dlg.Close() })
        }

        if ($InitialData) {
            $res = Convert-ASN1Structure -InputData $InitialData
            if ($res) {
                if ($dlgControls['GridAsn1Nodes']) { $dlgControls['GridAsn1Nodes'].ItemsSource = $res.Tree }
                if ($dlgControls['TxtAsn1HexDump']) { $dlgControls['TxtAsn1HexDump'].Text = $res.HexDump }
                if ($dlgControls['TxtAsn1Status']) { $dlgControls['TxtAsn1Status'].Text = "Decoded $($res.TotalElements) ASN.1 elements ($($res.TotalBytes) bytes parsed)." }
            }
        }

        [void]$dlg.ShowDialog()
    } catch {
        [System.Windows.MessageBox]::Show("Failed to open ASN.1 Viewer: $($_.Exception.Message)", "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
    }
}

function Show-CompareValuesDialog {
    param([string]$LeftValue = "", [string]$RightValue = "")
    try {
        $dlgPath = Join-Path $viewsPath "CompareValuesDialog.xaml"
        $dlg = Load-XamlWindow -XamlPath $dlgPath
        $dlg.Owner = $window

        $dlgControls = @{}
        $r = [System.Xml.XmlReader]::Create([System.IO.StringReader](Get-Content $dlgPath -Raw -Encoding UTF8))
        while ($r.Read()) {
            if ($r.NodeType -eq [System.Xml.XmlNodeType]::Element) {
                $name = $r.GetAttribute("Name")
                if (-not [string]::IsNullOrWhiteSpace($name)) {
                    $dlgControls[$name] = $dlg.FindName($name)
                }
            }
        }
        $r.Close()

        if ($LeftValue -and $dlgControls['TxtDiffLeftInput']) { $dlgControls['TxtDiffLeftInput'].Text = $LeftValue }
        if ($RightValue -and $dlgControls['TxtDiffRightInput']) { $dlgControls['TxtDiffRightInput'].Text = $RightValue }

        $runCompare = {
            $lText = if ($dlgControls['TxtDiffLeftInput']) { $dlgControls['TxtDiffLeftInput'].Text } else { "" }
            $rText = if ($dlgControls['TxtDiffRightInput']) { $dlgControls['TxtDiffRightInput'].Text } else { "" }
            $diffOnly = if ($dlgControls['ChkDiffDifferencesOnly']) { $dlgControls['ChkDiffDifferencesOnly'].IsChecked -eq $true } else { $false }
            
            $lLines = $lText -split "`r?`n"
            $rLines = $rText -split "`r?`n"
            $maxLen = [Math]::Max($lLines.Count, $rLines.Count)
            
            $rows = [System.Collections.Generic.List[PSObject]]::new()
            $diffCount = 0
            for ($i = 0; $i -lt $maxLen; $i++) {
                $lineNum = $i + 1
                $leftVal = if ($i -lt $lLines.Count) { $lLines[$i] } else { "" }
                $rightVal = if ($i -lt $rLines.Count) { $rLines[$i] } else { "" }
                $isMatch = ($leftVal -ceq $rightVal)
                $status = if ($isMatch) { "Identical" } elseif ([string]::IsNullOrEmpty($leftVal)) { "Added Right" } elseif ([string]::IsNullOrEmpty($rightVal)) { "Removed Right" } else { "Different" }
                if (-not $isMatch) { $diffCount++ }
                
                if (-not $diffOnly -or -not $isMatch) {
                    $rows.Add([PSCustomObject]@{
                        LineNumber = $lineNum
                        Status     = $status
                        LeftValue  = $leftVal
                        RightValue = $rightVal
                    })
                }
            }

            if ($dlgControls['GridValueDiff']) { $dlgControls['GridValueDiff'].ItemsSource = $rows }
            if ($dlgControls['TxtDiffSummaryStats']) { $dlgControls['TxtDiffSummaryStats'].Text = "Lines: $maxLen | Differences: $diffCount" }
            if ($dlgControls['TxtDiffStatus']) { $dlgControls['TxtDiffStatus'].Text = if ($diffCount -eq 0) { "Values are 100% identical." } else { "Found $diffCount differing lines." } }
        }

        if ($dlgControls['BtnDiffCompare']) {
            $dlgControls['BtnDiffCompare'].Add_Click({ & $runCompare })
        }

        if ($dlgControls['BtnDiffClose']) {
            $dlgControls['BtnDiffClose'].Add_Click({ $dlg.Close() })
        }

        if ($LeftValue -or $RightValue) {
            & $runCompare
        }

        [void]$dlg.ShowDialog()
    } catch {
        [System.Windows.MessageBox]::Show("Failed to open Diff Viewer: $($_.Exception.Message)", "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
    }
}

# --- 19. Access Control & ACL Suite Handlers ---
function Init-SecurityAclUI {
    if ($controls['TxtAclTargetDN'] -and [string]::IsNullOrWhiteSpace($controls['TxtAclTargetDN'].Text)) {
        $controls['TxtAclTargetDN'].Text = if ($adContext.DefaultNamingContext) { $adContext.DefaultNamingContext } else { "DC=corp,DC=local" }
    }
    if ($controls['TxtAclTrustee'] -and [string]::IsNullOrWhiteSpace($controls['TxtAclTrustee'].Text)) {
        $controls['TxtAclTrustee'].Text = "Domain Admins"
    }
    if ($controls['CmbDelegationScope'] -and $controls['CmbDelegationScope'].ItemsSource -eq $null) {
        $controls['CmbDelegationScope'].Items.Clear()
        $cat = Get-ADDelegationReportsCatalog
        $scopeList = [System.Collections.Generic.List[string]]::new()
        [void]$scopeList.Add("All Sensitive Delegations")
        if ($cat) {
            foreach ($c in $cat) {
                if ($c.Name -and -not $scopeList.Contains($c.Name)) {
                    [void]$scopeList.Add($c.Name)
                }
            }
        }
        $controls['CmbDelegationScope'].ItemsSource = @($scopeList)
        $controls['CmbDelegationScope'].SelectedIndex = 0
    }
}

if ($controls['BtnSecLaunchDialog']) {
    $controls['BtnSecLaunchDialog'].Add_Click({
        $dn = if ($controls['TxtAclTargetDN']) { $controls['TxtAclTargetDN'].Text.Trim() } else { "" }
        Show-AclBrowserDialog -TargetDN $dn
    })
}

if ($controls['BtnAclLoad']) {
    $controls['BtnAclLoad'].Add_Click({
        $target = if ($controls['TxtAclTargetDN']) { $controls['TxtAclTargetDN'].Text.Trim() } else { "" }
        if ([string]::IsNullOrWhiteSpace($target)) {
            [System.Windows.MessageBox]::Show("Please enter a valid target object Distinguished Name or username.", "Target Required", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            return
        }
        Set-Status -Message "Inspecting security descriptor for $target..."
        $aclRes = Get-ADObjectAcl -Identity $target
        if ($aclRes) {
            if ($controls['TxtAclOwner']) { $controls['TxtAclOwner'].Text = $aclRes.Owner }
            if ($controls['TxtAclGroup']) { $controls['TxtAclGroup'].Text = $aclRes.Group }
            if ($controls['TxtAclInheritance']) {
                $controls['TxtAclInheritance'].Text = if ($aclRes.InheritanceBlocked) { "Blocked (Explicit Only)" } else { "Enabled (Inherits from Parent)" }
            }
            $state.CurrentAclSddl = $aclRes.Sddl
            if ($controls['GridAclAces']) { $controls['GridAclAces'].ItemsSource = $aclRes.Dacl }
            Set-Status -Message "Security descriptor loaded ($($aclRes.Dacl.Count) DACL ACEs)."
        }
    })
}

if ($controls['BtnAclCopySddl']) {
    $controls['BtnAclCopySddl'].Add_Click({
        if ($state.CurrentAclSddl) {
            [System.Windows.Clipboard]::SetText($state.CurrentAclSddl)
            [System.Windows.MessageBox]::Show("SDDL string copied to clipboard.", "SDDL Copied", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        } else {
            [System.Windows.MessageBox]::Show("No SDDL string loaded yet. Inspect an object first.", "Information", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        }
    })
}

if ($controls['BtnAclCalcEffective']) {
    $controls['BtnAclCalcEffective'].Add_Click({
        $target = if ($controls['TxtAclTargetDN']) { $controls['TxtAclTargetDN'].Text.Trim() } else { "" }
        $trustee = if ($controls['TxtAclTrustee']) { $controls['TxtAclTrustee'].Text.Trim() } else { "" }
        if ([string]::IsNullOrWhiteSpace($target) -or [string]::IsNullOrWhiteSpace($trustee)) {
            [System.Windows.MessageBox]::Show("Please specify both a target object and a trustee.", "Parameters Required", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            return
        }
        Set-Status -Message "Calculating effective permissions for $trustee on $target..."
        $effRes = Get-ADEffectivePermissions -Identity $target -Trustee $trustee
        if ($effRes) {
            if ($controls['GridAclEffective']) { $controls['GridAclEffective'].ItemsSource = $effRes.Permissions }
            if ($controls['TxtEffectiveStatus']) {
                $controls['TxtEffectiveStatus'].Text = "Trustee: $($effRes.Trustee) | $($effRes.GrantedCount) Granted, $($effRes.DeniedCount) Denied"
            }
            Set-Status -Message "Effective permissions computed for $trustee."
        }
    })
}

if ($controls['BtnScanAdminSdHolder']) {
    $controls['BtnScanAdminSdHolder'].Add_Click({
        Set-Status -Message "Scanning domain for AdminSDHolder protected orphans..."
        $orphans = Find-AdminSDHolderOrphans
        if ($controls['GridAdminSdOrphans']) {
            $controls['GridAdminSdOrphans'].ItemsSource = $orphans
        }
        Set-Status -Message "AdminSDHolder scan complete. Found $($orphans.Count) orphan accounts."
    })
}

if ($controls['BtnFixAdminSdHolder']) {
    $controls['BtnFixAdminSdHolder'].Add_Click({
        $sel = if ($controls['GridAdminSdOrphans']) { $controls['GridAdminSdOrphans'].SelectedItem } else { $null }
        if (-not $sel) {
            [System.Windows.MessageBox]::Show("Please select an orphan account from the grid to remediate.", "Select Orphan", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            return
        }
        $confirm = [System.Windows.MessageBox]::Show("Reset adminCount to 0 and re-enable ACL inheritance for '$($sel.Name)'?", "Confirm Remediation", [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Question)
        if ($confirm -eq [System.Windows.MessageBoxResult]::Yes) {
            $fixRes = Reset-AdminSDHolderOrphan -Identity $sel.DistinguishedName
            if ($fixRes.Success) {
                [System.Windows.MessageBox]::Show($fixRes.Message, "Remediation Successful", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
                if ($controls['BtnScanAdminSdHolder']) { $controls['BtnScanAdminSdHolder'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent)) }
            } else {
                [System.Windows.MessageBox]::Show($fixRes.Message, "Remediation Failed", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
            }
        }
    })
}

if ($controls['BtnRunDelegationReport']) {
    $controls['BtnRunDelegationReport'].Add_Click({
        $scope = if ($controls['CmbDelegationScope']) {
            if ($controls['CmbDelegationScope'].SelectedItem -is [System.Windows.Controls.ComboBoxItem]) {
                $controls['CmbDelegationScope'].SelectedItem.Content.ToString()
            } elseif ($controls['CmbDelegationScope'].SelectedItem) {
                $controls['CmbDelegationScope'].SelectedItem.ToString()
            } elseif ($controls['CmbDelegationScope'].Text) {
                $controls['CmbDelegationScope'].Text
            } else { "All Sensitive Delegations" }
        } else { "All Sensitive Delegations" }
        Set-Status -Message "Generating delegation report for scope: $scope..."
        $rep = Get-ADDelegationReport -Scope $scope
        if ($controls['GridDelegationReport']) { $controls['GridDelegationReport'].ItemsSource = $rep }
        Set-Status -Message "Delegation report complete: $($rep.Count) entries located."
    })
}

if ($controls['BtnExportDelegationReport']) {
    $controls['BtnExportDelegationReport'].Add_Click({
        $saveDlg = New-Object System.Windows.Forms.SaveFileDialog
        $saveDlg.FileName = "Delegation_Report_$((Get-Date).ToString('yyyyMMdd_HHmm')).csv"
        $saveDlg.Filter = "CSV files (*.csv)|*.csv|All files (*.*)|*.*"
        if ($saveDlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $dataToExport = @($controls['GridDelegationReport'].ItemsSource)
            $res = Export-ADDataToCsv -Data $dataToExport -FilePath $saveDlg.FileName -Delimiter ($appConfig.Defaults.ExportDelimiter)
            if ($res.Success) {
                [System.Windows.MessageBox]::Show($res.Message, "Export Successful", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            }
        }
    })
}

if ($controls['BtnAclListUsers']) {
    $controls['BtnAclListUsers'].Add_Click({
        $trustee = if ($controls['TxtAclTrustee']) { $controls['TxtAclTrustee'].Text.Trim() } else { "" }
        if ([string]::IsNullOrWhiteSpace($trustee)) {
            [System.Windows.MessageBox]::Show("Please enter a trustee group or principal name to expand.", "Trustee Required", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            return
        }
        Set-Status -Message "Expanding recursive members for trustee '$trustee'..."
        $members = Expand-ADTrusteeMembers -Trustee $trustee
        if ($controls['GridAclEffective']) {
            $controls['GridAclEffective'].ItemsSource = $members
        }
        if ($controls['TxtEffectiveStatus']) {
            $controls['TxtEffectiveStatus'].Text = "Trustee '$trustee' resolved to $($members.Count) recursive member principals."
        }
        Set-Status -Message "Trustee members resolved ($($members.Count) members)."
    })
}

if ($controls['BtnRunAclCompare']) {
    $controls['BtnRunAclCompare'].Add_Click({
        $src = if ($controls['TxtAclCompareObjA']) { $controls['TxtAclCompareObjA'].Text.Trim() } else { "" }
        $tgt = if ($controls['TxtAclCompareObjB']) { $controls['TxtAclCompareObjB'].Text.Trim() } else { "" }
        if ([string]::IsNullOrWhiteSpace($src) -or [string]::IsNullOrWhiteSpace($tgt)) {
            [System.Windows.MessageBox]::Show("Please enter both Object A and Object B distinguished names or account names to compare.", "Objects Required", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            return
        }
        Set-Status -Message "Comparing ACLs between '$src' and '$tgt'..."
        $comp = Compare-ADPermissions -SourceIdentity $src -TargetIdentity $tgt
        if ($comp) {
            if ($controls['GridAclCompare']) { $controls['GridAclCompare'].ItemsSource = $comp.Entries }
            Set-Status -Message "ACL compare complete: $($comp.Entries.Count) permission comparisons evaluated."
        }
    })
}

if ($controls['BtnLoadExtRights']) {
    $controls['BtnLoadExtRights'].Add_Click({
        Set-Status -Message "Querying Extended Rights and Control Access Rights from Configuration Naming Context..."
        $rights = Get-ADControlAccessRights
        if ($controls['GridExtRights']) { $controls['GridExtRights'].ItemsSource = $rights }
        Set-Status -Message "Extended Rights loaded ($($rights.Count) rights)."
    })
}

if ($controls['BtnSearchPropSets']) {
    $controls['BtnSearchPropSets'].Add_Click({
        $filter = if ($controls['TxtPropSetFilter']) { $controls['TxtPropSetFilter'].Text.Trim() } else { "" }
        Set-Status -Message "Searching property sets in AD schema..."
        $props = Find-ADPropertySet -PropertyOrSetName $filter
        if ($controls['GridPropSets']) { $controls['GridPropSets'].ItemsSource = $props }
        Set-Status -Message "Property sets search completed ($($props.Count) sets located)."
    })
}

# --- 20. Kerberos & Authentication Suite Handlers ---
function Refresh-KerberosTickets {
    Set-Status -Message "Querying LSA Kerberos ticket cache..."
    $tickets = Get-KerberosTicketCache
    if ($controls['GridKerberosTickets']) { $controls['GridKerberosTickets'].ItemsSource = $tickets }
    if ($controls['TxtTicketCacheSummary']) {
        $controls['TxtTicketCacheSummary'].Text = "Cached tickets: $($tickets.Count) active tickets in Kerberos LSA session cache."
    }
    Set-Status -Message "Kerberos ticket cache refreshed ($($tickets.Count) tickets)."
}

if ($controls['BtnRefreshTickets']) {
    $controls['BtnRefreshTickets'].Add_Click({ Refresh-KerberosTickets })
}

if ($controls['BtnPurgeTickets']) {
    $controls['BtnPurgeTickets'].Add_Click({
        $confirm = [System.Windows.MessageBox]::Show("Purge all cached Kerberos tickets for current session? (Equivalent to 'klist purge')", "Confirm Purge", [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Warning)
        if ($confirm -eq [System.Windows.MessageBoxResult]::Yes) {
            Clear-KerberosTicketCache
            Refresh-KerberosTickets
            [System.Windows.MessageBox]::Show("Kerberos ticket cache purged.", "Purged", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        }
    })
}

if ($controls['BtnTestSpnTicket']) {
    $controls['BtnTestSpnTicket'].Add_Click({
        $spn = if ($controls['TxtTestSpn']) { $controls['TxtTestSpn'].Text.Trim() } else { "" }
        if ([string]::IsNullOrWhiteSpace($spn)) {
            [System.Windows.MessageBox]::Show("Please enter an SPN to test (e.g. HOST/dc1.corp.local).", "SPN Required", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            return
        }
        Set-Status -Message "Requesting Kerberos ticket for SPN $spn..."
        $res = Test-KerberosSpnTicket -Spn $spn
        if ($controls['TxtTestSpnResult']) {
            $controls['TxtTestSpnResult'].Text = "Status: $($res.Status) | Enc: $($res.EncryptionType) | Latency: $($res.Latency) | $($res.Message)"
        }
        Set-Status -Message "SPN ticket test: $($res.Status)."
    })
}

if ($controls['BtnCalcTokenSize']) {
    $controls['BtnCalcTokenSize'].Add_Click({
        $user = if ($controls['TxtTokenUser']) { $controls['TxtTokenUser'].Text.Trim() } else { "" }
        if ([string]::IsNullOrWhiteSpace($user)) {
            [System.Windows.MessageBox]::Show("Please enter a username or DN to calculate token size.", "User Required", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            return
        }
        Set-Status -Message "Calculating access token PAC size for $user..."
        $tRes = Measure-ADUserTokenSize -Identity $user
        if ($tRes) {
            if ($controls['TxtTokenSizeBytes']) { $controls['TxtTokenSizeBytes'].Text = "$($tRes.EstimatedTokenSizeBytes.ToString('N0')) Bytes" }
            if ($controls['TxtTokenDomainGroups']) { $controls['TxtTokenDomainGroups'].Text = $tRes.DomainGroupCount.ToString() }
            if ($controls['TxtTokenExtraSids']) { $controls['TxtTokenExtraSids'].Text = $tRes.SidHistoryCount.ToString() }
            if ($controls['TxtTokenRiskBadge']) {
                $controls['TxtTokenRiskBadge'].Text = $tRes.RiskLevel
                $riskColor = if ($tRes.RiskLevel -match 'Critical') { "#EF4444" } elseif ($tRes.RiskLevel -match 'Elevated') { "#F59E0B" } else { "#10B981" }
                $controls['TxtTokenRiskBadge'].Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString($riskColor)
            }
            if ($controls['GridTokenGroups']) { $controls['GridTokenGroups'].ItemsSource = $tRes.ContributingGroups }
            Set-Status -Message "Token PAC calculated: $($tRes.EstimatedTokenSizeBytes) Bytes ($($tRes.RiskLevel))."
        }
    })
}

if ($controls['BtnRefreshRidPool']) {
    $controls['BtnRefreshRidPool'].Add_Click({
        Set-Status -Message "Querying RID Master pool allocation..."
        $rids = Get-ADRidPoolStatus
        if ($controls['GridRidPool']) { $controls['GridRidPool'].ItemsSource = $rids }
        Set-Status -Message "RID pool allocation refreshed."
    })
}

# --- 21. Replication & Topology Suite Handlers ---
function Refresh-ReplicationTopology {
    Set-Status -Message "Refreshing Active Directory Sites topology..."
    $sites = Get-ADSitesTopology
    if ($controls['BtnScanSubnetOverlaps']) {
        $controls['BtnScanSubnetOverlaps'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
    }
}

if ($controls['BtnRefreshReplicationSuite']) {
    $controls['BtnRefreshReplicationSuite'].Add_Click({ Refresh-ReplicationTopology })
}

if ($controls['BtnScanMultiDcLogon']) {
    $controls['BtnScanMultiDcLogon'].Add_Click({
        $target = if ($controls['TxtMultiDcTarget']) { $controls['TxtMultiDcTarget'].Text.Trim() } else { "" }
        if ([string]::IsNullOrWhiteSpace($target)) {
            [System.Windows.MessageBox]::Show("Please enter a username or computer name to scan across DCs.", "Target Required", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            return
        }
        Set-Status -Message "Querying all domain controllers for real-time lastLogon for $target..."
        $res = Get-ADMultiDCRealTimeLastLogon -Identity $target
        if ($res) {
            if ($controls['GridMultiDcLogon']) { $controls['GridMultiDcLogon'].ItemsSource = $res.DCResults }
            if ($controls['TxtMultiDcConsensus']) {
                $controls['TxtMultiDcConsensus'].Text = "Most recent logon consensus: $($res.ConsensusLastLogon) | Originating DC: $($res.OriginatingDC) ($($res.DCResults.Count) DCs scanned)"
            }
            Set-Status -Message "Multi-DC logon scan complete for $target."
        }
    })
}

if ($controls['BtnScanSubnetOverlaps']) {
    $controls['BtnScanSubnetOverlaps'].Add_Click({
        Set-Status -Message "Auditing AD subnet boundaries for conflicts and overlaps..."
        $subs = Test-ADSubnetOverlap
        if ($controls['GridSubnetOverlaps']) { $controls['GridSubnetOverlaps'].ItemsSource = $subs }
        Set-Status -Message "Subnet boundary audit complete: $($subs.Count) subnets analyzed."
    })
}

if ($controls['BtnExportSubnets']) {
    $controls['BtnExportSubnets'].Add_Click({
        $saveDlg = New-Object System.Windows.Forms.SaveFileDialog
        $saveDlg.FileName = "AD_Subnets_$((Get-Date).ToString('yyyyMMdd_HHmm')).csv"
        $saveDlg.Filter = "CSV files (*.csv)|*.csv|All files (*.*)|*.*"
        if ($saveDlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $dataToExport = @($controls['GridSubnetOverlaps'].ItemsSource)
            $res = Export-ADDataToCsv -Data $dataToExport -FilePath $saveDlg.FileName -Delimiter ($appConfig.Defaults.ExportDelimiter)
            if ($res.Success) {
                [System.Windows.MessageBox]::Show($res.Message, "Export Successful", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            }
        }
    })
}

if ($controls['BtnCheckGpoSync']) {
    $controls['BtnCheckGpoSync'].Add_Click({
        Set-Status -Message "Auditing GPO Active Directory vs SYSVOL GPT.ini version consistency..."
        $gpos = Test-GpoReplicationConsistency
        if ($controls['GridGpoSync']) { $controls['GridGpoSync'].ItemsSource = $gpos }
        Set-Status -Message "GPO consistency audit complete: $($gpos.Count) policies checked."
    })
}

if ($controls['BtnGetReplMetadata']) {
    $controls['BtnGetReplMetadata'].Add_Click({
        $target = if ($controls['TxtReplMetaTarget']) { $controls['TxtReplMetaTarget'].Text.Trim() } else { "" }
        if ([string]::IsNullOrWhiteSpace($target)) {
            [System.Windows.MessageBox]::Show("Please enter a target object DN to inspect replication attribute metadata.", "DN Required", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            return
        }
        Set-Status -Message "Fetching msDS-ReplAttributeMetaData for $target..."
        $meta = Get-ADReplicationAttributeMetadata -Identity $target
        if ($controls['GridReplMetadata']) { $controls['GridReplMetadata'].ItemsSource = $meta }
        Set-Status -Message "Replication metadata loaded ($($meta.Count) attributes)."
    })
}

if ($controls['BtnLoadSiteBrowser']) {
    $controls['BtnLoadSiteBrowser'].Add_Click({
        Set-Status -Message "Querying 3-branch site hierarchy (Sites, Site Links, Subnets)..."
        $siteData = Get-ADSiteBrowserData
        if ($siteData) {
            if ($controls['GridSites']) { $controls['GridSites'].ItemsSource = $siteData.Sites }
            if ($controls['GridSiteLinks']) { $controls['GridSiteLinks'].ItemsSource = $siteData.SiteLinks }
            if ($controls['GridSubnets']) { $controls['GridSubnets'].ItemsSource = $siteData.Subnets }
            Set-Status -Message "Site browser topology loaded ($($siteData.Sites.Count) sites, $($siteData.SiteLinks.Count) links, $($siteData.Subnets.Count) subnets)."
        }
    })
}

if ($controls['BtnRunLatencyProbe']) {
    $controls['BtnRunLatencyProbe'].Add_Click({
        Set-Status -Message "Running cross-DC replication latency convergence probe..."
        $probe = Test-ADReplicationLatencyProbe
        if ($probe) {
            if ($controls['GridLatencyProbe']) { $controls['GridLatencyProbe'].ItemsSource = $probe.DCResults }
            Set-Status -Message "Latency probe complete: $($probe.StatusBadge) - $($probe.Summary)"
        }
    })
}

if ($controls['BtnLoadSchemaMatrix']) {
    $controls['BtnLoadSchemaMatrix'].Add_Click({
        Set-Status -Message "Evaluating schema versions matrix and forest convergence..."
        $matrix = Get-ADSchemaVersionsMatrix
        if ($matrix) {
            if ($controls['GridSchemaConvergence']) { $controls['GridSchemaConvergence'].ItemsSource = $matrix.DCConvergence }
            Set-Status -Message "Schema Matrix: Forest Schema v$($matrix.ForestSchemaVersion) ($($matrix.ForestOSRelease)), Domain Functional: $($matrix.DomainFunctionalLevel)"
        }
    })
}

# --- 22. Diagnostics & Advanced Utilities Handlers ---
if ($controls['BtnDiagOpenResolver']) {
    $controls['BtnDiagOpenResolver'].Add_Click({ Show-ResolverDialog })
}

if ($controls['BtnScanCircularGroups']) {
    $controls['BtnScanCircularGroups'].Add_Click({
        Set-Status -Message "Scanning domain group hierarchies for circular reference cycles..."
        $cycles = Find-CircularGroupReferences
        if ($controls['GridCircularGroups']) { $controls['GridCircularGroups'].ItemsSource = $cycles }
        Set-Status -Message "Cycle scan finished. $($cycles.Count) cyclic loops identified."
    })
}

if ($controls['BtnCompareUserGroups']) {
    $controls['BtnCompareUserGroups'].Add_Click({
        $uA = if ($controls['TxtDiffUserA']) { $controls['TxtDiffUserA'].Text.Trim() } else { "" }
        $uB = if ($controls['TxtDiffUserB']) { $controls['TxtDiffUserB'].Text.Trim() } else { "" }
        if ([string]::IsNullOrWhiteSpace($uA) -or [string]::IsNullOrWhiteSpace($uB)) {
            [System.Windows.MessageBox]::Show("Please specify both User A and User B to compare.", "Users Required", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            return
        }
        Set-Status -Message "Comparing group memberships between $uA and $uB..."
        $diff = Compare-ADUserGroupMemberships -UserA $uA -UserB $uB
        if ($diff) {
            if ($controls['TxtDiffSummary']) {
                $controls['TxtDiffSummary'].Text = "Unique to ${uA}: $($diff.UniqueToUserACount) | Common Memberships: $($diff.CommonCount) | Unique to ${uB}: $($diff.UniqueToUserBCount)"
            }
            if ($controls['GridDiffResults']) { $controls['GridDiffResults'].ItemsSource = $diff.ComparisonRows }
            Set-Status -Message "Group diff complete: $($diff.ComparisonRows.Count) groups evaluated."
        }
    })
}

if ($controls['BtnTraceLockout']) {
    $controls['BtnTraceLockout'].Add_Click({
        $user = if ($controls['TxtLockoutTargetUser']) { $controls['TxtLockoutTargetUser'].Text.Trim() } else { "" }
        if ([string]::IsNullOrWhiteSpace($user)) {
            [System.Windows.MessageBox]::Show("Please specify a target username to investigate lockout.", "Username Required", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            return
        }
        Set-Status -Message "Tracing lockout and Event 4740 for $user across all domain controllers..."
        $lockRes = Find-ADAccountLockoutSource -Identity $user
        if ($lockRes) {
            if ($controls['TxtLockoutStateBadge']) {
                $controls['TxtLockoutStateBadge'].Text = if ($lockRes.IsLocked) { "LOCKED OUT" } else { "NOT LOCKED (ACTIVE)" }
                $lockColor = if ($lockRes.IsLocked) { "#EF4444" } else { "#10B981" }
                $controls['TxtLockoutStateBadge'].Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString($lockColor)
            }
            if ($controls['TxtLockoutDetails']) {
                $controls['TxtLockoutDetails'].Text = "Bad Password Attempts: $($lockRes.BadPasswordAttempts) | Lockout Time: $($lockRes.LockoutTime)"
            }
            if ($controls['TxtLockoutCallerHost']) {
                $controls['TxtLockoutCallerHost'].Text = if ($lockRes.CallerWorkstation) { "Host: $($lockRes.CallerWorkstation)" } else { "-- Workstation Not Logged --" }
            }
            if ($controls['TxtLockoutCallerIp']) {
                $controls['TxtLockoutCallerIp'].Text = "IP: $($lockRes.CallerIP) | Timestamp: $($lockRes.EventTime)"
            }
            if ($controls['GridLockoutDcs']) { $controls['GridLockoutDcs'].ItemsSource = $lockRes.DCSummary }
            Set-Status -Message "Lockout investigation complete for $user."
        }
    })
}

if ($controls['BtnUnlockUserAllDCs']) {
    $controls['BtnUnlockUserAllDCs'].Add_Click({
        $user = if ($controls['TxtLockoutTargetUser']) { $controls['TxtLockoutTargetUser'].Text.Trim() } else { "" }
        if ([string]::IsNullOrWhiteSpace($user)) {
            [System.Windows.MessageBox]::Show("Please specify a target username to unlock.", "Username Required", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            return
        }
        $confirm = [System.Windows.MessageBox]::Show("Unlock account '$user' across all domain controllers?", "Confirm Unlock", [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Question)
        if ($confirm -eq [System.Windows.MessageBoxResult]::Yes) {
            $unlRes = Unlock-ADUserAcrossDCs -Identity $user
            if ($unlRes.Success) {
                [System.Windows.MessageBox]::Show($unlRes.Message, "Account Unlocked", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
                if ($controls['BtnTraceLockout']) { $controls['BtnTraceLockout'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent)) }
            } else {
                [System.Windows.MessageBox]::Show($unlRes.Message, "Unlock Failed", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
            }
        }
    })
}

if ($controls['BtnDecodeErrorCode']) {
    $controls['BtnDecodeErrorCode'].Add_Click({
        $code = if ($controls['TxtErrorCodeInput']) { $controls['TxtErrorCodeInput'].Text.Trim() } else { "" }
        $cat = if ($controls['CmbErrorCodeType']) { $controls['CmbErrorCodeType'].Text } else { "Auto-Detect" }
        if ([string]::IsNullOrWhiteSpace($code)) { return }
        $dec = Resolve-ADErrorCode -ErrorCode $code -Category $cat
        if ($controls['TxtErrorDecodeOutput']) {
            $controls['TxtErrorDecodeOutput'].Text = "Symbolic Name: $($dec.SymbolicName)`r`nHex Code:      $($dec.HexCode)`r`nDecimal:       $($dec.DecimalCode)`r`nCategory:      $($dec.Category)`r`nDescription:   $($dec.Description)"
        }
    })
}

if ($controls['BtnConvertTimestamp']) {
    $controls['BtnConvertTimestamp'].Add_Click({
        $val = if ($controls['TxtTimestampInput']) { $controls['TxtTimestampInput'].Text.Trim() } else { "" }
        $fmt = if ($controls['CmbTimestampFormat']) { $controls['CmbTimestampFormat'].Text } else { "Auto-Detect" }
        if ([string]::IsNullOrWhiteSpace($val)) { return }
        $timeRes = Convert-ADTimestamp -Value $val -Format $fmt
        if ($controls['TxtTimestampOutput']) {
            $controls['TxtTimestampOutput'].Text = "UTC Time:   $($timeRes.UtcTime)`r`nLocal Time: $($timeRes.LocalTime)`r`nElapsed:    $($timeRes.AgeDescription)`r`nDetected:   $($timeRes.DetectedFormat)"
        }
    })
}

if ($controls['BtnScanGroupChanges']) {
    $controls['BtnScanGroupChanges'].Add_Click({
        $u = if ($controls['TxtGroupChangesUser']) { $controls['TxtGroupChangesUser'].Text.Trim() } else { "" }
        if ([string]::IsNullOrWhiteSpace($u)) {
            [System.Windows.MessageBox]::Show("Please enter a username or DN to analyze group membership metadata.", "User Required", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            return
        }
        Set-Status -Message "Reading msDS-ReplValueMetaData for group membership forensic history on '$u'..."
        $hist = Find-ADUserGroupChanges -Identity $u
        if ($hist) {
            if ($controls['GridGroupChanges']) { $controls['GridGroupChanges'].ItemsSource = $hist }
            Set-Status -Message "Group forensics complete: $($hist.Count) additions/removals discovered."
        }
    })
}

if ($controls['BtnEvalPso']) {
    $controls['BtnEvalPso'].Add_Click({
        $u = if ($controls['TxtPsoUser']) { $controls['TxtPsoUser'].Text.Trim() } else { "" }
        if ([string]::IsNullOrWhiteSpace($u)) {
            [System.Windows.MessageBox]::Show("Please enter a username or DN to compute resultant PSO.", "User Required", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            return
        }
        Set-Status -Message "Evaluating resultant Fine-Grained Password Policy (PSO) for '$u'..."
        $pso = Get-ADResultantPSO -Identity $u
        if ($pso) {
            if ($controls['TxtPsoResultPolicy']) { $controls['TxtPsoResultPolicy'].Text = $pso.PolicyName }
            if ($controls['TxtPsoResultPrecedence']) { $controls['TxtPsoResultPrecedence'].Text = $pso.Precedence.ToString() }
            if ($controls['TxtPsoMinLength']) { $controls['TxtPsoMinLength'].Text = "$($pso.MinPasswordLength) chars" }
            if ($controls['TxtPsoLockout']) { $controls['TxtPsoLockout'].Text = "$($pso.LockoutThreshold) attempts" }
            if ($controls['TxtPsoSummaryBadge']) { $controls['TxtPsoSummaryBadge'].Text = $pso.PrecedenceBadge }
            Set-Status -Message "Resultant PSO computed for '$u': $($pso.PolicyName) (Precedence $($pso.Precedence))."
        }
    })
}

if ($controls['BtnQuerySessions']) {
    $controls['BtnQuerySessions'].Add_Click({
        Set-Status -Message "Querying active and disconnected logon sessions and terminal services..."
        $sess = Get-LocalLogonSessions
        if ($sess) {
            if ($controls['GridSessions']) { $controls['GridSessions'].ItemsSource = $sess }
            Set-Status -Message "Session query complete: $($sess.Count) logon sessions identified."
        }
    })
}

# --- 23. Network Diagnostics & Connectivity Suite Handlers ---
function Init-NetworkDiagnosticsUI {
    if ($controls['TxtDcScanHost'] -and [string]::IsNullOrWhiteSpace($controls['TxtDcScanHost'].Text)) {
        $controls['TxtDcScanHost'].Text = if ($adContext.DomainController) { $adContext.DomainController } else { "dc1.corp.local" }
    }
    if ($controls['TxtUncPathInput'] -and [string]::IsNullOrWhiteSpace($controls['TxtUncPathInput'].Text)) {
        $domain = if ($adContext.Domain) { $adContext.Domain } else { "corp.local" }
        $controls['TxtUncPathInput'].Text = "\\$domain\sysvol"
    }
    if ($controls['TxtCertUrlInput'] -and [string]::IsNullOrWhiteSpace($controls['TxtCertUrlInput'].Text)) {
        $controls['TxtCertUrlInput'].Text = if ($adContext.DomainController) { $adContext.DomainController } else { "dc1.corp.local" }
    }
}

if ($controls['BtnRunUncTest']) {
    $controls['BtnRunUncTest'].Add_Click({
        $unc = if ($controls['TxtUncPathInput']) { $controls['TxtUncPathInput'].Text.Trim() } else { "" }
        if ([string]::IsNullOrWhiteSpace($unc)) {
            [System.Windows.MessageBox]::Show("Please enter a UNC path to test (e.g. \\domain.com\sysvol).", "Path Required", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            return
        }
        Set-Status -Message "Running 7-step diagnostics on UNC path $unc..."
        $res = Test-ADUncPath -UncPath $unc
        if ($res) {
            if ($controls['GridUncResults']) { $controls['GridUncResults'].ItemsSource = $res.Steps }
            Set-Status -Message "UNC Check Verdict: $($res.OverallVerdict) (Latency: $($res.TotalLatencyMs) ms)."
        }
    })
}

if ($controls['BtnCheckCert']) {
    $controls['BtnCheckCert'].Add_Click({
        $hostName = if ($controls['TxtCertUrlInput']) { $controls['TxtCertUrlInput'].Text.Trim() } else { "" }
        if ([string]::IsNullOrWhiteSpace($hostName)) {
            [System.Windows.MessageBox]::Show("Please enter a hostname or URL to inspect SSL/TLS certificate.", "Host Required", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            return
        }
        Set-Status -Message "Testing SSL/TLS certificate and checking CRL/OCSP revocation for $hostName..."
        $certRes = Test-WebsiteCertificate -HostName $hostName
        if ($certRes) {
            if ($controls['GridCertResults']) { $controls['GridCertResults'].ItemsSource = $certRes.CertChain }
            Set-Status -Message "Certificate Check: Status: $($certRes.Status) | Revocation: $($certRes.RevocationStatus) | Issuer: $($certRes.Issuer)"
        }
    })
}

if ($controls['BtnRunDcPortScan']) {
    $controls['BtnRunDcPortScan'].Add_Click({
        $dcHost = if ($controls['TxtDcScanHost']) { $controls['TxtDcScanHost'].Text.Trim() } else { "" }
        $prof = if ($controls['CmbDcScanProfile']) {
            if ($controls['CmbDcScanProfile'].SelectedItem -is [System.Windows.Controls.ComboBoxItem]) {
                $controls['CmbDcScanProfile'].SelectedItem.Content.ToString()
            } elseif ($controls['CmbDcScanProfile'].SelectedItem) {
                $controls['CmbDcScanProfile'].SelectedItem.ToString()
            } elseif ($controls['CmbDcScanProfile'].Text) {
                $controls['CmbDcScanProfile'].Text
            } else { "StandardAD" }
        } else { "StandardAD" }
        if ([string]::IsNullOrWhiteSpace($dcHost)) {
            [System.Windows.MessageBox]::Show("Please enter a domain controller or domain name to scan.", "Host Required", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            return
        }
        Set-Status -Message "Scanning AD service ports on $dcHost using profile $prof..."
        $scan = Test-ADDcResolution -DomainOrDC $dcHost -Profile $prof
        if ($scan) {
            if ($controls['GridDcPorts']) { $controls['GridDcPorts'].ItemsSource = $scan.PortResults }
            Set-Status -Message "Port scan complete: $($scan.OpenPortCount) Open, $($scan.ClosedPortCount) Closed."
        }
    })
}

if ($controls['BtnSimulateDsGetDcName']) {
    $controls['BtnSimulateDsGetDcName'].Add_Click({
        $domain = if ($controls['TxtDcScanHost']) { $controls['TxtDcScanHost'].Text.Trim() } else { "" }
        Set-Status -Message "Invoking DsGetDcName locator for domain '$domain'..."
        $dcInfo = Invoke-DsGetDcName -DomainName $domain
        if ($dcInfo) {
            if ($controls['TxtDsGetDcNameSummary']) {
                $controls['TxtDsGetDcNameSummary'].Text = "DC: $($dcInfo.DomainControllerName)`r`nAddress: $($dcInfo.DomainControllerAddress)`r`nSite: $($dcInfo.DcSiteName) (Client Site: $($dcInfo.ClientSiteName))`r`nFlags: $($dcInfo.Flags)`r`nStatus: $($dcInfo.Status)"
            }
            Set-Status -Message "DsGetDcName resolved DC: $($dcInfo.DomainControllerName)"
        }
    })
}

# --- Header Quick Action Buttons ---
if ($controls['BtnHeaderResolver']) {
    $controls['BtnHeaderResolver'].Add_Click({ Show-ResolverDialog })
}

if ($controls['BtnHeaderLockout']) {
    $controls['BtnHeaderLockout'].Add_Click({
        Show-Panel "DiagnosticsToolbox"
        if ($controls['NavDiagnosticsToolbox']) { $controls['NavDiagnosticsToolbox'].IsChecked = $true }
    })
}

if ($controls['BtnHeaderGpoExplorer']) {
    $controls['BtnHeaderGpoExplorer'].Add_Click({ Show-GpoExplorerDialog })
}

if ($controls['BtnHeaderAsn1Viewer']) {
    $controls['BtnHeaderAsn1Viewer'].Add_Click({ Show-Asn1ViewerDialog })
}

if ($controls['BtnHeaderDiffViewer']) {
    $controls['BtnHeaderDiffViewer'].Add_Click({ Show-CompareValuesDialog })
}

# --- Universal "Use With..." Context Menus ---
# Users DataGrid
if ($controls['CtxUserUseWithAcl']) {
    $controls['CtxUserUseWithAcl'].Add_Click({
        $u = $controls['GridUsers'].SelectedItem
        if ($u) {
            Show-Panel "SecurityAcl"
            if ($controls['NavSecurityAcl']) { $controls['NavSecurityAcl'].IsChecked = $true }
            if ($controls['TxtAclTargetDN']) {
                $controls['TxtAclTargetDN'].Text = if ($u.DistinguishedName) { $u.DistinguishedName } else { $u.SamAccountName }
                if ($controls['BtnAclLoad']) { $controls['BtnAclLoad'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent)) }
            }
        }
    })
}
if ($controls['CtxUserUseWithTokenSize']) {
    $controls['CtxUserUseWithTokenSize'].Add_Click({
        $u = $controls['GridUsers'].SelectedItem
        if ($u) {
            Show-Panel "KerberosSuite"
            if ($controls['NavKerberosSuite']) { $controls['NavKerberosSuite'].IsChecked = $true }
            if ($controls['TxtTokenUser']) {
                $controls['TxtTokenUser'].Text = $u.SamAccountName
                if ($controls['BtnCalcTokenSize']) { $controls['BtnCalcTokenSize'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent)) }
            }
        }
    })
}
if ($controls['CtxUserUseWithLockout']) {
    $controls['CtxUserUseWithLockout'].Add_Click({
        $u = $controls['GridUsers'].SelectedItem
        if ($u) {
            Show-Panel "DiagnosticsToolbox"
            if ($controls['NavDiagnosticsToolbox']) { $controls['NavDiagnosticsToolbox'].IsChecked = $true }
            if ($controls['TxtLockoutTargetUser']) {
                $controls['TxtLockoutTargetUser'].Text = $u.SamAccountName
                if ($controls['BtnTraceLockout']) { $controls['BtnTraceLockout'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent)) }
            }
        }
    })
}
if ($controls['CtxUserUseWithReplication']) {
    $controls['CtxUserUseWithReplication'].Add_Click({
        $u = $controls['GridUsers'].SelectedItem
        if ($u) {
            Show-Panel "ReplicationSuite"
            if ($controls['NavReplicationSuite']) { $controls['NavReplicationSuite'].IsChecked = $true }
            if ($controls['TxtMultiDcTarget']) {
                $controls['TxtMultiDcTarget'].Text = $u.SamAccountName
                if ($controls['BtnScanMultiDcLogon']) { $controls['BtnScanMultiDcLogon'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent)) }
            }
        }
    })
}
if ($controls['CtxUserUseWithResolver']) {
    $controls['CtxUserUseWithResolver'].Add_Click({
        $u = $controls['GridUsers'].SelectedItem
        if ($u) { Show-ResolverDialog -InitialInput "$($u.SamAccountName)`r`n$($u.DistinguishedName)" }
    })
}
if ($controls['CtxUserCopyToDetached']) {
    $controls['CtxUserCopyToDetached'].Add_Click({
        Show-DetachedGridDialog -ItemsSource $controls['GridUsers'].ItemsSource -Title "Users Directory Dataset"
    })
}

# Groups DataGrid
if ($controls['CtxGroupUseWithAcl']) {
    $controls['CtxGroupUseWithAcl'].Add_Click({
        $g = $controls['GridGroups'].SelectedItem
        if ($g) {
            Show-Panel "SecurityAcl"
            if ($controls['NavSecurityAcl']) { $controls['NavSecurityAcl'].IsChecked = $true }
            if ($controls['TxtAclTargetDN']) {
                $controls['TxtAclTargetDN'].Text = if ($g.DistinguishedName) { $g.DistinguishedName } else { $g.Name }
                if ($controls['BtnAclLoad']) { $controls['BtnAclLoad'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent)) }
            }
        }
    })
}
if ($controls['CtxGroupUseWithCircular']) {
    $controls['CtxGroupUseWithCircular'].Add_Click({
        Show-Panel "DiagnosticsToolbox"
        if ($controls['NavDiagnosticsToolbox']) { $controls['NavDiagnosticsToolbox'].IsChecked = $true }
        if ($controls['BtnScanCircularGroups']) { $controls['BtnScanCircularGroups'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent)) }
    })
}
if ($controls['CtxGroupUseWithDiff']) {
    $controls['CtxGroupUseWithDiff'].Add_Click({
        $g = $controls['GridGroups'].SelectedItem
        if ($g) {
            Show-Panel "DiagnosticsToolbox"
            if ($controls['NavDiagnosticsToolbox']) { $controls['NavDiagnosticsToolbox'].IsChecked = $true }
            if ($controls['TxtDiffUserA']) { $controls['TxtDiffUserA'].Text = $g.Name }
        }
    })
}
if ($controls['CtxGroupUseWithResolver']) {
    $controls['CtxGroupUseWithResolver'].Add_Click({
        $g = $controls['GridGroups'].SelectedItem
        if ($g) { Show-ResolverDialog -InitialInput "$($g.Name)`r`n$($g.DistinguishedName)" }
    })
}
if ($controls['CtxGroupCopyToDetached']) {
    $controls['CtxGroupCopyToDetached'].Add_Click({
        Show-DetachedGridDialog -ItemsSource $controls['GridGroups'].ItemsSource -Title "Groups Directory Dataset"
    })
}

# Computers DataGrid
if ($controls['CtxCompUseWithAcl']) {
    $controls['CtxCompUseWithAcl'].Add_Click({
        $c = $controls['GridComputers'].SelectedItem
        if ($c) {
            Show-Panel "SecurityAcl"
            if ($controls['NavSecurityAcl']) { $controls['NavSecurityAcl'].IsChecked = $true }
            if ($controls['TxtAclTargetDN']) {
                $controls['TxtAclTargetDN'].Text = if ($c.DistinguishedName) { $c.DistinguishedName } else { "$($c.Name)$" }
                if ($controls['BtnAclLoad']) { $controls['BtnAclLoad'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent)) }
            }
        }
    })
}
if ($controls['CtxCompUseWithSpn']) {
    $controls['CtxCompUseWithSpn'].Add_Click({
        $c = $controls['GridComputers'].SelectedItem
        if ($c) {
            Show-Panel "KerberosSuite"
            if ($controls['NavKerberosSuite']) { $controls['NavKerberosSuite'].IsChecked = $true }
            if ($controls['TxtTestSpn']) {
                $controls['TxtTestSpn'].Text = if ($c.DNSHostName) { "HOST/$($c.DNSHostName)" } else { "HOST/$($c.Name)" }
                if ($controls['BtnTestSpnTicket']) { $controls['BtnTestSpnTicket'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent)) }
            }
        }
    })
}
if ($controls['CtxCompUseWithReplication']) {
    $controls['CtxCompUseWithReplication'].Add_Click({
        $c = $controls['GridComputers'].SelectedItem
        if ($c) {
            Show-Panel "ReplicationSuite"
            if ($controls['NavReplicationSuite']) { $controls['NavReplicationSuite'].IsChecked = $true }
            if ($controls['TxtMultiDcTarget']) {
                $controls['TxtMultiDcTarget'].Text = "$($c.Name)$"
                if ($controls['BtnScanMultiDcLogon']) { $controls['BtnScanMultiDcLogon'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent)) }
            }
        }
    })
}
if ($controls['CtxCompUseWithResolver']) {
    $controls['CtxCompUseWithResolver'].Add_Click({
        $c = $controls['GridComputers'].SelectedItem
        if ($c) { Show-ResolverDialog -InitialInput "$($c.Name)`r`n$($c.DNSHostName)" }
    })
}
if ($controls['CtxCompCopyToDetached']) {
    $controls['CtxCompCopyToDetached'].Add_Click({
        Show-DetachedGridDialog -ItemsSource $controls['GridComputers'].ItemsSource -Title "Computers Inventory Dataset"
    })
}

# Search Results DataGrid
if ($controls['CtxSearchUseWithAcl']) {
    $controls['CtxSearchUseWithAcl'].Add_Click({
        $s = $controls['GridSearchResults'].SelectedItem
        if ($s) {
            Show-Panel "SecurityAcl"
            if ($controls['NavSecurityAcl']) { $controls['NavSecurityAcl'].IsChecked = $true }
            if ($controls['TxtAclTargetDN']) {
                $controls['TxtAclTargetDN'].Text = if ($s.DistinguishedName) { $s.DistinguishedName } else { $s.SamAccountName }
                if ($controls['BtnAclLoad']) { $controls['BtnAclLoad'].RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent)) }
            }
        }
    })
}
if ($controls['CtxSearchUseWithResolver']) {
    $controls['CtxSearchUseWithResolver'].Add_Click({
        $s = $controls['GridSearchResults'].SelectedItem
        if ($s) { Show-ResolverDialog -InitialInput "$($s.SamAccountName)`r`n$($s.DistinguishedName)" }
    })
}
if ($controls['CtxSearchCopyToDetached']) {
    $controls['CtxSearchCopyToDetached'].Add_Click({
        Show-DetachedGridDialog -ItemsSource $controls['GridSearchResults'].ItemsSource -Title "Directory Search Dataset"
    })
}
#endregion

#region 15. Settings Panel Logic
function Load-SettingsPanel {
    if ($controls['ChkAutoDetect']) { $controls['ChkAutoDetect'].IsChecked = $true }
    if ($controls['TxtCfgSearchBase']) { $controls['TxtCfgSearchBase'].Text = $appConfig.Domain.SearchBase }
    if ($controls['TxtCfgPasswordLength']) { $controls['TxtCfgPasswordLength'].Text = $appConfig.Defaults.PasswordLength.ToString() }
    if ($controls['ChkCfgRequirePwChange']) {
        $reqPw = if ($null -ne $appConfig.Defaults.PasswordRequireChange) { $appConfig.Defaults.PasswordRequireChange } else { $appConfig.Defaults.RequirePasswordChange }
        $controls['ChkCfgRequirePwChange'].IsChecked = [bool]$reqPw
    }
    if ($controls['CmbUsernameFormat']) {
        $fmt = if ($appConfig.Defaults.UsernameFormat) { $appConfig.Defaults.UsernameFormat } else { "first.last" }
        $controls['CmbUsernameFormat'].SelectedIndex = if ($fmt -eq "flast") { 1 } else { 0 }
    }
    if ($controls['CmbExportDelimiter']) {
        $delim = if ($appConfig.Defaults.ExportDelimiter) { $appConfig.Defaults.ExportDelimiter } else { ";" }
        $controls['CmbExportDelimiter'].SelectedIndex = if ($delim -eq ",") { 1 } else { 0 }
    }
    if ($controls['CmbThemeMode']) {
        $controls['CmbThemeMode'].SelectedIndex = if ($appConfig.UI.Theme -eq "Light") { 1 } else { 0 }
    }
    if ($controls['CmbAccentTone']) {
        $toneIdx = switch -Wildcard ($appConfig.UI.AccentTone) {
            "*Sky*"     { 1 }
            "*Emerald*" { 2 }
            "*Indigo*"  { 3 }
            "*Amber*"   { 4 }
            default     { 0 }
        }
        $controls['CmbAccentTone'].SelectedIndex = $toneIdx
    }
    if ($controls['ChkThemeAutoSync']) {
        $controls['ChkThemeAutoSync'].IsChecked = if ($null -ne $appConfig.UI.SyncHtmlViewTheme) { [bool]$appConfig.UI.SyncHtmlViewTheme } else { $true }
    }
    if ($controls['CmbWorkspaceMode']) {
        $controls['CmbWorkspaceMode'].SelectedIndex = if ($appConfig.UI.WorkspaceMode -eq "Single") { 1 } else { 0 }
    }
    if ($controls['ChkAllowMultiWindow']) {
        $controls['ChkAllowMultiWindow'].IsChecked = if ($null -ne $appConfig.UI.AllowMultiWindow) { [bool]$appConfig.UI.AllowMultiWindow } else { $true }
    }
    if ($controls['ChkRestoreTabsOnStartup']) {
        $controls['ChkRestoreTabsOnStartup'].IsChecked = if ($null -ne $appConfig.UI.RestoreTabsOnStartup) { [bool]$appConfig.UI.RestoreTabsOnStartup } else { $true }
    }
    if ($controls['GridExternalTools']) {
        $controls['GridExternalTools'].ItemsSource = $null
        $controls['GridExternalTools'].ItemsSource = $state.ExternalTools
    }
}

if ($controls['BtnAddExternalTool']) {
    $controls['BtnAddExternalTool'].Add_Click({
        $name = [Microsoft.VisualBasic.Interaction]::InputBox("Enter Tool Name (e.g. Ping Host, PowerShell Query):", "Add External Tool", "Custom Tool")
        if (-not $name) { return }
        $cmd = [Microsoft.VisualBasic.Interaction]::InputBox("Enter Executable or Command (e.g. ping.exe, mstsc.exe, powershell.exe):", "Tool Executable", "powershell.exe")
        if (-not $cmd) { return }
        $args = [Microsoft.VisualBasic.Interaction]::InputBox("Enter Arguments with Tokens (%sAMAccountName%, %dNSHostName%, %distinguishedName%, %mail%):", "Tool Arguments", "-NoExit -Command Write-Host 'Inspecting %sAMAccountName%'")

        if (-not $state.ExternalTools) { $state.ExternalTools = [System.Collections.ArrayList]::new() }
        $toolObj = [PSCustomObject]@{
            Name = $name
            Command = $cmd
            Arguments = $args
        }
        [void]$state.ExternalTools.Add($toolObj)
        $controls['GridExternalTools'].ItemsSource = $null
        $controls['GridExternalTools'].ItemsSource = $state.ExternalTools
        Populate-AllExternalToolsMenus
        Set-Status -Message "Added external tool: $name"
    })
}

if ($controls['BtnEditExternalTool']) {
    $controls['BtnEditExternalTool'].Add_Click({
        $sel = if ($controls['GridExternalTools']) { $controls['GridExternalTools'].SelectedItem } else { $null }
        if (-not $sel) {
            [System.Windows.MessageBox]::Show("Please select an external tool to edit.", "Selection Required", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            return
        }
        $name = [Microsoft.VisualBasic.Interaction]::InputBox("Edit Tool Name:", "Edit Tool", $sel.Name)
        if (-not $name) { return }
        $cmd = [Microsoft.VisualBasic.Interaction]::InputBox("Edit Executable:", "Edit Executable", $sel.Command)
        if (-not $cmd) { return }
        $args = [Microsoft.VisualBasic.Interaction]::InputBox("Edit Arguments:", "Edit Arguments", $sel.Arguments)
        $sel.Name = $name
        $sel.Command = $cmd
        $sel.Arguments = $args
        $controls['GridExternalTools'].Items.Refresh()
        Populate-AllExternalToolsMenus
        Set-Status -Message "Updated external tool: $name"
    })
}

if ($controls['BtnDeleteExternalTool']) {
    $controls['BtnDeleteExternalTool'].Add_Click({
        $sel = if ($controls['GridExternalTools']) { $controls['GridExternalTools'].SelectedItem } else { $null }
        if (-not $sel) {
            [System.Windows.MessageBox]::Show("Please select an external tool to delete.", "Selection Required", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            return
        }
        $confirm = [System.Windows.MessageBox]::Show("Are you sure you want to delete '$($sel.Name)'?", "Confirm Delete", [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Question)
        if ($confirm -eq [System.Windows.MessageBoxResult]::Yes) {
            [void]$state.ExternalTools.Remove($sel)
            $controls['GridExternalTools'].ItemsSource = $null
            $controls['GridExternalTools'].ItemsSource = $state.ExternalTools
            Populate-AllExternalToolsMenus
            Set-Status -Message "Deleted tool: $($sel.Name)"
        }
    })
}

if ($controls['BtnResetDefaultTools']) {
    $controls['BtnResetDefaultTools'].Add_Click({
        $defaultTools = @(
            [PSCustomObject]@{ Name = "Ping Hostname"; Command = "ping.exe"; Arguments = "%dNSHostName% -t" },
            [PSCustomObject]@{ Name = "Remote Desktop (RDP)"; Command = "mstsc.exe"; Arguments = "/v:%dNSHostName%" },
            [PSCustomObject]@{ Name = "PowerShell AD Inspector"; Command = "powershell.exe"; Arguments = "-NoExit -Command `"Get-ADObject -Identity '%distinguishedName%' -Properties * | Format-List`"" },
            [PSCustomObject]@{ Name = "Test LDAP Port 389"; Command = "powershell.exe"; Arguments = "-NoExit -Command `"Test-NetConnection '%dNSHostName%' -Port 389`"" },
            [PSCustomObject]@{ Name = "DNS Lookup (nslookup)"; Command = "cmd.exe"; Arguments = "/k nslookup %dNSHostName%" },
            [PSCustomObject]@{ Name = "Computer Management"; Command = "mmc.exe"; Arguments = "compmgmt.msc /computer=%dNSHostName%" },
            [PSCustomObject]@{ Name = "Event Viewer"; Command = "mmc.exe"; Arguments = "eventvwr.msc %dNSHostName%" }
        )
        $state.ExternalTools = [System.Collections.ArrayList]::new($defaultTools)
        $controls['GridExternalTools'].ItemsSource = $null
        $controls['GridExternalTools'].ItemsSource = $state.ExternalTools
        Populate-AllExternalToolsMenus
        Set-Status -Message "Restored default external tools."
    })
}

if ($controls['BtnTestExternalTool']) {
    $controls['BtnTestExternalTool'].Add_Click({
        $sel = if ($controls['GridExternalTools']) { $controls['GridExternalTools'].SelectedItem } else { $null }
        if (-not $sel) {
            [System.Windows.MessageBox]::Show("Please select an external tool from the table to test.", "Selection Required", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            return
        }
        $dummy = [PSCustomObject]@{
            dNSHostName = if ($adContext.PDCEmulator) { $adContext.PDCEmulator } else { "127.0.0.1" }
            sAMAccountName = "Administrator"
            distinguishedName = if ($state.DefaultNamingContext) { "CN=Administrator,CN=Users,$($state.DefaultNamingContext)" } else { "CN=Administrator,DC=domain,DC=local" }
            mail = "admin@domain.local"
            cn = "Administrator"
        }
        Invoke-ExternalTool -Tool $sel -TargetObject $dummy
    })
}

if ($controls['BtnSaveSettings']) {
    $controls['BtnSaveSettings'].Add_Click({
        $appConfig.Domain.SearchBase = if ($controls['TxtCfgSearchBase']) { $controls['TxtCfgSearchBase'].Text.Trim() } else { "" }
        
        $pwLen = 16
        if ($controls['TxtCfgPasswordLength'] -and [int]::TryParse($controls['TxtCfgPasswordLength'].Text, [ref]$pwLen)) {
            $appConfig.Defaults.PasswordLength = $pwLen
        }

        if ($controls['ChkCfgRequirePwChange']) {
            $val = [bool]$controls['ChkCfgRequirePwChange'].IsChecked
            if ($appConfig.Defaults.PSObject.Properties['PasswordRequireChange']) {
                $appConfig.Defaults.PasswordRequireChange = $val
            } elseif ($appConfig.Defaults.PSObject.Properties['RequirePasswordChange']) {
                $appConfig.Defaults.RequirePasswordChange = $val
            } else {
                $appConfig.Defaults | Add-Member -MemberType NoteProperty -Name "PasswordRequireChange" -Value $val -Force
            }
        }

        if ($controls['CmbUsernameFormat']) {
            $appConfig.Defaults.UsernameFormat = if ($controls['CmbUsernameFormat'].SelectedIndex -eq 1) { "flast" } else { "first.last" }
        }

        if ($controls['CmbExportDelimiter']) {
            $appConfig.Defaults.ExportDelimiter = if ($controls['CmbExportDelimiter'].SelectedIndex -eq 1) { "," } else { ";" }
        }

        if ($controls['CmbThemeMode']) {
            $appConfig.UI.Theme = if ($controls['CmbThemeMode'].SelectedIndex -eq 1) { "Light" } else { "Dark" }
        }

        if ($controls['CmbAccentTone']) {
            $appConfig.UI.AccentTone = switch ($controls['CmbAccentTone'].SelectedIndex) {
                1 { "Sky" }
                2 { "Emerald" }
                3 { "Indigo" }
                4 { "Amber" }
                default { "Blue" }
            }
        }

        if ($controls['ChkThemeAutoSync']) {
            $appConfig.UI.SyncHtmlViewTheme = [bool]$controls['ChkThemeAutoSync'].IsChecked
        }

        if ($controls['CmbWorkspaceMode']) {
            $newMode = if ($controls['CmbWorkspaceMode'].SelectedIndex -eq 1) { "Single" } else { "Tabs" }
            $appConfig.UI.WorkspaceMode = $newMode
            Set-WorkspaceMode -Mode $newMode
        }
        if ($controls['ChkAllowMultiWindow']) {
            $appConfig.UI.AllowMultiWindow = [bool]$controls['ChkAllowMultiWindow'].IsChecked
            $state.AllowMultiWindow = $appConfig.UI.AllowMultiWindow
        }
        if ($controls['ChkRestoreTabsOnStartup']) {
            $appConfig.UI.RestoreTabsOnStartup = [bool]$controls['ChkRestoreTabsOnStartup'].IsChecked
            $state.RestoreTabsOnStartup = $appConfig.UI.RestoreTabsOnStartup
        }

        $appConfig.ExternalTools = @($state.ExternalTools)

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

function Update-HeaderLayoutResponsive {
    $w = if ($window.ActualWidth -gt 0) { $window.ActualWidth } else { $window.Width }
    
    # Text labels on header buttons collapse when window is under 1240px
    $showFullLabels = ($w -ge 1240)
    $labelVis = if ($showFullLabels) { [System.Windows.Visibility]::Visible } else { [System.Windows.Visibility]::Collapsed }
    
    if ($controls['TxtHeaderResolver']) { $controls['TxtHeaderResolver'].Visibility = $labelVis }
    if ($controls['TxtHeaderLockout'])  { $controls['TxtHeaderLockout'].Visibility  = $labelVis }
    if ($controls['TxtHeaderGpo'])      { $controls['TxtHeaderGpo'].Visibility      = $labelVis }
    if ($controls['TxtHeaderAsn1'])     { $controls['TxtHeaderAsn1'].Visibility     = $labelVis }
    if ($controls['TxtHeaderDiff'])     { $controls['TxtHeaderDiff'].Visibility     = $labelVis }
    if ($controls['TxtHeaderDiag'])       { $controls['TxtHeaderDiag'].Visibility       = $labelVis }
    if ($controls['TxtHeaderRefresh'])    { $controls['TxtHeaderRefresh'].Visibility    = $labelVis }
    if ($controls['TxtHeaderLayoutText']) { $controls['TxtHeaderLayoutText'].Visibility = $labelVis }

    # Telemetry badge in center only displays when there is ample width (>= 1380px)
    if ($controls['BorderTelemetryBadge']) {
        $controls['BorderTelemetryBadge'].Visibility = if ($w -ge 1380) { [System.Windows.Visibility]::Visible } else { [System.Windows.Visibility]::Collapsed }
    }
}

# Initial Window Launch
$window.Add_Loaded({
    if ($appConfig.UI -and $appConfig.UI.Theme -eq "Light") {
        Set-ApplicationTheme -Theme "Light" -AccentTone $appConfig.UI.AccentTone
    }
    Init-ElevationBadge
    Init-SidebarNavigationContextMenus

    # Initialize Workspace Tabs
    if (-not [string]::IsNullOrWhiteSpace($InitialTool)) {
        Add-WorkspaceTab -PanelName $InitialTool -Activate $true
    } elseif ($state.RestoreTabsOnStartup -and $appConfig.UI.OpenTabs -and ($appConfig.UI.OpenTabs.Count -gt 0)) {
        foreach ($tabName in $appConfig.UI.OpenTabs) {
            Add-WorkspaceTab -PanelName $tabName -Activate $false
        }
        $firstTab = if ($state.OpenTabs.Count -gt 0) { $state.OpenTabs[0].Id } else { "Dashboard" }
        Select-WorkspaceTab -TabId $firstTab
    } else {
        Add-WorkspaceTab -PanelName "Dashboard" -Activate $true
    }
    Set-WorkspaceMode -Mode $state.WorkspaceMode

    Refresh-All
    Refresh-Connections
    Populate-SearchAttributeDropdowns
    Populate-AllExternalToolsMenus
    Update-HeaderLayoutResponsive
})

$window.Add_Closing({
    param($sender, $e)
    # Persist open tabs if enabled
    if ($state.RestoreTabsOnStartup) {
        $openNames = @($state.OpenTabs | ForEach-Object { $_.PanelName })
        if ($openNames.Count -gt 0) {
            $appConfig.UI.OpenTabs = $openNames
            [void](Save-AppSettings -Config $appConfig)
        }
    }
    # Safely close all detached child windows
    if ($state.DetachedWindows) {
        $keys = @($state.DetachedWindows.Keys)
        foreach ($k in $keys) {
            $dWin = $state.DetachedWindows[$k]
            if ($dWin) {
                try { $dWin.Close() } catch {}
            }
        }
    }
})

$window.Add_SizeChanged({
    param($sender, $e)
    Update-HeaderLayoutResponsive
})

# Keyboard shortcuts: Ctrl+T theme, Ctrl+R Resolver, Ctrl+W close tab, Ctrl+Tab cycle tabs, Ctrl+Shift+D detach, Ctrl+N new window, Ctrl+Shift+N duplicate tab
$window.Add_KeyDown({
    param($sender, $e)
    if ($e.Key -eq [System.Windows.Input.Key]::T -and ([System.Windows.Input.Keyboard]::Modifiers -band [System.Windows.Input.ModifierKeys]::Control)) {
        $newTheme = if ($state.CurrentTheme -eq "Light") { "Dark" } else { "Light" }
        Set-ApplicationTheme -Theme $newTheme -SavePreference
        $e.Handled = $true
    }
    if ($e.Key -eq [System.Windows.Input.Key]::R -and ([System.Windows.Input.Keyboard]::Modifiers -band [System.Windows.Input.ModifierKeys]::Control)) {
        Show-ResolverDialog
        $e.Handled = $true
    }
    if ($e.Key -eq [System.Windows.Input.Key]::W -and ([System.Windows.Input.Keyboard]::Modifiers -band [System.Windows.Input.ModifierKeys]::Control)) {
        if ($state.WorkspaceMode -eq "Tabs" -and $state.ActiveTabId) {
            Remove-WorkspaceTab -TabId $state.ActiveTabId
            $e.Handled = $true
        }
    }
    if ($e.Key -eq [System.Windows.Input.Key]::Tab -and ([System.Windows.Input.Keyboard]::Modifiers -band [System.Windows.Input.ModifierKeys]::Control)) {
        if ($state.WorkspaceMode -eq "Tabs" -and $state.OpenTabs.Count -gt 1) {
            $currIdx = -1
            for ($i = 0; $i -lt $state.OpenTabs.Count; $i++) {
                if ($state.OpenTabs[$i].Id -eq $state.ActiveTabId) { $currIdx = $i; break }
            }
            if ($currIdx -ge 0) {
                $isShift = [bool]([System.Windows.Input.Keyboard]::Modifiers -band [System.Windows.Input.ModifierKeys]::Shift)
                $nextIdx = if ($isShift) {
                    if ($currIdx -eq 0) { $state.OpenTabs.Count - 1 } else { $currIdx - 1 }
                } else {
                    ($currIdx + 1) % $state.OpenTabs.Count
                }
                Select-WorkspaceTab -TabId $state.OpenTabs[$nextIdx].Id
                $e.Handled = $true
            }
        }
    }
    if ($e.Key -eq [System.Windows.Input.Key]::D -and ([System.Windows.Input.Keyboard]::Modifiers -band [System.Windows.Input.ModifierKeys]::Control) -and ([System.Windows.Input.Keyboard]::Modifiers -band [System.Windows.Input.ModifierKeys]::Shift)) {
        if ($state.ActiveTabId) {
            $activeTab = $state.OpenTabs | Where-Object { $_.Id -eq $state.ActiveTabId } | Select-Object -First 1
            $p = if ($activeTab) { $activeTab.PanelName } else { $state.ActiveTabId }
            Detach-PanelToWindow -PanelName $p
            $e.Handled = $true
        }
    }
    if ($e.Key -eq [System.Windows.Input.Key]::N -and ([System.Windows.Input.Keyboard]::Modifiers -band [System.Windows.Input.ModifierKeys]::Control) -and -not ([System.Windows.Input.Keyboard]::Modifiers -band [System.Windows.Input.ModifierKeys]::Shift)) {
        Launch-NewApplicationWindow
        $e.Handled = $true
    }
    if ($e.Key -eq [System.Windows.Input.Key]::N -and ([System.Windows.Input.Keyboard]::Modifiers -band [System.Windows.Input.ModifierKeys]::Control) -and ([System.Windows.Input.Keyboard]::Modifiers -band [System.Windows.Input.ModifierKeys]::Shift)) {
        if ($state.ActiveTabId) {
            $activeTab = $state.OpenTabs | Where-Object { $_.Id -eq $state.ActiveTabId } | Select-Object -First 1
            $p = if ($activeTab) { $activeTab.PanelName } else { $state.ActiveTabId }
            Add-WorkspaceTab -PanelName $p -NewInstance -Activate $true
            $e.Handled = $true
        }
    }
    if ($e.Key -eq [System.Windows.Input.Key]::M -and ([System.Windows.Input.Keyboard]::Modifiers -band [System.Windows.Input.ModifierKeys]::Control) -and ([System.Windows.Input.Keyboard]::Modifiers -band [System.Windows.Input.ModifierKeys]::Shift)) {
        $newMode = if ($state.WorkspaceMode -eq "Tabs") { "Single" } else { "Tabs" }
        Set-WorkspaceMode -Mode $newMode
        Save-AppSettings -Config $appConfig
        Set-Status -Message "Workspace mode changed to: $(if ($newMode -eq 'Tabs') { 'Multi-Tab Workspace' } else { 'Single Viewport' })"
        $e.Handled = $true
    }
    if ($e.Key -eq [System.Windows.Input.Key]::L -and ([System.Windows.Input.Keyboard]::Modifiers -band [System.Windows.Input.ModifierKeys]::Control) -and ([System.Windows.Input.Keyboard]::Modifiers -band [System.Windows.Input.ModifierKeys]::Shift)) {
        Show-WorkspaceLayoutMenu -targetElement $controls['BtnWorkspaceLayoutMenu']
        $e.Handled = $true
    }
})

# Show Main Window
[void]$window.ShowDialog()