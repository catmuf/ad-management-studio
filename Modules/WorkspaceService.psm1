<#
.SYNOPSIS
    Multi-Tab & Detachable Multi-Window Workspace Engine with XAML Fragment Caching.
.DESCRIPTION
    Manages workspace tabs, session state persistence, detached monitors, layout presets,
    navigation context menus, and fast cached per-panel XAML instantiation.
#>

$script:window             = $null
$script:controls           = @{}
$script:state              = $null
$script:appConfig          = $null
$script:mainWindowXamlPath = ""
$script:viewsPath          = ""
$script:mainScriptPath     = ""
$script:DefaultStartupTabs = @("Dashboard", "Users", "SecurityAcl", "ReplicationSuite")
$script:PanelCatalog       = [ordered]@{}
$script:WorkspaceHostInvoke = $null

function Initialize-WorkspaceContext {
    [CmdletBinding()]
    param(
        $Window,
        $Controls,
        $State,
        $Config,
        [string]$MainWindowXamlPath,
        [string]$ViewsPath,
        [string]$MainScriptPath = "",
        [string[]]$DefaultStartupTabs,
        $PanelCatalog,
        [scriptblock]$HostInvoke
    )
    $script:window              = $Window
    $script:controls            = $Controls
    $script:state               = $State
    $script:appConfig           = $Config
    $script:mainWindowXamlPath  = $MainWindowXamlPath
    $script:viewsPath           = $ViewsPath
    $script:mainScriptPath      = $MainScriptPath
    if ($DefaultStartupTabs) { $script:DefaultStartupTabs = $DefaultStartupTabs }
    if ($PanelCatalog)       { $script:PanelCatalog = $PanelCatalog }
    $script:WorkspaceHostInvoke = $HostInvoke
}

function Invoke-WorkspaceHost {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [hashtable]$NamedArgs = @{},
        [object[]]$PosArgs = @()
    )
    if ($script:WorkspaceHostInvoke) {
        return & $script:WorkspaceHostInvoke $Name $NamedArgs $PosArgs
    }
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if ($cmd) {
        if ($NamedArgs.Count -gt 0) { return & $cmd @NamedArgs }
        elseif ($PosArgs.Count -gt 0) { return & $cmd @PosArgs }
        else { return & $cmd }
    }
}
#region Workspace Engine (Multi-Tabs & Detachable Multi-Windows)

Set-Alias -Name Launch-NewApplicationWindow -Value Start-NewApplicationWindow -Scope Global
function Start-NewApplicationWindow {
    param([string]$ToolName = "")
    $powershellExe = (Get-Process -Id $PID).Path
    $entryPath = if (-not [string]::IsNullOrWhiteSpace($script:mainScriptPath)) { $script:mainScriptPath } else { Join-Path (Split-Path -Parent $PSScriptRoot) "main.ps1" }
    $argList = "-STA -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$entryPath`""
    if (-not [string]::IsNullOrWhiteSpace($ToolName)) {
        $argList += " -InitialTool `"$ToolName`""
    }
    Start-Process -FilePath $powershellExe -ArgumentList $argList -WindowStyle Hidden
    $suffix = if ($ToolName) { " for $ToolName" } else { "" }
    Invoke-WorkspaceHost -Name "Set-Status" -NamedArgs @{ Message = "Launched new independent window${suffix}." }
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
            if ($state.UsersCurrentList) { $Tab.State['UsersCurrentList'] = $state.UsersCurrentList }
            if ($state.UsersPage) { $Tab.State['UsersPage'] = $state.UsersPage }
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
        "HtmlView" {
            if ($Tab.InstanceNumber -le 1 -and $Tab.Id -eq $state.ActiveTabId) {
                if ($controls['TxtHtmlViewDN'] -and $controls['TxtHtmlViewDN'].Text) {
                    $Tab.State['CurrentHtmlDN'] = $controls['TxtHtmlViewDN'].Text
                }
                if ($state.CurrentHtmlTemplate) { $Tab.State['CurrentHtmlTemplate'] = $state.CurrentHtmlTemplate }
                if ($state.CurrentHtmlRaw) { $Tab.State['CurrentHtmlRaw'] = $state.CurrentHtmlRaw }
                if ($state.CurrentHtmlObject) { $Tab.State['CurrentHtmlObject'] = $state.CurrentHtmlObject }
            }
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
            if ($Tab.State.ContainsKey('UsersCurrentList') -and $Tab.State['UsersCurrentList']) {
                $state.UsersCurrentList = $Tab.State['UsersCurrentList']
                $state.UsersPage = if ($Tab.State.ContainsKey('UsersPage')) { $Tab.State['UsersPage'] } else { 1 }
                Invoke-WorkspaceHost -Name "Show-PagedUsers" -NamedArgs @{ SourceItems = $state.UsersCurrentList }
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
        "HtmlView" {
            if ($Tab.State.ContainsKey('CurrentHtmlDN') -and $Tab.State['CurrentHtmlDN']) {
                $state.CurrentHtmlDN = $Tab.State['CurrentHtmlDN']
                if ($Tab.State.ContainsKey('CurrentHtmlTemplate')) { $state.CurrentHtmlTemplate = $Tab.State['CurrentHtmlTemplate'] }
                if ($Tab.State.ContainsKey('CurrentHtmlRaw')) { $state.CurrentHtmlRaw = $Tab.State['CurrentHtmlRaw'] }
                if ($Tab.State.ContainsKey('CurrentHtmlObject')) { $state.CurrentHtmlObject = $Tab.State['CurrentHtmlObject'] }
                if ($controls['TxtHtmlViewDN']) { $controls['TxtHtmlViewDN'].Text = $state.CurrentHtmlDN }
                if ($controls['BrowserHtmlView'] -and $state.CurrentHtmlRaw) {
                    Invoke-WorkspaceHost -Name "Set-SafeBrowserHtml" -NamedArgs @{ Browser = $controls['BrowserHtmlView']; Html = $state.CurrentHtmlRaw }
                }
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
        $meta = if (-not [string]::IsNullOrWhiteSpace($pName) -and $script:PanelCatalog.Contains($pName)) { $script:PanelCatalog[$pName] } else { [PSCustomObject]@{ Title = $pName; Icon = "📄"; Category = "Tool" } }
        $isActive = ($state.ActiveTabId -eq $tab.Id)
        $isDetached = ($state.DetachedWindows.ContainsKey($tab.Id))
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
            $btnDetach.Tag = $tab.Id
            $btnDetach.Add_Click([System.Windows.RoutedEventHandler]{
                param($s, $e)
                $e.Handled = $true
                $tId = if ($s -is [System.Windows.FrameworkElement] -and $s.Tag) { $s.Tag } else { $null }
                if (-not [string]::IsNullOrWhiteSpace($tId)) {
                    if ($state.DetachedWindows.ContainsKey($tId)) {
                        Dock-PanelToMainWindow -TabId $tId
                    } else {
                        Detach-PanelToWindow -TabId $tId
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
            $null = $e
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
                        $curActive = $state.OpenTabs | Where-Object { $_.Id -eq $state.ActiveTabId } | Select-Object -First 1
                        if ($curActive) { $appConfig.UI.ActiveTab = $curActive.PanelName }
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
            $null = $e
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
            $null = $e
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
            $null = $e
            $tId = if ($s -is [System.Windows.FrameworkElement] -and $s.Tag) { $s.Tag } else { $null }
            if (-not [string]::IsNullOrWhiteSpace($tId)) {
                Rename-WorkspaceTab -TabId $tId
            }
        })
        [void]$cm.Items.Add($miRename)

        $miNewWin = [System.Windows.Controls.MenuItem]::new()
        $miNewWin.Header = "⧉  Open in Detached Window"
        $miNewWin.Tag = $pName
        $miNewWin.Add_Click([System.Windows.RoutedEventHandler]{
            param($s, $e)
            $null = $e
            $p = if ($s -is [System.Windows.FrameworkElement] -and $s.Tag) { $s.Tag } else { $null }
            if (-not [string]::IsNullOrWhiteSpace($p)) {
                Add-WorkspaceTab -PanelName $p -NewInstance -Activate $true
                $newTab = $state.OpenTabs | Where-Object { $_.PanelName -eq $p } | Select-Object -Last 1
                if ($newTab) { Detach-PanelToWindow -TabId $newTab.Id }
            }
        })
        [void]$cm.Items.Add($miNewWin)

        [void]$cm.Items.Add([System.Windows.Controls.Separator]::new())

        $miDetach = [System.Windows.Controls.MenuItem]::new()
        $miDetach.Header = if ($isDetached) { "$([char]0x2B07) Dock Back into Main Window" } else { "$([char]0x29C9) Detach to Separate Window" }
        $miDetach.Tag = $tab.Id
        $miDetach.Add_Click([System.Windows.RoutedEventHandler]{
            param($s, $e)
            $null = $e
            $tId = if ($s -is [System.Windows.FrameworkElement] -and $s.Tag) { $s.Tag } else { $null }
            if (-not [string]::IsNullOrWhiteSpace($tId)) {
                if ($state.DetachedWindows.ContainsKey($tId)) {
                    Dock-PanelToMainWindow -TabId $tId
                } else {
                    Detach-PanelToWindow -TabId $tId
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
            $null = $e
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
            $null = $e
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
            $null = $s; $null = $e
            $toClose = @($state.OpenTabs)
            foreach ($t in $toClose) { Remove-WorkspaceTab -TabId $t.Id }
        })
        [void]$cm.Items.Add($miCloseAll)

        $tabBorder.ContextMenu = $cm
        [void]$tabHost.Children.Add($tabBorder)
    }
}

function Disconnect-VisualElement {
    param([System.Windows.UIElement]$Element)
    if (-not $Element) { return }
    try {
        if ($Element -is [System.Windows.FrameworkElement]) {
            $parent = $Element.Parent
            if ($parent -is [System.Windows.Controls.Panel]) {
                $parent.Children.Remove($Element)
            } elseif ($parent -is [System.Windows.Controls.ContentControl]) {
                $parent.Content = $null
            } elseif ($parent -is [System.Windows.Controls.Decorator]) {
                $parent.Child = $null
            }
        }
        $visualParent = [System.Windows.Media.VisualTreeHelper]::GetParent($Element)
        if ($visualParent -and $visualParent -is [System.Windows.Controls.Panel] -and $visualParent.Children.Contains($Element)) {
            $visualParent.Children.Remove($Element)
        }
    } catch {
        Write-AppLog -Level "WARN" -Category "Workspace" -Message "Exception during visual element disconnect: $_"
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
        Write-AppLog -Level "INFO" -Category "Workspace" -Message "Switching to existing tab for '$PanelName' (Id=$($existing.Id))"
        if ($Activate) {
            Select-WorkspaceTab -TabId $existing.Id
        } else {
            Update-WorkspaceTabStrip
        }
        return
    }

    $meta = if (-not [string]::IsNullOrWhiteSpace($PanelName) -and $script:PanelCatalog.Contains($PanelName)) {
        $script:PanelCatalog[$PanelName]
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
        Id                  = $tabId
        PanelName           = $PanelName
        Title               = $displayTitle
        Icon                = $meta.Icon
        InstanceNumber      = $instanceNum
        State               = @{}
        DockedPanelInstance = $null
    }
    $state.OpenTabs.Add($tabObj)

    Write-AppLog -Level "INFO" -Category "Workspace" -Message "Opened tab '$displayTitle' (Panel=$PanelName, Id=$tabId, Instance=$instanceNum)"

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

    Write-AppLog -Level "INFO" -Category "Workspace" -Message "Closing tab '$($targetTab.Title)' (Id=$($targetTab.Id), Panel=$($targetTab.PanelName))"

    if ($state.DetachedWindows.ContainsKey($targetTab.Id)) {
        $dRec = $state.DetachedWindows[$targetTab.Id]
        $dWin = if ($dRec -is [System.Collections.IDictionary] -and $dRec.ContainsKey('Window')) { $dRec['Window'] } else { $dRec }
        if ($dWin -and $dWin -is [System.Windows.Window]) {
            $dWin.Tag = "TabRemoved"
            try { $dWin.Close() } catch { Write-AppError -Category "Workspace" -Message "Error closing detached window for tab $($targetTab.Id): $_" }
        }
        [void]$state.DetachedWindows.Remove($targetTab.Id)
    }

    if ($targetTab.PSObject.Properties['DockedPanelInstance'] -and $targetTab.DockedPanelInstance) {
        Disconnect-VisualElement -Element $targetTab.DockedPanelInstance
        $targetTab.DockedPanelInstance = $null
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

function Get-NamedElements {
    param([System.Windows.DependencyObject]$element)
    $res = @{}
    if (-not $element) { return $res }
    $queue = [System.Collections.Queue]::new()
    $visited = [System.Collections.Generic.HashSet[System.Windows.DependencyObject]]::new()
    $queue.Enqueue($element)
    while ($queue.Count -gt 0) {
        $curr = $queue.Dequeue()
        if (-not $curr -or -not $visited.Add($curr)) { continue }
        if ($curr -is [System.Windows.FrameworkElement] -and -not [string]::IsNullOrWhiteSpace($curr.Name)) {
            $res[$curr.Name] = $curr
        }
        if ($curr -is [System.Windows.FrameworkElement] -and $curr.ContextMenu) {
            $queue.Enqueue($curr.ContextMenu)
        }
        if ($curr -is [System.Windows.Controls.ItemsControl]) {
            foreach ($item in $curr.Items) {
                if ($item -is [System.Windows.DependencyObject]) {
                    $queue.Enqueue($item)
                }
            }
        }
        foreach ($child in [System.Windows.LogicalTreeHelper]::GetChildren($curr)) {
            if ($child -is [System.Windows.DependencyObject]) {
                $queue.Enqueue($child)
            }
        }
    }
    return $res
}

$script:CachedWindowResourcesXml = $null
$script:PanelFragmentCache = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::OrdinalIgnoreCase)

function Initialize-PanelXamlCache {
    [CmdletBinding()]
    param([string]$XamlPath = "")
    if ([string]::IsNullOrWhiteSpace($XamlPath)) { $XamlPath = $script:mainWindowXamlPath }
    if ([string]::IsNullOrWhiteSpace($XamlPath) -or -not (Test-Path $XamlPath)) { return }
    if ($script:CachedWindowResourcesXml -and $script:PanelFragmentCache.Count -gt 0) { return }

    $rawXaml = [System.IO.File]::ReadAllText($XamlPath)
    [xml]$doc = $rawXaml
    $ns = [System.Xml.XmlNamespaceManager]::new($doc.NameTable)
    $ns.AddNamespace('w', 'http://schemas.microsoft.com/winfx/2006/xaml/presentation')

    $resNode = $doc.SelectSingleNode('//w:Window.Resources', $ns)
    if ($resNode) {
        $script:CachedWindowResourcesXml = $resNode.InnerXml
    }
    $vp = $doc.SelectSingleNode('//w:Grid[@Name="ViewportContainer"]', $ns)
    if ($vp) {
        foreach ($child in $vp.ChildNodes) {
            if ($child.NodeType -eq [System.Xml.XmlNodeType]::Element) {
                $n = $child.GetAttribute('Name')
                if ($n -and $n.StartsWith('Panel', [System.StringComparison]::Ordinal)) {
                    $pKey = $n.Substring(5)
                    $script:PanelFragmentCache[$pKey] = $child.OuterXml
                }
            }
        }
    }
}

function New-PanelInstance {
    [CmdletBinding()]
    param([string]$PanelName)

    if (-not $script:CachedWindowResourcesXml -or $script:PanelFragmentCache.Count -eq 0) {
        Initialize-PanelXamlCache -XamlPath $script:mainWindowXamlPath
    }

    $panel = $null
    if ($script:PanelFragmentCache.ContainsKey($PanelName) -and $script:CachedWindowResourcesXml) {
        $fragXml = "<Grid xmlns=`"http://schemas.microsoft.com/winfx/2006/xaml/presentation`" xmlns:x=`"http://schemas.microsoft.com/winfx/2006/xaml`"><Grid.Resources>$($script:CachedWindowResourcesXml)</Grid.Resources>$($script:PanelFragmentCache[$PanelName])</Grid>"
        $wrapper = [System.Windows.Markup.XamlReader]::Parse($fragXml)
        if ($wrapper -and $wrapper.Children.Count -gt 0) {
            $panel = $wrapper.Children[0]
            $wrapper.Children.Remove($panel)
            if ($wrapper.Resources) {
                foreach ($rk in $wrapper.Resources.Keys) {
                    if (-not $panel.Resources.Contains($rk)) {
                        $panel.Resources[$rk] = $wrapper.Resources[$rk]
                    }
                }
            }
        }
    }

    if (-not $panel) {
        $xmlR = [System.Xml.XmlReader]::Create($script:mainWindowXamlPath)
        $tempWin = [System.Windows.Markup.XamlReader]::Load($xmlR)
        $xmlR.Close()
        $panel = $tempWin.FindName("Panel$PanelName")
        $viewport = $tempWin.FindName("ViewportContainer")
        if ($viewport -and $viewport.Children.Contains($panel)) {
            $viewport.Children.Remove($panel)
        }
    }

    if ($panel -and $script:window -and $script:window.Resources) {
        foreach ($rk in $script:window.Resources.Keys) {
            if ($script:window.Resources[$rk] -is [System.Windows.Media.Brush]) {
                $panel.Resources[$rk] = $script:window.Resources[$rk]
            }
        }
    }

    $ctrls = Get-NamedElements -element $panel
    return [PSCustomObject]@{
        Panel    = $panel
        Controls = $ctrls
    }
}

function Save-SecondaryPanelSessionState {
    param($Tab, $PanelObj, [string]$PanelName)
    if (-not $Tab -or -not $Tab.State -or -not $PanelObj) { return }
    $c = $PanelObj.Controls
    switch ($PanelName) {
        "HtmlView" {
            if ($c['TxtHtmlViewDN']) { $Tab.State['CurrentHtmlDN'] = $c['TxtHtmlViewDN'].Text }
            if ($state.CurrentHtmlRaw -and (-not $Tab.State.ContainsKey('CurrentHtmlRaw') -or -not $Tab.State['CurrentHtmlRaw'])) {
                $Tab.State['CurrentHtmlRaw'] = $state.CurrentHtmlRaw
            }
            if ($state.CurrentHtmlTemplate -and (-not $Tab.State.ContainsKey('CurrentHtmlTemplate') -or -not $Tab.State['CurrentHtmlTemplate'])) {
                $Tab.State['CurrentHtmlTemplate'] = $state.CurrentHtmlTemplate
            }
            if ($state.CurrentHtmlObject -and (-not $Tab.State.ContainsKey('CurrentHtmlObject') -or -not $Tab.State['CurrentHtmlObject'])) {
                $Tab.State['CurrentHtmlObject'] = $state.CurrentHtmlObject
            }
        }
        "Users" {
            if ($c['TxtSearchUsers']) { $Tab.State['SearchUsers'] = $c['TxtSearchUsers'].Text }
            if ($c['FilterUserAll']) {
                $Tab.State['FilterUser'] = if ($c['FilterUserActive'] -and $c['FilterUserActive'].IsChecked) { "Active" }
                    elseif ($c['FilterUserDisabled'] -and $c['FilterUserDisabled'].IsChecked) { "Disabled" }
                    elseif ($c['FilterUserLocked'] -and $c['FilterUserLocked'].IsChecked) { "Locked" }
                    else { "All" }
            }
            if ($c['CmbUserOUFilter']) { $Tab.State['OUFilter'] = $c['CmbUserOUFilter'].SelectedIndex }
        }
        "Groups" {
            if ($c['TxtSearchGroups']) { $Tab.State['SearchGroups'] = $c['TxtSearchGroups'].Text }
            if ($c['FilterGroupAll']) {
                $Tab.State['FilterGroup'] = if ($c['FilterGroupSec'] -and $c['FilterGroupSec'].IsChecked) { "Security" }
                    elseif ($c['FilterGroupDist'] -and $c['FilterGroupDist'].IsChecked) { "Distribution" }
                    else { "All" }
            }
        }
        "Computers" {
            if ($c['TxtSearchComputers']) { $Tab.State['SearchComputers'] = $c['TxtSearchComputers'].Text }
            if ($c['FilterCompAll']) {
                $Tab.State['FilterComp'] = if ($c['FilterCompEnabled'] -and $c['FilterCompEnabled'].IsChecked) { "Enabled" }
                    elseif ($c['FilterCompDisabled'] -and $c['FilterCompDisabled'].IsChecked) { "Disabled" }
                    else { "All" }
            }
        }
        "DirectorySearch" {
            if ($c['TxtRawLdapFilter']) { $Tab.State['LdapFilter'] = $c['TxtRawLdapFilter'].Text }
            if ($c['TxtSearchBaseDn']) { $Tab.State['SearchBase'] = $c['TxtSearchBaseDn'].Text }
            if ($c['CmbSearchScope']) { $Tab.State['ScopeIndex'] = $c['CmbSearchScope'].SelectedIndex }
        }
        "LdapSql" {
            if ($c['TxtSqlQuery']) { $Tab.State['SqlQuery'] = $c['TxtSqlQuery'].Text }
        }
        "AttributeEditor" {
            if ($c['TxtAttrEditorDN']) { $Tab.State['AttrDN'] = $c['TxtAttrEditorDN'].Text }
            if ($c['TxtSearchAttributes']) { $Tab.State['SearchAttr'] = $c['TxtSearchAttributes'].Text }
            if ($c['ChkShowOperationalAttributes']) { $Tab.State['ShowOpAttr'] = [bool]$c['ChkShowOperationalAttributes'].IsChecked }
        }
        "SecurityAcl" {
            if ($c['TxtAclTargetDN']) { $Tab.State['AclDN'] = $c['TxtAclTargetDN'].Text }
            if ($c['TxtAclTrustee']) { $Tab.State['AclTrustee'] = $c['TxtAclTrustee'].Text }
        }
        "OUs" {
            if ($c['TxtFilterOUs']) { $Tab.State['FilterOUs'] = $c['TxtFilterOUs'].Text }
        }
        "RecycleBin" {
            if ($c['TxtSearchRecycleBin']) { $Tab.State['SearchRecycleBin'] = $c['TxtSearchRecycleBin'].Text }
        }
        "AuditReports" {
            if ($c['CmbAuditCategory']) { $Tab.State['AuditCatIdx'] = $c['CmbAuditCategory'].SelectedIndex }
            if ($c['CmbAuditDays']) { $Tab.State['AuditDaysIdx'] = $c['CmbAuditDays'].SelectedIndex }
        }
        "SchemaBrowser" {
            if ($c['TxtSearchSchema']) { $Tab.State['SearchSchema'] = $c['TxtSearchSchema'].Text }
        }
        "RequestLog" {
            if ($c['TxtFilterRequestLog']) { $Tab.State['FilterReqLog'] = $c['TxtFilterRequestLog'].Text }
        }
        "Connections" {
            if ($c['TxtSearchConnections']) { $Tab.State['SearchConnections'] = $c['TxtSearchConnections'].Text }
        }
        "ObjectCompare" {
            if ($c['TxtCompareObjectA']) { $Tab.State['CompA'] = $c['TxtCompareObjectA'].Text }
            if ($c['TxtCompareObjectB']) { $Tab.State['CompB'] = $c['TxtCompareObjectB'].Text }
        }
        "LdifStudio" {
            if ($c['TxtLdifEditor']) { $Tab.State['LdifText'] = $c['TxtLdifEditor'].Text }
        }
    }
}

function Restore-SecondaryPanelSessionState {
    param($Tab, $PanelObj, [string]$PanelName)
    if (-not $Tab -or -not $Tab.State -or -not $PanelObj) { return }
    $c = $PanelObj.Controls
    if (-not $c) { return }
    switch ($PanelName) {
        "Users" {
            if ($c['TxtSearchUsers'] -and $Tab.State.ContainsKey('SearchUsers')) {
                $c['TxtSearchUsers'].Text = $Tab.State['SearchUsers']
            }
            if ($Tab.State.ContainsKey('FilterUser')) {
                switch ($Tab.State['FilterUser']) {
                    "Active"   { if ($c['FilterUserActive'])   { $c['FilterUserActive'].IsChecked = $true } }
                    "Disabled" { if ($c['FilterUserDisabled']) { $c['FilterUserDisabled'].IsChecked = $true } }
                    "Locked"   { if ($c['FilterUserLocked'])   { $c['FilterUserLocked'].IsChecked = $true } }
                    default    { if ($c['FilterUserAll'])      { $c['FilterUserAll'].IsChecked = $true } }
                }
            }
            if ($c['CmbUserOUFilter'] -and $Tab.State.ContainsKey('OUFilter')) {
                $c['CmbUserOUFilter'].SelectedIndex = $Tab.State['OUFilter']
            }
        }
        "Groups" {
            if ($c['TxtSearchGroups'] -and $Tab.State.ContainsKey('SearchGroups')) {
                $c['TxtSearchGroups'].Text = $Tab.State['SearchGroups']
            }
            if ($Tab.State.ContainsKey('FilterGroup')) {
                switch ($Tab.State['FilterGroup']) {
                    "Security"     { if ($c['FilterGroupSec'])  { $c['FilterGroupSec'].IsChecked = $true } }
                    "Distribution" { if ($c['FilterGroupDist']) { $c['FilterGroupDist'].IsChecked = $true } }
                    default        { if ($c['FilterGroupAll'])  { $c['FilterGroupAll'].IsChecked = $true } }
                }
            }
        }
        "Computers" {
            if ($c['TxtSearchComputers'] -and $Tab.State.ContainsKey('SearchComputers')) {
                $c['TxtSearchComputers'].Text = $Tab.State['SearchComputers']
            }
            if ($Tab.State.ContainsKey('FilterComp')) {
                switch ($Tab.State['FilterComp']) {
                    "Enabled"  { if ($c['FilterCompEnabled'])  { $c['FilterCompEnabled'].IsChecked = $true } }
                    "Disabled" { if ($c['FilterCompDisabled']) { $c['FilterCompDisabled'].IsChecked = $true } }
                    default    { if ($c['FilterCompAll'])       { $c['FilterCompAll'].IsChecked = $true } }
                }
            }
        }
        "DirectorySearch" {
            if ($c['TxtRawLdapFilter'] -and $Tab.State.ContainsKey('LdapFilter')) { $c['TxtRawLdapFilter'].Text = $Tab.State['LdapFilter'] }
            if ($c['TxtSearchBaseDn'] -and $Tab.State.ContainsKey('SearchBase')) { $c['TxtSearchBaseDn'].Text = $Tab.State['SearchBase'] }
            if ($c['CmbSearchScope'] -and $Tab.State.ContainsKey('ScopeIndex')) { $c['CmbSearchScope'].SelectedIndex = $Tab.State['ScopeIndex'] }
        }
        "LdapSql" {
            if ($c['TxtSqlQuery'] -and $Tab.State.ContainsKey('SqlQuery')) { $c['TxtSqlQuery'].Text = $Tab.State['SqlQuery'] }
        }
        "AttributeEditor" {
            if ($c['TxtAttrEditorDN'] -and $Tab.State.ContainsKey('AttrDN')) { $c['TxtAttrEditorDN'].Text = $Tab.State['AttrDN'] }
            if ($c['TxtSearchAttributes'] -and $Tab.State.ContainsKey('SearchAttr')) { $c['TxtSearchAttributes'].Text = $Tab.State['SearchAttr'] }
            if ($c['ChkShowOperationalAttributes'] -and $Tab.State.ContainsKey('ShowOpAttr')) { $c['ChkShowOperationalAttributes'].IsChecked = $Tab.State['ShowOpAttr'] }
        }
        "SecurityAcl" {
            if ($c['TxtAclTargetDN'] -and $Tab.State.ContainsKey('AclDN')) { $c['TxtAclTargetDN'].Text = $Tab.State['AclDN'] }
            if ($c['TxtAclTrustee'] -and $Tab.State.ContainsKey('AclTrustee')) { $c['TxtAclTrustee'].Text = $Tab.State['AclTrustee'] }
        }
        "OUs" {
            if ($c['TxtFilterOUs'] -and $Tab.State.ContainsKey('FilterOUs')) { $c['TxtFilterOUs'].Text = $Tab.State['FilterOUs'] }
        }
        "RecycleBin" {
            if ($c['TxtSearchRecycleBin'] -and $Tab.State.ContainsKey('SearchRecycleBin')) { $c['TxtSearchRecycleBin'].Text = $Tab.State['SearchRecycleBin'] }
        }
        "AuditReports" {
            if ($c['CmbAuditCategory'] -and $Tab.State.ContainsKey('AuditCatIdx')) { $c['CmbAuditCategory'].SelectedIndex = $Tab.State['AuditCatIdx'] }
            if ($c['CmbAuditDays'] -and $Tab.State.ContainsKey('AuditDaysIdx')) { $c['CmbAuditDays'].SelectedIndex = $Tab.State['AuditDaysIdx'] }
        }
        "SchemaBrowser" {
            if ($c['TxtSearchSchema'] -and $Tab.State.ContainsKey('SearchSchema')) { $c['TxtSearchSchema'].Text = $Tab.State['SearchSchema'] }
        }
        "RequestLog" {
            if ($c['TxtFilterRequestLog'] -and $Tab.State.ContainsKey('FilterReqLog')) { $c['TxtFilterRequestLog'].Text = $Tab.State['FilterReqLog'] }
        }
        "Connections" {
            if ($c['TxtSearchConnections'] -and $Tab.State.ContainsKey('SearchConnections')) { $c['TxtSearchConnections'].Text = $Tab.State['SearchConnections'] }
        }
        "ObjectCompare" {
            if ($c['TxtCompareObjectA'] -and $Tab.State.ContainsKey('CompA')) { $c['TxtCompareObjectA'].Text = $Tab.State['CompA'] }
            if ($c['TxtCompareObjectB'] -and $Tab.State.ContainsKey('CompB')) { $c['TxtCompareObjectB'].Text = $Tab.State['CompB'] }
        }
        "LdifStudio" {
            if ($c['TxtLdifEditor'] -and $Tab.State.ContainsKey('LdifText')) { $c['TxtLdifEditor'].Text = $Tab.State['LdifText'] }
        }
        "HtmlView" {
            if ($c['TxtHtmlViewDN'] -and $Tab.State.ContainsKey('CurrentHtmlDN')) {
                $c['TxtHtmlViewDN'].Text = $Tab.State['CurrentHtmlDN']
            }
            if ($c['TxtHtmlViewDNPlaceholder']) {
                $hasText = -not [string]::IsNullOrEmpty($c['TxtHtmlViewDN'].Text)
                $c['TxtHtmlViewDNPlaceholder'].Visibility = if ($hasText) { [System.Windows.Visibility]::Collapsed } else { [System.Windows.Visibility]::Visible }
            }
            if ($c['TxtHtmlViewStatusBadge'] -and $Tab.State.ContainsKey('CurrentHtmlDN') -and $Tab.State['CurrentHtmlDN']) {
                $disp = ($Tab.State['CurrentHtmlDN'] -split ',')[0] -replace '^CN=|^OU=', ''
                $c['TxtHtmlViewStatusBadge'].Text = $disp
            }
            if ($c['BrowserHtmlView'] -and $Tab.State.ContainsKey('CurrentHtmlRaw') -and $Tab.State['CurrentHtmlRaw']) {
                Invoke-WorkspaceHost -Name "Set-SafeBrowserHtml" -NamedArgs @{ Browser = $c['BrowserHtmlView']; Html = $Tab.State['CurrentHtmlRaw'] }
            }
        }

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

    if (-not ($targetTab.PSObject.Properties['DockedPanelInstance'])) {
        $targetTab | Add-Member -MemberType NoteProperty -Name "DockedPanelInstance" -Value $null -Force
    }

    # If this specific tab instance is detached in its own window, keep it in foreground
    if ($state.DetachedWindows.ContainsKey($targetTab.Id)) {
        $dRec = $state.DetachedWindows[$targetTab.Id]
        $dWin = if ($dRec -is [System.Windows.Window]) { $dRec }
                elseif ($dRec -is [System.Collections.IDictionary] -and $dRec.ContainsKey('Window')) { $dRec['Window'] }
                elseif ($dRec.Window) { $dRec.Window }
                else { $null }
        if ($dWin) {
            if ($dWin.WindowState -eq [System.Windows.WindowState]::Minimized) {
                $dWin.WindowState = [System.Windows.WindowState]::Normal
            }
            [void]$dWin.Activate()
            [void]$dWin.Focus()
            return
        }
    }

    # Save state of previously active tab before switching
    if ($state.ActiveTabId -and $state.ActiveTabId -ne $targetTab.Id) {
        $prevTab = $state.OpenTabs | Where-Object { $_.Id -eq $state.ActiveTabId } | Select-Object -First 1
        if ($prevTab) {
            Save-TabSessionState -Tab $prevTab
        }
    }

    $state.ActiveTabId = $targetTab.Id
    $PanelName = $targetTab.PanelName
    $targetCtrlName = "Panel$PanelName"

    # Restore session state for the selected tab
    Restore-TabSessionState -Tab $targetTab

    $primaryPanel = $controls[$targetCtrlName]
    if ($controls['ViewportContainer']) {
        if (-not ($targetTab.PSObject.Properties['DockedPanelInstance'])) {
            $targetTab | Add-Member -MemberType NoteProperty -Name "DockedPanelInstance" -Value $null -Force
        }
        if ($targetTab.InstanceNumber -gt 1) {
            # Secondary instance: Ensure its dedicated panel instance is mounted in ViewportContainer
            if (-not $targetTab.DockedPanelInstance) {
                $secObj = New-PanelInstance -PanelName $PanelName
                Invoke-WorkspaceHost -Name "Connect-SecondaryPanelInstance" -NamedArgs @{ panelObj = $secObj; win = $script:window; tab = $targetTab; PanelName = $PanelName }
                $targetTab.DockedPanelInstance = $secObj.Panel
                if (-not ($targetTab.PSObject.Properties['DockedPanelControls'])) {
                    $targetTab | Add-Member -MemberType NoteProperty -Name "DockedPanelControls" -Value $secObj.Controls -Force
                } else {
                    $targetTab.DockedPanelControls = $secObj.Controls
                }
                Restore-SecondaryPanelSessionState -Tab $targetTab -PanelObj $secObj -PanelName $PanelName
            }
            if ($targetTab.DockedPanelInstance -and -not $controls['ViewportContainer'].Children.Contains($targetTab.DockedPanelInstance)) {
                Disconnect-VisualElement -Element $targetTab.DockedPanelInstance
                [void]$controls['ViewportContainer'].Children.Add($targetTab.DockedPanelInstance)
            }
            if ($targetTab.DockedPanelInstance) {
                $targetTab.DockedPanelInstance.Visibility = [System.Windows.Visibility]::Visible
            }
        } else {
            # Primary instance: Ensure primary panel is in ViewportContainer if not detached
            if ($primaryPanel -and -not $state.DetachedWindows.ContainsKey($targetTab.Id)) {
                if (-not $controls['ViewportContainer'].Children.Contains($primaryPanel)) {
                    Disconnect-VisualElement -Element $primaryPanel
                    [void]$controls['ViewportContainer'].Children.Add($primaryPanel)
                }
            }
        }

        foreach ($child in $controls['ViewportContainer'].Children) {
            if ($child -is [System.Windows.UIElement]) {
                $child.Visibility = if ($targetTab.DockedPanelInstance -and $child -eq $targetTab.DockedPanelInstance) {
                    [System.Windows.Visibility]::Visible
                } elseif (-not $targetTab.DockedPanelInstance -and $child -eq $primaryPanel) {
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

    Invoke-WorkspaceHost -Name "Add-NavHistory" -NamedArgs @{ PanelName = $PanelName }
    Update-WorkspaceTabStrip
}

Set-Alias -Name Detach-PanelToWindow -Value Dismount-PanelToWindow -Scope Global
function Dismount-PanelToWindow {    param (
        [string]$PanelName = "",
        [string]$TabId = ""
    )
    if (-not $state.AllowMultiWindow) {
        [System.Windows.MessageBox]::Show("Multi-Window workspace is currently disabled in Settings.", "Workspace Notice", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
        return
    }

    $targetTab = if (-not [string]::IsNullOrWhiteSpace($TabId)) {
        $state.OpenTabs | Where-Object { $_.Id -eq $TabId } | Select-Object -First 1
    } elseif ($state.ActiveTabId) {
        $activeT = $state.OpenTabs | Where-Object { $_.Id -eq $state.ActiveTabId } | Select-Object -First 1
        if ($activeT -and (-not $PanelName -or $activeT.PanelName -eq $PanelName)) { $activeT } else { $null }
    } else { $null }

    if (-not $targetTab -and -not [string]::IsNullOrWhiteSpace($PanelName)) {
        $targetTab = $state.OpenTabs | Where-Object { $_.PanelName -eq $PanelName } | Select-Object -First 1
    }

    if (-not $targetTab) { return }

    $targetTabId = $targetTab.Id
    $pName = $targetTab.PanelName

    # If already detached, activate and focus
    if ($state.DetachedWindows.ContainsKey($targetTabId)) {
        $dRec = $state.DetachedWindows[$targetTabId]
        $dWin = if ($dRec -is [System.Windows.Window]) { $dRec }
                elseif ($dRec -is [System.Collections.IDictionary] -and $dRec.ContainsKey('Window')) { $dRec['Window'] }
                elseif ($dRec.Window) { $dRec.Window }
                else { $null }
        if ($dWin) {
            if ($dWin.WindowState -eq [System.Windows.WindowState]::Minimized) {
                $dWin.WindowState = [System.Windows.WindowState]::Normal
            }
            [void]$dWin.Activate()
            [void]$dWin.Focus()
        }
        return
    }

    # Save session state before detaching
    Save-TabSessionState -Tab $targetTab

    $meta = if (-not [string]::IsNullOrWhiteSpace($pName) -and $script:PanelCatalog.Contains($pName)) {
        $script:PanelCatalog[$pName]
    } else {
        [PSCustomObject]@{ Title = $pName; Icon = "📋"; Category = "Tool Window" }
    }
    $tabDisplayTitle = if ($targetTab.Title) { $targetTab.Title } else { $meta.Title }

    # Load detached window instance
    $detachedXamlPath = Join-Path $viewsPath "DetachedPanelWindow.xaml"
    $detachedWin = Invoke-WorkspaceHost -Name "Import-XamlWindow" -NamedArgs @{ XamlPath = $detachedXamlPath }
    $currTheme  = if ($state -and $state.CurrentTheme) { $state.CurrentTheme } else { "Light" }
    $currAccent = if ($appConfig -and $appConfig.UI -and $appConfig.UI.AccentTone) { $appConfig.UI.AccentTone } else { "Blue" }
    if (Get-Command Sync-WindowThemeResources -ErrorAction SilentlyContinue) {
        Sync-WindowThemeResources -TargetWindow $detachedWin -Theme $currTheme -AccentTone $currAccent
    } else {
        foreach ($k in $window.Resources.Keys) {
            $detachedWin.Resources[$k] = $window.Resources[$k]
        }
    }
    if (Get-Command Apply-ThemeNode -ErrorAction SilentlyContinue) {
        Apply-ThemeNode $detachedWin $currTheme
    }
    Register-WpfExceptionHandler -Dispatcher $detachedWin.Dispatcher -Window $detachedWin

    $detachedWin.Title = "Active Directory Management Studio - $tabDisplayTitle"

    $txtIcon = $detachedWin.FindName("TxtDetachedIcon")
    if ($txtIcon) { $txtIcon.Text = if ($targetTab.Icon) { $targetTab.Icon } elseif ($meta.Icon) { $meta.Icon } else { "📋" } }
    $txtTitle = $detachedWin.FindName("TxtDetachedTitle")
    if ($txtTitle) { $txtTitle.Text = $tabDisplayTitle }
    $txtCategory = $detachedWin.FindName("TxtDetachedCategory")
    if ($txtCategory) { $txtCategory.Text = $meta.Category }

    $contentHost = $detachedWin.FindName("DetachedContentHost")

    $primaryKey = "Panel$pName"
    $primaryPanel = $controls[$primaryKey]
    $isPrimaryTab = ($targetTab.InstanceNumber -le 1)
    $primaryAlreadyDetached = [bool]($state.DetachedWindows.Values | Where-Object { -not $_.IsSecondary -and $_.PanelName -eq $pName })

    $panelToMount = $null
    $isSecondary = $false
    $namedControls = @{}

    if ($isPrimaryTab -and $primaryPanel -and -not $primaryAlreadyDetached) {
        Disconnect-VisualElement -Element $primaryPanel
        $panelToMount = $primaryPanel
        $isSecondary = $false
        $namedControls = $controls
    } else {
        $isSecondary = $true
        if ($targetTab.DockedPanelInstance) {
            $panelToMount = $targetTab.DockedPanelInstance
            Disconnect-VisualElement -Element $panelToMount
            $namedControls = if ($targetTab.PSObject.Properties['DockedPanelControls'] -and $targetTab.DockedPanelControls) {
                $targetTab.DockedPanelControls
            } else {
                Get-NamedElements -element $panelToMount
            }
        } else {
            $panelObj = New-PanelInstance -PanelName $pName
            $panelToMount = $panelObj.Panel
            $namedControls = $panelObj.Controls
            if (-not ($targetTab.PSObject.Properties['DockedPanelInstance'])) {
                $targetTab | Add-Member -MemberType NoteProperty -Name "DockedPanelInstance" -Value $panelToMount -Force
            } else {
                $targetTab.DockedPanelInstance = $panelToMount
            }
            if (-not ($targetTab.PSObject.Properties['DockedPanelControls'])) {
                $targetTab | Add-Member -MemberType NoteProperty -Name "DockedPanelControls" -Value $namedControls -Force
            } else {
                $targetTab.DockedPanelControls = $namedControls
            }
            Invoke-WorkspaceHost -Name "Connect-SecondaryPanelInstance" -NamedArgs @{ panelObj = $panelObj; win = $detachedWin; tab = $targetTab; PanelName = $pName }
            Restore-SecondaryPanelSessionState -Tab $targetTab -PanelObj $panelObj -PanelName $pName
        }
    }

    if ($contentHost -and $panelToMount) {
        Disconnect-VisualElement -Element $panelToMount
        [void]$contentHost.Children.Add($panelToMount)
        $panelToMount.Visibility = [System.Windows.Visibility]::Visible
    }

    $state.DetachedWindows[$targetTabId] = @{
        Window      = $detachedWin
        TabId       = $targetTabId
        PanelName   = $pName
        Panel       = $panelToMount
        IsSecondary = $isSecondary
        Controls    = $namedControls
    }

    $detachedWinClosed = $false
    $HandleCloseOrDock = {
        param([bool]$DockBackToMain)
        if ($detachedWinClosed) { return }
        $detachedWinClosed = $true
        if ($detachedWin.Tag -eq "TabRemoved") {
            if ($state.DetachedWindows.ContainsKey($targetTabId)) {
                [void]$state.DetachedWindows.Remove($targetTabId)
            }
            return
        }

        if ($isSecondary) {
            Save-SecondaryPanelSessionState -Tab $targetTab -PanelObj @{ Panel = $panelToMount; Controls = $namedControls } -PanelName $pName
        } else {
            Save-TabSessionState -Tab $targetTab
        }

        $gControlsVar = Get-Variable -Name 'controls' -Scope Global -ErrorAction SilentlyContinue
        $gControls = if ($gControlsVar) { $gControlsVar.Value } else { $null }
        $vContainer = if ($controls -and $controls['ViewportContainer']) { $controls['ViewportContainer'] }
                      elseif ($script:controls -and $script:controls['ViewportContainer']) { $script:controls['ViewportContainer'] }
                      elseif ($gControls -and $gControls['ViewportContainer']) { $gControls['ViewportContainer'] }
                      elseif ($window) { $window.FindName('ViewportContainer') }
                      else { $null }

        if (-not $isSecondary -and $primaryPanel -and $vContainer) {
            Disconnect-VisualElement -Element $primaryPanel
            if (-not $vContainer.Children.Contains($primaryPanel)) {
                [void]$vContainer.Children.Add($primaryPanel)
            }
            $primaryPanel.Visibility = if ($DockBackToMain) { [System.Windows.Visibility]::Visible } else { [System.Windows.Visibility]::Collapsed }
        } elseif ($isSecondary -and $panelToMount -and $vContainer) {
            Disconnect-VisualElement -Element $panelToMount
            if (-not ($targetTab.PSObject.Properties['DockedPanelInstance'])) {
                $targetTab | Add-Member -MemberType NoteProperty -Name "DockedPanelInstance" -Value $panelToMount -Force
            } else {
                $targetTab.DockedPanelInstance = $panelToMount
            }
            if (-not ($targetTab.PSObject.Properties['DockedPanelControls'])) {
                $targetTab | Add-Member -MemberType NoteProperty -Name "DockedPanelControls" -Value $namedControls -Force
            } else {
                $targetTab.DockedPanelControls = $namedControls
            }
            if (-not $vContainer.Children.Contains($panelToMount)) {
                [void]$vContainer.Children.Add($panelToMount)
            }
            $panelToMount.Visibility = if ($DockBackToMain) { [System.Windows.Visibility]::Visible } else { [System.Windows.Visibility]::Collapsed }
        }

        if ($state.DetachedWindows.ContainsKey($targetTabId)) {
            [void]$state.DetachedWindows.Remove($targetTabId)
        }

        if ($DockBackToMain) {
            Select-WorkspaceTab -TabId $targetTabId
            if ($window) {
                if ($window.WindowState -eq [System.Windows.WindowState]::Minimized) {
                    $window.WindowState = [System.Windows.WindowState]::Normal
                }
                [void]$window.Activate()
                [void]$window.Focus()
            }
        } else {
            Update-WorkspaceTabStrip
        }
    }.GetNewClosure()

    $detachedWin.Tag = $HandleCloseOrDock

    $btnDock = $detachedWin.FindName("BtnDockBack")
    if ($btnDock) {
        $btnDock.Add_Click([System.Windows.RoutedEventHandler]{
            param($s, $e)
            $null = $s; $null = $e
            & $HandleCloseOrDock $true
            $detachedWin.Close()
        }.GetNewClosure())
    }

    $detachedWin.Add_Closing([System.ComponentModel.CancelEventHandler]{
        param($s, $e)
        $null = $s; $null = $e
        & $HandleCloseOrDock $true
    }.GetNewClosure())

    $detachedWin.Add_KeyDown([System.Windows.Input.KeyEventHandler]{
        param($s, $e)
        $null = $s
        if ($e.Key -eq [System.Windows.Input.Key]::W -and ($e.KeyboardDevice.Modifiers -band [System.Windows.Input.ModifierKeys]::Control)) {
            & $HandleCloseOrDock $true
            $detachedWin.Close()
            $e.Handled = $true
        }
    }.GetNewClosure())

    $detachedWin.Show()
    Update-WorkspaceTabStrip

    # If this was the active tab in MainWindow, switch MainWindow to an active docked tab
    if ($state.ActiveTabId -eq $targetTabId) {
        $remainingDocked = $state.OpenTabs | Where-Object { -not $state.DetachedWindows.ContainsKey($_.Id) }
        if ($remainingDocked -and ($remainingDocked.Count -gt 0)) {
            Select-WorkspaceTab -TabId $remainingDocked[0].Id
        }
    }
}

Set-Alias -Name Dock-PanelToMainWindow -Value Mount-PanelToMainWindow -Scope Global
function Mount-PanelToMainWindow {    param (
        [string]$PanelName = "",
        [string]$TabId = "",
        [switch]$NoActivate
    )
    $targetTabId = if (-not [string]::IsNullOrWhiteSpace($TabId)) {
        $TabId
    } elseif (-not [string]::IsNullOrWhiteSpace($PanelName)) {
        $found = foreach ($k in $state.DetachedWindows.Keys) {
            $t = $state.OpenTabs | Where-Object { $_.Id -eq $k -and $_.PanelName -eq $PanelName } | Select-Object -First 1
            if ($t) { $t.Id; break }
        }
        $found
    } else { $null }

    if (-not $targetTabId -or -not $state.DetachedWindows.ContainsKey($targetTabId)) { return }

    $dRec = $state.DetachedWindows[$targetTabId]
    $dWin = if ($dRec -is [System.Windows.Window]) { $dRec }
            elseif ($dRec -is [System.Collections.IDictionary] -and $dRec.ContainsKey('Window')) { $dRec['Window'] }
            elseif ($dRec.Window) { $dRec.Window }
            else { $null }

    if ($dWin) {
        try {
            $closeDockHandler = $dWin.Tag
            if ($closeDockHandler -is [scriptblock]) {
                & $closeDockHandler (-not $NoActivate)
            }
            $dWin.Close()
        } catch {
            Write-AppError -Category "Workspace" -Message "Error during dock back: $_"
        }
    } else {
        [void]$state.DetachedWindows.Remove($targetTabId)
    }

    if (-not $NoActivate -and -not $dWin) {
        Select-WorkspaceTab -TabId $targetTabId
        if ($window) {
            if ($window.WindowState -eq [System.Windows.WindowState]::Minimized) {
                $window.WindowState = [System.Windows.WindowState]::Normal
            }
            [void]$window.Activate()
            [void]$window.Focus()
        }
    } else {
        Update-WorkspaceTabStrip
    }
}

Set-Alias -Name Dock-AllDetachedWindows -Value Mount-AllDetachedWindows -Scope Global
function Mount-AllDetachedWindows {    if (-not $state.DetachedWindows -or $state.DetachedWindows.Count -eq 0) {
        Invoke-WorkspaceHost -Name "Set-Status" -NamedArgs @{ Message = "No detached tool windows are currently open." }
        return
    }
    $tabIds = @($state.DetachedWindows.Keys)
    foreach ($tId in $tabIds) {
        Dock-PanelToMainWindow -TabId $tId -NoActivate
    }
    if ($state.ActiveTabId) {
        Select-WorkspaceTab -TabId $state.ActiveTabId
    }
    Invoke-WorkspaceHost -Name "Set-Status" -NamedArgs @{ Message = "All detached tool windows docked back into main window." }
}

function Show-AllDetachedWindows {
    if (-not $state.DetachedWindows -or $state.DetachedWindows.Count -eq 0) {
        Invoke-WorkspaceHost -Name "Set-Status" -NamedArgs @{ Message = "No detached tool windows are currently open." }
        return
    }
    foreach ($dRec in $state.DetachedWindows.Values) {
        $dWin = if ($dRec -is [System.Windows.Window]) { $dRec }
                elseif ($dRec -is [System.Collections.IDictionary] -and $dRec.ContainsKey('Window')) { $dRec['Window'] }
                elseif ($dRec.Window) { $dRec.Window }
                else { $null }
        if ($dWin) {
            if ($dWin.WindowState -eq [System.Windows.WindowState]::Minimized) {
                $dWin.WindowState = [System.Windows.WindowState]::Normal
            }
            [void]$dWin.Activate()
        }
    }
    Invoke-WorkspaceHost -Name "Set-Status" -NamedArgs @{ Message = "All detached tool windows active." }
}

function Reset-WorkspaceLayout {
    Dock-AllDetachedWindows
    $defaultTabs = if ($script:DefaultStartupTabs) { @($script:DefaultStartupTabs) } else { @("Dashboard", "Users", "SecurityAcl", "ReplicationSuite") }
    $state.OpenTabs.Clear()
    foreach ($t in $defaultTabs) {
        Add-WorkspaceTab -PanelName $t -Activate $false
    }
    $dashTab = $state.OpenTabs | Where-Object { $_.PanelName -eq "Dashboard" } | Select-Object -First 1
    $targetId = if ($dashTab) { $dashTab.Id } elseif ($state.OpenTabs.Count -gt 0) { $state.OpenTabs[0].Id } else { "Dashboard" }
    Select-WorkspaceTab -TabId $targetId
    Set-WorkspaceMode -Mode "Tabs"
    $appConfig.UI.OpenTabs = @($defaultTabs)
    $appConfig.UI.ActiveTab = "Dashboard"
    Save-AppSettings -Config $appConfig
    Invoke-WorkspaceHost -Name "Set-Status" -NamedArgs @{ Message = "Workspace layout reset to default multi-tab layout." }
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
        $null = $s; $null = $e
        Set-WorkspaceMode -Mode "Tabs"
        Save-AppSettings -Config $appConfig
        Invoke-WorkspaceHost -Name "Set-Status" -NamedArgs @{ Message = "Workspace layout changed to: Multi-Tab Workspace" }
    })
    [void]$cm.Items.Add($miTabs)

    # Item: Single Window Viewport
    $miSingle = [System.Windows.Controls.MenuItem]::new()
    $isSingle = ($state.WorkspaceMode -eq "Single")
    $miSingle.Header = if ($isSingle) { "✔  🔲 Single Window Viewport (Active)" } else { "    🔲 Single Window Viewport" }
    $miSingle.FontWeight = if ($isSingle) { [System.Windows.FontWeights]::SemiBold } else { [System.Windows.FontWeights]::Normal }
    $miSingle.Add_Click([System.Windows.RoutedEventHandler]{
        param($s, $e)
        $null = $s; $null = $e
        Set-WorkspaceMode -Mode "Single"
        Save-AppSettings -Config $appConfig
        Invoke-WorkspaceHost -Name "Set-Status" -NamedArgs @{ Message = "Workspace layout changed to: Single Window Viewport" }
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
        $null = $s; $null = $e
        Launch-NewApplicationWindow
    })
    [void]$cm.Items.Add($miNewAppWin)

    # Open Active Tool in Detached Window
    $miNewToolWin = [System.Windows.Controls.MenuItem]::new()
    $miNewToolWin.Header = "⧉  Open Active Tool in Detached Window"
    $miNewToolWin.IsEnabled = [bool]($state.ActiveTabId)
    $miNewToolWin.Add_Click([System.Windows.RoutedEventHandler]{
        param($s, $e)
        $null = $s; $null = $e
        $activeTab = $state.OpenTabs | Where-Object { $_.Id -eq $state.ActiveTabId } | Select-Object -First 1
        $p = if ($activeTab) { $activeTab.PanelName } else { $state.ActiveTabId }
        if (-not [string]::IsNullOrWhiteSpace($p)) {
            Add-WorkspaceTab -PanelName $p -NewInstance -Activate $true
            $newTab = $state.OpenTabs | Where-Object { $_.PanelName -eq $p } | Select-Object -Last 1
            if ($newTab) { Detach-PanelToWindow -TabId $newTab.Id }
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
        $null = $s; $null = $e
        $activeTab = $state.OpenTabs | Where-Object { $_.Id -eq $state.ActiveTabId } | Select-Object -First 1
        if ($activeTab) {
            Detach-PanelToWindow -PanelName $activeTab.PanelName -TabId $activeTab.Id
        }
    })
    [void]$cm.Items.Add($miDetachCur)

    # Dock All Windows Back
    $miDockAll = [System.Windows.Controls.MenuItem]::new()
    $miDockAll.Header = if ($detachedCount -gt 0) { "⬇️  Dock All Windows Back into Main Window ($detachedCount detached)" } else { "⬇️  Dock All Windows Back into Main Window" }
    $miDockAll.IsEnabled = ($detachedCount -gt 0)
    $miDockAll.Add_Click([System.Windows.RoutedEventHandler]{
        param($s, $e)
        $null = $s; $null = $e
        Dock-AllDetachedWindows
    })
    [void]$cm.Items.Add($miDockAll)

    if ($detachedCount -gt 0) {
        $miFocusAll = [System.Windows.Controls.MenuItem]::new()
        $miFocusAll.Header = "🪟  Bring All Detached Windows to Front"
        $miFocusAll.Add_Click([System.Windows.RoutedEventHandler]{
            param($s, $e)
            $null = $s; $null = $e
            Show-AllDetachedWindows
        })
        [void]$cm.Items.Add($miFocusAll)
    }

    # Toggle Multi-Window Allowed
    $miAllowMulti = [System.Windows.Controls.MenuItem]::new()
    $miAllowMulti.Header = if ($state.AllowMultiWindow) { "✔  Allow Multi-Window (Detached Windows Enabled)" } else { "    Allow Multi-Window (Detached Windows Disabled)" }
    $miAllowMulti.Add_Click([System.Windows.RoutedEventHandler]{
        param($s, $e)
        $null = $s; $null = $e
        $state.AllowMultiWindow = -not $state.AllowMultiWindow
        $appConfig.UI.AllowMultiWindow = $state.AllowMultiWindow
        Save-AppSettings -Config $appConfig
        if (-not $state.AllowMultiWindow) {
            Dock-AllDetachedWindows
        }
        Update-WorkspaceTabStrip
        Invoke-WorkspaceHost -Name "Set-Status" -NamedArgs @{ Message = "Multi-Window workspace is now $(if ($state.AllowMultiWindow) { 'Enabled' } else { 'Disabled' })." }
    })
    [void]$cm.Items.Add($miAllowMulti)

    # SEPARATOR
    [void]$cm.Items.Add([System.Windows.Controls.Separator]::new())

    # SECTION 3: TABS & LAYOUT PRESETS
    $miNewTab = [System.Windows.Controls.MenuItem]::new()
    $miNewTab.Header = "➕  Open Tool in New Tab..."
    $miNewTab.Add_Click([System.Windows.RoutedEventHandler]{
        param($s, $e)
        $null = $s; $null = $e
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
        $null = $s; $null = $e
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
        $null = $s; $null = $e
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

Set-Alias -Name Init-SidebarNavigationContextMenus -Value Initialize-SidebarNavigationContextMenus -Scope Global
function Initialize-SidebarNavigationContextMenus {    $panels = @(
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
                $null = $e
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
                $null = $e
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
                $null = $e
                $target = if ($s -is [System.Windows.FrameworkElement] -and $s.Tag) { $s.Tag } else { $null }
                if (-not [string]::IsNullOrWhiteSpace($target)) {
                    Detach-PanelToWindow -PanelName $target
                }
            })
            [void]$cm.Items.Add($miWin)

            $miIndWin = [System.Windows.Controls.MenuItem]::new()
            $miIndWin.Header = "⧉ Open in Detached Window"
            $miIndWin.Tag = $p
            $miIndWin.Add_Click([System.Windows.RoutedEventHandler]{
                param($s, $e)
                $null = $e
                $target = if ($s -is [System.Windows.FrameworkElement] -and $s.Tag) { $s.Tag } else { $null }
                if (-not [string]::IsNullOrWhiteSpace($target)) {
                    Add-WorkspaceTab -PanelName $target -NewInstance -Activate $true
                    $newTab = $state.OpenTabs | Where-Object { $_.PanelName -eq $target } | Select-Object -Last 1
                    if ($newTab) { Detach-PanelToWindow -TabId $newTab.Id }
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

    # JIT Lazy Service Loading for Target Panel
    $lazyServices = switch ($PanelName) {
        'SecurityAcl'        { @('AclService') }
        'KerberosSuite'      { @('KerberosService') }
        'ReplicationSuite'   { @('ReplicationService', 'GpoService') }
        'DiagnosticsToolbox' { @('DiagnosticService') }
        'NetworkDiagnostics' { @('NetworkService') }
        'DirectorySearch'    { @('ScimFilterService', 'ScimService') }
        default              { @() }
    }
    foreach ($svc in $lazyServices) {
        if ($ExecutionContext.SessionState.InvokeCommand.GetCommand('Import-ServiceLazy', [System.Management.Automation.CommandTypes]::All)) {
            Import-ServiceLazy $svc
        } else {
            Invoke-WorkspaceHost -Name "Import-ServiceLazy" -NamedArgs @{ ServiceName = $svc }
        }
    }

    if ($state.WorkspaceMode -eq "Tabs") {
        $activeDocked = $state.OpenTabs | Where-Object { $_.Id -eq $state.ActiveTabId -and $_.PanelName -eq $PanelName } | Select-Object -First 1
        if ($activeDocked) {
            Select-WorkspaceTab -TabId $activeDocked.Id
            Invoke-WorkspaceHost -Name "Add-NavHistory" -NamedArgs @{ PanelName = $PanelName }
            return
        }
        $dockedTab = $state.OpenTabs | Where-Object { $_.PanelName -eq $PanelName -and -not $state.DetachedWindows.ContainsKey($_.Id) } | Select-Object -First 1
        if ($dockedTab) {
            Select-WorkspaceTab -TabId $dockedTab.Id
        } else {
            $detachedTab = $state.OpenTabs | Where-Object { $_.PanelName -eq $PanelName -and $state.DetachedWindows.ContainsKey($_.Id) } | Select-Object -First 1
            if ($detachedTab) {
                $dRec = $state.DetachedWindows[$detachedTab.Id]
                $dWin = if ($dRec -is [System.Windows.Window]) { $dRec }
                        elseif ($dRec -is [System.Collections.IDictionary] -and $dRec.ContainsKey('Window')) { $dRec['Window'] }
                        elseif ($dRec.Window) { $dRec.Window }
                        else { $null }
                if ($dWin) {
                    if ($dWin.WindowState -eq [System.Windows.WindowState]::Minimized) { $dWin.WindowState = [System.Windows.WindowState]::Normal }
                    [void]$dWin.Activate()
                    [void]$dWin.Focus()
                }
            } else {
                Add-WorkspaceTab -PanelName $PanelName -Activate $true
            }
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
    Invoke-WorkspaceHost -Name "Add-NavHistory" -NamedArgs @{ PanelName = $PanelName }
}

Export-ModuleMember -Function `
    Initialize-WorkspaceContext, `
    Initialize-PanelXamlCache, `
    Start-NewApplicationWindow, `
    Rename-WorkspaceTab, `
    Save-TabSessionState, `
    Restore-TabSessionState, `
    Update-WorkspaceTabStrip, `
    Disconnect-VisualElement, `
    Add-WorkspaceTab, `
    Remove-WorkspaceTab, `
    Get-NamedElements, `
    New-PanelInstance, `
    Save-SecondaryPanelSessionState, `
    Restore-SecondaryPanelSessionState, `
    Select-WorkspaceTab, `
    Dismount-PanelToWindow, `
    Mount-PanelToMainWindow, `
    Mount-AllDetachedWindows, `
    Show-AllDetachedWindows, `
    Reset-WorkspaceLayout, `
    Show-WorkspaceLayoutMenu, `
    Set-WorkspaceMode, `
    Initialize-SidebarNavigationContextMenus, `
    Show-Panel `
    -Alias `
    Launch-NewApplicationWindow, `
    Detach-PanelToWindow, `
    Dock-PanelToMainWindow, `
    Dock-AllDetachedWindows, `
    Init-SidebarNavigationContextMenus