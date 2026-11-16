<#
.SYNOPSIS
    Theme Engine & Semantic Palette Manager for Active Directory Management Studio.
.DESCRIPTION
    Provides O(1) ResourceDictionary theme switching between Dark and Light modes,
    accent tone resolution, recursive fallback brush synchronization for legacy nodes,
    and unified WPF modal input prompt helpers replacing Win32 InputBox popups.
#>

$script:BrushConverter = New-Object System.Windows.Media.BrushConverter
$script:OriginalBrushes = @{}
$script:ThemeDictCache = @{}

$script:ColorMapBgLight = @{
    '#0E1017' = '#F8FAFC'
    '#0F1015' = '#F1F5F9'
    '#0F1117' = '#F8FAFC'
    '#111319' = '#FFFFFF'
    '#111827' = '#F8FAFC'
    '#13151D' = '#F1F5F9'
    '#14161C' = '#F8FAFC'
    '#14161F' = '#F8FAFC'
    '#15171E' = '#FFFFFF'
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
    '#1E3A5F' = '#E0F2FE'
    '#1F232E' = '#F1F5F9'
    '#1F232F' = '#F1F5F9'
    '#1F2937' = '#F1F5F9'
    '#22252F' = '#F1F5F9'
    '#222634' = '#F1F5F9'
    '#252936' = '#FFFFFF'
    '#252A3A' = '#F1F5F9'
    '#253352' = '#E2E8F0'
    '#262A38' = '#E2E8F0'
    '#282D3E' = '#F1F5F9'
    '#292E3E' = '#F1F5F9'
    '#292F42' = '#F1F5F9'
    '#2A2D3A' = '#FFFFFF'
    '#2B2F3E' = '#F1F5F9'
    '#2D313F' = '#F1F5F9'
    '#2D3243' = '#E2E8F0'
    '#2E3345' = '#FFFFFF'
    '#323749' = '#E2E8F0'
    '#334155' = '#E2E8F0'
    '#373B4D' = '#E2E8F0'
    '#3A1C20' = '#FEF2F2'
    '#3A3F52' = '#E2E8F0'
    '#064E3B' = '#ECFDF5'
    '#78350F' = '#FEFCE8'
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
    '#A7F3D0' = '#047857'
    '#34D399' = '#059669'
    '#10B981' = '#047857'
    '#FBBF24' = '#D97706'
    '#F59E0B' = '#B45309'
    '#FDE68A' = '#92400E'
    '#EF4444' = '#DC2626'
    '#4B5563' = '#475569'
    '#FFA3A8' = '#DC2626'
}

$script:ColorMapBorderLight = @{
    '#1F2937' = '#CBD5E1'
    '#252936' = '#CBD5E1'
    '#252A3A' = '#CBD5E1'
    '#262A38' = '#CBD5E1'
    '#292E3E' = '#CBD5E1'
    '#2D313F' = '#CBD5E1'
    '#2E3345' = '#CBD5E1'
    '#2F3446' = '#CBD5E1'
    '#334155' = '#CBD5E1'
    '#373B4D' = '#CBD5E1'
    '#374151' = '#CBD5E1'
    '#383E54' = '#CBD5E1'
    '#3A3F52' = '#CBD5E1'
    '#4B526D' = '#94A3B8'
    '#4E546D' = '#94A3B8'
}

$script:ColorMapBgDark = @{
    '#F1F5F9' = '#161820'
    '#F8FAFC' = '#14161C'
    '#FFFFFF' = '#1A1D27'
    '#E2E8F0' = '#253352'
    '#FEF2F2' = '#3A1C20'
    '#E0F2FE' = '#1E3A5F'
    '#FEFCE8' = '#78350F'
}

$script:ColorMapFgDark = @{
    '#0F172A' = '#FFFFFF'
    '#1E293B' = '#E5E7EB'
    '#334155' = '#D1D5DB'
    '#475569' = '#9CA3AF'
    '#64748B' = '#6B7280'
    '#2563EB' = '#60A5FA'
    '#0284C7' = '#38BDF8'
    '#0369A1' = '#38BDF8'
    '#1D4ED8' = '#93C5FD'
    '#7C3AED' = '#A78BFA'
    '#059669' = '#34D399'
    '#047857' = '#10B981'
    '#D97706' = '#FBBF24'
    '#B45309' = '#F59E0B'
    '#92400E' = '#FDE68A'
    '#DC2626' = '#EF4444'
}

$script:ColorMapBorderDark = @{
    '#CBD5E1' = '#2F3446'
    '#94A3B8' = '#4B526D'
    '#E2E8F0' = '#252936'
}

function Convert-BrushToHex {
    param($Brush)
    if (-not $Brush) { return "" }
    if ($Brush -is [System.Windows.Media.SolidColorBrush]) {
        if ($Brush.Color.A -eq 0) { return "TRANSPARENT" }
        return ("#{0:X2}{1:X2}{2:X2}" -f $Brush.Color.R, $Brush.Color.G, $Brush.Color.B).ToUpper()
    }
    return ""
}

function Test-IsDynamicExpression {
    param($Node, $Property)
    if (-not $Node -or -not $Property) { return $false }
    try {
        $source = [System.Windows.DependencyPropertyHelper]::GetValueSource($Node, $Property)
        return [bool]$source.IsExpression
    } catch {
        return $false
    }
}

function Import-ThemeDictionary {
    [CmdletBinding()]
    param(
        [ValidateSet("Dark", "Light")]
        [string]$Theme = "Dark",
        [string]$ThemesPath = ""
    )
    if ($script:ThemeDictCache.ContainsKey($Theme) -and $script:ThemeDictCache[$Theme]) {
        return $script:ThemeDictCache[$Theme]
    }
    if ([string]::IsNullOrWhiteSpace($ThemesPath)) {
        $ThemesPath = Join-Path (Split-Path -Parent $PSScriptRoot) "Themes"
    }
    $file = Join-Path $ThemesPath "${Theme}Theme.xaml"
    if (-not (Test-Path $file)) { return $null }
    $fs = [System.IO.FileStream]::new($file, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read, 16384)
    try {
        $dict = [System.Windows.Markup.XamlReader]::Load($fs)
        $script:ThemeDictCache[$Theme] = $dict
        return $dict
    } finally {
        $fs.Dispose()
    }
}

function Set-ThemeNode {
    param(
        $Node,
        [string]$TargetTheme
    )
    if (-not $Node -or -not ($Node -is [System.Windows.FrameworkElement])) { return }
    if ($Node.Name -in @('BorderSearchAttrOutcome', 'TxtSearchAttrOutcomeLabel', 'TxtSearchAttrOutcome')) {
        return
    }
    $id = $Node.GetHashCode()

    $bgProp = switch ($Node) {
        { $_ -is [System.Windows.Controls.Border] }    { [System.Windows.Controls.Border]::BackgroundProperty }
        { $_ -is [System.Windows.Controls.Control] }   { [System.Windows.Controls.Control]::BackgroundProperty }
        { $_ -is [System.Windows.Controls.Panel] }     { [System.Windows.Controls.Panel]::BackgroundProperty }
        { $_ -is [System.Windows.Controls.TextBlock] } { [System.Windows.Controls.TextBlock]::BackgroundProperty }
        default { $null }
    }
    $fgProp = switch ($Node) {
        { $_ -is [System.Windows.Controls.Control] }   { [System.Windows.Controls.Control]::ForegroundProperty }
        { $_ -is [System.Windows.Controls.TextBlock] } { [System.Windows.Controls.TextBlock]::ForegroundProperty }
        default { $null }
    }
    $borderProp = switch ($Node) {
        { $_ -is [System.Windows.Controls.Border] }  { [System.Windows.Controls.Border]::BorderBrushProperty }
        { $_ -is [System.Windows.Controls.Control] } { [System.Windows.Controls.Control]::BorderBrushProperty }
        default { $null }
    }

    $localBg = if ($bgProp) { $Node.ReadLocalValue($bgProp) } else { [System.Windows.DependencyProperty]::UnsetValue }
    $isBgDynamic = ($bgProp -and (Test-IsDynamicExpression $Node $bgProp))
    $hasLocalBg = ($localBg -ne [System.Windows.DependencyProperty]::UnsetValue -and -not $isBgDynamic)

    $localFg = if ($fgProp) { $Node.ReadLocalValue($fgProp) } else { [System.Windows.DependencyProperty]::UnsetValue }
    $isFgDynamic = ($fgProp -and (Test-IsDynamicExpression $Node $fgProp))
    $hasLocalFg = ($localFg -ne [System.Windows.DependencyProperty]::UnsetValue -and -not $isFgDynamic)

    $localBorder = if ($borderProp) { $Node.ReadLocalValue($borderProp) } else { [System.Windows.DependencyProperty]::UnsetValue }
    $isBorderDynamic = ($borderProp -and (Test-IsDynamicExpression $Node $borderProp))
    $hasLocalBorder = ($localBorder -ne [System.Windows.DependencyProperty]::UnsetValue -and -not $isBorderDynamic)

    if ($TargetTheme -eq "Light") {
        if (-not $script:OriginalBrushes.ContainsKey($id)) {
            $script:OriginalBrushes[$id] = @{
                Bg     = if ($hasLocalBg) { $localBg } else { $null }
                Fg     = if ($hasLocalFg) { $localFg } else { $null }
                Border = if ($hasLocalBorder) { $localBorder } else { $null }
            }
        }
        $orig = $script:OriginalBrushes[$id]

        if ($orig.Bg) {
            $hex = Convert-BrushToHex $orig.Bg
            if ($hex -ne "TRANSPARENT" -and $script:ColorMapBgLight.ContainsKey($hex)) {
                $Node.Background = $script:BrushConverter.ConvertFromString($script:ColorMapBgLight[$hex])
            }
        }

        if ($orig.Fg) {
            $isAccentHost = $false
            $checkBg = $Node.Background
            if (-not $checkBg -and ($Node.Parent -is [System.Windows.Controls.Button] -or $Node.Parent -is [System.Windows.Controls.Border])) {
                $checkBg = $Node.Parent.Background
            } elseif (-not $checkBg -and $Node.Parent -is [System.Windows.Controls.Panel] -and ($Node.Parent.Parent -is [System.Windows.Controls.Button] -or $Node.Parent.Parent -is [System.Windows.Controls.Border])) {
                $checkBg = $Node.Parent.Parent.Background
            }
            if ($checkBg) {
                $bgHex = Convert-BrushToHex $checkBg
                if ($bgHex -in @('#0078D4', '#107C41', '#D13438', '#D97706', '#4F46E5', '#0284C7', '#DC2626', '#064E3B', '#2563EB', '#8E5AA5')) {
                    $isAccentHost = $true
                }
            }
            if (-not $isAccentHost) {
                $hex = Convert-BrushToHex $orig.Fg
                if ($hex -ne "TRANSPARENT" -and $script:ColorMapFgLight.ContainsKey($hex)) {
                    $Node.Foreground = $script:BrushConverter.ConvertFromString($script:ColorMapFgLight[$hex])
                }
            }
        }

        if ($orig.Border) {
            $hex = Convert-BrushToHex $orig.Border
            if ($hex -ne "TRANSPARENT" -and $script:ColorMapBorderLight.ContainsKey($hex)) {
                $Node.BorderBrush = $script:BrushConverter.ConvertFromString($script:ColorMapBorderLight[$hex])
            }
        }
    } else {
        if ($script:OriginalBrushes.ContainsKey($id)) {
            $saved = $script:OriginalBrushes[$id]
            if ($null -ne $saved.Bg) { $Node.Background = $saved.Bg } elseif ($bgProp -and -not $isBgDynamic) { $Node.ClearValue($bgProp) }
            if ($null -ne $saved.Fg) { $Node.Foreground = $saved.Fg } elseif ($fgProp -and -not $isFgDynamic) { $Node.ClearValue($fgProp) }
            if ($null -ne $saved.Border) { $Node.BorderBrush = $saved.Border } elseif ($borderProp -and -not $isBorderDynamic) { $Node.ClearValue($borderProp) }
        } else {
            if ($bgProp -and -not $isBgDynamic -and $hasLocalBg) {
                $hex = Convert-BrushToHex $localBg
                if ($script:ColorMapBgDark.ContainsKey($hex)) {
                    $Node.Background = $script:BrushConverter.ConvertFromString($script:ColorMapBgDark[$hex])
                } else { $Node.ClearValue($bgProp) }
            }
            if ($fgProp -and -not $isFgDynamic -and $hasLocalFg) {
                $hex = Convert-BrushToHex $localFg
                if ($script:ColorMapFgDark.ContainsKey($hex)) {
                    $Node.Foreground = $script:BrushConverter.ConvertFromString($script:ColorMapFgDark[$hex])
                } else { $Node.ClearValue($fgProp) }
            }
            if ($borderProp -and -not $isBorderDynamic -and $hasLocalBorder) {
                $hex = Convert-BrushToHex $localBorder
                if ($script:ColorMapBorderDark.ContainsKey($hex)) {
                    $Node.BorderBrush = $script:BrushConverter.ConvertFromString($script:ColorMapBorderDark[$hex])
                } else { $Node.ClearValue($borderProp) }
            }
        }
    }

    foreach ($child in [System.Windows.LogicalTreeHelper]::GetChildren($Node)) {
        if ($child -is [System.Windows.FrameworkElement]) {
            Set-ThemeNode -Node $child -TargetTheme $TargetTheme
        }
    }
}

function Sync-WindowThemeResources {
    param(
        [System.Windows.Window]$TargetWindow,
        [ValidateSet("Dark", "Light")]
        [string]$Theme = "Dark",
        [string]$AccentTone = "Blue"
    )
    if (-not $TargetWindow) { return }
    $dict = Import-ThemeDictionary -Theme $Theme
    if ($dict) {
        foreach ($key in $dict.Keys) {
            $TargetWindow.Resources[$key] = $dict[$key]
            if ([System.Windows.Application]::Current -and [System.Windows.Application]::Current.Resources) {
                [System.Windows.Application]::Current.Resources[$key] = $dict[$key]
            }
        }
    }
    $accentPair = switch -Wildcard ($AccentTone) {
        "*Sky*"     { @("#0284C7", "#0EA5E9", "#0369A1") }
        "*Emerald*" { @("#107C41", "#15803D", "#065F46") }
        "*Indigo*"  { @("#4F46E5", "#6366F1", "#4338CA") }
        "*Amber*"   { @("#D97706", "#F59E0B", "#B45309") }
        default     { @("#0078D4", "#1084D9", "#006CBE") }
    }
    $accentBrush       = $script:BrushConverter.ConvertFromString($accentPair[0])
    $accentHoverBrush  = $script:BrushConverter.ConvertFromString($accentPair[1])
    $accentActiveBrush = $script:BrushConverter.ConvertFromString($accentPair[2])
    $TargetWindow.Resources["AccentPrimary"] = $accentBrush
    $TargetWindow.Resources["AccentHover"]   = $accentHoverBrush
    $TargetWindow.Resources["AccentActive"]  = $accentActiveBrush
    if ([System.Windows.Application]::Current -and [System.Windows.Application]::Current.Resources) {
        [System.Windows.Application]::Current.Resources["AccentPrimary"] = $accentBrush
        [System.Windows.Application]::Current.Resources["AccentHover"]   = $accentHoverBrush
        [System.Windows.Application]::Current.Resources["AccentActive"]  = $accentActiveBrush
    }
}

Set-Alias -Name Apply-ThemeNode -Value Set-ThemeNode -Scope Global

Export-ModuleMember -Function `
    Convert-BrushToHex, `
    Test-IsDynamicExpression, `
    Import-ThemeDictionary, `
    Set-ThemeNode, `
    Sync-WindowThemeResources `
    -Alias Apply-ThemeNode
