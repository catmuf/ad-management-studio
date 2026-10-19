<#
.SYNOPSIS
    Automated WPF Screen Capture Engine for Active Directory Management Studio.
.DESCRIPTION
    Renders high-resolution application views and specialized studio dialogs in
    Light Theme (default operator presentation) directly to docs/images/*.png without
    requiring manual GUI interaction.
.OUTPUTS
    docs/images/01_dashboard_overview.png
    docs/images/02_users_and_inspector.png
    docs/images/03_specialized_editor_hex.png
    docs/images/04_specialized_editor_cert.png
    docs/images/05_scim_filter_studio.png
    docs/images/06_security_acl_6way.png
    docs/images/07_kerberos_token_bloat.png
    docs/images/08_circular_groups_loop.png
    docs/images/09_audit_reports_48.png
    docs/images/10_network_7tier_unc.png
    docs/images/11_native_menu_and_omnibar.png
    docs/images/12_html_dossier_technical.png
    docs/images/13_ldap_sql_console.png
    docs/images/14_object_compare_diff.png
    docs/images/15_replication_and_dc_matrix.png
    docs/images/16_ldif_studio_and_safety.png
    docs/images/17_schema_class_browser.png
    docs/images/18_modification_logs_rollback.png
    docs/images/19_connection_profiles_manager.png
#>

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

# Verify STA Apartment State
if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne [System.Threading.ApartmentState]::STA) {
    Write-Output "[INFO] Re-launching screenshot engine under Single-Threaded Apartment (STA)..."
    & pwsh -NoProfile -STA -File $PSCommandPath
    exit $LASTEXITCODE
}

# Load Core WPF & GDI Assemblies
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName WindowsBase
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Xml

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $scriptDir
$docsImagesDir = Join-Path $projectRoot "docs\images"

if (-not (Test-Path $docsImagesDir)) {
    [void](New-Item -ItemType Directory -Path $docsImagesDir -Force)
}

$script:BrushConverter = New-Object System.Windows.Media.BrushConverter

# Full Light Theme Color Mappings
$script:ColorMapBgLight = @{
    '#0E1017' = '#F8FAFC'; '#0F1015' = '#F1F5F9'; '#111319' = '#FFFFFF';
    '#111827' = '#F8FAFC'; '#13151D' = '#F1F5F9'; '#14161C' = '#F8FAFC';
    '#14161F' = '#F8FAFC'; '#161820' = '#F8FAFC'; '#161821' = '#F8FAFC';
    '#161822' = '#F8FAFC'; '#18191D' = '#F8FAFC'; '#181A20' = '#F8FAFC';
    '#181A22' = '#FFFFFF'; '#181B24' = '#FFFFFF'; '#1A1C23' = '#FFFFFF';
    '#1A1D27' = '#FFFFFF'; '#1B1E28' = '#F8FAFC'; '#1E212B' = '#FFFFFF';
    '#1E212D' = '#FFFFFF'; '#1E222D' = '#FFFFFF'; '#1E2232' = '#FFFFFF';
    '#1E293B' = '#F1F5F9'; '#22252F' = '#FFFFFF'; '#252936' = '#F8FAFC';
    '#282C37' = '#E2E8F0'; '#2B2F3E' = '#E2E8F0'; '#15171E' = '#FFFFFF';
    '#1F232F' = '#F1F5F9'; '#282D3E' = '#E2E8F0'; '#323749' = '#E2E8F0';
}

$script:ColorMapFgLight = @{
    '#FFFFFF' = '#0F172A'; '#F9FAFB' = '#0F172A'; '#F3F4F6' = '#0F172A';
    '#E5E7EB' = '#1E293B'; '#D1D5DB' = '#334155'; '#9CA3AF' = '#475569';
    '#6B7280' = '#64748B'; '#94A3B8' = '#475569';
}

$script:ColorMapBorderLight = @{
    '#1F2937' = '#CBD5E1'; '#252936' = '#CBD5E1'; '#252A3A' = '#CBD5E1';
    '#292E3E' = '#CBD5E1'; '#2D313F' = '#CBD5E1'; '#2E3345' = '#CBD5E1';
    '#2F3446' = '#CBD5E1'; '#334155' = '#CBD5E1'; '#373B4D' = '#CBD5E1';
    '#374151' = '#CBD5E1'; '#383E54' = '#CBD5E1'; '#4B526D' = '#94A3B8';
}

function Format-NodeThemeLight ($node) {
    if (-not $node -or -not ($node -is [System.Windows.FrameworkElement])) { return }

    if ($node -is [System.Windows.Controls.Border]) {
        if ($node.Background -is [System.Windows.Media.SolidColorBrush]) {
            $hex = ("#{0:X2}{1:X2}{2:X2}" -f $node.Background.Color.R, $node.Background.Color.G, $node.Background.Color.B).ToUpper()
            if ($script:ColorMapBgLight.ContainsKey($hex)) {
                $node.Background = $script:BrushConverter.ConvertFromString($script:ColorMapBgLight[$hex])
            }
        }
        if ($node.BorderBrush -is [System.Windows.Media.SolidColorBrush]) {
            $hex = ("#{0:X2}{1:X2}{2:X2}" -f $node.BorderBrush.Color.R, $node.BorderBrush.Color.G, $node.BorderBrush.Color.B).ToUpper()
            if ($script:ColorMapBorderLight.ContainsKey($hex)) {
                $node.BorderBrush = $script:BrushConverter.ConvertFromString($script:ColorMapBorderLight[$hex])
            }
        }
    }
    elseif ($node -is [System.Windows.Controls.Control]) {
        if ($node.Background -is [System.Windows.Media.SolidColorBrush]) {
            $hex = ("#{0:X2}{1:X2}{2:X2}" -f $node.Background.Color.R, $node.Background.Color.G, $node.Background.Color.B).ToUpper()
            if ($script:ColorMapBgLight.ContainsKey($hex)) {
                $node.Background = $script:BrushConverter.ConvertFromString($script:ColorMapBgLight[$hex])
            }
        }
        if ($node.Foreground -is [System.Windows.Media.SolidColorBrush]) {
            $hex = ("#{0:X2}{1:X2}{2:X2}" -f $node.Foreground.Color.R, $node.Foreground.Color.G, $node.Foreground.Color.B).ToUpper()
            if ($script:ColorMapFgLight.ContainsKey($hex)) {
                $node.Foreground = $script:BrushConverter.ConvertFromString($script:ColorMapFgLight[$hex])
            }
        }
        if ($node.BorderBrush -is [System.Windows.Media.SolidColorBrush]) {
            $hex = ("#{0:X2}{1:X2}{2:X2}" -f $node.BorderBrush.Color.R, $node.BorderBrush.Color.G, $node.BorderBrush.Color.B).ToUpper()
            if ($script:ColorMapBorderLight.ContainsKey($hex)) {
                $node.BorderBrush = $script:BrushConverter.ConvertFromString($script:ColorMapBorderLight[$hex])
            }
        }
    }
    elseif ($node -is [System.Windows.Controls.TextBlock]) {
        if ($node.Foreground -is [System.Windows.Media.SolidColorBrush]) {
            $hex = ("#{0:X2}{1:X2}{2:X2}" -f $node.Foreground.Color.R, $node.Foreground.Color.G, $node.Foreground.Color.B).ToUpper()
            if ($script:ColorMapFgLight.ContainsKey($hex)) {
                $node.Foreground = $script:BrushConverter.ConvertFromString($script:ColorMapFgLight[$hex])
            }
        }
    }

    $count = [System.Windows.Media.VisualTreeHelper]::GetChildrenCount($node)
    for ($i = 0; $i -lt $count; $i++) {
        $child = [System.Windows.Media.VisualTreeHelper]::GetChild($node, $i)
        if ($child -is [System.Windows.FrameworkElement]) {
            Format-NodeThemeLight $child
        }
    }
}

function Format-WindowLightTheme ($win) {
    $resourceMap = @{
        "BgDark"              = "#F8FAFC"
        "BgSidebar"           = "#F1F5F9"
        "BgSurface"           = "#FFFFFF"
        "BgCard"              = "#FFFFFF"
        "BgInput"             = "#FFFFFF"
        "BorderBrushColor"    = "#CBD5E1"
        "TextPrimary"         = "#0F172A"
        "TextSecondary"       = "#475569"
        "TextMuted"           = "#64748B"
        "NavHoverBg"          = "#E2E8F0"
        "NavSelectedBg"       = "#E2E8F0"
        "DropDownBg"          = "#FFFFFF"
        "DropDownBorderBrush" = "#CBD5E1"
        "DropDownItemHoverBg" = "#F1F5F9"
        "DropDownItemHoverFg" = "#0F172A"
        "ButtonBg"            = "#F1F5F9"
        "ButtonHoverBg"       = "#E2E8F0"
        "ButtonHoverBorder"   = "#94A3B8"
        "DataGridHeaderBg"    = "#F1F5F9"
        "DataGridHeaderFg"    = "#1E293B"
        "DataGridRowBg"       = "#FFFFFF"
        "DataGridAltRowBg"    = "#F8FAFC"
        "DataGridGridLines"   = "#E2E8F0"
        "ContextMenuBg"       = "#FFFFFF"
        "DangerButtonBg"      = "#FEF2F2"
        "DangerButtonFg"      = "#DC2626"
        "DangerButtonBorder"  = "#FCA5A5"
        "AccentPrimary"       = "#0284C7"
        "AccentHover"         = "#0369A1"
    }

    foreach ($k in $resourceMap.Keys) {
        $win.Resources[$k] = $script:BrushConverter.ConvertFromString($resourceMap[$k])
    }
    $win.Background = $script:BrushConverter.ConvertFromString("#F8FAFC")
    $win.Foreground = $script:BrushConverter.ConvertFromString("#0F172A")
}

# Helper: Load and Show Window Offscreen, apply Light theme, capture RenderTargetBitmap
function Export-WindowOffscreen {
    param(
        [string]$XamlPath,
        [int]$Width,
        [int]$Height,
        [scriptblock]$PreShowBlock,
        [scriptblock]$PostShowBlock,
        [string]$OutputPath
    )

    $raw = [System.IO.File]::ReadAllText($XamlPath)
    $sr = [System.IO.StringReader]::new($raw)
    $xr = [System.Xml.XmlReader]::Create($sr)
    $win = [System.Windows.Markup.XamlReader]::Load($xr)
    $xr.Close()
    $sr.Close()

    Format-WindowLightTheme $win

    $win.WindowStartupLocation = [System.Windows.WindowStartupLocation]::Manual
    $win.Left = -32000
    $win.Top = -32000
    $win.Width = $Width
    $win.Height = $Height

    if ($null -ne $PreShowBlock) {
        & $PreShowBlock $win
    }

    $win.Show()

    # Flush WPF Dispatcher queue to complete all visual layouts and template bindings
    [System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Loaded)
    [System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::ContextIdle)

    if ($null -ne $PostShowBlock) {
        & $PostShowBlock $win
        [System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Loaded)
        [System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::ContextIdle)
    }

    # Apply node theme across newly materialized visual tree
    Format-NodeThemeLight $win

    [System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Render)

    $rtb = New-Object System.Windows.Media.Imaging.RenderTargetBitmap($Width, $Height, 96, 96, [System.Windows.Media.PixelFormats]::Pbgra32)
    $rtb.Render($win)

    $win.Close()

    $encoder = New-Object System.Windows.Media.Imaging.PngBitmapEncoder
    $encoder.Frames.Add([System.Windows.Media.Imaging.BitmapFrame]::Create($rtb))

    $fileStream = [System.IO.File]::Create($OutputPath)
    $encoder.Save($fileStream)
    $fileStream.Close()

    Write-Output "  [CAPTURED] -> $OutputPath ($Width x $Height px)"
}
Set-Alias -Name Render-WindowOffscreen -Value Export-WindowOffscreen -Scope Script

Write-Output "================================================================="
Write-Output "   ACTIVE DIRECTORY MANAGEMENT STUDIO - SCREENSHOT CAPTURE ENGINE"
Write-Output "   Mode: Light Theme (Default Operator Presentation)"
Write-Output "================================================================="

$mainXamlPath = Join-Path $projectRoot "Views\MainWindow.xaml"
$editorXamlPath = Join-Path $projectRoot "Views\SpecializedEditorDialog.xaml"

# -----------------------------------------------------------------------------
# 1. 01_dashboard_overview.png
# -----------------------------------------------------------------------------
Write-Output "[1/19] Capturing Dashboard Overview..."
Render-WindowOffscreen -XamlPath $mainXamlPath -Width 1366 -Height 850 -OutputPath (Join-Path $docsImagesDir "01_dashboard_overview.png") -PreShowBlock {
    param($win)
    $vp = $win.FindName("ViewportContainer")
    if ($vp) {
        foreach ($c in $vp.Children) {
            $c.Visibility = if ($c.Name -eq "PanelDashboard") { [System.Windows.Visibility]::Visible } else { [System.Windows.Visibility]::Collapsed }
        }
    }
} -PostShowBlock {
    param($win)
    $kUsers = $win.FindName("TxtKpiTotalUsers"); if ($kUsers) { $kUsers.Text = "1,248" }
    $kComp = $win.FindName("TxtKpiTotalComputers"); if ($kComp) { $kComp.Text = "320" }
    $kGroups = $win.FindName("TxtKpiTotalGroups"); if ($kGroups) { $kGroups.Text = "185" }
    $kLocked = $win.FindName("TxtKpiLockedAccounts"); if ($kLocked) { $kLocked.Text = "14" }
}

# -----------------------------------------------------------------------------
# 2. 02_users_and_inspector.png
# -----------------------------------------------------------------------------
Write-Output "[2/19] Capturing Users Grid & Attribute Inspector..."
Render-WindowOffscreen -XamlPath $mainXamlPath -Width 1366 -Height 850 -OutputPath (Join-Path $docsImagesDir "02_users_and_inspector.png") -PreShowBlock {
    param($win)
    $vp = $win.FindName("ViewportContainer")
    if ($vp) {
        foreach ($c in $vp.Children) {
            $c.Visibility = if ($c.Name -eq "PanelUsers") { [System.Windows.Visibility]::Visible } else { [System.Windows.Visibility]::Collapsed }
        }
    }
} -PostShowBlock {
    param($win)
    $g = $win.FindName("GridUsers")
    if ($g) {
        $g.ItemsSource = @(
            [PSCustomObject]@{ sAMAccountName = "alex.morgan"; displayName = "Alex Morgan"; mail = "alex.morgan@contoso.com"; title = "Senior Systems Architect"; department = "IT Infrastructure"; enabled = $true; lastLogonTimestamp = "2026-10-14 08:32" },
            [PSCustomObject]@{ sAMAccountName = "sarah.chen"; displayName = "Sarah Chen"; mail = "sarah.chen@contoso.com"; title = "Lead Security Engineer"; department = "SecOps"; enabled = $true; lastLogonTimestamp = "2026-10-14 09:12" },
            [PSCustomObject]@{ sAMAccountName = "marcus.vance"; displayName = "Marcus Vance"; mail = "marcus.vance@contoso.com"; title = "DevOps Lead"; department = "Cloud Engineering"; enabled = $true; lastLogonTimestamp = "2026-10-14 07:45" },
            [PSCustomObject]@{ sAMAccountName = "elena.rostova"; displayName = "Elena Rostova"; mail = "elena.rostova@contoso.com"; title = "Identity Governance Lead"; department = "IAM"; enabled = $true; lastLogonTimestamp = "2026-10-13 18:20" },
            [PSCustomObject]@{ sAMAccountName = "david.kim"; displayName = "David Kim"; mail = "david.kim@contoso.com"; title = "Principal DBA"; department = "Data Operations"; enabled = $true; lastLogonTimestamp = "2026-10-14 06:50" },
            [PSCustomObject]@{ sAMAccountName = "rachel.adams"; displayName = "Rachel Adams"; mail = "rachel.adams@contoso.com"; title = "HR Director"; department = "Human Resources"; enabled = $true; lastLogonTimestamp = "2026-10-13 16:15" },
            [PSCustomObject]@{ sAMAccountName = "james.wilson"; displayName = "James Wilson"; mail = "james.wilson@contoso.com"; title = "Network Architect"; department = "Core Networks"; enabled = $true; lastLogonTimestamp = "2026-10-14 08:05" },
            [PSCustomObject]@{ sAMAccountName = "service-ldap-sync"; displayName = "SVC LDAP DirSync"; mail = "svc-dirsync@contoso.com"; title = "Managed Service Account"; department = "Identity Services"; enabled = $true; lastLogonTimestamp = "2026-10-14 09:15" }
        )
        $g.SelectedIndex = 0
    }
    $tName = $win.FindName("TxtInspectorDisplayName"); if ($tName) { $tName.Text = "Alex Morgan" }
    $tSam = $win.FindName("TxtInspectorSamAccountName"); if ($tSam) { $tSam.Text = "alex.morgan" }
    $tMail = $win.FindName("TxtInspectorMail"); if ($tMail) { $tMail.Text = "alex.morgan@contoso.com" }
    $tTitle = $win.FindName("TxtInspectorTitle"); if ($tTitle) { $tTitle.Text = "Senior Systems Architect" }
    $tDept = $win.FindName("TxtInspectorDepartment"); if ($tDept) { $tDept.Text = "IT Infrastructure" }
    $tDn = $win.FindName("TxtInspectorDN"); if ($tDn) { $tDn.Text = "CN=Alex Morgan,OU=Engineers,OU=Staff,DC=contoso,DC=local" }
}

# -----------------------------------------------------------------------------
# 3. 03_specialized_editor_hex.png
# -----------------------------------------------------------------------------
Write-Output "[3/19] Capturing Specialized Hex Editor Dialog..."
Render-WindowOffscreen -XamlPath $editorXamlPath -Width 920 -Height 660 -OutputPath (Join-Path $docsImagesDir "03_specialized_editor_hex.png") -PreShowBlock {
    param($win)
    $tc = $win.FindName("TabControlEditors")
    if ($tc) { $tc.SelectedIndex = 0 }
} -PostShowBlock {
    param($win)
    $dumpView = $win.FindName("TxtHexDumpView")
    if ($dumpView) {
        $dumpView.Text = "00000000   30 82 04 2E  30 82 03 16  A0 03 02 01  02 02 10 3B   0...0..........;`n" +
                         "00000010   A4 F8 91 C2  D0 49 1E B6  A5 11 02 FF  E4 90 2A 0D   .....I........*.`n" +
                         "00000020   06 09 2A 86  48 86 F7 0D  01 01 0B 05  00 30 5A 31   ..*.H........0Z1`n" +
                         "00000030   0B 30 09 06  03 55 04 06  13 02 55 53  31 10 30 0E   .0...U....US1.0.`n" +
                         "00000040   06 03 55 04  08 0C 07 43  61 6C 69 66  6F 72 31 16   ..U....Califor1.`n" +
                         "00000050   30 14 06 03  55 04 07 0C  0D 53 61 6E  20 46 72 61   0...U....San Fra`n" +
                         "00000060   6E 63 69 73  63 6F 31 23  30 21 06 03  55 04 0A 0C   ncisco1#0!..U...`n" +
                         "00000070   1A 43 6F 6E  74 6F 73 6F  20 45 6E 74  65 72 70 72   .Contoso Enterpr"
    }
    $rawInput = $win.FindName("TxtHexRawInput")
    if ($rawInput) {
        $rawInput.Text = "3082042E30820316A00302010202103BA4F891C2D0491EB6A51102FFE4902A0D06092A864886F70D01010B0500305A310B30090603550406130255533110300E06035504080C0743616C69666F723116301406035504070C0D53616E204672616E636973636F"
    }
    $asciiP = $win.FindName("TxtHexAsciiPreview"); if ($asciiP) { $asciiP.Text = "0...0..........;.....I........*...*.H........0Z1.0...U....US1.0...U....Califor1.0...U....San Francisco" }
    $b64P = $win.FindName("TxtHexBase64Preview"); if ($b64P) { $b64P.Text = "MIIELjCCAxagAwIBAgIQO6T4kcLQSX62pRECA//kkC==" }
    $bCount = $win.FindName("TxtHexByteCount"); if ($bCount) { $bCount.Text = "Total Bytes: 1,074 bytes (0x0432)" }
}

# -----------------------------------------------------------------------------
# 4. 04_specialized_editor_cert.png
# -----------------------------------------------------------------------------
Write-Output "[4/19] Capturing Specialized Certificate Viewer..."
Render-WindowOffscreen -XamlPath $editorXamlPath -Width 920 -Height 660 -OutputPath (Join-Path $docsImagesDir "04_specialized_editor_cert.png") -PreShowBlock {
    param($win)
    $tc = $win.FindName("TabControlEditors")
    $tabCert = $win.FindName("TabCertViewer")
    if ($tc -and $tabCert) {
        $tc.SelectedItem = $tabCert
        $tabCert.IsSelected = $true
    }
} -PostShowBlock {
    param($win)
    $tCn = $win.FindName("TxtCertSubjectCN"); if ($tCn) { $tCn.Text = "corp-dc01.ad.contoso.com" }
    $tSub = $win.FindName("TxtCertSubject"); if ($tSub) { $tSub.Text = "CN=corp-dc01.ad.contoso.com, OU=Domain Controllers, DC=contoso, DC=local" }
    $tIcn = $win.FindName("TxtCertIssuerCN"); if ($tIcn) { $tIcn.Text = "Contoso Enterprise Root CA" }
    $tIss = $win.FindName("TxtCertIssuer"); if ($tIss) { $tIss.Text = "CN=Contoso Enterprise Root CA, DC=contoso, DC=local" }
    $tSer = $win.FindName("TxtCertSerial"); if ($tSer) { $tSer.Text = "3BA4F891C2D0491EB6A51102FFE4902A" }
    $tNb = $win.FindName("TxtCertNotBefore"); if ($tNb) { $tNb.Text = "2025-01-01 00:00:00 UTC" }
    $tNa = $win.FindName("TxtCertNotAfter"); if ($tNa) { $tNa.Text = "2027-01-01 23:59:59 UTC" }
    $tVs = $win.FindName("TxtCertValidityStatus"); if ($tVs) { $tVs.Text = "VALID (Active: 443 days remaining)" }
    $tPk = $win.FindName("TxtCertPublicKey"); if ($tPk) { $tPk.Text = "RSA 2048 bits" }
    $tSa = $win.FindName("TxtCertSigAlgo"); if ($tSa) { $tSa.Text = "sha256RSA (1.2.840.113549.1.1.11)" }
    $tKu = $win.FindName("TxtCertKeyUsage"); if ($tKu) { $tKu.Text = "Digital Signature, Key Encipherment, Server Authentication, Client Authentication" }
    $tSan = $win.FindName("TxtCertSan"); if ($tSan) { $tSan.Text = "DNS:corp-dc01.ad.contoso.com, DNS:dc01.contoso.local" }
    $tTh = $win.FindName("TxtCertThumbprint"); if ($tTh) { $tTh.Text = "8F A2 7D 94 3B 10 C5 E6 92 B1 48 07 D9 44 21 89 CE AF 30 1A" }
    $tTh256 = $win.FindName("TxtCertThumbprint256"); if ($tTh256) { $tTh256.Text = "5C7A2E9F1D8B4C0A3E7F8D6B2C9A1E0F5A4B3C2D1E0F9A8B7C6D5E4F3A2B1C0D" }
    $tRev = $win.FindName("TxtCertRevocationResult"); if ($tRev) { $tRev.Text = "STATUS: VALID`nRevocation Check: ONLINE (CRL and OCSP validated).`nChain Status: Complete trusted root chain to 'Contoso Enterprise Root CA'." }
}

# -----------------------------------------------------------------------------
# 5. 05_scim_filter_studio.png
# -----------------------------------------------------------------------------
Write-Output "[5/19] Capturing SCIM 2.0 Query & Filter Studio..."
Render-WindowOffscreen -XamlPath $mainXamlPath -Width 1366 -Height 850 -OutputPath (Join-Path $docsImagesDir "05_scim_filter_studio.png") -PreShowBlock {
    param($win)
    $vp = $win.FindName("ViewportContainer")
    if ($vp) {
        foreach ($c in $vp.Children) {
            $c.Visibility = if ($c.Name -eq "PanelLdapSql") { [System.Windows.Visibility]::Visible } else { [System.Windows.Visibility]::Collapsed }
        }
    }
} -PostShowBlock {
    param($win)
    $tSql = $win.FindName("TxtLdapSql")
    if ($tSql) {
        $tSql.Text = "SCIM-QUERY: userName sw ""alex"" and title pr and emails[type eq ""work""].value ew ""@contoso.com""`n`n" +
                     "-- COMPILED NATIVE LDAP FILTER (RFC 7644 -> RFC 4515):`n" +
                     "(&(objectCategory=person)(objectClass=user)(sAMAccountName=alex*)(title=*)(mail=*@contoso.com))`n`n" +
                     "-- SCIM RFC 7643 ATTRIBUTE MAPPINGS & EXTENSIONS:`n" +
                     "urn:ietf:params:scim:schemas:core:2.0:User -> sAMAccountName, displayName, mail, title`n" +
                     "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User -> department, manager, employeeNumber`n`n" +
                     "-- EXECUTION RESULT: 1 Object Matched in 4.2ms [VLV Page 1/1]"
    }
}

# -----------------------------------------------------------------------------
# 6. 06_security_acl_6way.png
# -----------------------------------------------------------------------------
Write-Output "[6/19] Capturing 6-Way Effective Rights & ACL Security..."
Render-WindowOffscreen -XamlPath $mainXamlPath -Width 1366 -Height 850 -OutputPath (Join-Path $docsImagesDir "06_security_acl_6way.png") -PreShowBlock {
    param($win)
    $vp = $win.FindName("ViewportContainer")
    if ($vp) {
        foreach ($c in $vp.Children) {
            $c.Visibility = if ($c.Name -eq "PanelSecurityAcl") { [System.Windows.Visibility]::Visible } else { [System.Windows.Visibility]::Collapsed }
        }
    }
} -PostShowBlock {
    param($win)
    $tDn = $win.FindName("TxtAclTargetDN"); if ($tDn) { $tDn.Text = "CN=Alex Morgan,OU=Engineers,OU=Staff,DC=contoso,DC=local" }
    $tTr = $win.FindName("TxtAclTrustee"); if ($tTr) { $tTr.Text = "CONTOSO\Domain Admins" }
    $tOw = $win.FindName("TxtAclOwner"); if ($tOw) { $tOw.Text = "CONTOSO\Domain Admins" }
    $tGr = $win.FindName("TxtAclGroup"); if ($tGr) { $tGr.Text = "CONTOSO\Domain Admins" }
    $tIn = $win.FindName("TxtAclInheritance"); if ($tIn) { $tIn.Text = "ENABLED (Inheriting from OU=Staff)" }

    $gAces = $win.FindName("GridAclAces")
    if ($gAces) {
        $gAces.ItemsSource = @(
            [PSCustomObject]@{ Type = "Allow"; IdentityReference = "NT AUTHORITY\SYSTEM"; ActiveDirectoryRights = "GenericAll"; Inheritance = "Inherited"; InheritedObjectType = "(All Attributes)" },
            [PSCustomObject]@{ Type = "Allow"; IdentityReference = "CONTOSO\Domain Admins"; ActiveDirectoryRights = "GenericAll"; Inheritance = "Inherited"; InheritedObjectType = "(All Attributes)" },
            [PSCustomObject]@{ Type = "Allow"; IdentityReference = "CONTOSO\Enterprise Admins"; ActiveDirectoryRights = "GenericAll"; Inheritance = "Inherited"; InheritedObjectType = "(All Attributes)" },
            [PSCustomObject]@{ Type = "Allow"; IdentityReference = "CONTOSO\HelpDesk-Tier1"; ActiveDirectoryRights = "ReadProperty, WriteProperty"; Inheritance = "Direct"; InheritedObjectType = "lockoutTime, pwdLastSet" },
            [PSCustomObject]@{ Type = "Allow"; IdentityReference = "NT AUTHORITY\SELF"; ActiveDirectoryRights = "ReadProperty, WriteProperty"; Inheritance = "Direct"; InheritedObjectType = "personalTitle, telephoneNumber" }
        )
    }

    $gEff = $win.FindName("GridAclEffective")
    if ($gEff) {
        $gEff.ItemsSource = @(
            [PSCustomObject]@{ RightName = "GenericAll (Full Control)"; Category = "Full Control"; StatusBadge = "GRANTED"; SourceTrustee = "CONTOSO\Domain Admins" },
            [PSCustomObject]@{ RightName = "ReadProperty (All)"; Category = "Read Rights"; StatusBadge = "GRANTED"; SourceTrustee = "NT AUTHORITY\SYSTEM" },
            [PSCustomObject]@{ RightName = "WriteProperty (All)"; Category = "Write Rights"; StatusBadge = "GRANTED"; SourceTrustee = "CONTOSO\Domain Admins" },
            [PSCustomObject]@{ RightName = "ResetPassword"; Category = "Extended Right"; StatusBadge = "GRANTED"; SourceTrustee = "CONTOSO\HelpDesk-Tier1" },
            [PSCustomObject]@{ RightName = "ChangePassword"; Category = "Extended Right"; StatusBadge = "GRANTED"; SourceTrustee = "NT AUTHORITY\SELF" },
            [PSCustomObject]@{ RightName = "DeleteChild"; Category = "Lifecycle"; StatusBadge = "GRANTED"; SourceTrustee = "CONTOSO\Domain Admins" }
        )
    }
}

# -----------------------------------------------------------------------------
# 7. 07_kerberos_token_bloat.png
# -----------------------------------------------------------------------------
Write-Output "[7/19] Capturing Kerberos PAC Bloat Calculator..."
Render-WindowOffscreen -XamlPath $mainXamlPath -Width 1366 -Height 850 -OutputPath (Join-Path $docsImagesDir "07_kerberos_token_bloat.png") -PreShowBlock {
    param($win)
    $vp = $win.FindName("ViewportContainer")
    if ($vp) {
        foreach ($c in $vp.Children) {
            $c.Visibility = if ($c.Name -eq "PanelKerberosSuite") { [System.Windows.Visibility]::Visible } else { [System.Windows.Visibility]::Collapsed }
        }
    }
    # Select MaxTokenSize tab
    $pKerb = $win.FindName("PanelKerberosSuite")
    if ($pKerb) {
        $tcKerb = $pKerb.Children | Where-Object { $_ -is [System.Windows.Controls.TabControl] }
        if ($tcKerb) { $tcKerb.SelectedIndex = 1 }
    }
} -PostShowBlock {
    param($win)
    $tUser = $win.FindName("TxtTokenUser"); if ($tUser) { $tUser.Text = "alex.morgan" }
    $tBytes = $win.FindName("TxtTokenSizeBytes"); if ($tBytes) { $tBytes.Text = "18,240 Bytes" }
    $tDom = $win.FindName("TxtTokenDomainGroups"); if ($tDom) { $tDom.Text = "68" }
    $tExt = $win.FindName("TxtTokenExtraSids"); if ($tExt) { $tExt.Text = "74" }
    $tForm = $win.FindName("TxtTokenFormulaSummary"); if ($tForm) { $tForm.Text = "1200 + 40(68) + 8(74)" }
    $tRisk = $win.FindName("TxtTokenRiskBadge"); if ($tRisk) { $tRisk.Text = "Normal (OK)" }

    $gTok = $win.FindName("GridTokenGroups")
    if ($gTok) {
        $gTok.ItemsSource = @(
            [PSCustomObject]@{ Name = "Domain Admins"; Scope = "Global"; Type = "Security"; DistinguishedName = "CN=Domain Admins,CN=Users,DC=contoso,DC=local" },
            [PSCustomObject]@{ Name = "Enterprise Admins"; Scope = "Universal"; Type = "Security"; DistinguishedName = "CN=Enterprise Admins,CN=Users,DC=contoso,DC=local" },
            [PSCustomObject]@{ Name = "Schema Admins"; Scope = "Universal"; Type = "Security"; DistinguishedName = "CN=Schema Admins,CN=Users,DC=contoso,DC=local" },
            [PSCustomObject]@{ Name = "Group Policy Creator Owners"; Scope = "Global"; Type = "Security"; DistinguishedName = "CN=Group Policy Creator Owners,CN=Users,DC=contoso,DC=local" },
            [PSCustomObject]@{ Name = "IT-Infrastructure-Leads"; Scope = "DomainLocal"; Type = "Security"; DistinguishedName = "CN=IT-Infrastructure-Leads,OU=Groups,DC=contoso,DC=local" },
            [PSCustomObject]@{ Name = "Cloud-Platform-Architects"; Scope = "Global"; Type = "Security"; DistinguishedName = "CN=Cloud-Platform-Architects,OU=Groups,DC=contoso,DC=local" }
        )
    }
}

# -----------------------------------------------------------------------------
# 8. 08_circular_groups_loop.png
# -----------------------------------------------------------------------------
Write-Output "[8/19] Capturing Circular Group Loop Diagnostics..."
Render-WindowOffscreen -XamlPath $mainXamlPath -Width 1366 -Height 850 -OutputPath (Join-Path $docsImagesDir "08_circular_groups_loop.png") -PreShowBlock {
    param($win)
    $vp = $win.FindName("ViewportContainer")
    if ($vp) {
        foreach ($c in $vp.Children) {
            $c.Visibility = if ($c.Name -eq "PanelDiagnosticsToolbox") { [System.Windows.Visibility]::Visible } else { [System.Windows.Visibility]::Collapsed }
        }
    }
} -PostShowBlock {
    param($win)
    $gl = $win.FindName("GridCircularGroups")
    if ($gl) {
        $gl.ItemsSource = @(
            [PSCustomObject]@{ StatusBadge = "LOOP DETECTED"; RootGroup = "IT-Admins-Core"; CyclePath = "IT-Admins-Core ➔ DevOps-Infrastructure ➔ SecOps-Auditors ➔ IT-Admins-Core"; Depth = 3; Action = "Disconnect SecOps-Auditors ➔ IT-Admins-Core reference" },
            [PSCustomObject]@{ StatusBadge = "LOOP DETECTED"; RootGroup = "App-Developers-Global"; CyclePath = "App-Developers-Global ➔ Frontend-Engineers ➔ App-Developers-Global"; Depth = 2; Action = "Disconnect Frontend-Engineers ➔ App-Developers-Global reference" }
        )
    }
}

# -----------------------------------------------------------------------------
# 9. 09_audit_reports_48.png
# -----------------------------------------------------------------------------
Write-Output "[9/19] Capturing 48 Enterprise Security Audit Reports..."
Render-WindowOffscreen -XamlPath $mainXamlPath -Width 1366 -Height 850 -OutputPath (Join-Path $docsImagesDir "09_audit_reports_48.png") -PreShowBlock {
    param($win)
    $vp = $win.FindName("ViewportContainer")
    if ($vp) {
        foreach ($c in $vp.Children) {
            $c.Visibility = if ($c.Name -eq "PanelAuditReports") { [System.Windows.Visibility]::Visible } else { [System.Windows.Visibility]::Collapsed }
        }
    }
} -PostShowBlock {
    param($win)
    $tSum = $win.FindName("TxtAuditSummary"); if ($tSum) { $tSum.Text = "Audit Complete: Found 28 stale inactive user accounts (> 90 days without interactive logon)." }
    $tCnt = $win.FindName("TxtAuditCount"); if ($tCnt) { $tCnt.Text = "28 Findings Matched" }

    $gr = $win.FindName("GridAuditResults")
    if ($gr) {
        $gr.ItemsSource = @(
            [PSCustomObject]@{ SamAccountName = "j.smith_stale"; DisplayName = "John Smith (Stale)"; Department = "Sales"; Status = "Inactive"; Finding = "Last Logon: 2026-05-24 (143 days ago)"; DistinguishedName = "CN=John Smith,OU=Sales,DC=contoso,DC=local" },
            [PSCustomObject]@{ SamAccountName = "svc_backup_old"; DisplayName = "Legacy Backup Service"; Department = "IT Infrastructure"; Status = "Inactive"; Finding = "Last Logon: 2026-03-12 (216 days ago); PwdExpired"; DistinguishedName = "CN=svc_backup_old,OU=Services,DC=contoso,DC=local" },
            [PSCustomObject]@{ SamAccountName = "m.taylor_contract"; DisplayName = "Mark Taylor"; Department = "Contractors"; Status = "Inactive"; Finding = "AccountExpires: 2026-07-01 (Contract Ended)"; DistinguishedName = "CN=Mark Taylor,OU=Contractors,DC=contoso,DC=local" },
            [PSCustomObject]@{ SamAccountName = "test_lab_user01"; DisplayName = "Lab Evaluation Account"; Department = "Engineering QA"; Status = "Inactive"; Finding = "Never Logged On (Created 120 days ago)"; DistinguishedName = "CN=Lab User 01,OU=QA,DC=contoso,DC=local" }
        )
    }
}

# -----------------------------------------------------------------------------
# 10. 10_network_7tier_unc.png
# -----------------------------------------------------------------------------
Write-Output "[10/19] Capturing NetTools 7-Tier UNC Diagnostics..."
Render-WindowOffscreen -XamlPath $mainXamlPath -Width 1366 -Height 850 -OutputPath (Join-Path $docsImagesDir "10_network_7tier_unc.png") -PreShowBlock {
    param($win)
    $vp = $win.FindName("ViewportContainer")
    if ($vp) {
        foreach ($c in $vp.Children) {
            $c.Visibility = if ($c.Name -eq "PanelNetworkDiagnostics") { [System.Windows.Visibility]::Visible } else { [System.Windows.Visibility]::Collapsed }
        }
    }
} -PostShowBlock {
    param($win)
    $gUnc = $win.FindName("GridUncResults")
    if ($gUnc) {
        $gUnc.ItemsSource = @(
            [PSCustomObject]@{ StepNumber = 1; StepName = "DNS Resolution"; StatusBadge = "PASS"; LatencyMs = "1.2"; Target = "dc01.corp.local"; Details = "Resolved A record to 10.0.1.10 successfully" },
            [PSCustomObject]@{ StepNumber = 2; StepName = "ICMP Ping"; StatusBadge = "PASS"; LatencyMs = "0.8"; Target = "10.0.1.10"; Details = "Host responding, TTL=128" },
            [PSCustomObject]@{ StepNumber = 3; StepName = "RPC Endpoint Mapper"; StatusBadge = "PASS"; LatencyMs = "1.5"; Target = "10.0.1.10:135"; Details = "TCP port 135 OPEN, EPM active" },
            [PSCustomObject]@{ StepNumber = 4; StepName = "SMB Protocol Port"; StatusBadge = "PASS"; LatencyMs = "2.1"; Target = "10.0.1.10:445"; Details = "TCP port 445 OPEN, SMB 3.1.1 negotiated" },
            [PSCustomObject]@{ StepNumber = 5; StepName = "NetShareGetInfo"; StatusBadge = "PASS"; LatencyMs = "3.4"; Target = "\\dc01.corp.local\SYSVOL"; Details = "Share accessible, Type=DiskTree, MaxUsers=Unlimited" },
            [PSCustomObject]@{ StepNumber = 6; StepName = "Share Permissions"; StatusBadge = "PASS"; LatencyMs = "2.8"; Target = "\\dc01.corp.local\SYSVOL"; Details = "Read & Execute granted to Authenticated Users" },
            [PSCustomObject]@{ StepNumber = 7; StepName = "Path Traversal & Read"; StatusBadge = "PASS"; LatencyMs = "1.9"; Target = "SYSVOL\corp.local\Policies"; Details = "Folder accessible, GPT.INI found" }
        )
    }
    $tPath = $win.FindName("TxtUncPathInput")
    if ($tPath) { $tPath.Text = "\\dc01.corp.local\SYSVOL\corp.local" }
}

# -----------------------------------------------------------------------------
# 11. 11_native_menu_and_omnibar.png
# -----------------------------------------------------------------------------
Write-Output "[11/19] Capturing Native Horizontal Menu & Omnibar..."
Render-WindowOffscreen -XamlPath $mainXamlPath -Width 1366 -Height 850 -OutputPath (Join-Path $docsImagesDir "11_native_menu_and_omnibar.png") -PreShowBlock {
    param($win)
    $vp = $win.FindName("ViewportContainer")
    if ($vp) {
        foreach ($c in $vp.Children) {
            $c.Visibility = if ($c.Name -eq "PanelDashboard") { [System.Windows.Visibility]::Visible } else { [System.Windows.Visibility]::Collapsed }
        }
    }
} -PostShowBlock {
    param($win)
    $kUsers = $win.FindName("TxtKpiTotalUsers"); if ($kUsers) { $kUsers.Text = "1,248" }
    $kComp = $win.FindName("TxtKpiTotalComputers"); if ($kComp) { $kComp.Text = "320" }
    $kGroups = $win.FindName("TxtKpiTotalGroups"); if ($kGroups) { $kGroups.Text = "185" }

    $tOmni = $win.FindName("TxtGlobalSearch")
    if ($tOmni) {
        $tOmni.Text = "alex"
        $tOmni.Foreground = [System.Windows.Media.Brushes]::Black
    }

    # Overlay quick search results card below the Omnibar search box
    if ($win.Content -is [System.Windows.Controls.Grid]) {
        $rootGrid = $win.Content
        $overlayBorder = New-Object System.Windows.Controls.Border
        $overlayBorder.Background = [System.Windows.Media.Brushes]::White
        $overlayBorder.BorderBrush = $script:BrushConverter.ConvertFromString("#0078D4")
        $overlayBorder.BorderThickness = New-Object System.Windows.Thickness(1.5)
        $overlayBorder.CornerRadius = New-Object System.Windows.CornerRadius(6)
        $overlayBorder.Padding = New-Object System.Windows.Thickness(12)
        $overlayBorder.Width = 490
        $overlayBorder.HorizontalAlignment = [System.Windows.HorizontalAlignment]::Right
        $overlayBorder.VerticalAlignment = [System.Windows.VerticalAlignment]::Top
        $overlayBorder.Margin = New-Object System.Windows.Thickness(0, 78, 14, 0)
        [System.Windows.Controls.Grid]::SetRowSpan($overlayBorder, 4)
        [System.Windows.Controls.Panel]::SetZIndex($overlayBorder, 9999)

        $overlayStack = New-Object System.Windows.Controls.StackPanel

        # Header row
        $headGrid = New-Object System.Windows.Controls.Grid
        $col1 = New-Object System.Windows.Controls.ColumnDefinition; $col1.Width = [System.Windows.GridLength]::Auto
        $col2 = New-Object System.Windows.Controls.ColumnDefinition; $col2.Width = New-Object System.Windows.GridLength(1, [System.Windows.GridUnitType]::Star)
        $col3 = New-Object System.Windows.Controls.ColumnDefinition; $col3.Width = [System.Windows.GridLength]::Auto
        [void]$headGrid.ColumnDefinitions.Add($col1)
        [void]$headGrid.ColumnDefinitions.Add($col2)
        [void]$headGrid.ColumnDefinitions.Add($col3)

        $hdrText = New-Object System.Windows.Controls.TextBlock
        $hdrText.Text = "🔍 Quick Search Results (Ctrl+K)"
        $hdrText.FontWeight = [System.Windows.FontWeights]::Bold
        $hdrText.FontSize = 12
        $hdrText.Foreground = $script:BrushConverter.ConvertFromString("#0078D4")
        [System.Windows.Controls.Grid]::SetColumn($hdrText, 0)
        [void]$headGrid.Children.Add($hdrText)

        $badgeText = New-Object System.Windows.Controls.TextBlock
        $badgeText.Text = "4 matches in contoso.local"
        $badgeText.FontSize = 10.5
        $badgeText.Foreground = $script:BrushConverter.ConvertFromString("#64748B")
        [System.Windows.Controls.Grid]::SetColumn($badgeText, 2)
        [void]$headGrid.Children.Add($badgeText)
        $headGrid.Margin = New-Object System.Windows.Thickness(0, 0, 0, 8)
        [void]$overlayStack.Children.Add($headGrid)

        $results = @(
            @{ Type = "USER"; Name = "Alex Morgan"; DN = "CN=Alex Morgan,OU=Engineering,DC=contoso,DC=local"; Color = "#0284C7" },
            @{ Type = "GROUP"; Name = "SecOps-Auditors"; DN = "CN=SecOps-Auditors,OU=Groups,DC=contoso,DC=local"; Color = "#16A34A" },
            @{ Type = "OU"; Name = "Engineering"; DN = "OU=Engineering,DC=contoso,DC=local"; Color = "#F59E0B" },
            @{ Type = "DC"; Name = "DC01"; DN = "CN=DC01,OU=Domain Controllers,DC=contoso,DC=local"; Color = "#8B5CF6" }
        )

        foreach ($r in $results) {
            $itemBorder = New-Object System.Windows.Controls.Border
            $itemBorder.Background = $script:BrushConverter.ConvertFromString("#F8FAFC")
            $itemBorder.BorderBrush = $script:BrushConverter.ConvertFromString("#E2E8F0")
            $itemBorder.BorderThickness = New-Object System.Windows.Thickness(1)
            $itemBorder.CornerRadius = New-Object System.Windows.CornerRadius(4)
            $itemBorder.Padding = New-Object System.Windows.Thickness(8, 6, 8, 6)
            $itemBorder.Margin = New-Object System.Windows.Thickness(0, 2, 0, 4)

            $itemGrid = New-Object System.Windows.Controls.Grid
            $ic1 = New-Object System.Windows.Controls.ColumnDefinition; $ic1.Width = [System.Windows.GridLength]::Auto
            $ic2 = New-Object System.Windows.Controls.ColumnDefinition; $ic2.Width = New-Object System.Windows.GridLength(1, [System.Windows.GridUnitType]::Star)
            [void]$itemGrid.ColumnDefinitions.Add($ic1)
            [void]$itemGrid.ColumnDefinitions.Add($ic2)

            $badge = New-Object System.Windows.Controls.Border
            $badge.Background = $script:BrushConverter.ConvertFromString($r.Color)
            $badge.CornerRadius = New-Object System.Windows.CornerRadius(3)
            $badge.Padding = New-Object System.Windows.Thickness(6, 2, 6, 2)
            $badge.Margin = New-Object System.Windows.Thickness(0, 0, 10, 0)
            $badge.VerticalAlignment = [System.Windows.VerticalAlignment]::Center

            $badgeTb = New-Object System.Windows.Controls.TextBlock
            $badgeTb.Text = $r.Type
            $badgeTb.Foreground = [System.Windows.Media.Brushes]::White
            $badgeTb.FontSize = 9.5
            $badgeTb.FontWeight = [System.Windows.FontWeights]::Bold
            $badge.Child = $badgeTb
            [System.Windows.Controls.Grid]::SetColumn($badge, 0)
            [void]$itemGrid.Children.Add($badge)

            $infoStack = New-Object System.Windows.Controls.StackPanel
            $titleTb = New-Object System.Windows.Controls.TextBlock
            $titleTb.Text = $r.Name
            $titleTb.FontWeight = [System.Windows.FontWeights]::SemiBold
            $titleTb.FontSize = 12
            $titleTb.Foreground = $script:BrushConverter.ConvertFromString("#0F172A")
            [void]$infoStack.Children.Add($titleTb)

            $dnTb = New-Object System.Windows.Controls.TextBlock
            $dnTb.Text = $r.DN
            $dnTb.FontSize = 10
            $dnTb.Foreground = $script:BrushConverter.ConvertFromString("#475569")
            [void]$infoStack.Children.Add($dnTb)

            [System.Windows.Controls.Grid]::SetColumn($infoStack, 1)
            [void]$itemGrid.Children.Add($infoStack)

            $itemBorder.Child = $itemGrid
            [void]$overlayStack.Children.Add($itemBorder)
        }

        $overlayBorder.Child = $overlayStack
        [void]$rootGrid.Children.Add($overlayBorder)
    }
}

# -----------------------------------------------------------------------------
# 12. 12_html_dossier_technical.png
# -----------------------------------------------------------------------------
Write-Output "[12/19] Capturing In-App HTML Technical Dossier..."
Render-WindowOffscreen -XamlPath $mainXamlPath -Width 1366 -Height 850 -OutputPath (Join-Path $docsImagesDir "12_html_dossier_technical.png") -PreShowBlock {
    param($win)
    $vp = $win.FindName("ViewportContainer")
    if ($vp) {
        foreach ($c in $vp.Children) {
            $c.Visibility = if ($c.Name -eq "PanelHtmlView") { [System.Windows.Visibility]::Visible } else { [System.Windows.Visibility]::Collapsed }
        }
    }
} -PostShowBlock {
    param($win)
    $tDN = $win.FindName("TxtHtmlViewDN")
    if ($tDN) { $tDN.Text = "CN=Alex Morgan,OU=Engineering,DC=contoso,DC=local" }
    $tPlace = $win.FindName("TxtHtmlViewDNPlaceholder")
    if ($tPlace) { $tPlace.Visibility = [System.Windows.Visibility]::Collapsed }
    $tBadge = $win.FindName("TxtHtmlViewStatusBadge")
    if ($tBadge) { $tBadge.Text = "Active Directory Dossier: Alex Morgan (contoso.local)" }

    # Replace BrowserHtmlView HwndHost with rendered WPF visual dossier
    $browser = $win.FindName("BrowserHtmlView")
    if ($browser -and $browser.Parent -is [System.Windows.Controls.Border]) {
        $parentBorder = $browser.Parent
        $parentBorder.Child = $null

        $scroll = New-Object System.Windows.Controls.ScrollViewer
        $scroll.VerticalScrollBarVisibility = [System.Windows.Controls.ScrollBarVisibility]::Auto
        $scroll.Background = $script:BrushConverter.ConvertFromString("#F8FAFC")
        $scroll.Padding = New-Object System.Windows.Thickness(20)

        $dossierStack = New-Object System.Windows.Controls.StackPanel

        # 1. Identity Header Card
        $cardHeader = New-Object System.Windows.Controls.Border
        $cardHeader.Background = [System.Windows.Media.Brushes]::White
        $cardHeader.BorderBrush = $script:BrushConverter.ConvertFromString("#CBD5E1")
        $cardHeader.BorderThickness = New-Object System.Windows.Thickness(1)
        $cardHeader.CornerRadius = New-Object System.Windows.CornerRadius(6)
        $cardHeader.Padding = New-Object System.Windows.Thickness(18)
        $cardHeader.Margin = New-Object System.Windows.Thickness(0, 0, 0, 14)

        $headG = New-Object System.Windows.Controls.Grid
        $hgCol1 = New-Object System.Windows.Controls.ColumnDefinition; $hgCol1.Width = [System.Windows.GridLength]::Auto
        $hgCol2 = New-Object System.Windows.Controls.ColumnDefinition; $hgCol2.Width = New-Object System.Windows.GridLength(1, [System.Windows.GridUnitType]::Star)
        $hgCol3 = New-Object System.Windows.Controls.ColumnDefinition; $hgCol3.Width = [System.Windows.GridLength]::Auto
        [void]$headG.ColumnDefinitions.Add($hgCol1)
        [void]$headG.ColumnDefinitions.Add($hgCol2)
        [void]$headG.ColumnDefinitions.Add($hgCol3)

        $avatar = New-Object System.Windows.Controls.Border
        $avatar.Width = 64; $avatar.Height = 64
        $avatar.CornerRadius = New-Object System.Windows.CornerRadius(32)
        $avatar.Background = $script:BrushConverter.ConvertFromString("#0284C7")
        $avatar.Margin = New-Object System.Windows.Thickness(0, 0, 16, 0)
        $avTb = New-Object System.Windows.Controls.TextBlock
        $avTb.Text = "AM"
        $avTb.FontSize = 22
        $avTb.FontWeight = [System.Windows.FontWeights]::Bold
        $avTb.Foreground = [System.Windows.Media.Brushes]::White
        $avTb.HorizontalAlignment = [System.Windows.HorizontalAlignment]::Center
        $avTb.VerticalAlignment = [System.Windows.VerticalAlignment]::Center
        $avatar.Child = $avTb
        [System.Windows.Controls.Grid]::SetColumn($avatar, 0)
        [void]$headG.Children.Add($avatar)

        $idInfo = New-Object System.Windows.Controls.StackPanel
        $nameTb = New-Object System.Windows.Controls.TextBlock
        $nameTb.Text = "Alex Morgan"
        $nameTb.FontSize = 18
        $nameTb.FontWeight = [System.Windows.FontWeights]::Bold
        $nameTb.Foreground = $script:BrushConverter.ConvertFromString("#0F172A")
        [void]$idInfo.Children.Add($nameTb)

        $upnTb = New-Object System.Windows.Controls.TextBlock
        $upnTb.Text = "alex.morgan@contoso.local  •  Lead Cloud Solutions Architect"
        $upnTb.FontSize = 12
        $upnTb.Foreground = $script:BrushConverter.ConvertFromString("#475569")
        $upnTb.Margin = New-Object System.Windows.Thickness(0, 2, 0, 0)
        [void]$idInfo.Children.Add($upnTb)

        $dnSubTb = New-Object System.Windows.Controls.TextBlock
        $dnSubTb.Text = "CN=Alex Morgan,OU=Engineering,DC=contoso,DC=local"
        $dnSubTb.FontSize = 11
        $dnSubTb.FontFamily = New-Object System.Windows.Media.FontFamily("Consolas")
        $dnSubTb.Foreground = $script:BrushConverter.ConvertFromString("#64748B")
        $dnSubTb.Margin = New-Object System.Windows.Thickness(0, 4, 0, 0)
        [void]$idInfo.Children.Add($dnSubTb)

        [System.Windows.Controls.Grid]::SetColumn($idInfo, 1)
        [void]$headG.Children.Add($idInfo)

        $statusPill = New-Object System.Windows.Controls.Border
        $statusPill.Background = $script:BrushConverter.ConvertFromString("#DCFCE7")
        $statusPill.BorderBrush = $script:BrushConverter.ConvertFromString("#16A34A")
        $statusPill.BorderThickness = New-Object System.Windows.Thickness(1)
        $statusPill.CornerRadius = New-Object System.Windows.CornerRadius(12)
        $statusPill.Padding = New-Object System.Windows.Thickness(12, 4, 12, 4)
        $statusPill.VerticalAlignment = [System.Windows.VerticalAlignment]::Top

        $statusTb = New-Object System.Windows.Controls.TextBlock
        $statusTb.Text = "● ACTIVE (Enabled)"
        $statusTb.Foreground = $script:BrushConverter.ConvertFromString("#15803D")
        $statusTb.FontWeight = [System.Windows.FontWeights]::Bold
        $statusTb.FontSize = 11
        $statusPill.Child = $statusTb
        [System.Windows.Controls.Grid]::SetColumn($statusPill, 2)
        [void]$headG.Children.Add($statusPill)

        $cardHeader.Child = $headG
        [void]$dossierStack.Children.Add($cardHeader)

        # 2. Key Attributes Grid Card
        $cardAttr = New-Object System.Windows.Controls.Border
        $cardAttr.Background = [System.Windows.Media.Brushes]::White
        $cardAttr.BorderBrush = $script:BrushConverter.ConvertFromString("#CBD5E1")
        $cardAttr.BorderThickness = New-Object System.Windows.Thickness(1)
        $cardAttr.CornerRadius = New-Object System.Windows.CornerRadius(6)
        $cardAttr.Padding = New-Object System.Windows.Thickness(16)
        $cardAttr.Margin = New-Object System.Windows.Thickness(0, 0, 0, 14)

        $attrStack = New-Object System.Windows.Controls.StackPanel
        $secHdr = New-Object System.Windows.Controls.TextBlock
        $secHdr.Text = "📋 Identity & Directory Attributes"
        $secHdr.FontSize = 13.5
        $secHdr.FontWeight = [System.Windows.FontWeights]::Bold
        $secHdr.Foreground = $script:BrushConverter.ConvertFromString("#0284C7")
        $secHdr.Margin = New-Object System.Windows.Thickness(0, 0, 0, 10)
        [void]$attrStack.Children.Add($secHdr)

        $kvItems = @(
            @("sAMAccountName", "alex.morgan", "objectSid", "S-1-5-21-392819283-109283918-2918239-1104"),
            @("userPrincipalName", "alex.morgan@contoso.local", "objectGUID", "{a4d8c72e-3351-4fa3-9f81-018274d1a039}"),
            @("mail", "alex.morgan@contoso.local", "userAccountControl", "512 (NORMAL_ACCOUNT)"),
            @("department", "Enterprise IT & Cloud", "manager", "CN=Sarah Jenkins,OU=Leadership,DC=contoso,DC=local"),
            @("pwdLastSet", "2026-09-15 11:20:44 UTC", "lastLogonTimestamp", "2026-10-19 08:42:15 UTC (DC01)")
        )

        foreach ($row in $kvItems) {
            $rg = New-Object System.Windows.Controls.Grid
            $rg.Margin = New-Object System.Windows.Thickness(0, 3, 0, 3)
            [void]$rg.ColumnDefinitions.Add((New-Object System.Windows.Controls.ColumnDefinition -Property @{ Width = New-Object System.Windows.GridLength(140) }))
            [void]$rg.ColumnDefinitions.Add((New-Object System.Windows.Controls.ColumnDefinition -Property @{ Width = New-Object System.Windows.GridLength(1, [System.Windows.GridUnitType]::Star) }))
            [void]$rg.ColumnDefinitions.Add((New-Object System.Windows.Controls.ColumnDefinition -Property @{ Width = New-Object System.Windows.GridLength(140) }))
            [void]$rg.ColumnDefinitions.Add((New-Object System.Windows.Controls.ColumnDefinition -Property @{ Width = New-Object System.Windows.GridLength(1, [System.Windows.GridUnitType]::Star) }))

            $k1 = New-Object System.Windows.Controls.TextBlock; $k1.Text = $row[0]; $k1.FontWeight = [System.Windows.FontWeights]::SemiBold; $k1.Foreground = $script:BrushConverter.ConvertFromString("#64748B"); $k1.FontSize = 11
            $v1 = New-Object System.Windows.Controls.TextBlock; $v1.Text = $row[1]; $v1.Foreground = $script:BrushConverter.ConvertFromString("#0F172A"); $v1.FontSize = 11; $v1.FontFamily = New-Object System.Windows.Media.FontFamily("Consolas")
            $k2 = New-Object System.Windows.Controls.TextBlock; $k2.Text = $row[2]; $k2.FontWeight = [System.Windows.FontWeights]::SemiBold; $k2.Foreground = $script:BrushConverter.ConvertFromString("#64748B"); $k2.FontSize = 11
            $v2 = New-Object System.Windows.Controls.TextBlock; $v2.Text = $row[3]; $v2.Foreground = $script:BrushConverter.ConvertFromString("#0F172A"); $v2.FontSize = 11; $v2.FontFamily = New-Object System.Windows.Media.FontFamily("Consolas")

            [System.Windows.Controls.Grid]::SetColumn($k1, 0); $rg.Children.Add($k1)
            [System.Windows.Controls.Grid]::SetColumn($v1, 1); $rg.Children.Add($v1)
            [System.Windows.Controls.Grid]::SetColumn($k2, 2); $rg.Children.Add($k2)
            [System.Windows.Controls.Grid]::SetColumn($v2, 3); $rg.Children.Add($v2)

            [void]$attrStack.Children.Add($rg)
        }

        $cardAttr.Child = $attrStack
        [void]$dossierStack.Children.Add($cardAttr)

        # 3. Security & Group Memberships
        $cardGroups = New-Object System.Windows.Controls.Border
        $cardGroups.Background = [System.Windows.Media.Brushes]::White
        $cardGroups.BorderBrush = $script:BrushConverter.ConvertFromString("#CBD5E1")
        $cardGroups.BorderThickness = New-Object System.Windows.Thickness(1)
        $cardGroups.CornerRadius = New-Object System.Windows.CornerRadius(6)
        $cardGroups.Padding = New-Object System.Windows.Thickness(16)

        $grpStack = New-Object System.Windows.Controls.StackPanel
        $grpHdr = New-Object System.Windows.Controls.TextBlock
        $grpHdr.Text = "🛡️ Group Memberships & Token Security (6 Groups)"
        $grpHdr.FontSize = 13.5
        $grpHdr.FontWeight = [System.Windows.FontWeights]::Bold
        $grpHdr.Foreground = $script:BrushConverter.ConvertFromString("#0284C7")
        $grpHdr.Margin = New-Object System.Windows.Thickness(0, 0, 0, 10)
        [void]$grpStack.Children.Add($grpHdr)

        $wrapGroups = New-Object System.Windows.Controls.WrapPanel
        $grpList = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Cloud-Platform-Architects", "IT-Infrastructure-Leads", "VPN-Authorized-Users")
        foreach ($g in $grpList) {
            $gb = New-Object System.Windows.Controls.Border
            $gb.Background = $script:BrushConverter.ConvertFromString("#F1F5F9")
            $gb.BorderBrush = $script:BrushConverter.ConvertFromString("#CBD5E1")
            $gb.BorderThickness = New-Object System.Windows.Thickness(1)
            $gb.CornerRadius = New-Object System.Windows.CornerRadius(4)
            $gb.Padding = New-Object System.Windows.Thickness(8, 4, 8, 4)
            $gb.Margin = New-Object System.Windows.Thickness(0, 0, 8, 8)

            $gtb = New-Object System.Windows.Controls.TextBlock
            $gtb.Text = "👥 $g"
            $gtb.FontSize = 11
            $gtb.FontWeight = [System.Windows.FontWeights]::SemiBold
            $gtb.Foreground = $script:BrushConverter.ConvertFromString("#1E293B")
            $gb.Child = $gtb
            [void]$wrapGroups.Children.Add($gb)
        }
        [void]$grpStack.Children.Add($wrapGroups)
        $cardGroups.Child = $grpStack
        [void]$dossierStack.Children.Add($cardGroups)

        $scroll.Content = $dossierStack
        $parentBorder.Child = $scroll
    }
}

# -----------------------------------------------------------------------------
# 13. 13_ldap_sql_console.png
# -----------------------------------------------------------------------------
Write-Output "[13/19] Capturing Extended LDAP-SQL Query Console..."
Render-WindowOffscreen -XamlPath $mainXamlPath -Width 1366 -Height 850 -OutputPath (Join-Path $docsImagesDir "13_ldap_sql_console.png") -PreShowBlock {
    param($win)
    $vp = $win.FindName("ViewportContainer")
    if ($vp) {
        foreach ($c in $vp.Children) {
            $c.Visibility = if ($c.Name -eq "PanelLdapSql") { [System.Windows.Visibility]::Visible } else { [System.Windows.Visibility]::Collapsed }
        }
    }
} -PostShowBlock {
    param($win)
    $tSql = $win.FindName("TxtSqlQuery")
    if ($tSql) {
        $tSql.Text = "SELECT sAMAccountName, displayName, mail, department, title FROM SUBTREE WHERE objectClass = 'user' AND department = 'Engineering' ORDER BY displayName ASC"
    }
    $tStat = $win.FindName("TxtSqlStatus")
    if ($tStat) {
        $tStat.Text = "Executed successfully in 4.2 ms. 5 matching entries returned."
        $tStat.Foreground = $script:BrushConverter.ConvertFromString("#107C41")
    }

    $bExplain = $win.FindName("BorderSqlExplainPlan")
    if ($bExplain) { $bExplain.Visibility = [System.Windows.Visibility]::Visible }
    $tExplain = $win.FindName("TxtSqlExecutionPlan")
    if ($tExplain) {
        $tExplain.Text = "LDAP Filter: (&(objectClass=user)(department=Engineering))`r`nBase DN: DC=contoso,DC=local`r`nScope: Subtree (Whole Subtree)`r`nAttributes: [sAMAccountName, displayName, mail, department, title]`r`nSort Key: displayName (ASC)`r`nExecution Cost: Indexed Attribute Scan (idx_dept), 5 candidate entries scanned, 0 unindexed evaluations."
    }

    $gSql = $win.FindName("GridSqlResults")
    if ($gSql) {
        $gSql.ItemsSource = @(
            [PSCustomObject]@{ sAMAccountName = "alex.morgan"; displayName = "Alex Morgan"; mail = "alex.morgan@contoso.local"; department = "Engineering"; title = "Lead Cloud Solutions Architect" },
            [PSCustomObject]@{ sAMAccountName = "d.kim"; displayName = "David Kim"; mail = "david.kim@contoso.local"; department = "Engineering"; title = "Cloud DevOps Engineer" },
            [PSCustomObject]@{ sAMAccountName = "e.rostova"; displayName = "Elena Rostova"; mail = "elena.rostova@contoso.local"; department = "Engineering"; title = "Site Reliability Engineer" },
            [PSCustomObject]@{ sAMAccountName = "m.chen"; displayName = "Marcus Chen"; mail = "marcus.chen@contoso.local"; department = "Engineering"; title = "Principal Systems Architect" },
            [PSCustomObject]@{ sAMAccountName = "r.patel"; displayName = "Raj Patel"; mail = "raj.patel@contoso.local"; department = "Engineering"; title = "Senior Platform Engineer" }
        )
    }
}

# -----------------------------------------------------------------------------
# 14. 14_object_compare_diff.png
# -----------------------------------------------------------------------------
Write-Output "[14/19] Capturing Dual Object Compare & Diff..."
Render-WindowOffscreen -XamlPath $mainXamlPath -Width 1366 -Height 850 -OutputPath (Join-Path $docsImagesDir "14_object_compare_diff.png") -PreShowBlock {
    param($win)
    $vp = $win.FindName("ViewportContainer")
    if ($vp) {
        foreach ($c in $vp.Children) {
            $c.Visibility = if ($c.Name -eq "PanelObjectCompare") { [System.Windows.Visibility]::Visible } else { [System.Windows.Visibility]::Collapsed }
        }
    }
} -PostShowBlock {
    param($win)
    $tObjA = $win.FindName("TxtCompareObjectA"); if ($tObjA) { $tObjA.Text = "CN=Alex Morgan,OU=Engineering,DC=contoso,DC=local" }
    $tObjB = $win.FindName("TxtCompareObjectB"); if ($tObjB) { $tObjB.Text = "CN=Alex Morgan (Staging),OU=Staging,DC=contoso,DC=local" }
    $tSum = $win.FindName("TxtCompareSummary"); if ($tSum) { $tSum.Text = "Comparison Complete: 5 attributes differ, 18 attributes identical. Object drift detected." }
    $chkDiff = $win.FindName("ChkCompareDiffsOnly"); if ($chkDiff) { $chkDiff.IsChecked = $true }

    $gCmp = $win.FindName("GridCompareResults")
    if ($gCmp) {
        $gCmp.ItemsSource = @(
            [PSCustomObject]@{ Attribute = "department"; DisplayStatus = "MODIFIED"; ValueA = "Enterprise IT & Cloud Infrastructure"; ValueB = "Legacy Systems IT" },
            [PSCustomObject]@{ Attribute = "title"; DisplayStatus = "MODIFIED"; ValueA = "Lead Cloud Solutions Architect"; ValueB = "Senior Systems Engineer" },
            [PSCustomObject]@{ Attribute = "memberOf"; DisplayStatus = "MODIFIED"; ValueA = "Domain Admins; Enterprise Admins; Cloud-Architects"; ValueB = "Domain Admins; VPN-Users" },
            [PSCustomObject]@{ Attribute = "pwdLastSet"; DisplayStatus = "MODIFIED"; ValueA = "2026-09-15 11:20:44 UTC"; ValueB = "2026-06-01 08:00:12 UTC" },
            [PSCustomObject]@{ Attribute = "whenChanged"; DisplayStatus = "MODIFIED"; ValueA = "2026-10-18 14:22:01 UTC"; ValueB = "2026-06-05 10:14:30 UTC" }
        )
    }
}

# -----------------------------------------------------------------------------
# 15. 15_replication_and_dc_matrix.png
# -----------------------------------------------------------------------------
Write-Output "[15/19] Capturing Replication Suite & DC Matrix..."
Render-WindowOffscreen -XamlPath $mainXamlPath -Width 1366 -Height 850 -OutputPath (Join-Path $docsImagesDir "15_replication_and_dc_matrix.png") -PreShowBlock {
    param($win)
    $vp = $win.FindName("ViewportContainer")
    if ($vp) {
        foreach ($c in $vp.Children) {
            $c.Visibility = if ($c.Name -eq "PanelReplicationSuite") { [System.Windows.Visibility]::Visible } else { [System.Windows.Visibility]::Collapsed }
        }
    }
} -PostShowBlock {
    param($win)
    $tTarget = $win.FindName("TxtMultiDcTarget"); if ($tTarget) { $tTarget.Text = "alex.morgan" }
    $tSum = $win.FindName("TxtMultiDcSummary"); if ($tSum) { $tSum.Text = "Most recent interactive logon occurred on DC01 (Seattle-HQ) at 2026-10-19 08:42:15 UTC" }

    $gRepl = $win.FindName("GridMultiDcLogon")
    if ($gRepl) {
        $gRepl.ItemsSource = @(
            [PSCustomObject]@{ DCName = "DC01.corp.local"; SiteName = "Seattle-HQ"; LastLogonRaw = "133748291050000000"; LastLogonDateTime = "2026-10-19 08:42:15 UTC"; LogonCount = 412; BadPwdCount = 0; ResponseMs = "1.2 ms"; StatusBadge = "LATEST LOGON" },
            [PSCustomObject]@{ DCName = "DC02.corp.local"; SiteName = "Dallas-DR"; LastLogonRaw = "133747802100000000"; LastLogonDateTime = "2026-10-18 19:10:10 UTC"; LogonCount = 389; BadPwdCount = 0; ResponseMs = "14.8 ms"; StatusBadge = "REPLICATED" },
            [PSCustomObject]@{ DCName = "DC03.corp.local"; SiteName = "Frankfurt-EU"; LastLogonRaw = "133746912000000000"; LastLogonDateTime = "2026-10-17 18:40:00 UTC"; LogonCount = 295; BadPwdCount = 0; ResponseMs = "88.4 ms"; StatusBadge = "REPLICATED" },
            [PSCustomObject]@{ DCName = "DC04.corp.local"; SiteName = "Tokyo-APAC"; LastLogonRaw = "133745012300000000"; LastLogonDateTime = "2026-10-15 14:20:30 UTC"; LogonCount = 184; BadPwdCount = 0; ResponseMs = "132.1 ms"; StatusBadge = "REPLICATED" }
        )
    }
}

# -----------------------------------------------------------------------------
# 16. 16_ldif_studio_and_safety.png
# -----------------------------------------------------------------------------
Write-Output "[16/19] Capturing LDIF Studio & Safety Engine..."
Render-WindowOffscreen -XamlPath $mainXamlPath -Width 1366 -Height 850 -OutputPath (Join-Path $docsImagesDir "16_ldif_studio_and_safety.png") -PreShowBlock {
    param($win)
    $vp = $win.FindName("ViewportContainer")
    if ($vp) {
        foreach ($c in $vp.Children) {
            $c.Visibility = if ($c.Name -eq "PanelLdifStudio") { [System.Windows.Visibility]::Visible } else { [System.Windows.Visibility]::Collapsed }
        }
    }
} -PostShowBlock {
    param($win)
    $listRec = $win.FindName("ListLdifRecords")
    if ($listRec) {
        $listRec.ItemsSource = @(
            [PSCustomObject]@{ ChangeType = "modify"; DN = "CN=Alex Morgan,OU=Engineering,DC=contoso,DC=local" },
            [PSCustomObject]@{ ChangeType = "add"; DN = "CN=App-Cloud-Prod,OU=Groups,DC=contoso,DC=local" }
        )
    }
    $tEdit = $win.FindName("TxtLdifEditor")
    if ($tEdit) {
        $tEdit.Text = @"
version: 1
dn: CN=Alex Morgan,OU=Engineering,DC=contoso,DC=local
changetype: modify
replace: title
title: Lead Cloud Solutions Architect
-
replace: department
department: Enterprise IT & Cloud Infrastructure
-

dn: CN=App-Cloud-Prod,OU=Groups,DC=contoso,DC=local
changetype: add
objectClass: top
objectClass: group
cn: App-Cloud-Prod
sAMAccountName: App-Cloud-Prod
groupType: -2147483646
description: Production Cloud Infrastructure Access Security Group
"@
    }
    $tLog = $win.FindName("TxtLdifLog")
    if ($tLog) {
        $tLog.Text = @"
[2026-10-19 09:30:12] [DRY-RUN VALIDATION ENGINE]
[PARSER] 2 RFC 2849 records parsed successfully. Syntax VALID.
[SAFETY AUDIT] No destructive bulk deletes or unindexed operations detected.
[SIMULATION] Record 1 (modify): Target DN exists. Attributes 'title', 'department' valid in Active Directory schema.
[SIMULATION] Record 2 (add): Target DN available. Mandatory attributes (cn, sAMAccountName, groupType) present.
[RESULT] DRY-RUN SIMULATION PASSED. 0 errors, 0 warnings. Safe to execute live.
"@
    }
}

# -----------------------------------------------------------------------------
# 17. 17_schema_class_browser.png
# -----------------------------------------------------------------------------
Write-Output "[17/19] Capturing Active Directory Schema Browser..."
Render-WindowOffscreen -XamlPath $mainXamlPath -Width 1366 -Height 850 -OutputPath (Join-Path $docsImagesDir "17_schema_class_browser.png") -PreShowBlock {
    param($win)
    $vp = $win.FindName("ViewportContainer")
    if ($vp) {
        foreach ($c in $vp.Children) {
            $c.Visibility = if ($c.Name -eq "PanelSchemaBrowser") { [System.Windows.Visibility]::Visible } else { [System.Windows.Visibility]::Collapsed }
        }
    }
} -PostShowBlock {
    param($win)
    $tSearch = $win.FindName("TxtSearchSchema"); if ($tSearch) { $tSearch.Text = "user" }
    $gSchema = $win.FindName("GridSchema")
    if ($gSchema) {
        $gSchema.ItemsSource = @(
            [PSCustomObject]@{ Name = "user"; OID = "1.2.840.113556.1.5.9"; Type = "Class"; Category = "Structural"; Description = "Active Directory User Account Object"; SubClassOf = "organizationalPerson" },
            [PSCustomObject]@{ Name = "computer"; OID = "1.2.840.113556.1.5.1"; Type = "Class"; Category = "Structural"; Description = "Workstation or Server Computer Account"; SubClassOf = "user" },
            [PSCustomObject]@{ Name = "group"; OID = "1.2.840.113556.1.5.8"; Type = "Class"; Category = "Structural"; Description = "Security or Distribution Group Object"; SubClassOf = "top" },
            [PSCustomObject]@{ Name = "organizationalUnit"; OID = "2.5.6.5"; Type = "Class"; Category = "Structural"; Description = "Directory Container for Administrative Delegation"; SubClassOf = "top" },
            [PSCustomObject]@{ Name = "contact"; OID = "1.2.840.113556.1.5.4"; Type = "Class"; Category = "Structural"; Description = "Mail-Enabled External Contact"; SubClassOf = "organizationalPerson" }
        )
    }

    $tName = $win.FindName("TxtSchemaDetailName"); if ($tName) { $tName.Text = "user" }
    $tOid = $win.FindName("TxtSchemaDetailOID"); if ($tOid) { $tOid.Text = "1.2.840.113556.1.5.9" }
    $tCat = $win.FindName("TxtSchemaDetailCategory"); if ($tCat) { $tCat.Text = "Structural (1)" }
    $tInh = $win.FindName("TxtSchemaDetailInheritance"); if ($tInh) { $tInh.Text = "top ➔ person ➔ organizationalPerson ➔ user" }

    $lMust = $win.FindName("ListSchemaMust")
    if ($lMust) { $lMust.ItemsSource = @("cn", "sAMAccountName", "objectSid") }
    $lMay = $win.FindName("ListSchemaMay")
    if ($lMay) { $lMay.ItemsSource = @("displayName", "mail", "userPrincipalName", "department", "title", "telephoneNumber", "memberOf", "userAccountControl") }
}

# -----------------------------------------------------------------------------
# 18. 18_modification_logs_rollback.png
# -----------------------------------------------------------------------------
Write-Output "[18/19] Capturing Modification Logs & Rollback Suite..."
Render-WindowOffscreen -XamlPath $mainXamlPath -Width 1366 -Height 850 -OutputPath (Join-Path $docsImagesDir "18_modification_logs_rollback.png") -PreShowBlock {
    param($win)
    $vp = $win.FindName("ViewportContainer")
    if ($vp) {
        foreach ($c in $vp.Children) {
            $c.Visibility = if ($c.Name -eq "PanelRequestLog") { [System.Windows.Visibility]::Visible } else { [System.Windows.Visibility]::Collapsed }
        }
    }
} -PostShowBlock {
    param($win)
    $tBadge = $win.FindName("TxtRequestLogCountBadge"); if ($tBadge) { $tBadge.Text = "142 wire requests" }

    $gLog = $win.FindName("GridRequestLog")
    if ($gLog) {
        $gLog.ItemsSource = @(
            [PSCustomObject]@{ Timestamp = "09:12:44.120"; Operation = "MODIFY"; Status = "SUCCESS (0)"; Duration = "4.2 ms"; TargetDN = "CN=Alex Morgan,OU=Engineering,DC=contoso,DC=local"; Filter = "replace: title, department" },
            [PSCustomObject]@{ Timestamp = "09:11:30.850"; Operation = "SEARCH"; Status = "SUCCESS (0)"; Duration = "2.1 ms"; TargetDN = "DC=contoso,DC=local"; Filter = "(&(objectClass=user)(sAMAccountName=alex*))" },
            [PSCustomObject]@{ Timestamp = "09:10:15.220"; Operation = "ADD"; Status = "SUCCESS (0)"; Duration = "8.7 ms"; TargetDN = "CN=App-Cloud-Prod,OU=Groups,DC=contoso,DC=local"; Filter = "cn=App-Cloud-Prod, groupType=-2147483646" },
            [PSCustomObject]@{ Timestamp = "09:08:02.100"; Operation = "MODIFY"; Status = "SUCCESS (0)"; Duration = "3.9 ms"; TargetDN = "CN=David Kim,OU=Engineering,DC=contoso,DC=local"; Filter = "replace: userAccountControl [512]" },
            [PSCustomObject]@{ Timestamp = "09:05:40.400"; Operation = "BIND"; Status = "SUCCESS (0)"; Duration = "1.4 ms"; TargetDN = "CN=Administrator,CN=Users,DC=contoso,DC=local"; Filter = "NTLM / Kerberos Negotiate SASL" }
        )
    }

    $tDet = $win.FindName("TxtRequestLogDetails")
    if ($tDet) {
        $tDet.Text = @"
# =============================================================================
# WIRE PROTOCOL MUTATION INSPECTOR & INVERSE LDIF ROLLBACK GENERATOR
# Timestamp: 2026-10-19 09:12:44.120 UTC | Operation: LDAP_REQ_MODIFY (0x66)
# Client IP: 10.0.1.50 | Server: dc01.corp.local:389 | Latency: 4.2 ms
# =============================================================================
# INVERSE ROLLBACK LDIF (Execute in LDIF Studio to safely revert mutation):
dn: CN=Alex Morgan,OU=Engineering,DC=contoso,DC=local
changetype: modify
replace: title
title: Senior Cloud Architect
-
replace: department
department: Cloud Architecture & DevOps
-
# Status: Recorded in transactional modification audit journal.
"@
    }
}

# -----------------------------------------------------------------------------
# 19. 19_connection_profiles_manager.png
# -----------------------------------------------------------------------------
Write-Output "[19/19] Capturing Connection Profiles & DC Health..."
Render-WindowOffscreen -XamlPath $mainXamlPath -Width 1366 -Height 850 -OutputPath (Join-Path $docsImagesDir "19_connection_profiles_manager.png") -PreShowBlock {
    param($win)
    $vp = $win.FindName("ViewportContainer")
    if ($vp) {
        foreach ($c in $vp.Children) {
            $c.Visibility = if ($c.Name -eq "PanelConnections") { [System.Windows.Visibility]::Visible } else { [System.Windows.Visibility]::Collapsed }
        }
    }
} -PostShowBlock {
    param($win)
    $lProf = $win.FindName("ListProfiles")
    if ($lProf) {
        $lProf.ItemsSource = @(
            "Contoso Forest Production (dc01.corp.local:636 - LDAPS)",
            "Contoso Disaster Recovery (dc02.corp.local:636 - LDAPS)",
            "Fabrikam Partner Domain (dc-stg.fabrikam.local:389 - StartTLS)",
            "Development Lab Sandbox (192.168.100.10:389 - Plain)"
        )
        $lProf.SelectedIndex = 0
    }

    $tSrv = $win.FindName("TxtDiagServer"); if ($tSrv) { $tSrv.Text = "dc01.corp.local" }
    $tIp = $win.FindName("TxtDiagIp"); if ($tIp) { $tIp.Text = "10.0.1.10" }
    $tPort = $win.FindName("TxtDiagPortStatus"); if ($tPort) { $tPort.Text = "OPEN (TCP 389 / 636 Active)" }
    $tLat = $win.FindName("TxtDiagLatency"); if ($tLat) { $tLat.Text = "1.8 ms (High Performance)" }
    $tDefNc = $win.FindName("TxtDiagDefaultNC"); if ($tDefNc) { $tDefNc.Text = "DC=contoso,DC=local" }
    $tMsg = $win.FindName("TxtDiagMessage"); if ($tMsg) { $tMsg.Text = "Profile connected. TLS 1.3 negotiated with dc01.corp.local." }

    $tDnsDomain = $win.FindName("TxtDnsDiscoveryDomain"); if ($tDnsDomain) { $tDnsDomain.Text = "contoso.local" }
    $gDns = $win.FindName("GridDnsDiscoveredDCs")
    if ($gDns) {
        $gDns.ItemsSource = @(
            [PSCustomObject]@{ Service = "_ldap._tcp.dc._msdcs"; Role = "Primary Domain Controller"; HostName = "dc01.corp.local"; IPAddress = "10.0.1.10"; Port = 389; LatencyMs = "1.8"; Status = "ONLINE (Active)" },
            [PSCustomObject]@{ Service = "_kerberos._tcp.dc._msdcs"; Role = "Kerberos KDC Key Distribution"; HostName = "dc01.corp.local"; IPAddress = "10.0.1.10"; Port = 88; LatencyMs = "1.2"; Status = "ONLINE (Active)" },
            [PSCustomObject]@{ Service = "_gc._tcp.contoso.local"; Role = "Forest Global Catalog"; HostName = "dc01.corp.local"; IPAddress = "10.0.1.10"; Port = 3268; LatencyMs = "1.5"; Status = "ONLINE (Active)" },
            [PSCustomObject]@{ Service = "_ldap._tcp.dc._msdcs"; Role = "Secondary Domain Controller"; HostName = "dc02.corp.local"; IPAddress = "10.0.2.10"; Port = 389; LatencyMs = "14.8"; Status = "ONLINE (Active)" }
        )
    }
}

Write-Output "================================================================="
Write-Output "   ALL 19 LIGHT-THEME SCREENSHOTS GENERATED SUCCESSFULLY!"
Write-Output "   Target: $docsImagesDir"
Write-Output "================================================================="
