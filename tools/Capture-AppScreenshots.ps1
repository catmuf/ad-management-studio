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
#>

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

# Verify STA Apartment State
if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne [System.Threading.ApartmentState]::STA) {
    Write-Host "[INFO] Re-launching screenshot engine under Single-Threaded Apartment (STA)..." -ForegroundColor Cyan
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

function Set-NodeThemeLight ($node) {
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
            Set-NodeThemeLight $child
        }
    }
}
Set-Alias -Name Apply-NodeThemeLight -Value Set-NodeThemeLight -Scope Script

function Set-WindowLightTheme ($win) {
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

    Set-WindowLightTheme $win

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
    Apply-NodeThemeLight $win

    [System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Render)

    $rtb = New-Object System.Windows.Media.Imaging.RenderTargetBitmap($Width, $Height, 96, 96, [System.Windows.Media.PixelFormats]::Pbgra32)
    $rtb.Render($win)

    $win.Close()

    $encoder = New-Object System.Windows.Media.Imaging.PngBitmapEncoder
    $encoder.Frames.Add([System.Windows.Media.Imaging.BitmapFrame]::Create($rtb))

    $fileStream = [System.IO.File]::Create($OutputPath)
    $encoder.Save($fileStream)
    $fileStream.Close()

    Write-Host "  [CAPTURED] -> $OutputPath ($Width x $Height px)" -ForegroundColor Green
}
Set-Alias -Name Render-WindowOffscreen -Value Export-WindowOffscreen -Scope Script

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "   ACTIVE DIRECTORY MANAGEMENT STUDIO - SCREENSHOT CAPTURE ENGINE" -ForegroundColor Cyan
Write-Host "   Mode: Light Theme (Default Operator Presentation)" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

$mainXamlPath = Join-Path $projectRoot "Views\MainWindow.xaml"
$editorXamlPath = Join-Path $projectRoot "Views\SpecializedEditorDialog.xaml"

# -----------------------------------------------------------------------------
# 1. 01_dashboard_overview.png
# -----------------------------------------------------------------------------
Write-Host "[1/10] Capturing Dashboard Overview..." -ForegroundColor Yellow
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
Write-Host "[2/10] Capturing Users Grid & Attribute Inspector..." -ForegroundColor Yellow
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
Write-Host "[3/10] Capturing Specialized Hex Editor Dialog..." -ForegroundColor Yellow
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
Write-Host "[4/10] Capturing Specialized Certificate Viewer..." -ForegroundColor Yellow
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
Write-Host "[5/10] Capturing SCIM 2.0 Query & Filter Studio..." -ForegroundColor Yellow
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
Write-Host "[6/10] Capturing 6-Way Effective Rights & ACL Security..." -ForegroundColor Yellow
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
Write-Host "[7/10] Capturing Kerberos PAC Bloat Calculator..." -ForegroundColor Yellow
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
Write-Host "[8/10] Capturing Circular Group Loop Diagnostics..." -ForegroundColor Yellow
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
Write-Host "[9/10] Capturing 48 Enterprise Security Audit Reports..." -ForegroundColor Yellow
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
Write-Host "[10/10] Capturing NetTools 7-Tier UNC Diagnostics..." -ForegroundColor Yellow
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

Write-Host "=================================================================" -ForegroundColor Green
Write-Host "   ALL 10 LIGHT-THEME SCREENSHOTS GENERATED SUCCESSFULLY!" -ForegroundColor Green
Write-Host "   Target: $docsImagesDir" -ForegroundColor Green
Write-Host "=================================================================" -ForegroundColor Green
