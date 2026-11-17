<#
.SYNOPSIS
    ConfigService module for Active Directory Management Studio.
.DESCRIPTION
    Manages application configuration, JSON persistence, and Active Directory environment discovery.
#>

function Get-AppSettings {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [Alias("Get-AppConfig")]
    param (
        [string]$ConfigPath = "$PSScriptRoot\..\config.json"
    )

    $defaultConfig = [PSCustomObject]@{
        Domain = [PSCustomObject]@{
            AutoDetect       = $true
            DomainName       = ""
            DomainController = ""
            SearchBase       = ""
            DisableOU        = ""
        }
        UI = [PSCustomObject]@{
            Theme                  = "Light"
            AccentTone             = "Blue"
            SyncHtmlViewTheme      = $true
            AutoRefresh            = $false
            RefreshIntervalSeconds = 60
            PageSize               = 500
            WorkspaceMode          = "Tabs"
            AllowMultiWindow       = $true
            RestoreTabsOnStartup   = $false
            OpenTabs               = @("Dashboard", "Users", "SecurityAcl", "ReplicationSuite")
            ActiveTab              = "Dashboard"
        }
        Defaults = [PSCustomObject]@{
            PasswordLength        = 16
            PasswordRequireChange = $true
            UsernameFormat        = "first.last"
            ExportDelimiter       = ";"
            ExportPath            = ""
        }
        Ldap = [PSCustomObject]@{
            Port           = 389
            UseSSL         = $false
            TimeoutSeconds = 30
            PageSize       = 1000
        }
        Profiles = @()
        ExternalTools = @(
            [PSCustomObject]@{ Name = "Ping Hostname"; Command = "ping.exe"; Arguments = "%dNSHostName% -t" },
            [PSCustomObject]@{ Name = "Remote Desktop (RDP)"; Command = "mstsc.exe"; Arguments = "/v:%dNSHostName%" },
            [PSCustomObject]@{ Name = "PowerShell AD Inspector"; Command = "powershell.exe"; Arguments = "-NoExit -Command `"Get-ADObject -Identity '%distinguishedName%' -Properties * | Format-List`"" },
            [PSCustomObject]@{ Name = "Test LDAP Port 389"; Command = "powershell.exe"; Arguments = "-NoExit -Command `"Test-NetConnection '%dNSHostName%' -Port 389`"" },
            [PSCustomObject]@{ Name = "DNS Lookup (nslookup)"; Command = "cmd.exe"; Arguments = "/k nslookup %dNSHostName%" },
            [PSCustomObject]@{ Name = "Computer Management"; Command = "mmc.exe"; Arguments = "compmgmt.msc /computer=%dNSHostName%" },
            [PSCustomObject]@{ Name = "Event Viewer"; Command = "mmc.exe"; Arguments = "eventvwr.msc %dNSHostName%" }
        )
        CustomReports = @(
            [PSCustomObject]@{
                Name        = "Active Administrators"
                Description = "All enabled administrative accounts in the domain"
                Filter      = "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(adminCount=1))"
                ObjectClass = "User"
            }
        )
        Basket = [PSCustomObject]@{
            KeepContents = $true
            Items        = @()
        }
        Bookmarks = @()
    }

    if (Test-Path $ConfigPath) {
        try {
            $jsonContent = Get-Content -Path $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
            if (-not $jsonContent.UI) {
                $jsonContent | Add-Member -MemberType NoteProperty -Name "UI" -Value $defaultConfig.UI -Force
            } else {
                if (-not $jsonContent.UI.Theme) { $jsonContent.UI | Add-Member -MemberType NoteProperty -Name "Theme" -Value "Light" -Force }
                if (-not $jsonContent.UI.AccentTone) { $jsonContent.UI | Add-Member -MemberType NoteProperty -Name "AccentTone" -Value "Blue" -Force }
                if ($null -eq $jsonContent.UI.SyncHtmlViewTheme) { $jsonContent.UI | Add-Member -MemberType NoteProperty -Name "SyncHtmlViewTheme" -Value $true -Force }
                if (-not $jsonContent.UI.WorkspaceMode) { $jsonContent.UI | Add-Member -MemberType NoteProperty -Name "WorkspaceMode" -Value "Tabs" -Force }
                if ($null -eq $jsonContent.UI.AllowMultiWindow) { $jsonContent.UI | Add-Member -MemberType NoteProperty -Name "AllowMultiWindow" -Value $true -Force }
                if ($null -eq $jsonContent.UI.RestoreTabsOnStartup) { $jsonContent.UI | Add-Member -MemberType NoteProperty -Name "RestoreTabsOnStartup" -Value $false -Force }
                if (-not $jsonContent.UI.OpenTabs -or $jsonContent.UI.OpenTabs.Count -eq 0) { $jsonContent.UI | Add-Member -MemberType NoteProperty -Name "OpenTabs" -Value @("Dashboard", "Users", "SecurityAcl", "ReplicationSuite") -Force }
                if (-not $jsonContent.UI.ActiveTab) { $jsonContent.UI | Add-Member -MemberType NoteProperty -Name "ActiveTab" -Value "Dashboard" -Force }
            }
            if (-not $jsonContent.Basket) {
                $jsonContent | Add-Member -MemberType NoteProperty -Name "Basket" -Value $defaultConfig.Basket -Force
            } else {
                if ($null -eq $jsonContent.Basket.KeepContents) { $jsonContent.Basket | Add-Member -MemberType NoteProperty -Name "KeepContents" -Value $true -Force }
                if (-not $jsonContent.Basket.Items) { $jsonContent.Basket | Add-Member -MemberType NoteProperty -Name "Items" -Value @() -Force }
            }
            if (-not $jsonContent.Bookmarks) {
                $jsonContent | Add-Member -MemberType NoteProperty -Name "Bookmarks" -Value @() -Force
            }
            if (-not $jsonContent.ExternalTools) {
                $jsonContent | Add-Member -MemberType NoteProperty -Name "ExternalTools" -Value $defaultConfig.ExternalTools -Force
            }
            if (-not $jsonContent.CustomReports) {
                $jsonContent | Add-Member -MemberType NoteProperty -Name "CustomReports" -Value $defaultConfig.CustomReports -Force
            }
            # Keep connection profiles strictly session-only in memory; never persist or load from config.json
            $jsonContent | Add-Member -MemberType NoteProperty -Name "Profiles" -Value @() -Force
            return $jsonContent
        }
        catch {
            Write-Warning "Failed to parse $ConfigPath. Using default configuration. Error: $_"
            return $defaultConfig
        }
    }
    else {
        Save-AppSettings -Config $defaultConfig -ConfigPath $ConfigPath
        return $defaultConfig
    }
}

function Save-AppSettings {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [Alias("Save-AppConfig", "Set-AppSettings")]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [Alias("Settings")]
        [psobject]$Config,
        [string]$ConfigPath = "$PSScriptRoot\..\config.json"
    )

    $origProfiles = $null
    $hasProfiles = $null -ne $Config.PSObject.Properties['Profiles']
    if ($hasProfiles) {
        $origProfiles = $Config.Profiles
        $Config.Profiles = @()
    }
    try {
        $json = $Config | ConvertTo-Json -Depth 5
        $utf8WithBom = [System.Text.UTF8Encoding]::new($true)
        [System.IO.File]::WriteAllText($ConfigPath, $json, $utf8WithBom)
        return $true
    }
    catch {
        Write-Error "Failed to save configuration to $($ConfigPath): $_"
        return $false
    }
    finally {
        if ($hasProfiles) {
            $Config.Profiles = $origProfiles
        }
    }
}

function Get-ADEnvironmentContext {
    [CmdletBinding()]
    param (
        [PSCustomObject]$Config,
        [string]$Server = "",
        [int]$Port = 0,
        [bool]$UseSSL = $false,
        [string]$SearchBase = "",
        [System.Management.Automation.PSCredential]$Credential = $null
    )

    $explicitServer = -not [string]::IsNullOrWhiteSpace($Server)
    $resolvedServer = $Server.Trim()
    if (-not $explicitServer -and $Config -and $Config.Domain -and (-not [string]::IsNullOrWhiteSpace($Config.Domain.DomainController))) {
        $resolvedServer = $Config.Domain.DomainController.Trim()
    }

    $resolvedUseSsl = $UseSSL
    if (-not $PSBoundParameters.ContainsKey('UseSSL') -and $Port -le 0 -and -not $explicitServer -and $Config -and $Config.Ldap -and $Config.Ldap.UseSSL) {
        $resolvedUseSsl = [bool]$Config.Ldap.UseSSL
    }

    $resolvedPort = if ($Port -gt 0) {
        $Port
    } elseif (-not $explicitServer -and $Config -and $Config.Ldap -and $Config.Ldap.Port) {
        [int]$Config.Ldap.Port
    } elseif ($resolvedUseSsl) {
        636
    } else {
        389
    }
    if ($resolvedPort -eq 636) { $resolvedUseSsl = $true }
    elseif ($resolvedPort -eq 389 -and -not $PSBoundParameters.ContainsKey('UseSSL')) { $resolvedUseSsl = $false }

    $resolvedSearchBase = $SearchBase.Trim()
    if ([string]::IsNullOrWhiteSpace($resolvedSearchBase) -and -not $explicitServer -and $Config -and $Config.Domain -and (-not [string]::IsNullOrWhiteSpace($Config.Domain.SearchBase))) {
        $resolvedSearchBase = $Config.Domain.SearchBase.Trim()
    }

    $currentIdentity = try {
        if ($Credential -and -not [string]::IsNullOrWhiteSpace($Credential.UserName)) {
            $Credential.UserName
        } else {
            [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        }
    } catch { "" }

    $context = [PSCustomObject]@{
        IsConnected           = $false
        Server                = $resolvedServer
        Port                  = $resolvedPort
        UseSSL                = $resolvedUseSsl
        DomainName            = ""
        ForestName            = ""
        NetBIOSName           = ""
        PDCEmulator           = ""
        DefaultNamingContext  = ""
        RootNamingContext     = ""
        ConfigurationNC       = ""
        SearchBase            = $resolvedSearchBase
        DomainControllers     = @()
        CurrentUser           = $currentIdentity
        IsRSAT                = [bool](Get-Module -Name ActiveDirectory -ErrorAction SilentlyContinue)
        LatencyMs             = 0
        ErrorMessage          = ""
    }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $disposeMethod = [System.IDisposable].GetMethod('Dispose')

    # Strategy 1: Fast Native .NET ADSI RootDSE (supports explicit host, port, SSL, and custom credentials without RSAT)
    $rootDse = $null
    try {
        $hostPortPart = ""
        if (-not [string]::IsNullOrWhiteSpace($resolvedServer)) {
            $prefHost = $resolvedServer
            $prefPort = $resolvedPort
            if ($resolvedServer -match '^([^:]+):(\d+)$') {
                $prefHost = $Matches[1]
                $prefPort = [int]$Matches[2]
                $hostPortPart = $resolvedServer
            } else {
                $hostPortPart = "${resolvedServer}:${resolvedPort}"
            }

            # Fast TCP preflight avoids 21s blocking TCP SYN timeouts when a remote DC is unreachable
            $tcp = $null
            try {
                $tcp = [System.Net.Sockets.TcpClient]::new()
                $ar = $tcp.BeginConnect($prefHost, $prefPort, $null, $null)
                if (-not $ar.AsyncWaitHandle.WaitOne(2500, $false)) {
                    throw "TCP connection to '${prefHost}:${prefPort}' timed out after 2500 ms."
                }
                $tcp.EndConnect($ar)
            } finally {
                if ($null -ne $tcp) {
                    try { $tcp.Close() } catch { $null = $_ }
                }
            }
        }
        $dsePath = if ($hostPortPart) { "LDAP://$hostPortPart/RootDSE" } else { "LDAP://RootDSE" }

        if ($Credential) {
            $authType = [System.DirectoryServices.AuthenticationTypes]::Secure
            if ($resolvedUseSsl) {
                $authType = $authType -bor [System.DirectoryServices.AuthenticationTypes]::SecureSocketsLayer
            }
            $netCred = $Credential.GetNetworkCredential()
            $rootDse = [System.DirectoryServices.DirectoryEntry]::new($dsePath, $Credential.UserName, $netCred.Password, $authType)
        } elseif ($resolvedUseSsl) {
            $authType = [System.DirectoryServices.AuthenticationTypes]::Secure -bor [System.DirectoryServices.AuthenticationTypes]::SecureSocketsLayer
            $rootDse = [System.DirectoryServices.DirectoryEntry]::new($dsePath, $null, $null, $authType)
        } else {
            $rootDse = [System.DirectoryServices.DirectoryEntry]::new($dsePath)
        }

        $props = $rootDse.Properties
        $defNC = if ($props -and $props.Contains('defaultNamingContext')) { $props['defaultNamingContext'].Value } else { $null }
        $rootDomNC = if ($props -and $props.Contains('rootDomainNamingContext')) { $props['rootDomainNamingContext'].Value } else { $null }
        $cfgNC = if ($props -and $props.Contains('configurationNamingContext')) { $props['configurationNamingContext'].Value } else { $null }
        $dnsHost = if ($props -and $props.Contains('dnsHostName')) { $props['dnsHostName'].Value } else { $null }

        $effectiveNC = if (-not [string]::IsNullOrWhiteSpace($resolvedSearchBase)) { $resolvedSearchBase } else { [string]$defNC }
        if (-not [string]::IsNullOrWhiteSpace($effectiveNC)) {
            $ncForFqdn = if ($defNC) { [string]$defNC } else { $effectiveNC }
            $parts = ($ncForFqdn -split '(?i)DC=' | Where-Object { $_ }) | ForEach-Object { $_.TrimEnd(',') }
            $domainFqdn = $parts -join '.'

            $forestFqdn = ""
            if ($rootDomNC) {
                $fParts = ([string]$rootDomNC -split '(?i)DC=' | Where-Object { $_ }) | ForEach-Object { $_.TrimEnd(',') }
                $forestFqdn = $fParts -join '.'
            }

            $sw.Stop()
            $context.IsConnected          = $true
            $context.Server               = if ($resolvedServer) { $resolvedServer } elseif ($dnsHost) { [string]$dnsHost } else { $domainFqdn }
            $context.DomainName           = if ($domainFqdn) { $domainFqdn } elseif ($dnsHost) { [string]$dnsHost } else { $resolvedServer }
            $context.ForestName           = $forestFqdn
            $context.PDCEmulator          = if ($dnsHost) { [string]$dnsHost } else { $context.Server }
            $context.DefaultNamingContext = $effectiveNC
            $context.RootNamingContext    = [string]$defNC
            $context.ConfigurationNC      = [string]$cfgNC
            $context.SearchBase           = $effectiveNC
            $context.DomainControllers    = @($context.PDCEmulator)
            $context.LatencyMs            = [int]$sw.ElapsedMilliseconds
            $context.ErrorMessage         = ""
            return $context
        }
    }
    catch {
        $context.ErrorMessage = $_.Exception.Message
    }
    finally {
        if ($null -ne $rootDse -and ($rootDse -is [System.IDisposable])) {
            try { [void]$disposeMethod.Invoke($rootDse, $null) } catch { $null = $_ }
        }
    }

    # Strategy 2: ActiveDirectory PowerShell Module (Fallback if RootDSE was uncontactable)
    if (Get-Module -Name ActiveDirectory -ErrorAction SilentlyContinue) {
        try {
            $domParams = @{ ErrorAction = 'Stop' }
            if ($resolvedServer) { $domParams['Server'] = $resolvedServer }
            if ($Credential)     { $domParams['Credential'] = $Credential }
            $adDomain = Get-ADDomain @domParams

            $sw.Stop()
            $effectiveNC = if (-not [string]::IsNullOrWhiteSpace($resolvedSearchBase)) { $resolvedSearchBase } else { $adDomain.DistinguishedName }
            $context.IsConnected          = $true
            $context.Server               = if ($resolvedServer) { $resolvedServer } else { $adDomain.PDCEmulator }
            $context.DomainName           = $adDomain.DNSRoot
            $context.ForestName           = $adDomain.Forest
            $context.NetBIOSName          = $adDomain.NetBIOSName
            $context.PDCEmulator          = $adDomain.PDCEmulator
            $context.DefaultNamingContext = $effectiveNC
            $context.RootNamingContext    = $adDomain.DistinguishedName
            $context.SearchBase           = $effectiveNC
            $context.IsRSAT               = $true
            $context.LatencyMs            = [int]$sw.ElapsedMilliseconds
            $context.DomainControllers    = @($adDomain.ReplicaDirectoryServers)
            if ($adDomain.PDCEmulator -and -not ($context.DomainControllers -contains $adDomain.PDCEmulator)) {
                $context.DomainControllers = @($adDomain.PDCEmulator) + $context.DomainControllers
            }
            $context.ErrorMessage         = ""
            return $context
        }
        catch {
            $context.ErrorMessage = $_.Exception.Message
        }
    }

    $sw.Stop()
    $context.LatencyMs = [int]$sw.ElapsedMilliseconds
    return $context
}

function Get-ADBookmarks {
    <#
    .SYNOPSIS
        Retrieves directory favorites/bookmarks from application configuration.
    #>
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    param (
        [string]$ConfigPath = "$PSScriptRoot\..\config.json"
    )
    $cfg = Get-AppSettings -ConfigPath $ConfigPath
    if ($cfg.Bookmarks) { return @($cfg.Bookmarks) }
    return @()
}

function Add-ADBookmark {
    <#
    .SYNOPSIS
        Adds an Active Directory object to persistent favorites/bookmarks.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$DistinguishedName,
        [string]$Name = "",
        [string]$ObjectClass = "",
        [string]$ConfigPath = "$PSScriptRoot\..\config.json"
    )
    $cfg = Get-AppSettings -ConfigPath $ConfigPath
    if (-not $cfg.Bookmarks) {
        $cfg | Add-Member -MemberType NoteProperty -Name "Bookmarks" -Value @() -Force
    }
    $existing = @($cfg.Bookmarks) | Where-Object { $_.DistinguishedName -ieq $DistinguishedName }
    if ($existing) {
        return $false
    }
    $dnLeaf = ($DistinguishedName -split ',')[0] -replace '^[A-Za-z]+=',''
    $bookmarkName = if (-not [string]::IsNullOrWhiteSpace($Name)) { $Name } elseif ($dnLeaf) { $dnLeaf } else { $DistinguishedName }
    $newBookmark = [PSCustomObject]@{
        Name              = $bookmarkName
        DistinguishedName = $DistinguishedName
        ObjectClass       = $ObjectClass
        AddedAt           = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    }
    $cfg.Bookmarks = @($cfg.Bookmarks) + @($newBookmark)
    Save-AppSettings -Config $cfg -ConfigPath $ConfigPath | Out-Null
    return $true
}

function Remove-ADBookmark {
    <#
    .SYNOPSIS
        Removes an Active Directory object from persistent favorites/bookmarks.
    #>
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    param (
        [Parameter(Mandatory = $true)]
        [string]$DistinguishedName,
        [string]$ConfigPath = "$PSScriptRoot\..\config.json"
    )
    $cfg = Get-AppSettings -ConfigPath $ConfigPath
    if ($cfg.Bookmarks) {
        $cfg.Bookmarks = @($cfg.Bookmarks | Where-Object { $_.DistinguishedName -ine $DistinguishedName })
        Save-AppSettings -Config $cfg -ConfigPath $ConfigPath | Out-Null
        return $true
    }
    return $false
}

Set-Alias -Name Save-AppConfig -Value Save-AppSettings
Set-Alias -Name Get-AppConfig -Value Get-AppSettings
Set-Alias -Name Set-AppSettings -Value Save-AppSettings

Export-ModuleMember -Function Get-AppSettings, Save-AppSettings, Get-ADEnvironmentContext, Get-ADBookmarks, Add-ADBookmark, Remove-ADBookmark -Alias Save-AppConfig, Get-AppConfig, Set-AppSettings
