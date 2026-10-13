<#
.SYNOPSIS
    ConfigService module for Active Directory Management Studio.
.DESCRIPTION
    Manages application configuration, JSON persistence, and Active Directory environment discovery.
#>

function Get-AppSettings {
    [CmdletBinding()]
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
            Theme                  = "Dark"
            AccentTone             = "Blue"
            SyncHtmlViewTheme      = $true
            AutoRefresh            = $false
            RefreshIntervalSeconds = 60
            PageSize               = 500
            WorkspaceMode          = "Tabs"
            AllowMultiWindow       = $true
            RestoreTabsOnStartup   = $true
            OpenTabs               = @("Dashboard")
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
        Profiles = @(
            [PSCustomObject]@{
                Name                  = "Default (Auto-Detect)"
                Server                = ""
                Port                  = 389
                UseSSL                = $false
                SearchBase            = ""
                UseCurrentCredentials = $true
                Username              = ""
            }
        )
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
                if (-not $jsonContent.UI.Theme) { $jsonContent.UI | Add-Member -MemberType NoteProperty -Name "Theme" -Value "Dark" -Force }
                if (-not $jsonContent.UI.AccentTone) { $jsonContent.UI | Add-Member -MemberType NoteProperty -Name "AccentTone" -Value "Blue" -Force }
                if ($null -eq $jsonContent.UI.SyncHtmlViewTheme) { $jsonContent.UI | Add-Member -MemberType NoteProperty -Name "SyncHtmlViewTheme" -Value $true -Force }
                if (-not $jsonContent.UI.WorkspaceMode) { $jsonContent.UI | Add-Member -MemberType NoteProperty -Name "WorkspaceMode" -Value "Tabs" -Force }
                if ($null -eq $jsonContent.UI.AllowMultiWindow) { $jsonContent.UI | Add-Member -MemberType NoteProperty -Name "AllowMultiWindow" -Value $true -Force }
                if ($null -eq $jsonContent.UI.RestoreTabsOnStartup) { $jsonContent.UI | Add-Member -MemberType NoteProperty -Name "RestoreTabsOnStartup" -Value $true -Force }
                if (-not $jsonContent.UI.OpenTabs) { $jsonContent.UI | Add-Member -MemberType NoteProperty -Name "OpenTabs" -Value @("Dashboard") -Force }
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
    [Alias("Save-AppConfig", "Set-AppSettings")]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [Alias("Settings")]
        [psobject]$Config,
        [string]$ConfigPath = "$PSScriptRoot\..\config.json"
    )

    try {
        $json = $Config | ConvertTo-Json -Depth 5
        [System.IO.File]::WriteAllText($ConfigPath, $json, [System.Text.Encoding]::UTF8)
        return $true
    }
    catch {
        Write-Error "Failed to save configuration to $($ConfigPath): $_"
        return $false
    }
}

function Get-ADEnvironmentContext {
    [CmdletBinding()]
    param (
        [PSCustomObject]$Config
    )

    $context = [PSCustomObject]@{
        IsConnected          = $false
        DomainName           = ""
        ForestName           = ""
        NetBIOSName          = ""
        PDCEmulator          = ""
        DefaultNamingContext = ""
        DomainControllers    = @()
        ErrorMessage         = ""
    }

    $targetServer = $null
    if ($Config -and $Config.Domain -and (-not [string]::IsNullOrWhiteSpace($Config.Domain.DomainController))) {
        $targetServer = $Config.Domain.DomainController
    }

    # Strategy 1: ActiveDirectory PowerShell Module
    $hasAdModule = $false
    if (Get-Module -Name ActiveDirectory -ErrorAction SilentlyContinue) {
        $hasAdModule = $true
    } else {
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            $hasAdModule = $true
        } catch {
            $hasAdModule = $false
        }
    }

    if ($hasAdModule) {
        try {
            $adDomain = if ($targetServer) {
                Get-ADDomain -Server $targetServer -ErrorAction Stop
            } else {
                Get-ADDomain -ErrorAction Stop
            }

            $context.IsConnected          = $true
            $context.DomainName           = $adDomain.DNSRoot
            $context.ForestName           = $adDomain.Forest
            $context.NetBIOSName          = $adDomain.NetBIOSName
            $context.PDCEmulator          = $adDomain.PDCEmulator
            $context.DefaultNamingContext = $adDomain.DistinguishedName
            $context.DomainControllers    = @($adDomain.ReplicaDirectoryServers)
            if ($adDomain.PDCEmulator -and -not ($context.DomainControllers -contains $adDomain.PDCEmulator)) {
                $context.DomainControllers = @($adDomain.PDCEmulator) + $context.DomainControllers
            }
            return $context
        }
        catch {
            # Fall through to RootDSE ADSI fallback
            $context.ErrorMessage = $_.Exception.Message
        }
    }

    # Strategy 2: Native .NET ADSI RootDSE (Zero dependencies on RSAT)
    try {
        $dsePath = if ($targetServer) { "LDAP://$targetServer/RootDSE" } else { "LDAP://RootDSE" }
        $rootDse = [System.DirectoryServices.DirectoryEntry]$dsePath
        
        $defNC = $rootDse.defaultNamingContext
        $dnsHost = $rootDse.dnsHostName
        $rootNC = $rootDse.rootDomainNamingContext

        if ($defNC) {
            $parts = ($defNC -split 'DC=' | Where-Object { $_ }) | ForEach-Object { $_.TrimEnd(',') }
            $domainFqdn = $parts -join '.'

            $context.IsConnected          = $true
            $context.DomainName           = if ($domainFqdn) { $domainFqdn } else { $dnsHost }
            $context.PDCEmulator          = $dnsHost
            $context.DefaultNamingContext = $defNC
            $context.DomainControllers    = @($dnsHost)
            $context.ErrorMessage         = ""
            return $context
        }
    }
    catch {
        $context.IsConnected = $false
        if (-not $context.ErrorMessage) {
            $context.ErrorMessage = $_.Exception.Message
        }
    }

    return $context
}

function Get-ADBookmarks {
    <#
    .SYNOPSIS
        Retrieves directory favorites/bookmarks from application configuration.
    #>
    [CmdletBinding()]
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
