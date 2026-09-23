<#
.SYNOPSIS
    ConfigService module for Active Directory Management Studio.
.DESCRIPTION
    Manages application configuration, JSON persistence, and Active Directory environment discovery.
#>

function Get-AppSettings {
    [CmdletBinding()]
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
            AutoRefresh            = $false
            RefreshIntervalSeconds = 60
            PageSize               = 500
        }
        Defaults = [PSCustomObject]@{
            PasswordLength        = 16
            PasswordRequireChange = $true
            UsernameFormat        = "first.last"
            ExportDelimiter       = ";"
            ExportPath            = ""
        }
    }

    if (Test-Path $ConfigPath) {
        try {
            $jsonContent = Get-Content -Path $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
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
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Config,
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

    if (-not (Get-Module -Name ActiveDirectory -ErrorAction SilentlyContinue)) {
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
        }
        catch {
            $context.ErrorMessage = "ActiveDirectory PowerShell module is not installed or available."
            return $context
        }
    }

    try {
        $targetServer = $null
        if ($Config -and $Config.Domain -and (-not [string]::IsNullOrWhiteSpace($Config.Domain.DomainController))) {
            $targetServer = $Config.Domain.DomainController
        }

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
    }
    catch {
        $context.IsConnected  = $false
        $context.ErrorMessage = $_.Exception.Message
    }

    return $context
}

Export-ModuleMember -Function Get-AppSettings, Save-AppSettings, Get-ADEnvironmentContext
