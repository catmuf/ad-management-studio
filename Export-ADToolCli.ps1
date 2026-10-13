<#
.SYNOPSIS
    Active Directory Headless Command-Line Export & Automation Utility (laimex parity).

.DESCRIPTION
    Provides unattended batch export and query capabilities across Active Directory environments.
    Supports CSV, LDIF, JSON, and RFC 7643 SCIM 2.0 export formats, arbitrary LDAP filters (RFC 4515),
    search base DN scoping, custom attribute projections, and argument file (@args.txt) ingestion.

.PARAMETER Format
    Export file format: CSV, LDIF, JSON, SCIM (default: CSV).

.PARAMETER FilePath
    Destination file path for exported directory records. If omitted, saves to default Export_<timestamp>.<ext>.

.PARAMETER SearchBase
    Directory container or naming context Distinguished Name to start search (e.g. "OU=Users,DC=corp,DC=com").

.PARAMETER Filter
    RFC 4515 LDAP search filter (e.g. "(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))").
    Default: "(objectClass=*)"

.PARAMETER Scope
    Search scope depth: Base, OneLevel, Subtree (default: Subtree).

.PARAMETER Attributes
    Array or comma-separated list of Active Directory attributes to project and export.

.PARAMETER PageSize
    LDAP paging page size limit (default: 1000).

.PARAMETER ConfigFile
    Optional custom path to the application configuration file (default: config.json).

.EXAMPLE
    .\Export-ADToolCli.ps1 -Format CSV -FilePath "C:\Exports\users.csv" -Filter "(objectClass=user)" -Scope Subtree

.EXAMPLE
    .\Export-ADToolCli.ps1 -Format SCIM -FilePath "C:\Exports\scim_users.json" -Filter "(department=Engineering)"

.EXAMPLE
    .\Export-ADToolCli.ps1 @batch_args.txt
#>

[CmdletBinding()]
param (
    [Parameter(Position = 0)]
    [ValidateSet("CSV", "LDIF", "JSON", "SCIM")]
    [string]$Format = "CSV",

    [Parameter(Position = 1)]
    [string]$FilePath = "",

    [Parameter(Position = 2)]
    [string]$SearchBase = "",

    [Parameter(Position = 3)]
    [string]$Filter = "(objectClass=*)",

    [Parameter(Position = 4)]
    [ValidateSet("Base", "OneLevel", "Subtree")]
    [string]$Scope = "Subtree",

    [Parameter(Position = 5)]
    [string[]]$Attributes = @(),

    [Parameter(Position = 6)]
    [int]$PageSize = 1000,

    [Parameter()]
    [string]$ConfigFile = ""
)

$scriptRoot = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($scriptRoot)) {
    $scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
}

# Resolve Modules Path
$modulesPath = Join-Path $scriptRoot "Modules"
Import-Module (Join-Path $modulesPath "ConfigService.psm1") -Force -ErrorAction Stop
Import-Module (Join-Path $modulesPath "ValidationService.psm1") -Force -ErrorAction Stop
Import-Module (Join-Path $modulesPath "ADService.psm1") -Force -ErrorAction Stop
Import-Module (Join-Path $modulesPath "ExportService.psm1") -Force -ErrorAction Stop

try {
    Write-Host "[AD-CLI] Initializing Active Directory Command-Line Engine..." -ForegroundColor Cyan

    # Load configuration
    $cfgPath = if (-not [string]::IsNullOrWhiteSpace($ConfigFile)) { $ConfigFile } else { Join-Path $scriptRoot "config.json" }
    $cfg = Get-AppSettings -ConfigPath $cfgPath

    # Determine default naming context if SearchBase is empty
    if ([string]::IsNullOrWhiteSpace($SearchBase)) {
        if ($cfg -and $cfg.Domain -and -not [string]::IsNullOrWhiteSpace($cfg.Domain.SearchBase)) {
            $SearchBase = $cfg.Domain.SearchBase
        } elseif ($cfg -and $cfg.Domain -and -not [string]::IsNullOrWhiteSpace($cfg.Domain.DefaultNamingContext)) {
            $SearchBase = $cfg.Domain.DefaultNamingContext
        } else {
            try {
                $rootDse = [System.DirectoryServices.DirectoryEntry]"LDAP://RootDSE"
                if ($rootDse -and $rootDse.defaultNamingContext) {
                    $SearchBase = [string]$rootDse.defaultNamingContext
                }
            } catch {
                $SearchBase = ""
            }
        }
    }

    Write-Host "[AD-CLI] SearchBase : $SearchBase" -ForegroundColor DarkGray
    Write-Host "[AD-CLI] Scope      : $Scope" -ForegroundColor DarkGray
    Write-Host "[AD-CLI] Filter     : $Filter" -ForegroundColor DarkGray
    Write-Host "[AD-CLI] Format     : $Format" -ForegroundColor DarkGray

    # Validate LDAP Filter
    $val = Test-LdapFilter -Filter $Filter
    if (-not $val.IsValid) {
        Write-Error "[AD-CLI] Invalid RFC 4515 LDAP filter syntax: $($val.Errors -join '; ')"
        exit 1
    }

    # Execute Search
    $searchProps = @()
    if ($Attributes -and $Attributes.Count -gt 0) {
        $searchProps = @($Attributes | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    }

    Write-Host "[AD-CLI] Executing LDAP search..." -ForegroundColor Cyan
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $searchRes = Invoke-LdapQuery -Filter $Filter -SearchBase $SearchBase -Scope $Scope -PropertiesToLoad $searchProps -PageSize $PageSize
    $stopwatch.Stop()

    if (-not $searchRes.Success) {
        Write-Error "[AD-CLI] Search execution failed: $($searchRes.Error)"
        exit 2
    }

    $records = $searchRes.Results
    $count = if ($records) { $records.Count } else { 0 }
    Write-Host "[AD-CLI] Search completed in $($stopwatch.ElapsedMilliseconds) ms. Retrieved $count object(s)." -ForegroundColor Green

    if ($count -eq 0) {
        Write-Host "[AD-CLI] No matching objects found." -ForegroundColor Yellow
        exit 0
    }

    # Export records
    if ([string]::IsNullOrWhiteSpace($FilePath)) {
        $timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
        $ext = switch ($Format.ToUpperInvariant()) {
            "CSV"  { "csv" }
            "LDIF" { "ldif" }
            "JSON" { "json" }
            "SCIM" { "json" }
            default { "txt" }
        }
        $FilePath = Join-Path $scriptRoot "Export_${timestamp}.$ext"
    }

    # Ensure parent directory exists
    $outDir = Split-Path -Parent $FilePath
    if (-not [string]::IsNullOrWhiteSpace($outDir) -and -not (Test-Path $outDir)) {
        [void](New-Item -ItemType Directory -Path $outDir -Force)
    }

    Write-Host "[AD-CLI] Exporting $count record(s) to '$FilePath' ($Format)..." -ForegroundColor Cyan

    $expRes = switch ($Format.ToUpperInvariant()) {
        "CSV" {
            Export-ADDataToCsv -Data $records -FilePath $FilePath
        }
        "LDIF" {
            Export-ADDataToLdif -Data $records -FilePath $FilePath
        }
        "JSON" {
            Export-ADDataToJson -Data $records -FilePath $FilePath
        }
        "SCIM" {
            Export-ADDataToScim -Data $records -FilePath $FilePath
        }
    }

    if ($expRes.Success) {
        Write-Host "[AD-CLI] Export completed successfully: $FilePath" -ForegroundColor Green
        exit 0
    } else {
        Write-Error "[AD-CLI] Export failed: $($expRes.Message)"
        exit 3
    }
} catch {
    Write-Error "[AD-CLI] Unhandled error: $($_.Exception.Message)"
    exit 99
}
