<#
.SYNOPSIS
    Active Directory Management Studio - Headless Automation CLI
.DESCRIPTION
    Command-line interface for unattended Active Directory directory queries,
    bulk LDIF script imports, security hygiene audits, and LDAP-SQL queries.
    Engineered for sysadmin automation, CI/CD pipelines, and scheduled tasks.
    Compatible with Windows PowerShell 5.1 and PowerShell 7+.

.PARAMETER Export
    Executes an LDAP directory query and exports the matching objects.
.PARAMETER Filter
    RFC 4515 LDAP search filter (e.g., "(objectClass=user)", "(sAMAccountName=admin*)").
.PARAMETER BaseDN
    Starting Distinguished Name for the search (defaults to domain DefaultNamingContext).
.PARAMETER Scope
    LDAP Search Scope: Subtree, OneLevel, or Base (default: Subtree).
.PARAMETER Format
    Export file format: CSV, JSON, or LDIF (default: CSV).
.PARAMETER OutFile
    Target output file path. If omitted, matching objects are output to the stdout stream.
.PARAMETER Properties
    Array of specific Active Directory attribute names to load and export.
.PARAMETER Delimiter
    Delimiter character for CSV export (default: ";").

.PARAMETER ImportLDIF
    Imports and applies directory changes defined in an RFC 2849 LDIF file.
.PARAMETER InFile
    Path to the LDIF file to process.
.PARAMETER DryRun
    Simulates LDIF import without applying writes to the directory (ValidateOnly mode).

.PARAMETER Audit
    Executes automated security posture and hygiene audits against the directory.
.PARAMETER Category
    Audit category: All, InactiveUsers, PasswordsNeverExpire, LockedAccounts, PrivilegedAccounts,
    EmptyGroups, UnprotectedOUs, AdminCount, DisabledAccounts, ServiceAccounts, InactiveComputers.
.PARAMETER Days
    Inactivity or cutoff threshold in days for relevant audits (default: 90).
.PARAMETER OutReport
    Target report output file path (.html, .csv, .json, or .txt).
.PARAMETER ReportFormat
    Report format: HTML, CSV, JSON, or Text (default: HTML).

.PARAMETER QuerySQL
    Executes an LDAP-SQL query (e.g., "SELECT sAMAccountName, mail FROM 'OU=IT,...' WHERE objectClass = 'user'").
.PARAMETER Query
    The ANSI-style SQL query string to execute.
.PARAMETER QueryFormat
    Display format for SQL results: Table, CSV, or JSON (default: Table).

.PARAMETER Server
    Target Domain Controller FQDN or IP address. Overrides configuration settings.
.PARAMETER Profile
    Name of a saved connection profile in config.json to utilize.
.PARAMETER ConfigPath
    Custom path to config.json.
.PARAMETER Quiet
    Suppresses console banners, headers, and verbose logs. Outputs only data or error messages.
.PARAMETER Help
    Displays syntax guidance and usage examples.

.EXAMPLE
    .\tools\ad-studio-cli.ps1 -Export -Filter "(objectClass=user)" -Format CSV -OutFile "C:\exports\users.csv"
.EXAMPLE
    .\tools\ad-studio-cli.ps1 -Export -Filter "(&(objectClass=group)(groupType:1.2.840.113556.1.4.803:=2147483648))" -Format JSON -OutFile "C:\exports\security_groups.json"
.EXAMPLE
    .\tools\ad-studio-cli.ps1 -ImportLDIF -InFile "C:\scripts\bulk_depts.ldif" -DryRun
.EXAMPLE
    .\tools\ad-studio-cli.ps1 -ImportLDIF -InFile "C:\scripts\bulk_depts.ldif"
.EXAMPLE
    .\tools\ad-studio-cli.ps1 -Audit -Category All -OutReport "C:\reports\domain_audit.html"
.EXAMPLE
    .\tools\ad-studio-cli.ps1 -Audit -Category LockedAccounts -OutReport "C:\reports\locked.csv"
.EXAMPLE
    .\tools\ad-studio-cli.ps1 -QuerySQL -Query "SELECT sAMAccountName, mail, department FROM 'DC=example,DC=com' WHERE objectClass = 'user'"
#>

[CmdletBinding(DefaultParameterSetName = "Default")]
param (
    # --- Mode Switches ---
    [Parameter(ParameterSetName = "Export", Mandatory = $true)]
    [switch]$Export,

    [Parameter(ParameterSetName = "ImportLDIF", Mandatory = $true)]
    [switch]$ImportLDIF,

    [Parameter(ParameterSetName = "Audit", Mandatory = $true)]
    [switch]$Audit,

    [Parameter(ParameterSetName = "QuerySQL", Mandatory = $true)]
    [switch]$QuerySQL,

    # --- Export Parameters ---
    [Parameter(ParameterSetName = "Export")]
    [string]$Filter = "(objectClass=*)",

    [Parameter(ParameterSetName = "Export")]
    [Parameter(ParameterSetName = "QuerySQL")]
    [string]$BaseDN = "",

    [Parameter(ParameterSetName = "Export")]
    [ValidateSet("Subtree", "OneLevel", "Base")]
    [string]$Scope = "Subtree",

    [Parameter(ParameterSetName = "Export")]
    [ValidateSet("CSV", "JSON", "LDIF")]
    [string]$Format = "CSV",

    [Parameter(ParameterSetName = "Export")]
    [Parameter(ParameterSetName = "QuerySQL")]
    [string]$OutFile = "",

    [Parameter(ParameterSetName = "Export")]
    [Alias("Attributes", "Props")]
    [string[]]$Properties = @(),

    [Parameter(ParameterSetName = "Export")]
    [Parameter(ParameterSetName = "QuerySQL")]
    [Parameter(ParameterSetName = "Audit")]
    [string]$Delimiter = ";",

    # --- Import LDIF Parameters ---
    [Parameter(ParameterSetName = "ImportLDIF", Mandatory = $true)]
    [string]$InFile = "",

    [Parameter(ParameterSetName = "ImportLDIF")]
    [Alias("ValidateOnly")]
    [switch]$DryRun,

    # --- Audit Parameters ---
    [Parameter(ParameterSetName = "Audit")]
    [ValidateSet("All", "InactiveUsers", "PasswordsNeverExpire", "PasswordNeverExpires", "PasswordExpiringSoon", "PrivilegedAccounts", "EmptyGroups", "UnprotectedOUs", "LockedAccounts", "LockedOutUsers", "DisabledAccounts", "ServiceAccounts", "InactiveComputers", "AdminCount", "AdminCountAccounts")]
    [Alias("AuditType", "AuditCategory")]
    [string]$Category = "All",

    [Parameter(ParameterSetName = "Audit")]
    [int]$Days = 90,

    [Parameter(ParameterSetName = "Audit")]
    [string]$OutReport = "",

    [Parameter(ParameterSetName = "Audit")]
    [ValidateSet("HTML", "CSV", "JSON", "Text")]
    [string]$ReportFormat = "HTML",

    # --- SQL Query Parameters ---
    [Parameter(ParameterSetName = "QuerySQL", Mandatory = $true)]
    [Alias("SQL", "QueryString")]
    [string]$Query = "",

    [Parameter(ParameterSetName = "QuerySQL")]
    [ValidateSet("Table", "CSV", "JSON")]
    [string]$QueryFormat = "Table",

    # --- Global Connection & Profile Options ---
    [Parameter()]
    [string]$Server = "",

    [Parameter()]
    [string]$Profile = "",

    [Parameter()]
    [string]$ConfigPath = "",

    [Parameter()]
    [switch]$Quiet,

    [Parameter()]
    [Alias("h", "?")]
    [switch]$Help
)

Set-StrictMode -Off
$ErrorActionPreference = "Stop"

# Determine base directory
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $scriptDir) { $scriptDir = $PSScriptRoot }
if (-not $scriptDir) { $scriptDir = (Get-Location).Path }
$projectRoot = Split-Path -Parent $scriptDir

# Helper: Show ASCII banner and usage
function Show-CliBanner {
    if ($Quiet) { return }
    Write-Host @"
==============================================================================
   Active Directory Management Studio - Automation CLI (v2026.1)
   Headless Directory Engine | Softerra LDAP & Apache Studio Equivalence
==============================================================================
"@ -ForegroundColor Cyan
}

function Show-CliHelp {
    Show-CliBanner
    Write-Host @"
USAGE:
   .\tools\ad-studio-cli.ps1 -Export [options]
   .\tools\ad-studio-cli.ps1 -ImportLDIF [options]
   .\tools\ad-studio-cli.ps1 -Audit [options]
   .\tools\ad-studio-cli.ps1 -QuerySQL [options]

COMMAND MODES:
   -Export      Queries directory using LDAP filter and writes CSV, JSON, or LDIF.
   -ImportLDIF  Parses and executes an RFC 2849 LDIF script (supports -DryRun).
   -Audit       Runs directory hygiene/security checks (inactive, locked, UAC, etc.).
   -QuerySQL    Executes ANSI-SQL queries against LDAP endpoints.

EXPORT OPTIONS:
   -Filter <string>        RFC 4515 LDAP Filter (default: '(objectClass=*)')
   -BaseDN <string>        Search root DN (defaults to RootDSE DefaultNamingContext)
   -Scope <string>         Subtree | OneLevel | Base (default: Subtree)
   -Format <string>        CSV | JSON | LDIF (default: CSV)
   -OutFile <string>       Destination path for exported file
   -Properties <array>     Attribute names to load and export (e.g. sAMAccountName,mail)
   -Delimiter <char>       CSV delimiter character (default: ';')

IMPORT LDIF OPTIONS:
   -InFile <path>          Path to .ldif change script
   -DryRun                 Simulate changes without committing writes

AUDIT OPTIONS:
   -Category <string>      All | InactiveUsers | PasswordsNeverExpire | LockedAccounts |
                           PrivilegedAccounts | EmptyGroups | UnprotectedOUs | AdminCount
   -Days <int>             Cutoff threshold for inactivity in days (default: 90)
   -OutReport <path>       Report target path (.html, .csv, .json, or .txt)
   -ReportFormat <string>  HTML | CSV | JSON | Text (default: HTML)

LDAP-SQL OPTIONS:
   -Query <string>         SQL query: SELECT [cols] FROM '[DN]' WHERE [filter]
   -QueryFormat <string>   Table | CSV | JSON (default: Table)
   -OutFile <path>         Destination file path (optional)

GLOBAL OPTIONS:
   -Server <string>        Domain Controller host or IP override
   -Profile <string>       Named connection profile from config.json
   -ConfigPath <path>      Custom config.json location
   -Quiet                  Suppress banner and progress; output data or errors only
   -Help                   Show this manual

EXAMPLES:
   # Export all enabled users to CSV
   .\tools\ad-studio-cli.ps1 -Export -Filter '(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' -OutFile 'users.csv'

   # Validate an LDIF script without touching AD
   .\tools\ad-studio-cli.ps1 -ImportLDIF -InFile 'changes.ldif' -DryRun

   # Run complete domain hygiene audit and output executive HTML report
   .\tools\ad-studio-cli.ps1 -Audit -Category All -OutReport 'audit_report.html'

   # Execute LDAP SQL query
   .\tools\ad-studio-cli.ps1 -QuerySQL -Query "SELECT sAMAccountName, mail FROM 'DC=example,DC=com' WHERE objectClass = 'user'"
"@ -ForegroundColor Yellow
}

# Check if Help was requested or no parameters provided
if ($Help -or ($PSCmdlet.ParameterSetName -eq "Default" -and -not $Export -and -not $ImportLDIF -and -not $Audit -and -not $QuerySQL)) {
    Show-CliHelp
    exit 0
}

Show-CliBanner

# Load Modules
$modulesDir = Join-Path $projectRoot "Modules"
try {
    Import-Module (Join-Path $modulesDir "ConfigService.psm1") -ErrorAction Stop
    Import-Module (Join-Path $modulesDir "ValidationService.psm1") -ErrorAction Stop
    Import-Module (Join-Path $modulesDir "ADService.psm1") -ErrorAction Stop
    Import-Module (Join-Path $modulesDir "ExportService.psm1") -ErrorAction Stop
}
catch {
    Write-Error "Failed to load application modules from '$modulesDir': $_"
    exit 1
}

# Resolve Configuration
$cfgPath = if ($ConfigPath) { $ConfigPath } else { Join-Path $projectRoot "config.json" }
$appSettings = Get-AppSettings -ConfigPath $cfgPath

# Resolve Connection Target
$resolvedServer = $Server
$resolvedBaseDN = $BaseDN

if (-not $resolvedServer -and $Profile -and $appSettings.Profiles) {
    $matchedProfile = $appSettings.Profiles | Where-Object { $_.Name -eq $Profile }
    if ($matchedProfile) {
        if ($matchedProfile.Server) { $resolvedServer = $matchedProfile.Server }
        if (-not $resolvedBaseDN -and $matchedProfile.SearchBase) { $resolvedBaseDN = $matchedProfile.SearchBase }
    }
}

if (-not $resolvedServer -and $appSettings.Domain -and $appSettings.Domain.DomainController) {
    $resolvedServer = $appSettings.Domain.DomainController
}

if (-not $resolvedBaseDN -and $appSettings.Domain -and $appSettings.Domain.SearchBase) {
    $resolvedBaseDN = $appSettings.Domain.SearchBase
}

if (-not $Quiet -and $resolvedServer) {
    Write-Host "[INFO] Target Server: $resolvedServer" -ForegroundColor DarkGray
}

# ==============================================================================
# MODE: -Export
# ==============================================================================
if ($Export) {
    $searchScope = switch ($Scope) {
        "OneLevel" { [System.DirectoryServices.SearchScope]::OneLevel }
        "Base"     { [System.DirectoryServices.SearchScope]::Base }
        default    { [System.DirectoryServices.SearchScope]::Subtree }
    }

    if (-not $Quiet) {
        Write-Host "[EXPORT] Searching directory with filter: $Filter" -ForegroundColor Gray
        Write-Host "[EXPORT] Base DN: $(if ($resolvedBaseDN) { $resolvedBaseDN } else { 'RootDSE DefaultNamingContext' })" -ForegroundColor Gray
        Write-Host "[EXPORT] Scope: $Scope | Format: $Format" -ForegroundColor Gray
    }

    $resolvedProperties = @()
    if ($Properties) {
        foreach ($p in $Properties) {
            foreach ($sub in ($p -split '[,;]')) {
                $trimmed = $sub.Trim().Trim("'", '"')
                if ($trimmed) { $resolvedProperties += $trimmed }
            }
        }
    }

    $queryResult = Invoke-LdapQuery -Filter $Filter `
                                   -SearchBase $resolvedBaseDN `
                                   -Scope $searchScope `
                                   -PropertiesToLoad $resolvedProperties `
                                   -Server $resolvedServer

    if (-not $queryResult.Success) {
        Write-Error "Export search failed: $($queryResult.Error)"
        exit 1
    }

    $records = $queryResult.Results
    if (-not $Quiet) {
        Write-Host "[EXPORT] Retrieved $($records.Count) objects in $($queryResult.ElapsedMilliseconds) ms." -ForegroundColor Green
    }

    if ($OutFile) {
        $resolvedOutPath = [System.IO.Path]::GetFullPath($OutFile)
        $exportResult = $null
        switch ($Format.ToUpper()) {
            "JSON" {
                $exportResult = Export-ADDataToJson -Data $records -FilePath $resolvedOutPath
            }
            "LDIF" {
                $exportResult = Export-ADDataToLdif -Data $records -FilePath $resolvedOutPath
            }
            default { # CSV
                $exportResult = Export-ADDataToCsv -Data $records -FilePath $resolvedOutPath -Delimiter $Delimiter -PropertiesToExport $resolvedProperties
            }
        }

        if (-not $exportResult.Success) {
            Write-Error "Failed to write export file: $($exportResult.Message)"
            exit 1
        }

        if (-not $Quiet) {
            Write-Host "[SUCCESS] Successfully written $($records.Count) records to: $resolvedOutPath" -ForegroundColor Cyan
        }
    }
    else {
        # Output directly to stdout
        $records
    }

    exit 0
}

# ==============================================================================
# MODE: -ImportLDIF
# ==============================================================================
if ($ImportLDIF) {
    if (-not (Test-Path $InFile)) {
        Write-Error "LDIF source file not found: '$InFile'"
        exit 1
    }

    if (-not $Quiet) {
        Write-Host "[LDIF] Reading LDIF file: $InFile" -ForegroundColor Gray
        if ($DryRun) {
            Write-Host "[LDIF] Dry-Run mode enabled: No changes will be committed to AD." -ForegroundColor Yellow
        }
    }

    $ldifContent = [System.IO.File]::ReadAllText($InFile, [System.Text.Encoding]::UTF8)
    $importResult = Invoke-LdifImport -LdifContent $ldifContent -ValidateOnly:$DryRun -Server $resolvedServer

    if (-not $Quiet) {
        Write-Host ""
        Write-Host $importResult.LogText
        Write-Host ""
    }

    if (-not $importResult.Success) {
        Write-Error "LDIF execution encountered $($importResult.ErrorCount) error(s)."
        exit 1
    }

    if (-not $Quiet) {
        Write-Host "[SUCCESS] LDIF operations finished successfully ($($importResult.SuccessCount) applied)." -ForegroundColor Green
    }

    exit 0
}

# ==============================================================================
# MODE: -Audit
# ==============================================================================
if ($Audit) {
    if (-not $Quiet) {
        Write-Host "[AUDIT] Initiating security & hygiene audit (Category: $Category)..." -ForegroundColor Gray
    }

    # Determine automatic format if OutReport has extension
    $targetFormat = $ReportFormat
    $resolvedOutReport = if ($OutReport) { [System.IO.Path]::GetFullPath($OutReport) } else { "" }
    if ($resolvedOutReport) {
        $ext = [System.IO.Path]::GetExtension($resolvedOutReport).ToLower()
        if ($ext -eq ".html" -or $ext -eq ".htm") { $targetFormat = "HTML" }
        elseif ($ext -eq ".csv")                 { $targetFormat = "CSV" }
        elseif ($ext -eq ".json")                { $targetFormat = "JSON" }
        elseif ($ext -eq ".txt")                 { $targetFormat = "Text" }
    }

    if ($Category -eq "All") {
        $allCategories = @("InactiveUsers", "LockedAccounts", "PasswordsNeverExpire", "PrivilegedAccounts", "EmptyGroups", "UnprotectedOUs", "AdminCount")
        $combinedFindings = New-Object System.Collections.Generic.List[PSCustomObject]
        $summaryTable = [ordered]@{}

        foreach ($cat in $allCategories) {
            if (-not $Quiet) {
                Write-Host "  -> Evaluating category: $cat..." -ForegroundColor DarkGray
            }
            $rep = Get-ADSecurityAuditReport -Category $cat -Days $Days -Server $resolvedServer
            $summaryTable[$rep.Title] = "$($rep.Count) issue(s)"
            foreach ($item in $rep.Findings) {
                $propHash = [ordered]@{}
                $propHash['AuditCategory'] = $cat
                foreach ($p in $item.PSObject.Properties) {
                    $propHash[$p.Name] = $p.Value
                }
                $combinedFindings.Add([PSCustomObject]$propHash)
            }
        }

        $reportTitle = "Active Directory Enterprise Security & Hygiene Audit"
        if ($resolvedOutReport) {
            switch ($targetFormat) {
                "HTML" {
                    $res = Export-ADSecurityAuditToHtml -ReportTitle $reportTitle `
                                                        -SummaryStats $summaryTable `
                                                        -Data $combinedFindings `
                                                        -FilePath $resolvedOutReport
                    if (-not $res.Success) { Write-Error $res.Message; exit 1 }
                }
                "CSV" {
                    $res = Export-ADDataToCsv -Data $combinedFindings -FilePath $resolvedOutReport -Delimiter $Delimiter
                    if (-not $res.Success) { Write-Error $res.Message; exit 1 }
                }
                "JSON" {
                    $res = Export-ADDataToJson -Data $combinedFindings -FilePath $resolvedOutReport
                    if (-not $res.Success) { Write-Error $res.Message; exit 1 }
                }
                "Text" {
                    $sb = New-Object System.Text.StringBuilder
                    [void]$sb.AppendLine("=== $reportTitle ===")
                    [void]$sb.AppendLine("Execution Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
                    [void]$sb.AppendLine("Server: $resolvedServer")
                    [void]$sb.AppendLine("--------------------------------------------------")
                    foreach ($k in $summaryTable.Keys) {
                        [void]$sb.AppendLine(("{0,-50} : {1}" -f $k, $summaryTable[$k]))
                    }
                    [void]$sb.AppendLine("==================================================")
                    [System.IO.File]::WriteAllText($resolvedOutReport, $sb.ToString(), [System.Text.Encoding]::UTF8)
                }
            }
            if (-not $Quiet) {
                Write-Host "[SUCCESS] Comprehensive audit exported to: $resolvedOutReport" -ForegroundColor Cyan
            }
        }
        else {
            if (-not $Quiet) {
                Write-Host ""
                Write-Host "=== AUDIT SUMMARY ===" -ForegroundColor Yellow
                foreach ($k in $summaryTable.Keys) {
                    Write-Host ("{0,-50} : {1}" -f $k, $summaryTable[$k]) -ForegroundColor White
                }
                Write-Host ""
            }
            $combinedFindings
        }
    }
    else {
        # Single category audit
        $report = Get-ADSecurityAuditReport -Category $Category -Days $Days -Server $resolvedServer

        if ($resolvedOutReport) {
            switch ($targetFormat) {
                "HTML" {
                    $res = Export-ADSecurityAuditToHtml -AuditReport $report -FilePath $resolvedOutReport
                    if (-not $res.Success) { Write-Error $res.Message; exit 1 }
                }
                "CSV" {
                    $res = Export-ADDataToCsv -Data $report.Findings -FilePath $resolvedOutReport -Delimiter $Delimiter
                    if (-not $res.Success) { Write-Error $res.Message; exit 1 }
                }
                "JSON" {
                    $res = Export-ADDataToJson -Data $report.Findings -FilePath $resolvedOutReport
                    if (-not $res.Success) { Write-Error $res.Message; exit 1 }
                }
                "Text" {
                    $sb = New-Object System.Text.StringBuilder
                    [void]$sb.AppendLine("=== $($report.Title) ===")
                    [void]$sb.AppendLine("Category: $($report.Category)")
                    [void]$sb.AppendLine("Findings Count: $($report.Count)")
                    [void]$sb.AppendLine("Execution Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
                    [void]$sb.AppendLine("--------------------------------------------------")
                    if ($report.SummaryStats) {
                        foreach ($k in $report.SummaryStats.Keys) {
                            [void]$sb.AppendLine(("{0,-30} : {1}" -f $k, $report.SummaryStats[$k]))
                        }
                    }
                    [void]$sb.AppendLine("==================================================")
                    [System.IO.File]::WriteAllText($resolvedOutReport, $sb.ToString(), [System.Text.Encoding]::UTF8)
                }
            }
            if (-not $Quiet) {
                Write-Host "[SUCCESS] Audit report for '$Category' exported to: $resolvedOutReport" -ForegroundColor Cyan
            }
        }
        else {
            if (-not $Quiet) {
                Write-Host "[INFO] $($report.Title): $($report.Count) finding(s) found." -ForegroundColor Yellow
            }
            $report.Findings
        }
    }

    exit 0
}

# ==============================================================================
# MODE: -QuerySQL
# ==============================================================================
if ($QuerySQL) {
    if (-not $Quiet) {
        Write-Host "[SQL] Executing LDAP-SQL query: $Query" -ForegroundColor Gray
    }

    $sqlResult = Invoke-LdapSqlQuery -SqlQuery $Query -DefaultSearchBase $resolvedBaseDN -Server $resolvedServer

    if (-not $sqlResult.Success) {
        Write-Error "LDAP-SQL Query execution failed: $($sqlResult.Message)"
        exit 1
    }

    $rows = $sqlResult.Results
    if (-not $Quiet) {
        Write-Host "[SQL] Returned $($rows.Count) record(s) in $($sqlResult.ElapsedMilliseconds) ms." -ForegroundColor Green
    }

    if ($OutFile) {
        $resolvedOutFile = [System.IO.Path]::GetFullPath($OutFile)
        $exportResult = $null
        $ext = [System.IO.Path]::GetExtension($resolvedOutFile).ToLower()
        if ($ext -eq ".json" -or $QueryFormat -eq "JSON") {
            $exportResult = Export-ADDataToJson -Data $rows -FilePath $resolvedOutFile
        }
        else {
            $exportResult = Export-ADDataToCsv -Data $rows -FilePath $resolvedOutFile -Delimiter $Delimiter
        }

        if (-not $exportResult.Success) {
            Write-Error "Failed to write SQL results to file: $($exportResult.Message)"
            exit 1
        }

        if (-not $Quiet) {
            Write-Host "[SUCCESS] Query results written to: $resolvedOutFile" -ForegroundColor Cyan
        }
    }
    else {
        if ($Quiet) {
            $rows
        }
        else {
            if ($QueryFormat -eq "CSV") {
                $rows | ConvertTo-Csv -Delimiter $Delimiter -NoTypeInformation
            }
            elseif ($QueryFormat -eq "JSON") {
                $rows | ConvertTo-Json -Depth 4
            }
            else {
                $rows | Format-Table -AutoSize
            }
        }
    }

    exit 0
}
