<#
.SYNOPSIS
    ExportService module for Active Directory Management Studio.
.DESCRIPTION
    Provides CSV/Excel-compatible export capabilities with proper encoding, delimiter selection,
    and column mapping.
#>

function Export-ADDataToCsv {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.Collections.IEnumerable]$Data,

        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [string]$Delimiter = ";",

        [string[]]$PropertiesToExport = @()
    )

    try {
        $targetDir = [System.IO.Path]::GetDirectoryName($FilePath)
        if (-not (Test-Path $targetDir)) {
            [void](New-Item -ItemType Directory -Path $targetDir -Force)
        }

        $exportList = if ($PropertiesToExport -and $PropertiesToExport.Count -gt 0) {
            $Data | Select-Object -Property $PropertiesToExport
        } else {
            $Data
        }

        # Export with UTF-8 encoding and specified delimiter
        $exportList | Export-Csv -Path $FilePath -Delimiter $Delimiter -NoTypeInformation -Encoding UTF8

        return [PSCustomObject]@{
            Success  = $true
            FilePath = $FilePath
            Count    = @($exportList).Count
            Message  = "Export completed successfully ($(@($exportList).Count) records)."
        }
    }
    catch {
        return [PSCustomObject]@{
            Success  = $false
            FilePath = $FilePath
            Count    = 0
            Message  = "Export failed: $_"
        }
    }
}

Export-ModuleMember -Function Export-ADDataToCsv
