<#
.SYNOPSIS
    LoggingService module for Active Directory Management Studio.
.DESCRIPTION
    Provides high-performance, structured application and error logging.
    Catches all types of application errors including unhandled .NET AppDomain exceptions,
    WPF Dispatcher UI thread exceptions, and PowerShell script runtime errors.
    Automatically manages the logs folder and supports daily rolling log files.
#>

$script:LogsDirectory = $null
$script:LogLock = [System.Object]::new()
$script:IsInitialized = $false
$script:SessionTimestamp = $null

function Get-AppLogsDirectory {
    [CmdletBinding()]
    param()
    if ([string]::IsNullOrWhiteSpace($script:LogsDirectory)) {
        $moduleRoot = if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) { $PSScriptRoot } else { (Get-Location).Path }
        $repoRoot = [System.IO.Path]::GetFullPath((Join-Path $moduleRoot ".."))
        $script:LogsDirectory = Join-Path $repoRoot "logs"
    }
    return $script:LogsDirectory
}

function Get-AppLogSessionTimestamp {
    [CmdletBinding()]
    param()
    if ([string]::IsNullOrWhiteSpace($script:SessionTimestamp)) {
        $script:SessionTimestamp = (Get-Date).ToString("yyyy-MM-dd_HH-mm")
    }
    return $script:SessionTimestamp
}

function Initialize-AppLogging {
    [CmdletBinding()]
    param(
        [string]$LogsPath = "",
        [string]$SessionTimestamp = "",
        [bool]$RegisterGlobalHandlers = $true
    )

    if (-not [string]::IsNullOrWhiteSpace($LogsPath)) {
        $script:LogsDirectory = [System.IO.Path]::GetFullPath($LogsPath)
    } else {
        $script:LogsDirectory = Get-AppLogsDirectory
    }

    if (-not [string]::IsNullOrWhiteSpace($SessionTimestamp)) {
        $script:SessionTimestamp = $SessionTimestamp
    } elseif ([string]::IsNullOrWhiteSpace($script:SessionTimestamp)) {
        $script:SessionTimestamp = (Get-Date).ToString("yyyy-MM-dd_HH-mm")
    }

    # Ensure logs directory exists
    if (-not (Test-Path $script:LogsDirectory)) {
        try {
            [void](New-Item -ItemType Directory -Path $script:LogsDirectory -Force)
        } catch {
            Write-Warning "Failed to create logs directory at '$script:LogsDirectory': $_"
            return $false
        }
    }

    # Ensure .gitkeep exists so git preserves directory
    $gitKeepPath = Join-Path $script:LogsDirectory ".gitkeep"
    if (-not (Test-Path $gitKeepPath)) {
        try {
            [System.IO.File]::WriteAllText($gitKeepPath, "# Preserves logs directory`n", [System.Text.Encoding]::UTF8)
        } catch {
            $null = $_ # Suppress file write failure if gitkeep cannot be written
        }
    }

    if ($RegisterGlobalHandlers) {
        Register-GlobalAppDomainExceptionHandler
    }

    $script:IsInitialized = $true

    # Log application session startup banner
    $psVersion = if ($PSVersionTable -and $PSVersionTable.PSVersion) { $PSVersionTable.PSVersion.ToString() } else { "Unknown" }
    $clrVersion = [System.Environment]::Version.ToString()
    $osVersion = [System.Environment]::OSVersion.VersionString
    $is64Bit = [System.Environment]::Is64BitProcess
    $processId = $PID

    $startupDetails = "AD Management Studio Session Started [PID=$processId | PS=$psVersion | CLR=$clrVersion | 64Bit=$is64Bit | OS=$osVersion]"
    Write-AppLog -Level "INFO" -Category "Startup" -Message $startupDetails

    return $script:LogsDirectory
}

function Get-AppLogFilePath {
    param(
        [ValidateSet("App", "Error")][string]$Type = "App"
    )
    $dir = Get-AppLogsDirectory
    if ([string]::IsNullOrWhiteSpace($script:SessionTimestamp)) {
        $script:SessionTimestamp = (Get-Date).ToString("yyyy-MM-dd_HH-mm")
    }
    $fileName = if ($Type -eq "Error") {
        "errors_$($script:SessionTimestamp).log"
    } else {
        "$($script:SessionTimestamp).log"
    }
    return (Join-Path $dir $fileName)
}

function Write-AppLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [ValidateSet("DEBUG", "INFO", "WARN", "ERROR", "FATAL")]
        [string]$Level = "INFO",

        [string]$Category = "General",

        [System.Exception]$Exception = $null,

        [System.Management.Automation.ErrorRecord]$ErrorRecord = $null,

        [object]$Context = $null
    )

    $logDir = Get-AppLogsDirectory
    if (-not (Test-Path $logDir)) {
        try { [void](New-Item -ItemType Directory -Path $logDir -Force) } catch { $null = $_ } # Directory creation handled on file write
    }

    $now = Get-Date
    $timeStr = $now.ToString("yyyy-MM-dd HH:mm:ss.fff")
    $threadId = [System.Threading.Thread]::CurrentThread.ManagedThreadId

    $logEntry = [System.Text.StringBuilder]::new()
    [void]$logEntry.Append("[$timeStr] [$Level] [$Category] [T:$threadId] $Message")

    if ($Context) {
        try {
            $ctxStr = if ($Context -is [string]) { $Context } else { $Context | ConvertTo-Json -Compress -Depth 2 }
            [void]$logEntry.Append(" | Context: $ctxStr")
        } catch {
            $null = $_ # Suppress JSON serialization failure for complex context objects
        }
    }
    [void]$logEntry.AppendLine()

    # Append Exception details if provided
    $ex = if ($Exception) { $Exception } elseif ($ErrorRecord -and $ErrorRecord.Exception) { $ErrorRecord.Exception } else { $null }
    if ($ex) {
        [void]$logEntry.AppendLine("    --> Exception Type: $($ex.GetType().FullName)")
        [void]$logEntry.AppendLine("    --> Message: $($ex.Message)")
        if ($ex.HResult) {
            [void]$logEntry.AppendLine("    --> HResult: 0x$($ex.HResult.ToString('X8'))")
        }
        if (-not [string]::IsNullOrWhiteSpace($ex.StackTrace)) {
            [void]$logEntry.AppendLine("    --> StackTrace:")
            foreach ($line in ($ex.StackTrace -split "`r?`n")) {
                if (-not [string]::IsNullOrWhiteSpace($line)) {
                    [void]$logEntry.AppendLine("        $line")
                }
            }
        }

        # Inspect InnerException chain
        $inner = $ex.InnerException
        $depth = 1
        while ($inner -and $depth -le 5) {
            [void]$logEntry.AppendLine("    --> [InnerException Level $depth] $($inner.GetType().FullName): $($inner.Message)")
            if (-not [string]::IsNullOrWhiteSpace($inner.StackTrace)) {
                foreach ($iline in ($inner.StackTrace -split "`r?`n")) {
                    if (-not [string]::IsNullOrWhiteSpace($iline)) {
                        [void]$logEntry.AppendLine("        $iline")
                    }
                }
            }
            $inner = $inner.InnerException
            $depth++
        }
    }

    # Append PowerShell ErrorRecord details
    if ($ErrorRecord) {
        if ($ErrorRecord.InvocationInfo) {
            $inv = $ErrorRecord.InvocationInfo
            [void]$logEntry.AppendLine("    --> Script: $($inv.ScriptName) (Line $($inv.ScriptLineNumber), Col $($inv.OffsetInLine))")
            if (-not [string]::IsNullOrWhiteSpace($inv.Line)) {
                [void]$logEntry.AppendLine("    --> Command Line: $($inv.Line.Trim())")
            }
        }
        if ($ErrorRecord.ScriptStackTrace) {
            [void]$logEntry.AppendLine("    --> Script StackTrace:")
            foreach ($sline in ($ErrorRecord.ScriptStackTrace -split "`r?`n")) {
                if (-not [string]::IsNullOrWhiteSpace($sline)) {
                    [void]$logEntry.AppendLine("        $sline")
                }
            }
        }
    }

    $rawText = $logEntry.ToString()

    # Thread-safe write to log file
    [System.Threading.Monitor]::Enter($script:LogLock)
    try {
        # Always write to main rolling app log
        $appLogFile = Get-AppLogFilePath -Type "App"
        [System.IO.File]::AppendAllText($appLogFile, $rawText, [System.Text.Encoding]::UTF8)

        # Also write errors to dedicated errors log for fast debugging
        if ($Level -in @("WARN", "ERROR", "FATAL") -or ($null -ne $ex) -or ($null -ne $ErrorRecord)) {
            $errorLogFile = Get-AppLogFilePath -Type "Error"
            [System.IO.File]::AppendAllText($errorLogFile, $rawText, [System.Text.Encoding]::UTF8)
        }
    } catch {
        # Last resort fallback to stderr if file append fails
        [System.Console]::Error.WriteLine("[LoggingService Failure] Could not write to log: $_")
    } finally {
        [System.Threading.Monitor]::Exit($script:LogLock)
    }
}

function Write-AppError {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [System.Exception]$Exception = $null,

        [System.Management.Automation.ErrorRecord]$ErrorRecord = $null,

        [string]$Category = "Error",

        [object]$Context = $null
    )

    Write-AppLog -Message $Message -Level "ERROR" -Category $Category -Exception $Exception -ErrorRecord $ErrorRecord -Context $Context
}

function Register-GlobalAppDomainExceptionHandler {
    [CmdletBinding()]
    param()

    try {
        [System.AppDomain]::CurrentDomain.add_UnhandledException([System.UnhandledExceptionEventHandler]{
            param($eventSender, $eventArgsObj)
            $null = $eventSender
            $ex = $eventArgsObj.ExceptionObject
            $isTerminating = $eventArgsObj.IsTerminating
            $msg = "UNHANDLED .NET APPDOMAIN EXCEPTION (IsTerminating=$isTerminating)"

            if ($ex -is [System.Exception]) {
                Write-AppLog -Level "FATAL" -Category "AppDomain" -Message $msg -Exception $ex
            } else {
                Write-AppLog -Level "FATAL" -Category "AppDomain" -Message "$($msg): $ex"
            }
        })
    } catch {
        Write-AppLog -Level "WARN" -Category "Logging" -Message "Failed to attach AppDomain.UnhandledException handler: $_"
    }
}

function Register-WpfExceptionHandler {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Windows.Threading.Dispatcher]$Dispatcher,

        [System.Windows.Window]$Window = $null
    )

    if (-not $Dispatcher) { return }
    $null = $Window

    try {
        $Dispatcher.add_UnhandledException([System.Windows.Threading.DispatcherUnhandledExceptionEventHandler]{
            param($eventSender, $e)
            $null = $eventSender
            $ex = $e.Exception
            $winTitle = if ($Window -and $Window.Title) { $Window.Title } else { "Main UI" }
            $msg = "UNHANDLED WPF DISPATCHER EXCEPTION in [$winTitle]"

            Write-AppLog -Level "FATAL" -Category "WpfDispatcher" -Message $msg -Exception $ex

            # If window is available and has status message control, notify user gracefully
            if ($Window -and (Get-Command Set-Status -ErrorAction SilentlyContinue)) {
                try {
                    Set-Status -Message "An unexpected error occurred: $($ex.Message). Details logged to application log." -Type "Error"
                } catch {
                    $null = $_ # Suppress UI status update failure during unhandled exception
                }
            }

            # Prevent process termination if recoverable
            $e.Handled = $true
        })
    } catch {
        Write-AppError -Category "Logging" -Message "Failed to attach Dispatcher.UnhandledException handler: $_"
    }
}

function Get-LatestLogFile {
    [CmdletBinding()]
    param(
        [ValidateSet("App", "Error")][string]$Type = "Error"
    )

    $dir = Get-AppLogsDirectory
    if (-not (Test-Path $dir)) { return $null }

    $files = if ($Type -eq "Error") {
        @(Get-ChildItem -Path $dir -Filter "errors_*.log" | Sort-Object LastWriteTime -Descending)
    } else {
        @(Get-ChildItem -Path $dir -Filter "*.log" | Where-Object { $_.Name -notlike "errors_*" } | Sort-Object LastWriteTime -Descending)
    }

    if ($files.Count -gt 0) {
        return $files[0].FullName
    }

    # Fallback to current date log path
    return (Get-AppLogFilePath -Type $Type)
}

function Open-LogsFolder {
    [CmdletBinding()]
    param()

    $dir = Get-AppLogsDirectory
    if (-not (Test-Path $dir)) {
        try { [void](New-Item -ItemType Directory -Path $dir -Force) } catch { $null = $_ } # Suppress folder creation error prior to explorer launch
    }

    try {
        [System.Diagnostics.Process]::Start("explorer.exe", $dir) | Out-Null
        Write-AppLog -Level "INFO" -Category "UI" -Message "Opened logs folder in Explorer: $dir"
    } catch {
        Write-AppError -Category "UI" -Message "Failed to open logs folder '$dir'" -Exception $_
    }
}

function Open-LatestLogFile {
    [CmdletBinding()]
    param(
        [ValidateSet("App", "Error")][string]$Type = "Error"
    )

    $file = Get-LatestLogFile -Type $Type
    if (-not $file -or -not (Test-Path $file)) {
        # Create an initial entry if file does not exist yet
        Write-AppLog -Level "INFO" -Category "LogViewer" -Message "Initialized $Type log viewer"
        $file = Get-AppLogFilePath -Type $Type
    }

    try {
        [System.Diagnostics.Process]::Start("notepad.exe", $file) | Out-Null
        Write-AppLog -Level "INFO" -Category "UI" -Message "Opened log file in Notepad: $file"
    } catch {
        Write-AppError -Category "UI" -Message "Failed to open log file '$file'" -Exception $_
    }
}

function Clear-AppLog {
    [CmdletBinding()]
    param(
        [int]$OlderThanDays = 0
    )

    $dir = Get-AppLogsDirectory
    if (-not (Test-Path $dir)) { return 0 }

    $cleared = 0
    $cutoff = (Get-Date).AddDays(-$OlderThanDays)

    [System.Threading.Monitor]::Enter($script:LogLock)
    try {
        $logFiles = Get-ChildItem -Path $dir -Filter "*.log"
        foreach ($file in $logFiles) {
            if ($OlderThanDays -eq 0 -or $file.LastWriteTime -lt $cutoff) {
                try {
                    Remove-Item -Path $file.FullName -Force -ErrorAction SilentlyContinue
                    $cleared++
                } catch {
                    $null = $_ # Suppress locked log file deletion failure
                }
            }
        }
    } finally {
        [System.Threading.Monitor]::Exit($script:LogLock)
    }

    Write-AppLog -Level "INFO" -Category "Maintenance" -Message "Cleared $cleared old log file(s)."
    return $cleared
}

Set-Alias -Name Clear-AppLogs -Value Clear-AppLog

Export-ModuleMember -Function @(
    "Get-AppLogsDirectory",
    "Get-AppLogSessionTimestamp",
    "Initialize-AppLogging",
    "Get-AppLogFilePath",
    "Write-AppLog",
    "Write-AppError",
    "Register-GlobalAppDomainExceptionHandler",
    "Register-WpfExceptionHandler",
    "Get-LatestLogFile",
    "Open-LogsFolder",
    "Open-LatestLogFile",
    "Clear-AppLog"
) -Alias @(
    "Clear-AppLogs"
)
