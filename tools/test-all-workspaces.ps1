[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
[CmdletBinding()]
param()

$projectRoot = (Get-Location).Path
$ErrorActionPreference = "Continue"

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "   TESTING ALL 24 WORKSPACE TABS: OPEN -> DETACH -> DOCK -> CLOSE" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan

# Load all modules
$modules = @(
    "ConfigService.psm1", "LoggingService.psm1", "ValidationService.psm1",
    "ADService.psm1", "ExportService.psm1", "TemplateService.psm1",
    "AclService.psm1", "KerberosService.psm1", "DiagnosticService.psm1",
    "NetworkService.psm1", "ReplicationService.psm1", "GpoService.psm1",
    "SpecializedEditorService.psm1", "ScimFilterService.psm1", "ScimService.psm1"
)
foreach ($m in $modules) {
    Import-Module (Join-Path $projectRoot "Modules\$m") -DisableNameChecking -Force
}

# Load main.ps1 offscreen
$mainScript = Get-Content (Join-Path $projectRoot "main.ps1") -Raw -Encoding utf8
$mainScriptOffscreen = $mainScript -replace '\[void\]\$window\.ShowDialog\(\)', '$window.WindowStartupLocation = [System.Windows.WindowStartupLocation]::Manual; $window.Left = -32000; $window.Top = -32000; $window.Show()'

. ([scriptblock]::Create($mainScriptOffscreen))

# Process dispatcher events
[System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Loaded)
[System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::ContextIdle)

Write-Host "MainWindow loaded successfully off-screen." -ForegroundColor Green

$allPanels = @(
    'Dashboard', 'Users', 'Groups', 'OUs', 'Computers',
    'DirectorySearch', 'LdapSql', 'AttributeEditor', 'HtmlView', 'ObjectCompare',
    'LdifStudio', 'AuditReports', 'SchemaBrowser', 'BulkEditor', 'Basket',
    'RequestLog', 'Connections', 'Settings', 'RecycleBin', 'ServerMonitor',
    'SecurityAcl', 'KerberosSuite', 'ReplicationSuite', 'DiagnosticsToolbox', 'NetworkDiagnostics'
)

$results = [System.Collections.Generic.List[PSCustomObject]]::new()
$initialErrorCount = $Error.Count

foreach ($p in $allPanels) {
    Write-Host "`nTesting workspace: [$p]" -ForegroundColor Yellow
    $errBefore = $Error.Count
    $openOk = $false
    $detachOk = $false
    $dockOk = $false
    $closeOk = $false
    $tId = $null

    # 1. OPEN TAB
    try {
        Add-WorkspaceTab -PanelName $p -Activate $true
        [System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::ContextIdle)
        $tab = $state.OpenTabs | Where-Object { $_.PanelName -eq $p } | Select-Object -Last 1
        if ($tab) {
            $tId = $tab.Id
            $openOk = $true
            Write-Host "  [OPEN]   OK (Id=$tId)" -ForegroundColor Green
        } else {
            Write-Host "  [OPEN]   FAILED: Tab not found in OpenTabs" -ForegroundColor Red
        }
    } catch {
        Write-Host "  [OPEN]   EXCEPTION: $_" -ForegroundColor Red
    }

    # 2. DETACH TAB
    if ($openOk -and $tId) {
        try {
            Detach-PanelToWindow -TabId $tId
            [System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Loaded)
            [System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::ContextIdle)
            if ($state.DetachedWindows.ContainsKey($tId)) {
                $detachOk = $true
                Write-Host "  [DETACH] OK" -ForegroundColor Green
            } else {
                Write-Host "  [DETACH] FAILED: Not in DetachedWindows" -ForegroundColor Red
            }
        } catch {
            Write-Host "  [DETACH] EXCEPTION: $_" -ForegroundColor Red
        }
    }

    # 3. DOCK TAB BACK
    if ($detachOk -and $tId) {
        try {
            Dock-PanelToMainWindow -TabId $tId
            [System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Loaded)
            [System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::ContextIdle)
            if (-not $state.DetachedWindows.ContainsKey($tId)) {
                $dockOk = $true
                Write-Host "  [DOCK]   OK" -ForegroundColor Green
            } else {
                Write-Host "  [DOCK]   FAILED: Still in DetachedWindows" -ForegroundColor Red
            }
        } catch {
            Write-Host "  [DOCK]   EXCEPTION: $_" -ForegroundColor Red
        }
    }

    # 4. CLOSE TAB (keep Dashboard open as home)
    if ($p -ne "Dashboard" -and $tId) {
        try {
            Remove-WorkspaceTab -TabId $tId
            [System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::ContextIdle)
            $rem = $state.OpenTabs | Where-Object { $_.Id -eq $tId }
            if (-not $rem) {
                $closeOk = $true
                Write-Host "  [CLOSE]  OK" -ForegroundColor Green
            } else {
                Write-Host "  [CLOSE]  FAILED: Still in OpenTabs" -ForegroundColor Red
            }
        } catch {
            Write-Host "  [CLOSE]  EXCEPTION: $_" -ForegroundColor Red
        }
    } else {
        $closeOk = $true
    }

    $newErrors = $Error.Count - $errBefore
    $results.Add([PSCustomObject]@{
        Workspace = $p
        Open      = $openOk
        Detach    = $detachOk
        Dock      = $dockOk
        Close     = $closeOk
        NewErrors = $newErrors
    })
}

$window.Close()

Write-Host "`n================================================================" -ForegroundColor Cyan
Write-Host "   WORKSPACE TAB LIFECYCLE AUDIT RESULTS (ALL 24 PANELS)" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
$results | Format-Table -AutoSize

$totalNewErrors = $Error.Count - $initialErrorCount
Write-Host "`nTotal New Errors Logged to `$Error: $totalNewErrors" $(if ($totalNewErrors -eq 0) { "Green" } else { "Red" })
if ($totalNewErrors -gt 0) {
    Write-Host "`nTop Errors Recorded in `$Error:" -ForegroundColor Red
    for ($i = 0; $i -lt [Math]::Min($totalNewErrors, 10); $i++) {
        $e = $Error[$i]
        Write-Host " [$i] $e" -ForegroundColor Red
        if ($e.InvocationInfo) {
            Write-Host "     Line $($e.InvocationInfo.ScriptLineNumber): $($e.InvocationInfo.Line.Trim())" -ForegroundColor DarkRed
        }
    }
}
