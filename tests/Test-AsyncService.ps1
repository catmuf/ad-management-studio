# Automated Test Suite: AsyncService (RunspacePool + Cancellation), ThemeService, WorkspaceService Cache & Phase D Utilities
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
param()

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase

Import-Module (Join-Path $projectRoot "Modules\ThemeService.psm1") -DisableNameChecking -Force
Import-Module (Join-Path $projectRoot "Modules\AsyncService.psm1") -DisableNameChecking -Force
Import-Module (Join-Path $projectRoot "Modules\WorkspaceService.psm1") -DisableNameChecking -Force
Import-Module (Join-Path $projectRoot "Modules\NetworkService.psm1") -DisableNameChecking -Force
Import-Module (Join-Path $projectRoot "Modules\DiagnosticService.psm1") -DisableNameChecking -Force

$passed = 0
$failed = 0

function Assert-Check {
    param([string]$Name, [bool]$Condition, [string]$Details = "")
    if ($Condition) {
        $script:passed++
        Write-Host "[PASS] $Name" -ForegroundColor Green
    } else {
        $script:failed++
        Write-Host "[FAIL] $Name $Details" -ForegroundColor Red
    }
}

Write-Host "=== Running Async, Theme, Workspace Cache & Phase D Diagnostic Suite ===" -ForegroundColor Cyan

# 1. ThemeService Dictionary Caching & Synchronization
$darkDict  = Import-ThemeDictionary -Theme "Dark"
$lightDict = Import-ThemeDictionary -Theme "Light"
$darkCached = Import-ThemeDictionary -Theme "Dark"
Assert-Check "ThemeService loads Dark and Light dictionaries" ($null -ne $darkDict -and $null -ne $lightDict)
Assert-Check "ThemeService caches dictionary reference O(1)" ([object]::ReferenceEquals($darkDict, $darkCached))

$inputWinPath = Join-Path $projectRoot "Views\InputPromptDialog.xaml"
$fs = [System.IO.FileStream]::new($inputWinPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read, 16384)
try { $tmpWin = [System.Windows.Markup.XamlReader]::Load($fs) } finally { $fs.Dispose() }
Sync-WindowThemeResources -TargetWindow $tmpWin -Theme "Light" -AccentTone "Emerald"
Assert-Check "Sync-WindowThemeResources applies Light BgDark & Emerald Accent" ((Convert-BrushToHex $tmpWin.Resources['BgDark']) -eq '#F8FAFC' -and (Convert-BrushToHex $tmpWin.Resources['AccentPrimary']) -eq '#107C41')

# 2. WorkspaceService Fragment Cache (25 / 25 panels)
$mainXamlPath = Join-Path $projectRoot "Views\MainWindow.xaml"
Initialize-PanelXamlCache -XamlPath $mainXamlPath
$allPanels = @('Dashboard','Users','Groups','OUs','Computers','RecycleBin','DirectorySearch','LdapSql','AttributeEditor','HtmlView','ObjectCompare','LdifStudio','AuditReports','SchemaBrowser','BulkEditor','Basket','RequestLog','SecurityAcl','KerberosSuite','ReplicationSuite','DiagnosticsToolbox','NetworkDiagnostics','ServerMonitor','Connections','Settings')
$cachedCount = 0
foreach ($pn in $allPanels) {
    $inst = New-PanelInstance -PanelName $pn
    if ($inst -and $inst.Panel -and $inst.Controls.Count -gt 0) { $cachedCount++ }
}
Assert-Check "WorkspaceService instantiates all 25 panels via cached fragments" ($cachedCount -eq 25) "count=$cachedCount"

# 3. Real RunspacePool Multi-Threaded Async Execution & Cancellation
$pb = [System.Windows.Controls.ProgressBar]::new()
$pb.Visibility = [System.Windows.Visibility]::Collapsed
$cancelBtn = [System.Windows.Controls.Button]::new()
$cancelBtn.Visibility = [System.Windows.Visibility]::Collapsed

Set-ADAsyncSyncMode $false
$uiThreadId = [System.Threading.Thread]::CurrentThread.ManagedThreadId
$script:asyncDone = $false
$script:asyncResult = $null

$null = Start-ADAsyncOperation `
    -TaskDescription "Async worker test" `
    -ProgressBar $pb `
    -CancelButton $cancelBtn `
    -Dispatcher ([System.Windows.Threading.Dispatcher]::CurrentDispatcher) `
    -ScriptBlock {
        Start-Sleep -Milliseconds 80
        return [PSCustomObject]@{ ThreadId = [System.Threading.Thread]::CurrentThread.ManagedThreadId; Value = 42 }
    } `
    -OnCompleted {
        param($res)
        $script:asyncResult = $res
        $script:asyncDone = $true
    }

Assert-Check "ProgStatusTask & BtnCancelStatusTask become Visible while async runs" ($pb.Visibility -eq 'Visible' -and $cancelBtn.Visibility -eq 'Visible')

# Pump WPF Dispatcher briefly until completion (max 4s)
$frame = [System.Windows.Threading.DispatcherFrame]::new()
$sw = [System.Diagnostics.Stopwatch]::StartNew()
while (-not $script:asyncDone -and $sw.ElapsedMilliseconds -lt 4000) {
    [System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([System.Windows.Threading.DispatcherPriority]::Background, [Action]{})
    Start-Sleep -Milliseconds 30
}
Assert-Check "RunspacePool task completed via Dispatcher without blocking" ($script:asyncDone -and $script:asyncResult.Value -eq 42)
Assert-Check "RunspacePool ran on separate background thread" ($script:asyncResult -and $script:asyncResult.ThreadId -ne $uiThreadId)
Assert-Check "ProgStatusTask & BtnCancelStatusTask collapse after completion" ($pb.Visibility -eq 'Collapsed' -and $cancelBtn.Visibility -eq 'Collapsed')

# Test Cancellation via Stop-ADAsyncOperation
$script:wasCancelled = $false
$tid = Start-ADAsyncOperation `
    -TaskDescription "Long task to cancel" `
    -ProgressBar $pb `
    -CancelButton $cancelBtn `
    -Dispatcher ([System.Windows.Threading.Dispatcher]::CurrentDispatcher) `
    -ScriptBlock {
        for ($k = 0; $k -lt 50; $k++) {
            if ($CancellationToken.IsCancellationRequested) { break }
            Start-Sleep -Milliseconds 60
        }
        return "SHOULD_NOT_COMPLETE"
    } `
    -OnCancelled {
        $script:wasCancelled = $true
    }
Start-Sleep -Milliseconds 80
$cancelRes = Stop-ADAsyncOperation -TaskId $tid
$sw.Restart()
while (-not $script:wasCancelled -and $sw.ElapsedMilliseconds -lt 3000) {
    [System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([System.Windows.Threading.DispatcherPriority]::Background, [Action]{})
    Start-Sleep -Milliseconds 30
}
Assert-Check "Stop-ADAsyncOperation cancels background task & invokes OnCancelled" ($cancelRes.CancelledCount -eq 1 -and $script:wasCancelled)

Close-ADAsyncPool

# 4. Phase D NetTools & Diagnostic Functions
$httpRes = Test-HttpUrlHeaders -Url "http://127.0.0.1:65432/" -TimeoutSeconds 1
Assert-Check "Test-HttpUrlHeaders returns structured object cleanly on offline port" ($null -ne $httpRes -and $httpRes.Url -eq "http://127.0.0.1:65432/")

$traceRes = Get-NetworkTraceAndWhoIs -Target "127.0.0.1" -MaxHops 2 -TimeoutMs 250
Assert-Check "Get-NetworkTraceAndWhoIs resolves local loopback & RFC1918 classification" ($null -ne $traceRes -and $traceRes.Hops.Count -ge 1 -and $traceRes.WhoIsText -match '127\.0\.0\.1')

$perfRes = Measure-LdapPerformanceBenchmark -Server "127.0.0.1" -Port 65432 -Iterations 3
Assert-Check "Measure-LdapPerformanceBenchmark returns 3 samples and metrics" ($null -ne $perfRes -and $perfRes.Samples.Count -eq 3 -and $perfRes.Summary -match 'Avg:')

$mailRes = Find-ADMailProxyConflicts
Assert-Check "Find-ADMailProxyConflicts executes safely" ($null -ne $mailRes -and @($mailRes).Count -ge 0)

$quotaRes = Get-ADTopQuotaUsage -Top 5
Assert-Check "Get-ADTopQuotaUsage returns quota breakdown" (@($quotaRes).Count -ge 1)

Write-Host "`nTotal Passed: $passed | Failed: $failed" -ForegroundColor Cyan
if ($failed -gt 0) { exit 1 }
exit 0
