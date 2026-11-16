<#
.SYNOPSIS
    Asynchronous RunspacePool & Cancellation Engine for Active Directory Management Studio.
.DESCRIPTION
    Executes blocking Active Directory, LDAP, replication, and network diagnostic queries
    on a pooled background RunspacePool with CancellationTokenSource support, polling
    completion safely on the WPF UI Dispatcher and wiring ProgStatusTask / BtnCancelStatusTask.
#>

$script:AsyncPool = $null
$script:ActiveAsyncTasks = [System.Collections.Generic.Dictionary[string, hashtable]]::new([System.StringComparer]::OrdinalIgnoreCase)
$script:LatestAsyncTaskId = $null
$script:AsyncForceSync = $false

function Set-ADAsyncSyncMode {
    [CmdletBinding()]
    param([bool]$Enabled = $false)
    $script:AsyncForceSync = $Enabled
}

function Initialize-ADAsyncPool {
    [CmdletBinding()]
    param(
        [int]$MinRunspaces = 1,
        [int]$MaxRunspaces = 4
    )
    if ($script:AsyncPool -and $script:AsyncPool.RunspacePoolStateInfo.State -eq 'Opened') {
        return $script:AsyncPool
    }
    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool($MinRunspaces, $MaxRunspaces, $iss, $Host)
    $pool.ApartmentState = [System.Threading.ApartmentState]::MTA
    $pool.ThreadOptions  = [System.Management.Automation.Runspaces.PSThreadOptions]::ReuseThread
    $pool.Open()
    $script:AsyncPool = $pool
    return $script:AsyncPool
}

function Close-ADAsyncPool {
    [CmdletBinding()]
    param()
    try { Stop-ADAsyncOperation -All } catch { $null = $_ }
    if ($script:AsyncPool) {
        try {
            $script:AsyncPool.Close()
            $script:AsyncPool.Dispose()
        } catch { $null = $_ }
        $script:AsyncPool = $null
    }
}

function Get-ADAsyncOperationStatus {
    [CmdletBinding()]
    param()
    $latest = if ($script:LatestAsyncTaskId -and $script:ActiveAsyncTasks.ContainsKey($script:LatestAsyncTaskId)) {
        $script:ActiveAsyncTasks[$script:LatestAsyncTaskId]
    } else { $null }
    return [PSCustomObject]@{
        IsBusy          = ($script:ActiveAsyncTasks.Count -gt 0)
        ActiveCount     = $script:ActiveAsyncTasks.Count
        TaskDescription = if ($latest) { $latest.Description } else { "" }
        LatestTaskId    = $script:LatestAsyncTaskId
    }
}

function Update-AsyncStatusUi {
    param(
        $ProgressBar,
        $CancelButton,
        [bool]$Busy
    )
    $vis = if ($Busy) { [System.Windows.Visibility]::Visible } else { [System.Windows.Visibility]::Collapsed }
    if ($ProgressBar) {
        $ProgressBar.IsIndeterminate = $Busy
        $ProgressBar.Visibility = $vis
    }
    if ($CancelButton) {
        $CancelButton.Visibility = $vis
        $CancelButton.IsEnabled  = $Busy
    }
}

function Stop-ADAsyncOperation {
    [CmdletBinding()]
    param(
        [string]$TaskId = "",
        [switch]$All
    )
    $ids = if ($All -or [string]::IsNullOrWhiteSpace($TaskId)) {
        @($script:ActiveAsyncTasks.Keys)
    } else {
        @($TaskId)
    }

    $cancelledCount = 0
    foreach ($id in $ids) {
        if (-not $script:ActiveAsyncTasks.ContainsKey($id)) { continue }
        $rec = $script:ActiveAsyncTasks[$id]
        try {
            if ($rec.Cts) { $rec.Cts.Cancel() }
        } catch { $null = $_ }
        try {
            if ($rec.PowerShell) { [void]$rec.PowerShell.BeginStop($null, $null) }
        } catch { $null = $_ }
        if ($rec.StatusCallback) {
            try { & $rec.StatusCallback "Cancelled: $($rec.Description)" } catch { $null = $_ }
        }
        $cancelledCount++
    }
    return [PSCustomObject]@{
        Success        = $true
        CancelledCount = $cancelledCount
    }
}

function Start-ADAsyncOperation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,
        [hashtable]$Parameters = @{},
        [string[]]$ModulesToImport = @(),
        [string]$TaskDescription = "Executing background task...",
        [scriptblock]$OnCompleted,
        [scriptblock]$OnError,
        [scriptblock]$OnCancelled,
        [System.Windows.Threading.Dispatcher]$Dispatcher = $null,
        $ProgressBar = $null,
        $CancelButton = $null,
        [scriptblock]$StatusCallback = $null,
        [switch]$Synchronous
    )

    if ($StatusCallback) {
        try { & $StatusCallback $TaskDescription } catch { $null = $_ }
    }

    $runSync = $Synchronous -or $script:AsyncForceSync -or ($env:AD_STUDIO_SYNC_MODE -eq '1')
    if ($runSync) {
        try {
            $syncRes = & $ScriptBlock @Parameters
            if ($OnCompleted) { & $OnCompleted $syncRes }
            return $syncRes
        } catch {
            if ($OnError) { & $OnError $_ }
            return $null
        }
    }

    $pool = Initialize-ADAsyncPool
    $taskId = [Guid]::NewGuid().ToString("N")
    $cts = [System.Threading.CancellationTokenSource]::new()
    $ps  = [PowerShell]::Create()
    $ps.RunspacePool = $pool

    $sbText = $ScriptBlock.ToString()
    $bootstrap = @'
param(
    [string[]]$__ModPaths,
    [string]$__ScriptBody,
    [hashtable]$__UserParams,
    [System.Threading.CancellationToken]$__CancelToken
)
$ErrorActionPreference = 'Continue'
if ($__ModPaths) {
    foreach ($mp in $__ModPaths) {
        if (-not [string]::IsNullOrWhiteSpace($mp) -and (Test-Path $mp)) {
            Import-Module $mp -DisableNameChecking -Global -ErrorAction SilentlyContinue
        }
    }
}
$CancellationToken = $__CancelToken
if ($__CancelToken.IsCancellationRequested) { return $null }
$innerSb = [scriptblock]::Create($__ScriptBody)
if ($__UserParams -and $__UserParams.Count -gt 0) {
    & $innerSb @__UserParams
} else {
    & $innerSb
}
'@
    [void]$ps.AddScript($bootstrap)
    [void]$ps.AddParameter('__ModPaths', @($ModulesToImport))
    [void]$ps.AddParameter('__ScriptBody', $sbText)
    [void]$ps.AddParameter('__UserParams', $(if ($Parameters) { $Parameters } else { @{} }))
    [void]$ps.AddParameter('__CancelToken', $cts.Token)

    $asyncHandle = $ps.BeginInvoke()

    $rec = @{
        Id             = $taskId
        Description    = $TaskDescription
        PowerShell     = $ps
        AsyncHandle    = $asyncHandle
        Cts            = $cts
        ProgressBar    = $ProgressBar
        CancelButton   = $CancelButton
        StatusCallback = $StatusCallback
        OnCompleted    = $OnCompleted
        OnError        = $OnError
        OnCancelled    = $OnCancelled
        StartedAt      = [DateTime]::UtcNow
    }
    $script:ActiveAsyncTasks[$taskId] = $rec
    $script:LatestAsyncTaskId = $taskId

    Update-AsyncStatusUi -ProgressBar $ProgressBar -CancelButton $CancelButton -Busy $true

    $timer = [System.Windows.Threading.DispatcherTimer]::new([System.Windows.Threading.DispatcherPriority]::Background, $(if ($Dispatcher) { $Dispatcher } else { [System.Windows.Threading.Dispatcher]::CurrentDispatcher }))
    $timer.Interval = [System.TimeSpan]::FromMilliseconds(60)
    $timer.Tag = $taskId
    $timer.Add_Tick({
        param($sender, $args)
        $null = $args
        $tid = "$($sender.Tag)"
        if (-not $script:ActiveAsyncTasks.ContainsKey($tid)) {
            $sender.Stop()
            return
        }
        $taskRec = $script:ActiveAsyncTasks[$tid]
        $isCancelled = ($taskRec.Cts -and $taskRec.Cts.IsCancellationRequested)
        if (-not $isCancelled -and -not $taskRec.AsyncHandle.IsCompleted) {
            return
        }

        $sender.Stop()
        [void]$script:ActiveAsyncTasks.Remove($tid)
        $stillBusy = ($script:ActiveAsyncTasks.Count -gt 0)
        Update-AsyncStatusUi -ProgressBar $taskRec.ProgressBar -CancelButton $taskRec.CancelButton -Busy $stillBusy

        try {
            if ($isCancelled) {
                try { if ($taskRec.PowerShell) { $taskRec.PowerShell.Stop() } } catch { $null = $_ }
                if ($taskRec.OnCancelled) { & $taskRec.OnCancelled }
            } else {
                $output = $null
                $errRec = $null
                try {
                    $output = $taskRec.PowerShell.EndInvoke($taskRec.AsyncHandle)
                    if ($taskRec.PowerShell.HadErrors -and $taskRec.PowerShell.Streams.Error.Count -gt 0) {
                        $errRec = $taskRec.PowerShell.Streams.Error[0]
                    }
                } catch {
                    $errRec = $_
                }

                if ($errRec -and $taskRec.OnError) {
                    & $taskRec.OnError $errRec
                } elseif ($taskRec.OnCompleted) {
                    $unwrapped = if ($output -is [System.Collections.IList] -and $output.Count -eq 1) { $output[0] } else { $output }
                    & $taskRec.OnCompleted $unwrapped
                }
            }
        } finally {
            try { if ($taskRec.PowerShell) { $taskRec.PowerShell.Dispose() } } catch { $null = $_ }
            try { if ($taskRec.Cts) { $taskRec.Cts.Dispose() } } catch { $null = $_ }
        }
    })
    $timer.Start()
    $rec['Timer'] = $timer
    return $taskId
}

Export-ModuleMember -Function `
    Set-ADAsyncSyncMode, `
    Initialize-ADAsyncPool, `
    Close-ADAsyncPool, `
    Get-ADAsyncOperationStatus, `
    Stop-ADAsyncOperation, `
    Start-ADAsyncOperation
