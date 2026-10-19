[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
[CmdletBinding()]
param()

$projectRoot = (Get-Location).Path
$logOutput = [System.Collections.Generic.List[string]]::new()

function Write-TestLog ($msg, $color = "White") {
    $formatted = "[TEST $(Get-Date -Format 'HH:mm:ss.fff')] $msg"
    Write-Host $formatted -ForegroundColor $color
    $logOutput.Add($formatted)
}

Write-TestLog "Starting Runtime Usability & Tab Test..." "Cyan"

# Load modules
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

# Read main.ps1, modify last line to offscreen Show() instead of blocking ShowDialog()
$mainScript = Get-Content (Join-Path $projectRoot "main.ps1") -Raw -Encoding utf8
$mainScriptOffscreen = $mainScript -replace '\[void\]\$window\.ShowDialog\(\)', '$window.WindowStartupLocation = [System.Windows.WindowStartupLocation]::Manual; $window.Left = -32000; $window.Top = -32000; $window.Show()'

$recordedErrors = [System.Collections.Generic.List[object]]::new()

try {
    # Execute main.ps1 offscreen in current scope
    . ([scriptblock]::Create($mainScriptOffscreen))
    
    # Process dispatcher events to complete Loaded handler
    [System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Loaded)
    [System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::ContextIdle)

    Write-TestLog "MainWindow loaded off-screen successfully." "Green"
    Write-TestLog "Initial OpenTabs count: $($state.OpenTabs.Count)" "Yellow"
    foreach ($t in $state.OpenTabs) {
        Write-TestLog "  - Tab: Id=$($t.Id), PanelName=$($t.PanelName), Title=$($t.Title)" "Gray"
    }

    # STEP 1: Test opening multiple tabs
    Write-TestLog "`n--- STEP 1: Opening multiple tabs ---" "Cyan"
    $panelsToOpen = @('Users', 'DirectorySearch', 'Groups', 'OUs', 'Computers', 'LdapSql', 'SecurityAcl', 'KerberosSuite')
    foreach ($p in $panelsToOpen) {
        try {
            Write-TestLog "Opening tab for panel: $p"
            Add-WorkspaceTab -PanelName $p -Activate $true
            [System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::ContextIdle)
            Write-TestLog "  -> Success. OpenTabs count: $($state.OpenTabs.Count)" "Green"
        } catch {
            Write-TestLog "  -> ERROR opening $($p): $_" "Red"
            $recordedErrors.Add($_)
        }
    }

    # STEP 2: Test duplicate tab instances
    Write-TestLog "`n--- STEP 2: Opening duplicate tab instances ---" "Cyan"
    try {
        Write-TestLog "Opening second instance of Users tab..."
        Add-WorkspaceTab -PanelName "Users" -NewInstance -Activate $true
        [System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::ContextIdle)
        Write-TestLog "  -> Success. OpenTabs count: $($state.OpenTabs.Count)" "Green"
    } catch {
        Write-TestLog "  -> ERROR opening duplicate Users tab: $_" "Red"
        $recordedErrors.Add($_)
    }

    # STEP 3: Detach a tab to a separate window
    Write-TestLog "`n--- STEP 3: Detaching tab to separate window ---" "Cyan"
    $userTab = $state.OpenTabs | Where-Object { $_.PanelName -eq "Users" } | Select-Object -First 1
    if ($userTab) {
        try {
            Write-TestLog "Detaching tab $($userTab.Id) ($($userTab.PanelName))..."
            Detach-PanelToWindow -TabId $userTab.Id
            [System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Loaded)
            [System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::ContextIdle)
            Write-TestLog "  -> Detached successfully. Detached count: $($state.DetachedWindows.Count)" "Green"
        } catch {
            Write-TestLog "  -> ERROR detaching tab: $_" "Red"
            $recordedErrors.Add($_)
        }
    }

    # STEP 4: While tab is detached, switch tabs in MainWindow
    Write-TestLog "`n--- STEP 4: Switching tabs in MainWindow while detached ---" "Cyan"
    try {
        $otherTab = $state.OpenTabs | Where-Object { $_.Id -ne $userTab.Id -and -not $state.DetachedWindows.ContainsKey($_.Id) } | Select-Object -First 1
        if ($otherTab) {
            Write-TestLog "Switching to docked tab: $($otherTab.Id) ($($otherTab.PanelName))"
            Select-WorkspaceTab -TabId $otherTab.Id
            [System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::ContextIdle)
            Write-TestLog "  -> Switched successfully. ActiveTabId: $($state.ActiveTabId)" "Green"
        }
    } catch {
        Write-TestLog "  -> ERROR switching tabs: $_" "Red"
        $recordedErrors.Add($_)
    }

    # STEP 5: Dock detached tab back into MainWindow
    Write-TestLog "`n--- STEP 5: Docking detached tab back into MainWindow ---" "Cyan"
    if ($userTab) {
        try {
            Write-TestLog "Docking tab $($userTab.Id) back..."
            Dock-PanelToMainWindow -TabId $userTab.Id
            [System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Loaded)
            [System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::ContextIdle)
            Write-TestLog "  -> Docked back successfully. Detached count: $($state.DetachedWindows.Count)" "Green"
        } catch {
            Write-TestLog "  -> ERROR docking tab back: $_" "Red"
            $recordedErrors.Add($_)
        }
    }

    # STEP 6: Detach a secondary/duplicate tab
    Write-TestLog "`n--- STEP 6: Detaching second/duplicate tab ---" "Cyan"
    $userTab2 = $state.OpenTabs | Where-Object { $_.PanelName -eq "Users" } | Select-Object -Last 1
    if ($userTab2 -and $userTab2.Id -ne $userTab.Id) {
        try {
            Write-TestLog "Detaching second Users instance ($($userTab2.Id))..."
            Detach-PanelToWindow -TabId $userTab2.Id
            [System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Loaded)
            [System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::ContextIdle)
            Write-TestLog "  -> Detached secondary tab successfully. Detached count: $($state.DetachedWindows.Count)" "Green"
        } catch {
            Write-TestLog "  -> ERROR detaching secondary tab: $_" "Red"
            $recordedErrors.Add($_)
        }

        Write-TestLog "`n--- STEP 7: Docking secondary tab back ---" "Cyan"
        try {
            Write-TestLog "Docking second Users instance back..."
            Dock-PanelToMainWindow -TabId $userTab2.Id
            [System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Loaded)
            [System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::ContextIdle)
            Write-TestLog "  -> Docked back secondary tab successfully. Detached count: $($state.DetachedWindows.Count)" "Green"
        } catch {
            Write-TestLog "  -> ERROR docking back secondary tab: $_" "Red"
            $recordedErrors.Add($_)
        }
    }

    # STEP 8: Detach non-standard panel (e.g. DirectorySearch)
    Write-TestLog "`n--- STEP 8: Detaching DirectorySearch ---" "Cyan"
    $dsTab = $state.OpenTabs | Where-Object { $_.PanelName -eq "DirectorySearch" } | Select-Object -First 1
    if ($dsTab) {
        try {
            Write-TestLog "Detaching DirectorySearch ($($dsTab.Id))..."
            Detach-PanelToWindow -TabId $dsTab.Id
            [System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Loaded)
            [System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::ContextIdle)
            Write-TestLog "  -> Detached DirectorySearch successfully. Detached count: $($state.DetachedWindows.Count)" "Green"
        } catch {
            Write-TestLog "  -> ERROR detaching DirectorySearch: $_" "Red"
            $recordedErrors.Add($_)
        }

        Write-TestLog "`n--- STEP 9: Docking DirectorySearch back ---" "Cyan"
        try {
            Write-TestLog "Docking DirectorySearch back..."
            Dock-PanelToMainWindow -TabId $dsTab.Id
            [System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::Loaded)
            [System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::ContextIdle)
            Write-TestLog "  -> Docked DirectorySearch back successfully." "Green"
        } catch {
            Write-TestLog "  -> ERROR docking DirectorySearch back: $_" "Red"
            $recordedErrors.Add($_)
        }
    }

    # STEP 10: Close tabs
    Write-TestLog "`n--- STEP 10: Closing tabs ---" "Cyan"
    $tabsToClose = @($state.OpenTabs | Where-Object { $_.PanelName -ne "Dashboard" })
    foreach ($tc in $tabsToClose) {
        try {
            Write-TestLog "Closing tab: $($tc.Id)"
            Remove-WorkspaceTab -TabId $tc.Id
            [System.Windows.Threading.Dispatcher]::CurrentDispatcher.Invoke([Action]{}, [System.Windows.Threading.DispatcherPriority]::ContextIdle)
        } catch {
            Write-TestLog "  -> ERROR closing tab $($tc.Id): $_" "Red"
            $recordedErrors.Add($_)
        }
    }
    Write-TestLog "Remaining OpenTabs count: $($state.OpenTabs.Count)" "Yellow"

    # Close main window
    $window.Close()
    Write-TestLog "MainWindow closed." "Gray"

} catch {
    Write-TestLog "FATAL ERROR during test execution: $_" "Red"
    $recordedErrors.Add($_)
}

Write-TestLog "`n========================================================" "Cyan"
Write-TestLog "   TEST RUN SUMMARY" "Cyan"
Write-TestLog "========================================================" "Cyan"
Write-TestLog "Total Recorded Errors: $($recordedErrors.Count)" $(if ($recordedErrors.Count -eq 0) { "Green" } else { "Red" })

if ($recordedErrors.Count -gt 0) {
    foreach ($err in $recordedErrors) {
        Write-TestLog "ERROR: $err" "Red"
    }
}
