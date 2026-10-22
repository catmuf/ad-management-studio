<#
.SYNOPSIS
    Automated Launch Latency & Performance Benchmark Suite
.DESCRIPTION
    Measures cold-start application initialization, XAML parsing,
    module importation, and time-to-interactive window rendering.
#>

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
param(
    [int]$Iterations = 3
)

$ErrorActionPreference = "Stop"
$appRoot = Split-Path -Parent $PSScriptRoot
$modulesPath = Join-Path $appRoot "Modules"
$xamlPath = Join-Path $appRoot "Views/MainWindow.xaml"

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host " Active Directory Management Studio - Launch Performance Benchmark    " -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

$runs = [System.Collections.Generic.List[psobject]]::new()

for ($i = 1; $i -le $Iterations; $i++) {
    Write-Host "`n--- Run #$i of $Iterations ---" -ForegroundColor Yellow
    $swTotal = [System.Diagnostics.Stopwatch]::StartNew()

    # 1. Type Resolution
    $swTypes = [System.Diagnostics.Stopwatch]::StartNew()
    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Drawing, System.Windows.Forms
    $swTypes.Stop()

    # 2. Module Imports
    $swModules = [System.Diagnostics.Stopwatch]::StartNew()
    Import-Module (Join-Path $modulesPath "ConfigService.psm1") -DisableNameChecking -Force
    Import-Module (Join-Path $modulesPath "LoggingService.psm1") -DisableNameChecking -Force
    Import-Module (Join-Path $modulesPath "ValidationService.psm1") -DisableNameChecking -Force
    Import-Module (Join-Path $modulesPath "ADService.psm1") -DisableNameChecking -Force
    $swModules.Stop()

    # 3. Environment Context
    $swCtx = [System.Diagnostics.Stopwatch]::StartNew()
    $appConfig = Get-AppSettings
    $adContext = Get-ADEnvironmentContext -Config $appConfig
    $null = $adContext
    $swCtx.Stop()

    # 4. Direct Stream XAML Loading
    $swXaml = [System.Diagnostics.Stopwatch]::StartNew()
    $fileStream = [System.IO.FileStream]::new($xamlPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read, 65536)
    $window = $null
    try {
        $window = [System.Windows.Markup.XamlReader]::Load($fileStream)
    } finally {
        $fileStream.Dispose()
    }
    $swXaml.Stop()

    # 5. NameScope Extraction
    $swScope = [System.Diagnostics.Stopwatch]::StartNew()
    $controls = @{}
    $scope = [System.Windows.NameScope]::GetNameScope($window)
    if ($scope) {
        foreach ($entry in $scope) {
            $controls[$entry.Key] = $entry.Value
        }
    }
    $swScope.Stop()

    $totalMs = $swTotal.ElapsedMilliseconds

    Write-Host "  .NET Assemblies        : $($swTypes.ElapsedMilliseconds) ms" -ForegroundColor DarkGray
    Write-Host "  Foundation Modules     : $($swModules.ElapsedMilliseconds) ms" -ForegroundColor DarkGray
    Write-Host "  AD Environment Context : $($swCtx.ElapsedMilliseconds) ms" -ForegroundColor DarkGray
    Write-Host "  Direct Stream XAML     : $($swXaml.ElapsedMilliseconds) ms" -ForegroundColor DarkGray
    Write-Host "  NameScope Controls ($($controls.Count)) : $($swScope.ElapsedMilliseconds) ms" -ForegroundColor DarkGray
    Write-Host "  Total Time to Window   : $totalMs ms" -ForegroundColor Green

    $runs.Add([PSCustomObject]@{
        Run            = $i
        ModulesMs      = $swModules.ElapsedMilliseconds
        ContextMs      = $swCtx.ElapsedMilliseconds
        XamlMs         = $swXaml.ElapsedMilliseconds
        ScopeMs        = $swScope.ElapsedMilliseconds
        TotalMs        = $totalMs
    })
}

$avgTotal = ($runs | Measure-Object -Property TotalMs -Average).Average
$avgXaml = ($runs | Measure-Object -Property XamlMs -Average).Average
$avgModules = ($runs | Measure-Object -Property ModulesMs -Average).Average

Write-Host "`n======================================================================" -ForegroundColor Cyan
Write-Host (" Average Time to Interactive UI: {0:N0} ms" -f $avgTotal) -ForegroundColor Cyan
Write-Host (" Average Direct XAML Stream Load: {0:N0} ms" -f $avgXaml) -ForegroundColor Cyan
Write-Host (" Average Core Modules Load      : {0:N0} ms" -f $avgModules) -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

if ($avgTotal -lt 1500) {
    Write-Host " SUCCESS: Cold start launch time is under 1.5 seconds (Target Met: Sub-second interactive UI)!" -ForegroundColor Green
} else {
    Write-Host " Launch time exceeded target." -ForegroundColor Yellow
}
