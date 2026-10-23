<#
.SYNOPSIS
    Publishes or synchronizes all release markdown documents to GitHub Releases.
.DESCRIPTION
    Iterates through all 12 release markdown files in docs/releases/ (v0.1.0 to v3.4.0)
    and publishes them to the GitHub Releases API (https://api.github.com/repos/catmuf/ad-management-studio/releases).
    If a GitHub Token ($env:GITHUB_TOKEN or -Token) is provided, it calls the REST API directly.
    Otherwise, it outputs one-click release links and instructions for web publishing.
.EXAMPLE
    pwsh -NoProfile -File tools/Publish-AllGitHubReleases.ps1
    pwsh -NoProfile -File tools/Publish-AllGitHubReleases.ps1 -Token "ghp_..."
#>

[CmdletBinding()]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
param(
    [string]$Token = $env:GITHUB_TOKEN,
    [string]$Owner = "catmuf",
    [string]$Repo  = "ad-management-studio"
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $scriptDir
$releaseDir = Join-Path $projectRoot "docs\releases"

$versions = @("v0.1.0", "v1.0.0", "v2.0.0", "v2.1.0", "v2.2.0", "v2.3.0", "v2.4.0", "v3.0.0", "v3.1.0", "v3.2.0", "v3.3.0", "v3.4.0")

Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "   Active Directory Management Studio - GitHub Releases Sync      " -ForegroundColor Cyan
Write-Host "   Repository: $Owner/$Repo                                       " -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan

if ([string]::IsNullOrWhiteSpace($Token)) {
    Write-Host "`n[NOTE] No GITHUB_TOKEN detected in environment." -ForegroundColor Yellow
    Write-Host "All $($versions.Count) releases prepared!" -ForegroundColor Green
    Write-Host "You can publish or edit any release directly in your browser using these links:`\n"

    foreach ($v in $versions) {
        $mdPath = Join-Path $releaseDir "$v.md"
        $createUrl = "https://github.com/$Owner/$Repo/releases/new?tag=$v"
        Write-Host "  * Release $v ($([System.IO.Path]::GetFileName($mdPath))):" -ForegroundColor White
        Write-Host "    Web URL: $createUrl" -ForegroundColor Gray
    }

    Write-Host "`nTo publish automatically via API, re-run with:" -ForegroundColor Cyan
    Write-Host "  `$env:GITHUB_TOKEN = '<your_personal_access_token>'" -ForegroundColor Gray
    Write-Host "  .\tools\Publish-AllGitHubReleases.ps1`n" -ForegroundColor Gray
    return
}

$headers = @{
    "Authorization" = "token $Token"
    "Accept"        = "application/vnd.github.v3+json"
    "User-Agent"    = "ADManagementStudio-ReleaseSync"
}

# Fetch existing releases from repository
$existingReleases = @()
try {
    $existingReleases = Invoke-RestMethod -Uri "https://api.github.com/repos/$Owner/$Repo/releases" -Headers $headers -Method Get
} catch {
    Write-Warning "Failed to query existing releases: $_"
}

foreach ($v in $versions) {
    $mdPath = Join-Path $releaseDir "$v.md"
    if (-not (Test-Path $mdPath)) {
        Write-Warning "Skipping $v - File not found: $mdPath"
        continue
    }

    $body = [System.IO.File]::ReadAllText((Resolve-Path $mdPath), [System.Text.Encoding]::UTF8)
    $title = "Active Directory Management Studio $v (Enterprise Edition)"

    $matchedRelease = $existingReleases | Where-Object { $_.tag_name -eq $v }

    if ($matchedRelease) {
        Write-Host "[UPDATING] Release $v (ID: $($matchedRelease.id))..." -ForegroundColor Cyan
        $payload = @{
            tag_name   = $v
            name       = $title
            body       = $body
            draft      = $false
            prerelease = ($v -eq "v0.1.0")
        } | ConvertTo-Json -Depth 5

        try {
            $res = Invoke-RestMethod -Uri "https://api.github.com/repos/$Owner/$Repo/releases/$($matchedRelease.id)" -Headers $headers -Method Patch -Body $payload -ContentType "application/json; charset=utf-8"
            Write-Host "  -> [SUCCESS] Updated $v ($($res.html_url))" -ForegroundColor Green
        } catch {
            Write-Error "Failed to update release $($v): $_"
        }
    } else {
        Write-Host "[CREATING] Release $v..." -ForegroundColor Cyan
        $payload = @{
            tag_name   = $v
            name       = $title
            body       = $body
            draft      = $false
            prerelease = ($v -eq "v0.1.0")
        } | ConvertTo-Json -Depth 5

        try {
            $res = Invoke-RestMethod -Uri "https://api.github.com/repos/$Owner/$Repo/releases" -Headers $headers -Method Post -Body $payload -ContentType "application/json; charset=utf-8"
            Write-Host "  -> [SUCCESS] Created $v ($($res.html_url))" -ForegroundColor Green
        } catch {
            Write-Error "Failed to create release $($v): $_"
        }
    }
}

Write-Host "`nAll releases synchronized successfully!" -ForegroundColor Green
