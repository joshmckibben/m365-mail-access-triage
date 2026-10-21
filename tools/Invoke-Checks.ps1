#Requires -Version 7.2
<#
.SYNOPSIS
    Runs PSScriptAnalyzer and the Pester suite. Exits non-zero on any failure.
    Set TRIAGE_TEST_SHELL=powershell.exe to run the script under Windows PowerShell 5.1.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repo = if ($PSScriptRoot) { Split-Path $PSScriptRoot -Parent } else { (Get-Location).Path }

foreach ($module in @{ Name = 'Pester'; Min = '5.5.0' }, @{ Name = 'PSScriptAnalyzer'; Min = '1.21.0' }) {
    if (-not (Get-Module -ListAvailable $module.Name | Where-Object Version -ge $module.Min)) {
        Write-Host "Installing $($module.Name)..." -ForegroundColor Yellow
        Install-Module $module.Name -MinimumVersion $module.Min -Scope CurrentUser -Force -SkipPublisherCheck
    }
}

Write-Host "`n== PSScriptAnalyzer ==" -ForegroundColor Cyan
$issues = Invoke-ScriptAnalyzer -Path (Join-Path $repo 'Invoke-MailAccessTriage.ps1') -Settings (Join-Path $repo 'PSScriptAnalyzerSettings.psd1')
if ($issues) { $issues | Format-Table RuleName, Severity, Line, Message -AutoSize -Wrap } else { Write-Host 'No issues.' -ForegroundColor Green }

Write-Host "`n== Pester ==" -ForegroundColor Cyan
$config = New-PesterConfiguration
$config.Run.Path = Join-Path $repo 'tests'
$config.Run.PassThru = $true
$config.Output.Verbosity = 'Detailed'
$result = Invoke-Pester -Configuration $config

if ($issues -or $result.FailedCount -gt 0) { exit 1 }
