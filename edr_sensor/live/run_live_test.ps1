<#
  run_live_test.ps1 -- check the sensor end-to-end against REAL Sysmon events.
  Prerequisite: install_windows.ps1 (installs Sysmon + edr_sensor).
  Run from an ELEVATED PowerShell:
      powershell -ExecutionPolicy Bypass -File edr_sensor\live\run_live_test.ps1

  The test only launches harmless commands and never kills anything.
  Saved results (next to this script):
      live_run.log           full transcript of this run
      live_test_result.txt   the test report
#>
param(
    [string]$Python = (Get-Command python -ErrorAction SilentlyContinue).Source
)
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { throw "Run this from an elevated (Administrator) PowerShell." }
if (-not $Python) { throw "Python not found on PATH (or pass -Python <path>)." }
if (-not (Get-Service Sysmon64 -ErrorAction SilentlyContinue)) {
    throw "Sysmon is not installed -- run install_windows.ps1 first."
}

Start-Transcript -Path (Join-Path $here "live_run.log") -Force | Out-Null
try {
    Get-Service Sysmon64 | Format-Table Name, Status -AutoSize
    & $Python (Join-Path $here "live_test.py")
    Write-Host "live_test.py exit code: $LASTEXITCODE"
}
finally {
    Stop-Transcript | Out-Null
}
