<#
  install_windows.ps1 -- set up the Telltale agent on a real Windows 10/11 x64 machine.

  Run from an ELEVATED PowerShell in the repository folder:
      powershell -ExecutionPolicy Bypass -File .\install_windows.ps1
  Options:
      -Mode enforce        kill threats instead of only alerting (default: alert)
      -NoTask              don't register the auto-start task (run agent.py yourself)
      -ApplySysmonConfig   apply this project's Sysmon config to an EXISTING Sysmon install
      -Uninstall           remove the auto-start task (add -RemoveSysmon to uninstall Sysmon too)

  What it does:
      1. pip install -r requirements.txt
      2. builds + installs the Rust Sysmon sensor (edr_sensor) if Rust is available
      3. installs Sysmon (downloaded from Microsoft Sysinternals, signature verified)
         with edr_sensor\live\sysmon_edr.xml -- this accepts the Sysmon EULA
      4. registers scheduled task "Telltale-Agent": starts agent.py as SYSTEM at boot,
         restarts it if it crashes
  Logs: agent.log in this folder.
#>
param(
    [ValidateSet("alert", "enforce")] [string]$Mode = "alert",
    [switch]$NoTask,
    [switch]$ApplySysmonConfig,
    [switch]$Uninstall,
    [switch]$RemoveSysmon
)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$TaskName = "Telltale-Agent"
$SysmonCfg = Join-Path $Root "edr_sensor\live\sysmon_edr.xml"
$ToolsDir = Join-Path $Root "tools\sysmon"

function Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { throw "Run this from an elevated (Administrator) PowerShell." }

function Get-SysmonExe {
    $exe = Join-Path $ToolsDir "Sysmon64.exe"
    if (-not (Test-Path $exe)) {
        New-Item -ItemType Directory -Force -Path $ToolsDir | Out-Null
        $zip = Join-Path $ToolsDir "Sysmon.zip"
        Write-Host "Downloading Sysmon from https://download.sysinternals.com/files/Sysmon.zip"
        Invoke-WebRequest -UseBasicParsing -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile $zip
        Expand-Archive -Path $zip -DestinationPath $ToolsDir -Force
    }
    $sig = Get-AuthenticodeSignature $exe
    if ($sig.Status -ne "Valid" -or $sig.SignerCertificate.Subject -notmatch "O=Microsoft Corporation") {
        throw "Sysmon64.exe signature check failed: $($sig.Status) $($sig.SignerCertificate.Subject)"
    }
    return $exe
}

# ─────────────────────────── uninstall ───────────────────────────
if ($Uninstall) {
    Step "Removing scheduled task $TaskName"
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "Task removed."
    } else { Write-Host "Task not found." }
    if ($RemoveSysmon) {
        Step "Uninstalling Sysmon"
        & (Get-SysmonExe) -u
    }
    return
}

# ─────────────────────────── 1. Python deps ───────────────────────────
Step "Checking Python"
$py = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $py) { throw "Python 3.10+ not found on PATH. Install it from python.org (tick 'Add to PATH')." }
$ver = & $py -c "import sys; print('%d.%d' % sys.version_info[:2])"
if ([version]$ver -lt [version]"3.10") { throw "Python $ver found; 3.10+ required." }
Write-Host "Python $ver at $py"

Step "Installing Python requirements"
& $py -m pip install --disable-pip-version-check -r (Join-Path $Root "requirements.txt")
if ($LASTEXITCODE -ne 0) { throw "pip install failed" }

# ─────────────────────────── 2. Rust sensor ───────────────────────────
Step "Installing the Sysmon feature sensor (edr_sensor)"
$hasSensor = (& $py -c "import importlib.util; print(importlib.util.find_spec('edr_sensor') is not None)") -eq "True"
if ($hasSensor) {
    Write-Host "edr_sensor already installed."
} elseif (Get-Command cargo -ErrorAction SilentlyContinue) {
    & $py -m pip install --disable-pip-version-check "maturin>=1.5,<2"
    $dist = Join-Path $Root "edr_sensor\dist"
    & $py -m maturin build --release -m (Join-Path $Root "edr_sensor\Cargo.toml") -o $dist
    if ($LASTEXITCODE -ne 0) { throw "edr_sensor build failed" }
    $whl = Get-ChildItem $dist -Filter "edr_sensor-*.whl" | Sort-Object LastWriteTime | Select-Object -Last 1
    & $py -m pip install --force-reinstall --disable-pip-version-check $whl.FullName
} else {
    Write-Warning ("Rust (cargo) not found -- edr_sensor not built. The agent will run on SIMULATED " +
                   "features (no real detection). Install Rust from https://rustup.rs and re-run.")
}

# ─────────────────────────── 3. Sysmon ───────────────────────────
Step "Sysmon"
if (Get-Service Sysmon64 -ErrorAction SilentlyContinue) {
    if ($ApplySysmonConfig) {
        & (Get-SysmonExe) -c $SysmonCfg
        Write-Host "Applied $SysmonCfg to the existing Sysmon."
    } else {
        Write-Host "Sysmon is already installed -- keeping your config. It must log EventIDs 1, 3, 11, 12-14, 22"
        Write-Host "(re-run with -ApplySysmonConfig to use this project's config)."
    }
} else {
    $exe = Get-SysmonExe
    & $exe -accepteula -i $SysmonCfg
    if ($LASTEXITCODE -ne 0) { throw "Sysmon install failed (exit $LASTEXITCODE)" }
}
Get-Service Sysmon64 | Format-Table Name, Status -AutoSize

# ─────────────────────────── 4. auto-start task ───────────────────────────
if ($NoTask) {
    Step "Done. Start the agent yourself:  python agent.py --mode $Mode   (elevated)"
    return
}
Step "Registering scheduled task $TaskName (SYSTEM, at startup, mode=$Mode)"
$action = New-ScheduledTaskAction -Execute $py -Argument "`"$(Join-Path $Root 'agent.py')`" --mode $Mode" -WorkingDirectory $Root
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal `
    -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName
Start-Sleep -Seconds 3
Get-ScheduledTask -TaskName $TaskName | Format-Table TaskName, State -AutoSize

Write-Host ""
Write-Host "Installed. Mode: $Mode $(if ($Mode -eq 'alert') { '(threats are logged, not killed)' } else { '(threats are KILLED)' })"
Write-Host "Watch alerts:  Get-Content `"$(Join-Path $Root 'agent.log')`" -Wait -Tail 20"
Write-Host "Remove:        powershell -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`" -Uninstall"
