<#
Install osquery (winget) and Sysmon (Microsoft Sysinternals) on Windows, then start them.

  Double-click install.cmd in the repo root, or from an admin PowerShell:
    .\windows\install.ps1                                   standalone (local log files)
    .\windows\install.ps1 -FleetUrl https://fleet.lan:8080 -EnrollSecret XXXX [-FleetCert fleet.pem]
    .\windows\install.ps1 -NoSysmon                         skip Sysmon

Fleet settings can also live in agent.env in the repo root (see agent.env.example).
#>
#Requires -RunAsAdministrator
param(
    [string]$FleetUrl = "",
    [string]$EnrollSecret = "",
    [string]$FleetCert = "",
    [switch]$Standalone,
    [switch]$NoSysmon,
    [switch]$Window            # set by install.cmd: close the window on success, wait on failure
)
$ErrorActionPreference = "Stop"
trap {
    Write-Host "error: $_" -ForegroundColor Red
    if ($Window) { Read-Host "Install failed. Press Enter to close" }
    break
}
$ProgressPreference = "SilentlyContinue"   # Invoke-WebRequest is very slow with the progress bar
$Repo = Split-Path -Parent $PSScriptRoot

function Say($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Warn($msg) { Write-Host "warning: $msg" -ForegroundColor Yellow }

# agent.env: KEY=value lines; command-line parameters win.
$envFile = Join-Path $Repo "agent.env"
if (Test-Path $envFile) {
    foreach ($line in Get-Content $envFile) {
        if ($line -match '^\s*([A-Z_]+)\s*=\s*"?([^"]*)"?\s*$') {
            switch ($Matches[1]) {
                "FLEET_URL"     { if (-not $FleetUrl)     { $FleetUrl = $Matches[2] } }
                "ENROLL_SECRET" { if (-not $EnrollSecret) { $EnrollSecret = $Matches[2] } }
                "FLEET_CERT"    { if (-not $FleetCert)    { $FleetCert = $Matches[2] } }
            }
        }
    }
}
if ($Standalone) { $FleetUrl = "" }
$Mode = if ($FleetUrl) { "fleet" } else { "standalone" }
if ($Mode -eq "fleet" -and -not $EnrollSecret) { throw "-FleetUrl needs -EnrollSecret (or ENROLL_SECRET in agent.env)" }
Say "Mode: $Mode"

# ---------------------------------------------------------------- osquery
if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
    throw "winget isn't available. Install 'App Installer' from the Microsoft Store, then run this again."
}
Say "Installing osquery with winget"
# No --scope: osquery's winget package is a single per-machine MSI that declares no scope, and asking for
# "--scope machine" filters it out ("No applicable installer found").
winget install --id osquery.osquery --exact --silent --accept-package-agreements --accept-source-agreements
# winget exits non-zero when the package is already installed and current; that's fine.

$Root = Join-Path $env:ProgramFiles "osquery"
$osqueryd = Get-ChildItem -Path $Root -Filter osqueryd.exe -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $osqueryd) { throw "osqueryd.exe not found under $Root after install" }

$flags = Join-Path $Root "osquery.flags"
$conf = Join-Path $Root "osquery.conf"
$db = Join-Path $Root "osquery.db"
$logs = Join-Path $Root "log"
New-Item -ItemType Directory -Force -Path $logs | Out-Null
# The results log holds Sysmon command lines, which can contain secrets: only SYSTEM, Administrators and the
# person who installed it (who reads it from WSL for tapwatch) may read it, not every local account.
$reader = (Get-CimInstance Win32_ComputerSystem).UserName
if (-not $reader) { $reader = "$env:USERDOMAIN\$env:USERNAME" }
icacls $logs /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" "${reader}:(OI)(CI)RX" /T /Q | Out-Null
Copy-Item (Join-Path $Repo "config\osquery.conf") $conf -Force

if ($Mode -eq "fleet") {
    $fleetHost = ($FleetUrl -replace '^https?://', '') -replace '/.*$', ''
    $secretPath = Join-Path $Root "enroll_secret"
    Set-Content -Path $secretPath -Value $EnrollSecret -NoNewline -Encoding ascii
    # Only SYSTEM and Administrators may read the secret.
    icacls $secretPath /inheritance:r /grant:r "SYSTEM:R" "Administrators:R" | Out-Null
    $certFlag = ""
    if ($FleetCert) {
        if (-not [System.IO.Path]::IsPathRooted($FleetCert)) { $FleetCert = Join-Path $Repo $FleetCert }
        if (-not (Test-Path $FleetCert)) { throw "Fleet certificate not found: $FleetCert" }
        Copy-Item $FleetCert (Join-Path $Root "fleet.pem") -Force
        $certFlag = "--tls_server_certs=" + (Join-Path $Root "fleet.pem")
    }
    $text = (Get-Content (Join-Path $Repo "config\fleet.flags") -Raw).
        Replace("@FLEET_HOST@", $fleetHost).Replace("@SECRET_PATH@", $secretPath).
        Replace("@CERT_FLAG@", $certFlag).Replace("@DB_PATH@", $db)
} else {
    $text = (Get-Content (Join-Path $Repo "config\standalone.flags") -Raw).
        Replace("@CONF_PATH@", $conf).Replace("@LOG_PATH@", $logs).Replace("@DB_PATH@", $db)
}
$text = $text.TrimEnd() + "`n" + (Get-Content (Join-Path $Repo "config\windows.flags") -Raw)   # Sysmon events
[System.IO.File]::WriteAllText($flags, ($text -replace "`r`n", "`n"))   # LF only, so no stray \r ends up in a flag value

Say "Starting the osqueryd service"
$svc = Get-Service -Name osqueryd -ErrorAction SilentlyContinue
if (-not $svc) {
    New-Service -Name osqueryd -DisplayName "osqueryd" -StartupType Automatic `
        -BinaryPathName "`"$($osqueryd.FullName)`" --flagfile=`"$flags`"" | Out-Null
} else {
    Set-Service -Name osqueryd -StartupType Automatic
}
Restart-Service -Name osqueryd -Force -ErrorAction SilentlyContinue
if ((Get-Service osqueryd).Status -ne "Running") { Start-Service osqueryd }

# ---------------------------------------------------------------- Sysmon
if (-not $NoSysmon) {
    Say "Installing Sysmon (records every process start and network connection, with the program behind it)"
    $tmp = Join-Path $env:TEMP ("sysmon-" + [guid]::NewGuid())
    New-Item -ItemType Directory -Path $tmp | Out-Null
    try {
        Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$tmp\Sysmon.zip" -UseBasicParsing
        Expand-Archive "$tmp\Sysmon.zip" -DestinationPath $tmp
        $exe = Join-Path $tmp $(if ([Environment]::Is64BitOperatingSystem) { "Sysmon64.exe" } else { "Sysmon.exe" })
        $sig = Get-AuthenticodeSignature $exe
        if ($sig.Status -ne "Valid" -or $sig.SignerCertificate.Subject -notmatch "O=Microsoft Corporation") {
            throw "Sysmon download failed its signature check ($($sig.Status)); not installing it"
        }
        $config = Join-Path $PSScriptRoot "sysmon.xml"
        $svcName = [System.IO.Path]::GetFileNameWithoutExtension($exe)
        if (Get-Service -Name $svcName -ErrorAction SilentlyContinue) {
            & $exe -c $config | Out-Null      # already installed: just load our config
        } else {
            & $exe -accepteula -i $config | Out-Null
        }
        if ($LASTEXITCODE -ne 0) { throw "Sysmon exited with code $LASTEXITCODE" }
        # Default log is 64 MB, a few days of history at most; give it 256 MB.
        wevtutil sl Microsoft-Windows-Sysmon/Operational /ms:268435456
    } finally {
        Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
    }
}

Write-Host ""
$version = (& $osqueryd.FullName --version) -replace '.* ', ''
Say "Done. osquery $version, service: $((Get-Service osqueryd).Status)"
if ($Mode -eq "fleet") {
    Write-Host "    The host should appear in Fleet (Hosts) within a minute."
} else {
    Write-Host "    Scheduled results: $logs\osqueryd.results.log"
    Write-Host "    Ask it anything:   & `"$Root\osqueryi.exe`" `"SELECT name, port FROM listening_ports JOIN processes USING (pid);`""
}
if (-not $NoSysmon) {
    Write-Host "    Sysmon network history (osqueryi): SELECT datetime, data FROM windows_eventlog"
    Write-Host "      WHERE channel = 'Microsoft-Windows-Sysmon/Operational' AND eventid = 3 LIMIT 20;"
}
if ($Window) {
    Write-Host ""
    Write-Host "This window closes in 15 seconds."
    Start-Sleep -Seconds 15
}
