<#
Install osquery and Sysmon (Microsoft Sysinternals) on Windows, then start them.

  Double-click install.cmd in the repo root, or from an admin PowerShell:
    .\windows\install.ps1                                   standalone (local log files)
    .\windows\install.ps1 -FleetUrl https://fleet.lan:8080 -EnrollSecret XXXX [-FleetCert fleet.pem]
    .\windows\install.ps1 -NoSysmon                         skip Sysmon

  From a deployment tool (Intune, an RMM, PDQ, a GPO startup script), as SYSTEM, no prompts: install-silent.cmd,
  or  powershell -NoProfile -ExecutionPolicy Bypass -File windows\install.ps1 -Silent
  -Silent installs osquery from its pinned official MSI (winget is usually missing for SYSTEM), writes everything to
  %ProgramData%\tapwatch\agent-install.log, and exits 0 when the agent runs, 1 when it doesn't. Running it again
  is safe; it is also how to update.

Fleet settings can also live in agent.env in the repo root (see agent.env.example).
#>
#Requires -RunAsAdministrator
param(
    [string]$FleetUrl = "",
    [string]$EnrollSecret = "",
    [string]$FleetCert = "",
    [switch]$Standalone,
    [switch]$NoSysmon,
    [switch]$Window,           # set by install.cmd: close the window on success, wait on failure
    [switch]$Silent            # a deployment tool: no prompts, a log file, exit code 0/1
)
$ErrorActionPreference = "Stop"
trap {
    Write-Host "error: $_" -ForegroundColor Red
    if ($Silent) { Write-Host "exit code 1"; Stop-Transcript -ErrorAction SilentlyContinue | Out-Null; exit 1 }
    if ($Window) { Read-Host "Install failed. Press Enter to close" }
    break
}
$ProgressPreference = "SilentlyContinue"   # Invoke-WebRequest is very slow with the progress bar
# Windows PowerShell 5.1 can default to TLS 1.0 on an older build; GitHub and Sysinternals need 1.2.
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
# A folder only SYSTEM and Administrators can open, for the downloads this script runs as SYSTEM (osquery's MSI,
# Sysmon) and for the install log. Windows\Temp, SYSTEM's TEMP, lets any user create a file there first and swap
# its contents between the hash check and msiexec. The log can carry -EnrollSecret if a tool passed it on the
# command line.
$Work = Join-Path $env:ProgramData "tapwatch"
New-Item -ItemType Directory -Force -Path $Work | Out-Null
icacls $Work /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null
if ($Silent) { Start-Transcript -Path (Join-Path $Work "agent-install.log") -Append | Out-Null }
# The 64-bit Program Files even from a 32-bit PowerShell (Intune's Win32 apps and some RMMs start one), where
# $env:ProgramFiles is "Program Files (x86)" and the x64 MSI's osquery would not be found.
$ProgramFiles64 = if ($env:ProgramW6432) { $env:ProgramW6432 } else { $env:ProgramFiles }
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
                "PROXY"         { $Proxy = $Matches[2] }
            }
        }
    }
}
if ($Standalone) { $FleetUrl = "" }
if ($Silent -and -not $FleetUrl -and -not $Standalone) {
    # A deployment that lost agent.env would otherwise install standalone, report success, and never reach Fleet.
    throw "no Fleet address: agent.env is missing next to install-silent.cmd (or pass -Standalone on purpose)"
}
if ($Proxy) {
    # PROXY=host:port in agent.env, for an office that only reaches the internet through a proxy: the downloads
    # here, and osquery's own connection to Fleet (its --proxy_hostname flag below).
    $PSDefaultParameterValues["Invoke-WebRequest:Proxy"] = "http://$Proxy"
}
$Mode = if ($FleetUrl) { "fleet" } else { "standalone" }
if ($Mode -eq "fleet" -and -not $EnrollSecret) { throw "-FleetUrl needs -EnrollSecret (or ENROLL_SECRET in agent.env)" }
Say "Mode: $Mode"

# ---------------------------------------------------------------- osquery
# The official MSI from osquery's GitHub release, pinned by the SHA-256 the release publishes (the MSI itself is not
# code-signed): what -Silent installs, and the fallback when winget is missing. x64 only; ARM64 Windows runs it
# under emulation. Bump the version and hash together.
$OsqueryMsi = @{ Version = "5.24.0"; Sha256 = "5f123c07936ee927d7b44ccdaf5d01c4b9bab2956328a4d8c7adc3395812a659"
                 Url = "https://github.com/osquery/osquery/releases/download/5.24.0/osquery-5.24.0.msi" }
$installed = Get-ChildItem -Path (Join-Path $ProgramFiles64 "osquery") -Filter osqueryd.exe -Recurse -ErrorAction SilentlyContinue |
    Select-Object -First 1
$have = $null   # osqueryd.exe's version, when it parses
$useWinget = -not $Silent -and (Get-Command winget -ErrorAction SilentlyContinue)
if ($useWinget) {
    Say "Installing osquery with winget"
    # No --scope: osquery's winget package is a single per-machine MSI that declares no scope, and asking for
    # "--scope machine" filters it out ("No applicable installer found").
    winget install --id osquery.osquery --exact --silent --accept-package-agreements --accept-source-agreements
    # winget exits non-zero when the package is already installed and current; that's fine.
} elseif ($installed -and [version]::TryParse((("$($installed.VersionInfo.ProductVersion)" -split '[^0-9.]')[0]), [ref]$have) -and
          $have -ge [version]$OsqueryMsi.Version) {
    # The same or newer (winget, or an earlier run): msiexec would refuse a downgrade anyway.
    Say "osquery $($installed.VersionInfo.ProductVersion) is installed"
} else {
    Say "Installing osquery $($OsqueryMsi.Version) from its official MSI"
    $msi = Join-Path $Work ("osquery-" + [guid]::NewGuid() + ".msi")
    Invoke-WebRequest -Uri $OsqueryMsi.Url -OutFile $msi -UseBasicParsing
    $got = (Get-FileHash -Algorithm SHA256 $msi).Hash.ToLower()
    if ($got -ne $OsqueryMsi.Sha256) {
        Remove-Item -Force $msi
        throw "the osquery download doesn't match the pinned SHA-256 ($got); not installing it"
    }
    $msiLog = Join-Path $Work "osquery-msi.log"
    # 1618: another installation is running (Windows Update, or the deployment tool's next package): wait for it, up
    # to 10 minutes, then hand 1618 back, which Intune's default return codes treat as "retry".
    for ($try = 1; ; $try++) {
        $p = Start-Process msiexec.exe -ArgumentList @("/i", "`"$msi`"", "/qn", "/norestart", "/l*v", "`"$msiLog`"") -Wait -PassThru
        if ($p.ExitCode -ne 1618 -or $try -ge 20) { break }
        Say "another installation is running; trying again in 30 s"
        Start-Sleep -Seconds 30
    }
    Remove-Item -Force $msi -ErrorAction SilentlyContinue
    if ($p.ExitCode -eq 1618 -and $Silent) {
        Write-Host "error: another installation kept running for 10 minutes; the deployment tool can retry"
        Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
        exit 1618
    }
    if ($p.ExitCode -notin @(0, 3010)) { throw "the osquery MSI failed (msiexec exit $($p.ExitCode)); see $msiLog" }   # 3010: reboot later
}

$Root = Join-Path $ProgramFiles64 "osquery"
$osqueryd = Get-ChildItem -Path $Root -Filter osqueryd.exe -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $osqueryd) { throw "osqueryd.exe not found under $Root after install" }

$flags = Join-Path $Root "osquery.flags"
$conf = Join-Path $Root "osquery.conf"
$db = Join-Path $Root "osquery.db"
$logs = Join-Path $Root "log"
New-Item -ItemType Directory -Force -Path $logs | Out-Null
# osquery's MSI starts its service on a fresh install, and the running osqueryd holds osquery.conf open: Copy-Item
# then fails ("being used by another process"). Stopped here, started again below with the new flags.
Stop-Service -Name osqueryd -Force -ErrorAction SilentlyContinue
Copy-Item (Join-Path $Repo "config\osquery.conf") $conf -Force

if ($Mode -eq "fleet") {
    $fleetHost = ($FleetUrl -replace '^https?://', '') -replace '/.*$', ''
    $secretPath = Join-Path $Root "enroll_secret"
    # A run before this one left the file readable only (below), Administrators included, so it can't be rewritten
    # ("Access to the path ... enroll_secret is denied"). Its owner is Administrators (this installer runs elevated), and
    # an owner may always change the permissions: give write back. If another account owns it, take ownership first.
    if (Test-Path $secretPath) {
        icacls $secretPath /grant:r "*S-1-5-32-544:F" | Out-Null
        if ($LASTEXITCODE -ne 0) {
            takeown /f $secretPath /a | Out-Null
            icacls $secretPath /grant:r "*S-1-5-32-544:F" | Out-Null
        }
    }
    Set-Content -Path $secretPath -Value $EnrollSecret -NoNewline -Encoding ascii
    # Only SYSTEM and Administrators may read the secret.
    # By SID (SYSTEM, Administrators): the group names are translated on a non-English Windows and icacls would fail.
    icacls $secretPath /inheritance:r /grant:r "*S-1-5-18:R" "*S-1-5-32-544:R" | Out-Null
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
if ($Proxy) { $text = $text.TrimEnd() + "`n--proxy_hostname=$Proxy`n" }
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
# Where Sysmon comes from, in this order:
#   1. one already installed (Sysmon, Sysmon64, Sysmon64a): our config is loaded into it.
#   2. Windows' own: Windows 11 26H2 ships Sysmon as an optional feature, and on those builds Windows has already
#      registered Sysmon's event log, so the Sysinternals download fails with exit 13 ("Event manifest installation
#      failed"). Seen on two 26H2 PCs. Turning the feature on needs no restart and puts sysmon.exe in System32; it
#      writes to the same Microsoft-Windows-Sysmon/Operational channel osquery reads.
#   3. the Sysinternals download, signature-checked, on older Windows.
function Invoke-Sysmon($exe, [string[]]$arguments) {
    # Sysmon prints its banner on stderr. With ErrorActionPreference Stop, Windows PowerShell 5.1 turns every stderr
    # line of a native command captured with 2>&1 into a terminating RemoteException before Sysmon has finished:
    # relax it for this call and judge by the exit code.
    $oldEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try { $out = & $exe @arguments 2>&1 } finally { $ErrorActionPreference = $oldEap }
    if ($LASTEXITCODE -ne 0) {
        # Sysmon's own words, without its banner (its output is UTF-16: drop the NULs a 5.1 capture leaves in).
        $why = ($out | ForEach-Object { ("$_" -replace "`0", "").Trim() } |
            Where-Object { $_ -and $_ -notmatch '^(System Monitor|By Mark|Copyright|Using libxml2|Sysinternals|System\.Management\.Automation\.RemoteException)' }) -join " / "
        throw "Sysmon exited with code $LASTEXITCODE ($exe): $why"
    }
}
if (-not $NoSysmon) {
    $config = Join-Path $PSScriptRoot "sysmon.xml"
    $existing = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -in @("Sysmon", "Sysmon64", "Sysmon64a") } | Select-Object -First 1
    $inbox = Get-WindowsOptionalFeature -Online -FeatureName Sysmon -ErrorAction SilentlyContinue
    if ($existing) {
        Say "Sysmon is installed ($($existing.Name)): loading tapwatch's config into it"
        Invoke-Sysmon ($existing.PathName.Trim('"')) @("-accepteula", "-c", $config)   # SYSTEM may never have accepted the EULA
    } elseif ($inbox) {
        Say "Turning on Windows' built-in Sysmon (records every process start and network connection)"
        if ($inbox.State -ne "Enabled") { Enable-WindowsOptionalFeature -Online -FeatureName Sysmon -All -NoRestart | Out-Null }
        $exe = Join-Path $env:windir "System32\sysmon.exe"
        if (-not (Test-Path $exe)) { throw "Windows' Sysmon feature is on but $exe isn't there" }
        Invoke-Sysmon $exe @("-accepteula", "-i", $config)
    } else {
        Say "Installing Sysmon (records every process start and network connection, with the program behind it)"
        $tmp = Join-Path $Work ("sysmon-" + [guid]::NewGuid())
        New-Item -ItemType Directory -Path $tmp | Out-Null
        try {
            Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$tmp\Sysmon.zip" -UseBasicParsing
            Expand-Archive "$tmp\Sysmon.zip" -DestinationPath $tmp
            # ARM laptops (Snapdragon) need Sysmon64a.exe: the x64 build can't load its driver there and exits with an
            # error. From the CPU itself (Win32_Processor.Architecture 12 = ARM64): an x64-emulated PowerShell reports AMD64.
            $arch = if ((Get-CimInstance Win32_Processor | Select-Object -First 1).Architecture -eq 12) { "ARM64" } else { "x64" }
            $exe = Join-Path $tmp $(if ($arch -eq "ARM64") { "Sysmon64a.exe" } elseif ([Environment]::Is64BitOperatingSystem) { "Sysmon64.exe" } else { "Sysmon.exe" })
            $sig = Get-AuthenticodeSignature $exe
            if ($sig.Status -ne "Valid" -or $sig.SignerCertificate.Subject -notmatch "O=Microsoft Corporation") {
                throw "Sysmon download failed its signature check ($($sig.Status)); not installing it"
            }
            Invoke-Sysmon $exe @("-accepteula", "-i", $config)
        } finally {
            Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
        }
    }
    # Default log is 64 MB, a few days of history at most; give it 256 MB.
    wevtutil sl Microsoft-Windows-Sysmon/Operational /ms:268435456
    # A Sysmon that "installed" but isn't running records nothing: fail rather than report success.
    $running = Get-Service -Name "Sysmon", "Sysmon64", "Sysmon64a" -ErrorAction SilentlyContinue | Where-Object Status -eq "Running"
    if (-not $running) { throw "Sysmon installed but its service isn't running" }
    # osqueryd was started above, before Sysmon's event channel existed on a fresh PC, and it subscribes to the channel
    # only when it starts: until a restart it receives no Sysmon events at all (the first laptop enrolled: Sysmon
    # logging hundreds of events, osquery's windows_events publisher at 0).
    Restart-Service -Name osqueryd -Force
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
    Write-Host "    Sysmon: program starts, connections and DNS lookups reach osquery as 'sysmon_events' each minute"
    Write-Host "      (command lines only as yes/no signals). Rows appear within about two minutes:"
    if ($Mode -eq "fleet") {
        Write-Host "      in Fleet, the host's sysmon_events query results."
    } else {
        Write-Host "      Select-String -Path `"$logs\osqueryd.results.log`" -Pattern sysmon_events | Select-Object -Last 3"
    }
}
if ($Window) {
    Write-Host ""
    Write-Host "This window closes in 15 seconds."
    Start-Sleep -Seconds 15
}
if ($Silent) {
    $code = if ((Get-Service osqueryd).Status -eq "Running") { 0 } else { 1 }
    Write-Host "exit code $code"   # in the log too, so a tool's report can be checked against it
    Stop-Transcript | Out-Null
    exit $code
}
