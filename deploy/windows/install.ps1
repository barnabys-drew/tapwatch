<#
tapwatch for a Windows PC, in one go. Double-click install-windows.cmd in the folder you unzipped;
it asks for admin rights once and runs this.

What it does, each step skipped when it's already done, so running it again is safe (and is how to update):
  1. Checks this PC can run it (Windows version, virtualization, winget, disk space).
  2. Asks the everyday questions (Linux account name, which network port, where alerts go, router logs).
  3. Turns on the Windows features WSL needs, restarts, and carries on by itself after you sign in.
  4. Installs Ubuntu without its first-run prompts, with mirrored networking and systemd, then asks the
     secret questions (Linux password, webhook, optional AI keys) once, right before they're needed.
  5. Installs Wireshark (for dumpcap) and Npcap (downloaded from npcap.com, signature checked; its
     installer is the one window you click through).
  6. Inside Ubuntu (deploy/windows/wsl-setup.sh): git, Python, Docker, tapwatch, settings, lists, services.
  7. Keeps the PC awake and tapwatch running after restarts; the osquery + Sysmon agent; the router's firewall rules.
  8. Ends with `tapwatch doctor --send`: what works, what's left, and a test alert.

Everything it prints, the Linux steps included, goes to %LOCALAPPDATA%\tapwatch\install.log, the file to send
for help. Secrets (the password, webhook, keys, the ntfy address) are typed hidden or shown only after the log
closes, reach Ubuntu in environment variables, and are never written to the log or to disk.
#>
#Requires -RunAsAdministrator
param([switch]$Resume)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"         # Invoke-WebRequest is very slow with the progress bar
$env:WSL_UTF8 = "1"                               # wsl.exe prints UTF-16 otherwise, which PowerShell 5 garbles
[Console]::OutputEncoding = [Text.Encoding]::UTF8 # Linux output (wslpath of a non-ASCII user folder) is UTF-8

$Distro = "Ubuntu"
$RepoUrl = "https://github.com/barnabys-drew/tapwatch"
$Here = Split-Path -Parent $PSScriptRoot | Split-Path -Parent          # the unzipped repo
# GitHub names a branch's ZIP folder tapwatch-<branch>; inside Ubuntu, tapwatch is downloaded from that same branch.
$Branch = if ((Split-Path -Leaf $Here) -match '^tapwatch-(.+)$') { $Matches[1] } else { "main" }
# QuickEdit off for this window: a click in a console window otherwise freezes the program ("Select" in the title)
# until Esc, which looks exactly like a hung installer.
try {
    Add-Type -Name ConsoleMode -Namespace TapWatch -MemberDefinition @'
[DllImport("kernel32.dll")] public static extern IntPtr GetStdHandle(int h);
[DllImport("kernel32.dll")] public static extern bool GetConsoleMode(IntPtr h, out uint m);
[DllImport("kernel32.dll")] public static extern bool SetConsoleMode(IntPtr h, uint m);
'@
    $stdin = [TapWatch.ConsoleMode]::GetStdHandle(-10)
    $mode = [uint32]0
    if ([TapWatch.ConsoleMode]::GetConsoleMode($stdin, [ref]$mode)) {
        [void][TapWatch.ConsoleMode]::SetConsoleMode($stdin, ($mode -band (-bnot [uint32]0x40)) -bor 0x80)   # QUICK_EDIT off, EXTENDED_FLAGS on
    }
} catch { }
$StateDir = Join-Path $env:LOCALAPPDATA "tapwatch"
$Answers = Join-Path $StateDir "installer-answers.json"                # the everyday answers, kept over the restart
$ResumeTask = "tapwatch installer (continues after restart)"
New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
Start-Transcript -Path (Join-Path $StateDir "install.log") -Append | Out-Null

function Say($msg) { Write-Host ""; Write-Host "==> $msg" -ForegroundColor Cyan }
function Note($msg) { Write-Host "    $msg" }
function Warn($msg) { Write-Host "    ! $msg" -ForegroundColor Yellow }
function Stop-Install($msg) {
    Write-Host ""
    Write-Host "Stopped: $msg" -ForegroundColor Red
    Write-Host "If you need help, send this file: $(Join-Path $StateDir 'install.log')"
    Stop-Transcript | Out-Null
    Read-Host "Press Enter to close"
    exit 1
}
trap { Stop-Install "$_" }

function Ask($question, $default) {
    $hint = if ($default) { " [$default]" } else { "" }
    $got = Read-Host "$question$hint"
    if ($got) { return $got.Trim() } else { return $default }
}
function Ask-Secret($question) {
    $s = Read-Host $question -AsSecureString
    $p = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($s)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($p).Trim() } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($p) }
}
function Ask-YesNo($question, $default = "y") {
    while ($true) {
        $got = (Ask "$question (y/n)" $default).ToLower()
        if ($got -in @("y", "yes")) { return $true }
        if ($got -in @("n", "no")) { return $false }
    }
}

# A native command, with its stderr allowed: in Windows PowerShell 5.1, under ErrorActionPreference Stop, a
# redirected stderr line from a native program is a terminating error. Returns stdout; $LASTEXITCODE is kept.
function Quiet([scriptblock]$cmd) {
    $old = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try { return (& $cmd 2>$null) } finally { $ErrorActionPreference = $old }
}

function Distro-Installed {
    $list = (Quiet { & wsl.exe -l -q }) -join "`n"
    return ($LASTEXITCODE -eq 0) -and ($list -match "(?m)^\s*$Distro\s*$")
}

# Every Linux command runs with `wsl.exe -e`, never `--`: `--` hands the line to the Linux shell, which ate the
# backslashes of a Windows path (C:\x\y became C:xy) and would split a path with a space in it.

# Linux steps: wsl-setup.sh from this folder, as root or as the tapwatch user. Values in $vars reach the
# script as environment variables through WSLENV, so they never appear on a command line. Its output goes
# through Write-Host so the transcript (the support log) has it: native output otherwise bypasses it.
function Invoke-Linux($user, [string[]]$stageArgs, [hashtable]$vars = @{}, [switch]$Capture) {
    $script = ((Quiet { & wsl.exe -d $Distro -u root -e wslpath -a (Join-Path $Here "deploy\windows\wsl-setup.sh") }) -join "").Trim()
    if (-not $script) { throw "Ubuntu can't see this folder: $Here" }
    $names = @()
    foreach ($k in $vars.Keys) { Set-Item "env:$k" $vars[$k]; $names += $k }
    $env:WSLENV = ($names -join ":")
    $old = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        if ($Capture) { return ((& wsl.exe -d $Distro -u $user -e bash $script @stageArgs 2>$null) -join "`n") }
        # One line at a time: apt's output can arrive as one block with bare line feeds, which the console draws
        # as a staircase.
        & wsl.exe -d $Distro -u $user -e bash $script @stageArgs 2>&1 |
            ForEach-Object { foreach ($line in ("$_" -split "`r?`n")) { if ($line.Trim()) { Write-Host "    $($line.TrimEnd("`r"))" } } }
        if ($LASTEXITCODE -ne 0) { throw "the Linux step '$($stageArgs[0])' failed (exit $LASTEXITCODE); the lines above say why" }
    } finally {
        $ErrorActionPreference = $old
        foreach ($k in $names) { Remove-Item "env:$k" -ErrorAction SilentlyContinue }
        Remove-Item env:WSLENV -ErrorAction SilentlyContinue
    }
}

# ------------------------------------------------------------------ 1. can this PC run it?
if ($Resume) {
    Unregister-ScheduledTask -TaskName $ResumeTask -Confirm:$false -ErrorAction SilentlyContinue
    Say "Welcome back. Carrying on with the tapwatch install."
} else {
    Write-Host "tapwatch installer" -ForegroundColor Green
    Note "This takes about 30 minutes and restarts the PC once. Keep this window open."
}
Get-ChildItem -Path $Here -Recurse -File | Unblock-File   # downloaded ZIP: drop the "from the internet" mark

Say "Checking this PC"
$build = [int](Get-CimInstance Win32_OperatingSystem).BuildNumber
if ($build -lt 19041) { Stop-Install "Windows is too old (build $build). Update Windows 10 to 2004 or later, or use Windows 11." }
$mirroredOk = $build -ge 22621
if (-not $mirroredOk) { Warn "Windows 10: the router's logs can't reach tapwatch here (that needs Windows 11). Everything else works." }
$cs = Get-CimInstance Win32_ComputerSystem
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
if (-not $cs.HypervisorPresent -and -not $cpu.VirtualizationFirmwareEnabled) {
    Stop-Install "Virtualization is turned off in this PC's firmware (BIOS/UEFI). Turn on 'Intel VT-x' or 'AMD-V' (sometimes called SVM), then run this again."
}
if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
    Stop-Install "winget isn't available. Install 'App Installer' from the Microsoft Store, then run this again."
}
$free = (Get-PSDrive -Name ($env:SystemDrive.TrimEnd(':'))).Free / 1GB
if ($free -lt 20) { Stop-Install ("Only {0:N0} GB free on {1}; tapwatch needs about 20 GB." -f $free, $env:SystemDrive) }
Note "Windows build $build, virtualization on, $([int]$free) GB free"
if ($Branch -ne "main") { Warn "Installing the '$Branch' branch (a test version), from this folder's name." }
$route = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1
$gateway = if ($route) { $route.NextHop } else { "" }
$thisIp = if ($route) { (Get-NetIPAddress -InterfaceIndex $route.ifIndex -AddressFamily IPv4 | Select-Object -First 1).IPAddress } else { "" }
if (-not $thisIp) { Stop-Install "This PC has no internet connection right now; tapwatch needs one to install." }
Note "This PC's address: $thisIp (the router's logs go here)    router: $gateway"

# ------------------------------------------------------------------ 2. everyday questions (kept over the restart)
$saved = $null
if (Test-Path $Answers) { $saved = Get-Content $Answers -Raw | ConvertFrom-Json }
if ($saved) {
    $linuxUser, $iface, $alerts, $syslog = $saved.linuxUser, $saved.iface, $saved.alerts, $saved.syslog
} else {
    Say "A few questions first (Enter takes the suggestion in [brackets])"
    $existing = ""
    if (Distro-Installed) {
        $existing = ((Quiet { & wsl.exe -d $Distro -u root -e getent passwd 1000 }) -join "").Split(":")[0]
        Note "Ubuntu is already on this PC. If tapwatch is set up in it, its settings are kept: answer as before."
    }
    $linuxUser = if ($existing) { $existing } else { ($env:USERNAME.ToLower() -replace '[^a-z0-9_-]', '') }
    if ($linuxUser -notmatch '^[a-z_][a-z0-9_-]{0,31}$') { $linuxUser = "tapwatch" }
    while ($true) {
        $linuxUser = Ask "Name for the Linux account tapwatch runs as" $linuxUser
        if ($linuxUser -match '^[a-z_][a-z0-9_-]{0,31}$') { break }
        Warn "Lower-case letters, digits, - and _ only, starting with a letter."
    }

    Write-Host ""
    Note "Which network port is plugged into the switch's copy (mirror) port? This PC's wired ports:"
    $adapters = @(Get-NetAdapter -Physical | Where-Object {
        $_.MediaType -eq "802.3" -and $_.InterfaceDescription -notmatch 'Bluetooth|Wi-?Fi|Wireless|802\.11' } | Sort-Object Name)
    if ($adapters.Count -eq 0) { Stop-Install "this PC has no wired network port. Plug in a USB-to-Ethernet adapter, then run this again." }
    $suggest = 0
    for ($j = 0; $j -lt $adapters.Count; $j++) {
        $a = $adapters[$j]
        $internet = $route -and $a.ifIndex -eq $route.ifIndex
        $role = if ($internet) { "this PC's internet connection" } elseif ($a.Status -eq "Up") { "connected, not used for the internet: likely the mirror port" } else { "not connected" }
        Note ("{0}. {1}  ({2}) - {3}" -f ($j + 1), $a.Name, $a.InterfaceDescription, $role)
        if (-not $internet -and $a.Status -eq "Up" -and -not $suggest) { $suggest = $j + 1 }
    }
    if (-not $suggest) { for ($j = 0; $j -lt $adapters.Count; $j++) { if (-not ($route -and $adapters[$j].ifIndex -eq $route.ifIndex)) { $suggest = $j + 1; break } } }
    if (-not $suggest) { $suggest = 1 }
    while ($true) {
        $pick = Ask "Number" "$suggest"
        if ($pick -match '^\d+$' -and [int]$pick -ge 1 -and [int]$pick -le $adapters.Count) { break }
        Warn "Type one of the numbers above."
    }
    $chosen = $adapters[[int]$pick - 1]
    $iface = $chosen.Name
    if ($route -and $chosen.ifIndex -eq $route.ifIndex) {
        Warn "That's the port this PC uses for the internet: tapwatch will only see this PC's own traffic until"
        Warn "a second port is plugged into the mirror port (a USB-to-Ethernet adapter works). Fine for a first try."
    }

    Write-Host ""
    Note "Where should alerts go?"
    Note "1. Phone app 'ntfy' (free, recommended: install ntfy from the App Store or Google Play)"
    Note "2. A Discord channel"
    Note "3. Nowhere for now (you can add one later)"
    $alerts = @{ "1" = "ntfy"; "2" = "discord"; "3" = "none" }[(Ask "Number" "1")]
    if (-not $alerts) { $alerts = "ntfy" }

    Write-Host ""
    $syslog = Ask-YesNo "Is the router UniFi, and should tapwatch read its logs (blocked attacks, admin logins)?" "y"
    @{ linuxUser = $linuxUser; iface = $iface; alerts = $alerts; syslog = $syslog } | ConvertTo-Json | Set-Content $Answers
}

# ------------------------------------------------------------------ 3. Windows features (restart once)
Say "Turning on the Windows features WSL needs"
$restart = $false
foreach ($f in @("Microsoft-Windows-Subsystem-Linux", "VirtualMachinePlatform")) {
    $state = (Get-WindowsOptionalFeature -Online -FeatureName $f).State
    if ($state -eq "Enabled") { Note "$f is on"; continue }
    if ($state -ne "EnablePending") {
        Enable-WindowsOptionalFeature -Online -FeatureName $f -All -NoRestart | Out-Null
    }
    $restart = $true
}
if ($restart) {
    $action = New-ScheduledTaskAction -Execute "powershell.exe" `
        -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Resume"
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User "$env:USERDOMAIN\$env:USERNAME"
    $principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Highest
    # A laptop on battery: Task Scheduler's defaults would never start it.
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero)
    Register-ScheduledTask -TaskName $ResumeTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
    Say "Windows needs to restart to finish turning these on."
    Note "After you sign back in, this window opens again by itself and carries on."
    Stop-Transcript | Out-Null
    Read-Host "Save your work in other programs, then press Enter to restart"
    Restart-Computer -Force
    exit 0
}

# ------------------------------------------------------------------ 4. Ubuntu, then the secret questions
Say "Setting up WSL and Ubuntu"
Quiet { & wsl.exe --update } | Out-Null
$cfgPath = Join-Path $env:USERPROFILE ".wslconfig"
$wslcfg = if (Test-Path $cfgPath) { Get-Content $cfgPath -Raw } else { "" }
if ($mirroredOk -and $wslcfg -notmatch '(?m)^\s*networkingMode\s*=\s*mirrored') {
    if ($wslcfg -match '(?m)^\s*\[wsl2\]') { $wslcfg = $wslcfg -replace '(?m)^(\s*\[wsl2\]\s*)$', "`$1`r`nnetworkingMode=mirrored" }
    else { $wslcfg = $wslcfg.TrimEnd() + "`r`n[wsl2]`r`nnetworkingMode=mirrored`r`n" }
    Set-Content -Path $cfgPath -Value $wslcfg.TrimStart()
    Note "mirrored networking on (Ubuntu shares this PC's network address)"
}
if (-not (Distro-Installed)) {
    Note "Downloading Ubuntu (a few minutes)"
    Quiet { & wsl.exe --install -d $Distro --no-launch } | ForEach-Object { Note $_ }
    if (-not (Distro-Installed)) {
        # Store-packaged Ubuntu installs the app but registers the distro only on first launch; register it
        # as root, so its "create a user" prompt never appears (the account is made below instead).
        $launcher = Get-Command ubuntu.exe -ErrorAction SilentlyContinue
        if ($launcher) { Quiet { & $launcher.Source install --root } | Out-Null }
    }
    if (-not (Distro-Installed)) { Stop-Install "Ubuntu didn't install. Try 'wsl --install -d Ubuntu' in this window, then run this again." }
}

$hasAccount = (Quiet { & wsl.exe -d $Distro -u root -e id -u $linuxUser }) -and $LASTEXITCODE -eq 0
$password = ""
if (-not $hasAccount) {
    Write-Host ""
    Note "Pick a password for the Linux account '$linuxUser'. You'll rarely need it (only for admin commands in Ubuntu)."
    while ($true) {
        $password = Ask-Secret "Password (hidden as you type)"
        if ($password.Length -lt 8) { Warn "At least 8 characters, please (that was $($password.Length))."; continue }
        if ((Ask-Secret "Same password again") -eq $password) { break }
        Warn "Those didn't match. Again:"
    }
}
$pwVar = @{}
if ($password) { $pwVar = @{ TW_PW = "${linuxUser}:$password" } }
Invoke-Linux "root" @("root", $linuxUser) $pwVar
$password, $pwVar = "", $null
Quiet { & wsl.exe --shutdown } | Out-Null   # applies systemd, the default user, the docker group and mirrored networking
Invoke-Linux "root" @("linger", $linuxUser)

Quiet { & wsl.exe -d $Distro -u $linuxUser -e test -f "/home/$linuxUser/tapwatch/config.yaml" } | Out-Null
$needSettings = $LASTEXITCODE -ne 0
$discordUrl, $typesafeKey, $anthropicKey = "", "", ""
if (-not $needSettings) {
    Note "tapwatch is already set up in Ubuntu: keeping its settings (alerts, keys)."
} else {
    if ($alerts -eq "discord") {
        Write-Host ""
        Note "Discord: Server Settings > Integrations > Webhooks > New Webhook > Copy Webhook URL, then paste it here."
        for ($try = 1; ; $try++) {
            $discordUrl = Ask-Secret "Webhook URL (hidden while you paste)"
            if ($discordUrl -match '^https://(discord|discordapp)\.com/api/webhooks/\S+$') { break }
            if ($try -ge 3) { Stop-Install "that doesn't look like a Discord webhook URL; run this again to retry" }
            Warn "That doesn't look like a Discord webhook URL (it starts https://discord.com/api/webhooks/). Copy it again and paste:"
        }
    }
    Write-Host ""
    Note "Optional AI keys. Press Enter to skip either one; tapwatch works without them."
    Note "TypeSafe: an AI reads unclear cases and helps decide what's worth interrupting you for."
    $typesafeKey = Ask-Secret "TypeSafe key, or just press Enter to skip"
    Note "Anthropic: names the kind of website when tapwatch's list doesn't know it."
    $anthropicKey = Ask-Secret "Anthropic key, or just press Enter to skip"
}

# ------------------------------------------------------------------ 5. Wireshark + Npcap
Say "Installing the capture tools"
$dumpcap = Join-Path $env:ProgramFiles "Wireshark\dumpcap.exe"
if (-not (Test-Path $dumpcap)) {
    Note "Wireshark (provides dumpcap, which reads the mirror port)"
    Quiet { & winget install -e --id WiresharkFoundation.Wireshark --silent --accept-package-agreements --accept-source-agreements } | Out-Null
    if (-not (Test-Path $dumpcap)) { Stop-Install "Wireshark didn't install (no $dumpcap)" }
} else { Note "Wireshark is installed" }
$npcap = Get-Service npcap -ErrorAction SilentlyContinue
if (-not $npcap -or $npcap.Status -ne "Running") {
    $page = (Invoke-WebRequest -Uri "https://npcap.com/" -UseBasicParsing).Content
    $m = [regex]::Match($page, 'dist/npcap-[0-9.]+\.exe')
    if (-not $m.Success) { Stop-Install "couldn't find the Npcap download on npcap.com; install it from there by hand, then run this again" }
    $exe = Join-Path $env:TEMP ($m.Value -replace '^dist/', '')
    Invoke-WebRequest -Uri "https://npcap.com/$($m.Value)" -OutFile $exe -UseBasicParsing
    $sig = Get-AuthenticodeSignature $exe
    if ($sig.Status -ne "Valid" -or $sig.SignerCertificate.Subject -notmatch 'Nmap Software LLC|Insecure\.Com LLC') {
        Remove-Item $exe -Force
        Stop-Install "the Npcap download failed its signature check ($($sig.Status)); not running it"
    }
    Say "Npcap's installer opens now: click 'I Agree', keep the ticked options, 'Install', then 'Finish'."
    Start-Process -FilePath $exe -Wait
    Remove-Item $exe -Force -ErrorAction SilentlyContinue
    $npcap = Get-Service npcap -ErrorAction SilentlyContinue
    if (-not $npcap -or $npcap.Status -ne "Running") { Stop-Install "Npcap isn't running. Run this installer again to retry." }
} else { Note "Npcap is running" }

# ------------------------------------------------------------------ 6. tapwatch inside Ubuntu
Say "Installing tapwatch inside Ubuntu"
$answersJson = @{ gateway = $gateway; this_ip = $thisIp; windows_capture = "yes"; capture_iface = $iface;
                  alerts = $alerts; download_feeds = "no" }
if ($discordUrl) { $answersJson.discord_url = $discordUrl }
if ($typesafeKey) { $answersJson.typesafe_key = $typesafeKey }
if ($anthropicKey) { $answersJson.anthropic_key = $anthropicKey }
$vars = @{ TW_ANSWERS = ($answersJson | ConvertTo-Json -Compress); TW_IFACE = $iface; TW_SYSLOG = $(if ($syslog) { "yes" } else { "no" }) }
Invoke-Linux $linuxUser @("app", $RepoUrl, $Branch) $vars
$discordUrl, $typesafeKey, $anthropicKey, $vars, $answersJson = "", "", "", $null, $null

# ------------------------------------------------------------------ 7. keep running; agent; router
Say "Keeping the PC awake and tapwatch running after restarts"
Quiet { & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Here "deploy\windows\keep-alive.ps1") -Install -AtStartup -Distro $Distro } | ForEach-Object { Note $_ }
if (-not (Get-ScheduledTask -TaskName "tapwatch keep-alive" -ErrorAction SilentlyContinue)) { Stop-Install "the keep-alive task didn't install" }

Say "Installing the PC agent (osquery and Sysmon: which program made a connection)"
Quiet { & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Here "agents\windows\install.ps1") } | ForEach-Object { Note $_ }
$osq = Get-Service osqueryd -ErrorAction SilentlyContinue
if (-not $osq -or $osq.Status -ne "Running") { Stop-Install "the PC agent (osqueryd) isn't running" }

if ($syslog -and $gateway -and $mirroredOk) {
    Say "Letting the router's logs reach tapwatch (two firewall rules, from $gateway only)"
    if (-not (Get-NetFirewallHyperVRule -Name tapwatch-syslog -ErrorAction SilentlyContinue)) {
        New-NetFirewallHyperVRule -Name tapwatch-syslog -DisplayName "tapwatch syslog" -Direction Inbound `
            -VMCreatorId '{40E0AC32-46A5-438D-A0A5-56A1FF8A6E6E}' -Protocol UDP -LocalPorts 5514 `
            -RemoteAddresses $gateway -Action Allow | Out-Null
    }
    if (-not (Get-NetFirewallRule -DisplayName "tapwatch syslog" -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName "tapwatch syslog" -Direction Inbound -Protocol UDP `
            -LocalPort 5514 -RemoteAddress $gateway -Action Allow | Out-Null
    }
}

# ------------------------------------------------------------------ 8. check and finish
Say "Checking everything (and sending a test alert)"
Invoke-Linux $linuxUser @("doctor")
Remove-Item $Answers -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "tapwatch is installed." -ForegroundColor Green
Note "Anything marked [!] or [FAIL] above says what to do. The UniFi steps (mirror port, router logs) are in"
Note "docs/setup/office-unifi.md. To check again later, open Ubuntu and run:  cd ~/tapwatch; .venv/bin/tapwatch doctor"
Note "The first 3 days are a learning period: expect it to be quiet while it learns this network."
Stop-Transcript | Out-Null   # the ntfy address is a secret: shown on screen only, after the log is closed
if ($alerts -eq "ntfy") {
    $ntfy = Invoke-Linux $linuxUser @("ntfy-url") -Capture
    if ($ntfy) {
        Write-Host ""
        Write-Host "Last step: phone alerts." -ForegroundColor Green
        Note "1. Open the ntfy app on your phone and tap +"
        Note "2. Type this address exactly, then Subscribe:"
        Write-Host ""
        Write-Host "       $ntfy" -ForegroundColor Yellow
        Write-Host ""
        Note "Keep it private: anyone who has it can read your alerts. (It's also in Ubuntu: ~/tapwatch/.env)"
        while ($true) {
            $again = Read-Host "Once you've subscribed, press Enter to send a test alert (or type 'skip')"
            if ($again -eq "skip") { break }
            Invoke-Linux $linuxUser @("test-alert") -Capture | ForEach-Object { Note $_ }
            if (Ask-YesNo "Did the test alert arrive on your phone?" "y") { break }
            Note "Check the address was typed exactly (it's case-sensitive), then try again."
        }
    }
}
Read-Host "All done. Press Enter to close"
