# tapwatch keep-alive for the Windows path: keeps the PC from idle-sleeping and keeps a WSL
# process running, so the distro (and tapwatch's systemd services in it) stays up. No admin
# needed for normal use.
#
#   powershell -ExecutionPolicy Bypass -File keep-alive.ps1 -Install [-Distro Ubuntu]   # logon task, starts now
#   powershell -ExecutionPolicy Bypass -File keep-alive.ps1 -Install -AtStartup          # boot task (admin, once)
#   powershell -ExecutionPolicy Bypass -File keep-alive.ps1 -Uninstall
#
# -AtStartup runs the task at boot whether or not anyone signs in, so tapwatch comes back on its own
# after a Windows Update restart. It uses an S4U logon: Windows stores no password, and the task
# can't reach network shares or the desktop, which it doesn't need. Registering it needs admin once.
#
# Closing the lid or choosing Sleep still sleeps the PC; this only blocks *idle* sleep.
param([switch]$Install, [switch]$AtStartup, [switch]$Uninstall, [string]$Distro = "")

$TaskName = "tapwatch keep-alive"

if ($Install) {
    $script = $PSCommandPath
    if ($AtStartup) {
        # At boot WSL isn't running, so a script on \\wsl$ can't be read (and S4U tasks can't use network
        # paths anyway). Run a local copy instead.
        $dir = Join-Path $env:LOCALAPPDATA "tapwatch"
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        $script = Join-Path $dir "keep-alive.ps1"
        if ($PSCommandPath -ne $script) { Copy-Item -LiteralPath $PSCommandPath -Destination $script -Force }
    }
    $argList = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$script`""
    if ($Distro) { $argList += " -Distro `"$Distro`"" }
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $argList
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
    $user = "$env:USERDOMAIN\$env:USERNAME"
    if ($AtStartup) {
        $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)
        if (-not $admin) { throw "-AtStartup needs an admin PowerShell (once, to register the boot task)" }
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType S4U -RunLevel Limited
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal `
            -Settings $settings -Force | Out-Null
        $when = "at every boot, signed in or not"
    } else {
        $trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Force | Out-Null
        $when = "at every logon"
    }
    Start-ScheduledTask -TaskName $TaskName
    Write-Output "installed and started '$TaskName' (runs $when)"
    return
}

if ($Uninstall) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Output "removed '$TaskName'"
    return
}

# The task body: block idle sleep while this runs, and hold a WSL process open.
Add-Type -Name Power -Namespace TapWatch -MemberDefinition `
    '[DllImport("kernel32.dll")] public static extern uint SetThreadExecutionState(uint flags);'
[TapWatch.Power]::SetThreadExecutionState(0x80000001) | Out-Null   # ES_CONTINUOUS | ES_SYSTEM_REQUIRED

$wslArgs = @("--exec", "sleep", "infinity")
if ($Distro) { $wslArgs = @("-d", $Distro) + $wslArgs }
while ($true) {
    & wsl.exe @wslArgs        # returns only if WSL shuts down; then bring it back
    Start-Sleep -Seconds 30
}
