# tapwatch keep-alive for the Windows path: keeps the PC from idle-sleeping and keeps a WSL
# process running, so the distro (and tapwatch's systemd services in it) stays up. No admin
# needed for normal use.
#
#   powershell -ExecutionPolicy Bypass -File keep-alive.ps1 -Install [-Distro Ubuntu]   # logon task, starts now
#   powershell -ExecutionPolicy Bypass -File keep-alive.ps1 -Uninstall
#
# Closing the lid or choosing Sleep still sleeps the PC; this only blocks *idle* sleep.
param([switch]$Install, [switch]$Uninstall, [string]$Distro = "")

$TaskName = "tapwatch keep-alive"

if ($Install) {
    $argList = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    if ($Distro) { $argList += " -Distro `"$Distro`"" }
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $argList
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Force | Out-Null
    Start-ScheduledTask -TaskName $TaskName
    Write-Output "installed and started '$TaskName' (runs at every logon)"
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
