<#
Remove osquery and Sysmon installed by install.ps1. Run from an admin PowerShell, or uninstall.cmd.
#>
#Requires -RunAsAdministrator
param([switch]$Window)     # set by uninstall.cmd: close the window when done
$ErrorActionPreference = "Continue"
Stop-Service osqueryd -Force -ErrorAction SilentlyContinue
winget uninstall --id osquery.osquery --exact --silent
Remove-Item -Recurse -Force (Join-Path $env:ProgramFiles "osquery") -ErrorAction SilentlyContinue

foreach ($name in "Sysmon64", "Sysmon") {
    $exe = Join-Path $env:WINDIR "$name.exe"
    if (Test-Path $exe) { & $exe -u force }
}
Write-Host "osquery and Sysmon removed."
if ($Window) { Write-Host "This window closes in 10 seconds."; Start-Sleep -Seconds 10 }
