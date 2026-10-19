@echo off
rem Double-click to install tapwatch on this Windows PC. Asks for admin rights once (UAC).
rem What it does, step by step: deploy\windows\install.ps1
if not exist "%~dp0deploy\windows\install.ps1" (
  echo The installer files are not next to this one.
  echo Right-click the downloaded ZIP, choose Extract All, then double-click install-windows.cmd
  echo in the extracted folder.
  pause
  exit /b 1
)
rem The path goes through an environment variable, so a quote or apostrophe in it cannot break the command.
set "TW_INSTALLER=%~dp0deploy\windows\install.ps1"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "Start-Process powershell -Verb RunAs -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -File \"' + $env:TW_INSTALLER + '\"')"
