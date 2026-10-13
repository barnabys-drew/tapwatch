@echo off
rem Double-click to remove osquery + Sysmon from Windows. Asks for admin rights (UAC).
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "Start-Process powershell -Verb RunAs -ArgumentList ('-NoProfile -NoExit -ExecutionPolicy Bypass -File \"%~dp0windows\uninstall.ps1\"')"
