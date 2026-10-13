@echo off
rem Double-click to install osquery + Sysmon on Windows. Asks for admin rights (UAC).
rem Extra options go to windows\install.ps1, e.g.  install.cmd -NoSysmon
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "Start-Process powershell -Verb RunAs -ArgumentList ('-NoProfile -NoExit -ExecutionPolicy Bypass -File \"%~dp0windows\install.ps1\" %*')"
