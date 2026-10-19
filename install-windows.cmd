@echo off
rem Double-click to install tapwatch on this Windows PC. Asks for admin rights once (UAC).
rem What it does, step by step: deploy\windows\install.ps1
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "Start-Process powershell -Verb RunAs -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -File \"%~dp0deploy\windows\install.ps1\"')"
