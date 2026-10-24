@echo off
rem For a deployment tool (Intune Win32 app, an RMM, PDQ) running as SYSTEM: installs osquery and Sysmon and enrolls
rem in Fleet with the settings in agent.env next to this file, with no prompts.
rem Log: %ProgramData%\tapwatch\agent-install.log. Exit code 0: the agent is running; 1: it isn't (see the log);
rem 1618: another installation kept running for 10 minutes (retry later).
rem 64-bit PowerShell even when the tool starts this from a 32-bit process (Sysnative exists only there).
set "PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if exist "%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe" set "PS=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
"%PS%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0windows\install.ps1" -Silent %*
exit /b %ERRORLEVEL%
