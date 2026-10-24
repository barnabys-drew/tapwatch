@echo off
rem For a deployment tool (Intune, an RMM, PDQ, a GPO startup script) running as SYSTEM: installs osquery and
rem Sysmon and enrolls in Fleet with the settings in agent.env next to this file, with no prompts.
rem Log: %ProgramData%\tapwatch\agent-install.log. Exit code 0: the agent is running; 1: it isn't (see the log).
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0windows\install.ps1" -Silent %*
exit /b %ERRORLEVEL%
