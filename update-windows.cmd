@echo off
rem Double-click to update tapwatch on this Windows PC to the newest release. It shows what changed and asks first;
rem if the new version fails its checks, it goes back to the one you had. Same as, in Ubuntu:
rem   cd ~/tapwatch && .venv/bin/tapwatch update
wsl.exe -d Ubuntu --cd ~ -e bash -lc "cd ~/tapwatch && .venv/bin/tapwatch update"
pause
