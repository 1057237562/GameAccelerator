@echo off
echo Starting Game Accelerator Server...
cd /d "%~dp0"
python -m server.main %*
