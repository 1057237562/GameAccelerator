@echo off
echo Starting Game Accelerator Client...
cd /d "%~dp0"
python -m client.main %*
