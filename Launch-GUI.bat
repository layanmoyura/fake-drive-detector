@echo off
cd /d "%~dp0"

:: Check for Administrator privileges for diskpart capabilities
net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -NoProfile -WindowStyle Hidden -Command "Start-Process pythonw -ArgumentList '\"%~dp0app.py\"' -Verb RunAs"
    exit /b
)

start "" pythonw "%~dp0app.py"
if %errorlevel% neq 0 (
    start "" python "%~dp0app.py"
)
exit
