@echo off
title FakeDriveShield GUI Launcher
cd /d "%~dp0"

:: Check for Administrator privileges for diskpart capabilities
net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -Command "Start-Process cmd -ArgumentList '/c \"\"%~f0\"\"' -Verb RunAs"
    exit /b
)

start "" pythonw "%~dp0app.py"
if %errorlevel% neq 0 (
    python "%~dp0app.py"
)
exit
