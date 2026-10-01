@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0ssh_remote_manager.ps1"
if errorlevel 1 pause
