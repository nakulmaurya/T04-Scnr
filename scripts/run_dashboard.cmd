@echo off
setlocal
rem Uses the reviewed local launcher without changing machine/user policy.
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0run_dashboard.ps1" %*
exit /b %errorlevel%
