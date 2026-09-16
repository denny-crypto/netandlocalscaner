@echo off
setlocal
cd /d "%~dp0"

start "SpyNet Agent" /b py -3 "%~dp0spynetagent.py"
py -3 "%~dp0virus_scanner.py"

exit /b %ERRORLEVEL%