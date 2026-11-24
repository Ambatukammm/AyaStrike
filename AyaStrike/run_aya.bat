@echo off
REM AyaStrike launcher for Windows. Double-click this file to run.
REM Keeps the window open so you can read any error message.
cd /d "%~dp0"

REM Prefer the Python launcher (py), fall back to python on PATH.
where py >nul 2>nul
if %ERRORLEVEL%==0 (
    py -3 main.py
) else (
    where python >nul 2>nul
    if %ERRORLEVEL%==0 (
        python main.py
    ) else (
        echo.
        echo Python was not found on your PATH.
        echo Install Python 3 from https://www.python.org/downloads/
        echo During install, tick "Add python.exe to PATH".
        echo.
    )
)

echo.
echo AyaStrike has exited. If it failed, see ayastrike_error.log in this folder.
pause
