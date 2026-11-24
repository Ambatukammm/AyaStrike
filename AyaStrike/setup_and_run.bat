@echo off
REM ===========================================================================
REM  AyaStrike - one-click setup & run  (made by Ruel)
REM  Double-click this file. It finds Python, installs dependencies,
REM  checks the environment, and launches the app. The window stays open so
REM  you can read any message.
REM ===========================================================================
setlocal enabledelayedexpansion
cd /d "%~dp0"
title AyaStrike - Setup ^& Run

echo.
echo  ============================================================
echo    AYASTRIKE - All-In-One Penetration Testing Toolkit
echo    made by Ruel   -   authorised use only
echo  ============================================================
echo.

REM --- 1. Find a working Python -------------------------------------------
REM  Prefer the "py" launcher: the bare "python" command on Windows is often
REM  the Microsoft Store alias that opens nothing, which is the usual reason
REM  "nothing happens".
set "PYCMD="
py -3 --version >nul 2>nul && set "PYCMD=py -3"
if not defined PYCMD (
    python --version >nul 2>nul && set "PYCMD=python"
)
if not defined PYCMD (
    python3 --version >nul 2>nul && set "PYCMD=python3"
)

if not defined PYCMD (
    echo  [X] Python 3 was not found.
    echo.
    echo      Install it from:  https://www.python.org/downloads/
    echo      IMPORTANT: on the first installer screen, tick
    echo                 "Add python.exe to PATH".
    echo.
    echo      After installing, double-click this file again.
    echo.
    pause
    exit /b 1
)

for /f "delims=" %%v in ('%PYCMD% --version 2^>^&1') do set "PYVER=%%v"
echo  [1/4] Using Python:  !PYVER!   ^(!PYCMD!^)
echo.

REM --- 2. Install dependencies (best effort; core runs without them) -------
echo  [2/4] Installing dependencies (this may take a minute the first time)...
%PYCMD% -m pip install --upgrade pip >nul 2>nul
%PYCMD% -m pip install -r requirements.txt
if errorlevel 1 (
    echo.
    echo      Note: some packages could not be installed ^(no internet?^).
    echo      The core suite still runs on the Python standard library.
)
echo.

REM --- 3. Environment self-check ------------------------------------------
echo  [3/4] Checking environment...
echo.
%PYCMD% main.py --check
echo.

REM --- 4. Launch ----------------------------------------------------------
echo  [4/4] Launching AyaStrike...
echo.
%PYCMD% main.py
set "RC=%ERRORLEVEL%"

if not "%RC%"=="0" (
    echo.
    echo  ------------------------------------------------------------
    echo   AyaStrike exited with an error ^(code %RC%^).
    if exist "ayastrike_error.log" (
        echo   Details from ayastrike_error.log:
        echo  ------------------------------------------------------------
        type "ayastrike_error.log"
    ) else (
        echo   No error log was written. If the window closed instantly
        echo   before, this run should now show the cause above.
    )
    echo  ------------------------------------------------------------
)

echo.
echo  AyaStrike has closed. You can close this window.
pause
endlocal
