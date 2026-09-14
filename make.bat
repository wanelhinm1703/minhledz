@echo off
setlocal enabledelayedexpansion
set PYTHON=python

if "%1"=="" goto help
if "%1"=="help" goto help
if "%1"=="setup" goto setup
if "%1"=="scan" goto scan
if "%1"=="pipeline" goto pipeline
if "%1"=="test" goto test
if "%1"=="dev" goto dev
goto help

:help
echo AI-Pentest Copilot - Windows Helper
echo   make setup
echo   make scan TARGET=^<target^>
echo   make pipeline TARGET=^<target^>
echo   make test
echo   make dev
goto end

:setup
%PYTHON% toolkit/scripts/init_dirs.py
%PYTHON% -m pip install -q -r backend/requirements.txt
goto end

:scan
if not "%3"=="" (
    set TARGET_VAL=%3
) else if not "%2"=="" (
    set TARGET_VAL=%2
    set TARGET_VAL=!TARGET_VAL:TARGET=!
    set TARGET_VAL=!TARGET_VAL:^==!
) else (
    echo ERROR: TARGET argument required. Example: make scan TARGET=192.168.56.101
    exit /b 1
)
%PYTHON% toolkit/scripts/targets.py scan --target "!TARGET_VAL!"
goto end

:pipeline
if not "%3"=="" (
    set TARGET_VAL=%3
) else if not "%2"=="" (
    set TARGET_VAL=%2
    set TARGET_VAL=!TARGET_VAL:TARGET=!
    set TARGET_VAL=!TARGET_VAL:^==!
) else (
    echo ERROR: TARGET argument required. Example: make pipeline TARGET=192.168.56.101
    exit /b 1
)
%PYTHON% toolkit/scripts/pipeline_runner.py "!TARGET_VAL!"
goto end

:test
%PYTHON% -m pytest backend/tests -v
goto end

:dev
uvicorn backend.app.main:app --reload --port 8000
goto end

:end
