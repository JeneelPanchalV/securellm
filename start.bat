@echo off
title SecureLLM Launcher
echo.
echo  =====================================================
echo   SecureLLM  ^|  Starting backend + frontend server
echo  =====================================================
echo.

set ROOT=%~dp0
set PYTHON=C:\Users\diyad\miniconda3\envs\textgen\python.exe

rem Start the backend in a new window
start "SecureLLM Backend" /D "%ROOT%backend" cmd /k "%ROOT%backend\start.bat"

rem Start the frontend HTTP server in a new window
echo  [Frontend] Serving project/ on http://localhost:3000
start "SecureLLM Frontend" /D "%ROOT%project" "%PYTHON%" -m http.server 3000

rem Give both servers time to start before opening the browser
timeout /t 4 /nobreak >nul

echo  [Frontend] Opening http://localhost:3000/index.html
start "" "http://localhost:3000/index.html"
