@echo off
title SecureLLM Backend
echo.
echo  ===================================================
echo   SecureLLM Backend  ^|  localhost:8000
echo   Model: Meta-Llama-3.1-8B-Instruct + CVE LoRA
echo  ===================================================
echo.

set PYTHON=C:\Users\diyad\miniconda3\envs\textgen\python.exe
set BACKEND_DIR=%~dp0

cd /d "%BACKEND_DIR%"
"%PYTHON%" main.py

pause
