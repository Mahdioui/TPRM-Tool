@echo off
title PCAP Security Analyzer

echo ========================================
echo   PCAP Security Analyzer - Starting
echo ========================================
echo.

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python is not installed or not in PATH
    echo Please install Python 3.8+ and try again
    pause
    exit /b 1
)

REM Try to start the analyzer
python start_analyzer.py

pause
