@echo off
cd /d "%~dp0"

echo ================================================
echo   Azure Policy Analyzer
echo ================================================
echo.

python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python is not installed or not in PATH.
    echo Please install Python 3.9+ from https://python.org
    pause
    exit /b 1
)

echo Installing / updating dependencies...
pip install -r requirements.txt --quiet

echo.
echo Starting server...
echo Open http://localhost:5000 in your browser
echo Press Ctrl+C to stop.
echo.
python app.py
pause
