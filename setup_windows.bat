@echo off
echo ========================================
echo  Telegram to Google Drive Bot Setup
echo ========================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python from https://www.python.org/downloads/
    echo Make sure to check "Add Python to PATH" during installation
    pause
    exit /b 1
)

echo Python is installed. Version:
python --version
echo.

REM Install required packages
echo Installing required Python packages...
pip install -r requirements.txt
if errorlevel 1 (
    echo ERROR: Failed to install required packages
    pause
    exit /b 1
)
echo.

REM Create .env file if it doesn't exist
if not exist ".env" (
    echo Creating .env file from template...
    copy .env.example .env >nul
    echo .env file created successfully!
    echo.
    echo IMPORTANT: Please edit the .env file and add your:
    echo - Telegram bot token
    echo - Google Drive folder ID (optional)
    echo.
) else (
    echo .env file already exists.
    echo.
)

REM Check for credentials.json
if not exist "credentials.json" (
    echo WARNING: credentials.json file not found!
    echo Please download your Google API credentials and save as 'credentials.json'
    echo.
) else (
    echo Google API credentials found.
    echo.
)

echo ========================================
echo  Setup Complete!
echo ========================================
echo.
echo Next steps:
echo 1. Edit the .env file with your bot token and folder ID
echo 2. Make sure credentials.json is in this folder
echo 3. Run: python telegram_bot.py
echo.
echo For detailed instructions, see README.md
echo.
pause