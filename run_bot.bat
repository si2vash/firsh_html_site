@echo off
title Telegram to Google Drive Bot
echo ========================================
echo  Starting Telegram to Google Drive Bot
echo ========================================
echo.

REM Check if .env file exists
if not exist ".env" (
    echo ERROR: .env file not found!
    echo Please run setup_windows.bat first or create .env file manually
    pause
    exit /b 1
)

REM Check if credentials.json exists
if not exist "credentials.json" (
    echo ERROR: credentials.json file not found!
    echo Please download your Google API credentials and save as 'credentials.json'
    pause
    exit /b 1
)

echo Starting bot...
echo Press Ctrl+C to stop the bot
echo.

python telegram_bot.py

echo.
echo Bot stopped.
pause