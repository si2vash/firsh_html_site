# Telegram to Google Drive Bot

A Telegram bot that automatically uploads files sent to it to Google Drive and provides downloadable links. Perfect for sharing files across devices or with others.

## Features

- 📁 Upload any file type to Google Drive
- 🔗 Get instant download links
- 🔒 Secure Google Drive integration
- 📱 Support for all Telegram file types (documents, photos, videos, audio, stickers, etc.)
- 🚀 Easy to set up and deploy

## Requirements

- Python 3.8 or higher
- Google Drive API credentials
- Telegram Bot Token
- Windows OS (as requested)

## Step-by-Step Setup Guide

### Step 1: Install Python

1. Download Python from [python.org](https://www.python.org/downloads/)
2. During installation, make sure to check "Add Python to PATH"
3. Verify installation by opening Command Prompt and running:
   ```cmd
   python --version
   ```

### Step 2: Create a Telegram Bot

1. Open Telegram and search for `@BotFather`
2. Start a chat with BotFather
3. Send `/newbot` command
4. Follow the instructions to create your bot:
   - Choose a name for your bot (e.g., "My Drive Bot")
   - Choose a username (must end with 'bot', e.g., "mydrive_bot")
5. Copy the bot token (looks like `123456789:ABCdefGHIjklMNOpqrsTUVwxyz`)
6. Save this token - you'll need it later

### Step 3: Set Up Google Drive API

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable the Google Drive API:
   - Go to "APIs & Services" > "Library"
   - Search for "Google Drive API"
   - Click on it and press "Enable"
4. Create credentials:
   - Go to "APIs & Services" > "Credentials"
   - Click "Create Credentials" > "OAuth 2.0 Client IDs"
   - If prompted, configure the OAuth consent screen first:
     - Choose "External" user type
     - Fill in the required fields (App name, User support email, Developer contact)
     - Add your email to test users
   - For Application type, choose "Desktop application"
   - Give it a name (e.g., "Telegram Bot")
   - Click "Create"
5. Download the credentials JSON file
6. Rename it to `credentials.json`

### Step 4: Create Google Drive Folder (Optional)

1. Go to [Google Drive](https://drive.google.com/)
2. Create a new folder for your bot uploads
3. Right-click the folder and select "Get link"
4. Copy the folder ID from the URL (the part after `/folders/`)
   - Example: `https://drive.google.com/drive/folders/1ABC123def456GHI789jkl` → ID is `1ABC123def456GHI789jkl`

### Step 5: Set Up the Project

1. Download or clone this project to your Windows machine
2. Open Command Prompt and navigate to the project folder:
   ```cmd
   cd path\to\your\project\folder
   ```
3. Install required packages:
   ```cmd
   pip install -r requirements.txt
   ```
4. Copy your `credentials.json` file to the project folder
5. Copy `.env.example` to `.env`:
   ```cmd
   copy .env.example .env
   ```
6. Edit the `.env` file with your details:
   - Open `.env` in Notepad or any text editor
   - Replace `your_telegram_bot_token_here` with your bot token from Step 2
   - Replace `your_google_drive_folder_id_here` with your folder ID from Step 4 (optional)
   - Save the file

### Step 6: First Run and Authentication

1. Run the bot for the first time:
   ```cmd
   python telegram_bot.py
   ```
2. The first time you run it, a browser window will open for Google authentication:
   - Sign in with your Google account
   - Grant the necessary permissions
   - The browser will show a success message
3. A `token.json` file will be created automatically for future runs
4. The bot should now be running and show "Starting Telegram bot..." in the console

### Step 7: Test Your Bot

1. Open Telegram and find your bot (search for the username you created)
2. Start a chat with your bot
3. Send `/start` to see the welcome message
4. Send any file to test the upload functionality
5. You should receive a Google Drive download link

## Usage

### Commands
- `/start` - Show welcome message and instructions
- `/help` - Get help information

### Supported File Types
- Documents (PDF, DOC, DOCX, TXT, etc.)
- Images (JPG, PNG, GIF, WEBP, etc.)
- Videos (MP4, AVI, MOV, etc.)
- Audio files (MP3, WAV, OGG, etc.)
- Archives (ZIP, RAR, 7Z, etc.)
- Stickers and voice messages
- Any other file type

## Running the Bot

### For Development/Testing
```cmd
python telegram_bot.py
```

### For Production (Windows Service)
You can use tools like `nssm` (Non-Sucking Service Manager) to run the bot as a Windows service:

1. Download NSSM from [nssm.cc](https://nssm.cc/download)
2. Install the service:
   ```cmd
   nssm install TelegramBot python.exe "C:\path\to\your\project\telegram_bot.py"
   ```
3. Start the service:
   ```cmd
   nssm start TelegramBot
   ```

## Configuration

### Environment Variables (.env file)

```env
# Required: Your Telegram bot token
TELEGRAM_BOT_TOKEN=your_bot_token_here

# Optional: Google Drive folder ID (if not set, files go to root)
GOOGLE_DRIVE_FOLDER_ID=your_folder_id_here

# Optional: Make files publicly accessible (default: True)
MAKE_FILES_PUBLIC=True
```

## Troubleshooting

### Common Issues

1. **"ModuleNotFoundError"**
   - Make sure you installed all requirements: `pip install -r requirements.txt`

2. **"TELEGRAM_BOT_TOKEN not found"**
   - Check your `.env` file exists and has the correct token
   - Make sure there are no extra spaces in the token

3. **Google Authentication Issues**
   - Make sure `credentials.json` is in the project folder
   - Delete `token.json` and run again to re-authenticate
   - Check that Google Drive API is enabled in your Google Cloud project

4. **"Permission denied" errors**
   - Make sure your Google account has access to create files in Drive
   - Check that the OAuth consent screen is properly configured

5. **Bot doesn't respond**
   - Check that the bot token is correct
   - Make sure the bot is running (check console output)
   - Verify your internet connection

### Getting Help

If you encounter issues:
1. Check the console output for error messages
2. Verify all setup steps were completed correctly
3. Make sure all files are in the correct locations
4. Check that your credentials and tokens are valid

## Security Notes

- Keep your `credentials.json` and `.env` files secure
- Don't share your bot token or Google API credentials
- Files uploaded through the bot will be publicly accessible if `MAKE_FILES_PUBLIC=True`
- Consider setting up proper access controls for production use

## File Structure

```
telegram-drive-bot/
├── telegram_bot.py          # Main bot application
├── google_drive_handler.py  # Google Drive integration
├── requirements.txt         # Python dependencies
├── .env.example            # Environment variables template
├── .env                    # Your environment variables (create this)
├── credentials.json        # Google API credentials (download this)
├── token.json              # Auto-generated Google auth token
└── README.md               # This file
```

## License

This project is open source and available under the MIT License.