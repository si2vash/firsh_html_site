import os
import logging
import mimetypes
from io import BytesIO
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes
from google_drive_handler import GoogleDriveHandler
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

class TelegramBot:
    def __init__(self):
        self.token = os.getenv('TELEGRAM_BOT_TOKEN')
        self.folder_id = os.getenv('GOOGLE_DRIVE_FOLDER_ID')
        self.drive_handler = GoogleDriveHandler(self.folder_id)
        
        if not self.token:
            raise ValueError("TELEGRAM_BOT_TOKEN not found in environment variables")

    async def start(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Send a message when the command /start is issued."""
        welcome_message = (
            "🤖 Welcome to the Telegram to Google Drive Bot!\n\n"
            "📁 Send me any file and I'll upload it to Google Drive and provide you with a download link.\n\n"
            "Supported file types:\n"
            "• Documents (PDF, DOC, TXT, etc.)\n"
            "• Images (JPG, PNG, GIF, etc.)\n"
            "• Videos (MP4, AVI, MOV, etc.)\n"
            "• Audio files (MP3, WAV, etc.)\n"
            "• Archives (ZIP, RAR, etc.)\n"
            "• And many more!\n\n"
            "Commands:\n"
            "/start - Show this welcome message\n"
            "/help - Get help information\n\n"
            "Just send me a file to get started! 🚀"
        )
        await update.message.reply_text(welcome_message)

    async def help_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Send a message when the command /help is issued."""
        help_message = (
            "ℹ️ How to use this bot:\n\n"
            "1. Send any file to this chat\n"
            "2. Wait for the bot to upload it to Google Drive\n"
            "3. Receive a direct download link\n\n"
            "⚠️ Important notes:\n"
            "• Files are uploaded to a shared Google Drive folder\n"
            "• Download links are publicly accessible\n"
            "• Large files may take longer to process\n"
            "• Maximum file size depends on Telegram limits (2GB)\n\n"
            "If you encounter any issues, please try again or contact support."
        )
        await update.message.reply_text(help_message)

    async def handle_document(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle document files."""
        document = update.message.document
        await self._process_file(update, document, document.file_name, document.mime_type)

    async def handle_photo(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle photo files."""
        photo = update.message.photo[-1]  # Get the highest resolution photo
        file_name = f"photo_{photo.file_id}.jpg"
        await self._process_file(update, photo, file_name, "image/jpeg")

    async def handle_video(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle video files."""
        video = update.message.video
        file_name = video.file_name or f"video_{video.file_id}.mp4"
        mime_type = video.mime_type or "video/mp4"
        await self._process_file(update, video, file_name, mime_type)

    async def handle_audio(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle audio files."""
        audio = update.message.audio
        file_name = audio.file_name or f"audio_{audio.file_id}.mp3"
        mime_type = audio.mime_type or "audio/mpeg"
        await self._process_file(update, audio, file_name, mime_type)

    async def handle_voice(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle voice messages."""
        voice = update.message.voice
        file_name = f"voice_{voice.file_id}.ogg"
        await self._process_file(update, voice, file_name, "audio/ogg")

    async def handle_video_note(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle video notes (circular videos)."""
        video_note = update.message.video_note
        file_name = f"video_note_{video_note.file_id}.mp4"
        await self._process_file(update, video_note, file_name, "video/mp4")

    async def handle_sticker(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle stickers."""
        sticker = update.message.sticker
        file_extension = "webp" if sticker.is_animated else "webp"
        file_name = f"sticker_{sticker.file_id}.{file_extension}"
        await self._process_file(update, sticker, file_name, "image/webp")

    async def _process_file(self, update: Update, file_obj, file_name: str, mime_type: str):
        """Process and upload file to Google Drive."""
        try:
            # Send initial processing message
            processing_msg = await update.message.reply_text(
                f"📤 Processing your file: {file_name}\n"
                "Please wait while I upload it to Google Drive..."
            )

            # Get file from Telegram
            file = await file_obj.get_file()
            
            # Download file content
            file_content = BytesIO()
            await file.download_to_memory(file_content)
            file_content.seek(0)

            # Determine MIME type if not provided
            if not mime_type:
                mime_type, _ = mimetypes.guess_type(file_name)
                if not mime_type:
                    mime_type = 'application/octet-stream'

            # Upload to Google Drive
            file_id, download_link = self.drive_handler.upload_file(
                file_content.getvalue(),
                file_name,
                mime_type
            )

            # Format file size
            file_size = len(file_content.getvalue())
            size_mb = file_size / (1024 * 1024)
            size_str = f"{size_mb:.2f} MB" if size_mb >= 1 else f"{file_size / 1024:.2f} KB"

            # Send success message with download link
            success_message = (
                f"✅ File uploaded successfully!\n\n"
                f"📁 File: {file_name}\n"
                f"📊 Size: {size_str}\n"
                f"🔗 Download Link: {download_link}\n\n"
                f"💡 You can share this link with anyone to download the file directly."
            )

            await processing_msg.edit_text(success_message)

        except Exception as e:
            logger.error(f"Error processing file {file_name}: {str(e)}")
            error_message = (
                f"❌ Sorry, there was an error processing your file: {file_name}\n\n"
                f"Error: {str(e)}\n\n"
                "Please try again or contact support if the problem persists."
            )
            try:
                await processing_msg.edit_text(error_message)
            except:
                await update.message.reply_text(error_message)

    async def handle_text(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle text messages."""
        await update.message.reply_text(
            "📝 I can only process files, not text messages.\n\n"
            "Please send me a file (document, image, video, audio, etc.) "
            "and I'll upload it to Google Drive for you!"
        )

    def run(self):
        """Start the bot."""
        # Create the Application
        application = Application.builder().token(self.token).build()

        # Add handlers
        application.add_handler(CommandHandler("start", self.start))
        application.add_handler(CommandHandler("help", self.help_command))
        
        # File handlers
        application.add_handler(MessageHandler(filters.Document.ALL, self.handle_document))
        application.add_handler(MessageHandler(filters.PHOTO, self.handle_photo))
        application.add_handler(MessageHandler(filters.VIDEO, self.handle_video))
        application.add_handler(MessageHandler(filters.AUDIO, self.handle_audio))
        application.add_handler(MessageHandler(filters.VOICE, self.handle_voice))
        application.add_handler(MessageHandler(filters.VIDEO_NOTE, self.handle_video_note))
        application.add_handler(MessageHandler(filters.Sticker.ALL, self.handle_sticker))
        
        # Text handler (fallback)
        application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, self.handle_text))

        # Start the bot
        logger.info("Starting Telegram bot...")
        application.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == '__main__':
    bot = TelegramBot()
    bot.run()