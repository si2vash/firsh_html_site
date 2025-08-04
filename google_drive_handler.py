import os
import io
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
import logging

# If modifying these scopes, delete the file token.json.
SCOPES = ['https://www.googleapis.com/auth/drive.file']

logger = logging.getLogger(__name__)

class GoogleDriveHandler:
    def __init__(self, folder_id=None):
        self.folder_id = folder_id
        self.service = self._authenticate()

    def _authenticate(self):
        """Authenticate and return Google Drive service object."""
        creds = None
        
        # The file token.json stores the user's access and refresh tokens.
        if os.path.exists('token.json'):
            creds = Credentials.from_authorized_user_file('token.json', SCOPES)
        
        # If there are no (valid) credentials available, let the user log in.
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(
                    'credentials.json', SCOPES)
                creds = flow.run_local_server(port=0)
            
            # Save the credentials for the next run
            with open('token.json', 'w') as token:
                token.write(creds.to_json())

        service = build('drive', 'v3', credentials=creds)
        return service

    def upload_file(self, file_content, filename, mime_type):
        """Upload a file to Google Drive and return the file ID and download link."""
        try:
            # Create file metadata
            file_metadata = {
                'name': filename,
                'parents': [self.folder_id] if self.folder_id else []
            }

            # Create media upload object
            media = MediaIoBaseUpload(
                io.BytesIO(file_content),
                mimetype=mime_type,
                resumable=True
            )

            # Upload file
            file = self.service.files().create(
                body=file_metadata,
                media_body=media,
                fields='id'
            ).execute()

            file_id = file.get('id')
            logger.info(f"File uploaded successfully. File ID: {file_id}")

            # Make file publicly accessible
            self._make_file_public(file_id)

            # Generate download link
            download_link = f"https://drive.google.com/uc?id={file_id}&export=download"
            
            return file_id, download_link

        except Exception as error:
            logger.error(f"An error occurred while uploading file: {error}")
            raise

    def _make_file_public(self, file_id):
        """Make a file publicly accessible."""
        try:
            permission = {
                'type': 'anyone',
                'role': 'reader'
            }
            self.service.permissions().create(
                fileId=file_id,
                body=permission
            ).execute()
            logger.info(f"File {file_id} made publicly accessible")
        except Exception as error:
            logger.error(f"Error making file public: {error}")

    def get_file_info(self, file_id):
        """Get file information from Google Drive."""
        try:
            file = self.service.files().get(fileId=file_id, fields='name,size,mimeType').execute()
            return file
        except Exception as error:
            logger.error(f"Error getting file info: {error}")
            return None

    def delete_file(self, file_id):
        """Delete a file from Google Drive."""
        try:
            self.service.files().delete(fileId=file_id).execute()
            logger.info(f"File {file_id} deleted successfully")
            return True
        except Exception as error:
            logger.error(f"Error deleting file: {error}")
            return False