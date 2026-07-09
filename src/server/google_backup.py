import json
import os
from datetime import datetime, timezone
from pathlib import Path
from io import BytesIO

from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload, MediaFileUpload

from server.gmail_oauth import decode_credentials
from server.repository import ScanRepository

class GoogleBackupService:
    def __init__(self, repository: ScanRepository = None):
        self.repository = repository or ScanRepository()

    def get_drive_service(self, user_id: str):
        record = self.repository.get_backup_token(user_id)
        if not record:
            return None
        creds = decode_credentials(record["token_blob"])
        return build("drive", "v3", credentials=creds)

    def find_or_create_backup_folder(self, drive_service) -> str:
        # Search for folder
        query = "mimeType = 'application/vnd.google-apps.folder' and name = 'SafeMail X_AI_Backup' and trashed = false"
        response = drive_service.files().list(q=query, spaces='drive', fields='files(id, name)').execute()
        files = response.get('files', [])
        if files:
            return files[0]['id']

        # Create folder
        file_metadata = {
            'name': 'SafeMail X_AI_Backup',
            'mimeType': 'application/vnd.google-apps.folder'
        }
        folder = drive_service.files().create(body=file_metadata, fields='id').execute()
        return folder.get('id')

    def find_or_create_subfolder(self, drive_service, parent_id: str, name: str) -> str:
        query = f"mimeType = 'application/vnd.google-apps.folder' and name = '{name}' and '{parent_id}' in parents and trashed = false"
        response = drive_service.files().list(q=query, spaces='drive', fields='files(id, name)').execute()
        files = response.get('files', [])
        if files:
            return files[0]['id']

        file_metadata = {
            'name': name,
            'mimeType': 'application/vnd.google-apps.folder',
            'parents': [parent_id]
        }
        folder = drive_service.files().create(body=file_metadata, fields='id').execute()
        return folder.get('id')

    def sync_scans_to_drive(self, user_id: str) -> dict:
        drive_service = self.get_drive_service(user_id)
        if not drive_service:
            raise ValueError("Google account not connected for cloud backup.")

        # 1. Get/Create Folder Structure
        folder_id = self.find_or_create_backup_folder(drive_service)
        reports_folder_id = self.find_or_create_subfolder(drive_service, folder_id, "Reports")

        # 2. Get local scans
        local_scans = self.repository.list_scans_detailed(user_id=user_id)
        local_scans_dict = {s["id"]: s for s in local_scans}

        # 3. Check for remote backup data
        remote_data = None
        remote_file_id = None
        
        query = f"name = 'safemailx_backup_data.json' and '{folder_id}' in parents and trashed = false"
        response = drive_service.files().list(q=query, spaces='drive', fields='files(id, name)').execute()
        files = response.get('files', [])
        
        if files:
            remote_file_id = files[0]['id']
            try:
                # Download remote data
                from googleapiclient.http import MediaIoBaseDownload
                file_content = BytesIO()
                request = drive_service.files().get_media(fileId=remote_file_id)
                downloader = MediaIoBaseDownload(file_content, request)
                done = False
                while not done:
                    _, done = downloader.next_chunk()
                
                file_content.seek(0)
                remote_data = json.loads(file_content.read().decode('utf-8'))
            except Exception as e:
                print(f"Error downloading remote backup file: {e}")

        # 4. Bidirectional Merge
        restored_count = 0
        uploaded_count = 0

        if remote_data and isinstance(remote_data, dict):
            remote_scans = remote_data.get("scans", [])
            for r_scan in remote_scans:
                rid = r_scan.get("id")
                if not rid:
                    continue
                # If remote scan doesn't exist locally, restore it!
                if rid not in local_scans_dict:
                    self.repository.upsert_scan_detailed(r_scan)
                    local_scans_dict[rid] = r_scan
                    restored_count += 1
                else:
                    # Sync local reference
                    pass

        # 5. Compile merged dataset
        final_scans = list(local_scans_dict.values())
        
        stats = {
            "total_scans": len(final_scans),
            "legitimate": sum(1 for s in final_scans if s["final_label"] == "legitimate"),
            "suspicious": sum(1 for s in final_scans if s["final_label"] == "suspicious"),
            "phishing": sum(1 for s in final_scans if s["final_label"] == "phishing"),
        }

        backup_payload = {
            "backup_version": 1,
            "last_updated": datetime.now(timezone.utc).isoformat(),
            "user_id": user_id,
            "stats": stats,
            "scans": final_scans
        }

        # 6. Save back to Google Drive
        json_data = json.dumps(backup_payload, indent=2).encode('utf-8')
        media = MediaIoBaseUpload(BytesIO(json_data), mimetype='application/json', resumable=True)

        if remote_file_id:
            # Update existing backup file
            drive_service.files().update(
                fileId=remote_file_id,
                media_body=media
            ).execute()
        else:
            # Create new backup file
            file_metadata = {
                'name': 'safemailx_backup_data.json',
                'parents': [folder_id]
            }
            drive_service.files().create(
                body=file_metadata,
                media_body=media
            ).execute()

        # 7. Backup individual PDF files under "Reports/" subfolder
        pdf_uploaded_count = 0
        for scan in final_scans:
            pdf_path_str = scan.get("report_pdf")
            if not pdf_path_str:
                continue
            
            pdf_path = Path(pdf_path_str)
            if not pdf_path.exists():
                continue

            # Standardized PDF name on Google Drive
            # Example: "2026-05-26 - Urgent Account Warning - phishing.pdf"
            date_prefix = scan["created_at"][:10]
            clean_subject = scan["subject"].replace("/", "_").replace("\\", "_")
            gdrive_filename = f"{date_prefix} - {clean_subject} - {scan['final_label']}.pdf"

            # Check if PDF already exists in Reports folder
            pdf_query = f"name = '{gdrive_filename}' and '{reports_folder_id}' in parents and trashed = false"
            pdf_response = drive_service.files().list(q=pdf_query, spaces='drive', fields='files(id, name)').execute()
            pdf_files = pdf_response.get('files', [])

            if not pdf_files:
                try:
                    pdf_media = MediaFileUpload(str(pdf_path), mimetype='application/pdf')
                    pdf_metadata = {
                        'name': gdrive_filename,
                        'parents': [reports_folder_id]
                    }
                    drive_service.files().create(
                        body=pdf_metadata,
                        media_body=pdf_media
                    ).execute()
                    pdf_uploaded_count += 1
                except Exception as ex:
                    print(f"Failed to upload report PDF for scan {scan['id']}: {ex}")

        # Update last sync timestamp in the database
        self.repository.update_backup_sync_time(user_id)

        return {
            "status": "success",
            "stats": stats,
            "restored_count": restored_count,
            "pdf_uploaded_count": pdf_uploaded_count,
            "last_sync": datetime.now(timezone.utc).isoformat()
        }
