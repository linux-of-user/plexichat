# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from sqlmodel import Session


from datetime import datetime


from fastapi import HTTPException, status

from plexichat.app.logger_config import logger
from plexichat.app.models.enhanced_models import FileRecord, Message, MessageType, User

# Define FilePermissionType enum
class FilePermissionType:
    READ = "read"
    WRITE = "write"
    DELETE = "delete"

try:
    from plexichat.app.services.file_permissions import FilePermissionService  # type: ignore
except ImportError:
    class FilePermissionService:
        def __init__(self, session):
            self.session = session

        async def check_file_access(self, user_id, file_id, permission_type):
            return {"has_access": True, "permission_source": "mock"}

"""
import time
Enhanced message service with file attachment and permission handling.
Validates file access when creating messages with embedded files.
"""

class MessageService:
    """Service for handling messages with file attachments and permissions."""

    def __init__(self, session: Session):
        self.session = session
        self.file_permission_service = FilePermissionService(session)

    async def create_message_with_files(
        self,
        sender_id: int,
        recipient_id: Optional[int] = None,
        channel_id: Optional[int] = None,
        guild_id: Optional[int] = None,
        content: Optional[str] = None,
        file_ids: Optional[List[int]] = None,
        message_type: MessageType = MessageType.DEFAULT,
        reply_to_id: Optional[int] = None,
        expires_after_seconds: Optional[int] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Message:
        """
        Create a message with file attachments, validating file permissions.
        """
        try:
            # Validate sender exists
            sender = self.session.get(User, sender_id)
            if not sender:
                raise HTTPException(status_code=404, detail="Sender not found")

            # Validate recipient if specified
            if recipient_id:
                recipient = self.session.get(User, recipient_id)
                if not recipient:
                    raise HTTPException(status_code=404, detail="Recipient not found")

            # Process file attachments
            attached_files = []
            embedded_files = []

            if file_ids:
                for file_id in file_ids:
                    # Check if sender has access to the file
                    has_access, error_message, access_context = await self.file_permission_service.check_file_access(
                        file_id, sender_id, FilePermissionType.READ, ip_address, user_agent
                    )

                    if not has_access:
                        logger.warning(f"User {sender_id} attempted to attach file {file_id} without permission: {error_message}")
                        raise HTTPException(
                            status_code=status.HTTP_403_FORBIDDEN,
                            detail=f"No permission to attach file {file_id}: {error_message}"
                        )

                    # Get file details for embedding
                    file_record = self.session.get(FileRecord, file_id)
                    if not file_record:
                        raise HTTPException(status_code=404, detail=f"File {file_id} not found")

                    attached_files.append(file_id)

                    # Create embed metadata
                    embed_info = {
                        "file_id": file_id,
                        "file_uuid": file_record.uuid,
                        "filename": file_record.filename,
                        "size": file_record.size,
                        "mime_type": file_record.mime_type,
                        "access_level": file_record.access_level.value,
                        "permission_source": access_context.get("permission_source") if access_context else "owner",
                        "attached_at": datetime.utcnow().isoformat()
                    }

                    # Add thumbnail for images
                    if file_record.mime_type and file_record.mime_type.startswith('image/'):
                        embed_info["thumbnail_url"] = f"/api/v1/files/thumbnail/{file_record.uuid}"

                    embedded_files.append(embed_info)

            # Calculate expiration time
            expires_at = None
            if expires_after_seconds:
                expires_at = datetime.utcnow() + timedelta(seconds=expires_after_seconds)

            # Create message
            message = Message(
                sender_id=sender_id,
                recipient_id=recipient_id,
                channel_id=channel_id,
                guild_id=guild_id,
                author_id=sender_id,  # For Discord-like compatibility
                content=content,
                type=message_type,
                referenced_message_id=reply_to_id,
                attached_files=attached_files,
                embedded_files=embedded_files,
                expires_at=expires_at,
                auto_delete_after=expires_after_seconds
            )

            self.session.add(message)
            self.session.commit()
            self.session.refresh(message)

            logger.info(f"Created message {message.id} with {len(attached_files)} file attachments")
            return message

        except HTTPException:
            raise
        except Exception as e:
            self.session.rollback()
            logger.error(f"Error creating message with files: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create message"
            )

    async def validate_message_file_access(
        self,
        message_id: int,
        user_id: int,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Validate user's access to all files in a message.
        Returns access status for each file.
        """
        try:
            message = self.session.get(Message, message_id)
            if not message:
                raise HTTPException(status_code=404, detail="Message not found")

            if not message.attached_files:
                return {"accessible_files": [], "inaccessible_files": []}

            accessible_files = []
            inaccessible_files = []

            for file_id in message.attached_files:
                has_access, error_message, access_context = await self.file_permission_service.check_file_access(
                    file_id, user_id, FilePermissionType.READ, ip_address, user_agent
                )

                file_record = self.session.get(FileRecord, file_id)
                if not file_record:
                    continue

                file_info = {
                    "file_id": file_id,
                    "file_uuid": file_record.uuid,
                    "filename": file_record.filename,
                    "size": file_record.size,
                    "mime_type": file_record.mime_type
                }

                if has_access:
                    file_info.update({
                        "download_url": f"/api/v1/files/download/{file_record.uuid}",
                        "permission_source": access_context.get("permission_source") if access_context else None
                    })
                    accessible_files.append(file_info)
                else:
                    file_info["error"] = error_message
                    inaccessible_files.append(file_info)

            return {
                "accessible_files": accessible_files,
                "inaccessible_files": inaccessible_files
            }

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error validating message file access: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to validate file access"
            )

    async def update_message(
        self,
        message_id: int,
        user_id: int,
        content: Optional[str] = None,
        add_file_ids: Optional[List[int]] = None,
        remove_file_ids: Optional[List[int]] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Message:
        """
        Update a message, including file attachments.
        Validates permissions for new files.
        """
        try:
            message = self.session.get(Message, message_id)
            if not message:
                raise HTTPException(status_code=404, detail="Message not found")

            # Check if user can edit this message
            if message.sender_id != user_id and message.author_id != user_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Cannot edit message from another user"
                )

            # Update content if provided
            if content is not None:
                message.content = content
                message.edited_timestamp = datetime.now()
                message.is_edited = True

            # Handle file additions
            if add_file_ids:
                current_files = message.attached_files or []
                current_embeds = message.embedded_files or []

                for file_id in add_file_ids:
                    if file_id in current_files:
                        continue  # Already attached

                    # Validate access to new file
                    has_access, error_message, access_context = await self.file_permission_service.check_file_access(
                        file_id, user_id, FilePermissionType.READ, ip_address, user_agent
                    )

                    if not has_access:
                        raise HTTPException(
                            status_code=status.HTTP_403_FORBIDDEN,
                            detail=f"No permission to attach file {file_id}: {error_message}"
                        )

                    # Get file details
                    file_record = self.session.get(FileRecord, file_id)
                    if not file_record:
                        raise HTTPException(status_code=404, detail=f"File {file_id} not found")

                    current_files.append(file_id)

                    # Add embed info
                    embed_info = {
                        "file_id": file_id,
                        "file_uuid": file_record.uuid,
                        "filename": file_record.filename,
                        "size": file_record.size,
                        "mime_type": file_record.mime_type,
                        "access_level": file_record.access_level.value,
                        "permission_source": access_context.get("permission_source") if access_context else "owner",
                        "attached_at": datetime.utcnow().isoformat()
                    }

                    if file_record.mime_type and file_record.mime_type.startswith('image/'):
                        embed_info["thumbnail_url"] = f"/api/v1/files/thumbnail/{file_record.uuid}"

                    current_embeds.append(embed_info)

                message.attached_files = current_files
                message.embedded_files = current_embeds

            # Handle file removals
            if remove_file_ids:
                current_files = message.attached_files or []
                current_embeds = message.embedded_files or []

                # Remove files
                message.attached_files = [f for f in current_files if f not in remove_file_ids]

                # Remove corresponding embeds
                message.embedded_files = [
                    e for e in current_embeds
                    if e.get("file_id") not in remove_file_ids
                ]

            self.session.commit()
            self.session.refresh(message)

            logger.info(f"Updated message {message_id}")
            return message

        except HTTPException:
            raise
        except Exception as e:
            self.session.rollback()
            logger.error(f"Error updating message: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update message"
            )

    async def delete_message(
        self,
        message_id: int,
        user_id: int,
        hard_delete: bool = False
    ) -> bool:
        """
        Delete a message (soft delete by default).
        """
        try:
            message = self.session.get(Message, message_id)
            if not message:
                raise HTTPException(status_code=404, detail="Message not found")

            # Check if user can delete this message
            if message.sender_id != user_id and message.author_id != user_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Cannot delete message from another user"
                )

            if hard_delete:
                self.session.delete(message)
            else:
                message.is_deleted = True
                message.content = "[Message deleted]"
                message.attached_files = []
                message.embedded_files = []

            self.session.commit()
            logger.info(f"Deleted message {message_id} (hard_delete={hard_delete})")
            return True

        except HTTPException:
            raise
        except Exception as e:
            self.session.rollback()
            logger.error(f"Error deleting message: {e}")
            return False
