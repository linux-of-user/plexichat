"""
Enhanced File Sharing Module for PlexiChat

Provides advanced file sharing features including:
- Drag-and-drop uploads
- File previews
- Sharing permissions
- File versioning
- Batch operations
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    from PIL import Image
except ImportError:
    Image = None

from plexichat.core.files.file_manager import FileManager, FileMetadata, file_manager

# Notification integration
notification_manager = None
try:
    from plexichat.core.notifications import notification_manager as nm

    notification_manager = nm
except ImportError:
    pass

logger = logging.getLogger(__name__)


@dataclass
class SharingPermissions:
    """File sharing permissions structure."""

    public: bool = False
    shared_with: List[int] = field(default_factory=list)
    can_download: bool = True
    can_share: bool = True


class EnhancedFileSharing:
    """Enhanced file sharing functionality."""

    def __init__(self, file_manager: FileManager):
        self.file_manager = file_manager

    async def share_file(
        self,
        file_id: str,
        user_id: int,
        shared_with: List[int],
        can_download: bool = True,
        can_share: bool = True,
    ) -> bool:
        """Share file with specific users."""
        try:
            metadata = await self.file_manager.get_file_metadata(file_id)
            if not metadata:
                return False

            # Check if user has permission to share
            if (
                metadata.uploaded_by != user_id
                and user_id not in metadata.sharing_permissions.get("shared_with", [])
            ):
                logger.warning(
                    f"User {user_id} attempted to share file {file_id} without permission"
                )
                return False

            # Update sharing permissions
            metadata.sharing_permissions = {
                "public": False,
                "shared_with": shared_with,
                "can_download": can_download,
                "can_share": can_share,
            }

            # Update in database
            if self.file_manager.db_manager:
                await self.file_manager.initialize()
                async with self.file_manager.db_manager.get_session() as session:
                    update_data = {
                        "sharing_permissions": json.dumps(metadata.sharing_permissions)
                    }
                    await session.update(
                        "files", update_data, where={"file_id": file_id}
                    )
                    await session.commit()

            # Clear cache
            if (
                self.file_manager.db_manager
                and hasattr(self.file_manager, "cache_delete")
                and self.file_manager.cache_delete
            ):
                await self.file_manager.cache_delete(f"file_{file_id}")

            # Send notifications to shared users
            await self._send_file_share_notifications(
                file_id, metadata, user_id, shared_with
            )

            logger.info(f"File {file_id} shared with users: {shared_with}")
            return True

        except Exception as e:
            logger.error(f"Error sharing file: {e}")
            return False

    async def _send_file_share_notifications(
        self,
        file_id: str,
        metadata: FileMetadata,
        sharer_id: int,
        shared_with: List[int],
    ):
        """Send notifications when files are shared."""
        try:
            if not notification_manager:
                return

            # Get sharer name (this would need to be implemented)
            sharer_name = f"User {sharer_id}"  # Placeholder

            for user_id in shared_with:
                try:
                    await notification_manager.create_notification(
                        user_id=user_id,
                        notification_type=notification_manager.NotificationType.INFO,
                        title=f"File shared with you",
                        message=f"{sharer_name} shared '{metadata.original_filename}' with you",
                        priority=notification_manager.NotificationPriority.NORMAL,
                        data={
                            "file_id": file_id,
                            "filename": metadata.original_filename,
                            "file_size": metadata.file_size,
                            "content_type": metadata.content_type,
                            "sharer_id": sharer_id,
                            "shared_at": datetime.now().isoformat(),
                        },
                    )
                except Exception as e:
                    logger.error(
                        f"Error creating file share notification for user {user_id}: {e}"
                    )

        except Exception as e:
            logger.error(f"Error sending file share notifications: {e}")

    async def create_file_version(
        self, file_id: str, user_id: int, new_file_data: bytes, filename: str
    ) -> Optional[FileMetadata]:
        """Create a new version of an existing file."""
        try:
            # Get original file metadata
            original_metadata = await self.file_manager.get_file_metadata(file_id)
            if not original_metadata:
                return None

            # Check permissions
            if original_metadata.uploaded_by != user_id:
                logger.warning(
                    f"User {user_id} attempted to version file {file_id} without permission"
                )
                return None

            # Upload new version
            new_metadata = await self.file_manager.upload_file(
                new_file_data, filename, user_id, tags=original_metadata.tags
            )

            if new_metadata:
                # Set version info
                new_metadata.version = original_metadata.version + 1
                new_metadata.parent_version_id = file_id

                # Update in database
                if self.file_manager.db_manager:
                    await self.file_manager.initialize()
                    async with self.file_manager.db_manager.get_session() as session:
                        update_data = {
                            "version": new_metadata.version,
                            "parent_version_id": new_metadata.parent_version_id,
                        }
                        await session.update(
                            "files",
                            update_data,
                            where={"file_id": new_metadata.file_id},
                        )
                        await session.commit()

                logger.info(
                    f"New version {new_metadata.version} created for file {file_id}"
                )
                return new_metadata

            return None

        except Exception as e:
            logger.error(f"Error creating file version: {e}")
            return None

    async def get_file_versions(self, file_id: str) -> List[FileMetadata]:
        """Get all versions of a file."""
        try:
            if not self.file_manager.db_manager:
                return []

            await self.file_manager.initialize()
            async with self.file_manager.db_manager.get_session() as session:
                # Get all versions in the chain
                versions = []
                current_id = file_id

                while current_id:
                    query = "SELECT * FROM files WHERE file_id = :file_id"
                    row = await session.fetchone(query, {"file_id": current_id})

                    if row:
                        metadata = FileMetadata(
                            file_id=row["file_id"],
                            filename=row["filename"],
                            original_filename=row["original_filename"],
                            file_path=row["file_path"],
                            file_size=row["file_size"],
                            content_type=row["content_type"],
                            checksum=row["checksum"],
                            uploaded_by=row["uploaded_by"],
                            uploaded_at=row["uploaded_at"],
                            is_public=bool(row["is_public"]),
                            tags=row["tags"].split(",") if row["tags"] else [],
                            metadata=(
                                json.loads(row["metadata"]) if row["metadata"] else {}
                            ),
                            sharing_permissions=(
                                json.loads(row["sharing_permissions"])
                                if row.get("sharing_permissions")
                                else {
                                    "public": False,
                                    "shared_with": [],
                                    "can_download": True,
                                    "can_share": True,
                                }
                            ),
                            version=row.get("version", 1),
                            parent_version_id=row.get("parent_version_id"),
                            preview_path=row.get("preview_path"),
                            thumbnail_path=row.get("thumbnail_path"),
                        )
                        versions.append(metadata)
                        current_id = row.get("parent_version_id")
                    else:
                        break

                return versions

        except Exception as e:
            logger.error(f"Error getting file versions: {e}")
            return []

    async def batch_delete_files(
        self, file_ids: List[str], user_id: int
    ) -> Dict[str, bool]:
        """Delete multiple files in batch."""
        results = {}
        for file_id in file_ids:
            results[file_id] = await self.file_manager.delete_file(file_id, user_id)
        return results

    async def check_file_access(self, file_id: str, user_id: int) -> Tuple[bool, str]:
        """Check if user has access to a file."""
        try:
            metadata = await self.file_manager.get_file_metadata(file_id)
            if not metadata:
                return False, "File not found"

            # Owner always has access
            if metadata.uploaded_by == user_id:
                return True, "Owner access"

            # Public files
            if metadata.is_public:
                return True, "Public access"

            # Check sharing permissions
            shared_with = metadata.sharing_permissions.get("shared_with", [])
            if user_id in shared_with:
                return True, "Shared access"

            return False, "Access denied"

        except Exception as e:
            logger.error(f"Error checking file access: {e}")
            return False, "Error checking access"

    def _generate_preview(self, file_path: Path, content_type: str) -> Optional[Path]:
        """Generate preview for documents and images."""
        try:
            if content_type.startswith("image/"):
                # For images, create a smaller preview
                if not Image:
                    return None

                preview_path = (
                    file_path.parent / f"{file_path.stem}_preview{file_path.suffix}"
                )
                with Image.open(file_path) as img:
                    # Create preview (max 800x600)
                    img.thumbnail((800, 600), Image.Resampling.LANCZOS)
                    img.save(preview_path, optimize=True, quality=90)
                return preview_path

            elif content_type == "application/pdf":
                # For PDFs, we could use a library like PyPDF2 or pdf2image
                # For now, just return None as PDF preview requires additional dependencies
                return None

            elif content_type.startswith("text/"):
                # For text files, we could create a text preview
                # For now, just return None
                return None

            return None

        except Exception as e:
            logger.error(f"Error generating preview: {e}")
            return None

    async def get_user_files(
        self, user_id: int, include_shared: bool = True
    ) -> List[FileMetadata]:
        """Get all files for a user (owned and shared)."""
        try:
            if not self.file_manager.db_manager:
                return []

            await self.file_manager.initialize()
            async with self.file_manager.db_manager.get_session() as session:
                files = []

                # Get owned files
                owned_query = "SELECT * FROM files WHERE uploaded_by = :user_id ORDER BY uploaded_at DESC"
                owned_rows = await session.fetchall(owned_query, {"user_id": user_id})

                for row in owned_rows:
                    metadata = FileMetadata(
                        file_id=row["file_id"],
                        filename=row["filename"],
                        original_filename=row["original_filename"],
                        file_path=row["file_path"],
                        file_size=row["file_size"],
                        content_type=row["content_type"],
                        checksum=row["checksum"],
                        uploaded_by=row["uploaded_by"],
                        uploaded_at=row["uploaded_at"],
                        is_public=bool(row["is_public"]),
                        tags=row["tags"].split(",") if row["tags"] else [],
                        metadata=json.loads(row["metadata"]) if row["metadata"] else {},
                        sharing_permissions=(
                            json.loads(row["sharing_permissions"])
                            if row.get("sharing_permissions")
                            else {
                                "public": False,
                                "shared_with": [],
                                "can_download": True,
                                "can_share": True,
                            }
                        ),
                        version=row.get("version", 1),
                        parent_version_id=row.get("parent_version_id"),
                        preview_path=row.get("preview_path"),
                        thumbnail_path=row.get("thumbnail_path"),
                    )
                    files.append(metadata)

                if include_shared:
                    # Get shared files (this would require a more complex query in a real implementation)
                    # For now, we'll skip this as it requires additional database schema
                    pass

                return files

        except Exception as e:
            logger.error(f"Error getting user files: {e}")
            return []


# Global enhanced file sharing instance
enhanced_file_sharing = EnhancedFileSharing(file_manager)


# Convenience functions
async def share_file(
    file_id: str, user_id: int, shared_with: List[int], **kwargs
) -> bool:
    """Share file using enhanced file sharing."""
    return await enhanced_file_sharing.share_file(
        file_id, user_id, shared_with, **kwargs
    )


async def create_file_version(
    file_id: str, user_id: int, new_file_data: bytes, filename: str
) -> Optional[FileMetadata]:
    """Create file version using enhanced file sharing."""
    return await enhanced_file_sharing.create_file_version(
        file_id, user_id, new_file_data, filename
    )


async def get_file_versions(file_id: str) -> List[FileMetadata]:
    """Get file versions using enhanced file sharing."""
    return await enhanced_file_sharing.get_file_versions(file_id)


async def batch_delete_files(file_ids: List[str], user_id: int) -> Dict[str, bool]:
    """Batch delete files using enhanced file sharing."""
    return await enhanced_file_sharing.batch_delete_files(file_ids, user_id)


async def check_file_access(file_id: str, user_id: int) -> Tuple[bool, str]:
    """Check file access using enhanced file sharing."""
    return await enhanced_file_sharing.check_file_access(file_id, user_id)


async def get_user_files(
    user_id: int, include_shared: bool = True
) -> List[FileMetadata]:
    """Get user files using enhanced file sharing."""
    return await enhanced_file_sharing.get_user_files(user_id, include_shared)
