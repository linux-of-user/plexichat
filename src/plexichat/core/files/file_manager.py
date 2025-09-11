
"""
PlexiChat File Manager

File management with threading and performance optimization.
"""


from dataclasses import dataclass, field
from datetime import datetime
import hashlib
import json
import logging
import mimetypes
from pathlib import Path
import time
from typing import Any
from uuid import uuid4

try:
    from PIL import Image
except ImportError:
    Image = None

try:
    from plexichat.core.database.manager import DatabaseSession, database_manager
except ImportError:
    database_manager = None
    DatabaseSession = None

try:
    from plexichat.core.threading.thread_manager import (
        async_thread_manager,
        submit_task,
    )
except ImportError:
    async_thread_manager = None
    submit_task = None

try:
    from plexichat.core.caching.unified_cache_integration import (
        CacheKeyBuilder,
        cache_delete,
        cache_get,
        cache_set,
    )
except ImportError:
    cache_get = None
    cache_set = None
    cache_delete = None

try:
    from plexichat.core.security import security_manager
except ImportError:
    security_manager = None

try:
    from plexichat.core.logging import (
        MetricType,  # type: ignore
        get_performance_logger,
    )
    from plexichat.core.performance.optimization_engine import (
        PerformanceOptimizationEngine,
    )
except ImportError:
    PerformanceOptimizationEngine = None
    get_performance_logger = None
    MetricType = None

# Notification integration
notification_manager = None
try:
    from plexichat.core.notifications import notification_manager as nm

    notification_manager = nm
except ImportError:
    pass

logger = logging.getLogger(__name__)
performance_logger = get_performance_logger() if get_performance_logger else None


@dataclass
class FileMetadata:
    """File metadata structure."""

    file_id: str
    filename: str
    original_filename: str
    file_path: str
    file_size: int
    content_type: str
    checksum: str
    uploaded_by: int
    uploaded_at: datetime
    is_public: bool
    tags: list[str]
    metadata: dict[str, Any]
    # Enhanced sharing fields
    sharing_permissions: dict[str, Any] = field(
        default_factory=lambda: {
            "public": False,
            "shared_with": [],
            "can_download": True,
            "can_share": True,
        }
    )
    version: int = 1
    parent_version_id: str | None = None
    preview_path: str | None = None
    thumbnail_path: str | None = None


class FileManager:
    """File manager with threading support."""

    def __init__(
        self, upload_dir: str = "uploads", max_file_size: int = 100 * 1024 * 1024
    ):
        self.upload_dir = Path(upload_dir)
        self.max_file_size = max_file_size
        self.db_manager = database_manager
        self.performance_logger = performance_logger
        self.async_thread_manager = async_thread_manager
        self.security_manager = security_manager
        self._db_initialized = False

        # Create upload directory
        self.upload_dir.mkdir(parents=True, exist_ok=True)

        # Allowed file types
        self.allowed_extensions = {
            ".jpg",
            ".jpeg",
            ".png",
            ".gif",
            ".bmp",
            ".webp",  # Images
            ".pdf",
            ".txt",
            ".doc",
            ".docx",
            ".rtf",  # Documents
            ".mp3",
            ".wav",
            ".ogg",
            ".m4a",  # Audio
            ".mp4",
            ".avi",
            ".mov",
            ".wmv",
            ".flv",  # Video
            ".zip",
            ".rar",
            ".7z",
            ".tar",
            ".gz",  # Archives
        }

        # MIME type mapping
        self.mime_types = {
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".png": "image/png",
            ".gif": "image/gif",
            ".pdf": "application/pdf",
            ".txt": "text/plain",
            ".mp3": "audio/mpeg",
            ".mp4": "video/mp4",
        }

    def _generate_file_id(self) -> str:
        """Generate unique file ID."""
        return str(uuid4())

    def _generate_file_path(self, file_id: str, extension: str) -> Path:
        """Generate file path with directory structure."""
        # Create subdirectories based on file ID for better organization
        subdir = file_id[:2]
        return self.upload_dir / subdir / f"{file_id}{extension}"

    def _calculate_checksum(self, file_path: Path) -> str:
        """Calculate file checksum."""
        try:
            hash_md5 = hashlib.md5()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except Exception as e:
            logger.error(f"Error calculating checksum: {e}")
            return ""

    def _validate_file(
        self, filename: str, file_size: int, content_type: str
    ) -> tuple[bool, str]:
        """Validate file upload."""
        try:
            # Check file size
            if file_size > self.max_file_size:
                return (
                    False,
                    f"File too large. Maximum size: {self.max_file_size / (1024*1024):.1f}MB",
                )

            # Check file extension
            file_ext = Path(filename).suffix.lower()
            if file_ext not in self.allowed_extensions:
                return False, f"File type not allowed: {file_ext}"

            # Use security manager if available
            if self.security_manager:
                is_valid, message = self.security_manager.validate_file_upload(
                    filename, content_type, file_size
                )
                if not is_valid:
                    return False, message

            return True, "Valid file"

        except Exception as e:
            logger.error(f"Error validating file: {e}")
            return False, "Validation error"

    def _process_image(self, file_path: Path) -> dict[str, Any]:
        """Process image file and extract metadata."""
        try:
            if not Image:
                return {}

            with Image.open(file_path) as img:
                return {
                    "width": img.width,
                    "height": img.height,
                    "format": img.format,
                    "mode": img.mode,
                    "has_transparency": img.mode in ("RGBA", "LA")
                    or "transparency" in img.info,
                }
        except Exception as e:
            logger.error(f"Error processing image: {e}")
            return {}

    def _create_thumbnail(
        self, file_path: Path, thumbnail_size: tuple[int, int] = (200, 200)
    ) -> Path | None:
        """Create thumbnail for image."""
        try:
            if not Image:
                return None

            thumbnail_path = (
                file_path.parent / f"{file_path.stem}_thumb{file_path.suffix}"
            )

            with Image.open(file_path) as img:
                img.thumbnail(thumbnail_size, Image.Resampling.LANCZOS)
                img.save(thumbnail_path, optimize=True, quality=85)

            return thumbnail_path

        except Exception as e:
            logger.error(f"Error creating thumbnail: {e}")
            return None

    async def initialize(self):
        """Initialize the file manager and ensure database table exists."""
        if self._db_initialized or not self.db_manager:
            return

        schema = {
            "file_id": "TEXT PRIMARY KEY",
            "filename": "TEXT NOT NULL",
            "original_filename": "TEXT NOT NULL",
            "file_path": "TEXT NOT NULL",
            "file_size": "INTEGER NOT NULL",
            "content_type": "TEXT",
            "checksum": "TEXT",
            "uploaded_by": "INTEGER NOT NULL",
            "uploaded_at": "TIMESTAMP NOT NULL",
            "is_public": "BOOLEAN NOT NULL DEFAULT 0",
            "tags": "TEXT",
            "metadata": "TEXT",
            # Enhanced sharing fields
            "sharing_permissions": "TEXT",
            "version": "INTEGER DEFAULT 1",
            "parent_version_id": "TEXT",
            "preview_path": "TEXT",
            "thumbnail_path": "TEXT",
        }
        try:
            await self.db_manager.ensure_table_exists("files", schema)
            self._db_initialized = True
            logger.info("File manager database table 'files' initialized.")
        except Exception as e:
            logger.error(f"Failed to initialize 'files' table: {e}")
            self._db_initialized = False

    async def upload_file(
        self,
        file_data: bytes,
        filename: str,
        uploaded_by: int,
        content_type: str | None = None,
        is_public: bool = False,
        tags: list[str] | None = None,
    ) -> FileMetadata | None:
        """Upload file with threading."""
        try:
            start_time = time.time()

            # Validate file
            file_size = len(file_data)
            if not content_type:
                content_type = (
                    mimetypes.guess_type(filename)[0] or "application/octet-stream"
                )

            is_valid, error_message = self._validate_file(
                filename, file_size, content_type
            )
            if not is_valid:
                raise ValueError(error_message)

            # Generate file metadata
            file_id = self._generate_file_id()
            file_ext = Path(filename).suffix.lower()
            file_path = self._generate_file_path(file_id, file_ext)

            # Create directory if needed
            file_path.parent.mkdir(parents=True, exist_ok=True)

            # Save file (threaded)
            if self.async_thread_manager:
                await self.async_thread_manager.run_in_thread(
                    self._save_file_sync, file_data, file_path
                )
            else:
                self._save_file_sync(file_data, file_path)

            # Calculate checksum (threaded)
            if self.async_thread_manager:
                checksum = await self.async_thread_manager.run_in_thread(
                    self._calculate_checksum, file_path
                )
            else:
                checksum = self._calculate_checksum(file_path)

            # Process file metadata
            metadata = {}
            if content_type.startswith("image/"):
                if self.async_thread_manager:
                    image_metadata = await self.async_thread_manager.run_in_thread(
                        self._process_image, file_path
                    )
                else:
                    image_metadata = self._process_image(file_path)
                metadata.update(image_metadata)

                # Create thumbnail
                if self.async_thread_manager:
                    thumbnail_path = await self.async_thread_manager.run_in_thread(
                        self._create_thumbnail, file_path
                    )
                else:
                    thumbnail_path = self._create_thumbnail(file_path)

                if thumbnail_path:
                    metadata["thumbnail_path"] = str(thumbnail_path)

            # Create file metadata object
            file_metadata = FileMetadata(
                file_id=file_id,
                filename=f"{file_id}{file_ext}",
                original_filename=filename,
                file_path=str(file_path),
                file_size=file_size,
                content_type=content_type,
                checksum=checksum,
                uploaded_by=uploaded_by,
                uploaded_at=datetime.now(),
                is_public=is_public,
                tags=tags or [],
                metadata=metadata,
            )

            # Store in database
            await self._store_file_metadata(file_metadata)

            # Cache file metadata if cache is available
            if cache_set:
                await cache_set(f"file_{file_id}", file_metadata.__dict__, ttl=3600)

            # Trigger file upload notification
            await self._send_file_upload_notification(file_metadata)

            # Performance tracking
            if self.performance_logger:
                duration = time.time() - start_time
                self.performance_logger.record_timer("file_upload_duration", duration)
                self.performance_logger.increment_counter("files_uploaded", 1)
                self.performance_logger.set_gauge("file_upload_size", file_size)

            logger.info(f"File uploaded: {file_id} ({filename})")
            return file_metadata

        except Exception as e:
            logger.error(f"Error uploading file: {e}")
            if self.performance_logger:
                self.performance_logger.increment_counter("file_upload_errors", 1)
            raise

    async def _send_file_upload_notification(self, file_metadata: FileMetadata):
        """Send notification when a file is uploaded."""
        try:
            if not notification_manager:
                return

            # Create notification for the uploader (confirmation)
            await notification_manager.create_notification(
                user_id=file_metadata.uploaded_by,
                notification_type=notification_manager.NotificationType.INFO,
                title="File uploaded successfully",
                message=f"Your file '{file_metadata.original_filename}' has been uploaded successfully",
                priority=notification_manager.NotificationPriority.LOW,
                data={
                    "file_id": file_metadata.file_id,
                    "filename": file_metadata.original_filename,
                    "file_size": file_metadata.file_size,
                    "content_type": file_metadata.content_type,
                    "uploaded_at": file_metadata.uploaded_at.isoformat(),
                },
            )

        except Exception as e:
            logger.error(f"Error sending file upload notification: {e}")

    def _save_file_sync(self, file_data: bytes, file_path: Path):
        """Save file data synchronously."""
        try:
            with open(file_path, "wb") as f:
                f.write(file_data)
        except Exception as e:
            logger.error(f"Error saving file: {e}")
            raise

    async def _store_file_metadata(self, file_metadata: FileMetadata):
        """Store file metadata in the database."""
        if not self.db_manager:
            return
        try:
            await self.initialize()  # Ensure table exists
            async with self.db_manager.get_session() as session:
                insert_data = {
                    "file_id": file_metadata.file_id,
                    "filename": file_metadata.filename,
                    "original_filename": file_metadata.original_filename,
                    "file_path": file_metadata.file_path,
                    "file_size": file_metadata.file_size,
                    "content_type": file_metadata.content_type,
                    "checksum": file_metadata.checksum,
                    "uploaded_by": file_metadata.uploaded_by,
                    "uploaded_at": file_metadata.uploaded_at,
                    "is_public": file_metadata.is_public,
                    "tags": ",".join(file_metadata.tags),
                    "metadata": json.dumps(file_metadata.metadata),
                }
                await session.insert("files", insert_data)
                await session.commit()
        except Exception as e:
            logger.error(f"Error storing file metadata: {e}")
            raise

    async def get_file_metadata(self, file_id: str) -> FileMetadata | None:
        """Get file metadata."""
        try:
            # Check cache first
            if cache_get:
                cached_data = await cache_get(f"file_{file_id}")
                if cached_data:
                    return FileMetadata(**cached_data)

            # Get from database
            if not self.db_manager:
                return None

            await self.initialize()
            async with self.db_manager.get_session() as session:
                query = "SELECT * FROM files WHERE file_id = :file_id"
                row = await session.fetchone(query, {"file_id": file_id})

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
                        metadata=json.loads(row["metadata"]) if row["metadata"] else {},
                    )

                    # Cache result
                    if cache_set:
                        await cache_set(f"file_{file_id}", metadata.__dict__, ttl=3600)
                    return metadata
            return None
        except Exception as e:
            logger.error(f"Error getting file metadata for {file_id}: {e}")
            return None

    async def get_file_data(self, file_id: str) -> bytes | None:
        """Get file data."""
        try:
            metadata = await self.get_file_metadata(file_id)
            if not metadata:
                return None

            file_path = Path(metadata.file_path)
            if not file_path.exists():
                logger.error(f"File not found: {file_path}")
                return None

            # Read file (threaded)
            if self.async_thread_manager:
                return await self.async_thread_manager.run_in_thread(
                    self._read_file_sync, file_path
                )
            else:
                return self._read_file_sync(file_path)

        except Exception as e:
            logger.error(f"Error getting file data: {e}")
            return None

    def _read_file_sync(self, file_path: Path) -> bytes:
        """Read file data synchronously."""
        try:
            with open(file_path, "rb") as f:
                return f.read()
        except Exception as e:
            logger.error(f"Error reading file: {e}")
            raise

    async def delete_file(self, file_id: str, user_id: int) -> bool:
        """Delete file."""
        try:
            metadata = await self.get_file_metadata(file_id)
            if not metadata:
                return False

            # Check permissions
            if metadata.uploaded_by != user_id:
                logger.warning(
                    f"User {user_id} attempted to delete file {file_id} owned by {metadata.uploaded_by}"
                )
                return False

            # Delete file (threaded)
            file_path = Path(metadata.file_path)
            if self.async_thread_manager:
                await self.async_thread_manager.run_in_thread(
                    self._delete_file_sync, file_path
                )
            else:
                self._delete_file_sync(file_path)

            # Delete from database
            if self.db_manager:
                await self.initialize()
                async with self.db_manager.get_session() as session:
                    await session.delete("files", where={"file_id": file_id})
                    await session.commit()

            # Clear cache
            if cache_delete:
                await cache_delete(f"file_{file_id}")

            # Performance tracking
            if self.performance_logger:
                self.performance_logger.increment_counter("files_deleted", 1)

            logger.info(f"File deleted: {file_id}")
            return True

        except Exception as e:
            logger.error(f"Error deleting file: {e}")
            return False

    def _delete_file_sync(self, file_path: Path):
        """Delete file synchronously."""
        try:
            if file_path.exists():
                file_path.unlink()

            # Delete thumbnail if exists
            thumbnail_path = (
                file_path.parent / f"{file_path.stem}_thumb{file_path.suffix}"
            )
            if thumbnail_path.exists():
                thumbnail_path.unlink()

        except Exception as e:
            logger.error(f"Error deleting file: {e}")
            raise

    def get_stats(self) -> dict[str, Any]:
        """Get file manager statistics."""
        try:
            total_size = 0
            file_count = 0

            for file_path in self.upload_dir.rglob("*"):
                if file_path.is_file():
                    file_count += 1
                    total_size += file_path.stat().st_size

            return {
                "total_files": file_count,
                "total_size": total_size,
                "total_size_mb": total_size / (1024 * 1024),
                "upload_dir": str(self.upload_dir),
                "max_file_size": self.max_file_size,
                "allowed_extensions": list(self.allowed_extensions),
            }
        except Exception as e:
            logger.error(f"Error getting file stats: {e}")
            return {}


# Global file manager
file_manager = FileManager()


# Convenience functions
async def initialize_file_manager():
    """Initialize the global file manager instance."""
    await file_manager.initialize()


async def upload_file(
    file_data: bytes, filename: str, uploaded_by: int, **kwargs
) -> FileMetadata | None:
    """Upload file using global file manager."""
    return await file_manager.upload_file(file_data, filename, uploaded_by, **kwargs)


async def get_file_metadata(file_id: str) -> FileMetadata | None:
    """Get file metadata using global file manager."""
    return await file_manager.get_file_metadata(file_id)


async def get_file_data(file_id: str) -> bytes | None:
    """Get file data using global file manager."""
    return await file_manager.get_file_data(file_id)


async def delete_file(file_id: str, user_id: int) -> bool:
    """Delete file using global file manager."""

    async def share_file(
        self,
        file_id: str,
        user_id: int,
        shared_with: list[int],
        can_download: bool = True,
        can_share: bool = True,
    ) -> bool:
        """Share file with specific users."""
        try:
            metadata = await self.get_file_metadata(file_id)
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
            if self.db_manager:
                await self.initialize()
                async with self.db_manager.get_session() as session:
                    update_data = {
                        "sharing_permissions": json.dumps(metadata.sharing_permissions)
                    }
                    await session.update(
                        "files", update_data, where={"file_id": file_id}
                    )
                    await session.commit()

            # Clear cache
            if cache_delete:
                await cache_delete(f"file_{file_id}")

            logger.info(f"File {file_id} shared with users: {shared_with}")
            return True

        except Exception as e:
            logger.error(f"Error sharing file: {e}")
            return False

    async def create_file_version(
        self, file_id: str, user_id: int, new_file_data: bytes, filename: str
    ) -> FileMetadata | None:
        """Create a new version of an existing file."""
        try:
            # Get original file metadata
            original_metadata = await self.get_file_metadata(file_id)
            if not original_metadata:
                return None

            # Check permissions
            if original_metadata.uploaded_by != user_id:
                logger.warning(
                    f"User {user_id} attempted to version file {file_id} without permission"
                )
                return None

            # Upload new version
            new_metadata = await self.upload_file(
                new_file_data, filename, user_id, tags=original_metadata.tags
            )

            if new_metadata:
                # Set version info
                new_metadata.version = original_metadata.version + 1
                new_metadata.parent_version_id = file_id

                # Update in database
                if self.db_manager:
                    await self.initialize()
                    async with self.db_manager.get_session() as session:
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

    async def get_file_versions(self, file_id: str) -> list[FileMetadata]:
        """Get all versions of a file."""
        try:
            if not self.db_manager:
                return []

            await self.initialize()
            async with self.db_manager.get_session() as session:
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
        self, file_ids: list[str], user_id: int
    ) -> dict[str, bool]:
        """Delete multiple files in batch."""
        results = {}
        for file_id in file_ids:
            results[file_id] = await self.delete_file(file_id, user_id)
        return results

    async def check_file_access(self, file_id: str, user_id: int) -> tuple[bool, str]:
        """Check if user has access to a file."""
        try:
            metadata = await self.get_file_metadata(file_id)
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

    def _generate_preview(self, file_path: Path, content_type: str) -> Path | None:
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
    ) -> list[FileMetadata]:
        """Get all files for a user (owned and shared)."""
        try:
            if not self.db_manager:
                return []

            await self.initialize()
            async with self.db_manager.get_session() as session:
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


# Update convenience functions
async def share_file(
    file_id: str, user_id: int, shared_with: list[int], **kwargs
) -> bool:
    """Share file using global file manager."""
    return await file_manager.share_file(file_id, user_id, shared_with, **kwargs)


async def create_file_version(
    file_id: str, user_id: int, new_file_data: bytes, filename: str
) -> FileMetadata | None:
    """Create file version using global file manager."""
    return await file_manager.create_file_version(
        file_id, user_id, new_file_data, filename
    )


async def get_file_versions(file_id: str) -> list[FileMetadata]:
    """Get file versions using global file manager."""
    return await file_manager.get_file_versions(file_id)


async def batch_delete_files(file_ids: list[str], user_id: int) -> dict[str, bool]:
    """Batch delete files using global file manager."""
    return await file_manager.batch_delete_files(file_ids, user_id)


async def check_file_access(file_id: str, user_id: int) -> tuple[bool, str]:
    """Check file access using global file manager."""
    return await file_manager.check_file_access(file_id, user_id)


async def get_user_files(
    user_id: int, include_shared: bool = True
) -> list[FileMetadata]:
    """Get user files using global file manager."""
    return await file_manager.get_user_files(user_id, include_shared)
    return await file_manager.delete_file(file_id, user_id)
