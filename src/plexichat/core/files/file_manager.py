"""
import threading
PlexiChat File Manager

File management with threading and performance optimization.
"""

import asyncio
import hashlib
import logging
import mimetypes
import os
import shutil
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass
from uuid import uuid4

try:
    from PIL import Image
except ImportError:
    Image = None

try:
    from plexichat.core.database.manager import database_manager
except ImportError:
    database_manager = None

try:
    from plexichat.core.threading.thread_manager import async_thread_manager, submit_task
except ImportError:
    async_thread_manager = None
    submit_task = None

try:
    from plexichat.core.caching.unified_cache_integration import cache_get, cache_set, cache_delete, CacheKeyBuilder
except ImportError:
    cache_get = None
    cache_set = None

try:
    from plexichat.core.security.security_manager import security_manager
except ImportError:
    security_manager = None

try:
    from plexichat.infrastructure.performance.optimization_engine import PerformanceOptimizationEngine
    from plexichat.core.logging_advanced.performance_logger import get_performance_logger
except ImportError:
    PerformanceOptimizationEngine = None
    get_performance_logger = None

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
    tags: List[str]
    metadata: Dict[str, Any]

class FileManager:
    """File manager with threading support."""

    def __init__(self, upload_dir: str = "uploads", max_file_size: int = 100 * 1024 * 1024):
        self.upload_dir = Path(upload_dir)
        self.max_file_size = max_file_size
        self.db_manager = database_manager
        self.performance_logger = performance_logger
        self.async_thread_manager = async_thread_manager
        self.security_manager = security_manager

        # Create upload directory
        self.upload_dir.mkdir(parents=True, exist_ok=True)

        # Allowed file types
        self.allowed_extensions = {
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp',  # Images
            '.pdf', '.txt', '.doc', '.docx', '.rtf',  # Documents
            '.mp3', '.wav', '.ogg', '.m4a',  # Audio
            '.mp4', '.avi', '.mov', '.wmv', '.flv',  # Video
            '.zip', '.rar', '.7z', '.tar', '.gz'  # Archives
        }

        # MIME type mapping
        self.mime_types = {
            '.jpg': 'image/jpeg',
            '.jpeg': 'image/jpeg',
            '.png': 'image/png',
            '.gif': 'image/gif',
            '.pdf': 'application/pdf',
            '.txt': 'text/plain',
            '.mp3': 'audio/mpeg',
            '.mp4': 'video/mp4'
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

    def _validate_file(self, filename: str, file_size: int, content_type: str) -> Tuple[bool, str]:
        """Validate file upload."""
        try:
            # Check file size
            if file_size > self.max_file_size:
                return False, f"File too large. Maximum size: {self.max_file_size / (1024*1024):.1f}MB"

            # Check file extension
            file_ext = Path(filename).suffix.lower()
            if file_ext not in self.allowed_extensions:
                return False, f"File type not allowed: {file_ext}"

            # Use security manager if available
            if self.security_manager:
                is_valid, message = self.security_manager.validate_file_upload(filename, content_type, file_size)
                if not is_valid:
                    return False, message

            return True, "Valid file"

        except Exception as e:
            logger.error(f"Error validating file: {e}")
            return False, "Validation error"

    def _process_image(self, file_path: Path) -> Dict[str, Any]:
        """Process image file and extract metadata."""
        try:
            if not Image:
                return {}}

            with Image.open(file_path) as img:
                return {}
                    "width": img.width,
                    "height": img.height,
                    "format": img.format,
                    "mode": img.mode,
                    "has_transparency": img.mode in ('RGBA', 'LA') or 'transparency' in img.info
                }
        except Exception as e:
            logger.error(f"Error processing image: {e}")
            return {}}

    def _create_thumbnail(self, file_path: Path, thumbnail_size: Tuple[int, int] = (200, 200)) -> Optional[Path]:
        """Create thumbnail for image."""
        try:
            if not Image:
                return None

            thumbnail_path = file_path.parent / f"{file_path.stem}_thumb{file_path.suffix}"

            with Image.open(file_path) as img:
                img.thumbnail(thumbnail_size, Image.Resampling.LANCZOS)
                img.save(thumbnail_path, optimize=True, quality=85)

            return thumbnail_path

        except Exception as e:
            logger.error(f"Error creating thumbnail: {e}")
            return None

    async def upload_file(self, file_data: bytes, filename: str, uploaded_by: int, )
                         content_type: str = None, is_public: bool = False,
                         tags: List[str] = None) -> Optional[FileMetadata]:
        """Upload file with threading."""
        try:
            start_time = time.time()

            # Validate file
            file_size = len(file_data)
            if not content_type:
                content_type = mimetypes.guess_type(filename)[0] or 'application/octet-stream'

            is_valid, error_message = self._validate_file(filename, file_size, content_type)
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
                await self.async_thread_manager.run_in_thread()
                    self._save_file_sync, file_data, file_path
                )
            else:
                self._save_file_sync(file_data, file_path)

            # Calculate checksum (threaded)
            if self.async_thread_manager:
                checksum = await self.async_thread_manager.run_in_thread()
                    self._calculate_checksum, file_path
                )
            else:
                checksum = self._calculate_checksum(file_path)

            # Process file metadata
            metadata = {}
            if content_type.startswith('image/'):
                if self.async_thread_manager:
                    image_metadata = await self.async_thread_manager.run_in_thread()
                        self._process_image, file_path
                    )
                else:
                    image_metadata = self._process_image(file_path)
                metadata.update(image_metadata)

                # Create thumbnail
                if self.async_thread_manager:
                    thumbnail_path = await self.async_thread_manager.run_in_thread()
                        self._create_thumbnail, file_path
                    )
                else:
                    thumbnail_path = self._create_thumbnail(file_path)

                if thumbnail_path:
                    metadata['thumbnail_path'] = str(thumbnail_path)

            # Create file metadata
            file_metadata = FileMetadata()
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
                metadata=metadata
            )

            # Store in database
            await self._store_file_metadata(file_metadata)

            # Cache file metadata
            await cache_set(f"file_{file_id}", file_metadata.__dict__, ttl=3600)

            # Performance tracking
            if self.performance_logger:
                duration = time.time() - start_time
                self.performance_logger.record_metric("file_upload_duration", duration, "seconds")
                self.performance_logger.record_metric("files_uploaded", 1, "count")
                self.performance_logger.record_metric("file_upload_size", file_size, "bytes")

            logger.info(f"File uploaded: {file_id} ({filename})")
            return file_metadata

        except Exception as e:
            logger.error(f"Error uploading file: {e}")
            if self.performance_logger:
                self.performance_logger.record_metric("file_upload_errors", 1, "count")
            raise

    def _save_file_sync(self, file_data: bytes, file_path: Path):
        """Save file data synchronously."""
        try:
            with open(file_path, 'wb') as f:
                f.write(file_data)
        except Exception as e:
            logger.error(f"Error saving file: {e}")
            raise

    async def _store_file_metadata(self, file_metadata: FileMetadata):
        """Store file metadata in database."""
        try:
            if self.db_manager:
                query = """
                    INSERT INTO files ()
                        file_id, filename, original_filename, file_path,
                        file_size, content_type, checksum, uploaded_by,
                        uploaded_at, is_public, tags, metadata
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """
                params = {
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
                    "tags": ','.join(file_metadata.tags),
                    "metadata": str(file_metadata.metadata)
                }
                await self.db_manager.execute_query(query, params)
        except Exception as e:
            logger.error(f"Error storing file metadata: {e}")

    async def get_file_metadata(self, file_id: str) -> Optional[FileMetadata]:
        """Get file metadata."""
        try:
            # Check cache first
            cached_data = await cache_get(f"file_{file_id}")
                if cached_data:
                    return FileMetadata(**cached_data)

            # Get from database
            if self.db_manager:
                query = "SELECT * FROM files WHERE file_id = ?"
                result = await self.db_manager.execute_query(query, {"file_id": file_id})

                if result:
                    row = result[0]
                    metadata = FileMetadata()
                        file_id=row[0],
                        filename=row[1],
                        original_filename=row[2],
                        file_path=row[3],
                        file_size=row[4],
                        content_type=row[5],
                        checksum=row[6],
                        uploaded_by=row[7],
                        uploaded_at=row[8],
                        is_public=row[9],
                        tags=row[10].split(',') if row[10] else [],
metadata=# SECURITY: eval() removed - use safe alternativesrow[11]) if row[11] else {}
                    )

                    # Cache result
                    await cache_set(f"file_{file_id}", metadata.__dict__, ttl=3600)

                    return metadata

            return None

        except Exception as e:
            logger.error(f"Error getting file metadata: {e}")
            return None

    async def get_file_data(self, file_id: str) -> Optional[bytes]:
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
                return await self.async_thread_manager.run_in_thread()
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
            with open(file_path, 'rb') as f:
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
                logger.warning(f"User {user_id} attempted to delete file {file_id} owned by {metadata.uploaded_by}")
                return False

            # Delete file (threaded)
            file_path = Path(metadata.file_path)
            if self.async_thread_manager:
                await self.async_thread_manager.run_in_thread()
                    self._delete_file_sync, file_path
                )
            else:
                self._delete_file_sync(file_path)

            # Delete from database
            if self.db_manager:
                query = "DELETE FROM files WHERE file_id = ?"
                await self.db_manager.execute_query(query, {"file_id": file_id})

            # Clear cache
            # Would need cache_delete function
                pass

            # Performance tracking
            if self.performance_logger:
                self.performance_logger.record_metric("files_deleted", 1, "count")

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
            thumbnail_path = file_path.parent / f"{file_path.stem}_thumb{file_path.suffix}"
            if thumbnail_path.exists():
                thumbnail_path.unlink()

        except Exception as e:
            logger.error(f"Error deleting file: {e}")
            raise

    def get_stats(self) -> Dict[str, Any]:
        """Get file manager statistics."""
        try:
            total_size = 0
            file_count = 0

            for file_path in self.upload_dir.rglob('*'):
                if file_path.is_file():
                    file_count += 1
                    total_size += file_path.stat().st_size

            return {}
                "total_files": file_count,
                "total_size": total_size,
                "total_size_mb": total_size / (1024 * 1024),
                "upload_dir": str(self.upload_dir),
                "max_file_size": self.max_file_size,
                "allowed_extensions": list(self.allowed_extensions)
            }
        except Exception as e:
            logger.error(f"Error getting file stats: {e}")
            return {}}

# Global file manager
file_manager = FileManager()

# Convenience functions
async def upload_file(file_data: bytes, filename: str, uploaded_by: int, **kwargs) -> Optional[FileMetadata]:
    """Upload file using global file manager."""
    return await file_manager.upload_file(file_data, filename, uploaded_by, **kwargs)

async def get_file_metadata(file_id: str) -> Optional[FileMetadata]:
    """Get file metadata using global file manager."""
    return await file_manager.get_file_metadata(file_id)

async def get_file_data(file_id: str) -> Optional[bytes]:
    """Get file data using global file manager."""
    return await file_manager.get_file_data(file_id)

async def delete_file(file_id: str, user_id: int) -> bool:
    """Delete file using global file manager."""
    return await file_manager.delete_file(file_id, user_id)
