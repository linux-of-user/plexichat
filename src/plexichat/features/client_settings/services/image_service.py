"""
PlexiChat Client Settings Image Service
======================================

Service for handling image uploads, storage, and management for client settings.
"""

import os
import uuid
import shutil
import logging
from typing import Dict, List, Optional, Tuple, BinaryIO
from datetime import datetime
from PIL import Image
import aiofiles

# Configuration
try:
    from plexichat.core.config.client_settings_config import get_client_settings_config
except ImportError:
    get_client_settings_config = lambda: None

# Repository
from ..repositories.client_settings_repository import ClientSettingsRepository
from ..models.client_settings import ClientSettingImageResponse, ImageStatus

logger = logging.getLogger(__name__)

class ImageService:
    """Service for managing client setting images."""
    
    def __init__(self, repository: ClientSettingsRepository):
        """Initialize image service."""
        self.repository = repository
        self.config = get_client_settings_config()
    
    async def upload_image(
        self, 
        user_id: str, 
        file_content: bytes, 
        filename: str, 
        mime_type: str,
        setting_key: Optional[str] = None,
        description: Optional[str] = None,
        alt_text: Optional[str] = None
    ) -> ClientSettingImageResponse:
        """Upload and store an image."""
        try:
            # Validate file
            self._validate_image_upload(file_content, filename, mime_type)
            
            # Check user limits
            if not await self._check_upload_limits(user_id, len(file_content)):
                raise ValueError("Upload would exceed user limits")
            
            # Generate unique filename
            file_ext = os.path.splitext(filename)[1].lower()
            stored_filename = f"{uuid.uuid4()}{file_ext}"
            
            # Get user image directory
            user_image_dir = self._get_user_image_directory(user_id)
            file_path = os.path.join(user_image_dir, stored_filename)
            
            # Save file
            async with aiofiles.open(file_path, 'wb') as f:
                await f.write(file_content)
            
            # Get image dimensions
            width, height = self._get_image_dimensions(file_path)
            
            # Create database record
            image_data = {
                'setting_key': setting_key,
                'original_filename': filename,
                'stored_filename': stored_filename,
                'file_path': file_path,
                'mime_type': mime_type,
                'file_size': len(file_content),
                'width': width,
                'height': height,
                'description': description,
                'alt_text': alt_text
            }
            
            image_record = await self.repository.create_image_record(user_id, image_data)
            
            logger.info(f"Image uploaded successfully: {image_record.id} for user {user_id}")
            return image_record
            
        except Exception as e:
            logger.error(f"Error uploading image: {e}")
            # Clean up file if it was created
            try:
                if 'file_path' in locals() and os.path.exists(file_path):
                    os.remove(file_path)
            except:
                pass
            raise
    
    async def get_image_file(self, user_id: str, image_id: str) -> Tuple[Optional[bytes], Optional[str]]:
        """Get image file content and mime type."""
        try:
            # Get image record
            image_record = await self.repository.get_image(user_id, image_id)
            if not image_record:
                return None, None
            
            # Check if file exists
            if not os.path.exists(image_record.file_path):
                logger.warning(f"Image file not found: {image_record.file_path}")
                return None, None
            
            # Read file
            async with aiofiles.open(image_record.file_path, 'rb') as f:
                content = await f.read()
            
            return content, image_record.mime_type
            
        except Exception as e:
            logger.error(f"Error getting image file: {e}")
            return None, None
    
    async def delete_image(self, user_id: str, image_id: str) -> bool:
        """Delete an image."""
        try:
            # Get image record
            image_record = await self.repository.get_image(user_id, image_id)
            if not image_record:
                return False
            
            # Mark as deleted in database
            deleted = await self.repository.delete_image(user_id, image_id)
            
            if deleted:
                # Delete physical file
                try:
                    if os.path.exists(image_record.file_path):
                        os.remove(image_record.file_path)
                        logger.info(f"Deleted image file: {image_record.file_path}")
                except Exception as e:
                    logger.warning(f"Could not delete image file {image_record.file_path}: {e}")
                
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error deleting image: {e}")
            return False
    
    async def update_image_metadata(
        self, 
        user_id: str, 
        image_id: str, 
        setting_key: Optional[str] = None,
        description: Optional[str] = None,
        alt_text: Optional[str] = None
    ) -> Optional[ClientSettingImageResponse]:
        """Update image metadata."""
        try:
            # This would require an update method in the repository
            # For now, we'll return the existing image
            return await self.repository.get_image(user_id, image_id)
        except Exception as e:
            logger.error(f"Error updating image metadata: {e}")
            return None
    
    async def get_user_storage_stats(self, user_id: str) -> Dict[str, any]:
        """Get user's image storage statistics."""
        try:
            stats = await self.repository.get_user_stats(user_id)
            
            # Add additional storage info
            if self.config:
                stats['limits'] = {
                    'max_images': self.config.limits.max_images_per_user,
                    'max_total_storage_mb': self.config.limits.max_total_storage_mb,
                    'max_image_size_mb': self.config.limits.max_image_size_mb
                }
                
                stats['remaining'] = {
                    'images': max(0, self.config.limits.max_images_per_user - stats['total_images']),
                    'storage_mb': max(0, self.config.limits.max_total_storage_mb - stats['total_storage_used_mb'])
                }
            
            return stats
            
        except Exception as e:
            logger.error(f"Error getting storage stats: {e}")
            return {}}}
    
    def _validate_image_upload(self, file_content: bytes, filename: str, mime_type: str):
        """Validate image upload."""
        if not self.config:
            return  # Skip validation if no config
        
        # Check file size
        max_size = self.config.get_max_file_size_bytes()
        if len(file_content) > max_size:
            raise ValueError(f"File too large. Maximum size: {self.config.limits.max_image_size_mb}MB")
        
        # Check mime type
        if not self.config.is_allowed_image_type(mime_type):
            raise ValueError(f"File type not allowed: {mime_type}")
        
        # Check file extension
        if not self.config.is_allowed_image_extension(filename):
            raise ValueError(f"File extension not allowed: {filename}")
        
        # Validate it's actually an image
        try:
            from PIL import Image
            import io
            Image.open(io.BytesIO(file_content))
        except Exception:
            raise ValueError("File is not a valid image")
    
    async def _check_upload_limits(self, user_id: str, file_size: int) -> bool:
        """Check if upload is within user limits."""
        if not self.config:
            return True
        
        stats = await self.repository.get_user_stats(user_id)
        
        # Check image count limit
        if stats['total_images'] >= self.config.limits.max_images_per_user:
            return False
        
        # Check storage limit
        new_total_mb = (stats['total_storage_used_bytes'] + file_size) / (1024 * 1024)
        if new_total_mb > self.config.limits.max_total_storage_mb:
            return False
        
        return True
    
    def _get_user_image_directory(self, user_id: str) -> str:
        """Get or create user's image directory."""
        if self.config:
            return self.config.get_user_image_path(user_id)
        else:
            # Fallback
            user_dir = os.path.join("data", "client_settings", "images", user_id)
            os.makedirs(user_dir, exist_ok=True)
            return user_dir
    
    def _get_image_dimensions(self, file_path: str) -> Tuple[Optional[int], Optional[int]]:
        """Get image dimensions."""
        try:
            with Image.open(file_path) as img:
                return img.width, img.height
        except Exception as e:
            logger.warning(f"Could not get image dimensions for {file_path}: {e}")
            return None, None
    
    async def cleanup_deleted_images(self, user_id: Optional[str] = None) -> Dict[str, int]:
        """Clean up physically deleted image files."""
        try:
            # This would be a maintenance operation
            # For now, return empty stats
            return {}}
                'files_cleaned': 0,
                'space_freed_mb': 0
            }
        except Exception as e:
            logger.error(f"Error in cleanup: {e}")
            return {}}'files_cleaned': 0, 'space_freed_mb': 0}
