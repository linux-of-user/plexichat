"""
PlexiChat Client Settings Repository
===================================

Database repository for client settings using the DB abstraction system.
"""

import logging
import os
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any, Union
from sqlalchemy import and_, func, desc
from sqlalchemy.exc import IntegrityError

# Core database imports
try:
    from plexichat.core.database.db_manager import DatabaseManager
    from plexichat.core.database.base_repository import BaseRepository
except ImportError:
    # Fallback for development
    DatabaseManager = None
    BaseRepository = object

# Models
from ..models.client_settings import (
    ClientSetting, ClientSettingImage, SettingType, ImageStatus,
    ClientSettingCreate, ClientSettingUpdate, ClientSettingResponse,
    ClientSettingImageCreate, ClientSettingImageUpdate, ClientSettingImageResponse
)

# Configuration
try:
    from plexichat.core.config.client_settings_config import get_client_settings_config
except ImportError:
    get_client_settings_config = lambda: None

logger = logging.getLogger(__name__)

class ClientSettingsRepository(BaseRepository if BaseRepository != object else object):
    """Repository for client settings operations."""
    
    def __init__(self, db_manager: Optional[DatabaseManager] = None):
        """Initialize repository."""
        if BaseRepository != object:
            super().__init__(db_manager)
        self.db_manager = db_manager
        self.config = get_client_settings_config()
    
    # Key-Value Settings Operations
    async def get_user_settings(self, user_id: str, include_public: bool = False) -> List[ClientSettingResponse]:
        """Get all settings for a user."""
        try:
            if self.db_manager:
                query = self.db_manager.session.query(ClientSetting).filter(
                    ClientSetting.user_id == user_id
                )
                if not include_public:
                    # Only get user's own settings, not public ones from others
                    pass  # Already filtered by user_id
                
                settings = query.all()
                return [ClientSettingResponse.from_orm(setting) for setting in settings]
            else:
                # Fallback: in-memory storage
                return self._get_user_settings_fallback(user_id)
        except Exception as e:
            logger.error(f"Error getting user settings: {e}")
            return []
    
    async def get_setting(self, user_id: str, setting_key: str) -> Optional[ClientSettingResponse]:
        """Get a specific setting."""
        try:
            if self.db_manager:
                setting = self.db_manager.session.query(ClientSetting).filter(
                    and_(
                        ClientSetting.user_id == user_id,
                        ClientSetting.setting_key == setting_key
                    )
                ).first()
                
                if setting:
                    return ClientSettingResponse.from_orm(setting)
                return None
            else:
                # Fallback implementation
                return self._get_setting_fallback(user_id, setting_key)
        except Exception as e:
            logger.error(f"Error getting setting {setting_key}: {e}")
            return None
    
    async def set_setting(self, user_id: str, setting_key: str, setting_data: ClientSettingCreate) -> ClientSettingResponse:
        """Set or update a setting."""
        try:
            # Validate limits
            if not await self._check_user_limits(user_id):
                raise ValueError("User has reached maximum number of settings")
            
            if self.db_manager:
                # Check if setting exists
                existing = self.db_manager.session.query(ClientSetting).filter(
                    and_(
                        ClientSetting.user_id == user_id,
                        ClientSetting.setting_key == setting_key
                    )
                ).first()
                
                if existing:
                    # Update existing
                    existing.setting_value = setting_data.setting_value
                    existing.setting_type = setting_data.setting_type.value
                    existing.description = setting_data.description
                    existing.is_public = setting_data.is_public
                    existing.updated_at = datetime.utcnow()
                    setting = existing
                else:
                    # Create new
                    setting = ClientSetting(
                        user_id=user_id,
                        setting_key=setting_key,
                        setting_value=setting_data.setting_value,
                        setting_type=setting_data.setting_type.value,
                        description=setting_data.description,
                        is_public=setting_data.is_public
                    )
                    self.db_manager.session.add(setting)
                
                self.db_manager.session.commit()
                return ClientSettingResponse.from_orm(setting)
            else:
                # Fallback implementation
                return self._set_setting_fallback(user_id, setting_key, setting_data)
        except Exception as e:
            if self.db_manager:
                self.db_manager.session.rollback()
            logger.error(f"Error setting {setting_key}: {e}")
            raise
    
    async def delete_setting(self, user_id: str, setting_key: str) -> bool:
        """Delete a setting."""
        try:
            if self.db_manager:
                deleted = self.db_manager.session.query(ClientSetting).filter(
                    and_(
                        ClientSetting.user_id == user_id,
                        ClientSetting.setting_key == setting_key
                    )
                ).delete()
                
                self.db_manager.session.commit()
                return deleted > 0
            else:
                return self._delete_setting_fallback(user_id, setting_key)
        except Exception as e:
            if self.db_manager:
                self.db_manager.session.rollback()
            logger.error(f"Error deleting setting {setting_key}: {e}")
            return False
    
    # Image Operations
    async def get_user_images(self, user_id: str) -> List[ClientSettingImageResponse]:
        """Get all images for a user."""
        try:
            if self.db_manager:
                images = self.db_manager.session.query(ClientSettingImage).filter(
                    and_(
                        ClientSettingImage.user_id == user_id,
                        ClientSettingImage.status == ImageStatus.ACTIVE.value
                    )
                ).order_by(desc(ClientSettingImage.created_at)).all()
                
                return [ClientSettingImageResponse.from_orm(image) for image in images]
            else:
                return self._get_user_images_fallback(user_id)
        except Exception as e:
            logger.error(f"Error getting user images: {e}")
            return []
    
    async def get_image(self, user_id: str, image_id: str) -> Optional[ClientSettingImageResponse]:
        """Get a specific image."""
        try:
            if self.db_manager:
                image = self.db_manager.session.query(ClientSettingImage).filter(
                    and_(
                        ClientSettingImage.id == image_id,
                        ClientSettingImage.user_id == user_id,
                        ClientSettingImage.status == ImageStatus.ACTIVE.value
                    )
                ).first()
                
                if image:
                    return ClientSettingImageResponse.from_orm(image)
                return None
            else:
                return self._get_image_fallback(user_id, image_id)
        except Exception as e:
            logger.error(f"Error getting image {image_id}: {e}")
            return None
    
    async def create_image_record(self, user_id: str, image_data: Dict[str, Any]) -> ClientSettingImageResponse:
        """Create an image record in the database."""
        try:
            # Check image limits
            if not await self._check_image_limits(user_id):
                raise ValueError("User has reached maximum number of images")
            
            image_id = str(uuid.uuid4())
            
            if self.db_manager:
                image = ClientSettingImage(
                    id=image_id,
                    user_id=user_id,
                    setting_key=image_data.get('setting_key'),
                    original_filename=image_data['original_filename'],
                    stored_filename=image_data['stored_filename'],
                    file_path=image_data['file_path'],
                    mime_type=image_data['mime_type'],
                    file_size=image_data['file_size'],
                    width=image_data.get('width'),
                    height=image_data.get('height'),
                    description=image_data.get('description'),
                    alt_text=image_data.get('alt_text'),
                    status=ImageStatus.ACTIVE.value
                )
                
                self.db_manager.session.add(image)
                self.db_manager.session.commit()
                
                return ClientSettingImageResponse.from_orm(image)
            else:
                return self._create_image_record_fallback(user_id, image_id, image_data)
        except Exception as e:
            if self.db_manager:
                self.db_manager.session.rollback()
            logger.error(f"Error creating image record: {e}")
            raise
    
    async def delete_image(self, user_id: str, image_id: str) -> bool:
        """Delete an image (mark as deleted)."""
        try:
            if self.db_manager:
                updated = self.db_manager.session.query(ClientSettingImage).filter(
                    and_(
                        ClientSettingImage.id == image_id,
                        ClientSettingImage.user_id == user_id
                    )
                ).update({
                    'status': ImageStatus.DELETED.value,
                    'updated_at': datetime.utcnow()
                })
                
                self.db_manager.session.commit()
                return updated > 0
            else:
                return self._delete_image_fallback(user_id, image_id)
        except Exception as e:
            if self.db_manager:
                self.db_manager.session.rollback()
            logger.error(f"Error deleting image {image_id}: {e}")
            return False
    
    # Statistics and Limits
    async def get_user_stats(self, user_id: str) -> Dict[str, Any]:
        """Get user statistics."""
        try:
            if self.db_manager:
                # Count settings
                settings_count = self.db_manager.session.query(ClientSetting).filter(
                    ClientSetting.user_id == user_id
                ).count()
                
                # Count images
                images_count = self.db_manager.session.query(ClientSettingImage).filter(
                    and_(
                        ClientSettingImage.user_id == user_id,
                        ClientSettingImage.status == ImageStatus.ACTIVE.value
                    )
                ).count()
                
                # Calculate storage used
                storage_used = self.db_manager.session.query(
                    func.sum(ClientSettingImage.file_size)
                ).filter(
                    and_(
                        ClientSettingImage.user_id == user_id,
                        ClientSettingImage.status == ImageStatus.ACTIVE.value
                    )
                ).scalar() or 0
                
                # Settings by type
                settings_by_type = {}
                if settings_count > 0:
                    type_counts = self.db_manager.session.query(
                        ClientSetting.setting_type,
                        func.count(ClientSetting.setting_type)
                    ).filter(
                        ClientSetting.user_id == user_id
                    ).group_by(ClientSetting.setting_type).all()
                    
                    settings_by_type = {type_name: count for type_name, count in type_counts}
                
                return {}}
                    'total_settings': settings_count,
                    'total_images': images_count,
                    'total_storage_used_bytes': storage_used,
                    'total_storage_used_mb': round(storage_used / (1024 * 1024), 2),
                    'settings_by_type': settings_by_type
                }
            else:
                return self._get_user_stats_fallback(user_id)
        except Exception as e:
            logger.error(f"Error getting user stats: {e}")
            return {}}
                'total_settings': 0,
                'total_images': 0,
                'total_storage_used_bytes': 0,
                'total_storage_used_mb': 0.0,
                'settings_by_type': {}
            }
    
    async def _check_user_limits(self, user_id: str) -> bool:
        """Check if user can add more settings."""
        if not self.config:
            return True
        
        stats = await self.get_user_stats(user_id)
        return stats['total_settings'] < self.config.limits.max_key_value_pairs
    
    async def _check_image_limits(self, user_id: str) -> bool:
        """Check if user can add more images."""
        if not self.config:
            return True
        
        stats = await self.get_user_stats(user_id)
        return stats['total_images'] < self.config.limits.max_images_per_user
    
    # Bulk Operations
    async def bulk_update_settings(self, user_id: str, settings: Dict[str, Any]) -> Dict[str, Any]:
        """Bulk update multiple settings."""
        try:
            updated_keys = []
            errors = []

            for key, value in settings.items():
                try:
                    if isinstance(value, dict):
                        # Handle complex setting data
                        setting_data = ClientSettingCreate(
                            setting_key=key,
                            setting_value=str(value.get('value', '')),
                            setting_type=SettingType(value.get('type', 'text')),
                            description=value.get('description'),
                            is_public=value.get('is_public', False)
                        )
                    else:
                        # Simple string value
                        setting_data = ClientSettingCreate(
                            setting_key=key,
                            setting_value=str(value),
                            setting_type=SettingType.TEXT
                        )

                    await self.set_setting(user_id, key, setting_data)
                    updated_keys.append(key)
                except Exception as e:
                    errors.append({'key': key, 'error': str(e)})

            return {}}
                'success': len(errors) == 0,
                'updated_count': len(updated_keys),
                'failed_count': len(errors),
                'errors': errors,
                'updated_keys': updated_keys
            }
        except Exception as e:
            logger.error(f"Error in bulk update: {e}")
            return {}}
                'success': False,
                'updated_count': 0,
                'failed_count': len(settings),
                'errors': [{'error': str(e)}],
                'updated_keys': []
            }

    # Fallback implementations for when DB is not available
    def _get_user_settings_fallback(self, user_id: str) -> List[ClientSettingResponse]:
        """Fallback implementation for getting user settings."""
        # In-memory storage would go here
        return []
    
    def _get_setting_fallback(self, user_id: str, setting_key: str) -> Optional[ClientSettingResponse]:
        """Fallback implementation for getting a setting."""
        return None
    
    def _set_setting_fallback(self, user_id: str, setting_key: str, setting_data: ClientSettingCreate) -> ClientSettingResponse:
        """Fallback implementation for setting a value."""
        # Create a mock response
        return ClientSettingResponse(
            user_id=user_id,
            setting_key=setting_key,
            setting_value=setting_data.setting_value,
            setting_type=setting_data.setting_type,
            description=setting_data.description,
            is_public=setting_data.is_public,
            is_encrypted=False,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
    
    def _delete_setting_fallback(self, user_id: str, setting_key: str) -> bool:
        """Fallback implementation for deleting a setting."""
        return True
    
    def _get_user_images_fallback(self, user_id: str) -> List[ClientSettingImageResponse]:
        """Fallback implementation for getting user images."""
        return []
    
    def _get_image_fallback(self, user_id: str, image_id: str) -> Optional[ClientSettingImageResponse]:
        """Fallback implementation for getting an image."""
        return None
    
    def _create_image_record_fallback(self, user_id: str, image_id: str, image_data: Dict[str, Any]) -> ClientSettingImageResponse:
        """Fallback implementation for creating image record."""
        return ClientSettingImageResponse(
            id=image_id,
            user_id=user_id,
            setting_key=image_data.get('setting_key'),
            original_filename=image_data['original_filename'],
            stored_filename=image_data['stored_filename'],
            file_path=image_data['file_path'],
            mime_type=image_data['mime_type'],
            file_size=image_data['file_size'],
            width=image_data.get('width'),
            height=image_data.get('height'),
            description=image_data.get('description'),
            alt_text=image_data.get('alt_text'),
            status=ImageStatus.ACTIVE,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
    
    def _delete_image_fallback(self, user_id: str, image_id: str) -> bool:
        """Fallback implementation for deleting an image."""
        return True
    
    def _get_user_stats_fallback(self, user_id: str) -> Dict[str, Any]:
        """Fallback implementation for getting user stats."""
        return {}}
            'total_settings': 0,
            'total_images': 0,
            'total_storage_used_bytes': 0,
            'total_storage_used_mb': 0.0,
            'settings_by_type': {}
        }
