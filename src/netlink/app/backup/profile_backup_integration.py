"""
Profile Backup Integration for NetLink

Integrates the advanced profile system with the enhanced backup system:
- Automatic profile backup with user preferences
- Tier information and badge backup
- Subscription data backup with encryption
- Selective restore capabilities
- Profile versioning and history
- Cross-device profile synchronization
"""

import asyncio
import json
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Set
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum
import aiofiles

from app.logger_config import logger
from app.profiles.advanced_profile_system import (
    advanced_profile_system, UserProfile, UserTier, UserBadge, UserSubscription
)
from app.backup.enhanced_backup_system import (
    enhanced_backup_system, BackupType, ShardMetadata, BackupJob
)

class ProfileBackupType(str, Enum):
    """Types of profile data that can be backed up."""
    BASIC_INFO = "basic_info"           # Username, display name, email, etc.
    PREFERENCES = "preferences"         # Theme, language, timezone, etc.
    ACTIVITY_DATA = "activity_data"     # Messages sent, files shared, login count
    BADGES_ACHIEVEMENTS = "badges"      # Earned badges and achievements
    SUBSCRIPTION_DATA = "subscription"  # Subscription information
    SOCIAL_DATA = "social"             # Friends list, blocked users
    CUSTOM_FIELDS = "custom_fields"    # Custom profile fields
    FULL_PROFILE = "full_profile"      # Complete profile backup

class ProfileRestoreMode(str, Enum):
    """Profile restore modes."""
    MERGE = "merge"                    # Merge with existing profile
    REPLACE = "replace"                # Replace existing profile
    SELECTIVE = "selective"            # Restore only selected components

@dataclass
class ProfileBackupMetadata:
    """Metadata for profile backups."""
    user_id: int
    backup_types: List[ProfileBackupType]
    backup_timestamp: datetime
    profile_version: int
    tier_at_backup: UserTier
    badges_count: int
    subscription_active: bool
    backup_size_bytes: int
    checksum: str
    encryption_key_id: str

@dataclass
class ProfileRestoreRequest:
    """Profile restore request specification."""
    user_id: int
    backup_timestamp: datetime
    restore_mode: ProfileRestoreMode
    components_to_restore: List[ProfileBackupType]
    preserve_current_tier: bool = True
    preserve_current_subscription: bool = True
    merge_badges: bool = True

class ProfileBackupIntegration:
    """Integration between profile system and backup system."""
    
    def __init__(self):
        self.backup_metadata: Dict[int, List[ProfileBackupMetadata]] = {}
        self.restore_history: Dict[int, List[Dict[str, Any]]] = {}
        
        # Configuration
        self.config = {
            "auto_backup_enabled": True,
            "backup_frequency_hours": 24,
            "max_profile_versions": 30,
            "compress_backups": True,
            "encrypt_sensitive_data": True,
            "backup_on_tier_change": True,
            "backup_on_subscription_change": True,
            "backup_on_badge_earned": False,  # Too frequent
            "selective_backup_enabled": True,
            "cross_device_sync": True
        }
        
        # Backup scheduling
        self.scheduled_backups: Dict[int, datetime] = {}
        self.backup_in_progress: Set[int] = set()
        
        logger.info("📋 Profile Backup Integration initialized")
    
    async def initialize(self):
        """Initialize the profile backup integration."""
        try:
            # Load existing backup metadata
            await self._load_backup_metadata()
            
            # Schedule automatic backups for all users
            await self._schedule_automatic_backups()
            
            # Start background backup task
            asyncio.create_task(self._background_backup_task())
            
            logger.info("📋 Profile backup integration initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize profile backup integration: {e}")
            raise
    
    async def backup_user_profile(self, 
                                 user_id: int,
                                 backup_types: List[ProfileBackupType] = None,
                                 force: bool = False) -> bool:
        """Backup a user's profile data."""
        try:
            if user_id in self.backup_in_progress and not force:
                logger.warning(f"Backup already in progress for user {user_id}")
                return False
            
            self.backup_in_progress.add(user_id)
            
            try:
                # Get user profile
                profile = await advanced_profile_system.get_user_profile(user_id)
                if not profile:
                    logger.error(f"Profile not found for user {user_id}")
                    return False
                
                # Check user backup preferences
                if not await self._check_backup_preferences(user_id, backup_types or [ProfileBackupType.FULL_PROFILE]):
                    logger.info(f"User {user_id} has opted out of profile backup")
                    return True  # Not an error, user choice
                
                # Determine what to backup
                if not backup_types:
                    backup_types = [ProfileBackupType.FULL_PROFILE]
                
                # Create backup data
                backup_data = await self._create_backup_data(profile, backup_types)
                
                # Create backup metadata
                metadata = ProfileBackupMetadata(
                    user_id=user_id,
                    backup_types=backup_types,
                    backup_timestamp=datetime.now(timezone.utc),
                    profile_version=profile.profile_version,
                    tier_at_backup=profile.tier,
                    badges_count=len(profile.badges_earned),
                    subscription_active=profile.subscription is not None and profile.subscription.status.value == "active",
                    backup_size_bytes=len(json.dumps(backup_data).encode()),
                    checksum=hashlib.sha256(json.dumps(backup_data, sort_keys=True).encode()).hexdigest(),
                    encryption_key_id=f"profile_{user_id}_{int(datetime.now(timezone.utc).timestamp())}"
                )
                
                # Store backup using enhanced backup system
                backup_job = BackupJob(
                    job_id=f"profile_{user_id}_{int(metadata.backup_timestamp.timestamp())}",
                    backup_type=BackupType.PROFILES,
                    source_path=f"profile_{user_id}",
                    user_id=user_id,
                    priority=1,  # High priority for profiles
                    metadata={
                        "profile_backup_metadata": metadata.__dict__,
                        "backup_types": [bt.value for bt in backup_types]
                    }
                )
                
                # Create backup through enhanced backup system
                success = await enhanced_backup_system.create_backup(backup_job, backup_data)
                
                if success:
                    # Store metadata
                    await self._store_backup_metadata(user_id, metadata)
                    
                    # Update scheduled backup time
                    self.scheduled_backups[user_id] = datetime.now(timezone.utc) + timedelta(
                        hours=self.config["backup_frequency_hours"]
                    )
                    
                    logger.info(f"✅ Profile backup completed for user {user_id}")
                    return True
                else:
                    logger.error(f"Failed to create profile backup for user {user_id}")
                    return False
                
            finally:
                self.backup_in_progress.discard(user_id)
            
        except Exception as e:
            logger.error(f"Profile backup failed for user {user_id}: {e}")
            self.backup_in_progress.discard(user_id)
            return False
    
    async def _check_backup_preferences(self, user_id: int, backup_types: List[ProfileBackupType]) -> bool:
        """Check if user allows these backup types."""
        try:
            # Get user backup preferences from enhanced backup system
            preferences = await enhanced_backup_system.get_user_backup_preferences(user_id)
            
            if not preferences:
                return True  # Default to allowing backups
            
            # Check if profiles backup is enabled
            if BackupType.PROFILES in preferences.opt_out_types:
                return False
            
            # Check specific profile backup types if user has granular preferences
            if hasattr(preferences, 'profile_backup_preferences'):
                profile_prefs = preferences.profile_backup_preferences
                for backup_type in backup_types:
                    if backup_type.value in profile_prefs.get('opt_out_components', []):
                        return False
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to check backup preferences for user {user_id}: {e}")
            return True  # Default to allowing
    
    async def _create_backup_data(self, profile: UserProfile, backup_types: List[ProfileBackupType]) -> Dict[str, Any]:
        """Create backup data based on specified types."""
        try:
            backup_data = {
                "backup_timestamp": datetime.now(timezone.utc).isoformat(),
                "profile_version": profile.profile_version,
                "backup_types": [bt.value for bt in backup_types]
            }
            
            for backup_type in backup_types:
                if backup_type == ProfileBackupType.BASIC_INFO:
                    backup_data["basic_info"] = {
                        "user_id": profile.user_id,
                        "username": profile.username,
                        "display_name": profile.display_name,
                        "email": profile.email,
                        "avatar_url": profile.avatar_url,
                        "bio": profile.bio,
                        "join_date": profile.join_date.isoformat()
                    }
                
                elif backup_type == ProfileBackupType.PREFERENCES:
                    backup_data["preferences"] = {
                        "theme_preference": profile.theme_preference,
                        "language_preference": profile.language_preference,
                        "timezone": profile.timezone,
                        "profile_visibility": profile.profile_visibility,
                        "show_online_status": profile.show_online_status,
                        "allow_direct_messages": profile.allow_direct_messages
                    }
                
                elif backup_type == ProfileBackupType.ACTIVITY_DATA:
                    backup_data["activity_data"] = {
                        "total_login_count": profile.total_login_count,
                        "total_messages_sent": profile.total_messages_sent,
                        "total_files_shared": profile.total_files_shared,
                        "last_active": profile.last_active.isoformat() if profile.last_active else None,
                        "experience_points": profile.experience_points,
                        "level": profile.level,
                        "reputation_score": profile.reputation_score
                    }
                
                elif backup_type == ProfileBackupType.BADGES_ACHIEVEMENTS:
                    backup_data["badges_achievements"] = {
                        "badges_earned": [
                            {
                                "badge_id": badge.badge_id,
                                "earned_date": badge.earned_date.isoformat(),
                                "progress_data": badge.progress_data,
                                "earned_context": badge.earned_context,
                                "is_displayed": badge.is_displayed,
                                "display_priority": badge.display_priority
                            }
                            for badge in profile.badges_earned
                        ],
                        "achievements_unlocked": profile.achievements_unlocked
                    }
                
                elif backup_type == ProfileBackupType.SUBSCRIPTION_DATA:
                    if profile.subscription:
                        backup_data["subscription_data"] = {
                            "subscription_tier": profile.subscription.subscription_tier,
                            "status": profile.subscription.status.value,
                            "start_date": profile.subscription.start_date.isoformat(),
                            "end_date": profile.subscription.end_date.isoformat() if profile.subscription.end_date else None,
                            "features_enabled": profile.subscription.features_enabled,
                            "usage_limits": profile.subscription.usage_limits,
                            "billing_cycle": profile.subscription.billing_cycle,
                            "amount_paid": profile.subscription.amount_paid,
                            "currency": profile.subscription.currency,
                            "external_subscription_id": profile.subscription.external_subscription_id,
                            "payment_provider": profile.subscription.payment_provider
                        }
                
                elif backup_type == ProfileBackupType.SOCIAL_DATA:
                    backup_data["social_data"] = {
                        "friends_list": profile.friends_list,
                        "blocked_users": profile.blocked_users,
                        "favorite_channels": profile.favorite_channels
                    }
                
                elif backup_type == ProfileBackupType.CUSTOM_FIELDS:
                    backup_data["custom_fields"] = {
                        "custom_fields": profile.custom_fields,
                        "profile_tags": profile.profile_tags,
                        "premium_features_used": profile.premium_features_used
                    }
                
                elif backup_type == ProfileBackupType.FULL_PROFILE:
                    # Include all components for full backup
                    all_types = [t for t in ProfileBackupType if t != ProfileBackupType.FULL_PROFILE]
                    return await self._create_backup_data(profile, all_types)
            
            return backup_data
            
        except Exception as e:
            logger.error(f"Failed to create backup data: {e}")
            raise
    
    async def _store_backup_metadata(self, user_id: int, metadata: ProfileBackupMetadata):
        """Store backup metadata."""
        try:
            if user_id not in self.backup_metadata:
                self.backup_metadata[user_id] = []
            
            self.backup_metadata[user_id].append(metadata)
            
            # Keep only the most recent backups
            self.backup_metadata[user_id] = sorted(
                self.backup_metadata[user_id],
                key=lambda x: x.backup_timestamp,
                reverse=True
            )[:self.config["max_profile_versions"]]
            
            # Save to disk
            await self._save_backup_metadata()
            
        except Exception as e:
            logger.error(f"Failed to store backup metadata: {e}")
    
    async def _load_backup_metadata(self):
        """Load backup metadata from disk."""
        try:
            metadata_file = Path("data/backup/profile_backup_metadata.json")
            
            if metadata_file.exists():
                async with aiofiles.open(metadata_file, 'r') as f:
                    data = json.loads(await f.read())
                
                # Convert back to objects
                for user_id_str, metadata_list in data.items():
                    user_id = int(user_id_str)
                    self.backup_metadata[user_id] = []
                    
                    for metadata_dict in metadata_list:
                        metadata = ProfileBackupMetadata(
                            user_id=metadata_dict["user_id"],
                            backup_types=[ProfileBackupType(bt) for bt in metadata_dict["backup_types"]],
                            backup_timestamp=datetime.fromisoformat(metadata_dict["backup_timestamp"]),
                            profile_version=metadata_dict["profile_version"],
                            tier_at_backup=UserTier(metadata_dict["tier_at_backup"]),
                            badges_count=metadata_dict["badges_count"],
                            subscription_active=metadata_dict["subscription_active"],
                            backup_size_bytes=metadata_dict["backup_size_bytes"],
                            checksum=metadata_dict["checksum"],
                            encryption_key_id=metadata_dict["encryption_key_id"]
                        )
                        self.backup_metadata[user_id].append(metadata)
            
        except Exception as e:
            logger.error(f"Failed to load backup metadata: {e}")
    
    async def _save_backup_metadata(self):
        """Save backup metadata to disk."""
        try:
            metadata_file = Path("data/backup/profile_backup_metadata.json")
            metadata_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Convert to serializable format
            data = {}
            for user_id, metadata_list in self.backup_metadata.items():
                data[str(user_id)] = [
                    {
                        "user_id": metadata.user_id,
                        "backup_types": [bt.value for bt in metadata.backup_types],
                        "backup_timestamp": metadata.backup_timestamp.isoformat(),
                        "profile_version": metadata.profile_version,
                        "tier_at_backup": metadata.tier_at_backup.value,
                        "badges_count": metadata.badges_count,
                        "subscription_active": metadata.subscription_active,
                        "backup_size_bytes": metadata.backup_size_bytes,
                        "checksum": metadata.checksum,
                        "encryption_key_id": metadata.encryption_key_id
                    }
                    for metadata in metadata_list
                ]
            
            async with aiofiles.open(metadata_file, 'w') as f:
                await f.write(json.dumps(data, indent=2))
            
        except Exception as e:
            logger.error(f"Failed to save backup metadata: {e}")
    
    async def _schedule_automatic_backups(self):
        """Schedule automatic backups for all users."""
        try:
            # Get all user profiles
            for user_id in advanced_profile_system.profiles:
                if self.config["auto_backup_enabled"]:
                    # Schedule next backup
                    next_backup = datetime.now(timezone.utc) + timedelta(
                        hours=self.config["backup_frequency_hours"]
                    )
                    self.scheduled_backups[user_id] = next_backup
            
            logger.info(f"📅 Scheduled automatic backups for {len(self.scheduled_backups)} users")
            
        except Exception as e:
            logger.error(f"Failed to schedule automatic backups: {e}")
    
    async def _background_backup_task(self):
        """Background task for automatic profile backups."""
        while True:
            try:
                current_time = datetime.now(timezone.utc)
                
                # Check for scheduled backups
                for user_id, scheduled_time in list(self.scheduled_backups.items()):
                    if current_time >= scheduled_time:
                        # Perform backup
                        await self.backup_user_profile(user_id)
                
                # Sleep for 1 hour before checking again
                await asyncio.sleep(3600)
                
            except Exception as e:
                logger.error(f"Background backup task error: {e}")
                await asyncio.sleep(3600)  # Continue after error

    async def restore_user_profile(self, restore_request: ProfileRestoreRequest) -> bool:
        """Restore a user's profile from backup."""
        try:
            user_id = restore_request.user_id

            # Find the backup
            backup_metadata = None
            for metadata in self.backup_metadata.get(user_id, []):
                if metadata.backup_timestamp == restore_request.backup_timestamp:
                    backup_metadata = metadata
                    break

            if not backup_metadata:
                logger.error(f"Backup not found for user {user_id} at {restore_request.backup_timestamp}")
                return False

            # Retrieve backup data from enhanced backup system
            backup_job_id = f"profile_{user_id}_{int(backup_metadata.backup_timestamp.timestamp())}"
            backup_data = await enhanced_backup_system.retrieve_backup_data(backup_job_id)

            if not backup_data:
                logger.error(f"Failed to retrieve backup data for {backup_job_id}")
                return False

            # Verify backup integrity
            if not await self._verify_backup_integrity(backup_data, backup_metadata):
                logger.error(f"Backup integrity verification failed for user {user_id}")
                return False

            # Get current profile
            current_profile = await advanced_profile_system.get_user_profile(user_id)

            # Perform restore based on mode
            if restore_request.restore_mode == ProfileRestoreMode.REPLACE:
                success = await self._restore_replace_mode(user_id, backup_data, restore_request)
            elif restore_request.restore_mode == ProfileRestoreMode.MERGE:
                success = await self._restore_merge_mode(user_id, backup_data, current_profile, restore_request)
            elif restore_request.restore_mode == ProfileRestoreMode.SELECTIVE:
                success = await self._restore_selective_mode(user_id, backup_data, current_profile, restore_request)
            else:
                logger.error(f"Unknown restore mode: {restore_request.restore_mode}")
                return False

            if success:
                # Record restore in history
                await self._record_restore_history(user_id, restore_request, backup_metadata)
                logger.info(f"✅ Profile restore completed for user {user_id}")
                return True
            else:
                logger.error(f"Profile restore failed for user {user_id}")
                return False

        except Exception as e:
            logger.error(f"Profile restore failed for user {user_id}: {e}")
            return False

    async def _verify_backup_integrity(self, backup_data: Dict[str, Any], metadata: ProfileBackupMetadata) -> bool:
        """Verify backup data integrity."""
        try:
            # Calculate checksum
            calculated_checksum = hashlib.sha256(
                json.dumps(backup_data, sort_keys=True).encode()
            ).hexdigest()

            if calculated_checksum != metadata.checksum:
                logger.error(f"Checksum mismatch: expected {metadata.checksum}, got {calculated_checksum}")
                return False

            # Verify required fields
            if "backup_timestamp" not in backup_data:
                logger.error("Missing backup_timestamp in backup data")
                return False

            if "backup_types" not in backup_data:
                logger.error("Missing backup_types in backup data")
                return False

            return True

        except Exception as e:
            logger.error(f"Backup integrity verification failed: {e}")
            return False

    async def _restore_replace_mode(self, user_id: int, backup_data: Dict[str, Any],
                                   restore_request: ProfileRestoreRequest) -> bool:
        """Restore profile in replace mode."""
        try:
            # Create new profile from backup data
            restored_profile = await self._create_profile_from_backup(user_id, backup_data)

            if not restored_profile:
                return False

            # Preserve certain fields if requested
            if restore_request.preserve_current_tier:
                current_profile = await advanced_profile_system.get_user_profile(user_id)
                if current_profile:
                    restored_profile.tier = current_profile.tier

            if restore_request.preserve_current_subscription:
                current_profile = await advanced_profile_system.get_user_profile(user_id)
                if current_profile and current_profile.subscription:
                    restored_profile.subscription = current_profile.subscription

            # Update profile
            success = await advanced_profile_system.update_user_profile(restored_profile)
            return success

        except Exception as e:
            logger.error(f"Replace mode restore failed: {e}")
            return False

    async def _restore_merge_mode(self, user_id: int, backup_data: Dict[str, Any],
                                 current_profile: UserProfile, restore_request: ProfileRestoreRequest) -> bool:
        """Restore profile in merge mode."""
        try:
            if not current_profile:
                # No current profile, treat as replace
                return await self._restore_replace_mode(user_id, backup_data, restore_request)

            # Merge backup data with current profile
            for component in restore_request.components_to_restore:
                if component.value in backup_data:
                    await self._merge_profile_component(current_profile, component, backup_data[component.value])

            # Handle badges specially if merge is requested
            if (ProfileBackupType.BADGES_ACHIEVEMENTS in restore_request.components_to_restore and
                restore_request.merge_badges and "badges_achievements" in backup_data):
                await self._merge_badges(current_profile, backup_data["badges_achievements"])

            # Update profile
            success = await advanced_profile_system.update_user_profile(current_profile)
            return success

        except Exception as e:
            logger.error(f"Merge mode restore failed: {e}")
            return False

    async def _restore_selective_mode(self, user_id: int, backup_data: Dict[str, Any],
                                     current_profile: UserProfile, restore_request: ProfileRestoreRequest) -> bool:
        """Restore profile in selective mode."""
        try:
            if not current_profile:
                current_profile = await advanced_profile_system.create_user_profile(user_id, f"user_{user_id}")

            # Restore only selected components
            for component in restore_request.components_to_restore:
                if component.value in backup_data:
                    await self._restore_profile_component(current_profile, component, backup_data[component.value])

            # Update profile
            success = await advanced_profile_system.update_user_profile(current_profile)
            return success

        except Exception as e:
            logger.error(f"Selective mode restore failed: {e}")
            return False

    async def _create_profile_from_backup(self, user_id: int, backup_data: Dict[str, Any]) -> Optional[UserProfile]:
        """Create a profile object from backup data."""
        try:
            # Start with basic info
            basic_info = backup_data.get("basic_info", {})
            username = basic_info.get("username", f"user_{user_id}")

            # Create base profile
            profile = await advanced_profile_system.create_user_profile(user_id, username)

            if not profile:
                return None

            # Restore all components
            for component_name, component_data in backup_data.items():
                if component_name in ["backup_timestamp", "profile_version", "backup_types"]:
                    continue

                component_type = ProfileBackupType(component_name)
                await self._restore_profile_component(profile, component_type, component_data)

            return profile

        except Exception as e:
            logger.error(f"Failed to create profile from backup: {e}")
            return None

    async def _restore_profile_component(self, profile: UserProfile, component_type: ProfileBackupType,
                                        component_data: Dict[str, Any]):
        """Restore a specific profile component."""
        try:
            if component_type == ProfileBackupType.BASIC_INFO:
                profile.display_name = component_data.get("display_name", profile.display_name)
                profile.email = component_data.get("email", profile.email)
                profile.avatar_url = component_data.get("avatar_url", profile.avatar_url)
                profile.bio = component_data.get("bio", profile.bio)

            elif component_type == ProfileBackupType.PREFERENCES:
                profile.theme_preference = component_data.get("theme_preference", profile.theme_preference)
                profile.language_preference = component_data.get("language_preference", profile.language_preference)
                profile.timezone = component_data.get("timezone", profile.timezone)
                profile.profile_visibility = component_data.get("profile_visibility", profile.profile_visibility)
                profile.show_online_status = component_data.get("show_online_status", profile.show_online_status)
                profile.allow_direct_messages = component_data.get("allow_direct_messages", profile.allow_direct_messages)

            elif component_type == ProfileBackupType.ACTIVITY_DATA:
                profile.total_login_count = component_data.get("total_login_count", profile.total_login_count)
                profile.total_messages_sent = component_data.get("total_messages_sent", profile.total_messages_sent)
                profile.total_files_shared = component_data.get("total_files_shared", profile.total_files_shared)
                profile.experience_points = component_data.get("experience_points", profile.experience_points)
                profile.level = component_data.get("level", profile.level)
                profile.reputation_score = component_data.get("reputation_score", profile.reputation_score)

                if component_data.get("last_active"):
                    profile.last_active = datetime.fromisoformat(component_data["last_active"])

            elif component_type == ProfileBackupType.BADGES_ACHIEVEMENTS:
                # Restore badges
                profile.badges_earned = []
                for badge_data in component_data.get("badges_earned", []):
                    badge = UserBadge(
                        badge_id=badge_data["badge_id"],
                        earned_date=datetime.fromisoformat(badge_data["earned_date"]),
                        progress_data=badge_data.get("progress_data", {}),
                        earned_context=badge_data.get("earned_context", ""),
                        is_displayed=badge_data.get("is_displayed", True),
                        display_priority=badge_data.get("display_priority", 0)
                    )
                    profile.badges_earned.append(badge)

                profile.achievements_unlocked = component_data.get("achievements_unlocked", [])

            elif component_type == ProfileBackupType.SUBSCRIPTION_DATA:
                if component_data:
                    subscription = UserSubscription(
                        subscription_tier=component_data["subscription_tier"],
                        status=component_data["status"],
                        start_date=datetime.fromisoformat(component_data["start_date"]),
                        end_date=datetime.fromisoformat(component_data["end_date"]) if component_data.get("end_date") else None,
                        features_enabled=component_data.get("features_enabled", []),
                        usage_limits=component_data.get("usage_limits", {}),
                        billing_cycle=component_data.get("billing_cycle", "monthly"),
                        amount_paid=component_data.get("amount_paid", 0.0),
                        currency=component_data.get("currency", "USD"),
                        external_subscription_id=component_data.get("external_subscription_id"),
                        payment_provider=component_data.get("payment_provider")
                    )
                    profile.subscription = subscription

            elif component_type == ProfileBackupType.SOCIAL_DATA:
                profile.friends_list = component_data.get("friends_list", [])
                profile.blocked_users = component_data.get("blocked_users", [])
                profile.favorite_channels = component_data.get("favorite_channels", [])

            elif component_type == ProfileBackupType.CUSTOM_FIELDS:
                profile.custom_fields = component_data.get("custom_fields", {})
                profile.profile_tags = component_data.get("profile_tags", [])
                profile.premium_features_used = component_data.get("premium_features_used", [])

        except Exception as e:
            logger.error(f"Failed to restore profile component {component_type}: {e}")

    async def _merge_profile_component(self, profile: UserProfile, component_type: ProfileBackupType,
                                      component_data: Dict[str, Any]):
        """Merge a profile component with existing data."""
        try:
            if component_type == ProfileBackupType.CUSTOM_FIELDS:
                # Merge custom fields
                backup_fields = component_data.get("custom_fields", {})
                profile.custom_fields.update(backup_fields)

                # Merge tags
                backup_tags = component_data.get("profile_tags", [])
                profile.profile_tags = list(set(profile.profile_tags + backup_tags))

            elif component_type == ProfileBackupType.SOCIAL_DATA:
                # Merge friends and blocked users
                backup_friends = component_data.get("friends_list", [])
                profile.friends_list = list(set(profile.friends_list + backup_friends))

                backup_blocked = component_data.get("blocked_users", [])
                profile.blocked_users = list(set(profile.blocked_users + backup_blocked))

                backup_channels = component_data.get("favorite_channels", [])
                profile.favorite_channels = list(set(profile.favorite_channels + backup_channels))

            else:
                # For other components, use regular restore
                await self._restore_profile_component(profile, component_type, component_data)

        except Exception as e:
            logger.error(f"Failed to merge profile component {component_type}: {e}")

    async def _merge_badges(self, profile: UserProfile, badges_data: Dict[str, Any]):
        """Merge badges with existing badges."""
        try:
            backup_badges = badges_data.get("badges_earned", [])
            existing_badge_ids = {badge.badge_id for badge in profile.badges_earned}

            # Add new badges from backup
            for badge_data in backup_badges:
                if badge_data["badge_id"] not in existing_badge_ids:
                    badge = UserBadge(
                        badge_id=badge_data["badge_id"],
                        earned_date=datetime.fromisoformat(badge_data["earned_date"]),
                        progress_data=badge_data.get("progress_data", {}),
                        earned_context=badge_data.get("earned_context", ""),
                        is_displayed=badge_data.get("is_displayed", True),
                        display_priority=badge_data.get("display_priority", 0)
                    )
                    profile.badges_earned.append(badge)

            # Merge achievements
            backup_achievements = badges_data.get("achievements_unlocked", [])
            profile.achievements_unlocked = list(set(profile.achievements_unlocked + backup_achievements))

        except Exception as e:
            logger.error(f"Failed to merge badges: {e}")

    async def _record_restore_history(self, user_id: int, restore_request: ProfileRestoreRequest,
                                     backup_metadata: ProfileBackupMetadata):
        """Record profile restore in history."""
        try:
            if user_id not in self.restore_history:
                self.restore_history[user_id] = []

            restore_record = {
                "restore_timestamp": datetime.now(timezone.utc).isoformat(),
                "backup_timestamp": restore_request.backup_timestamp.isoformat(),
                "restore_mode": restore_request.restore_mode.value,
                "components_restored": [ct.value for ct in restore_request.components_to_restore],
                "backup_version": backup_metadata.profile_version,
                "preserve_current_tier": restore_request.preserve_current_tier,
                "preserve_current_subscription": restore_request.preserve_current_subscription,
                "merge_badges": restore_request.merge_badges
            }

            self.restore_history[user_id].append(restore_record)

            # Keep only recent restore history
            self.restore_history[user_id] = self.restore_history[user_id][-50:]  # Keep last 50 restores

        except Exception as e:
            logger.error(f"Failed to record restore history: {e}")

    def get_user_backup_history(self, user_id: int) -> List[ProfileBackupMetadata]:
        """Get backup history for a user."""
        return self.backup_metadata.get(user_id, [])

    def get_user_restore_history(self, user_id: int) -> List[Dict[str, Any]]:
        """Get restore history for a user."""
        return self.restore_history.get(user_id, [])

    async def cleanup_old_backups(self, user_id: int = None):
        """Clean up old profile backups."""
        try:
            if user_id:
                users_to_clean = [user_id]
            else:
                users_to_clean = list(self.backup_metadata.keys())

            for uid in users_to_clean:
                if uid in self.backup_metadata:
                    # Keep only the most recent backups
                    old_count = len(self.backup_metadata[uid])
                    self.backup_metadata[uid] = self.backup_metadata[uid][:self.config["max_profile_versions"]]
                    new_count = len(self.backup_metadata[uid])

                    if old_count > new_count:
                        logger.info(f"Cleaned up {old_count - new_count} old backups for user {uid}")

            # Save updated metadata
            await self._save_backup_metadata()

        except Exception as e:
            logger.error(f"Failed to cleanup old backups: {e}")

# Global profile backup integration instance
profile_backup_integration = ProfileBackupIntegration()
