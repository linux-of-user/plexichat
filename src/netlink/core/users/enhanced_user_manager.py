"""
NetLink Enhanced User Management System

Advanced user management with granular permissions, user tags (alpha/beta tester),
profile customization, and third-party admin API integration.
"""

import asyncio
import json
import secrets
from typing import Dict, List, Optional, Any, Set, Tuple
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field, asdict
from enum import Enum
import logging
from pathlib import Path
import hashlib
import bcrypt

logger = logging.getLogger(__name__)


class UserTier(Enum):
    """Enhanced user tiers with special privileges."""
    BASIC = "basic"
    PREMIUM = "premium"
    ALPHA_TESTER = "alpha_tester"
    BETA_TESTER = "beta_tester"
    MODERATOR = "moderator"
    ADMIN = "admin"
    SUPER_ADMIN = "super_admin"


class UserTag(Enum):
    """User tags for special features and privileges."""
    ALPHA_TESTER = "alpha_tester"
    BETA_TESTER = "beta_tester"
    EARLY_ADOPTER = "early_adopter"
    CONTRIBUTOR = "contributor"
    DEVELOPER = "developer"
    VIP = "vip"
    VERIFIED = "verified"
    PREMIUM = "premium"
    LIFETIME = "lifetime"
    STAFF = "staff"


class PermissionScope(Enum):
    """Permission scopes for granular access control."""
    GLOBAL = "global"
    SERVER = "server"
    CHANNEL = "channel"
    USER = "user"
    API = "api"
    ADMIN = "admin"
    SYSTEM = "system"


class Permission(Enum):
    """Granular permissions system."""
    # Basic permissions
    READ_MESSAGES = "read_messages"
    SEND_MESSAGES = "send_messages"
    DELETE_OWN_MESSAGES = "delete_own_messages"
    DELETE_ANY_MESSAGES = "delete_any_messages"
    EDIT_OWN_MESSAGES = "edit_own_messages"
    EDIT_ANY_MESSAGES = "edit_any_messages"
    
    # File permissions
    UPLOAD_FILES = "upload_files"
    DOWNLOAD_FILES = "download_files"
    DELETE_OWN_FILES = "delete_own_files"
    DELETE_ANY_FILES = "delete_any_files"
    SHARE_FILES = "share_files"
    
    # User management
    VIEW_USER_PROFILES = "view_user_profiles"
    EDIT_OWN_PROFILE = "edit_own_profile"
    EDIT_ANY_PROFILE = "edit_any_profile"
    MANAGE_USERS = "manage_users"
    BAN_USERS = "ban_users"
    KICK_USERS = "kick_users"
    
    # Channel/Server management
    CREATE_CHANNELS = "create_channels"
    DELETE_CHANNELS = "delete_channels"
    MANAGE_CHANNELS = "manage_channels"
    MANAGE_ROLES = "manage_roles"
    
    # API permissions
    API_READ = "api_read"
    API_WRITE = "api_write"
    API_ADMIN = "api_admin"
    API_SYSTEM = "api_system"
    
    # Admin permissions
    ADMIN_PANEL = "admin_panel"
    SYSTEM_CONFIG = "system_config"
    VIEW_LOGS = "view_logs"
    MANAGE_PLUGINS = "manage_plugins"
    MANAGE_BACKUPS = "manage_backups"
    
    # Special permissions
    BYPASS_RATE_LIMITS = "bypass_rate_limits"
    ACCESS_BETA_FEATURES = "access_beta_features"
    ACCESS_ALPHA_FEATURES = "access_alpha_features"
    PRIORITY_SUPPORT = "priority_support"


@dataclass
class UserProfile:
    """Enhanced user profile with customization options."""
    user_id: str
    username: str
    email: str
    display_name: Optional[str] = None
    
    # Profile customization
    avatar_url: Optional[str] = None
    banner_url: Optional[str] = None
    bio: Optional[str] = None
    status_message: Optional[str] = None
    theme: str = "default"
    accent_color: str = "#007bff"
    
    # User information
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    date_of_birth: Optional[datetime] = None
    location: Optional[str] = None
    website: Optional[str] = None
    
    # Account details
    tier: UserTier = UserTier.BASIC
    tags: Set[UserTag] = field(default_factory=set)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_active: Optional[datetime] = None
    
    # Statistics
    total_messages: int = 0
    total_files_uploaded: int = 0
    reputation_score: int = 0
    experience_points: int = 0
    
    # Preferences
    language: str = "en"
    timezone: str = "UTC"
    email_notifications: bool = True
    push_notifications: bool = True
    privacy_level: str = "normal"  # minimal, normal, maximum
    
    # Social features
    friends: Set[str] = field(default_factory=set)
    blocked_users: Set[str] = field(default_factory=set)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert profile to dictionary."""
        data = asdict(self)
        # Convert sets to lists for JSON serialization
        data['tags'] = [tag.value for tag in self.tags]
        data['friends'] = list(self.friends)
        data['blocked_users'] = list(self.blocked_users)
        data['tier'] = self.tier.value
        # Convert datetime objects
        for key, value in data.items():
            if isinstance(value, datetime):
                data[key] = value.isoformat()
        return data


@dataclass
class UserPermissions:
    """User permissions with granular scope control."""
    user_id: str
    global_permissions: Set[Permission] = field(default_factory=set)
    scoped_permissions: Dict[str, Dict[str, Set[Permission]]] = field(default_factory=dict)  # scope_type -> scope_id -> permissions
    denied_permissions: Dict[str, Dict[str, Set[Permission]]] = field(default_factory=dict)  # scope_type -> scope_id -> denied permissions
    roles: Set[str] = field(default_factory=set)
    temporary_permissions: Dict[Permission, datetime] = field(default_factory=dict)  # permission -> expires_at
    
    def has_permission(self, permission: Permission, scope: PermissionScope = PermissionScope.GLOBAL, scope_id: str = "global") -> bool:
        """Check if user has a specific permission."""
        # Check if permission is explicitly denied
        scope_str = scope.value
        if scope_str in self.denied_permissions and scope_id in self.denied_permissions[scope_str]:
            if permission in self.denied_permissions[scope_str][scope_id]:
                return False
        
        # Check temporary permissions
        if permission in self.temporary_permissions:
            if datetime.now(timezone.utc) < self.temporary_permissions[permission]:
                return True
            else:
                # Remove expired temporary permission
                del self.temporary_permissions[permission]
        
        # Check global permissions
        if permission in self.global_permissions:
            return True
        
        # Check scoped permissions
        if scope_str in self.scoped_permissions and scope_id in self.scoped_permissions[scope_str]:
            if permission in self.scoped_permissions[scope_str][scope_id]:
                return True
        
        return False


@dataclass
class TierBenefits:
    """Benefits for each user tier."""
    max_file_size_mb: int
    max_daily_uploads: int
    api_rate_limit: int
    storage_quota_gb: int
    priority_support: bool
    custom_themes: bool
    beta_access: bool
    alpha_access: bool
    enhanced_profile: bool
    streaming_quality: str  # "standard", "hd", "4k"
    concurrent_streams: int
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


class EnhancedUserManager:
    """Enhanced user management system."""
    
    def __init__(self, config_dir: str = "config/users"):
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(exist_ok=True)
        
        # Storage
        self.users: Dict[str, UserProfile] = {}
        self.user_permissions: Dict[str, UserPermissions] = {}
        self.user_credentials: Dict[str, Dict[str, Any]] = {}  # username -> {password_hash, salt, etc.}
        
        # Tier benefits configuration
        self.tier_benefits = self._setup_tier_benefits()
        
        # Tag benefits configuration
        self.tag_benefits = self._setup_tag_benefits()
        
        # Statistics
        self.stats = {
            "total_users": 0,
            "active_users": 0,
            "users_by_tier": {},
            "users_by_tag": {}
        }
        
        # Load existing data
        self._load_user_data()
        
        logger.info("Enhanced User Manager initialized")
    
    def _setup_tier_benefits(self) -> Dict[UserTier, TierBenefits]:
        """Setup tier benefits configuration."""
        return {
            UserTier.BASIC: TierBenefits(
                max_file_size_mb=10,
                max_daily_uploads=50,
                api_rate_limit=1000,
                storage_quota_gb=1,
                priority_support=False,
                custom_themes=False,
                beta_access=False,
                alpha_access=False,
                enhanced_profile=False,
                streaming_quality="standard",
                concurrent_streams=1
            ),
            UserTier.PREMIUM: TierBenefits(
                max_file_size_mb=100,
                max_daily_uploads=500,
                api_rate_limit=5000,
                storage_quota_gb=10,
                priority_support=True,
                custom_themes=True,
                beta_access=False,
                alpha_access=False,
                enhanced_profile=True,
                streaming_quality="hd",
                concurrent_streams=3
            ),
            UserTier.ALPHA_TESTER: TierBenefits(
                max_file_size_mb=500,
                max_daily_uploads=1000,
                api_rate_limit=10000,
                storage_quota_gb=50,
                priority_support=True,
                custom_themes=True,
                beta_access=True,
                alpha_access=True,
                enhanced_profile=True,
                streaming_quality="4k",
                concurrent_streams=5
            ),
            UserTier.BETA_TESTER: TierBenefits(
                max_file_size_mb=200,
                max_daily_uploads=750,
                api_rate_limit=7500,
                storage_quota_gb=25,
                priority_support=True,
                custom_themes=True,
                beta_access=True,
                alpha_access=False,
                enhanced_profile=True,
                streaming_quality="hd",
                concurrent_streams=4
            ),
            UserTier.MODERATOR: TierBenefits(
                max_file_size_mb=1000,
                max_daily_uploads=2000,
                api_rate_limit=25000,
                storage_quota_gb=100,
                priority_support=True,
                custom_themes=True,
                beta_access=True,
                alpha_access=True,
                enhanced_profile=True,
                streaming_quality="4k",
                concurrent_streams=10
            ),
            UserTier.ADMIN: TierBenefits(
                max_file_size_mb=-1,  # Unlimited
                max_daily_uploads=-1,  # Unlimited
                api_rate_limit=-1,  # Unlimited
                storage_quota_gb=-1,  # Unlimited
                priority_support=True,
                custom_themes=True,
                beta_access=True,
                alpha_access=True,
                enhanced_profile=True,
                streaming_quality="4k",
                concurrent_streams=-1  # Unlimited
            )
        }
    
    def _setup_tag_benefits(self) -> Dict[UserTag, Dict[str, Any]]:
        """Setup tag-specific benefits."""
        return {
            UserTag.ALPHA_TESTER: {
                "api_rate_limit_multiplier": 2.0,
                "file_size_multiplier": 2.0,
                "early_feature_access": True,
                "special_badge": True
            },
            UserTag.BETA_TESTER: {
                "api_rate_limit_multiplier": 1.5,
                "file_size_multiplier": 1.5,
                "beta_feature_access": True,
                "special_badge": True
            },
            UserTag.VIP: {
                "api_rate_limit_multiplier": 3.0,
                "file_size_multiplier": 3.0,
                "priority_support": True,
                "exclusive_features": True
            },
            UserTag.DEVELOPER: {
                "api_rate_limit_multiplier": 5.0,
                "enhanced_api_access": True,
                "debug_features": True
            },
            UserTag.PREMIUM: {
                "storage_multiplier": 2.0,
                "streaming_quality_boost": True,
                "ad_free": True
            }
        }
    
    def _load_user_data(self):
        """Load user data from storage."""
        try:
            users_file = self.config_dir / "users.json"
            if users_file.exists():
                with open(users_file, 'r') as f:
                    data = json.load(f)
                    for user_id, user_data in data.items():
                        # Convert back to UserProfile
                        user_data['tags'] = {UserTag(tag) for tag in user_data.get('tags', [])}
                        user_data['tier'] = UserTier(user_data.get('tier', 'basic'))
                        user_data['friends'] = set(user_data.get('friends', []))
                        user_data['blocked_users'] = set(user_data.get('blocked_users', []))
                        
                        # Convert datetime strings back to datetime objects
                        for key in ['created_at', 'last_active', 'date_of_birth']:
                            if user_data.get(key):
                                user_data[key] = datetime.fromisoformat(user_data[key])
                        
                        self.users[user_id] = UserProfile(**user_data)
            
            # Load permissions
            permissions_file = self.config_dir / "permissions.json"
            if permissions_file.exists():
                with open(permissions_file, 'r') as f:
                    data = json.load(f)
                    for user_id, perm_data in data.items():
                        # Convert back to UserPermissions
                        perm_data['global_permissions'] = {Permission(p) for p in perm_data.get('global_permissions', [])}
                        perm_data['roles'] = set(perm_data.get('roles', []))
                        
                        # Convert scoped permissions
                        scoped_perms = {}
                        for scope_type, scopes in perm_data.get('scoped_permissions', {}).items():
                            scoped_perms[scope_type] = {}
                            for scope_id, perms in scopes.items():
                                scoped_perms[scope_type][scope_id] = {Permission(p) for p in perms}
                        perm_data['scoped_permissions'] = scoped_perms
                        
                        # Convert denied permissions
                        denied_perms = {}
                        for scope_type, scopes in perm_data.get('denied_permissions', {}).items():
                            denied_perms[scope_type] = {}
                            for scope_id, perms in scopes.items():
                                denied_perms[scope_type][scope_id] = {Permission(p) for p in perms}
                        perm_data['denied_permissions'] = denied_perms
                        
                        # Convert temporary permissions
                        temp_perms = {}
                        for perm, expires_str in perm_data.get('temporary_permissions', {}).items():
                            temp_perms[Permission(perm)] = datetime.fromisoformat(expires_str)
                        perm_data['temporary_permissions'] = temp_perms
                        
                        self.user_permissions[user_id] = UserPermissions(**perm_data)
            
            logger.info(f"Loaded {len(self.users)} users and {len(self.user_permissions)} permission sets")
            
        except Exception as e:
            logger.error(f"Failed to load user data: {e}")
    
    def _save_user_data(self):
        """Save user data to storage."""
        try:
            # Save users
            users_data = {}
            for user_id, user in self.users.items():
                users_data[user_id] = user.to_dict()
            
            users_file = self.config_dir / "users.json"
            with open(users_file, 'w') as f:
                json.dump(users_data, f, indent=2, default=str)
            
            # Save permissions
            permissions_data = {}
            for user_id, perms in self.user_permissions.items():
                perm_dict = {
                    'user_id': perms.user_id,
                    'global_permissions': [p.value for p in perms.global_permissions],
                    'roles': list(perms.roles),
                    'scoped_permissions': {},
                    'denied_permissions': {},
                    'temporary_permissions': {}
                }
                
                # Convert scoped permissions
                for scope_type, scopes in perms.scoped_permissions.items():
                    perm_dict['scoped_permissions'][scope_type] = {}
                    for scope_id, scope_perms in scopes.items():
                        perm_dict['scoped_permissions'][scope_type][scope_id] = [p.value for p in scope_perms]
                
                # Convert denied permissions
                for scope_type, scopes in perms.denied_permissions.items():
                    perm_dict['denied_permissions'][scope_type] = {}
                    for scope_id, scope_perms in scopes.items():
                        perm_dict['denied_permissions'][scope_type][scope_id] = [p.value for p in scope_perms]
                
                # Convert temporary permissions
                for perm, expires_at in perms.temporary_permissions.items():
                    perm_dict['temporary_permissions'][perm.value] = expires_at.isoformat()
                
                permissions_data[user_id] = perm_dict
            
            permissions_file = self.config_dir / "permissions.json"
            with open(permissions_file, 'w') as f:
                json.dump(permissions_data, f, indent=2, default=str)
            
            logger.info("User data saved successfully")
            
        except Exception as e:
            logger.error(f"Failed to save user data: {e}")
    
    async def create_user(self, username: str, email: str, password: str, 
                         tier: UserTier = UserTier.BASIC, tags: Set[UserTag] = None) -> str:
        """Create a new user."""
        try:
            # Generate user ID
            user_id = secrets.token_hex(16)
            
            # Hash password
            salt = bcrypt.gensalt()
            password_hash = bcrypt.hashpw(password.encode('utf-8'), salt)
            
            # Create user profile
            profile = UserProfile(
                user_id=user_id,
                username=username,
                email=email,
                tier=tier,
                tags=tags or set()
            )
            
            # Create user permissions based on tier
            permissions = UserPermissions(user_id=user_id)
            self._assign_tier_permissions(permissions, tier)
            self._assign_tag_permissions(permissions, tags or set())
            
            # Store user data
            self.users[user_id] = profile
            self.user_permissions[user_id] = permissions
            self.user_credentials[username] = {
                'user_id': user_id,
                'password_hash': password_hash.decode('utf-8'),
                'salt': salt.decode('utf-8')
            }
            
            # Update statistics
            self.stats["total_users"] += 1
            self.stats["users_by_tier"][tier.value] = self.stats["users_by_tier"].get(tier.value, 0) + 1
            for tag in (tags or set()):
                self.stats["users_by_tag"][tag.value] = self.stats["users_by_tag"].get(tag.value, 0) + 1
            
            # Save data
            self._save_user_data()
            
            logger.info(f"Created user {username} with ID {user_id}")
            return user_id

        except Exception as e:
            logger.error(f"Failed to create user {username}: {e}")
            raise

    def _assign_tier_permissions(self, permissions: UserPermissions, tier: UserTier):
        """Assign permissions based on user tier."""
        base_permissions = {
            Permission.READ_MESSAGES,
            Permission.SEND_MESSAGES,
            Permission.DELETE_OWN_MESSAGES,
            Permission.EDIT_OWN_PROFILE,
            Permission.UPLOAD_FILES,
            Permission.DOWNLOAD_FILES,
            Permission.DELETE_OWN_FILES,
            Permission.VIEW_USER_PROFILES
        }

        if tier in [UserTier.PREMIUM, UserTier.ALPHA_TESTER, UserTier.BETA_TESTER]:
            base_permissions.update({
                Permission.SHARE_FILES,
                Permission.API_READ
            })

        if tier in [UserTier.ALPHA_TESTER, UserTier.BETA_TESTER]:
            base_permissions.update({
                Permission.ACCESS_BETA_FEATURES,
                Permission.API_WRITE
            })

        if tier == UserTier.ALPHA_TESTER:
            base_permissions.add(Permission.ACCESS_ALPHA_FEATURES)

        if tier in [UserTier.MODERATOR, UserTier.ADMIN, UserTier.SUPER_ADMIN]:
            base_permissions.update({
                Permission.DELETE_ANY_MESSAGES,
                Permission.EDIT_ANY_MESSAGES,
                Permission.DELETE_ANY_FILES,
                Permission.MANAGE_USERS,
                Permission.BAN_USERS,
                Permission.KICK_USERS,
                Permission.CREATE_CHANNELS,
                Permission.MANAGE_CHANNELS,
                Permission.API_ADMIN,
                Permission.BYPASS_RATE_LIMITS,
                Permission.PRIORITY_SUPPORT
            })

        if tier in [UserTier.ADMIN, UserTier.SUPER_ADMIN]:
            base_permissions.update({
                Permission.ADMIN_PANEL,
                Permission.SYSTEM_CONFIG,
                Permission.VIEW_LOGS,
                Permission.MANAGE_PLUGINS,
                Permission.MANAGE_BACKUPS,
                Permission.MANAGE_ROLES,
                Permission.API_SYSTEM
            })

        permissions.global_permissions.update(base_permissions)

    def _assign_tag_permissions(self, permissions: UserPermissions, tags: Set[UserTag]):
        """Assign permissions based on user tags."""
        for tag in tags:
            if tag == UserTag.ALPHA_TESTER:
                permissions.global_permissions.add(Permission.ACCESS_ALPHA_FEATURES)
            elif tag == UserTag.BETA_TESTER:
                permissions.global_permissions.add(Permission.ACCESS_BETA_FEATURES)
            elif tag == UserTag.DEVELOPER:
                permissions.global_permissions.update({
                    Permission.API_READ,
                    Permission.API_WRITE,
                    Permission.API_ADMIN
                })
            elif tag == UserTag.VIP:
                permissions.global_permissions.update({
                    Permission.BYPASS_RATE_LIMITS,
                    Permission.PRIORITY_SUPPORT
                })

    async def authenticate_user(self, username: str, password: str) -> Optional[str]:
        """Authenticate user and return user ID if successful."""
        try:
            if username not in self.user_credentials:
                return None

            creds = self.user_credentials[username]
            stored_hash = creds['password_hash'].encode('utf-8')

            if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
                user_id = creds['user_id']
                # Update last active
                if user_id in self.users:
                    self.users[user_id].last_active = datetime.now(timezone.utc)
                    self._save_user_data()
                return user_id

            return None

        except Exception as e:
            logger.error(f"Authentication error for {username}: {e}")
            return None

    def get_user_profile(self, user_id: str) -> Optional[UserProfile]:
        """Get user profile by ID."""
        return self.users.get(user_id)

    def get_user_by_username(self, username: str) -> Optional[UserProfile]:
        """Get user profile by username."""
        for user in self.users.values():
            if user.username == username:
                return user
        return None

    def update_user_profile(self, user_id: str, updates: Dict[str, Any]) -> bool:
        """Update user profile."""
        try:
            if user_id not in self.users:
                return False

            user = self.users[user_id]

            # Update allowed fields
            allowed_fields = {
                'display_name', 'bio', 'status_message', 'theme', 'accent_color',
                'first_name', 'last_name', 'location', 'website', 'language',
                'timezone', 'email_notifications', 'push_notifications', 'privacy_level'
            }

            for field, value in updates.items():
                if field in allowed_fields and hasattr(user, field):
                    setattr(user, field, value)

            self._save_user_data()
            logger.info(f"Updated profile for user {user_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to update profile for user {user_id}: {e}")
            return False

    def add_user_tag(self, user_id: str, tag: UserTag) -> bool:
        """Add tag to user."""
        try:
            if user_id not in self.users:
                return False

            user = self.users[user_id]
            user.tags.add(tag)

            # Update permissions based on new tag
            if user_id in self.user_permissions:
                self._assign_tag_permissions(self.user_permissions[user_id], {tag})

            # Update statistics
            self.stats["users_by_tag"][tag.value] = self.stats["users_by_tag"].get(tag.value, 0) + 1

            self._save_user_data()
            logger.info(f"Added tag {tag.value} to user {user_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to add tag {tag.value} to user {user_id}: {e}")
            return False

    def remove_user_tag(self, user_id: str, tag: UserTag) -> bool:
        """Remove tag from user."""
        try:
            if user_id not in self.users:
                return False

            user = self.users[user_id]
            if tag in user.tags:
                user.tags.remove(tag)

                # Update statistics
                self.stats["users_by_tag"][tag.value] = max(0, self.stats["users_by_tag"].get(tag.value, 0) - 1)

                self._save_user_data()
                logger.info(f"Removed tag {tag.value} from user {user_id}")
                return True

            return False

        except Exception as e:
            logger.error(f"Failed to remove tag {tag.value} from user {user_id}: {e}")
            return False

    def upgrade_user_tier(self, user_id: str, new_tier: UserTier) -> bool:
        """Upgrade user tier."""
        try:
            if user_id not in self.users:
                return False

            user = self.users[user_id]
            old_tier = user.tier
            user.tier = new_tier

            # Update permissions
            if user_id in self.user_permissions:
                # Clear old tier permissions and assign new ones
                self.user_permissions[user_id].global_permissions.clear()
                self._assign_tier_permissions(self.user_permissions[user_id], new_tier)
                self._assign_tag_permissions(self.user_permissions[user_id], user.tags)

            # Update statistics
            self.stats["users_by_tier"][old_tier.value] = max(0, self.stats["users_by_tier"].get(old_tier.value, 0) - 1)
            self.stats["users_by_tier"][new_tier.value] = self.stats["users_by_tier"].get(new_tier.value, 0) + 1

            self._save_user_data()
            logger.info(f"Upgraded user {user_id} from {old_tier.value} to {new_tier.value}")
            return True

        except Exception as e:
            logger.error(f"Failed to upgrade user {user_id} tier: {e}")
            return False

    def get_user_permissions(self, user_id: str) -> Optional[UserPermissions]:
        """Get user permissions."""
        return self.user_permissions.get(user_id)

    def grant_permission(self, user_id: str, permission: Permission,
                        scope: PermissionScope = PermissionScope.GLOBAL, scope_id: str = "global") -> bool:
        """Grant permission to user."""
        try:
            if user_id not in self.user_permissions:
                self.user_permissions[user_id] = UserPermissions(user_id=user_id)

            perms = self.user_permissions[user_id]

            if scope == PermissionScope.GLOBAL:
                perms.global_permissions.add(permission)
            else:
                scope_str = scope.value
                if scope_str not in perms.scoped_permissions:
                    perms.scoped_permissions[scope_str] = {}
                if scope_id not in perms.scoped_permissions[scope_str]:
                    perms.scoped_permissions[scope_str][scope_id] = set()

                perms.scoped_permissions[scope_str][scope_id].add(permission)

            self._save_user_data()
            logger.info(f"Granted permission {permission.value} to user {user_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to grant permission {permission.value} to user {user_id}: {e}")
            return False

    def revoke_permission(self, user_id: str, permission: Permission,
                         scope: PermissionScope = PermissionScope.GLOBAL, scope_id: str = "global") -> bool:
        """Revoke permission from user."""
        try:
            if user_id not in self.user_permissions:
                return False

            perms = self.user_permissions[user_id]

            if scope == PermissionScope.GLOBAL:
                perms.global_permissions.discard(permission)
            else:
                scope_str = scope.value
                if (scope_str in perms.scoped_permissions and
                    scope_id in perms.scoped_permissions[scope_str]):
                    perms.scoped_permissions[scope_str][scope_id].discard(permission)

            self._save_user_data()
            logger.info(f"Revoked permission {permission.value} from user {user_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to revoke permission {permission.value} from user {user_id}: {e}")
            return False

    def check_permission(self, user_id: str, permission: Permission,
                        scope: PermissionScope = PermissionScope.GLOBAL, scope_id: str = "global") -> bool:
        """Check if user has permission."""
        if user_id not in self.user_permissions:
            return False

        return self.user_permissions[user_id].has_permission(permission, scope, scope_id)

    def get_user_benefits(self, user_id: str) -> Dict[str, Any]:
        """Get user benefits based on tier and tags."""
        if user_id not in self.users:
            return {}

        user = self.users[user_id]
        benefits = self.tier_benefits[user.tier].to_dict()

        # Apply tag benefits
        for tag in user.tags:
            if tag in self.tag_benefits:
                tag_benefits = self.tag_benefits[tag]

                # Apply multipliers
                if "api_rate_limit_multiplier" in tag_benefits:
                    if benefits["api_rate_limit"] > 0:
                        benefits["api_rate_limit"] = int(benefits["api_rate_limit"] * tag_benefits["api_rate_limit_multiplier"])

                if "file_size_multiplier" in tag_benefits:
                    if benefits["max_file_size_mb"] > 0:
                        benefits["max_file_size_mb"] = int(benefits["max_file_size_mb"] * tag_benefits["file_size_multiplier"])

                if "storage_multiplier" in tag_benefits:
                    if benefits["storage_quota_gb"] > 0:
                        benefits["storage_quota_gb"] = int(benefits["storage_quota_gb"] * tag_benefits["storage_multiplier"])

                # Apply boolean benefits
                for key, value in tag_benefits.items():
                    if isinstance(value, bool) and value:
                        benefits[key] = True

        return benefits

    def get_statistics(self) -> Dict[str, Any]:
        """Get user management statistics."""
        active_users = sum(1 for user in self.users.values()
                          if user.last_active and
                          (datetime.now(timezone.utc) - user.last_active).days < 30)

        self.stats["active_users"] = active_users

        return self.stats.copy()

    def search_users(self, query: str, filters: Dict[str, Any] = None) -> List[UserProfile]:
        """Search users by various criteria."""
        results = []
        filters = filters or {}

        for user in self.users.values():
            # Text search
            if query:
                search_fields = [user.username, user.display_name or "", user.email, user.bio or ""]
                if not any(query.lower() in field.lower() for field in search_fields):
                    continue

            # Apply filters
            if "tier" in filters and user.tier != UserTier(filters["tier"]):
                continue

            if "tags" in filters:
                required_tags = {UserTag(tag) for tag in filters["tags"]}
                if not required_tags.issubset(user.tags):
                    continue

            if "created_after" in filters:
                if user.created_at < datetime.fromisoformat(filters["created_after"]):
                    continue

            results.append(user)

        return results

    def export_user_data(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Export all user data for GDPR compliance."""
        if user_id not in self.users:
            return None

        user = self.users[user_id]
        permissions = self.user_permissions.get(user_id)

        export_data = {
            "profile": user.to_dict(),
            "permissions": {
                "global_permissions": [p.value for p in permissions.global_permissions] if permissions else [],
                "roles": list(permissions.roles) if permissions else [],
                "scoped_permissions": {},
                "denied_permissions": {}
            } if permissions else {},
            "benefits": self.get_user_benefits(user_id),
            "export_timestamp": datetime.now(timezone.utc).isoformat()
        }

        if permissions:
            # Convert scoped permissions for export
            for scope_type, scopes in permissions.scoped_permissions.items():
                export_data["permissions"]["scoped_permissions"][scope_type] = {}
                for scope_id, perms in scopes.items():
                    export_data["permissions"]["scoped_permissions"][scope_type][scope_id] = [p.value for p in perms]

            # Convert denied permissions for export
            for scope_type, scopes in permissions.denied_permissions.items():
                export_data["permissions"]["denied_permissions"][scope_type] = {}
                for scope_id, perms in scopes.items():
                    export_data["permissions"]["denied_permissions"][scope_type][scope_id] = [p.value for p in perms]

        return export_data


# Global enhanced user manager instance
enhanced_user_manager = EnhancedUserManager()

def get_enhanced_user_manager() -> EnhancedUserManager:
    """Get the global enhanced user manager."""
    return enhanced_user_manager
