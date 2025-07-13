import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


from pathlib import Path
from datetime import datetime
from datetime import datetime
from datetime import datetime
from datetime import datetime
from datetime import datetime
from datetime import datetime
from datetime import datetime
from datetime import datetime
from datetime import datetime
from datetime import datetime
from datetime import datetime


from pathlib import Path
from datetime import datetime
from datetime import datetime
from datetime import datetime
from datetime import datetime
from datetime import datetime
from datetime import datetime
from datetime import datetime
from datetime import datetime
from datetime import datetime
from datetime import datetime
from datetime import datetime

from plexichat.app.logger_config import logger

"""
Role-Based Permission System for PlexiChat
Comprehensive permission management with granular access control.
"""

class Permission(Enum):
    """System permissions."""
    # Basic permissions
    READ_MESSAGES = "read_messages"
    SEND_MESSAGES = "send_messages"
    DELETE_MESSAGES = "delete_messages"
    EDIT_MESSAGES = "edit_messages"
    
    # File permissions
    UPLOAD_FILES = "upload_files"
    DOWNLOAD_FILES = "download_files"
    DELETE_FILES = "delete_files"
    SHARE_FILES = "share_files"
    
    # User management
    VIEW_USERS = "view_users"
    MANAGE_USERS = "manage_users"
    BAN_USERS = "ban_users"
    KICK_USERS = "kick_users"
    
    # Server management
    MANAGE_SERVERS = "manage_servers"
    CREATE_CHANNELS = "create_channels"
    DELETE_CHANNELS = "delete_channels"
    MANAGE_ROLES = "manage_roles"
    
    # Administrative
    ADMIN_PANEL = "admin_panel"
    SYSTEM_CONFIG = "system_config"
    VIEW_LOGS = "view_logs"
    MANAGE_PLUGINS = "manage_plugins"
    
    # API access
    API_READ = "api_read"
    API_WRITE = "api_write"
    API_ADMIN = "api_admin"
    
    # Rate limiting
    BYPASS_RATE_LIMITS = "bypass_rate_limits"
    MANAGE_RATE_LIMITS = "manage_rate_limits"
    
    # Security
    VIEW_SECURITY_LOGS = "view_security_logs"
    MANAGE_SECURITY = "manage_security"
    QUARANTINE_USERS = "quarantine_users"
    
    # Backup and clustering
    MANAGE_BACKUPS = "manage_backups"
    MANAGE_CLUSTERS = "manage_clusters"
    VIEW_SYSTEM_STATUS = "view_system_status"
    
    # AI features
    USE_AI = "use_ai"
    MANAGE_AI = "manage_ai"
    
    # Emoji and reactions
    USE_EMOJIS = "use_emojis"
    MANAGE_EMOJIS = "manage_emojis"
    
    # Profile management
    UPDATE_PROFILE = "update_profile"
    VIEW_PROFILES = "view_profiles"

class PermissionScope(Enum):
    """Permission scopes."""
    GLOBAL = "global"
    SERVER = "server"
    CHANNEL = "channel"
    USER = "user"

@dataclass
class Role:
    """User role with permissions."""
    name: str
    display_name: str
    description: str
    permissions: Set[Permission] = field(default_factory=set)
    priority: int = 0  # Higher priority = more important role
    color: str = "#ffffff"
    is_default: bool = False
    is_system: bool = False
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    
    def __post_init__(self):
        if isinstance(self.permissions, list):
            self.permissions = set(Permission(p) if isinstance(p, str) else p for p in self.permissions)

@dataclass
class UserPermissions:
    """User's permissions across different scopes."""
    user_id: str
    global_roles: List[str] = field(default_factory=list)
    server_roles: Dict[str, List[str]] = field(default_factory=dict)  # server_id -> roles
    channel_roles: Dict[str, List[str]] = field(default_factory=dict)  # channel_id -> roles
    explicit_permissions: Dict[str, Set[Permission]] = field(default_factory=dict)  # scope_id -> permissions
    denied_permissions: Dict[str, Set[Permission]] = field(default_factory=dict)  # scope_id -> denied permissions
    is_active: bool = True
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)

@dataclass
class PermissionCheck:
    """Result of a permission check."""
    user_id: str
    permission: Permission
    scope: PermissionScope
    scope_id: Optional[str]
    granted: bool
    reason: str
    roles_checked: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)

class PermissionManager:
    """Manages roles and permissions."""
    
    def __init__(self, config_path: str = "config/permissions.json"):
        self.config_path = from pathlib import Path
Path(config_path)
        self.roles: Dict[str, Role] = {}
        self.user_permissions: Dict[str, UserPermissions] = {}
        self.permission_cache: Dict[str, Dict[str, bool]] = {}
        
        # Load configuration
        self.load_config()
        
        # Create default roles if none exist
        if not self.roles:
            self._create_default_roles()
    
    def load_config(self) -> None:
        """Load permissions configuration."""
        try:
            if self.config_path.exists():
                with open(self.config_path, 'r') as f:
                    config_data = json.load(f)
                
                # Load roles
                for role_data in config_data.get("roles", []):
                    role = Role(
                        name=role_data["name"],
                        display_name=role_data["display_name"],
                        description=role_data["description"],
                        permissions=set(Permission(p) for p in role_data.get("permissions", [])),
                        priority=role_data.get("priority", 0),
                        color=role_data.get("color", "#ffffff"),
                        is_default=role_data.get("is_default", False),
                        is_system=role_data.get("is_system", False),
                        created_at=datetime.fromisoformat(role_data.get("created_at", from datetime import datetime
datetime.now().isoformat())),
                        updated_at=datetime.fromisoformat(role_data.get("updated_at", from datetime import datetime
datetime.now().isoformat()))
                    )
                    self.roles[role.name] = role
                
                # Load user permissions
                for user_data in config_data.get("user_permissions", []):
                    user_perms = UserPermissions(
                        user_id=user_data["user_id"],
                        global_roles=user_data.get("global_roles", []),
                        server_roles=user_data.get("server_roles", {}),
                        channel_roles=user_data.get("channel_roles", {}),
                        explicit_permissions={
                            scope_id: set(Permission(p) for p in perms)
                            for scope_id, perms in user_data.get("explicit_permissions", {}).items()
                        },
                        denied_permissions={
                            scope_id: set(Permission(p) for p in perms)
                            for scope_id, perms in user_data.get("denied_permissions", {}).items()
                        },
                        is_active=user_data.get("is_active", True),
                        created_at=datetime.fromisoformat(user_data.get("created_at", from datetime import datetime
datetime.now().isoformat())),
                        updated_at=datetime.fromisoformat(user_data.get("updated_at", from datetime import datetime
datetime.now().isoformat()))
                    )
                    self.user_permissions[user_perms.user_id] = user_perms
                
                logger.info(f" Loaded {len(self.roles)} roles and {len(self.user_permissions)} user permissions")
            else:
                self._create_default_roles()
                
        except Exception as e:
            logger.error(f" Failed to load permissions config: {e}")
            self._create_default_roles()
    
    def save_config(self) -> None:
        """Save permissions configuration."""
        try:
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            
            config_data = {
                "roles": [
                    {
                        "name": role.name,
                        "display_name": role.display_name,
                        "description": role.description,
                        "permissions": [p.value for p in role.permissions],
                        "priority": role.priority,
                        "color": role.color,
                        "is_default": role.is_default,
                        "is_system": role.is_system,
                        "created_at": role.created_at.isoformat(),
                        "updated_at": role.updated_at.isoformat()
                    }
                    for role in self.roles.values()
                ],
                "user_permissions": [
                    {
                        "user_id": user_perms.user_id,
                        "global_roles": user_perms.global_roles,
                        "server_roles": user_perms.server_roles,
                        "channel_roles": user_perms.channel_roles,
                        "explicit_permissions": {
                            scope_id: [p.value for p in perms]
                            for scope_id, perms in user_perms.explicit_permissions.items()
                        },
                        "denied_permissions": {
                            scope_id: [p.value for p in perms]
                            for scope_id, perms in user_perms.denied_permissions.items()
                        },
                        "is_active": user_perms.is_active,
                        "created_at": user_perms.created_at.isoformat(),
                        "updated_at": user_perms.updated_at.isoformat()
                    }
                    for user_perms in self.user_permissions.values()
                ]
            }
            
            with open(self.config_path, 'w') as f:
                json.dump(config_data, f, indent=2, default=str)
            
            logger.info(" Permissions configuration saved")
            
        except Exception as e:
            logger.error(f" Failed to save permissions config: {e}")
    
    def _create_default_roles(self) -> None:
        """Create default system roles."""
        default_roles = [
            Role(
                name="admin",
                display_name="Administrator",
                description="Full system access",
                permissions=set(Permission),  # All permissions
                priority=1000,
                color="#ff0000",
                is_system=True
            ),
            Role(
                name="moderator",
                display_name="Moderator",
                description="Server moderation capabilities",
                permissions={
                    Permission.READ_MESSAGES, Permission.SEND_MESSAGES, Permission.DELETE_MESSAGES,
                    Permission.VIEW_USERS, Permission.KICK_USERS, Permission.BAN_USERS,
                    Permission.MANAGE_ROLES, Permission.VIEW_LOGS, Permission.USE_EMOJIS,
                    Permission.UPDATE_PROFILE, Permission.VIEW_PROFILES, Permission.USE_AI
                },
                priority=500,
                color="#00ff00"
            ),
            Role(
                name="user",
                display_name="User",
                description="Standard user permissions",
                permissions={
                    Permission.READ_MESSAGES, Permission.SEND_MESSAGES, Permission.UPLOAD_FILES,
                    Permission.DOWNLOAD_FILES, Permission.USE_EMOJIS, Permission.UPDATE_PROFILE,
                    Permission.VIEW_PROFILES, Permission.USE_AI
                },
                priority=100,
                color="#0000ff",
                is_default=True
            ),
            Role(
                name="guest",
                display_name="Guest",
                description="Limited guest access",
                permissions={
                    Permission.READ_MESSAGES, Permission.VIEW_PROFILES
                },
                priority=10,
                color="#888888"
            ),
            Role(
                name="banned",
                display_name="Banned",
                description="Banned user with no permissions",
                permissions=set(),
                priority=0,
                color="#000000"
            )
        ]
        
        for role in default_roles:
            self.roles[role.name] = role
        
        self.save_config()
        logger.info(" Created default permission roles")
    
    def create_role(self, role: Role) -> bool:
        """Create a new role."""
        try:
            if role.name in self.roles:
                logger.warning(f" Role already exists: {role.name}")
                return False
            
            role.created_at = from datetime import datetime
datetime.now()
            role.updated_at = from datetime import datetime
datetime.now()
            self.roles[role.name] = role
            self.save_config()
            self._clear_permission_cache()
            
            logger.info(f" Created role: {role.name}")
            return True
            
        except Exception as e:
            logger.error(f" Failed to create role {role.name}: {e}")
            return False
    
    def update_role(self, role_name: str, updates: Dict[str, Any]) -> bool:
        """Update an existing role."""
        try:
            if role_name not in self.roles:
                logger.warning(f" Role not found: {role_name}")
                return False
            
            role = self.roles[role_name]
            
            if role.is_system and "permissions" in updates:
                logger.warning(f" Cannot modify permissions of system role: {role_name}")
                return False
            
            for key, value in updates.items():
                if hasattr(role, key):
                    if key == "permissions":
                        role.permissions = set(Permission(p) if isinstance(p, str) else p for p in value)
                    else:
                        setattr(role, key, value)
            
            role.updated_at = from datetime import datetime
datetime.now()
            self.save_config()
            self._clear_permission_cache()
            
            logger.info(f" Updated role: {role_name}")
            return True
            
        except Exception as e:
            logger.error(f" Failed to update role {role_name}: {e}")
            return False
    
    def delete_role(self, role_name: str) -> bool:
        """Delete a role."""
        try:
            if role_name not in self.roles:
                logger.warning(f" Role not found: {role_name}")
                return False
            
            role = self.roles[role_name]
            if role.is_system:
                logger.warning(f" Cannot delete system role: {role_name}")
                return False
            
            # Remove role from all users
            for user_perms in self.user_permissions.values():
                if role_name in user_perms.global_roles:
                    user_perms.global_roles.remove(role_name)
                
                for server_roles in user_perms.server_roles.values():
                    if role_name in server_roles:
                        server_roles.remove(role_name)
                
                for channel_roles in user_perms.channel_roles.values():
                    if role_name in channel_roles:
                        channel_roles.remove(role_name)
            
            del self.roles[role_name]
            self.save_config()
            self._clear_permission_cache()
            
            logger.info(f" Deleted role: {role_name}")
            return True
            
        except Exception as e:
            logger.error(f" Failed to delete role {role_name}: {e}")
            return False

    def assign_role(self, user_id: str, role_name: str, scope: PermissionScope = PermissionScope.GLOBAL, scope_id: Optional[str] = None) -> bool:
        """Assign a role to a user."""
        try:
            if role_name not in self.roles:
                logger.warning(f" Role not found: {role_name}")
                return False

            if user_id not in self.user_permissions:
                self.user_permissions[user_id] = UserPermissions(user_id=user_id)

            user_perms = self.user_permissions[user_id]

            if scope == PermissionScope.GLOBAL:
                if role_name not in user_perms.global_roles:
                    user_perms.global_roles.append(role_name)
            elif scope == PermissionScope.SERVER and scope_id:
                if scope_id not in user_perms.server_roles:
                    user_perms.server_roles[scope_id] = []
                if role_name not in user_perms.server_roles[scope_id]:
                    user_perms.server_roles[scope_id].append(role_name)
            elif scope == PermissionScope.CHANNEL and scope_id:
                if scope_id not in user_perms.channel_roles:
                    user_perms.channel_roles[scope_id] = []
                if role_name not in user_perms.channel_roles[scope_id]:
                    user_perms.channel_roles[scope_id].append(role_name)

            user_perms.updated_at = from datetime import datetime
datetime.now()
            self.save_config()
            self._clear_user_cache(user_id)

            logger.info(f" Assigned role {role_name} to user {user_id} in scope {scope.value}")
            return True

        except Exception as e:
            logger.error(f" Failed to assign role {role_name} to user {user_id}: {e}")
            return False

    def revoke_role(self, user_id: str, role_name: str, scope: PermissionScope = PermissionScope.GLOBAL, scope_id: Optional[str] = None) -> bool:
        """Revoke a role from a user."""
        try:
            if user_id not in self.user_permissions:
                logger.warning(f" User permissions not found: {user_id}")
                return False

            user_perms = self.user_permissions[user_id]

            if scope == PermissionScope.GLOBAL:
                if role_name in user_perms.global_roles:
                    user_perms.global_roles.remove(role_name)
            elif scope == PermissionScope.SERVER and scope_id:
                if scope_id in user_perms.server_roles and role_name in user_perms.server_roles[scope_id]:
                    user_perms.server_roles[scope_id].remove(role_name)
            elif scope == PermissionScope.CHANNEL and scope_id:
                if scope_id in user_perms.channel_roles and role_name in user_perms.channel_roles[scope_id]:
                    user_perms.channel_roles[scope_id].remove(role_name)

            user_perms.updated_at = from datetime import datetime
datetime.now()
            self.save_config()
            self._clear_user_cache(user_id)

            logger.info(f" Revoked role {role_name} from user {user_id} in scope {scope.value}")
            return True

        except Exception as e:
            logger.error(f" Failed to revoke role {role_name} from user {user_id}: {e}")
            return False

    def grant_permission(self, user_id: str, permission: Permission, scope_id: str = "global") -> bool:
        """Grant explicit permission to a user."""
        try:
            if user_id not in self.user_permissions:
                self.user_permissions[user_id] = UserPermissions(user_id=user_id)

            user_perms = self.user_permissions[user_id]

            if scope_id not in user_perms.explicit_permissions:
                user_perms.explicit_permissions[scope_id] = set()

            user_perms.explicit_permissions[scope_id].add(permission)
            user_perms.updated_at = from datetime import datetime
datetime.now()
            self.save_config()
            self._clear_user_cache(user_id)

            logger.info(f" Granted permission {permission.value} to user {user_id} in scope {scope_id}")
            return True

        except Exception as e:
            logger.error(f" Failed to grant permission {permission.value} to user {user_id}: {e}")
            return False

    def deny_permission(self, user_id: str, permission: Permission, scope_id: str = "global") -> bool:
        """Explicitly deny permission to a user."""
        try:
            if user_id not in self.user_permissions:
                self.user_permissions[user_id] = UserPermissions(user_id=user_id)

            user_perms = self.user_permissions[user_id]

            if scope_id not in user_perms.denied_permissions:
                user_perms.denied_permissions[scope_id] = set()

            user_perms.denied_permissions[scope_id].add(permission)
            user_perms.updated_at = from datetime import datetime
datetime.now()
            self.save_config()
            self._clear_user_cache(user_id)

            logger.info(f" Denied permission {permission.value} to user {user_id} in scope {scope_id}")
            return True

        except Exception as e:
            logger.error(f" Failed to deny permission {permission.value} to user {user_id}: {e}")
            return False

    def check_permission(self, user_id: str, permission: Permission, scope: PermissionScope = PermissionScope.GLOBAL, scope_id: Optional[str] = None) -> PermissionCheck:
        """Check if user has a specific permission."""
        try:
            # Check cache first
            cache_key = f"{user_id}:{permission.value}:{scope.value}:{scope_id or 'none'}"
            if cache_key in self.permission_cache.get(user_id, {}):
                cached_result = self.permission_cache[user_id][cache_key]
                return PermissionCheck(
                    user_id=user_id,
                    permission=permission,
                    scope=scope,
                    scope_id=scope_id,
                    granted=cached_result,
                    reason="cached result"
                )

            if user_id not in self.user_permissions:
                # Assign default role if user has no permissions
                default_role = next((role for role in self.roles.values() if role.is_default), None)
                if default_role:
                    self.assign_role(user_id, default_role.name)
                else:
                    result = PermissionCheck(
                        user_id=user_id,
                        permission=permission,
                        scope=scope,
                        scope_id=scope_id,
                        granted=False,
                        reason="no permissions configured and no default role"
                    )
                    self._cache_permission_result(user_id, cache_key, False)
                    return result

            user_perms = self.user_permissions[user_id]

            if not user_perms.is_active:
                result = PermissionCheck(
                    user_id=user_id,
                    permission=permission,
                    scope=scope,
                    scope_id=scope_id,
                    granted=False,
                    reason="user account is inactive"
                )
                self._cache_permission_result(user_id, cache_key, False)
                return result

            # Check explicit denials first
            denial_scopes = ["global"]
            if scope_id:
                denial_scopes.append(scope_id)

            for denial_scope in denial_scopes:
                if denial_scope in user_perms.denied_permissions:
                    if permission in user_perms.denied_permissions[denial_scope]:
                        result = PermissionCheck(
                            user_id=user_id,
                            permission=permission,
                            scope=scope,
                            scope_id=scope_id,
                            granted=False,
                            reason=f"explicitly denied in scope {denial_scope}"
                        )
                        self._cache_permission_result(user_id, cache_key, False)
                        return result

            # Check explicit grants
            grant_scopes = ["global"]
            if scope_id:
                grant_scopes.append(scope_id)

            for grant_scope in grant_scopes:
                if grant_scope in user_perms.explicit_permissions:
                    if permission in user_perms.explicit_permissions[grant_scope]:
                        result = PermissionCheck(
                            user_id=user_id,
                            permission=permission,
                            scope=scope,
                            scope_id=scope_id,
                            granted=True,
                            reason=f"explicitly granted in scope {grant_scope}"
                        )
                        self._cache_permission_result(user_id, cache_key, True)
                        return result

            # Check role-based permissions
            roles_to_check = []
            roles_checked = []

            # Add global roles
            roles_to_check.extend(user_perms.global_roles)

            # Add scope-specific roles
            if scope == PermissionScope.SERVER and scope_id:
                roles_to_check.extend(user_perms.server_roles.get(scope_id, []))
            elif scope == PermissionScope.CHANNEL and scope_id:
                roles_to_check.extend(user_perms.channel_roles.get(scope_id, []))

            # Sort roles by priority (highest first)
            roles_to_check = sorted(set(roles_to_check), key=lambda r: self.roles.get(r, Role("", "", "", set(), 0)).priority, reverse=True)

            for role_name in roles_to_check:
                roles_checked.append(role_name)
                if role_name in self.roles:
                    role = self.roles[role_name]
                    if permission in role.permissions:
                        result = PermissionCheck(
                            user_id=user_id,
                            permission=permission,
                            scope=scope,
                            scope_id=scope_id,
                            granted=True,
                            reason=f"granted by role {role_name}",
                            roles_checked=roles_checked
                        )
                        self._cache_permission_result(user_id, cache_key, True)
                        return result

            # Permission not found
            result = PermissionCheck(
                user_id=user_id,
                permission=permission,
                scope=scope,
                scope_id=scope_id,
                granted=False,
                reason="permission not granted by any role or explicit grant",
                roles_checked=roles_checked
            )
            self._cache_permission_result(user_id, cache_key, False)
            return result

        except Exception as e:
            logger.error(f" Failed to check permission {permission.value} for user {user_id}: {e}")
            return PermissionCheck(
                user_id=user_id,
                permission=permission,
                scope=scope,
                scope_id=scope_id,
                granted=False,
                reason=f"error during permission check: {e}"
            )

    def _cache_permission_result(self, user_id: str, cache_key: str, result: bool) -> None:
        """Cache permission check result."""
        if user_id not in self.permission_cache:
            self.permission_cache[user_id] = {}
        self.permission_cache[user_id][cache_key] = result

    def _clear_permission_cache(self) -> None:
        """Clear all permission cache."""
        self.permission_cache.clear()

    def _clear_user_cache(self, user_id: str) -> None:
        """Clear permission cache for specific user."""
        if user_id in self.permission_cache:
            del self.permission_cache[user_id]
