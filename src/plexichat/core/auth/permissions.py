"""
PlexiChat Permissions
=====================

Defines system-wide permissions using Enums for type safety and consistency.
"""

from enum import Enum, auto

class Permission(str, Enum):
    """
    Enumeration of all available system permissions.
    """
    # User Management
    USER_READ = "user:read"
    USER_WRITE = "user:write"
    USER_DELETE = "user:delete"
    USER_BAN = "user:ban"
    
    # Messaging
    MESSAGE_SEND = "message:send"
    MESSAGE_READ = "message:read"
    MESSAGE_DELETE = "message:delete"
    MESSAGE_EDIT = "message:edit"
    
    # Channels/Groups
    CHANNEL_CREATE = "channel:create"
    CHANNEL_DELETE = "channel:delete"
    CHANNEL_MANAGE = "channel:manage"
    
    # Admin
    ADMIN_ACCESS = "admin:access"
    SYSTEM_CONFIG = "system:config"
    VIEW_LOGS = "system:logs"
    
    # AI
    AI_USE = "ai:use"
    AI_MANAGE = "ai:manage"

    def __str__(self):
        return self.value
