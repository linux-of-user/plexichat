"""
PlexiChat Channel Management Features - MODERN ARCHITECTURE

Discord-like server and channel system with comprehensive features:
- Server and channel management
- Role-based permissions system
- Permission overwrites
- Message management
- Reaction system
- Member management
- Advanced moderation tools

Uses shared components for consistent error handling and type definitions.
"""

from typing import Optional

# Import shared components (NEW ARCHITECTURE)
from ...shared.models import Channel, Message, User, Permission, Role, Priority, Status
from ...shared.types import ChannelId, UserId, JSON, ConfigDict
from ...shared.exceptions import ()
    ValidationError, AuthorizationError, ResourceNotFoundError,
    QuotaExceededError
)
from ...shared.constants import ()
    MAX_CHANNEL_NAME_LENGTH, MAX_CHANNEL_DESCRIPTION_LENGTH, MAX_CHANNEL_MEMBERS
)

# Import local components
from .models import *
from .repositories import *
from .services import *

__version__ = "3.0.0"
__all__ = [
    # Shared components re-exports
    "Channel",
    "Message",
    "User",
    "Permission",
    "Role",
    "Priority",
    "Status",
    "ChannelId",
    "UserId",
    "JSON",
    "ConfigDict",

    # Exceptions
    "ValidationError",
    "AuthorizationError",
    "ResourceNotFoundError",
    "QuotaExceededError",

    # Local Models
    "Server",
    "PermissionOverwrite",
    "Reaction",
    "ServerMember",

    # Repositories
    "ServerRepository",
    "ChannelRepository",
    "RoleRepository",
    "PermissionOverwriteRepository",
    "MessageRepository",
    "ReactionRepository",
    "ServerMemberRepository",

    # Services
    "ServerService",
    "ChannelService",
    "RoleService",
    "PermissionService",
    "PermissionOverwriteService",
    "ReactionService",
    "MessageService",
