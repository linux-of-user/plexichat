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



# Import shared components (NEW ARCHITECTURE)
from ...shared.models import Channel, Message, User, Permission, Role, Priority, Status
from ...shared.types import ChannelId, UserId, JSON, ConfigDict
from ...shared.exceptions import (
    ValidationError, AuthorizationError, ResourceNotFoundError,
    QuotaExceededError
)
# Constants not available in shared.constants

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

    # Local Models (only include what exists)
    "Server",
    "ServerMember",

    # Repositories (only include what exists)
    "ServerRepository",
    "ChannelRepository",
    "RoleRepository",
    "MessageRepository",
    "ServerMemberRepository",

    # Services (only include what exists)
    "ServerService",
    "ChannelService",
    "RoleService",
    "MessageService",
]
