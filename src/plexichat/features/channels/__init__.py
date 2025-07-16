# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
from .models import *
from .repositories import *
from .services import *
from typing import Optional



"""
PlexiChat Channels Feature Package

Discord-like server and channel system with comprehensive role-based permissions.
"""

__version__ = "1.0.0"
__all__ = [
    # Models
    "Server",
    "Channel",
    "Role",
    "PermissionOverwrite",
    "Message",
    "Reaction",
    "ServerMember",
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
