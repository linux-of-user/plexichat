# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
from .comment_repository import CommentRepository
from .post_repository import PostRepository
from .space_member_repository import SpaceMemberRepository
from .space_repository import SpaceRepository
from typing import Optional


"""
PlexiChat Spaces Repositories Package

Data access layer for Reddit-like community spaces.
"""

__all__ = [
    "SpaceRepository",
    "PostRepository",
    "CommentRepository",
    "SpaceMemberRepository",
]
