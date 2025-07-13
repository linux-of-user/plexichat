"""
PlexiChat Spaces Repositories Package

Data access layer for Reddit-like community spaces.
"""

from .comment_repository import CommentRepository
from .post_repository import PostRepository
from .space_member_repository import SpaceMemberRepository
from .space_repository import SpaceRepository

__all__ = [
    "SpaceRepository",
    "PostRepository",
    "CommentRepository",
    "SpaceMemberRepository",
]
