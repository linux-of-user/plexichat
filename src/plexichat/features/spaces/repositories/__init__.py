"""
PlexiChat Spaces Repositories Package

Data access layer for Reddit-like community spaces.
"""

from .space_repository import SpaceRepository
from .post_repository import PostRepository
from .comment_repository import CommentRepository
from .space_member_repository import SpaceMemberRepository

__all__ = [
    "SpaceRepository",
    "PostRepository",
    "CommentRepository",
    "SpaceMemberRepository",
]
