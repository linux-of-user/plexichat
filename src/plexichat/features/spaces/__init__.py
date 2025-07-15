from .models import *
from .repositories import *
from .services import *
from typing import Optional


"""
PlexiChat Spaces Feature Package

Reddit-like community spaces with posts, comments, and voting.
"""

__version__ = "1.0.0"
__all__ = [
    # Models
    "Space",
    "Post",
    "Comment",
    "SpaceMember",
    "Vote",
    # Repositories
    "SpaceRepository",
    "PostRepository",
    "CommentRepository",
    "SpaceMemberRepository",
    "VoteRepository",
    # Services
    "SpaceService",
    "PostService",
    "CommentService",
    "VotingService",
]
