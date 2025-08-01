# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
from .edge_analytics import router as analytics_router
from .edge_computing import router as edge_router
from .edge_nodes import router as nodes_router
from typing import Optional


"""
PlexiChat API v1 - Edge Computing Module

Enhanced edge computing and distributed processing capabilities.
"""

__all__ = ["edge_router", "nodes_router", "analytics_router"]
