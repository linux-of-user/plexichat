"""
PlexiChat API v1 - Edge Computing Module

Enhanced edge computing and distributed processing capabilities.
"""

from .edge_computing import router as edge_router
from .edge_nodes import router as nodes_router
from .edge_analytics import router as analytics_router

__all__ = [
    "edge_router",
    "nodes_router", 
    "analytics_router"
]
