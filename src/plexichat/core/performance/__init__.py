# pyright: reportMissingImports=false
# pyright: reportGeneralTypeIssues=false
# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
# from .edge_computing_manager import *  # Temporarily disabled due to syntax errors


__all__ = [
    "EdgeComputingManager",
    "EdgeNode",
    "NodeType",
    "LoadLevel",
    "ScalingAction",
    "LoadMetrics",
    "ScalingDecision",
    "get_edge_computing_manager"
]

# Version information
from plexichat.src.plexichat.core.config_manager import get_config

__version__ = get_config("system.version", "0.0.0")
__author__ = "PlexiChat Development Team"
__description__ = "PlexiChat Performance & Edge Computing Module"
