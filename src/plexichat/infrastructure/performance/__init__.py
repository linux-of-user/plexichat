# pyright: reportMissingImports=false
# pyright: reportGeneralTypeIssues=false
# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
from .edge_computing_manager import *
from typing import Optional

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
__version__ = "1.0.0"
__author__ = "PlexiChat Development Team"
__description__ = "PlexiChat Performance & Edge Computing Module"
