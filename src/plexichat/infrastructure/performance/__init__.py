"""
PlexiChat Performance & Edge Computing Module

This module provides comprehensive performance optimization and edge computing
capabilities for the PlexiChat platform.

Features:
- Edge Computing & Auto-scaling Manager
- Distributed node management with geographic distribution
- Intelligent traffic routing and load balancing
- Automatic resource scaling based on demand patterns
- Performance monitoring and analytics
- Health monitoring with automatic failover
- Predictive scaling based on historical patterns
- Multi-tier caching system integration
- Real-time performance metrics collection

Components:
- EdgeComputingManager: Core edge computing and auto-scaling functionality
- Performance monitoring and metrics collection
- Traffic routing optimization
- Node health monitoring and failover
- API endpoints for management and monitoring
"""

from .edge_computing_manager import (
    EdgeComputingManager,
    EdgeNode,
    NodeType,
    LoadLevel,
    ScalingAction,
    LoadMetrics,
    ScalingDecision,
    get_edge_computing_manager
)

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
