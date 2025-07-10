"""
NetLink Advanced Clustering System

Consolidated clustering functionality from:
- src/netlink/clustering/ (main clustering system)
- src/netlink/app/clustering/ (additional node management)

The defining feature of NetLink - a sophisticated clustering system with:
- Performance optimization and tangible gains
- Intelligent load balancing
- Real-time performance monitoring
- Smart node distribution
- Automatic failover and recovery
- Government-level security
- Multi-node clustering with specialized nodes
- Hybrid cloud support
- Service mesh architecture
"""

from .core.cluster_manager import AdvancedClusterManager
from .core.node_manager import IntelligentNodeManager
from .core.load_balancer import SmartLoadBalancer
from .core.performance_monitor import RealTimePerformanceMonitor
from .core.failover_manager import AutomaticFailoverManager
from .core.task_manager import AdvancedTaskManager, TaskStatus, TaskPriority, TaskType, ClusterTask

__version__ = "2.0.0"
__all__ = [
    "AdvancedClusterManager",
    "IntelligentNodeManager",
    "SmartLoadBalancer",
    "RealTimePerformanceMonitor",
    "AutomaticFailoverManager",
    "AdvancedTaskManager",
    "TaskStatus",
    "TaskPriority",
    "TaskType",
    "ClusterTask"
]

# Clustering system capabilities and performance targets
CLUSTERING_FEATURES = {
    "minimum_performance_gain": "50%",
    "target_performance_gain": "300%",
    "supported_load_balancing_strategies": 6,
    "real_time_monitoring": True,
    "automatic_failover": True,
    "intelligent_scaling": True,
    "government_level_security": True,
    "comprehensive_analytics": True,
    "components": {
        "cluster_manager": "Advanced orchestration and coordination",
        "node_manager": "Intelligent node optimization and distribution",
        "load_balancer": "AI-optimized traffic distribution",
        "performance_monitor": "Real-time metrics and analysis",
        "failover_manager": "Automatic failure detection and recovery",
        "task_manager": "Intelligent task scheduling and distribution"
    }
}
