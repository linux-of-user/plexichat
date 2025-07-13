from enum import Enum
from typing import Any, Dict

"""
PlexiChat Clustering Core Components

Core clustering system constants and configuration for government-level
performance optimization and intelligent load distribution.
"""

# Clustering System Version
CLUSTERING_VERSION = "2.0.0"

# Performance Constants
MINIMUM_PERFORMANCE_GAIN = 1.5  # 50% minimum performance improvement
TARGET_PERFORMANCE_GAIN = 3.0   # 300% target performance improvement
MAXIMUM_LATENCY_MS = 100        # Maximum acceptable latency
OPTIMAL_LATENCY_MS = 10         # Optimal latency target

# Load Balancing Constants
DEFAULT_LOAD_THRESHOLD = 0.8    # 80% load threshold
CRITICAL_LOAD_THRESHOLD = 0.95  # 95% critical load threshold
REBALANCE_INTERVAL = 30         # 30 seconds rebalancing interval
MAX_CONCURRENT_CONNECTIONS = 10000

# Node Management Constants
MINIMUM_CLUSTER_SIZE = 3        # Minimum nodes for clustering
OPTIMAL_CLUSTER_SIZE = 7        # Optimal cluster size
MAXIMUM_CLUSTER_SIZE = 50       # Maximum supported cluster size
NODE_HEALTH_CHECK_INTERVAL = 15 # 15 seconds health check

# Failover Constants
FAILOVER_TIMEOUT_SECONDS = 5    # 5 second failover timeout
MAX_FAILOVER_ATTEMPTS = 3       # Maximum failover attempts
RECOVERY_VERIFICATION_TIME = 60 # 60 seconds recovery verification

# Security Constants
CLUSTER_ENCRYPTION_ENABLED = True
INTER_NODE_AUTHENTICATION = True
CLUSTER_ACCESS_CONTROL = True

# Performance Monitoring Constants
METRICS_COLLECTION_INTERVAL = 5  # 5 seconds metrics collection
PERFORMANCE_HISTORY_DAYS = 30    # 30 days performance history
ALERT_THRESHOLD_CPU = 0.9        # 90% CPU alert threshold
ALERT_THRESHOLD_MEMORY = 0.85    # 85% memory alert threshold
ALERT_THRESHOLD_DISK = 0.9       # 90% disk alert threshold

# Encrypted Communication Constants
INTER_NODE_ENCRYPTION = True     # Enable encrypted inter-node communication
ENCRYPTION_ALGORITHM = "AES-256-GCM"  # Encryption algorithm for node communication
KEY_ROTATION_INTERVAL = 3600     # 1 hour key rotation
HEARTBEAT_ENCRYPTION = True      # Encrypt heartbeat messages
HOT_UPDATE_SUPPORT = True        # Support for hot updates without downtime

class ClusterRole(Enum):
    """Cluster node roles."""
    MASTER = "master"
    WORKER = "worker"
    COORDINATOR = "coordinator"
    BACKUP = "backup"
    GATEWAY = "gateway"           # Gateway/proxy node
    ANTIVIRUS = "antivirus"       # Specialized antivirus scanning node
    GENERAL_PURPOSE = "general_purpose"  # Multi-purpose node
    OBSERVER = "observer"

class NodeStatus(Enum):
    """Node status in cluster."""
    ONLINE = "online"
    OFFLINE = "offline"
    DEGRADED = "degraded"
    MAINTENANCE = "maintenance"
    JOINING = "joining"
    LEAVING = "leaving"
    FAILED = "failed"

class LoadBalancingStrategy(Enum):
    """Load balancing strategies."""
    ROUND_ROBIN = "round_robin"
    LEAST_CONNECTIONS = "least_connections"
    WEIGHTED_ROUND_ROBIN = "weighted_round_robin"
    LEAST_RESPONSE_TIME = "least_response_time"
    RESOURCE_BASED = "resource_based"
    AI_OPTIMIZED = "ai_optimized"

class PerformanceMetric(Enum):
    """Performance metrics."""
    CPU_USAGE = "cpu_usage"
    MEMORY_USAGE = "memory_usage"
    DISK_USAGE = "disk_usage"
    NETWORK_THROUGHPUT = "network_throughput"
    RESPONSE_TIME = "response_time"
    REQUESTS_PER_SECOND = "requests_per_second"
    ERROR_RATE = "error_rate"
    AVAILABILITY = "availability"

# Default Configuration
DEFAULT_CLUSTER_CONFIG: Dict[str, Any] = {
    "cluster_name": "plexichat_cluster",
    "security_level": "government",
    "encryption_enabled": CLUSTER_ENCRYPTION_ENABLED,
    "authentication_required": INTER_NODE_AUTHENTICATION,
    "load_balancing_strategy": LoadBalancingStrategy.AI_OPTIMIZED.value,
    "performance_monitoring": True,
    "automatic_failover": True,
    "auto_scaling": True,
    "metrics_retention_days": PERFORMANCE_HISTORY_DAYS,
    "health_check_interval": NODE_HEALTH_CHECK_INTERVAL,
    "rebalance_interval": REBALANCE_INTERVAL,
    "max_nodes": MAXIMUM_CLUSTER_SIZE,
    "min_nodes": MINIMUM_CLUSTER_SIZE,
    "target_performance_gain": TARGET_PERFORMANCE_GAIN
}
