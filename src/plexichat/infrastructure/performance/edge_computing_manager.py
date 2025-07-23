# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import asyncio
import math
import random
import statistics
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

try:
    import numpy as np  # type: ignore
except ImportError:
    np = None

from ...core.config import get_config
from plexichat.core.logging import get_logger


try:
    import psutil
except ImportError:
    # Mock psutil for when it's not available
    class MockPsutil:
        @staticmethod
        def cpu_percent():
            return 50.0

        @staticmethod
        def virtual_memory():
            class MockMemory:
                percent = 60.0
                available = 1024 * 1024 * 1024  # 1GB
            return MockMemory()

        @staticmethod
        def disk_usage(path):
            # Mock disk usage for path
            class MockDisk:
                percent = 70.0
                free = 1024 * 1024 * 1024  # 1GB
            return MockDisk()

    psutil = MockPsutil()

"""
PlexiChat Edge Computing & Auto-scaling Manager

Provides distributed computing at network edges with automatic resource scaling
based on load and intelligent traffic routing for optimal performance.
"""

logger = get_logger(__name__)


class NodeType(Enum):
    """Edge node types."""
    EDGE = "edge"
    GATEWAY = "gateway"
    COMPUTE = "compute"
    STORAGE = "storage"
    HYBRID = "hybrid"


class LoadLevel(Enum):
    """System load levels."""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"


class ScalingAction(Enum):
    """Auto-scaling actions."""
    SCALE_UP = "scale_up"
    SCALE_DOWN = "scale_down"
    MAINTAIN = "maintain"
    REDISTRIBUTE = "redistribute"


@dataclass
class EdgeNode:
    """Edge computing node."""
    node_id: str
    node_type: NodeType
    location: str
    ip_address: str
    port: int

    # Resource specifications
    cpu_cores: int
    memory_gb: float
    storage_gb: float
    network_bandwidth_mbps: float

    # Current status
    is_active: bool = True
    is_healthy: bool = True
    last_heartbeat: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # Performance metrics
    cpu_usage_percent: float = 0.0
    memory_usage_percent: float = 0.0
    storage_usage_percent: float = 0.0
    network_usage_percent: float = 0.0

    # Load balancing
    current_connections: int = 0
    max_connections: int = 1000
    request_queue_size: int = 0

    # Geographic info
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    region: Optional[str] = None

    # Capabilities
    supported_services: List[str] = field(default_factory=list)
    gpu_available: bool = False
    ai_acceleration: bool = False

    # Enhanced edge features
    container_runtime: str = "docker"
    kubernetes_enabled: bool = False
    edge_cache_size_gb: float = 10.0
    edge_cache_hit_ratio: float = 0.0
    avg_response_time_ms: float = 0.0
    network_latency_ms: float = 0.0
    uptime_seconds: int = 0

    # Security and compliance
    security_level: str = "standard"  # standard, high, government
    compliance_certifications: List[str] = field(default_factory=list)
    encryption_enabled: bool = True

    # Performance history
    performance_history: deque = field(default_factory=lambda: deque(maxlen=100))

    def update_metrics(self, metrics: Dict[str, float]):
        """Update node metrics with enhanced tracking."""
        self.cpu_usage_percent = metrics.get('cpu_usage', self.cpu_usage_percent)
        self.memory_usage_percent = metrics.get('memory_usage', self.memory_usage_percent)
        self.storage_usage_percent = metrics.get('storage_usage', self.storage_usage_percent)
        self.network_usage_percent = metrics.get('network_usage', self.network_usage_percent)
        self.current_connections = metrics.get('connections', self.current_connections)
        self.request_queue_size = metrics.get('queue_size', self.request_queue_size)
        self.avg_response_time_ms = metrics.get('response_time', self.avg_response_time_ms)
        self.edge_cache_hit_ratio = metrics.get('cache_hit_ratio', self.edge_cache_hit_ratio)
        self.network_latency_ms = metrics.get('network_latency', self.network_latency_ms)

        # Update health status with enhanced criteria
        self.is_healthy = (
            self.cpu_usage_percent < 95 and
            self.memory_usage_percent < 95 and
            self.current_connections < self.max_connections and
            self.avg_response_time_ms < 5000 and  # 5 second max response time
            self.network_latency_ms < 1000  # 1 second max network latency
        )

        # Store in performance history
        self.performance_history.append({
            'timestamp': datetime.now(timezone.utc),
            'cpu_usage': self.cpu_usage_percent,
            'memory_usage': self.memory_usage_percent,
            'storage_usage': self.storage_usage_percent,
            'network_usage': self.network_usage_percent,
            'connections': self.current_connections,
            'response_time': self.avg_response_time_ms,
            'cache_hit_ratio': self.edge_cache_hit_ratio,
            'network_latency': self.network_latency_ms
        })

        self.last_heartbeat = datetime.now(timezone.utc)

    def get_load_level(self) -> LoadLevel:
        """Determine current load level with enhanced criteria."""
        # Consider multiple factors for load calculation
        cpu_weight = 0.4
        memory_weight = 0.3
        connection_weight = 0.2
        response_time_weight = 0.1

        cpu_score = self.cpu_usage_percent
        memory_score = self.memory_usage_percent
        connection_score = (self.current_connections / max(self.max_connections, 1)) * 100
        response_time_score = min(100, (self.avg_response_time_ms / 1000) * 20)  # Normalize to 0-100

        weighted_load = (
            cpu_score * cpu_weight +
            memory_score * memory_weight +
            connection_score * connection_weight +
            response_time_score * response_time_weight
        )

        if weighted_load >= 85:
            return LoadLevel.CRITICAL
        elif weighted_load >= 70:
            return LoadLevel.HIGH
        elif weighted_load >= 40:
            return LoadLevel.NORMAL
        else:
            return LoadLevel.LOW

    def calculate_distance(self, lat: float, lon: float) -> float:
        """Calculate distance to given coordinates using Haversine formula."""
        if self.latitude is None or self.longitude is None:
            return float('inf')

        # Haversine formula for more accurate distance calculation
        R = 6371  # Earth's radius in kilometers

        lat1_rad = math.radians(self.latitude)
        lon1_rad = math.radians(self.longitude)
        lat2_rad = math.radians(lat)
        lon2_rad = math.radians(lon)

        dlat = lat2_rad - lat1_rad
        dlon = lon2_rad - lon1_rad

        a = (math.sin(dlat/2)**2 +
             math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(dlon/2)**2)
        c = 2 * math.asin(math.sqrt(a))

        return R * c

    def get_efficiency_score(self) -> float:
        """Calculate node efficiency score based on multiple factors."""
        # Efficiency factors
        resource_efficiency = 100 - ((self.cpu_usage_percent + self.memory_usage_percent) / 2)
        response_efficiency = max(0, 100 - (self.avg_response_time_ms / 10))  # Lower response time = higher efficiency
        cache_efficiency = self.edge_cache_hit_ratio * 100
        connection_efficiency = max(0, 100 - (self.current_connections / max(self.max_connections, 1) * 100))

        # Weighted efficiency score
        efficiency_score = (
            resource_efficiency * 0.3 +
            response_efficiency * 0.3 +
            cache_efficiency * 0.2 +
            connection_efficiency * 0.2
        )

        return min(100, max(0, efficiency_score))

    def supports_service(self, service_name: str) -> bool:
        """Check if node supports a specific service."""
        return service_name in self.supported_services or len(self.supported_services) == 0

    def get_capacity_remaining(self) -> Dict[str, float]:
        """Get remaining capacity for each resource type."""
        return {
            "cpu_percent": max(0, 100 - self.cpu_usage_percent),
            "memory_percent": max(0, 100 - self.memory_usage_percent),
            "storage_percent": max(0, 100 - self.storage_usage_percent),
            "network_percent": max(0, 100 - self.network_usage_percent),
            "connections": max(0, self.max_connections - self.current_connections)
        }


@dataclass
class LoadMetrics:
    """System load metrics."""
    timestamp: datetime
    total_requests_per_second: float
    average_response_time_ms: float
    error_rate_percent: float
    cpu_usage_percent: float
    memory_usage_percent: float
    network_usage_percent: float
    active_connections: int
    queue_depth: int


@dataclass
class ScalingDecision:
    """Auto-scaling decision."""
    action: ScalingAction
    target_nodes: List[str]
    reason: str
    confidence: float
    estimated_impact: Dict[str, float]
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class EdgeComputingManager:
    """
    Edge Computing & Auto-scaling Manager.

    Features:
    - Distributed edge node management with geographic distribution
    - Intelligent traffic routing based on latency and load
    - Automatic resource scaling based on demand patterns
    - Load balancing with health monitoring
    - Performance optimization with predictive scaling
    - Edge caching and content delivery
    - Fault tolerance with automatic failover
    - Resource allocation optimization
    - Geographic load distribution
    - Real-time performance monitoring
    """

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or self._load_default_config()

        # Edge nodes management
        self.edge_nodes: Dict[str, EdgeNode] = {}
        self.node_groups: Dict[str, List[str]] = defaultdict(list)

        # Load monitoring
        self.load_history: deque = deque(maxlen=1000)
        self.performance_metrics: Dict[str, deque] = defaultdict(lambda: deque(maxlen=500))

        # Auto-scaling
        self.scaling_decisions: deque = deque(maxlen=100)
        self.scaling_cooldown_seconds = self.config.get("scaling_cooldown_seconds", 300)
        self.last_scaling_action = datetime.now(timezone.utc) - timedelta(seconds=self.scaling_cooldown_seconds)

        # Traffic routing
        self.routing_table: Dict[str, List[str]] = {}
        self.traffic_patterns: Dict[str, Dict[str, float]] = defaultdict(dict)

        # Performance thresholds
        self.load_thresholds = self.config.get("load_thresholds", {
            "cpu_high": 80.0,
            "cpu_critical": 95.0,
            "memory_high": 85.0,
            "memory_critical": 95.0,
            "response_time_high": 1000.0,  # ms
            "response_time_critical": 2000.0,  # ms
            "error_rate_high": 5.0,  # %
            "error_rate_critical": 10.0  # %
        })

        # Scaling parameters
        self.min_nodes = self.config.get("min_nodes", 2)
        self.max_nodes = self.config.get("max_nodes", 50)
        self.scale_up_threshold = self.config.get("scale_up_threshold", 0.8)
        self.scale_down_threshold = self.config.get("scale_down_threshold", 0.3)

        # Geographic routing
        self.enable_geographic_routing = self.config.get("enable_geographic_routing", True)
        self.max_routing_distance_km = self.config.get("max_routing_distance_km", 1000)

        # Statistics
        self.edge_stats = {
            "total_requests_routed": 0,
            "scaling_actions_taken": 0,
            "nodes_added": 0,
            "nodes_removed": 0,
            "failovers_performed": 0,
            "average_response_time_ms": 0.0,
            "uptime_seconds": 0
        }

        self.initialized = False
        self.start_time = datetime.now(timezone.utc)

        logger.info(" Edge Computing & Auto-scaling Manager initialized")

    def _load_default_config(self) -> Dict[str, Any]:
        """Load default edge computing configuration."""
        return {
            "monitoring_interval_seconds": 30,
            "scaling_cooldown_seconds": 300,
            "health_check_interval_seconds": 60,
            "load_balancing_algorithm": "weighted_round_robin",
            "enable_geographic_routing": True,
            "enable_predictive_scaling": True,
            "enable_edge_caching": True,
            "max_routing_distance_km": 1000,
            "min_nodes": 2,
            "max_nodes": 50,
            "scale_up_threshold": 0.8,
            "scale_down_threshold": 0.3,
            "auto_scaling_enabled": True,
            "failover_timeout_seconds": 30,
            "node_discovery_enabled": True
        }

    async def initialize(self) -> Dict[str, Any]:
        """Initialize the edge computing manager."""
        try:
            if self.initialized:
                return {"success": True, "message": "Already initialized"}

            logger.info(" Initializing edge computing manager...")

            # Discover and register initial edge nodes
            await self._discover_edge_nodes()

            # Start monitoring and management loops
            asyncio.create_task(self._load_monitoring_loop())
            asyncio.create_task(self._auto_scaling_loop())
            asyncio.create_task(self._health_monitoring_loop())
            asyncio.create_task(self._traffic_routing_optimization_loop())

            if self.config.get("enable_predictive_scaling", True):
                asyncio.create_task(self._predictive_scaling_loop())

            self.initialized = True

            logger.info(f" Edge computing manager initialized with {len(self.edge_nodes)} nodes")

            return {
                "success": True,
                "edge_nodes_count": len(self.edge_nodes),
                "auto_scaling_enabled": self.config.get("auto_scaling_enabled", True),
                "geographic_routing_enabled": self.enable_geographic_routing
            }

        except Exception as e:
            logger.error(f" Failed to initialize edge computing manager: {e}")
            return {"success": False, "error": str(e)}

    async def _discover_edge_nodes(self):
        """Discover and register edge nodes."""
        try:
            logger.info(" Discovering edge nodes...")

            # Add local node as primary edge node
            local_node = EdgeNode(
                node_id="local_primary",
                node_type=NodeType.HYBRID,
                location="local",
                ip_address="127.0.0.1",
                port=8080,
                cpu_cores=psutil.cpu_count(),
                memory_gb=psutil.virtual_memory().total / (1024**3),
                storage_gb=psutil.disk_usage('/').total / (1024**3),
                network_bandwidth_mbps=1000.0,  # Assumed
                supported_services=["api", "web", "backup", "ai", "collaboration"]
            )

            await self.register_edge_node(local_node)

            # TODO: Implement actual node discovery (network scanning, service registry, etc.)
            # For now, create some simulated edge nodes for demonstration

            simulated_nodes = [
                EdgeNode(
                    node_id="edge_east_1",
                    node_type=NodeType.EDGE,
                    location="us-east-1",
                    ip_address="10.0.1.100",
                    port=8080,
                    cpu_cores=8,
                    memory_gb=32.0,
                    storage_gb=500.0,
                    network_bandwidth_mbps=1000.0,
                    latitude=40.7128,
                    longitude=-74.0060,
                    region="us-east",
                    supported_services=["api", "web", "cache"]
                ),
                EdgeNode(
                    node_id="edge_west_1",
                    node_type=NodeType.EDGE,
                    location="us-west-1",
                    ip_address="10.0.2.100",
                    port=8080,
                    cpu_cores=16,
                    memory_gb=64.0,
                    storage_gb=1000.0,
                    network_bandwidth_mbps=2000.0,
                    latitude=37.7749,
                    longitude=-122.4194,
                    region="us-west",
                    supported_services=["api", "web", "ai", "compute"]
                ),
                EdgeNode(
                    node_id="compute_gpu_1",
                    node_type=NodeType.COMPUTE,
                    location="compute-cluster-1",
                    ip_address="10.0.3.100",
                    port=8080,
                    cpu_cores=32,
                    memory_gb=128.0,
                    storage_gb=2000.0,
                    network_bandwidth_mbps=5000.0,
                    gpu_available=True,
                    ai_acceleration=True,
                    supported_services=["ai", "compute", "ml"]
                )
            ]

            for node in simulated_nodes:
                await self.register_edge_node(node)

            logger.info(f" Node discovery completed: {len(self.edge_nodes)} nodes registered")

        except Exception as e:
            logger.error(f" Failed to discover edge nodes: {e}")

    async def register_edge_node(self, node: EdgeNode) -> bool:
        """Register a new edge node."""
        try:
            self.edge_nodes[node.node_id] = node

            # Add to appropriate node group
            self.node_groups[node.node_type.value].append(node.node_id)
            if node.region:
                self.node_groups[f"region_{node.region}"].append(node.node_id)

            # Initialize routing for this node
            await self._update_routing_table()

            logger.info(f" Edge node registered: {node.node_id} ({node.node_type.value}) at {node.location}")

            return True

        except Exception as e:
            logger.error(f" Failed to register edge node {node.node_id}: {e}")
            return False

    async def _load_monitoring_loop(self):
        """Monitor system load and performance."""
        try:
            logger.info(" Starting load monitoring loop...")

            while True:
                try:
                    await asyncio.sleep(self.config.get("monitoring_interval_seconds", 30))

                    # Collect load metrics from all nodes
                    await self._collect_load_metrics()

                    # Analyze load patterns
                    await self._analyze_load_patterns()

                    # Update statistics
                    self.edge_stats["uptime_seconds"] = (datetime.now(timezone.utc) - self.start_time).total_seconds()

                except Exception as e:
                    logger.error(f" Error in load monitoring loop: {e}")
                    continue

        except asyncio.CancelledError:
            logger.info(" Load monitoring loop cancelled")
        except Exception as e:
            logger.error(f" Load monitoring loop failed: {e}")

    async def _collect_load_metrics(self):
        """Collect load metrics from all edge nodes."""
        try:
            current_time = datetime.now(timezone.utc)
            total_requests = 0
            total_response_time = 0.0
            total_errors = 0
            total_cpu = 0.0
            total_memory = 0.0
            total_network = 0.0
            active_nodes = 0
            total_connections = 0
            total_queue_depth = 0

            for node_id, node in self.edge_nodes.items():
                if not node.is_active or not node.is_healthy:
                    continue

                # Simulate metrics collection (in real implementation, this would query actual nodes)
                node_metrics = await self._get_node_metrics(node_id)

                # Update node status
                node.cpu_usage_percent = node_metrics.get("cpu_usage", 0.0)
                node.memory_usage_percent = node_metrics.get("memory_usage", 0.0)
                node.network_usage_percent = node_metrics.get("network_usage", 0.0)
                node.current_connections = node_metrics.get("connections", 0)
                node.request_queue_size = node_metrics.get("queue_size", 0)

                # Aggregate metrics
                total_requests += node_metrics.get("requests_per_second", 0)
                total_response_time += node_metrics.get("response_time_ms", 0)
                total_errors += node_metrics.get("errors_per_second", 0)
                total_cpu += node.cpu_usage_percent
                total_memory += node.memory_usage_percent
                total_network += node.network_usage_percent
                total_connections += node.current_connections
                total_queue_depth += node.request_queue_size
                active_nodes += 1

            if active_nodes > 0:
                # Create aggregate load metrics
                load_metrics = LoadMetrics(
                    timestamp=current_time,
                    total_requests_per_second=total_requests,
                    average_response_time_ms=total_response_time / active_nodes,
                    error_rate_percent=(total_errors / max(total_requests, 1)) * 100,
                    cpu_usage_percent=total_cpu / active_nodes,
                    memory_usage_percent=total_memory / active_nodes,
                    network_usage_percent=total_network / active_nodes,
                    active_connections=total_connections,
                    queue_depth=total_queue_depth
                )

                self.load_history.append(load_metrics)

                # Update performance metrics history
                self.performance_metrics["requests_per_second"].append(load_metrics.total_requests_per_second)
                self.performance_metrics["response_time_ms"].append(load_metrics.average_response_time_ms)
                self.performance_metrics["cpu_usage"].append(load_metrics.cpu_usage_percent)
                self.performance_metrics["memory_usage"].append(load_metrics.memory_usage_percent)

                # Update statistics
                self.edge_stats["average_response_time_ms"] = load_metrics.average_response_time_ms

        except Exception as e:
            logger.error(f" Failed to collect load metrics: {e}")

    async def _get_node_metrics(self, node_id: str) -> Dict[str, float]:
        """Get metrics from a specific node."""
        try:
            # TODO: Implement actual node metrics collection
            # For now, simulate realistic metrics

            base_load = 0.3 + (0.4 * random.random())  # 30-70% base load

            return {
                "cpu_usage": base_load * 100 + (random.random() * 20 - 10),
                "memory_usage": base_load * 100 + (random.random() * 15 - 7.5),
                "network_usage": base_load * 80 + (random.random() * 20 - 10),
                "requests_per_second": base_load * 1000 + (random.random() * 200 - 100),
                "response_time_ms": 50 + (base_load * 200) + (random.random() * 100 - 50),
                "errors_per_second": base_load * 10 + (random.random() * 5),
                "connections": int(base_load * 500 + (random.random() * 100 - 50)),
                "queue_size": int(base_load * 50 + (random.random() * 20 - 10))
            }

        except Exception as e:
            logger.error(f" Failed to get metrics for node {node_id}: {e}")
            return {}

    async def _analyze_load_patterns(self):
        """Analyze load patterns and trends."""
        try:
            if len(self.load_history) < 5:
                return

            recent_metrics = list(self.load_history)[-10:]  # Last 10 measurements

            # Calculate trends
            cpu_trend = self._calculate_trend([m.cpu_usage_percent for m in recent_metrics])
            memory_trend = self._calculate_trend([m.memory_usage_percent for m in recent_metrics])
            response_time_trend = self._calculate_trend([m.average_response_time_ms for m in recent_metrics])

            # Store trends for decision making
            self.performance_metrics["cpu_trend"].append(cpu_trend)
            self.performance_metrics["memory_trend"].append(memory_trend)
            self.performance_metrics["response_time_trend"].append(response_time_trend)

        except Exception as e:
            logger.error(f" Failed to analyze load patterns: {e}")

    def _calculate_trend(self, values: List[float]) -> float:
        """Calculate trend using numpy if available, else return 0."""
        if not values or len(values) < 2:
            return 0.0
        if np is None:
            return 0.0
        x = np.arange(len(values)) if np is not None else list(range(len(values)))
        y = np.array(values) if np is not None else values
        try:
            slope, _ = np.polyfit(x, y, 1)
            return slope
        except Exception:
            return 0.0

    async def _auto_scaling_loop(self):
        """Auto-scaling decision and execution loop."""
        try:
            logger.info(" Starting auto-scaling loop...")

            while True:
                try:
                    await asyncio.sleep(60)  # Check every minute

                    if not self.config.get("auto_scaling_enabled", True):
                        continue

                    # Check if we're in cooldown period
                    if (datetime.now(timezone.utc) - self.last_scaling_action).total_seconds() < self.scaling_cooldown_seconds:
                        continue

                    # Make scaling decision
                    scaling_decision = await self._make_scaling_decision()

                    if scaling_decision and scaling_decision.action != ScalingAction.MAINTAIN:
                        await self._execute_scaling_decision(scaling_decision)

                except Exception as e:
                    logger.error(f" Error in auto-scaling loop: {e}")
                    continue

        except asyncio.CancelledError:
            logger.info(" Auto-scaling loop cancelled")
        except Exception as e:
            logger.error(f" Auto-scaling loop failed: {e}")

    async def _make_scaling_decision(self) -> Optional[ScalingDecision]:
        """Make intelligent scaling decision based on current metrics."""
        try:
            if len(self.load_history) < 3:
                return None

            recent_metrics = list(self.load_history)[-5:]

            # Calculate average metrics over recent period
            avg_cpu = statistics.mean([m.cpu_usage_percent for m in recent_metrics])
            avg_memory = statistics.mean([m.memory_usage_percent for m in recent_metrics])
            avg_response_time = statistics.mean([m.average_response_time_ms for m in recent_metrics])
            avg_error_rate = statistics.mean([m.error_rate_percent for m in recent_metrics])

            # Get trends
            cpu_trend = self.performance_metrics["cpu_trend"][-1] if self.performance_metrics["cpu_trend"] else 0
            memory_trend = self.performance_metrics["memory_trend"][-1] if self.performance_metrics["memory_trend"] else 0
            response_time_trend = self.performance_metrics["response_time_trend"][-1] if self.performance_metrics["response_time_trend"] else 0

            # Count active nodes
            active_nodes = len([n for n in self.edge_nodes.values() if n.is_active and n.is_healthy])

            # Scaling decision logic
            scale_up_score = 0
            scale_down_score = 0
            reasons = []

            # CPU-based scaling
            if avg_cpu > self.load_thresholds["cpu_high"]:
                scale_up_score += 3
                reasons.append(f"High CPU usage: {avg_cpu:.1f}%")
            elif avg_cpu < self.scale_down_threshold * 100:
                scale_down_score += 2
                reasons.append(f"Low CPU usage: {avg_cpu:.1f}%")

            # Memory-based scaling
            if avg_memory > self.load_thresholds["memory_high"]:
                scale_up_score += 3
                reasons.append(f"High memory usage: {avg_memory:.1f}%")
            elif avg_memory < self.scale_down_threshold * 100:
                scale_down_score += 2
                reasons.append(f"Low memory usage: {avg_memory:.1f}%")

            # Response time-based scaling
            if avg_response_time > self.load_thresholds["response_time_high"]:
                scale_up_score += 4
                reasons.append(f"High response time: {avg_response_time:.1f}ms")
            elif avg_response_time < 100:  # Very fast response times
                scale_down_score += 1
                reasons.append(f"Fast response time: {avg_response_time:.1f}ms")

            # Error rate-based scaling
            if avg_error_rate > self.load_thresholds["error_rate_high"]:
                scale_up_score += 5
                reasons.append(f"High error rate: {avg_error_rate:.1f}%")

            # Trend-based scaling
            if cpu_trend > 5 or memory_trend > 5 or response_time_trend > 10:
                scale_up_score += 2
                reasons.append("Increasing load trend detected")
            elif cpu_trend < -5 and memory_trend < -5 and response_time_trend < -10:
                scale_down_score += 1
                reasons.append("Decreasing load trend detected")

            # Node count constraints
            if active_nodes >= self.max_nodes:
                scale_up_score = 0
                reasons = ["Maximum node count reached"]
            elif active_nodes <= self.min_nodes:
                scale_down_score = 0
                reasons = ["Minimum node count reached"]

            # Make decision
            if scale_up_score > scale_down_score and scale_up_score >= 3:
                action = ScalingAction.SCALE_UP
                confidence = min(0.9, scale_up_score / 10.0)
            elif scale_down_score > scale_up_score and scale_down_score >= 3 and active_nodes > self.min_nodes:
                action = ScalingAction.SCALE_DOWN
                confidence = min(0.8, scale_down_score / 8.0)
            else:
                action = ScalingAction.MAINTAIN
                confidence = 0.5

            if action == ScalingAction.MAINTAIN:
                return None

            # Select target nodes
            target_nodes = await self._select_scaling_targets(action)

            return ScalingDecision(
                action=action,
                target_nodes=target_nodes,
                reason="; ".join(reasons),
                confidence=confidence,
                estimated_impact={
                    "cpu_reduction": -20.0 if action == ScalingAction.SCALE_UP else 10.0,
                    "response_time_improvement": -100.0 if action == ScalingAction.SCALE_UP else 50.0,
                    "capacity_increase": 50.0 if action == ScalingAction.SCALE_UP else -25.0
                }
            )

        except Exception as e:
            logger.error(f" Failed to make scaling decision: {e}")
            return None

    async def _select_scaling_targets(self, action: ScalingAction) -> List[str]:
        """Select target nodes for scaling action."""
        try:
            if action == ScalingAction.SCALE_UP:
                # TODO: Implement node provisioning logic
                # For now, return placeholder for new node
                return ["new_node_placeholder"]

            elif action == ScalingAction.SCALE_DOWN:
                # Select least utilized nodes for removal
                active_nodes = [(node_id, node) for node_id, node in self.edge_nodes.items()
                              if node.is_active and node.is_healthy]

                if len(active_nodes) <= self.min_nodes:
                    return []

                # Sort by utilization (CPU + Memory + Network)
                active_nodes.sort(key=lambda x: (
                    x[1].cpu_usage_percent +
                    x[1].memory_usage_percent +
                    x[1].network_usage_percent
                ))

                # Return the least utilized node
                return [active_nodes[0][0]] if active_nodes else []

            return []

        except Exception as e:
            logger.error(f" Failed to select scaling targets: {e}")
            return []

    async def _execute_scaling_decision(self, decision: ScalingDecision):
        """Execute scaling decision."""
        try:
            logger.info(f" Executing scaling decision: {decision.action.value} - {decision.reason}")

            if decision.action == ScalingAction.SCALE_UP:
                success = await self._scale_up_nodes(decision.target_nodes)
                if success:
                    self.edge_stats["nodes_added"] += len(decision.target_nodes)

            elif decision.action == ScalingAction.SCALE_DOWN:
                success = await self._scale_down_nodes(decision.target_nodes)
                if success:
                    self.edge_stats["nodes_removed"] += len(decision.target_nodes)

            elif decision.action == ScalingAction.REDISTRIBUTE:
                success = await self._redistribute_load(decision.target_nodes)

            else:
                success = False

            if success:
                self.scaling_decisions.append(decision)
                self.last_scaling_action = datetime.now(timezone.utc)
                self.edge_stats["scaling_actions_taken"] += 1

                logger.info(f" Scaling action completed: {decision.action.value}")
            else:
                logger.warning(f" Scaling action failed: {decision.action.value}")

        except Exception as e:
            logger.error(f" Failed to execute scaling decision: {e}")

    async def _scale_up_nodes(self, target_nodes: List[str]) -> bool:
        """Scale up by adding new nodes."""
        try:
            # TODO: Implement actual node provisioning
            # This would typically involve:
            # 1. Provisioning new cloud instances
            # 2. Installing and configuring PlexiChat
            # 3. Registering the new nodes
            # 4. Updating load balancer configuration

            logger.info(f" Scaling up: Adding {len(target_nodes)} nodes")

            # For demonstration, simulate adding nodes
            for i, target in enumerate(target_nodes):
                logger.info(f"Adding node {i} with target {target}")
                new_node = EdgeNode(
                    node_id=f"auto_scaled_{int(time.time())}_{i}",
                    node_type=NodeType.EDGE,
                    location=f"auto-scaled-{i}",
                    ip_address=f"10.0.100.{100 + i}",
                    port=8080,
                    cpu_cores=8,
                    memory_gb=32.0,
                    storage_gb=500.0,
                    network_bandwidth_mbps=1000.0,
                    supported_services=["api", "web"]
                )

                await self.register_edge_node(new_node)

            return True

        except Exception as e:
            logger.error(f" Failed to scale up nodes: {e}")
            return False

    async def _scale_down_nodes(self, target_nodes: List[str]) -> bool:
        """Scale down by removing nodes."""
        try:
            logger.info(f" Scaling down: Removing {len(target_nodes)} nodes")

            for node_id in target_nodes:
                if node_id in self.edge_nodes:
                    # Gracefully drain connections
                    await self._drain_node_connections(node_id)

                    # Remove from routing
                    await self._remove_node_from_routing(node_id)

                    # Deactivate node
                    self.edge_nodes[node_id].is_active = False

                    logger.info(f" Node deactivated: {node_id}")

            return True

        except Exception as e:
            logger.error(f" Failed to scale down nodes: {e}")
            return False

    async def _drain_node_connections(self, node_id: str):
        """Gracefully drain connections from a node."""
        try:
            # TODO: Implement connection draining
            # This would involve:
            # 1. Stop accepting new connections
            # 2. Wait for existing connections to complete
            # 3. Redirect remaining connections to other nodes

            logger.info(f" Draining connections from node: {node_id}")

            # Simulate draining delay
            await asyncio.sleep(5)

        except Exception as e:
            logger.error(f" Failed to drain connections from node {node_id}: {e}")

    async def _redistribute_load(self, target_nodes: List[str]) -> bool:
        """Redistribute load across nodes."""
        try:
            logger.info(f" Redistributing load across {len(target_nodes)} nodes")

            # Update routing weights based on current node capacity
            await self._update_routing_weights()

            return True

        except Exception as e:
            logger.error(f" Failed to redistribute load: {e}")
            return False

    async def _health_monitoring_loop(self):
        """Monitor node health and perform failover if needed."""
        try:
            logger.info(" Starting health monitoring loop...")

            while True:
                try:
                    await asyncio.sleep(self.config.get("health_check_interval_seconds", 60))

                    # Check health of all nodes
                    await self._check_node_health()

                    # Perform failover for unhealthy nodes
                    await self._handle_node_failures()

                except Exception as e:
                    logger.error(f" Error in health monitoring loop: {e}")
                    continue

        except asyncio.CancelledError:
            logger.info(" Health monitoring loop cancelled")
        except Exception as e:
            logger.error(f" Health monitoring loop failed: {e}")

    async def _check_node_health(self):
        """Check health status of all nodes."""
        try:
            current_time = datetime.now(timezone.utc)

            for node_id, node in self.edge_nodes.items():
                if not node.is_active:
                    continue

                # Check heartbeat timeout
                heartbeat_timeout = timedelta(seconds=self.config.get("heartbeat_timeout_seconds", 120))
                if current_time - node.last_heartbeat > heartbeat_timeout:
                    node.is_healthy = False
                    logger.warning(f" Node {node_id} heartbeat timeout")
                    continue

                # Check resource thresholds
                if (node.cpu_usage_percent > 95 or
                    node.memory_usage_percent > 95 or
                    node.request_queue_size > node.max_connections * 0.9):
                    node.is_healthy = False
                    logger.warning(f" Node {node_id} resource exhaustion")
                    continue

                # Node is healthy
                if not node.is_healthy:
                    node.is_healthy = True
                    logger.info(f" Node {node_id} recovered")

        except Exception as e:
            logger.error(f" Failed to check node health: {e}")

    async def _handle_node_failures(self):
        """Handle failed nodes with automatic failover."""
        try:
            failed_nodes = [node_id for node_id, node in self.edge_nodes.items()
                          if node.is_active and not node.is_healthy]

            if not failed_nodes:
                return

            logger.warning(f" Handling {len(failed_nodes)} failed nodes")

            for node_id in failed_nodes:
                # Remove from routing
                await self._remove_node_from_routing(node_id)

                # Redistribute its load
                await self._redistribute_node_load(node_id)

                # Mark as inactive
                self.edge_nodes[node_id].is_active = False

                self.edge_stats["failovers_performed"] += 1

                logger.warning(f" Node {node_id} failed over")

        except Exception as e:
            logger.error(f" Failed to handle node failures: {e}")

    async def _remove_node_from_routing(self, node_id: str):
        """Remove node from routing table."""
        try:
            # Remove from all routing groups
            for service, nodes in self.routing_table.items():
                if node_id in nodes:
                    logger.info(f"Removing node {node_id} from service {service}")
                    nodes.remove(node_id)

            # Remove from node groups
            for group, nodes in self.node_groups.items():
                if node_id in nodes:
                    logger.info(f"Removing node {node_id} from group {group}")
                    nodes.remove(node_id)

            logger.info(f" Node {node_id} removed from routing")

        except Exception as e:
            logger.error(f" Failed to remove node from routing: {e}")

    async def _redistribute_node_load(self, failed_node_id: str):
        """Redistribute load from a failed node."""
        try:
            failed_node = self.edge_nodes.get(failed_node_id)
            if not failed_node:
                return

            # Find healthy nodes that can handle the load
            healthy_nodes = [node for node in self.edge_nodes.values()
                           if node.is_active and node.is_healthy and node.node_id != failed_node_id]

            if not healthy_nodes:
                logger.error(" No healthy nodes available for load redistribution")
                return

            # Distribute connections across healthy nodes
            connections_per_node = failed_node.current_connections // len(healthy_nodes)

            for node in healthy_nodes:
                node.current_connections += connections_per_node

            logger.info(f" Redistributed {failed_node.current_connections} connections from {failed_node_id}")

        except Exception as e:
            logger.error(f" Failed to redistribute node load: {e}")

    async def _traffic_routing_optimization_loop(self):
        """Optimize traffic routing based on performance metrics."""
        try:
            logger.info(" Starting traffic routing optimization loop...")

            while True:
                try:
                    await asyncio.sleep(300)  # Optimize every 5 minutes

                    # Update routing table based on current performance
                    await self._optimize_routing_table()

                    # Update routing weights
                    await self._update_routing_weights()

                except Exception as e:
                    logger.error(f" Error in traffic routing optimization: {e}")
                    continue

        except asyncio.CancelledError:
            logger.info(" Traffic routing optimization loop cancelled")
        except Exception as e:
            logger.error(f" Traffic routing optimization loop failed: {e}")

    async def _optimize_routing_table(self):
        """Optimize routing table based on node performance."""
        try:
            # Group nodes by service capabilities
            service_nodes = defaultdict(list)

            for node_id, node in self.edge_nodes.items():
                if not node.is_active or not node.is_healthy:
                    continue

                for service in node.supported_services:
                    service_nodes[service].append(node_id)

            # Update routing table
            self.routing_table = dict(service_nodes)

            logger.debug(f" Routing table updated: {len(self.routing_table)} services")

        except Exception as e:
            logger.error(f" Failed to optimize routing table: {e}")

    async def _update_routing_weights(self):
        """Update routing weights based on node performance."""
        try:
            for service, node_ids in self.routing_table.items():
                weights = {}

                for node_id in node_ids:
                    node = self.edge_nodes.get(node_id)
                    if not node or not node.is_healthy:
                        weights[node_id] = 0
                        continue

                    # Calculate weight based on available capacity
                    cpu_capacity = max(0, 100 - node.cpu_usage_percent)
                    memory_capacity = max(0, 100 - node.memory_usage_percent)
                    connection_capacity = max(0, node.max_connections - node.current_connections)

                    # Normalize connection capacity to 0-100 scale
                    connection_capacity_percent = (connection_capacity / node.max_connections) * 100

                    # Calculate composite weight
                    weight = (cpu_capacity + memory_capacity + connection_capacity_percent) / 3
                    weights[node_id] = max(1, weight)  # Minimum weight of 1

                # Store weights for load balancer
                self.traffic_patterns[service] = weights

        except Exception as e:
            logger.error(f" Failed to update routing weights: {e}")

    async def _update_routing_table(self):
        """Update routing table with current healthy nodes."""
        try:
            await self._optimize_routing_table()

        except Exception as e:
            logger.error(f" Failed to update routing table: {e}")

    async def _predictive_scaling_loop(self):
        """Predictive scaling based on historical patterns."""
        try:
            logger.info(" Starting predictive scaling loop...")

            while True:
                try:
                    await asyncio.sleep(1800)  # Run every 30 minutes

                    # Analyze historical patterns
                    predictions = await self._analyze_scaling_patterns()

                    # Make predictive scaling decisions
                    for prediction in predictions:
                        await self._execute_predictive_scaling(prediction)

                except Exception as e:
                    logger.error(f" Error in predictive scaling: {e}")
                    continue

        except asyncio.CancelledError:
            logger.info(" Predictive scaling loop cancelled")
        except Exception as e:
            logger.error(f" Predictive scaling loop failed: {e}")

    async def _analyze_scaling_patterns(self) -> List[Dict[str, Any]]:
        """Analyze historical patterns for predictive scaling."""
        try:
            if len(self.load_history) < 50:  # Need sufficient history
                return []

            predictions = []

            # Analyze load patterns by time of day
            current_hour = datetime.now(timezone.utc).hour

            # Get historical data for the same hour
            same_hour_metrics = [
                m for m in self.load_history
                if m.timestamp.hour == current_hour
            ]

            if len(same_hour_metrics) >= 5:
                # Calculate average load for this hour
                avg_cpu = statistics.mean([m.cpu_usage_percent for m in same_hour_metrics])
                avg_memory = statistics.mean([m.memory_usage_percent for m in same_hour_metrics])
                avg_response_time = statistics.mean([m.average_response_time_ms for m in same_hour_metrics])

                # Predict if scaling will be needed
                if avg_cpu > self.load_thresholds["cpu_high"] * 0.8:
                    predictions.append({
                        "action": "scale_up",
                        "reason": f"Historical pattern shows high CPU at hour {current_hour}",
                        "confidence": 0.7,
                        "metric": "cpu",
                        "predicted_value": avg_cpu
                    })

                if avg_response_time > self.load_thresholds["response_time_high"] * 0.8:
                    predictions.append({
                        "action": "scale_up",
                        "reason": f"Historical pattern shows high response time at hour {current_hour}",
                        "confidence": 0.6,
                        "metric": "response_time",
                        "predicted_value": avg_response_time
                    })

            return predictions

        except Exception as e:
            logger.error(f" Failed to analyze scaling patterns: {e}")
            return []

    async def _execute_predictive_scaling(self, prediction: Dict[str, Any]):
        """Execute predictive scaling decision."""
        try:
            if prediction["confidence"] < 0.6:
                return  # Skip low-confidence predictions

            logger.info(f" Executing predictive scaling: {prediction['reason']}")

            # Create scaling decision
            if prediction["action"] == "scale_up":
                target_nodes = await self._select_scaling_targets(ScalingAction.SCALE_UP)

                decision = ScalingDecision(
                    action=ScalingAction.SCALE_UP,
                    target_nodes=target_nodes,
                    reason=f"Predictive: {prediction['reason']}",
                    confidence=prediction["confidence"],
                    estimated_impact={"predictive": True}
                )

                await self._execute_scaling_decision(decision)

        except Exception as e:
            logger.error(f" Failed to execute predictive scaling: {e}")

    async def get_edge_status(self) -> Dict[str, Any]:
        """Get comprehensive edge computing status."""
        try:
            active_nodes = [n for n in self.edge_nodes.values() if n.is_active]
            healthy_nodes = [n for n in active_nodes if n.is_healthy]

            # Calculate aggregate metrics
            total_cpu_capacity = sum(n.cpu_cores for n in active_nodes)
            total_memory_capacity = sum(n.memory_gb for n in active_nodes)
            total_storage_capacity = sum(n.storage_gb for n in active_nodes)

            avg_cpu_usage = statistics.mean([n.cpu_usage_percent for n in healthy_nodes]) if healthy_nodes else 0
            avg_memory_usage = statistics.mean([n.memory_usage_percent for n in healthy_nodes]) if healthy_nodes else 0

            # Get recent performance
            recent_metrics = list(self.load_history)[-10:] if self.load_history else []
            avg_response_time = statistics.mean([m.average_response_time_ms for m in recent_metrics]) if recent_metrics else 0

            return {
                "total_nodes": len(self.edge_nodes),
                "active_nodes": len(active_nodes),
                "healthy_nodes": len(healthy_nodes),
                "node_types": {
                    node_type.value: len(self.node_groups.get(node_type.value, []))
                    for node_type in NodeType
                },
                "capacity": {
                    "total_cpu_cores": total_cpu_capacity,
                    "total_memory_gb": total_memory_capacity,
                    "total_storage_gb": total_storage_capacity
                },
                "utilization": {
                    "average_cpu_percent": avg_cpu_usage,
                    "average_memory_percent": avg_memory_usage,
                    "average_response_time_ms": avg_response_time
                },
                "scaling": {
                    "auto_scaling_enabled": self.config.get("auto_scaling_enabled", True),
                    "recent_scaling_actions": len(self.scaling_decisions),
                    "last_scaling_action": self.last_scaling_action.isoformat() if self.last_scaling_action else None
                },
                "routing": {
                    "services_configured": len(self.routing_table),
                    "geographic_routing_enabled": self.enable_geographic_routing
                },
                "statistics": self.edge_stats.copy()
            }

        except Exception as e:
            logger.error(f" Failed to get edge status: {e}")
            return {}

    async def get_node_details(self, node_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a specific node."""
        try:
            node = self.edge_nodes.get(node_id)
            if not node:
                return None

            return {
                "node_id": node.node_id,
                "node_type": node.node_type.value,
                "location": node.location,
                "address": f"{node.ip_address}:{node.port}",
                "status": {
                    "is_active": node.is_active,
                    "is_healthy": node.is_healthy,
                    "last_heartbeat": node.last_heartbeat.isoformat()
                },
                "resources": {
                    "cpu_cores": node.cpu_cores,
                    "memory_gb": node.memory_gb,
                    "storage_gb": node.storage_gb,
                    "network_bandwidth_mbps": node.network_bandwidth_mbps
                },
                "utilization": {
                    "cpu_usage_percent": node.cpu_usage_percent,
                    "memory_usage_percent": node.memory_usage_percent,
                    "storage_usage_percent": node.storage_usage_percent,
                    "network_usage_percent": node.network_usage_percent
                },
                "connections": {
                    "current_connections": node.current_connections,
                    "max_connections": node.max_connections,
                    "request_queue_size": node.request_queue_size
                },
                "capabilities": {
                    "supported_services": node.supported_services,
                    "gpu_available": node.gpu_available,
                    "ai_acceleration": node.ai_acceleration
                },
                "geographic": {
                    "latitude": node.latitude,
                    "longitude": node.longitude,
                    "region": node.region
                }
            }

        except Exception as e:
            logger.error(f" Failed to get node details for {node_id}: {e}")
            return None

    # ==================== ENHANCED EDGE COMPUTING METHODS ====================

    async def deploy_service_to_edge(self, service_name: str, node_ids: List[str], deployment_config: Dict[str, Any]) -> Dict[str, Any]:
        """Deploy a service to specific edge nodes."""
        try:
            deployment_results = {}

            for node_id in node_ids:
                if node_id not in self.edge_nodes:
                    deployment_results[node_id] = {"success": False, "error": "Node not found"}
                    continue

                node = self.edge_nodes[node_id]

                # Check if node supports the service
                if not node.supports_service(service_name):
                    deployment_results[node_id] = {"success": False, "error": "Service not supported"}
                    continue

                # Check resource availability
                capacity = node.get_capacity_remaining()
                required_cpu = deployment_config.get("cpu_percent", 10)
                required_memory = deployment_config.get("memory_percent", 10)

                if capacity["cpu_percent"] < required_cpu or capacity["memory_percent"] < required_memory:
                    deployment_results[node_id] = {"success": False, "error": "Insufficient resources"}
                    continue

                # Simulate deployment (in real implementation, this would use container orchestration)
                deployment_results[node_id] = {
                    "success": True,
                    "deployment_id": f"{service_name}_{node_id}_{int(time.time())}",
                    "resources_allocated": {
                        "cpu_percent": required_cpu,
                        "memory_percent": required_memory
                    }
                }

                logger.info(f" Service {service_name} deployed to node {node_id}")

            return {
                "service_name": service_name,
                "deployment_results": deployment_results,
                "total_deployments": len([r for r in deployment_results.values() if r["success"]]),
                "failed_deployments": len([r for r in deployment_results.values() if not r["success"]])
            }

        except Exception as e:
            logger.error(f" Failed to deploy service {service_name}: {e}")
            return {"error": str(e)}

    async def get_optimal_node_for_request(self, client_lat: float, client_lon: float, service_name: Optional[str] = None) -> Optional[str]:
        """Find the optimal edge node for a client request."""
        try:
            candidate_nodes = []

            for node_id, node in self.edge_nodes.items():
                if not node.is_active or not node.is_healthy:
                    continue

                if service_name and not node.supports_service(service_name):
                    continue

                # Calculate distance
                distance = node.calculate_distance(client_lat, client_lon)
                if distance > self.max_routing_distance_km:
                    continue

                # Calculate node score based on multiple factors
                load_level = node.get_load_level()
                efficiency_score = node.get_efficiency_score()

                # Scoring weights
                distance_weight = 0.4
                load_weight = 0.3
                efficiency_weight = 0.2
                response_time_weight = 0.1

                # Normalize scores (lower is better for distance and load, higher is better for efficiency)
                distance_score = max(0, 100 - (distance / 100))  # Normalize distance
                load_score = 100 - (load_level.value == "critical" and 100 or
                                   load_level.value == "high" and 75 or
                                   load_level.value == "normal" and 50 or 25)
                response_score = max(0, 100 - (node.avg_response_time_ms / 50))

                total_score = (
                    distance_score * distance_weight +
                    load_score * load_weight +
                    efficiency_score * efficiency_weight +
                    response_score * response_time_weight
                )

                candidate_nodes.append({
                    "node_id": node_id,
                    "score": total_score,
                    "distance": distance,
                    "load_level": load_level.value,
                    "efficiency": efficiency_score
                })

            if not candidate_nodes:
                return None

            # Sort by score (highest first)
            candidate_nodes.sort(key=lambda x: x["score"], reverse=True)

            return candidate_nodes[0]["node_id"]

        except Exception as e:
            logger.error(f" Failed to find optimal node: {e}")
            return None

    async def remove_edge_node(self, node_id: str) -> bool:
        """Remove an edge node from the system."""
        try:
            if node_id not in self.edge_nodes:
                return False

            # Remove from edge nodes
            del self.edge_nodes[node_id]

            # Remove from node groups
            for group_nodes in self.node_groups.values():
                if node_id in group_nodes:
                    group_nodes.remove(node_id)

            # Update routing table
            await self._update_routing_table()

            logger.info(f" Edge node {node_id} removed successfully")
            return True

        except Exception as e:
            logger.error(f" Failed to remove edge node {node_id}: {e}")
            return False


# Global instance
_edge_computing_manager: Optional[EdgeComputingManager] = None


def get_edge_computing_manager() -> EdgeComputingManager:
    """Get the global edge computing manager instance."""
    global _edge_computing_manager
    if _edge_computing_manager is None:
        config = get_config().get("edge_computing", {})
        _edge_computing_manager = EdgeComputingManager(config)
    return _edge_computing_manager
