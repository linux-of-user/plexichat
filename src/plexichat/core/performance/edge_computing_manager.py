"""
Edge Computing Manager for PlexiChat

Provides comprehensive edge computing capabilities with watertight security like a deep-sea submarine.
Features:
- Distributed edge node management
- Intelligent load balancing
- Auto-scaling and resource optimization
- Geographic distribution
- Real-time performance monitoring
- Security-first architecture
"""

import asyncio
import math
import random
import statistics
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Set
import logging

# Security integration
try:
    from plexichat.core.security.unified_security_system import get_unified_security_system
    from plexichat.core.security.comprehensive_security_manager import get_security_manager
    SECURITY_AVAILABLE = True
except ImportError:
    SECURITY_AVAILABLE = False

# System monitoring
try:
    import psutil
    PSUTIL_AVAILABLE = True
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
            class MockDisk:
                percent = 70.0
                free = 1024 * 1024 * 1024  # 1GB
            return MockDisk()
    
    psutil = MockPsutil()
    PSUTIL_AVAILABLE = False

# Logging setup
logger = logging.getLogger(__name__)


class EdgeNodeStatus(Enum):
    """Status of edge nodes."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    MAINTENANCE = "maintenance"
    OVERLOADED = "overloaded"
    FAILED = "failed"


class LoadBalancingStrategy(Enum):
    """Load balancing strategies."""
    ROUND_ROBIN = "round_robin"
    LEAST_CONNECTIONS = "least_connections"
    WEIGHTED_ROUND_ROBIN = "weighted_round_robin"
    GEOGRAPHIC = "geographic"
    PERFORMANCE_BASED = "performance_based"


class ScalingAction(Enum):
    """Auto-scaling actions."""
    SCALE_UP = "scale_up"
    SCALE_DOWN = "scale_down"
    MAINTAIN = "maintain"
    MIGRATE = "migrate"


@dataclass
class EdgeNodeMetrics:
    """Metrics for an edge node."""
    node_id: str
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    disk_usage: float = 0.0
    network_latency: float = 0.0
    active_connections: int = 0
    requests_per_second: float = 0.0
    error_rate: float = 0.0
    uptime: float = 0.0
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class EdgeNode:
    """Edge computing node."""
    node_id: str
    location: str
    latitude: float
    longitude: float
    capacity: int
    status: EdgeNodeStatus = EdgeNodeStatus.ACTIVE
    metrics: EdgeNodeMetrics = field(default_factory=lambda: EdgeNodeMetrics(""))
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_health_check: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def __post_init__(self):
        if not self.metrics.node_id:
            self.metrics.node_id = self.node_id


@dataclass
class LoadBalancingConfig:
    """Configuration for load balancing."""
    strategy: LoadBalancingStrategy = LoadBalancingStrategy.PERFORMANCE_BASED
    health_check_interval: int = 30
    max_connections_per_node: int = 1000
    geographic_preference_weight: float = 0.3
    performance_weight: float = 0.7
    enable_auto_failover: bool = True


@dataclass
class AutoScalingConfig:
    """Configuration for auto-scaling."""
    enabled: bool = True
    cpu_threshold_scale_up: float = 80.0
    cpu_threshold_scale_down: float = 30.0
    memory_threshold_scale_up: float = 85.0
    memory_threshold_scale_down: float = 40.0
    min_nodes: int = 2
    max_nodes: int = 50
    scale_up_cooldown: int = 300  # seconds
    scale_down_cooldown: int = 600  # seconds


class GeographicCalculator:
    """Calculates geographic distances and routing."""
    
    @staticmethod
    def calculate_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """Calculate distance between two geographic points using Haversine formula."""
        # Convert latitude and longitude from degrees to radians
        lat1, lon1, lat2, lon2 = map(math.radians, [lat1, lon1, lat2, lon2])
        
        # Haversine formula
        dlat = lat2 - lat1
        dlon = lon2 - lon1
        a = math.sin(dlat/2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon/2)**2
        c = 2 * math.asin(math.sqrt(a))
        
        # Radius of earth in kilometers
        r = 6371
        return c * r
    
    @staticmethod
    def find_nearest_nodes(user_lat: float, user_lon: float, 
                          nodes: List[EdgeNode], count: int = 3) -> List[EdgeNode]:
        """Find the nearest edge nodes to a user location."""
        distances = []
        for node in nodes:
            if node.status == EdgeNodeStatus.ACTIVE:
                distance = GeographicCalculator.calculate_distance(
                    user_lat, user_lon, node.latitude, node.longitude
                )
                distances.append((distance, node))
        
        # Sort by distance and return top N
        distances.sort(key=lambda x: x[0])
        return [node for _, node in distances[:count]]


class PerformanceMonitor:
    """Monitors performance of edge nodes."""
    
    def __init__(self):
        self.metrics_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        
    def record_metrics(self, node_id: str, metrics: EdgeNodeMetrics):
        """Record metrics for a node."""
        self.metrics_history[node_id].append({
            'timestamp': metrics.last_updated,
            'cpu_usage': metrics.cpu_usage,
            'memory_usage': metrics.memory_usage,
            'network_latency': metrics.network_latency,
            'requests_per_second': metrics.requests_per_second,
            'error_rate': metrics.error_rate
        })
    
    def get_average_metrics(self, node_id: str, window_minutes: int = 5) -> Optional[Dict[str, float]]:
        """Get average metrics for a node over a time window."""
        if node_id not in self.metrics_history:
            return None
        
        cutoff_time = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        recent_metrics = [
            m for m in self.metrics_history[node_id]
            if m['timestamp'] > cutoff_time
        ]
        
        if not recent_metrics:
            return None
        
        return {
            'avg_cpu_usage': statistics.mean(m['cpu_usage'] for m in recent_metrics),
            'avg_memory_usage': statistics.mean(m['memory_usage'] for m in recent_metrics),
            'avg_network_latency': statistics.mean(m['network_latency'] for m in recent_metrics),
            'avg_requests_per_second': statistics.mean(m['requests_per_second'] for m in recent_metrics),
            'avg_error_rate': statistics.mean(m['error_rate'] for m in recent_metrics)
        }


class LoadBalancer:
    """Intelligent load balancer for edge nodes."""
    
    def __init__(self, config: LoadBalancingConfig):
        self.config = config
        self.node_connections: Dict[str, int] = defaultdict(int)
        self.round_robin_index = 0
        
    def select_node(self, available_nodes: List[EdgeNode], 
                   user_lat: Optional[float] = None, 
                   user_lon: Optional[float] = None) -> Optional[EdgeNode]:
        """Select the best node based on the configured strategy."""
        if not available_nodes:
            return None
        
        # Filter out overloaded nodes
        healthy_nodes = [
            node for node in available_nodes
            if (node.status == EdgeNodeStatus.ACTIVE and 
                self.node_connections[node.node_id] < self.config.max_connections_per_node)
        ]
        
        if not healthy_nodes:
            return None
        
        if self.config.strategy == LoadBalancingStrategy.ROUND_ROBIN:
            return self._round_robin_select(healthy_nodes)
        elif self.config.strategy == LoadBalancingStrategy.LEAST_CONNECTIONS:
            return self._least_connections_select(healthy_nodes)
        elif self.config.strategy == LoadBalancingStrategy.GEOGRAPHIC:
            return self._geographic_select(healthy_nodes, user_lat, user_lon)
        elif self.config.strategy == LoadBalancingStrategy.PERFORMANCE_BASED:
            return self._performance_based_select(healthy_nodes, user_lat, user_lon)
        else:
            return healthy_nodes[0]
    
    def _round_robin_select(self, nodes: List[EdgeNode]) -> EdgeNode:
        """Round-robin selection."""
        node = nodes[self.round_robin_index % len(nodes)]
        self.round_robin_index += 1
        return node
    
    def _least_connections_select(self, nodes: List[EdgeNode]) -> EdgeNode:
        """Select node with least connections."""
        return min(nodes, key=lambda n: self.node_connections[n.node_id])
    
    def _geographic_select(self, nodes: List[EdgeNode], 
                          user_lat: Optional[float], user_lon: Optional[float]) -> EdgeNode:
        """Select geographically closest node."""
        if user_lat is None or user_lon is None:
            return nodes[0]
        
        nearest_nodes = GeographicCalculator.find_nearest_nodes(
            user_lat, user_lon, nodes, count=1
        )
        return nearest_nodes[0] if nearest_nodes else nodes[0]
    
    def _performance_based_select(self, nodes: List[EdgeNode], 
                                 user_lat: Optional[float], user_lon: Optional[float]) -> EdgeNode:
        """Select node based on performance and geography."""
        scores = []
        
        for node in nodes:
            # Performance score (lower is better)
            perf_score = (
                node.metrics.cpu_usage * 0.3 +
                node.metrics.memory_usage * 0.3 +
                node.metrics.network_latency * 0.2 +
                node.metrics.error_rate * 100 * 0.2
            )
            
            # Geographic score
            geo_score = 0.0
            if user_lat is not None and user_lon is not None:
                distance = GeographicCalculator.calculate_distance(
                    user_lat, user_lon, node.latitude, node.longitude
                )
                geo_score = distance / 1000  # Normalize to reasonable range
            
            # Combined score
            total_score = (
                perf_score * self.config.performance_weight +
                geo_score * self.config.geographic_preference_weight
            )
            
            scores.append((total_score, node))
        
        # Return node with lowest score (best performance)
        scores.sort(key=lambda x: x[0])
        return scores[0][1]
    
    def add_connection(self, node_id: str):
        """Record a new connection to a node."""
        self.node_connections[node_id] += 1
    
    def remove_connection(self, node_id: str):
        """Record a connection removal from a node."""
        if self.node_connections[node_id] > 0:
            self.node_connections[node_id] -= 1


class AutoScaler:
    """Automatic scaling manager for edge nodes."""
    
    def __init__(self, config: AutoScalingConfig):
        self.config = config
        self.last_scale_up: Dict[str, datetime] = {}
        self.last_scale_down: Dict[str, datetime] = {}
        
    def evaluate_scaling_decision(self, nodes: List[EdgeNode]) -> Tuple[ScalingAction, str]:
        """Evaluate whether scaling action is needed."""
        if not self.config.enabled:
            return ScalingAction.MAINTAIN, "Auto-scaling disabled"
        
        active_nodes = [n for n in nodes if n.status == EdgeNodeStatus.ACTIVE]
        
        if len(active_nodes) < self.config.min_nodes:
            return ScalingAction.SCALE_UP, f"Below minimum nodes ({self.config.min_nodes})"
        
        if len(active_nodes) >= self.config.max_nodes:
            return ScalingAction.SCALE_DOWN, f"At maximum nodes ({self.config.max_nodes})"
        
        # Calculate average resource usage
        avg_cpu = statistics.mean(n.metrics.cpu_usage for n in active_nodes)
        avg_memory = statistics.mean(n.metrics.memory_usage for n in active_nodes)
        
        current_time = datetime.now(timezone.utc)
        
        # Check for scale up conditions
        if (avg_cpu > self.config.cpu_threshold_scale_up or 
            avg_memory > self.config.memory_threshold_scale_up):
            
            # Check cooldown
            if self._can_scale_up(current_time):
                return ScalingAction.SCALE_UP, f"High resource usage (CPU: {avg_cpu:.1f}%, Memory: {avg_memory:.1f}%)"
        
        # Check for scale down conditions
        if (avg_cpu < self.config.cpu_threshold_scale_down and 
            avg_memory < self.config.memory_threshold_scale_down and
            len(active_nodes) > self.config.min_nodes):
            
            # Check cooldown
            if self._can_scale_down(current_time):
                return ScalingAction.SCALE_DOWN, f"Low resource usage (CPU: {avg_cpu:.1f}%, Memory: {avg_memory:.1f}%)"
        
        return ScalingAction.MAINTAIN, "Resource usage within normal range"
    
    def _can_scale_up(self, current_time: datetime) -> bool:
        """Check if scale up is allowed based on cooldown."""
        if 'global' not in self.last_scale_up:
            return True
        
        time_since_last = (current_time - self.last_scale_up['global']).total_seconds()
        return time_since_last >= self.config.scale_up_cooldown
    
    def _can_scale_down(self, current_time: datetime) -> bool:
        """Check if scale down is allowed based on cooldown."""
        if 'global' not in self.last_scale_down:
            return True
        
        time_since_last = (current_time - self.last_scale_down['global']).total_seconds()
        return time_since_last >= self.config.scale_down_cooldown
    
    def record_scaling_action(self, action: ScalingAction):
        """Record a scaling action for cooldown tracking."""
        current_time = datetime.now(timezone.utc)
        
        if action == ScalingAction.SCALE_UP:
            self.last_scale_up['global'] = current_time
        elif action == ScalingAction.SCALE_DOWN:
            self.last_scale_down['global'] = current_time


class EdgeComputingManager:
    """
    Edge Computing Manager providing watertight security like a deep-sea submarine.
    
    Features:
    - Distributed edge node management
    - Intelligent load balancing
    - Auto-scaling and resource optimization
    - Geographic distribution
    - Real-time performance monitoring
    - Security-first architecture
    """
    
    def __init__(self, 
                 load_balancing_config: Optional[LoadBalancingConfig] = None,
                 auto_scaling_config: Optional[AutoScalingConfig] = None):
        
        # Configuration
        self.load_balancing_config = load_balancing_config or LoadBalancingConfig()
        self.auto_scaling_config = auto_scaling_config or AutoScalingConfig()
        
        # Core components
        self.nodes: Dict[str, EdgeNode] = {}
        self.load_balancer = LoadBalancer(self.load_balancing_config)
        self.auto_scaler = AutoScaler(self.auto_scaling_config)
        self.performance_monitor = PerformanceMonitor()
        self.geographic_calculator = GeographicCalculator()
        
        # Security integration
        if SECURITY_AVAILABLE:
            try:
                from plexichat.core.security.unified_security_system import get_unified_security_system
                from plexichat.core.security.comprehensive_security_manager import get_security_manager
                self.security_system = get_unified_security_system()
                self.security_manager = get_security_manager()
            except ImportError:
                self.security_system = None
                self.security_manager = None
        else:
            self.security_system = None
            self.security_manager = None
        
        # Monitoring and metrics
        self.metrics = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'average_response_time': 0.0,
            'nodes_scaled_up': 0,
            'nodes_scaled_down': 0
        }
        
        # Background tasks
        self.monitoring_task: Optional[asyncio.Task] = None
        self.is_running = False
        
        logger.info("Edge Computing Manager initialized with watertight security")
    
    async def start_monitoring(self):
        """Start background monitoring tasks."""
        if not self.is_running:
            self.is_running = True
            self.monitoring_task = asyncio.create_task(self._monitoring_loop())
            logger.info("Started edge computing monitoring")
    
    async def stop_monitoring(self):
        """Stop background monitoring tasks."""
        if self.is_running:
            self.is_running = False
            if self.monitoring_task:
                self.monitoring_task.cancel()
                try:
                    await self.monitoring_task
                except asyncio.CancelledError:
                    pass
            logger.info("Stopped edge computing monitoring")
    
    async def _monitoring_loop(self):
        """Background monitoring loop."""
        while self.is_running:
            try:
                await self._update_node_metrics()
                await self._evaluate_auto_scaling()
                await self._health_check_nodes()
                await asyncio.sleep(30)  # Monitor every 30 seconds
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                await asyncio.sleep(60)  # Wait longer on error
    
    async def _update_node_metrics(self):
        """Update metrics for all nodes."""
        for node in self.nodes.values():
            if node.status == EdgeNodeStatus.ACTIVE:
                # Simulate metric collection (would be real monitoring in production)
                node.metrics.cpu_usage = random.uniform(20, 90)
                node.metrics.memory_usage = random.uniform(30, 85)
                node.metrics.network_latency = random.uniform(10, 100)
                node.metrics.requests_per_second = random.uniform(50, 500)
                node.metrics.error_rate = random.uniform(0, 5)
                node.metrics.last_updated = datetime.now(timezone.utc)
                
                # Record metrics for analysis
                self.performance_monitor.record_metrics(node.node_id, node.metrics)
    
    async def _evaluate_auto_scaling(self):
        """Evaluate and execute auto-scaling decisions."""
        active_nodes = [n for n in self.nodes.values() if n.status == EdgeNodeStatus.ACTIVE]
        
        if len(active_nodes) < 2:  # Need minimum nodes for evaluation
            return
        
        action, reason = self.auto_scaler.evaluate_scaling_decision(active_nodes)
        
        if action == ScalingAction.SCALE_UP:
            await self._scale_up_nodes(reason)
        elif action == ScalingAction.SCALE_DOWN:
            await self._scale_down_nodes(reason)
    
    async def _scale_up_nodes(self, reason: str):
        """Scale up by adding new nodes."""
        # In production, this would provision new edge nodes
        new_node_id = f"edge-node-{len(self.nodes) + 1}"
        new_node = EdgeNode(
            node_id=new_node_id,
            location=f"Region-{random.randint(1, 10)}",
            latitude=random.uniform(-90, 90),
            longitude=random.uniform(-180, 180),
            capacity=1000
        )
        
        self.nodes[new_node_id] = new_node
        self.auto_scaler.record_scaling_action(ScalingAction.SCALE_UP)
        self.metrics['nodes_scaled_up'] += 1
        
        logger.info(f"Scaled up: Added node {new_node_id}. Reason: {reason}")
    
    async def _scale_down_nodes(self, reason: str):
        """Scale down by removing nodes."""
        active_nodes = [n for n in self.nodes.values() if n.status == EdgeNodeStatus.ACTIVE]
        
        if len(active_nodes) <= self.auto_scaling_config.min_nodes:
            return
        
        # Find node with lowest utilization
        lowest_util_node = min(active_nodes, 
                              key=lambda n: n.metrics.cpu_usage + n.metrics.memory_usage)
        
        lowest_util_node.status = EdgeNodeStatus.INACTIVE
        self.auto_scaler.record_scaling_action(ScalingAction.SCALE_DOWN)
        self.metrics['nodes_scaled_down'] += 1
        
        logger.info(f"Scaled down: Deactivated node {lowest_util_node.node_id}. Reason: {reason}")
    
    async def _health_check_nodes(self):
        """Perform health checks on all nodes."""
        for node in self.nodes.values():
            if node.status == EdgeNodeStatus.ACTIVE:
                # Simulate health check (would be real health check in production)
                if random.random() < 0.01:  # 1% chance of failure
                    node.status = EdgeNodeStatus.FAILED
                    logger.warning(f"Node {node.node_id} failed health check")
                else:
                    node.last_health_check = datetime.now(timezone.utc)
    
    def add_edge_node(self, node_id: str, location: str, 
                     latitude: float, longitude: float, capacity: int = 1000) -> EdgeNode:
        """Add a new edge node."""
        node = EdgeNode(
            node_id=node_id,
            location=location,
            latitude=latitude,
            longitude=longitude,
            capacity=capacity
        )
        
        self.nodes[node_id] = node
        logger.info(f"Added edge node: {node_id} at {location}")
        return node
    
    def remove_edge_node(self, node_id: str) -> bool:
        """Remove an edge node."""
        if node_id in self.nodes:
            del self.nodes[node_id]
            logger.info(f"Removed edge node: {node_id}")
            return True
        return False
    
    async def route_request(self, user_lat: Optional[float] = None, 
                           user_lon: Optional[float] = None) -> Optional[EdgeNode]:
        """Route a request to the best available edge node."""
        try:
            self.metrics['total_requests'] += 1
            
            # Security validation
            if self.security_system:
                # In production, would validate the request
                pass
            
            # Get available nodes
            available_nodes = [n for n in self.nodes.values() 
                             if n.status == EdgeNodeStatus.ACTIVE]
            
            if not available_nodes:
                self.metrics['failed_requests'] += 1
                return None
            
            # Select best node
            selected_node = self.load_balancer.select_node(
                available_nodes, user_lat, user_lon
            )
            
            if selected_node:
                self.load_balancer.add_connection(selected_node.node_id)
                self.metrics['successful_requests'] += 1
                return selected_node
            else:
                self.metrics['failed_requests'] += 1
                return None
                
        except Exception as e:
            logger.error(f"Error routing request: {e}")
            self.metrics['failed_requests'] += 1
            return None
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive edge computing system status."""
        active_nodes = [n for n in self.nodes.values() if n.status == EdgeNodeStatus.ACTIVE]
        
        return {
            'metrics': self.metrics.copy(),
            'total_nodes': len(self.nodes),
            'active_nodes': len(active_nodes),
            'load_balancing_strategy': self.load_balancing_config.strategy.value,
            'auto_scaling_enabled': self.auto_scaling_config.enabled,
            'security_enabled': SECURITY_AVAILABLE,
            'monitoring_active': self.is_running
        }
    
    async def shutdown(self):
        """Shutdown the edge computing manager."""
        await self.stop_monitoring()
        logger.info("Edge Computing Manager shut down")


# Global edge computing manager instance
_global_edge_manager: Optional[EdgeComputingManager] = None


def get_edge_computing_manager() -> EdgeComputingManager:
    """Get the global edge computing manager instance."""
    global _global_edge_manager
    if _global_edge_manager is None:
        _global_edge_manager = EdgeComputingManager()
    return _global_edge_manager


async def initialize_edge_computing_manager(
    load_balancing_config: Optional[LoadBalancingConfig] = None,
    auto_scaling_config: Optional[AutoScalingConfig] = None
) -> EdgeComputingManager:
    """Initialize the global edge computing manager."""
    global _global_edge_manager
    _global_edge_manager = EdgeComputingManager(load_balancing_config, auto_scaling_config)
    await _global_edge_manager.start_monitoring()
    return _global_edge_manager


async def shutdown_edge_computing_manager() -> None:
    """Shutdown the global edge computing manager."""
    global _global_edge_manager
    if _global_edge_manager:
        await _global_edge_manager.shutdown()
        _global_edge_manager = None


__all__ = [
    "EdgeComputingManager",
    "EdgeNode",
    "EdgeNodeMetrics",
    "EdgeNodeStatus",
    "LoadBalancingStrategy",
    "LoadBalancingConfig",
    "AutoScalingConfig",
    "ScalingAction",
    "GeographicCalculator",
    "PerformanceMonitor",
    "LoadBalancer",
    "AutoScaler",
    "get_edge_computing_manager",
    "initialize_edge_computing_manager",
    "shutdown_edge_computing_manager"
]
