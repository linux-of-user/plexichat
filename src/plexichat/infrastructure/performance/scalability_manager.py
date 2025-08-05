"""
Scalability Management System

Comprehensive scalability management with horizontal scaling, load balancing,
capacity planning, and auto-scaling for optimal system performance.
"""

import asyncio
import logging
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Callable
import psutil
import statistics

logger = logging.getLogger(__name__)


@dataclass
class NodeMetrics:
    """Metrics for a single node."""
    node_id: str
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    disk_usage: float = 0.0
    network_io: float = 0.0
    active_connections: int = 0
    request_rate: float = 0.0
    response_time: float = 0.0
    error_rate: float = 0.0
    health_score: float = 1.0
    last_updated: datetime = field(default_factory=datetime.now)


@dataclass
class LoadBalancerConfig:
    """Load balancer configuration."""
    algorithm: str = "round_robin"  # round_robin, least_connections, weighted_round_robin, ip_hash
    health_check_interval: int = 30
    health_check_timeout: int = 5
    max_retries: int = 3
    sticky_sessions: bool = False
    session_timeout: int = 3600


@dataclass
class AutoScalingConfig:
    """Auto-scaling configuration."""
    enabled: bool = True
    min_nodes: int = 2
    max_nodes: int = 10
    scale_up_threshold: float = 0.8
    scale_down_threshold: float = 0.3
    scale_up_cooldown: int = 300  # seconds
    scale_down_cooldown: int = 600  # seconds
    metrics_window: int = 300  # seconds


class LoadBalancer:
    """Advanced load balancer with multiple algorithms."""

    def __init__(self, config: LoadBalancerConfig):
        self.config = config
        self.nodes: Dict[str, NodeMetrics] = {}
        self.healthy_nodes: Set[str] = set()
        self.current_node_index = 0
        self.session_affinity: Dict[str, str] = {}
        self.request_counts: Dict[str, int] = defaultdict(int)

    def add_node(self, node_id: str, initial_metrics: Optional[NodeMetrics] = None):
        """Add a node to the load balancer."""
        if initial_metrics:
            self.nodes[node_id] = initial_metrics
        else:
            self.nodes[node_id] = NodeMetrics(node_id=node_id)

        self.healthy_nodes.add(node_id)
        logger.info(f"[SCALE] Added node to load balancer: {node_id}")

    def remove_node(self, node_id: str):
        """Remove a node from the load balancer."""
        self.nodes.pop(node_id, None)
        self.healthy_nodes.discard(node_id)

        # Clean up session affinity
        sessions_to_remove = [
            session_id for session_id, assigned_node in self.session_affinity.items()
            if assigned_node == node_id
        ]
        for session_id in sessions_to_remove:
            del self.session_affinity[session_id]

        logger.info(f"[SCALE] Removed node from load balancer: {node_id}")

    def update_node_metrics(self, node_id: str, metrics: NodeMetrics):
        """Update metrics for a node."""
        if node_id in self.nodes:
            self.nodes[node_id] = metrics

            # Update health status
            if metrics.health_score > 0.5:
                self.healthy_nodes.add(node_id)
            else:
                self.healthy_nodes.discard(node_id)

    def select_node(self, session_id: Optional[str] = None, client_ip: Optional[str] = None) -> Optional[str]:
        """Select a node based on the configured algorithm."""
        if not self.healthy_nodes:
            return None

        # Check session affinity first
        if session_id and self.config.sticky_sessions:
            if session_id in self.session_affinity:
                assigned_node = self.session_affinity[session_id]
                if assigned_node in self.healthy_nodes:
                    return assigned_node

        # Select based on algorithm
        if self.config.algorithm == "round_robin":
            return self._round_robin_selection()
        elif self.config.algorithm == "least_connections":
            return self._least_connections_selection()
        elif self.config.algorithm == "weighted_round_robin":
            return self._weighted_round_robin_selection()
        elif self.config.algorithm == "ip_hash":
            return self._ip_hash_selection(client_ip)
        else:
            return self._round_robin_selection()

    def _round_robin_selection(self) -> str:
        """Round-robin node selection."""
        healthy_nodes_list = list(self.healthy_nodes)
        if not healthy_nodes_list:
            return None

        selected_node = healthy_nodes_list[self.current_node_index % len(healthy_nodes_list)]
        self.current_node_index += 1
        return selected_node

    def _least_connections_selection(self) -> str:
        """Select node with least connections."""
        if not self.healthy_nodes:
            return None

        min_connections = float('inf')
        selected_node = None

        for node_id in self.healthy_nodes:
            connections = self.nodes[node_id].active_connections
            if connections < min_connections:
                min_connections = connections
                selected_node = node_id

        return selected_node

    def _weighted_round_robin_selection(self) -> str:
        """Weighted round-robin based on node health scores."""
        if not self.healthy_nodes:
            return None

        # Calculate weights based on health scores
        weights = {}
        total_weight = 0

        for node_id in self.healthy_nodes:
            weight = self.nodes[node_id].health_score
            weights[node_id] = weight
            total_weight += weight

        if total_weight == 0:
            return self._round_robin_selection()

        # Select based on weights
        import random
        rand_val = random.uniform(0, total_weight)
        current_weight = 0

        for node_id, weight in weights.items():
            current_weight += weight
            if rand_val <= current_weight:
                return node_id

        return list(self.healthy_nodes)[0]

    def _ip_hash_selection(self, client_ip: Optional[str]) -> str:
        """Select node based on client IP hash."""
        if not client_ip or not self.healthy_nodes:
            return self._round_robin_selection()

        healthy_nodes_list = sorted(list(self.healthy_nodes))
        hash_value = hash(client_ip)
        selected_index = hash_value % len(healthy_nodes_list)
        return healthy_nodes_list[selected_index]

    def record_request(self, node_id: str):
        """Record a request to a node."""
        self.request_counts[node_id] += 1

    def get_load_distribution(self) -> Dict[str, Any]:
        """Get current load distribution across nodes."""
        total_requests = sum(self.request_counts.values())

        distribution = {}
        for node_id in self.nodes:
            requests = self.request_counts.get(node_id, 0)
            distribution[node_id] = {
                'requests': requests,
                'percentage': (requests / total_requests * 100) if total_requests > 0 else 0,
                'health_score': self.nodes[node_id].health_score,
                'is_healthy': node_id in self.healthy_nodes
            }

        return distribution


class AutoScaler:
    """Auto-scaling system for horizontal scaling."""

    def __init__(self, config: AutoScalingConfig):
        self.config = config
        self.metrics_history: deque = deque(maxlen=100)
        self.last_scale_up = datetime.min
        self.last_scale_down = datetime.min
        self.scaling_events: List[Dict[str, Any]] = []

    def add_metrics(self, cluster_metrics: Dict[str, Any]):
        """Add cluster metrics for scaling decisions."""
        self.metrics_history.append({
            'timestamp': datetime.now(),
            'metrics': cluster_metrics
        })

    def should_scale_up(self) -> bool:
        """Determine if cluster should scale up."""
        if not self.config.enabled:
            return False

        # Check cooldown period
        if (datetime.now() - self.last_scale_up).total_seconds() < self.config.scale_up_cooldown:
            return False

        # Check if we're at max capacity
        current_nodes = self._get_current_node_count()
        if current_nodes >= self.config.max_nodes:
            return False

        # Analyze recent metrics
        recent_metrics = self._get_recent_metrics()
        if not recent_metrics:
            return False

        # Check if average load exceeds threshold
        avg_cpu = statistics.mean([m['cpu_usage'] for m in recent_metrics])
        avg_memory = statistics.mean([m['memory_usage'] for m in recent_metrics])
        avg_load = max(avg_cpu, avg_memory) / 100.0

        return avg_load > self.config.scale_up_threshold

    def should_scale_down(self) -> bool:
        """Determine if cluster should scale down."""
        if not self.config.enabled:
            return False

        # Check cooldown period
        if (datetime.now() - self.last_scale_down).total_seconds() < self.config.scale_down_cooldown:
            return False

        # Check if we're at min capacity
        current_nodes = self._get_current_node_count()
        if current_nodes <= self.config.min_nodes:
            return False

        # Analyze recent metrics
        recent_metrics = self._get_recent_metrics()
        if not recent_metrics:
            return False

        # Check if average load is below threshold
        avg_cpu = statistics.mean([m['cpu_usage'] for m in recent_metrics])
        avg_memory = statistics.mean([m['memory_usage'] for m in recent_metrics])
        avg_load = max(avg_cpu, avg_memory) / 100.0

        return avg_load < self.config.scale_down_threshold

    def _get_recent_metrics(self) -> List[Dict[str, Any]]:
        """Get metrics from the recent time window."""
        cutoff_time = datetime.now() - timedelta(seconds=self.config.metrics_window)

        recent_metrics = []
        for entry in self.metrics_history:
            if entry['timestamp'] > cutoff_time:
                recent_metrics.append(entry['metrics'])

        return recent_metrics

    def _get_current_node_count(self) -> int:
        """Get current number of nodes."""
        if self.metrics_history:
            latest = self.metrics_history[-1]
            return latest['metrics'].get('node_count', 1)
        return 1

    def record_scaling_event(self, event_type: str, details: Dict[str, Any]):
        """Record a scaling event."""
        event = {
            'timestamp': datetime.now(),
            'type': event_type,
            'details': details
        }
        self.scaling_events.append(event)

        if event_type == 'scale_up':
            self.last_scale_up = datetime.now()
        elif event_type == 'scale_down':
            self.last_scale_down = datetime.now()

        logger.info(f"[UP] Scaling event: {event_type} - {details}")


class CapacityPlanner:
    """Capacity planning system for predictive scaling."""

    def __init__(self):
        self.usage_history: deque = deque(maxlen=1000)
        self.growth_trends: Dict[str, float] = {}
        self.seasonal_patterns: Dict[str, List[float]] = {}

    def add_usage_data(self, usage_data: Dict[str, Any]):
        """Add usage data for capacity planning."""
        self.usage_history.append({
            'timestamp': datetime.now(),
            'data': usage_data
        })

    def analyze_growth_trends(self) -> Dict[str, float]:
        """Analyze growth trends in resource usage."""
        if len(self.usage_history) < 10:
            return {}}

        # Simple linear trend analysis
        trends = {}
        metrics = ['cpu_usage', 'memory_usage', 'request_rate', 'storage_usage']

        for metric in metrics:
            values = []
            timestamps = []

            for entry in self.usage_history:
                if metric in entry['data']:
                    values.append(entry['data'][metric])
                    timestamps.append(entry['timestamp'].timestamp())

            if len(values) >= 5:
                # Calculate simple linear trend
                trend = self._calculate_linear_trend(timestamps, values)
                trends[metric] = trend

        self.growth_trends = trends
        return trends

    def _calculate_linear_trend(self, x_values: List[float], y_values: List[float]) -> float:
        """Calculate linear trend slope."""
        if len(x_values) != len(y_values) or len(x_values) < 2:
            return 0.0

        n = len(x_values)
        sum_x = sum(x_values)
        sum_y = sum(y_values)
        sum_xy = sum(x * y for x, y in zip(x_values, y_values))
        sum_x2 = sum(x * x for x in x_values)

        denominator = n * sum_x2 - sum_x * sum_x
        if denominator == 0:
            return 0.0

        slope = (n * sum_xy - sum_x * sum_y) / denominator
        return slope

    def predict_capacity_needs(self, days_ahead: int = 30) -> Dict[str, Any]:
        """Predict capacity needs for the specified time period."""
        predictions = {}

        current_time = datetime.now()
        future_time = current_time + timedelta(days=days_ahead)
        time_delta = (future_time - current_time).total_seconds()

        for metric, trend in self.growth_trends.items():
            if len(self.usage_history) > 0:
                current_value = self.usage_history[-1]['data'].get(metric, 0)
                predicted_value = current_value + (trend * time_delta)

                predictions[metric] = {
                    'current': current_value,
                    'predicted': max(0, predicted_value),
                    'growth_rate': trend,
                    'change_percent': ((predicted_value - current_value) / current_value * 100) if current_value > 0 else 0
                }

        return predictions

    def get_capacity_recommendations(self) -> List[str]:
        """Get capacity planning recommendations."""
        recommendations = []

        predictions = self.predict_capacity_needs(30)

        for metric, prediction in predictions.items():
            change_percent = prediction['change_percent']

            if change_percent > 50:
                recommendations.append(
                    f"High growth predicted for {metric}: {change_percent:.1f}% increase expected. "
                    "Consider scaling up resources proactively."
                )
            elif change_percent > 25:
                recommendations.append(
                    f"Moderate growth predicted for {metric}: {change_percent:.1f}% increase expected. "
                    "Monitor closely and prepare for scaling."
                )
            elif change_percent < -25:
                recommendations.append(
                    f"Declining usage predicted for {metric}: {change_percent:.1f}% decrease expected. "
                    "Consider scaling down to optimize costs."
                )

        return recommendations


class ScalabilityManager:
    """Main scalability management system."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}

        # Components
        lb_config = LoadBalancerConfig(**self.config.get('load_balancer', {}))
        self.load_balancer = LoadBalancer(lb_config)

        as_config = AutoScalingConfig(**self.config.get('auto_scaling', {}))
        self.auto_scaler = AutoScaler(as_config)

        self.capacity_planner = CapacityPlanner()

        # Monitoring
        self.cluster_metrics: Dict[str, Any] = {}
        self.scaling_history: List[Dict[str, Any]] = []

        # Background tasks
        self._monitoring_task = None
        self._scaling_task = None
        self._running = False

        logger.info("[METRICS] Scalability Manager initialized")

    async def initialize(self) -> bool:
        """Initialize scalability management."""
        try:
            # Start monitoring and scaling
            await self.start_monitoring()

            logger.info("[START] Scalability management initialized")
            return True

        except Exception as e:
            logger.error(f"Scalability management initialization failed: {e}")
            return False

    async def shutdown(self):
        """Shutdown scalability manager."""
        try:
            self._running = False

            if self._monitoring_task:
                self._monitoring_task.cancel()
            if self._scaling_task:
                self._scaling_task.cancel()

            logger.info("[STOP] Scalability manager shutdown complete")

        except Exception as e:
            logger.error(f"Error during scalability manager shutdown: {e}")

    async def start_monitoring(self):
        """Start scalability monitoring."""
        if self._running:
            return

        self._running = True
        self._monitoring_task = asyncio.create_task(self._monitoring_loop())
        self._scaling_task = asyncio.create_task(self._scaling_loop())

        logger.info("[METRICS] Scalability monitoring started")

    async def _monitoring_loop(self):
        """Background monitoring loop."""
        while self._running:
            try:
                await self._collect_cluster_metrics()
                await asyncio.sleep(30)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Scalability monitoring error: {e}")
                await asyncio.sleep(10)

    async def _scaling_loop(self):
        """Background scaling decision loop."""
        while self._running:
            try:
                await self._evaluate_scaling_decisions()
                await asyncio.sleep(60)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Scaling evaluation error: {e}")
                await asyncio.sleep(30)

    async def _collect_cluster_metrics(self):
        """Collect cluster-wide metrics."""
        try:
            # Collect system metrics
            cpu_usage = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()

            self.cluster_metrics = {
                'timestamp': datetime.now(),
                'node_count': len(self.load_balancer.nodes),
                'healthy_nodes': len(self.load_balancer.healthy_nodes),
                'cpu_usage': cpu_usage,
                'memory_usage': memory.percent,
                'total_requests': sum(self.load_balancer.request_counts.values()),
                'load_distribution': self.load_balancer.get_load_distribution()
            }

            # Add to auto-scaler and capacity planner
            self.auto_scaler.add_metrics(self.cluster_metrics)
            self.capacity_planner.add_usage_data(self.cluster_metrics)

        except Exception as e:
            logger.error(f"Error collecting cluster metrics: {e}")

    async def _evaluate_scaling_decisions(self):
        """Evaluate and execute scaling decisions."""
        try:
            if self.auto_scaler.should_scale_up():
                await self._scale_up()
            elif self.auto_scaler.should_scale_down():
                await self._scale_down()

        except Exception as e:
            logger.error(f"Error evaluating scaling decisions: {e}")

    async def _scale_up(self):
        """Scale up the cluster."""
        try:
            # In a real implementation, this would provision new nodes
            new_node_id = f"node_{len(self.load_balancer.nodes) + 1}"

            # Simulate adding a new node
            self.load_balancer.add_node(new_node_id)

            self.auto_scaler.record_scaling_event('scale_up', {
                'new_node': new_node_id,
                'total_nodes': len(self.load_balancer.nodes)
            })

            logger.info(f"[UP] Scaled up: Added node {new_node_id}")

        except Exception as e:
            logger.error(f"Error scaling up: {e}")

    async def _scale_down(self):
        """Scale down the cluster."""
        try:
            if len(self.load_balancer.healthy_nodes) <= self.auto_scaler.config.min_nodes:
                return

            # Select node to remove (simple strategy: remove last added)
            nodes_list = list(self.load_balancer.nodes.keys())
            if nodes_list:
                node_to_remove = nodes_list[-1]
                self.load_balancer.remove_node(node_to_remove)

                self.auto_scaler.record_scaling_event('scale_down', {
                    'removed_node': node_to_remove,
                    'total_nodes': len(self.load_balancer.nodes)
                })

                logger.info(f"[DOWN] Scaled down: Removed node {node_to_remove}")

        except Exception as e:
            logger.error(f"Error scaling down: {e}")

    def get_scalability_stats(self) -> Dict[str, Any]:
        """Get comprehensive scalability statistics."""
        return {}
            'cluster': {
                'total_nodes': len(self.load_balancer.nodes),
                'healthy_nodes': len(self.load_balancer.healthy_nodes),
                'current_metrics': self.cluster_metrics
            },
            'load_balancer': {
                'algorithm': self.load_balancer.config.algorithm,
                'load_distribution': self.load_balancer.get_load_distribution(),
                'total_requests': sum(self.load_balancer.request_counts.values())
            },
            'auto_scaling': {
                'enabled': self.auto_scaler.config.enabled,
                'min_nodes': self.auto_scaler.config.min_nodes,
                'max_nodes': self.auto_scaler.config.max_nodes,
                'recent_events': self.auto_scaler.scaling_events[-10:]
            },
            'capacity_planning': {
                'growth_trends': self.capacity_planner.growth_trends,
                'predictions': self.capacity_planner.predict_capacity_needs(30),
                'recommendations': self.capacity_planner.get_capacity_recommendations()
            }
        }


# Global scalability manager instance
scalability_manager = ScalabilityManager()
