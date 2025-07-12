"""
Real-Time Performance Monitor

Advanced performance monitoring system with real-time metrics collection,
predictive analytics, and performance optimization recommendations.
"""

import asyncio
import logging
import secrets
import json
import time
import statistics
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum
import aiosqlite
import psutil

from . import (
    PerformanceMetric, METRICS_COLLECTION_INTERVAL, PERFORMANCE_HISTORY_DAYS,
    ALERT_THRESHOLD_CPU, ALERT_THRESHOLD_MEMORY, ALERT_THRESHOLD_DISK
)

logger = logging.getLogger(__name__)


class AlertSeverity(Enum):
    """Alert severity levels."""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    EMERGENCY = "emergency"


class PerformanceTrend(Enum):
    """Performance trend directions."""
    IMPROVING = "improving"
    STABLE = "stable"
    DEGRADING = "degrading"
    VOLATILE = "volatile"


class NodeHealthStatus(Enum):
    """Node health status levels."""
    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"
    FAILED = "failed"
    RECOVERING = "recovering"
    MAINTENANCE = "maintenance"


class AutoHealingAction(Enum):
    """Available auto-healing actions."""
    RESTART_SERVICE = "restart_service"
    CLEAR_CACHE = "clear_cache"
    REDISTRIBUTE_LOAD = "redistribute_load"
    SCALE_RESOURCES = "scale_resources"
    ISOLATE_NODE = "isolate_node"
    FAILOVER = "failover"
    GARBAGE_COLLECT = "garbage_collect"
    RESET_CONNECTIONS = "reset_connections"


@dataclass
class PerformanceAlert:
    """Performance alert."""
    alert_id: str
    node_id: str
    metric: PerformanceMetric
    severity: AlertSeverity
    threshold: float
    current_value: float
    message: str
    recommendations: List[str]
    created_at: datetime
    acknowledged: bool = False
    resolved: bool = False
    resolved_at: Optional[datetime] = None


@dataclass
class PerformanceSnapshot:
    """Performance snapshot for a node."""
    node_id: str
    timestamp: datetime
    cpu_usage: float
    memory_usage: float
    disk_usage: float
    network_throughput_mbps: float
    response_time_ms: float
    requests_per_second: float
    error_rate: float
    availability: float
    custom_metrics: Dict[str, float] = field(default_factory=dict)

    # Enhanced health metrics
    node_health_score: float = 1.0
    connection_count: int = 0
    queue_depth: int = 0
    gc_frequency: float = 0.0
    memory_fragmentation: float = 0.0
    disk_io_wait: float = 0.0
    network_latency_ms: float = 0.0
    service_status: Dict[str, bool] = field(default_factory=dict)
    last_heartbeat: Optional[datetime] = None


@dataclass
class PerformanceAnalysis:
    """Performance analysis results."""
    node_id: str
    analysis_period: timedelta
    trend: PerformanceTrend
    performance_score: float
    bottlenecks: List[str]
    recommendations: List[str]
    predicted_issues: List[str]
    optimization_opportunities: List[str]
    created_at: datetime

    # Enhanced analysis fields
    health_degradation_rate: float = 0.0
    failure_probability: float = 0.0
    recovery_suggestions: List[str] = field(default_factory=list)
    auto_healing_actions: List[str] = field(default_factory=list)
    escalation_required: bool = False


@dataclass
class NodeHealthReport:
    """Comprehensive node health report."""
    node_id: str
    timestamp: datetime
    health_status: NodeHealthStatus
    health_score: float
    uptime_seconds: float
    last_heartbeat: datetime
    service_statuses: Dict[str, bool]
    resource_utilization: Dict[str, float]
    performance_metrics: PerformanceSnapshot
    active_alerts: List[PerformanceAlert]
    recommended_actions: List[AutoHealingAction]
    failure_indicators: List[str]
    recovery_progress: float = 0.0
    maintenance_mode: bool = False


@dataclass
class ClusterHealthSummary:
    """Overall cluster health summary."""
    timestamp: datetime
    total_nodes: int
    healthy_nodes: int
    warning_nodes: int
    critical_nodes: int
    failed_nodes: int
    overall_health_score: float
    cluster_stability: float
    auto_healing_active: bool
    pending_actions: List[str]
    cluster_capacity_utilization: float
    estimated_failure_risk: float


class RealTimePerformanceMonitor:
    """
    Real-Time Performance Monitor
    
    Provides comprehensive performance monitoring with:
    - Real-time metrics collection
    - Performance trend analysis
    - Predictive issue detection
    - Automated alerting system
    - Performance optimization recommendations
    - Historical performance tracking
    - Bottleneck identification
    - Capacity planning insights
    """
    
    def __init__(self, cluster_manager):
        """Initialize the performance monitor."""
        self.cluster_manager = cluster_manager
        self.performance_snapshots: Dict[str, List[PerformanceSnapshot]] = {}
        self.active_alerts: Dict[str, PerformanceAlert] = {}
        self.performance_analyses: Dict[str, List[PerformanceAnalysis]] = {}

        # Enhanced health monitoring
        self.node_health_reports: Dict[str, NodeHealthReport] = {}
        self.cluster_health_history: List[ClusterHealthSummary] = []
        self.auto_healing_enabled = True
        self.healing_actions_in_progress: Dict[str, List[AutoHealingAction]] = {}
        self.node_failure_counts: Dict[str, int] = {}
        self.last_heartbeats: Dict[str, datetime] = {}

        # Configuration
        self.collection_interval = METRICS_COLLECTION_INTERVAL
        self.history_retention_days = PERFORMANCE_HISTORY_DAYS
        self.heartbeat_timeout_seconds = 60
        self.max_failure_count = 3
        self.auto_healing_cooldown = 300  # 5 minutes

        self.alert_thresholds = {
            PerformanceMetric.CPU_USAGE: ALERT_THRESHOLD_CPU,
            PerformanceMetric.MEMORY_USAGE: ALERT_THRESHOLD_MEMORY,
            PerformanceMetric.DISK_USAGE: ALERT_THRESHOLD_DISK,
            PerformanceMetric.RESPONSE_TIME: 1000.0,  # 1 second
            PerformanceMetric.ERROR_RATE: 0.05,  # 5%
            PerformanceMetric.AVAILABILITY: 0.95  # 95%
        }

        # Health score thresholds
        self.health_thresholds = {
            NodeHealthStatus.HEALTHY: 0.8,
            NodeHealthStatus.WARNING: 0.6,
            NodeHealthStatus.CRITICAL: 0.3,
            NodeHealthStatus.FAILED: 0.1
        }
        
        # Performance tracking
        self.baseline_performance: Dict[str, Dict[str, float]] = {}
        self.performance_improvements: Dict[str, float] = {}
        
        logger.info("Real-Time Performance Monitor initialized")
    
    async def initialize(self):
        """Initialize the performance monitor."""
        await self._initialize_performance_tracking()
        await self._establish_baseline_performance()
        
        # Start background tasks
        asyncio.create_task(self._metrics_collection_task())
        asyncio.create_task(self._performance_analysis_task())
        asyncio.create_task(self._alert_monitoring_task())
        asyncio.create_task(self._cleanup_task())
        
        logger.info("Performance Monitor initialized successfully")
    
    async def _initialize_performance_tracking(self):
        """Initialize performance tracking for all nodes."""
        for node_id in self.cluster_manager.cluster_nodes.keys():
            self.performance_snapshots[node_id] = []
            self.performance_analyses[node_id] = []
    
    async def _establish_baseline_performance(self):
        """Establish baseline performance metrics."""
        logger.info("Establishing baseline performance metrics")
        
        for node_id in self.cluster_manager.cluster_nodes.keys():
            # Collect initial performance snapshot
            snapshot = await self._collect_node_metrics(node_id)
            if snapshot:
                self.baseline_performance[node_id] = {
                    "cpu_usage": snapshot.cpu_usage,
                    "memory_usage": snapshot.memory_usage,
                    "disk_usage": snapshot.disk_usage,
                    "response_time_ms": snapshot.response_time_ms,
                    "requests_per_second": snapshot.requests_per_second
                }
                
                logger.debug(f"Baseline established for node {node_id}")
    
    async def _collect_node_metrics(self, node_id: str) -> Optional[PerformanceSnapshot]:
        """Collect performance metrics for a specific node."""
        if node_id not in self.cluster_manager.cluster_nodes:
            return None
        
        node = self.cluster_manager.cluster_nodes[node_id]
        
        try:
            # Collect system metrics
            if node_id == self.cluster_manager.local_node_id:
                # Local node - collect real metrics
                cpu_usage = psutil.cpu_percent(interval=1)
                memory = psutil.virtual_memory()
                memory_usage = memory.percent
                disk = psutil.disk_usage('/')
                disk_usage = (disk.used / disk.total) * 100
                
                # Network metrics (simplified)
                network_io = psutil.net_io_counters()
                network_throughput = (network_io.bytes_sent + network_io.bytes_recv) / (1024 * 1024)  # MB
                
            else:
                # Remote node - simulate metrics based on current load
                cpu_usage = node.current_load * 100
                memory_usage = min(90, cpu_usage * 0.8)
                disk_usage = min(80, cpu_usage * 0.6)
                network_throughput = node.current_load * 50  # Simulate network usage
            
            # Application metrics (simulated for now)
            response_time_ms = 50 + (cpu_usage * 2)  # Response time increases with CPU load
            requests_per_second = max(1, 100 - (cpu_usage * 0.5))  # RPS decreases with load
            error_rate = max(0, (cpu_usage - 80) * 0.01) if cpu_usage > 80 else 0  # Errors increase with high load
            availability = 1.0 if node.status.value == "online" else 0.0
            
            snapshot = PerformanceSnapshot(
                node_id=node_id,
                timestamp=datetime.now(timezone.utc),
                cpu_usage=cpu_usage / 100,  # Convert to 0-1 range
                memory_usage=memory_usage / 100,  # Convert to 0-1 range
                disk_usage=disk_usage / 100,  # Convert to 0-1 range
                network_throughput_mbps=network_throughput,
                response_time_ms=response_time_ms,
                requests_per_second=requests_per_second,
                error_rate=error_rate,
                availability=availability
            )
            
            return snapshot
            
        except Exception as e:
            logger.error(f"Failed to collect metrics for node {node_id}: {e}")
            return None
    
    async def collect_cluster_metrics(self) -> Dict[str, Any]:
        """Collect comprehensive cluster performance metrics."""
        cluster_metrics = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_nodes": len(self.cluster_manager.cluster_nodes),
            "active_nodes": 0,
            "cluster_cpu_usage": 0.0,
            "cluster_memory_usage": 0.0,
            "cluster_disk_usage": 0.0,
            "total_requests_per_second": 0.0,
            "average_response_time_ms": 0.0,
            "cluster_error_rate": 0.0,
            "cluster_availability": 0.0,
            "performance_gain_factor": 1.0,
            "node_metrics": {}
        }
        
        active_nodes = 0
        total_cpu = 0.0
        total_memory = 0.0
        total_disk = 0.0
        total_rps = 0.0
        total_response_time = 0.0
        total_error_rate = 0.0
        total_availability = 0.0
        
        for node_id in self.cluster_manager.cluster_nodes.keys():
            snapshot = await self._collect_node_metrics(node_id)
            if snapshot:
                active_nodes += 1
                total_cpu += snapshot.cpu_usage
                total_memory += snapshot.memory_usage
                total_disk += snapshot.disk_usage
                total_rps += snapshot.requests_per_second
                total_response_time += snapshot.response_time_ms
                total_error_rate += snapshot.error_rate
                total_availability += snapshot.availability
                
                # Store snapshot
                if node_id not in self.performance_snapshots:
                    self.performance_snapshots[node_id] = []
                
                self.performance_snapshots[node_id].append(snapshot)
                
                # Keep only recent snapshots
                if len(self.performance_snapshots[node_id]) > 1000:
                    self.performance_snapshots[node_id] = self.performance_snapshots[node_id][-1000:]
                
                # Add to cluster metrics
                cluster_metrics["node_metrics"][node_id] = {
                    "cpu_usage": snapshot.cpu_usage,
                    "memory_usage": snapshot.memory_usage,
                    "disk_usage": snapshot.disk_usage,
                    "response_time_ms": snapshot.response_time_ms,
                    "requests_per_second": snapshot.requests_per_second,
                    "error_rate": snapshot.error_rate,
                    "availability": snapshot.availability
                }
        
        if active_nodes > 0:
            cluster_metrics["active_nodes"] = active_nodes
            cluster_metrics["cluster_cpu_usage"] = total_cpu / active_nodes
            cluster_metrics["cluster_memory_usage"] = total_memory / active_nodes
            cluster_metrics["cluster_disk_usage"] = total_disk / active_nodes
            cluster_metrics["total_requests_per_second"] = total_rps
            cluster_metrics["average_response_time_ms"] = total_response_time / active_nodes
            cluster_metrics["cluster_error_rate"] = total_error_rate / active_nodes
            cluster_metrics["cluster_availability"] = total_availability / active_nodes
            
            # Calculate performance gain factor
            cluster_metrics["performance_gain_factor"] = self._calculate_performance_gain_factor(active_nodes, total_rps)
        
        return cluster_metrics

    async def generate_node_health_report(self, node_id: str) -> Optional[NodeHealthReport]:
        """Generate comprehensive health report for a node."""
        try:
            if node_id not in self.performance_snapshots or not self.performance_snapshots[node_id]:
                return None

            latest_snapshot = self.performance_snapshots[node_id][-1]
            current_time = datetime.now(timezone.utc)

            # Calculate health score
            health_score = self._calculate_node_health_score(node_id, latest_snapshot)

            # Determine health status
            health_status = self._determine_health_status(health_score)

            # Get service statuses
            service_statuses = await self._check_node_services(node_id)

            # Calculate uptime
            uptime_seconds = self._calculate_node_uptime(node_id)

            # Get active alerts for this node
            node_alerts = [alert for alert in self.active_alerts.values() if alert.node_id == node_id]

            # Generate recommended actions
            recommended_actions = self._generate_healing_actions(node_id, health_status, latest_snapshot)

            # Identify failure indicators
            failure_indicators = self._identify_failure_indicators(node_id, latest_snapshot)

            # Get last heartbeat
            last_heartbeat = self.last_heartbeats.get(node_id, current_time)

            return NodeHealthReport(
                node_id=node_id,
                timestamp=current_time,
                health_status=health_status,
                health_score=health_score,
                uptime_seconds=uptime_seconds,
                last_heartbeat=last_heartbeat,
                service_statuses=service_statuses,
                resource_utilization={
                    "cpu": latest_snapshot.cpu_usage,
                    "memory": latest_snapshot.memory_usage,
                    "disk": latest_snapshot.disk_usage,
                    "network": latest_snapshot.network_throughput_mbps
                },
                performance_metrics=latest_snapshot,
                active_alerts=node_alerts,
                recommended_actions=recommended_actions,
                failure_indicators=failure_indicators,
                recovery_progress=self._calculate_recovery_progress(node_id),
                maintenance_mode=self._is_node_in_maintenance(node_id)
            )

        except Exception as e:
            logger.error(f"Failed to generate health report for node {node_id}: {e}")
            return None

    async def generate_cluster_health_summary(self) -> ClusterHealthSummary:
        """Generate overall cluster health summary."""
        try:
            current_time = datetime.now(timezone.utc)
            total_nodes = len(self.cluster_manager.cluster_nodes)

            # Count nodes by health status
            healthy_nodes = 0
            warning_nodes = 0
            critical_nodes = 0
            failed_nodes = 0

            total_health_score = 0.0

            for node_id in self.cluster_manager.cluster_nodes.keys():
                health_report = await self.generate_node_health_report(node_id)
                if health_report:
                    total_health_score += health_report.health_score

                    if health_report.health_status == NodeHealthStatus.HEALTHY:
                        healthy_nodes += 1
                    elif health_report.health_status == NodeHealthStatus.WARNING:
                        warning_nodes += 1
                    elif health_report.health_status == NodeHealthStatus.CRITICAL:
                        critical_nodes += 1
                    elif health_report.health_status == NodeHealthStatus.FAILED:
                        failed_nodes += 1

            # Calculate overall health score
            overall_health_score = total_health_score / total_nodes if total_nodes > 0 else 0.0

            # Calculate cluster stability
            cluster_stability = self._calculate_cluster_stability()

            # Get pending auto-healing actions
            pending_actions = []
            for node_actions in self.healing_actions_in_progress.values():
                pending_actions.extend([action.value for action in node_actions])

            # Calculate capacity utilization
            cluster_metrics = await self.collect_cluster_metrics()
            capacity_utilization = (
                cluster_metrics.get("cluster_cpu_usage", 0) +
                cluster_metrics.get("cluster_memory_usage", 0) +
                cluster_metrics.get("cluster_disk_usage", 0)
            ) / 3.0

            # Estimate failure risk
            failure_risk = self._estimate_cluster_failure_risk(failed_nodes, critical_nodes, total_nodes)

            summary = ClusterHealthSummary(
                timestamp=current_time,
                total_nodes=total_nodes,
                healthy_nodes=healthy_nodes,
                warning_nodes=warning_nodes,
                critical_nodes=critical_nodes,
                failed_nodes=failed_nodes,
                overall_health_score=overall_health_score,
                cluster_stability=cluster_stability,
                auto_healing_active=self.auto_healing_enabled,
                pending_actions=pending_actions,
                cluster_capacity_utilization=capacity_utilization,
                estimated_failure_risk=failure_risk
            )

            # Store in history
            self.cluster_health_history.append(summary)
            if len(self.cluster_health_history) > 1000:
                self.cluster_health_history = self.cluster_health_history[-1000:]

            return summary

        except Exception as e:
            logger.error(f"Failed to generate cluster health summary: {e}")
            return ClusterHealthSummary(
                timestamp=current_time,
                total_nodes=0,
                healthy_nodes=0,
                warning_nodes=0,
                critical_nodes=0,
                failed_nodes=0,
                overall_health_score=0.0,
                cluster_stability=0.0,
                auto_healing_active=False,
                pending_actions=[],
                cluster_capacity_utilization=0.0,
                estimated_failure_risk=1.0
            )

    def _calculate_performance_gain_factor(self, active_nodes: int, total_rps: float) -> float:
        """Calculate the performance gain factor from clustering."""
        if active_nodes <= 1:
            return 1.0
        
        # Theoretical maximum gain is linear with nodes, but real-world has overhead
        theoretical_gain = active_nodes
        
        # Apply efficiency factor (clustering overhead reduces theoretical gain)
        efficiency_factor = 0.85  # 85% efficiency due to coordination overhead
        
        # Calculate actual gain based on throughput
        baseline_rps = 100.0  # Assume single node baseline
        actual_gain = total_rps / baseline_rps if baseline_rps > 0 else 1.0
        
        # Return the minimum of theoretical and actual gain
        return min(theoretical_gain * efficiency_factor, actual_gain)
    
    async def analyze_node_performance(self, node_id: str, analysis_period: timedelta = None) -> Optional[PerformanceAnalysis]:
        """Analyze performance for a specific node."""
        if node_id not in self.performance_snapshots or not self.performance_snapshots[node_id]:
            return None
        
        if analysis_period is None:
            analysis_period = timedelta(hours=1)
        
        # Get snapshots within analysis period
        cutoff_time = datetime.now(timezone.utc) - analysis_period
        recent_snapshots = [
            snapshot for snapshot in self.performance_snapshots[node_id]
            if snapshot.timestamp >= cutoff_time
        ]
        
        if len(recent_snapshots) < 2:
            return None
        
        # Analyze trends
        trend = self._analyze_performance_trend(recent_snapshots)
        
        # Calculate performance score
        performance_score = self._calculate_node_performance_score(recent_snapshots)
        
        # Identify bottlenecks
        bottlenecks = self._identify_bottlenecks(recent_snapshots)
        
        # Generate recommendations
        recommendations = self._generate_performance_recommendations(node_id, recent_snapshots, bottlenecks)
        
        # Predict potential issues
        predicted_issues = self._predict_performance_issues(recent_snapshots)
        
        # Find optimization opportunities
        optimization_opportunities = self._find_optimization_opportunities(node_id, recent_snapshots)
        
        analysis = PerformanceAnalysis(
            node_id=node_id,
            analysis_period=analysis_period,
            trend=trend,
            performance_score=performance_score,
            bottlenecks=bottlenecks,
            recommendations=recommendations,
            predicted_issues=predicted_issues,
            optimization_opportunities=optimization_opportunities,
            created_at=datetime.now(timezone.utc)
        )
        
        # Store analysis
        if node_id not in self.performance_analyses:
            self.performance_analyses[node_id] = []
        
        self.performance_analyses[node_id].append(analysis)
        
        # Keep only recent analyses
        if len(self.performance_analyses[node_id]) > 100:
            self.performance_analyses[node_id] = self.performance_analyses[node_id][-100:]
        
        return analysis

    def _analyze_performance_trend(self, snapshots: List[PerformanceSnapshot]) -> PerformanceTrend:
        """Analyze performance trend from snapshots."""
        if len(snapshots) < 3:
            return PerformanceTrend.STABLE

        # Calculate trend for key metrics
        cpu_values = [s.cpu_usage for s in snapshots]
        response_time_values = [s.response_time_ms for s in snapshots]
        error_rate_values = [s.error_rate for s in snapshots]

        # Calculate slopes (simple linear trend)
        cpu_trend = self._calculate_trend_slope(cpu_values)
        response_trend = self._calculate_trend_slope(response_time_values)
        error_trend = self._calculate_trend_slope(error_rate_values)

        # Determine overall trend
        improving_indicators = 0
        degrading_indicators = 0

        if cpu_trend < -0.01:  # CPU usage decreasing
            improving_indicators += 1
        elif cpu_trend > 0.01:  # CPU usage increasing
            degrading_indicators += 1

        if response_trend < -1.0:  # Response time decreasing
            improving_indicators += 1
        elif response_trend > 1.0:  # Response time increasing
            degrading_indicators += 1

        if error_trend < -0.001:  # Error rate decreasing
            improving_indicators += 1
        elif error_trend > 0.001:  # Error rate increasing
            degrading_indicators += 1

        # Check for volatility
        cpu_volatility = statistics.stdev(cpu_values) if len(cpu_values) > 1 else 0
        response_volatility = statistics.stdev(response_time_values) if len(response_time_values) > 1 else 0

        if cpu_volatility > 0.2 or response_volatility > 50:  # High volatility thresholds
            return PerformanceTrend.VOLATILE

        if improving_indicators > degrading_indicators:
            return PerformanceTrend.IMPROVING
        elif degrading_indicators > improving_indicators:
            return PerformanceTrend.DEGRADING
        else:
            return PerformanceTrend.STABLE

    def _calculate_trend_slope(self, values: List[float]) -> float:
        """Calculate the slope of a trend line."""
        if len(values) < 2:
            return 0.0

        n = len(values)
        x_values = list(range(n))

        # Calculate slope using least squares method
        x_mean = sum(x_values) / n
        y_mean = sum(values) / n

        numerator = sum((x - x_mean) * (y - y_mean) for x, y in zip(x_values, values))
        denominator = sum((x - x_mean) ** 2 for x in x_values)

        if denominator == 0:
            return 0.0

        return numerator / denominator

    def _calculate_node_performance_score(self, snapshots: List[PerformanceSnapshot]) -> float:
        """Calculate overall performance score for a node."""
        if not snapshots:
            return 0.0

        # Calculate average metrics
        avg_cpu = sum(s.cpu_usage for s in snapshots) / len(snapshots)
        avg_memory = sum(s.memory_usage for s in snapshots) / len(snapshots)
        avg_response_time = sum(s.response_time_ms for s in snapshots) / len(snapshots)
        avg_error_rate = sum(s.error_rate for s in snapshots) / len(snapshots)
        avg_availability = sum(s.availability for s in snapshots) / len(snapshots)

        # Calculate component scores (0-1, higher is better)
        cpu_score = max(0, 1.0 - avg_cpu)  # Lower CPU usage is better
        memory_score = max(0, 1.0 - avg_memory)  # Lower memory usage is better
        response_score = max(0, 1.0 - min(1.0, avg_response_time / 1000))  # Lower response time is better
        error_score = max(0, 1.0 - min(1.0, avg_error_rate * 20))  # Lower error rate is better
        availability_score = avg_availability  # Higher availability is better

        # Weighted composite score
        performance_score = (
            cpu_score * 0.25 +
            memory_score * 0.20 +
            response_score * 0.25 +
            error_score * 0.15 +
            availability_score * 0.15
        )

        return max(0.0, min(1.0, performance_score))

    def _identify_bottlenecks(self, snapshots: List[PerformanceSnapshot]) -> List[str]:
        """Identify performance bottlenecks."""
        bottlenecks = []

        if not snapshots:
            return bottlenecks

        # Calculate average metrics
        avg_cpu = sum(s.cpu_usage for s in snapshots) / len(snapshots)
        avg_memory = sum(s.memory_usage for s in snapshots) / len(snapshots)
        avg_disk = sum(s.disk_usage for s in snapshots) / len(snapshots)
        avg_response_time = sum(s.response_time_ms for s in snapshots) / len(snapshots)
        avg_error_rate = sum(s.error_rate for s in snapshots) / len(snapshots)

        # Identify bottlenecks based on thresholds
        if avg_cpu > 0.8:
            bottlenecks.append("High CPU usage")

        if avg_memory > 0.85:
            bottlenecks.append("High memory usage")

        if avg_disk > 0.9:
            bottlenecks.append("High disk usage")

        if avg_response_time > 500:
            bottlenecks.append("High response time")

        if avg_error_rate > 0.05:
            bottlenecks.append("High error rate")

        # Check for resource contention
        cpu_memory_correlation = self._calculate_correlation(
            [s.cpu_usage for s in snapshots],
            [s.memory_usage for s in snapshots]
        )

        if cpu_memory_correlation > 0.8:
            bottlenecks.append("CPU-Memory contention")

        return bottlenecks

    def _calculate_correlation(self, x_values: List[float], y_values: List[float]) -> float:
        """Calculate correlation coefficient between two metrics."""
        if len(x_values) != len(y_values) or len(x_values) < 2:
            return 0.0

        n = len(x_values)
        x_mean = sum(x_values) / n
        y_mean = sum(y_values) / n

        numerator = sum((x - x_mean) * (y - y_mean) for x, y in zip(x_values, y_values))
        x_variance = sum((x - x_mean) ** 2 for x in x_values)
        y_variance = sum((y - y_mean) ** 2 for y in y_values)

        denominator = (x_variance * y_variance) ** 0.5

        if denominator == 0:
            return 0.0

        return numerator / denominator

    def _generate_performance_recommendations(self, node_id: str, snapshots: List[PerformanceSnapshot],
                                           bottlenecks: List[str]) -> List[str]:
        """Generate performance improvement recommendations."""
        recommendations = []

        if not snapshots:
            return recommendations

        avg_cpu = sum(s.cpu_usage for s in snapshots) / len(snapshots)
        avg_memory = sum(s.memory_usage for s in snapshots) / len(snapshots)
        avg_response_time = sum(s.response_time_ms for s in snapshots) / len(snapshots)

        # CPU-based recommendations
        if avg_cpu > 0.8:
            recommendations.append("Consider scaling up CPU resources or distributing load")
        elif avg_cpu < 0.3:
            recommendations.append("CPU resources are underutilized - consider consolidating workload")

        # Memory-based recommendations
        if avg_memory > 0.85:
            recommendations.append("Increase memory allocation or optimize memory usage")

        # Response time recommendations
        if avg_response_time > 500:
            recommendations.append("Optimize application performance or add caching")

        # Bottleneck-specific recommendations
        if "High CPU usage" in bottlenecks and "High memory usage" in bottlenecks:
            recommendations.append("Consider upgrading to a higher-tier instance")

        if "CPU-Memory contention" in bottlenecks:
            recommendations.append("Optimize resource allocation or separate CPU and memory intensive tasks")

        # Load balancing recommendations
        if node_id in self.cluster_manager.cluster_nodes:
            node = self.cluster_manager.cluster_nodes[node_id]
            if node.current_load > 0.7:
                recommendations.append("Redistribute workload to other nodes in the cluster")

        return recommendations

    def _predict_performance_issues(self, snapshots: List[PerformanceSnapshot]) -> List[str]:
        """Predict potential performance issues based on trends."""
        predicted_issues = []

        if len(snapshots) < 5:
            return predicted_issues

        # Analyze trends for prediction
        recent_snapshots = snapshots[-5:]  # Last 5 measurements

        cpu_trend = self._calculate_trend_slope([s.cpu_usage for s in recent_snapshots])
        memory_trend = self._calculate_trend_slope([s.memory_usage for s in recent_snapshots])
        response_trend = self._calculate_trend_slope([s.response_time_ms for s in recent_snapshots])
        error_trend = self._calculate_trend_slope([s.error_rate for s in recent_snapshots])

        # Predict issues based on trends
        if cpu_trend > 0.05:  # CPU usage increasing rapidly
            predicted_issues.append("CPU exhaustion predicted within 30 minutes")

        if memory_trend > 0.05:  # Memory usage increasing rapidly
            predicted_issues.append("Memory exhaustion predicted within 30 minutes")

        if response_trend > 10:  # Response time increasing rapidly
            predicted_issues.append("Performance degradation predicted")

        if error_trend > 0.01:  # Error rate increasing
            predicted_issues.append("Service instability predicted")

        return predicted_issues

    def _find_optimization_opportunities(self, node_id: str, snapshots: List[PerformanceSnapshot]) -> List[str]:
        """Find optimization opportunities."""
        opportunities = []

        if not snapshots:
            return opportunities

        avg_cpu = sum(s.cpu_usage for s in snapshots) / len(snapshots)
        avg_memory = sum(s.memory_usage for s in snapshots) / len(snapshots)
        avg_rps = sum(s.requests_per_second for s in snapshots) / len(snapshots)

        # Resource optimization opportunities
        if avg_cpu < 0.3 and avg_memory < 0.4:
            opportunities.append("Node is underutilized - consider consolidating workloads")

        if avg_rps < 50:
            opportunities.append("Low request volume - consider load balancing optimization")

        # Performance optimization opportunities
        baseline = self.baseline_performance.get(node_id, {})
        if baseline:
            current_response_time = sum(s.response_time_ms for s in snapshots) / len(snapshots)
            baseline_response_time = baseline.get("response_time_ms", current_response_time)

            if current_response_time > baseline_response_time * 1.2:
                opportunities.append("Response time degraded - investigate performance regression")

        return opportunities

    async def _metrics_collection_task(self):
        """Background task for metrics collection."""
        while True:
            try:
                await asyncio.sleep(self.collection_interval)

                # Collect metrics from all nodes
                await self.collect_cluster_metrics()

            except Exception as e:
                logger.error(f"Metrics collection task error: {e}")

    async def _performance_analysis_task(self):
        """Background task for performance analysis."""
        while True:
            try:
                await asyncio.sleep(600)  # Analyze every 10 minutes

                # Analyze performance for all nodes
                for node_id in self.cluster_manager.cluster_nodes.keys():
                    analysis = await self.analyze_node_performance(node_id)
                    if analysis:
                        # Check for alerts based on analysis
                        await self._check_performance_alerts(node_id, analysis)

            except Exception as e:
                logger.error(f"Performance analysis task error: {e}")

    async def _alert_monitoring_task(self):
        """Background task for alert monitoring."""
        while True:
            try:
                await asyncio.sleep(30)  # Check alerts every 30 seconds

                # Check all nodes for alert conditions
                for node_id in self.cluster_manager.cluster_nodes.keys():
                    await self._check_node_alerts(node_id)

                # Clean up resolved alerts
                await self._cleanup_resolved_alerts()

            except Exception as e:
                logger.error(f"Alert monitoring task error: {e}")

    async def _cleanup_task(self):
        """Background task for data cleanup."""
        while True:
            try:
                await asyncio.sleep(3600)  # Cleanup every hour

                # Clean up old performance snapshots
                cutoff_time = datetime.now(timezone.utc) - timedelta(days=self.history_retention_days)

                for node_id in self.performance_snapshots.keys():
                    self.performance_snapshots[node_id] = [
                        snapshot for snapshot in self.performance_snapshots[node_id]
                        if snapshot.timestamp >= cutoff_time
                    ]

                # Clean up old analyses
                for node_id in self.performance_analyses.keys():
                    self.performance_analyses[node_id] = [
                        analysis for analysis in self.performance_analyses[node_id]
                        if analysis.created_at >= cutoff_time
                    ]

                logger.debug("Completed performance data cleanup")

            except Exception as e:
                logger.error(f"Cleanup task error: {e}")

    async def _check_performance_alerts(self, node_id: str, analysis: PerformanceAnalysis):
        """Check for performance alerts based on analysis."""
        # Check for degrading performance trend
        if analysis.trend == PerformanceTrend.DEGRADING and analysis.performance_score < 0.5:
            await self._create_alert(
                node_id=node_id,
                metric=PerformanceMetric.RESPONSE_TIME,
                severity=AlertSeverity.WARNING,
                current_value=analysis.performance_score,
                threshold=0.5,
                message=f"Performance degrading on node {node_id}",
                recommendations=analysis.recommendations
            )

        # Check for predicted issues
        if analysis.predicted_issues:
            await self._create_alert(
                node_id=node_id,
                metric=PerformanceMetric.CPU_USAGE,
                severity=AlertSeverity.CRITICAL,
                current_value=1.0,
                threshold=0.95,
                message=f"Performance issues predicted: {', '.join(analysis.predicted_issues)}",
                recommendations=analysis.recommendations
            )

    async def _check_node_alerts(self, node_id: str):
        """Check for alert conditions on a specific node."""
        if node_id not in self.performance_snapshots or not self.performance_snapshots[node_id]:
            return

        # Get latest snapshot
        latest_snapshot = self.performance_snapshots[node_id][-1]

        # Check CPU usage
        if latest_snapshot.cpu_usage > self.alert_thresholds[PerformanceMetric.CPU_USAGE]:
            await self._create_alert(
                node_id=node_id,
                metric=PerformanceMetric.CPU_USAGE,
                severity=AlertSeverity.CRITICAL,
                current_value=latest_snapshot.cpu_usage,
                threshold=self.alert_thresholds[PerformanceMetric.CPU_USAGE],
                message=f"High CPU usage on node {node_id}: {latest_snapshot.cpu_usage:.1%}",
                recommendations=["Scale up resources", "Redistribute workload"]
            )

        # Check memory usage
        if latest_snapshot.memory_usage > self.alert_thresholds[PerformanceMetric.MEMORY_USAGE]:
            await self._create_alert(
                node_id=node_id,
                metric=PerformanceMetric.MEMORY_USAGE,
                severity=AlertSeverity.CRITICAL,
                current_value=latest_snapshot.memory_usage,
                threshold=self.alert_thresholds[PerformanceMetric.MEMORY_USAGE],
                message=f"High memory usage on node {node_id}: {latest_snapshot.memory_usage:.1%}",
                recommendations=["Increase memory allocation", "Optimize memory usage"]
            )

        # Check response time
        if latest_snapshot.response_time_ms > self.alert_thresholds[PerformanceMetric.RESPONSE_TIME]:
            await self._create_alert(
                node_id=node_id,
                metric=PerformanceMetric.RESPONSE_TIME,
                severity=AlertSeverity.WARNING,
                current_value=latest_snapshot.response_time_ms,
                threshold=self.alert_thresholds[PerformanceMetric.RESPONSE_TIME],
                message=f"High response time on node {node_id}: {latest_snapshot.response_time_ms:.1f}ms",
                recommendations=["Optimize application performance", "Add caching"]
            )

    async def _create_alert(self, node_id: str, metric: PerformanceMetric, severity: AlertSeverity,
                          current_value: float, threshold: float, message: str,
                          recommendations: List[str]):
        """Create a performance alert."""
        alert_id = f"alert_{secrets.token_hex(8)}"

        # Check if similar alert already exists
        existing_alert = None
        for alert in self.active_alerts.values():
            if (alert.node_id == node_id and
                alert.metric == metric and
                not alert.resolved):
                existing_alert = alert
                break

        if existing_alert:
            # Update existing alert
            existing_alert.current_value = current_value
            existing_alert.message = message
            return

        # Create new alert
        alert = PerformanceAlert(
            alert_id=alert_id,
            node_id=node_id,
            metric=metric,
            severity=severity,
            threshold=threshold,
            current_value=current_value,
            message=message,
            recommendations=recommendations,
            created_at=datetime.now(timezone.utc)
        )

        self.active_alerts[alert_id] = alert
        logger.warning(f"Performance alert created: {message}")

    async def _cleanup_resolved_alerts(self):
        """Clean up resolved alerts."""
        resolved_alerts = []

        for alert_id, alert in self.active_alerts.items():
            if alert.resolved:
                continue

            # Check if alert condition is resolved
            if alert.node_id in self.performance_snapshots and self.performance_snapshots[alert.node_id]:
                latest_snapshot = self.performance_snapshots[alert.node_id][-1]

                current_value = None
                if alert.metric == PerformanceMetric.CPU_USAGE:
                    current_value = latest_snapshot.cpu_usage
                elif alert.metric == PerformanceMetric.MEMORY_USAGE:
                    current_value = latest_snapshot.memory_usage
                elif alert.metric == PerformanceMetric.RESPONSE_TIME:
                    current_value = latest_snapshot.response_time_ms

                if current_value is not None and current_value < alert.threshold:
                    alert.resolved = True
                    alert.resolved_at = datetime.now(timezone.utc)
                    resolved_alerts.append(alert_id)
                    logger.info(f"Performance alert resolved: {alert.message}")

        # Remove resolved alerts after some time
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=1)
        for alert_id in list(self.active_alerts.keys()):
            alert = self.active_alerts[alert_id]
            if alert.resolved and alert.resolved_at and alert.resolved_at < cutoff_time:
                del self.active_alerts[alert_id]

    def _calculate_node_health_score(self, node_id: str, snapshot: PerformanceSnapshot) -> float:
        """Calculate comprehensive health score for a node."""
        try:
            # Base score from performance metrics
            cpu_score = max(0, 1.0 - snapshot.cpu_usage)
            memory_score = max(0, 1.0 - snapshot.memory_usage)
            disk_score = max(0, 1.0 - snapshot.disk_usage)

            # Response time score (lower is better)
            response_score = max(0, 1.0 - min(1.0, snapshot.response_time_ms / 5000.0))

            # Error rate score (lower is better)
            error_score = max(0, 1.0 - min(1.0, snapshot.error_rate * 10))

            # Availability score
            availability_score = snapshot.availability

            # Weighted average
            health_score = (
                cpu_score * 0.2 +
                memory_score * 0.2 +
                disk_score * 0.15 +
                response_score * 0.2 +
                error_score * 0.15 +
                availability_score * 0.1
            )

            # Apply penalties for specific conditions
            if snapshot.response_time_ms > 10000:  # 10 seconds
                health_score *= 0.5

            if snapshot.error_rate > 0.1:  # 10% error rate
                health_score *= 0.7

            # Check heartbeat freshness
            if node_id in self.last_heartbeats:
                heartbeat_age = (datetime.now(timezone.utc) - self.last_heartbeats[node_id]).total_seconds()
                if heartbeat_age > self.heartbeat_timeout_seconds:
                    health_score *= max(0.1, 1.0 - (heartbeat_age / (self.heartbeat_timeout_seconds * 2)))

            return max(0.0, min(1.0, health_score))

        except Exception as e:
            logger.error(f"Failed to calculate health score for node {node_id}: {e}")
            return 0.0

    def _determine_health_status(self, health_score: float) -> NodeHealthStatus:
        """Determine health status based on health score."""
        if health_score >= self.health_thresholds[NodeHealthStatus.HEALTHY]:
            return NodeHealthStatus.HEALTHY
        elif health_score >= self.health_thresholds[NodeHealthStatus.WARNING]:
            return NodeHealthStatus.WARNING
        elif health_score >= self.health_thresholds[NodeHealthStatus.CRITICAL]:
            return NodeHealthStatus.CRITICAL
        else:
            return NodeHealthStatus.FAILED

    async def _check_node_services(self, node_id: str) -> Dict[str, bool]:
        """Check status of services on a node."""
        try:
            # This would typically make actual service health checks
            # For now, return a basic status based on performance
            services = {
                "web_server": True,
                "database": True,
                "cache": True,
                "message_queue": True,
                "file_system": True
            }

            # Check if node is responsive
            if node_id in self.performance_snapshots and self.performance_snapshots[node_id]:
                latest = self.performance_snapshots[node_id][-1]

                # Mark services as down if severe issues
                if latest.cpu_usage > 0.95:
                    services["web_server"] = False
                if latest.memory_usage > 0.95:
                    services["cache"] = False
                if latest.disk_usage > 0.95:
                    services["database"] = False
                    services["file_system"] = False
                if latest.error_rate > 0.5:
                    services["web_server"] = False
                    services["message_queue"] = False

            return services

        except Exception as e:
            logger.error(f"Failed to check services for node {node_id}: {e}")
            return {}

    def _calculate_node_uptime(self, node_id: str) -> float:
        """Calculate node uptime in seconds."""
        try:
            if node_id not in self.performance_snapshots or not self.performance_snapshots[node_id]:
                return 0.0

            # Find the earliest snapshot
            earliest_snapshot = min(self.performance_snapshots[node_id], key=lambda s: s.timestamp)
            current_time = datetime.now(timezone.utc)

            uptime = (current_time - earliest_snapshot.timestamp).total_seconds()
            return max(0.0, uptime)

        except Exception as e:
            logger.error(f"Failed to calculate uptime for node {node_id}: {e}")
            return 0.0

    def _generate_healing_actions(self, node_id: str, health_status: NodeHealthStatus,
                                snapshot: PerformanceSnapshot) -> List[AutoHealingAction]:
        """Generate recommended auto-healing actions."""
        actions = []

        try:
            if health_status == NodeHealthStatus.FAILED:
                actions.extend([
                    AutoHealingAction.RESTART_SERVICE,
                    AutoHealingAction.FAILOVER,
                    AutoHealingAction.ISOLATE_NODE
                ])
            elif health_status == NodeHealthStatus.CRITICAL:
                if snapshot.cpu_usage > 0.9:
                    actions.append(AutoHealingAction.REDISTRIBUTE_LOAD)
                if snapshot.memory_usage > 0.9:
                    actions.extend([
                        AutoHealingAction.GARBAGE_COLLECT,
                        AutoHealingAction.CLEAR_CACHE
                    ])
                if snapshot.error_rate > 0.2:
                    actions.append(AutoHealingAction.RESTART_SERVICE)
                if snapshot.response_time_ms > 10000:
                    actions.append(AutoHealingAction.RESET_CONNECTIONS)
            elif health_status == NodeHealthStatus.WARNING:
                if snapshot.cpu_usage > 0.8:
                    actions.append(AutoHealingAction.REDISTRIBUTE_LOAD)
                if snapshot.memory_usage > 0.8:
                    actions.append(AutoHealingAction.GARBAGE_COLLECT)
                if snapshot.disk_usage > 0.8:
                    actions.append(AutoHealingAction.CLEAR_CACHE)

            return list(set(actions))  # Remove duplicates

        except Exception as e:
            logger.error(f"Failed to generate healing actions for node {node_id}: {e}")
            return []

    def _identify_failure_indicators(self, node_id: str, snapshot: PerformanceSnapshot) -> List[str]:
        """Identify potential failure indicators."""
        indicators = []

        try:
            if snapshot.cpu_usage > 0.95:
                indicators.append("CPU usage critically high")
            if snapshot.memory_usage > 0.95:
                indicators.append("Memory usage critically high")
            if snapshot.disk_usage > 0.95:
                indicators.append("Disk usage critically high")
            if snapshot.response_time_ms > 30000:
                indicators.append("Response time extremely high")
            if snapshot.error_rate > 0.5:
                indicators.append("Error rate critically high")
            if snapshot.availability < 0.5:
                indicators.append("Availability critically low")

            # Check heartbeat
            if node_id in self.last_heartbeats:
                heartbeat_age = (datetime.now(timezone.utc) - self.last_heartbeats[node_id]).total_seconds()
                if heartbeat_age > self.heartbeat_timeout_seconds * 2:
                    indicators.append("Heartbeat timeout exceeded")

            # Check failure count
            failure_count = self.node_failure_counts.get(node_id, 0)
            if failure_count >= self.max_failure_count:
                indicators.append(f"Multiple failures detected ({failure_count})")

            return indicators

        except Exception as e:
            logger.error(f"Failed to identify failure indicators for node {node_id}: {e}")
            return []

    def _calculate_recovery_progress(self, node_id: str) -> float:
        """Calculate recovery progress for a node."""
        try:
            if node_id not in self.healing_actions_in_progress:
                return 0.0

            # Simple progress calculation based on time since healing started
            # In a real implementation, this would track actual recovery metrics
            return min(1.0, len(self.healing_actions_in_progress[node_id]) * 0.25)

        except Exception as e:
            logger.error(f"Failed to calculate recovery progress for node {node_id}: {e}")
            return 0.0

    def _is_node_in_maintenance(self, node_id: str) -> bool:
        """Check if node is in maintenance mode."""
        try:
            # This would typically check a maintenance flag or schedule
            # For now, return False
            return False

        except Exception as e:
            logger.error(f"Failed to check maintenance status for node {node_id}: {e}")
            return False

    def _calculate_cluster_stability(self) -> float:
        """Calculate overall cluster stability."""
        try:
            if len(self.cluster_health_history) < 2:
                return 1.0

            # Calculate stability based on health score variance over time
            recent_scores = [summary.overall_health_score for summary in self.cluster_health_history[-10:]]

            if not recent_scores:
                return 1.0

            # Calculate coefficient of variation (lower is more stable)
            mean_score = sum(recent_scores) / len(recent_scores)
            if mean_score == 0:
                return 0.0

            variance = sum((score - mean_score) ** 2 for score in recent_scores) / len(recent_scores)
            std_dev = variance ** 0.5
            cv = std_dev / mean_score

            # Convert to stability score (0-1, higher is more stable)
            stability = max(0.0, 1.0 - min(1.0, cv))
            return stability

        except Exception as e:
            logger.error(f"Failed to calculate cluster stability: {e}")
            return 0.0

    def _estimate_cluster_failure_risk(self, failed_nodes: int, critical_nodes: int, total_nodes: int) -> float:
        """Estimate the risk of cluster failure."""
        try:
            if total_nodes == 0:
                return 1.0

            # Calculate risk based on failed and critical nodes
            failed_ratio = failed_nodes / total_nodes
            critical_ratio = critical_nodes / total_nodes

            # Risk increases exponentially with failed nodes
            risk = failed_ratio * 0.8 + critical_ratio * 0.4

            # Additional risk if too many nodes are problematic
            problematic_ratio = (failed_nodes + critical_nodes) / total_nodes
            if problematic_ratio > 0.5:
                risk += (problematic_ratio - 0.5) * 0.6

            return min(1.0, risk)

        except Exception as e:
            logger.error(f"Failed to estimate cluster failure risk: {e}")
            return 1.0

    async def execute_auto_healing_action(self, node_id: str, action: AutoHealingAction) -> bool:
        """Execute an auto-healing action on a node."""
        try:
            if not self.auto_healing_enabled:
                logger.info(f"Auto-healing disabled, skipping action {action.value} for node {node_id}")
                return False

            logger.info(f"Executing auto-healing action {action.value} on node {node_id}")

            # Track action in progress
            if node_id not in self.healing_actions_in_progress:
                self.healing_actions_in_progress[node_id] = []
            self.healing_actions_in_progress[node_id].append(action)

            # Execute the action based on type
            success = False

            if action == AutoHealingAction.RESTART_SERVICE:
                success = await self._restart_node_service(node_id)
            elif action == AutoHealingAction.CLEAR_CACHE:
                success = await self._clear_node_cache(node_id)
            elif action == AutoHealingAction.REDISTRIBUTE_LOAD:
                success = await self._redistribute_load_from_node(node_id)
            elif action == AutoHealingAction.SCALE_RESOURCES:
                success = await self._scale_node_resources(node_id)
            elif action == AutoHealingAction.ISOLATE_NODE:
                success = await self._isolate_node(node_id)
            elif action == AutoHealingAction.FAILOVER:
                success = await self._failover_node(node_id)
            elif action == AutoHealingAction.GARBAGE_COLLECT:
                success = await self._trigger_garbage_collection(node_id)
            elif action == AutoHealingAction.RESET_CONNECTIONS:
                success = await self._reset_node_connections(node_id)

            # Remove action from progress
            if node_id in self.healing_actions_in_progress:
                try:
                    self.healing_actions_in_progress[node_id].remove(action)
                    if not self.healing_actions_in_progress[node_id]:
                        del self.healing_actions_in_progress[node_id]
                except ValueError:
                    pass

            if success:
                logger.info(f"Auto-healing action {action.value} completed successfully for node {node_id}")
            else:
                logger.warning(f"Auto-healing action {action.value} failed for node {node_id}")
                # Increment failure count
                self.node_failure_counts[node_id] = self.node_failure_counts.get(node_id, 0) + 1

            return success

        except Exception as e:
            logger.error(f"Failed to execute auto-healing action {action.value} for node {node_id}: {e}")
            return False

    async def _restart_node_service(self, node_id: str) -> bool:
        """Restart services on a node."""
        try:
            # In a real implementation, this would send restart commands to the node
            logger.info(f"Restarting services on node {node_id}")
            await asyncio.sleep(1)  # Simulate restart time
            return True
        except Exception as e:
            logger.error(f"Failed to restart services on node {node_id}: {e}")
            return False

    async def _clear_node_cache(self, node_id: str) -> bool:
        """Clear cache on a node."""
        try:
            logger.info(f"Clearing cache on node {node_id}")
            await asyncio.sleep(0.5)  # Simulate cache clear time
            return True
        except Exception as e:
            logger.error(f"Failed to clear cache on node {node_id}: {e}")
            return False

    async def _redistribute_load_from_node(self, node_id: str) -> bool:
        """Redistribute load away from a node."""
        try:
            logger.info(f"Redistributing load from node {node_id}")
            # This would typically involve load balancer reconfiguration
            await asyncio.sleep(2)  # Simulate redistribution time
            return True
        except Exception as e:
            logger.error(f"Failed to redistribute load from node {node_id}: {e}")
            return False

    async def _scale_node_resources(self, node_id: str) -> bool:
        """Scale resources for a node."""
        try:
            logger.info(f"Scaling resources for node {node_id}")
            # This would typically involve container/VM scaling
            await asyncio.sleep(3)  # Simulate scaling time
            return True
        except Exception as e:
            logger.error(f"Failed to scale resources for node {node_id}: {e}")
            return False

    async def _isolate_node(self, node_id: str) -> bool:
        """Isolate a problematic node."""
        try:
            logger.info(f"Isolating node {node_id}")
            # This would remove the node from active rotation
            await asyncio.sleep(1)  # Simulate isolation time
            return True
        except Exception as e:
            logger.error(f"Failed to isolate node {node_id}: {e}")
            return False

    async def _failover_node(self, node_id: str) -> bool:
        """Failover from a node to backup nodes."""
        try:
            logger.info(f"Failing over from node {node_id}")
            # This would activate backup nodes and transfer state
            await asyncio.sleep(5)  # Simulate failover time
            return True
        except Exception as e:
            logger.error(f"Failed to failover from node {node_id}: {e}")
            return False

    async def _trigger_garbage_collection(self, node_id: str) -> bool:
        """Trigger garbage collection on a node."""
        try:
            logger.info(f"Triggering garbage collection on node {node_id}")
            await asyncio.sleep(1)  # Simulate GC time
            return True
        except Exception as e:
            logger.error(f"Failed to trigger garbage collection on node {node_id}: {e}")
            return False

    async def _reset_node_connections(self, node_id: str) -> bool:
        """Reset connections on a node."""
        try:
            logger.info(f"Resetting connections on node {node_id}")
            await asyncio.sleep(1)  # Simulate connection reset time
            return True
        except Exception as e:
            logger.error(f"Failed to reset connections on node {node_id}: {e}")
            return False

    async def update_node_heartbeat(self, node_id: str) -> None:
        """Update the last heartbeat time for a node."""
        try:
            self.last_heartbeats[node_id] = datetime.now(timezone.utc)
            logger.debug(f"Updated heartbeat for node {node_id}")
        except Exception as e:
            logger.error(f"Failed to update heartbeat for node {node_id}: {e}")

    async def enable_auto_healing(self) -> None:
        """Enable auto-healing functionality."""
        self.auto_healing_enabled = True
        logger.info("Auto-healing enabled")

    async def disable_auto_healing(self) -> None:
        """Disable auto-healing functionality."""
        self.auto_healing_enabled = False
        logger.info("Auto-healing disabled")

    async def get_healing_status(self) -> Dict[str, Any]:
        """Get current auto-healing status."""
        return {
            "auto_healing_enabled": self.auto_healing_enabled,
            "actions_in_progress": {
                node_id: [action.value for action in actions]
                for node_id, actions in self.healing_actions_in_progress.items()
            },
            "node_failure_counts": self.node_failure_counts.copy(),
            "last_heartbeats": {
                node_id: heartbeat.isoformat()
                for node_id, heartbeat in self.last_heartbeats.items()
            }
        }

    async def shutdown(self) -> None:
        """Gracefully shutdown the performance monitor."""
        try:
            logger.info("🛑 Shutting down Real-Time Performance Monitor")

            # Stop auto-healing
            await self.disable_auto_healing()

            # Cancel any ongoing healing actions
            for node_id in list(self.healing_actions_in_progress.keys()):
                self.healing_actions_in_progress[node_id].clear()

            # Clear state
            self.performance_snapshots.clear()
            self.active_alerts.clear()
            self.performance_analyses.clear()
            self.node_health_reports.clear()
            self.cluster_health_history.clear()

            # Log final statistics
            logger.info("📊 Final performance monitoring statistics:")
            logger.info(f"   Total snapshots collected: {sum(len(snapshots) for snapshots in self.performance_snapshots.values())}")
            logger.info(f"   Total alerts generated: {len(self.active_alerts)}")
            logger.info(f"   Auto-healing actions performed: {sum(self.node_failure_counts.values())}")

            logger.info("✅ Real-Time Performance Monitor shutdown complete")

        except Exception as e:
            logger.error(f"❌ Error during performance monitor shutdown: {e}")

    async def get_comprehensive_health_report(self) -> Dict[str, Any]:
        """Get comprehensive cluster health report."""
        try:
            current_time = datetime.now(timezone.utc)

            # Generate cluster health summary
            cluster_summary = await self.generate_cluster_health_summary()

            # Get individual node health reports
            node_reports = {}
            for node_id in self.cluster_manager.cluster_nodes.keys():
                health_report = await self.generate_node_health_report(node_id)
                if health_report:
                    node_reports[node_id] = {
                        "health_status": health_report.health_status.value,
                        "health_score": health_report.health_score,
                        "uptime_seconds": health_report.uptime_seconds,
                        "service_statuses": health_report.service_statuses,
                        "active_alerts": len(health_report.active_alerts),
                        "recommended_actions": [action.value for action in health_report.recommended_actions],
                        "failure_indicators": health_report.failure_indicators,
                        "maintenance_mode": health_report.maintenance_mode
                    }

            # Performance trends
            performance_trends = await self._calculate_performance_trends()

            # System recommendations
            recommendations = await self._generate_system_recommendations(cluster_summary, node_reports)

            return {
                "report_metadata": {
                    "generated_at": current_time.isoformat(),
                    "report_type": "comprehensive_health_report",
                    "cluster_id": getattr(self.cluster_manager, 'cluster_id', 'unknown')
                },
                "cluster_summary": {
                    "total_nodes": cluster_summary.total_nodes,
                    "healthy_nodes": cluster_summary.healthy_nodes,
                    "warning_nodes": cluster_summary.warning_nodes,
                    "critical_nodes": cluster_summary.critical_nodes,
                    "failed_nodes": cluster_summary.failed_nodes,
                    "overall_health_score": cluster_summary.overall_health_score,
                    "cluster_stability": cluster_summary.cluster_stability,
                    "auto_healing_active": cluster_summary.auto_healing_active,
                    "capacity_utilization": cluster_summary.cluster_capacity_utilization,
                    "failure_risk": cluster_summary.estimated_failure_risk
                },
                "node_reports": node_reports,
                "performance_trends": performance_trends,
                "active_alerts": [
                    {
                        "alert_id": alert.alert_id,
                        "node_id": alert.node_id,
                        "metric": alert.metric.value,
                        "severity": alert.severity.value,
                        "threshold": alert.threshold,
                        "current_value": alert.current_value,
                        "message": alert.message,
                        "created_at": alert.created_at.isoformat(),
                        "resolved": alert.resolved
                    }
                    for alert in self.active_alerts.values()
                ],
                "healing_status": await self.get_healing_status(),
                "recommendations": recommendations,
                "system_health": "healthy" if cluster_summary.overall_health_score > 0.8 else "degraded"
            }

        except Exception as e:
            logger.error(f"❌ Error generating comprehensive health report: {e}")
            return {"error": str(e)}

    async def _calculate_performance_trends(self) -> Dict[str, Any]:
        """Calculate performance trends across the cluster."""
        try:
            trends = {}

            for node_id, snapshots in self.performance_snapshots.items():
                if len(snapshots) < 2:
                    continue

                # Get recent snapshots (last hour)
                recent_cutoff = datetime.now(timezone.utc) - timedelta(hours=1)
                recent_snapshots = [s for s in snapshots if s.timestamp >= recent_cutoff]

                if len(recent_snapshots) < 2:
                    continue

                # Calculate trends
                cpu_trend = self._calculate_metric_trend([s.cpu_usage for s in recent_snapshots])
                memory_trend = self._calculate_metric_trend([s.memory_usage for s in recent_snapshots])
                response_trend = self._calculate_metric_trend([s.response_time_ms for s in recent_snapshots])

                trends[node_id] = {
                    "cpu_trend": cpu_trend,
                    "memory_trend": memory_trend,
                    "response_time_trend": response_trend,
                    "overall_trend": "improving" if (cpu_trend + memory_trend - response_trend) > 0 else "degrading"
                }

            return trends

        except Exception as e:
            logger.error(f"❌ Error calculating performance trends: {e}")
            return {}

    def _calculate_metric_trend(self, values: List[float]) -> float:
        """Calculate trend for a metric (positive = improving, negative = degrading)."""
        try:
            if len(values) < 2:
                return 0.0

            # Simple linear trend calculation
            n = len(values)
            x_sum = sum(range(n))
            y_sum = sum(values)
            xy_sum = sum(i * values[i] for i in range(n))
            x2_sum = sum(i * i for i in range(n))

            # Calculate slope
            slope = (n * xy_sum - x_sum * y_sum) / (n * x2_sum - x_sum * x_sum)
            return -slope  # Negative because lower values are better for most metrics

        except Exception:
            return 0.0

    async def _generate_system_recommendations(self, cluster_summary: Any,
                                             node_reports: Dict[str, Any]) -> List[str]:
        """Generate system-wide recommendations."""
        recommendations = []

        try:
            # Cluster-level recommendations
            if cluster_summary.overall_health_score < 0.7:
                recommendations.append("Cluster health is critical - immediate attention required")
                recommendations.append("Consider emergency maintenance procedures")
            elif cluster_summary.overall_health_score < 0.8:
                recommendations.append("Cluster health is degraded - investigate failing nodes")

            if cluster_summary.failed_nodes > 0:
                recommendations.append(f"Replace or repair {cluster_summary.failed_nodes} failed nodes")

            if cluster_summary.cluster_capacity_utilization > 0.8:
                recommendations.append("High cluster utilization - consider adding more nodes")

            if cluster_summary.estimated_failure_risk > 0.3:
                recommendations.append("High failure risk detected - review backup procedures")

            # Node-level recommendations
            critical_nodes = [node_id for node_id, report in node_reports.items()
                            if report["health_status"] in ["critical", "failed"]]

            if len(critical_nodes) > 1:
                recommendations.append(f"Multiple critical nodes detected: {', '.join(critical_nodes)}")

            # Auto-healing recommendations
            if not cluster_summary.auto_healing_active:
                recommendations.append("Auto-healing is disabled - consider enabling for better resilience")

            if not recommendations:
                recommendations.append("Cluster is operating optimally")

            return recommendations

        except Exception as e:
            logger.error(f"❌ Error generating recommendations: {e}")
            return ["Error generating recommendations"]
