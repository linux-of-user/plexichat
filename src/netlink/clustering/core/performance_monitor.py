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
        
        # Configuration
        self.collection_interval = METRICS_COLLECTION_INTERVAL
        self.history_retention_days = PERFORMANCE_HISTORY_DAYS
        self.alert_thresholds = {
            PerformanceMetric.CPU_USAGE: ALERT_THRESHOLD_CPU,
            PerformanceMetric.MEMORY_USAGE: ALERT_THRESHOLD_MEMORY,
            PerformanceMetric.DISK_USAGE: ALERT_THRESHOLD_DISK,
            PerformanceMetric.RESPONSE_TIME: 1000.0,  # 1 second
            PerformanceMetric.ERROR_RATE: 0.05,  # 5%
            PerformanceMetric.AVAILABILITY: 0.95  # 95%
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
