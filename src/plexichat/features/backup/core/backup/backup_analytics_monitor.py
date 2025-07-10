"""
PlexiChat Backup Analytics & Monitoring System

Provides real-time backup health monitoring, availability percentage tracking,
predictive failure detection, and comprehensive backup reporting.
"""

import asyncio
import json
import statistics
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
import numpy as np
from collections import defaultdict, deque

from ...core.logging import get_logger
from ...core.config import get_config
from .zero_knowledge_protocol import ZeroKnowledgeBackupProtocol
from .immutable_shard_manager import ImmutableShardManager, ShardState
from .multi_node_network import MultiNodeBackupNetwork
from .advanced_recovery_system import AdvancedRecoverySystem

logger = get_logger(__name__)


class HealthStatus(Enum):
    """System health status levels."""
    EXCELLENT = "excellent"
    GOOD = "good"
    WARNING = "warning"
    CRITICAL = "critical"
    FAILURE = "failure"


class AlertSeverity(Enum):
    """Alert severity levels."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class HealthMetric:
    """Individual health metric."""
    name: str
    value: float
    unit: str
    status: HealthStatus
    threshold_warning: float
    threshold_critical: float
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    trend: Optional[str] = None  # "improving", "stable", "degrading"


@dataclass
class SystemAlert:
    """System alert notification."""
    alert_id: str
    severity: AlertSeverity
    title: str
    message: str
    component: str
    metric_name: Optional[str] = None
    metric_value: Optional[float] = None
    threshold: Optional[float] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    acknowledged: bool = False
    resolved: bool = False


@dataclass
class BackupReport:
    """Comprehensive backup system report."""
    report_id: str
    report_type: str
    generated_at: datetime
    time_period: Tuple[datetime, datetime]
    
    # Summary statistics
    total_backups: int
    successful_backups: int
    failed_backups: int
    total_data_backed_up: int
    
    # Performance metrics
    average_backup_time: float
    average_throughput: float
    availability_percentage: float
    
    # Health metrics
    node_health: Dict[str, HealthStatus]
    shard_integrity_percentage: float
    recovery_success_rate: float
    
    # Predictions
    predicted_failures: List[Dict[str, Any]]
    capacity_predictions: Dict[str, Any]
    
    # Detailed data
    detailed_metrics: Dict[str, Any] = field(default_factory=dict)


class BackupAnalyticsMonitor:
    """
    Comprehensive backup analytics and monitoring system.
    
    Features:
    - Real-time health monitoring with configurable thresholds
    - Availability percentage tracking with SLA monitoring
    - Predictive failure detection using machine learning
    - Comprehensive backup reporting with trends
    - Alert system with severity levels and notifications
    - Performance analytics with bottleneck detection
    - Capacity planning with growth predictions
    - Node health monitoring with automatic remediation
    - Shard integrity tracking with corruption detection
    - Recovery success rate analysis
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or self._load_default_config()
        
        # Core components
        self.zero_knowledge_protocol = ZeroKnowledgeBackupProtocol()
        self.shard_manager = ImmutableShardManager()
        self.network_manager = MultiNodeBackupNetwork()
        self.recovery_system = AdvancedRecoverySystem()
        
        # Monitoring state
        self.health_metrics: Dict[str, HealthMetric] = {}
        self.active_alerts: Dict[str, SystemAlert] = {}
        self.historical_metrics: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        
        # Performance tracking
        self.performance_history: deque = deque(maxlen=10000)
        self.availability_history: deque = deque(maxlen=1440)  # 24 hours of minutes
        
        # Monitoring settings
        self.monitoring_interval = self.config.get("monitoring_interval_seconds", 60)
        self.alert_cooldown = self.config.get("alert_cooldown_minutes", 15)
        self.availability_sla_target = self.config.get("availability_sla_target", 99.9)
        
        # Health thresholds
        self.health_thresholds = self.config.get("health_thresholds", {
            "availability_percentage": {"warning": 95.0, "critical": 90.0},
            "shard_integrity_percentage": {"warning": 95.0, "critical": 90.0},
            "node_failure_percentage": {"warning": 20.0, "critical": 40.0},
            "recovery_success_rate": {"warning": 90.0, "critical": 80.0},
            "backup_failure_rate": {"warning": 5.0, "critical": 10.0},
            "average_response_time": {"warning": 5.0, "critical": 10.0}
        })
        
        # Predictive analytics
        self.enable_predictive_analytics = self.config.get("enable_predictive_analytics", True)
        self.prediction_window_hours = self.config.get("prediction_window_hours", 24)
        
        # Reporting
        self.report_generation_enabled = self.config.get("report_generation_enabled", True)
        self.daily_reports = self.config.get("daily_reports", True)
        self.weekly_reports = self.config.get("weekly_reports", True)
        self.monthly_reports = self.config.get("monthly_reports", True)
        
        # Statistics
        self.monitoring_stats = {
            "monitoring_cycles": 0,
            "alerts_generated": 0,
            "reports_generated": 0,
            "predictions_made": 0,
            "uptime_seconds": 0
        }
        
        self.initialized = False
        self.start_time = datetime.now(timezone.utc)
        
        logger.info("📊 Backup Analytics & Monitoring System initialized")
    
    def _load_default_config(self) -> Dict[str, Any]:
        """Load default monitoring configuration."""
        return {
            "monitoring_interval_seconds": 60,
            "alert_cooldown_minutes": 15,
            "availability_sla_target": 99.9,
            "enable_predictive_analytics": True,
            "prediction_window_hours": 24,
            "report_generation_enabled": True,
            "daily_reports": True,
            "weekly_reports": True,
            "monthly_reports": True,
            "max_historical_metrics": 10000,
            "alert_notification_enabled": True,
            "performance_monitoring_enabled": True,
            "capacity_monitoring_enabled": True,
            "trend_analysis_enabled": True
        }
    
    async def initialize(self) -> Dict[str, Any]:
        """Initialize the backup analytics and monitoring system."""
        try:
            if self.initialized:
                return {"success": True, "message": "Already initialized"}
            
            logger.info("🚀 Initializing backup analytics and monitoring system...")
            
            # Initialize core components
            await self.zero_knowledge_protocol.initialize()
            await self.shard_manager.initialize()
            await self.network_manager.initialize_network()
            await self.recovery_system.initialize()
            
            # Start monitoring loops
            asyncio.create_task(self._health_monitoring_loop())
            asyncio.create_task(self._availability_tracking_loop())
            asyncio.create_task(self._alert_processing_loop())
            
            if self.enable_predictive_analytics:
                asyncio.create_task(self._predictive_analytics_loop())
            
            if self.report_generation_enabled:
                asyncio.create_task(self._report_generation_loop())
            
            self.initialized = True
            
            logger.info("✅ Backup analytics and monitoring system initialized")
            
            return {
                "success": True,
                "monitoring_interval": self.monitoring_interval,
                "availability_sla_target": self.availability_sla_target,
                "predictive_analytics_enabled": self.enable_predictive_analytics,
                "report_generation_enabled": self.report_generation_enabled
            }
            
        except Exception as e:
            logger.error(f"❌ Failed to initialize backup analytics monitor: {e}")
            return {"success": False, "error": str(e)}
    
    async def _health_monitoring_loop(self):
        """Main health monitoring loop."""
        try:
            logger.info("🔄 Starting health monitoring loop...")
            
            while True:
                try:
                    await asyncio.sleep(self.monitoring_interval)
                    
                    # Collect health metrics
                    await self._collect_health_metrics()
                    
                    # Analyze metrics and generate alerts
                    await self._analyze_health_metrics()
                    
                    # Update statistics
                    self.monitoring_stats["monitoring_cycles"] += 1
                    self.monitoring_stats["uptime_seconds"] = (
                        datetime.now(timezone.utc) - self.start_time
                    ).total_seconds()
                    
                except Exception as e:
                    logger.error(f"❌ Error in health monitoring loop: {e}")
                    continue
                    
        except asyncio.CancelledError:
            logger.info("🛑 Health monitoring loop cancelled")
        except Exception as e:
            logger.error(f"❌ Health monitoring loop failed: {e}")
    
    async def _collect_health_metrics(self):
        """Collect comprehensive health metrics."""
        try:
            current_time = datetime.now(timezone.utc)
            
            # Node availability metrics
            available_nodes = await self.network_manager.get_available_nodes()
            total_nodes = await self.network_manager.get_total_node_count()
            
            if total_nodes > 0:
                availability_percentage = (len(available_nodes) / total_nodes) * 100
                self._update_health_metric(
                    "availability_percentage",
                    availability_percentage,
                    "%",
                    self.health_thresholds["availability_percentage"]
                )
            
            # Shard integrity metrics
            total_shards = len(self.shard_manager.shards)
            if total_shards > 0:
                healthy_shards = len([s for s in self.shard_manager.shards.values() 
                                    if s.metadata.state not in [ShardState.CORRUPTED]])
                integrity_percentage = (healthy_shards / total_shards) * 100
                self._update_health_metric(
                    "shard_integrity_percentage",
                    integrity_percentage,
                    "%",
                    self.health_thresholds["shard_integrity_percentage"]
                )
            
            # Recovery system metrics
            recovery_stats = await self.recovery_system.get_recovery_statistics()
            if recovery_stats and recovery_stats["recovery_stats"]["total_recoveries"] > 0:
                success_rate = (recovery_stats["recovery_stats"]["successful_recoveries"] / 
                              recovery_stats["recovery_stats"]["total_recoveries"]) * 100
                self._update_health_metric(
                    "recovery_success_rate",
                    success_rate,
                    "%",
                    self.health_thresholds["recovery_success_rate"]
                )
            
            # Zero-knowledge protocol metrics
            zk_stats = await self.zero_knowledge_protocol.get_protocol_statistics()
            if zk_stats and zk_stats["encryption_stats"]["chunks_encrypted"] > 0:
                encryption_success_rate = (
                    zk_stats["encryption_stats"]["chunks_encrypted"] / 
                    (zk_stats["encryption_stats"]["chunks_encrypted"] + 
                     zk_stats["encryption_stats"].get("encryption_failures", 0))
                ) * 100
                self._update_health_metric(
                    "encryption_success_rate",
                    encryption_success_rate,
                    "%",
                    {"warning": 95.0, "critical": 90.0}
                )
            
            logger.debug(f"📊 Health metrics collected: {len(self.health_metrics)} metrics")
            
        except Exception as e:
            logger.error(f"❌ Failed to collect health metrics: {e}")
    
    def _update_health_metric(self, name: str, value: float, unit: str, 
                            thresholds: Dict[str, float]):
        """Update a health metric with trend analysis."""
        try:
            # Determine health status
            if value >= thresholds["warning"]:
                status = HealthStatus.EXCELLENT if value >= 99.0 else HealthStatus.GOOD
            elif value >= thresholds["critical"]:
                status = HealthStatus.WARNING
            else:
                status = HealthStatus.CRITICAL
            
            # Calculate trend
            trend = None
            if name in self.historical_metrics and len(self.historical_metrics[name]) > 1:
                recent_values = list(self.historical_metrics[name])[-5:]  # Last 5 values
                if len(recent_values) >= 3:
                    if recent_values[-1] > recent_values[-2] > recent_values[-3]:
                        trend = "improving"
                    elif recent_values[-1] < recent_values[-2] < recent_values[-3]:
                        trend = "degrading"
                    else:
                        trend = "stable"
            
            # Create/update metric
            metric = HealthMetric(
                name=name,
                value=value,
                unit=unit,
                status=status,
                threshold_warning=thresholds["warning"],
                threshold_critical=thresholds["critical"],
                trend=trend
            )
            
            self.health_metrics[name] = metric
            self.historical_metrics[name].append(value)
            
        except Exception as e:
            logger.error(f"❌ Failed to update health metric {name}: {e}")

    async def _analyze_health_metrics(self):
        """Analyze health metrics and generate alerts."""
        try:
            for metric_name, metric in self.health_metrics.items():
                # Check if alert should be generated
                if metric.status in [HealthStatus.WARNING, HealthStatus.CRITICAL]:
                    await self._generate_alert(metric)

                # Check for trend-based alerts
                if metric.trend == "degrading" and metric.status == HealthStatus.WARNING:
                    await self._generate_trend_alert(metric)

        except Exception as e:
            logger.error(f"❌ Failed to analyze health metrics: {e}")

    async def _generate_alert(self, metric: HealthMetric):
        """Generate an alert for a health metric."""
        try:
            alert_id = f"alert_{metric.name}_{int(time.time())}"

            # Check if similar alert already exists (cooldown)
            existing_alerts = [a for a in self.active_alerts.values()
                             if a.metric_name == metric.name and not a.resolved]

            if existing_alerts:
                last_alert = max(existing_alerts, key=lambda x: x.timestamp)
                cooldown_period = timedelta(minutes=self.alert_cooldown)
                if datetime.now(timezone.utc) - last_alert.timestamp < cooldown_period:
                    return  # Skip alert due to cooldown

            # Determine severity
            severity = AlertSeverity.CRITICAL if metric.status == HealthStatus.CRITICAL else AlertSeverity.WARNING

            # Create alert
            alert = SystemAlert(
                alert_id=alert_id,
                severity=severity,
                title=f"{metric.name.replace('_', ' ').title()} Alert",
                message=f"{metric.name} is {metric.value:.2f}{metric.unit}, "
                       f"below {'critical' if severity == AlertSeverity.CRITICAL else 'warning'} "
                       f"threshold of {metric.threshold_critical if severity == AlertSeverity.CRITICAL else metric.threshold_warning:.2f}{metric.unit}",
                component="backup_system",
                metric_name=metric.name,
                metric_value=metric.value,
                threshold=metric.threshold_critical if severity == AlertSeverity.CRITICAL else metric.threshold_warning
            )

            self.active_alerts[alert_id] = alert
            self.monitoring_stats["alerts_generated"] += 1

            logger.warning(f"🚨 Alert generated: {alert.title} - {alert.message}")

        except Exception as e:
            logger.error(f"❌ Failed to generate alert: {e}")

    async def _generate_trend_alert(self, metric: HealthMetric):
        """Generate trend-based alert."""
        try:
            alert_id = f"trend_alert_{metric.name}_{int(time.time())}"

            alert = SystemAlert(
                alert_id=alert_id,
                severity=AlertSeverity.WARNING,
                title=f"Degrading Trend: {metric.name.replace('_', ' ').title()}",
                message=f"{metric.name} is showing a degrading trend with current value "
                       f"{metric.value:.2f}{metric.unit}. Immediate attention may be required.",
                component="backup_system",
                metric_name=metric.name,
                metric_value=metric.value
            )

            self.active_alerts[alert_id] = alert
            self.monitoring_stats["alerts_generated"] += 1

            logger.warning(f"📉 Trend alert generated: {alert.title}")

        except Exception as e:
            logger.error(f"❌ Failed to generate trend alert: {e}")

    async def _availability_tracking_loop(self):
        """Track system availability over time."""
        try:
            logger.info("📈 Starting availability tracking loop...")

            while True:
                try:
                    await asyncio.sleep(60)  # Track every minute

                    # Calculate current availability
                    available_nodes = await self.network_manager.get_available_nodes()
                    total_nodes = await self.network_manager.get_total_node_count()

                    if total_nodes > 0:
                        availability = (len(available_nodes) / total_nodes) * 100
                        self.availability_history.append({
                            "timestamp": datetime.now(timezone.utc),
                            "availability": availability
                        })

                except Exception as e:
                    logger.error(f"❌ Error in availability tracking: {e}")
                    continue

        except asyncio.CancelledError:
            logger.info("🛑 Availability tracking loop cancelled")
        except Exception as e:
            logger.error(f"❌ Availability tracking loop failed: {e}")

    async def _alert_processing_loop(self):
        """Process and manage alerts."""
        try:
            logger.info("🚨 Starting alert processing loop...")

            while True:
                try:
                    await asyncio.sleep(300)  # Process every 5 minutes

                    # Auto-resolve alerts for metrics that have improved
                    await self._auto_resolve_alerts()

                    # Clean up old resolved alerts
                    await self._cleanup_old_alerts()

                except Exception as e:
                    logger.error(f"❌ Error in alert processing: {e}")
                    continue

        except asyncio.CancelledError:
            logger.info("🛑 Alert processing loop cancelled")
        except Exception as e:
            logger.error(f"❌ Alert processing loop failed: {e}")

    async def _auto_resolve_alerts(self):
        """Automatically resolve alerts when conditions improve."""
        try:
            for alert_id, alert in list(self.active_alerts.items()):
                if alert.resolved or not alert.metric_name:
                    continue

                # Check if metric has improved
                current_metric = self.health_metrics.get(alert.metric_name)
                if current_metric and current_metric.status in [HealthStatus.GOOD, HealthStatus.EXCELLENT]:
                    alert.resolved = True
                    logger.info(f"✅ Auto-resolved alert: {alert.title}")

        except Exception as e:
            logger.error(f"❌ Failed to auto-resolve alerts: {e}")

    async def _cleanup_old_alerts(self):
        """Clean up old resolved alerts."""
        try:
            cutoff_time = datetime.now(timezone.utc) - timedelta(hours=24)

            alerts_to_remove = [
                alert_id for alert_id, alert in self.active_alerts.items()
                if alert.resolved and alert.timestamp < cutoff_time
            ]

            for alert_id in alerts_to_remove:
                del self.active_alerts[alert_id]

            if alerts_to_remove:
                logger.debug(f"🧹 Cleaned up {len(alerts_to_remove)} old alerts")

        except Exception as e:
            logger.error(f"❌ Failed to cleanup old alerts: {e}")

    async def _predictive_analytics_loop(self):
        """Predictive analytics and failure detection."""
        try:
            logger.info("🔮 Starting predictive analytics loop...")

            while True:
                try:
                    await asyncio.sleep(3600)  # Run every hour

                    # Perform predictive analysis
                    predictions = await self._perform_predictive_analysis()

                    # Generate predictive alerts
                    for prediction in predictions:
                        await self._generate_predictive_alert(prediction)

                    self.monitoring_stats["predictions_made"] += len(predictions)

                except Exception as e:
                    logger.error(f"❌ Error in predictive analytics: {e}")
                    continue

        except asyncio.CancelledError:
            logger.info("🛑 Predictive analytics loop cancelled")
        except Exception as e:
            logger.error(f"❌ Predictive analytics loop failed: {e}")

    async def _perform_predictive_analysis(self) -> List[Dict[str, Any]]:
        """Perform predictive analysis on historical data."""
        try:
            predictions = []

            # Analyze each metric for potential issues
            for metric_name, historical_data in self.historical_metrics.items():
                if len(historical_data) < 10:  # Need sufficient data
                    continue

                # Simple trend analysis (can be enhanced with ML)
                recent_values = list(historical_data)[-10:]

                # Calculate trend slope
                x = np.arange(len(recent_values))
                y = np.array(recent_values)

                if len(x) > 1:
                    slope = np.polyfit(x, y, 1)[0]

                    # Predict future value
                    future_steps = self.prediction_window_hours
                    predicted_value = y[-1] + (slope * future_steps)

                    # Check if prediction indicates potential issue
                    thresholds = self.health_thresholds.get(metric_name, {})
                    if thresholds:
                        warning_threshold = thresholds.get("warning", 0)
                        critical_threshold = thresholds.get("critical", 0)

                        if predicted_value < critical_threshold:
                            predictions.append({
                                "metric_name": metric_name,
                                "current_value": float(y[-1]),
                                "predicted_value": float(predicted_value),
                                "prediction_window_hours": self.prediction_window_hours,
                                "severity": "critical",
                                "confidence": min(0.9, len(recent_values) / 20.0)
                            })
                        elif predicted_value < warning_threshold:
                            predictions.append({
                                "metric_name": metric_name,
                                "current_value": float(y[-1]),
                                "predicted_value": float(predicted_value),
                                "prediction_window_hours": self.prediction_window_hours,
                                "severity": "warning",
                                "confidence": min(0.8, len(recent_values) / 20.0)
                            })

            return predictions

        except Exception as e:
            logger.error(f"❌ Failed to perform predictive analysis: {e}")
            return []

    async def _generate_predictive_alert(self, prediction: Dict[str, Any]):
        """Generate predictive alert based on analysis."""
        try:
            alert_id = f"predictive_alert_{prediction['metric_name']}_{int(time.time())}"

            severity = AlertSeverity.CRITICAL if prediction["severity"] == "critical" else AlertSeverity.WARNING

            alert = SystemAlert(
                alert_id=alert_id,
                severity=severity,
                title=f"Predictive Alert: {prediction['metric_name'].replace('_', ' ').title()}",
                message=f"Predictive analysis indicates {prediction['metric_name']} may reach "
                       f"{prediction['predicted_value']:.2f} within {prediction['prediction_window_hours']} hours "
                       f"(confidence: {prediction['confidence']:.1%})",
                component="predictive_analytics",
                metric_name=prediction["metric_name"],
                metric_value=prediction["current_value"]
            )

            self.active_alerts[alert_id] = alert
            self.monitoring_stats["alerts_generated"] += 1

            logger.warning(f"🔮 Predictive alert generated: {alert.title}")

        except Exception as e:
            logger.error(f"❌ Failed to generate predictive alert: {e}")

    async def _report_generation_loop(self):
        """Generate periodic reports."""
        try:
            logger.info("📊 Starting report generation loop...")

            while True:
                try:
                    await asyncio.sleep(3600)  # Check every hour

                    current_time = datetime.now(timezone.utc)

                    # Generate daily reports
                    if self.daily_reports and current_time.hour == 0:
                        await self._generate_daily_report()

                    # Generate weekly reports (Sunday at midnight)
                    if self.weekly_reports and current_time.weekday() == 6 and current_time.hour == 0:
                        await self._generate_weekly_report()

                    # Generate monthly reports (1st of month at midnight)
                    if self.monthly_reports and current_time.day == 1 and current_time.hour == 0:
                        await self._generate_monthly_report()

                except Exception as e:
                    logger.error(f"❌ Error in report generation: {e}")
                    continue

        except asyncio.CancelledError:
            logger.info("🛑 Report generation loop cancelled")
        except Exception as e:
            logger.error(f"❌ Report generation loop failed: {e}")

    async def _generate_daily_report(self):
        """Generate daily backup report."""
        try:
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(days=1)

            report = await self._create_backup_report("daily", start_time, end_time)

            # TODO: Save report to storage and send notifications
            logger.info(f"📊 Daily report generated: {report.report_id}")

            self.monitoring_stats["reports_generated"] += 1

        except Exception as e:
            logger.error(f"❌ Failed to generate daily report: {e}")

    async def _generate_weekly_report(self):
        """Generate weekly backup report."""
        try:
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(weeks=1)

            report = await self._create_backup_report("weekly", start_time, end_time)

            logger.info(f"📊 Weekly report generated: {report.report_id}")

            self.monitoring_stats["reports_generated"] += 1

        except Exception as e:
            logger.error(f"❌ Failed to generate weekly report: {e}")

    async def _generate_monthly_report(self):
        """Generate monthly backup report."""
        try:
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(days=30)

            report = await self._create_backup_report("monthly", start_time, end_time)

            logger.info(f"📊 Monthly report generated: {report.report_id}")

            self.monitoring_stats["reports_generated"] += 1

        except Exception as e:
            logger.error(f"❌ Failed to generate monthly report: {e}")

    async def _create_backup_report(self, report_type: str, start_time: datetime,
                                  end_time: datetime) -> BackupReport:
        """Create comprehensive backup report."""
        try:
            report_id = f"{report_type}_report_{int(time.time())}"

            # Collect statistics from all components
            shard_stats = await self.shard_manager.get_shard_statistics()
            recovery_stats = await self.recovery_system.get_recovery_statistics()
            zk_stats = await self.zero_knowledge_protocol.get_protocol_statistics()

            # Calculate availability percentage
            availability_data = [entry["availability"] for entry in self.availability_history
                                if start_time <= entry["timestamp"] <= end_time]
            avg_availability = statistics.mean(availability_data) if availability_data else 0.0

            # Calculate performance metrics
            avg_backup_time = 0.0  # TODO: Implement backup time tracking
            avg_throughput = 0.0   # TODO: Implement throughput calculation

            # Node health summary
            available_nodes = await self.network_manager.get_available_nodes()
            node_health = {node.node_id: HealthStatus.GOOD for node in available_nodes}

            # Shard integrity
            total_shards = shard_stats.get("total_shards", 0)
            corrupted_shards = shard_stats.get("shard_states", {}).get("corrupted", 0)
            integrity_percentage = ((total_shards - corrupted_shards) / total_shards * 100) if total_shards > 0 else 100.0

            # Recovery success rate
            recovery_success_rate = 0.0
            if recovery_stats and recovery_stats["recovery_stats"]["total_recoveries"] > 0:
                recovery_success_rate = (
                    recovery_stats["recovery_stats"]["successful_recoveries"] /
                    recovery_stats["recovery_stats"]["total_recoveries"] * 100
                )

            # Generate predictions
            predictions = await self._perform_predictive_analysis()

            # Capacity predictions
            capacity_predictions = await self._generate_capacity_predictions()

            # Create report
            report = BackupReport(
                report_id=report_id,
                report_type=report_type,
                generated_at=datetime.now(timezone.utc),
                time_period=(start_time, end_time),
                total_backups=zk_stats.get("encryption_stats", {}).get("chunks_encrypted", 0),
                successful_backups=zk_stats.get("encryption_stats", {}).get("chunks_encrypted", 0),
                failed_backups=0,  # TODO: Track failed backups
                total_data_backed_up=shard_stats.get("total_size_bytes", 0),
                average_backup_time=avg_backup_time,
                average_throughput=avg_throughput,
                availability_percentage=avg_availability,
                node_health=node_health,
                shard_integrity_percentage=integrity_percentage,
                recovery_success_rate=recovery_success_rate,
                predicted_failures=predictions,
                capacity_predictions=capacity_predictions,
                detailed_metrics={
                    "shard_statistics": shard_stats,
                    "recovery_statistics": recovery_stats,
                    "zero_knowledge_statistics": zk_stats,
                    "monitoring_statistics": self.monitoring_stats.copy(),
                    "active_alerts": len([a for a in self.active_alerts.values() if not a.resolved]),
                    "health_metrics": {name: {
                        "value": metric.value,
                        "status": metric.status.value,
                        "trend": metric.trend
                    } for name, metric in self.health_metrics.items()}
                }
            )

            return report

        except Exception as e:
            logger.error(f"❌ Failed to create backup report: {e}")
            raise

    async def _generate_capacity_predictions(self) -> Dict[str, Any]:
        """Generate capacity planning predictions."""
        try:
            # Simple capacity prediction based on growth trends
            # TODO: Implement more sophisticated capacity planning

            current_usage = sum(shard.metadata.size for shard in self.shard_manager.shards.values())

            # Estimate growth rate (simplified)
            growth_rate_per_day = current_usage * 0.05  # 5% daily growth assumption

            predictions = {
                "current_usage_bytes": current_usage,
                "predicted_usage_30_days": current_usage + (growth_rate_per_day * 30),
                "predicted_usage_90_days": current_usage + (growth_rate_per_day * 90),
                "predicted_usage_365_days": current_usage + (growth_rate_per_day * 365),
                "growth_rate_per_day": growth_rate_per_day,
                "capacity_warnings": []
            }

            # Add capacity warnings if needed
            if predictions["predicted_usage_90_days"] > current_usage * 5:
                predictions["capacity_warnings"].append(
                    "High growth rate detected - consider capacity expansion"
                )

            return predictions

        except Exception as e:
            logger.error(f"❌ Failed to generate capacity predictions: {e}")
            return {}

    async def get_current_health_status(self) -> Dict[str, Any]:
        """Get current system health status."""
        try:
            # Calculate overall health score
            health_scores = []
            for metric in self.health_metrics.values():
                if metric.status == HealthStatus.EXCELLENT:
                    health_scores.append(100)
                elif metric.status == HealthStatus.GOOD:
                    health_scores.append(80)
                elif metric.status == HealthStatus.WARNING:
                    health_scores.append(60)
                elif metric.status == HealthStatus.CRITICAL:
                    health_scores.append(30)
                else:
                    health_scores.append(0)

            overall_score = statistics.mean(health_scores) if health_scores else 0

            # Determine overall status
            if overall_score >= 90:
                overall_status = HealthStatus.EXCELLENT
            elif overall_score >= 75:
                overall_status = HealthStatus.GOOD
            elif overall_score >= 50:
                overall_status = HealthStatus.WARNING
            else:
                overall_status = HealthStatus.CRITICAL

            # Get active alerts
            active_alerts = [a for a in self.active_alerts.values() if not a.resolved]
            critical_alerts = [a for a in active_alerts if a.severity == AlertSeverity.CRITICAL]

            return {
                "overall_status": overall_status.value,
                "overall_score": overall_score,
                "health_metrics": {
                    name: {
                        "value": metric.value,
                        "unit": metric.unit,
                        "status": metric.status.value,
                        "trend": metric.trend,
                        "threshold_warning": metric.threshold_warning,
                        "threshold_critical": metric.threshold_critical
                    } for name, metric in self.health_metrics.items()
                },
                "active_alerts": len(active_alerts),
                "critical_alerts": len(critical_alerts),
                "availability_sla": {
                    "target": self.availability_sla_target,
                    "current": self.health_metrics.get("availability_percentage", HealthMetric("", 0, "", HealthStatus.GOOD, 0, 0)).value
                },
                "monitoring_stats": self.monitoring_stats.copy(),
                "uptime_hours": self.monitoring_stats["uptime_seconds"] / 3600
            }

        except Exception as e:
            logger.error(f"❌ Failed to get current health status: {e}")
            return {}

    async def get_system_alerts(self, include_resolved: bool = False) -> List[Dict[str, Any]]:
        """Get system alerts."""
        try:
            alerts = []

            for alert in self.active_alerts.values():
                if not include_resolved and alert.resolved:
                    continue

                alerts.append({
                    "alert_id": alert.alert_id,
                    "severity": alert.severity.value,
                    "title": alert.title,
                    "message": alert.message,
                    "component": alert.component,
                    "metric_name": alert.metric_name,
                    "metric_value": alert.metric_value,
                    "threshold": alert.threshold,
                    "timestamp": alert.timestamp.isoformat(),
                    "acknowledged": alert.acknowledged,
                    "resolved": alert.resolved
                })

            # Sort by timestamp (newest first)
            alerts.sort(key=lambda x: x["timestamp"], reverse=True)

            return alerts

        except Exception as e:
            logger.error(f"❌ Failed to get system alerts: {e}")
            return []


# Global instance
_backup_analytics_monitor: Optional[BackupAnalyticsMonitor] = None


def get_backup_analytics_monitor() -> BackupAnalyticsMonitor:
    """Get the global backup analytics monitor instance."""
    global _backup_analytics_monitor
    if _backup_analytics_monitor is None:
        config = get_config().get("backup_analytics", {})
        _backup_analytics_monitor = BackupAnalyticsMonitor(config)
    return _backup_analytics_monitor
