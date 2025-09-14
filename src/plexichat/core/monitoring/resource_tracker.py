"""
Resource Tracking Service

Tracks and analyzes resource usage patterns for memory, CPU, disk, and network.
Provides historical analysis and resource optimization recommendations.
"""

import asyncio
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import logging
import statistics
from typing import Any

from plexichat.core.database.manager import database_manager

from .base_monitor import MonitorBase

logger = logging.getLogger(__name__)


@dataclass
class ResourceUsage:
    """Resource usage data point."""

    resource_type: str
    resource_name: str
    current_value: float
    max_value: float
    min_value: float
    avg_value: float
    timestamp: datetime
    period_seconds: int
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ResourcePattern:
    """Resource usage pattern analysis."""

    resource_type: str
    resource_name: str
    pattern_type: str  # steady, increasing, decreasing, cyclical, bursty
    confidence: float
    trend_slope: float
    peak_times: list[str]
    recommendations: list[str]
    analysis_period: int  # seconds


class ResourceTracker(MonitorBase):
    """Resource tracking and analysis service."""

    def __init__(self, tracking_window_hours: int = 24) -> None:
        self.tracking_window = timedelta(hours=tracking_window_hours)
        self.resource_history: dict[str, deque[tuple[datetime, float]]] = defaultdict(
            lambda: deque(maxlen=1000)
        )
        self.patterns_cache: dict[str, ResourcePattern] = {}
        self.analysis_interval = 300  # 5 minutes
        self.running = False
        self.task: asyncio.Task[None] | None = None

        logger.info("Resource tracker initialized")

    async def start(self) -> None:
        """Start the resource tracking service."""
        if self.running:
            return

        await super().start()
        logger.info("Resource tracker started")

    async def stop(self) -> None:
        """Stop the resource tracking service."""
        if not self.running:
            return

        await super().stop()

        logger.info("Resource tracker stopped")

    def track_resource_usage(
        self,
        resource_type: str,
        resource_name: str,
        current_value: float,
        period_seconds: int = 60,
    ) -> None:
        """Track resource usage data point."""
        now = datetime.now()

        # Calculate rolling statistics
        history_key = f"{resource_type}:{resource_name}"
        history = self.resource_history[history_key]

        # Add current value to history
        history.append((now, current_value))

        # Calculate statistics from recent history (last hour)
        recent_values = []
        cutoff = now - timedelta(hours=1)

        for timestamp, value in history:
            if timestamp >= cutoff:
                recent_values.append(value)

        if recent_values:
            max_value = max(recent_values)
            min_value = min(recent_values)
            avg_value = statistics.mean(recent_values)
        else:
            max_value = min_value = avg_value = current_value

        # Create usage record
        usage = ResourceUsage(
            resource_type=resource_type,
            resource_name=resource_name,
            current_value=current_value,
            max_value=max_value,
            min_value=min_value,
            avg_value=avg_value,
            timestamp=now,
            period_seconds=period_seconds,
        )

        # Save to database asynchronously
        asyncio.create_task(self._save_resource_usage(usage))

        # Record metrics
        self.record_metric(
            f"resource_{resource_type}_{resource_name}_current", current_value, "value"
        )
        self.record_metric(
            f"resource_{resource_type}_{resource_name}_max", max_value, "value"
        )
        self.record_metric(
            f"resource_{resource_type}_{resource_name}_min", min_value, "value"
        )
        self.record_metric(
            f"resource_{resource_type}_{resource_name}_avg", avg_value, "value"
        )

    async def _save_resource_usage(self, usage: ResourceUsage) -> None:
        """Save resource usage to database."""
        try:
            data = {
                "resource_type": usage.resource_type,
                "resource_name": usage.resource_name,
                "current_value": usage.current_value,
                "max_value": usage.max_value,
                "min_value": usage.min_value,
                "avg_value": usage.avg_value,
                "timestamp": usage.timestamp.isoformat(),
                "period_seconds": usage.period_seconds,
                "created_at": datetime.now().isoformat(),
                "updated_at": datetime.now().isoformat(),
                "metadata": str(usage.metadata),
            }

            async with database_manager.get_session() as session:
                await session.insert("resource_tracking", data)
                await session.commit()

        except Exception as e:
            logger.error(f"Failed to save resource usage: {e}")

    async def _collect_metrics(self) -> None:
        """Override to perform resource pattern analysis."""
        try:
            await self._analyze_patterns()
        except Exception as e:
            logger.error(f"Error in resource analysis: {e}")

    async def _analyze_patterns(self) -> None:
        """Analyze resource usage patterns."""
        for history_key, history in self.resource_history.items():
            if len(history) < 10:  # Need minimum data points
                continue

            try:
                resource_type, resource_name = history_key.split(":", 1)
                pattern = self._analyze_resource_pattern(history_key, history)
                self.patterns_cache[history_key] = pattern

                # Log significant pattern changes
                if pattern.confidence > 0.8:
                    logger.info(
                        f"Resource pattern detected: {resource_type}:{resource_name} - {pattern.pattern_type} (confidence: {pattern.confidence:.2f})"
                    )

            except Exception as e:
                logger.error(f"Error analyzing pattern for {history_key}: {e}")

    def _analyze_resource_pattern(
        self, history_key: str, history: deque[tuple[datetime, float]]
    ) -> ResourcePattern:
        """Analyze usage pattern for a specific resource."""
        # Extract values and timestamps
        timestamps = [t for t, v in history]
        values = [v for t, v in history]

        # Calculate trend (linear regression)
        n = len(values)
        if n < 2:
            return ResourcePattern(
                resource_type=history_key.split(":")[0],
                resource_name=history_key.split(":")[1],
                pattern_type="insufficient_data",
                confidence=0.0,
                trend_slope=0.0,
                peak_times=[],
                recommendations=["Need more data points for analysis"],
                analysis_period=self.analysis_interval,
            )

        x_values = [(t - timestamps[0]).total_seconds() for t in timestamps]
        x_mean = statistics.mean(x_values)
        y_mean = statistics.mean(values)

        numerator = sum(
            (x - x_mean) * (y - y_mean) for x, y in zip(x_values, values, strict=False)
        )
        denominator = sum((x - x_mean) ** 2 for x in x_values)

        trend_slope = numerator / denominator if denominator != 0 else 0

        # Calculate variability (coefficient of variation)
        if y_mean != 0:
            cv = statistics.stdev(values) / abs(y_mean)
        else:
            cv = 0

        # Determine pattern type
        pattern_type = "steady"
        confidence = 0.5

        if abs(trend_slope) > 0.1:  # Significant trend
            if trend_slope > 0:
                pattern_type = "increasing"
                confidence = min(abs(trend_slope) * 10, 0.9)
            else:
                pattern_type = "decreasing"
                confidence = min(abs(trend_slope) * 10, 0.9)
        elif cv > 0.5:  # High variability
            pattern_type = "bursty"
            confidence = min(cv, 0.8)
        elif self._detect_cyclical_pattern(values):
            pattern_type = "cyclical"
            confidence = 0.7

        # Generate recommendations
        recommendations = self._generate_recommendations(
            history_key.split(":")[0],
            history_key.split(":")[1],
            pattern_type,
            trend_slope,
            cv,
        )

        # Find peak usage times (simplified)
        peak_times = self._find_peak_times(timestamps, values)

        return ResourcePattern(
            resource_type=history_key.split(":")[0],
            resource_name=history_key.split(":")[1],
            pattern_type=pattern_type,
            confidence=confidence,
            trend_slope=trend_slope,
            peak_times=peak_times,
            recommendations=recommendations,
            analysis_period=self.analysis_interval,
        )

    def _detect_cyclical_pattern(self, values: list[float]) -> bool:
        """Simple cyclical pattern detection using autocorrelation."""
        if len(values) < 10:
            return False

        # Check for periodicity (simplified)
        # This is a basic implementation - could be enhanced with FFT
        try:
            # Calculate autocorrelation at different lags
            mean_val = statistics.mean(values)
            autocorr = []

            for lag in range(1, min(10, len(values) // 2)):
                corr = 0
                count = 0
                for i in range(len(values) - lag):
                    corr += (values[i] - mean_val) * (values[i + lag] - mean_val)
                    count += 1
                if count > 0:
                    corr /= count
                    autocorr.append(abs(corr))

            # If any autocorrelation is significant, consider it cyclical
            max_autocorr = max(autocorr) if autocorr else 0
            return max_autocorr > 0.3  # Threshold for cyclical detection

        except Exception:
            return False

    def _find_peak_times(
        self, timestamps: list[datetime], values: list[float]
    ) -> list[str]:
        """Find times when resource usage peaks."""
        if len(values) < 5:
            return []

        try:
            # Simple peak detection
            peaks = []
            threshold = statistics.mean(values) + statistics.stdev(values)

            for i, (timestamp, value) in enumerate(
                zip(timestamps, values, strict=False)
            ):
                if value > threshold:
                    peaks.append(timestamp.strftime("%H:%M"))

            return list(set(peaks))[:5]  # Return up to 5 unique peak times

        except Exception:
            return []

    def _generate_recommendations(
        self,
        resource_type: str,
        resource_name: str,
        pattern_type: str,
        trend_slope: float,
        cv: float,
    ) -> list[str]:
        """Generate optimization recommendations based on pattern analysis."""
        recommendations = []

        if pattern_type == "increasing":
            if resource_type == "memory":
                recommendations.append(
                    "Consider increasing memory allocation or optimizing memory usage"
                )
            elif resource_type == "cpu":
                recommendations.append("Monitor for potential performance bottlenecks")
            elif resource_type == "disk":
                recommendations.append("Plan for additional storage capacity")

        elif pattern_type == "bursty":
            recommendations.append("Implement resource pooling or load balancing")
            recommendations.append("Consider autoscaling for bursty workloads")

        elif pattern_type == "cyclical":
            recommendations.append("Schedule maintenance during low-usage periods")
            recommendations.append(
                "Implement predictive scaling based on usage patterns"
            )

        if cv > 0.7:
            recommendations.append(
                "High variability detected - consider resource optimization"
            )

        if trend_slope > 0.5:
            recommendations.append(
                "Strong upward trend - monitor closely for capacity planning"
            )

        return recommendations[:3]  # Limit to 3 recommendations

    def get_resource_patterns(
        self, resource_type: str | None = None, resource_name: str | None = None
    ) -> list[ResourcePattern]:
        """Get analyzed resource patterns."""
        patterns = list(self.patterns_cache.values())

        if resource_type:
            patterns = [p for p in patterns if p.resource_type == resource_type]

        if resource_name:
            patterns = [p for p in patterns if p.resource_name == resource_name]

        return patterns

    def get_resource_usage_history(
        self, resource_type: str, resource_name: str, hours: int = 24
    ) -> list[tuple[datetime, float]]:
        """Get historical usage data for a resource."""
        history_key = f"{resource_type}:{resource_name}"
        history = self.resource_history.get(history_key, deque())

        cutoff = datetime.now() - timedelta(hours=hours)
        return [(t, v) for t, v in history if t >= cutoff]

    def get_resource_stats(
        self, resource_type: str, resource_name: str, hours: int = 24
    ) -> dict[str, Any]:
        """Get comprehensive statistics for a resource."""
        history = self.get_resource_usage_history(resource_type, resource_name, hours)

        if not history:
            return {"error": "No data available"}

        values = [v for _, v in history]

        percentiles_data = {"25": 0.0, "75": 0.0, "95": 0.0}

        if len(values) >= 4:
            quantiles = statistics.quantiles(values, n=4)
            percentiles_data["25"] = quantiles[0]
            percentiles_data["75"] = quantiles[2]

        if len(values) >= 20:
            quantiles = statistics.quantiles(values, n=20)
            percentiles_data["95"] = quantiles[18]
        elif values:
            percentiles_data["95"] = max(values)

        return {
            "resource_type": resource_type,
            "resource_name": resource_name,
            "period_hours": hours,
            "data_points": len(values),
            "current": values[-1] if values else 0,
            "average": statistics.mean(values) if values else 0,
            "maximum": max(values) if values else 0,
            "minimum": min(values) if values else 0,
            "median": statistics.median(values) if values else 0,
            "std_dev": statistics.stdev(values) if len(values) > 1 else 0,
            "percentiles": percentiles_data,
        }


# Global instance
resource_tracker = ResourceTracker()


# Convenience functions
def track_memory_usage(current_mb: float, period_seconds: int = 60) -> None:
    """Track memory usage."""
    resource_tracker.track_resource_usage(
        "memory", "system", current_mb, period_seconds
    )


def track_cpu_usage(current_percent: float, period_seconds: int = 60) -> None:
    """Track CPU usage."""
    resource_tracker.track_resource_usage(
        "cpu", "system", current_percent, period_seconds
    )


def track_disk_usage(current_percent: float, period_seconds: int = 60) -> None:
    """Track disk usage."""
    resource_tracker.track_resource_usage(
        "disk", "system", current_percent, period_seconds
    )


def track_network_usage(current_mbps: float, period_seconds: int = 60) -> None:
    """Track network usage."""
    resource_tracker.track_resource_usage(
        "network", "system", current_mbps, period_seconds
    )


async def start_resource_tracking() -> None:
    """Start the resource tracking service."""
    await resource_tracker.start()


async def stop_resource_tracking() -> None:
    """Stop the resource tracking service."""
    await resource_tracker.stop()


def get_resource_patterns(
    resource_type: str | None = None, resource_name: str | None = None
) -> list[ResourcePattern]:
    """Get resource usage patterns."""
    return resource_tracker.get_resource_patterns(resource_type, resource_name)


def get_resource_stats(
    resource_type: str, resource_name: str, hours: int = 24
) -> dict[str, Any]:
    """Get resource usage statistics."""
    return resource_tracker.get_resource_stats(resource_type, resource_name, hours)


__all__ = [
    "ResourcePattern",
    "ResourceTracker",
    "ResourceUsage",
    "get_resource_patterns",
    "get_resource_stats",
    "resource_tracker",
    "start_resource_tracking",
    "stop_resource_tracking",
    "track_cpu_usage",
    "track_disk_usage",
    "track_memory_usage",
    "track_network_usage",
]
