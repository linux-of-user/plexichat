import asyncio
import logging
import statistics
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, List

from .exceptions import ErrorCategory, ErrorSeverity

from datetime import datetime
from datetime import datetime
from datetime import datetime
from datetime import datetime
from datetime import datetime
from datetime import datetime
from datetime import datetime
from datetime import datetime
from datetime import datetime

from datetime import datetime
from datetime import datetime
from datetime import datetime
from datetime import datetime
from datetime import datetime
from datetime import datetime
from datetime import datetime
from datetime import datetime
from datetime import datetime

"""
PlexiChat Error Analytics

Advanced error analytics system for pattern detection, trend analysis,
and predictive error prevention.
"""

logger = logging.getLogger(__name__, Optional)


@dataclass
class ErrorTrend:
    """Represents an error trend over time."""
    trend_type: str  # increasing, decreasing, stable, spike
    confidence: float  # 0.0 to 1.0
    rate_of_change: float
    prediction: Dict[str, Any]
    time_window: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ErrorPattern:
    """Represents a detected error pattern."""
    pattern_id: str
    pattern_type: str
    frequency: int
    components_involved: List[str]
    time_pattern: str  # hourly, daily, weekly
    correlation_score: float
    suggested_actions: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ErrorAnalytics:
    """Advanced error analytics and pattern detection."""

    def __init__(self):
        self.error_data: List[Dict[str, Any]] = []
        self.detected_patterns: List[ErrorPattern] = []
        self.trends: Dict[str, ErrorTrend] = {}
        self.correlations: Dict[str, float] = {}

        # Analytics configuration
        self.analytics_enabled = True
        self.pattern_detection_window_hours = 24
        self.trend_analysis_window_days = 7
        self.correlation_threshold = 0.7
        self.min_pattern_frequency = 3

        # Background tasks
        self.background_tasks: List[asyncio.Task] = []
        self.initialized = False

    async def initialize(self, config: Dict[str, Any] = None):
        """Initialize the error analytics system."""
        if config:
            self.analytics_enabled = config.get('analytics_enabled', True)
            self.pattern_detection_window_hours = config.get('pattern_detection_window_hours', 24)
            self.trend_analysis_window_days = config.get('trend_analysis_window_days', 7)
            self.correlation_threshold = config.get('correlation_threshold', 0.7)
            self.min_pattern_frequency = config.get('min_pattern_frequency', 3)

        if self.analytics_enabled:
            # Start background analytics tasks
            self.background_tasks = [
                asyncio.create_task(self._pattern_detection_loop()),
                asyncio.create_task(self._trend_analysis_loop()),
                asyncio.create_task(self._correlation_analysis_loop())
            ]

        self.initialized = True
        logger.info("Error Analytics initialized")

    async def record_error(self, error_info: Dict[str, Any]):
        """Record an error for analytics."""
        analytics_data = {
            'timestamp': error_info.get('timestamp', from datetime import datetime
datetime = datetime.now()),
            'severity': error_info.get('severity', ErrorSeverity.MEDIUM),
            'category': error_info.get('category', ErrorCategory.UNKNOWN),
            'component': error_info.get('component', 'unknown'),
            'exception_type': error_info.get('exception_type', 'Unknown'),
            'message': error_info.get('message', ''),
            'context': error_info.get('context', {}),
            'user_id': error_info.get('user_id'),
            'session_id': error_info.get('session_id'),
            'request_id': error_info.get('request_id')
        }

        self.error_data.append(analytics_data)

        # Keep only recent data to prevent memory issues
        from datetime import datetime
cutoff_time = datetime.now()
datetime = datetime.now() - timedelta(days=30)
        self.error_data = [
            error for error in self.error_data
            if error['timestamp'] >= cutoff_time
        ]

    async def _pattern_detection_loop(self):
        """Background task for pattern detection."""
        while self.analytics_enabled:
            try:
                await self._detect_patterns()
                await asyncio.sleep(3600)  # Run every hour
            except Exception as e:
                logger.error(f"Pattern detection error: {e}")
                await asyncio.sleep(3600)

    async def _trend_analysis_loop(self):
        """Background task for trend analysis."""
        while self.analytics_enabled:
            try:
                await self._analyze_trends()
                await asyncio.sleep(7200)  # Run every 2 hours
            except Exception as e:
                logger.error(f"Trend analysis error: {e}")
                await asyncio.sleep(7200)

    async def _correlation_analysis_loop(self):
        """Background task for correlation analysis."""
        while self.analytics_enabled:
            try:
                await self._analyze_correlations()
                await asyncio.sleep(14400)  # Run every 4 hours
            except Exception as e:
                logger.error(f"Correlation analysis error: {e}")
                await asyncio.sleep(14400)

    async def _detect_patterns(self):
        """Detect error patterns in recent data."""
        from datetime import datetime
cutoff_time = datetime.now()
datetime = datetime.now() - timedelta(hours=self.pattern_detection_window_hours)
        recent_errors = [
            error for error in self.error_data
            if error['timestamp'] >= cutoff_time
        ]

        if len(recent_errors) < self.min_pattern_frequency:
            return

        # Pattern 1: Recurring error types
        error_type_patterns = self._detect_error_type_patterns(recent_errors)

        # Pattern 2: Component failure patterns
        component_patterns = self._detect_component_patterns(recent_errors)

        # Pattern 3: Time-based patterns
        time_patterns = self._detect_time_patterns(recent_errors)

        # Pattern 4: User/session patterns
        user_patterns = self._detect_user_patterns(recent_errors)

        # Combine all patterns
        all_patterns = error_type_patterns + component_patterns + time_patterns + user_patterns

        # Update detected patterns
        self.detected_patterns = all_patterns

        logger.info(f"Detected {len(all_patterns)} error patterns")

    def _detect_error_type_patterns(self, errors: List[Dict[str, Any]]) -> List[ErrorPattern]:
        """Detect patterns in error types."""
        patterns = []
        error_type_counts = Counter(error['exception_type'] for error in errors)

        for error_type, count in error_type_counts.items():
            if count >= self.min_pattern_frequency:
                # Find components involved
                components = list(set(
                    error['component'] for error in errors
                    if error['exception_type'] == error_type
                ))

                pattern = ErrorPattern(
                    pattern_id=f"error_type_{error_type}_{from datetime import datetime
datetime = datetime.now().strftime('%Y%m%d')}",
                    pattern_type="recurring_error_type",
                    frequency=count,
                    components_involved=components,
                    time_pattern="recent",
                    correlation_score=min(count / len(errors), 1.0),
                    suggested_actions=[
                        f"Investigate root cause of {error_type} errors",
                        f"Review {', '.join(components)} components",
                        "Consider implementing circuit breaker",
                        "Add specific error handling for this error type"
                    ]
                )
                patterns.append(pattern)

        return patterns

    def _detect_component_patterns(self, errors: List[Dict[str, Any]]) -> List[ErrorPattern]:
        """Detect patterns in component failures."""
        patterns = []
        component_counts = Counter(error['component'] for error in errors)

        for component, count in component_counts.items():
            if count >= self.min_pattern_frequency:
                # Find error types for this component
                list(set(
                    error['exception_type'] for error in errors
                    if error['component'] == component
                ))

                pattern = ErrorPattern(
                    pattern_id=f"component_{component}_{from datetime import datetime
datetime = datetime.now().strftime('%Y%m%d')}",
                    pattern_type="component_failure",
                    frequency=count,
                    components_involved=[component],
                    time_pattern="recent",
                    correlation_score=min(count / len(errors), 1.0),
                    suggested_actions=[
                        f"Review {component} component health",
                        f"Check {component} dependencies",
                        "Consider component restart or scaling",
                        f"Review recent changes to {component}"
                    ]
                )
                patterns.append(pattern)

        return patterns

    def _detect_time_patterns(self, errors: List[Dict[str, Any]]) -> List[ErrorPattern]:
        """Detect time-based error patterns."""
        patterns = []

        # Group errors by hour
        hourly_counts = defaultdict(int)
        for error in errors:
            hour = error['timestamp'].hour
            hourly_counts[hour] += 1

        # Find peak error hours
        if hourly_counts:
            avg_hourly = statistics.mean(hourly_counts.values())
            std_hourly = statistics.stdev(hourly_counts.values()) if len(hourly_counts) > 1 else 0

            for hour, count in hourly_counts.items():
                if count > avg_hourly + (2 * std_hourly) and count >= self.min_pattern_frequency:
                    pattern = ErrorPattern(
                        pattern_id=f"time_pattern_hour_{hour}_{from datetime import datetime
datetime = datetime.now().strftime('%Y%m%d')}",
                        pattern_type="time_based",
                        frequency=count,
                        components_involved=[],
                        time_pattern=f"hourly_peak_at_{hour}",
                        correlation_score=min((count - avg_hourly) / max(avg_hourly, 1), 1.0),
                        suggested_actions=[
                            f"Investigate system load at hour {hour}",
                            "Consider load balancing adjustments",
                            "Review scheduled tasks or batch jobs",
                            "Monitor resource usage patterns"
                        ]
                    )
                    patterns.append(pattern)

        return patterns

    def _detect_user_patterns(self, errors: List[Dict[str, Any]]) -> List[ErrorPattern]:
        """Detect user or session-based patterns."""
        patterns = []

        # Group by user_id
        user_errors = defaultdict(int)
        for error in errors:
            if error.get('user_id'):
                user_errors[error['user_id']] += 1

        # Find users with high error rates
        if user_errors:
            avg_user_errors = statistics.mean(user_errors.values())

            for user_id, count in user_errors.items():
                if count > avg_user_errors * 3 and count >= self.min_pattern_frequency:
                    pattern = ErrorPattern(
                        pattern_id=f"user_pattern_{user_id}_{from datetime import datetime
datetime = datetime.now().strftime('%Y%m%d')}",
                        pattern_type="user_specific",
                        frequency=count,
                        components_involved=[],
                        time_pattern="recent",
                        correlation_score=min(count / len(errors), 1.0),
                        suggested_actions=[
                            f"Review user {user_id} activity",
                            "Check for malicious activity",
                            "Validate user permissions",
                            "Consider rate limiting for this user"
                        ]
                    )
                    patterns.append(pattern)

        return patterns

    async def _analyze_trends(self):
        """Analyze error trends over time."""
        from datetime import datetime
cutoff_time = datetime.now()
datetime = datetime.now() - timedelta(days=self.trend_analysis_window_days)
        trend_data = [
            error for error in self.error_data
            if error['timestamp'] >= cutoff_time
        ]

        if len(trend_data) < 10:  # Need minimum data for trend analysis
            return

        # Analyze overall error trend
        daily_counts = self._get_daily_error_counts(trend_data)
        overall_trend = self._calculate_trend(daily_counts)
        self.trends['overall'] = overall_trend

        # Analyze trends by severity
        for severity in ErrorSeverity:
            severity_data = [e for e in trend_data if e['severity'] == severity]
            if len(severity_data) >= 5:
                daily_counts = self._get_daily_error_counts(severity_data)
                trend = self._calculate_trend(daily_counts)
                self.trends[f'severity_{severity.value}'] = trend

        # Analyze trends by component
        components = set(error['component'] for error in trend_data)
        for component in components:
            component_data = [e for e in trend_data if e['component'] == component]
            if len(component_data) >= 5:
                daily_counts = self._get_daily_error_counts(component_data)
                trend = self._calculate_trend(daily_counts)
                self.trends[f'component_{component}'] = trend

    def _get_daily_error_counts(self, errors: List[Dict[str, Any]]) -> List[int]:
        """Get daily error counts from error data."""
        daily_counts = defaultdict(int)
        for error in errors:
            date = error['timestamp'].date()
            daily_counts[date] += 1

        # Fill in missing days with 0
        if daily_counts:
            start_date = min(daily_counts.keys())
            end_date = max(daily_counts.keys())
            current_date = start_date

            counts = []
            while current_date <= end_date:
                counts.append(daily_counts.get(current_date, 0))
                current_date += timedelta(days=1)

            return counts

        return []

    def _calculate_trend(self, daily_counts: List[int]) -> ErrorTrend:
        """Calculate trend from daily counts."""
        if len(daily_counts) < 2:
            return ErrorTrend("stable", 0.0, 0.0, {}, f"{len(daily_counts)} days")

        # Simple linear trend calculation
        n = len(daily_counts)
        x_values = list(range(n))

        # Calculate slope (rate of change)
        x_mean = statistics.mean(x_values)
        y_mean = statistics.mean(daily_counts)

        numerator = sum((x - x_mean) * (y - y_mean) for x, y in zip(x_values, daily_counts))
        denominator = sum((x - x_mean) ** 2 for x in x_values)

        if denominator == 0:
            slope = 0
        else:
            slope = numerator / denominator

        # Determine trend type
        if abs(slope) < 0.1:
            trend_type = "stable"
        elif slope > 0.5:
            trend_type = "increasing"
        elif slope < -0.5:
            trend_type = "decreasing"
        elif slope > 2:
            trend_type = "spike"
        else:
            trend_type = "stable"

        # Calculate confidence (simplified)
        variance = statistics.variance(daily_counts) if len(daily_counts) > 1 else 0
        confidence = min(abs(slope) / max(variance, 1), 1.0)

        # Make prediction for next period
        next_value = daily_counts[-1] + slope
        prediction = {
            'next_day_estimate': max(0, int(next_value)),
            'trend_direction': 'up' if slope > 0 else 'down' if slope < 0 else 'stable'
        }

        return ErrorTrend(
            trend_type=trend_type,
            confidence=confidence,
            rate_of_change=slope,
            prediction=prediction,
            time_window=f"{len(daily_counts)} days"
        )

    async def _analyze_correlations(self):
        """Analyze correlations between different error factors."""
        # This is a simplified correlation analysis
        # In a real implementation, you might use more sophisticated statistical methods

        if len(self.error_data) < 20:
            return

        # Analyze correlation between components and error types
        component_error_matrix = defaultdict(lambda: defaultdict(int))
        for error in self.error_data:
            component_error_matrix[error['component']][error['exception_type']] += 1

        # Calculate simple correlation scores
        for component, error_types in component_error_matrix.items():
            total_errors = sum(error_types.values())
            for error_type, count in error_types.items():
                correlation = count / total_errors
                if correlation >= self.correlation_threshold:
                    self.correlations[f"{component}_{error_type}"] = correlation

    def get_analytics_report(self) -> Dict[str, Any]:
        """Get comprehensive analytics report."""
        return {
            'patterns': [pattern.to_dict() for pattern in self.detected_patterns],
            'trends': {name: trend.to_dict() for name, trend in self.trends.items()},
            'correlations': self.correlations,
            'summary': {
                'total_errors_analyzed': len(self.error_data),
                'patterns_detected': len(self.detected_patterns),
                'trends_analyzed': len(self.trends),
                'correlations_found': len(self.correlations),
                'analysis_window_hours': self.pattern_detection_window_hours,
                'last_analysis': from datetime import datetime
datetime = datetime.now().isoformat()
            }
        }

    async def shutdown(self):
        """Shutdown the error analytics system."""
        self.analytics_enabled = False
        for task in self.background_tasks:
            task.cancel()
        await asyncio.gather(*self.background_tasks, return_exceptions=True)


# Global error analytics instance
error_analytics = ErrorAnalytics()
