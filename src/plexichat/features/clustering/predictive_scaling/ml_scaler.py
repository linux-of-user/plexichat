# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from datetime import datetime


"""
import time
PlexiChat Predictive Scaling with Machine Learning

Advanced ML-powered auto-scaling system with:
- Time series forecasting for resource demand
- Anomaly detection for unusual traffic patterns
- Multi-dimensional scaling decisions (CPU, memory, network, storage)
- Cost-aware scaling optimization
- Seasonal pattern recognition
- Real-time model adaptation
- Integration with hybrid cloud and service mesh
"""

logger = logging.getLogger(__name__)


class ScalingDirection(Enum):
    """Scaling direction."""
    SCALE_UP = "scale_up"
    SCALE_DOWN = "scale_down"
    MAINTAIN = "maintain"


class ResourceType(Enum):
    """Resource types for scaling."""
    CPU = "cpu"
    MEMORY = "memory"
    NETWORK = "network"
    STORAGE = "storage"
    INSTANCES = "instances"


class ScalingTrigger(Enum):
    """Scaling trigger types."""
    THRESHOLD = "threshold"
    PREDICTIVE = "predictive"
    ANOMALY = "anomaly"
    COST_OPTIMIZATION = "cost_optimization"
    MANUAL = "manual"


@dataclass
class MetricDataPoint:
    """Single metric data point."""
    timestamp: datetime
    value: float
    resource_type: ResourceType
    service_name: str
    node_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {}}
            "timestamp": self.timestamp.isoformat(),
            "value": self.value,
            "resource_type": self.resource_type.value,
            "service_name": self.service_name,
            "node_id": self.node_id
        }


@dataclass
class ScalingPrediction:
    """Scaling prediction result."""
    service_name: str
    resource_type: ResourceType
    current_value: float
    predicted_value: float
    predicted_at: datetime
    confidence: float
    scaling_direction: ScalingDirection
    recommended_scale_factor: float
    reasoning: str
    cost_impact: float = 0.0

    @property
    def should_scale(self) -> bool:
        """Check if scaling is recommended."""
        return self.scaling_direction != ScalingDirection.MAINTAIN


@dataclass
class ScalingAction:
    """Scaling action to be executed."""
    action_id: str
    service_name: str
    resource_type: ResourceType
    current_capacity: float
    target_capacity: float
    scaling_direction: ScalingDirection
    trigger: ScalingTrigger
    prediction: Optional[ScalingPrediction] = None
    executed_at: Optional[datetime] = None
    success: bool = False
    error: Optional[str] = None


class TimeSeriesForecaster:
    """Time series forecasting for resource demand prediction."""

    def __init__(self):
        self.models: Dict[str, Any] = {}  # service_name -> model
        self.training_data: Dict[str, List[MetricDataPoint]] = {}
        self.model_accuracy: Dict[str, float] = {}

        # Forecasting parameters
        self.lookback_window = 168  # 7 days in hours
        self.forecast_horizon = 24  # 24 hours ahead
        self.min_training_points = 100

    def add_data_point(self, data_point: MetricDataPoint):
        """Add new data point for training."""
        key = f"{data_point.service_name}_{data_point.resource_type.value}"

        if key not in self.training_data:
            self.training_data[key] = []

        self.training_data[key].append(data_point)

        # Keep only recent data
        cutoff_time = datetime.now(timezone.utc) - timedelta(days=30)
        self.training_data[key] = [
            dp for dp in self.training_data[key]
            if dp.timestamp > cutoff_time
        ]

    async def train_model(self, service_name: str, resource_type: ResourceType) -> bool:
        """Train forecasting model for service and resource type."""
        try:
            key = f"{service_name}_{resource_type.value}"

            if key not in self.training_data:
                logger.warning(f"No training data for {key}")
                return False

            data_points = self.training_data[key]

            if len(data_points) < self.min_training_points:
                logger.warning(f"Insufficient training data for {key}: {len(data_points)} < {self.min_training_points}")
                return False

            # Prepare time series data
            timestamps = [dp.timestamp for dp in data_points]
            values = [dp.value for dp in data_points]

            # Simple moving average model (in production, use ARIMA, LSTM, etc.)
            model = self._create_simple_model(timestamps, values)

            self.models[key] = model

            # Calculate model accuracy
            accuracy = await self._evaluate_model_accuracy(key, data_points[-50:])  # Test on last 50 points
            self.model_accuracy[key] = accuracy

            logger.info(f"Model trained for {key} with accuracy: {accuracy:.2f}")
            return True

        except Exception as e:
            logger.error(f"Model training failed for {service_name}: {e}")
            return False

    def _create_simple_model(self, timestamps: List[datetime], values: List[float]) -> Dict[str, Any]:
        """Create simple forecasting model."""
        # Convert timestamps to hours since start
        start_time = min(timestamps)
        [(ts - start_time).total_seconds() / 3600 for ts in timestamps]

        # Calculate moving averages and trends
        window_size = min(24, len(values) // 4)  # 24-hour window or 1/4 of data

        moving_avg = []
        for i in range(len(values)):
            start_idx = max(0, i - window_size + 1)
            avg = sum(values[start_idx:i+1]) / (i - start_idx + 1)
            moving_avg.append(avg)

        # Calculate trend
        if len(values) >= 2:
            trend = (values[-1] - values[0]) / len(values)
        else:
            trend = 0.0

        # Detect seasonal patterns (simplified)
        seasonal_pattern = self._detect_seasonal_pattern(values)

        return {}}
            "type": "simple_forecast",
            "moving_avg": moving_avg[-1] if moving_avg else 0.0,
            "trend": trend,
            "seasonal_pattern": seasonal_pattern,
            "last_values": values[-24:] if len(values) >= 24 else values,
            "trained_at": datetime.now(timezone.utc)
        }

    def _detect_seasonal_pattern(self, values: List[float]) -> Dict[str, float]:
        """Detect seasonal patterns in data."""
        if len(values) < 24:
            return {}}}

        # Daily pattern (24 hours)
        daily_pattern = {}
        for hour in range(24):
            hour_values = [values[i] for i in range(hour, len(values), 24)]
            if hour_values:
                daily_pattern[str(hour)] = sum(hour_values) / len(hour_values)

        return {}}"daily": daily_pattern}

    async def _evaluate_model_accuracy(self, key: str, test_data: List[MetricDataPoint]) -> float:
        """Evaluate model accuracy on test data."""
        if key not in self.models or len(test_data) < 10:
            return 0.0

        model = self.models[key]
        predictions = []
        actuals = []

        for i in range(5, len(test_data)):  # Start from 5th point to have history
            # Predict next value
            predicted = await self._predict_next_value(model, test_data[:i])
            actual = test_data[i].value

            predictions.append(predicted)
            actuals.append(actual)

        # Calculate Mean Absolute Percentage Error (MAPE)
        if not predictions:
            return 0.0

        mape = sum(abs((a - p) / max(a, 0.001)) for a, p in zip(actuals, predictions)) / len(predictions)
        accuracy = max(0.0, 1.0 - mape)

        return accuracy

    async def _predict_next_value(self, model: Dict[str, Any], historical_data: List[MetricDataPoint]) -> float:
        """Predict next value using model."""
        if not historical_data:
            return 0.0

        # Simple prediction based on moving average and trend
        recent_values = [dp.value for dp in historical_data[-24:]]

        if not recent_values:
            return 0.0

        # Base prediction on moving average
        base_prediction = sum(recent_values) / len(recent_values)

        # Apply trend
        trend_adjustment = model.get("trend", 0.0) * len(recent_values)

        # Apply seasonal adjustment
        current_hour = historical_data[-1].timestamp.hour
        seasonal_pattern = model.get("seasonal_pattern", {}).get("daily", {})
        seasonal_adjustment = seasonal_pattern.get(str(current_hour), 1.0)

        prediction = (base_prediction + trend_adjustment) * seasonal_adjustment

        return max(0.0, prediction)

    async def forecast(self, service_name: str, resource_type: ResourceType,)
                     hours_ahead: int = 1) -> Optional[float]:
        """Forecast resource demand."""
        key = f"{service_name}_{resource_type.value}"

        if key not in self.models:
            logger.warning(f"No model available for {key}")
            return None

        if key not in self.training_data:
            return None

        model = self.models[key]
        historical_data = self.training_data[key]

        # Predict multiple steps ahead
        current_data = historical_data.copy()

        for _ in range(hours_ahead):
            next_value = await self._predict_next_value(model, current_data)

            # Add predicted value to data for next prediction
            next_timestamp = current_data[-1].timestamp + timedelta(hours=1)
            predicted_point = MetricDataPoint()
                timestamp=next_timestamp,
                value=next_value,
                resource_type=resource_type,
                service_name=service_name
            )
            current_data.append(predicted_point)

        return current_data[-1].value


class AnomalyDetector:
    """Detects anomalies in resource usage patterns."""

    def __init__(self):
        self.baseline_models: Dict[str, Dict[str, float]] = {}
        self.anomaly_threshold = 2.0  # Standard deviations

    def update_baseline(self, service_name: str, resource_type: ResourceType,):
                       data_points: List[MetricDataPoint]):
        """Update baseline model for anomaly detection."""
        if len(data_points) < 10:
            return

        key = f"{service_name}_{resource_type.value}"
        values = [dp.value for dp in data_points]

        # Calculate statistics
        mean_value = sum(values) / len(values)
        variance = sum((v - mean_value) ** 2 for v in values) / len(values)
        std_dev = variance ** 0.5

        self.baseline_models[key] = {
            "mean": mean_value,
            "std_dev": std_dev,
            "min": min(values),
            "max": max(values),
            "updated_at": datetime.now(timezone.utc).isoformat()
        }

    def detect_anomaly(self, service_name: str, resource_type: ResourceType,):
                      current_value: float) -> Tuple[bool, float]:
        """Detect if current value is anomalous."""
        key = f"{service_name}_{resource_type.value}"

        if key not in self.baseline_models:
            return False, 0.0

        baseline = self.baseline_models[key]
        mean = baseline["mean"]
        std_dev = baseline["std_dev"]

        if std_dev == 0:
            return False, 0.0

        # Calculate z-score
        z_score = abs(current_value - mean) / std_dev

        is_anomaly = z_score > self.anomaly_threshold

        return is_anomaly, z_score


class PredictiveScaler:
    """Main predictive scaling engine."""

    def __init__(self):
        self.forecaster = TimeSeriesForecaster()
        self.anomaly_detector = AnomalyDetector()
        self.scaling_history: List[ScalingAction] = []
        self.active_services: Set[str] = set()

        # Scaling thresholds
        self.scale_up_threshold = 0.8  # 80% utilization
        self.scale_down_threshold = 0.3  # 30% utilization
        self.prediction_confidence_threshold = 0.7

        # Cost optimization
        self.cost_per_unit: Dict[ResourceType, float] = {
            ResourceType.CPU: 0.05,  # $ per CPU hour
            ResourceType.MEMORY: 0.01,  # $ per GB hour
            ResourceType.INSTANCES: 0.10  # $ per instance hour
        }

    async def initialize(self):
        """Initialize predictive scaler."""
        await self._load_historical_data()
        await self._train_initial_models()
        await self._start_background_tasks()
        logger.info("Predictive scaler initialized")

    async def add_metric(self, data_point: MetricDataPoint):
        """Add new metric data point."""
        self.forecaster.add_data_point(data_point)
        self.active_services.add(data_point.service_name)

        # Update anomaly detection baseline
        key = f"{data_point.service_name}_{data_point.resource_type.value}"
        recent_data = self.forecaster.training_data.get(key, [])[-100:]  # Last 100 points
        if len(recent_data) >= 10:
            self.anomaly_detector.update_baseline()
                data_point.service_name,
                data_point.resource_type,
                recent_data
            )

    async def predict_scaling_need(self, service_name: str, resource_type: ResourceType,)
                                 current_value: float) -> Optional[ScalingPrediction]:
        """Predict if scaling is needed for service."""
        try:
            # Get forecast
            predicted_value = await self.forecaster.forecast(service_name, resource_type, hours_ahead=1)

            if predicted_value is None:
                return None

            # Check for anomalies
            is_anomaly, anomaly_score = self.anomaly_detector.detect_anomaly()
                service_name, resource_type, current_value
            )

            # Determine scaling direction
            scaling_direction = ScalingDirection.MAINTAIN
            scale_factor = 1.0
            reasoning = "No scaling needed"

            if predicted_value > self.scale_up_threshold:
                scaling_direction = ScalingDirection.SCALE_UP
                scale_factor = min(2.0, predicted_value / self.scale_up_threshold)
                reasoning = f"Predicted utilization {predicted_value:.2f} > threshold {self.scale_up_threshold}"
            elif predicted_value < self.scale_down_threshold:
                scaling_direction = ScalingDirection.SCALE_DOWN
                scale_factor = max(0.5, predicted_value / self.scale_down_threshold)
                reasoning = f"Predicted utilization {predicted_value:.2f} < threshold {self.scale_down_threshold}"

            # Adjust for anomalies
            if is_anomaly and anomaly_score > 3.0:
                if current_value > predicted_value:
                    scaling_direction = ScalingDirection.SCALE_UP
                    scale_factor = min(2.0, scale_factor * 1.5)
                    reasoning += f" + anomaly detected (z-score: {anomaly_score:.2f})"

            # Calculate confidence
            model_key = f"{service_name}_{resource_type.value}"
            model_accuracy = self.forecaster.model_accuracy.get(model_key, 0.5)
            confidence = model_accuracy * (1.0 - min(0.5, anomaly_score / 10.0))

            # Calculate cost impact
            cost_impact = self._calculate_cost_impact(resource_type, scale_factor)

            return ScalingPrediction()
                service_name=service_name,
                resource_type=resource_type,
                current_value=current_value,
                predicted_value=predicted_value,
                predicted_at=datetime.now(timezone.utc),
                confidence=confidence,
                scaling_direction=scaling_direction,
                recommended_scale_factor=scale_factor,
                reasoning=reasoning,
                cost_impact=cost_impact
            )

        except Exception as e:
            logger.error(f"Prediction failed for {service_name}: {e}")
            return None

    def _calculate_cost_impact(self, resource_type: ResourceType, scale_factor: float) -> float:
        """Calculate cost impact of scaling action."""
        base_cost = self.cost_per_unit.get(resource_type, 0.0)
        cost_change = base_cost * (scale_factor - 1.0)
        return cost_change

    async def execute_scaling_action(self, prediction: ScalingPrediction) -> ScalingAction:
        """Execute scaling action based on prediction."""
        action_id = f"scale_{prediction.service_name}_{int(datetime.now().timestamp())}"

        action = ScalingAction()
            action_id=action_id,
            service_name=prediction.service_name,
            resource_type=prediction.resource_type,
            current_capacity=prediction.current_value,
            target_capacity=prediction.current_value * prediction.recommended_scale_factor,
            scaling_direction=prediction.scaling_direction,
            trigger=ScalingTrigger.PREDICTIVE,
            prediction=prediction
        )

        try:
            # Execute scaling (integrate with cluster manager)
            success = await self._perform_scaling(action)

            action.executed_at = datetime.now(timezone.utc)
            action.success = success

            if success:
                logger.info(f"Scaling action executed: {action.service_name} {action.scaling_direction.value}")
            else:
                action.error = "Scaling execution failed"
                logger.error(f"Scaling action failed: {action.service_name}")

        except Exception as e:
            action.executed_at = datetime.now(timezone.utc)
            action.success = False
            action.error = str(e)
            logger.error(f"Scaling action error: {e}")

        self.scaling_history.append(action)
        return action

    async def _perform_scaling(self, action: ScalingAction) -> bool:
        """Perform actual scaling operation."""
        # In production, this would integrate with:
        # - Kubernetes HPA/VPA
        # - Cloud provider auto-scaling groups
        # - PlexiChat's cluster manager
        # - Service mesh for traffic management

        logger.info(f"Scaling {action.service_name} from {action.current_capacity} to {action.target_capacity}")

        # Simulate scaling operation
        await asyncio.sleep(0.1)
        return True

    async def get_scaling_recommendations(self) -> List[ScalingPrediction]:
        """Get scaling recommendations for all active services."""
        recommendations = []

        for service_name in self.active_services:
            for resource_type in ResourceType:
                # Get current metrics (simplified)
                current_value = await self._get_current_metric_value(service_name, resource_type)

                if current_value is not None:
                    prediction = await self.predict_scaling_need(service_name, resource_type, current_value)

                    if prediction and prediction.should_scale and prediction.confidence > self.prediction_confidence_threshold:
                        recommendations.append(prediction)

        return recommendations

    async def _get_current_metric_value(self, service_name: str, resource_type: ResourceType) -> Optional[float]:
        """Get current metric value for service."""
        key = f"{service_name}_{resource_type.value}"

        if key in self.forecaster.training_data:
            recent_data = self.forecaster.training_data[key]
            if recent_data:
                return recent_data[-1].value

        return None

    async def _load_historical_data(self):
        """Load historical metrics data."""
        # In production, this would load from persistent storage
        logger.info("Loading historical metrics data")

    async def _train_initial_models(self):
        """Train initial forecasting models."""
        for service_name in self.active_services:
            for resource_type in ResourceType:
                await self.forecaster.train_model(service_name, resource_type)

    async def _start_background_tasks(self):
        """Start background tasks."""
        asyncio.create_task(self._model_retraining_task())
        asyncio.create_task(self._scaling_monitoring_task())
        asyncio.create_task(self._cost_optimization_task())

    async def get_scaling_metrics(self) -> Dict[str, Any]:
        """Get scaling system metrics."""
        recent_actions = self.scaling_history[-100:]

        successful_actions = [a for a in recent_actions if a.success]
        failed_actions = [a for a in recent_actions if not a.success]

        total_cost_impact = sum(a.prediction.cost_impact for a in recent_actions if a.prediction)

        return {}}
            "total_actions": len(recent_actions),
            "successful_actions": len(successful_actions),
            "failed_actions": len(failed_actions),
            "success_rate": len(successful_actions) / max(len(recent_actions), 1) * 100,
            "total_cost_impact": total_cost_impact,
            "active_services": len(self.active_services),
            "trained_models": len(self.forecaster.models),
            "average_model_accuracy": sum(self.forecaster.model_accuracy.values()) / max(len(self.forecaster.model_accuracy), 1)
        }

    async def cleanup(self):
        """Cleanup predictive scaler resources."""
        logger.info("Cleaning up predictive scaler")


# Global predictive scaler instance
predictive_scaler = PredictiveScaler()
