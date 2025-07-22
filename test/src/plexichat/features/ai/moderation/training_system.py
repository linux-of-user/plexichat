# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import hashlib
import json
import logging
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split

from .moderation_engine import ModerationAction, ModerationCategory, ModerationSeverity

"""
AI Moderation Training System
Progressive learning system that improves moderation accuracy based on user feedback.
"""

logger = logging.getLogger(__name__)

class TrainingDataSource(str, Enum):
    """Source of training data."""
    USER_FEEDBACK = "user_feedback"
    HUMAN_REVIEW = "human_review"
    AUTOMATED = "automated"
    IMPORTED = "imported"

@dataclass
class TrainingData:
    """Training data point."""
    content: str
    label: ModerationAction
    confidence: float
    categories: List[ModerationCategory]
    severity: ModerationSeverity
    source: TrainingDataSource
    metadata: Dict[str, Any]
    created_at: datetime

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "content": self.content,
            "label": self.label.value,
            "confidence": self.confidence,
            "categories": [cat.value for cat in self.categories],
            "severity": self.severity.value,
            "source": self.source.value,
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat()
        }

@dataclass
class TrainingResult:
    """Result of model training."""
    model_version: str
    accuracy: float
    training_samples: int
    validation_samples: int
    feature_count: int
    training_time_seconds: float
    metrics: Dict[str, Any]
    created_at: datetime

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "model_version": self.model_version,
            "accuracy": self.accuracy,
            "training_samples": self.training_samples,
            "validation_samples": self.validation_samples,
            "feature_count": self.feature_count,
            "training_time_seconds": self.training_time_seconds,
            "metrics": self.metrics,
            "created_at": self.created_at.isoformat()
        }

class ModerationTrainingSystem:
    """AI moderation training system with progressive learning."""

    def __init__(self, data_path: str = "data/moderation_training"):
        self.data_path = Path(data_path)
        self.data_path.mkdir(parents=True, exist_ok=True)

        self.db_path = self.data_path / "training.db"
        self.models_path = self.data_path / "models"
        self.models_path.mkdir(exist_ok=True)

        self.vectorizer: Optional[TfidfVectorizer] = None
        self.classifier: Optional[LogisticRegression] = None
        self.current_model_version = "1.0.0"

        self._init_database()
        self._load_latest_model()

    def _init_database(self):
        """Initialize training database using abstraction layer."""
        # Use TrainingDataService for all DB initialization and CRUD
        from src.plexichat.features.ai.moderation.training_data_service import TrainingDataService
        self.training_service = TrainingDataService()
        # Replace any direct DB/table creation with service-based initialization
        # (If needed, add an async initialization method)
        pass

    def add_training_data(self,
        content: str,
        label: ModerationAction,
        confidence: float,
        categories: List[ModerationCategory],
        severity: ModerationSeverity,
        source: TrainingDataSource,
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Add training data point."""
        try:
            content_hash = hashlib.sha256(content.encode()).hexdigest()

            training_data = TrainingData()
            training_data.content = content
            training_data.label = label
            training_data.confidence = confidence
            training_data.categories = categories
            training_data.severity = severity
            training_data.source = source
            training_data.metadata = metadata or {}
            training_data.created_at = datetime.now(timezone.utc)

            from plexichat.features.ai.moderation.training_data_service import TrainingDataService
            training_data_service = TrainingDataService(self.db_path)
            training_data_service.add_training_data(training_data)

            logger.info(f"Added training data: {label.value} (confidence: {confidence:.2f})")
            return True

        except Exception as e:
            logger.error(f"Failed to add training data: {e}")
            return False

    def add_user_feedback(self,
        content_id: str,
        original_prediction: ModerationAction,
        user_correction: ModerationAction,
        user_id: str,
        confidence: float = 1.0,
        reasoning: Optional[str] = None
    ) -> bool:
        """Add user feedback for training."""
        try:
            from plexichat.features.ai.moderation.feedback_data_service import FeedbackDataService
            feedback_data_service = FeedbackDataService(self.db_path)
            feedback_data_service.add_feedback_data(content_id, original_prediction, user_correction, user_id, confidence, reasoning)

            logger.info(f"Added user feedback: {original_prediction.value} -> {user_correction.value}")
            return True

        except Exception as e:
            logger.error(f"Failed to add user feedback: {e}")
            return False

    async def train_model(self, min_samples: int = 100) -> Optional[TrainingResult]:
        """Train moderation model with available data."""
        start_time = time.time()

        try:
            from plexichat.features.ai.moderation.training_data_service import TrainingDataService
            training_data_service = TrainingDataService(self.db_path)
            training_data = training_data_service.get_training_data(min_samples)

            if len(training_data) < min_samples:
                logger.warning(f"Insufficient training data: {len(training_data)} < {min_samples}")
                return None

            # Prepare data
            texts = [item["content"] for item in training_data]
            labels = [item["label"] for item in training_data]

            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                texts, labels, test_size=0.2, random_state=42, stratify=labels
            )

            # Vectorize text
            self.vectorizer = TfidfVectorizer()
            self.vectorizer.max_features = 10000
            self.vectorizer.stop_words = 'english'
            self.vectorizer.ngram_range = (1, 2)
            self.vectorizer.min_df = 2
            self.vectorizer.max_df = 0.95

            X_train_vec = self.vectorizer.fit_transform(X_train)
            X_test_vec = self.vectorizer.transform(X_test)

            # Train classifier
            self.classifier = LogisticRegression()
            self.classifier.max_iter = 1000
            self.classifier.class_weight = 'balanced'
            self.classifier.random_state = 42

            self.classifier.fit(X_train_vec, y_train)

            # Evaluate
            y_pred = self.classifier.predict(X_test_vec)
            accuracy = accuracy_score(y_test, y_pred)

            # Generate detailed metrics
            report = classification_report(y_test, y_pred, output_dict=True)

            # Create new model version
            model_version = f"v{datetime.now().strftime('%Y%m%d_%H%M%S')}_{str(uuid.uuid4())[:8]}"

            # Save model
            model_file = self.models_path / f"{model_version}.joblib"
            vectorizer_file = self.models_path / f"{model_version}_vectorizer.joblib"

            joblib.dump(self.classifier, model_file)
            joblib.dump(self.vectorizer, vectorizer_file)

            training_time = time.time() - start_time

            # Create training result
            result = TrainingResult()
            result.model_version = model_version
            result.accuracy = accuracy
            result.training_samples = len(X_train)
            result.validation_samples = len(X_test)
            result.feature_count = X_train_vec.shape[1]
            result.training_time_seconds = training_time
            result.metrics = report
            result.created_at = datetime.now(timezone.utc)

            # Store result
            from plexichat.features.ai.moderation.training_result_service import TrainingResultService
            training_result_service = TrainingResultService(self.db_path)
            training_result_service.add_training_result(result)

            # Mark data as used
            training_data_service.mark_data_as_used([item["id"] for item in training_data])

            # Update current model
            self.current_model_version = model_version

            logger.info(f"Model training completed: {model_version} (accuracy: {accuracy:.3f})")
            return result

        except Exception as e:
            logger.error(f"Model training failed: {e}")
            return None
