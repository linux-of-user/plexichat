# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import hashlib
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from .moderation_engine import ModerationAction, ModerationCategory, ModerationSeverity
from .training_system import ModerationTrainingSystem, TrainingDataSource

from pathlib import Path

"""
import time
AI Moderation Feedback Collector
Collects and processes user feedback for improving moderation accuracy.


logger = logging.getLogger(__name__)

class FeedbackType(str, Enum):
    """Type of feedback."""
        CORRECTION = "correction"
    CONFIRMATION = "confirmation"
    REPORT = "report"
    APPEAL = "appeal"

class FeedbackSource(str, Enum):
    """Source of feedback."""
    USER_INTERFACE = "user_interface"
    API_ENDPOINT = "api_endpoint"
    AUTOMATED_REVIEW = "automated_review"
    HUMAN_MODERATOR = "human_moderator"

@dataclass
class ModerationFeedback:
    """Moderation feedback data.
        content_id: str
    user_id: str
    feedback_type: FeedbackType
    source: FeedbackSource
    original_action: ModerationAction
    suggested_action: ModerationAction
    confidence: float
    reasoning: str
    categories: List[ModerationCategory]
    severity: ModerationSeverity
    metadata: Dict[str, Any]
    created_at: datetime
    processed: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "content_id": self.content_id,
            "user_id": self.user_id,
            "feedback_type": self.feedback_type.value,
            "source": self.source.value,
            "original_action": self.original_action.value,
            "suggested_action": self.suggested_action.value,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
            "categories": [cat.value for cat in self.categories],
            "severity": self.severity.value,
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat(),
            "processed": self.processed
        }}

class FeedbackCollector:
    """Collects and processes moderation feedback."""
        def __init__(self, data_path: str = "data/moderation_feedback"):
        self.data_path = Path(data_path)
        self.data_path.mkdir(parents=True, exist_ok=True)

        self.db_path = self.data_path / "feedback.db"
        self.training_system = ModerationTrainingSystem()

        self._init_database()

    def _init_database(self):
        """Initialize feedback database.
        # Use FeedbackDataService for all DB initialization and CRUD
        from src.plexichat.features.ai.moderation.feedback_data_service import FeedbackDataService
        self.feedback_service = FeedbackDataService()
        # Replace any direct DB/table creation with service-based initialization
        # (If needed, add an async initialization method)
        pass

    async def submit_feedback(self,
        content_id: str,
        user_id: str,
        feedback_type: FeedbackType,
        source: FeedbackSource,
        original_action: ModerationAction,
        suggested_action: ModerationAction,
        confidence: float,
        reasoning: str,
        categories: List[ModerationCategory],
        severity: ModerationSeverity,
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Submit moderation feedback."""
        try:
            feedback = ModerationFeedback(
                content_id=content_id,
                user_id=user_id,
                feedback_type=feedback_type,
                source=source,
                original_action=original_action,
                suggested_action=suggested_action,
                confidence=confidence,
                reasoning=reasoning,
                categories=categories,
                severity=severity,
                metadata=metadata or {},
                created_at=datetime.now(timezone.utc)
            )

            await self.feedback_service.add_feedback(feedback)

            logger.info(f"Feedback submitted: {content_id} by {user_id}")

            # Process feedback immediately if it's a correction
            if feedback_type == FeedbackType.CORRECTION:
                await self._process_correction_feedback(feedback)

            return True

        except Exception as e:
            logger.error(f"Failed to submit feedback: {e}")
            return False

    async def _process_correction_feedback(self, feedback: ModerationFeedback):
        """Process correction feedback for training."""
        try:
            # Get the original content
            content = await self._get_content(feedback.content_id)
            if not content:
                logger.warning(f"Content not found for feedback: {feedback.content_id}")
                return

            # Add to training data
            success = self.training_system.add_training_data(
                content=content,
                label=feedback.suggested_action,
                confidence=feedback.confidence,
                categories=feedback.categories,
                severity=feedback.severity,
                source=TrainingDataSource.USER_FEEDBACK,
                metadata={
                    "original_action": feedback.original_action.value,
                    "user_id": feedback.user_id,
                    "reasoning": feedback.reasoning,
                    "feedback_source": feedback.source.value
                }
            )

            if success:
                # Mark feedback as processed
                await self.feedback_service.mark_feedback_processed(feedback.content_id, feedback.user_id)

                logger.info(f"Processed correction feedback for {feedback.content_id}")

        except Exception as e:
            logger.error(f"Failed to process correction feedback: {e}")

    async def _get_content(self, content_id: str) -> Optional[str]:
        """Get content by ID from cache."""
        try:
            # Assuming content_cache table is removed or replaced by a service
            # For now, we'll just return None as the cache mechanism is removed
            return None
        except Exception as e:
            logger.error(f"Failed to get content {content_id}: {e}")
            return None

    async def cache_content(self, content_id: str, content: str):
        """Cache content for feedback processing."""
        try:
            # Generate content hash for potential future use
            _ = hashlib.sha256(content.encode()).hexdigest()

            # Assuming content_cache table is removed or replaced by a service
            # For now, we'll just return as the cache mechanism is removed
            logger.debug(f"Content {content_id} cached (placeholder)")

        except Exception as e:
            logger.error(f"Failed to cache content {content_id}: {e}")

    async def get_feedback_stats(self, days: int = 7) -> Dict[str, Any]:
        """Get feedback statistics."""
        try:
            # Assuming FeedbackDataService handles this
            return await self.feedback_service.get_feedback_stats(days)

        except Exception as e:
            logger.error(f"Failed to get feedback stats: {e}")
            return {"error": str(e)}

    async def get_user_feedback_history(self, user_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Get feedback history for a user."""
        try:
            # Assuming FeedbackDataService handles this
            return await self.feedback_service.get_user_feedback_history(user_id, limit)

        except Exception as e:
            logger.error(f"Failed to get user feedback history: {e}")
            return []
