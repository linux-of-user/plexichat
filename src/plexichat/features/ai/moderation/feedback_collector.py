"""
AI Moderation Feedback Collector
Collects and processes user feedback for improving moderation accuracy.
"""

import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

# Import with fallbacks
try:
    from plexichat.features.ai.moderation.moderation_engine import ModerationAction, ModerationCategory, ModerationSeverity  # type: ignore
except ImportError:
    ModerationAction = str
    ModerationCategory = str
    ModerationSeverity = str

from plexichat.features.ai.moderation.training_data_service import ModerationTrainingSystem, TrainingDataSource

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
    """Moderation feedback data."""
    content_id: str
    user_id: str
    feedback_type: FeedbackType
    source: FeedbackSource
    original_action: str  # ModerationAction will be imported later
    suggested_action: str  # ModerationAction will be imported later
    confidence: float
    reasoning: str
    categories: List[str]  # ModerationCategory will be imported later
    severity: str  # ModerationSeverity will be imported later
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    processed: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "content_id": self.content_id,
            "user_id": self.user_id,
            "feedback_type": self.feedback_type.value,
            "source": self.source.value,
            "original_action": self.original_action,
            "suggested_action": self.suggested_action,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
            "categories": self.categories,
            "severity": self.severity,
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat(),
            "processed": self.processed
        }

class FeedbackCollector:
    """Collects and processes moderation feedback."""

    def __init__(self, data_path: str = "data/moderation_feedback"):
        """Initialize the feedback collector."""
        self.data_path = Path(data_path)
        self.data_path.mkdir(parents=True, exist_ok=True)

        self.db_path = self.data_path / "feedback.db"
        self.training_system = None  # Will be initialized later
        self.feedback_service = None  # Will be initialized later

        self._init_database()

    def _init_database(self):
        """Initialize feedback database."""
        try:
            # Use FeedbackDataService for all DB initialization and CRUD
            from plexichat.features.ai.moderation.feedback_data_service import FeedbackDataService
            self.feedback_service = FeedbackDataService()
        except ImportError:
            logger.warning("FeedbackDataService not available, using fallback")
            self.feedback_service = None

    async def submit_feedback(self,
        content_id: str,
        user_id: str,
        feedback_type: FeedbackType,
        source: FeedbackSource,
        original_action: str,  # ModerationAction
        suggested_action: str,  # ModerationAction
        confidence: float,
        reasoning: str,
        categories: List[str],  # List[ModerationCategory]
        severity: str,  # ModerationSeverity
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

            if self.feedback_service:
                await self.feedback_service.add_feedback(feedback)  # type: ignore
            else:
                # Fallback: save to file
                await self._save_feedback_to_file(feedback)

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
            if self.training_system:
                success = self.training_system.add_training_data(
                    content=content,
                    label=feedback.suggested_action,
                    confidence=feedback.confidence,
                    categories=feedback.categories,
                    severity=feedback.severity,
                    source="USER_FEEDBACK",  # TrainingDataSource.USER_FEEDBACK
                    metadata={
                        "original_action": feedback.original_action,
                        "user_id": feedback.user_id,
                        "reasoning": feedback.reasoning,
                        "feedback_source": feedback.source.value
                    }
                )
            else:
                success = True  # Fallback

            if success:
                # Mark feedback as processed
                if self.feedback_service:
                    await self.feedback_service.mark_feedback_processed(feedback.content_id, feedback.user_id)  # type: ignore

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
            if self.feedback_service:
                return await self.feedback_service.get_feedback_stats(days)  # type: ignore
            else:
                return {"total": 0, "processed": 0, "pending": 0}

        except Exception as e:
            logger.error(f"Failed to get feedback stats: {e}")
            return {"error": str(e)}

    async def get_user_feedback_history(self, user_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Get feedback history for a user."""
        try:
            if self.feedback_service:
                return await self.feedback_service.get_user_feedback_history(user_id, limit)  # type: ignore
            else:
                return []

        except Exception as e:
            logger.error(f"Failed to get user feedback history: {e}")
            return []

    async def _save_feedback_to_file(self, feedback: ModerationFeedback):
        """Fallback method to save feedback to file."""
        try:
            feedback_file = self.data_path / f"feedback_{feedback.content_id}_{feedback.user_id}.json"
            with open(feedback_file, 'w') as f:
                json.dump(feedback.to_dict(), f, indent=2)
            logger.debug(f"Feedback saved to file: {feedback_file}")
        except Exception as e:
            logger.error(f"Failed to save feedback to file: {e}")
