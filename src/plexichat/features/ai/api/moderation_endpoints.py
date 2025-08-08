"""
AI Moderation API Endpoints for PlexiChat
=========================================

RESTful API endpoints for AI moderation functionality.
"""

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from fastapi import APIRouter, HTTPException, BackgroundTasks
    from pydantic import BaseModel, Field

try:
    from fastapi import APIRouter, HTTPException, BackgroundTasks
    from pydantic import BaseModel, Field
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False
    BaseModel = None
    Field = None
    APIRouter = None
    HTTPException = None
    BackgroundTasks = None

from ..ai_coordinator import AICoordinator

logger = logging.getLogger(__name__)

# Initialize AI coordinator
ai_coordinator = AICoordinator()

# API Models (only if FastAPI is available)
if FASTAPI_AVAILABLE:
    class ModerationRequest(BaseModel):  # type: ignore
        """API model for moderation requests."""
        content: str
        user_id: Optional[str] = None
        context: Optional[Dict[str, Any]] = None
        severity_threshold: float = Field(default=0.5, ge=0.0, le=1.0)  # type: ignore
        categories: Optional[List[str]] = None

    class ModerationResponse(BaseModel):  # type: ignore
        """API model for moderation responses."""
        request_id: str
        is_appropriate: bool
        confidence: float
        categories: List[str]
        severity: float
        action: str
        reason: Optional[str] = None
        timestamp: datetime

    class FeedbackRequest(BaseModel):  # type: ignore
        """API model for moderation feedback."""
        moderation_id: str
        user_id: str
        feedback_type: str  # "correct", "incorrect", "partial"
        comments: Optional[str] = None

    # Create API router
    router = APIRouter(prefix="/ai/moderation", tags=["AI Moderation"])  # type: ignore

    @router.post("/moderate", response_model=ModerationResponse)
    async def moderate_content(request: ModerationRequest):
        """Moderate content using AI."""
        try:
            # Use the AI coordinator for moderation
            result = await ai_coordinator.smart_content_moderation(
                content=request.content,
                context=request.context
            )

            return ModerationResponse(
                request_id=str(uuid.uuid4()),
                is_appropriate=result.get("is_appropriate", True),
                confidence=result.get("confidence", 0.5),
                categories=result.get("categories", []),
                severity=result.get("severity", 0.0),
                action=result.get("action", "none"),
                reason=result.get("reason"),
                timestamp=datetime.now(timezone.utc)
            )

        except Exception as e:
            logger.error(f"Content moderation failed: {e}")
            raise HTTPException(status_code=500, detail=str(e))  # type: ignore

    @router.post("/feedback")
    async def submit_feedback(request: FeedbackRequest, background_tasks: BackgroundTasks):  # type: ignore
        """Submit feedback on moderation results."""
        try:
            # Process feedback in background
            background_tasks.add_task(
                _process_moderation_feedback,
                request.moderation_id,
                request.user_id,
                request.feedback_type,
                request.comments
            )

            return {"status": "feedback_received", "message": "Thank you for your feedback"}

        except Exception as e:
            logger.error(f"Feedback submission failed: {e}")
            raise HTTPException(status_code=500, detail=str(e))  # type: ignore

    @router.get("/health")
    async def moderation_health():
        """Check moderation system health."""
        try:
            status = ai_coordinator.get_health_status()
            return {
                "status": "healthy",
                "moderation_enabled": True,
                "details": status
            }
        except Exception as e:
            logger.error(f"Moderation health check failed: {e}")
            raise HTTPException(status_code=500, detail=str(e))  # type: ignore

    async def _process_moderation_feedback(
        moderation_id: str,
        user_id: str,
        feedback_type: str,
        comments: Optional[str]
    ):
        """Process moderation feedback in background."""
        try:
            # Log feedback for now
            logger.info(f"Moderation feedback: {moderation_id} - {feedback_type} from {user_id}")
            if comments:
                logger.info(f"Feedback comments: {comments}")
        except Exception as e:
            logger.error(f"Failed to process moderation feedback: {e}")

else:
    # Fallback when FastAPI is not available
    logger.warning("FastAPI not available, AI moderation API endpoints disabled")
    router = None

# Export the router
__all__ = ["router"]
