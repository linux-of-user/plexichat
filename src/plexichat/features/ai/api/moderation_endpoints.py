import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


from ..moderation import (

from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel, Field

"""
AI Moderation API Endpoints
RESTful API endpoints for AI moderation, training, and feedback collection.
"""

    FeedbackCollector,
    FeedbackSource,
    FeedbackType,
    ModerationAction,
    ModerationCategory,
    ModerationEngine,
    ModerationSeverity,
    ModerationTrainingSystem,
    TrainingDataSource,
)

logger = logging.getLogger(__name__)

# Initialize components
moderation_engine = ModerationEngine()
training_system = ModerationTrainingSystem()
feedback_collector = FeedbackCollector()

router = APIRouter(prefix="/api/v1/moderation", tags=["AI Moderation"])

# Request/Response Models
class ModerationRequest(BaseModel):
    content: str = Field(..., description="Content to moderate")
    content_id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Unique content identifier")
    content_type: str = Field(default="text", description="Type of content")
    provider: str = Field(default="openai", description="AI provider to use")
    metadata: Optional[Dict[str, Any]] = Field(default=None, description="Additional metadata")

class ModerationResponse(BaseModel):
    content_id: str
    confidence_score: float
    recommended_action: str
    severity: str
    categories: List[str]
    reasoning: str
    processing_time_ms: int
    model_used: str
    requires_human_review: bool
    timestamp: str

class FeedbackRequest(BaseModel):
    content_id: str = Field(..., description="Content identifier")
    user_id: str = Field(..., description="User providing feedback")
    feedback_type: str = Field(..., description="Type of feedback")
    original_action: str = Field(..., description="Original moderation action")
    suggested_action: str = Field(..., description="Suggested action")
    confidence: float = Field(default=1.0, description="Confidence in feedback")
    reasoning: str = Field(default="", description="Reasoning for feedback")
    categories: List[str] = Field(default_factory=list, description="Content categories")
    severity: str = Field(default="medium", description="Content severity")

class TrainingRequest(BaseModel):
    content: str = Field(..., description="Training content")
    label: str = Field(..., description="Correct moderation action")
    confidence: float = Field(default=1.0, description="Label confidence")
    categories: List[str] = Field(default_factory=list, description="Content categories")
    severity: str = Field(default="medium", description="Content severity")
    source: str = Field(default="manual", description="Training data source")

# API Endpoints
@router.post("/moderate", response_model=ModerationResponse)
async def moderate_content(request: ModerationRequest, background_tasks: BackgroundTasks):
    """Moderate content using AI."""
    try:
        # Cache content for potential feedback
        background_tasks.add_task(
            feedback_collector.cache_content,
            request.content_id,
            request.content
        )
        
        # Perform moderation
        result = await moderation_engine.moderate_content(
            content=request.content,
            content_id=request.content_id,
            content_type=request.content_type,
            provider=request.provider,
            metadata=request.metadata
        )
        
        return ModerationResponse(
            content_id=result.content_id,
            confidence_score=result.confidence_score,
            recommended_action=result.recommended_action.value,
            severity=result.severity.value,
            categories=[cat.value for cat in result.categories],
            reasoning=result.reasoning,
            processing_time_ms=result.processing_time_ms,
            model_used=result.model_used,
            requires_human_review=result.requires_human_review,
            timestamp=result.timestamp.isoformat()
        )
        
    except Exception as e:
        logger.error(f"Moderation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Moderation failed: {str(e)}")

@router.post("/feedback")
async def submit_feedback(request: FeedbackRequest):
    """Submit feedback for moderation improvement."""
    try:
        success = await feedback_collector.submit_feedback(
            content_id=request.content_id,
            user_id=request.user_id,
            feedback_type=FeedbackType(request.feedback_type),
            source=FeedbackSource.API_ENDPOINT,
            original_action=ModerationAction(request.original_action),
            suggested_action=ModerationAction(request.suggested_action),
            confidence=request.confidence,
            reasoning=request.reasoning,
            categories=[ModerationCategory(cat) for cat in request.categories],
            severity=ModerationSeverity(request.severity)
        )
        
        if success:
            return {"status": "success", "message": "Feedback submitted successfully"}
        else:
            raise HTTPException(status_code=500, detail="Failed to submit feedback")
            
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid input: {str(e)}")
    except Exception as e:
        logger.error(f"Feedback submission failed: {e}")
        raise HTTPException(status_code=500, detail=f"Feedback submission failed: {str(e)}")

@router.post("/training/add")
async def add_training_data(request: TrainingRequest):
    """Add training data for model improvement."""
    try:
        success = training_system.add_training_data(
            content=request.content,
            label=ModerationAction(request.label),
            confidence=request.confidence,
            categories=[ModerationCategory(cat) for cat in request.categories],
            severity=ModerationSeverity(request.severity),
            source=TrainingDataSource(request.source)
        )
        
        if success:
            return {"status": "success", "message": "Training data added successfully"}
        else:
            raise HTTPException(status_code=500, detail="Failed to add training data")
            
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid input: {str(e)}")
    except Exception as e:
        logger.error(f"Training data addition failed: {e}")
        raise HTTPException(status_code=500, detail=f"Training data addition failed: {str(e)}")

@router.post("/training/train")
async def train_model(background_tasks: BackgroundTasks, min_samples: int = 100):
    """Train moderation model with available data."""
    try:
        # Run training in background
        background_tasks.add_task(_train_model_background, min_samples)
        
        return {
            "status": "success", 
            "message": f"Model training started with minimum {min_samples} samples"
        }
        
    except Exception as e:
        logger.error(f"Training initiation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Training initiation failed: {str(e)}")

async def _train_model_background(min_samples: int):
    """Background task for model training."""
    try:
        result = await training_system.train_model(min_samples)
        if result:
            logger.info(f"Model training completed: {result.model_version} (accuracy: {result.accuracy:.3f})")
        else:
            logger.warning("Model training failed or insufficient data")
    except Exception as e:
        logger.error(f"Background training failed: {e}")

@router.get("/stats")
async def get_moderation_stats(days: int = 7):
    """Get moderation statistics."""
    try:
        moderation_stats = await moderation_engine.get_moderation_stats(days)
        feedback_stats = await feedback_collector.get_feedback_stats(days)
        training_stats = await training_system.get_training_stats()
        
        return {
            "moderation": moderation_stats,
            "feedback": feedback_stats,
            "training": training_stats,
            "period_days": days
        }
        
    except Exception as e:
        logger.error(f"Stats retrieval failed: {e}")
        raise HTTPException(status_code=500, detail=f"Stats retrieval failed: {str(e)}")

@router.get("/feedback/user/{user_id}")
async def get_user_feedback(user_id: str, limit: int = 50):
    """Get feedback history for a user."""
    try:
        feedback_history = await feedback_collector.get_user_feedback_history(user_id, limit)
        return {
            "user_id": user_id,
            "feedback_count": len(feedback_history),
            "feedback": feedback_history
        }
        
    except Exception as e:
        logger.error(f"User feedback retrieval failed: {e}")
        raise HTTPException(status_code=500, detail=f"User feedback retrieval failed: {str(e)}")

@router.get("/training/predict")
async def predict_with_trained_model(content: str):
    """Make prediction using trained model."""
    try:
        prediction = await training_system.predict(content)
        
        if prediction:
            return {
                "status": "success",
                "prediction": prediction
            }
        else:
            return {
                "status": "no_model",
                "message": "No trained model available"
            }
            
    except Exception as e:
        logger.error(f"Prediction failed: {e}")
        raise HTTPException(status_code=500, detail=f"Prediction failed: {str(e)}")

@router.get("/health")
async def health_check():
    """Health check for moderation system."""
    try:
        return {
            "status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "components": {
                "moderation_engine": "available",
                "training_system": "available", 
                "feedback_collector": "available"
            }
        }
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
