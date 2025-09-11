"""
AI API Endpoints for PlexiChat
==============================

RESTful API endpoints for AI functionality.
"""

from datetime import datetime
import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from fastapi import APIRouter, HTTPException
    from pydantic import BaseModel, Field

try:
    from fastapi import APIRouter, HTTPException
    from pydantic import BaseModel, Field
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False
    BaseModel = None
    Field = None
    APIRouter = None
    HTTPException = None

from plexichat.features.ai.ai_coordinator import AICoordinator
from plexichat.features.ai.core.ai_abstraction_layer import (
    AIRequest,
)

logger = logging.getLogger(__name__)

# Initialize AI coordinator
ai_coordinator = AICoordinator()

# API Models (only if FastAPI is available)
if FASTAPI_AVAILABLE:
    class AIRequestModel(BaseModel):  # type: ignore
        """API model for AI requests."""
        user_id: str
        model_id: str
        prompt: str
        max_tokens: int | None = None
        temperature: float = Field(default=0.7, ge=0.0, le=2.0)  # type: ignore
        stream: bool = False
        system_prompt: str | None = None
        context: str | None = None
        metadata: dict[str, Any] | None = None
        priority: int = Field(default=1, ge=1, le=10)  # type: ignore
        timeout_seconds: int = Field(default=30, ge=5, le=300)  # type: ignore

    class AIResponseModel(BaseModel):  # type: ignore
        """API model for AI responses."""
        request_id: str
        model_id: str
        content: str
        usage: dict[str, int]
        cost: float
        latency_ms: int
        provider: str
        timestamp: datetime
        success: bool
        error: str | None = None
        cached: bool = False
        fallback_used: bool = False
        fallback_model: str | None = None

    class ModelInfoModel(BaseModel):  # type: ignore
        """API model for model information."""
        id: str
        name: str
        provider: str
        capabilities: list[str]
        max_tokens: int
        cost_per_token: float
        status: str
        description: str | None = None

    # Create API router
    router = APIRouter(prefix="/ai", tags=["AI"])  # type: ignore

    @router.post("/chat", response_model=AIResponseModel)
    async def chat_completion(request: AIRequestModel):
        """Process a chat completion request."""
        try:
            # Convert API model to internal request
            ai_request = AIRequest(
                prompt=request.prompt,
                model_id=request.model_id,
                user_id=request.user_id,
                parameters={
                    "max_tokens": request.max_tokens,
                    "temperature": request.temperature
                },
                context=request.system_prompt,
                metadata=request.metadata
            )

            # Process the request
            response = await ai_coordinator.process_request(ai_request)

            # Convert internal response to API model
            return AIResponseModel(
                request_id=response.request_id,
                model_id=response.model_id,
                content=response.content,
                usage=response.usage or {},
                cost=0.0,  # Calculate based on usage
                latency_ms=0,  # Calculate from timing
                provider=response.provider,
                timestamp=datetime.now(),
                success=response.status == "success",
                error=response.error
            )

        except Exception as e:
            logger.error(f"Chat completion failed: {e}")
            raise HTTPException(status_code=500, detail=str(e))  # type: ignore

    @router.get("/models", response_model=list[ModelInfoModel])
    async def list_models():
        """Get list of available AI models."""
        try:
            models = ai_coordinator.get_available_models()
            return [
                ModelInfoModel(
                    id=model.id,
                    name=model.name,
                    provider=model.provider.value,
                    capabilities=[cap.value for cap in model.capabilities],
                    max_tokens=model.max_tokens,
                    cost_per_token=model.cost_per_token,
                    status=model.status.value,
                    description=model.description
                )
                for model in models
            ]
        except Exception as e:
            logger.error(f"Failed to list models: {e}")
            raise HTTPException(status_code=500, detail=str(e))  # type: ignore

    @router.get("/models/{model_id}", response_model=ModelInfoModel)
    async def get_model(model_id: str):
        """Get information about a specific model."""
        try:
            model = ai_coordinator.get_model_info(model_id)
            if not model:
                raise HTTPException(status_code=404, detail="Model not found")  # type: ignore

            return ModelInfoModel(
                id=model.id,
                name=model.name,
                provider=model.provider.value,
                capabilities=[cap.value for cap in model.capabilities],
                max_tokens=model.max_tokens,
                cost_per_token=model.cost_per_token,
                status=model.status.value,
                description=model.description
            )
        except HTTPException:  # type: ignore
            raise
        except Exception as e:
            logger.error(f"Failed to get model {model_id}: {e}")
            raise HTTPException(status_code=500, detail=str(e))  # type: ignore

    @router.get("/health")
    async def health_check():
        """Check AI system health."""
        try:
            status = ai_coordinator.get_health_status()
            return {"status": "healthy", "details": status}
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            raise HTTPException(status_code=500, detail=str(e))  # type: ignore

else:
    # Fallback when FastAPI is not available
    logger.warning("FastAPI not available, AI API endpoints disabled")
    router = None

# Export the router
__all__ = ["router"]
