# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional


from ....features.ai.core.ai_abstraction_layer import AIAbstractionLayer
from ....features.ai.moderation.content_moderator import ContentModerator
from ....features.ai.monitoring.metrics_collector import MetricsCollector
from ....features.ai.monitoring.request_logger import RequestLogger

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

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query
from pydantic import BaseModel, Field

"""
PlexiChat AI API Endpoints

Consolidated AI management API endpoints including:
- AI request processing
- Model management
- Provider configuration
- Moderation controls
- Monitoring and analytics

Merged from:
- features/ai/api/ai_endpoints.py
- features/ai/api/moderation_endpoints.py
- features/ai/api/monitoring_endpoints.py
- features/ai/api/provider_endpoints.py
"""

logger = logging.getLogger(__name__)

# Create router
router = APIRouter(prefix="/ai", tags=["AI Management"])

# API Models
class AIRequestModel(BaseModel):
    """API model for AI requests."""
    user_id: str
    model_id: str
    prompt: str
    max_tokens: Optional[int] = None
    temperature: float = Field(default=0.7, ge=0.0, le=2.0)
    stream: bool = False
    functions: Optional[List[Dict[str, Any]]] = None
    system_prompt: Optional[str] = None
    context: Optional[List[Dict[str, str]]] = None
    metadata: Optional[Dict[str, Any]] = None
    priority: int = Field(default=1, ge=1, le=10)
    timeout_seconds: int = Field(default=30, ge=5, le=300)

class AIResponseModel(BaseModel):
    """API model for AI responses."""
    request_id: str
    model_id: str
    content: str
    usage: Dict[str, int]
    cost: float
    latency_ms: int
    provider: str
    timestamp: datetime
    success: bool
    error: Optional[str] = None

class ModelInfo(BaseModel):
    """Model information."""
    id: str
    name: str
    provider: str
    capabilities: List[str]
    status: str
    max_tokens: int
    cost_per_token: float
    description: Optional[str] = None

class ProviderConfig(BaseModel):
    """Provider configuration."""
    name: str
    api_key: str
    base_url: Optional[str] = None
    enabled: bool = True
    rate_limit: int = 100
    timeout: int = 30
    retry_attempts: int = 3

class ModerationRequest(BaseModel):
    """Moderation request model."""
    content: str
    user_id: str
    context: Optional[str] = None
    severity_threshold: float = Field(default=0.7, ge=0.0, le=1.0)

class ModerationResult(BaseModel):
    """Moderation result model."""
    flagged: bool
    categories: Dict[str, float]
    severity: float
    action: str
    reason: Optional[str] = None

class MonitoringMetrics(BaseModel):
    """Monitoring metrics model."""
    total_requests: int
    successful_requests: int
    failed_requests: int
    average_latency: float
    total_cost: float
    requests_per_minute: float
    error_rate: float

# AI Request Processing Endpoints
@router.post("/request", response_model=AIResponseModel)
async def process_ai_request(
    request: AIRequestModel,
    background_tasks: BackgroundTasks
):
    """Process an AI request."""
    try:
        # Import AI layer here to avoid circular imports
        ai_layer = AIAbstractionLayer()

        # Convert API model to internal model
        ai_request = {
            "user_id": request.user_id,
            "model_id": request.model_id,
            "prompt": request.prompt,
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
            "stream": request.stream,
            "functions": request.functions,
            "system_prompt": request.system_prompt,
            "context": request.context,
            "metadata": request.metadata,
            "priority": request.priority,
            "timeout_seconds": request.timeout_seconds
        }

        # Process request
        response = await ai_layer.process_request(ai_request)

        # Log request for monitoring
        background_tasks.add_task(log_ai_request, request, response)

        return AIResponseModel(
            request_id=response.get("request_id", ""),
            model_id=response.get("model_id", request.model_id),
            content=response.get("content", ""),
            usage=response.get("usage", {}),
            cost=response.get("cost", 0.0),
            latency_ms=response.get("latency_ms", 0),
            provider=response.get("provider", ""),
            timestamp=response.get("timestamp", from datetime import datetime
datetime = datetime.now()),
            success=response.get("success", False),
            error=response.get("error")
        )

    except Exception as e:
        logger.error(f"AI request processing failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/models", response_model=List[ModelInfo])
async def list_available_models():
    """List all available AI models."""
    try:
        ai_layer = AIAbstractionLayer()
        models = await ai_layer.get_available_models()

        return [
            ModelInfo(
                id=model.get("id", ""),
                name=model.get("name", ""),
                provider=model.get("provider", ""),
                capabilities=model.get("capabilities", []),
                status=model.get("status", "unknown"),
                max_tokens=model.get("max_tokens", 0),
                cost_per_token=model.get("cost_per_token", 0.0),
                description=model.get("description")
            )
            for model in models
        ]

    except Exception as e:
        logger.error(f"Failed to list models: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Provider Management Endpoints
@router.get("/providers", response_model=List[Dict[str, Any]])
async def list_providers():
    """List all AI providers."""
    try:
        ai_layer = AIAbstractionLayer()
        providers = await ai_layer.get_providers()
        return providers

    except Exception as e:
        logger.error(f"Failed to list providers: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/providers/{provider_name}/configure")
async def configure_provider(
    provider_name: str,
    config: ProviderConfig
):
    """Configure an AI provider."""
    try:
        ai_layer = AIAbstractionLayer()
        await ai_layer.configure_provider(provider_name, config.dict())

        return {"success": True, "message": f"Provider {provider_name} configured successfully"}

    except Exception as e:
        logger.error(f"Failed to configure provider {provider_name}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Moderation Endpoints
@router.post("/moderate", response_model=ModerationResult)
async def moderate_content(request: ModerationRequest):
    """Moderate content using AI."""
    try:
        moderator = ContentModerator()
        result = await moderator.moderate(
            content=request.content,
            user_id=request.user_id,
            context=request.context,
            threshold=request.severity_threshold
        )

        return ModerationResult(
            flagged=result.get("flagged", False),
            categories=result.get("categories", {}),
            severity=result.get("severity", 0.0),
            action=result.get("action", "none"),
            reason=result.get("reason")
        )

    except Exception as e:
        logger.error(f"Content moderation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Monitoring Endpoints
@router.get("/metrics", response_model=MonitoringMetrics)
async def get_ai_metrics(
    start_time: Optional[datetime] = Query(None),
    end_time: Optional[datetime] = Query(None)
):
    """Get AI system metrics."""
    try:
        collector = MetricsCollector()

        if not start_time:
            from datetime import datetime
start_time = datetime.now()
datetime = datetime.now() - timedelta(hours=24)
        if not end_time:
            from datetime import datetime
end_time = datetime.now()
datetime = datetime.now()

        metrics = await collector.get_metrics(start_time, end_time)

        return MonitoringMetrics(
            total_requests=metrics.get("total_requests", 0),
            successful_requests=metrics.get("successful_requests", 0),
            failed_requests=metrics.get("failed_requests", 0),
            average_latency=metrics.get("average_latency", 0.0),
            total_cost=metrics.get("total_cost", 0.0),
            requests_per_minute=metrics.get("requests_per_minute", 0.0),
            error_rate=metrics.get("error_rate", 0.0)
        )

    except Exception as e:
        logger.error(f"Failed to get AI metrics: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/health")
async def ai_health_check():
    """Check AI system health."""
    try:
        ai_layer = AIAbstractionLayer()
        health = await ai_layer.health_check()

        return {
            "status": "healthy" if health.get("healthy", False) else "unhealthy",
            "providers": health.get("providers", {}),
            "models": health.get("models", {}),
            "timestamp": from datetime import datetime
datetime = datetime.now()
        }

    except Exception as e:
        logger.error(f"AI health check failed: {e}")
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": from datetime import datetime
datetime = datetime.now()
        }

# Helper functions
async def log_ai_request(request: AIRequestModel, response: Dict[str, Any]):
    """Log AI request for monitoring and analytics."""
    try:
        logger_instance = RequestLogger()
        await logger_instance.log_request(request.dict(), response)

    except Exception as e:
        logger.error(f"Failed to log AI request: {e}")

# Export router
__all__ = ["router"]
