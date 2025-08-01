# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from ..core.ai_abstraction_layer import ()


    AI,
    API,
    AIAbstractionLayer,
    AIModel,
    AIProvider,
    AIRequest,
    APIRouter,
    BaseModel,
    Comprehensive,
    Endpoints,
    Field,
    HTTPException,
    Management,
    ModelCapability,
    ModelStatus,
    """,
    and,
    fastapi,
    for,
    from,
    import,
    managing,
    models,
    providers,
    pydantic,
    requests.,
)

logger = logging.getLogger(__name__)

# Initialize AI abstraction layer
ai_layer = AIAbstractionLayer()

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
    cached: bool = False
    fallback_used: bool = False
    fallback_model: Optional[str] = None

class ModelConfigModel(BaseModel):
    """API model for model configuration."""
    id: str
    name: str
    provider: AIProvider
    capabilities: List[ModelCapability]
    max_tokens: int
    cost_per_1k_tokens: float
    context_window: int
    supports_streaming: bool = True
    supports_functions: bool = False
    priority: int = Field(default=1, ge=1, le=10)
    rate_limit_rpm: int = Field(default=60, ge=1)
    rate_limit_tpm: int = Field(default=90000, ge=1000)
    fallback_models: List[str] = []
    custom_endpoint: Optional[str] = None

class ProviderConfigModel(BaseModel):
    """API model for provider configuration."""
    provider: AIProvider
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    enabled: bool = True
    organization: Optional[str] = None
    timeout: int = Field(default=30, ge=5, le=300)
    max_retries: int = Field(default=3, ge=0, le=10)

class UserPermissionModel(BaseModel):
    """API model for user permissions."""
    user_id: str
    model_id: str
    capabilities: List[ModelCapability]

class HealthCheckResponse(BaseModel):
    """API model for health check response."""
    overall_status: str
    total_models: int
    available_models: int
    unavailable_models: int
    providers: Dict[str, Dict[str, int]]
    models: Dict[str, Dict[str, Any]]

# Create API router
router = APIRouter(prefix="/api/v1/ai", tags=["AI Management"])

# AI Request Endpoints
@router.post("/chat", response_model=AIResponseModel)
async def chat_completion(request: AIRequestModel):
    """Process AI chat completion request."""
    try:
        ai_request = AIRequest()
            user_id=request.user_id,
            model_id=request.model_id,
            prompt=request.prompt,
            max_tokens=request.max_tokens,
            temperature=request.temperature,
            stream=request.stream,
            functions=request.functions,
            system_prompt=request.system_prompt,
            context=request.context or [],
            metadata=request.metadata or {},
            priority=request.priority,
            timeout_seconds=request.timeout_seconds
        )

        response = await ai_layer.process_request(ai_request)

        return AIResponseModel()
            request_id=response.request_id,
            model_id=response.model_id,
            content=response.content,
            usage=response.usage,
            cost=response.cost,
            latency_ms=response.latency_ms,
            provider=response.provider,
            timestamp=response.timestamp,
            success=response.success,
            error=response.error,
            cached=response.cached,
            fallback_used=response.fallback_used,
            fallback_model=response.fallback_model
        )

    except Exception as e:
        logger.error(f"Chat completion error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/models", response_model=List[ModelConfigModel])
async def get_models(user_id: Optional[str] = None, capability: Optional[ModelCapability] = None):
    """Get available AI models."""
    try:
        if user_id:
            models = ai_layer.get_available_models(user_id, capability)
        else:
            models = list(ai_layer.models.values())

        return [
            ModelConfigModel()
                id=model.id,
                name=model.name,
                provider=model.provider,
                capabilities=model.capabilities,
                max_tokens=model.max_tokens,
                cost_per_1k_tokens=model.cost_per_1k_tokens,
                context_window=model.context_window,
                supports_streaming=model.supports_streaming,
                supports_functions=model.supports_functions,
                priority=model.priority,
                rate_limit_rpm=model.rate_limit_rpm,
                rate_limit_tpm=model.rate_limit_tpm,
                fallback_models=model.fallback_models,
                custom_endpoint=model.custom_endpoint
            )
            for model in models
        ]

    except Exception as e:
        logger.error(f"Get models error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/models")
async def add_model(model: ModelConfigModel):
    """Add new AI model."""
    try:
        ai_model = AIModel()
            id=model.id,
            name=model.name,
            provider=model.provider,
            capabilities=model.capabilities,
            max_tokens=model.max_tokens,
            cost_per_1k_tokens=model.cost_per_1k_tokens,
            context_window=model.context_window,
            supports_streaming=model.supports_streaming,
            supports_functions=model.supports_functions,
            priority=model.priority,
            rate_limit_rpm=model.rate_limit_rpm,
            rate_limit_tpm=model.rate_limit_tpm,
            fallback_models=model.fallback_models,
            custom_endpoint=model.custom_endpoint
        )

        success = await ai_layer.add_model(ai_model)
        if not success:
            raise HTTPException(status_code=400, detail="Failed to add model")

        return {"message": f"Model {model.id} added successfully"}

    except Exception as e:
        logger.error(f"Add model error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/models/{model_id}")
async def remove_model(model_id: str):
    """Remove AI model."""
    try:
        success = await ai_layer.remove_model(model_id)
        if not success:
            raise HTTPException(status_code=404, detail="Model not found")

        return {"message": f"Model {model_id} removed successfully"}

    except Exception as e:
        logger.error(f"Remove model error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.patch("/models/{model_id}/status")
async def update_model_status(model_id: str, status: ModelStatus):
    """Update model status."""
    try:
        success = await ai_layer.update_model_status(model_id, status)
        if not success:
            raise HTTPException(status_code=404, detail="Model not found")

        return {"message": f"Model {model_id} status updated to {status}"}

    except Exception as e:
        logger.error(f"Update model status error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Provider Management Endpoints
@router.post("/providers/configure")
async def configure_provider(config: ProviderConfigModel):
    """Configure AI provider."""
    try:
        provider_config = {
            "enabled": config.enabled,
            "timeout": config.timeout,
            "max_retries": config.max_retries
        }

        if config.api_key:
            provider_config["api_key"] = config.api_key
        if config.base_url:
            provider_config["base_url"] = config.base_url
        if config.organization:
            provider_config["organization"] = config.organization

        success = await ai_layer.configure_provider(config.provider, provider_config)
        if not success:
            raise HTTPException(status_code=400, detail="Failed to configure provider")

        return {"message": f"Provider {config.provider} configured successfully"}

    except Exception as e:
        logger.error(f"Configure provider error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/providers")
async def get_providers():
    """Get provider configurations."""
    try:
        providers = {}
        for provider, config in ai_layer.providers.items():
            # Don't expose encrypted API keys
            safe_config = {k: v for k, v in config.items() if k != "api_key_encrypted"}
            safe_config["has_api_key"] = bool(config.get("api_key_encrypted"))
            providers[provider] = safe_config

        return providers

    except Exception as e:
        logger.error(f"Get providers error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Permission Management Endpoints
@router.post("/permissions")
async def add_user_permission(permission: UserPermissionModel):
    """Add user permission for AI model."""
    try:
        ai_layer.access_control.add_user_permission()
            permission.user_id,
            permission.model_id,
            permission.capabilities
        )
        ai_layer.save_config()

        return {"message": f"Permission added for user {permission.user_id}"}

    except Exception as e:
        logger.error(f"Add permission error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/permissions/{user_id}")
async def get_user_permissions(user_id: str):
    """Get user permissions."""
    try:
        permissions = ai_layer.access_control.user_permissions.get(user_id, {})
        return {"user_id": user_id, "permissions": permissions}

    except Exception as e:
        logger.error(f"Get permissions error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Health and Monitoring Endpoints
@router.get("/health", response_model=HealthCheckResponse)
async def health_check():
    """Get AI system health status."""
    try:
        health = await ai_layer.health_check()
        return HealthCheckResponse(**health)

    except Exception as e:
        logger.error(f"Health check error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/usage/{user_id}")
async def get_user_usage(user_id: str):
    """Get user usage statistics."""
    try:
        usage = ai_layer.get_usage_stats(user_id)
        return {"user_id": user_id, "usage": usage}

    except Exception as e:
        logger.error(f"Get usage error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/cache/clear")
async def clear_cache():
    """Clear AI request cache."""
    try:
        ai_layer.clear_cache()
        return {"message": "Cache cleared successfully"}

    except Exception as e:
        logger.error(f"Clear cache error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/stats")
async def get_system_stats():
    """Get AI system statistics."""
    try:
        stats = {
            "total_models": len(ai_layer.models),
            "total_requests": len(ai_layer.request_history),
            "total_responses": len(ai_layer.response_history),
            "cache_size": len(ai_layer.request_cache),
            "model_health": ai_layer.model_health,
            "providers": {
                provider: {"enabled": config.get("enabled", False)}
                for provider, config in ai_layer.providers.items()
            }
        }

        return stats

    except Exception as e:
        logger.error(f"Get stats error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
