"""
AI Provider Management API Endpoints
RESTful API endpoints for managing AI providers, models, and configurations.
"""

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from pydantic import BaseModel, Field
import uuid

from ..core.ai_abstraction_layer import AIAbstractionLayer, AIProvider, AIModel, ModelCapability, ModelStatus
from ..providers import ProviderStatus

logger = logging.getLogger(__name__)

# Initialize AI abstraction layer
ai_layer = AIAbstractionLayer()

router = APIRouter(prefix="/api/v1/ai", tags=["AI Provider Management"])

# Request/Response Models
class ProviderConfigRequest(BaseModel):
    provider: str = Field(..., description="Provider type")
    config: Dict[str, Any] = Field(..., description="Provider configuration")
    enabled: bool = Field(default=True, description="Enable provider")

class ModelRequest(BaseModel):
    id: str = Field(..., description="Model ID")
    name: str = Field(..., description="Model name")
    provider: str = Field(..., description="Provider type")
    capabilities: List[str] = Field(..., description="Model capabilities")
    max_tokens: int = Field(default=4096, description="Maximum tokens")
    cost_per_1k_tokens: float = Field(default=0.0, description="Cost per 1K tokens")
    context_window: int = Field(default=4096, description="Context window size")
    supports_streaming: bool = Field(default=True, description="Supports streaming")
    supports_functions: bool = Field(default=False, description="Supports function calling")
    priority: int = Field(default=1, description="Model priority")
    fallback_models: List[str] = Field(default_factory=list, description="Fallback models")

class UserPermissionRequest(BaseModel):
    user_id: str = Field(..., description="User ID")
    model_id: str = Field(..., description="Model ID")
    capabilities: List[str] = Field(..., description="Allowed capabilities")

# Provider Management Endpoints
@router.get("/providers")
async def list_providers():
    """List all AI providers and their status."""
    try:
        provider_status = await ai_layer.get_provider_status()
        provider_configs = ai_layer.providers
        
        providers = []
        for provider_type in AIProvider:
            config = provider_configs.get(provider_type, {})
            status = provider_status.get(provider_type, {})
            
            providers.append({
                "provider": provider_type,
                "enabled": config.get("enabled", False),
                "status": status.get("status", ProviderStatus.UNAVAILABLE),
                "health": status.get("health", {}),
                "models": status.get("models", []),
                "config": {k: v for k, v in config.items() if not k.endswith("_encrypted")}
            })
        
        return {"providers": providers}
        
    except Exception as e:
        logger.error(f"Failed to list providers: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to list providers: {str(e)}")

@router.post("/providers/configure")
async def configure_provider(request: ProviderConfigRequest):
    """Configure an AI provider."""
    try:
        provider = AIProvider(request.provider)
        config = request.config.copy()
        config["enabled"] = request.enabled
        
        success = await ai_layer.configure_provider(provider, config)
        
        if success:
            # Refresh provider instance
            await ai_layer.refresh_provider(provider)
            return {"status": "success", "message": f"Provider {provider} configured successfully"}
        else:
            raise HTTPException(status_code=500, detail="Failed to configure provider")
            
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid provider: {str(e)}")
    except Exception as e:
        logger.error(f"Provider configuration failed: {e}")
        raise HTTPException(status_code=500, detail=f"Provider configuration failed: {str(e)}")

@router.post("/providers/{provider}/refresh")
async def refresh_provider(provider: str):
    """Refresh/reinitialize a provider."""
    try:
        provider_enum = AIProvider(provider)
        success = await ai_layer.refresh_provider(provider_enum)
        
        if success:
            return {"status": "success", "message": f"Provider {provider} refreshed successfully"}
        else:
            raise HTTPException(status_code=500, detail="Failed to refresh provider")
            
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid provider: {str(e)}")
    except Exception as e:
        logger.error(f"Provider refresh failed: {e}")
        raise HTTPException(status_code=500, detail=f"Provider refresh failed: {str(e)}")

@router.get("/providers/{provider}/status")
async def get_provider_status(provider: str):
    """Get status of a specific provider."""
    try:
        provider_enum = AIProvider(provider)
        status = await ai_layer.get_provider_status(provider_enum)
        return status
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid provider: {str(e)}")
    except Exception as e:
        logger.error(f"Failed to get provider status: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get provider status: {str(e)}")

# Model Management Endpoints
@router.get("/models")
async def list_models(user_id: Optional[str] = None, capability: Optional[str] = None):
    """List available AI models."""
    try:
        if user_id and capability:
            capability_enum = ModelCapability(capability)
            models = ai_layer.get_available_models(user_id, capability_enum)
        else:
            models = list(ai_layer.models.values())
        
        model_data = []
        for model in models:
            health = ai_layer.get_model_health(model.id)
            model_data.append({
                "id": model.id,
                "name": model.name,
                "provider": model.provider,
                "capabilities": [cap.value for cap in model.capabilities],
                "max_tokens": model.max_tokens,
                "cost_per_1k_tokens": model.cost_per_1k_tokens,
                "context_window": model.context_window,
                "supports_streaming": model.supports_streaming,
                "supports_functions": model.supports_functions,
                "status": model.status,
                "priority": model.priority,
                "fallback_models": model.fallback_models,
                "health": health
            })
        
        return {"models": model_data}
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid capability: {str(e)}")
    except Exception as e:
        logger.error(f"Failed to list models: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to list models: {str(e)}")

@router.post("/models")
async def add_model(request: ModelRequest):
    """Add a new AI model."""
    try:
        model = AIModel(
            id=request.id,
            name=request.name,
            provider=AIProvider(request.provider),
            capabilities=[ModelCapability(cap) for cap in request.capabilities],
            max_tokens=request.max_tokens,
            cost_per_1k_tokens=request.cost_per_1k_tokens,
            context_window=request.context_window,
            supports_streaming=request.supports_streaming,
            supports_functions=request.supports_functions,
            priority=request.priority,
            fallback_models=request.fallback_models
        )
        
        success = await ai_layer.add_model(model)
        
        if success:
            return {"status": "success", "message": f"Model {request.id} added successfully"}
        else:
            raise HTTPException(status_code=500, detail="Failed to add model")
            
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid input: {str(e)}")
    except Exception as e:
        logger.error(f"Model addition failed: {e}")
        raise HTTPException(status_code=500, detail=f"Model addition failed: {str(e)}")

@router.delete("/models/{model_id}")
async def remove_model(model_id: str):
    """Remove an AI model."""
    try:
        success = await ai_layer.remove_model(model_id)
        
        if success:
            return {"status": "success", "message": f"Model {model_id} removed successfully"}
        else:
            raise HTTPException(status_code=404, detail="Model not found")
            
    except Exception as e:
        logger.error(f"Model removal failed: {e}")
        raise HTTPException(status_code=500, detail=f"Model removal failed: {str(e)}")

@router.patch("/models/{model_id}/status")
async def update_model_status(model_id: str, status: str):
    """Update model status."""
    try:
        status_enum = ModelStatus(status)
        success = await ai_layer.update_model_status(model_id, status_enum)
        
        if success:
            return {"status": "success", "message": f"Model {model_id} status updated to {status}"}
        else:
            raise HTTPException(status_code=404, detail="Model not found")
            
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid status: {str(e)}")
    except Exception as e:
        logger.error(f"Model status update failed: {e}")
        raise HTTPException(status_code=500, detail=f"Model status update failed: {str(e)}")

# Ollama-specific endpoints
@router.get("/ollama/models")
async def list_ollama_models():
    """List available Ollama models."""
    try:
        models = await ai_layer.discover_ollama_models()
        return {"models": models}
        
    except Exception as e:
        logger.error(f"Failed to list Ollama models: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to list Ollama models: {str(e)}")

@router.post("/ollama/models/{model_id}/pull")
async def pull_ollama_model(model_id: str, background_tasks: BackgroundTasks):
    """Pull an Ollama model."""
    try:
        # Run pull in background
        background_tasks.add_task(_pull_ollama_model_background, model_id)
        
        return {
            "status": "success", 
            "message": f"Started pulling Ollama model: {model_id}"
        }
        
    except Exception as e:
        logger.error(f"Ollama model pull initiation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Ollama model pull initiation failed: {str(e)}")

async def _pull_ollama_model_background(model_id: str):
    """Background task for pulling Ollama model."""
    try:
        success = await ai_layer.pull_ollama_model(model_id)
        if success:
            logger.info(f"Successfully pulled Ollama model: {model_id}")
        else:
            logger.warning(f"Failed to pull Ollama model: {model_id}")
    except Exception as e:
        logger.error(f"Background Ollama model pull failed: {e}")

@router.delete("/ollama/models/{model_id}")
async def delete_ollama_model(model_id: str):
    """Delete an Ollama model."""
    try:
        success = await ai_layer.delete_ollama_model(model_id)
        
        if success:
            return {"status": "success", "message": f"Ollama model {model_id} deleted successfully"}
        else:
            raise HTTPException(status_code=500, detail="Failed to delete Ollama model")
            
    except Exception as e:
        logger.error(f"Ollama model deletion failed: {e}")
        raise HTTPException(status_code=500, detail=f"Ollama model deletion failed: {str(e)}")

# User Permission Management
@router.post("/permissions")
async def add_user_permission(request: UserPermissionRequest):
    """Add user permission for AI model access."""
    try:
        capabilities = [ModelCapability(cap) for cap in request.capabilities]
        ai_layer.access_control.add_user_permission(
            request.user_id, 
            request.model_id, 
            capabilities
        )
        
        return {"status": "success", "message": "User permission added successfully"}
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid capability: {str(e)}")
    except Exception as e:
        logger.error(f"Permission addition failed: {e}")
        raise HTTPException(status_code=500, detail=f"Permission addition failed: {str(e)}")

@router.get("/permissions/{user_id}")
async def get_user_permissions(user_id: str):
    """Get user permissions."""
    try:
        permissions = ai_layer.access_control.user_permissions.get(user_id, {})
        return {"user_id": user_id, "permissions": permissions}
        
    except Exception as e:
        logger.error(f"Failed to get user permissions: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get user permissions: {str(e)}")

# System Health and Statistics
@router.get("/health")
async def health_check():
    """Comprehensive AI system health check."""
    try:
        health = await ai_layer.health_check()
        return health
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return {
            "overall_status": "error",
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

@router.get("/stats")
async def get_system_stats():
    """Get AI system statistics."""
    try:
        return {
            "total_models": len(ai_layer.models),
            "total_providers": len(ai_layer.providers),
            "active_providers": len(ai_layer.provider_instances),
            "request_cache_size": len(ai_layer.request_cache),
            "request_history_size": len(ai_layer.request_history),
            "response_history_size": len(ai_layer.response_history),
            "model_health": ai_layer.model_health,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to get system stats: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get system stats: {str(e)}")

@router.post("/cache/clear")
async def clear_cache():
    """Clear AI request cache."""
    try:
        ai_layer.clear_cache()
        return {"status": "success", "message": "AI request cache cleared"}
        
    except Exception as e:
        logger.error(f"Cache clear failed: {e}")
        raise HTTPException(status_code=500, detail=f"Cache clear failed: {str(e)}")
