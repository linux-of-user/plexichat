"""
AI Management WebUI Components
Web interface for managing AI providers, models, and monitoring.
"""

import asyncio
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
from fastapi import APIRouter, Request, Form, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path

from ..core.ai_abstraction_layer import AIAbstractionLayer, AIProvider, ModelCapability, ModelStatus

logger = logging.getLogger(__name__)

# Initialize templates
templates_dir = Path(__file__).parent / "templates"
templates_dir.mkdir(exist_ok=True)
templates = Jinja2Templates(directory=str(templates_dir))

# Initialize AI layer
ai_layer = AIAbstractionLayer()

# Create router
router = APIRouter(prefix="/ui/ai", tags=["AI Management UI"])

@router.get("/", response_class=HTMLResponse)
async def ai_dashboard(request: Request):
    """AI management dashboard."""
    try:
        # Get system health
        health = await ai_layer.health_check()
        
        # Get models
        models = list(ai_layer.models.values())
        
        # Get providers
        providers = ai_layer.providers
        
        # Get recent requests (last 10)
        recent_requests = ai_layer.request_history[-10:] if ai_layer.request_history else []
        
        context = {
            "request": request,
            "health": health,
            "models": models,
            "providers": providers,
            "recent_requests": recent_requests,
            "model_capabilities": [cap.value for cap in ModelCapability],
            "ai_providers": [provider.value for provider in AIProvider],
            "model_statuses": [status.value for status in ModelStatus]
        }
        
        return templates.TemplateResponse("ai_dashboard.html", context)
        
    except Exception as e:
        logger.error(f"AI dashboard error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/models", response_class=HTMLResponse)
async def models_management(request: Request):
    """AI models management page."""
    try:
        models = list(ai_layer.models.values())
        model_health = ai_layer.model_health
        
        context = {
            "request": request,
            "models": models,
            "model_health": model_health,
            "model_capabilities": [cap.value for cap in ModelCapability],
            "ai_providers": [provider.value for provider in AIProvider],
            "model_statuses": [status.value for status in ModelStatus]
        }
        
        return templates.TemplateResponse("ai_models.html", context)
        
    except Exception as e:
        logger.error(f"Models management error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/models/add")
async def add_model_form(
    request: Request,
    model_id: str = Form(...),
    model_name: str = Form(...),
    provider: str = Form(...),
    capabilities: List[str] = Form(...),
    max_tokens: int = Form(...),
    cost_per_1k_tokens: float = Form(...),
    context_window: int = Form(...),
    priority: int = Form(1),
    supports_streaming: bool = Form(False),
    supports_functions: bool = Form(False)
):
    """Add new AI model via form."""
    try:
        from ..core.ai_abstraction_layer import AIModel
        
        model = AIModel(
            id=model_id,
            name=model_name,
            provider=AIProvider(provider),
            capabilities=[ModelCapability(cap) for cap in capabilities],
            max_tokens=max_tokens,
            cost_per_1k_tokens=cost_per_1k_tokens,
            context_window=context_window,
            priority=priority,
            supports_streaming=supports_streaming,
            supports_functions=supports_functions
        )
        
        success = await ai_layer.add_model(model)
        if not success:
            raise HTTPException(status_code=400, detail="Failed to add model")
            
        return {"success": True, "message": f"Model {model_id} added successfully"}
        
    except Exception as e:
        logger.error(f"Add model form error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/models/{model_id}/delete")
async def delete_model_form(model_id: str):
    """Delete AI model via form."""
    try:
        success = await ai_layer.remove_model(model_id)
        if not success:
            raise HTTPException(status_code=404, detail="Model not found")
            
        return {"success": True, "message": f"Model {model_id} deleted successfully"}
        
    except Exception as e:
        logger.error(f"Delete model form error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/models/{model_id}/status")
async def update_model_status_form(model_id: str, status: str = Form(...)):
    """Update model status via form."""
    try:
        success = await ai_layer.update_model_status(model_id, ModelStatus(status))
        if not success:
            raise HTTPException(status_code=404, detail="Model not found")
            
        return {"success": True, "message": f"Model {model_id} status updated"}
        
    except Exception as e:
        logger.error(f"Update model status form error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/providers", response_class=HTMLResponse)
async def providers_management(request: Request):
    """AI providers management page."""
    try:
        providers = ai_layer.providers
        
        context = {
            "request": request,
            "providers": providers,
            "ai_providers": [provider.value for provider in AIProvider]
        }
        
        return templates.TemplateResponse("ai_providers.html", context)
        
    except Exception as e:
        logger.error(f"Providers management error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/providers/configure")
async def configure_provider_form(
    request: Request,
    provider: str = Form(...),
    api_key: str = Form(""),
    base_url: str = Form(""),
    enabled: bool = Form(False),
    organization: str = Form(""),
    timeout: int = Form(30),
    max_retries: int = Form(3)
):
    """Configure AI provider via form."""
    try:
        config = {
            "enabled": enabled,
            "timeout": timeout,
            "max_retries": max_retries
        }
        
        if api_key:
            config["api_key"] = api_key
        if base_url:
            config["base_url"] = base_url
        if organization:
            config["organization"] = organization
            
        success = await ai_layer.configure_provider(AIProvider(provider), config)
        if not success:
            raise HTTPException(status_code=400, detail="Failed to configure provider")
            
        return {"success": True, "message": f"Provider {provider} configured successfully"}
        
    except Exception as e:
        logger.error(f"Configure provider form error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/permissions", response_class=HTMLResponse)
async def permissions_management(request: Request):
    """AI permissions management page."""
    try:
        user_permissions = ai_layer.access_control.user_permissions
        admin_users = ai_layer.access_control.admin_users
        models = list(ai_layer.models.keys())
        
        context = {
            "request": request,
            "user_permissions": user_permissions,
            "admin_users": admin_users,
            "models": models,
            "model_capabilities": [cap.value for cap in ModelCapability]
        }
        
        return templates.TemplateResponse("ai_permissions.html", context)
        
    except Exception as e:
        logger.error(f"Permissions management error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/permissions/add")
async def add_permission_form(
    request: Request,
    user_id: str = Form(...),
    model_id: str = Form(...),
    capabilities: List[str] = Form(...)
):
    """Add user permission via form."""
    try:
        ai_layer.access_control.add_user_permission(
            user_id,
            model_id,
            [ModelCapability(cap) for cap in capabilities]
        )
        ai_layer.save_config()
        
        return {"success": True, "message": f"Permission added for user {user_id}"}
        
    except Exception as e:
        logger.error(f"Add permission form error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/monitoring", response_class=HTMLResponse)
async def ai_monitoring(request: Request):
    """AI monitoring and analytics page."""
    try:
        # Get health status
        health = await ai_layer.health_check()
        
        # Get usage statistics
        usage_stats = ai_layer.get_usage_stats()
        
        # Get model health
        model_health = ai_layer.model_health
        
        # Get recent activity
        recent_requests = ai_layer.request_history[-20:] if ai_layer.request_history else []
        recent_responses = ai_layer.response_history[-20:] if ai_layer.response_history else []
        
        # Calculate statistics
        total_requests = len(ai_layer.request_history)
        successful_requests = sum(1 for r in ai_layer.response_history if r.success)
        failed_requests = total_requests - successful_requests
        
        avg_latency = 0
        if ai_layer.response_history:
            avg_latency = sum(r.latency_ms for r in ai_layer.response_history) / len(ai_layer.response_history)
            
        total_cost = sum(r.cost for r in ai_layer.response_history)
        
        context = {
            "request": request,
            "health": health,
            "usage_stats": usage_stats,
            "model_health": model_health,
            "recent_requests": recent_requests,
            "recent_responses": recent_responses,
            "stats": {
                "total_requests": total_requests,
                "successful_requests": successful_requests,
                "failed_requests": failed_requests,
                "success_rate": (successful_requests / total_requests * 100) if total_requests > 0 else 0,
                "avg_latency": avg_latency,
                "total_cost": total_cost,
                "cache_size": len(ai_layer.request_cache)
            }
        }
        
        return templates.TemplateResponse("ai_monitoring.html", context)
        
    except Exception as e:
        logger.error(f"AI monitoring error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/test", response_class=HTMLResponse)
async def ai_test_interface(request: Request):
    """AI testing interface."""
    try:
        models = list(ai_layer.models.values())
        available_models = [m for m in models if m.status == ModelStatus.AVAILABLE]
        
        context = {
            "request": request,
            "models": available_models,
            "model_capabilities": [cap.value for cap in ModelCapability]
        }
        
        return templates.TemplateResponse("ai_test.html", context)
        
    except Exception as e:
        logger.error(f"AI test interface error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/test/request")
async def test_ai_request(
    request: Request,
    user_id: str = Form("test_user"),
    model_id: str = Form(...),
    prompt: str = Form(...),
    max_tokens: int = Form(100),
    temperature: float = Form(0.7),
    system_prompt: str = Form("")
):
    """Test AI request via form."""
    try:
        from ..core.ai_abstraction_layer import AIRequest
        
        ai_request = AIRequest(
            user_id=user_id,
            model_id=model_id,
            prompt=prompt,
            max_tokens=max_tokens,
            temperature=temperature,
            system_prompt=system_prompt if system_prompt else None
        )
        
        response = await ai_layer.process_request(ai_request)
        
        return {
            "success": response.success,
            "response": {
                "content": response.content,
                "usage": response.usage,
                "cost": response.cost,
                "latency_ms": response.latency_ms,
                "provider": response.provider,
                "cached": response.cached,
                "fallback_used": response.fallback_used,
                "error": response.error
            }
        }
        
    except Exception as e:
        logger.error(f"Test AI request error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/cache/clear")
async def clear_cache_form():
    """Clear AI cache via form."""
    try:
        ai_layer.clear_cache()
        return {"success": True, "message": "Cache cleared successfully"}
        
    except Exception as e:
        logger.error(f"Clear cache form error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
