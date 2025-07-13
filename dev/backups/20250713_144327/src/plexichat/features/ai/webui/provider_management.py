import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional

from ..core.ai_abstraction_layer import (


    AI,
    AIAbstractionLayer,
    AIModel,
    AIProvider,
    FastAPI,
    Form,
    HTMLResponse,
    Jinja2Templates,
    Management,
    ModelCapability,
    ModelStatus,
    Provider,
    ProviderStatus,
    RedirectResponse,
    Request,
    Web,
    WebUI,
    """,
    ..providers,
    and,
    configurations.,
    fastapi,
    fastapi.responses,
    fastapi.templating,
    for,
    from,
    import,
    interface,
    managing,
    models,
    providers,
)

logger = logging.getLogger(__name__)

# Initialize AI abstraction layer
ai_layer = AIAbstractionLayer()

# Initialize templates
templates = Jinja2Templates(directory="src/plexichat/ai/webui/templates")

class AIProviderWebUI:
    """Web interface for AI provider management."""

    def __init__(self, app: FastAPI):
        self.app = app
        self.setup_routes()

    def setup_routes(self):
        """Setup WebUI routes."""

        @self.app.get("/ui/ai", response_class=HTMLResponse)
        async def ai_dashboard(request: Request):
            """AI management dashboard."""
            try:
                provider_status = await ai_layer.get_provider_status()
                models = list(ai_layer.models.values())
                health = await ai_layer.health_check()

                return templates.TemplateResponse("ai_dashboard.html", {
                    "request": request,
                    "providers": provider_status,
                    "models": models,
                    "health": health,
                    "total_models": len(models),
                    "active_providers": len(ai_layer.provider_instances)
                })

            except Exception as e:
                logger.error(f"AI dashboard error: {e}")
                return templates.TemplateResponse("error.html", {
                    "request": request,
                    "error": f"Failed to load AI dashboard: {str(e)}"
                })

        @self.app.get("/ui/ai/providers", response_class=HTMLResponse)
        async def providers_page(request: Request):
            """AI providers management page."""
            try:
                provider_status = await ai_layer.get_provider_status()
                provider_configs = ai_layer.providers

                providers_data = []
                for provider_type in AIProvider:
                    config = provider_configs.get(provider_type, {})
                    status = provider_status.get(provider_type, {})

                    providers_data.append({
                        "provider": provider_type,
                        "enabled": config.get("enabled", False),
                        "status": status.get("status", ProviderStatus.UNAVAILABLE),
                        "health": status.get("health", {}),
                        "models": status.get("models", []),
                        "config": {k: v for k, v in config.items() if not k.endswith("_encrypted")}
                    })

                return templates.TemplateResponse("ai_providers.html", {
                    "request": request,
                    "providers": providers_data,
                    "provider_types": [p.value for p in AIProvider]
                })

            except Exception as e:
                logger.error(f"Providers page error: {e}")
                return templates.TemplateResponse("error.html", {
                    "request": request,
                    "error": f"Failed to load providers page: {str(e)}"
                })

        @self.app.post("/ui/ai/providers/configure")
        async def configure_provider(
            request: Request,
            provider: str = Form(...),
            enabled: bool = Form(False),
            api_key: Optional[str] = Form(None),
            base_url: Optional[str] = Form(None),
            timeout: Optional[int] = Form(None),
            max_retries: Optional[int] = Form(None)
        ):
            """Configure AI provider."""
            try:
                provider_enum = AIProvider(provider)

                # Get current config
                current_config = ai_layer.providers.get(provider_enum, {})
                config = current_config.copy()

                # Update config
                config["enabled"] = enabled
                if api_key:
                    config["api_key"] = api_key
                if base_url:
                    config["base_url"] = base_url
                if timeout:
                    config["timeout"] = timeout
                if max_retries:
                    config["max_retries"] = max_retries

                success = await ai_layer.configure_provider(provider_enum, config)

                if success:
                    # Refresh provider instance
                    await ai_layer.refresh_provider(provider_enum)
                    return RedirectResponse(url="/ui/ai/providers?success=configured", status_code=303)
                else:
                    return RedirectResponse(url="/ui/ai/providers?error=config_failed", status_code=303)

            except ValueError:
                return RedirectResponse(url="/ui/ai/providers?error=invalid_provider", status_code=303)
            except Exception as e:
                logger.error(f"Provider configuration error: {e}")
                return RedirectResponse(url="/ui/ai/providers?error=config_error", status_code=303)

        @self.app.get("/ui/ai/models", response_class=HTMLResponse)
        async def models_page(request: Request):
            """AI models management page."""
            try:
                models = list(ai_layer.models.values())
                model_health = ai_layer.model_health

                models_data = []
                for model in models:
                    health = model_health.get(model.id, {})
                    models_data.append({
                        "model": model,
                        "health": health,
                        "capabilities": [cap.value for cap in model.capabilities]
                    })

                return templates.TemplateResponse("ai_models.html", {
                    "request": request,
                    "models": models_data,
                    "provider_types": [p.value for p in AIProvider],
                    "capabilities": [c.value for c in ModelCapability],
                    "statuses": [s.value for s in ModelStatus]
                })

            except Exception as e:
                logger.error(f"Models page error: {e}")
                return templates.TemplateResponse("error.html", {
                    "request": request,
                    "error": f"Failed to load models page: {str(e)}"
                })

        @self.app.post("/ui/ai/models/add")
        async def add_model(
            request: Request,
            model_id: str = Form(...),
            name: str = Form(...),
            provider: str = Form(...),
            capabilities: str = Form(...),
            max_tokens: int = Form(4096),
            cost_per_1k_tokens: float = Form(0.0),
            context_window: int = Form(4096),
            supports_streaming: bool = Form(False),
            supports_functions: bool = Form(False),
            priority: int = Form(1)
        ):
            """Add new AI model."""
            try:
                capabilities_list = [ModelCapability(cap.strip()) for cap in capabilities.split(",")]

                model = AIModel(
                    id=model_id,
                    name=name,
                    provider=AIProvider(provider),
                    capabilities=capabilities_list,
                    max_tokens=max_tokens,
                    cost_per_1k_tokens=cost_per_1k_tokens,
                    context_window=context_window,
                    supports_streaming=supports_streaming,
                    supports_functions=supports_functions,
                    priority=priority
                )

                success = await ai_layer.add_model(model)

                if success:
                    return RedirectResponse(url="/ui/ai/models?success=added", status_code=303)
                else:
                    return RedirectResponse(url="/ui/ai/models?error=add_failed", status_code=303)

            except ValueError as e:
                return RedirectResponse(url=f"/ui/ai/models?error=invalid_input&details={str(e)}", status_code=303)
            except Exception as e:
                logger.error(f"Model addition error: {e}")
                return RedirectResponse(url="/ui/ai/models?error=add_error", status_code=303)

        @self.app.post("/ui/ai/models/{model_id}/delete")
        async def delete_model(request: Request, model_id: str):
            """Delete AI model."""
            try:
                success = await ai_layer.remove_model(model_id)

                if success:
                    return RedirectResponse(url="/ui/ai/models?success=deleted", status_code=303)
                else:
                    return RedirectResponse(url="/ui/ai/models?error=not_found", status_code=303)

            except Exception as e:
                logger.error(f"Model deletion error: {e}")
                return RedirectResponse(url="/ui/ai/models?error=delete_error", status_code=303)

        @self.app.get("/ui/ai/ollama", response_class=HTMLResponse)
        async def ollama_page(request: Request):
            """Ollama models management page."""
            try:
                available_models = await ai_layer.discover_ollama_models()

                return templates.TemplateResponse("ai_ollama.html", {
                    "request": request,
                    "available_models": available_models,
                    "ollama_enabled": ai_layer.providers.get(AIProvider.OLLAMA, {}).get("enabled", False)
                })

            except Exception as e:
                logger.error(f"Ollama page error: {e}")
                return templates.TemplateResponse("error.html", {
                    "request": request,
                    "error": f"Failed to load Ollama page: {str(e)}"
                })

        @self.app.post("/ui/ai/ollama/pull")
        async def pull_ollama_model(request: Request, model_id: str = Form(...)):
            """Pull Ollama model."""
            try:
                # Start pull in background
                asyncio.create_task(ai_layer.pull_ollama_model(model_id))

                return RedirectResponse(url=f"/ui/ai/ollama?success=pulling&model={model_id}", status_code=303)

            except Exception as e:
                logger.error(f"Ollama pull error: {e}")
                return RedirectResponse(url="/ui/ai/ollama?error=pull_error", status_code=303)

        @self.app.post("/ui/ai/ollama/{model_id}/delete")
        async def delete_ollama_model(request: Request, model_id: str):
            """Delete Ollama model."""
            try:
                success = await ai_layer.delete_ollama_model(model_id)

                if success:
                    return RedirectResponse(url="/ui/ai/ollama?success=deleted", status_code=303)
                else:
                    return RedirectResponse(url="/ui/ai/ollama?error=delete_failed", status_code=303)

            except Exception as e:
                logger.error(f"Ollama deletion error: {e}")
                return RedirectResponse(url="/ui/ai/ollama?error=delete_error", status_code=303)

        @self.app.get("/ui/ai/health", response_class=HTMLResponse)
        async def health_page(request: Request):
            """AI system health monitoring page."""
            try:
                health = await ai_layer.health_check()
                usage_stats = ai_layer.get_usage_stats()

                return templates.TemplateResponse("ai_health.html", {
                    "request": request,
                    "health": health,
                    "usage_stats": usage_stats,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                })

            except Exception as e:
                logger.error(f"Health page error: {e}")
                return templates.TemplateResponse("error.html", {
                    "request": request,
                    "error": f"Failed to load health page: {str(e)}"
                })

        @self.app.get("/api/v1/ai/health/live")
        async def live_health_check():
            """Live health check endpoint for AJAX updates."""
            try:
                health = await ai_layer.health_check()
                return {
                    "status": "success",
                    "health": health,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }

            except Exception as e:
                logger.error(f"Live health check error: {e}")
                return {
                    "status": "error",
                    "error": str(e),
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }

def setup_ai_webui(app: FastAPI):
    """Setup AI management WebUI."""
    return AIProviderWebUI(app)
