"""
Ollama Provider Implementation
Comprehensive Ollama integration with model management and local inference.
"""

import json
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, AsyncGenerator, Dict, List, Optional

from .base_provider import AIRequest, AIResponse, BaseAIProvider, ProviderConfig, ProviderStatus

logger = logging.getLogger(__name__)

@dataclass
class OllamaConfig(ProviderConfig):
    """Ollama-specific configuration."""
    auto_pull_models: bool = True
    model_cache_path: str = "data/ollama_models"
    gpu_enabled: bool = True
    max_concurrent_requests: int = 4
    keep_alive: str = "5m"
    
    def __post_init__(self):
        super().__post_init__()
        self.provider_type = "ollama"

@dataclass
class OllamaModel:
    """Ollama model information."""
    name: str
    tag: str
    size: int
    digest: str
    modified_at: datetime
    details: Dict[str, Any]
    
    @classmethod
    def from_api_response(cls, data: Dict[str, Any]) -> 'OllamaModel':
        """Create from Ollama API response."""
        return cls(
            name=data.get("name", ""),
            tag=data.get("tag", "latest"),
            size=data.get("size", 0),
            digest=data.get("digest", ""),
            modified_at=datetime.fromisoformat(data.get("modified_at", datetime.now().isoformat())),
            details=data.get("details", {})
        )

class OllamaProvider(BaseAIProvider):
    """Ollama provider with comprehensive model management."""
    
    def __init__(self, config: OllamaConfig):
        super().__init__(config)
        self.config: OllamaConfig = config
        self.available_models: List[OllamaModel] = []
        self.concurrent_requests = 0
        self.model_cache = {}
        
    async def _test_connection(self) -> bool:
        """Test Ollama connection."""
        try:
            async with self.session.get(f"{self.config.base_url}/api/tags") as response:
                if response.status == 200:
                    data = await response.json()
                    self.available_models = [
                        OllamaModel.from_api_response(model) 
                        for model in data.get("models", [])
                    ]
                    logger.info(f"Ollama connected with {len(self.available_models)} models")
                    return True
                else:
                    logger.error(f"Ollama connection failed: {response.status}")
                    return False
        except Exception as e:
            logger.error(f"Ollama connection test failed: {e}")
            return False
    
    async def generate(self, request: AIRequest) -> AIResponse:
        """Generate response using Ollama."""
        start_time = time.time()
        
        if not await self.check_rate_limit(request.model_id):
            return AIResponse(
                request_id=request.request_id or "",
                model_id=request.model_id,
                content="",
                usage={},
                cost=0.0,
                latency_ms=0,
                provider="ollama",
                timestamp=datetime.now(timezone.utc),
                success=False,
                error="Rate limit exceeded"
            )
        
        if self.concurrent_requests >= self.config.max_concurrent_requests:
            return AIResponse(
                request_id=request.request_id or "",
                model_id=request.model_id,
                content="",
                usage={},
                cost=0.0,
                latency_ms=0,
                provider="ollama",
                timestamp=datetime.now(timezone.utc),
                success=False,
                error="Max concurrent requests exceeded"
            )
        
        self.concurrent_requests += 1
        
        try:
            # Ensure model is available
            if not await self._ensure_model_available(request.model_id):
                raise Exception(f"Model {request.model_id} not available")
            
            # Build prompt
            full_prompt = self._build_prompt(request)
            
            # Prepare request
            payload = {
                "model": request.model_id,
                "prompt": full_prompt,
                "stream": False,
                "options": {
                    "temperature": request.temperature,
                    "num_predict": request.max_tokens or -1
                },
                "keep_alive": self.config.keep_alive
            }
            
            # Make request
            async with self.session.post(
                f"{self.config.base_url}/api/generate",
                json=payload
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    latency_ms = int((time.time() - start_time) * 1000)
                    
                    return AIResponse(
                        request_id=request.request_id or "",
                        model_id=request.model_id,
                        content=data.get("response", ""),
                        usage={
                            "prompt_tokens": data.get("prompt_eval_count", 0),
                            "completion_tokens": data.get("eval_count", 0),
                            "total_tokens": data.get("prompt_eval_count", 0) + data.get("eval_count", 0)
                        },
                        cost=0.0,  # Ollama is free
                        latency_ms=latency_ms,
                        provider="ollama",
                        timestamp=datetime.now(timezone.utc),
                        metadata={
                            "model": data.get("model", ""),
                            "done": data.get("done", False),
                            "total_duration": data.get("total_duration", 0),
                            "load_duration": data.get("load_duration", 0),
                            "prompt_eval_duration": data.get("prompt_eval_duration", 0),
                            "eval_duration": data.get("eval_duration", 0)
                        }
                    )
                else:
                    error_text = await response.text()
                    raise Exception(f"Ollama API error {response.status}: {error_text}")
                    
        except Exception as e:
            logger.error(f"Ollama generation failed: {e}")
            return AIResponse(
                request_id=request.request_id or "",
                model_id=request.model_id,
                content="",
                usage={},
                cost=0.0,
                latency_ms=int((time.time() - start_time) * 1000),
                provider="ollama",
                timestamp=datetime.now(timezone.utc),
                success=False,
                error=str(e)
            )
        finally:
            self.concurrent_requests -= 1
    
    async def stream_generate(self, request: AIRequest) -> AsyncGenerator[str, None]:
        """Generate streaming response using Ollama."""
        if not await self.check_rate_limit(request.model_id):
            yield f"data: {json.dumps({'error': 'Rate limit exceeded'})}\n\n"
            return
        
        if self.concurrent_requests >= self.config.max_concurrent_requests:
            yield f"data: {json.dumps({'error': 'Max concurrent requests exceeded'})}\n\n"
            return
        
        self.concurrent_requests += 1
        
        try:
            # Ensure model is available
            if not await self._ensure_model_available(request.model_id):
                yield f"data: {json.dumps({'error': f'Model {request.model_id} not available'})}\n\n"
                return
            
            # Build prompt
            full_prompt = self._build_prompt(request)
            
            # Prepare request
            payload = {
                "model": request.model_id,
                "prompt": full_prompt,
                "stream": True,
                "options": {
                    "temperature": request.temperature,
                    "num_predict": request.max_tokens or -1
                },
                "keep_alive": self.config.keep_alive
            }
            
            # Make streaming request
            async with self.session.post(
                f"{self.config.base_url}/api/generate",
                json=payload
            ) as response:
                if response.status == 200:
                    async for line in response.content:
                        if line:
                            try:
                                data = json.loads(line.decode('utf-8'))
                                if "response" in data:
                                    yield f"data: {json.dumps({'content': data['response']})}\n\n"
                                if data.get("done", False):
                                    yield f"data: {json.dumps({'done': True})}\n\n"
                                    break
                            except json.JSONDecodeError:
                                continue
                else:
                    error_text = await response.text()
                    yield f"data: {json.dumps({'error': f'Ollama API error {response.status}: {error_text}'})}\n\n"
                    
        except Exception as e:
            logger.error(f"Ollama streaming failed: {e}")
            yield f"data: {json.dumps({'error': str(e)})}\n\n"
        finally:
            self.concurrent_requests -= 1
    
    def _build_prompt(self, request: AIRequest) -> str:
        """Build full prompt from request."""
        full_prompt = ""
        
        if request.system_prompt:
            full_prompt += f"System: {request.system_prompt}\n\n"
        
        if request.context:
            for msg in request.context:
                role = msg.get("role", "user")
                content = msg.get("content", "")
                full_prompt += f"{role.title()}: {content}\n\n"
        
        full_prompt += f"User: {request.prompt}\n\nAssistant:"
        return full_prompt

    async def get_available_models(self) -> List[Dict[str, Any]]:
        """Get list of available models."""
        try:
            async with self.session.get(f"{self.config.base_url}/api/tags") as response:
                if response.status == 200:
                    data = await response.json()
                    models = []
                    for model_data in data.get("models", []):
                        models.append({
                            "id": model_data.get("name", ""),
                            "name": model_data.get("name", ""),
                            "size": model_data.get("size", 0),
                            "digest": model_data.get("digest", ""),
                            "modified_at": model_data.get("modified_at", ""),
                            "details": model_data.get("details", {}),
                            "provider": "ollama"
                        })
                    return models
                else:
                    logger.error(f"Failed to get Ollama models: {response.status}")
                    return []
        except Exception as e:
            logger.error(f"Failed to get Ollama models: {e}")
            return []

    async def _ensure_model_available(self, model_id: str) -> bool:
        """Ensure model is available, pull if necessary."""
        # Check if model exists
        models = await self.get_available_models()
        model_exists = any(model["id"] == model_id for model in models)

        if model_exists:
            return True

        if not self.config.auto_pull_models:
            logger.warning(f"Model {model_id} not available and auto-pull disabled")
            return False

        # Try to pull model
        logger.info(f"Pulling model {model_id}...")
        return await self.pull_model(model_id)

    async def pull_model(self, model_id: str) -> bool:
        """Pull a model from Ollama registry."""
        try:
            payload = {"name": model_id}

            async with self.session.post(
                f"{self.config.base_url}/api/pull",
                json=payload
            ) as response:
                if response.status == 200:
                    # Stream the pull progress
                    async for line in response.content:
                        if line:
                            try:
                                data = json.loads(line.decode('utf-8'))
                                status = data.get("status", "")
                                if "completed" in status.lower():
                                    logger.info(f"Model {model_id} pulled successfully")
                                    return True
                                elif "error" in status.lower():
                                    logger.error(f"Failed to pull model {model_id}: {status}")
                                    return False
                            except json.JSONDecodeError:
                                continue
                    return True
                else:
                    error_text = await response.text()
                    logger.error(f"Failed to pull model {model_id}: {response.status} - {error_text}")
                    return False

        except Exception as e:
            logger.error(f"Failed to pull model {model_id}: {e}")
            return False

    async def delete_model(self, model_id: str) -> bool:
        """Delete a model from Ollama."""
        try:
            payload = {"name": model_id}

            async with self.session.delete(
                f"{self.config.base_url}/api/delete",
                json=payload
            ) as response:
                if response.status == 200:
                    logger.info(f"Model {model_id} deleted successfully")
                    return True
                else:
                    error_text = await response.text()
                    logger.error(f"Failed to delete model {model_id}: {response.status} - {error_text}")
                    return False

        except Exception as e:
            logger.error(f"Failed to delete model {model_id}: {e}")
            return False

    async def get_model_info(self, model_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a model."""
        try:
            payload = {"name": model_id}

            async with self.session.post(
                f"{self.config.base_url}/api/show",
                json=payload
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        "name": data.get("modelfile", ""),
                        "parameters": data.get("parameters", ""),
                        "template": data.get("template", ""),
                        "details": data.get("details", {}),
                        "model_info": data.get("model_info", {})
                    }
                else:
                    logger.error(f"Failed to get model info for {model_id}: {response.status}")
                    return None

        except Exception as e:
            logger.error(f"Failed to get model info for {model_id}: {e}")
            return None

    async def health_check(self) -> Dict[str, Any]:
        """Perform comprehensive health check."""
        health_info = {
            "status": self.status.value,
            "available": self.status == ProviderStatus.AVAILABLE,
            "models_count": len(self.available_models),
            "concurrent_requests": self.concurrent_requests,
            "max_concurrent": self.config.max_concurrent_requests,
            "base_url": self.config.base_url,
            "gpu_enabled": self.config.gpu_enabled,
            "auto_pull_models": self.config.auto_pull_models
        }

        try:
            # Test basic connectivity
            async with self.session.get(f"{self.config.base_url}/api/tags") as response:
                health_info["api_accessible"] = response.status == 200
                if response.status == 200:
                    data = await response.json()
                    health_info["models"] = [
                        {
                            "name": model.get("name", ""),
                            "size": model.get("size", 0),
                            "modified_at": model.get("modified_at", "")
                        }
                        for model in data.get("models", [])
                    ]
                else:
                    health_info["api_error"] = f"HTTP {response.status}"
        except Exception as e:
            health_info["api_accessible"] = False
            health_info["api_error"] = str(e)

        return health_info
