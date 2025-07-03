"""
Enhanced AI Management System
Comprehensive AI abstraction layer with multiple provider support, fallbacks, and access control.
"""

import asyncio
import json
import time
import hashlib
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Union, Callable
from dataclasses import dataclass, asdict
from enum import Enum
import aiohttp
import openai
from anthropic import Anthropic

logger = logging.getLogger(__name__)

class AIProvider(str, Enum):
    """Supported AI providers."""
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GOOGLE = "google"
    COHERE = "cohere"
    HUGGINGFACE = "huggingface"
    OLLAMA = "ollama"
    CUSTOM = "custom"

class ModelCapability(str, Enum):
    """AI model capabilities."""
    TEXT_GENERATION = "text_generation"
    CODE_GENERATION = "code_generation"
    CHAT = "chat"
    MODERATION = "moderation"
    EMBEDDING = "embedding"
    IMAGE_GENERATION = "image_generation"
    IMAGE_ANALYSIS = "image_analysis"
    AUDIO_TRANSCRIPTION = "audio_transcription"
    TRANSLATION = "translation"

@dataclass
class AIModel:
    """AI model configuration."""
    id: str
    name: str
    provider: AIProvider
    capabilities: List[ModelCapability]
    max_tokens: int
    cost_per_1k_tokens: float
    context_window: int
    supports_streaming: bool = True
    supports_functions: bool = False
    is_available: bool = True
    priority: int = 1  # Lower number = higher priority
    rate_limit_rpm: int = 60  # Requests per minute
    rate_limit_tpm: int = 90000  # Tokens per minute

@dataclass
class AIRequest:
    """AI request structure."""
    user_id: str
    model_id: str
    prompt: str
    max_tokens: Optional[int] = None
    temperature: float = 0.7
    stream: bool = False
    functions: Optional[List[Dict]] = None
    metadata: Optional[Dict[str, Any]] = None
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()

@dataclass
class AIResponse:
    """AI response structure."""
    request_id: str
    model_id: str
    content: str
    usage: Dict[str, int]
    cost: float
    latency_ms: int
    provider: AIProvider
    timestamp: datetime
    metadata: Optional[Dict[str, Any]] = None

class AIAccessControl:
    """AI access control and permissions."""
    
    def __init__(self):
        self.user_permissions: Dict[str, Dict[str, Any]] = {}
        self.model_restrictions: Dict[str, Dict[str, Any]] = {}
        self.usage_limits: Dict[str, Dict[str, Any]] = {}
    
    def check_user_permission(self, user_id: str, model_id: str, capability: ModelCapability) -> bool:
        """Check if user has permission to use model for specific capability."""
        user_perms = self.user_permissions.get(user_id, {})
        
        # Check if user is allowed to use AI at all
        if not user_perms.get("ai_enabled", True):
            return False
        
        # Check model-specific permissions
        allowed_models = user_perms.get("allowed_models", [])
        if allowed_models and model_id not in allowed_models:
            return False
        
        # Check capability permissions
        allowed_capabilities = user_perms.get("allowed_capabilities", list(ModelCapability))
        if capability not in allowed_capabilities:
            return False
        
        return True
    
    def check_rate_limit(self, user_id: str, model_id: str) -> bool:
        """Check if user is within rate limits."""
        current_time = time.time()
        user_usage = self.usage_limits.get(user_id, {})
        
        # Get user's rate limits
        user_perms = self.user_permissions.get(user_id, {})
        max_requests_per_hour = user_perms.get("max_requests_per_hour", 100)
        max_tokens_per_hour = user_perms.get("max_tokens_per_hour", 50000)
        
        # Check hourly request limit
        recent_requests = [req_time for req_time in user_usage.get("request_times", []) 
                          if current_time - req_time < 3600]
        
        if len(recent_requests) >= max_requests_per_hour:
            return False
        
        # Check hourly token limit
        recent_tokens = sum(tokens for timestamp, tokens in user_usage.get("token_usage", [])
                           if current_time - timestamp < 3600)
        
        if recent_tokens >= max_tokens_per_hour:
            return False
        
        return True
    
    def record_usage(self, user_id: str, model_id: str, tokens_used: int):
        """Record AI usage for rate limiting."""
        current_time = time.time()
        
        if user_id not in self.usage_limits:
            self.usage_limits[user_id] = {"request_times": [], "token_usage": []}
        
        user_usage = self.usage_limits[user_id]
        user_usage["request_times"].append(current_time)
        user_usage["token_usage"].append((current_time, tokens_used))
        
        # Clean old entries (older than 24 hours)
        cutoff_time = current_time - 86400
        user_usage["request_times"] = [t for t in user_usage["request_times"] if t > cutoff_time]
        user_usage["token_usage"] = [(t, tokens) for t, tokens in user_usage["token_usage"] if t > cutoff_time]

class EnhancedAIManager:
    """Enhanced AI management system with multiple providers and advanced features."""
    
    def __init__(self, config_path: str = "ai_config.json"):
        self.config_path = Path(config_path)
        self.models: Dict[str, AIModel] = {}
        self.providers: Dict[AIProvider, Dict[str, Any]] = {}
        self.access_control = AIAccessControl()
        
        # Request tracking
        self.request_history: List[AIRequest] = []
        self.response_history: List[AIResponse] = []
        
        # Model health monitoring
        self.model_health: Dict[str, Dict[str, Any]] = {}
        
        # Load configuration
        self.load_config()
        
        # Initialize providers
        self._initialize_providers()
    
    def load_config(self):
        """Load AI configuration from file."""
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r') as f:
                    config = json.load(f)
                
                # Load models
                for model_data in config.get('models', []):
                    model = AIModel(**model_data)
                    self.models[model.id] = model
                
                # Load provider configurations
                self.providers = config.get('providers', {})
                
                # Load access control settings
                access_config = config.get('access_control', {})
                self.access_control.user_permissions = access_config.get('user_permissions', {})
                self.access_control.model_restrictions = access_config.get('model_restrictions', {})
                
                logger.info(f"Loaded {len(self.models)} AI models and {len(self.providers)} providers")
                
            except Exception as e:
                logger.error(f"Failed to load AI config: {e}")
                self._create_default_config()
        else:
            self._create_default_config()
    
    def _create_default_config(self):
        """Create default AI configuration."""
        # Default models
        default_models = [
            AIModel(
                id="gpt-4",
                name="GPT-4",
                provider=AIProvider.OPENAI,
                capabilities=[ModelCapability.TEXT_GENERATION, ModelCapability.CHAT, ModelCapability.CODE_GENERATION],
                max_tokens=8192,
                cost_per_1k_tokens=0.03,
                context_window=8192,
                supports_functions=True,
                priority=1
            ),
            AIModel(
                id="gpt-3.5-turbo",
                name="GPT-3.5 Turbo",
                provider=AIProvider.OPENAI,
                capabilities=[ModelCapability.TEXT_GENERATION, ModelCapability.CHAT, ModelCapability.CODE_GENERATION],
                max_tokens=4096,
                cost_per_1k_tokens=0.002,
                context_window=4096,
                supports_functions=True,
                priority=2
            ),
            AIModel(
                id="claude-3-opus",
                name="Claude 3 Opus",
                provider=AIProvider.ANTHROPIC,
                capabilities=[ModelCapability.TEXT_GENERATION, ModelCapability.CHAT, ModelCapability.CODE_GENERATION],
                max_tokens=4096,
                cost_per_1k_tokens=0.015,
                context_window=200000,
                priority=1
            )
        ]
        
        for model in default_models:
            self.models[model.id] = model
        
        # Default provider configurations
        self.providers = {
            AIProvider.OPENAI: {
                "api_key": "",
                "base_url": "https://api.openai.com/v1",
                "enabled": False
            },
            AIProvider.ANTHROPIC: {
                "api_key": "",
                "base_url": "https://api.anthropic.com",
                "enabled": False
            }
        }
        
        self.save_config()
    
    def save_config(self):
        """Save AI configuration to file."""
        try:
            config = {
                'models': [asdict(model) for model in self.models.values()],
                'providers': self.providers,
                'access_control': {
                    'user_permissions': self.access_control.user_permissions,
                    'model_restrictions': self.access_control.model_restrictions
                },
                'last_updated': datetime.now().isoformat()
            }
            
            with open(self.config_path, 'w') as f:
                json.dump(config, f, indent=2, default=str)
                
        except Exception as e:
            logger.error(f"Failed to save AI config: {e}")
    
    def _initialize_providers(self):
        """Initialize AI provider clients."""
        # Initialize OpenAI
        openai_config = self.providers.get(AIProvider.OPENAI, {})
        if openai_config.get("enabled") and openai_config.get("api_key"):
            openai.api_key = openai_config["api_key"]
            if openai_config.get("base_url"):
                openai.api_base = openai_config["base_url"]
        
        # Initialize Anthropic
        anthropic_config = self.providers.get(AIProvider.ANTHROPIC, {})
        if anthropic_config.get("enabled") and anthropic_config.get("api_key"):
            self.anthropic_client = Anthropic(api_key=anthropic_config["api_key"])
        
        logger.info("AI providers initialized")

    async def process_request(self, request: AIRequest) -> AIResponse:
        """Process an AI request with fallback support."""
        # Check permissions
        model = self.models.get(request.model_id)
        if not model:
            raise ValueError(f"Model not found: {request.model_id}")

        # Determine capability from request
        capability = ModelCapability.CHAT  # Default capability
        if request.functions:
            capability = ModelCapability.CODE_GENERATION

        if not self.access_control.check_user_permission(request.user_id, request.model_id, capability):
            raise PermissionError(f"User {request.user_id} not permitted to use {request.model_id} for {capability}")

        if not self.access_control.check_rate_limit(request.user_id, request.model_id):
            raise Exception("Rate limit exceeded")

        # Try primary model first
        try:
            response = await self._make_request(request, model)
            self.access_control.record_usage(request.user_id, request.model_id, response.usage.get('total_tokens', 0))
            return response
        except Exception as e:
            logger.warning(f"Primary model {request.model_id} failed: {e}")

            # Try fallback models
            fallback_models = self._get_fallback_models(model)
            for fallback_model in fallback_models:
                try:
                    fallback_request = AIRequest(
                        user_id=request.user_id,
                        model_id=fallback_model.id,
                        prompt=request.prompt,
                        max_tokens=request.max_tokens,
                        temperature=request.temperature,
                        stream=request.stream,
                        functions=request.functions if fallback_model.supports_functions else None,
                        metadata=request.metadata
                    )

                    response = await self._make_request(fallback_request, fallback_model)
                    self.access_control.record_usage(request.user_id, fallback_model.id, response.usage.get('total_tokens', 0))
                    logger.info(f"Fallback successful with model: {fallback_model.id}")
                    return response

                except Exception as fallback_error:
                    logger.warning(f"Fallback model {fallback_model.id} failed: {fallback_error}")
                    continue

            # All models failed
            raise Exception(f"All models failed for request. Last error: {e}")

    def _get_fallback_models(self, primary_model: AIModel) -> List[AIModel]:
        """Get fallback models for a primary model."""
        # Find models with same capabilities, sorted by priority
        fallback_models = []

        for model in self.models.values():
            if (model.id != primary_model.id and
                model.is_available and
                any(cap in model.capabilities for cap in primary_model.capabilities)):
                fallback_models.append(model)

        # Sort by priority (lower number = higher priority)
        fallback_models.sort(key=lambda m: m.priority)
        return fallback_models[:3]  # Limit to 3 fallbacks

    async def _make_request(self, request: AIRequest, model: AIModel) -> AIResponse:
        """Make request to specific AI model."""
        start_time = time.time()
        request_id = hashlib.md5(f"{request.user_id}{request.timestamp}{request.prompt}".encode()).hexdigest()

        try:
            if model.provider == AIProvider.OPENAI:
                response = await self._make_openai_request(request, model)
            elif model.provider == AIProvider.ANTHROPIC:
                response = await self._make_anthropic_request(request, model)
            else:
                raise NotImplementedError(f"Provider {model.provider} not implemented")

            latency_ms = int((time.time() - start_time) * 1000)

            ai_response = AIResponse(
                request_id=request_id,
                model_id=model.id,
                content=response['content'],
                usage=response['usage'],
                cost=self._calculate_cost(model, response['usage']),
                latency_ms=latency_ms,
                provider=model.provider,
                timestamp=datetime.now(),
                metadata=response.get('metadata')
            )

            # Record request and response
            self.request_history.append(request)
            self.response_history.append(ai_response)

            # Update model health
            self._update_model_health(model.id, True, latency_ms)

            return ai_response

        except Exception as e:
            self._update_model_health(model.id, False, 0)
            raise e

    async def _make_openai_request(self, request: AIRequest, model: AIModel) -> Dict[str, Any]:
        """Make request to OpenAI API."""
        try:
            messages = [{"role": "user", "content": request.prompt}]

            kwargs = {
                "model": model.id,
                "messages": messages,
                "max_tokens": request.max_tokens or model.max_tokens,
                "temperature": request.temperature,
                "stream": request.stream
            }

            if request.functions and model.supports_functions:
                kwargs["functions"] = request.functions

            if request.stream:
                # Handle streaming response
                response_content = ""
                async for chunk in await openai.ChatCompletion.acreate(**kwargs):
                    if chunk.choices[0].delta.get('content'):
                        response_content += chunk.choices[0].delta.content

                usage = {"prompt_tokens": 0, "completion_tokens": len(response_content.split()), "total_tokens": 0}
            else:
                response = await openai.ChatCompletion.acreate(**kwargs)
                response_content = response.choices[0].message.content
                usage = response.usage.to_dict()

            return {
                "content": response_content,
                "usage": usage,
                "metadata": {"model": model.id, "provider": "openai"}
            }

        except Exception as e:
            logger.error(f"OpenAI request failed: {e}")
            raise e

    async def _make_anthropic_request(self, request: AIRequest, model: AIModel) -> Dict[str, Any]:
        """Make request to Anthropic API."""
        try:
            if not hasattr(self, 'anthropic_client'):
                raise Exception("Anthropic client not initialized")

            response = await self.anthropic_client.messages.create(
                model=model.id,
                max_tokens=request.max_tokens or model.max_tokens,
                temperature=request.temperature,
                messages=[{"role": "user", "content": request.prompt}]
            )

            usage = {
                "prompt_tokens": response.usage.input_tokens,
                "completion_tokens": response.usage.output_tokens,
                "total_tokens": response.usage.input_tokens + response.usage.output_tokens
            }

            return {
                "content": response.content[0].text,
                "usage": usage,
                "metadata": {"model": model.id, "provider": "anthropic"}
            }

        except Exception as e:
            logger.error(f"Anthropic request failed: {e}")
            raise e

    def _calculate_cost(self, model: AIModel, usage: Dict[str, int]) -> float:
        """Calculate cost for AI request."""
        total_tokens = usage.get('total_tokens', 0)
        return (total_tokens / 1000) * model.cost_per_1k_tokens

    def _update_model_health(self, model_id: str, success: bool, latency_ms: int):
        """Update model health metrics."""
        if model_id not in self.model_health:
            self.model_health[model_id] = {
                "total_requests": 0,
                "successful_requests": 0,
                "failed_requests": 0,
                "average_latency": 0,
                "last_success": None,
                "last_failure": None,
                "is_healthy": True
            }

        health = self.model_health[model_id]
        health["total_requests"] += 1

        if success:
            health["successful_requests"] += 1
            health["last_success"] = datetime.now()

            # Update average latency
            if health["average_latency"] == 0:
                health["average_latency"] = latency_ms
            else:
                health["average_latency"] = (health["average_latency"] + latency_ms) / 2
        else:
            health["failed_requests"] += 1
            health["last_failure"] = datetime.now()

        # Calculate health status
        success_rate = health["successful_requests"] / health["total_requests"]
        health["is_healthy"] = success_rate >= 0.8  # 80% success rate threshold

        # Update model availability
        if model_id in self.models:
            self.models[model_id].is_available = health["is_healthy"]

    async def scan_models(self) -> Dict[str, Any]:
        """Scan and test all configured models."""
        scan_results = {
            "timestamp": datetime.now().isoformat(),
            "models": {},
            "summary": {
                "total": len(self.models),
                "available": 0,
                "unavailable": 0,
                "errors": []
            }
        }

        test_prompt = "Hello, this is a test message. Please respond with 'Test successful'."

        for model_id, model in self.models.items():
            try:
                # Create test request
                test_request = AIRequest(
                    user_id="system",
                    model_id=model_id,
                    prompt=test_prompt,
                    max_tokens=50,
                    temperature=0.1
                )

                # Test the model
                start_time = time.time()
                response = await self._make_request(test_request, model)
                test_time = time.time() - start_time

                scan_results["models"][model_id] = {
                    "status": "available",
                    "response_time": test_time,
                    "response_content": response.content[:100],  # First 100 chars
                    "cost": response.cost,
                    "provider": model.provider.value
                }

                scan_results["summary"]["available"] += 1

            except Exception as e:
                scan_results["models"][model_id] = {
                    "status": "unavailable",
                    "error": str(e),
                    "provider": model.provider.value
                }

                scan_results["summary"]["unavailable"] += 1
                scan_results["summary"]["errors"].append(f"{model_id}: {str(e)}")

        return scan_results

    def get_model_recommendations(self, capability: ModelCapability, user_id: str) -> List[str]:
        """Get recommended models for a specific capability and user."""
        recommendations = []

        for model_id, model in self.models.items():
            if (capability in model.capabilities and
                model.is_available and
                self.access_control.check_user_permission(user_id, model_id, capability)):
                recommendations.append(model_id)

        # Sort by priority and health
        recommendations.sort(key=lambda mid: (
            self.models[mid].priority,
            -self.model_health.get(mid, {}).get("successful_requests", 0)
        ))

        return recommendations

    def get_usage_statistics(self, user_id: Optional[str] = None) -> Dict[str, Any]:
        """Get AI usage statistics."""
        stats = {
            "total_requests": len(self.request_history),
            "total_responses": len(self.response_history),
            "total_cost": sum(r.cost for r in self.response_history),
            "average_latency": sum(r.latency_ms for r in self.response_history) / len(self.response_history) if self.response_history else 0,
            "models_used": {},
            "providers_used": {},
            "capabilities_used": {},
            "time_range": {
                "start": min(r.timestamp for r in self.response_history).isoformat() if self.response_history else None,
                "end": max(r.timestamp for r in self.response_history).isoformat() if self.response_history else None
            }
        }

        # Filter by user if specified
        responses = self.response_history
        requests = self.request_history

        if user_id:
            requests = [r for r in requests if r.user_id == user_id]
            request_ids = {r.timestamp.isoformat() + r.user_id for r in requests}
            responses = [r for r in responses if r.timestamp.isoformat() + user_id in request_ids]

        # Model usage statistics
        for response in responses:
            model_id = response.model_id
            if model_id not in stats["models_used"]:
                stats["models_used"][model_id] = {"count": 0, "cost": 0, "avg_latency": 0}

            stats["models_used"][model_id]["count"] += 1
            stats["models_used"][model_id]["cost"] += response.cost
            stats["models_used"][model_id]["avg_latency"] = (
                stats["models_used"][model_id]["avg_latency"] + response.latency_ms
            ) / stats["models_used"][model_id]["count"]

        # Provider usage statistics
        for response in responses:
            provider = response.provider.value
            if provider not in stats["providers_used"]:
                stats["providers_used"][provider] = {"count": 0, "cost": 0}

            stats["providers_used"][provider]["count"] += 1
            stats["providers_used"][provider]["cost"] += response.cost

        return stats

    def add_model(self, model: AIModel) -> bool:
        """Add a new AI model."""
        try:
            self.models[model.id] = model
            self.save_config()
            logger.info(f"Added new AI model: {model.id}")
            return True
        except Exception as e:
            logger.error(f"Failed to add model {model.id}: {e}")
            return False

    def remove_model(self, model_id: str) -> bool:
        """Remove an AI model."""
        try:
            if model_id in self.models:
                del self.models[model_id]
                if model_id in self.model_health:
                    del self.model_health[model_id]
                self.save_config()
                logger.info(f"Removed AI model: {model_id}")
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to remove model {model_id}: {e}")
            return False

    def update_user_permissions(self, user_id: str, permissions: Dict[str, Any]) -> bool:
        """Update user AI permissions."""
        try:
            self.access_control.user_permissions[user_id] = permissions
            self.save_config()
            logger.info(f"Updated AI permissions for user: {user_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to update permissions for {user_id}: {e}")
            return False

    def get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive AI system status."""
        return {
            "models": {
                "total": len(self.models),
                "available": sum(1 for m in self.models.values() if m.is_available),
                "health": self.model_health
            },
            "providers": {
                "configured": len(self.providers),
                "enabled": sum(1 for p in self.providers.values() if p.get("enabled", False))
            },
            "usage": {
                "total_requests": len(self.request_history),
                "total_cost": sum(r.cost for r in self.response_history),
                "active_users": len(set(r.user_id for r in self.request_history[-1000:]))  # Last 1000 requests
            },
            "system": {
                "config_loaded": self.config_path.exists(),
                "last_scan": max(h.get("last_success", datetime.min) for h in self.model_health.values()) if self.model_health else None
            }
        }
