"""
NetLink AI Abstraction Layer
Comprehensive AI management system with multiple providers, fallbacks, and access control.
"""

import asyncio
import json
import time
import hashlib
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Union, Callable, AsyncGenerator
from dataclasses import dataclass, asdict
from enum import Enum
import aiohttp
import aiofiles
from cryptography.fernet import Fernet

# Import new provider system
from ..providers import (
    BaseAIProvider,
    OllamaProvider,
    OllamaConfig,
    ProviderConfig,
    ProviderStatus
)
from ..providers.base_provider import AIRequest as ProviderAIRequest, AIResponse as ProviderAIResponse
from ..monitoring.analytics_engine import analytics_engine, UsageMetric, PerformanceMetric

logger = logging.getLogger(__name__)

class AIProvider(str, Enum):
    """Supported AI providers."""
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GOOGLE = "google"
    COHERE = "cohere"
    HUGGINGFACE = "huggingface"
    OLLAMA = "ollama"
    AZURE_OPENAI = "azure_openai"
    AWS_BEDROCK = "aws_bedrock"
    GROQ = "groq"
    TOGETHER = "together"
    REPLICATE = "replicate"
    MISTRAL = "mistral"
    PERPLEXITY = "perplexity"
    CLAUDE = "claude"
    GEMINI = "gemini"
    LLAMA = "llama"
    CUSTOM = "custom"
    LOCAL = "local"

class ModelCapability(str, Enum):
    """AI model capabilities."""
    TEXT_GENERATION = "text_generation"
    CHAT_COMPLETION = "chat_completion"
    CODE_GENERATION = "code_generation"
    MODERATION = "moderation"
    EMBEDDING = "embedding"
    IMAGE_GENERATION = "image_generation"
    IMAGE_ANALYSIS = "image_analysis"
    AUDIO_TRANSCRIPTION = "audio_transcription"
    TRANSLATION = "translation"
    FUNCTION_CALLING = "function_calling"
    STREAMING = "streaming"

class ModelStatus(str, Enum):
    """Model availability status."""
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    RATE_LIMITED = "rate_limited"
    ERROR = "error"
    MAINTENANCE = "maintenance"

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
    status: ModelStatus = ModelStatus.AVAILABLE
    priority: int = 1  # Lower number = higher priority
    rate_limit_rpm: int = 60  # Requests per minute
    rate_limit_tpm: int = 90000  # Tokens per minute
    fallback_models: List[str] = None
    custom_endpoint: Optional[str] = None
    model_version: Optional[str] = None
    created_at: datetime = None
    updated_at: datetime = None

    def __post_init__(self):
        if self.fallback_models is None:
            self.fallback_models = []
        if self.created_at is None:
            self.created_at = datetime.now()
        if self.updated_at is None:
            self.updated_at = datetime.now()

@dataclass
class AIRequest:
    """AI request structure."""
    user_id: str
    model_id: str
    prompt: str
    max_tokens: Optional[int] = None
    temperature: float = 0.7
    stream: bool = False
    functions: Optional[List[Dict[str, Any]]] = None
    system_prompt: Optional[str] = None
    context: Optional[List[Dict[str, str]]] = None
    metadata: Optional[Dict[str, Any]] = None
    request_id: Optional[str] = None
    priority: int = 1
    timeout_seconds: int = 30

    def __post_init__(self):
        if self.request_id is None:
            self.request_id = hashlib.md5(f"{self.user_id}_{time.time()}".encode()).hexdigest()
        if self.context is None:
            self.context = []
        if self.metadata is None:
            self.metadata = {}

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
    success: bool = True
    error: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    cached: bool = False
    fallback_used: bool = False
    fallback_model: Optional[str] = None

class AIAccessControl:
    """AI access control and rate limiting."""
    
    def __init__(self):
        self.user_permissions: Dict[str, Dict[str, List[ModelCapability]]] = {}
        self.rate_limits: Dict[str, Dict[str, List[float]]] = {}
        self.usage_tracking: Dict[str, Dict[str, Dict[str, Any]]] = {}
        self.admin_users: List[str] = []
        
    def add_user_permission(self, user_id: str, model_id: str, capabilities: List[ModelCapability]):
        """Add user permission for specific model and capabilities."""
        if user_id not in self.user_permissions:
            self.user_permissions[user_id] = {}
        self.user_permissions[user_id][model_id] = capabilities
        
    def check_user_permission(self, user_id: str, model_id: str, capability: ModelCapability) -> bool:
        """Check if user has permission for model and capability."""
        if user_id in self.admin_users:
            return True
            
        user_perms = self.user_permissions.get(user_id, {})
        model_perms = user_perms.get(model_id, [])
        return capability in model_perms
        
    def check_rate_limit(self, user_id: str, model_id: str, tokens: int = 1) -> bool:
        """Check if user is within rate limits."""
        current_time = time.time()
        
        if user_id not in self.rate_limits:
            self.rate_limits[user_id] = {}
        if model_id not in self.rate_limits[user_id]:
            self.rate_limits[user_id][model_id] = []
            
        # Clean old requests (older than 1 minute)
        requests = self.rate_limits[user_id][model_id]
        requests = [req_time for req_time in requests if current_time - req_time < 60]
        
        # Check limits (simplified - 60 requests per minute)
        if len(requests) >= 60:
            return False
            
        # Add current request
        requests.append(current_time)
        self.rate_limits[user_id][model_id] = requests
        return True
        
    def record_usage(self, user_id: str, model_id: str, tokens: int, cost: float):
        """Record usage for billing/tracking."""
        if user_id not in self.usage_tracking:
            self.usage_tracking[user_id] = {}
        if model_id not in self.usage_tracking[user_id]:
            self.usage_tracking[user_id][model_id] = {
                "total_tokens": 0,
                "total_cost": 0.0,
                "request_count": 0,
                "last_request": None
            }
            
        usage = self.usage_tracking[user_id][model_id]
        usage["total_tokens"] += tokens
        usage["total_cost"] += cost
        usage["request_count"] += 1
        usage["last_request"] = datetime.now()

class AIAbstractionLayer:
    """Main AI abstraction layer managing all providers and models."""

    def __init__(self, config_path: str = "config/ai_config.json"):
        self.config_path = Path(config_path)
        self.models: Dict[str, AIModel] = {}
        self.providers: Dict[AIProvider, Dict[str, Any]] = {}
        self.access_control = AIAccessControl()
        self.encryption_key = self._get_or_create_encryption_key()

        # New provider instances
        self.provider_instances: Dict[AIProvider, BaseAIProvider] = {}

        # Request tracking and caching
        self.request_cache: Dict[str, AIResponse] = {}
        self.request_history: List[AIRequest] = []
        self.response_history: List[AIResponse] = []

        # Model health monitoring
        self.model_health: Dict[str, Dict[str, Any]] = {}

        # Background tasks
        self.background_tasks: List[asyncio.Task] = []

        # Load configuration
        self.load_config()

        # Initialize provider instances
        self._initialize_providers()

        # Start monitoring system
        try:
            analytics_engine.start_monitoring()
            logger.info("AI monitoring system started")
        except Exception as e:
            logger.warning(f"Failed to start AI monitoring: {e}")
        
    def _get_or_create_encryption_key(self) -> Fernet:
        """Get or create encryption key for API keys."""
        key_path = Path("config/ai_encryption.key")
        key_path.parent.mkdir(exist_ok=True)
        
        if key_path.exists():
            with open(key_path, 'rb') as f:
                key = f.read()
        else:
            key = Fernet.generate_key()
            with open(key_path, 'wb') as f:
                f.write(key)
                
        return Fernet(key)

    def _initialize_providers(self):
        """Initialize provider instances based on configuration."""
        for provider_type, config in self.providers.items():
            if not config.get("enabled", False):
                continue

            try:
                if provider_type == AIProvider.OLLAMA:
                    ollama_config = OllamaConfig(
                        base_url=config.get("base_url", "http://localhost:11434"),
                        timeout=config.get("timeout", 60),
                        max_retries=config.get("max_retries", 2),
                        concurrent_requests=config.get("concurrent_requests", 5)
                    )
                    self.provider_instances[provider_type] = OllamaProvider(ollama_config)

                # Add other provider initializations here as they're implemented
                logger.info(f"Initialized provider: {provider_type}")

            except Exception as e:
                logger.error(f"Failed to initialize provider {provider_type}: {e}")

    def load_config(self):
        """Load AI configuration from file."""
        if not self.config_path.exists():
            self._create_default_config()
            return
            
        try:
            with open(self.config_path, 'r') as f:
                config = json.load(f)
                
            # Load models
            for model_data in config.get("models", []):
                model = AIModel(**model_data)
                self.models[model.id] = model
                
            # Load providers
            self.providers = config.get("providers", {})
            
            # Load access control
            access_data = config.get("access_control", {})
            self.access_control.user_permissions = access_data.get("user_permissions", {})
            self.access_control.admin_users = access_data.get("admin_users", [])
            
            logger.info(f"Loaded {len(self.models)} AI models and {len(self.providers)} providers")
            
        except Exception as e:
            logger.error(f"Failed to load AI config: {e}")
            self._create_default_config()

    def _create_default_config(self):
        """Create default AI configuration."""
        # Default models
        default_models = [
            AIModel(
                id="gpt-4",
                name="GPT-4",
                provider=AIProvider.OPENAI,
                capabilities=[ModelCapability.TEXT_GENERATION, ModelCapability.CHAT_COMPLETION,
                            ModelCapability.CODE_GENERATION, ModelCapability.FUNCTION_CALLING],
                max_tokens=8192,
                cost_per_1k_tokens=0.03,
                context_window=8192,
                supports_functions=True,
                priority=1,
                fallback_models=["gpt-3.5-turbo", "claude-3-sonnet"]
            ),
            AIModel(
                id="gpt-3.5-turbo",
                name="GPT-3.5 Turbo",
                provider=AIProvider.OPENAI,
                capabilities=[ModelCapability.TEXT_GENERATION, ModelCapability.CHAT_COMPLETION,
                            ModelCapability.CODE_GENERATION, ModelCapability.FUNCTION_CALLING],
                max_tokens=4096,
                cost_per_1k_tokens=0.002,
                context_window=4096,
                supports_functions=True,
                priority=2,
                fallback_models=["claude-3-haiku"]
            ),
            AIModel(
                id="claude-3-opus",
                name="Claude 3 Opus",
                provider=AIProvider.ANTHROPIC,
                capabilities=[ModelCapability.TEXT_GENERATION, ModelCapability.CHAT_COMPLETION,
                            ModelCapability.CODE_GENERATION],
                max_tokens=4096,
                cost_per_1k_tokens=0.015,
                context_window=200000,
                priority=1,
                fallback_models=["claude-3-sonnet", "gpt-4"]
            ),
            AIModel(
                id="claude-3-sonnet",
                name="Claude 3 Sonnet",
                provider=AIProvider.ANTHROPIC,
                capabilities=[ModelCapability.TEXT_GENERATION, ModelCapability.CHAT_COMPLETION,
                            ModelCapability.CODE_GENERATION],
                max_tokens=4096,
                cost_per_1k_tokens=0.003,
                context_window=200000,
                priority=2,
                fallback_models=["claude-3-haiku", "gpt-3.5-turbo"]
            ),
            AIModel(
                id="claude-3-haiku",
                name="Claude 3 Haiku",
                provider=AIProvider.ANTHROPIC,
                capabilities=[ModelCapability.TEXT_GENERATION, ModelCapability.CHAT_COMPLETION],
                max_tokens=4096,
                cost_per_1k_tokens=0.00025,
                context_window=200000,
                priority=3,
                fallback_models=["gpt-3.5-turbo"]
            )
        ]

        for model in default_models:
            self.models[model.id] = model

        # Default provider configurations
        self.providers = {
            AIProvider.OPENAI: {
                "api_key_encrypted": "",
                "base_url": "https://api.openai.com/v1",
                "enabled": False,
                "organization": "",
                "timeout": 30,
                "max_retries": 3
            },
            AIProvider.ANTHROPIC: {
                "api_key_encrypted": "",
                "base_url": "https://api.anthropic.com",
                "enabled": False,
                "timeout": 30,
                "max_retries": 3
            },
            AIProvider.GOOGLE: {
                "api_key_encrypted": "",
                "base_url": "https://generativelanguage.googleapis.com/v1",
                "enabled": False,
                "timeout": 30,
                "max_retries": 3
            },
            AIProvider.COHERE: {
                "api_key_encrypted": "",
                "base_url": "https://api.cohere.ai/v1",
                "enabled": False,
                "timeout": 30,
                "max_retries": 3
            },
            AIProvider.GROQ: {
                "api_key_encrypted": "",
                "base_url": "https://api.groq.com/openai/v1",
                "enabled": False,
                "timeout": 30,
                "max_retries": 3
            },
            AIProvider.TOGETHER: {
                "api_key_encrypted": "",
                "base_url": "https://api.together.xyz/v1",
                "enabled": False,
                "timeout": 30,
                "max_retries": 3
            },
            AIProvider.REPLICATE: {
                "api_key_encrypted": "",
                "base_url": "https://api.replicate.com/v1",
                "enabled": False,
                "timeout": 60,
                "max_retries": 3
            },
            AIProvider.OLLAMA: {
                "base_url": "http://localhost:11434",
                "enabled": False,
                "timeout": 60,
                "max_retries": 2,
                "concurrent_requests": 5
            },
            AIProvider.AZURE_OPENAI: {
                "api_key_encrypted": "",
                "base_url": "",  # Set by user: https://{resource}.openai.azure.com
                "enabled": False,
                "api_version": "2023-12-01-preview",
                "timeout": 30,
                "max_retries": 3
            },
            AIProvider.AWS_BEDROCK: {
                "access_key_encrypted": "",
                "secret_key_encrypted": "",
                "region": "us-east-1",
                "enabled": False,
                "timeout": 30,
                "max_retries": 3
            }
        }

        # Default admin user (should be changed)
        self.access_control.admin_users = ["admin"]

        self.save_config()
        logger.info("Created default AI configuration")

    def save_config(self):
        """Save AI configuration to file."""
        try:
            self.config_path.parent.mkdir(exist_ok=True)

            config = {
                "models": [asdict(model) for model in self.models.values()],
                "providers": self.providers,
                "access_control": {
                    "user_permissions": self.access_control.user_permissions,
                    "admin_users": self.access_control.admin_users
                },
                "last_updated": datetime.now().isoformat()
            }

            with open(self.config_path, 'w') as f:
                json.dump(config, f, indent=2, default=str)

            logger.info("AI configuration saved")

        except Exception as e:
            logger.error(f"Failed to save AI config: {e}")

    def encrypt_api_key(self, api_key: str) -> str:
        """Encrypt API key for secure storage."""
        return self.encryption_key.encrypt(api_key.encode()).decode()

    def decrypt_api_key(self, encrypted_key: str) -> str:
        """Decrypt API key for use."""
        return self.encryption_key.decrypt(encrypted_key.encode()).decode()

    async def configure_provider(self, provider: AIProvider, config: Dict[str, Any]) -> bool:
        """Configure an AI provider."""
        try:
            # Encrypt API key if provided
            if "api_key" in config:
                config["api_key_encrypted"] = self.encrypt_api_key(config["api_key"])
                del config["api_key"]

            self.providers[provider] = {**self.providers.get(provider, {}), **config}
            self.save_config()

            logger.info(f"Configured AI provider: {provider}")
            return True

        except Exception as e:
            logger.error(f"Failed to configure provider {provider}: {e}")
            return False

    async def process_request(self, request: AIRequest) -> AIResponse:
        """Process an AI request with fallback support."""
        start_time = time.time()

        # Validate model
        model = self.models.get(request.model_id)
        if not model:
            return AIResponse(
                request_id=request.request_id,
                model_id=request.model_id,
                content="",
                usage={},
                cost=0.0,
                latency_ms=0,
                provider=AIProvider.CUSTOM,
                timestamp=datetime.now(),
                success=False,
                error=f"Model not found: {request.model_id}"
            )

        # Check permissions
        capability = self._determine_capability(request)
        if not self.access_control.check_user_permission(request.user_id, request.model_id, capability):
            return AIResponse(
                request_id=request.request_id,
                model_id=request.model_id,
                content="",
                usage={},
                cost=0.0,
                latency_ms=0,
                provider=model.provider,
                timestamp=datetime.now(),
                success=False,
                error=f"Permission denied for {capability}"
            )

        # Check rate limits
        if not self.access_control.check_rate_limit(request.user_id, request.model_id):
            return AIResponse(
                request_id=request.request_id,
                model_id=request.model_id,
                content="",
                usage={},
                cost=0.0,
                latency_ms=0,
                provider=model.provider,
                timestamp=datetime.now(),
                success=False,
                error="Rate limit exceeded"
            )

        # Check cache first
        cache_key = self._generate_cache_key(request)
        if cache_key in self.request_cache:
            cached_response = self.request_cache[cache_key]
            cached_response.cached = True
            cached_response.request_id = request.request_id
            cached_response.timestamp = datetime.now()
            return cached_response

        # Try primary model
        try:
            response = await self._make_request(request, model)

            # Cache successful response
            if response.success:
                self.request_cache[cache_key] = response
                self.access_control.record_usage(
                    request.user_id,
                    request.model_id,
                    response.usage.get('total_tokens', 0),
                    response.cost
                )

            return response

        except Exception as e:
            logger.warning(f"Primary model {request.model_id} failed: {e}")

            # Try fallback models
            for fallback_model_id in model.fallback_models:
                fallback_model = self.models.get(fallback_model_id)
                if not fallback_model or fallback_model.status != ModelStatus.AVAILABLE:
                    continue

                try:
                    # Create fallback request
                    fallback_request = AIRequest(
                        user_id=request.user_id,
                        model_id=fallback_model_id,
                        prompt=request.prompt,
                        max_tokens=request.max_tokens,
                        temperature=request.temperature,
                        stream=request.stream,
                        functions=request.functions if fallback_model.supports_functions else None,
                        system_prompt=request.system_prompt,
                        context=request.context,
                        metadata=request.metadata,
                        priority=request.priority,
                        timeout_seconds=request.timeout_seconds
                    )

                    response = await self._make_request(fallback_request, fallback_model)

                    if response.success:
                        response.fallback_used = True
                        response.fallback_model = fallback_model_id

                        # Cache and record usage
                        self.request_cache[cache_key] = response
                        self.access_control.record_usage(
                            request.user_id,
                            fallback_model_id,
                            response.usage.get('total_tokens', 0),
                            response.cost
                        )

                        logger.info(f"Fallback successful with model: {fallback_model_id}")
                        return response

                except Exception as fallback_error:
                    logger.warning(f"Fallback model {fallback_model_id} failed: {fallback_error}")
                    continue

            # All models failed
            return AIResponse(
                request_id=request.request_id,
                model_id=request.model_id,
                content="",
                usage={},
                cost=0.0,
                latency_ms=int((time.time() - start_time) * 1000),
                provider=model.provider,
                timestamp=datetime.now(),
                success=False,
                error="All models failed"
            )

    def _determine_capability(self, request: AIRequest) -> ModelCapability:
        """Determine the capability needed for a request."""
        if request.functions:
            return ModelCapability.FUNCTION_CALLING
        elif request.stream:
            return ModelCapability.STREAMING
        elif "code" in request.prompt.lower() or "python" in request.prompt.lower():
            return ModelCapability.CODE_GENERATION
        else:
            return ModelCapability.CHAT_COMPLETION

    def _generate_cache_key(self, request: AIRequest) -> str:
        """Generate cache key for request."""
        cache_data = {
            "model_id": request.model_id,
            "prompt": request.prompt,
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
            "system_prompt": request.system_prompt,
            "functions": request.functions
        }
        return hashlib.md5(json.dumps(cache_data, sort_keys=True).encode()).hexdigest()

    async def _make_request(self, request: AIRequest, model: AIModel) -> AIResponse:
        """Make request to specific AI model."""
        start_time = time.time()

        try:
            # Try to use new provider system first
            if model.provider in self.provider_instances:
                provider_instance = self.provider_instances[model.provider]

                # Convert to provider request format
                provider_request = ProviderAIRequest(
                    model_id=model.id,
                    prompt=request.prompt,
                    max_tokens=request.max_tokens,
                    temperature=request.temperature,
                    stream=request.stream,
                    system_prompt=request.system_prompt,
                    context=request.context,
                    metadata=request.metadata
                )

                provider_response = await provider_instance.generate(provider_request)

                # Convert back to abstraction layer response format
                response = AIResponse(
                    request_id=request.request_id,
                    model_id=model.id,
                    content=provider_response.content,
                    usage=provider_response.usage,
                    cost=self._calculate_cost(model, provider_response.usage),
                    latency_ms=provider_response.latency_ms,
                    provider=model.provider,
                    timestamp=provider_response.timestamp,
                    success=provider_response.success,
                    error=provider_response.error,
                    metadata=provider_response.metadata
                )

            else:
                # Fall back to legacy provider methods
                if model.provider == AIProvider.OPENAI:
                    response_data = await self._make_openai_request(request, model)
                elif model.provider == AIProvider.ANTHROPIC:
                    response_data = await self._make_anthropic_request(request, model)
                elif model.provider == AIProvider.OLLAMA:
                    response_data = await self._make_ollama_request(request, model)
                else:
                    raise NotImplementedError(f"Provider {model.provider} not implemented")

                latency_ms = int((time.time() - start_time) * 1000)

                response = AIResponse(
                    request_id=request.request_id,
                    model_id=model.id,
                    content=response_data['content'],
                    usage=response_data.get('usage', {}),
                    cost=self._calculate_cost(model, response_data.get('usage', {})),
                    latency_ms=latency_ms,
                    provider=model.provider,
                    timestamp=datetime.now(),
                    success=True,
                    metadata=response_data.get('metadata')
                )

            # Update model health
            self._update_model_health(model.id, response.success, response.latency_ms)

            # Record request and response
            self.request_history.append(request)
            self.response_history.append(response)

            # Record metrics for monitoring
            try:
                # Usage metric
                usage_metric = UsageMetric(
                    timestamp=datetime.now(timezone.utc),
                    user_id=request.user_id or "anonymous",
                    model_id=model.id,
                    provider=model.provider.value,
                    tokens_used=response.usage.get("total_tokens", 0),
                    cost=response.cost,
                    latency_ms=response.latency_ms,
                    success=response.success,
                    capability=request.capability.value,
                    request_size=len(str(request.messages)),
                    response_size=len(response.content)
                )
                analytics_engine.record_usage(usage_metric)

                # Performance metric
                performance_metric = PerformanceMetric(
                    timestamp=datetime.now(timezone.utc),
                    model_id=model.id,
                    provider=model.provider.value,
                    latency_ms=response.latency_ms,
                    success=response.success,
                    tokens_per_second=response.usage.get("total_tokens", 0) / (response.latency_ms / 1000) if response.latency_ms > 0 else None
                )
                analytics_engine.record_performance(performance_metric)

            except Exception as e:
                logger.warning(f"Failed to record metrics: {e}")

            return response

        except Exception as e:
            latency_ms = int((time.time() - start_time) * 1000)
            self._update_model_health(model.id, False, latency_ms)

            error_response = AIResponse(
                request_id=request.request_id,
                model_id=model.id,
                content="",
                usage={},
                cost=0.0,
                latency_ms=latency_ms,
                provider=model.provider,
                timestamp=datetime.now(),
                success=False,
                error=str(e)
            )

            # Record failed metrics for monitoring
            try:
                # Performance metric for failed request
                performance_metric = PerformanceMetric(
                    timestamp=datetime.now(timezone.utc),
                    model_id=model.id,
                    provider=model.provider.value,
                    latency_ms=latency_ms,
                    success=False,
                    error_type=type(e).__name__
                )
                analytics_engine.record_performance(performance_metric)

            except Exception as metric_error:
                logger.warning(f"Failed to record error metrics: {metric_error}")

            return error_response

    async def _make_openai_request(self, request: AIRequest, model: AIModel) -> Dict[str, Any]:
        """Make request to OpenAI API."""
        provider_config = self.providers.get(AIProvider.OPENAI, {})
        if not provider_config.get("enabled"):
            raise Exception("OpenAI provider not enabled")

        api_key = self.decrypt_api_key(provider_config["api_key_encrypted"])
        base_url = provider_config.get("base_url", "https://api.openai.com/v1")

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }

        if provider_config.get("organization"):
            headers["OpenAI-Organization"] = provider_config["organization"]

        # Build messages
        messages = []
        if request.system_prompt:
            messages.append({"role": "system", "content": request.system_prompt})

        # Add context
        messages.extend(request.context)

        # Add current prompt
        messages.append({"role": "user", "content": request.prompt})

        payload = {
            "model": model.id,
            "messages": messages,
            "max_tokens": request.max_tokens or model.max_tokens,
            "temperature": request.temperature,
            "stream": request.stream
        }

        if request.functions and model.supports_functions:
            payload["functions"] = request.functions

        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=request.timeout_seconds)) as session:
            async with session.post(f"{base_url}/chat/completions", headers=headers, json=payload) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        "content": data["choices"][0]["message"]["content"],
                        "usage": data.get("usage", {}),
                        "metadata": {"finish_reason": data["choices"][0].get("finish_reason")}
                    }
                else:
                    error_data = await response.json()
                    raise Exception(f"OpenAI API error: {error_data.get('error', {}).get('message', 'Unknown error')}")

    async def _make_anthropic_request(self, request: AIRequest, model: AIModel) -> Dict[str, Any]:
        """Make request to Anthropic API."""
        provider_config = self.providers.get(AIProvider.ANTHROPIC, {})
        if not provider_config.get("enabled"):
            raise Exception("Anthropic provider not enabled")

        api_key = self.decrypt_api_key(provider_config["api_key_encrypted"])
        base_url = provider_config.get("base_url", "https://api.anthropic.com")

        headers = {
            "x-api-key": api_key,
            "Content-Type": "application/json",
            "anthropic-version": "2023-06-01"
        }

        # Build prompt for Anthropic format
        full_prompt = ""
        if request.system_prompt:
            full_prompt += f"System: {request.system_prompt}\n\n"

        # Add context
        for msg in request.context:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            full_prompt += f"{role.title()}: {content}\n\n"

        full_prompt += f"Human: {request.prompt}\n\nAssistant:"

        payload = {
            "model": model.id,
            "prompt": full_prompt,
            "max_tokens_to_sample": request.max_tokens or model.max_tokens,
            "temperature": request.temperature,
            "stream": request.stream
        }

        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=request.timeout_seconds)) as session:
            async with session.post(f"{base_url}/v1/complete", headers=headers, json=payload) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        "content": data["completion"].strip(),
                        "usage": {"completion_tokens": len(data["completion"].split())},
                        "metadata": {"stop_reason": data.get("stop_reason")}
                    }
                else:
                    error_data = await response.json()
                    raise Exception(f"Anthropic API error: {error_data.get('error', {}).get('message', 'Unknown error')}")

    async def _make_ollama_request(self, request: AIRequest, model: AIModel) -> Dict[str, Any]:
        """Make request to Ollama local API."""
        provider_config = self.providers.get(AIProvider.OLLAMA, {})
        if not provider_config.get("enabled"):
            raise Exception("Ollama provider not enabled")

        base_url = provider_config.get("base_url", "http://localhost:11434")

        # Build prompt
        full_prompt = ""
        if request.system_prompt:
            full_prompt += f"System: {request.system_prompt}\n\n"

        for msg in request.context:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            full_prompt += f"{role.title()}: {content}\n\n"

        full_prompt += f"User: {request.prompt}\n\nAssistant:"

        payload = {
            "model": model.id,
            "prompt": full_prompt,
            "stream": False,
            "options": {
                "temperature": request.temperature,
                "num_predict": request.max_tokens or model.max_tokens
            }
        }

        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=request.timeout_seconds)) as session:
            async with session.post(f"{base_url}/api/generate", json=payload) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        "content": data["response"].strip(),
                        "usage": {"completion_tokens": len(data["response"].split())},
                        "metadata": {"done": data.get("done", True)}
                    }
                else:
                    error_text = await response.text()
                    raise Exception(f"Ollama API error: {error_text}")

    def _calculate_cost(self, model: AIModel, usage: Dict[str, int]) -> float:
        """Calculate cost for request."""
        total_tokens = usage.get('total_tokens', 0)
        if total_tokens == 0:
            # Estimate from completion tokens
            completion_tokens = usage.get('completion_tokens', 0)
            prompt_tokens = usage.get('prompt_tokens', 0)
            total_tokens = completion_tokens + prompt_tokens

        return (total_tokens / 1000) * model.cost_per_1k_tokens

    def _update_model_health(self, model_id: str, success: bool, latency_ms: int):
        """Update model health metrics."""
        if model_id not in self.model_health:
            self.model_health[model_id] = {
                "total_requests": 0,
                "successful_requests": 0,
                "failed_requests": 0,
                "average_latency_ms": 0,
                "last_success": None,
                "last_failure": None,
                "status": ModelStatus.AVAILABLE
            }

        health = self.model_health[model_id]
        health["total_requests"] += 1

        if success:
            health["successful_requests"] += 1
            health["last_success"] = datetime.now()

            # Update average latency
            current_avg = health["average_latency_ms"]
            total_successful = health["successful_requests"]
            health["average_latency_ms"] = ((current_avg * (total_successful - 1)) + latency_ms) / total_successful

        else:
            health["failed_requests"] += 1
            health["last_failure"] = datetime.now()

        # Update status based on recent performance
        success_rate = health["successful_requests"] / health["total_requests"]
        if success_rate < 0.5 and health["total_requests"] > 5:
            health["status"] = ModelStatus.ERROR
            self.models[model_id].status = ModelStatus.ERROR
        elif success_rate > 0.8:
            health["status"] = ModelStatus.AVAILABLE
            self.models[model_id].status = ModelStatus.AVAILABLE

    # Management and utility methods
    def get_available_models(self, user_id: str, capability: Optional[ModelCapability] = None) -> List[AIModel]:
        """Get available models for user and capability."""
        available = []

        for model in self.models.values():
            if model.status != ModelStatus.AVAILABLE:
                continue

            if capability and capability not in model.capabilities:
                continue

            if not self.access_control.check_user_permission(user_id, model.id, capability or ModelCapability.CHAT_COMPLETION):
                continue

            available.append(model)

        # Sort by priority and health
        available.sort(key=lambda m: (
            m.priority,
            -self.model_health.get(m.id, {}).get("successful_requests", 0)
        ))

        return available

    def get_model_health(self, model_id: Optional[str] = None) -> Dict[str, Any]:
        """Get model health information."""
        if model_id:
            return self.model_health.get(model_id, {})
        return self.model_health

    def get_usage_stats(self, user_id: Optional[str] = None) -> Dict[str, Any]:
        """Get usage statistics."""
        if user_id:
            return self.access_control.usage_tracking.get(user_id, {})
        return self.access_control.usage_tracking

    async def add_model(self, model: AIModel) -> bool:
        """Add new AI model."""
        try:
            self.models[model.id] = model
            self.save_config()
            logger.info(f"Added AI model: {model.id}")
            return True
        except Exception as e:
            logger.error(f"Failed to add model {model.id}: {e}")
            return False

    async def remove_model(self, model_id: str) -> bool:
        """Remove AI model."""
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

    async def update_model_status(self, model_id: str, status: ModelStatus) -> bool:
        """Update model status."""
        try:
            if model_id in self.models:
                self.models[model_id].status = status
                self.save_config()
                logger.info(f"Updated model {model_id} status to {status}")
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to update model status: {e}")
            return False

    def clear_cache(self):
        """Clear request cache."""
        self.request_cache.clear()
        logger.info("AI request cache cleared")

    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on all models."""
        health_status = {
            "overall_status": "healthy",
            "total_models": len(self.models),
            "available_models": 0,
            "unavailable_models": 0,
            "providers": {},
            "models": {}
        }

        for model_id, model in self.models.items():
            model_health = self.model_health.get(model_id, {})

            if model.status == ModelStatus.AVAILABLE:
                health_status["available_models"] += 1
            else:
                health_status["unavailable_models"] += 1

            # Provider stats
            provider = model.provider
            if provider not in health_status["providers"]:
                health_status["providers"][provider] = {"total": 0, "available": 0}
            health_status["providers"][provider]["total"] += 1
            if model.status == ModelStatus.AVAILABLE:
                health_status["providers"][provider]["available"] += 1

            # Model details
            health_status["models"][model_id] = {
                "status": model.status,
                "provider": model.provider,
                "health": model_health
            }

        # Overall status
        if health_status["available_models"] == 0:
            health_status["overall_status"] = "critical"
        elif health_status["unavailable_models"] > health_status["available_models"]:
            health_status["overall_status"] = "degraded"

        return health_status

    # Enhanced provider management methods
    async def get_provider_status(self, provider: Optional[AIProvider] = None) -> Dict[str, Any]:
        """Get status of AI providers."""
        if provider:
            if provider in self.provider_instances:
                instance = self.provider_instances[provider]
                return {
                    "provider": provider,
                    "status": await instance.get_status(),
                    "health": await instance.health_check(),
                    "models": await instance.list_models() if hasattr(instance, 'list_models') else []
                }
            else:
                return {
                    "provider": provider,
                    "status": ProviderStatus.UNAVAILABLE,
                    "error": "Provider not initialized"
                }

        # Get status for all providers
        status = {}
        for provider_type, instance in self.provider_instances.items():
            try:
                status[provider_type] = {
                    "status": await instance.get_status(),
                    "health": await instance.health_check(),
                    "models": await instance.list_models() if hasattr(instance, 'list_models') else []
                }
            except Exception as e:
                status[provider_type] = {
                    "status": ProviderStatus.ERROR,
                    "error": str(e)
                }

        return status

    async def refresh_provider(self, provider: AIProvider) -> bool:
        """Refresh/reinitialize a provider."""
        try:
            if provider in self.provider_instances:
                # Close existing instance
                instance = self.provider_instances[provider]
                if hasattr(instance, 'close'):
                    await instance.close()
                del self.provider_instances[provider]

            # Reinitialize
            config = self.providers.get(provider, {})
            if config.get("enabled", False):
                if provider == AIProvider.OLLAMA:
                    ollama_config = OllamaConfig(
                        base_url=config.get("base_url", "http://localhost:11434"),
                        timeout=config.get("timeout", 60),
                        max_retries=config.get("max_retries", 2),
                        concurrent_requests=config.get("concurrent_requests", 5)
                    )
                    self.provider_instances[provider] = OllamaProvider(ollama_config)

                logger.info(f"Refreshed provider: {provider}")
                return True

            return False

        except Exception as e:
            logger.error(f"Failed to refresh provider {provider}: {e}")
            return False

    async def discover_ollama_models(self) -> List[str]:
        """Discover available Ollama models."""
        if AIProvider.OLLAMA in self.provider_instances:
            ollama_provider = self.provider_instances[AIProvider.OLLAMA]
            try:
                return await ollama_provider.list_models()
            except Exception as e:
                logger.error(f"Failed to discover Ollama models: {e}")
        return []

    async def pull_ollama_model(self, model_id: str) -> bool:
        """Pull an Ollama model."""
        if AIProvider.OLLAMA in self.provider_instances:
            ollama_provider = self.provider_instances[AIProvider.OLLAMA]
            try:
                return await ollama_provider.pull_model(model_id)
            except Exception as e:
                logger.error(f"Failed to pull Ollama model {model_id}: {e}")
        return False

    async def delete_ollama_model(self, model_id: str) -> bool:
        """Delete an Ollama model."""
        if AIProvider.OLLAMA in self.provider_instances:
            ollama_provider = self.provider_instances[AIProvider.OLLAMA]
            try:
                return await ollama_provider.delete_model(model_id)
            except Exception as e:
                logger.error(f"Failed to delete Ollama model {model_id}: {e}")
        return False
