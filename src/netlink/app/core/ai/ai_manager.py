"""
Comprehensive AI Abstraction Layer for NetLink
Supports multiple AI providers, model fallbacks, access control, and scanning capabilities.
"""

import asyncio
import json
import time
import hashlib
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, Optional, List, Union, Callable
from dataclasses import dataclass, asdict
from enum import Enum
import aiohttp
import requests
from cryptography.fernet import Fernet

logger = logging.getLogger("netlink.ai")


class AIProvider(Enum):
    """Supported AI providers."""
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GOOGLE = "google"
    COHERE = "cohere"
    HUGGINGFACE = "huggingface"
    LOCAL_OLLAMA = "local_ollama"
    LOCAL_LLAMACPP = "local_llamacpp"
    AZURE_OPENAI = "azure_openai"
    AWS_BEDROCK = "aws_bedrock"
    CUSTOM = "custom"


class ModelCapability(Enum):
    """AI model capabilities."""
    TEXT_GENERATION = "text_generation"
    CHAT_COMPLETION = "chat_completion"
    CODE_GENERATION = "code_generation"
    MODERATION = "moderation"
    EMBEDDING = "embedding"
    IMAGE_GENERATION = "image_generation"
    IMAGE_ANALYSIS = "image_analysis"
    FUNCTION_CALLING = "function_calling"
    STREAMING = "streaming"


class AccessLevel(Enum):
    """Access control levels for AI features."""
    PUBLIC = "public"
    AUTHENTICATED = "authenticated"
    ADMIN = "admin"
    SYSTEM = "system"


@dataclass
class AIModelConfig:
    """Configuration for an AI model."""
    provider: AIProvider
    model_name: str
    display_name: str
    capabilities: List[ModelCapability]
    max_tokens: int
    cost_per_1k_tokens: float
    rate_limit_per_minute: int
    access_level: AccessLevel
    endpoint_url: Optional[str] = None
    api_key_hash: Optional[str] = None
    custom_headers: Dict[str, str] = None
    timeout_seconds: int = 30
    max_retries: int = 3
    fallback_models: List[str] = None
    enabled: bool = True
    
    def __post_init__(self):
        if self.custom_headers is None:
            self.custom_headers = {}
        if self.fallback_models is None:
            self.fallback_models = []
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['provider'] = self.provider.value
        result['capabilities'] = [cap.value for cap in self.capabilities]
        result['access_level'] = self.access_level.value
        return result


@dataclass
class AIRequest:
    """AI request structure."""
    model_id: str
    prompt: str
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    max_tokens: Optional[int] = None
    temperature: float = 0.7
    system_prompt: Optional[str] = None
    context: List[Dict[str, str]] = None
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.context is None:
            self.context = []
        if self.metadata is None:
            self.metadata = {}


@dataclass
class AIResponse:
    """AI response structure."""
    model_id: str
    content: str
    usage: Dict[str, int]
    latency_ms: float
    provider: AIProvider
    success: bool
    error: Optional[str] = None
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['provider'] = self.provider.value
        return result


class AIProviderInterface:
    """Base interface for AI providers."""
    
    def __init__(self, config: AIModelConfig):
        self.config = config
        self.session = None
        self.rate_limiter = {}
        
    async def initialize(self) -> bool:
        """Initialize the provider."""
        try:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.config.timeout_seconds)
            )
            return True
        except Exception as e:
            logger.error(f"Failed to initialize {self.config.provider.value}: {e}")
            return False
    
    async def cleanup(self):
        """Cleanup resources."""
        if self.session:
            await self.session.close()
    
    async def generate(self, request: AIRequest) -> AIResponse:
        """Generate AI response."""
        raise NotImplementedError("Subclasses must implement generate method")
    
    def check_rate_limit(self, user_id: str) -> bool:
        """Check if user is within rate limits."""
        current_time = time.time()
        user_requests = self.rate_limiter.get(user_id, [])
        
        # Remove old requests (older than 1 minute)
        user_requests = [req_time for req_time in user_requests if current_time - req_time < 60]
        
        # Check if under limit
        if len(user_requests) >= self.config.rate_limit_per_minute:
            return False
        
        # Add current request
        user_requests.append(current_time)
        self.rate_limiter[user_id] = user_requests
        
        return True


class OpenAIProvider(AIProviderInterface):
    """OpenAI provider implementation."""
    
    async def generate(self, request: AIRequest) -> AIResponse:
        start_time = time.time()
        
        try:
            # Check rate limit
            if request.user_id and not self.check_rate_limit(request.user_id):
                return AIResponse(
                    model_id=request.model_id,
                    content="",
                    usage={},
                    latency_ms=0,
                    provider=self.config.provider,
                    success=False,
                    error="Rate limit exceeded"
                )
            
            # Prepare request
            headers = {
                "Authorization": f"Bearer {self._decrypt_api_key()}",
                "Content-Type": "application/json",
                **self.config.custom_headers
            }
            
            # Build messages
            messages = []
            if request.system_prompt:
                messages.append({"role": "system", "content": request.system_prompt})
            
            # Add context
            for msg in request.context:
                messages.append(msg)
            
            # Add current prompt
            messages.append({"role": "user", "content": request.prompt})
            
            payload = {
                "model": self.config.model_name,
                "messages": messages,
                "max_tokens": request.max_tokens or self.config.max_tokens,
                "temperature": request.temperature
            }
            
            # Make request
            endpoint = self.config.endpoint_url or "https://api.openai.com/v1/chat/completions"
            
            async with self.session.post(endpoint, headers=headers, json=payload) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    content = data["choices"][0]["message"]["content"]
                    usage = data.get("usage", {})
                    
                    latency_ms = (time.time() - start_time) * 1000
                    
                    return AIResponse(
                        model_id=request.model_id,
                        content=content,
                        usage=usage,
                        latency_ms=latency_ms,
                        provider=self.config.provider,
                        success=True
                    )
                else:
                    error_data = await response.json()
                    return AIResponse(
                        model_id=request.model_id,
                        content="",
                        usage={},
                        latency_ms=(time.time() - start_time) * 1000,
                        provider=self.config.provider,
                        success=False,
                        error=error_data.get("error", {}).get("message", "Unknown error")
                    )
                    
        except Exception as e:
            return AIResponse(
                model_id=request.model_id,
                content="",
                usage={},
                latency_ms=(time.time() - start_time) * 1000,
                provider=self.config.provider,
                success=False,
                error=str(e)
            )
    
    def _decrypt_api_key(self) -> str:
        """Decrypt API key (placeholder implementation)."""
        # In production, implement proper key decryption
        return "your-openai-api-key"


class AnthropicProvider(AIProviderInterface):
    """Anthropic Claude provider implementation."""
    
    async def generate(self, request: AIRequest) -> AIResponse:
        start_time = time.time()
        
        try:
            if request.user_id and not self.check_rate_limit(request.user_id):
                return AIResponse(
                    model_id=request.model_id,
                    content="",
                    usage={},
                    latency_ms=0,
                    provider=self.config.provider,
                    success=False,
                    error="Rate limit exceeded"
                )
            
            headers = {
                "x-api-key": self._decrypt_api_key(),
                "Content-Type": "application/json",
                "anthropic-version": "2023-06-01",
                **self.config.custom_headers
            }
            
            # Build prompt for Claude
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
                "model": self.config.model_name,
                "prompt": full_prompt,
                "max_tokens_to_sample": request.max_tokens or self.config.max_tokens,
                "temperature": request.temperature
            }
            
            endpoint = self.config.endpoint_url or "https://api.anthropic.com/v1/complete"
            
            async with self.session.post(endpoint, headers=headers, json=payload) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    content = data.get("completion", "")
                    usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}  # Anthropic doesn't provide detailed usage
                    
                    latency_ms = (time.time() - start_time) * 1000
                    
                    return AIResponse(
                        model_id=request.model_id,
                        content=content,
                        usage=usage,
                        latency_ms=latency_ms,
                        provider=self.config.provider,
                        success=True
                    )
                else:
                    error_data = await response.json()
                    return AIResponse(
                        model_id=request.model_id,
                        content="",
                        usage={},
                        latency_ms=(time.time() - start_time) * 1000,
                        provider=self.config.provider,
                        success=False,
                        error=error_data.get("error", {}).get("message", "Unknown error")
                    )
                    
        except Exception as e:
            return AIResponse(
                model_id=request.model_id,
                content="",
                usage={},
                latency_ms=(time.time() - start_time) * 1000,
                provider=self.config.provider,
                success=False,
                error=str(e)
            )
    
    def _decrypt_api_key(self) -> str:
        """Decrypt API key (placeholder implementation)."""
        return "your-anthropic-api-key"
