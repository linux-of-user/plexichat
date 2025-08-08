"""
OpenAI Provider for PlexiChat
=============================

Provides integration with OpenAI's GPT models.
"""

import asyncio
import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

try:
    import openai  # type: ignore
    from openai import OpenAI  # type: ignore
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    openai = None
    OpenAI = None

from ..core.ai_abstraction_layer import (
    AIModel,
    AIProvider,
    AIRequest,
    AIResponse,
    ModelCapability,
    ModelStatus,
)
from .base_provider import BaseAIProvider, ProviderConfig, ProviderStatus

logger = logging.getLogger(__name__)


@dataclass
class OpenAIConfig(ProviderConfig):
    """OpenAI-specific configuration."""
    organization: Optional[str] = None
    project: Optional[str] = None


class OpenAIProvider(BaseAIProvider):
    """OpenAI provider implementation."""
    
    def __init__(self, config: OpenAIConfig):
        """Initialize OpenAI provider."""
        super().__init__(config)
        self.config: OpenAIConfig = config
        self.client: Optional[Any] = None
        
        if not OPENAI_AVAILABLE:
            logger.error("OpenAI library not available")
            self.status = ProviderStatus.ERROR
            return
            
        try:
            if OpenAI:
                self.client = OpenAI(
                    api_key=config.api_key,
                    organization=config.organization,
                    project=config.project,
                base_url=config.base_url,
                timeout=config.timeout,
                max_retries=config.max_retries
            )
            self._load_models()
        except Exception as e:
            logger.error(f"Failed to initialize OpenAI client: {e}")
            self.status = ProviderStatus.ERROR

    def _load_models(self) -> None:
        """Load available OpenAI models."""
        try:
            # Define common OpenAI models
            models_data = [
                {
                    "id": "gpt-4",
                    "name": "GPT-4",
                    "capabilities": [ModelCapability.CHAT, ModelCapability.TEXT_GENERATION],
                    "max_tokens": 8192,
                    "cost_per_token": 0.00003
                },
                {
                    "id": "gpt-4-turbo",
                    "name": "GPT-4 Turbo",
                    "capabilities": [ModelCapability.CHAT, ModelCapability.TEXT_GENERATION],
                    "max_tokens": 128000,
                    "cost_per_token": 0.00001
                },
                {
                    "id": "gpt-3.5-turbo",
                    "name": "GPT-3.5 Turbo",
                    "capabilities": [ModelCapability.CHAT, ModelCapability.TEXT_GENERATION],
                    "max_tokens": 4096,
                    "cost_per_token": 0.0000015
                }
            ]
            
            for model_data in models_data:
                model = AIModel(
                    id=model_data["id"],
                    name=model_data["name"],
                    provider=AIProvider.OPENAI,
                    capabilities=model_data["capabilities"],
                    max_tokens=model_data["max_tokens"],
                    cost_per_token=model_data["cost_per_token"],
                    status=ModelStatus.AVAILABLE
                )
                self.models[model.id] = model
                
        except Exception as e:
            logger.error(f"Failed to load OpenAI models: {e}")

    async def test_connection(self) -> bool:
        """Test OpenAI connection."""
        if not self.client:
            return False
            
        try:
            # Try to list models as a connection test
            models = self.client.models.list()
            return len(models.data) > 0
        except Exception as e:
            logger.error(f"OpenAI connection test failed: {e}")
            return False

    def get_available_models(self) -> List[AIModel]:
        """Get list of available OpenAI models."""
        return list(self.models.values())

    def is_model_available(self, model_id: str) -> bool:
        """Check if OpenAI model is available."""
        return model_id in self.models and self.status == ProviderStatus.AVAILABLE

    async def process_request(self, request: AIRequest) -> AIResponse:
        """Process request using OpenAI."""
        if not self.client:
            return AIResponse(
                request_id=request.id,
                content="",
                model_id=request.model_id,
                provider=AIProvider.OPENAI.value,
                status="error",
                error="OpenAI client not initialized"
            )

        try:
            # Prepare messages for chat completion
            messages = [{"role": "user", "content": request.prompt}]
            
            if request.context:
                messages.insert(0, {"role": "system", "content": request.context})

            # Make the API call
            response = self.client.chat.completions.create(  # type: ignore
                model=request.model_id,
                messages=messages,  # type: ignore
                max_tokens=request.parameters.get("max_tokens", 1000) if request.parameters else 1000,
                temperature=request.parameters.get("temperature", 0.7) if request.parameters else 0.7
            )

            # Extract response content
            content = response.choices[0].message.content if response.choices else ""
            if content is None:
                content = ""
            
            # Calculate usage
            usage = {
                "prompt_tokens": response.usage.prompt_tokens if response.usage else 0,
                "completion_tokens": response.usage.completion_tokens if response.usage else 0,
                "total_tokens": response.usage.total_tokens if response.usage else 0
            }

            return AIResponse(
                request_id=request.id,
                content=content,
                model_id=request.model_id,
                provider=AIProvider.OPENAI.value,
                usage=usage,
                metadata={"model": response.model}
            )

        except Exception as e:
            logger.error(f"OpenAI request failed: {e}")
            return AIResponse(
                request_id=request.id,
                content="",
                model_id=request.model_id,
                provider=AIProvider.OPENAI.value,
                status="error",
                error=str(e)
            )
