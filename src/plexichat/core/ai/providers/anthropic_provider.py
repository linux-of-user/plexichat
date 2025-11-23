"""
Anthropic Provider for PlexiChat
================================

Provides integration with Anthropic's Claude models.
"""

from dataclasses import dataclass
import logging
from typing import Any

try:
    import anthropic  # type: ignore
    from anthropic import Anthropic  # type: ignore

    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False
    anthropic = None
    Anthropic = None

from plexichat.features.ai.core.ai_abstraction_layer import (
    AIModel,
    AIProvider,
    AIRequest,
    AIResponse,
    ModelCapability,
    ModelStatus,
)
from plexichat.features.ai.providers.base_provider import (
    BaseAIProvider,
    ProviderConfig,
    ProviderStatus,
)

logger = logging.getLogger(__name__)


@dataclass
class AnthropicConfig(ProviderConfig):
    """Anthropic-specific configuration."""

    pass


class AnthropicProvider(BaseAIProvider):
    """Anthropic provider implementation."""

    def __init__(self, config: AnthropicConfig):
        """Initialize Anthropic provider."""
        super().__init__(config)
        self.config: AnthropicConfig = config
        self.client: Any | None = None

        if not ANTHROPIC_AVAILABLE:
            logger.error("Anthropic library not available")
            self.status = ProviderStatus.ERROR
            return

        try:
            if Anthropic:
                self.client = Anthropic(
                    api_key=config.api_key,
                    base_url=config.base_url,
                    timeout=config.timeout,
                    max_retries=config.max_retries,
                )
            self._load_models()
        except Exception as e:
            logger.error(f"Failed to initialize Anthropic client: {e}")
            self.status = ProviderStatus.ERROR

    def _load_models(self) -> None:
        """Load available Anthropic models."""
        try:
            # Define common Anthropic models
            models_data = [
                {
                    "id": "claude-3-opus-20240229",
                    "name": "Claude 3 Opus",
                    "capabilities": [
                        ModelCapability.CHAT,
                        ModelCapability.TEXT_GENERATION,
                    ],
                    "max_tokens": 4096,
                    "cost_per_token": 0.000015,
                },
                {
                    "id": "claude-3-sonnet-20240229",
                    "name": "Claude 3 Sonnet",
                    "capabilities": [
                        ModelCapability.CHAT,
                        ModelCapability.TEXT_GENERATION,
                    ],
                    "max_tokens": 4096,
                    "cost_per_token": 0.000003,
                },
                {
                    "id": "claude-3-haiku-20240307",
                    "name": "Claude 3 Haiku",
                    "capabilities": [
                        ModelCapability.CHAT,
                        ModelCapability.TEXT_GENERATION,
                    ],
                    "max_tokens": 4096,
                    "cost_per_token": 0.00000025,
                },
            ]

            for model_data in models_data:
                model = AIModel(
                    id=model_data["id"],
                    name=model_data["name"],
                    provider=AIProvider.ANTHROPIC,
                    capabilities=model_data["capabilities"],
                    max_tokens=model_data["max_tokens"],
                    cost_per_token=model_data["cost_per_token"],
                    status=ModelStatus.AVAILABLE,
                )
                self.models[model.id] = model

        except Exception as e:
            logger.error(f"Failed to load Anthropic models: {e}")

    async def test_connection(self) -> bool:
        """Test Anthropic connection."""
        if not self.client:
            return False

        try:
            # Try a simple message as a connection test
            message = self.client.messages.create(
                model="claude-3-haiku-20240307",
                max_tokens=10,
                messages=[{"role": "user", "content": "Hi"}],
            )
            return message is not None
        except Exception as e:
            logger.error(f"Anthropic connection test failed: {e}")
            return False

    def get_available_models(self) -> list[AIModel]:
        """Get list of available Anthropic models."""
        return list(self.models.values())

    def is_model_available(self, model_id: str) -> bool:
        """Check if Anthropic model is available."""
        return model_id in self.models and self.status == ProviderStatus.AVAILABLE

    async def process_request(self, request: AIRequest) -> AIResponse:
        """Process request using Anthropic."""
        if not self.client:
            return AIResponse(
                request_id=request.id,
                content="",
                model_id=request.model_id,
                provider=AIProvider.ANTHROPIC.value,
                status="error",
                error="Anthropic client not initialized",
            )

        try:
            # Prepare messages for Claude
            messages = [{"role": "user", "content": request.prompt}]

            # Make the API call
            response = self.client.messages.create(
                model=request.model_id,
                max_tokens=(
                    request.parameters.get("max_tokens", 1000)
                    if request.parameters
                    else 1000
                ),
                temperature=(
                    request.parameters.get("temperature", 0.7)
                    if request.parameters
                    else 0.7
                ),
                system=request.context if request.context else "",
                messages=messages,
            )

            # Extract response content
            content = response.content[0].text if response.content else ""

            # Calculate usage
            usage = {
                "input_tokens": response.usage.input_tokens if response.usage else 0,
                "output_tokens": response.usage.output_tokens if response.usage else 0,
                "total_tokens": (
                    (response.usage.input_tokens + response.usage.output_tokens)
                    if response.usage
                    else 0
                ),
            }

            return AIResponse(
                request_id=request.id,
                content=content,
                model_id=request.model_id,
                provider=AIProvider.ANTHROPIC.value,
                usage=usage,
                metadata={"model": response.model},
            )

        except Exception as e:
            logger.error(f"Anthropic request failed: {e}")
            return AIResponse(
                request_id=request.id,
                content="",
                model_id=request.model_id,
                provider=AIProvider.ANTHROPIC.value,
                status="error",
                error=str(e),
            )
