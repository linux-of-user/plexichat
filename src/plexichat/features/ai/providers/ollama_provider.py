"""
Ollama Provider for PlexiChat
=============================

Provides integration with Ollama for local AI models.
"""

from dataclasses import dataclass
import logging

import aiohttp

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
class OllamaConfig(ProviderConfig):
    """Ollama-specific configuration."""
    host: str = "localhost"
    port: int = 11434

    def get_base_url(self) -> str:
        """Get the base URL for Ollama."""
        return f"http://{self.host}:{self.port}"


class OllamaProvider(BaseAIProvider):
    """Ollama provider implementation."""

    def __init__(self, config: OllamaConfig):
        """Initialize Ollama provider."""
        super().__init__(config)
        self.config: OllamaConfig = config
        self.session: aiohttp.ClientSession | None = None

        # Initialize session
        self._initialize_session()

    def _initialize_session(self) -> None:
        """Initialize HTTP session."""
        try:
            timeout = aiohttp.ClientTimeout(total=self.config.timeout)
            self.session = aiohttp.ClientSession(timeout=timeout)
        except Exception as e:
            logger.error(f"Failed to initialize Ollama session: {e}")
            self.status = ProviderStatus.ERROR

    async def _load_models(self) -> None:
        """Load available Ollama models."""
        if not self.session:
            return

        try:
            async with self.session.get(f"{self.config.get_base_url()}/api/tags") as response:
                if response.status == 200:
                    data = await response.json()
                    models_data = data.get("models", [])

                    for model_data in models_data:
                        model = AIModel(
                            id=model_data["name"],
                            name=model_data.get("name", model_data["name"]),
                            provider=AIProvider.OLLAMA,
                            capabilities=[ModelCapability.CHAT, ModelCapability.TEXT_GENERATION],
                            max_tokens=4096,  # Default for most Ollama models
                            cost_per_token=0.0,  # Local models are free
                            status=ModelStatus.AVAILABLE,
                            description=f"Ollama model: {model_data['name']}"
                        )
                        self.models[model.id] = model

        except Exception as e:
            logger.error(f"Failed to load Ollama models: {e}")

    async def test_connection(self) -> bool:
        """Test Ollama connection."""
        if not self.session:
            return False

        try:
            async with self.session.get(f"{self.config.get_base_url()}/api/tags") as response:
                return response.status == 200
        except Exception as e:
            logger.error(f"Ollama connection test failed: {e}")
            return False

    def get_available_models(self) -> list[AIModel]:
        """Get list of available Ollama models."""
        return list(self.models.values())

    def is_model_available(self, model_id: str) -> bool:
        """Check if Ollama model is available."""
        return model_id in self.models and self.status == ProviderStatus.AVAILABLE

    async def process_request(self, request: AIRequest) -> AIResponse:
        """Process request using Ollama."""
        if not self.session:
            return AIResponse(
                request_id=request.id,
                content="",
                model_id=request.model_id,
                provider=AIProvider.OLLAMA.value,
                status="error",
                error="Ollama session not initialized"
            )

        try:
            # Prepare the request payload
            payload = {
                "model": request.model_id,
                "prompt": request.prompt,
                "stream": False,
                "options": {
                    "temperature": request.parameters.get("temperature", 0.7) if request.parameters else 0.7,
                    "num_predict": request.parameters.get("max_tokens", 1000) if request.parameters else 1000
                }
            }

            if request.context:
                payload["system"] = request.context

            # Make the API call
            async with self.session.post(
                f"{self.config.get_base_url()}/api/generate",
                json=payload
            ) as response:

                if response.status == 200:
                    data = await response.json()

                    return AIResponse(
                        request_id=request.id,
                        content=data.get("response", ""),
                        model_id=request.model_id,
                        provider=AIProvider.OLLAMA.value,
                        usage={
                            "prompt_eval_count": data.get("prompt_eval_count", 0),
                            "eval_count": data.get("eval_count", 0),
                            "total_duration": data.get("total_duration", 0)
                        },
                        metadata={
                            "model": data.get("model", request.model_id),
                            "done": data.get("done", True)
                        }
                    )
                else:
                    error_text = await response.text()
                    return AIResponse(
                        request_id=request.id,
                        content="",
                        model_id=request.model_id,
                        provider=AIProvider.OLLAMA.value,
                        status="error",
                        error=f"HTTP {response.status}: {error_text}"
                    )

        except Exception as e:
            logger.error(f"Ollama request failed: {e}")
            return AIResponse(
                request_id=request.id,
                content="",
                model_id=request.model_id,
                provider=AIProvider.OLLAMA.value,
                status="error",
                error=str(e)
            )

    async def close(self) -> None:
        """Close the HTTP session."""
        if self.session:
            await self.session.close()
            self.session = None


