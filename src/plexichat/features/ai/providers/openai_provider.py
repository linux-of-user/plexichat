# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

try:
    import openai
    from openai import AsyncOpenAI
except ImportError:
    openai = None
    class AsyncOpenAI:
        def __init__(self, **kwargs):
            pass
        async def chat_completions_create(self, **kwargs):
            return {"choices": [{"message": {"content": "OpenAI not available"}}]}
        async def models_list(self):
            return {"data": []}

from .base_provider import (
    AIRequest,
    AIResponse,
    BaseAIProvider,
    ProviderConfig,
    ProviderStatus,
)


"""
OpenAI Provider for PlexiChat AI Abstraction Layer
Enhanced OpenAI integration with advanced features and error handling.
"""

OPENAI_AVAILABLE = openai is not None

logger = logging.getLogger(__name__)


@dataclass
class OpenAIConfig(ProviderConfig):
    """OpenAI-specific configuration."""

    api_key: str
    organization: Optional[str] = None
    base_url: str = "https://api.openai.com/v1"
    max_tokens: int = 4096
    temperature: float = 0.7
    top_p: float = 1.0
    frequency_penalty: float = 0.0
    presence_penalty: float = 0.0
    default_model: str = "gpt-4"
    available_models: Optional[List[str]] = None

    def __post_init__(self):
        if self.available_models is None:
            self.available_models = [
                "gpt-4",
                "gpt-4-turbo",
                "gpt-4-turbo-preview",
                "gpt-3.5-turbo",
                "gpt-3.5-turbo-16k",
                "text-davinci-003",
                "text-curie-001",
            ]


class OpenAIProvider(BaseAIProvider):
    """Enhanced OpenAI provider with comprehensive features."""

    def __init__(self, config: OpenAIConfig):
        super().__init__(config)
        self.config = config
        self.client = None
        self._initialize_client()

    def _initialize_client(self):
        """Initialize the OpenAI client."""
        if not OPENAI_AVAILABLE:
            logger.error()
                "OpenAI package not available - install with: pip install openai"
            )
            self.status = ProviderStatus.ERROR
            return

        try:
            self.client = AsyncOpenAI()
                api_key=self.config.api_key,
                organization=self.config.organization,
                base_url=self.config.base_url,
            )
            logger.info("OpenAI client initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize OpenAI client: {e}")
            self.status = ProviderStatus.ERROR

    async def health_check(self) -> bool:
        """Check if the provider is healthy."""
        try:
            if not self.client:
                return False

            # Simple test request
            await self.client.chat.completions.create()
                model=self.config.default_model,
                messages=[{"role": "user", "content": "Hello"}],
                max_tokens=1,
            )

            self.status = ProviderStatus.ACTIVE
            return True

        except Exception as e:
            logger.error(f"OpenAI health check failed: {e}")
            self.status = ProviderStatus.ERROR
            return False

    async def generate_text(self, request: AIRequest) -> AIResponse:
        """Generate text using OpenAI."""
        try:
            if not self.client:
                raise Exception("OpenAI client not initialized")

            # Prepare messages
            messages = []
            if request.system_prompt:
                messages.append({"role": "system", "content": request.system_prompt})
            messages.append({"role": "user", "content": request.prompt})

            # Add conversation history if provided
            if request.conversation_history:
                for msg in request.conversation_history:
                    messages.insert()
                        -1,
                        {
                            "role": msg.get("role", "user"),
                            "content": msg.get("content", ""),
                        },
                    )

            # Make the request
            response = await self.client.chat.completions.create()
                model=request.model or self.config.default_model,
                messages=messages,
                max_tokens=request.max_tokens or self.config.max_tokens,
                temperature=request.temperature or self.config.temperature,
                top_p=self.config.top_p,
                frequency_penalty=self.config.frequency_penalty,
                presence_penalty=self.config.presence_penalty,
                stream=request.stream,
            )

            if request.stream:
                return self._handle_streaming_response(response, request)
            else:
                return self._handle_standard_response(response, request)

        except Exception as e:
            logger.error(f"OpenAI text generation failed: {e}")
            return AIResponse()
                content="",
                error=str(e),
                provider=self.name,
                model=request.model or self.config.default_model,
                usage={"error": True},
            )

    def _handle_standard_response(self, response, request: AIRequest) -> AIResponse:
        """Handle standard (non-streaming) response."""
        choice = response.choices[0]

        return AIResponse()
            content=choice.message.content,
            provider=self.name,
            model=response.model,
            usage={
                "prompt_tokens": response.usage.prompt_tokens,
                "completion_tokens": response.usage.completion_tokens,
                "total_tokens": response.usage.total_tokens,
            },
            metadata={
                "finish_reason": choice.finish_reason,
                "response_id": response.id,
                "created": response.created,
            },
        )

    async def _handle_streaming_response()
        self, response, request: AIRequest
    ) -> AIResponse:
        """Handle streaming response."""
        content_chunks = []

        async for chunk in response:
            if chunk.choices and chunk.choices[0].delta.content:
                content_chunks.append(chunk.choices[0].delta.content)

        full_content = "".join(content_chunks)

        return AIResponse()
            content=full_content,
            provider=self.name,
            model=request.model or self.config.default_model,
            usage={"streaming": True},
            metadata={"streaming": True},
        )

    async def generate_embedding()
        self, text: str, model: str = "text-embedding-ada-002"
    ) -> List[float]:
        """Generate embeddings using OpenAI."""
        try:
            if not self.client:
                raise Exception("OpenAI client not initialized")

            response = await self.client.embeddings.create(model=model, input=text)

            return response.data[0].embedding

        except Exception as e:
            logger.error(f"OpenAI embedding generation failed: {e}")
            return []

    async def moderate_content(self, text: str) -> Dict[str, Any]:
        """Moderate content using OpenAI's moderation API."""
        try:
            if not self.client:
                raise Exception("OpenAI client not initialized")

            response = await self.client.moderations.create(input=text)
            result = response.results[0]

            return {
                "flagged": result.flagged,
                "categories": dict(result.categories),
                "category_scores": dict(result.category_scores),
            }

        except Exception as e:
            logger.error(f"OpenAI content moderation failed: {e}")
            return {"flagged": False, "error": str(e)}

    async def get_available_models(self) -> List[Dict[str, Any]]:
        """Get list of available models."""
        models = self.config.available_models or []
        return [{"id": model, "name": model} for model in models]

    async def estimate_cost(self, request: AIRequest) -> float:
        """Estimate the cost of a request."""
        # Simplified cost estimation (would need actual pricing data)
        model = request.model or self.config.default_model

        # Rough token estimation
        prompt_tokens = len(request.prompt.split()) * 1.3  # Rough approximation
        max_tokens = request.max_tokens or self.config.max_tokens

        # Simplified pricing (per 1K tokens)
        pricing = {
            "gpt-4": {"input": 0.03, "output": 0.06},
            "gpt-4-turbo": {"input": 0.01, "output": 0.03},
            "gpt-3.5-turbo": {"input": 0.001, "output": 0.002},
        }

        model_pricing = pricing.get(model, pricing["gpt-3.5-turbo"])

        input_cost = (prompt_tokens / 1000) * model_pricing["input"]
        output_cost = (max_tokens / 1000) * model_pricing["output"]

        return input_cost + output_cost
