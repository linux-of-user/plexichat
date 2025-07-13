"""
Anthropic Provider for PlexiChat AI Abstraction Layer
Enhanced Anthropic Claude integration with advanced features.
"""

import json
import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

try:
    import anthropic
    from anthropic import AsyncAnthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False
    anthropic = None
    AsyncAnthropic = None

from .base_provider import AIRequest, AIResponse, BaseAIProvider, ProviderConfig, ProviderStatus

logger = logging.getLogger(__name__)

@dataclass
class AnthropicConfig(ProviderConfig):
    """Anthropic-specific configuration."""
    api_key: str
    base_url: Optional[str] = None
    max_tokens: int = 4096
    temperature: float = 0.7
    top_p: float = 1.0
    default_model: str = "claude-3-sonnet-20240229"
    available_models: List[str] = None
    
    def __post_init__(self):
        if self.available_models is None:
            self.available_models = [
                "claude-3-opus-20240229",
                "claude-3-sonnet-20240229", 
                "claude-3-haiku-20240307",
                "claude-2.1",
                "claude-2.0",
                "claude-instant-1.2"
            ]

class AnthropicProvider(BaseAIProvider):
    """Enhanced Anthropic provider with comprehensive features."""
    
    def __init__(self, config: AnthropicConfig):
        super().__init__(config)
        self.config = config
        self.client = None
        self._initialize_client()
    
    def _initialize_client(self):
        """Initialize the Anthropic client."""
        if not ANTHROPIC_AVAILABLE:
            logger.error("Anthropic package not available - install with: pip install anthropic")
            self.status = ProviderStatus.ERROR
            return

        try:
            self.client = AsyncAnthropic(
                api_key=self.config.api_key,
                base_url=self.config.base_url
            )
            logger.info("Anthropic client initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize Anthropic client: {e}")
            self.status = ProviderStatus.ERROR
    
    async def health_check(self) -> bool:
        """Check if the provider is healthy."""
        try:
            if not self.client:
                return False
            
            # Simple test request
            await self.client.messages.create(
                model=self.config.default_model,
                max_tokens=1,
                messages=[{"role": "user", "content": "Hello"}]
            )
            
            self.status = ProviderStatus.ACTIVE
            return True
            
        except Exception as e:
            logger.error(f"Anthropic health check failed: {e}")
            self.status = ProviderStatus.ERROR
            return False
    
    async def generate_text(self, request: AIRequest) -> AIResponse:
        """Generate text using Anthropic Claude."""
        try:
            if not self.client:
                raise Exception("Anthropic client not initialized")
            
            # Prepare messages
            messages = []
            
            # Add conversation history if provided
            if request.conversation_history:
                for msg in request.conversation_history:
                    messages.append({
                        "role": msg.get("role", "user"),
                        "content": msg.get("content", "")
                    })
            
            # Add current prompt
            messages.append({"role": "user", "content": request.prompt})
            
            # Prepare request parameters
            params = {
                "model": request.model or self.config.default_model,
                "max_tokens": request.max_tokens or self.config.max_tokens,
                "temperature": request.temperature or self.config.temperature,
                "top_p": self.config.top_p,
                "messages": messages
            }
            
            # Add system prompt if provided
            if request.system_prompt:
                params["system"] = request.system_prompt
            
            # Make the request
            if request.stream:
                return await self._handle_streaming_request(params, request)
            else:
                response = await self.client.messages.create(**params)
                return self._handle_standard_response(response, request)
                
        except Exception as e:
            logger.error(f"Anthropic text generation failed: {e}")
            return AIResponse(
                content="",
                error=str(e),
                provider=self.name,
                model=request.model or self.config.default_model,
                usage={"error": True}
            )
    
    def _handle_standard_response(self, response, request: AIRequest) -> AIResponse:
        """Handle standard (non-streaming) response."""
        content = ""
        if response.content and len(response.content) > 0:
            content = response.content[0].text
        
        return AIResponse(
            content=content,
            provider=self.name,
            model=response.model,
            usage={
                "input_tokens": response.usage.input_tokens,
                "output_tokens": response.usage.output_tokens,
                "total_tokens": response.usage.input_tokens + response.usage.output_tokens
            },
            metadata={
                "stop_reason": response.stop_reason,
                "response_id": response.id,
                "role": response.role
            }
        )
    
    async def _handle_streaming_request(self, params: Dict, request: AIRequest) -> AIResponse:
        """Handle streaming request."""
        try:
            content_chunks = []
            
            async with self.client.messages.stream(**params) as stream:
                async for text in stream.text_stream:
                    content_chunks.append(text)
            
            full_content = "".join(content_chunks)
            
            return AIResponse(
                content=full_content,
                provider=self.name,
                model=request.model or self.config.default_model,
                usage={"streaming": True},
                metadata={"streaming": True}
            )
            
        except Exception as e:
            logger.error(f"Anthropic streaming failed: {e}")
            return AIResponse(
                content="",
                error=str(e),
                provider=self.name,
                model=request.model or self.config.default_model,
                usage={"error": True}
            )
    
    async def generate_embedding(self, text: str, model: str = None) -> List[float]:
        """Generate embeddings (Anthropic doesn't have embedding API, return empty)."""
        logger.warning("Anthropic doesn't provide embedding API")
        return []
    
    async def moderate_content(self, text: str) -> Dict[str, Any]:
        """Basic content moderation using Claude."""
        try:
            if not self.client:
                raise Exception("Anthropic client not initialized")
            
            moderation_prompt = f"""
            Please analyze the following text for harmful content including:
            - Hate speech
            - Violence
            - Sexual content
            - Self-harm
            - Illegal activities
            
            Text: {text}
            
            Respond with only a JSON object containing:
            {{"flagged": true/false, "categories": ["category1", "category2"], "confidence": 0.0-1.0}}
            """
            
            response = await self.client.messages.create(
                model=self.config.default_model,
                max_tokens=200,
                messages=[{"role": "user", "content": moderation_prompt}]
            )
            
            try:
                result = json.loads(response.content[0].text)
                return result
            except json.JSONDecodeError:
                return {"flagged": False, "error": "Invalid response format"}
                
        except Exception as e:
            logger.error(f"Anthropic content moderation failed: {e}")
            return {"flagged": False, "error": str(e)}
    
    def get_available_models(self) -> List[str]:
        """Get list of available models."""
        return self.config.available_models
    
    async def estimate_cost(self, request: AIRequest) -> float:
        """Estimate the cost of a request."""
        model = request.model or self.config.default_model
        
        # Rough token estimation
        prompt_tokens = len(request.prompt.split()) * 1.3
        max_tokens = request.max_tokens or self.config.max_tokens
        
        # Simplified pricing (per 1M tokens)
        pricing = {
            "claude-3-opus-20240229": {"input": 15.0, "output": 75.0},
            "claude-3-sonnet-20240229": {"input": 3.0, "output": 15.0},
            "claude-3-haiku-20240307": {"input": 0.25, "output": 1.25},
            "claude-2.1": {"input": 8.0, "output": 24.0},
            "claude-2.0": {"input": 8.0, "output": 24.0},
            "claude-instant-1.2": {"input": 0.8, "output": 2.4}
        }
        
        model_pricing = pricing.get(model, pricing["claude-3-sonnet-20240229"])
        
        input_cost = (prompt_tokens / 1000000) * model_pricing["input"]
        output_cost = (max_tokens / 1000000) * model_pricing["output"]
        
        return input_cost + output_cost
