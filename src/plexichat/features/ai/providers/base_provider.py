import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, AsyncGenerator, Dict, List, Optional

import aiohttp


"""
Base AI Provider Interface
Common interface for all AI providers with standardized methods and error handling.
"""

logger = logging.getLogger(__name__)

class ProviderStatus(str, Enum):
    """Provider status."""
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    RATE_LIMITED = "rate_limited"
    ERROR = "error"
    MAINTENANCE = "maintenance"
    INITIALIZING = "initializing"

@dataclass
class ProviderConfig:
    """Base provider configuration."""
    name: str
    provider_type: str
    api_key: str
    base_url: str
    timeout_seconds: int = 30
    max_retries: int = 3
    rate_limit_rpm: int = 60
    rate_limit_tpm: int = 90000
    enabled: bool = True
    custom_headers: Dict[str, str] = None
    
    def __post_init__(self):
        if self.custom_headers is None:
            self.custom_headers = {}

@dataclass
class AIRequest:
    """Standardized AI request."""
    user_id: str
    model_id: str
    prompt: str
    max_tokens: Optional[int] = None
    temperature: float = 0.7
    stream: bool = False
    system_prompt: Optional[str] = None
    context: Optional[List[Dict[str, str]]] = None
    metadata: Optional[Dict[str, Any]] = None
    request_id: Optional[str] = None

@dataclass
class AIResponse:
    """Standardized AI response."""
    request_id: str
    model_id: str
    content: str
    usage: Dict[str, Any]
    cost: float
    latency_ms: int
    provider: str
    timestamp: datetime
    metadata: Optional[Dict[str, Any]] = None
    success: bool = True
    error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "request_id": self.request_id,
            "model_id": self.model_id,
            "content": self.content,
            "usage": self.usage,
            "cost": self.cost,
            "latency_ms": self.latency_ms,
            "provider": self.provider,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
            "success": self.success,
            "error": self.error
        }

class BaseAIProvider(ABC):
    """Base class for all AI providers."""
    
    def __init__(self, config: ProviderConfig):
        self.config = config
        self.status = ProviderStatus.INITIALIZING
        self.session: Optional[aiohttp.ClientSession] = None
        self.rate_limiter = {}
        self.last_request_time = {}
        
    async def initialize(self) -> bool:
        """Initialize the provider."""
        try:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.config.timeout_seconds),
                headers=self.config.custom_headers
            )
            
            # Test connection
            if await self._test_connection():
                self.status = ProviderStatus.AVAILABLE
                logger.info(f"Provider {self.config.name} initialized successfully")
                return True
            else:
                self.status = ProviderStatus.ERROR
                logger.error(f"Provider {self.config.name} connection test failed")
                return False
                
        except Exception as e:
            self.status = ProviderStatus.ERROR
            logger.error(f"Failed to initialize provider {self.config.name}: {e}")
            return False
    
    async def cleanup(self):
        """Cleanup resources."""
        if self.session:
            await self.session.close()
        self.status = ProviderStatus.UNAVAILABLE
    
    @abstractmethod
    async def _test_connection(self) -> bool:
        """Test provider connection."""
    
    @abstractmethod
    async def generate(self, request: AIRequest) -> AIResponse:
        """Generate AI response."""
    
    @abstractmethod
    async def stream_generate(self, request: AIRequest) -> AsyncGenerator[str, None]:
        """Generate streaming AI response."""
    
    @abstractmethod
    async def get_available_models(self) -> List[Dict[str, Any]]:
        """Get list of available models."""
    
    async def check_rate_limit(self, model_id: str) -> bool:
        """Check if request is within rate limits."""
        current_time = datetime.now(timezone.utc)
        
        # Simple rate limiting implementation
        if model_id not in self.rate_limiter:
            self.rate_limiter[model_id] = []
        
        # Remove old requests (older than 1 minute)
        minute_ago = current_time.timestamp() - 60
        self.rate_limiter[model_id] = [
            req_time for req_time in self.rate_limiter[model_id]
            if req_time > minute_ago
        ]
        
        # Check if under limit
        if len(self.rate_limiter[model_id]) >= self.config.rate_limit_rpm:
            self.status = ProviderStatus.RATE_LIMITED
            return False
        
        # Add current request
        self.rate_limiter[model_id].append(current_time.timestamp())
        return True
    
    def _calculate_cost(self, model_id: str, usage: Dict[str, Any]) -> float:
        """Calculate request cost (to be overridden by providers)."""
        return 0.0
    
    def get_status(self) -> Dict[str, Any]:
        """Get provider status information."""
        return {
            "name": self.config.name,
            "provider_type": self.config.provider_type,
            "status": self.status.value,
            "enabled": self.config.enabled,
            "base_url": self.config.base_url,
            "rate_limit_rpm": self.config.rate_limit_rpm,
            "rate_limit_tpm": self.config.rate_limit_tpm
        }
