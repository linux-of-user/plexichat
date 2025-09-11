"""
Base Provider for AI Services
============================

Abstract base class for all AI providers in PlexiChat.
Provides common interface and functionality.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import logging
from typing import Any

from plexichat.features.ai.core.ai_abstraction_layer import (
    AIModel,
    AIRequest,
    AIResponse,
    ModelStatus,
)

logger = logging.getLogger(__name__)


class ProviderStatus(Enum):
    """Provider status enumeration."""
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    ERROR = "error"
    MAINTENANCE = "maintenance"
    RATE_LIMITED = "rate_limited"


@dataclass
class ProviderConfig:
    """Base configuration for AI providers."""
    api_key: str | None = None
    base_url: str | None = None
    timeout: int = 30
    max_retries: int = 3
    rate_limit: int | None = None
    enabled: bool = True


class BaseAIProvider(ABC):
    """Abstract base class for AI providers."""

    def __init__(self, config: ProviderConfig):
        """Initialize the provider."""
        self.config = config
        self.status = ProviderStatus.UNAVAILABLE
        self.models: dict[str, AIModel] = {}
        self.metrics: dict = {}
        self.last_health_check: datetime | None = None

        # Initialize provider
        self._initialize()

    def _initialize(self) -> None:
        """Initialize the provider."""
        try:
            if self.config.enabled:
                self.status = ProviderStatus.AVAILABLE
                logger.info(f"Initialized provider: {self.__class__.__name__}")
            else:
                self.status = ProviderStatus.UNAVAILABLE
                logger.info(f"Provider disabled: {self.__class__.__name__}")
        except Exception as e:
            self.status = ProviderStatus.ERROR
            logger.error(f"Failed to initialize provider {self.__class__.__name__}: {e}")

    @abstractmethod
    async def test_connection(self) -> bool:
        """Test provider connection."""
        pass

    @abstractmethod
    def get_available_models(self) -> list[AIModel]:
        """Get list of available models."""
        pass

    @abstractmethod
    def is_model_available(self, model_id: str) -> bool:
        """Check if a specific model is available."""
        pass

    def get_model_info(self, model_id: str) -> AIModel | None:
        """Get information about a specific model."""
        return self.models.get(model_id)

    def get_model_status(self, model_id: str) -> ModelStatus:
        """Get the status of a specific model."""
        model = self.get_model_info(model_id)
        if not model:
            return ModelStatus.UNAVAILABLE

        if not self.is_model_available(model_id):
            return ModelStatus.UNAVAILABLE

        if self.status == ProviderStatus.RATE_LIMITED:
            return ModelStatus.RATE_LIMITED
        elif self.status == ProviderStatus.ERROR:
            return ModelStatus.ERROR
        elif self.status == ProviderStatus.MAINTENANCE:
            return ModelStatus.MAINTENANCE
        else:
            return ModelStatus.AVAILABLE

    def get_provider_status(self) -> ProviderStatus:
        """Get current provider status."""
        return self.status

    @abstractmethod
    async def process_request(self, request: AIRequest) -> AIResponse:
        """Process an AI request."""
        pass

    async def health_check(self) -> bool:
        """Perform health check."""
        try:
            result = await self.test_connection()
            self.last_health_check = datetime.now()

            if result:
                if self.status == ProviderStatus.ERROR:
                    self.status = ProviderStatus.AVAILABLE
                return True
            else:
                self.status = ProviderStatus.ERROR
                return False

        except Exception as e:
            logger.error(f"Health check failed for {self.__class__.__name__}: {e}")
            self.status = ProviderStatus.ERROR
            return False

    def get_metrics(self) -> dict[str, Any]:
        """Get provider metrics."""
        return {
            "status": self.status.value,
            "models_count": len(self.models),
            "last_health_check": self.last_health_check.isoformat() if self.last_health_check else None,
            "metrics": self.metrics
        }

    def update_metrics(self, metric_name: str, value: Any) -> None:
        """Update provider metrics."""
        self.metrics[metric_name] = value

    def __str__(self) -> str:
        """String representation."""
        return f"{self.__class__.__name__}(status={self.status.value})"

    def __repr__(self) -> str:
        """Detailed representation."""
        return f"{self.__class__.__name__}(status={self.status.value}, models={len(self.models)})"
