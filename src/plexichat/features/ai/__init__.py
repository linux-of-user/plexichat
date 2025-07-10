"""
PlexiChat AI Module

Consolidated AI functionality from:
- src/plexichat/ai/ (main AI system)
- src/plexichat/app/api/v1/ai_features.py (AI API features)

Comprehensive AI abstraction layer with multi-provider support, featuring:
- Multi-provider AI integration (OpenAI, Anthropic, Ollama, etc.)
- AI-powered features (summarization, content suggestions, sentiment analysis)
- Content moderation and safety systems
- Real-time monitoring and analytics
- Provider management and failover
- API endpoints for AI features
"""

# Core AI components
from .core.ai_abstraction_layer import (
    AIAbstractionLayer,
    AIRequest,
    AIResponse,
    AIModel,
    AIProvider,
    ModelCapability,
    ModelStatus,
    AIAccessControl
)

# AI features and services
from .features.ai_powered_features_service import AIPoweredFeaturesService
from .moderation.moderation_engine import ModerationEngine
from .monitoring.analytics_engine import AnalyticsEngine
from .providers.base_provider import BaseProvider
from .ai_coordinator import AICoordinator

# API components
from .api.ai_endpoints import router as ai_router
from .api.moderation_endpoints import router as moderation_router
from .api.monitoring_endpoints import router as monitoring_router
from .api.provider_endpoints import router as provider_router

__version__ = "2.0.0"
__all__ = [
    # Core AI components
    "AIAbstractionLayer",
    "AIRequest",
    "AIResponse",
    "AIModel",
    "AIProvider",
    "ModelCapability",
    "ModelStatus",
    "AIAccessControl",

    # AI services
    "AIPoweredFeaturesService",
    "ModerationEngine",
    "AnalyticsEngine",
    "BaseProvider",
    "AICoordinator",

    # API routers
    "ai_router",
    "moderation_router",
    "monitoring_router",
    "provider_router"
]

# AI system capabilities
AI_FEATURES = {
    "multi_provider_support": True,
    "content_moderation": True,
    "sentiment_analysis": True,
    "text_summarization": True,
    "content_suggestions": True,
    "semantic_search": True,
    "real_time_monitoring": True,
    "provider_failover": True,
    "api_integration": True,
    "web_ui_management": True
}
