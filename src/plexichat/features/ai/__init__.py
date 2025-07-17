# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
# Import AI components
from .ai_coordinator_simple import AICoordinator
# from .api.ai_endpoints import router as ai_router
# from .api.moderation_endpoints import router as moderation_router
# from .api.monitoring_endpoints import router as monitoring_router
# from .api.provider_endpoints import router as provider_router
from typing import Optional
from .core.ai_abstraction_layer_simple import (
    AIAbstractionLayer,
    AIAccessControl,
    AIModel,
    AIProvider,
    AIRequest,
    AIResponse,
    ModelCapability,
    ModelStatus,
)

"""
Comprehensive AI abstraction layer with multi-provider support, featuring:
- Multi-provider AI integration (OpenAI, Anthropic, Ollama, etc.)
- AI-powered features (summarization, content suggestions, sentiment analysis)
- Content moderation and safety systems
- Real-time monitoring and analytics
- Provider management and failover
- API endpoints for AI features
"""

# AI features and services
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
    "AICoordinator",
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
