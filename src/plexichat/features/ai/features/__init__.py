# pyright: reportMissingImports=false
# pyright: reportGeneralTypeIssues=false
# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
from .ai_powered_features_service import AIPoweredFeaturesService, SummarizationResult, ContentSuggestion, SentimentAnalysisResult, SemanticSearchResult, ModerationResult, Sentiment, ModerationAction
from typing import Optional
from plexichat.infrastructure.modules.interfaces import ModulePriority


__all__ = [
    'AIPoweredFeaturesService',
    'SummarizationResult',
    'ContentSuggestion',
    'SentimentAnalysisResult',
    'SemanticSearchResult',
    'ModerationResult',
    'Sentiment',
    'ModerationAction'
]

# Service instance for global access
_ai_features_service = None


def get_ai_features_service() -> AIPoweredFeaturesService:
    """Get the global AI features service instance."""
    global _ai_features_service
    if _ai_features_service is None:
        _ai_features_service = AIPoweredFeaturesService()
    return _ai_features_service


def initialize_ai_features_service(config: Optional[dict] = None) -> AIPoweredFeaturesService:
    """Initialize the AI features service with optional configuration."""
    global _ai_features_service
    _ai_features_service = AIPoweredFeaturesService(config)
    return _ai_features_service
