from .ai_powered_features_service import (
from typing import Optional


    AI,
    TF-IDF,
    AI-Powered,
    AI-powered,
    AIPoweredFeaturesService,
    All,
    Automated,
    Content,
    ContentSuggestion,
    Features,
    ModerationAction,
    ModerationResult,
    Module,
    PlexiChat,
    PlexiChat's,
    Semantic,
    SemanticSearchResult,
    Sentiment,
    SentimentAnalysisResult,
    Smart,
    SummarizationResult,
    This,
    """,
    -,
    abstraction,
    alternatives,
    analysis,
    and,
    are,
    built,
    completion,
    comprehensive,
    content,
    detection,
    emotion,
    fallbacks.,
    features,
    for,
    improvement,
    including:,
    intelligent,
    layer,
    moderation,
    module,
    multiple,
    of,
    on,
    providers,
    provides,
    search,
    suggestions,
    summarization,
    summary,
    support,
    top,
    types,
    vectorization,
    violation,
    with,
)

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
