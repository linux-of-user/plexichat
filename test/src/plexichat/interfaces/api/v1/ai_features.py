# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import logging

from typing import Any, Dict, Optional


from ....ai.features.ai_powered_features_service import AIPoweredFeaturesService
from ....core.logging import get_logger


from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

"""
PlexiChat AI-Powered Features API

FastAPI router for AI-powered features including summarization,
content suggestions, sentiment analysis, semantic search, and moderation.
"""

logger = get_logger(__name__)

# Create router
router = APIRouter(prefix="/admin/ai-features", tags=["ai-features-admin"])

# Templates
templates = Jinja2Templates(directory="src/plexichat/web/templates")

# Global service instance
ai_features_service: Optional[AIPoweredFeaturesService] = None


def get_ai_features_service() -> AIPoweredFeaturesService:
    """Get or create AI features service instance."""
    global ai_features_service
    if ai_features_service is None:
        ai_features_service = AIPoweredFeaturesService()
    return ai_features_service


# Pydantic models
class SummarizationRequest(BaseModel):
    text: str
    summary_type: str = "brief"
    max_length: Optional[int] = None
    user_id: str = "admin"


class ContentSuggestionsRequest(BaseModel):
    context: str
    suggestion_type: str = "completion"
    max_suggestions: int = 3
    user_id: str = "admin"


class SentimentAnalysisRequest(BaseModel):
    text: str
    include_emotions: bool = True
    user_id: str = "admin"


class SemanticSearchRequest(BaseModel):
    query: str
    max_results: int = 10
    similarity_threshold: float = 0.3
    filters: Optional[Dict[str, Any]] = None


class ContentModerationRequest(BaseModel):
    content: str
    content_id: Optional[str] = None
    user_id: str = "admin"
    metadata: Optional[Dict[str, Any]] = None


class AddToIndexRequest(BaseModel):
    content_id: str
    content: str
    metadata: Dict[str, Any] = {}


class ClearCacheRequest(BaseModel):
    feature_type: Optional[str] = None


# Routes
@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """AI features management dashboard."""
    try:
        service = get_ai_features_service()

        # Get service statistics
        stats = await service.get_feature_statistics()

        # Get health status
        health = await service.health_check()

        return templates.TemplateResponse()
            "admin/ai_features_management.html",
            {
                "request": request,
                "stats": stats,
                "health": health,
                "config": service.config,
            },
        )

    except Exception as e:
        logger.error(f"Failed to load AI features dashboard: {e}")
        return templates.TemplateResponse()
            "admin/ai_features_management.html",
            {
                "request": request,
                "stats": {},
                "health": {},
                "config": {},
                "error": str(e),
            },
        )


@router.post("/api/summarize")
async def api_summarize(request: SummarizationRequest):
    """API endpoint for text summarization."""
    try:
        service = get_ai_features_service()
        result = await service.create_summary()
            text=request.text,
            summary_type=request.summary_type,
            user_id=request.user_id,
            max_length=request.max_length,
        )

        return JSONResponse()
            {
                "success": True,
                "result": {
                    "summary_id": result.summary_id,
                    "summary": result.summary,
                    "summary_type": result.summary_type,
                    "confidence_score": result.confidence_score,
                    "processing_time_ms": result.processing_time_ms,
                    "word_count_original": result.word_count_original,
                    "word_count_summary": result.word_count_summary,
                    "compression_ratio": result.compression_ratio,
                    "key_topics": result.key_topics,
                    "created_at": result.created_at.isoformat(),
                },
            }
        )

    except Exception as e:
        logger.error(f"Summarization API error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/suggest-content")
async def api_suggest_content(request: ContentSuggestionsRequest):
    """API endpoint for content suggestions."""
    try:
        service = get_ai_features_service()
        suggestions = await service.generate_content_suggestions()
            context=request.context,
            suggestion_type=request.suggestion_type,
            user_id=request.user_id,
            max_suggestions=request.max_suggestions,
        )

        return JSONResponse()
            {
                "success": True,
                "suggestions": [
                    {
                        "suggestion_id": s.suggestion_id,
                        "suggestion": s.suggestion,
                        "suggestion_type": s.suggestion_type,
                        "confidence_score": s.confidence_score,
                        "relevance_score": s.relevance_score,
                        "created_at": s.created_at.isoformat(),
                    }
                    for s in suggestions
                ],
            }
        )

    except Exception as e:
        logger.error(f"Content suggestions API error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/analyze-sentiment")
async def api_analyze_sentiment(request: SentimentAnalysisRequest):
    """API endpoint for sentiment analysis."""
    try:
        service = get_ai_features_service()
        result = await service.analyze_sentiment()
            text=request.text,
            user_id=request.user_id,
            include_emotions=request.include_emotions,
        )

        return JSONResponse()
            {
                "success": True,
                "result": {
                    "analysis_id": result.analysis_id,
                    "sentiment": result.sentiment.value,
                    "confidence_score": result.confidence_score,
                    "emotion_scores": result.emotion_scores,
                    "key_phrases": result.key_phrases,
                    "processing_time_ms": result.processing_time_ms,
                    "created_at": result.created_at.isoformat(),
                },
            }
        )

    except Exception as e:
        logger.error(f"Sentiment analysis API error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/semantic-search")
async def api_semantic_search(request: SemanticSearchRequest):
    """API endpoint for semantic search."""
    try:
        service = get_ai_features_service()
        results = await service.semantic_search()
            query=request.query,
            max_results=request.max_results,
            similarity_threshold=request.similarity_threshold,
            filters=request.filters,
        )

        return JSONResponse()
            {
                "success": True,
                "results": [
                    {
                        "result_id": r.result_id,
                        "content": ()
                            r.content[:500] + "..."
                            if len(r.content) > 500
                            else r.content
                        ),
                        "similarity_score": r.similarity_score,
                        "metadata": r.metadata,
                        "highlighted_text": ()
                            r.highlighted_text[:500] + "..."
                            if r.highlighted_text and len(r.highlighted_text) > 500
                            else r.highlighted_text
                        ),
                    }
                    for r in results
                ],
                "total_results": len(results),
            }
        )

    except Exception as e:
        logger.error(f"Semantic search API error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/moderate-content")
async def api_moderate_content(request: ContentModerationRequest):
    """API endpoint for content moderation."""
    try:
        service = get_ai_features_service()
        result = await service.moderate_content()
            content=request.content,
            content_id=request.content_id,
            user_id=request.user_id,
            metadata=request.metadata,
        )

        return JSONResponse()
            {
                "success": True,
                "result": {
                    "moderation_id": result.moderation_id,
                    "action": result.action.value,
                    "confidence_score": result.confidence_score,
                    "violation_categories": result.violation_categories,
                    "severity_score": result.severity_score,
                    "explanation": result.explanation,
                    "processing_time_ms": result.processing_time_ms,
                    "created_at": result.created_at.isoformat(),
                },
            }
        )

    except Exception as e:
        logger.error(f"Content moderation API error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/add-to-index")
async def api_add_to_index(request: AddToIndexRequest):
    """API endpoint to add content to semantic search index."""
    try:
        service = get_ai_features_service()
        success = await service.add_to_semantic_index()
            content_id=request.content_id,
            content=request.content,
            metadata=request.metadata,
        )

        return JSONResponse()
            {
                "success": success,
                "message": ()
                    "Content added to semantic index"
                    if success
                    else "Failed to add content to index"
                ),
            }
        )

    except Exception as e:
        logger.error(f"Add to index API error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/statistics")
async def api_statistics():
    """API endpoint to get feature statistics."""
    try:
        service = get_ai_features_service()
        stats = await service.get_feature_statistics()

        return JSONResponse({"success": True, "statistics": stats})

    except Exception as e:
        logger.error(f"Statistics API error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/health")
async def api_health():
    """API endpoint for health check."""
    try:
        service = get_ai_features_service()
        health = await service.health_check()

        return JSONResponse({"success": True, "health": health})

    except Exception as e:
        logger.error(f"Health check API error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/clear-cache")
async def api_clear_cache(request: ClearCacheRequest):
    """API endpoint to clear feature caches."""
    try:
        service = get_ai_features_service()
        await service.clear_cache(request.feature_type)

        return JSONResponse()
            {
                "success": True,
                "message": f"Cache cleared for: {request.feature_type or 'all features'}",
            }
        )

    except Exception as e:
        logger.error(f"Clear cache API error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/config")
async def get_config():
    """Get AI features configuration."""
    try:
        service = get_ai_features_service()
        return JSONResponse({"success": True, "config": service.config})

    except Exception as e:
        logger.error(f"Get config API error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/config")
async def update_config(config: Dict[str, Any]):
    """Update AI features configuration."""
    try:
        service = get_ai_features_service()
        service.config.update(config)
        service.save_configuration()

        return JSONResponse()
            {"success": True, "message": "Configuration updated successfully"}
        )

    except Exception as e:
        logger.error(f"Update config API error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
