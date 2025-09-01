import time
from typing import Dict, List, Optional, Any
from fastapi import APIRouter, Depends, Query, HTTPException
from pydantic import BaseModel, Field
from datetime import datetime

from plexichat.core.search_service import (
    get_search_service,
    SearchFilter,
    SearchResult as CoreSearchResult,
    SearchSuggestion,
    SearchHistory
)

# Mock user dependency - replace with actual auth
def get_current_user():
    return {"user_id": "mock_user"}

router = APIRouter(prefix="/search", tags=["Search & Analytics"])


class AdvancedSearchQuery(BaseModel):
    """Advanced search query with filters."""
    query: str = Field(..., min_length=1, max_length=200, description="Search query")
    user_id: Optional[str] = Field(None, description="Filter by specific user")
    channel_id: Optional[str] = Field(None, description="Filter by specific channel")
    date_from: Optional[datetime] = Field(None, description="Filter messages from this date")
    date_to: Optional[datetime] = Field(None, description="Filter messages until this date")
    message_type: Optional[str] = Field(None, description="Filter by message type")
    has_attachments: Optional[bool] = Field(None, description="Filter messages with/without attachments")
    limit: int = Field(50, ge=1, le=100, description="Number of results to return")
    offset: int = Field(0, ge=0, description="Number of results to skip")


class SearchResult(BaseModel):
    """Search result response model."""
    message_id: str
    content: str
    user_id: str
    channel_id: str
    created_at: datetime
    score: float
    highlights: List[str] = []
    metadata: Dict[str, Any] = {}


class SuggestionResponse(BaseModel):
    """Search suggestion response model."""
    text: str
    type: str
    frequency: int = 0
    last_used: Optional[datetime] = None


class HistoryResponse(BaseModel):
    """Search history response model."""
    id: str
    user_id: str
    query: str
    filters: Dict[str, Any]
    result_count: int
    timestamp: datetime
    duration_ms: int


@router.post("/", response_model=Dict[str, Any])
async def advanced_search(query: AdvancedSearchQuery, current_user: dict = Depends(get_current_user)):
    """Perform advanced message search with filters."""
    try:
        search_service = await get_search_service()

        # Convert to SearchFilter
        filters = SearchFilter(
            query=query.query,
            user_id=query.user_id,
            channel_id=query.channel_id,
            date_from=query.date_from,
            date_to=query.date_to,
            message_type=query.message_type,
            has_attachments=query.has_attachments,
            limit=query.limit,
            offset=query.offset
        )

        # Perform search
        results, total = await search_service.search_messages(filters, current_user["user_id"])

        # Convert to response model
        response_results = []
        for result in results:
            response_result = SearchResult(
                message_id=result.message_id,
                content=result.content,
                user_id=result.user_id,
                channel_id=result.channel_id,
                created_at=result.created_at,
                score=result.score,
                highlights=result.highlights,
                metadata=result.metadata
            )
            response_results.append(response_result)

        return {
            "results": response_results,
            "total": total,
            "query": query.query,
            "filters_applied": {
                "user_id": query.user_id,
                "channel_id": query.channel_id,
                "date_from": query.date_from.isoformat() if query.date_from else None,
                "date_to": query.date_to.isoformat() if query.date_to else None,
                "message_type": query.message_type,
                "has_attachments": query.has_attachments
            }
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Search failed: {str(e)}")


@router.get("/suggestions", response_model=List[SuggestionResponse])
async def get_search_suggestions(
    q: str = Query(..., min_length=1, max_length=50, description="Search prefix"),
    limit: int = Query(10, ge=1, le=20, description="Number of suggestions to return")
):
    """Get search suggestions based on prefix."""
    try:
        search_service = await get_search_service()
        suggestions = await search_service.get_suggestions(q, limit)

        # Convert to response model
        response_suggestions = []
        for suggestion in suggestions:
            response_suggestion = SuggestionResponse(
                text=suggestion.text,
                type=suggestion.type,
                frequency=suggestion.frequency,
                last_used=suggestion.last_used
            )
            response_suggestions.append(response_suggestion)

        return response_suggestions

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get suggestions: {str(e)}")


@router.get("/history", response_model=List[HistoryResponse])
async def get_search_history(
    limit: int = Query(20, ge=1, le=100, description="Number of history items to return"),
    current_user: dict = Depends(get_current_user)
):
    """Get user's search history."""
    try:
        search_service = await get_search_service()
        history = await search_service.get_search_history(current_user["user_id"], limit)

        # Convert to response model
        response_history = []
        for entry in history:
            response_entry = HistoryResponse(
                id=entry.id,
                user_id=entry.user_id,
                query=entry.query,
                filters=entry.filters,
                result_count=entry.result_count,
                timestamp=entry.timestamp,
                duration_ms=entry.duration_ms
            )
            response_history.append(response_entry)

        return response_history

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get search history: {str(e)}")


@router.get("/status", response_model=Dict[str, Any])
async def search_status():
    """Get search system status and statistics."""
    try:
        search_service = await get_search_service()
        stats = await search_service.get_search_stats()

        return {
            "status": "operational",
            "service_initialized": search_service._initialized,
            "statistics": stats
        }

    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "service_initialized": False
        }


@router.delete("/history/{history_id}")
async def delete_search_history_entry(
    history_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Delete a specific search history entry."""
    try:
        # Note: This would need to be implemented in the search service
        # For now, return not implemented
        raise HTTPException(status_code=501, detail="Delete history entry not yet implemented")

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete history entry: {str(e)}")


@router.delete("/history")
async def clear_search_history(current_user: dict = Depends(get_current_user)):
    """Clear all search history for the current user."""
    try:
        # Note: This would need to be implemented in the search service
        # For now, return not implemented
        raise HTTPException(status_code=501, detail="Clear history not yet implemented")

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to clear history: {str(e)}")
