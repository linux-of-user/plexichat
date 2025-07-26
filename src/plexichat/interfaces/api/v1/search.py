"""
Advanced search and analytics endpoints for PlexiChat v1 API.
Provides comprehensive search, filtering, and analytics capabilities.
"""

import time
import re
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from .auth import get_current_user

# Router setup
router = APIRouter(prefix="/search", tags=["Search & Analytics"])

# Import data from other modules (in production, use database)
try:
    from .messages import messages_db
    from .users import users_db
    from .files import files_db
except ImportError:
    # Fallback empty databases
    messages_db = {}
    users_db = {}
    files_db = {}

# Models
class SearchQuery(BaseModel):
    query: str
    type: Optional[str] = "all"  # all, messages, users, files
    filters: Optional[Dict[str, Any]] = {}
    sort_by: Optional[str] = "relevance"  # relevance, date, popularity
    limit: int = 20
    offset: int = 0

class SearchResult(BaseModel):
    id: str
    type: str
    title: str
    content: str
    score: float
    metadata: Dict[str, Any]
    created_at: float

class AnalyticsQuery(BaseModel):
    metric: str
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    granularity: str = "day"  # hour, day, week, month
    filters: Optional[Dict[str, Any]] = {}

# Search functions
def search_messages(query: str, user_id: str, limit: int = 20, offset: int = 0) -> List[SearchResult]:
    """Search through messages."""
    results = []
    query_lower = query.lower()
    
    for msg_id, message in messages_db.items():
        # Check if user has access to this message
        if message.get("sender_id") != user_id and message.get("recipient_id") != user_id:
            continue
        
        content = message.get("content", "").lower()
        if query_lower in content:
            score = calculate_relevance_score(query_lower, content)
            
            result = SearchResult(
                id=msg_id,
                type="message",
                title=f"Message from {message.get('sender_id', 'Unknown')}",
                content=message.get("content", "")[:200] + "..." if len(message.get("content", "")) > 200 else message.get("content", ""),
                score=score,
                metadata={
                    "sender_id": message.get("sender_id"),
                    "recipient_id": message.get("recipient_id"),
                    "message_type": message.get("message_type", "text")
                },
                created_at=message.get("created_at", time.time())
            )
            results.append(result)
    
    # Sort by score (relevance)
    results.sort(key=lambda x: x.score, reverse=True)
    return results[offset:offset + limit]

def search_users(query: str, limit: int = 20, offset: int = 0) -> List[SearchResult]:
    """Search through users."""
    results = []
    query_lower = query.lower()
    
    for user_id, user in users_db.items():
        username = user.get("username", "").lower()
        email = user.get("email", "").lower()
        display_name = user.get("display_name", "").lower()
        
        if query_lower in username or query_lower in email or query_lower in display_name:
            score = calculate_user_relevance_score(query_lower, user)
            
            result = SearchResult(
                id=user_id,
                type="user",
                title=user.get("display_name") or user.get("username", "Unknown"),
                content=f"@{user.get('username', 'unknown')} - {user.get('email', '')}",
                score=score,
                metadata={
                    "username": user.get("username"),
                    "email": user.get("email"),
                    "status": user.get("status", "offline"),
                    "last_active": user.get("last_active")
                },
                created_at=user.get("created_at", time.time())
            )
            results.append(result)
    
    results.sort(key=lambda x: x.score, reverse=True)
    return results[offset:offset + limit]

def search_files(query: str, user_id: str, limit: int = 20, offset: int = 0) -> List[SearchResult]:
    """Search through files."""
    results = []
    query_lower = query.lower()
    
    for file_id, file_info in files_db.items():
        # Check if user has access to this file
        if file_info.get("owner_id") != user_id:
            continue
        
        filename = file_info.get("filename", "").lower()
        description = file_info.get("description", "").lower()
        
        if query_lower in filename or query_lower in description:
            score = calculate_file_relevance_score(query_lower, file_info)
            
            result = SearchResult(
                id=file_id,
                type="file",
                title=file_info.get("filename", "Unknown File"),
                content=f"{file_info.get('description', '')} ({file_info.get('size', 0)} bytes)",
                score=score,
                metadata={
                    "filename": file_info.get("filename"),
                    "size": file_info.get("size"),
                    "mime_type": file_info.get("mime_type"),
                    "owner_id": file_info.get("owner_id")
                },
                created_at=file_info.get("created_at", time.time())
            )
            results.append(result)
    
    results.sort(key=lambda x: x.score, reverse=True)
    return results[offset:offset + limit]

def calculate_relevance_score(query: str, content: str) -> float:
    """Calculate relevance score for search results."""
    if not query or not content:
        return 0.0
    
    # Exact match gets highest score
    if query in content:
        score = 1.0
    else:
        # Partial match based on word overlap
        query_words = set(query.split())
        content_words = set(content.split())
        overlap = len(query_words.intersection(content_words))
        score = overlap / len(query_words) if query_words else 0.0
    
    # Boost score for matches at the beginning
    if content.startswith(query):
        score *= 1.5
    
    return min(score, 1.0)

def calculate_user_relevance_score(query: str, user: Dict) -> float:
    """Calculate relevance score for user search results."""
    username = user.get("username", "").lower()
    email = user.get("email", "").lower()
    display_name = user.get("display_name", "").lower()
    
    scores = []
    
    # Username match (highest priority)
    if query in username:
        scores.append(1.0 if username.startswith(query) else 0.8)
    
    # Display name match
    if query in display_name:
        scores.append(0.9 if display_name.startswith(query) else 0.7)
    
    # Email match (lower priority)
    if query in email:
        scores.append(0.6)
    
    return max(scores) if scores else 0.0

def calculate_file_relevance_score(query: str, file_info: Dict) -> float:
    """Calculate relevance score for file search results."""
    filename = file_info.get("filename", "").lower()
    description = file_info.get("description", "").lower()
    
    scores = []
    
    # Filename match (highest priority)
    if query in filename:
        scores.append(1.0 if filename.startswith(query) else 0.8)
    
    # Description match
    if query in description:
        scores.append(0.7)
    
    return max(scores) if scores else 0.0

# Search endpoints
@router.post("/")
async def search(
    search_query: SearchQuery,
    current_user: dict = Depends(get_current_user)
):
    """Perform comprehensive search across all content types."""
    results = []
    
    if search_query.type in ["all", "messages"]:
        message_results = search_messages(
            search_query.query, 
            current_user["user_id"], 
            search_query.limit, 
            search_query.offset
        )
        results.extend(message_results)
    
    if search_query.type in ["all", "users"]:
        user_results = search_users(
            search_query.query, 
            search_query.limit, 
            search_query.offset
        )
        results.extend(user_results)
    
    if search_query.type in ["all", "files"]:
        file_results = search_files(
            search_query.query, 
            current_user["user_id"], 
            search_query.limit, 
            search_query.offset
        )
        results.extend(file_results)
    
    # Sort all results by score
    if search_query.sort_by == "relevance":
        results.sort(key=lambda x: x.score, reverse=True)
    elif search_query.sort_by == "date":
        results.sort(key=lambda x: x.created_at, reverse=True)
    
    # Apply limit and offset to combined results
    total_results = len(results)
    results = results[search_query.offset:search_query.offset + search_query.limit]
    
    return {
        "results": results,
        "total": total_results,
        "query": search_query.query,
        "type": search_query.type,
        "limit": search_query.limit,
        "offset": search_query.offset
    }

@router.get("/suggestions")
async def get_search_suggestions(
    q: str = Query(..., description="Partial query for suggestions"),
    type: str = Query("all", description="Type of suggestions"),
    limit: int = Query(10, le=20),
    current_user: dict = Depends(get_current_user)
):
    """Get search suggestions based on partial query."""
    suggestions = []
    
    if type in ["all", "users"]:
        # User suggestions
        for user_id, user in users_db.items():
            username = user.get("username", "")
            if username.lower().startswith(q.lower()):
                suggestions.append({
                    "type": "user",
                    "text": f"@{username}",
                    "description": user.get("display_name", username)
                })
    
    if type in ["all", "files"]:
        # File suggestions
        for file_id, file_info in files_db.items():
            if file_info.get("owner_id") == current_user["user_id"]:
                filename = file_info.get("filename", "")
                if filename.lower().startswith(q.lower()):
                    suggestions.append({
                        "type": "file",
                        "text": filename,
                        "description": f"{file_info.get('size', 0)} bytes"
                    })
    
    return {
        "suggestions": suggestions[:limit],
        "query": q
    }

# Analytics endpoints
@router.get("/analytics/overview")
async def get_analytics_overview(
    current_user: dict = Depends(get_current_user)
):
    """Get analytics overview for the current user."""
    user_id = current_user["user_id"]
    
    # Message analytics
    user_messages = [m for m in messages_db.values() if m.get("sender_id") == user_id]
    messages_sent = len(user_messages)
    
    # File analytics
    user_files = [f for f in files_db.values() if f.get("owner_id") == user_id]
    files_uploaded = len(user_files)
    total_file_size = sum(f.get("size", 0) for f in user_files)
    
    # Activity analytics
    now = time.time()
    week_ago = now - (7 * 24 * 3600)
    recent_messages = [m for m in user_messages if m.get("created_at", 0) > week_ago]
    
    return {
        "user_id": user_id,
        "messages_sent": messages_sent,
        "files_uploaded": files_uploaded,
        "total_file_size": total_file_size,
        "recent_activity": {
            "messages_this_week": len(recent_messages),
            "files_this_week": len([f for f in user_files if f.get("created_at", 0) > week_ago])
        },
        "generated_at": now
    }

@router.get("/analytics/trends")
async def get_search_trends(
    days: int = Query(30, le=365, description="Number of days to analyze"),
    current_user: dict = Depends(get_current_user)
):
    """Get search and usage trends."""
    # This would typically analyze search logs and usage patterns
    # For now, return mock trend data
    
    trends = {
        "popular_searches": [
            {"query": "project", "count": 45},
            {"query": "meeting", "count": 32},
            {"query": "document", "count": 28},
            {"query": "report", "count": 21},
            {"query": "update", "count": 18}
        ],
        "search_volume": {
            "total_searches": 144,
            "unique_queries": 89,
            "average_per_day": 144 / days
        },
        "content_types": {
            "messages": 65,
            "files": 42,
            "users": 37
        },
        "period": f"Last {days} days"
    }
    
    return trends

@router.get("/status")
async def search_status():
    """Get search system status."""
    return {
        "status": "operational",
        "indexed_content": {
            "messages": len(messages_db),
            "users": len(users_db),
            "files": len(files_db)
        },
        "features": [
            "full_text_search",
            "user_search",
            "file_search",
            "search_suggestions",
            "analytics",
            "trend_analysis"
        ],
        "last_indexed": time.time()
    }
