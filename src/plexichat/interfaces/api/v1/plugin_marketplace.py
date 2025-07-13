"""
Plugin Marketplace API endpoints for PlexiChat.
Provides comprehensive marketplace functionality including search, installation,
reviews, and developer tools.
"""

from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from plexichat.core.auth import get_current_user, require_permissions
from plexichat.core.logging import get_logger
from plexichat.services.plugin_marketplace_service import (
    PluginCategory,
    PluginRating,
    get_plugin_marketplace_service,
)

logger = get_logger(__name__)
router = APIRouter(prefix="/api/v1/marketplace", tags=["Plugin Marketplace"])


# Pydantic models for API requests/responses
class PluginSearchRequest(BaseModel):
    """Plugin search request model."""
    query: str = Field(default="", description="Search query")
    category: Optional[str] = Field(default=None, description="Plugin category")
    tags: List[str] = Field(default_factory=list, description="Plugin tags")
    sort_by: str = Field(default="relevance", description="Sort criteria")
    limit: int = Field(default=20, ge=1, le=100, description="Results limit")
    offset: int = Field(default=0, ge=0, description="Results offset")


class PluginReviewRequest(BaseModel):
    """Plugin review request model."""
    plugin_id: str = Field(..., description="Plugin ID")
    rating: int = Field(..., ge=1, le=5, description="Rating (1-5 stars)")
    title: str = Field(..., min_length=1, max_length=100, description="Review title")
    content: str = Field(..., min_length=10, max_length=2000, description="Review content")


class PluginPublishRequest(BaseModel):
    """Plugin publish request model."""
    name: str = Field(..., min_length=1, max_length=100)
    version: str = Field(..., description="Plugin version")
    description: str = Field(..., min_length=10, max_length=1000)
    category: str = Field(..., description="Plugin category")
    tags: List[str] = Field(default_factory=list, max_items=10)
    homepage: Optional[str] = Field(default=None, description="Plugin homepage URL")
    repository: Optional[str] = Field(default=None, description="Repository URL")
    license: str = Field(default="MIT", description="Plugin license")
    price: float = Field(default=0.0, ge=0.0, description="Plugin price (0.0 for free)")


class WebhookRegisterRequest(BaseModel):
    """Webhook registration request model."""
    url: str = Field(..., description="Webhook endpoint URL")
    events: List[str] = Field(..., description="List of events to subscribe to")
    secret: Optional[str] = Field(default=None, description="Webhook secret (auto-generated if not provided)")


# Search and Discovery Endpoints
@router.get("/search")
async def search_plugins(
    query: str = Query(default="", description="Search query"),
    category: Optional[str] = Query(default=None, description="Plugin category"),
    tags: Optional[str] = Query(default=None, description="Comma-separated tags"),
    sort_by: str = Query(default="relevance", description="Sort by: relevance, name, rating, downloads, newest, updated"),
    limit: int = Query(default=20, ge=1, le=100, description="Results limit"),
    offset: int = Query(default=0, ge=0, description="Results offset")
):
    """Search plugins in the marketplace."""
    try:
        service = get_plugin_marketplace_service()
        
        # Parse category
        plugin_category = None
        if category:
            try:
                plugin_category = PluginCategory(category.lower())
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Invalid category: {category}")
        
        # Parse tags
        tag_list = []
        if tags:
            tag_list = [tag.strip() for tag in tags.split(",") if tag.strip()]
        
        # Perform search
        results = await service.search_plugins(
            query=query,
            category=plugin_category,
            tags=tag_list,
            sort_by=sort_by,
            limit=limit,
            offset=offset
        )
        
        return JSONResponse(content=results)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Plugin search failed: {e}")
        raise HTTPException(status_code=500, detail="Search failed")


@router.get("/categories")
async def get_categories():
    """Get all plugin categories with counts."""
    try:
        service = get_plugin_marketplace_service()
        categories = await service.get_categories()
        
        return JSONResponse(content={
            "success": True,
            "categories": categories
        })
        
    except Exception as e:
        logger.error(f"Failed to get categories: {e}")
        raise HTTPException(status_code=500, detail="Failed to get categories")


@router.get("/featured")
async def get_featured_plugins(
    limit: int = Query(default=10, ge=1, le=50, description="Number of featured plugins")
):
    """Get featured plugins."""
    try:
        service = get_plugin_marketplace_service()
        featured = await service.get_featured_plugins(limit=limit)
        
        return JSONResponse(content={
            "success": True,
            "featured_plugins": featured,
            "count": len(featured)
        })
        
    except Exception as e:
        logger.error(f"Failed to get featured plugins: {e}")
        raise HTTPException(status_code=500, detail="Failed to get featured plugins")


@router.get("/statistics")
async def get_marketplace_statistics():
    """Get marketplace statistics and insights."""
    try:
        service = get_plugin_marketplace_service()
        stats = await service.get_marketplace_statistics()
        
        return JSONResponse(content={
            "success": True,
            **stats
        })
        
    except Exception as e:
        logger.error(f"Failed to get statistics: {e}")
        raise HTTPException(status_code=500, detail="Failed to get statistics")


# Plugin Details and Information
@router.get("/plugins/{plugin_id}")
async def get_plugin_details(plugin_id: str):
    """Get detailed information about a specific plugin."""
    try:
        service = get_plugin_marketplace_service()
        plugin_details = await service.get_plugin_details(plugin_id)
        
        if not plugin_details:
            raise HTTPException(status_code=404, detail="Plugin not found")
        
        return JSONResponse(content={
            "success": True,
            "plugin": plugin_details
        })
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get plugin details: {e}")
        raise HTTPException(status_code=500, detail="Failed to get plugin details")


# Remote plugin installation removed - plugins managed locally through WebUI


# Reviews and Ratings
@router.post("/reviews")
async def add_plugin_review(
    request: PluginReviewRequest,
    current_user = Depends(get_current_user)
):
    """Add a review for a plugin."""
    try:
        service = get_plugin_marketplace_service()
        
        # Convert rating to enum
        try:
            rating = PluginRating(request.rating)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid rating value")
        
        result = await service.add_review(
            plugin_id=request.plugin_id,
            user_id=current_user.get("user_id", "unknown"),
            username=current_user.get("username", "Anonymous"),
            rating=rating,
            title=request.title,
            content=request.content
        )
        
        if result["success"]:
            return JSONResponse(content=result)
        else:
            raise HTTPException(status_code=400, detail=result["error"])
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to add review: {e}")
        raise HTTPException(status_code=500, detail="Failed to add review")


@router.get("/plugins/{plugin_id}/reviews")
async def get_plugin_reviews(
    plugin_id: str,
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0)
):
    """Get reviews for a specific plugin."""
    try:
        service = get_plugin_marketplace_service()
        plugin_details = await service.get_plugin_details(plugin_id)
        
        if not plugin_details:
            raise HTTPException(status_code=404, detail="Plugin not found")
        
        reviews = plugin_details.get("reviews", [])
        total_count = len(reviews)
        
        # Apply pagination
        paginated_reviews = reviews[offset:offset + limit]
        
        return JSONResponse(content={
            "success": True,
            "reviews": paginated_reviews,
            "total_count": total_count,
            "page_size": limit,
            "page_offset": offset,
            "has_more": offset + limit < total_count
        })
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get reviews: {e}")
        raise HTTPException(status_code=500, detail="Failed to get reviews")


# Developer Tools (Protected endpoints)
@router.post("/publish")
async def publish_plugin(
    request: PluginPublishRequest,
    current_user = Depends(get_current_user)
):
    """Publish a new plugin to the marketplace."""
    try:
        # Check permissions
        if not await require_permissions(current_user, ["plugin:publish"]):
            raise HTTPException(status_code=403, detail="Insufficient permissions to publish plugins")
        
        # TODO: Implement plugin publishing logic
        # This would involve:
        # 1. Validating plugin package
        # 2. Security scanning
        # 3. Creating marketplace entry
        # 4. Setting up download URLs
        
        return JSONResponse(content={
            "success": False,
            "message": "Plugin publishing not yet implemented",
            "todo": "Implement plugin publishing workflow"
        })
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Plugin publishing failed: {e}")
        raise HTTPException(status_code=500, detail="Publishing failed")


# Webhook Management
@router.post("/webhooks")
async def register_webhook(
    request: WebhookRegisterRequest,
    current_user = Depends(get_current_user)
):
    """Register a new webhook endpoint."""
    try:
        # Check permissions
        if not await require_permissions(current_user, ["webhook:manage"]):
            raise HTTPException(status_code=403, detail="Insufficient permissions")

        service = get_plugin_marketplace_service()
        result = await service.register_webhook(
            url=request.url,
            events=request.events,
            secret=request.secret
        )

        if result["success"]:
            return JSONResponse(content=result)
        else:
            raise HTTPException(status_code=400, detail=result["error"])

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Webhook registration failed: {e}")
        raise HTTPException(status_code=500, detail="Webhook registration failed")


@router.get("/webhooks")
async def get_webhooks(current_user = Depends(get_current_user)):
    """Get all registered webhook endpoints."""
    try:
        # Check permissions
        if not await require_permissions(current_user, ["webhook:read"]):
            raise HTTPException(status_code=403, detail="Insufficient permissions")

        service = get_plugin_marketplace_service()
        webhooks = await service.get_webhook_endpoints()

        return JSONResponse(content={
            "success": True,
            "webhooks": webhooks,
            "count": len(webhooks)
        })

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get webhooks: {e}")
        raise HTTPException(status_code=500, detail="Failed to get webhooks")


@router.get("/webhooks/{endpoint_id}/deliveries")
async def get_webhook_deliveries(
    endpoint_id: str,
    limit: int = Query(default=50, ge=1, le=200),
    current_user = Depends(get_current_user)
):
    """Get webhook delivery history for an endpoint."""
    try:
        # Check permissions
        if not await require_permissions(current_user, ["webhook:read"]):
            raise HTTPException(status_code=403, detail="Insufficient permissions")

        service = get_plugin_marketplace_service()
        deliveries = await service.get_webhook_deliveries(endpoint_id=endpoint_id, limit=limit)

        return JSONResponse(content={
            "success": True,
            "deliveries": deliveries,
            "count": len(deliveries)
        })

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get webhook deliveries: {e}")
        raise HTTPException(status_code=500, detail="Failed to get webhook deliveries")


# Health and Status
@router.get("/health")
async def marketplace_health():
    """Get marketplace service health status."""
    try:
        service = get_plugin_marketplace_service()

        # Basic health check
        stats = await service.get_marketplace_statistics()

        return JSONResponse(content={
            "success": True,
            "status": "healthy",
            "service": "plugin_marketplace",
            "plugins_available": stats["statistics"]["total_plugins"],
            "timestamp": datetime.now(timezone.utc).isoformat()
        })

    except Exception as e:
        logger.error(f"Marketplace health check failed: {e}")
        return JSONResponse(
            status_code=503,
            content={
                "success": False,
                "status": "unhealthy",
                "error": str(e)
            }
        )
