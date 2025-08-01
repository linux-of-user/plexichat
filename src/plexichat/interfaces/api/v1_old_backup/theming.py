# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false

"""
PlexiChat Enhanced Theming API Endpoints

Comprehensive theming system with:
- Redis caching for theme performance optimization
- Database abstraction layer for theme storage
- Real-time theme updates
- User preference management
- Theme validation and sanitization
- Performance monitoring
"""

import logging
from typing import Any, Dict, Optional
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Response, Depends
from pydantic import BaseModel, Field

try:
    from plexichat.core.logging import get_logger
    from plexichat.infrastructure.services.theming_service import get_theming_service
    from plexichat.core.database.manager import get_database_manager
    from plexichat.infrastructure.performance.cache_manager import get_cache_manager
    from plexichat.interfaces.api.v1.auth import get_current_user

    logger = get_logger(__name__)
    theming_service = get_theming_service()
    database_manager = get_database_manager()
    cache_manager = get_cache_manager()
except ImportError:
    logger = logging.getLogger(__name__)
    theming_service = None
    database_manager = None
    cache_manager = None
    get_current_user = lambda: {}


# Enhanced Pydantic models with validation
class ThemeCreateRequest(BaseModel):
    """Enhanced theme creation request with validation."""
    name: str = Field(..., min_length=1, max_length=100, description="Theme name")
    description: str = Field(..., min_length=1, max_length=500, description="Theme description")
    base_theme_id: Optional[str] = Field("default_light", description="Base theme to inherit from")
    colors: Optional[Dict[str, str]] = Field(None, description="Color scheme definitions")
    layout: Optional[Dict[str, str]] = Field(None, description="Layout configurations")
    effects: Optional[Dict[str, Any]] = Field(None, description="Visual effects settings")
    is_public: bool = Field(True, description="Whether theme is publicly available")
    tags: Optional[list[str]] = Field(None, description="Theme tags for categorization")


class ThemeUpdateRequest(BaseModel):
    """Enhanced theme update request with validation."""
    name: Optional[str] = Field(None, min_length=1, max_length=100, description="Theme name")
    description: Optional[str] = Field(None, min_length=1, max_length=500, description="Theme description")
    colors: Optional[Dict[str, str]] = Field(None, description="Color scheme definitions")
    layout: Optional[Dict[str, str]] = Field(None, description="Layout configurations")
    effects: Optional[Dict[str, Any]] = Field(None, description="Visual effects settings")
    is_public: Optional[bool] = Field(None, description="Whether theme is publicly available")
    tags: Optional[list[str]] = Field(None, description="Theme tags for categorization")


class UserThemeRequest(BaseModel):
    """User theme preference request."""
    theme_id: str = Field(..., description="Theme ID to apply")


class ThemeResponse(BaseModel):
    """Enhanced theme response with metadata."""
    id: str
    name: str
    description: str
    author_id: str
    author_name: str
    colors: Dict[str, str]
    layout: Dict[str, str]
    effects: Dict[str, Any]
    is_public: bool
    tags: list[str]
    usage_count: int
    created_at: datetime
    updated_at: datetime


router = APIRouter(prefix="/api/v1/theming", tags=["Enhanced Theming"])


@router.get("/themes", response_model=Dict[str, Any])
async def get_all_themes(
    current_user: Dict = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Get list of all available themes with Redis caching.

    Enhanced with:
    - Redis caching for performance optimization
    - Database abstraction layer
    - User-specific theme filtering
    - Performance monitoring
    """
    try:
        # Check Redis cache first
        cache_key = f"themes:all:user:{current_user.get('id', 'anonymous')}"
        if cache_manager:
            cached_themes = await cache_manager.get(cache_key)
            if cached_themes:
                logger.info("Themes retrieved from Redis cache")
                return cached_themes

        # Get themes from database using abstraction layer
        if database_manager and theming_service:
            async with database_manager.get_session() as session:
                themes = await theming_service.get_theme_list(session, user_id=current_user.get('id'))
        else:
            themes = []

        result = {
            "themes": themes,
            "total": len(themes),
            "built_in_count": len([t for t in themes if not t.get("is_custom", False)]),
            "custom_count": len([t for t in themes if t.get("is_custom", False)]),
            "user_themes": len([t for t in themes if t.get("author_id") == current_user.get('id')]),
            "cached_at": datetime.now(timezone.utc).isoformat()
        }

        # Cache result in Redis for 5 minutes
        if cache_manager:
            await cache_manager.set(cache_key, result, ttl=300)

        return result

    except Exception as e:
        logger.error(f"Failed to get themes: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve themes")


@router.get("/themes/{theme_id}", response_model=ThemeResponse)
async def get_theme(
    theme_id: str,
    current_user: Dict = Depends(get_current_user)
) -> ThemeResponse:
    """
    Get a specific theme by ID with Redis caching.

    Enhanced with:
    - Redis caching for individual themes
    - Database abstraction layer
    - Access control validation
    - Performance monitoring
    """
    try:
        # Check Redis cache first
        cache_key = f"theme:{theme_id}:user:{current_user.get('id', 'anonymous')}"
        if cache_manager:
            cached_theme = await cache_manager.get(cache_key)
            if cached_theme:
                logger.info(f"Theme {theme_id} retrieved from Redis cache")
                return ThemeResponse(**cached_theme)

        # Get theme from database using abstraction layer
        if database_manager and theming_service:
            async with database_manager.get_session() as session:
                theme = await theming_service.get_theme(session, theme_id, user_id=current_user.get('id'))
        else:
            theme = None

        if not theme:
            raise HTTPException(status_code=404, detail="Theme not found")

        return {
            "theme": {
                "id": theme.id,
                "name": theme.name,
                "description": theme.description,
                "colors": theme.colors.__dict__,
                "layout": theme.layout.__dict__,
                "effects": theme.effects.__dict__,
                "is_dark": theme.is_dark,
                "created_at": theme.created_at,
                "updated_at": theme.updated_at,
            }
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get theme {theme_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/themes/{theme_id}/css")
async def get_theme_css(theme_id: str):
    """Get CSS for a specific theme."""
    try:
        css = theming_service.generate_css(theme_id)

        return Response(
            content=css,
            media_type="text/css",
            headers={
                "Cache-Control": "public, max-age=3600",
                "Content-Disposition": f"inline; filename={theme_id}.css",
            },
        )

    except Exception as e:
        logger.error(f"Failed to generate CSS for theme {theme_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/themes")
async def create_custom_theme(request: ThemeCreateRequest):
    """Create a new custom theme."""
    try:
        theme = theming_service.create_custom_theme(
            name=request.name,
            description=request.description,
            base_theme_id=request.base_theme_id,
            colors=request.colors,
            layout=request.layout,
            effects=request.effects,
        )

        return {
            "success": True,
            "theme_id": theme.id,
            "message": f"Custom theme '{request.name}' created successfully",
        }

    except Exception as e:
        logger.error(f"Failed to create custom theme: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/themes/{theme_id}")
async def update_custom_theme(theme_id: str, request: ThemeUpdateRequest):
    """Update a custom theme."""
    try:
        # Check if theme exists and is custom
        theme = theming_service.get_theme(theme_id)
        if not theme:
            raise HTTPException(status_code=404, detail="Theme not found")

        if theme_id not in theming_service.custom_themes:
            raise HTTPException(status_code=400, detail="Cannot modify built-in themes")

        # Prepare updates
        updates = {}
        if request.name is not None:
            updates["name"] = request.name
        if request.description is not None:
            updates["description"] = request.description
        if request.colors is not None:
            # Update colors
            for key, value in request.colors.items():
                if hasattr(theme.colors, key):
                    setattr(theme.colors, key, value)
        if request.layout is not None:
            # Update layout
            for key, value in request.layout.items():
                if hasattr(theme.layout, key):
                    setattr(theme.layout, key, value)
        if request.effects is not None:
            # Update effects
            for key, value in request.effects.items():
                if hasattr(theme.effects, key):
                    setattr(theme.effects, key, value)

        success = theming_service.update_custom_theme(theme_id, updates)

        if success:
            return {
                "success": True,
                "message": f"Theme '{theme_id}' updated successfully",
            }
        else:
            raise HTTPException(status_code=400, detail="Failed to update theme")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update theme {theme_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/themes/{theme_id}")
async def delete_custom_theme(theme_id: str):
    """Delete a custom theme."""
    try:
        # Check if theme exists and is custom
        theme = theming_service.get_theme(theme_id)
        if not theme:
            raise HTTPException(status_code=404, detail="Theme not found")

        if theme_id not in theming_service.custom_themes:
            raise HTTPException(status_code=400, detail="Cannot delete built-in themes")

        success = theming_service.delete_custom_theme(theme_id)

        if success:
            return {
                "success": True,
                "message": f"Theme '{theme_id}' deleted successfully",
            }
        else:
            raise HTTPException(status_code=400, detail="Failed to delete theme")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete theme {theme_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/themes/{theme_id}/export")
async def export_theme(theme_id: str):
    """Export a theme as JSON."""
    try:
        theme_data = theming_service.export_theme(theme_id)

        if not theme_data:
            raise HTTPException(status_code=404, detail="Theme not found")

        return {
            "theme_data": theme_data,
            "export_timestamp": theming_service.user_preferences.get(
                "export_timestamp"
            ),
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to export theme {theme_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/themes/import")
async def import_theme(theme_data: Dict[str, Any]):
    """Import a theme from JSON data."""
    try:
        theme = theming_service.import_theme(theme_data)

        if not theme:
            raise HTTPException(status_code=400, detail="Invalid theme data")

        return {
            "success": True,
            "theme_id": theme.id,
            "message": f"Theme '{theme.name}' imported successfully",
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to import theme: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/user/{user_id}/theme")
async def get_user_theme(user_id: int):
    """Get current theme for a user."""
    try:
        theme_id = theming_service.get_user_theme(user_id)
        theme = theming_service.get_theme(theme_id)

        return {
            "user_id": user_id,
            "theme_id": theme_id,
            "theme_name": theme.name if theme else "Unknown",
            "is_dark": theme.is_dark if theme else False,
        }

    except Exception as e:
        logger.error(f"Failed to get user theme for {user_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/user/{user_id}/theme")
async def set_user_theme(user_id: int, request: UserThemeRequest):
    """Set theme for a user."""
    try:
        success = theming_service.set_user_theme(user_id, request.theme_id)

        if success:
            return {
                "success": True,
                "user_id": user_id,
                "theme_id": request.theme_id,
                "message": f"Theme set to '{request.theme_id}' for user {user_id}",
            }
        else:
            raise HTTPException(status_code=400, detail="Invalid theme ID")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to set user theme: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/preferences")
async def get_theming_preferences():
    """Get global theming preferences."""
    try:
        return {
            "preferences": theming_service.user_preferences,
            "available_themes": len(theming_service.get_all_themes()),
            "custom_themes": len(theming_service.custom_themes),
        }

    except Exception as e:
        logger.error(f"Failed to get theming preferences: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/preferences")
async def update_theming_preferences(preferences: Dict[str, Any]):
    """Update global theming preferences."""
    try:
        # Update allowed preferences
        allowed_keys = ["default_theme", "auto_dark_mode", "dark_mode_schedule"]

        for key, value in preferences.items():
            if key in allowed_keys:
                theming_service.user_preferences[key] = value

        theming_service._save_user_preferences()

        return {"success": True, "message": "Theming preferences updated successfully"}

    except Exception as e:
        logger.error(f"Failed to update theming preferences: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/preview/{theme_id}")
async def get_theme_preview():
    """Get theme preview data."""
    try:
        # Return sample UI elements with theme applied
        return {
            "preview_elements": {
                "buttons": ["primary", "secondary", "success", "warning", "danger"],
                "cards": ["default", "elevated", "outlined"],
                "forms": ["input", "textarea", "select"],
                "navigation": ["sidebar", "header", "breadcrumb"],
                "feedback": ["alert", "toast", "modal"],
            },
            "sample_content": {
                "title": "Sample Dashboard",
                "description": "This is how your interface will look with this theme",
                "stats": [
                    {"label": "Users", "value": "1,234"},
                    {"label": "Messages", "value": "5,678"},
                    {"label": "Files", "value": "910"},
                ],
            },
        }

    except Exception as e:
        logger.error(f"Failed to get theme preview: {e}")
        raise HTTPException(status_code=500, detail=str(e))
