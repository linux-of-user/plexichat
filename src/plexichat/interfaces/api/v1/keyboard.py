"""
Keyboard Shortcuts API

Provides REST endpoints for managing keyboard shortcuts including CRUD operations and validation.
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from plexichat.core.auth.fastapi_adapter import get_current_user
from plexichat.core.services.keyboard_shortcuts_service import (
    KeyboardShortcut,
    keyboard_shortcuts_service,
)

router = APIRouter(prefix="/keyboard", tags=["Keyboard Shortcuts"])
logger = logging.getLogger(__name__)


class ShortcutCreate(BaseModel):
    """Model for creating a new shortcut."""
    shortcut_key: str = Field(..., description="The keyboard shortcut key combination")
    action: str = Field(..., description="The action to perform when shortcut is triggered")
    description: str | None = Field(None, description="Optional description of the shortcut")


class ShortcutUpdate(BaseModel):
    """Model for updating an existing shortcut."""
    shortcut_key: str = Field(..., description="The keyboard shortcut key combination")
    action: str = Field(..., description="The action to perform when shortcut is triggered")
    description: str | None = Field(None, description="Optional description of the shortcut")


class ShortcutResponse(BaseModel):
    """Response model for shortcut data."""
    id: str
    user_id: str
    shortcut_key: str
    action: str
    description: str | None
    is_custom: bool
    created_at: str
    updated_at: str


class DefaultShortcutResponse(BaseModel):
    """Response model for default shortcuts."""
    shortcut_key: str
    action: str
    description: str
    is_custom: bool


class ValidationRequest(BaseModel):
    """Request model for shortcut validation."""
    shortcut_key: str = Field(..., description="The shortcut key to validate")


class ValidationResponse(BaseModel):
    """Response model for shortcut validation."""
    is_conflict: bool
    message: str


def _shortcut_to_response(shortcut: KeyboardShortcut) -> ShortcutResponse:
    """Convert KeyboardShortcut to response model."""
    return ShortcutResponse(
        id=shortcut.id,
        user_id=shortcut.user_id,
        shortcut_key=shortcut.shortcut_key,
        action=shortcut.action,
        description=shortcut.description,
        is_custom=shortcut.is_custom,
        created_at=shortcut.created_at.isoformat(),
        updated_at=shortcut.updated_at.isoformat()
    )


@router.get("/shortcuts", response_model=list[ShortcutResponse])
async def get_user_shortcuts(current_user: dict = Depends(get_current_user)):
    """
    Get all keyboard shortcuts for the current user.

    Returns both custom and default shortcuts configured for the user.
    """
    try:
        user_id = current_user.get("user_id") or current_user.get("id")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not authenticated"
            )

        shortcuts = await keyboard_shortcuts_service.get_shortcuts(user_id)

        logger.info(f"Retrieved {len(shortcuts)} shortcuts for user {user_id}")
        return [_shortcut_to_response(shortcut) for shortcut in shortcuts]

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting shortcuts for user: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve shortcuts"
        )


@router.post("/shortcuts", response_model=ShortcutResponse, status_code=status.HTTP_201_CREATED)
async def create_shortcut(
    shortcut_data: ShortcutCreate,
    current_user: dict = Depends(get_current_user)
):
    """
    Create a new keyboard shortcut for the current user.

    Validates for conflicts before creating the shortcut.
    """
    try:
        user_id = current_user.get("user_id") or current_user.get("id")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not authenticated"
            )

        # Convert to dict for service
        shortcut_dict = {
            "shortcut_key": shortcut_data.shortcut_key,
            "action": shortcut_data.action,
            "description": shortcut_data.description or "",
            "is_custom": True
        }

        shortcut = await keyboard_shortcuts_service.add_shortcut(user_id, shortcut_dict)

        if not shortcut:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Shortcut key conflicts with existing shortcut"
            )

        logger.info(f"Created shortcut {shortcut.id} for user {user_id}")
        return _shortcut_to_response(shortcut)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating shortcut for user: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create shortcut"
        )


@router.put("/shortcuts/{shortcut_id}", response_model=ShortcutResponse)
async def update_shortcut(
    shortcut_id: str,
    shortcut_data: ShortcutUpdate,
    current_user: dict = Depends(get_current_user)
):
    """
    Update an existing keyboard shortcut.

    Validates for conflicts before updating the shortcut.
    """
    try:
        user_id = current_user.get("user_id") or current_user.get("id")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not authenticated"
            )

        # Convert to dict for service
        shortcut_dict = {
            "shortcut_key": shortcut_data.shortcut_key,
            "action": shortcut_data.action,
            "description": shortcut_data.description or ""
        }

        shortcut = await keyboard_shortcuts_service.update_shortcut(user_id, shortcut_id, shortcut_dict)

        if not shortcut:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Shortcut not found or access denied"
            )

        logger.info(f"Updated shortcut {shortcut_id} for user {user_id}")
        return _shortcut_to_response(shortcut)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating shortcut {shortcut_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update shortcut"
        )


@router.delete("/shortcuts/{shortcut_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_shortcut(
    shortcut_id: str,
    current_user: dict = Depends(get_current_user)
):
    """
    Delete a keyboard shortcut.

    Only the owner of the shortcut can delete it.
    """
    try:
        user_id = current_user.get("user_id") or current_user.get("id")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not authenticated"
            )

        success = await keyboard_shortcuts_service.remove_shortcut(user_id, shortcut_id)

        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Shortcut not found or access denied"
            )

        logger.info(f"Deleted shortcut {shortcut_id} for user {user_id}")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting shortcut {shortcut_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete shortcut"
        )


@router.get("/defaults", response_model=list[DefaultShortcutResponse])
async def get_default_shortcuts():
    """
    Get the default keyboard shortcuts configuration.

    These are the system-provided shortcuts that are available to all users.
    """
    try:
        defaults = await keyboard_shortcuts_service.get_default_shortcuts()

        response = []
        for default in defaults:
            response.append(DefaultShortcutResponse(
                shortcut_key=default["shortcut_key"],
                action=default["action"],
                description=default["description"],
                is_custom=default["is_custom"]
            ))

        logger.info(f"Retrieved {len(response)} default shortcuts")
        return response

    except Exception as e:
        logger.error(f"Error getting default shortcuts: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve default shortcuts"
        )


@router.post("/validate", response_model=ValidationResponse)
async def validate_shortcut(
    validation_data: ValidationRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Validate if a shortcut key conflicts with existing shortcuts.

    Returns whether the shortcut key is available for use.
    """
    try:
        user_id = current_user.get("user_id") or current_user.get("id")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not authenticated"
            )

        is_conflict = await keyboard_shortcuts_service.validate_shortcut_conflicts(
            validation_data.shortcut_key,
            user_id
        )

        if is_conflict:
            message = f"Shortcut key '{validation_data.shortcut_key}' conflicts with existing shortcut"
        else:
            message = f"Shortcut key '{validation_data.shortcut_key}' is available"

        logger.info(f"Validated shortcut key '{validation_data.shortcut_key}' for user {user_id}: conflict={is_conflict}")
        return ValidationResponse(is_conflict=is_conflict, message=message)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error validating shortcut: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to validate shortcut"
        )
