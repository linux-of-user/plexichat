"""
PlexiChat - Real-time Communication Platform
Copyright (C) 2025 PlexiChat Contributors

Standardized License Header
"""

from fastapi import APIRouter, Depends
from typing import Dict, Any

from plexichat.core.logging import get_logger
from plexichat.core.config import get_config

logger = get_logger(__name__)
config = get_config()

router = APIRouter(prefix="/status", tags=["status"])

@router.get("/")
async def get_status() -> Dict[str, Any]:
    """Get system status."""
    return {
        "status": "healthy",
        "version": config.version,
        "app_name": config.app_name
    }

@router.get("/health")
async def health_check() -> Dict[str, str]:
    """Health check endpoint."""
    return {"status": "ok"}
