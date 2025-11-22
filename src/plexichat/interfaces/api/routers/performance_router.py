"""
PlexiChat - Real-time Communication Platform
Copyright (C) 2025 PlexiChat Contributors

Performance Monitoring Router
"""

from fastapi import APIRouter, Depends
from typing import Dict, Any

from plexichat.core.logging import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/performance", tags=["performance"])

@router.get("/metrics")
async def get_metrics() -> Dict[str, Any]:
    """Get performance metrics."""
    return {
        "cpu": 0.0,
        "memory": 0.0,
        "requests_per_second": 0.0
    }
