from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter

# Import models from the correct location
try:
    from plexichat.shared.models import Message, User

    models_available = True
except ImportError:
    User = None
    Message = None
    models_available = False

router = APIRouter()


@router.get("/", summary="Service status and metrics")
def get_status() -> dict[str, Any]:
    """Get service status and metrics."""
    # Calculate uptime from a reference point
    uptime_seconds = (
        datetime.now(UTC) - datetime(2025, 1, 1, tzinfo=UTC)
    ).total_seconds()

    status_info = {
        "status": "ok",
        "uptime": f"{uptime_seconds} seconds",
        "total_users": 0,  # Would be populated from actual database
        "total_messages": 0,  # Would be populated from actual database
        "server_time": datetime.now(UTC).isoformat(),
        "models_available": models_available,
    }

    if not models_available:
        status_info["note"] = "Models not available - database metrics unavailable"

    return status_info
