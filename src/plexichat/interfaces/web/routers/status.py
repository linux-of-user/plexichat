from fastapi import APIRouter, Request, HTTPException, status
from sqlmodel import Session, select
from sqlalchemy import func
from datetime import datetime, timezone

import logging

logger = logging.getLogger(__name__)
# settings import will be added when needed
from plexichat.core.database import engine
from plexichat.features.users.user import User
from plexichat.features.users.message import Message

server_start_time = datetime.now(timezone.utc)
router = APIRouter()

@router.get("/health", response_model=dict, responses={429: {"description": "Rate limit exceeded"}})
async def health_check(request: Request):
    logger.debug("Health check endpoint called")
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat() + "Z"}

@router.get("/uptime", response_model=dict, responses={429: {"description": "Rate limit exceeded"}})
async def return_uptime(request: Request):
    logger.debug("Uptime check endpoint called")
    now = datetime.now(timezone.utc)
    uptime_duration = now - server_start_time
    return {
        "status": "ok",
        "uptime_seconds": int(uptime_duration.total_seconds()),
        "uptime_readable": str(uptime_duration)
    }

@router.get("/metrics", response_model=dict, responses={429: {"description": "Rate limit exceeded"}})
async def metrics(request: Request):
    logger.debug("Metrics endpoint called")
    try:
        with Session(engine) as session:
            user_count = session.exec(select(func.count()).select_from(User)).one()[0]
            message_count = session.exec(select(func.count()).select_from(Message)).one()[0]
        logger.info(f"Metrics fetched: users={user_count}, messages={message_count}")
        return {
            "users": user_count,
            "messages": message_count,
            "version": settings.API_VERSION,
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }
    except Exception as e:
        logger.error(f"Failed to fetch metrics: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail={"code": 50001, "message": "Failed to fetch metrics"}
        )
