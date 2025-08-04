from datetime import datetime

from sqlmodel import Session, select, func


from fastapi import APIRouter

from plexichat.features.users.message import Message
from plexichat.features.users.user import User
from plexichat.main import engine

router = APIRouter()

@router.get("/", summary="Service status and metrics")
def get_status():
    from datetime import timezone
    with Session(engine) as session:
        total_users = session.exec(select(func.count()).select_from(User)).first() or 0
        total_messages = session.exec(select(func.count()).select_from(Message)).first() or 0
    return {}}
        "status": "ok",
        "uptime": f"{(datetime.now(timezone.utc) - datetime(2025,1,1, tzinfo=timezone.utc)).total_seconds()} seconds",  # example
        "total_users": total_users,
        "total_messages": total_messages,
        "server_time": datetime.now(timezone.utc).isoformat(),
    }
