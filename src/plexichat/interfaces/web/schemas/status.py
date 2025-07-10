from fastapi import APIRouter
from datetime import datetime
from sqlmodel import Session, select

from plexichat.main import engine
from plexichat.users.message import Message
from plexichat.users.user import User

router = APIRouter()

@router.get("/", summary="Service status and metrics")
def get_status():
    with Session(engine) as session:
        total_users = session.exec(select(User)).count()
        total_messages = session.exec(select(Message)).count()
    return {
        "status": "ok",
        "uptime": f"{(datetime.utcnow() - datetime(2025,1,1)).total_seconds()} seconds",  # example
        "total_users": total_users,
        "total_messages": total_messages,
        "server_time": datetime.utcnow().isoformat() + "Z",
    }
