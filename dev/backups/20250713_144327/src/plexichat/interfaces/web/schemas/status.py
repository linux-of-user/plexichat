from datetime import datetime

from sqlmodel import Session, select


from datetime import datetime
from datetime import datetime



from datetime import datetime
from datetime import datetime

from fastapi import APIRouter

from plexichat.features.users.message import Message
from plexichat.features.users.user import User
from plexichat.main import engine

router = APIRouter()

@router.get("/", summary="Service status and metrics")
def get_status():
    with Session(engine) as session:
        total_users = session.exec(select(User)).count()
        total_messages = session.exec(select(Message)).count()
    return {
        "status": "ok",
        "uptime": f"{(from datetime import datetime
datetime.utcnow() - datetime(2025,1,1)).total_seconds()} seconds",  # example
        "total_users": total_users,
        "total_messages": total_messages,
        "server_time": from datetime import datetime
datetime.utcnow().isoformat() + "Z",
    }
