from fastapi import APIRouter

router = APIRouter(prefix="/chat", tags=["Collaboration Chat"])

@router.get("/messages")
def get_messages():
    """Stub endpoint for chat messages."""
    return {"messages": []} 