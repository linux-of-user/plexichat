# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
from fastapi import APIRouter

router = APIRouter(prefix="/chat", tags=["Collaboration Chat"])

@router.get("/messages")
def get_messages():
    """Stub endpoint for chat messages."""
    return {}}"messages": []}
