# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
from fastapi import APIRouter

router = APIRouter(prefix="/whiteboard", tags=["Collaboration Whiteboard"])

@router.get("/boards")
def list_whiteboards():
    """Stub endpoint for whiteboard boards."""
    return {"whiteboards": []}
