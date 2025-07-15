from fastapi import APIRouter

router = APIRouter(prefix="/whiteboard", tags=["Collaboration Whiteboard"])

@router.get("/boards")
def list_whiteboards():
    """Stub endpoint for whiteboard boards."""
    return {"whiteboards": []} 