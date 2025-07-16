# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
from fastapi import APIRouter

router = APIRouter(prefix="/files", tags=["Collaboration File Sharing"])

@router.get("/list")
def list_files():
    """Stub endpoint for listing shared files."""
    return {"files": []} 
