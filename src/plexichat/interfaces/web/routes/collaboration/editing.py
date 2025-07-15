from fastapi import APIRouter

router = APIRouter(prefix="/editing", tags=["Collaboration Editing"])

@router.get("/documents")
def list_documents():
    """Stub endpoint for collaborative documents."""
    return {"documents": []} 