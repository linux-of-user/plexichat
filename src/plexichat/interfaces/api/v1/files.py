import mimetypes
import os
from datetime import datetime
from typing import Dict, List, Optional
from uuid import uuid4
import io

from fastapi import APIRouter, Depends, UploadFile, File, Form, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

# Mock user dependency
def get_current_user():
    return {"id": "mock_user_id", "username": "mock_user"}

router = APIRouter(prefix="/files", tags=["Files"])

# In-memory storage for demonstration
files_db: Dict[str, Dict] = {}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
ALLOWED_EXTENSIONS = {".txt", ".pdf", ".jpg", ".png"}

class FileInfo(BaseModel):
    id: str
    filename: str
    content_type: str
    size: int
    uploaded_at: datetime

def is_allowed_file(filename: str) -> bool:
    """Check if file extension is allowed."""
    return any(filename.lower().endswith(ext) for ext in ALLOWED_EXTENSIONS)

@router.post("/upload", response_model=FileInfo)
async def upload_file(
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user)
):
    """Upload a file."""
    if not is_allowed_file(file.filename):
        raise HTTPException(status_code=400, detail="File type not allowed.")

    content = await file.read()
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail="File is too large.")

    file_id = str(uuid4())
    file_record = {
        "id": file_id,
        "filename": file.filename,
        "content_type": file.content_type,
        "size": len(content),
        "content": content,
        "uploaded_by": current_user["id"],
        "uploaded_at": datetime.now(),
    }
    files_db[file_id] = file_record

    return FileInfo(**file_record)

@router.get("/{file_id}/download")
async def download_file(file_id: str, current_user: dict = Depends(get_current_user)):
    """Download a file."""
    if file_id not in files_db or files_db[file_id]["uploaded_by"] != current_user["id"]:
        raise HTTPException(status_code=404, detail="File not found or access denied.")

    file_record = files_db[file_id]
    return StreamingResponse(
        io.BytesIO(file_record["content"]),
        media_type=file_record["content_type"],
        headers={"Content-Disposition": f"attachment; filename={file_record['filename']}"}
    )

@router.get("/", response_model=List[FileInfo])
async def list_my_files(current_user: dict = Depends(get_current_user)):
    """List current user's files."""
    user_files = [
        FileInfo(**f) for f in files_db.values()
        if f["uploaded_by"] == current_user["id"]
    ]
    return sorted(user_files, key=lambda f: f.uploaded_at, reverse=True)

@router.delete("/{file_id}")
async def delete_file(file_id: str, current_user: dict = Depends(get_current_user)):
    """Delete a file."""
    if file_id in files_db and files_db[file_id]["uploaded_by"] == current_user["id"]:
        del files_db[file_id]
        return {"message": "File deleted"}
    raise HTTPException(status_code=404, detail="File not found or access denied.")

if __name__ == '__main__':
    # Example of how to run this API with uvicorn
    import uvicorn
    from fastapi import FastAPI

    app = FastAPI()
    app.include_router(router)

    # uvicorn.run(app, host="0.0.0.0", port=8000)
