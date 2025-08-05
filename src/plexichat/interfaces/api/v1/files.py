"""
PlexiChat API v1 - File Management Endpoints

Simple file handling with:
- File upload
- File download
- File sharing
- File metadata
- File deletion
"""

import mimetypes
import os
from datetime import datetime
from typing import Dict, List, Optional
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Depends, UploadFile, File, Form
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
import logging
import io

from .auth import get_current_user

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/files", tags=["Files"])

# In-memory file storage (use proper storage in production)
files_db = {}

# Configuration
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
ALLOWED_EXTENSIONS = {
    '.txt', '.pdf', '.doc', '.docx', '.jpg', '.jpeg', '.png', '.gif', 
    '.mp3', '.mp4', '.zip', '.csv', '.json', '.xml'
}

# Models
class FileInfo(BaseModel):
    id: str
    filename: str
    content_type: str
    size: int
    uploaded_by: str
    uploaded_at: datetime
    description: Optional[str] = None
    is_public: bool = False

class FileShare(BaseModel):
    user_id: str
    permission: str = "read"  # read, write, admin

# Utility functions
def is_allowed_file(filename: str) -> bool:
    """Check if file extension is allowed."""
    return any(filename.lower().endswith(ext) for ext in ALLOWED_EXTENSIONS)

def get_file_type(filename: str) -> str:
    """Get file type category."""
    ext = os.path.splitext(filename)[1].lower()
    
    if ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp']:
        return 'image'
    elif ext in ['.mp3', '.wav', '.ogg']:
        return 'audio'
    elif ext in ['.mp4', '.avi', '.mov']:
        return 'video'
    elif ext in ['.pdf', '.doc', '.docx', '.txt']:
        return 'document'
    else:
        return 'other'

# Endpoints
@router.post("/upload", response_model=FileInfo)
async def upload_file(
    file: UploadFile = File(...),
    description: Optional[str] = Form(None),
    is_public: bool = Form(False),
    current_user: dict = Depends(get_current_user)
):
    """Upload a file."""
    try:
        # Validate file
        if not file.filename:
            raise HTTPException(status_code=400, detail="No file provided")
        
        if not is_allowed_file(file.filename):
            raise HTTPException(status_code=400, detail="File type not allowed")
        
        # Read file content
        content = await file.read()
        
        if len(content) > MAX_FILE_SIZE:
            raise HTTPException(status_code=413, detail=f"File too large (max {MAX_FILE_SIZE // 1024 // 1024}MB)")
        
        # Create file record
        file_id = str(uuid4())
        content_type = file.content_type or mimetypes.guess_type(file.filename)[0] or 'application/octet-stream'
        
        file_record = {
            'id': file_id,
            'filename': file.filename,
            'content_type': content_type,
            'size': len(content),
            'content': content,  # Store in memory (use proper storage in production)
            'uploaded_by': current_user['id'],
            'uploaded_at': datetime.now(),
            'description': description,
            'is_public': is_public,
            'file_type': get_file_type(file.filename),
            'shares': {},  # user_id -> permission
            'download_count': 0
        }
        
        files_db[file_id] = file_record
        
        logger.info(f"File uploaded: {file.filename} ({file_id}) by {current_user['username']}")
        
        return FileInfo(
            id=file_id,
            filename=file.filename,
            content_type=content_type,
            size=len(content),
            uploaded_by=current_user['id'],
            uploaded_at=file_record['uploaded_at'],
            description=description,
            is_public=is_public
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"File upload error: {e}")
        raise HTTPException(status_code=500, detail="File upload failed")

@router.get("/{file_id}/download")
async def download_file(
    file_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Download a file."""
    try:
        if file_id not in files_db:
            raise HTTPException(status_code=404, detail="File not found")
        
        file_record = files_db[file_id]
        
        # Check permissions
        can_access = (
            file_record['uploaded_by'] == current_user['id'] or  # Owner
            file_record['is_public'] or  # Public file
            current_user['id'] in file_record['shares']  # Shared with user
        )
        
        if not can_access:
            raise HTTPException(status_code=403, detail="Access denied")
        
        # Increment download count
        file_record['download_count'] += 1
        
        # Create file stream
        file_stream = io.BytesIO(file_record['content'])
        
        logger.info(f"File downloaded: {file_record['filename']} ({file_id}) by {current_user['username']}")
        
        return StreamingResponse(
            io.BytesIO(file_record['content']),
            media_type=file_record['content_type'],
            headers={
                "Content-Disposition": f"attachment; filename={file_record['filename']}"
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"File download error: {e}")
        raise HTTPException(status_code=500, detail="File download failed")

@router.get("/{file_id}/info", response_model=FileInfo)
async def get_file_info(
    file_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get file information."""
    try:
        if file_id not in files_db:
            raise HTTPException(status_code=404, detail="File not found")
        
        file_record = files_db[file_id]
        
        # Check permissions
        can_access = (
            file_record['uploaded_by'] == current_user['id'] or
            file_record['is_public'] or
            current_user['id'] in file_record['shares']
        )
        
        if not can_access:
            raise HTTPException(status_code=403, detail="Access denied")
        
        return FileInfo(
            id=file_record['id'],
            filename=file_record['filename'],
            content_type=file_record['content_type'],
            size=file_record['size'],
            uploaded_by=file_record['uploaded_by'],
            uploaded_at=file_record['uploaded_at'],
            description=file_record['description'],
            is_public=file_record['is_public']
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get file info error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get file info")

@router.get("/")
async def list_my_files(
    file_type: Optional[str] = None,
    limit: int = 20,
    offset: int = 0,
    current_user: dict = Depends(get_current_user)
):
    """List current user's files."""
    try:
        user_files = []
        
        for file_record in files_db.values():
            if file_record['uploaded_by'] == current_user['id']:
                if file_type is None or file_record['file_type'] == file_type:
                    user_files.append(file_record)
        
        # Sort by upload date (newest first)
        user_files.sort(key=lambda x: x['uploaded_at'], reverse=True)
        
        # Apply pagination
        total = len(user_files)
        paginated_files = user_files[offset:offset + limit]
        
        # Format response
        files_list = []
        for file_record in paginated_files:
            files_list.append({
                "id": file_record['id'],
                "filename": file_record['filename'],
                "content_type": file_record['content_type'],
                "size": file_record['size'],
                "file_type": file_record['file_type'],
                "uploaded_at": file_record['uploaded_at'],
                "description": file_record['description'],
                "is_public": file_record['is_public'],
                "download_count": file_record['download_count']
            })
        
        return {}
            "files": files_list,
            "total": total,
            "limit": limit,
            "offset": offset,
            "has_more": offset + limit < total
        }
        
    except Exception as e:
        logger.error(f"List files error: {e}")
        raise HTTPException(status_code=500, detail="Failed to list files")

@router.post("/{file_id}/share")
async def share_file(
    file_id: str,
    share_data: FileShare,
    current_user: dict = Depends(get_current_user)
):
    """Share a file with another user."""
    try:
        if file_id not in files_db:
            raise HTTPException(status_code=404, detail="File not found")
        
        file_record = files_db[file_id]
        
        # Only owner can share
        if file_record['uploaded_by'] != current_user['id']:
            raise HTTPException(status_code=403, detail="Only file owner can share")
        
        # Validate user exists
        from .auth import users_db
        if share_data.user_id not in users_db:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Add share permission
        file_record['shares'][share_data.user_id] = share_data.permission
        
        logger.info(f"File shared: {file_record['filename']} ({file_id}) with {share_data.user_id}")
        
        return {}
            "success": True,
            "message": "File shared successfully",
            "shared_with": share_data.user_id,
            "permission": share_data.permission
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Share file error: {e}")
        raise HTTPException(status_code=500, detail="Failed to share file")

@router.delete("/{file_id}")
async def delete_file(
    file_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Delete a file."""
    try:
        if file_id not in files_db:
            raise HTTPException(status_code=404, detail="File not found")
        
        file_record = files_db[file_id]
        
        # Only owner can delete
        if file_record['uploaded_by'] != current_user['id']:
            raise HTTPException(status_code=403, detail="Only file owner can delete")
        
        filename = file_record['filename']
        del files_db[file_id]
        
        logger.info(f"File deleted: {filename} ({file_id}) by {current_user['username']}")
        
        return {}
            "success": True,
            "message": "File deleted successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Delete file error: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete file")

@router.get("/stats")
async def get_file_stats(current_user: dict = Depends(get_current_user)):
    """Get file statistics."""
    try:
        user_files = [f for f in files_db.values() if f['uploaded_by'] == current_user['id']]
        
        total_size = sum(f['size'] for f in user_files)
        total_downloads = sum(f['download_count'] for f in user_files)
        
        file_types = {}
        for f in user_files:
            file_type = f['file_type']
            if file_type not in file_types:
                file_types[file_type] = 0
            file_types[file_type] += 1
        
        return {}
            "total_files": len(user_files),
            "total_size_bytes": total_size,
            "total_downloads": total_downloads,
            "file_types": file_types,
            "public_files": sum(1 for f in user_files if f['is_public']),
            "shared_files": sum(1 for f in user_files if f['shares'])
        }
        
    except Exception as e:
        logger.error(f"Get file stats error: {e}")
        raise HTTPException(status_code=500, detail="Failed to get file stats")
