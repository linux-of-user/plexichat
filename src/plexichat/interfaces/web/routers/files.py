import hashlib
import logging
import mimetypes
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

import aiofiles
import magic
from PIL import Image
from sqlmodel import Session, select



from fastapi import (
from fastapi.responses import FileResponse

from plexichat.core.database import get_session
from plexichat.features.users.files import FileRecord, FileShare
from plexichat.features.users.user import User
from plexichat.infrastructure.utils.auth import from plexichat.infrastructure.utils.auth import get_current_user
from plexichat.infrastructure.utils.security import (
from plexichat.interfaces.web.schemas.files import (

"""
File management endpoints with comprehensive upload, download, and management capabilities.
Includes security features, virus scanning, and file type validation.
"""

    APIRouter,
    BackgroundTasks,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    UploadFile,
)
logger = logging.getLogger(__name__)
logging_manager = logging.getLogger(f"{__name__}.manager")
    sanitize_filename,
    scan_file_content,
    validate_file_type,
)
    FileInfoResponse,
    FileListResponse,
    FileUploadResponse,
)

router = APIRouter()

# Configuration
UPLOAD_DIR = from pathlib import Path
Path("uploads")
TEMP_DIR = from pathlib import Path
Path("temp")
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
ALLOWED_EXTENSIONS = {
    'images': {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'},
    'documents': {'.pdf', '.doc', '.docx', '.txt', '.rtf', '.odt'},
    'archives': {'.zip', '.tar', '.gz', '.rar', '.7z'},
    'data': {'.json', '.xml', '.csv', '.xlsx', '.xls'},
    'code': {'.py', '.js', '.html', '.css', '.sql', '.md'}
}

# Ensure directories exist
UPLOAD_DIR.mkdir(exist_ok=True)
TEMP_DIR.mkdir(exist_ok=True)

@router.post("/upload", response_model=FileUploadResponse)
async def upload_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    description: Optional[str] = Form(None),
    tags: Optional[str] = Form(None),
    public: bool = Form(False),
    session: Session = Depends(get_session),
    current_user: from plexichat.features.users.user import User
User = Depends(from plexichat.infrastructure.utils.auth import get_current_user)
):
    """
    Upload a file with comprehensive security checks and metadata extraction.
    """
    operation_id = f"file_upload_{current_user.id}_{from datetime import datetime
datetime.now().timestamp()}"
    logging_manager.start_performance_tracking(operation_id)
    
    try:
        # Validate file size
        if file.size and file.size > MAX_FILE_SIZE:
            raise HTTPException(
                status_code=413,
                detail=f"File too large. Maximum size is {MAX_FILE_SIZE // (1024*1024)}MB"
            )
        
        # Sanitize filename
        safe_filename = sanitize_filename(file.filename)
        if not safe_filename:
            raise HTTPException(status_code=400, detail="Invalid filename")
        
        # Validate file type
        file_extension = from pathlib import Path
Path(safe_filename).suffix.lower()
        if not validate_file_type(file_extension, ALLOWED_EXTENSIONS):
            raise HTTPException(
                status_code=400,
                detail=f"File type not allowed. Allowed types: {list(ALLOWED_EXTENSIONS.keys())}"
            )
        
        # Generate unique filename
        timestamp = from datetime import datetime
datetime.now().strftime("%Y%m%d_%H%M%S")
        unique_filename = f"{timestamp}_{safe_filename}"
        file_path = UPLOAD_DIR / unique_filename
        
        # Read and validate file content
        content = await file.read()
        await file.seek(0)  # Reset file pointer
        
        # Security scanning
        if not scan_file_content(content, file_extension):
            raise HTTPException(status_code=400, detail="File failed security scan")
        
        # Calculate file hash
        file_hash = hashlib.sha256(content).hexdigest()
        
        # Check for duplicates
        existing_file = session.exec(
            select(FileRecord).where(FileRecord.file_hash == file_hash)
        ).first()
        
        if existing_file:
            logger.info(f"Duplicate file detected: {file_hash}")
            return FileUploadResponse(
                id=existing_file.id,
                filename=existing_file.filename,
                size=existing_file.size,
                message="File already exists (duplicate detected)"
            )
        
        # Save file
        async with aiofiles.open(file_path, 'wb') as f:
            await f.write(content)
        
        # Extract metadata
        metadata = await extract_file_metadata(file_path, content)
        
        # Create database record
        file_record = FileRecord(
            filename=safe_filename,
            original_filename=file.filename,
            file_path=str(file_path),
            file_hash=file_hash,
            size=len(content),
            mime_type=file.content_type or mimetypes.guess_type(safe_filename)[0],
            extension=file_extension,
            description=description,
            tags=tags.split(',') if tags else [],
            metadata=metadata,
            is_public=public,
            uploaded_by=current_user.id,
            upload_date=from datetime import datetime
datetime.utcnow()
        )
        
        session.add(file_record)
        session.commit()
        session.refresh(file_record)
        
        # Schedule background tasks
        background_tasks.add_task(
            process_file_post_upload,
            file_record.id,
            str(file_path)
        )
        
        logger.info(f"File uploaded successfully: {safe_filename} by user {current_user.username}")
        
        return FileUploadResponse(
            id=file_record.id,
            filename=safe_filename,
            size=len(content),
            file_hash=file_hash,
            message="File uploaded successfully"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"File upload error: {e}")
        raise HTTPException(status_code=500, detail="File upload failed")
    finally:
        logging_manager.end_performance_tracking(
            operation_id,
            extra_context={"filename": file.filename, "user": current_user.username}
        )

@router.get("/list", response_model=FileListResponse)
async def list_files(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    file_type: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    my_files: bool = Query(False),
    session: Session = Depends(get_session),
    current_user: from plexichat.features.users.user import User
User = Depends(from plexichat.infrastructure.utils.auth import get_current_user)
):
    """
    List files with filtering, pagination, and search capabilities.
    """
    try:
        query = select(FileRecord)
        
        # Filter by user if requested
        if my_files:
            query = query.where(FileRecord.uploaded_by == current_user.id)
        else:
            # Show public files or user's own files
            query = query.where(
                (FileRecord.is_public) | 
                (FileRecord.uploaded_by == current_user.id)
            )
        
        # Filter by file type
        if file_type and file_type in ALLOWED_EXTENSIONS:
            extensions = ALLOWED_EXTENSIONS[file_type]
            query = query.where(FileRecord.extension.in_(extensions))
        
        # Search functionality
        if search:
            search_term = f"%{search}%"
            query = query.where(
                (FileRecord.filename.ilike(search_term)) |
                (FileRecord.description.ilike(search_term)) |
                (FileRecord.tags.contains([search]))
            )
        
        # Pagination
        offset = (page - 1) * limit
        files = session.exec(query.offset(offset).limit(limit)).all()
        
        # Get total count
        total_query = select(FileRecord)
        if my_files:
            total_query = total_query.where(FileRecord.uploaded_by == current_user.id)
        total_count = len(session.exec(total_query).all())
        
        return FileListResponse(
            files=[
                FileInfoResponse(
                    id=f.id,
                    filename=f.filename,
                    size=f.size,
                    mime_type=f.mime_type,
                    upload_date=f.upload_date,
                    description=f.description,
                    tags=f.tags,
                    is_public=f.is_public,
                    uploaded_by=f.uploaded_by
                ) for f in files
            ],
            total=total_count,
            page=page,
            limit=limit,
            has_more=offset + limit < total_count
        )
        
    except Exception as e:
        logger.error(f"File listing error: {e}")
        raise HTTPException(status_code=500, detail="Failed to list files")

@router.get("/{file_id}/download")
async def download_file(
    file_id: int,
    session: Session = Depends(get_session),
    current_user: from plexichat.features.users.user import User
User = Depends(from plexichat.infrastructure.utils.auth import get_current_user)
):
    """
    Download a file with access control and logging.
    """
    try:
        file_record = session.get(FileRecord, file_id)
        if not file_record:
            raise HTTPException(status_code=404, detail="File not found")
        
        # Check access permissions
        if not file_record.is_public and file_record.uploaded_by != current_user.id:
            # Check if file is shared with user
            share = session.exec(
                select(FileShare).where(
                    (FileShare.file_id == file_id) &
                    (FileShare.shared_with == current_user.id) &
                    (FileShare.expires_at > from datetime import datetime
datetime.utcnow())
                )
            ).first()
            
            if not share:
                raise HTTPException(status_code=403, detail="Access denied")
        
        file_path = from pathlib import Path
Path(file_record.file_path)
        if not file_path.exists():
            raise HTTPException(status_code=404, detail="File not found on disk")
        
        # Log download
        logger.info(f"File downloaded: {file_record.filename} by user {current_user.username}")
        
        # Update download count
        file_record.download_count = (file_record.download_count or 0) + 1
        file_record.last_accessed = from datetime import datetime
datetime.utcnow()
        session.add(file_record)
        session.commit()
        
        return FileResponse(
            path=file_path,
            filename=file_record.original_filename,
            media_type=file_record.mime_type
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"File download error: {e}")
        raise HTTPException(status_code=500, detail="File download failed")

async def extract_file_metadata(file_path: Path, content: bytes) -> Dict[str, Any]:
    """Extract metadata from uploaded file."""
    metadata = {}
    
    try:
        # Basic file info
        metadata['size'] = len(content)
        metadata['created'] = from datetime import datetime
datetime.now().isoformat()
        
        # MIME type detection
        mime_type = magic.from_buffer(content, mime=True)
        metadata['detected_mime_type'] = mime_type
        
        # Image metadata
        if mime_type.startswith('image/'):
            try:
                with Image.open(file_path) as img:
                    metadata['image'] = {
                        'width': img.width,
                        'height': img.height,
                        'format': img.format,
                        'mode': img.mode
                    }
                    
                    # EXIF data if available
                    if hasattr(img, '_getexif') and img._getexif():
                        metadata['image']['exif'] = dict(img._getexif())
            except Exception:
                pass
        
        # Text file analysis
        elif mime_type.startswith('text/'):
            try:
                text_content = content.decode('utf-8')
                metadata['text'] = {
                    'lines': len(text_content.splitlines()),
                    'characters': len(text_content),
                    'words': len(text_content.split())
                }
            except Exception:
                pass
        
    except Exception as e:
        logger.warning(f"Metadata extraction failed: {e}")
    
    return metadata

async def process_file_post_upload(file_id: int, file_path: str):
    """Background task for post-upload processing."""
    try:
        # Additional processing like thumbnail generation, virus scanning, etc.
        logger.info(f"Post-processing file {file_id}")
        
        # Generate thumbnails for images
        if from pathlib import Path
Path(file_path).suffix.lower() in {'.jpg', '.jpeg', '.png', '.gif'}:
            await generate_thumbnail(file_path)
        
        # Additional security scans
        # await run_advanced_security_scan(file_path)
        
    except Exception as e:
        logger.error(f"Post-upload processing failed for file {file_id}: {e}")

async def generate_thumbnail(file_path: str):
    """Generate thumbnail for image files."""
    try:
        with Image.open(file_path) as img:
            img.thumbnail((200, 200))
            thumbnail_path = from pathlib import Path
Path(file_path).with_suffix('.thumb.jpg')
            img.save(thumbnail_path, 'JPEG')
            logger.debug(f"Thumbnail generated: {thumbnail_path}")
    except Exception as e:
        logger.warning(f"Thumbnail generation failed: {e}")
