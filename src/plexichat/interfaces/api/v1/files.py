import io
import logging
import mimetypes
from datetime import datetime
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, UploadFile, File, HTTPException, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from uuid import uuid4

# Use the unified FastAPI auth adapter for authentication and rate limiting
from plexichat.core.auth.fastapi_adapter import get_current_user, rate_limit

# Use the centralized security system
try:
    from plexichat.core.security.security_manager import get_security_system
except Exception:
    get_security_system = None

# Use the centralized file manager
try:
    from plexichat.core.files import file_manager
except Exception:
    file_manager = None

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/files", tags=["Files"])

# Fallback constants if file_manager not available
DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
DEFAULT_ALLOWED_EXTENSIONS = {".txt", ".pdf", ".jpg", ".png"}


class FileInfo(BaseModel):
    id: str
    filename: str
    content_type: str
    size: int
    uploaded_at: datetime


def _get_allowed_extensions() -> set:
    """Retrieve allowed extensions from file manager if available, otherwise fallback."""
    try:
        if file_manager and hasattr(file_manager, "allowed_extensions"):
            exts = file_manager.allowed_extensions
            # ensure set of lower-case extensions
            return {e.lower() if e.startswith(".") else f".{e.lower()}" for e in exts}
    except Exception:
        logger.debug("Could not load allowed extensions from file_manager; using defaults.")
    return DEFAULT_ALLOWED_EXTENSIONS


def _get_max_file_size() -> int:
    """Get max file size from file manager if available, otherwise fallback."""
    try:
        if file_manager and hasattr(file_manager, "max_file_size"):
            return int(file_manager.max_file_size)
    except Exception:
        logger.debug("Could not load max_file_size from file_manager; using defaults.")
    return DEFAULT_MAX_FILE_SIZE


def _parse_sanitized_filename_from_message(message: str) -> Optional[str]:
    """Parse sanitized filename if the security validate_file_upload returned it in the message."""
    if not message:
        return None
    marker = "Sanitized filename:"
    if marker in message:
        try:
            return message.split(marker, 1)[1].strip()
        except Exception:
            return None
    return None


@router.post("/upload", response_model=FileInfo)
@rate_limit(action="file_upload", limit=10, window_seconds=60)  # limit to 10 uploads per minute per user
async def upload_file(
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user)
):
    """Upload a file with security checks, sanitization, rate limiting and persistence via file manager."""
    filename = file.filename or ""
    content_type = file.content_type or mimetypes.guess_type(filename)[0] or "application/octet-stream"

    # Basic filename presence check
    if not filename or not isinstance(filename, str) or filename.strip() == "":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Filename is required.")

    # Enforce filename maximum length early
    if len(filename) > 120:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Filename is too long (maximum 120 characters).")

    # Read content to get file size; reading into memory is necessary to pass bytes to file_manager
    try:
        content = await file.read()
    except Exception as e:
        logger.error(f"Failed to read uploaded file content: {e}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Failed to read uploaded file.")

    file_size = len(content)
    max_size = _get_max_file_size()
    if file_size > max_size:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail=f"File is too large. Maximum allowed size is {max_size} bytes.")

    # Allowed extension check (basic)
    allowed_exts = _get_allowed_extensions()
    ext = ""
    try:
        import os as _os
        _, ext = _os.path.splitext(filename)
        ext = ext.lower()
    except Exception:
        ext = ""

    if not ext or ext not in allowed_exts:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"File type not allowed: '{ext}'")

    # Use centralized security system for thorough validation and sanitization
    security_system = None
    if get_security_system:
        try:
            security_system = get_security_system()
        except Exception as e:
            logger.debug(f"Could not obtain security system instance: {e}")
            security_system = None

    if security_system:
        try:
            allowed, message = security_system.validate_file_upload(filename, content_type, file_size, policy_name="default")
            if not allowed:
                # Security-aware error message
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=message)
            # Try to extract sanitized filename from message; if not present, use sanitizer directly
            sanitized = _parse_sanitized_filename_from_message(message)
            if not sanitized and hasattr(security_system, "_sanitize_filename"):
                try:
                    sanitized = security_system._sanitize_filename(filename)
                except Exception:
                    sanitized = filename
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Security validation error: {e}")
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="File failed security validation.")
    else:
        # If no security system, do a minimal sanitize: strip path components
        try:
            from pathlib import Path
            sanitized = Path(filename).name
        except Exception:
            sanitized = filename

    # Persist file using the centralized file manager if available
    if file_manager:
        try:
            # file_manager.upload_file signature: (file_data: bytes, filename: str, uploaded_by: int, content_type: str = None, ...)
            file_meta = await file_manager.upload_file(content, sanitized, current_user.get("id"), content_type=content_type)
            if not file_meta:
                raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to store file.")
            # Map FileMetadata to FileInfo
            return FileInfo(
                id=getattr(file_meta, "file_id", getattr(file_meta, "fileId", "")),
                filename=getattr(file_meta, "original_filename", getattr(file_meta, "filename", sanitized)),
                content_type=getattr(file_meta, "content_type", content_type),
                size=int(getattr(file_meta, "file_size", file_size)),
                uploaded_at=getattr(file_meta, "uploaded_at", datetime.now())
            )
        except ValueError as ve:
            # File validation from file_manager failed (size/type etc.)
            logger.warning(f"File upload rejected by file manager: {ve}")
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Unexpected error during file upload persistence: {e}")
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal error while storing file.")
    else:
        # Fallback to in-memory storage (deprecated, only if file_manager missing)
        # Keep a simple in-memory map scoped to the module
        global _fallback_files_db
        try:
            _fallback_files_db
        except NameError:
            _fallback_files_db = {}

        file_id = str(uuid4())
        record = {
            "id": file_id,
            "filename": sanitized,
            "content_type": content_type,
            "size": file_size,
            "content": content,
            "uploaded_by": current_user.get("id"),
            "uploaded_at": datetime.now()
        }
        _fallback_files_db[file_id] = record
        return FileInfo(**record)


@router.get("/{file_id}/download")
async def download_file(file_id: str, current_user: dict = Depends(get_current_user)):
    """Download a file using the centralized file manager."""
    # Prefer file_manager if available
    if file_manager:
        try:
            metadata = await file_manager.get_file_metadata(file_id)
            if not metadata:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found.")

            # Check ownership (uploaded_by may be int or str in different setups)
            uploaded_by = getattr(metadata, "uploaded_by", None)
            if uploaded_by is not None and str(uploaded_by) != str(current_user.get("id")):
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied to this file.")

            data = await file_manager.get_file_data(file_id)
            if data is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File data not found.")

            # Use the original filename if available
            filename = getattr(metadata, "original_filename", getattr(metadata, "filename", file_id))
            # Ensure safe Content-Disposition by quoting the filename
            disposition = f'attachment; filename="{filename}"'
            return StreamingResponse(
                io.BytesIO(data),
                media_type=getattr(metadata, "content_type", "application/octet-stream"),
                headers={"Content-Disposition": disposition}
            )
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error during file download: {e}")
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to retrieve file.")
    else:
        # Fallback to in-memory
        try:
            _fallback_files_db
        except NameError:
            _fallback_files_db = {}

        record = _fallback_files_db.get(file_id)
        if not record or str(record.get("uploaded_by")) != str(current_user.get("id")):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found or access denied.")
        disposition = f'attachment; filename="{record["filename"]}"'
        return StreamingResponse(
            io.BytesIO(record["content"]),
            media_type=record["content_type"],
            headers={"Content-Disposition": disposition}
        )


@router.get("/", response_model=List[FileInfo])
async def list_my_files(current_user: dict = Depends(get_current_user)):
    """List current user's files. Uses the file manager's database when available."""
    results: List[FileInfo] = []

    # If file_manager exposes a DB manager, try to query files table for this user
    try:
        if file_manager and getattr(file_manager, "db_manager", None):
            dbm = file_manager.db_manager
            # Try common async session interface used elsewhere in the codebase
            try:
                async with dbm.get_session() as session:
                    query = "SELECT * FROM files WHERE uploaded_by = :uploaded_by ORDER BY uploaded_at DESC"
                    params = {"uploaded_by": current_user.get("id")}
                    # Attempt fetchall; some session implementations provide fetchall
                    rows = None
                    if hasattr(session, "fetchall"):
                        rows = await session.fetchall(query, params)
                    elif hasattr(session, "fetch") or hasattr(session, "fetchall_rows"):
                        # Best-effort fallbacks
                        try:
                            rows = await session.fetch(query, params)
                        except Exception:
                            try:
                                rows = await session.fetchall_rows(query, params)
                            except Exception:
                                rows = []
                    else:
                        rows = []

                    if rows:
                        for row in rows:
                            try:
                                uploaded_at = row.get("uploaded_at") if isinstance(row.get("uploaded_at"), datetime) else datetime.fromisoformat(row.get("uploaded_at")) if row.get("uploaded_at") else datetime.now()
                            except Exception:
                                uploaded_at = datetime.now()
                            results.append(FileInfo(
                                id=row.get("file_id") or row.get("id"),
                                filename=row.get("original_filename") or row.get("filename") or "",
                                content_type=row.get("content_type") or "application/octet-stream",
                                size=int(row.get("file_size") or 0),
                                uploaded_at=uploaded_at
                            ))
                        return results
            except Exception as db_err:
                logger.debug(f"Could not query files table from file_manager.db_manager: {db_err}")

    except Exception:
        logger.debug("Error while attempting to list files via file_manager database access; falling back if possible.")

    # Fallback: if file_manager offers no DB access, try scanning uploads directory metadata (best-effort)
    try:
        if file_manager and hasattr(file_manager, "get_stats"):
            stats = file_manager.get_stats()
            # Can't produce per-user listing from stats; so return empty list as conservative behavior
            return results
    except Exception:
        logger.debug("file_manager.get_stats failed during list operation.")

    # Final fallback to in-memory records if present
    try:
        _fallback_files_db
    except NameError:
        _fallback_files_db = {}

    for rec in _fallback_files_db.values():
        if str(rec.get("uploaded_by")) == str(current_user.get("id")):
            results.append(FileInfo(**rec))

    # Sort by uploaded_at desc
    results.sort(key=lambda f: f.uploaded_at, reverse=True)
    return results


@router.delete("/{file_id}")
async def delete_file(file_id: str, current_user: dict = Depends(get_current_user)):
    """Delete a file. Uses file_manager.delete_file when available."""
    if file_manager:
        try:
            success = await file_manager.delete_file(file_id, current_user.get("id"))
            if success:
                return {"message": "File deleted"}
            # If deletion failed due to permissions or not found, return 404 to avoid information disclosure
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found or access denied.")
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error deleting file: {e}")
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to delete file.")
    else:
        try:
            _fallback_files_db
        except NameError:
            _fallback_files_db = {}

        rec = _fallback_files_db.get(file_id)
        if not rec or str(rec.get("uploaded_by")) != str(current_user.get("id")):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found or access denied.")
        del _fallback_files_db[file_id]
        return {"message": "File deleted"}


if __name__ == '__main__':
    # Example of how to run this API with uvicorn
    import uvicorn
    from fastapi import FastAPI
    from uuid import uuid4  # used by fallback

    app = FastAPI()
    app.include_router(router)

    # uvicorn.run(app, host="0.0.0.0", port=8000)
