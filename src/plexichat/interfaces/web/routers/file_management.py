"""
File Management Router - Enhanced file operations and management.
"""

import logging
from typing import List, Optional, Dict, Any
from pathlib import Path
from fastapi import APIRouter, HTTPException, UploadFile, File, Depends, Query, status
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/file-management", tags=["file-management"])


class FileInfo(BaseModel):
    """File information model."""
        name: str = Field(..., description="File name")
    path: str = Field(..., description="File path")
    size: int = Field(..., description="File size in bytes")
    type: str = Field(..., description="File type")
    modified: str = Field(..., description="Last modified timestamp")
    is_directory: bool = Field(default=False, description="Is directory flag")


class DirectoryListing(BaseModel):
    """Directory listing model."""
        path: str = Field(..., description="Current directory path")
    files: List[FileInfo] = Field(default_factory=list, description="Files in directory")
    total_files: int = Field(default=0, description="Total number of files")


@router.get("/list", response_model=DirectoryListing)
async def list_directory(
    path: str = Query(".", description="Directory path to list"),
    show_hidden: bool = Query(False, description="Show hidden files")
):
    """List directory contents."""
    try:
        target_path = Path(path).resolve()
        
        # Security check - prevent directory traversal
        if not str(target_path).startswith(str(Path.cwd())):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: Path outside allowed directory"
            )
        
        if not target_path.exists():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Directory not found"
            )
        
        if not target_path.is_dir():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Path is not a directory"
            )
        
        files = []
        for item in target_path.iterdir():
            # Skip hidden files unless requested
            if not show_hidden and item.name.startswith('.'):
                continue
                
            try:
                stat = item.stat()
                file_info = FileInfo(
                    name=item.name,
                    path=str(item.relative_to(Path.cwd())),
                    size=stat.st_size,
                    type="directory" if item.is_dir() else item.suffix.lower(),
                    modified=str(stat.st_mtime),
                    is_directory=item.is_dir()
                )
                files.append(file_info)
            except (OSError, PermissionError):
                # Skip files we can't access
                continue
        
        # Sort files: directories first, then by name
        files.sort(key=lambda x: (not x.is_directory, x.name.lower()))
        
        return DirectoryListing(
            path=str(target_path.relative_to(Path.cwd())),
            files=files,
            total_files=len(files)
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error listing directory {path}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list directory"
        )


@router.post("/create-directory")
async def create_directory(
    path: str = Query(..., description="Directory path to create")
):
    """Create a new directory."""
    try:
        target_path = Path(path).resolve()
        
        # Security check
        if not str(target_path).startswith(str(Path.cwd())):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: Path outside allowed directory"
            )
        
        if target_path.exists():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Directory already exists"
            )
        
        target_path.mkdir(parents=True, exist_ok=False)
        
        return JSONResponse(
            content={"success": True, "message": f"Directory created: {path}"},
            status_code=status.HTTP_201_CREATED
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating directory {path}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create directory"
        )


@router.delete("/delete")
async def delete_file_or_directory(
    path: str = Query(..., description="Path to delete")
):
    """Delete a file or directory."""
    try:
        target_path = Path(path).resolve()
        
        # Security check
        if not str(target_path).startswith(str(Path.cwd())):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: Path outside allowed directory"
            )
        
        if not target_path.exists():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="File or directory not found"
            )
        
        if target_path.is_dir():
            # Remove directory and all contents
            import shutil
            shutil.rmtree(target_path)
        else:
            # Remove file
            target_path.unlink()
        
        return JSONResponse(
            content={"success": True, "message": f"Deleted: {path}"}
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting {path}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete file or directory"
        )


@router.get("/download")
async def download_file(
    path: str = Query(..., description="File path to download")
):
    """Download a file."""
    try:
        target_path = Path(path).resolve()
        
        # Security check
        if not str(target_path).startswith(str(Path.cwd())):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: Path outside allowed directory"
            )
        
        if not target_path.exists():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="File not found"
            )
        
        if target_path.is_dir():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot download directory"
            )
        
        return FileResponse(
            path=str(target_path),
            filename=target_path.name,
            media_type='application/octet-stream'
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error downloading file {path}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to download file"
        )


@router.get("/info")
async def get_file_info(
    path: str = Query(..., description="File path to get info for")
):
    """Get detailed file information."""
    try:
        target_path = Path(path).resolve()
        
        # Security check
        if not str(target_path).startswith(str(Path.cwd())):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: Path outside allowed directory"
            )
        
        if not target_path.exists():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="File not found"
            )
        
        stat = target_path.stat()
        
        file_info = FileInfo(
            name=target_path.name,
            path=str(target_path.relative_to(Path.cwd())),
            size=stat.st_size,
            type="directory" if target_path.is_dir() else target_path.suffix.lower(),
            modified=str(stat.st_mtime),
            is_directory=target_path.is_dir()
        )
        
        return file_info
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting file info for {path}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get file information"
        )


@router.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "file-management"}
