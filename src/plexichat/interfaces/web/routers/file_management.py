import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

import aiofiles
import yaml
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from plexichat.core.auth.dependencies import get_current_admin_user
from plexichat.features.users.user import User

"""
PlexiChat File Management API

Provides comprehensive file management capabilities for the WebUI file editor.
Handles configuration files, module configs, templates, and other system files.
"""

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/admin/files", tags=["File Management"])

class FileContent(BaseModel):
    """File content model."""
    path: str
    content: str

class FileInfo(BaseModel):
    """File information model."""
    name: str
    path: str
    size: int
    modified: datetime
    type: str
    readable: bool
    writable: bool

class FileTreeResponse(BaseModel):
    """File tree response model."""
    config_files: List[FileInfo]
    module_configs: List[FileInfo]
    security_configs: List[FileInfo]
    backup_configs: List[FileInfo]
    templates: List[FileInfo]
    other_files: List[FileInfo]

class FileManager:
    """Comprehensive file management system."""
    
    def __init__(self):
        self.root_path = from pathlib import Path
Path(".")
        self.allowed_extensions = {
            '.yaml', '.yml', '.json', '.py', '.js', '.html', '.css', 
            '.md', '.txt', '.log', '.conf', '.cfg', '.ini', '.toml'
        }
        self.config_paths = [
            "config",
            "configs", 
            "src/plexichat/app/config",
            "src/plexichat/app/modules",
            "src/plexichat/app/security",
            "src/plexichat/app/backup",
            "src/plexichat/ai/config",
            "templates",
            "src/plexichat/app/web/templates"
        ]
        
    async def get_file_tree(self) -> Dict[str, List[FileInfo]]:
        """Get organized file tree for the editor."""
        try:
            file_tree = {
                "config_files": [],
                "module_configs": [],
                "security_configs": [],
                "backup_configs": [],
                "templates": [],
                "other_files": []
            }
            
            # Scan all config paths
            for config_path in self.config_paths:
                path = self.root_path / config_path
                if path.exists() and path.is_dir():
                    await self._scan_directory(path, file_tree)
            
            # Sort files by name
            for category in file_tree.values():
                category.sort(key=lambda x: x.name.lower())
            
            return file_tree
            
        except Exception as e:
            logger.error(f"Error getting file tree: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to get file tree: {str(e)}")
    
    async def _scan_directory(self, directory: Path, file_tree: Dict[str, List[FileInfo]]):
        """Scan directory for configuration files."""
        try:
            for item in directory.rglob("*"):
                if item.is_file() and item.suffix.lower() in self.allowed_extensions:
                    # Skip hidden files and __pycache__
                    if item.name.startswith('.') or '__pycache__' in str(item):
                        continue
                    
                    file_info = await self._get_file_info(item)
                    category = self._categorize_file(item)
                    file_tree[category].append(file_info)
                    
        except Exception as e:
            logger.error(f"Error scanning directory {directory}: {e}")
    
    async def _get_file_info(self, file_path: Path) -> FileInfo:
        """Get detailed file information."""
        try:
            stat = file_path.stat()
            return FileInfo(
                name=file_path.name,
                path=str(file_path.relative_to(self.root_path)),
                size=stat.st_size,
                modified=datetime.fromtimestamp(stat.st_mtime),
                type=file_path.suffix.lower(),
                readable=os.access(file_path, os.R_OK),
                writable=os.access(file_path, os.W_OK)
            )
        except Exception as e:
            logger.error(f"Error getting file info for {file_path}: {e}")
            raise
    
    def _categorize_file(self, file_path: Path) -> str:
        """Categorize file based on path and name."""
        path_str = str(file_path).lower()
        name = file_path.name.lower()
        
        # Module configs
        if 'modules' in path_str or 'module' in name:
            return "module_configs"
        
        # Security configs
        if any(keyword in path_str for keyword in ['security', 'auth', 'ddos', 'rate_limit']):
            return "security_configs"
        
        # Backup configs
        if any(keyword in path_str for keyword in ['backup', 'shard', 'recovery']):
            return "backup_configs"
        
        # Templates
        if 'template' in path_str or file_path.suffix in ['.html', '.css', '.js']:
            return "templates"
        
        # Config files
        if any(keyword in name for keyword in ['config', 'settings', 'conf']):
            return "config_files"
        
        # Everything else
        return "other_files"
    
    async def read_file(self, file_path: str) -> Dict[str, Any]:
        """Read file content and metadata."""
        try:
            full_path = self.root_path / file_path
            
            # Security check
            if not self._is_safe_path(full_path):
                raise HTTPException(status_code=403, detail="Access denied")
            
            if not full_path.exists():
                raise HTTPException(status_code=404, detail="File not found")
            
            # Read file content
            async with aiofiles.open(full_path, 'r', encoding='utf-8') as f:
                content = await f.read()
            
            # Get file metadata
            stat = full_path.stat()
            
            return {
                "content": content,
                "size": stat.st_size,
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "encoding": "utf-8",
                "type": full_path.suffix.lower()
            }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error reading file {file_path}: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to read file: {str(e)}")
    
    async def write_file(self, file_path: str, content: str) -> bool:
        """Write content to file with backup."""
        try:
            full_path = self.root_path / file_path
            
            # Security check
            if not self._is_safe_path(full_path):
                raise HTTPException(status_code=403, detail="Access denied")
            
            # Create backup if file exists
            if full_path.exists():
                await self._create_backup(full_path)
            
            # Validate content based on file type
            await self._validate_content(full_path, content)
            
            # Ensure directory exists
            full_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Write file
            async with aiofiles.open(full_path, 'w', encoding='utf-8') as f:
                await f.write(content)
            
            logger.info(f"File saved: {file_path}")
            return True
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error writing file {file_path}: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to write file: {str(e)}")
    
    async def _create_backup(self, file_path: Path):
        """Create backup of existing file."""
        try:
            backup_dir = self.root_path / "backups" / "file_editor"
            backup_dir.mkdir(parents=True, exist_ok=True)
            
            timestamp = from datetime import datetime
datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_name = f"{file_path.name}.{timestamp}.bak"
            backup_path = backup_dir / backup_name
            
            # Copy file to backup
            async with aiofiles.open(file_path, 'r', encoding='utf-8') as src:
                content = await src.read()
            
            async with aiofiles.open(backup_path, 'w', encoding='utf-8') as dst:
                await dst.write(content)
            
            logger.info(f"Created backup: {backup_path}")
            
        except Exception as e:
            logger.warning(f"Failed to create backup for {file_path}: {e}")
    
    async def _validate_content(self, file_path: Path, content: str):
        """Validate file content based on type."""
        try:
            ext = file_path.suffix.lower()
            
            if ext == '.json':
                json.loads(content)  # Validate JSON
            elif ext in ['.yaml', '.yml']:
                yaml.safe_load(content)  # Validate YAML
            elif ext == '.py':
                compile(content, str(file_path), 'exec')  # Validate Python syntax
                
        except json.JSONDecodeError as e:
            raise HTTPException(status_code=400, detail=f"Invalid JSON: {str(e)}")
        except yaml.YAMLError as e:
            raise HTTPException(status_code=400, detail=f"Invalid YAML: {str(e)}")
        except SyntaxError as e:
            raise HTTPException(status_code=400, detail=f"Invalid Python syntax: {str(e)}")
    
    def _is_safe_path(self, file_path: Path) -> bool:
        """Check if file path is safe to access."""
        try:
            # Resolve path and check if it's within allowed directories
            resolved_path = file_path.resolve()
            root_resolved = self.root_path.resolve()
            
            # Must be within project root
            if not str(resolved_path).startswith(str(root_resolved)):
                return False
            
            # Block access to sensitive files
            blocked_patterns = [
                '.env', '.git', '__pycache__', '.pyc', 
                'node_modules', '.vscode', '.idea'
            ]
            
            path_str = str(resolved_path).lower()
            for pattern in blocked_patterns:
                if pattern in path_str:
                    return False
            
            return True
            
        except Exception:
            return False

# Global file manager instance
file_manager = FileManager()

@router.get("/tree", response_model=FileTreeResponse)
async def get_file_tree(current_user: from plexichat.features.users.user import User
User = Depends(get_current_admin_user)):
    """Get organized file tree for the editor."""
    return await file_manager.get_file_tree()

@router.get("/content")
async def get_file_content(
    path: str,
    current_user: from plexichat.features.users.user import User
User = Depends(get_current_admin_user)
):
    """Get file content and metadata."""
    return await file_manager.read_file(path)

@router.post("/save")
async def save_file_content(
    file_data: FileContent,
    current_user: from plexichat.features.users.user import User
User = Depends(get_current_admin_user)
):
    """Save file content."""
    success = await file_manager.write_file(file_data.path, file_data.content)
    return {"success": success, "message": "File saved successfully"}

@router.get("/validate")
async def validate_file_content(
    path: str,
    content: str,
    current_user: from plexichat.features.users.user import User
User = Depends(get_current_admin_user)
):
    """Validate file content without saving."""
    try:
        full_path = from pathlib import Path
Path(path)
        await file_manager._validate_content(full_path, content)
        return {"valid": True, "message": "Content is valid"}
    except HTTPException as e:
        return {"valid": False, "message": e.detail}

@router.get("/backups")
async def list_file_backups(
    path: str,
    current_user: from plexichat.features.users.user import User
User = Depends(get_current_admin_user)
):
    """List available backups for a file."""
    try:
        file_path = from pathlib import Path
Path(path)
        backup_dir = from pathlib import Path
Path("backups/file_editor")
        
        if not backup_dir.exists():
            return {"backups": []}
        
        backups = []
        pattern = f"{file_path.name}.*.bak"
        
        for backup_file in backup_dir.glob(pattern):
            stat = backup_file.stat()
            backups.append({
                "name": backup_file.name,
                "path": str(backup_file),
                "size": stat.st_size,
                "created": datetime.fromtimestamp(stat.st_ctime).isoformat()
            })
        
        # Sort by creation time (newest first)
        backups.sort(key=lambda x: x["created"], reverse=True)
        
        return {"backups": backups}
        
    except Exception as e:
        logger.error(f"Error listing backups for {path}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to list backups: {str(e)}")

@router.post("/restore")
async def restore_file_backup(
    backup_path: str,
    target_path: str,
    current_user: from plexichat.features.users.user import User
User = Depends(get_current_admin_user)
):
    """Restore file from backup."""
    try:
        backup_file = from pathlib import Path
Path(backup_path)
Path(target_path)
        
        if not backup_file.exists():
            raise HTTPException(status_code=404, detail="Backup file not found")
        
        # Read backup content
        async with aiofiles.open(backup_file, 'r', encoding='utf-8') as f:
            content = await f.read()
        
        # Save to target
        success = await file_manager.write_file(target_path, content)
        
        return {"success": success, "message": "File restored from backup"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error restoring backup {backup_path}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to restore backup: {str(e)}")
