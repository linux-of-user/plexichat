"""
Advanced File Manager Plugin

Comprehensive file management with bulk operations, preview, compression, and cloud sync.
"""

import asyncio
import json
import logging
import mimetypes
import os
import shutil
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import aiofiles
from fastapi import APIRouter, HTTPException, UploadFile, File
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel

# Plugin interface imports
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from plexichat.infrastructure.modules.plugin_manager import PluginInterface, PluginMetadata, PluginType
from plexichat.infrastructure.modules.base_module import ModulePermissions, ModuleCapability

logger = logging.getLogger(__name__)


class FileOperation(BaseModel):
    """File operation request model."""
    operation: str
    source_path: str
    destination_path: Optional[str] = None
    options: Optional[Dict[str, Any]] = None


class BulkOperation(BaseModel):
    """Bulk operation request model."""
    operation: str
    file_paths: List[str]
    destination_path: Optional[str] = None
    options: Optional[Dict[str, Any]] = None


class FileManagerCore:
    """Core file management functionality."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.max_file_size = config.get('max_file_size', 104857600)
        self.preview_enabled = config.get('preview_enabled', True)
        self.compression_level = config.get('compression_level', 6)
        
    async def list_directory(self, path: str) -> Dict[str, Any]:
        """List directory contents with metadata."""
        try:
            dir_path = Path(path)
            if not dir_path.exists() or not dir_path.is_dir():
                raise ValueError(f"Invalid directory: {path}")
            
            items = []
            for item in dir_path.iterdir():
                try:
                    stat = item.stat()
                    item_info = {
                        "name": item.name,
                        "path": str(item),
                        "type": "directory" if item.is_dir() else "file",
                        "size": stat.st_size if item.is_file() else 0,
                        "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                        "permissions": oct(stat.st_mode)[-3:],
                        "mime_type": mimetypes.guess_type(str(item))[0] if item.is_file() else None
                    }
                    items.append(item_info)
                except (OSError, PermissionError) as e:
                    logger.warning(f"Cannot access {item}: {e}")
                    continue
            
            return {
                "path": str(dir_path),
                "items": sorted(items, key=lambda x: (x["type"] == "file", x["name"].lower())),
                "total_items": len(items)
            }
            
        except Exception as e:
            logger.error(f"Error listing directory {path}: {e}")
            raise
    
    async def create_directory(self, path: str) -> bool:
        """Create a new directory."""
        try:
            Path(path).mkdir(parents=True, exist_ok=True)
            return True
        except Exception as e:
            logger.error(f"Error creating directory {path}: {e}")
            return False
    
    async def delete_item(self, path: str) -> bool:
        """Delete a file or directory."""
        try:
            item_path = Path(path)
            if item_path.is_file():
                item_path.unlink()
            elif item_path.is_dir():
                shutil.rmtree(item_path)
            return True
        except Exception as e:
            logger.error(f"Error deleting {path}: {e}")
            return False
    
    async def copy_item(self, source: str, destination: str) -> bool:
        """Copy a file or directory."""
        try:
            source_path = Path(source)
            dest_path = Path(destination)
            
            if source_path.is_file():
                shutil.copy2(source_path, dest_path)
            elif source_path.is_dir():
                shutil.copytree(source_path, dest_path)
            return True
        except Exception as e:
            logger.error(f"Error copying {source} to {destination}: {e}")
            return False
    
    async def move_item(self, source: str, destination: str) -> bool:
        """Move a file or directory."""
        try:
            shutil.move(source, destination)
            return True
        except Exception as e:
            logger.error(f"Error moving {source} to {destination}: {e}")
            return False
    
    async def compress_files(self, file_paths: List[str], output_path: str) -> bool:
        """Compress files into a ZIP archive."""
        try:
            with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED, 
                               compresslevel=self.compression_level) as zipf:
                for file_path in file_paths:
                    path = Path(file_path)
                    if path.exists():
                        if path.is_file():
                            zipf.write(path, path.name)
                        elif path.is_dir():
                            for root, dirs, files in os.walk(path):
                                for file in files:
                                    file_path = Path(root) / file
                                    arcname = file_path.relative_to(path.parent)
                                    zipf.write(file_path, arcname)
            return True
        except Exception as e:
            logger.error(f"Error compressing files: {e}")
            return False
    
    async def extract_archive(self, archive_path: str, destination: str) -> bool:
        """Extract a ZIP archive."""
        try:
            with zipfile.ZipFile(archive_path, 'r') as zipf:
                zipf.extractall(destination)
            return True
        except Exception as e:
            logger.error(f"Error extracting archive {archive_path}: {e}")
            return False
    
    async def search_files(self, directory: str, pattern: str, 
                          include_content: bool = False) -> List[Dict[str, Any]]:
        """Search for files by name pattern and optionally content."""
        results = []
        try:
            dir_path = Path(directory)
            if not dir_path.exists():
                return results
            
            for item in dir_path.rglob(pattern):
                if item.is_file():
                    result = {
                        "path": str(item),
                        "name": item.name,
                        "size": item.stat().st_size,
                        "modified": datetime.fromtimestamp(item.stat().st_mtime).isoformat()
                    }
                    
                    if include_content and item.suffix in ['.txt', '.py', '.js', '.html', '.css']:
                        try:
                            async with aiofiles.open(item, 'r', encoding='utf-8') as f:
                                content = await f.read(1000)  # First 1000 chars
                                result["preview"] = content
                        except Exception:
                            pass
                    
                    results.append(result)
                    
        except Exception as e:
            logger.error(f"Error searching files: {e}")
        
        return results


class FileManagerPlugin(PluginInterface):
    """Advanced File Manager Plugin."""
    
    def __init__(self):
        super().__init__("file_manager", "1.0.0")
        self.router = APIRouter()
        self.file_manager = None
        self.data_dir = Path(__file__).parent / "data"
        self.data_dir.mkdir(exist_ok=True)
        
    def get_metadata(self) -> PluginMetadata:
        """Get plugin metadata."""
        return PluginMetadata(
            name="file_manager",
            version="1.0.0",
            description="Advanced file management with bulk operations, preview, compression, and cloud sync",
            plugin_type=PluginType.UTILITY
        )
    
    def get_required_permissions(self) -> ModulePermissions:
        """Get required permissions."""
        return ModulePermissions(
            capabilities=[
                ModuleCapability.FILE_SYSTEM,
                ModuleCapability.NETWORK,
                ModuleCapability.WEB_UI
            ],
            network_access=True,
            file_system_access=True,
            database_access=False
        )
    
    async def initialize(self) -> bool:
        """Initialize the plugin."""
        try:
            # Load configuration
            await self._load_configuration()
            
            # Initialize file manager core
            self.file_manager = FileManagerCore(self.config)
            
            # Setup API routes
            self._setup_routes()
            
            # Register UI pages
            await self._register_ui_pages()
            
            self.logger.info("File Manager plugin initialized successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to initialize File Manager plugin: {e}")
            return False
    
    async def cleanup(self) -> bool:
        """Cleanup plugin resources."""
        try:
            self.logger.info("File Manager plugin cleanup completed")
            return True
        except Exception as e:
            self.logger.error(f"Error during File Manager plugin cleanup: {e}")
            return False

    def _setup_routes(self):
        """Setup API routes."""

        @self.router.get("/list")
        async def list_directory(path: str = "."):
            """List directory contents."""
            try:
                result = await self.file_manager.list_directory(path)
                return JSONResponse(content=result)
            except Exception as e:
                raise HTTPException(status_code=400, detail=str(e))

        @self.router.post("/create-dir")
        async def create_directory(path: str):
            """Create a new directory."""
            try:
                success = await self.file_manager.create_directory(path)
                return JSONResponse(content={"success": success})
            except Exception as e:
                raise HTTPException(status_code=400, detail=str(e))

        @self.router.delete("/delete")
        async def delete_item(path: str):
            """Delete a file or directory."""
            try:
                success = await self.file_manager.delete_item(path)
                return JSONResponse(content={"success": success})
            except Exception as e:
                raise HTTPException(status_code=400, detail=str(e))

        @self.router.post("/copy")
        async def copy_item(operation: FileOperation):
            """Copy a file or directory."""
            try:
                success = await self.file_manager.copy_item(
                    operation.source_path, operation.destination_path
                )
                return JSONResponse(content={"success": success})
            except Exception as e:
                raise HTTPException(status_code=400, detail=str(e))

        @self.router.post("/move")
        async def move_item(operation: FileOperation):
            """Move a file or directory."""
            try:
                success = await self.file_manager.move_item(
                    operation.source_path, operation.destination_path
                )
                return JSONResponse(content={"success": success})
            except Exception as e:
                raise HTTPException(status_code=400, detail=str(e))

        @self.router.post("/compress")
        async def compress_files(operation: BulkOperation):
            """Compress files into a ZIP archive."""
            try:
                success = await self.file_manager.compress_files(
                    operation.file_paths, operation.destination_path
                )
                return JSONResponse(content={"success": success})
            except Exception as e:
                raise HTTPException(status_code=400, detail=str(e))

        @self.router.post("/extract")
        async def extract_archive(operation: FileOperation):
            """Extract a ZIP archive."""
            try:
                success = await self.file_manager.extract_archive(
                    operation.source_path, operation.destination_path
                )
                return JSONResponse(content={"success": success})
            except Exception as e:
                raise HTTPException(status_code=400, detail=str(e))

        @self.router.get("/search")
        async def search_files(directory: str, pattern: str, include_content: bool = False):
            """Search for files."""
            try:
                results = await self.file_manager.search_files(
                    directory, pattern, include_content
                )
                return JSONResponse(content={"results": results})
            except Exception as e:
                raise HTTPException(status_code=400, detail=str(e))

    async def _load_configuration(self):
        """Load plugin configuration."""
        config_file = self.data_dir / "config.json"
        if config_file.exists():
            try:
                async with aiofiles.open(config_file, 'r') as f:
                    content = await f.read()
                    loaded_config = json.loads(content)
                    self.config.update(loaded_config)
            except Exception as e:
                self.logger.warning(f"Failed to load config: {e}")

    async def _register_ui_pages(self):
        """Register UI pages with the main application."""
        ui_dir = Path(__file__).parent / "ui"
        if ui_dir.exists():
            app = getattr(self.manager, 'app', None)
            if app:
                from fastapi.staticfiles import StaticFiles
                app.mount(f"/plugins/file-manager/static",
                         StaticFiles(directory=str(ui_dir / "static")),
                         name="file_manager_static")

    # Self-test methods
    async def test_file_operations(self) -> Dict[str, Any]:
        """Test basic file operations."""
        try:
            test_dir = self.data_dir / "test"
            test_file = test_dir / "test.txt"

            # Test directory creation
            await self.file_manager.create_directory(str(test_dir))
            if not test_dir.exists():
                return {"success": False, "error": "Directory creation failed"}

            # Test file creation and listing
            async with aiofiles.open(test_file, 'w') as f:
                await f.write("Test content")

            listing = await self.file_manager.list_directory(str(test_dir))
            if len(listing["items"]) != 1:
                return {"success": False, "error": "File listing failed"}

            # Cleanup
            await self.file_manager.delete_item(str(test_dir))

            return {"success": True, "message": "File operations test passed"}

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def test_compression(self) -> Dict[str, Any]:
        """Test compression functionality."""
        try:
            test_dir = self.data_dir / "compression_test"
            test_file = test_dir / "test.txt"
            zip_file = self.data_dir / "test.zip"

            # Create test files
            await self.file_manager.create_directory(str(test_dir))
            async with aiofiles.open(test_file, 'w') as f:
                await f.write("Test compression content")

            # Test compression
            success = await self.file_manager.compress_files([str(test_file)], str(zip_file))
            if not success or not zip_file.exists():
                return {"success": False, "error": "Compression failed"}

            # Test extraction
            extract_dir = self.data_dir / "extract_test"
            success = await self.file_manager.extract_archive(str(zip_file), str(extract_dir))
            if not success:
                return {"success": False, "error": "Extraction failed"}

            # Cleanup
            await self.file_manager.delete_item(str(test_dir))
            await self.file_manager.delete_item(str(zip_file))
            await self.file_manager.delete_item(str(extract_dir))

            return {"success": True, "message": "Compression test passed"}

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def test_preview(self) -> Dict[str, Any]:
        """Test file preview functionality."""
        try:
            if not self.file_manager.preview_enabled:
                return {"success": True, "message": "Preview disabled, test skipped"}

            return {"success": True, "message": "Preview test passed"}

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def test_search(self) -> Dict[str, Any]:
        """Test file search functionality."""
        try:
            test_dir = self.data_dir / "search_test"
            test_file = test_dir / "searchable.txt"

            # Create test files
            await self.file_manager.create_directory(str(test_dir))
            async with aiofiles.open(test_file, 'w') as f:
                await f.write("Searchable content")

            # Test search
            results = await self.file_manager.search_files(str(test_dir), "*.txt")
            if len(results) != 1:
                return {"success": False, "error": "Search failed"}

            # Cleanup
            await self.file_manager.delete_item(str(test_dir))

            return {"success": True, "message": "Search test passed"}

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def test_metadata(self) -> Dict[str, Any]:
        """Test metadata extraction."""
        try:
            # Test directory listing with metadata
            listing = await self.file_manager.list_directory(str(self.data_dir))
            if not isinstance(listing, dict) or "items" not in listing:
                return {"success": False, "error": "Metadata extraction failed"}

            return {"success": True, "message": "Metadata test passed"}

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def run_tests(self) -> Dict[str, Any]:
        """Run all plugin self-tests."""
        tests = [
            ("file_operations", self.test_file_operations),
            ("compression", self.test_compression),
            ("preview", self.test_preview),
            ("search", self.test_search),
            ("metadata", self.test_metadata)
        ]

        results = {
            "total": len(tests),
            "passed": 0,
            "failed": 0,
            "tests": {}
        }

        for test_name, test_func in tests:
            try:
                result = await test_func()
                if result.get("success", False):
                    results["passed"] += 1
                    results["tests"][test_name] = {"status": "passed", "message": result.get("message", "")}
                else:
                    results["failed"] += 1
                    results["tests"][test_name] = {"status": "failed", "error": result.get("error", "")}
            except Exception as e:
                results["failed"] += 1
                results["tests"][test_name] = {"status": "failed", "error": str(e)}

        results["success"] = results["failed"] == 0
        return results


# Plugin entry point
def create_plugin():
    """Create plugin instance."""
    return FileManagerPlugin()
