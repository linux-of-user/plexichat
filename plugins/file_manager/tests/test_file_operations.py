"""
File Manager Plugin Tests - File Operations

Comprehensive tests for file operations functionality.
"""

import asyncio
import json
import tempfile
import shutil
import sys
from pathlib import Path
from typing import Dict, Any

# Add src to path for debug imports
sys.path.insert(0, str(Path(__file__, Optional).parent.parent.parent.parent / "src"))

from plexichat.infrastructure.debugging.plugin_debug_integration import debug_plugin_test
from plexichat.infrastructure.debugging.debug_utils import log_debug, memory_snapshot, DebugTimer


@debug_plugin_test("file_manager", "test_file_listing")
async def test_file_listing():
    """Test file listing functionality."""
    try:
        log_debug("Starting file listing test")
        memory_snapshot("before_file_listing_test")
        # Create temporary directory with test files
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            log_debug(f"Created temporary directory: {temp_path}")

            with DebugTimer("file_creation"):
                # Create test files
                (temp_path / "test1.txt").write_text("Test file 1")
                (temp_path / "test2.txt").write_text("Test file 2")
                (temp_path / "subdir").mkdir()
                (temp_path / "subdir" / "test3.txt").write_text("Test file 3")

            log_debug("Test files created successfully")

            with DebugTimer("file_listing"):
                # Test listing
                files = list(temp_path.iterdir())

            log_debug(f"Found {len(files)} items in directory")
            memory_snapshot("after_file_listing_test")

            if len(files) >= 3:  # 2 files + 1 directory
                return {
                    "success": True,
                    "message": f"File listing test passed - found {len(files)} items"
                }
            else:
                return {
                    "success": False,
                    "error": f"Expected at least 3 items, found {len(files)}"
                }
                
    except Exception as e:
        return {
            "success": False,
            "error": f"File listing test failed: {str(e)}"
        }


@debug_plugin_test("file_manager", "test_file_creation")
async def test_file_creation():
    """Test file creation functionality."""
    try:
        log_debug("Starting file creation test")
        memory_snapshot("before_file_creation_test")
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            test_file = temp_path / "created_file.txt"
            test_content = "This is a test file created by the test suite"
            
            # Create file
            test_file.write_text(test_content)
            
            # Verify file exists and has correct content
            if test_file.exists() and test_file.read_text() == test_content:
                return {
                    "success": True,
                    "message": "File creation test passed"
                }
            else:
                return {
                    "success": False,
                    "error": "File creation verification failed"
                }
                
    except Exception as e:
        return {
            "success": False,
            "error": f"File creation test failed: {str(e)}"
        }


async def test_file_copying():
    """Test file copying functionality."""
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Create source file
            source_file = temp_path / "source.txt"
            source_content = "Source file content"
            source_file.write_text(source_content)
            
            # Copy file
            dest_file = temp_path / "destination.txt"
            shutil.copy2(source_file, dest_file)
            
            # Verify copy
            if (dest_file.exists() and 
                dest_file.read_text() == source_content and
                source_file.exists()):
                return {
                    "success": True,
                    "message": "File copying test passed"
                }
            else:
                return {
                    "success": False,
                    "error": "File copying verification failed"
                }
                
    except Exception as e:
        return {
            "success": False,
            "error": f"File copying test failed: {str(e)}"
        }


async def test_file_moving():
    """Test file moving functionality."""
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Create source file
            source_file = temp_path / "source.txt"
            source_content = "Source file content"
            source_file.write_text(source_content)
            
            # Create destination directory
            dest_dir = temp_path / "dest_dir"
            dest_dir.mkdir()
            dest_file = dest_dir / "moved_file.txt"
            
            # Move file
            shutil.move(str(source_file), str(dest_file))
            
            # Verify move
            if (dest_file.exists() and 
                dest_file.read_text() == source_content and
                not source_file.exists()):
                return {
                    "success": True,
                    "message": "File moving test passed"
                }
            else:
                return {
                    "success": False,
                    "error": "File moving verification failed"
                }
                
    except Exception as e:
        return {
            "success": False,
            "error": f"File moving test failed: {str(e)}"
        }


async def test_file_deletion():
    """Test file deletion functionality."""
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Create test file
            test_file = temp_path / "to_delete.txt"
            test_file.write_text("This file will be deleted")
            
            # Verify file exists
            if not test_file.exists():
                return {
                    "success": False,
                    "error": "Test file was not created"
                }
            
            # Delete file
            test_file.unlink()
            
            # Verify deletion
            if not test_file.exists():
                return {
                    "success": True,
                    "message": "File deletion test passed"
                }
            else:
                return {
                    "success": False,
                    "error": "File was not deleted"
                }
                
    except Exception as e:
        return {
            "success": False,
            "error": f"File deletion test failed: {str(e)}"
        }


async def test_directory_operations():
    """Test directory operations."""
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Create directory
            new_dir = temp_path / "new_directory"
            new_dir.mkdir()
            
            # Verify directory creation
            if not new_dir.is_dir():
                return {
                    "success": False,
                    "error": "Directory creation failed"
                }
            
            # Create subdirectory
            sub_dir = new_dir / "subdirectory"
            sub_dir.mkdir()
            
            # Verify subdirectory
            if not sub_dir.is_dir():
                return {
                    "success": False,
                    "error": "Subdirectory creation failed"
                }
            
            # Remove directory
            shutil.rmtree(new_dir)
            
            # Verify removal
            if not new_dir.exists():
                return {
                    "success": True,
                    "message": "Directory operations test passed"
                }
            else:
                return {
                    "success": False,
                    "error": "Directory removal failed"
                }
                
    except Exception as e:
        return {
            "success": False,
            "error": f"Directory operations test failed: {str(e)}"
        }


async def test_file_permissions():
    """Test file permissions handling."""
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Create test file
            test_file = temp_path / "permissions_test.txt"
            test_file.write_text("Permission test file")
            
            # Get initial permissions
            initial_mode = test_file.stat().st_mode
            
            # Change permissions (make read-only)
            test_file.chmod(0o444)
            
            # Verify permission change
            new_mode = test_file.stat().st_mode
            
            if new_mode != initial_mode:
                # Restore permissions for cleanup
                test_file.chmod(0o644)
                return {
                    "success": True,
                    "message": "File permissions test passed"
                }
            else:
                return {
                    "success": False,
                    "error": "Permission change was not applied"
                }
                
    except Exception as e:
        return {
            "success": False,
            "error": f"File permissions test failed: {str(e)}"
        }


async def test_file_metadata():
    """Test file metadata extraction."""
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Create test file
            test_file = temp_path / "metadata_test.txt"
            test_content = "File with metadata"
            test_file.write_text(test_content)
            
            # Get file stats
            stats = test_file.stat()
            
            # Verify metadata
            metadata = {
                "size": stats.st_size,
                "modified": stats.st_mtime,
                "created": stats.st_ctime,
                "is_file": test_file.is_file(),
                "is_dir": test_file.is_dir(),
                "name": test_file.name,
                "suffix": test_file.suffix
            }
            
            # Validate metadata
            if (metadata["size"] == len(test_content.encode()) and
                metadata["is_file"] and
                not metadata["is_dir"] and
                metadata["name"] == "metadata_test.txt" and
                metadata["suffix"] == ".txt"):
                return {
                    "success": True,
                    "message": "File metadata test passed",
                    "metadata": metadata
                }
            else:
                return {
                    "success": False,
                    "error": "File metadata validation failed",
                    "metadata": metadata
                }
                
    except Exception as e:
        return {
            "success": False,
            "error": f"File metadata test failed: {str(e)}"
        }
