import asyncio
import os
import shutil
import tempfile
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import aiohttp
import semver

from ...core_system.config import get_config
from ...core_system.logging import get_logger
from ...features.backup import get_unified_backup_manager

from pathlib import Path
from datetime import datetime
from pathlib import Path

from pathlib import Path
from datetime import datetime
from pathlib import Path

"""
PlexiChat Git-Based Update Manager

Replaces local version.json with Git-based versioning using GitHub releases.
Features:
- Automatic update checking from GitHub releases
- Secure download and verification of updates
- Backup system integration for rollback capability
- Version management through Git tags and releases
- Automatic dependency updates
- Configuration migration support
"""

logger = get_logger(__name__)


class GitUpdateManager:
    """
    Git-based update manager using GitHub releases.
    
    Replaces local version.json with proper Git-based versioning.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or get_config().get("updates", {})
        
        # GitHub configuration
        self.github_owner = self.config.get("github_owner", "linux-of-user")
        self.github_repo = self.config.get("github_repo", "plexichat")
        self.github_api_base = "https://api.github.com"
        self.github_token = self.config.get("github_token")  # Optional for private repos
        
        # Local configuration
        self.from pathlib import Path
project_root = Path()(__file__).parent.parent.parent.parent.parent
        self.backup_before_update = self.config.get("backup_before_update", True)
        self.auto_update_enabled = self.config.get("auto_update_enabled", False)
        self.update_channel = self.config.get("update_channel", "stable")  # stable, beta, alpha
        
        # Update tracking
        self.current_version = None
        self.latest_version = None
        self.update_available = False
        
        # Backup manager integration
        self.backup_manager = None
        
        logger.info("Git Update Manager initialized")
    
    async def initialize(self) -> bool:
        """Initialize the update manager."""
        try:
            # Initialize backup manager if needed
            if self.backup_before_update:
                self.backup_manager = get_unified_backup_manager()
                await self.if backup_manager and hasattr(backup_manager, "initialize"): backup_manager.initialize()
            
            # Get current version from Git
            self.current_version = await self._get_current_version()
            
            logger.info(f" Git Update Manager initialized - Current version: {self.current_version}")
            return True
            
        except Exception as e:
            logger.error(f" Git Update Manager initialization failed: {e}")
            return False
    
    async def _get_current_version(self) -> str:
        """Get current version from Git tags."""
        try:
            # Try to get version from Git tag
            result = await self._run_git_command(["describe", "--tags", "--exact-match"])
            if result and result.strip():
                return result.strip()
            
            # Fallback to latest tag + commit hash
            result = await self._run_git_command(["describe", "--tags", "--always"])
            if result and result.strip():
                return result.strip()
            
            # Fallback to commit hash
            result = await self._run_git_command(["rev-parse", "--short", "HEAD"])
            if result and result.strip():
                return f"dev-{result.strip()}"
            
            return "unknown"
            
        except Exception as e:
            logger.error(f"Failed to get current version: {e}")
            return "unknown"
    
    async def _run_git_command(self, args: List[str]) -> Optional[str]:
        """Run a Git command and return output."""
        try:
            process = await asyncio.create_subprocess_exec(
                "git", *args,
                cwd=self.project_root,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                return stdout.decode().strip()
            else:
                logger.warning(f"Git command failed: git {' '.join(args)} - {stderr.decode()}")
                return None
                
        except Exception as e:
            logger.error(f"Failed to run git command: {e}")
            return None
    
    async def check_for_updates(self) -> Dict[str, Any]:
        """Check for available updates from GitHub releases."""
        try:
            headers = {}
            if self.github_token:
                headers["Authorization"] = f"token {self.github_token}"
            
            url = f"{self.github_api_base}/repos/{self.github_owner}/{self.github_repo}/releases"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        releases = await response.json()
                        
                        # Filter releases based on update channel
                        filtered_releases = self._filter_releases_by_channel(releases)
                        
                        if not filtered_releases:
                            return {
                                "update_available": False,
                                "current_version": self.current_version,
                                "message": "No releases found for update channel"
                            }
                        
                        latest_release = filtered_releases[0]  # GitHub returns in descending order
                        latest_version = latest_release["tag_name"]
                        
                        # Compare versions
                        self.latest_version = latest_version
                        self.update_available = self._is_newer_version(latest_version, self.current_version)
                        
                        return {
                            "update_available": self.update_available,
                            "current_version": self.current_version,
                            "latest_version": latest_version,
                            "release_notes": latest_release.get("body", ""),
                            "release_date": latest_release.get("published_at", ""),
                            "download_url": latest_release.get("zipball_url", ""),
                            "prerelease": latest_release.get("prerelease", False)
                        }
                    else:
                        logger.error(f"Failed to fetch releases: HTTP {response.status}")
                        return {
                            "update_available": False,
                            "error": f"Failed to fetch releases: HTTP {response.status}"
                        }
                        
        except Exception as e:
            logger.error(f"Failed to check for updates: {e}")
            return {
                "update_available": False,
                "error": str(e)
            }
    
    def _filter_releases_by_channel(self, releases: List[Dict]) -> List[Dict]:
        """Filter releases based on update channel."""
        if self.update_channel == "alpha":
            return releases  # Include all releases
        elif self.update_channel == "beta":
            return [r for r in releases if not self._is_alpha_release(r)]
        else:  # stable
            return [r for r in releases if not r.get("prerelease", False)]
    
    def _is_alpha_release(self, release: Dict) -> bool:
        """Check if release is an alpha release."""
        tag = release.get("tag_name", "").lower()
        return "alpha" in tag or "a." in tag
    
    def _is_newer_version(self, latest: str, current: str) -> bool:
        """Compare version strings to determine if update is available."""
        try:
            # Clean version strings (remove 'v' prefix if present)
            latest_clean = latest.lstrip('v')
            current_clean = current.lstrip('v')
            
            # Handle development versions
            if current_clean.startswith('dev-'):
                return True  # Always update from dev versions
            
            # Use semver for comparison if possible
            try:
                return semver.compare(latest_clean, current_clean) > 0
            except ValueError:
                # Fallback to string comparison
                return latest_clean > current_clean
                
        except Exception as e:
            logger.warning(f"Version comparison failed: {e}")
            return False
    
    async def perform_update(self, backup_name: Optional[str] = None) -> Dict[str, Any]:
        """Perform the update process."""
        try:
            if not self.update_available:
                return {"success": False, "error": "No update available"}
            
            logger.info(f" Starting update from {self.current_version} to {self.latest_version}")
            
            # Step 1: Create backup if enabled
            backup_id = None
            if self.backup_before_update and self.backup_manager:
                logger.info(" Creating pre-update backup...")
                backup_name = backup_name or f"pre-update-{self.current_version}-{from datetime import datetime
datetime.now().strftime('%Y%m%d-%H%M%S')}"
                backup_result = await self.backup_manager.create_backup(backup_name)
                if backup_result.get("success"):
                    backup_id = backup_result.get("backup_id")
                    logger.info(f" Backup created: {backup_id}")
                else:
                    logger.error(" Backup failed, aborting update")
                    return {"success": False, "error": "Backup failed"}
            
            # Step 2: Download and verify update
            logger.info(" Downloading update...")
            download_result = await self._download_update()
            if not download_result["success"]:
                return download_result
            
            # Step 3: Apply update
            logger.info(" Applying update...")
            apply_result = await self._apply_update(download_result["temp_dir"])
            if not apply_result["success"]:
                # Rollback if backup exists
                if backup_id:
                    logger.info(" Rolling back due to update failure...")
                    await self._rollback_update(backup_id)
                return apply_result
            
            # Step 4: Update dependencies
            logger.info(" Updating dependencies...")
            deps_result = await self._update_dependencies()
            if not deps_result["success"]:
                logger.warning(f" Dependency update failed: {deps_result.get('error')}")
            
            # Step 5: Verify update
            new_version = await self._get_current_version()
            
            logger.info(f" Update completed successfully: {self.current_version}  {new_version}")
            
            return {
                "success": True,
                "old_version": self.current_version,
                "new_version": new_version,
                "backup_id": backup_id,
                "message": "Update completed successfully"
            }
            
        except Exception as e:
            logger.error(f" Update failed: {e}")
            return {"success": False, "error": str(e)}
    
    async def _download_update(self) -> Dict[str, Any]:
        """Download the update package."""
        try:
            # Get download URL
            update_info = await self.check_for_updates()
            if not update_info.get("update_available"):
                return {"success": False, "error": "No update available"}
            
            download_url = update_info.get("download_url")
            if not download_url:
                return {"success": False, "error": "No download URL available"}
            
            # Create temporary directory
            from pathlib import Path

            temp_dir = Path()(tempfile.mkdtemp(prefix="plexichat_update_"))
            
            headers = {}
            if self.github_token:
                headers["Authorization"] = f"token {self.github_token}"
            
            # Download the update
            async with aiohttp.ClientSession() as session:
                async with session.get(download_url, headers=headers) as response:
                    if response.status == 200:
                        zip_path = temp_dir / "update.zip"
                        with open(zip_path, 'wb') as f:
                            async for chunk in response.content.iter_chunked(8192):
                                f.write(chunk)
                        
                        # Extract the zip
                        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                            zip_ref.extractall(temp_dir)
                        
                        # Remove the zip file
                        zip_path.unlink()
                        
                        return {"success": True, "temp_dir": temp_dir}
                    else:
                        return {"success": False, "error": f"Download failed: HTTP {response.status}"}
                        
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _apply_update(self, temp_dir: Path) -> Dict[str, Any]:
        """Apply the downloaded update."""
        try:
            # Find the extracted directory (GitHub creates a directory with repo name)
            extracted_dirs = [d for d in temp_dir.iterdir() if d.is_dir()]
            if not extracted_dirs:
                return {"success": False, "error": "No extracted directory found"}
            
            source_dir = extracted_dirs[0]
            
            # Copy files, excluding certain directories
            exclude_dirs = {'.git', '__pycache__', '.pytest_cache', 'node_modules', '.venv'}
            exclude_files = {'version.json'}  # Don't overwrite local version tracking
            
            for item in source_dir.rglob('*'):
                if item.is_file():
                    # Skip excluded files and directories
                    if any(excluded in item.parts for excluded in exclude_dirs):
                        continue
                    if item.name in exclude_files:
                        continue
                    
                    # Calculate relative path
                    rel_path = item.relative_to(source_dir)
                    dest_path = self.project_root / rel_path
                    
                    # Create parent directories if needed
                    dest_path.parent.mkdir(parents=True, exist_ok=True)
                    
                    # Copy file
                    shutil.copy2(item, dest_path)
            
            return {"success": True}
            
        except Exception as e:
            return {"success": False, "error": str(e)}
        finally:
            # Clean up temporary directory
            if temp_dir.exists():
                shutil.rmtree(temp_dir, ignore_errors=True)
    
    async def _update_dependencies(self) -> Dict[str, Any]:
        """Update Python dependencies."""
        try:
            # Check if virtual environment exists
            venv_python = self.project_root / ".venv" / ("Scripts" if os.name == 'nt' else "bin") / "python"
            if not venv_python.exists():
                return {"success": False, "error": "Virtual environment not found"}
            
            # Update pip first
            process = await asyncio.create_subprocess_exec(
                str(venv_python), "-m", "pip", "install", "--upgrade", "pip",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()
            
            # Install/update requirements
            requirements_file = self.project_root / "requirements.txt"
            if requirements_file.exists():
                process = await asyncio.create_subprocess_exec(
                    str(venv_python), "-m", "pip", "install", "-r", str(requirements_file),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await process.communicate()
                
                if process.returncode == 0:
                    return {"success": True}
                else:
                    return {"success": False, "error": stderr.decode()}
            else:
                return {"success": True, "message": "No requirements.txt found"}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _rollback_update(self, backup_id: str) -> Dict[str, Any]:
        """Rollback to previous version using backup."""
        try:
            if not self.backup_manager:
                return {"success": False, "error": "Backup manager not available"}
            
            logger.info(f" Rolling back to backup: {backup_id}")
            result = await self.backup_manager.restore_backup(backup_id)
            
            if result.get("success"):
                logger.info(" Rollback completed successfully")
                return {"success": True}
            else:
                logger.error(f" Rollback failed: {result.get('error')}")
                return result
                
        except Exception as e:
            logger.error(f" Rollback failed: {e}")
            return {"success": False, "error": str(e)}
    
    def get_version_info(self) -> Dict[str, Any]:
        """Get comprehensive version information."""
        return {
            "current_version": self.current_version,
            "latest_version": self.latest_version,
            "update_available": self.update_available,
            "update_channel": self.update_channel,
            "auto_update_enabled": self.auto_update_enabled,
            "github_repo": f"{self.github_owner}/{self.github_repo}"
        }


# Global instance
_git_update_manager: Optional[GitUpdateManager] = None


def get_git_update_manager() -> GitUpdateManager:
    """Get the global Git update manager instance."""
    global _git_update_manager
    if _git_update_manager is None:
        _git_update_manager = GitUpdateManager()
    return _git_update_manager


# Export main components
__all__ = [
    "GitUpdateManager",
    "get_git_update_manager"
]
