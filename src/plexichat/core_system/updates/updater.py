import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

import requests

    from packaging import version
            from app.logger_config import settings
                from ...core.versioning.version_manager import version_manager
                    from pathlib import Path
import shutil
from pathlib import Path

                    from pathlib import Path

"""
PlexiChat Self-Update System
Handles automatic updates from GitHub repository.
"""

try:
except ImportError:
    # Fallback version comparison
    class version:
        @staticmethod
        def parse(v):
            return tuple(map(int, v.split('.')))

        class Version:
            def __init__(self, v):
                self.version = tuple(map(int, v.split('.')))

            def __gt__(self, other):
                return self.version > other.version

class PlexiChatUpdater:
    """Handles self-updating functionality."""
    
    def __init__(self, repo_owner: str = None, repo_name: str = None):
        self.current_version = self.get_current_version()
        self.repo_owner = repo_owner or os.getenv("PLEXICHAT_REPO_OWNER", "linux-of-user")
        self.repo_name = repo_name or os.getenv("PLEXICHAT_REPO_NAME", "plexichat")
        self.github_api_url = f"https://api.github.com/repos/{self.repo_owner}/{self.repo_name}"
        self.github_releases_url = f"{self.github_api_url}/releases"
        self.project_root = from pathlib import Path
Path(__file__).parent.parent.parent
        self.backup_dir = self.project_root / "backups"
        self.update_log_file = self.project_root / "logs" / "updates.log"
        self.ensure_directories()
    
    def get_current_version(self) -> str:
        """Get current version from from plexichat.core.config import settings
settings."""
        try:
            return getattr(settings, 'APP_VERSION', '1.0.0-alpha.1')
        except ImportError:
            try:
                return str(version_manager.get_current_version())
            except ImportError:
                return '1.0.0-alpha.1'
    
    def ensure_directories(self):
        """Ensure necessary directories exist."""
        self.backup_dir.mkdir(exist_ok=True)
        self.update_log_file.parent.mkdir(exist_ok=True)
    
    def log_update(self, message: str, level: str = "INFO"):
        """Log update activity."""
        timestamp = from datetime import datetime
datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}\n"
        
        try:
            with open(self.update_log_file, 'a', encoding='utf-8') as f:
                f.write(log_entry)
        except Exception:
            pass  # Don't fail if logging fails
        
        print(f"[UPDATE] {log_entry.strip()}")
    
    def check_for_updates(self) -> Dict[str, Any]:
        """Check for available updates."""
        try:
            self.log_update("Checking for updates...")
            
            # Get latest release info
            response = requests.get(f"{self.github_releases_url}/latest", timeout=10)
            response.raise_for_status()
            
            release_data = response.json()
            latest_version = release_data["tag_name"].lstrip('v')
            
            # Compare versions
            current_ver = version.parse(self.current_version)
            latest_ver = version.parse(latest_version)
            
            update_available = latest_ver > current_ver
            
            result = {
                "update_available": update_available,
                "current_version": self.current_version,
                "latest_version": latest_version,
                "release_notes": release_data.get("body", ""),
                "release_date": release_data.get("published_at", ""),
                "download_url": None,
                "size": 0
            }
            
            # Get download URL for source code
            if update_available:
                result["download_url"] = release_data["zipball_url"]
                
                # Try to get size from assets if available
                for asset in release_data.get("assets", []):
                    if asset["name"].endswith(".zip"):
                        result["download_url"] = asset["browser_download_url"]
                        result["size"] = asset["size"]
                        break
            
            self.log_update(f"Update check complete. Current: {self.current_version}, Latest: {latest_version}, Available: {update_available}")
            return result
            
        except requests.RequestException as e:
            self.log_update(f"Network error checking for updates: {e}", "ERROR")
            return {
                "error": f"Network error: {e}",
                "update_available": False,
                "current_version": self.current_version
            }
        except Exception as e:
            self.log_update(f"Error checking for updates: {e}", "ERROR")
            return {
                "error": f"Update check failed: {e}",
                "update_available": False,
                "current_version": self.current_version
            }
    
    def create_backup(self) -> str:
        """Create backup of current installation."""
        try:
            timestamp = from datetime import datetime
datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_name = f"plexichat_backup_{self.current_version}_{timestamp}"
            backup_path = self.backup_dir / f"{backup_name}.zip"
            
            self.log_update(f"Creating backup: {backup_path}")
            
            # Files and directories to backup
            backup_items = [
                "app",
                "cli.py",
                "run.py",
                "plexichat_gui.py",
                "requirements.txt",
                "data",
                ".env"
            ]
            
            with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as backup_zip:
                for item in backup_items:
                    item_path = self.project_root / item
                    if item_path.exists():
                        if item_path.is_file():
                            backup_zip.write(item_path, item)
                        elif item_path.is_dir():
                            for file_path in item_path.rglob('*'):
                                if file_path.is_file():
                                    arcname = file_path.relative_to(self.project_root)
                                    backup_zip.write(file_path, arcname)
            
            self.log_update(f"Backup created successfully: {backup_path}")
            return str(backup_path)
            
        except Exception as e:
            self.log_update(f"Failed to create backup: {e}", "ERROR")
            raise
    
    def download_update(self, download_url: str) -> str:
        """Download update package."""
        try:
            self.log_update(f"Downloading update from: {download_url}")
            
            # Create temporary file
            temp_dir = tempfile.mkdtemp()
            temp_file = from pathlib import Path
Path(temp_dir) / "plexichat_update.zip"
            
            # Download with progress
            response = requests.get(download_url, stream=True, timeout=30)
            response.raise_for_status()
            
            total_size = int(response.headers.get('content-length', 0))
            downloaded = 0
            
            with open(temp_file, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        
                        if total_size > 0:
                            progress = (downloaded / total_size) * 100
                            if downloaded % (1024 * 1024) == 0:  # Log every MB
                                self.log_update(f"Download progress: {progress:.1f}%")
            
            self.log_update(f"Download completed: {temp_file}")
            return str(temp_file)
            
        except Exception as e:
            self.log_update(f"Failed to download update: {e}", "ERROR")
            raise
    
    def apply_hot_update(self, update_file: str) -> bool:
        """Apply hot update without stopping the server."""
        try:
            self.log_update("Applying hot update...")

            # Extract update to temporary directory
            temp_dir = tempfile.mkdtemp()
            extract_dir = from pathlib import Path
Path(temp_dir) / "plexichat_update"

            with zipfile.ZipFile(update_file, 'r') as update_zip:
                update_zip.extractall(extract_dir)

            # Find the actual source directory (GitHub zips have a folder inside)
            source_dirs = [d for d in extract_dir.iterdir() if d.is_dir()]
            if source_dirs:
                source_dir = source_dirs[0]
            else:
                source_dir = extract_dir

            # Hot-updatable items (can be updated while running)
            hot_update_items = [
                "app/web/templates",
                "app/web/static",
                "app/routers",
                "app/core",
                "app/utils",
                "app/models"
            ]

            # Cold-update items (require restart)
            cold_update_items = [
                "app/main.py",
                "app/logger_config.py",
                "cli.py",
                "run.py",
                "plexichat_gui.py",
                "requirements.txt"
            ]

            # Apply hot updates first
            hot_updated = []
            for item in hot_update_items:
                source_path = source_dir / item
                target_path = self.project_root / item

                if source_path.exists():
                    if target_path.exists():
                        # Create backup
                        backup_path = target_path.with_suffix(f"{target_path.suffix}.backup")
                        if target_path.is_dir():
                            if backup_path.exists():
                                shutil.rmtree(backup_path)
                            shutil.copytree(target_path, backup_path)
                            shutil.rmtree(target_path)
                        else:
                            shutil.copy2(target_path, backup_path)
                            target_path.unlink()

                    if source_path.is_dir():
                        shutil.copytree(source_path, target_path)
                    else:
                        shutil.copy2(source_path, target_path)

                    hot_updated.append(item)
                    self.log_update(f"Hot updated: {item}")

            # Stage cold updates for next restart
            cold_staged = []
            staging_dir = self.project_root / ".update_staging"
            staging_dir.mkdir(exist_ok=True)

            for item in cold_update_items:
                source_path = source_dir / item
                if source_path.exists():
                    staging_path = staging_dir / item
                    staging_path.parent.mkdir(parents=True, exist_ok=True)

                    if source_path.is_dir():
                        if staging_path.exists():
                            shutil.rmtree(staging_path)
                        shutil.copytree(source_path, staging_path)
                    else:
                        shutil.copy2(source_path, staging_path)

                    cold_staged.append(item)
                    self.log_update(f"Staged for restart: {item}")

            # Create update completion script
            self.create_restart_update_script(cold_staged)

            self.log_update(f"Hot update completed. {len(hot_updated)} items updated, {len(cold_staged)} staged for restart")
            return True

        except Exception as e:
            self.log_update(f"Failed to apply hot update: {e}", "ERROR")
            return False
        finally:
            # Cleanup
            try:
                if 'temp_dir' in locals():
                    shutil.rmtree(temp_dir)
                if 'update_file' in locals():
Path(update_file).unlink(missing_ok=True)
            except Exception:
                pass

    def create_restart_update_script(self, staged_items: List[str]):
        """Create script to complete update on restart."""
        script_content = f"""#!/usr/bin/env python3
# PlexiChat Update Completion Script
def complete_update():
    project_root = from pathlib import Path
Path(__file__).parent
    staging_dir = project_root / ".update_staging"

    if not staging_dir.exists():
        return

    print("Completing staged updates...")

    staged_items = {staged_items}

    for item in staged_items:
        source_path = staging_dir / item
        target_path = project_root / item

        if source_path.exists():
            if target_path.exists():
                if target_path.is_dir():
                    shutil.rmtree(target_path)
                else:
                    target_path.unlink()

            if source_path.is_dir():
                shutil.copytree(source_path, target_path)
            else:
                shutil.copy2(source_path, target_path)

            print(f"Updated: {{item}}")

    # Cleanup staging directory
    shutil.rmtree(staging_dir)
    print("Update completion finished")

if __name__ == "__main__":
    complete_update()
"""

        script_path = self.project_root / "complete_update.py"
        with open(script_path, 'w') as f:
            f.write(script_content)
    
    def update_dependencies(self):
        """Update Python dependencies."""
        try:
            self.log_update("Updating dependencies...")
            
            requirements_file = self.project_root / "requirements.txt"
            if requirements_file.exists():
                result = subprocess.run([
                    sys.executable, "-m", "pip", "install", "-r", str(requirements_file), "--upgrade"
                ], capture_output=True, text=True, timeout=300)
                
                if result.returncode == 0:
                    self.log_update("Dependencies updated successfully")
                else:
                    self.log_update(f"Dependency update warning: {result.stderr}", "WARNING")
            
        except Exception as e:
            self.log_update(f"Failed to update dependencies: {e}", "WARNING")
    
    def restore_backup(self, backup_path: str) -> bool:
        """Restore from backup."""
        try:
            self.log_update(f"Restoring from backup: {backup_path}")
            
            backup_file = from pathlib import Path
Path(backup_path)
            if not backup_file.exists():
                raise FileNotFoundError(f"Backup file not found: {backup_path}")
            
            # Extract backup
            temp_dir = tempfile.mkdtemp()
            extract_dir = from pathlib import Path
Path(temp_dir) / "restore"
            
            with zipfile.ZipFile(backup_file, 'r') as backup_zip:
                backup_zip.extractall(extract_dir)
            
            # Restore files
            for item in extract_dir.rglob('*'):
                if item.is_file():
                    relative_path = item.relative_to(extract_dir)
                    target_path = self.project_root / relative_path
                    
                    target_path.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(item, target_path)
            
            self.log_update("Backup restored successfully")
            return True
            
        except Exception as e:
            self.log_update(f"Failed to restore backup: {e}", "ERROR")
            return False
        finally:
            try:
                if 'temp_dir' in locals():
                    shutil.rmtree(temp_dir)
            except Exception:
                pass
    
    def perform_hot_update_process(self, force: bool = False) -> Dict[str, Any]:
        """Perform hot update process without downtime."""
        try:
            # Check for updates
            update_info = self.check_for_updates()

            if "error" in update_info:
                return update_info

            if not update_info["update_available"] and not force:
                return {
                    "success": True,
                    "message": "No updates available",
                    "current_version": self.current_version,
                    "update_type": "none"
                }

            # Create backup
            backup_path = self.create_backup()

            try:
                # Download update
                download_url = update_info["download_url"]
                update_file = self.download_update(download_url)

                # Apply hot update
                if self.apply_hot_update(update_file):
                    return {
                        "success": True,
                        "message": "Hot update completed successfully",
                        "previous_version": self.current_version,
                        "new_version": update_info["latest_version"],
                        "backup_path": backup_path,
                        "update_type": "hot",
                        "restart_required": self.has_pending_restart_updates()
                    }
                else:
                    # Restore backup on failure
                    self.restore_backup(backup_path)
                    return {
                        "success": False,
                        "message": "Hot update failed, restored from backup",
                        "backup_restored": True,
                        "update_type": "failed"
                    }

            except Exception as e:
                # Restore backup on any error
                self.log_update(f"Hot update failed, restoring backup: {e}", "ERROR")
                self.restore_backup(backup_path)
                return {
                    "success": False,
                    "message": f"Hot update failed: {e}",
                    "backup_restored": True,
                    "update_type": "failed"
                }

        except Exception as e:
            self.log_update(f"Hot update process failed: {e}", "ERROR")
            return {
                "success": False,
                "message": f"Hot update process failed: {e}",
                "update_type": "failed"
            }

    def has_pending_restart_updates(self) -> bool:
        """Check if there are updates pending restart."""
        staging_dir = self.project_root / ".update_staging"
        return staging_dir.exists() and any(staging_dir.iterdir())

    def apply_pending_restart_updates(self) -> bool:
        """Apply updates that were staged for restart."""
        staging_dir = self.project_root / ".update_staging"

        if not staging_dir.exists():
            return True  # No pending updates

        try:
            self.log_update("Applying pending restart updates...")

            # Apply all staged files
            for item in staging_dir.rglob('*'):
                if item.is_file():
                    relative_path = item.relative_to(staging_dir)
                    target_path = self.project_root / relative_path

                    # Create target directory if needed
                    target_path.parent.mkdir(parents=True, exist_ok=True)

                    # Copy file
                    shutil.copy2(item, target_path)
                    self.log_update(f"Applied restart update: {relative_path}")

            # Remove staging directory
            shutil.rmtree(staging_dir)
            self.log_update("Pending restart updates applied successfully")

            return True

        except Exception as e:
            self.log_update(f"Failed to apply pending restart updates: {e}", "ERROR")
            return False

    def get_update_status(self) -> Dict[str, Any]:
        """Get comprehensive update status."""
        try:
            # Check for available updates
            update_info = self.check_for_updates()

            # Check for pending restart updates
            has_pending = self.has_pending_restart_updates()

            # Get recent update logs
            recent_logs = self.get_recent_update_logs(10)

            return {
                "current_version": self.current_version,
                "update_available": update_info.get("update_available", False),
                "latest_version": update_info.get("latest_version"),
                "has_pending_restart": has_pending,
                "last_check": from datetime import datetime
datetime.utcnow().isoformat(),
                "recent_logs": recent_logs,
                "update_system_healthy": True
            }

        except Exception as e:
            return {
                "current_version": self.current_version,
                "update_available": False,
                "has_pending_restart": False,
                "last_check": from datetime import datetime
datetime.utcnow().isoformat(),
                "error": str(e),
                "update_system_healthy": False
            }

    def get_recent_update_logs(self, count: int = 10) -> List[str]:
        """Get recent update log entries."""
        try:
            if not self.update_log_file.exists():
                return []

            with open(self.update_log_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()

            # Return last N lines
            return [line.strip() for line in lines[-count:]]

        except Exception:
            return []
    
    def list_backups(self) -> List[Dict[str, Any]]:
        """List available backups."""
        backups = []
        
        try:
            for backup_file in self.backup_dir.glob("plexichat_backup_*.zip"):
                stat = backup_file.stat()
                backups.append({
                    "name": backup_file.name,
                    "path": str(backup_file),
                    "size": stat.st_size,
                    "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                    "modified": datetime.fromtimestamp(stat.st_mtime).isoformat()
                })
        except Exception as e:
            self.log_update(f"Error listing backups: {e}", "ERROR")
        
        return sorted(backups, key=lambda x: x["created"], reverse=True)
    
    def cleanup_old_backups(self, keep_count: int = 5) -> int:
        """Clean up old backups, keeping only the most recent ones."""
        try:
            backups = self.list_backups()
            
            if len(backups) <= keep_count:
                return 0
            
            removed_count = 0
            for backup in backups[keep_count:]:
                try:
Path(backup["path"]).unlink()
                    removed_count += 1
                    self.log_update(f"Removed old backup: {backup['name']}")
                except Exception as e:
                    self.log_update(f"Failed to remove backup {backup['name']}: {e}", "WARNING")
            
            return removed_count
            
        except Exception as e:
            self.log_update(f"Error cleaning up backups: {e}", "ERROR")
            return 0

# Global updater instance
updater = PlexiChatUpdater()
