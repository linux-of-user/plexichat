import asyncio
import importlib
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import requests

from datetime import datetime
from pathlib import Path
from pathlib import Path
from datetime import datetime
from datetime import datetime
from datetime import datetime
from datetime import datetime
from datetime import datetime
from datetime import datetime

from datetime import datetime
from pathlib import Path
from pathlib import Path
from datetime import datetime
from datetime import datetime
from datetime import datetime
from datetime import datetime
from datetime import datetime
from datetime import datetime

"""
PlexiChat GitHub-Based Update System
Handles version checking, downloading, and updating from GitHub releases.
"""

logger = logging.getLogger(__name__)


@dataclass
class GitHubRelease:
    """GitHub release information."""
    tag_name: str
    name: str
    body: str
    published_at: datetime
    prerelease: bool
    draft: bool
    assets: List[Dict[str, Any]]
    zipball_url: str
    tarball_url: str

    @property
    def version(self) -> str:
        """Extract version from tag name."""
        # Remove 'v' prefix if present
        version = self.tag_name.lstrip('v')
        return version

    @property
    def is_stable(self) -> bool:
        """Check if this is a stable release."""
        return not self.prerelease and not self.draft


@dataclass
class UpdateInfo:
    """Update information."""
    current_version: str
    latest_version: str
    update_available: bool
    release_notes: str
    download_url: str
    file_size: int
    published_at: datetime
    is_major_update: bool
    is_security_update: bool


class GitHubUpdater:
    """GitHub-based update system for PlexiChat."""

    def __init__(self, repo_owner: str = "linux-of-user", repo_name: str = "plexichat"):
        """Initialize the GitHub updater."""
        self.repo_owner = repo_owner
        self.repo_name = repo_name
        self.api_base = "https://api.github.com"
        self.repo_url = f"https://github.com/{repo_owner}/{repo_name}"

        # Configuration
        self.config = {
            "check_interval_hours": 24,
            "auto_download": False,
            "auto_install": False,
            "backup_before_update": True,
            "verify_signatures": True,
            "allow_prerelease": False,
            "update_channel": "stable",  # stable, beta, alpha
            "seamless_updates": True,
            "health_check_timeout": 30,
            "rollback_on_failure": True,
            "max_rollback_attempts": 3
        }

        # Seamless update state
        self.update_in_progress = False
        self.health_check_callbacks = []
        self.rollback_stack = []

        # Paths
        self.root_path = Path.cwd()
        self.backup_path = self.root_path / "backups"
        self.temp_path = self.root_path / "temp"
        self.version_file = self.root_path / "version.json"

        # Ensure directories exist
        self.backup_path.mkdir(exist_ok=True)
        self.temp_path.mkdir(exist_ok=True)

        logger.info(f"GitHub updater initialized for {self.repo_owner}/{self.repo_name}")

    def get_current_version(self) -> str:
        """Get the current version from version.json."""
        try:
            if self.version_file.exists():
                with open(self.version_file, 'r') as f:
                    data = json.load(f)
                    return data.get("current_version", "a.1.1-1")
            return "a.1.1-1"
        except Exception as e:
            logger.error(f"Failed to get current version: {e}")
            return "a.1.1-1"

    def parse_version(self, version: str) -> Tuple[str, int, int, int]:
        """Parse version string into components (letter, major, minor, build)."""
        # Expected format: a.1.1-1, b.1.2-3, r.1.0-1, etc.
        match = re.match(r'^([abr])\.(\d+)\.(\d+)-(\d+)$', version)
        if match:
            letter = match.group(1)
            major = int(match.group(2))
            minor = int(match.group(3))
            build = int(match.group(4))
            return letter, major, minor, build
        else:
            # Fallback for other formats
            return 'a', 1, 1, 1

    def compare_versions(self, version1: str, version2: str) -> int:
        """Compare two versions. Returns -1, 0, or 1."""
        v1_letter, v1_major, v1_minor, v1_build = self.parse_version(version1)
        v2_letter, v2_major, v2_minor, v2_build = self.parse_version(version2)

        # Compare major version first
        if v1_major != v2_major:
            return -1 if v1_major < v2_major else 1

        # Compare minor version
        if v1_minor != v2_minor:
            return -1 if v1_minor < v2_minor else 1

        # Compare version type (r > b > a)
        type_order = {'a': 0, 'b': 1, 'r': 2}
        v1_type_order = type_order.get(v1_letter, 0)
        v2_type_order = type_order.get(v2_letter, 0)

        if v1_type_order != v2_type_order:
            return -1 if v1_type_order < v2_type_order else 1

        # Compare build number
        if v1_build != v2_build:
            return -1 if v1_build < v2_build else 1

        return 0

    async def get_releases(self, include_prerelease: bool = None) -> List[GitHubRelease]:
        """Get releases from GitHub API."""
        if include_prerelease is None:
            include_prerelease = self.config["allow_prerelease"]

        try:
            url = f"{self.api_base}/repos/{self.repo_owner}/{self.repo_name}/releases"

            # Add GitHub token if available for higher rate limits
            headers = {"Accept": "application/vnd.github.v3+json"}
            github_token = os.getenv("GITHUB_TOKEN")
            if github_token:
                headers["Authorization"] = f"token {github_token}"

            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status()

            releases_data = response.json()
            releases = []

            for release_data in releases_data:
                # Skip drafts
                if release_data.get("draft", False):
                    continue

                # Skip prereleases if not allowed
                if release_data.get("prerelease", False) and not include_prerelease:
                    continue

                release = GitHubRelease(
                    tag_name=release_data["tag_name"],
                    name=release_data["name"],
                    body=release_data["body"],
                    published_at=datetime.fromisoformat(
                        release_data["published_at"].replace('Z', '+00:00')
                    ),
                    prerelease=release_data.get("prerelease", False),
                    draft=release_data.get("draft", False),
                    assets=release_data.get("assets", []),
                    zipball_url=release_data["zipball_url"],
                    tarball_url=release_data["tarball_url"]
                )
                releases.append(release)

            logger.info(f"Retrieved {len(releases)} releases from GitHub")
            return releases

        except Exception as e:
            logger.error(f"Failed to get releases from GitHub: {e}")
            return []

    async def check_for_updates(self) -> Optional[UpdateInfo]:
        """Check if updates are available."""
        current_version = self.get_current_version()
        releases = await self.get_releases()

        if not releases:
            logger.warning("No releases found")
            return None

        # Find the latest applicable release
        latest_release = None
        for release in releases:
            release_letter, _, _, _ = self.parse_version(release.version)

            if self.config["update_channel"] == "stable" and release_letter != 'r':
                continue  # Only stable releases for stable channel
            elif self.config["update_channel"] == "beta" and release_letter == 'a':
                continue  # Skip alpha in beta channel

            if not latest_release or self.compare_versions(release.version, latest_release.version) > 0:
                latest_release = release

        if not latest_release:
            logger.info("No applicable releases found")
            return None

        # Check if update is available
        update_available = self.compare_versions(current_version, latest_release.version) < 0

        if not update_available:
            logger.info(f"Already on latest version: {current_version}")
            return None

        # Determine update type
        current_letter, current_major, current_minor, current_build = self.parse_version(current_version)
        latest_letter, latest_major, latest_minor, latest_build = self.parse_version(latest_release.version)

        is_major_update = latest_major > current_major or latest_minor > current_minor
        is_security_update = "security" in latest_release.body.lower() or "cve" in latest_release.body.lower()

        # Get download URL (prefer zipball for source code)
        download_url = latest_release.zipball_url
        file_size = 0  # GitHub doesn't provide size for zipballs

        # Check if there's a packaged release asset
        for asset in latest_release.assets:
            if asset["name"].endswith((".zip", ".tar.gz")) and "plexichat" in asset["name"].lower():
                download_url = asset["browser_download_url"]
                file_size = asset["size"]
                break

        update_info = UpdateInfo(
            current_version=current_version,
            latest_version=latest_release.version,
            update_available=True,
            release_notes=latest_release.body,
            download_url=download_url,
            file_size=file_size,
            published_at=latest_release.published_at,
            is_major_update=is_major_update,
            is_security_update=is_security_update
        )

        logger.info(f"Update available: {current_version} -> {latest_release.version}")
        return update_info

    async def download_update(self, update_info: UpdateInfo) -> Optional[Path]:
        """Download the update package."""
        try:
            logger.info(f"Downloading update from {update_info.download_url}")

            # Create temporary file
            temp_file = self.temp_path / f"plexichat_update_{update_info.latest_version}.zip"

            # Download with progress tracking
            response = requests.get(update_info.download_url, stream=True, timeout=300)
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
                                logger.info(f"Download progress: {progress:.1f}%")

            logger.info(f"Download completed: {temp_file}")
            return temp_file

        except Exception as e:
            logger.error(f"Failed to download update: {e}")
            return None

    def create_backup(self) -> Optional[Path]:
        """Create a backup of the current installation."""
        try:
            current_version = self.get_current_version()
            from datetime import datetime
timestamp = datetime.now()
datetime = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_name = f"plexichat_backup_{current_version}_{timestamp}.zip"
            backup_file = self.backup_path / backup_name

            logger.info(f"Creating backup: {backup_file}")

            # Files and directories to backup
            backup_items = [
                "src",
                "config",
                "version.json",
                "requirements.txt",
                "run.py"
            ]

            with zipfile.ZipFile(backup_file, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for item in backup_items:
                    item_path = self.root_path / item
                    if item_path.exists():
                        if item_path.is_file():
                            zipf.write(item_path, item)
                        elif item_path.is_dir():
                            for file_path in item_path.rglob('*'):
                                if file_path.is_file():
                                    arcname = file_path.relative_to(self.root_path)
                                    zipf.write(file_path, arcname)

            logger.info(f"Backup created successfully: {backup_file}")
            return backup_file

        except Exception as e:
            logger.error(f"Failed to create backup: {e}")
            return None

    def verify_update_package(self, package_path: Path) -> bool:
        """Verify the integrity of the update package."""
        try:
            # Basic verification - check if it's a valid zip file
            with zipfile.ZipFile(package_path, 'r') as zipf:
                # Test the zip file
                bad_file = zipf.testzip()
                if bad_file:
                    logger.error(f"Corrupted file in zip: {bad_file}")
                    return False

                # Check for essential files
                file_list = zipf.namelist()
                essential_files = ["run.py", "src/", "version.json"]

                for essential in essential_files:
                    found = any(f.startswith(essential) for f in file_list)
                    if not found:
                        logger.warning(f"Essential file/directory not found: {essential}")

                logger.info("Update package verification passed")
                return True

        except Exception as e:
            logger.error(f"Failed to verify update package: {e}")
            return False

    async def install_update(self, package_path: Path, update_info: UpdateInfo) -> bool:
        """Install the update package."""
        try:
            logger.info(f"Installing update {update_info.latest_version}")

            # Create backup if enabled
            if self.config["backup_before_update"]:
                backup_file = self.create_backup()
                if not backup_file:
                    logger.error("Failed to create backup, aborting update")
                    return False

            # Verify package
            if not self.verify_update_package(package_path):
                logger.error("Package verification failed, aborting update")
                return False

            # Extract to temporary directory
            temp_extract_dir = self.temp_path / f"extract_{update_info.latest_version}"
            temp_extract_dir.mkdir(exist_ok=True)

            with zipfile.ZipFile(package_path, 'r') as zipf:
                zipf.extractall(temp_extract_dir)

            # Find the actual content directory (GitHub zipballs have a wrapper directory)
            content_dirs = [d for d in temp_extract_dir.iterdir() if d.is_dir()]
            if len(content_dirs) == 1:
                source_dir = content_dirs[0]
            else:
                source_dir = temp_extract_dir

            # Stop services before update
            await self._stop_services()

            # Update files
            update_items = [
                ("src", "src"),
                ("run.py", "run.py"),
                ("requirements.txt", "requirements.txt")
            ]

            for source_item, dest_item in update_items:
                source_path = source_dir / source_item
                dest_path = self.root_path / dest_item

                if source_path.exists():
                    if dest_path.exists():
                        if dest_path.is_dir():
                            shutil.rmtree(dest_path)
                        else:
                            dest_path.unlink()

                    if source_path.is_dir():
                        shutil.copytree(source_path, dest_path)
                    else:
                        shutil.copy2(source_path, dest_path)

                    logger.info(f"Updated: {dest_item}")

            # Update version.json
            await self._update_version_file(update_info.latest_version)

            # Install/update dependencies
            await self._update_dependencies()

            # Clean up temporary files
            shutil.rmtree(temp_extract_dir, ignore_errors=True)
            package_path.unlink(missing_ok=True)

            logger.info(f"Update installation completed: {update_info.latest_version}")
            return True

        except Exception as e:
            logger.error(f"Failed to install update: {e}")
            return False

    async def _stop_services(self):
        """Stop PlexiChat services before update."""
        try:
            # This would integrate with the actual service management
            logger.info("Stopping PlexiChat services for update...")
            # Implementation would depend on how services are managed
        except Exception as e:
            logger.warning(f"Failed to stop services: {e}")

    async def _update_version_file(self, new_version: str):
        """Update the version.json file."""
        try:
            version_data = {
                "current_version": new_version,
                "last_updated": datetime.now(timezone.utc).isoformat(),
                "history": []
            }

            # Load existing history if available
            if self.version_file.exists():
                with open(self.version_file, 'r') as f:
                    existing_data = json.load(f)
                    version_data["history"] = existing_data.get("history", [])

            # Add current update to history
            version_data["history"].append({
                "version": new_version,
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "method": "github_auto_update"
            })

            # Keep only last 10 history entries
            version_data["history"] = version_data["history"][-10:]

            with open(self.version_file, 'w') as f:
                json.dump(version_data, f, indent=2)

            logger.info(f"Version file updated to {new_version}")

        except Exception as e:
            logger.error(f"Failed to update version file: {e}")

    async def _update_dependencies(self):
        """Update Python dependencies after update."""
        try:
            logger.info("Updating dependencies...")

            # Check if we're in a virtual environment
            venv_python = None
            if os.getenv("VIRTUAL_ENV"):
                from pathlib import Path
venv_python = Path
Path(os.getenv("VIRTUAL_ENV")) / "Scripts" / "python.exe"
                if not venv_python.exists():
                    from pathlib import Path
venv_python = Path
Path(os.getenv("VIRTUAL_ENV")) / "bin" / "python"

            python_cmd = str(venv_python) if venv_python and venv_python.exists() else "python"

            # Update dependencies
            requirements_file = self.root_path / "requirements.txt"
            if requirements_file.exists():
                result = subprocess.run(
                    [python_cmd, "-m", "pip", "install", "-r", str(requirements_file)],
                    capture_output=True,
                    text=True,
                    timeout=300
                )

                if result.returncode == 0:
                    logger.info("Dependencies updated successfully")
                else:
                    logger.warning(f"Dependency update had issues: {result.stderr}")

        except Exception as e:
            logger.error(f"Failed to update dependencies: {e}")

    def get_update_history(self) -> List[Dict[str, Any]]:
        """Get update history."""
        try:
            if self.version_file.exists():
                with open(self.version_file, 'r') as f:
                    data = json.load(f)
                    return data.get("history", [])
            return []
        except Exception as e:
            logger.error(f"Failed to get update history: {e}")
            return []

    def configure_auto_updates(self, enabled: bool, channel: str = "stable"):
        """Configure automatic updates."""
        self.config["auto_download"] = enabled
        self.config["update_channel"] = channel
        logger.info(f"Auto-updates configured: enabled={enabled}, channel={channel}")

    def register_health_check(self, callback: Callable[[], bool]):
        """Register a health check callback for seamless updates."""
        self.health_check_callbacks.append(callback)
        logger.debug(f"Registered health check callback: {callback.__name__}")

    async def perform_health_checks(self) -> bool:
        """Perform all registered health checks."""
        try:
            for callback in self.health_check_callbacks:
                if asyncio.iscoroutinefunction(callback):
                    result = await callback()
                else:
                    result = callback()

                if not result:
                    logger.warning(f"Health check failed: {callback.__name__}")
                    return False

            logger.info("All health checks passed")
            return True

        except Exception as e:
            logger.error(f"Health check error: {e}")
            return False

    async def seamless_install_update(self, package_path: Path, update_info: UpdateInfo) -> bool:
        """Install update with zero downtime using hot reload."""
        if self.update_in_progress:
            logger.warning("Update already in progress")
            return False

        self.update_in_progress = True

        try:
            logger.info(f"Starting seamless update to {update_info.latest_version}")

            # Create backup and add to rollback stack
            if self.config["backup_before_update"]:
                backup_file = self.create_backup()
                if backup_file:
                    self.rollback_stack.append({
                        "type": "backup",
                        "path": backup_file,
                        "version": self.get_current_version(),
                        "timestamp": from datetime import datetime
datetime = datetime.now()
                    })

            # Verify package
            if not self.verify_update_package(package_path):
                logger.error("Package verification failed")
                return await self._rollback_update("Package verification failed")

            # Extract to staging directory
            staging_dir = self.temp_path / f"staging_{update_info.latest_version}"
            staging_dir.mkdir(exist_ok=True)

            with zipfile.ZipFile(package_path, 'r') as zipf:
                zipf.extractall(staging_dir)

            # Find content directory
            content_dirs = [d for d in staging_dir.iterdir() if d.is_dir()]
            source_dir = content_dirs[0] if len(content_dirs) == 1 else staging_dir

            # Perform hot reload of modules
            success = await self._hot_reload_modules(source_dir)
            if not success:
                return await self._rollback_update("Hot reload failed")

            # Perform health checks
            health_ok = await self.perform_health_checks()
            if not health_ok:
                return await self._rollback_update("Health checks failed")

            # If everything is good, commit the update
            await self._commit_update(source_dir, update_info)

            # Clean up
            shutil.rmtree(staging_dir, ignore_errors=True)
            package_path.unlink(missing_ok=True)

            logger.info(f"Seamless update completed successfully: {update_info.latest_version}")
            return True

        except Exception as e:
            logger.error(f"Seamless update failed: {e}")
            return await self._rollback_update(f"Update error: {e}")

        finally:
            self.update_in_progress = False

    async def _hot_reload_modules(self, source_dir: Path) -> bool:
        """Hot reload Python modules without restarting the service."""
        try:
            logger.info("Performing hot reload of modules")

            # Get list of modules to reload
            src_path = source_dir / "src"
            if not src_path.exists():
                logger.error("Source directory not found in update package")
                return False

            # Find all Python modules in the new source
            modules_to_reload = []
            for py_file in src_path.rglob("*.py"):
                if py_file.name == "__init__.py":
                    continue

                # Convert file path to module name
                rel_path = py_file.relative_to(src_path)
                module_name = str(rel_path.with_suffix("")).replace(os.sep, ".")

                # Check if module is already loaded
                full_module_name = f"src.{module_name}"
                if full_module_name in sys.modules:
                    modules_to_reload.append(full_module_name)

            # Backup current modules
            module_backup = {}
            for module_name in modules_to_reload:
                module_backup[module_name] = sys.modules[module_name]

            self.rollback_stack.append({
                "type": "modules",
                "backup": module_backup,
                "timestamp": from datetime import datetime
datetime = datetime.now()
            })

            # Copy new source files
            dest_src = self.root_path / "src"
            temp_backup_src = self.temp_path / f"src_backup_{from datetime import datetime
datetime = datetime.now().strftime('%Y%m%d_%H%M%S')}"

            # Backup current src
            if dest_src.exists():
                shutil.copytree(dest_src, temp_backup_src)
                self.rollback_stack.append({
                    "type": "files",
                    "backup_path": temp_backup_src,
                    "original_path": dest_src,
                    "timestamp": from datetime import datetime
datetime = datetime.now()
                })

            # Copy new files
            if dest_src.exists():
                shutil.rmtree(dest_src)
            shutil.copytree(src_path, dest_src)

            # Reload modules
            reloaded_count = 0
            for module_name in modules_to_reload:
                try:
                    importlib.reload(sys.modules[module_name])
                    reloaded_count += 1
                    logger.debug(f"Reloaded module: {module_name}")
                except Exception as e:
                    logger.warning(f"Failed to reload module {module_name}: {e}")

            logger.info(f"Hot reload completed: {reloaded_count}/{len(modules_to_reload)} modules reloaded")
            return True

        except Exception as e:
            logger.error(f"Hot reload failed: {e}")
            return False

    async def _commit_update(self, source_dir: Path, update_info: UpdateInfo):
        """Commit the update by updating version and dependencies."""
        try:
            # Update version file
            await self._update_version_file(update_info.latest_version)

            # Update dependencies if needed
            requirements_src = source_dir / "requirements.txt"
            requirements_dest = self.root_path / "requirements.txt"

            if requirements_src.exists():
                shutil.copy2(requirements_src, requirements_dest)
                await self._update_dependencies()

            # Update other files
            other_files = ["run.py"]
            for file_name in other_files:
                src_file = source_dir / file_name
                dest_file = self.root_path / file_name

                if src_file.exists():
                    if dest_file.exists():
                        backup_file = self.temp_path / f"{file_name}_backup_{from datetime import datetime
datetime = datetime.now().strftime('%Y%m%d_%H%M%S')}"
                        shutil.copy2(dest_file, backup_file)
                        self.rollback_stack.append({
                            "type": "file",
                            "backup_path": backup_file,
                            "original_path": dest_file,
                            "timestamp": from datetime import datetime
datetime = datetime.now()
                        })

                    shutil.copy2(src_file, dest_file)

            logger.info("Update committed successfully")

        except Exception as e:
            logger.error(f"Failed to commit update: {e}")
            raise

    async def _rollback_update(self, reason: str) -> bool:
        """Rollback the update to previous state."""
        try:
            logger.warning(f"Rolling back update: {reason}")

            # Rollback in reverse order
            while self.rollback_stack:
                rollback_item = self.rollback_stack.pop()

                if rollback_item["type"] == "modules":
                    # Restore module backup
                    for module_name, module_obj in rollback_item["backup"].items():
                        sys.modules[module_name] = module_obj
                    logger.info("Restored module state")

                elif rollback_item["type"] == "files":
                    # Restore file backup
                    backup_path = rollback_item["backup_path"]
                    original_path = rollback_item["original_path"]

                    if original_path.exists():
                        shutil.rmtree(original_path)
                    shutil.copytree(backup_path, original_path)
                    shutil.rmtree(backup_path, ignore_errors=True)
                    logger.info(f"Restored files: {original_path}")

                elif rollback_item["type"] == "file":
                    # Restore single file
                    backup_path = rollback_item["backup_path"]
                    original_path = rollback_item["original_path"]

                    shutil.copy2(backup_path, original_path)
                    backup_path.unlink(missing_ok=True)
                    logger.info(f"Restored file: {original_path}")

            logger.info("Rollback completed successfully")
            return False  # Update failed

        except Exception as e:
            logger.error(f"Rollback failed: {e}")
            return False


# Global GitHub updater instance
github_updater = GitHubUpdater()
