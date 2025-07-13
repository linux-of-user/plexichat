import logging
from datetime import datetime
from typing import Any, Dict, List, Optional



        from core.updates.github_updater import github_updater
        
        from core.updates.github_updater import github_updater
        
        from core.updates.github_updater import github_updater
        
        from core.updates.github_updater import github_updater
        
        from core.updates.github_updater import github_updater
        
        from core.updates.github_updater import github_updater
        

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from pydantic import BaseModel, Field

from plexichat.interfaces.web.routers.auth import get_current_admin_user

"""
PlexiChat Update API Endpoints
Provides API access to the GitHub-based update system.
"""

logger = logging.getLogger(__name__)

router = APIRouter()


class UpdateCheckResponse(BaseModel):
    """Update check response model."""
    update_available: bool
    current_version: str
    latest_version: Optional[str] = None
    release_notes: Optional[str] = None
    published_at: Optional[datetime] = None
    is_major_update: bool = False
    is_security_update: bool = False
    download_url: Optional[str] = None
    file_size: int = 0


class UpdateConfigRequest(BaseModel):
    """Update configuration request model."""
    auto_download: bool = Field(default=False, description="Enable automatic downloads")
    auto_install: bool = Field(default=False, description="Enable automatic installation")
    update_channel: str = Field(default="stable", regex="^(stable|beta|alpha)$")
    check_interval_hours: int = Field(default=24, ge=1, le=168)


class UpdateHistoryResponse(BaseModel):
    """Update history response model."""
    history: List[Dict[str, Any]]
    total_updates: int


@router.get(
    "/check",
    response_model=UpdateCheckResponse,
    summary="Check for updates",
    description="Check if updates are available from GitHub"
)
async def check_for_updates(current_user=Depends(get_current_admin_user)):
    """Check for available updates."""
    try:
        # Import here to avoid circular imports
        logger.info(f"Admin {current_user.username} checking for updates")
        
        update_info = await github_updater.check_for_updates()
        
        if not update_info:
            # No updates available
            current_version = github_updater.get_current_version()
            return UpdateCheckResponse(
                update_available=False,
                current_version=current_version
            )
        
        return UpdateCheckResponse(
            update_available=True,
            current_version=update_info.current_version,
            latest_version=update_info.latest_version,
            release_notes=update_info.release_notes,
            published_at=update_info.published_at,
            is_major_update=update_info.is_major_update,
            is_security_update=update_info.is_security_update,
            download_url=update_info.download_url,
            file_size=update_info.file_size
        )
        
    except Exception as e:
        logger.error(f"Failed to check for updates: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to check for updates"
        )


@router.post(
    "/download",
    summary="Download update",
    description="Download the latest available update"
)
async def download_update(
    background_tasks: BackgroundTasks,
    current_user=Depends(get_current_admin_user)
):
    """Download the latest update."""
    try:
        logger.info(f"Admin {current_user.username} initiating update download")
        
        # Check for updates first
        update_info = await github_updater.check_for_updates()
        
        if not update_info:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No updates available"
            )
        
        # Start download in background
        async def download_task():
            try:
                package_path = await github_updater.download_update(update_info)
                if package_path:
                    logger.info(f"Update download completed: {package_path}")
                else:
                    logger.error("Update download failed")
            except Exception as e:
                logger.error(f"Background download failed: {e}")
        
        background_tasks.add_task(download_task)
        
        return {
            "message": "Update download started",
            "version": update_info.latest_version,
            "download_url": update_info.download_url
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to start update download: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to start update download"
        )


@router.post(
    "/install",
    summary="Install update",
    description="Install a downloaded update (requires restart)"
)
async def install_update(
    background_tasks: BackgroundTasks,
    current_user=Depends(get_current_admin_user)
):
    """Install a downloaded update."""
    try:
        logger.info(f"Admin {current_user.username} initiating update installation")
        
        # Check for updates
        update_info = await github_updater.check_for_updates()
        
        if not update_info:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No updates available"
            )
        
        # Check if update package exists
        temp_path = github_updater.temp_path
        package_files = list(temp_path.glob(f"plexichat_update_{update_info.latest_version}.*"))
        
        if not package_files:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Update package not found. Please download first."
            )
        
        package_path = package_files[0]
        
        # Start installation in background
        async def install_task():
            try:
                success = await github_updater.install_update(package_path, update_info)
                if success:
                    logger.info(f"Update installation completed: {update_info.latest_version}")
                else:
                    logger.error("Update installation failed")
            except Exception as e:
                logger.error(f"Background installation failed: {e}")
        
        background_tasks.add_task(install_task)
        
        return {
            "message": "Update installation started",
            "version": update_info.latest_version,
            "restart_required": True,
            "warning": "PlexiChat will need to be restarted after installation"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to start update installation: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to start update installation"
        )


@router.get(
    "/history",
    response_model=UpdateHistoryResponse,
    summary="Get update history",
    description="Get the history of updates"
)
async def get_update_history(current_user=Depends(get_current_admin_user)):
    """Get update history."""
    try:
        history = github_updater.get_update_history()
        
        return UpdateHistoryResponse(
            history=history,
            total_updates=len(history)
        )
        
    except Exception as e:
        logger.error(f"Failed to get update history: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get update history"
        )


@router.post(
    "/config",
    summary="Configure auto-updates",
    description="Configure automatic update settings"
)
async def configure_updates(
    config: UpdateConfigRequest,
    current_user=Depends(get_current_admin_user)
):
    """Configure automatic update from plexichat.core.config import settings
settings."""
    try:
        logger.info(f"Admin {current_user.username} configuring auto-updates")
        
        # Update configuration
        github_updater.config.update({
            "auto_download": config.auto_download,
            "auto_install": config.auto_install,
            "update_channel": config.update_channel,
            "check_interval_hours": config.check_interval_hours
        })
        
        return {
            "message": "Update configuration saved",
            "config": {
                "auto_download": config.auto_download,
                "auto_install": config.auto_install,
                "update_channel": config.update_channel,
                "check_interval_hours": config.check_interval_hours
            }
        }
        
    except Exception as e:
        logger.error(f"Failed to configure updates: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to configure updates"
        )


@router.get(
    "/releases",
    summary="Get GitHub releases",
    description="Get available releases from GitHub"
)
async def get_releases(
    include_prerelease: bool = False,
    current_user=Depends(get_current_admin_user)
):
    """Get available releases from GitHub."""
    try:
        releases = await github_updater.get_releases(include_prerelease)
        
        release_data = []
        for release in releases[:10]:  # Limit to 10 most recent
            release_data.append({
                "tag_name": release.tag_name,
                "name": release.name,
                "version": release.version,
                "published_at": release.published_at,
                "prerelease": release.prerelease,
                "is_stable": release.is_stable,
                "body": release.body[:500] + "..." if len(release.body) > 500 else release.body
            })
        
        return {
            "releases": release_data,
            "total": len(release_data),
            "repository": f"{github_updater.repo_owner}/{github_updater.repo_name}"
        }
        
    except Exception as e:
        logger.error(f"Failed to get releases: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get releases from GitHub"
        )
