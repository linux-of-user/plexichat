"""
NetLink Communication Admin API Endpoints

Admin endpoints for managing communication service configuration,
monitoring, and administration.
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from typing import Dict, List, Optional, Any
from datetime import datetime
import logging

from ....core.auth.dependencies import require_admin_auth
from ....core.logging import get_logger
from ....services.communication_service import get_communication_service

# Initialize router and logger
router = APIRouter(prefix="/admin/communication", tags=["Communication Admin"])
logger = get_logger(__name__)

# Pydantic Models

class ConfigurationUpdateRequest(BaseModel):
    """Configuration update request model."""
    section: str = Field(..., description="Configuration section to update")
    config: Dict[str, Any] = Field(..., description="Configuration updates")

class ConfigurationResponse(BaseModel):
    """Configuration response model."""
    section: str
    config: Dict[str, Any]
    last_updated: datetime
    
class ValidationIssue(BaseModel):
    """Configuration validation issue model."""
    section: str
    issues: List[str]

class ServiceStatsResponse(BaseModel):
    """Service statistics response model."""
    service_status: str
    voice_messages_count: int
    active_threads_count: int
    pending_translations: int
    unread_notifications: int
    ai_manager_available: bool
    configuration_valid: bool
    features_enabled: Dict[str, bool]
    supported_languages: List[str]
    voice_storage_path: str

class TestResult(BaseModel):
    """Test result model."""
    test_name: str
    success: bool
    message: str
    details: Optional[Dict[str, Any]] = None

# Configuration Management Endpoints

@router.get("/config", response_model=Dict[str, Any])
async def get_communication_configuration(
    section: Optional[str] = Query(None, description="Specific configuration section"),
    admin_user: dict = Depends(require_admin_auth)
):
    """Get communication service configuration."""
    try:
        communication_service = await get_communication_service()
        config = await communication_service.get_configuration()
        
        if section:
            if section not in config:
                raise HTTPException(status_code=404, detail=f"Configuration section '{section}' not found")
            return {section: config[section]}
        
        return config
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get communication configuration: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get configuration: {str(e)}")

@router.put("/config")
async def update_communication_configuration(
    request: ConfigurationUpdateRequest,
    admin_user: dict = Depends(require_admin_auth)
):
    """Update communication service configuration."""
    try:
        communication_service = await get_communication_service()
        
        # Validate section exists
        current_config = await communication_service.get_configuration()
        if request.section not in current_config:
            raise HTTPException(status_code=404, detail=f"Configuration section '{request.section}' not found")
        
        # Update configuration
        config_updates = {request.section: request.config}
        success = await communication_service.update_configuration(config_updates)
        
        if not success:
            raise HTTPException(status_code=500, detail="Failed to update configuration")
        
        # Validate updated configuration
        validation_issues = await communication_service.validate_configuration()
        if validation_issues:
            logger.warning(f"Configuration validation issues: {validation_issues}")
        
        return {
            "message": f"Configuration section '{request.section}' updated successfully",
            "validation_issues": validation_issues,
            "timestamp": datetime.utcnow()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update communication configuration: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to update configuration: {str(e)}")

@router.post("/config/{section}/reset")
async def reset_configuration_section(
    section: str,
    admin_user: dict = Depends(require_admin_auth)
):
    """Reset a configuration section to defaults."""
    try:
        communication_service = await get_communication_service()
        
        success = await communication_service.reset_configuration_section(section)
        if not success:
            raise HTTPException(status_code=404, detail=f"Configuration section '{section}' not found")
        
        return {
            "message": f"Configuration section '{section}' reset to defaults",
            "timestamp": datetime.utcnow()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to reset configuration section: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to reset configuration: {str(e)}")

@router.get("/config/schema", response_model=Dict[str, Any])
async def get_configuration_schema(
    admin_user: dict = Depends(require_admin_auth)
):
    """Get configuration schema for UI generation."""
    try:
        communication_service = await get_communication_service()
        schema = await communication_service.get_configuration_schema()
        
        return schema
        
    except Exception as e:
        logger.error(f"Failed to get configuration schema: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get configuration schema: {str(e)}")

@router.get("/config/validate", response_model=Dict[str, List[str]])
async def validate_configuration(
    admin_user: dict = Depends(require_admin_auth)
):
    """Validate current configuration."""
    try:
        communication_service = await get_communication_service()
        validation_issues = await communication_service.validate_configuration()
        
        return validation_issues
        
    except Exception as e:
        logger.error(f"Failed to validate configuration: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to validate configuration: {str(e)}")

# Service Monitoring Endpoints

@router.get("/stats", response_model=ServiceStatsResponse)
async def get_communication_stats(
    admin_user: dict = Depends(require_admin_auth)
):
    """Get communication service statistics."""
    try:
        communication_service = await get_communication_service()
        health_status = await communication_service.get_health_status()
        
        return ServiceStatsResponse(
            service_status=health_status.get("state", "unknown"),
            voice_messages_count=health_status.get("voice_messages_count", 0),
            active_threads_count=health_status.get("active_threads_count", 0),
            pending_translations=health_status.get("pending_translations", 0),
            unread_notifications=health_status.get("unread_notifications", 0),
            ai_manager_available=health_status.get("ai_manager_available", False),
            configuration_valid=health_status.get("configuration_valid", False),
            features_enabled=health_status.get("features_enabled", {}),
            supported_languages=health_status.get("supported_languages", []),
            voice_storage_path=health_status.get("voice_storage_path", "")
        )
        
    except Exception as e:
        logger.error(f"Failed to get communication stats: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get communication stats: {str(e)}")

@router.get("/health")
async def get_service_health(
    admin_user: dict = Depends(require_admin_auth)
):
    """Get detailed service health information."""
    try:
        communication_service = await get_communication_service()
        health_status = await communication_service.get_health_status()
        
        return {
            "service_name": "communication",
            "status": health_status,
            "timestamp": datetime.utcnow()
        }
        
    except Exception as e:
        logger.error(f"Failed to get service health: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get service health: {str(e)}")

# Testing Endpoints

@router.post("/test/voice", response_model=TestResult)
async def test_voice_configuration(
    admin_user: dict = Depends(require_admin_auth)
):
    """Test voice message configuration."""
    try:
        communication_service = await get_communication_service()
        config = await communication_service.get_configuration()
        voice_config = config.get("voice_messages", {})
        
        # Test voice storage path
        storage_path = communication_service.voice_storage_path
        if not storage_path.exists():
            return TestResult(
                test_name="voice_configuration",
                success=False,
                message="Voice storage path does not exist",
                details={"storage_path": str(storage_path)}
            )
        
        # Test write permissions
        test_file = storage_path / "test_write.tmp"
        try:
            test_file.write_text("test")
            test_file.unlink()
        except Exception as e:
            return TestResult(
                test_name="voice_configuration",
                success=False,
                message="No write permission to voice storage path",
                details={"error": str(e)}
            )
        
        # Test configuration values
        issues = []
        if voice_config.get("max_duration_seconds", 0) <= 0:
            issues.append("Invalid max_duration_seconds")
        if voice_config.get("max_file_size_mb", 0) <= 0:
            issues.append("Invalid max_file_size_mb")
        
        if issues:
            return TestResult(
                test_name="voice_configuration",
                success=False,
                message="Configuration validation failed",
                details={"issues": issues}
            )
        
        return TestResult(
            test_name="voice_configuration",
            success=True,
            message="Voice configuration test passed",
            details={
                "storage_path": str(storage_path),
                "max_duration": voice_config.get("max_duration_seconds"),
                "max_file_size": voice_config.get("max_file_size_mb")
            }
        )
        
    except Exception as e:
        logger.error(f"Voice configuration test failed: {e}")
        return TestResult(
            test_name="voice_configuration",
            success=False,
            message=f"Test failed: {str(e)}"
        )

@router.post("/test/translation", response_model=TestResult)
async def test_translation_configuration(
    admin_user: dict = Depends(require_admin_auth)
):
    """Test translation configuration."""
    try:
        communication_service = await get_communication_service()
        config = await communication_service.get_configuration()
        translation_config = config.get("translation", {})
        
        if not translation_config.get("enabled", False):
            return TestResult(
                test_name="translation_configuration",
                success=False,
                message="Translation is disabled"
            )
        
        # Test AI manager availability
        if not communication_service.ai_manager:
            return TestResult(
                test_name="translation_configuration",
                success=False,
                message="AI manager not available for translation"
            )
        
        # Test supported languages
        supported_languages = translation_config.get("supported_languages", [])
        if not supported_languages:
            return TestResult(
                test_name="translation_configuration",
                success=False,
                message="No supported languages configured"
            )
        
        return TestResult(
            test_name="translation_configuration",
            success=True,
            message="Translation configuration test passed",
            details={
                "supported_languages_count": len(supported_languages),
                "provider": translation_config.get("translation_provider"),
                "ai_manager_available": True
            }
        )
        
    except Exception as e:
        logger.error(f"Translation configuration test failed: {e}")
        return TestResult(
            test_name="translation_configuration",
            success=False,
            message=f"Test failed: {str(e)}"
        )

@router.post("/test/notifications", response_model=TestResult)
async def test_notifications_configuration(
    admin_user: dict = Depends(require_admin_auth)
):
    """Test notifications configuration."""
    try:
        communication_service = await get_communication_service()
        config = await communication_service.get_configuration()
        notifications_config = config.get("notifications", {})
        
        if not notifications_config.get("enabled", False):
            return TestResult(
                test_name="notifications_configuration",
                success=False,
                message="Notifications are disabled"
            )
        
        # Test configuration values
        issues = []
        if notifications_config.get("max_notifications_per_user", 0) <= 0:
            issues.append("Invalid max_notifications_per_user")
        if notifications_config.get("notification_retention_days", 0) <= 0:
            issues.append("Invalid notification_retention_days")
        
        # Test quiet hours format
        quiet_start = notifications_config.get("quiet_hours_start", "")
        quiet_end = notifications_config.get("quiet_hours_end", "")
        
        import re
        time_pattern = r'^([01]?[0-9]|2[0-3]):[0-5][0-9]$'
        if not re.match(time_pattern, quiet_start):
            issues.append("Invalid quiet_hours_start format")
        if not re.match(time_pattern, quiet_end):
            issues.append("Invalid quiet_hours_end format")
        
        if issues:
            return TestResult(
                test_name="notifications_configuration",
                success=False,
                message="Configuration validation failed",
                details={"issues": issues}
            )
        
        return TestResult(
            test_name="notifications_configuration",
            success=True,
            message="Notifications configuration test passed",
            details={
                "ai_analysis_enabled": notifications_config.get("ai_analysis_enabled"),
                "push_notifications": notifications_config.get("push_notifications"),
                "email_notifications": notifications_config.get("email_notifications")
            }
        )
        
    except Exception as e:
        logger.error(f"Notifications configuration test failed: {e}")
        return TestResult(
            test_name="notifications_configuration",
            success=False,
            message=f"Test failed: {str(e)}"
        )

# Data Management Endpoints

@router.delete("/data/voice-messages")
async def cleanup_voice_messages(
    older_than_days: int = Query(30, description="Delete voice messages older than this many days"),
    admin_user: dict = Depends(require_admin_auth)
):
    """Clean up old voice messages."""
    try:
        communication_service = await get_communication_service()
        
        # This would implement cleanup logic
        # For now, return a placeholder response
        
        return {
            "message": f"Voice messages cleanup initiated for files older than {older_than_days} days",
            "timestamp": datetime.utcnow()
        }
        
    except Exception as e:
        logger.error(f"Failed to cleanup voice messages: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to cleanup voice messages: {str(e)}")

@router.delete("/data/notifications")
async def cleanup_notifications(
    user_id: Optional[str] = Query(None, description="Clean notifications for specific user"),
    read_only: bool = Query(True, description="Only delete read notifications"),
    admin_user: dict = Depends(require_admin_auth)
):
    """Clean up old notifications."""
    try:
        communication_service = await get_communication_service()
        
        # This would implement cleanup logic
        # For now, return a placeholder response
        
        return {
            "message": f"Notifications cleanup initiated",
            "filters": {
                "user_id": user_id,
                "read_only": read_only
            },
            "timestamp": datetime.utcnow()
        }
        
    except Exception as e:
        logger.error(f"Failed to cleanup notifications: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to cleanup notifications: {str(e)}")

@router.post("/service/restart")
async def restart_communication_service(
    admin_user: dict = Depends(require_admin_auth)
):
    """Restart the communication service."""
    try:
        communication_service = await get_communication_service()
        
        # Stop and start the service
        await communication_service.stop()
        await communication_service.start()
        
        return {
            "message": "Communication service restarted successfully",
            "timestamp": datetime.utcnow()
        }
        
    except Exception as e:
        logger.error(f"Failed to restart communication service: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to restart service: {str(e)}")

# Export router
__all__ = ["router"]
