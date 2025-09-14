"""
Backup API endpoints with comprehensive security hardening.

This module provides RESTful API endpoints for backup operations with:
- Rate limiting and DDoS protection
- Authentication and authorization
- PII redaction in logging
- Input validation and sanitization
- AEAD encryption for all operations
"""

from datetime import datetime
import logging
import re
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from pydantic import BaseModel, Field, validator

from plexichat.core.auth.fastapi_adapter import get_current_user, rate_limit
from plexichat.core.logging.pii_redaction import redact_pii
from plexichat.features.backup.backup_engine import (
    BackupEngine,
    BackupType,
    SecurityLevel,
)
from plexichat.features.backup.encryption_service import EncryptionService

# Initialize router
router = APIRouter(prefix="/backups", tags=["backups"])

# Initialize services
backup_engine = BackupEngine()
encryption_service = EncryptionService()

# Configure logging with PII redaction
logger = logging.getLogger(__name__)


class BackupCreateRequest(BaseModel):
    """Request model for creating backups."""

    data: str = Field(
        ..., min_length=1, max_length=1000000, description="Data to backup"
    )
    backup_type: str = Field("full", description="Type of backup")
    security_level: str = Field("standard", description="Security level")
    tags: list[str] | None = Field(None, description="Backup tags")
    retention_days: int | None = Field(
        90, ge=1, le=3650, description="Retention period"
    )

    @validator("data")
    def validate_data(cls, v):
        """Validate and sanitize backup data."""
        if not v or not v.strip():
            raise ValueError("Data cannot be empty")

        # Remove any potentially dangerous content
        v = re.sub(r"[<>]", "", v)  # Remove angle brackets
        v = re.sub(r"javascript:", "", v, flags=re.IGNORECASE)  # Remove JS injection

        return v.strip()

    @validator("backup_type")
    def validate_backup_type(cls, v):
        """Validate backup type."""
        valid_types = ["full", "incremental", "differential", "snapshot"]
        if v not in valid_types:
            raise ValueError(f"Invalid backup type. Must be one of: {valid_types}")
        return v

    @validator("security_level")
    def validate_security_level(cls, v):
        """Validate security level."""
        valid_levels = ["basic", "standard", "high", "maximum", "government"]
        if v not in valid_levels:
            raise ValueError(f"Invalid security level. Must be one of: {valid_levels}")
        return v

    @validator("tags")
    def validate_tags(cls, v):
        """Validate and sanitize tags."""
        if v:
            # Sanitize each tag
            sanitized = []
            for tag in v:
                if len(tag) > 50:  # Limit tag length
                    continue
                # Remove special characters that could be used for injection
                tag = re.sub(r"[^a-zA-Z0-9\-_]", "", tag)
                if tag:
                    sanitized.append(tag)
            return sanitized[:10]  # Limit to 10 tags
        return v


class BackupResponse(BaseModel):
    """Response model for backup operations."""

    backup_id: str
    status: str
    created_at: datetime
    size_bytes: int
    security_level: str
    tags: list[str]


def sanitize_log_data(data: dict[str, Any]) -> dict[str, Any]:
    """Sanitize sensitive data for logging."""
    sanitized = data.copy()

    # Redact PII and sensitive fields
    sensitive_fields = ["password", "token", "key", "secret", "private", "auth"]
    for field in sensitive_fields:
        if field in sanitized:
            sanitized[field] = "[REDACTED]"

    # Redact data field if it's too large
    if "data" in sanitized and len(str(sanitized["data"])) > 100:
        sanitized["data"] = f"[DATA_REDACTED_{len(str(sanitized['data']))}chars]"

    return sanitized


@router.post("/", response_model=BackupResponse)
@rate_limit(action="backup_create", limit=10, window_seconds=60)
async def create_backup(
    request: BackupCreateRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user),
    req: Request = None,
):
    """
    Create a new backup with comprehensive security.

    - Rate limited to 10 requests per minute per IP
    - Requires authentication
    - Input validation and sanitization
    - PII redaction in logs
    """
    try:
        # Log sanitized request data
        log_data = sanitize_log_data(request.dict())
        logger.info(
            f"Backup creation requested by user {redact_pii(current_user.get('username', 'unknown'))}",
            extra={"user_id": current_user.get("id"), "request": log_data},
        )

        # Convert string data to appropriate type
        backup_data = request.data
        if request.data.startswith("{") or request.data.startswith("["):
            # Try to parse as JSON
            try:
                import json

                backup_data = json.loads(request.data)
            except json.JSONDecodeError:
                # Keep as string if not valid JSON
                pass

        # Create backup with security level mapping
        security_level_map = {
            "basic": SecurityLevel.BASIC,
            "standard": SecurityLevel.STANDARD,
            "high": SecurityLevel.HIGH,
            "maximum": SecurityLevel.MAXIMUM,
            "government": SecurityLevel.GOVERNMENT,
        }

        backup_type_map = {
            "full": BackupType.FULL,
            "incremental": BackupType.INCREMENTAL,
            "differential": BackupType.DIFFERENTIAL,
            "snapshot": BackupType.SNAPSHOT,
        }

        backup_metadata = await backup_engine.create_backup(
            data=backup_data,
            backup_type=backup_type_map[request.backup_type],
            security_level=security_level_map[request.security_level],
            user_id=current_user.get("id"),
            tags=request.tags,
            retention_days=request.retention_days,
        )

        # Log successful creation (without sensitive data)
        logger.info(
            f"Backup created successfully: {backup_metadata.backup_id}",
            extra={
                "user_id": current_user.get("id"),
                "backup_id": backup_metadata.backup_id,
            },
        )

        return BackupResponse(
            backup_id=backup_metadata.backup_id,
            status=backup_metadata.status.value,
            created_at=backup_metadata.created_at,
            size_bytes=backup_metadata.original_size,
            security_level=backup_metadata.security_level.value,
            tags=backup_metadata.tags,
        )

    except Exception as e:
        # Log error with redaction
        error_msg = str(e)
        logger.error(
            f"Backup creation failed: {redact_pii(error_msg)}",
            extra={"user_id": current_user.get("id")},
        )
        raise HTTPException(status_code=500, detail="Backup creation failed")


@router.get("/")
@rate_limit(action="backup_list", limit=30, window_seconds=60)
async def list_backups(
    limit: int = 50, offset: int = 0, current_user: dict = Depends(get_current_user)
):
    """
    List user backups with rate limiting.

    - Rate limited to 30 requests per minute per IP
    - Requires authentication
    - PII redaction in logs
    """
    try:
        # Validate parameters
        if limit < 1 or limit > 100:
            raise HTTPException(
                status_code=400, detail="Limit must be between 1 and 100"
            )
        if offset < 0:
            raise HTTPException(status_code=400, detail="Offset must be non-negative")

        backups = await backup_engine.list_backups(
            user_id=current_user.get("id"), limit=limit, offset=offset
        )

        # Redact sensitive information from response
        sanitized_backups = []
        for backup in backups:
            sanitized = backup.copy()
            # Remove or redact sensitive fields
            if "recovery_info" in sanitized:
                sanitized["recovery_info"] = "[REDACTED]"
            sanitized_backups.append(sanitized)

        logger.info(
            f"Backups listed for user {redact_pii(current_user.get('username', 'unknown'))}",
            extra={"user_id": current_user.get("id"), "count": len(sanitized_backups)},
        )

        return {"backups": sanitized_backups, "total": len(sanitized_backups)}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            f"Failed to list backups: {redact_pii(str(e))}",
            extra={"user_id": current_user.get("id")},
        )
        raise HTTPException(status_code=500, detail="Failed to list backups")


@router.get("/{backup_id}")
@rate_limit(action="backup_get", limit=60, window_seconds=60)
async def get_backup(backup_id: str, current_user: dict = Depends(get_current_user)):
    """
    Get backup details with authorization check.

    - Rate limited to 60 requests per minute per IP
    - Requires authentication and ownership
    - PII redaction in logs
    """
    try:
        # Validate backup_id format
        if not re.match(r"^backup_\d+_[a-f0-9]+$", backup_id):
            raise HTTPException(status_code=400, detail="Invalid backup ID format")

        backup = await backup_engine.get_backup_details(backup_id)

        if not backup:
            raise HTTPException(status_code=404, detail="Backup not found")

        # Check ownership
        if backup.get("user_id") != current_user.get("id"):
            logger.warning(
                f"Unauthorized access attempt to backup {backup_id}",
                extra={"user_id": current_user.get("id"), "backup_id": backup_id},
            )
            raise HTTPException(status_code=403, detail="Access denied")

        # Redact sensitive information
        sanitized_backup = backup.copy()
        if "recovery_info" in sanitized_backup:
            sanitized_backup["recovery_info"] = "[REDACTED]"

        logger.info(
            f"Backup details retrieved: {backup_id}",
            extra={"user_id": current_user.get("id")},
        )

        return sanitized_backup

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            f"Failed to get backup {backup_id}: {redact_pii(str(e))}",
            extra={"user_id": current_user.get("id")},
        )
        raise HTTPException(status_code=500, detail="Failed to get backup details")


@router.delete("/{backup_id}")
@rate_limit(action="backup_delete", limit=5, window_seconds=60)
async def delete_backup(backup_id: str, current_user: dict = Depends(get_current_user)):
    """
    Delete backup with strict authorization.

    - Rate limited to 5 requests per minute per IP
    - Requires authentication and ownership
    - PII redaction in logs
    """
    try:
        # Validate backup_id format
        if not re.match(r"^backup_\d+_[a-f0-9]+$", backup_id):
            raise HTTPException(status_code=400, detail="Invalid backup ID format")

        # Check ownership first
        backup = await backup_engine.get_backup_details(backup_id)
        if not backup:
            raise HTTPException(status_code=404, detail="Backup not found")

        if backup.get("user_id") != current_user.get("id"):
            logger.warning(
                f"Unauthorized delete attempt for backup {backup_id}",
                extra={"user_id": current_user.get("id")},
            )
            raise HTTPException(status_code=403, detail="Access denied")

        # Delete backup
        success = await backup_engine.delete_backup(backup_id)

        if success:
            logger.info(
                f"Backup deleted: {backup_id}",
                extra={"user_id": current_user.get("id")},
            )
            return {"message": "Backup deleted successfully"}
        else:
            raise HTTPException(status_code=500, detail="Failed to delete backup")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            f"Failed to delete backup {backup_id}: {redact_pii(str(e))}",
            extra={"user_id": current_user.get("id")},
        )
        raise HTTPException(status_code=500, detail="Failed to delete backup")


@router.post("/{backup_id}/rotate-keys")
@rate_limit(action="backup_rotate", limit=2, window_seconds=60)
async def rotate_backup_keys(
    backup_id: str, current_user: dict = Depends(get_current_user)
):
    """
    Rotate encryption keys for a backup.

    - Rate limited to 2 requests per minute per IP
    - Requires authentication and ownership
    - PII redaction in logs
    """
    try:
        # Validate backup_id format
        if not re.match(r"^backup_\d+_[a-f0-9]+$", backup_id):
            raise HTTPException(status_code=400, detail="Invalid backup ID format")

        # Check ownership
        backup = await backup_engine.get_backup_details(backup_id)
        if not backup:
            raise HTTPException(status_code=404, detail="Backup not found")

        if backup.get("user_id") != current_user.get("id"):
            logger.warning(
                f"Unauthorized key rotation attempt for backup {backup_id}",
                extra={"user_id": current_user.get("id")},
            )
            raise HTTPException(status_code=403, detail="Access denied")

        # Rotate keys
        rotation_result = await backup_engine.rotate_backup_keys(backup_id)

        logger.info(
            f"Keys rotated for backup {backup_id}",
            extra={"user_id": current_user.get("id")},
        )

        return rotation_result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            f"Failed to rotate keys for backup {backup_id}: {redact_pii(str(e))}",
            extra={"user_id": current_user.get("id")},
        )
        raise HTTPException(status_code=500, detail="Failed to rotate keys")


def get_client_ip(request: Request) -> str:
    """Get client IP address for rate limiting."""
    # Try X-Forwarded-For header first (for proxies)
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()

    # Fall back to direct client
    return request.client.host if request.client else "unknown"
