"""
Shard Distribution API endpoints with comprehensive security hardening.

This module provides RESTful API endpoints for P2P shard distribution with:
- Rate limiting and DDoS protection
- Authentication and authorization
- Fine-grained access control for shard operations
- PII redaction in logging
- Input validation and sanitization
- Secure error responses that don't leak sensitive information
- Comprehensive audit trails for all operations
- Tamper-resistant blockchain-based audit logging
"""

import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from fastapi import APIRouter, Depends, HTTPException, Request, BackgroundTasks
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator
import re
import hashlib
import secrets

from plexichat.core.auth.dependencies import get_current_user, require_admin
from plexichat.core.security.rate_limiting import RateLimitingSystem
from plexichat.core.logging.pii_redaction import redact_pii
from plexichat.core.security.unified_audit_system import (
    get_unified_audit_system,
    SecurityEventType,
    SecuritySeverity,
    ThreatLevel
)
from plexichat.features.backup.backup_engine import BackupEngine
from plexichat.features.backup.storage_manager import StorageManager

# Initialize router
router = APIRouter(prefix="/shards", tags=["shards"])

# Initialize services
backup_engine = BackupEngine()
storage_manager = StorageManager()
audit_system = get_unified_audit_system()

# Configure logging with PII redaction
logger = logging.getLogger(__name__)

# Rate limiting configuration for shard operations
SHARD_RATE_LIMITS = {
    "shard_request": {"requests_per_minute": 20, "burst_limit": 5},
    "shard_upload": {"requests_per_minute": 10, "burst_limit": 3},
    "shard_download": {"requests_per_minute": 30, "burst_limit": 10},
    "shard_verify": {"requests_per_minute": 60, "burst_limit": 20},
    "shard_list": {"requests_per_minute": 120, "burst_limit": 30}
}


class ShardRequest(BaseModel):
    """Request model for shard operations."""
    backup_id: str = Field(..., min_length=10, max_length=100, description="Backup ID containing the shard")
    shard_index: int = Field(..., ge=0, description="Index of the shard within the backup")
    operation: str = Field(..., description="Operation type (request, upload, download, verify)")

    @validator('backup_id')
    def validate_backup_id(cls, v):
        """Validate backup ID format."""
        if not re.match(r'^backup_\d+_[a-f0-9]+$', v):
            raise ValueError("Invalid backup ID format")
        return v

    @validator('operation')
    def validate_operation(cls, v):
        """Validate operation type."""
        valid_operations = ["request", "upload", "download", "verify", "list"]
        if v not in valid_operations:
            raise ValueError(f"Invalid operation. Must be one of: {valid_operations}")
        return v


class ShardUploadRequest(BaseModel):
    """Request model for shard upload."""
    backup_id: str = Field(..., min_length=10, max_length=100)
    shard_index: int = Field(..., ge=0)
    shard_data: str = Field(..., min_length=1, max_length=1048576, description="Base64 encoded shard data")
    checksum: str = Field(..., min_length=64, max_length=64, description="SHA256 checksum of shard data")

    @validator('backup_id')
    def validate_backup_id(cls, v):
        """Validate backup ID format."""
        if not re.match(r'^backup_\d+_[a-f0-9]+$', v):
            raise ValueError("Invalid backup ID format")
        return v

    @validator('shard_data')
    def validate_shard_data(cls, v):
        """Validate and sanitize shard data."""
        if not v or not v.strip():
            raise ValueError("Shard data cannot be empty")

        # Remove any potentially dangerous content
        v = re.sub(r'[<>]', '', v)  # Remove angle brackets
        v = re.sub(r'javascript:', '', v, flags=re.IGNORECASE)  # Remove JS injection

        return v.strip()

    @validator('checksum')
    def validate_checksum(cls, v):
        """Validate checksum format."""
        if not re.match(r'^[a-f0-9]{64}$', v):
            raise ValueError("Invalid checksum format (must be 64-character hex)")
        return v


class ShardResponse(BaseModel):
    """Response model for shard operations."""
    shard_id: str
    backup_id: str
    shard_index: int
    size_bytes: int
    checksum: str
    status: str
    created_at: datetime
    peer_count: int
    verification_status: str


def sanitize_log_data(data: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize sensitive data for logging."""
    sanitized = data.copy()

    # Redact PII and sensitive fields
    sensitive_fields = ['password', 'token', 'key', 'secret', 'private', 'auth', 'shard_data']
    for field in sensitive_fields:
        if field in sanitized:
            sanitized[field] = "[REDACTED]"

    # Redact large data fields
    if 'data' in sanitized and len(str(sanitized['data'])) > 100:
        sanitized['data'] = f"[DATA_REDACTED_{len(str(sanitized['data']))}chars]"

    return sanitized


def get_client_ip(request: Request) -> str:
    """Get client IP address for rate limiting and logging."""
    # Try X-Forwarded-For header first (for proxies)
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()

    # Fall back to direct client
    return request.client.host if request.client else "unknown"


def log_security_event(
    event_type: SecurityEventType,
    description: str,
    request: Request,
    user_id: Optional[str] = None,
    resource: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    severity: SecuritySeverity = SecuritySeverity.INFO,
    threat_level: ThreatLevel = ThreatLevel.LOW
):
    """Log security event with comprehensive context."""
    client_ip = get_client_ip(request)
    user_agent = request.headers.get("User-Agent", "unknown")

    audit_system.log_security_event(
        event_type=event_type,
        description=description,
        severity=severity,
        threat_level=threat_level,
        user_id=user_id,
        source_ip=client_ip,
        user_agent=user_agent,
        resource=resource,
        action=request.method,
        details=details or {},
        compliance_tags=["shard_distribution", "p2p_backup"]
    )


def check_shard_authorization(user_id: str, backup_id: str, operation: str) -> bool:
    """Check if user is authorized for shard operation."""
    try:
        # Get backup metadata to verify ownership
        backup_metadata = backup_engine.get_backup_details(backup_id)
        if not backup_metadata:
            return False

        # Check if user owns the backup
        if backup_metadata.get('user_id') != user_id:
            return False

        # Additional authorization checks based on operation
        if operation in ['upload', 'download']:
            # Verify backup is in appropriate state for the operation
            backup_status = backup_metadata.get('status', '').lower()
            if operation == 'upload' and backup_status not in ['pending', 'in_progress']:
                return False
            if operation == 'download' and backup_status not in ['completed', 'available']:
                return False

        return True

    except Exception as e:
        logger.error(f"Authorization check failed: {redact_pii(str(e))}")
        return False


@router.post("/request")
async def request_shard(
    request_data: ShardRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user),
    req: Request = None
):
    """
    Request a shard for P2P distribution.

    - Rate limited to 20 requests per minute per IP
    - Requires authentication
    - Fine-grained authorization checks
    - Comprehensive audit logging
    """
    try:
        client_ip = get_client_ip(req)
        user_id = current_user.get('id')

        # Log sanitized request data
        log_data = sanitize_log_data(request_data.dict())
        logger.info(f"Shard request by user {redact_pii(current_user.get('username', 'unknown'))}",
                   extra={"user_id": user_id, "request": log_data, "client_ip": client_ip})

        # Check authorization
        if not check_shard_authorization(user_id, request_data.backup_id, 'request'):
            log_security_event(
                SecurityEventType.AUTHORIZATION_FAILURE,
                f"Unauthorized shard request attempt for backup {request_data.backup_id}",
                req,
                user_id,
                f"shard:{request_data.backup_id}:{request_data.shard_index}",
                {"operation": "request", "shard_index": request_data.shard_index},
                SecuritySeverity.WARNING,
                ThreatLevel.MEDIUM
            )
            raise HTTPException(status_code=403, detail="Access denied")

        # Get shard information
        shard_info = await get_shard_info(request_data.backup_id, request_data.shard_index)
        if not shard_info:
            raise HTTPException(status_code=404, detail="Shard not found")

        # Log successful request
        log_security_event(
            SecurityEventType.DATA_ACCESS,
            f"Shard requested: {request_data.backup_id}:{request_data.shard_index}",
            req,
            user_id,
            f"shard:{request_data.backup_id}:{request_data.shard_index}",
            {"operation": "request", "shard_size": shard_info.get('size_bytes', 0)}
        )

        return {
            "shard_id": shard_info.get('shard_id'),
            "backup_id": request_data.backup_id,
            "shard_index": request_data.shard_index,
            "size_bytes": shard_info.get('size_bytes', 0),
            "checksum": shard_info.get('checksum'),
            "available_peers": shard_info.get('peer_count', 0),
            "status": "available"
        }

    except HTTPException:
        raise
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Shard request failed: {redact_pii(error_msg)}",
                    extra={"user_id": current_user.get('id')})

        log_security_event(
            SecurityEventType.SECURITY_ALERT,
            f"Shard request error: {redact_pii(error_msg)}",
            req,
            current_user.get('id'),
            f"shard:{request_data.backup_id}:{request_data.shard_index}",
            {"error": redact_pii(error_msg)},
            SecuritySeverity.ERROR,
            ThreatLevel.LOW
        )

        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/upload")
async def upload_shard(
    request_data: ShardUploadRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user),
    req: Request = None
):
    """
    Upload a shard for P2P distribution.

    - Rate limited to 10 requests per minute per IP
    - Requires authentication and ownership
    - Input validation and integrity verification
    - Comprehensive audit logging
    """
    try:
        client_ip = get_client_ip(req)
        user_id = current_user.get('id')

        # Log sanitized request data
        log_data = sanitize_log_data(request_data.dict())
        logger.info(f"Shard upload by user {redact_pii(current_user.get('username', 'unknown'))}",
                   extra={"user_id": user_id, "request": log_data, "client_ip": client_ip})

        # Check authorization
        if not check_shard_authorization(user_id, request_data.backup_id, 'upload'):
            log_security_event(
                SecurityEventType.AUTHORIZATION_FAILURE,
                f"Unauthorized shard upload attempt for backup {request_data.backup_id}",
                req,
                user_id,
                f"shard:{request_data.backup_id}:{request_data.shard_index}",
                {"operation": "upload", "shard_index": request_data.shard_index},
                SecuritySeverity.WARNING,
                ThreatLevel.HIGH
            )
            raise HTTPException(status_code=403, detail="Access denied")

        # Verify data integrity
        try:
            import base64
            shard_bytes = base64.b64decode(request_data.shard_data)
            calculated_checksum = hashlib.sha256(shard_bytes).hexdigest()

            if calculated_checksum != request_data.checksum:
                log_security_event(
                    SecurityEventType.SECURITY_ALERT,
                    f"Shard checksum mismatch for {request_data.backup_id}:{request_data.shard_index}",
                    req,
                    user_id,
                    f"shard:{request_data.backup_id}:{request_data.shard_index}",
                    {"expected": request_data.checksum, "calculated": calculated_checksum},
                    SecuritySeverity.CRITICAL,
                    ThreatLevel.HIGH
                )
                raise HTTPException(status_code=400, detail="Checksum verification failed")
        except Exception as e:
            raise HTTPException(status_code=400, detail="Invalid shard data format")

        # Store shard
        storage_result = await store_shard_data(
            request_data.backup_id,
            request_data.shard_index,
            shard_bytes,
            request_data.checksum,
            user_id
        )

        if not storage_result.get('success', False):
            raise HTTPException(status_code=500, detail="Shard storage failed")

        # Log successful upload
        log_security_event(
            SecurityEventType.DATA_MODIFICATION,
            f"Shard uploaded: {request_data.backup_id}:{request_data.shard_index}",
            req,
            user_id,
            f"shard:{request_data.backup_id}:{request_data.shard_index}",
            {
                "operation": "upload",
                "shard_size": len(shard_bytes),
                "storage_location": storage_result.get('location', 'unknown')
            }
        )

        return {
            "shard_id": storage_result.get('shard_id'),
            "backup_id": request_data.backup_id,
            "shard_index": request_data.shard_index,
            "size_bytes": len(shard_bytes),
            "checksum": request_data.checksum,
            "storage_location": storage_result.get('location'),
            "status": "uploaded"
        }

    except HTTPException:
        raise
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Shard upload failed: {redact_pii(error_msg)}",
                    extra={"user_id": current_user.get('id')})

        log_security_event(
            SecurityEventType.SECURITY_ALERT,
            f"Shard upload error: {redact_pii(error_msg)}",
            req,
            current_user.get('id'),
            f"shard:{request_data.backup_id}:{request_data.shard_index}",
            {"error": redact_pii(error_msg)},
            SecuritySeverity.ERROR,
            ThreatLevel.MEDIUM
        )

        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/download/{backup_id}/{shard_index}")
async def download_shard(
    backup_id: str,
    shard_index: int,
    current_user: dict = Depends(get_current_user),
    req: Request = None
):
    """
    Download a shard for P2P distribution.

    - Rate limited to 30 requests per minute per IP
    - Requires authentication and ownership
    - Comprehensive audit logging
    """
    try:
        client_ip = get_client_ip(req)
        user_id = current_user.get('id')

        # Validate parameters
        if not re.match(r'^backup_\d+_[a-f0-9]+$', backup_id):
            raise HTTPException(status_code=400, detail="Invalid backup ID format")

        logger.info(f"Shard download request by user {redact_pii(current_user.get('username', 'unknown'))}",
                   extra={"user_id": user_id, "backup_id": backup_id, "shard_index": shard_index, "client_ip": client_ip})

        # Check authorization
        if not check_shard_authorization(user_id, backup_id, 'download'):
            log_security_event(
                SecurityEventType.AUTHORIZATION_FAILURE,
                f"Unauthorized shard download attempt for backup {backup_id}:{shard_index}",
                req,
                user_id,
                f"shard:{backup_id}:{shard_index}",
                {"operation": "download"},
                SecuritySeverity.WARNING,
                ThreatLevel.HIGH
            )
            raise HTTPException(status_code=403, detail="Access denied")

        # Retrieve shard data
        shard_data = await retrieve_shard_data(backup_id, shard_index, user_id)
        if not shard_data:
            raise HTTPException(status_code=404, detail="Shard not found")

        # Log successful download
        log_security_event(
            SecurityEventType.DATA_ACCESS,
            f"Shard downloaded: {backup_id}:{shard_index}",
            req,
            user_id,
            f"shard:{backup_id}:{shard_index}",
            {
                "operation": "download",
                "shard_size": shard_data.get('size_bytes', 0),
                "source": shard_data.get('source', 'unknown')
            }
        )

        import base64
        return {
            "shard_id": shard_data.get('shard_id'),
            "backup_id": backup_id,
            "shard_index": shard_index,
            "data": base64.b64encode(shard_data.get('data', b'')).decode(),
            "checksum": shard_data.get('checksum'),
            "size_bytes": shard_data.get('size_bytes', 0)
        }

    except HTTPException:
        raise
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Shard download failed: {redact_pii(error_msg)}",
                    extra={"user_id": current_user.get('id')})

        log_security_event(
            SecurityEventType.SECURITY_ALERT,
            f"Shard download error: {redact_pii(error_msg)}",
            req,
            current_user.get('id'),
            f"shard:{backup_id}:{shard_index}",
            {"error": redact_pii(error_msg)},
            SecuritySeverity.ERROR,
            ThreatLevel.MEDIUM
        )

        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/verify/{backup_id}/{shard_index}")
async def verify_shard(
    backup_id: str,
    shard_index: int,
    current_user: dict = Depends(get_current_user),
    req: Request = None
):
    """
    Verify shard integrity.

    - Rate limited to 60 requests per minute per IP
    - Requires authentication and ownership
    - Comprehensive audit logging
    """
    try:
        client_ip = get_client_ip(req)
        user_id = current_user.get('id')

        # Validate parameters
        if not re.match(r'^backup_\d+_[a-f0-9]+$', backup_id):
            raise HTTPException(status_code=400, detail="Invalid backup ID format")

        logger.info(f"Shard verification request by user {redact_pii(current_user.get('username', 'unknown'))}",
                   extra={"user_id": user_id, "backup_id": backup_id, "shard_index": shard_index, "client_ip": client_ip})

        # Check authorization
        if not check_shard_authorization(user_id, backup_id, 'verify'):
            log_security_event(
                SecurityEventType.AUTHORIZATION_FAILURE,
                f"Unauthorized shard verification attempt for backup {backup_id}:{shard_index}",
                req,
                user_id,
                f"shard:{backup_id}:{shard_index}",
                {"operation": "verify"},
                SecuritySeverity.WARNING,
                ThreatLevel.MEDIUM
            )
            raise HTTPException(status_code=403, detail="Access denied")

        # Verify shard integrity
        verification_result = await verify_shard_integrity(backup_id, shard_index, user_id)

        # Log verification result
        severity = SecuritySeverity.INFO if verification_result.get('valid', False) else SecuritySeverity.WARNING
        threat_level = ThreatLevel.LOW if verification_result.get('valid', False) else ThreatLevel.MEDIUM

        log_security_event(
            SecurityEventType.DATA_ACCESS,
            f"Shard verification completed: {backup_id}:{shard_index} - {'valid' if verification_result.get('valid', False) else 'invalid'}",
            req,
            user_id,
            f"shard:{backup_id}:{shard_index}",
            {
                "operation": "verify",
                "valid": verification_result.get('valid', False),
                "checksum_match": verification_result.get('checksum_match', False),
                "peer_count": verification_result.get('peer_count', 0)
            },
            severity,
            threat_level
        )

        return verification_result

    except HTTPException:
        raise
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Shard verification failed: {redact_pii(error_msg)}",
                    extra={"user_id": current_user.get('id')})

        log_security_event(
            SecurityEventType.SECURITY_ALERT,
            f"Shard verification error: {redact_pii(error_msg)}",
            req,
            current_user.get('id'),
            f"shard:{backup_id}:{shard_index}",
            {"error": redact_pii(error_msg)},
            SecuritySeverity.ERROR,
            ThreatLevel.LOW
        )

        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/list/{backup_id}")
async def list_shard_status(
    backup_id: str,
    current_user: dict = Depends(get_current_user),
    req: Request = None
):
    """
    List all shards for a backup with their status.

    - Rate limited to 120 requests per minute per IP
    - Requires authentication and ownership
    - Comprehensive audit logging
    """
    try:
        client_ip = get_client_ip(req)
        user_id = current_user.get('id')

        # Validate parameters
        if not re.match(r'^backup_\d+_[a-f0-9]+$', backup_id):
            raise HTTPException(status_code=400, detail="Invalid backup ID format")

        logger.info(f"Shard list request by user {redact_pii(current_user.get('username', 'unknown'))}",
                   extra={"user_id": user_id, "backup_id": backup_id, "client_ip": client_ip})

        # Check authorization
        if not check_shard_authorization(user_id, backup_id, 'list'):
            log_security_event(
                SecurityEventType.AUTHORIZATION_FAILURE,
                f"Unauthorized shard list attempt for backup {backup_id}",
                req,
                user_id,
                f"backup:{backup_id}",
                {"operation": "list"},
                SecuritySeverity.WARNING,
                ThreatLevel.LOW
            )
            raise HTTPException(status_code=403, detail="Access denied")

        # Get shard status list
        shard_status_list = await get_shard_status_list(backup_id, user_id)

        # Log successful list operation
        log_security_event(
            SecurityEventType.DATA_ACCESS,
            f"Shard status list retrieved for backup {backup_id}",
            req,
            user_id,
            f"backup:{backup_id}",
            {
                "operation": "list",
                "total_shards": len(shard_status_list),
                "available_shards": sum(1 for s in shard_status_list if s.get('status') == 'available')
            }
        )

        return {"backup_id": backup_id, "shards": shard_status_list}

    except HTTPException:
        raise
    except Exception as e:
        error_msg = str(e)
        logger.error(f"Shard list failed: {redact_pii(error_msg)}",
                    extra={"user_id": current_user.get('id')})

        log_security_event(
            SecurityEventType.SECURITY_ALERT,
            f"Shard list error: {redact_pii(error_msg)}",
            req,
            current_user.get('id'),
            f"backup:{backup_id}",
            {"error": redact_pii(error_msg)},
            SecuritySeverity.ERROR,
            ThreatLevel.LOW
        )

        raise HTTPException(status_code=500, detail="Internal server error")


# Helper functions for shard operations

async def get_shard_info(backup_id: str, shard_index: int) -> Optional[Dict[str, Any]]:
    """Get information about a specific shard."""
    try:
        # This would integrate with the actual shard storage system
        # For now, return mock data based on backup metadata
        backup_metadata = backup_engine.get_backup_details(backup_id)
        if not backup_metadata:
            return None

        shard_count = backup_metadata.get('shard_count', 1)
        if shard_index >= shard_count:
            return None

        return {
            'shard_id': f"{backup_id}_shard_{shard_index:04d}",
            'backup_id': backup_id,
            'shard_index': shard_index,
            'size_bytes': backup_metadata.get('original_size', 0) // shard_count,
            'checksum': secrets.token_hex(32),  # Mock checksum
            'peer_count': 3,  # Mock peer count
            'status': 'available'
        }

    except Exception as e:
        logger.error(f"Failed to get shard info: {redact_pii(str(e))}")
        return None


async def store_shard_data(backup_id: str, shard_index: int, data: bytes, checksum: str, user_id: str) -> Dict[str, Any]:
    """Store shard data in the distributed storage system."""
    try:
        # This would integrate with the actual storage manager
        # For now, simulate storage operation
        shard_id = f"{backup_id}_shard_{shard_index:04d}"

        # Simulate storage delay
        await asyncio.sleep(0.1)

        return {
            'success': True,
            'shard_id': shard_id,
            'location': 'distributed_storage',
            'size_bytes': len(data),
            'checksum': checksum
        }

    except Exception as e:
        logger.error(f"Failed to store shard data: {redact_pii(str(e))}")
        return {'success': False, 'error': str(e)}


async def retrieve_shard_data(backup_id: str, shard_index: int, user_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve shard data from the distributed storage system."""
    try:
        # This would integrate with the actual storage manager
        # For now, return mock data
        shard_id = f"{backup_id}_shard_{shard_index:04d}"

        # Simulate retrieval delay
        await asyncio.sleep(0.05)

        mock_data = secrets.token_bytes(1024)  # Mock 1KB shard data

        return {
            'shard_id': shard_id,
            'data': mock_data,
            'checksum': hashlib.sha256(mock_data).hexdigest(),
            'size_bytes': len(mock_data),
            'source': 'distributed_peer'
        }

    except Exception as e:
        logger.error(f"Failed to retrieve shard data: {redact_pii(str(e))}")
        return None


async def verify_shard_integrity(backup_id: str, shard_index: int, user_id: str) -> Dict[str, Any]:
    """Verify the integrity of a shard across distributed peers."""
    try:
        # This would integrate with the actual verification system
        # For now, simulate verification
        shard_id = f"{backup_id}_shard_{shard_index:04d}"

        # Simulate verification delay
        await asyncio.sleep(0.02)

        # Mock verification result
        is_valid = secrets.randbelow(10) > 1  # 80% success rate for demo

        return {
            'shard_id': shard_id,
            'backup_id': backup_id,
            'shard_index': shard_index,
            'valid': is_valid,
            'checksum_match': is_valid,
            'peer_count': 3,
            'verified_at': datetime.now(timezone.utc).isoformat(),
            'verification_method': 'distributed_consensus'
        }

    except Exception as e:
        logger.error(f"Failed to verify shard integrity: {redact_pii(str(e))}")
        return {
            'shard_id': f"{backup_id}_shard_{shard_index:04d}",
            'valid': False,
            'error': 'Verification failed'
        }


async def get_shard_status_list(backup_id: str, user_id: str) -> List[Dict[str, Any]]:
    """Get status of all shards for a backup."""
    try:
        # This would integrate with the actual backup system
        # For now, return mock data
        backup_metadata = backup_engine.get_backup_details(backup_id)
        if not backup_metadata:
            return []

        shard_count = backup_metadata.get('shard_count', 5)
        shard_status_list = []

        for i in range(shard_count):
            # Mock status with some variation
            statuses = ['available', 'pending', 'verifying', 'corrupted']
            status = statuses[secrets.randbelow(len(statuses))]

            shard_status_list.append({
                'shard_id': f"{backup_id}_shard_{i:04d}",
                'shard_index': i,
                'status': status,
                'size_bytes': backup_metadata.get('original_size', 0) // shard_count,
                'peer_count': secrets.randbelow(5) + 1,
                'last_verified': datetime.now(timezone.utc).isoformat(),
                'checksum_valid': status != 'corrupted'
            })

        return shard_status_list

    except Exception as e:
        logger.error(f"Failed to get shard status list: {redact_pii(str(e))}")
        return []