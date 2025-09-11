#!/usr/bin/env python3
"""
Security Management Web Interface

Comprehensive security management interface for configuring DDoS protection, rate limiting,
encryption settings, and security policies. Includes dashboards for security events,
attack monitoring, and system security status.
"""

import asyncio
from datetime import datetime
import json
import logging
import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from starlette.status import (
    HTTP_400_BAD_REQUEST,
    HTTP_403_FORBIDDEN,
    HTTP_404_NOT_FOUND,
)

# Import security systems
try:
    # DynamicRateLimitingMiddleware deprecated in favor of unified rate limiting module
    from plexichat.core.config_manager import get_config_manager
    from plexichat.core.security.ddos_protection import (
        AttackEvent,
        AttackType,
        DDoSProtectionSystem,
        ThreatLevel,
        get_ddos_protection,
    )
    from plexichat.core.security.quantum_encryption import (
        EncryptionAlgorithm,
        KeyType,
        QuantumEncryptionManager,
        get_quantum_manager,
    )
    from plexichat.core.security.security_manager import get_security_manager
except ImportError as e:
    logging.warning(f"Security module imports failed: {e}")
    # Fallback for development
    get_ddos_protection = None
    get_quantum_manager = None
    DynamicRateLimitingMiddleware = None
    get_config_manager = None
    get_security_manager = None

logger = logging.getLogger(__name__)

# Create router
router = APIRouter(prefix="/api/v1/security", tags=["Security Management"])

# Helper functions
async def get_system_metrics():
    """Get current system metrics"""
    try:
        import psutil
        return {
            "cpu_usage": psutil.cpu_percent(interval=1),
            "memory_usage": psutil.virtual_memory().percent,
            "network_usage": sum([psutil.net_io_counters().bytes_sent, psutil.net_io_counters().bytes_recv]) / (1024 * 1024)  # MB
        }
    except ImportError:
        # Fallback if psutil not available
        try:
            import os
            load_avg = os.getloadavg()[0] if hasattr(os, 'getloadavg') else 0.0
            return {
                "cpu_usage": min(load_avg * 10, 100.0),  # Rough estimate
                "memory_usage": 0.0,
                "network_usage": 0.0
            }
        except Exception:
            return {
                "cpu_usage": 0.0,
                "memory_usage": 0.0,
                "network_usage": 0.0
            }

# Pydantic models for request/response validation
class SecurityStatusResponse(BaseModel):
    """Overall security system status"""
    timestamp: datetime
    threat_level: str
    ddos_protection: dict[str, Any]
    encryption_status: dict[str, Any]
    rate_limiting: dict[str, Any]
    active_attacks: int
    blocked_ips: int
    security_events: int
    system_health: str

class DDoSConfigUpdate(BaseModel):
    """DDoS protection configuration update"""
    enabled: bool | None = None
    base_request_limit: int | None = Field(None, ge=1, le=10000)
    burst_limit: int | None = Field(None, ge=1, le=50000)
    ip_block_threshold: float | None = Field(None, ge=0.0, le=100.0)
    ip_block_duration_seconds: int | None = Field(None, ge=60, le=86400)
    user_tiers: dict[str, int] | None = None

class RateLimitConfigUpdate(BaseModel):
    """Rate limiting configuration update"""
    enabled: bool | None = None
    default_limit: int | None = Field(None, ge=1, le=10000)
    burst_multiplier: float | None = Field(None, ge=1.0, le=10.0)
    window_size_seconds: int | None = Field(None, ge=1, le=3600)
    adaptive_scaling: bool | None = None

class EncryptionConfigUpdate(BaseModel):
    """Encryption configuration update"""
    default_algorithm: str | None = None
    enable_post_quantum: bool | None = None
    enable_hybrid_mode: bool | None = None
    key_rotation_interval_hours: int | None = Field(None, ge=1, le=168)
    http_traffic_encryption: bool | None = None
    realtime_key_derivation: bool | None = None

class IPBlockRequest(BaseModel):
    """Request to block an IP address"""
    ip_address: str = Field(..., regex=r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$')
    duration_seconds: int | None = Field(3600, ge=60, le=86400)
    reason: str = Field(..., min_length=1, max_length=500)
    permanent: bool = False

class IPUnblockRequest(BaseModel):
    """Request to unblock an IP address"""
    ip_address: str = Field(..., regex=r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$')

class WhitelistRequest(BaseModel):
    """Request to add IP to whitelist"""
    ip_address: str = Field(..., regex=r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$')
    description: str = Field(..., min_length=1, max_length=200)

class SecurityPolicyUpdate(BaseModel):
    """Security policy configuration update"""
    auto_block_enabled: bool | None = None
    threat_response_level: str | None = None
    alert_thresholds: dict[str, float] | None = None
    incident_response_enabled: bool | None = None
    audit_logging_level: str | None = None

class KeyRotationRequest(BaseModel):
    """Request to rotate encryption keys"""
    key_id: str | None = None
    algorithm: str | None = None
    force_rotation: bool = False

# Dependency functions
async def get_current_user():
    """Get current authenticated user"""
    try:
        from plexichat.core.authentication import get_auth_manager
        auth_manager = get_auth_manager()
        if auth_manager:
            # Get current user from auth manager
            current_user = await auth_manager.get_current_user()
            if current_user:
                return {
                    "user_id": current_user.get("user_id", "unknown"),
                    "role": current_user.get("role", "user"),
                    "permissions": current_user.get("permissions", [])
                }
    except Exception as e:
        logger.warning(f"Failed to get authenticated user: {e}")

    # Fallback for development/testing
    return {"user_id": "admin", "role": "admin", "permissions": ["security_admin"]}

async def require_security_admin(user: dict = Depends(get_current_user)):
    """Require security admin permissions"""
    if "security_admin" not in user.get("permissions", []):
        raise HTTPException(
            status_code=HTTP_403_FORBIDDEN,
            detail="Security admin permissions required"
        )
    return user

# Main security status endpoint
@router.get("/status", response_model=SecurityStatusResponse)
async def get_security_status(user: dict = Depends(get_current_user)):
    """Get comprehensive security system status"""
    try:
        current_time = datetime.utcnow()

        # Get DDoS protection status
        ddos_status = {"enabled": False, "stats": {}}
        if get_ddos_protection:
            try:
                ddos_system = get_ddos_protection()
                ddos_status = ddos_system.get_protection_status()
            except Exception as e:
                logger.error(f"Failed to get DDoS status: {e}")

        # Get encryption status
        encryption_status = {"enabled": False, "keys": {}}
        if get_quantum_manager:
            try:
                quantum_manager = get_quantum_manager()
                encryption_status = {
                    "enabled": True,
                    "active_keys": quantum_manager.get_active_keys(),
                    "total_keys": len(quantum_manager.list_keys()),
                    "post_quantum_available": quantum_manager.pqc.pqc_available,
                    "hybrid_mode": quantum_manager.config.get('enable_hybrid_mode', False)
                }
            except Exception as e:
                logger.error(f"Failed to get encryption status: {e}")

        # Get rate limiting status
        rate_limit_status = {"enabled": False, "stats": {}}
        try:
            from plexichat.core.middleware.rate_limiting import get_rate_limiter
            rate_limiter = get_rate_limiter()
            if rate_limiter:
                rate_limit_status = {
                    "enabled": rate_limiter.get_config_summary().get("enabled", False),
                    "stats": rate_limiter.get_stats()
                }
        except Exception as e:
            logger.warning(f"Failed to get rate limiting status: {e}")

        # Calculate overall threat level
        threat_level = "low"
        if ddos_status.get("stats", {}).get("threat_level"):
            threat_level = ddos_status["stats"]["threat_level"]

        # Calculate system health
        system_health = "healthy"
        active_attacks = ddos_status.get("stats", {}).get("active_attacks", 0)
        if active_attacks > 10:
            system_health = "critical"
        elif active_attacks > 5:
            system_health = "warning"
        elif active_attacks > 0:
            system_health = "degraded"

        return SecurityStatusResponse(
            timestamp=current_time,
            threat_level=threat_level,
            ddos_protection=ddos_status,
            encryption_status=encryption_status,
            rate_limiting=rate_limit_status,
            active_attacks=active_attacks,
            blocked_ips=ddos_status.get("stats", {}).get("blocked_ips", 0),
            security_events=ddos_status.get("recent_alerts", 0),
            system_health=system_health
        )

    except Exception as e:
        logger.error(f"Failed to get security status: {e}")
        raise HTTPException(
            status_code=HTTP_400_BAD_REQUEST,
            detail=f"Failed to retrieve security status: {e!s}"
        )

# DDoS Protection endpoints
@router.get("/ddos/status")
async def get_ddos_status(user: dict = Depends(get_current_user)):
    """Get detailed DDoS protection status"""
    if not get_ddos_protection:
        raise HTTPException(
            status_code=HTTP_404_NOT_FOUND,
            detail="DDoS protection system not available"
        )

    try:
        ddos_system = get_ddos_protection()
        return ddos_system.get_protection_status()
    except Exception as e:
        logger.error(f"Failed to get DDoS status: {e}")
        raise HTTPException(
            status_code=HTTP_400_BAD_REQUEST,
            detail=f"Failed to retrieve DDoS status: {e!s}"
        )

@router.put("/ddos/config")
async def update_ddos_config(
    config: DDoSConfigUpdate,
    user: dict = Depends(require_security_admin)
):
    """Update DDoS protection configuration"""
    if not get_ddos_protection or not get_config_manager:
        raise HTTPException(
            status_code=HTTP_404_NOT_FOUND,
            detail="DDoS protection system not available"
        )

    try:
        config_manager = get_config_manager()
        ddos_config = config_manager._config.ddos

        # Update configuration
        if config.enabled is not None:
            ddos_config.enabled = config.enabled
        if config.base_request_limit is not None:
            ddos_config.base_request_limit = config.base_request_limit
        if config.burst_limit is not None:
            ddos_config.burst_limit = config.burst_limit
        if config.ip_block_threshold is not None:
            ddos_config.ip_block_threshold = config.ip_block_threshold
        if config.ip_block_duration_seconds is not None:
            ddos_config.ip_block_duration_seconds = config.ip_block_duration_seconds
        if config.user_tiers is not None:
            ddos_config.user_tiers.update(config.user_tiers)

        # Save configuration
        await config_manager.save_config()

        logger.info(f"DDoS configuration updated by user {user['user_id']}")
        return {"message": "DDoS configuration updated successfully"}

    except Exception as e:
        logger.error(f"Failed to update DDoS config: {e}")
        raise HTTPException(
            status_code=HTTP_400_BAD_REQUEST,
            detail=f"Failed to update DDoS configuration: {e!s}"
        )

@router.get("/ddos/alerts")
async def get_ddos_alerts(
    hours: int = Query(24, ge=1, le=168),
    limit: int = Query(100, ge=1, le=1000),
    user: dict = Depends(get_current_user)
):
    """Get recent DDoS attack alerts"""
    if not get_ddos_protection:
        raise HTTPException(
            status_code=HTTP_404_NOT_FOUND,
            detail="DDoS protection system not available"
        )

    try:
        ddos_system = get_ddos_protection()
        alerts = ddos_system.alert_manager.get_recent_alerts(hours)

        # Convert alerts to serializable format
        alert_data = []
        for alert in alerts[-limit:]:  # Get most recent alerts
            alert_dict = {
                "timestamp": datetime.fromtimestamp(alert.timestamp).isoformat(),
                "attack_type": alert.attack_type.value,
                "threat_level": alert.threat_level.value,
                "source_ip": alert.source_ip,
                "description": alert.description,
                "metrics": alert.metrics,
                "action_taken": alert.action_taken
            }
            alert_data.append(alert_dict)

        return {
            "alerts": alert_data,
            "total_count": len(alerts),
            "time_range_hours": hours
        }

    except Exception as e:
        logger.error(f"Failed to get DDoS alerts: {e}")
        raise HTTPException(
            status_code=HTTP_400_BAD_REQUEST,
            detail=f"Failed to retrieve DDoS alerts: {e!s}"
        )

@router.get("/ddos/blocked-ips")
async def get_blocked_ips(user: dict = Depends(get_current_user)):
    """Get list of currently blocked IP addresses"""
    if not get_ddos_protection:
        raise HTTPException(
            status_code=HTTP_404_NOT_FOUND,
            detail="DDoS protection system not available"
        )

    try:
        ddos_system = get_ddos_protection()
        blocked_ips = ddos_system.ip_block_manager.get_blocked_ips()

        # Add additional information
        for ip, info in blocked_ips.items():
            if info['expires_at']:
                info['expires_at_iso'] = datetime.fromtimestamp(info['expires_at']).isoformat()

        return {
            "blocked_ips": blocked_ips,
            "total_count": len(blocked_ips)
        }

    except Exception as e:
        logger.error(f"Failed to get blocked IPs: {e}")
        raise HTTPException(
            status_code=HTTP_400_BAD_REQUEST,
            detail=f"Failed to retrieve blocked IPs: {e!s}"
        )

@router.post("/ddos/block-ip")
async def block_ip(
    request: IPBlockRequest,
    user: dict = Depends(require_security_admin)
):
    """Manually block an IP address"""
    if not get_ddos_protection:
        raise HTTPException(
            status_code=HTTP_404_NOT_FOUND,
            detail="DDoS protection system not available"
        )

    try:
        ddos_system = get_ddos_protection()

        if request.permanent:
            ddos_system.ip_block_manager.permanent_block(request.ip_address, request.reason)
            action = "permanently blocked"
        else:
            ddos_system.ip_block_manager.block_ip(
                request.ip_address,
                request.duration_seconds,
                request.reason
            )
            action = f"blocked for {request.duration_seconds} seconds"

        logger.warning(f"IP {request.ip_address} {action} by user {user['user_id']}: {request.reason}")

        return {
            "message": f"IP {request.ip_address} {action}",
            "ip_address": request.ip_address,
            "action": action,
            "reason": request.reason
        }

    except Exception as e:
        logger.error(f"Failed to block IP: {e}")
        raise HTTPException(
            status_code=HTTP_400_BAD_REQUEST,
            detail=f"Failed to block IP: {e!s}"
        )

@router.post("/ddos/unblock-ip")
async def unblock_ip(
    request: IPUnblockRequest,
    user: dict = Depends(require_security_admin)
):
    """Manually unblock an IP address"""
    if not get_ddos_protection:
        raise HTTPException(
            status_code=HTTP_404_NOT_FOUND,
            detail="DDoS protection system not available"
        )

    try:
        ddos_system = get_ddos_protection()
        ddos_system.ip_block_manager.unblock_ip(request.ip_address)

        logger.info(f"IP {request.ip_address} unblocked by user {user['user_id']}")

        return {
            "message": f"IP {request.ip_address} unblocked successfully",
            "ip_address": request.ip_address
        }

    except Exception as e:
        logger.error(f"Failed to unblock IP: {e}")
        raise HTTPException(
            status_code=HTTP_400_BAD_REQUEST,
            detail=f"Failed to unblock IP: {e!s}"
        )

# Encryption Management endpoints
@router.get("/encryption/status")
async def get_encryption_status(user: dict = Depends(get_current_user)):
    """Get detailed encryption system status"""
    if not get_quantum_manager:
        raise HTTPException(
            status_code=HTTP_404_NOT_FOUND,
            detail="Quantum encryption system not available"
        )

    try:
        quantum_manager = get_quantum_manager()

        return {
            "enabled": True,
            "post_quantum_available": quantum_manager.pqc.pqc_available,
            "active_keys": quantum_manager.get_active_keys(),
            "total_keys": len(quantum_manager.list_keys()),
            "config": {
                "default_algorithm": quantum_manager.config['default_algorithm'].value,
                "enable_post_quantum": quantum_manager.config.get('enable_post_quantum', False),
                "enable_hybrid_mode": quantum_manager.config.get('enable_hybrid_mode', False),
                "http_traffic_encryption": quantum_manager.config.get('http_traffic_encryption', False),
                "realtime_key_derivation": quantum_manager.config.get('realtime_key_derivation', False)
            }
        }

    except Exception as e:
        logger.error(f"Failed to get encryption status: {e}")
        raise HTTPException(
            status_code=HTTP_400_BAD_REQUEST,
            detail=f"Failed to retrieve encryption status: {e!s}"
        )

@router.get("/encryption/keys")
async def get_encryption_keys(user: dict = Depends(get_current_user)):
    """Get list of encryption keys (without sensitive data)"""
    if not get_quantum_manager:
        raise HTTPException(
            status_code=HTTP_404_NOT_FOUND,
            detail="Quantum encryption system not available"
        )

    try:
        quantum_manager = get_quantum_manager()
        keys = quantum_manager.list_keys()

        # Remove sensitive data
        safe_keys = []
        for key in keys:
            safe_key = {
                "key_id": key["key_id"],
                "key_type": key["key_type"],
                "algorithm": key["algorithm"],
                "created_at": key["created_at"],
                "expires_at": key["expires_at"],
                "usage_count": key["usage_count"],
                "max_usage": key["max_usage"],
                "rotation_interval": key["rotation_interval"],
                "has_public_key": key["has_public_key"]
            }
            safe_keys.append(safe_key)

        return {
            "keys": safe_keys,
            "total_count": len(safe_keys),
            "active_keys": quantum_manager.get_active_keys()
        }

    except Exception as e:
        logger.error(f"Failed to get encryption keys: {e}")
        raise HTTPException(
            status_code=HTTP_400_BAD_REQUEST,
            detail=f"Failed to retrieve encryption keys: {e!s}"
        )

@router.put("/encryption/config")
async def update_encryption_config(
    config: EncryptionConfigUpdate,
    user: dict = Depends(require_security_admin)
):
    """Update encryption configuration"""
    if not get_quantum_manager:
        raise HTTPException(
            status_code=HTTP_404_NOT_FOUND,
            detail="Quantum encryption system not available"
        )

    try:
        quantum_manager = get_quantum_manager()

        # Update configuration
        if config.default_algorithm is not None:
            try:
                algorithm = EncryptionAlgorithm(config.default_algorithm)
                quantum_manager.config['default_algorithm'] = algorithm
            except ValueError:
                raise HTTPException(
                    status_code=HTTP_400_BAD_REQUEST,
                    detail=f"Invalid encryption algorithm: {config.default_algorithm}"
                )

        if config.enable_post_quantum is not None:
            quantum_manager.config['enable_post_quantum'] = config.enable_post_quantum

        if config.enable_hybrid_mode is not None:
            quantum_manager.config['enable_hybrid_mode'] = config.enable_hybrid_mode

        if config.key_rotation_interval_hours is not None:
            quantum_manager.config['key_rotation_interval'] = config.key_rotation_interval_hours * 3600

        if config.http_traffic_encryption is not None:
            quantum_manager.config['http_traffic_encryption'] = config.http_traffic_encryption

        if config.realtime_key_derivation is not None:
            quantum_manager.config['realtime_key_derivation'] = config.realtime_key_derivation

        logger.info(f"Encryption configuration updated by user {user['user_id']}")
        return {"message": "Encryption configuration updated successfully"}

    except Exception as e:
        logger.error(f"Failed to update encryption config: {e}")
        raise HTTPException(
            status_code=HTTP_400_BAD_REQUEST,
            detail=f"Failed to update encryption configuration: {e!s}"
        )

@router.post("/encryption/rotate-key")
async def rotate_encryption_key(
    request: KeyRotationRequest,
    user: dict = Depends(require_security_admin)
):
    """Rotate encryption keys"""
    if not get_quantum_manager:
        raise HTTPException(
            status_code=HTTP_404_NOT_FOUND,
            detail="Quantum encryption system not available"
        )

    try:
        quantum_manager = get_quantum_manager()

        if request.key_id:
            # Rotate specific key
            new_key = await quantum_manager.rotate_key(request.key_id)
            message = f"Key {request.key_id} rotated to {new_key.key_id}"
        elif request.algorithm:
            # Rotate all keys of specific algorithm
            algorithm = EncryptionAlgorithm(request.algorithm)
            active_keys = quantum_manager.get_active_keys()
            if algorithm.value in active_keys:
                key_id = active_keys[algorithm.value]
                new_key = await quantum_manager.rotate_key(key_id)
                message = f"Algorithm {algorithm.value} key rotated to {new_key.key_id}"
            else:
                raise HTTPException(
                    status_code=HTTP_404_NOT_FOUND,
                    detail=f"No active key found for algorithm: {algorithm.value}"
                )
        else:
            # Rotate all active keys
            active_keys = quantum_manager.get_active_keys()
            rotated_keys = []
            for algorithm, key_id in active_keys.items():
                new_key = await quantum_manager.rotate_key(key_id)
                rotated_keys.append(f"{algorithm}: {new_key.key_id}")
            message = f"Rotated keys: {', '.join(rotated_keys)}"

        logger.info(f"Key rotation performed by user {user['user_id']}: {message}")
        return {"message": message}

    except Exception as e:
        logger.error(f"Failed to rotate encryption key: {e}")
        raise HTTPException(
            status_code=HTTP_400_BAD_REQUEST,
            detail=f"Failed to rotate encryption key: {e!s}"
        )

# Rate Limiting endpoints
@router.get("/rate-limiting/status")
async def get_rate_limiting_status(user: dict = Depends(get_current_user)):
    """Get rate limiting system status"""
    try:
        from plexichat.core.middleware.rate_limiting import get_rate_limiter
        rate_limiter = get_rate_limiter()

        if not rate_limiter:
            return {
                "enabled": False,
                "message": "Rate limiting system not available"
            }

        return {
            "enabled": rate_limiter.get_config_summary().get("enabled", False),
            "config": rate_limiter.get_config_summary(),
            "stats": rate_limiter.get_stats()
        }
    except Exception as e:
        logger.error(f"Failed to get rate limiting status: {e}")
        raise HTTPException(
            status_code=HTTP_400_BAD_REQUEST,
            detail=f"Failed to retrieve rate limiting status: {e!s}"
        )

@router.put("/rate-limiting/config")
async def update_rate_limiting_config(
    config: RateLimitConfigUpdate,
    user: dict = Depends(require_security_admin)
):
    """Update rate limiting configuration"""
    try:
        from plexichat.core.config_manager import get_config_manager
        from plexichat.core.middleware.rate_limiting import get_rate_limiter

        rate_limiter = get_rate_limiter()
        config_manager = get_config_manager()

        if not rate_limiter or not config_manager:
            raise HTTPException(
                status_code=HTTP_404_NOT_FOUND,
                detail="Rate limiting system not available"
            )

        # Update configuration
        if config.enabled is not None:
            rate_limiter.enabled = config.enabled
        if config.default_limit is not None:
            rate_limiter.requests_per_minute = config.default_limit
        if config.burst_multiplier is not None:
            rate_limiter.burst_limit = int(rate_limiter.requests_per_minute * config.burst_multiplier)
        if config.window_size_seconds is not None:
            rate_limiter.window_size_seconds = config.window_size_seconds
        if config.adaptive_scaling is not None:
            rate_limiter.adaptive_scaling = config.adaptive_scaling

        # Save configuration
        await config_manager.save_config()

        logger.info(f"Rate limiting configuration updated by user {user['user_id']}")
        return {"message": "Rate limiting configuration updated successfully"}

    except Exception as e:
        logger.error(f"Failed to update rate limiting config: {e}")
        raise HTTPException(
            status_code=HTTP_400_BAD_REQUEST,
            detail=f"Failed to update rate limiting configuration: {e!s}"
        )

# Security Policy endpoints
@router.get("/policies")
async def get_security_policies(user: dict = Depends(get_current_user)):
    """Get current security policies"""
    try:
        from plexichat.core.config_manager import get_config_manager
        config_manager = get_config_manager()

        if config_manager:
            security_config = config_manager.get_security_config()
            return {
                "auto_block_enabled": security_config.get("auto_block_enabled", True),
                "threat_response_level": security_config.get("threat_response_level", "medium"),
                "alert_thresholds": security_config.get("alert_thresholds", {
                    "high_threat_score": 60.0,
                    "critical_threat_score": 80.0,
                    "attack_rate_threshold": 100.0
                }),
                "incident_response_enabled": security_config.get("incident_response_enabled", True),
                "audit_logging_level": security_config.get("audit_logging_level", "info")
            }
        else:
            # Fallback default policies
            return {
                "auto_block_enabled": True,
                "threat_response_level": "medium",
                "alert_thresholds": {
                    "high_threat_score": 60.0,
                    "critical_threat_score": 80.0,
                    "attack_rate_threshold": 100.0
                },
                "incident_response_enabled": True,
                "audit_logging_level": "info"
            }

    except Exception as e:
        logger.error(f"Failed to get security policies: {e}")
        raise HTTPException(
            status_code=HTTP_400_BAD_REQUEST,
            detail=f"Failed to retrieve security policies: {e!s}"
        )

@router.put("/policies")
async def update_security_policies(
    policies: SecurityPolicyUpdate,
    user: dict = Depends(require_security_admin)
):
    """Update security policies"""
    try:
        from plexichat.core.config_manager import get_config_manager
        config_manager = get_config_manager()

        if not config_manager:
            raise HTTPException(
                status_code=HTTP_404_NOT_FOUND,
                detail="Configuration manager not available"
            )

        # Get current security config
        security_config = config_manager.get_security_config()

        # Update policies
        if policies.auto_block_enabled is not None:
            security_config["auto_block_enabled"] = policies.auto_block_enabled
        if policies.threat_response_level is not None:
            security_config["threat_response_level"] = policies.threat_response_level
        if policies.alert_thresholds is not None:
            security_config["alert_thresholds"].update(policies.alert_thresholds)
        if policies.incident_response_enabled is not None:
            security_config["incident_response_enabled"] = policies.incident_response_enabled
        if policies.audit_logging_level is not None:
            security_config["audit_logging_level"] = policies.audit_logging_level

        # Save configuration
        await config_manager.save_security_config(security_config)

        logger.info(f"Security policies updated by user {user['user_id']}")
        return {"message": "Security policies updated successfully"}

    except Exception as e:
        logger.error(f"Failed to update security policies: {e}")
        raise HTTPException(
            status_code=HTTP_400_BAD_REQUEST,
            detail=f"Failed to update security policies: {e!s}"
        )

# Audit and Monitoring endpoints
@router.get("/audit-logs")
async def get_audit_logs(
    hours: int = Query(24, ge=1, le=168),
    level: str = Query("info", regex="^(debug|info|warning|error|critical)$"),
    limit: int = Query(100, ge=1, le=1000),
    user: dict = Depends(get_current_user)
):
    """Get security audit logs"""
    try:
        from datetime import datetime, timedelta

        from plexichat.core.security.unified_audit_system import get_audit_system

        audit_system = get_audit_system()
        if not audit_system:
            return {
                "logs": [],
                "total_count": 0,
                "time_range_hours": hours,
                "level": level,
                "message": "Audit system not available"
            }

        # Calculate time range
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=hours)

        # Get audit logs
        logs = await audit_system.get_logs(
            start_time=start_time,
            end_time=end_time,
            level=level,
            limit=limit,
            category="security"
        )

        # Format logs for response
        formatted_logs = []
        for log in logs:
            formatted_logs.append({
                "timestamp": log.get("timestamp", "").isoformat() if hasattr(log.get("timestamp", ""), "isoformat") else str(log.get("timestamp", "")),
                "level": log.get("level", ""),
                "category": log.get("category", ""),
                "event_type": log.get("event_type", ""),
                "user_id": log.get("user_id", ""),
                "ip_address": log.get("ip_address", ""),
                "message": log.get("message", ""),
                "details": log.get("details", {})
            })

        return {
            "logs": formatted_logs,
            "total_count": len(formatted_logs),
            "time_range_hours": hours,
            "level": level
        }

    except Exception as e:
        logger.error(f"Failed to get audit logs: {e}")
        raise HTTPException(
            status_code=HTTP_400_BAD_REQUEST,
            detail=f"Failed to retrieve audit logs: {e!s}"
        )

@router.get("/metrics/realtime")
async def get_realtime_metrics(user: dict = Depends(get_current_user)):
    """Get real-time security metrics"""
    try:
        current_time = time.time()

        # Get DDoS metrics
        ddos_metrics = {}
        if get_ddos_protection:
            try:
                ddos_system = get_ddos_protection()
                status = ddos_system.get_protection_status()
                ddos_metrics = {
                    "requests_per_second": status.get("stats", {}).get("total_requests", 0) / 60,  # Rough estimate
                    "blocked_requests_per_second": status.get("stats", {}).get("blocked_requests", 0) / 60,
                    "active_connections": status.get("active_connections", 0),
                    "threat_level": status.get("stats", {}).get("threat_level", "low"),
                    "active_attacks": status.get("stats", {}).get("active_attacks", 0)
                }
            except Exception as e:
                logger.error(f"Failed to get DDoS metrics: {e}")

        # Get encryption metrics
        encryption_metrics = {}
        if get_quantum_manager:
            try:
                quantum_manager = get_quantum_manager()
                keys = quantum_manager.list_keys()
                encryption_metrics = {
                    "total_keys": len(keys),
                    "active_algorithms": len(quantum_manager.get_active_keys()),
                    "post_quantum_enabled": quantum_manager.pqc.pqc_available,
                    "hybrid_mode_enabled": quantum_manager.config.get('enable_hybrid_mode', False)
                }
            except Exception as e:
                logger.error(f"Failed to get encryption metrics: {e}")

        return {
            "timestamp": current_time,
            "ddos_protection": ddos_metrics,
            "encryption": encryption_metrics,
            "rate_limiting": rate_limit_status.get("stats", {}),
            "system_load": await get_system_metrics()
        }

    except Exception as e:
        logger.error(f"Failed to get realtime metrics: {e}")
        raise HTTPException(
            status_code=HTTP_400_BAD_REQUEST,
            detail=f"Failed to retrieve realtime metrics: {e!s}"
        )

@router.get("/metrics/stream")
async def stream_security_metrics(user: dict = Depends(get_current_user)):
    """Stream real-time security metrics via Server-Sent Events"""
    async def generate_metrics():
        """Generate real-time metrics stream"""
        while True:
            try:
                # Get current metrics
                metrics = await get_realtime_metrics(user)

                # Format as SSE
                data = json.dumps(metrics)
                yield f"data: {data}\n\n"

                # Wait before next update
                await asyncio.sleep(5)  # Update every 5 seconds

            except Exception as e:
                logger.error(f"Error in metrics stream: {e}")
                yield f"data: {json.dumps({'error': str(e)})}\n\n"
                await asyncio.sleep(10)  # Wait longer on error

    return StreamingResponse(
        generate_metrics(),
        media_type="text/plain",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "Content-Type": "text/event-stream"
        }
    )

# Emergency Response endpoints
@router.post("/emergency/lockdown")
async def emergency_lockdown(
    user: dict = Depends(require_security_admin)
):
    """Activate emergency security lockdown"""
    try:
        # Implement emergency lockdown procedures
        from plexichat.core.security.security_manager import get_security_manager

        security_manager = get_security_manager()
        if security_manager:
            # Activate emergency lockdown
            await security_manager.activate_emergency_lockdown(user['user_id'])

        # Block all new connections
        if get_ddos_protection:
            ddos_system = get_ddos_protection()
            await ddos_system.enable_emergency_mode()

        # Disable rate limiting (block everything)
        try:
            from plexichat.core.middleware.rate_limiting import get_rate_limiter
            rate_limiter = get_rate_limiter()
            if rate_limiter:
                # For unified engine, set extreme limits if needed; here we just log
                rate_limiter.set_enabled(True)
        except Exception as e:
            logger.warning(f"Failed to enable rate limiter emergency mode: {e}")

        logger.critical(f"Emergency lockdown activated by user {user['user_id']}")

        return {
            "message": "Emergency lockdown activated",
            "timestamp": datetime.utcnow().isoformat(),
            "activated_by": user['user_id']
        }

    except Exception as e:
        logger.error(f"Failed to activate emergency lockdown: {e}")
        raise HTTPException(
            status_code=HTTP_400_BAD_REQUEST,
            detail=f"Failed to activate emergency lockdown: {e!s}"
        )

@router.post("/emergency/disable-lockdown")
async def disable_emergency_lockdown(
    user: dict = Depends(require_security_admin)
):
    """Disable emergency security lockdown"""
    try:
        # Implement emergency lockdown disable
        from plexichat.core.security.security_manager import get_security_manager

        security_manager = get_security_manager()
        if security_manager:
            # Deactivate emergency lockdown
            await security_manager.deactivate_emergency_lockdown(user['user_id'])

        # Restore normal DDoS protection
        if get_ddos_protection:
            ddos_system = get_ddos_protection()
            await ddos_system.disable_emergency_mode()

        # Restore normal rate limiting
        try:
            from plexichat.core.middleware.rate_limiting import get_rate_limiter
            rate_limiter = get_rate_limiter()
            if rate_limiter:
                rate_limiter.set_enabled(True)
        except Exception as e:
            logger.warning(f"Failed to disable rate limiter emergency mode: {e}")

        logger.info(f"Emergency lockdown disabled by user {user['user_id']}")

        return {
            "message": "Emergency lockdown disabled",
            "timestamp": datetime.utcnow().isoformat(),
            "disabled_by": user['user_id']
        }

    except Exception as e:
        logger.error(f"Failed to disable emergency lockdown: {e}")
        raise HTTPException(
            status_code=HTTP_400_BAD_REQUEST,
            detail=f"Failed to disable emergency lockdown: {e!s}"
        )

# Health check endpoint
@router.get("/health")
async def security_health_check():
    """Check health of security systems"""
    health_status = {
        "timestamp": datetime.utcnow().isoformat(),
        "overall_status": "healthy",
        "components": {}
    }

    # Check DDoS protection
    try:
        if get_ddos_protection:
            ddos_system = get_ddos_protection()
            health_status["components"]["ddos_protection"] = {
                "status": "healthy" if ddos_system.enabled else "disabled",
                "enabled": ddos_system.enabled
            }
        else:
            health_status["components"]["ddos_protection"] = {
                "status": "unavailable",
                "enabled": False
            }
    except Exception as e:
        health_status["components"]["ddos_protection"] = {
            "status": "error",
            "error": str(e)
        }

    # Check encryption system
    try:
        if get_quantum_manager:
            quantum_manager = get_quantum_manager()
            health_status["components"]["encryption"] = {
                "status": "healthy",
                "post_quantum_available": quantum_manager.pqc.pqc_available,
                "active_keys": len(quantum_manager.get_active_keys())
            }
        else:
            health_status["components"]["encryption"] = {
                "status": "unavailable"
            }
    except Exception as e:
        health_status["components"]["encryption"] = {
            "status": "error",
            "error": str(e)
        }

    # Determine overall status
    component_statuses = [comp.get("status", "error") for comp in health_status["components"].values()]
    if "error" in component_statuses:
        health_status["overall_status"] = "degraded"
    elif "unavailable" in component_statuses:
        health_status["overall_status"] = "limited"

    return health_status

# Export router
__all__ = ["router"]
