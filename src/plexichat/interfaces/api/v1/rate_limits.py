#!/usr/bin/env python3
"""
Rate Limiting Management API

Provides endpoints for monitoring and managing the unified rate limiting system.
Includes statistics, configuration updates, and manual overrides.
"""

from fastapi import APIRouter, HTTPException, Depends, status, Request
from fastapi.responses import JSONResponse
from typing import Dict, Any, Optional, List
from pydantic import BaseModel, Field
from datetime import datetime
import logging

from plexichat.core.middleware.unified_rate_limiter import (
    get_rate_limiter, RateLimitStrategy, RateLimitAlgorithm
)
from plexichat.core.config.rate_limit_config import (
    get_rate_limit_config_manager, get_rate_limit_config
)
from plexichat.core.middleware.integrated_protection_system import (
    get_protection_system, SystemLoadLevel, AccountType
)
from plexichat.core.security.security_decorators import require_security_level, SecurityLevel

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/rate-limits", tags=["Rate Limiting"])

# Pydantic models for API
class RateLimitStats(BaseModel):
    """Rate limiting statistics."""
    total_requests: int
    blocked_requests: int
    block_rate: float
    violations_by_strategy: Dict[str, int]
    violations_by_key: Dict[str, int]
    active_blocks: int
    active_buckets: int
    active_windows: int
    timestamp: datetime = Field(default_factory=datetime.now)

class EndpointOverride(BaseModel):
    """Endpoint-specific rate limit override."""
    path: str
    per_ip: Optional[int] = None
    per_user: Optional[int] = None
    per_route: Optional[int] = None
    burst_limit: Optional[int] = None
    enabled: bool = True

class UserTierUpdate(BaseModel):
    """User tier rate limit multiplier update."""
    tier: str
    multiplier: float = Field(gt=0, le=100)

class ConfigUpdate(BaseModel):
    """Rate limiting configuration update."""
    enabled: Optional[bool] = None
    per_ip_requests_per_minute: Optional[int] = Field(None, gt=0, le=10000)
    per_user_requests_per_minute: Optional[int] = Field(None, gt=0, le=10000)
    per_route_requests_per_minute: Optional[int] = Field(None, gt=0, le=10000)
    global_requests_per_minute: Optional[int] = Field(None, gt=0, le=100000)

@router.get("/stats", response_model=RateLimitStats)
async def get_rate_limit_stats(
    current_user: Dict = Depends(require_security_level(SecurityLevel.ADMIN))
):
    """
    Get comprehensive rate limiting statistics.
    
    Requires admin privileges.
    """
    try:
        rate_limiter = get_rate_limiter()
        stats = rate_limiter.get_stats()
        
        return RateLimitStats(**stats)
        
    except Exception as e:
        logger.error(f"Failed to get rate limit stats: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve rate limiting statistics"
        )

@router.get("/config")
async def get_rate_limit_config(
    current_user: Dict = Depends(require_security_level(SecurityLevel.ADMIN))
):
    """
    Get current rate limiting configuration.
    
    Requires admin privileges.
    """
    try:
        config_manager = get_rate_limit_config_manager()
        config = config_manager.get_config()
        
        return {}}
            "enabled": config.enabled,
            "default_algorithm": config.default_algorithm.value,
            "per_ip_requests_per_minute": config.per_ip_requests_per_minute,
            "per_user_requests_per_minute": config.per_user_requests_per_minute,
            "per_route_requests_per_minute": config.per_route_requests_per_minute,
            "global_requests_per_minute": config.global_requests_per_minute,
            "endpoint_overrides": config.endpoint_overrides,
            "user_tier_multipliers": config.user_tier_multipliers
        }
        
    except Exception as e:
        logger.error(f"Failed to get rate limit config: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve rate limiting configuration"
        )

@router.put("/config")
async def update_rate_limit_config(
    config_update: ConfigUpdate,
    current_user: Dict = Depends(require_security_level(SecurityLevel.ADMIN))
):
    """
    Update rate limiting configuration.
    
    Requires admin privileges.
    """
    try:
        config_manager = get_rate_limit_config_manager()
        
        # Update only provided fields
        update_data = config_update.dict(exclude_unset=True)
        config_manager.update_config(**update_data)
        
        logger.info(f"Rate limit config updated by admin {current_user.get('username', 'unknown')}: {update_data}")
        
        return {}}
            "success": True,
            "message": "Rate limiting configuration updated successfully",
            "updated_fields": list(update_data.keys())
        }
        
    except Exception as e:
        logger.error(f"Failed to update rate limit config: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update rate limiting configuration"
        )

@router.post("/endpoint-overrides")
async def add_endpoint_override(
    override: EndpointOverride,
    current_user: Dict = Depends(require_security_level(SecurityLevel.ADMIN))
):
    """
    Add or update endpoint-specific rate limits.
    
    Requires admin privileges.
    """
    try:
        config_manager = get_rate_limit_config_manager()
        
        # Build limits dict
        limits = {}
        if override.per_ip is not None:
            limits["per_ip"] = override.per_ip
        if override.per_user is not None:
            limits["per_user"] = override.per_user
        if override.per_route is not None:
            limits["per_route"] = override.per_route
        if override.burst_limit is not None:
            limits["burst_limit"] = override.burst_limit
        
        config_manager.add_endpoint_override(override.path, limits)
        
        logger.info(f"Endpoint override added by admin {current_user.get('username', 'unknown')}: {override.path}")
        
        return {}}
            "success": True,
            "message": f"Endpoint override added for {override.path}",
            "limits": limits
        }
        
    except Exception as e:
        logger.error(f"Failed to add endpoint override: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to add endpoint override"
        )

@router.delete("/endpoint-overrides/{path:path}")
async def remove_endpoint_override(
    path: str,
    current_user: Dict = Depends(require_security_level(SecurityLevel.ADMIN))
):
    """
    Remove endpoint-specific rate limits.
    
    Requires admin privileges.
    """
    try:
        config_manager = get_rate_limit_config_manager()
        config_manager.remove_endpoint_override(f"/{path}")
        
        logger.info(f"Endpoint override removed by admin {current_user.get('username', 'unknown')}: /{path}")
        
        return {}}
            "success": True,
            "message": f"Endpoint override removed for /{path}"
        }
        
    except Exception as e:
        logger.error(f"Failed to remove endpoint override: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to remove endpoint override"
        )

@router.put("/user-tiers")
async def update_user_tier_multiplier(
    tier_update: UserTierUpdate,
    current_user: Dict = Depends(require_security_level(SecurityLevel.ADMIN))
):
    """
    Update rate limit multiplier for a user tier.
    
    Requires admin privileges.
    """
    try:
        config_manager = get_rate_limit_config_manager()
        config_manager.update_user_tier_multiplier(tier_update.tier, tier_update.multiplier)
        
        logger.info(f"User tier multiplier updated by admin {current_user.get('username', 'unknown')}: "
                   f"{tier_update.tier} = {tier_update.multiplier}")
        
        return {}}
            "success": True,
            "message": f"User tier multiplier updated for {tier_update.tier}",
            "tier": tier_update.tier,
            "multiplier": tier_update.multiplier
        }
        
    except Exception as e:
        logger.error(f"Failed to update user tier multiplier: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update user tier multiplier"
        )

@router.get("/effective-limits/{user_tier}")
async def get_effective_limits(
    user_tier: str,
    current_user: Dict = Depends(require_security_level(SecurityLevel.ADMIN))
):
    """
    Get effective rate limits for a specific user tier.
    
    Requires admin privileges.
    """
    try:
        config_manager = get_rate_limit_config_manager()
        limits = config_manager.get_effective_limits_for_user(user_tier)
        
        return {}}
            "user_tier": user_tier,
            "effective_limits": limits
        }
        
    except Exception as e:
        logger.error(f"Failed to get effective limits: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get effective limits"
        )

@router.post("/test-limits")
async def test_rate_limits(
    request: Request,
    strategy: RateLimitStrategy = RateLimitStrategy.PER_IP,
    current_user: Dict = Depends(require_security_level(SecurityLevel.ADMIN))
):
    """
    Test rate limiting for the current request.
    
    Useful for debugging and testing rate limit configurations.
    Requires admin privileges.
    """
    try:
        rate_limiter = get_rate_limiter()
        
        # Get client identifier for the strategy
        client_id = rate_limiter._get_client_identifier(request, strategy)
        
        # Get current limits
        max_requests, window_seconds = rate_limiter._get_rate_limit_for_strategy(strategy, request)
        current_count = rate_limiter._get_current_count(client_id, rate_limiter.config.default_algorithm)
        
        return {}}
            "strategy": strategy.value,
            "client_id": client_id,
            "max_requests": max_requests,
            "window_seconds": window_seconds,
            "current_count": current_count,
            "remaining": max(0, max_requests - current_count),
            "would_be_blocked": current_count >= max_requests
        }
        
    except Exception as e:
        logger.error(f"Failed to test rate limits: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to test rate limits"
        )

@router.get("/integrated-stats")
async def get_integrated_protection_stats(
    current_user: Dict = Depends(require_security_level(SecurityLevel.ADMIN))
):
    """
    Get comprehensive integrated protection system statistics.

    Includes DDoS protection, rate limiting, dynamic scaling, and system metrics.
    Requires admin privileges.
    """
    try:
        protection_system = get_protection_system()
        stats = protection_system.get_comprehensive_stats()

        return {}}
            "success": True,
            "timestamp": time.time(),
            "stats": stats
        }

    except Exception as e:
        logger.error(f"Failed to get integrated protection stats: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve integrated protection statistics"
        )

@router.put("/account-limits/{account_type}")
async def update_account_type_limits(
    account_type: str,
    requests_per_minute: int = Field(gt=0, le=10000),
    concurrent_requests: int = Field(gt=0, le=1000),
    bandwidth_per_second: int = Field(gt=0, le=1000000000),  # 1GB/s max
    current_user: Dict = Depends(require_security_level(SecurityLevel.ADMIN))
):
    """
    Update rate limits for a specific account type.

    Supports: GUEST, USER, BOT, MODERATOR, ADMIN
    Requires admin privileges.
    """
    try:
        # Validate account type
        try:
            account_type_enum = AccountType(account_type.upper())
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid account type: {account_type}. Valid types: GUEST, USER, BOT, MODERATOR, ADMIN"
            )

        protection_system = get_protection_system()

        # Create new limits
        from plexichat.core.config.rate_limiting_config import AccountTypeRateLimit
        new_limits = AccountTypeRateLimit(
            account_type=account_type_enum,
            global_requests_per_minute=requests_per_minute,
            global_requests_per_hour=requests_per_minute * 60,
            concurrent_requests=concurrent_requests,
            bandwidth_per_second=bandwidth_per_second
        )

        # Update limits
        protection_system.update_account_limits(account_type_enum, new_limits)

        logger.info(f"Account limits updated by admin {current_user.get('username', 'unknown')}: "
                   f"{account_type} = {requests_per_minute} req/min")

        return {}}
            "success": True,
            "message": f"Account limits updated for {account_type}",
            "account_type": account_type,
            "limits": {
                "requests_per_minute": requests_per_minute,
                "concurrent_requests": concurrent_requests,
                "bandwidth_per_second": bandwidth_per_second
            }
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update account limits: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update account limits"
        )

@router.put("/load-multipliers")
async def update_load_multipliers(
    low_load: float = Field(gt=0, le=10, default=1.5),
    normal_load: float = Field(gt=0, le=10, default=1.0),
    high_load: float = Field(gt=0, le=10, default=0.7),
    critical_load: float = Field(gt=0, le=10, default=0.3),
    current_user: Dict = Depends(require_security_level(SecurityLevel.ADMIN))
):
    """
    Update dynamic load multipliers for rate limiting.

    Multipliers adjust rate limits based on system load:
    - low_load: < 30% system load (default: 1.5x limits)
    - normal_load: 30-70% system load (default: 1.0x limits)
    - high_load: 70-90% system load (default: 0.7x limits)
    - critical_load: > 90% system load (default: 0.3x limits)

    Requires admin privileges.
    """
    try:
        protection_system = get_protection_system()

        multipliers = {
            SystemLoadLevel.LOW: low_load,
            SystemLoadLevel.NORMAL: normal_load,
            SystemLoadLevel.HIGH: high_load,
            SystemLoadLevel.CRITICAL: critical_load
        }

        protection_system.adjust_load_multipliers(multipliers)

        logger.info(f"Load multipliers updated by admin {current_user.get('username', 'unknown')}: {multipliers}")

        return {}}
            "success": True,
            "message": "Load multipliers updated successfully",
            "multipliers": {
                "low_load": low_load,
                "normal_load": normal_load,
                "high_load": high_load,
                "critical_load": critical_load
            }
        }

    except Exception as e:
        logger.error(f"Failed to update load multipliers: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update load multipliers"
        )

@router.get("/system-health")
async def get_system_health(
    current_user: Dict = Depends(require_security_level(SecurityLevel.ADMIN))
):
    """
    Get current system health and load information.

    Requires admin privileges.
    """
    try:
        protection_system = get_protection_system()
        stats = protection_system.get_comprehensive_stats()

        system_metrics = stats["system_metrics"]

        # Determine health status
        cpu_status = "healthy" if system_metrics["cpu_usage"] < 70 else "warning" if system_metrics["cpu_usage"] < 90 else "critical"
        memory_status = "healthy" if system_metrics["memory_usage"] < 70 else "warning" if system_metrics["memory_usage"] < 90 else "critical"

        overall_status = "critical" if cpu_status == "critical" or memory_status == "critical" else \
                        "warning" if cpu_status == "warning" or memory_status == "warning" else "healthy"

        return {}}
            "success": True,
            "timestamp": time.time(),
            "overall_status": overall_status,
            "system_metrics": system_metrics,
            "load_level": system_metrics["load_level"],
            "component_status": {
                "cpu": cpu_status,
                "memory": memory_status,
                "protection_system": "active"
            },
            "recommendations": _get_health_recommendations(system_metrics)
        }

    except Exception as e:
        logger.error(f"Failed to get system health: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve system health"
        )

def _get_health_recommendations(metrics: Dict[str, Any]) -> List[str]:
    """Generate health recommendations based on system metrics."""
    recommendations = []

    if metrics["cpu_usage"] > 80:
        recommendations.append("High CPU usage detected - consider scaling or optimizing")

    if metrics["memory_usage"] > 80:
        recommendations.append("High memory usage detected - check for memory leaks")

    if metrics["load_level"] == "critical":
        recommendations.append("System under critical load - emergency scaling recommended")
    elif metrics["load_level"] == "high":
        recommendations.append("System under high load - consider scaling")

    if not recommendations:
        recommendations.append("System is operating normally")

    return recommendations
