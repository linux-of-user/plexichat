from datetime import datetime
from typing import Any, Dict, List, Optional






from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from plexichat.app.logger_config import logger
from plexichat.app.security.permissions import Permission, PermissionManager
from plexichat.app.security.rate_limiter import (

    API,
    Comprehensive,
    ComprehensiveRateLimiter,
    DDoS,
    Endpoints,
    Limiting,
    Management,
    Rate,
    RateLimitAction,
    RateLimitRule,
    RateLimitType,
    """,
    and,
    for,
    limits,
    managing,
    protection.,
    rate,
)

router = APIRouter(prefix="/api/v1/rate-limits", tags=["Rate Limiting"])
security = HTTPBearer()

# Global instances
rate_limiter = None
permission_manager = None

def get_rate_limiter():
    """Get rate limiter instance."""
    global rate_limiter
    if rate_limiter is None:
        rate_limiter = ComprehensiveRateLimiter()
    return rate_limiter

def get_permission_manager():
    """Get permission manager instance."""
    global permission_manager
    if permission_manager is None:
        permission_manager = PermissionManager()
    return permission_manager

# Pydantic models
class RateLimitRuleCreate(BaseModel):
    name: str = Field(..., description="Rule name")
    limit_type: str = Field(..., description="Type of rate limit")
    max_requests: int = Field(..., gt=0, description="Maximum requests allowed")
    time_window: int = Field(..., gt=0, description="Time window in seconds")
    action: str = Field(..., description="Action to take when limit exceeded")
    delay_seconds: int = Field(0, ge=0, description="Delay in seconds for DELAY action")
    ban_duration: int = Field(3600, gt=0, description="Ban duration in seconds")
    whitelist_ips: List[str] = Field(default_factory=list, description="Whitelisted IP addresses")
    blacklist_ips: List[str] = Field(default_factory=list, description="Blacklisted IP addresses")
    user_roles: List[str] = Field(default_factory=list, description="Apply to specific user roles")
    endpoints: List[str] = Field(default_factory=list, description="Apply to specific endpoints")
    enabled: bool = Field(True, description="Whether rule is enabled")

class RateLimitRuleUpdate(BaseModel):
    max_requests: Optional[int] = Field(None, gt=0)
    time_window: Optional[int] = Field(None, gt=0)
    action: Optional[str] = None
    delay_seconds: Optional[int] = Field(None, ge=0)
    ban_duration: Optional[int] = Field(None, gt=0)
    whitelist_ips: Optional[List[str]] = None
    blacklist_ips: Optional[List[str]] = None
    user_roles: Optional[List[str]] = None
    endpoints: Optional[List[str]] = None
    enabled: Optional[bool] = None

class RateLimitStatus(BaseModel):
    user_id: Optional[str]
    client_ip: str
    rule_name: str
    current_count: int
    max_allowed: int
    time_remaining: int
    is_exceeded: bool

class ViolationResponse(BaseModel):
    timestamp: datetime
    client_ip: str
    user_id: Optional[str]
    rule_name: str
    limit_type: str
    current_count: int
    max_allowed: int
    action_taken: str
    endpoint: Optional[str]
    severity: str

async def verify_admin_permission(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Verify user has admin permissions for rate limit management."""
    try:
        # Extract user ID from token (simplified - implement proper JWT validation)
        user_id = "admin"  # TODO: Extract from JWT token

        perm_manager = get_permission_manager()
        check = perm_manager.check_permission(user_id, Permission.MANAGE_RATE_LIMITS)

        if not check.granted:
            raise HTTPException(status_code=403, detail="Insufficient permissions")

        return user_id
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid authentication")

@router.get("/rules", response_model=List[Dict[str, Any]])
async def get_rate_limit_rules(admin_user: str = Depends(verify_admin_permission)):
    """Get all rate limiting rules."""
    try:
        limiter = get_rate_limiter()
        rules = []

        for rule in limiter.rules.values():
            rules.append({
                "name": rule.name,
                "limit_type": rule.limit_type.value,
                "max_requests": rule.max_requests,
                "time_window": rule.time_window,
                "action": rule.action.value,
                "delay_seconds": rule.delay_seconds,
                "ban_duration": rule.ban_duration,
                "whitelist_ips": rule.whitelist_ips,
                "blacklist_ips": rule.blacklist_ips,
                "user_roles": rule.user_roles,
                "endpoints": rule.endpoints,
                "enabled": rule.enabled
            })

        return rules
    except Exception as e:
        logger.error(f"Failed to get rate limit rules: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve rules")

@router.post("/rules")
async def create_rate_limit_rule(
    rule_data: RateLimitRuleCreate,
    admin_user: str = Depends(verify_admin_permission)
):
    """Create a new rate limiting rule."""
    try:
        limiter = get_rate_limiter()

        # Validate enums
        try:
            limit_type = RateLimitType(rule_data.limit_type)
            action = RateLimitAction(rule_data.action)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"Invalid enum value: {e}")

        rule = RateLimitRule(
            name=rule_data.name,
            limit_type=limit_type,
            max_requests=rule_data.max_requests,
            time_window=rule_data.time_window,
            action=action,
            delay_seconds=rule_data.delay_seconds,
            ban_duration=rule_data.ban_duration,
            whitelist_ips=rule_data.whitelist_ips,
            blacklist_ips=rule_data.blacklist_ips,
            user_roles=rule_data.user_roles,
            endpoints=rule_data.endpoints,
            enabled=rule_data.enabled
        )

        if rule.name in limiter.rules:
            raise HTTPException(status_code=400, detail="Rule name already exists")

        limiter.rules[rule.name] = rule
        limiter.save_config()

        logger.info(f" Created rate limit rule: {rule.name}")
        return {"message": "Rule created successfully", "rule_name": rule.name}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to create rate limit rule: {e}")
        raise HTTPException(status_code=500, detail="Failed to create rule")

@router.put("/rules/{rule_name}")
async def update_rate_limit_rule(
    rule_name: str,
    rule_updates: RateLimitRuleUpdate,
    admin_user: str = Depends(verify_admin_permission)
):
    """Update an existing rate limiting rule."""
    try:
        limiter = get_rate_limiter()

        if rule_name not in limiter.rules:
            raise HTTPException(status_code=404, detail="Rule not found")

        rule = limiter.rules[rule_name]

        # Update fields
        update_data = rule_updates.dict(exclude_unset=True)
        for field, value in update_data.items():
            if field == "action" and value:
                try:
                    value = RateLimitAction(value)
                except ValueError:
                    raise HTTPException(status_code=400, detail=f"Invalid action: {value}")

            setattr(rule, field, value)

        limiter.save_config()

        logger.info(f" Updated rate limit rule: {rule_name}")
        return {"message": "Rule updated successfully", "rule_name": rule_name}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update rate limit rule: {e}")
        raise HTTPException(status_code=500, detail="Failed to update rule")

@router.delete("/rules/{rule_name}")
async def delete_rate_limit_rule(
    rule_name: str,
    admin_user: str = Depends(verify_admin_permission)
):
    """Delete a rate limiting rule."""
    try:
        limiter = get_rate_limiter()

        if rule_name not in limiter.rules:
            raise HTTPException(status_code=404, detail="Rule not found")

        del limiter.rules[rule_name]
        limiter.save_config()

        logger.info(f" Deleted rate limit rule: {rule_name}")
        return {"message": "Rule deleted successfully", "rule_name": rule_name}

    except Exception as e:
        logger.error(f"Failed to delete rate limit rule: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete rule")

@router.get("/status/{client_ip}")
async def get_rate_limit_status(
    client_ip: str,
    user_id: Optional[str] = None,
    admin_user: str = Depends(verify_admin_permission)
):
    """Get rate limit status for a client."""
    try:
        limiter = get_rate_limiter()
        status_list = []

        for rule in limiter.rules.values():
            if not rule.enabled:
                continue

            client_key = limiter._get_client_key(client_ip, user_id, rule)
            current_count = limiter.tracker.get_request_count(client_key, rule.time_window)

            status = RateLimitStatus(
                user_id=user_id,
                client_ip=client_ip,
                rule_name=rule.name,
                current_count=current_count,
                max_allowed=rule.max_requests,
                time_remaining=rule.time_window,
                is_exceeded=current_count >= rule.max_requests
            )
            status_list.append(status.dict())

        return status_list

    except Exception as e:
        logger.error(f"Failed to get rate limit status: {e}")
        raise HTTPException(status_code=500, detail="Failed to get status")

@router.get("/violations", response_model=List[ViolationResponse])
async def get_rate_limit_violations(
    limit: int = 100,
    admin_user: str = Depends(verify_admin_permission)
):
    """Get recent rate limit violations."""
    try:
        limiter = get_rate_limiter()
        violations = limiter.tracker.violations[-limit:]

        return [
            ViolationResponse(
                timestamp=datetime.fromtimestamp(v.timestamp),
                client_ip=v.client_ip,
                user_id=v.user_id,
                rule_name=v.rule_name,
                limit_type=v.limit_type.value,
                current_count=v.current_count,
                max_allowed=v.max_allowed,
                action_taken=v.action_taken.value,
                endpoint=v.endpoint,
                severity=getattr(v, 'severity', 'medium')
            )
            for v in violations
        ]

    except Exception as e:
        logger.error(f"Failed to get violations: {e}")
        raise HTTPException(status_code=500, detail="Failed to get violations")

@router.post("/unban-ip/{ip_address}")
async def unban_ip_address(
    ip_address: str,
    admin_user: str = Depends(verify_admin_permission)
):
    """Unban an IP address."""
    try:
        limiter = get_rate_limiter()

        if ip_address in limiter.tracker.banned_ips:
            del limiter.tracker.banned_ips[ip_address]
            logger.info(f" Unbanned IP: {ip_address}")
            return {"message": "IP address unbanned successfully", "ip": ip_address}
        else:
            raise HTTPException(status_code=404, detail="IP address not found in ban list")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to unban IP: {e}")
        raise HTTPException(status_code=500, detail="Failed to unban IP")

@router.post("/unban-user/{user_id}")
async def unban_user(
    user_id: str,
    admin_user: str = Depends(verify_admin_permission)
):
    """Unban a user."""
    try:
        limiter = get_rate_limiter()

        if user_id in limiter.tracker.banned_users:
            del limiter.tracker.banned_users[user_id]
            logger.info(f" Unbanned user: {user_id}")
            return {"message": "User unbanned successfully", "user_id": user_id}
        else:
            raise HTTPException(status_code=404, detail="User not found in ban list")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to unban user: {e}")
        raise HTTPException(status_code=500, detail="Failed to unban user")

@router.get("/banned")
async def get_banned_entities(admin_user: str = Depends(verify_admin_permission)):
    """Get all banned IPs and users."""
    try:
        limiter = get_rate_limiter()

        return {
            "banned_ips": [
                {"ip": ip, "ban_until": datetime.fromtimestamp(until).isoformat()}
                for ip, until in limiter.tracker.banned_ips.items()
            ],
            "banned_users": [
                {"user_id": user_id, "ban_until": datetime.fromtimestamp(until).isoformat()}
                for user_id, until in limiter.tracker.banned_users.items()
            ],
            "quarantined_ips": [
                {"ip": ip, "quarantine_until": datetime.fromtimestamp(until).isoformat()}
                for ip, until in limiter.tracker.quarantined_ips.items()
            ]
        }

    except Exception as e:
        logger.error(f"Failed to get banned entities: {e}")
        raise HTTPException(status_code=500, detail="Failed to get banned entities")

@router.post("/enable")
async def enable_rate_limiting(admin_user: str = Depends(verify_admin_permission)):
    """Enable rate limiting system."""
    try:
        limiter = get_rate_limiter()
        limiter.enabled = True
        limiter.save_config()

        logger.info(" Rate limiting enabled")
        return {"message": "Rate limiting enabled", "enabled": True}

    except Exception as e:
        logger.error(f"Failed to enable rate limiting: {e}")
        raise HTTPException(status_code=500, detail="Failed to enable rate limiting")

@router.post("/disable")
async def disable_rate_limiting(admin_user: str = Depends(verify_admin_permission)):
    """Disable rate limiting system."""
    try:
        limiter = get_rate_limiter()
        limiter.enabled = False
        limiter.save_config()

        logger.warning(" Rate limiting disabled")
        return {"message": "Rate limiting disabled", "enabled": False}

    except Exception as e:
        logger.error(f"Failed to disable rate limiting: {e}")
        raise HTTPException(status_code=500, detail="Failed to disable rate limiting")
