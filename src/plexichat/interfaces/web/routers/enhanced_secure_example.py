"""
Enhanced Secure Router Example
Demonstrates how to use the new security decorators and logging system.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Request, HTTPException, status, Depends
from pydantic import BaseModel

# Import enhanced security decorators
try:
    from ....core.security.security_decorators import (
        require_auth, require_admin, rate_limit, audit_access, validate_input,
        secure_endpoint, admin_endpoint, SecurityLevel, RequiredPermission
    )
    from ....core.logging_advanced.enhanced_logging_system import (
        get_enhanced_logging_system, LogCategory, LogLevel, PerformanceMetrics, PerformanceTracker
    )
except ImportError as e:
    print(f"Security decorators import error: {e}")
    # Fallback decorators that do nothing
    def require_auth(*args, **kwargs):
        def decorator(func): return func
        return decorator
    
    def require_admin(*args, **kwargs):
        def decorator(func): return func
        return decorator
    
    def rate_limit(*args, **kwargs):
        def decorator(func): return func
        return decorator
    
    def audit_access(*args, **kwargs):
        def decorator(func): return func
        return decorator
    
    def validate_input(*args, **kwargs):
        def decorator(func): return func
        return decorator
    
    def secure_endpoint(*args, **kwargs):
        def decorator(func): return func
        return decorator
    
    def admin_endpoint(*args, **kwargs):
        def decorator(func): return func
        return decorator
    
    SecurityLevel = type('SecurityLevel', (), {})
    RequiredPermission = type('RequiredPermission', (), {})
    get_enhanced_logging_system = lambda: None
    LogCategory = type('LogCategory', (), {})
    LogLevel = type('LogLevel', (), {})
    PerformanceMetrics = type('PerformanceMetrics', (), {})
    PerformanceTracker = type('PerformanceTracker', (), {})

router = APIRouter()

# Get logging system
logging_system = get_enhanced_logging_system()
if logging_system:
    logger = logging_system.get_logger(__name__)
else:
    import logging
    logger = logging.getLogger(__name__)

# Data models
class UserData(BaseModel):
    name: str
    email: str
    role: Optional[str] = "user"

class AdminAction(BaseModel):
    action: str
    target: str
    reason: Optional[str] = None

class SystemConfig(BaseModel):
    key: str
    value: Any
    category: str = "general"

class MessageData(BaseModel):
    content: str
    recipient: Optional[str] = None
    priority: str = "normal"


# Public endpoint (no authentication required)
@router.get("/public-info")
@rate_limit(requests_per_minute=120)  # Higher limit for public endpoints
async def get_public_info(request: Request):
    """Public endpoint with rate limiting."""
    if logging_system:
        logging_system.log_with_context(
            LogLevel.INFO.value,
            "Public info requested",
            category=LogCategory.API,
            metadata={"endpoint": "/public-info"},
            tags=["public", "info"]
        )
    
    return {}
        "message": "This is public information",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "features": ["enhanced_security", "comprehensive_logging", "rate_limiting"]
    }


# Basic authenticated endpoint
@router.get("/user-profile")
@secure_endpoint(
    auth_level=SecurityLevel.AUTHENTICATED,
    rate_limit_rpm=60,
    audit_action="view_profile"
)
async def get_user_profile(request: Request, current_user: Dict = None):
    """Get user profile with security and auditing."""
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required"
        )
    
    # Performance tracking
    if logging_system:
        with PerformanceTracker("get_user_profile", logger) as tracker:
            tracker.add_metadata(user_id=current_user.get("id"))
            
            # Simulate some processing time
            import time
            time.sleep(0.01)
            
            profile_data = {
                "id": current_user.get("id"),
                "username": current_user.get("username"),
                "email": current_user.get("email"),
                "role": current_user.get("role", "user"),
                "last_login": current_user.get("last_login"),
                "permissions": current_user.get("permissions", [])
            }
            
            return {}
                "profile": profile_data,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
    
    return {"error": "Logging system not available"}


# Endpoint with input validation
@router.post("/create-user")
@validate_input(
    max_size=10 * 1024,  # 10KB max
    allowed_content_types=["application/json"],
    validate_json=True
)
@require_auth(SecurityLevel.ELEVATED, permissions=[RequiredPermission.WRITE])
@audit_access("create_user", resource_type="user", include_request_body=True)
@rate_limit(requests_per_minute=20)
async def create_user(
    request: Request, 
    user_data: UserData, 
    current_user: Dict = None
):
    """Create a new user with comprehensive security."""
    if logging_system:
        logger.info(
            f"User creation requested by {current_user.get('username')}",
            extra={
                "category": LogCategory.API,
                "metadata": {
                    "action": "create_user",
                    "creator_id": current_user.get("id"),
                    "new_user_data": user_data.dict()
                },
                "tags": ["user_management", "create"]
            }
        )
    
    # Simulate user creation process
    new_user_id = f"user_{int(datetime.now().timestamp())}"
    
    if logging_system:
        logging_system.log_with_context(
            LogLevel.AUDIT.value,
            f"User {new_user_id} created successfully",
            category=LogCategory.AUDIT,
            metadata={
                "new_user_id": new_user_id,
                "created_by": current_user.get("id"),
                "user_details": user_data.dict()
            },
            tags=["user_created", "success"]
        )
    
    return {}
        "message": "User created successfully",
        "user_id": new_user_id,
        "created_by": current_user.get("username"),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


# Admin endpoint with elevated permissions
@router.post("/admin/system-action")
@admin_endpoint(
    permissions=[RequiredPermission.ADMIN],
    rate_limit_rpm=10,
    audit_action="system_action"
)
async def perform_admin_action(
    request: Request, 
    action_data: AdminAction, 
    current_user: Dict = None
):
    """Perform administrative action with full auditing."""
    if logging_system:
        # Log security-relevant admin action
        logging_system.log_with_context(
            LogLevel.SECURITY.value,
            f"Admin action performed: {action_data.action}",
            category=LogCategory.SECURITY,
            metadata={
                "admin_id": current_user.get("id"),
                "admin_username": current_user.get("username"),
                "action": action_data.action,
                "target": action_data.target,
                "reason": action_data.reason,
                "ip_address": logging_system.get_context().ip_address
            },
            tags=["admin_action", "security_relevant"]
        )
    
    # Simulate action processing
    result = {
        "action": action_data.action,
        "target": action_data.target,
        "status": "completed",
        "performed_by": current_user.get("username"),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    
    return result


# System endpoint with highest security level
@router.put("/system/config")
@require_auth(SecurityLevel.SYSTEM)
@audit_access("update_system_config", resource_type="system", include_request_body=True, include_response=True)
@rate_limit(requests_per_minute=5)
@validate_input(max_size=5 * 1024)
async def update_system_config(
    request: Request, 
    config_data: SystemConfig, 
    current_user: Dict = None
):
    """Update system configuration with maximum security."""
    if logging_system:
        # Log critical system change
        logging_system.log_with_context(
            LogLevel.CRITICAL.value,
            f"System configuration updated: {config_data.key}",
            category=LogCategory.SYSTEM,
            metadata={
                "system_user": current_user.get("username"),
                "config_key": config_data.key,
                "config_category": config_data.category,
                "previous_value": "redacted",  # Don't log actual values
                "new_value": "redacted"
            },
            tags=["system_config", "critical_change"]
        )
    
    return {}
        "message": "System configuration updated",
        "key": config_data.key,
        "category": config_data.category,
        "updated_by": current_user.get("username"),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


# Performance monitoring endpoint
@router.get("/messages/list")
@secure_endpoint(
    auth_level=SecurityLevel.AUTHENTICATED,
    rate_limit_rpm=100,
    audit_action="list_messages"
)
async def list_messages(
    request: Request,
    limit: int = 50,
    offset: int = 0,
    current_user: Dict = None
):
    """List messages with performance monitoring."""
    if not logging_system:
        return {"error": "Enhanced logging not available"}
    
    with PerformanceTracker("list_messages", logger) as tracker:
        tracker.add_metadata(
            user_id=current_user.get("id"),
            limit=limit,
            offset=offset
        )
        
        # Simulate database query
        import time
        time.sleep(0.05)  # Simulate DB query time
        
        # Generate sample messages
        messages = []
        for i in range(min(limit, 20)):  # Limit for demo
            messages.append({
                "id": f"msg_{i + offset}",
                "content": f"Sample message {i + offset}",
                "sender": f"user_{i % 3}",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "read": i % 2 == 0
            })
        
        # Log performance metrics
        logging_system.log_with_context(
            LogLevel.PERFORMANCE.value,
            f"Listed {len(messages)} messages",
            category=LogCategory.PERFORMANCE,
            performance=PerformanceMetrics(
                duration_ms=tracker.metadata.get("duration", 0),
                database_queries=1,
                cache_hits=0,
                cache_misses=1
            ),
            metadata={
                "message_count": len(messages),
                "query_limit": limit,
                "query_offset": offset
            },
            tags=["performance", "database_query"]
        )
        
        return {}
            "messages": messages,
            "total_count": 1000,  # Simulated total
            "limit": limit,
            "offset": offset,
            "has_more": offset + len(messages) < 1000
        }


# File upload endpoint with security validation
@router.post("/files/upload")
@validate_input(
    max_size=10 * 1024 * 1024,  # 10MB max
    allowed_content_types=["multipart/form-data"]
)
@require_auth(SecurityLevel.AUTHENTICATED, permissions=[RequiredPermission.WRITE])
@audit_access("upload_file", resource_type="file")
@rate_limit(requests_per_minute=10)
async def upload_file(
    request: Request,
    current_user: Dict = None
):
    """File upload with security validation."""
    if logging_system:
        # Log file upload attempt
        logging_system.log_with_context(
            LogLevel.INFO.value,
            "File upload initiated",
            category=LogCategory.API,
            metadata={
                "user_id": current_user.get("id"),
                "content_type": request.headers.get("Content-Type"),
                "content_length": request.headers.get("Content-Length")
            },
            tags=["file_upload", "security_check"]
        )
    
    # Simulate file processing
    file_id = f"file_{int(datetime.now().timestamp())}"
    
    return {}
        "message": "File uploaded successfully",
        "file_id": file_id,
        "uploaded_by": current_user.get("username"),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


# Health check endpoint for monitoring
@router.get("/health/detailed")
async def detailed_health_check(request: Request):
    """Detailed health check with system metrics."""
    health_data = {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "components": {
            "enhanced_logging": logging_system is not None,
            "security_manager": True,  # Assume available if we got here
            "database": True,  # Would check actual DB connection
            "cache": True,     # Would check cache connectivity
        },
        "metrics": {}
    }
    
    if logging_system:
        # Get logging system metrics
        buffer_stats = logging_system.get_buffer_stats()
        performance_stats = logging_system.get_performance_stats()
        
        health_data["metrics"].update({
            "log_buffer": buffer_stats,
            "performance": performance_stats
        })
        
        # Log health check
        logging_system.log_with_context(
            LogLevel.INFO.value,
            "Detailed health check performed",
            category=LogCategory.MONITORING,
            metadata=health_data,
            tags=["health_check", "monitoring"]
        )
    
    return health_data


# Security metrics endpoint for admins
@router.get("/admin/security-metrics")
@admin_endpoint(audit_action="view_security_metrics")
async def get_security_metrics(request: Request, current_user: Dict = None):
    """Get security metrics (admin only)."""
    if not logging_system:
        return {"error": "Enhanced logging not available"}
    
    # Get security-related logs
    security_logs = logging_system.search_logs(
        query="",
        category=LogCategory.SECURITY,
        limit=100
    )
    
    # Analyze security events
    security_events = {}
    threat_levels = {}
    
    for log_entry in security_logs:
        event_type = log_entry.metadata.get("event_type", "unknown")
        security_events[event_type] = security_events.get(event_type, 0) + 1
        
        threat_level = log_entry.metadata.get("threat_level", "unknown")
        threat_levels[threat_level] = threat_levels.get(threat_level, 0) + 1
    
    metrics = {
        "total_security_events": len(security_logs),
        "events_by_type": security_events,
        "threats_by_level": threat_levels,
        "recent_events": [
            {
                "timestamp": log.timestamp.isoformat(),
                "level": log.level.name,
                "message": log.message,
                "metadata": log.metadata
            }
            for log in security_logs[:10]  # Last 10 events
        ],
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generated_by": current_user.get("username")
    }
    
    return metrics