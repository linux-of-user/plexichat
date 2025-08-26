from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from typing import Dict, Optional, List
from datetime import datetime

# Mock dependencies for standalone execution
def require_admin():
    def admin_dependency():
        return {"username": "mock_admin"}
    return admin_dependency

class MockRateLimiter:
    def get_stats(self): return {"total_requests": 0, "blocked_requests": 0}

class MockConfigManager:
    def get_config(self): return {}
    def update_config(self, **kwargs): pass
    def add_endpoint_override(self, path, limits): pass
    def remove_endpoint_override(self, path): pass
    def update_user_tier_multiplier(self, tier, multiplier): pass
    def get_effective_limits_for_user(self, tier): return {}

def get_rate_limiter(): return MockRateLimiter()
def get_rate_limit_config_manager(): return MockConfigManager()

router = APIRouter(prefix="/rate-limits", tags=["Rate Limiting"])

class RateLimitStats(BaseModel):
    total_requests: int
    blocked_requests: int

class EndpointOverride(BaseModel):
    path: str
    limit: int

@router.get("/stats", response_model=RateLimitStats)
async def get_rate_limit_stats(current_user: dict = Depends(require_admin())):
    """Get comprehensive rate limiting statistics."""
    rate_limiter = get_rate_limiter()
    stats = rate_limiter.get_stats()
    return RateLimitStats(**stats)

@router.get("/config")
async def get_rate_limit_config(current_user: dict = Depends(require_admin())):
    """Get current rate limiting configuration."""
    config_manager = get_rate_limit_config_manager()
    return config_manager.get_config()

@router.post("/endpoint-overrides")
async def add_endpoint_override(override: EndpointOverride, current_user: dict = Depends(require_admin())):
    """Add or update an endpoint-specific rate limit."""
    config_manager = get_rate_limit_config_manager()
    config_manager.add_endpoint_override(override.path, {"per_ip": override.limit})
    return {"message": f"Override for {override.path} set."}

@router.delete("/endpoint-overrides/{path:path}")
async def remove_endpoint_override(path: str, current_user: dict = Depends(require_admin())):
    """Remove an endpoint-specific rate limit."""
    config_manager = get_rate_limit_config_manager()
    config_manager.remove_endpoint_override(f"/{path}")
    return {"message": f"Override for /{path} removed."}
