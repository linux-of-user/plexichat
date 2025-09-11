from fastapi import APIRouter, Depends
from pydantic import BaseModel


# Mock dependencies for standalone execution
def require_admin():
    def admin_dependency():
        return {"username": "mock_admin"}
    return admin_dependency

class MockConfigManager:
    def get_config(self): return {}
    def update_config(self, **kwargs): pass
    def add_endpoint_override(self, path, limits): pass
    def remove_endpoint_override(self, path): pass
    def update_user_tier_multiplier(self, tier, multiplier): pass
    def get_effective_limits_for_user(self, tier): return {}

from plexichat.core.middleware.rate_limiting import get_rate_limiter
from plexichat.core.middleware.rate_limiting import get_rate_limiter as get_rl


class RealRateLimitConfigManager:
    def __init__(self):
        self.limiter = get_rl()
    def get_config(self):
        return self.limiter.get_config_summary()
    def update_config(self, **kwargs):
        if 'enabled' in kwargs:
            self.limiter.set_enabled(kwargs['enabled'])
    def add_endpoint_override(self, path, limits):
        self.limiter.add_endpoint_override(path, limits)
    def remove_endpoint_override(self, path):
        self.limiter.remove_endpoint_override(path)
    def update_user_tier_multiplier(self, tier, multiplier):
        self.limiter.update_user_tier_multiplier(tier, multiplier)
    def get_effective_limits_for_user(self, tier):
        return {}

def get_rate_limit_config_manager():
    return RealRateLimitConfigManager()

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
