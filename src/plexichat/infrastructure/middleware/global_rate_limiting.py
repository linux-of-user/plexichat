"""
Global Adaptive Rate Limiting Middleware
Implements intelligent rate limiting with adaptive scaling based on traffic patterns.
"""

import asyncio
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, Optional

from fastapi import FastAPI, Request, Response, HTTPException, status
from fastapi.middleware.base import BaseHTTPMiddleware

# Placeholder imports for dependencies
def get_current_user_from_request(request): return None
class RateLimiter:
    async def is_allowed(self, key, max_attempts, window_minutes): return True
    async def get_stats(self): return {}
rate_limiter = RateLimiter()

# from plexichat.core.auth import get_current_user_from_request
# from plexichat.infrastructure.services.rate_limiter import rate_limiter

logger = logging.getLogger(__name__)

class GlobalAdaptiveRateLimitingMiddleware(BaseHTTPMiddleware):
    """
    Global adaptive rate limiting middleware that:
    1. Enforces global rate limits across all endpoints
    2. Adapts limits based on traffic patterns
    3. Provides per-user rank-based limiting
    4. Monitors and adjusts in real-time
    """
    def __init__(self, app: FastAPI):
        super().__init__(app)
        self.global_key = "global_traffic"
        self.stats_window = 300  # 5 minutes
        self.adjustment_interval = 60  # 1 minute
        self.last_adjustment = time.time()
        
        # Base limits (requests per minute)
        self.base_limits = {
            "global": 10000,  # Global limit
            "admin": 1000,    # Admin users
            "moderator": 500, # Moderator users
            "user": 100,      # Regular users
            "guest": 20       # Guest/unauthenticated
        }
        
        # Current adaptive limits
        self.current_limits = self.base_limits.copy()
        
        # Traffic monitoring
        self.traffic_history = []
        self.peak_traffic = 0
        
        logger.info("Global adaptive rate limiting middleware initialized")
    
    async def dispatch(self, request: Request, call_next):
        """Process request with global adaptive rate limiting."""
        start_time = time.time()
        
        try:
            # Get client identifier
            client_ip = self._get_client_ip(request)
            user_agent = request.headers.get("user-agent", "unknown")
            
            # Get user rank for per-user limiting
            user_rank = await self._get_user_rank(request)
            
            # Update adaptive limits if needed
            await self._update_adaptive_limits()
            
            # Check global rate limit first
            global_allowed = await self._check_global_limit(request)
            if not global_allowed:
                return self._create_rate_limit_response(
                    "Global rate limit exceeded. Please try again later.",
                    retry_after=60
                )
            
            # Check per-user rate limit
            user_allowed = await self._check_user_limit(request, user_rank, client_ip)
            if not user_allowed:
                return self._create_rate_limit_response(
                    f"Rate limit exceeded for {user_rank} users. Please try again later.",
                    retry_after=self._get_retry_after(user_rank)
                )
            
            # Process request
            response = await call_next(request)
            
            # Record successful request
            await self._record_request(client_ip, user_rank, True)
            
            # Add rate limit headers
            self._add_rate_limit_headers(response, user_rank)
            
            return response
            
        except Exception as e:
            logger.error(f"Rate limiting middleware error: {e}")
            # Don't block requests on middleware errors
            return await call_next(request)
    
    async def _check_global_limit(self, request: Request) -> bool:
        """Check global rate limit."""
        try:
            current_limit = self.current_limits["global"]
            
            # Use rate limiter with global key
            allowed = await rate_limiter.is_allowed(
                key=self.global_key,
                max_attempts=current_limit,
                window_minutes=1  # Per minute
            )
            
            if not allowed:
                logger.warning(f"Global rate limit exceeded: {current_limit}/min")
                await self._record_rate_limit_hit("global")
            
            return allowed
            
        except Exception as e:
            logger.error(f"Global rate limit check failed: {e}")
            return True  # Allow on error
    
    async def _check_user_limit(self, request: Request, user_rank: str, client_ip: str) -> bool:
        """Check per-user rate limit based on rank."""
        try:
            current_limit = self.current_limits.get(user_rank, self.current_limits["guest"])
            
            # Create user-specific key
            user_key = f"user_{user_rank}_{client_ip}"
            
            allowed = await rate_limiter.is_allowed(
                key=user_key,
                max_attempts=current_limit,
                window_minutes=1
            )
            
            if not allowed:
                logger.warning(f"User rate limit exceeded for {user_rank}: {current_limit}/min")
                await self._record_rate_limit_hit(user_rank)
            
            return allowed
            
        except Exception as e:
            logger.error(f"User rate limit check failed: {e}")
            return True  # Allow on error
    
    async def _get_user_rank(self, request: Request) -> str:
        """Get user rank for rate limiting."""
        try:
            # Try to get current user
            user = await get_current_user_from_request(request)
            
            if not user:
                return "guest"
            
            # Determine rank based on user properties
            if hasattr(user, 'is_admin') and user.is_admin:
                return "admin"
            elif hasattr(user, 'role') and user.role == "moderator":
                return "moderator"
            elif hasattr(user, 'id'):
                return "user"
            else:
                return "guest"
                
        except Exception:
            return "guest"
    
    async def _update_adaptive_limits(self):
        """Update rate limits based on traffic patterns."""
        current_time = time.time()
        
        # Only adjust every minute
        if current_time - self.last_adjustment < self.adjustment_interval:
            return
        
        try:
            # Get current traffic stats
            stats = await rate_limiter.get_stats()
            current_traffic = stats.get("requests_per_minute", 0)
            
            # Record traffic history
            self.traffic_history.append({
                "timestamp": current_time,
                "traffic": current_traffic
            })
            
            # Keep only recent history
            cutoff_time = current_time - self.stats_window
            self.traffic_history = [
                entry for entry in self.traffic_history 
                if entry["timestamp"] > cutoff_time
            ]
            
            # Calculate traffic metrics
            if self.traffic_history:
                recent_traffic = [entry["traffic"] for entry in self.traffic_history]
                avg_traffic = sum(recent_traffic) / len(recent_traffic)
                max_traffic = max(recent_traffic)
                
                # Update peak traffic
                self.peak_traffic = max(self.peak_traffic, max_traffic)
                
                # Adaptive scaling logic
                await self._adjust_limits_based_on_traffic(avg_traffic, max_traffic)
            
            self.last_adjustment = current_time
            
        except Exception as e:
            logger.error(f"Failed to update adaptive limits: {e}")
    
    async def _adjust_limits_based_on_traffic(self, avg_traffic: float, max_traffic: float):
        """Adjust rate limits based on traffic analysis."""
        try:
            # Calculate load factor
            base_global_limit = self.base_limits["global"]
            load_factor = max_traffic / base_global_limit if base_global_limit > 0 else 0
            
            # Adaptive scaling rules
            if load_factor > 0.9:  # High load - reduce limits
                scale_factor = 0.7
                logger.warning(f"High traffic detected ({load_factor:.2f}), reducing limits by 30%")
            elif load_factor > 0.7:  # Medium load - slight reduction
                scale_factor = 0.85
                logger.info(f"Medium traffic detected ({load_factor:.2f}), reducing limits by 15%")
            elif load_factor < 0.3:  # Low load - increase limits
                scale_factor = 1.2
                logger.info(f"Low traffic detected ({load_factor:.2f}), increasing limits by 20%")
            else:  # Normal load - maintain base limits
                scale_factor = 1.0
            
            # Apply scaling to all limits
            for rank in self.current_limits:
                base_limit = self.base_limits[rank]
                new_limit = int(base_limit * scale_factor)
                
                # Ensure minimum limits
                min_limits = {"global": 1000, "admin": 100, "moderator": 50, "user": 10, "guest": 5}
                new_limit = max(new_limit, min_limits.get(rank, 5))
                
                self.current_limits[rank] = new_limit
            
            logger.info(f"Adaptive limits updated: {self.current_limits}")
            
        except Exception as e:
            logger.error(f"Failed to adjust limits: {e}")
    
    async def _record_request(self, client_ip: str, user_rank: str, success: bool):
        """Record request for analytics."""
        try:
            # This could be expanded to store in database for analytics
            pass
        except Exception as e:
            logger.error(f"Failed to record request: {e}")
    
    async def _record_rate_limit_hit(self, limit_type: str):
        """Record rate limit hit for monitoring."""
        try:
            # This could trigger alerts or be stored for analysis
            logger.warning(f"Rate limit hit: {limit_type}")
        except Exception as e:
            logger.error(f"Failed to record rate limit hit: {e}")
    
    def _get_client_ip(self, request: Request) -> str:
        """Get client IP address."""
        # Check for forwarded headers first
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip
        
        # Fallback to direct client IP
        return request.client.host if request.client else "unknown"
    
    def _get_retry_after(self, user_rank: str) -> int:
        """Get retry-after time based on user rank."""
        retry_times = {
            "admin": 30,
            "moderator": 45,
            "user": 60,
            "guest": 120
        }
        return retry_times.get(user_rank, 60)
    
    def _create_rate_limit_response(self, message: str, retry_after: int) -> Response:
        """Create rate limit exceeded response."""
        return Response(
            content=f'{{"error": "{message}", "retry_after": {retry_after}}}',
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            headers={
                "Content-Type": "application/json",
                "Retry-After": str(retry_after),
                "X-RateLimit-Limit": str(self.current_limits.get("global", 0)),
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(int(time.time() + retry_after))
            }
        )
    
    def _add_rate_limit_headers(self, response: Response, user_rank: str):
        """Add rate limit headers to response."""
        try:
            current_limit = self.current_limits.get(user_rank, 0)
            response.headers["X-RateLimit-Limit"] = str(current_limit)
            response.headers["X-RateLimit-Window"] = "60"  # 1 minute window
            response.headers["X-RateLimit-Policy"] = f"adaptive-{user_rank}"
        except Exception as e:
            logger.error(f"Failed to add rate limit headers: {e}")

# Utility function to add middleware to FastAPI app
def add_global_rate_limiting(app: FastAPI):
    """Add global adaptive rate limiting middleware to FastAPI app."""
    app.add_middleware(GlobalAdaptiveRateLimitingMiddleware)
    logger.info("Global adaptive rate limiting middleware added to FastAPI app")
