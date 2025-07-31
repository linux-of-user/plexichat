#!/usr/bin/env python3
"""
Account-Type Based Rate Limiting Middleware
Implements different rate limits based on user account types (user, bot, admin, etc.)
"""

import time
import asyncio
from typing import Dict, Optional, Any, Callable
from fastapi import Request, Response, HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
import logging
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta

# Import configuration
try:
    from ..config.rate_limiting_config import (
        get_rate_limiting_config, AccountType, get_account_rate_limit
    )
except ImportError as e:
    print(f"Import error in account rate limiting middleware: {e}")
    # Fallback
    class AccountType:
        GUEST = "guest"
        USER = "user"
        BOT = "bot"
        ADMIN = "admin"
    
    def get_rate_limiting_config():
        return None
    
    def get_account_rate_limit(account_type, endpoint=None):
        return {"enabled": False}

logger = logging.getLogger(__name__)

@dataclass
class RateLimitInfo:
    """Information about rate limiting for a request."""
    account_type: AccountType
    endpoint: str
    requests_per_minute: int
    requests_per_hour: int
    concurrent_requests: int
    bandwidth_per_second: int
    burst_allowance: int
    dynamic_multiplier: float = 1.0

@dataclass
class RequestRecord:
    """Record of a single request for rate limiting."""
    timestamp: float
    endpoint: str
    ip_address: str
    user_id: Optional[str]
    account_type: AccountType
    bytes_transferred: int = 0

class AccountRateLimitingMiddleware(BaseHTTPMiddleware):
    """Account-type based rate limiting middleware."""
    
    def __init__(self, app):
        super().__init__(app)
        self.request_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.concurrent_requests: Dict[str, int] = defaultdict(int)
        self.bandwidth_usage: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        self.blocked_until: Dict[str, float] = {}
        
        # Cleanup task
        self._cleanup_task = None
        self._start_cleanup_task()
        
        logger.info("Account-based rate limiting middleware initialized")
    
    def _start_cleanup_task(self):
        """Start background cleanup task."""
        async def cleanup_old_records():
            while True:
                try:
                    await asyncio.sleep(60)  # Cleanup every minute
                    await self._cleanup_old_records()
                except Exception as e:
                    logger.error(f"Error in cleanup task: {e}")
        
        if not self._cleanup_task or self._cleanup_task.done():
            self._cleanup_task = asyncio.create_task(cleanup_old_records())
    
    async def _cleanup_old_records(self):
        """Clean up old request records."""
        current_time = time.time()
        cutoff_time = current_time - 3600  # Keep records for 1 hour
        
        for key in list(self.request_history.keys()):
            history = self.request_history[key]
            # Remove old records
            while history and history[0].timestamp < cutoff_time:
                history.popleft()
            
            # Remove empty histories
            if not history:
                del self.request_history[key]
        
        # Clean up expired blocks
        for key in list(self.blocked_until.keys()):
            if self.blocked_until[key] < current_time:
                del self.blocked_until[key]
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Main middleware dispatch method."""
        try:
            # Get rate limiting configuration
            config = get_rate_limiting_config()
            if not config or not config.global_enabled:
                return await call_next(request)
            
            # Extract request information
            client_ip = self._get_client_ip(request)
            endpoint = request.url.path
            user_info = await self._get_user_info(request)
            account_type = self._determine_account_type(user_info)
            
            # Get rate limit configuration for this account type and endpoint
            rate_limit_config = get_account_rate_limit(account_type, endpoint)
            if not rate_limit_config.get("enabled", False):
                return await call_next(request)
            
            # Create rate limit info
            rate_limit_info = RateLimitInfo(
                account_type=account_type,
                endpoint=endpoint,
                requests_per_minute=rate_limit_config.get("global_requests_per_minute", 60),
                requests_per_hour=rate_limit_config.get("global_requests_per_hour", 1000),
                concurrent_requests=rate_limit_config.get("concurrent_requests", 10),
                bandwidth_per_second=rate_limit_config.get("bandwidth_per_second", 1024*1024),
                burst_allowance=rate_limit_config.get("endpoint_burst_allowance", 5),
                dynamic_multiplier=rate_limit_config.get("dynamic_multiplier", 1.0)
            )
            
            # Check IP blacklist
            if config.is_ip_blacklisted(client_ip):
                logger.warning(f"Blocked request from blacklisted IP: {client_ip}")
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "Access denied",
                        "message": "Your IP address has been blocked",
                        "code": "IP_BLACKLISTED"
                    }
                )
            
            # Generate rate limiting key
            rate_key = self._generate_rate_key(client_ip, user_info, account_type)
            
            # Check if currently blocked
            if rate_key in self.blocked_until:
                if time.time() < self.blocked_until[rate_key]:
                    return self._create_rate_limit_response(
                        "Rate limit exceeded - temporarily blocked",
                        rate_limit_info,
                        retry_after=int(self.blocked_until[rate_key] - time.time())
                    )
                else:
                    del self.blocked_until[rate_key]
            
            # Check concurrent requests
            if self.concurrent_requests[rate_key] >= rate_limit_info.concurrent_requests:
                return self._create_rate_limit_response(
                    "Too many concurrent requests",
                    rate_limit_info
                )
            
            # Check rate limits
            rate_limit_check = await self._check_rate_limits(rate_key, rate_limit_info)
            if not rate_limit_check["allowed"]:
                # Apply temporary block for severe violations
                if rate_limit_check.get("severe_violation", False):
                    self.blocked_until[rate_key] = time.time() + 300  # 5 minute block
                
                return self._create_rate_limit_response(
                    rate_limit_check["message"],
                    rate_limit_info,
                    retry_after=rate_limit_check.get("retry_after", 60)
                )
            
            # Track concurrent request
            self.concurrent_requests[rate_key] += 1
            
            try:
                # Process request
                start_time = time.time()
                response = await call_next(request)
                end_time = time.time()
                
                # Record request
                request_record = RequestRecord(
                    timestamp=start_time,
                    endpoint=endpoint,
                    ip_address=client_ip,
                    user_id=user_info.get("id") if user_info else None,
                    account_type=account_type,
                    bytes_transferred=self._estimate_response_size(response)
                )
                
                self.request_history[rate_key].append(request_record)
                
                # Add rate limit headers
                self._add_rate_limit_headers(response, rate_limit_info, rate_key)
                
                return response
                
            finally:
                # Decrement concurrent request counter
                self.concurrent_requests[rate_key] = max(0, self.concurrent_requests[rate_key] - 1)
        
        except Exception as e:
            logger.error(f"Error in account rate limiting middleware: {e}")
            # Continue processing on middleware error
            return await call_next(request)
    
    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP address."""
        # Check for forwarded headers
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
        
        return request.client.host if request.client else "unknown"
    
    async def _get_user_info(self, request: Request) -> Optional[Dict[str, Any]]:
        """Extract user information from request."""
        try:
            # Try to get user info from request state (set by auth middleware)
            if hasattr(request.state, "user"):
                return request.state.user
            
            # Try to extract from Authorization header
            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                # This would normally validate the token and return user info
                # For now, return None to indicate guest user
                pass
            
            return None
        except Exception as e:
            logger.debug(f"Error getting user info: {e}")
            return None
    
    def _determine_account_type(self, user_info: Optional[Dict[str, Any]]) -> AccountType:
        """Determine account type from user information."""
        if not user_info:
            return AccountType.GUEST
        
        # Check for admin role
        if user_info.get("is_admin", False) or user_info.get("role") == "admin":
            return AccountType.ADMIN
        
        # Check for moderator role
        if user_info.get("role") == "moderator":
            return AccountType.MODERATOR
        
        # Check for bot account
        if user_info.get("is_bot", False) or user_info.get("account_type") == "bot":
            return AccountType.BOT
        
        # Default to regular user
        return AccountType.USER
    
    def _generate_rate_key(self, ip: str, user_info: Optional[Dict[str, Any]], account_type: AccountType) -> str:
        """Generate unique key for rate limiting."""
        if user_info and user_info.get("id"):
            return f"user:{user_info['id']}:{account_type.value}"
        else:
            return f"ip:{ip}:{account_type.value}"
    
    async def _check_rate_limits(self, rate_key: str, rate_limit_info: RateLimitInfo) -> Dict[str, Any]:
        """Check if request is within rate limits."""
        current_time = time.time()
        history = self.request_history[rate_key]
        
        # Apply dynamic multiplier
        requests_per_minute = int(rate_limit_info.requests_per_minute * rate_limit_info.dynamic_multiplier)
        requests_per_hour = int(rate_limit_info.requests_per_hour * rate_limit_info.dynamic_multiplier)
        
        # Count requests in the last minute
        minute_ago = current_time - 60
        minute_requests = sum(1 for record in history if record.timestamp > minute_ago)
        
        # Count requests in the last hour
        hour_ago = current_time - 3600
        hour_requests = sum(1 for record in history if record.timestamp > hour_ago)
        
        # Check minute limit
        if minute_requests >= requests_per_minute:
            # Check if this is a severe violation (way over limit)
            severe_violation = minute_requests > requests_per_minute * 2
            return {
                "allowed": False,
                "message": f"Rate limit exceeded: {minute_requests}/{requests_per_minute} requests per minute",
                "retry_after": 60,
                "severe_violation": severe_violation
            }
        
        # Check hour limit
        if hour_requests >= requests_per_hour:
            return {
                "allowed": False,
                "message": f"Rate limit exceeded: {hour_requests}/{requests_per_hour} requests per hour",
                "retry_after": 3600
            }
        
        # Check burst limit (requests in last 10 seconds)
        burst_ago = current_time - 10
        burst_requests = sum(1 for record in history if record.timestamp > burst_ago)
        
        if burst_requests >= rate_limit_info.burst_allowance:
            return {
                "allowed": False,
                "message": f"Burst limit exceeded: {burst_requests}/{rate_limit_info.burst_allowance} requests in 10 seconds",
                "retry_after": 10
            }
        
        return {"allowed": True}
    
    def _create_rate_limit_response(self, message: str, rate_limit_info: RateLimitInfo, 
                                  retry_after: int = 60) -> JSONResponse:
        """Create rate limit exceeded response."""
        return JSONResponse(
            status_code=429,
            content={
                "error": "Rate limit exceeded",
                "message": message,
                "account_type": rate_limit_info.account_type.value,
                "endpoint": rate_limit_info.endpoint,
                "retry_after": retry_after,
                "limits": {
                    "requests_per_minute": int(rate_limit_info.requests_per_minute * rate_limit_info.dynamic_multiplier),
                    "requests_per_hour": int(rate_limit_info.requests_per_hour * rate_limit_info.dynamic_multiplier),
                    "concurrent_requests": rate_limit_info.concurrent_requests,
                    "burst_allowance": rate_limit_info.burst_allowance
                },
                "code": "RATE_LIMIT_EXCEEDED"
            },
            headers={
                "Retry-After": str(retry_after),
                "X-RateLimit-Limit": str(int(rate_limit_info.requests_per_minute * rate_limit_info.dynamic_multiplier)),
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(int(time.time() + retry_after))
            }
        )
    
    def _add_rate_limit_headers(self, response: Response, rate_limit_info: RateLimitInfo, rate_key: str):
        """Add rate limiting headers to response."""
        try:
            current_time = time.time()
            history = self.request_history[rate_key]
            
            # Calculate remaining requests
            minute_ago = current_time - 60
            minute_requests = sum(1 for record in history if record.timestamp > minute_ago)
            
            requests_per_minute = int(rate_limit_info.requests_per_minute * rate_limit_info.dynamic_multiplier)
            remaining = max(0, requests_per_minute - minute_requests)
            
            response.headers["X-RateLimit-Limit"] = str(requests_per_minute)
            response.headers["X-RateLimit-Remaining"] = str(remaining)
            response.headers["X-RateLimit-Reset"] = str(int(current_time + 60))
            response.headers["X-RateLimit-Policy"] = f"{rate_limit_info.account_type.value}-{rate_limit_info.dynamic_multiplier:.2f}"
            
        except Exception as e:
            logger.error(f"Error adding rate limit headers: {e}")
    
    def _estimate_response_size(self, response: Response) -> int:
        """Estimate response size for bandwidth tracking."""
        try:
            if hasattr(response, "body") and response.body:
                return len(response.body)
            return 0
        except Exception:
            return 0

# Utility function to add middleware to FastAPI app
def add_account_rate_limiting_middleware(app):
    """Add account-based rate limiting middleware to FastAPI app."""
    app.add_middleware(AccountRateLimitingMiddleware)
    logger.info("Account-based rate limiting middleware added to FastAPI app")
