import asyncio
import json
import logging
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from functools import wraps
from pathlib import Path
from typing import Any, Dict, List, Optional

import redis

from pathlib import Path
from datetime import datetime
from datetime import datetime
from datetime import datetime
from datetime import datetime
from datetime import datetime
from datetime import datetime
from datetime import datetime
from datetime import datetime
from datetime import datetime
from datetime import datetime
from datetime import datetime


from pathlib import Path
from datetime import datetime
from datetime import datetime
from datetime import datetime
from datetime import datetime
from datetime import datetime
from datetime import datetime
from datetime import datetime
from datetime import datetime
from datetime import datetime
from datetime import datetime
from datetime import datetime

from fastapi import HTTPException, Request
from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

"""
Advanced Per-User Rate Limiting System for PlexiChat
Comprehensive rate limiting with granular controls for different resource types.
"""

class LimitType(Enum):
    """Types of rate limits."""
    API_CALLS = "api_calls"
    FILE_UPLOADS = "file_uploads"
    CHAT_MESSAGES = "chat_messages"
    EMOJI_REACTIONS = "emoji_reactions"
    PROFILE_UPDATES = "profile_updates"
    TOTAL_STORAGE = "total_storage"
    BANDWIDTH = "bandwidth"
    CONCURRENT_CONNECTIONS = "concurrent_connections"
    LOGIN_ATTEMPTS = "login_attempts"
    REQUESTS = "requests"
    DDOS_PROTECTION = "ddos_protection"

class LimitPeriod(Enum):
    """Rate limit time periods."""
    SECOND = "second"
    MINUTE = "minute"
    HOUR = "hour"
    DAY = "day"
    WEEK = "week"
    MONTH = "month"

@dataclass
class RateLimit:
    """Rate limit configuration."""
    limit_type: LimitType
    period: LimitPeriod
    max_requests: int
    max_size_bytes: Optional[int] = None
    burst_allowance: int = 0
    reset_on_success: bool = False

@dataclass
class UserLimits:
    """Per-user rate limit configuration."""
    user_id: str
    username: str
    user_tier: str = "standard"  # standard, premium, enterprise
    custom_limits: Dict[str, RateLimit] = None
    is_active: bool = True
    created_at: datetime = None
    updated_at: datetime = None

@dataclass
class RateLimitStatus:
    """Current rate limit status for a user."""
    user_id: str
    limit_type: LimitType
    current_count: int
    max_allowed: int
    reset_time: datetime
    is_exceeded: bool
    remaining: int

class RateLimitAction(Enum):
    """Actions to take when rate limit is exceeded."""
    BLOCK = "block"
    DELAY = "delay"
    WARN = "warn"
    QUARANTINE = "quarantine"
    BAN_IP = "ban_ip"
    BAN_USER = "ban_user"
    THROTTLE = "throttle"

@dataclass
class RateLimitViolation:
    """Rate limit violation record."""
    timestamp: float
    client_ip: str
    user_id: Optional[str]
    limit_type: LimitType
    current_count: int
    max_allowed: int
    action_taken: RateLimitAction
    endpoint: Optional[str] = None
    user_agent: Optional[str] = None
    severity: str = "medium"  # low, medium, high, critical

@dataclass
class EnhancedRateLimit(RateLimit):
    """Enhanced rate limit with additional security features."""
    action: RateLimitAction = RateLimitAction.BLOCK
    delay_seconds: int = 0
    ban_duration: int = 3600  # seconds
    whitelist_ips: List[str] = None
    blacklist_ips: List[str] = None
    user_roles: List[str] = None  # Apply to specific roles
    endpoints: List[str] = None  # Apply to specific endpoints
    enabled: bool = True
    priority: int = 1  # Higher priority rules are checked first

    def __post_init__(self):
        super().__post_init__() if hasattr(super(), '__post_init__') else None
        if self.whitelist_ips is None:
            self.whitelist_ips = []
        if self.blacklist_ips is None:
            self.blacklist_ips = []
        if self.user_roles is None:
            self.user_roles = []
        if self.endpoints is None:
            self.endpoints = []

class AdvancedRateLimiter:
    """Advanced rate limiting system with per-user granular controls."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Storage backends
        self.redis_client = None
        self.db_session = None
        self.memory_store = defaultdict(lambda: defaultdict(deque))
        
        # Configuration
        self.config_file = from pathlib import Path
Path("config/rate_limits.json")
        self.default_limits = self._load_default_limits()
        self.user_limits = {}
        
        # Performance tracking
        self.request_times = defaultdict(deque)
        self.blocked_requests = defaultdict(int)
        
        # Initialize storage
        self._init_storage()
        self._load_user_limits()
        
        # Start cleanup task
        self._start_cleanup_task()
    
    def _load_default_limits(self) -> Dict[str, Dict[LimitType, RateLimit]]:
        """Load default rate limits for different user tiers."""
        return {
            "standard": {
                LimitType.API_CALLS: RateLimit(LimitType.API_CALLS, LimitPeriod.MINUTE, 100, burst_allowance=20),
                LimitType.FILE_UPLOADS: RateLimit(LimitType.FILE_UPLOADS, LimitPeriod.HOUR, 50, max_size_bytes=100*1024*1024),
                LimitType.CHAT_MESSAGES: RateLimit(LimitType.CHAT_MESSAGES, LimitPeriod.MINUTE, 30),
                LimitType.TOTAL_STORAGE: RateLimit(LimitType.TOTAL_STORAGE, LimitPeriod.MONTH, 1, max_size_bytes=1*1024*1024*1024),
                LimitType.BANDWIDTH: RateLimit(LimitType.BANDWIDTH, LimitPeriod.DAY, 1, max_size_bytes=10*1024*1024*1024),
                LimitType.CONCURRENT_CONNECTIONS: RateLimit(LimitType.CONCURRENT_CONNECTIONS, LimitPeriod.SECOND, 10),
                LimitType.LOGIN_ATTEMPTS: RateLimit(LimitType.LOGIN_ATTEMPTS, LimitPeriod.HOUR, 10)
            },
            "premium": {
                LimitType.API_CALLS: RateLimit(LimitType.API_CALLS, LimitPeriod.MINUTE, 500, burst_allowance=100),
                LimitType.FILE_UPLOADS: RateLimit(LimitType.FILE_UPLOADS, LimitPeriod.HOUR, 200, max_size_bytes=500*1024*1024),
                LimitType.CHAT_MESSAGES: RateLimit(LimitType.CHAT_MESSAGES, LimitPeriod.MINUTE, 100),
                LimitType.TOTAL_STORAGE: RateLimit(LimitType.TOTAL_STORAGE, LimitPeriod.MONTH, 1, max_size_bytes=10*1024*1024*1024),
                LimitType.BANDWIDTH: RateLimit(LimitType.BANDWIDTH, LimitPeriod.DAY, 1, max_size_bytes=100*1024*1024*1024),
                LimitType.CONCURRENT_CONNECTIONS: RateLimit(LimitType.CONCURRENT_CONNECTIONS, LimitPeriod.SECOND, 50),
                LimitType.LOGIN_ATTEMPTS: RateLimit(LimitType.LOGIN_ATTEMPTS, LimitPeriod.HOUR, 20)
            },
            "enterprise": {
                LimitType.API_CALLS: RateLimit(LimitType.API_CALLS, LimitPeriod.MINUTE, 2000, burst_allowance=500),
                LimitType.FILE_UPLOADS: RateLimit(LimitType.FILE_UPLOADS, LimitPeriod.HOUR, 1000, max_size_bytes=2*1024*1024*1024),
                LimitType.CHAT_MESSAGES: RateLimit(LimitType.CHAT_MESSAGES, LimitPeriod.MINUTE, 500),
                LimitType.TOTAL_STORAGE: RateLimit(LimitType.TOTAL_STORAGE, LimitPeriod.MONTH, 1, max_size_bytes=100*1024*1024*1024),
                LimitType.BANDWIDTH: RateLimit(LimitType.BANDWIDTH, LimitPeriod.DAY, 1, max_size_bytes=1000*1024*1024*1024),
                LimitType.CONCURRENT_CONNECTIONS: RateLimit(LimitType.CONCURRENT_CONNECTIONS, LimitPeriod.SECOND, 200),
                LimitType.LOGIN_ATTEMPTS: RateLimit(LimitType.LOGIN_ATTEMPTS, LimitPeriod.HOUR, 50)
            }
        }
    
    def _init_storage(self):
        """Initialize storage backends."""
        try:
            # Try Redis first
            self.redis_client = redis.Redis(host='localhost', port=6379, db=1, decode_responses=True)
            self.redis_client.ping()
            self.logger.info("Redis connected for rate limiting")
        except Exception as e:
            self.logger.warning(f"Redis not available for rate limiting: {e}")
            self.redis_client = None
        
        # Initialize SQLite for persistent storage
        try:
            self.engine = create_engine('sqlite:///rate_limits.db')
            self._create_tables()
            Session = sessionmaker(bind=self.engine)
            self.db_session = Session()
            self.logger.info("SQLite initialized for rate limiting")
        except Exception as e:
            self.logger.error(f"Failed to initialize database: {e}")
    
    def _create_tables(self):
        """Create database tables for rate limiting."""
        Base = declarative_base()
        
        class UserRateLimit(Base):
            __tablename__ = 'user_rate_limits'
            
            id = Column(String, primary_key=True)
            user_id = Column(String, nullable=False)
            limit_type = Column(String, nullable=False)
            current_count = Column(Integer, default=0)
            reset_time = Column(DateTime, nullable=False)
            max_allowed = Column(Integer, nullable=False)
            created_at = Column(DateTime, default=datetime.utcnow)
        
        class UserLimitConfig(Base):
            __tablename__ = 'user_limit_configs'
            
            user_id = Column(String, primary_key=True)
            username = Column(String, nullable=False)
            user_tier = Column(String, default='standard')
            custom_limits = Column(Text)  # JSON
            is_active = Column(Boolean, default=True)
            created_at = Column(DateTime, default=datetime.utcnow)
            updated_at = Column(DateTime, default=datetime.utcnow)
        
        Base.metadata.create_all(self.engine)
        self.UserRateLimit = UserRateLimit
        self.UserLimitConfig = UserLimitConfig
    
    async def check_rate_limit(self, user_id: str, limit_type: LimitType, 
                              request_size: int = 1, ip_address: str = None) -> RateLimitStatus:
        """Check if user has exceeded rate limit."""
        try:
            # Get user limits
            user_limits = self._get_user_limits(user_id)
            if not user_limits or not user_limits.is_active:
                raise HTTPException(status_code=403, detail="User rate limiting not configured")
            
            # Get specific limit
            limit_config = self._get_limit_config(user_limits, limit_type)
            if not limit_config:
                raise HTTPException(status_code=400, detail=f"Rate limit not configured for {limit_type.value}")
            
            # Check current usage
            current_usage = await self._get_current_usage(user_id, limit_type)
            reset_time = self._get_reset_time(limit_config.period)
            
            # Calculate remaining allowance
            max_allowed = limit_config.max_requests
            if limit_config.burst_allowance > 0:
                max_allowed += self._calculate_burst_allowance(user_id, limit_type, limit_config)
            
            # Check size limits for file uploads and storage
            if limit_config.max_size_bytes and request_size > limit_config.max_size_bytes:
                raise HTTPException(
                    status_code=413, 
                    detail=f"Request size {request_size} exceeds limit {limit_config.max_size_bytes}"
                )
            
            # Check if limit exceeded
            new_count = current_usage + request_size
            is_exceeded = new_count > max_allowed
            
            status = RateLimitStatus(
                user_id=user_id,
                limit_type=limit_type,
                current_count=current_usage,
                max_allowed=max_allowed,
                reset_time=reset_time,
                is_exceeded=is_exceeded,
                remaining=max(0, max_allowed - current_usage)
            )
            
            if is_exceeded:
                self.blocked_requests[user_id] += 1
                self.logger.warning(f"Rate limit exceeded for user {user_id}: {limit_type.value}")
                raise HTTPException(
                    status_code=429,
                    detail=f"Rate limit exceeded for {limit_type.value}. Try again at {reset_time}",
                    headers={
                        "X-RateLimit-Limit": str(max_allowed),
                        "X-RateLimit-Remaining": str(status.remaining),
                        "X-RateLimit-Reset": str(int(reset_time.timestamp())),
                        "Retry-After": str(int((reset_time - from datetime import datetime
datetime.now()).total_seconds()))
                    }
                )
            
            # Update usage
            await self._update_usage(user_id, limit_type, request_size)
            
            return status
            
        except HTTPException:
            raise
        except Exception as e:
            self.logger.error(f"Rate limit check failed: {e}")
            # Fail open for availability
            return RateLimitStatus(
                user_id=user_id,
                limit_type=limit_type,
                current_count=0,
                max_allowed=999999,
                reset_time=from datetime import datetime
datetime.now() + timedelta(hours=1),
                is_exceeded=False,
                remaining=999999
            )
    
    async def _get_current_usage(self, user_id: str, limit_type: LimitType) -> int:
        """Get current usage for user and limit type."""
        key = f"rate_limit:{user_id}:{limit_type.value}"
        
        if self.redis_client:
            try:
                usage = self.redis_client.get(key)
                return int(usage) if usage else 0
            except Exception as e:
                self.logger.warning(f"Redis get failed: {e}")
        
        # Fallback to memory store
        now = from datetime import datetime
datetime.now()
        usage_queue = self.memory_store[user_id][limit_type.value]
        
        # Remove expired entries
        while usage_queue and usage_queue[0][1] < now:
            usage_queue.popleft()
        
        return sum(entry[0] for entry in usage_queue)
    
    async def _update_usage(self, user_id: str, limit_type: LimitType, amount: int):
        """Update usage counter."""
        key = f"rate_limit:{user_id}:{limit_type.value}"
        
        if self.redis_client:
            try:
                # Get limit config to determine TTL
                user_limits = self._get_user_limits(user_id)
                limit_config = self._get_limit_config(user_limits, limit_type)
                ttl = self._get_period_seconds(limit_config.period)
                
                # Atomic increment with expiry
                pipe = self.redis_client.pipeline()
                pipe.incr(key, amount)
                pipe.expire(key, ttl)
                pipe.execute()
                return
            except Exception as e:
                self.logger.warning(f"Redis update failed: {e}")
        
        # Fallback to memory store
        expire_time = from datetime import datetime
datetime.now() + timedelta(seconds=self._get_period_seconds(
            self._get_limit_config(self._get_user_limits(user_id), limit_type).period
        ))
        self.memory_store[user_id][limit_type.value].append((amount, expire_time))
    
    def _get_user_limits(self, user_id: str) -> Optional[UserLimits]:
        """Get user rate limit configuration."""
        if user_id in self.user_limits:
            return self.user_limits[user_id]
        
        # Try to load from database
        if self.db_session:
            try:
                config = self.db_session.query(self.UserLimitConfig).filter_by(user_id=user_id).first()
                if config:
                    custom_limits = json.loads(config.custom_limits) if config.custom_limits else None
                    user_limits = UserLimits(
                        user_id=config.user_id,
                        username=config.username,
                        user_tier=config.user_tier,
                        custom_limits=custom_limits,
                        is_active=config.is_active,
                        created_at=config.created_at,
                        updated_at=config.updated_at
                    )
                    self.user_limits[user_id] = user_limits
                    return user_limits
            except Exception as e:
                self.logger.error(f"Failed to load user limits: {e}")
        
        # Return default for standard tier
        return UserLimits(
            user_id=user_id,
            username=f"user_{user_id}",
            user_tier="standard",
            is_active=True,
            created_at=from datetime import datetime
datetime.now()
        )
    
    def _get_limit_config(self, user_limits: UserLimits, limit_type: LimitType) -> Optional[RateLimit]:
        """Get specific rate limit configuration."""
        # Check custom limits first
        if user_limits.custom_limits and limit_type.value in user_limits.custom_limits:
            return user_limits.custom_limits[limit_type.value]
        
        # Use default for user tier
        tier_limits = self.default_limits.get(user_limits.user_tier, self.default_limits["standard"])
        return tier_limits.get(limit_type)
    
    def _get_reset_time(self, period: LimitPeriod) -> datetime:
        """Calculate when the rate limit resets."""
        now = from datetime import datetime
datetime.now()
        
        if period == LimitPeriod.SECOND:
            return now.replace(microsecond=0) + timedelta(seconds=1)
        elif period == LimitPeriod.MINUTE:
            return now.replace(second=0, microsecond=0) + timedelta(minutes=1)
        elif period == LimitPeriod.HOUR:
            return now.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
        elif period == LimitPeriod.DAY:
            return now.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
        elif period == LimitPeriod.WEEK:
            days_ahead = 6 - now.weekday()
            return (now + timedelta(days=days_ahead)).replace(hour=0, minute=0, second=0, microsecond=0)
        elif period == LimitPeriod.MONTH:
            if now.month == 12:
                return now.replace(year=now.year+1, month=1, day=1, hour=0, minute=0, second=0, microsecond=0)
            else:
                return now.replace(month=now.month+1, day=1, hour=0, minute=0, second=0, microsecond=0)
        
        return now + timedelta(hours=1)  # Default fallback
    
    def _get_period_seconds(self, period: LimitPeriod) -> int:
        """Get period duration in seconds."""
        periods = {
            LimitPeriod.SECOND: 1,
            LimitPeriod.MINUTE: 60,
            LimitPeriod.HOUR: 3600,
            LimitPeriod.DAY: 86400,
            LimitPeriod.WEEK: 604800,
            LimitPeriod.MONTH: 2592000  # 30 days
        }
        return periods.get(period, 3600)
    
    def _calculate_burst_allowance(self, user_id: str, limit_type: LimitType, limit_config: RateLimit) -> int:
        """Calculate available burst allowance."""
        # Simple implementation - could be more sophisticated
        recent_usage = len(self.request_times[user_id])
        if recent_usage < limit_config.max_requests * 0.5:  # If under 50% usage
            return limit_config.burst_allowance
        return 0
    
    def create_user_limits(self, user_id: str, username: str, user_tier: str = "standard", 
                          custom_limits: Dict[str, RateLimit] = None) -> UserLimits:
        """Create or update user rate limit configuration."""
        user_limits = UserLimits(
            user_id=user_id,
            username=username,
            user_tier=user_tier,
            custom_limits=custom_limits,
            is_active=True,
            created_at=from datetime import datetime
datetime.now(),
            updated_at=from datetime import datetime
datetime.now()
        )
        
        # Store in memory
        self.user_limits[user_id] = user_limits
        
        # Store in database
        if self.db_session:
            try:
                config = self.UserLimitConfig(
                    user_id=user_id,
                    username=username,
                    user_tier=user_tier,
                    custom_limits=json.dumps(custom_limits) if custom_limits else None,
                    is_active=True,
                    created_at=from datetime import datetime
datetime.now(),
                    updated_at=from datetime import datetime
datetime.now()
                )
                self.db_session.merge(config)
                self.db_session.commit()
            except Exception as e:
                self.logger.error(f"Failed to save user limits: {e}")
        
        return user_limits
    
    def _load_user_limits(self):
        """Load all user limits from database."""
        if not self.db_session:
            return
        
        try:
            configs = self.db_session.query(self.UserLimitConfig).all()
            for config in configs:
                custom_limits = json.loads(config.custom_limits) if config.custom_limits else None
                user_limits = UserLimits(
                    user_id=config.user_id,
                    username=config.username,
                    user_tier=config.user_tier,
                    custom_limits=custom_limits,
                    is_active=config.is_active,
                    created_at=config.created_at,
                    updated_at=config.updated_at
                )
                self.user_limits[config.user_id] = user_limits
            
            self.logger.info(f"Loaded {len(configs)} user rate limit configurations")
        except Exception as e:
            self.logger.error(f"Failed to load user limits: {e}")
    
    def _start_cleanup_task(self):
        """Start background cleanup task."""
        def cleanup():
            while True:
                try:
                    # Clean up expired memory entries
                    now = from datetime import datetime
datetime.now()
                    for user_id in list(self.memory_store.keys()):
                        for limit_type in list(self.memory_store[user_id].keys()):
                            queue = self.memory_store[user_id][limit_type]
                            while queue and queue[0][1] < now:
                                queue.popleft()
                            
                            # Remove empty queues
                            if not queue:
                                del self.memory_store[user_id][limit_type]
                        
                        # Remove empty user entries
                        if not self.memory_store[user_id]:
                            del self.memory_store[user_id]
                    
                    # Clean up request times
                    cutoff = now - timedelta(hours=1)
                    for user_id in list(self.request_times.keys()):
                        queue = self.request_times[user_id]
                        while queue and queue[0] < cutoff:
                            queue.popleft()
                        
                        if not queue:
                            del self.request_times[user_id]
                    
                    time.sleep(300)  # Clean up every 5 minutes
                except Exception as e:
                    self.logger.error(f"Cleanup task error: {e}")
                    time.sleep(60)
        
        threading.Thread(target=cleanup, daemon=True).start()
    
    def get_user_status(self, user_id: str) -> Dict[str, Any]:
        """Get comprehensive rate limit status for user."""
        user_limits = self._get_user_limits(user_id)
        if not user_limits:
            return {"error": "User not found"}
        
        status = {
            "user_id": user_id,
            "username": user_limits.username,
            "user_tier": user_limits.user_tier,
            "is_active": user_limits.is_active,
            "limits": {},
            "blocked_requests": self.blocked_requests.get(user_id, 0)
        }
        
        # Get status for each limit type
        for limit_type in LimitType:
            limit_config = self._get_limit_config(user_limits, limit_type)
            if limit_config:
                try:
                    current_usage = asyncio.run(self._get_current_usage(user_id, limit_type))
                    status["limits"][limit_type.value] = {
                        "current_usage": current_usage,
                        "max_allowed": limit_config.max_requests,
                        "period": limit_config.period.value,
                        "max_size_bytes": limit_config.max_size_bytes,
                        "reset_time": self._get_reset_time(limit_config.period).isoformat()
                    }
                except Exception as e:
                    self.logger.error(f"Failed to get status for {limit_type}: {e}")
        
        return status

# Rate limiting decorators and middleware
def rate_limit(limit_type: LimitType, request_size: int = 1):
    """Decorator for rate limiting endpoints."""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract request and user info
            request = None
            user_id = None

            # Find request object in args/kwargs
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break

            if not request:
                for key, value in kwargs.items():
                    if isinstance(value, Request):
                        request = value
                        break

            if not request:
                raise HTTPException(status_code=500, detail="Request object not found for rate limiting")

            # Extract user ID from request (you'll need to implement this based on your auth system)
            user_id = await extract_user_id(request)
            if not user_id:
                raise HTTPException(status_code=401, detail="Authentication required for rate limiting")

            # Check rate limit
            ip_address = request.client.host if request.client else None
            await rate_limiter.check_rate_limit(user_id, limit_type, request_size, ip_address)

            # Call original function
            return await func(*args, **kwargs)

        return wrapper
    return decorator

async def extract_user_id(request: Request) -> Optional[str]:
    """Extract user ID from request. Implement based on your auth system."""
    # Try to get from session
    if hasattr(request.state, 'user_id'):
        return request.state.user_id

    # Try to get from headers
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        # You would decode the JWT token here
        # For now, return a placeholder
        return "user_from_token"

    # Try to get from cookies
    session_cookie = request.cookies.get('plexichat_session')
    if session_cookie:
        # You would validate the session here
        # For now, return a placeholder
        return "user_from_session"

    return None

class RateLimitMiddleware:
    """Middleware for automatic rate limiting."""

    def __init__(self, app):
        self.app = app
        self.rate_limiter = rate_limiter

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive)

        # Skip rate limiting for certain paths
        skip_paths = ["/health", "/docs", "/openapi.json", "/static"]
        if any(request.url.path.startswith(path) for path in skip_paths):
            await self.app(scope, receive, send)
            return

        try:
            # Extract user ID
            user_id = await extract_user_id(request)
            if user_id:
                # Apply general API rate limiting
                ip_address = request.client.host if request.client else None
                await self.rate_limiter.check_rate_limit(
                    user_id,
                    LimitType.API_CALLS,
                    1,
                    ip_address
                )

            await self.app(scope, receive, send)

        except HTTPException as e:
            # Send rate limit error response
            response = {
                "error": "Rate limit exceeded",
                "detail": e.detail,
                "status_code": e.status_code
            }

            await send({
                "type": "http.response.start",
                "status": e.status_code,
                "headers": [
                    [b"content-type", b"application/json"],
                    *[[k.encode(), v.encode()] for k, v in (e.headers or {}).items()]
                ],
            })

            await send({
                "type": "http.response.body",
                "body": json.dumps(response).encode(),
            })

# IP-based rate limiting for DDoS protection
class IPRateLimiter:
    """IP-based rate limiting for DDoS protection."""

    def __init__(self):
        self.ip_requests = defaultdict(deque)
        self.blocked_ips = set()
        self.suspicious_ips = defaultdict(int)

        # Configuration
        self.max_requests_per_minute = 300
        self.max_requests_per_hour = 3000
        self.block_duration = 3600  # 1 hour
        self.suspicious_threshold = 100

        # Start cleanup
        self._start_ip_cleanup()

    async def check_ip_rate_limit(self, ip_address: str) -> bool:
        """Check if IP is rate limited."""
        if not ip_address:
            return True

        # Check if IP is blocked
        if ip_address in self.blocked_ips:
            raise HTTPException(
                status_code=429,
                detail="IP address temporarily blocked due to excessive requests",
                headers={"Retry-After": str(self.block_duration)}
            )

        now = time.time()
        requests = self.ip_requests[ip_address]

        # Remove old requests
        while requests and requests[0] < now - 3600:  # Remove requests older than 1 hour
            requests.popleft()

        # Check hourly limit
        if len(requests) >= self.max_requests_per_hour:
            self.blocked_ips.add(ip_address)
            self.suspicious_ips[ip_address] += 1
            raise HTTPException(
                status_code=429,
                detail="Hourly rate limit exceeded",
                headers={"Retry-After": str(self.block_duration)}
            )

        # Check per-minute limit
        recent_requests = sum(1 for req_time in requests if req_time > now - 60)
        if recent_requests >= self.max_requests_per_minute:
            self.suspicious_ips[ip_address] += 1
            if self.suspicious_ips[ip_address] >= self.suspicious_threshold:
                self.blocked_ips.add(ip_address)

            raise HTTPException(
                status_code=429,
                detail="Rate limit exceeded",
                headers={"Retry-After": "60"}
            )

        # Record request
        requests.append(now)
        return True

    def _start_ip_cleanup(self):
        """Start IP cleanup task."""
        def cleanup():
            while True:
                try:
                    now = time.time()

                    # Clean up old requests
                    for ip in list(self.ip_requests.keys()):
                        requests = self.ip_requests[ip]
                        while requests and requests[0] < now - 3600:
                            requests.popleft()

                        if not requests:
                            del self.ip_requests[ip]

                    # Unblock IPs after block duration
                    # In a real implementation, you'd store block times
                    # For now, we'll clear blocks periodically
                    if len(self.blocked_ips) > 1000:  # Prevent memory bloat
                        self.blocked_ips.clear()
                        self.suspicious_ips.clear()

                    time.sleep(300)  # Clean up every 5 minutes
                except Exception as e:
                    logging.getLogger(__name__).error(f"IP cleanup error: {e}")
                    time.sleep(60)

        threading.Thread(target=cleanup, daemon=True).start()

# Global instances
rate_limiter = AdvancedRateLimiter()
ip_rate_limiter = IPRateLimiter()

# Dependencies for FastAPI
async def get_rate_limiter():
    return rate_limiter

async def get_ip_rate_limiter():
    return ip_rate_limiter

async def check_ip_rate_limit(request: Request):
    """Dependency to check IP rate limits."""
    ip_address = request.client.host if request.client else None
    await ip_rate_limiter.check_ip_rate_limit(ip_address)
    return True
