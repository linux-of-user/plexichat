#!/usr/bin/env python3
"""
Integrated Protection System for PlexiChat

Combines DDoS protection, rate limiting, and dynamic scaling based on system load.
Provides fair and comprehensive protection with account type support.
"""

import asyncio
import time
from typing import Dict, Any, Optional, Tuple, List
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque

# Import psutil safely
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

# Import logging safely
try:
    from ..logging.unified_logger import get_logger, LogCategory
    logger = get_logger("integrated_protection")
except ImportError:
    import logging
    logger = logging.getLogger("integrated_protection")

# Import other components safely
try:
    from ..middleware.unified_rate_limiter import (
        UnifiedRateLimiter, RateLimitConfig, RateLimitStrategy, RateLimitAlgorithm, RateLimitViolation
    )
except ImportError:
    # Create minimal fallback classes
    class RateLimitStrategy:
        PER_IP = "per_ip"
        PER_USER = "per_user"

    class RateLimitConfig:
        def __init__(self):
            self.enabled = True
            self.per_ip_requests_per_minute = 60

    class UnifiedRateLimiter:
        def __init__(self, config):
            self.config = config

class SystemLoadLevel(Enum):
    """System load levels for dynamic scaling."""
    LOW = "low"           # < 30% load
    NORMAL = "normal"     # 30-70% load  
    HIGH = "high"         # 70-90% load
    CRITICAL = "critical" # > 90% load

@dataclass
class SystemMetrics:
    """Current system metrics."""
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    disk_usage: float = 0.0
    network_io: float = 0.0
    active_connections: int = 0
    requests_per_second: float = 0.0
    load_level: SystemLoadLevel = SystemLoadLevel.NORMAL
    timestamp: float = field(default_factory=time.time)

@dataclass
class DynamicLimits:
    """Dynamic rate limits based on system load and account type."""
    base_limit: int
    current_limit: int
    load_multiplier: float
    account_multiplier: float
    burst_allowance: int
    fairness_factor: float = 1.0

class IntegratedProtectionSystem:
    """
    Integrated protection system combining:
    - DDoS protection
    - Dynamic rate limiting
    - Account type-based limits
    - System load-based scaling
    - Fairness algorithms
    """
    
    def __init__(self, rate_limit_config: Optional[RateLimitConfig] = None):
        # Core components
        self.rate_limiter = UnifiedRateLimiter(rate_limit_config or RateLimitConfig())
        self.ddos_service = EnhancedDDoSProtectionService()
        
        # System monitoring
        self.system_metrics = SystemMetrics()
        self.metrics_history = deque(maxlen=300)  # 5 minutes of data
        
        # Dynamic scaling configuration
        self.load_multipliers = {
            SystemLoadLevel.LOW: 1.5,      # Allow 50% more requests
            SystemLoadLevel.NORMAL: 1.0,   # Normal limits
            SystemLoadLevel.HIGH: 0.7,     # Reduce to 70%
            SystemLoadLevel.CRITICAL: 0.3  # Emergency mode - 30%
        }
        
        # Account type configurations
        self.account_limits: Dict[AccountType, AccountTypeRateLimit] = {}
        self._load_account_configurations()
        
        # Fairness tracking
        self.user_request_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        self.fairness_weights: Dict[str, float] = defaultdict(lambda: 1.0)
        
        # Statistics
        self.protection_stats = {
            "total_requests": 0,
            "blocked_by_ddos": 0,
            "blocked_by_rate_limit": 0,
            "dynamic_adjustments": 0,
            "fairness_adjustments": 0,
            "load_level_changes": 0
        }
        
        # Background tasks
        self._monitoring_task = None
        self._start_monitoring()
        
        if hasattr(logger, 'info'):
            logger.info("Integrated Protection System initialized", LogCategory.STARTUP)
        else:
            print("[INFO] Integrated Protection System initialized")
    
    def _load_account_configurations(self):
        """Load account type configurations."""
        # Default configurations for different account types
        self.account_limits = {
            AccountType.GUEST: AccountTypeRateLimit(
                account_type=AccountType.GUEST,
                global_requests_per_minute=30,
                global_requests_per_hour=300,
                concurrent_requests=3,
                bandwidth_per_second=256 * 1024  # 256KB/s
            ),
            AccountType.USER: AccountTypeRateLimit(
                account_type=AccountType.USER,
                global_requests_per_minute=120,
                global_requests_per_hour=2400,
                concurrent_requests=10,
                bandwidth_per_second=2 * 1024 * 1024  # 2MB/s
            ),
            AccountType.BOT: AccountTypeRateLimit(
                account_type=AccountType.BOT,
                global_requests_per_minute=600,
                global_requests_per_hour=12000,
                concurrent_requests=50,
                bandwidth_per_second=10 * 1024 * 1024  # 10MB/s
            ),
            AccountType.MODERATOR: AccountTypeRateLimit(
                account_type=AccountType.MODERATOR,
                global_requests_per_minute=300,
                global_requests_per_hour=6000,
                concurrent_requests=25,
                bandwidth_per_second=5 * 1024 * 1024  # 5MB/s
            ),
            AccountType.ADMIN: AccountTypeRateLimit(
                account_type=AccountType.ADMIN,
                global_requests_per_minute=1000,
                global_requests_per_hour=20000,
                concurrent_requests=100,
                bandwidth_per_second=50 * 1024 * 1024  # 50MB/s
            )
        }
    
    def _start_monitoring(self):
        """Start background monitoring tasks."""
        async def monitoring_loop():
            while True:
                try:
                    await self._update_system_metrics()
                    await self._adjust_dynamic_limits()
                    await self._update_fairness_weights()
                    await asyncio.sleep(1)  # Update every second
                except Exception as e:
                    if hasattr(logger, 'error'):
                        logger.error(f"Monitoring loop error: {e}", LogCategory.PERFORMANCE)
                    else:
                        print(f"[ERROR] Monitoring loop error: {e}")
                    await asyncio.sleep(5)
        
        self._monitoring_task = asyncio.create_task(monitoring_loop())
    
    async def _update_system_metrics(self):
        """Update current system metrics."""
        try:
            if PSUTIL_AVAILABLE:
                # Get system metrics using psutil
                cpu_percent = psutil.cpu_percent(interval=None)
                memory = psutil.virtual_memory()
                try:
                    disk = psutil.disk_usage('/')
                    disk_percent = disk.percent
                except:
                    disk_percent = 0.0

                # Update metrics
                self.system_metrics.cpu_usage = cpu_percent
                self.system_metrics.memory_usage = memory.percent
                self.system_metrics.disk_usage = disk_percent
            else:
                # Fallback metrics (simulated)
                import os
                try:
                    # Simple load average on Unix systems
                    if hasattr(os, 'getloadavg'):
                        load_avg = os.getloadavg()[0]
                        self.system_metrics.cpu_usage = min(load_avg * 20, 100)  # Rough approximation
                    else:
                        self.system_metrics.cpu_usage = 25.0  # Default moderate load
                except:
                    self.system_metrics.cpu_usage = 25.0

                self.system_metrics.memory_usage = 50.0  # Default
                self.system_metrics.disk_usage = 30.0    # Default

            self.system_metrics.timestamp = time.time()

            # Determine load level
            max_usage = max(self.system_metrics.cpu_usage, self.system_metrics.memory_usage)
            if max_usage < 30:
                new_load_level = SystemLoadLevel.LOW
            elif max_usage < 70:
                new_load_level = SystemLoadLevel.NORMAL
            elif max_usage < 90:
                new_load_level = SystemLoadLevel.HIGH
            else:
                new_load_level = SystemLoadLevel.CRITICAL

            if new_load_level != self.system_metrics.load_level:
                if hasattr(logger, 'info'):
                    logger.info(f"System load level changed: {self.system_metrics.load_level.value} -> {new_load_level.value}", LogCategory.PERFORMANCE)
                else:
                    print(f"[INFO] System load level changed: {self.system_metrics.load_level.value} -> {new_load_level.value}")
                self.protection_stats["load_level_changes"] += 1
                self.system_metrics.load_level = new_load_level

            # Store in history
            self.metrics_history.append(self.system_metrics)

        except Exception as e:
            if hasattr(logger, 'error'):
                logger.error(f"Failed to update system metrics: {e}", LogCategory.PERFORMANCE)
            else:
                print(f"[ERROR] Failed to update system metrics: {e}")
    
    async def _adjust_dynamic_limits(self):
        """Adjust rate limits based on current system load."""
        try:
            load_multiplier = self.load_multipliers[self.system_metrics.load_level]
            
            # Update rate limiter configuration
            current_config = self.rate_limiter.config
            
            # Calculate new limits
            new_per_ip = int(current_config.per_ip_requests_per_minute * load_multiplier)
            new_per_user = int(current_config.per_user_requests_per_minute * load_multiplier)
            new_global = int(current_config.global_requests_per_minute * load_multiplier)
            
            # Apply changes if significant difference
            if abs(new_per_ip - current_config.per_ip_requests_per_minute) > 5:
                current_config.per_ip_requests_per_minute = new_per_ip
                current_config.per_user_requests_per_minute = new_per_user
                current_config.global_requests_per_minute = new_global
                
                self.protection_stats["dynamic_adjustments"] += 1
                logger.debug(f"📊 Dynamic limits adjusted: IP={new_per_ip}, User={new_per_user}, Global={new_global}")
                
        except Exception as e:
            logger.error(f"Failed to adjust dynamic limits: {e}")
    
    async def _update_fairness_weights(self):
        """Update fairness weights based on usage patterns."""
        try:
            current_time = time.time()
            
            for user_id, request_history in self.user_request_history.items():
                # Remove old requests (older than 5 minutes)
                while request_history and request_history[0] < current_time - 300:
                    request_history.popleft()
                
                # Calculate fairness weight
                recent_requests = len(request_history)
                if recent_requests > 0:
                    # Users with fewer recent requests get higher weight (more allowance)
                    avg_requests = sum(len(h) for h in self.user_request_history.values()) / len(self.user_request_history)
                    if avg_requests > 0:
                        fairness_ratio = avg_requests / recent_requests
                        self.fairness_weights[user_id] = min(2.0, max(0.5, fairness_ratio))
                
        except Exception as e:
            logger.error(f"Failed to update fairness weights: {e}")
    
    def _get_account_type(self, request: Request) -> AccountType:
        """Determine account type from request."""
        # Check if user is authenticated and get account type
        user_data = getattr(request.state, 'user', None)
        if user_data:
            account_type_str = user_data.get('account_type', 'USER')
            try:
                return AccountType(account_type_str.upper())
            except ValueError:
                return AccountType.USER
        
        # Default to guest for unauthenticated requests
        return AccountType.GUEST
    
    def _calculate_dynamic_limits(self, account_type: AccountType, user_id: Optional[str] = None) -> DynamicLimits:
        """Calculate dynamic limits for account type and current conditions."""
        base_config = self.account_limits.get(account_type, self.account_limits[AccountType.GUEST])
        
        # Get base limit
        base_limit = base_config.global_requests_per_minute
        
        # Apply load multiplier
        load_multiplier = self.load_multipliers[self.system_metrics.load_level]
        
        # Apply account type multiplier
        account_multipliers = {
            AccountType.GUEST: 0.5,
            AccountType.USER: 1.0,
            AccountType.BOT: 3.0,
            AccountType.MODERATOR: 2.0,
            AccountType.ADMIN: 5.0
        }
        account_multiplier = account_multipliers.get(account_type, 1.0)
        
        # Apply fairness factor
        fairness_factor = 1.0
        if user_id:
            fairness_factor = self.fairness_weights.get(user_id, 1.0)
        
        # Calculate final limit
        current_limit = int(base_limit * load_multiplier * account_multiplier * fairness_factor)
        
        return DynamicLimits(
            base_limit=base_limit,
            current_limit=current_limit,
            load_multiplier=load_multiplier,
            account_multiplier=account_multiplier,
            burst_allowance=base_config.concurrent_requests,
            fairness_factor=fairness_factor
        )
    
    async def check_request(self, request: Request) -> Optional[Dict[str, Any]]:
        """
        Check if request should be allowed through integrated protection.
        
        Returns None if allowed, or dict with block info if blocked.
        """
        try:
            self.protection_stats["total_requests"] += 1
            
            # Extract request info
            client_ip = request.client.host if request.client else "unknown"
            user_agent = request.headers.get("User-Agent", "")
            endpoint = request.url.path
            method = request.method
            
            # Get user info
            user_data = getattr(request.state, 'user', None)
            user_id = user_data.get('id') if user_data else None
            account_type = self._get_account_type(request)
            
            # 1. DDoS Protection Check
            ddos_allowed, ddos_reason, ddos_metadata = await self.ddos_service.check_request(
                client_ip, user_agent, endpoint, method
            )
            
            if not ddos_allowed:
                self.protection_stats["blocked_by_ddos"] += 1
                return {
                    "blocked": True,
                    "reason": "ddos_protection",
                    "details": ddos_reason,
                    "metadata": ddos_metadata,
                    "retry_after": 60
                }
            
            # 2. Dynamic Rate Limiting Check
            dynamic_limits = self._calculate_dynamic_limits(account_type, user_id)
            
            # Update rate limiter with dynamic limits
            self.rate_limiter.config.per_user_requests_per_minute = dynamic_limits.current_limit
            
            # Check rate limits
            violation = await self.rate_limiter.check_rate_limits(request)
            
            if violation:
                self.protection_stats["blocked_by_rate_limit"] += 1
                return {
                    "blocked": True,
                    "reason": "rate_limit_exceeded",
                    "strategy": violation.strategy.value,
                    "limit": violation.limit,
                    "current": violation.current,
                    "retry_after": violation.retry_after,
                    "account_type": account_type.value,
                    "dynamic_limits": {
                        "base_limit": dynamic_limits.base_limit,
                        "current_limit": dynamic_limits.current_limit,
                        "load_multiplier": dynamic_limits.load_multiplier,
                        "account_multiplier": dynamic_limits.account_multiplier,
                        "fairness_factor": dynamic_limits.fairness_factor
                    }
                }
            
            # 3. Update fairness tracking
            if user_id:
                self.user_request_history[user_id].append(time.time())
            
            # Request allowed
            return None
            
        except Exception as e:
            logger.error(f"Integrated protection check failed: {e}")
            # Allow request on error to avoid breaking the application
            return None

    def get_comprehensive_stats(self) -> Dict[str, Any]:
        """Get comprehensive protection statistics."""
        ddos_metrics = self.ddos_service.get_metrics()
        rate_limit_stats = self.rate_limiter.get_stats()

        return {
            "system_metrics": {
                "cpu_usage": self.system_metrics.cpu_usage,
                "memory_usage": self.system_metrics.memory_usage,
                "disk_usage": self.system_metrics.disk_usage,
                "load_level": self.system_metrics.load_level.value,
                "requests_per_second": self.system_metrics.requests_per_second
            },
            "protection_stats": self.protection_stats,
            "ddos_metrics": {
                "total_requests": ddos_metrics.total_requests,
                "blocked_requests": ddos_metrics.blocked_requests,
                "threat_level": ddos_metrics.threat_level.value,
                "active_blocks": ddos_metrics.active_blocks,
                "unique_ips": ddos_metrics.unique_ips
            },
            "rate_limit_stats": rate_limit_stats,
            "dynamic_scaling": {
                "current_multipliers": {level.value: mult for level, mult in self.load_multipliers.items()},
                "active_users": len(self.user_request_history),
                "fairness_adjustments": len([w for w in self.fairness_weights.values() if w != 1.0])
            },
            "account_type_limits": {
                account_type.value: {
                    "requests_per_minute": config.global_requests_per_minute,
                    "concurrent_requests": config.concurrent_requests,
                    "bandwidth_per_second": config.bandwidth_per_second
                }
                for account_type, config in self.account_limits.items()
            }
        }

    def update_account_limits(self, account_type: AccountType, limits: AccountTypeRateLimit):
        """Update rate limits for a specific account type."""
        self.account_limits[account_type] = limits
        logger.info(f"Updated rate limits for {account_type.value}: {limits.global_requests_per_minute} req/min")

    def adjust_load_multipliers(self, multipliers: Dict[SystemLoadLevel, float]):
        """Adjust load multipliers for dynamic scaling."""
        self.load_multipliers.update(multipliers)
        logger.info(f"Updated load multipliers: {multipliers}")

    async def shutdown(self):
        """Shutdown the integrated protection system."""
        if self._monitoring_task:
            self._monitoring_task.cancel()
            try:
                await self._monitoring_task
            except asyncio.CancelledError:
                pass

        logger.info("🛡️  Integrated Protection System shutdown")

class IntegratedProtectionMiddleware:
    """FastAPI middleware for integrated protection system."""

    def __init__(self, rate_limit_config: Optional[RateLimitConfig] = None):
        self.protection_system = IntegratedProtectionSystem(rate_limit_config)

    async def __call__(self, request: Request, call_next):
        """Process request through integrated protection."""
        try:
            # Check protection systems
            block_info = await self.protection_system.check_request(request)

            if block_info and block_info.get("blocked"):
                # Create appropriate response based on block reason
                if block_info["reason"] == "ddos_protection":
                    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
                    message = "Service temporarily unavailable due to high load"
                else:
                    status_code = status.HTTP_429_TOO_MANY_REQUESTS
                    message = "Rate limit exceeded"

                response_data = {
                    "error": message,
                    "reason": block_info["reason"],
                    "retry_after": block_info.get("retry_after", 60)
                }

                # Add detailed info for rate limiting
                if "dynamic_limits" in block_info:
                    response_data["limits"] = block_info["dynamic_limits"]
                    response_data["account_type"] = block_info.get("account_type")

                headers = {
                    "Retry-After": str(block_info.get("retry_after", 60)),
                    "X-Protection-Reason": block_info["reason"]
                }

                # Add rate limit headers if available
                if "limit" in block_info:
                    headers.update({
                        "X-RateLimit-Limit": str(block_info["limit"]),
                        "X-RateLimit-Remaining": str(max(0, block_info["limit"] - block_info.get("current", 0))),
                        "X-RateLimit-Reset": str(int(time.time() + block_info.get("retry_after", 60)))
                    })

                return JSONResponse(
                    status_code=status_code,
                    content=response_data,
                    headers=headers
                )

            # Process request
            response = await call_next(request)

            # Add protection info headers to successful responses
            stats = self.protection_system.get_comprehensive_stats()
            response.headers["X-System-Load"] = stats["system_metrics"]["load_level"]
            response.headers["X-Protection-Active"] = "true"

            return response

        except Exception as e:
            logger.error(f"Integrated protection middleware error: {e}")
            # Continue processing on error to avoid breaking the application
            return await call_next(request)

    def get_stats(self) -> Dict[str, Any]:
        """Get comprehensive protection statistics."""
        return self.protection_system.get_comprehensive_stats()

    async def shutdown(self):
        """Shutdown the middleware."""
        await self.protection_system.shutdown()

# Global instance
_global_protection_system: Optional[IntegratedProtectionSystem] = None

def get_protection_system() -> IntegratedProtectionSystem:
    """Get the global protection system instance."""
    global _global_protection_system
    if _global_protection_system is None:
        _global_protection_system = IntegratedProtectionSystem()
    return _global_protection_system

def configure_protection_system(rate_limit_config: RateLimitConfig):
    """Configure the global protection system."""
    global _global_protection_system
    _global_protection_system = IntegratedProtectionSystem(rate_limit_config)
