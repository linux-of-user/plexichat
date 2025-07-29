#!/usr/bin/env python3
"""
Dynamic Rate Limiting Middleware
Automatically adjusts rate limits based on system load, performance metrics, and traffic patterns
"""

import asyncio
import time
import psutil
import logging
from typing import Dict, Optional, Any, Callable, List
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import deque, defaultdict
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
import threading
import json

# Import configuration
try:
    from ..config.rate_limiting_config import get_rate_limiting_config, DynamicRateLimitConfig
except ImportError as e:
    print(f"Import error in dynamic rate limiting middleware: {e}")
    # Fallback
    def get_rate_limiting_config():
        return None

logger = logging.getLogger(__name__)

@dataclass
class SystemMetrics:
    """System performance metrics."""
    timestamp: float
    cpu_percent: float
    memory_percent: float
    disk_io_read: float
    disk_io_write: float
    network_io_sent: float
    network_io_recv: float
    active_connections: int
    response_time_avg: float
    error_rate: float

@dataclass
class TrafficMetrics:
    """Traffic and request metrics."""
    timestamp: float
    requests_per_second: float
    concurrent_requests: int
    queue_length: int
    bandwidth_usage: float
    endpoint_distribution: Dict[str, int] = field(default_factory=dict)
    status_code_distribution: Dict[int, int] = field(default_factory=dict)

@dataclass
class LoadLevel:
    """System load level definition."""
    name: str
    cpu_threshold: float
    memory_threshold: float
    response_time_threshold: float
    error_rate_threshold: float
    rate_limit_multiplier: float
    description: str

class DynamicRateLimitingMiddleware(BaseHTTPMiddleware):
    """Dynamic rate limiting middleware that adapts to system load."""
    
    def __init__(self, app):
        super().__init__(app)
        
        # Configuration
        self.config = get_rate_limiting_config()
        if not self.config:
            logger.warning("Rate limiting config not available, using defaults")
            self.enabled = False
            return
        
        self.dynamic_config = self.config.dynamic_config
        self.enabled = self.dynamic_config.enabled
        
        if not self.enabled:
            logger.info("Dynamic rate limiting is disabled")
            return
        
        # Metrics storage
        self.system_metrics: deque = deque(maxlen=100)
        self.traffic_metrics: deque = deque(maxlen=100)
        self.request_times: deque = deque(maxlen=1000)
        self.error_counts: deque = deque(maxlen=1000)
        
        # Current state
        self.current_load_level = "normal"
        self.current_multiplier = 1.0
        self.last_adjustment = time.time()
        self.concurrent_requests = 0
        self.request_queue_length = 0
        
        # Load levels
        self.load_levels = self._define_load_levels()
        
        # Monitoring task
        self._monitoring_task = None
        self._adjustment_task = None
        self._start_monitoring()
        
        logger.info("Dynamic rate limiting middleware initialized")
    
    def _define_load_levels(self) -> Dict[str, LoadLevel]:
        """Define system load levels and their characteristics."""
        return {
            "low": LoadLevel(
                name="low",
                cpu_threshold=self.dynamic_config.cpu_threshold_low,
                memory_threshold=self.dynamic_config.memory_threshold_low,
                response_time_threshold=50.0,  # 50ms
                error_rate_threshold=0.01,  # 1%
                rate_limit_multiplier=self.dynamic_config.low_load_multiplier,
                description="Low system load - increased rate limits"
            ),
            "normal": LoadLevel(
                name="normal",
                cpu_threshold=self.dynamic_config.cpu_threshold_medium,
                memory_threshold=self.dynamic_config.memory_threshold_medium,
                response_time_threshold=200.0,  # 200ms
                error_rate_threshold=0.05,  # 5%
                rate_limit_multiplier=self.dynamic_config.medium_load_multiplier,
                description="Normal system load - standard rate limits"
            ),
            "high": LoadLevel(
                name="high",
                cpu_threshold=self.dynamic_config.cpu_threshold_high,
                memory_threshold=self.dynamic_config.memory_threshold_high,
                response_time_threshold=500.0,  # 500ms
                error_rate_threshold=0.10,  # 10%
                rate_limit_multiplier=self.dynamic_config.high_load_multiplier,
                description="High system load - reduced rate limits"
            ),
            "critical": LoadLevel(
                name="critical",
                cpu_threshold=1.0,  # Above high threshold
                memory_threshold=1.0,  # Above high threshold
                response_time_threshold=1000.0,  # 1000ms
                error_rate_threshold=0.20,  # 20%
                rate_limit_multiplier=self.dynamic_config.critical_load_multiplier,
                description="Critical system load - severely reduced rate limits"
            )
        }
    
    def _start_monitoring(self):
        """Start background monitoring tasks."""
        if not self.enabled:
            return
        
        async def monitor_system():
            """Monitor system metrics continuously."""
            while True:
                try:
                    await asyncio.sleep(self.dynamic_config.monitoring_interval)
                    await self._collect_system_metrics()
                except Exception as e:
                    logger.error(f"Error in system monitoring: {e}")
        
        async def adjust_limits():
            """Adjust rate limits based on collected metrics."""
            while True:
                try:
                    await asyncio.sleep(self.dynamic_config.adjustment_interval)
                    await self._adjust_rate_limits()
                except Exception as e:
                    logger.error(f"Error in rate limit adjustment: {e}")
        
        # Start monitoring tasks
        if not self._monitoring_task or self._monitoring_task.done():
            self._monitoring_task = asyncio.create_task(monitor_system())
        
        if not self._adjustment_task or self._adjustment_task.done():
            self._adjustment_task = asyncio.create_task(adjust_limits())
    
    async def _collect_system_metrics(self):
        """Collect current system performance metrics."""
        try:
            # CPU and memory
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            
            # Disk I/O
            disk_io = psutil.disk_io_counters()
            disk_read = disk_io.read_bytes if disk_io else 0
            disk_write = disk_io.write_bytes if disk_io else 0
            
            # Network I/O
            network_io = psutil.net_io_counters()
            network_sent = network_io.bytes_sent if network_io else 0
            network_recv = network_io.bytes_recv if network_io else 0
            
            # Active connections
            try:
                connections = len(psutil.net_connections())
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                connections = 0
            
            # Calculate response time average
            response_time_avg = self._calculate_avg_response_time()
            
            # Calculate error rate
            error_rate = self._calculate_error_rate()
            
            # Store metrics
            metrics = SystemMetrics(
                timestamp=time.time(),
                cpu_percent=cpu_percent,
                memory_percent=memory_percent,
                disk_io_read=disk_read,
                disk_io_write=disk_write,
                network_io_sent=network_sent,
                network_io_recv=network_recv,
                active_connections=connections,
                response_time_avg=response_time_avg,
                error_rate=error_rate
            )
            
            self.system_metrics.append(metrics)
            
            # Also collect traffic metrics
            await self._collect_traffic_metrics()
            
        except Exception as e:
            logger.error(f"Error collecting system metrics: {e}")
    
    async def _collect_traffic_metrics(self):
        """Collect traffic and request metrics."""
        try:
            current_time = time.time()
            
            # Calculate requests per second (last minute)
            minute_ago = current_time - 60
            recent_requests = [t for t in self.request_times if t > minute_ago]
            requests_per_second = len(recent_requests) / 60.0
            
            # Calculate bandwidth usage (estimate)
            bandwidth_usage = self._estimate_bandwidth_usage()
            
            # Store traffic metrics
            traffic_metrics = TrafficMetrics(
                timestamp=current_time,
                requests_per_second=requests_per_second,
                concurrent_requests=self.concurrent_requests,
                queue_length=self.request_queue_length,
                bandwidth_usage=bandwidth_usage
            )
            
            self.traffic_metrics.append(traffic_metrics)
            
        except Exception as e:
            logger.error(f"Error collecting traffic metrics: {e}")
    
    async def _adjust_rate_limits(self):
        """Adjust rate limits based on current system state."""
        try:
            if not self.system_metrics:
                return
            
            # Get latest metrics
            latest_metrics = self.system_metrics[-1]
            
            # Determine current load level
            new_load_level = self._determine_load_level(latest_metrics)
            
            # Check if load level changed
            if new_load_level != self.current_load_level:
                old_level = self.current_load_level
                self.current_load_level = new_load_level
                self.current_multiplier = self.load_levels[new_load_level].rate_limit_multiplier
                self.last_adjustment = time.time()
                
                logger.info(f"Load level changed: {old_level} -> {new_load_level} "
                           f"(multiplier: {self.current_multiplier:.2f})")
                
                # Log detailed metrics
                logger.info(f"System metrics - CPU: {latest_metrics.cpu_percent:.1f}%, "
                           f"Memory: {latest_metrics.memory_percent:.1f}%, "
                           f"Response time: {latest_metrics.response_time_avg:.1f}ms, "
                           f"Error rate: {latest_metrics.error_rate:.2%}")
            
        except Exception as e:
            logger.error(f"Error adjusting rate limits: {e}")
    
    def _determine_load_level(self, metrics: SystemMetrics) -> str:
        """Determine current load level based on metrics."""
        # Check critical level first
        if (metrics.cpu_percent > self.load_levels["high"].cpu_threshold * 100 or
            metrics.memory_percent > self.load_levels["high"].memory_threshold * 100 or
            metrics.response_time_avg > self.load_levels["critical"].response_time_threshold or
            metrics.error_rate > self.load_levels["critical"].error_rate_threshold):
            return "critical"
        
        # Check high level
        if (metrics.cpu_percent > self.load_levels["normal"].cpu_threshold * 100 or
            metrics.memory_percent > self.load_levels["normal"].memory_threshold * 100 or
            metrics.response_time_avg > self.load_levels["high"].response_time_threshold or
            metrics.error_rate > self.load_levels["high"].error_rate_threshold):
            return "high"
        
        # Check low level
        if (metrics.cpu_percent < self.load_levels["low"].cpu_threshold * 100 and
            metrics.memory_percent < self.load_levels["low"].memory_threshold * 100 and
            metrics.response_time_avg < self.load_levels["low"].response_time_threshold and
            metrics.error_rate < self.load_levels["low"].error_rate_threshold):
            return "low"
        
        # Default to normal
        return "normal"
    
    def _calculate_avg_response_time(self) -> float:
        """Calculate average response time from recent requests."""
        if not self.request_times:
            return 0.0
        
        # This is a simplified calculation
        # In a real implementation, you'd track actual response times
        recent_count = len([t for t in self.request_times if t > time.time() - 60])
        
        # Estimate response time based on load
        if recent_count > 100:
            return min(recent_count * 2, 1000)  # Cap at 1000ms
        return max(10, recent_count * 0.5)  # Minimum 10ms
    
    def _calculate_error_rate(self) -> float:
        """Calculate error rate from recent requests."""
        if not self.error_counts:
            return 0.0
        
        current_time = time.time()
        minute_ago = current_time - 60
        
        recent_errors = [t for t in self.error_counts if t > minute_ago]
        recent_requests = [t for t in self.request_times if t > minute_ago]
        
        if not recent_requests:
            return 0.0
        
        return len(recent_errors) / len(recent_requests)
    
    def _estimate_bandwidth_usage(self) -> float:
        """Estimate current bandwidth usage."""
        # This is a simplified estimation
        # In a real implementation, you'd track actual bytes transferred
        recent_requests = len([t for t in self.request_times if t > time.time() - 1])
        return recent_requests * 1024  # Estimate 1KB per request
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Main middleware dispatch method."""
        if not self.enabled:
            return await call_next(request)
        
        start_time = time.time()
        
        # Track concurrent requests
        self.concurrent_requests += 1
        
        try:
            # Process request
            response = await call_next(request)
            
            # Record request timing
            end_time = time.time()
            self.request_times.append(start_time)
            
            # Record errors
            if response.status_code >= 400:
                self.error_counts.append(start_time)
            
            # Add dynamic rate limiting headers
            self._add_dynamic_headers(response)
            
            return response
            
        except Exception as e:
            # Record error
            self.error_counts.append(start_time)
            raise
        finally:
            # Decrement concurrent requests
            self.concurrent_requests = max(0, self.concurrent_requests - 1)
    
    def _add_dynamic_headers(self, response: Response):
        """Add dynamic rate limiting headers to response."""
        try:
            response.headers["X-Dynamic-Rate-Limit-Level"] = self.current_load_level
            response.headers["X-Dynamic-Rate-Limit-Multiplier"] = f"{self.current_multiplier:.2f}"
            response.headers["X-Dynamic-Rate-Limit-Adjusted"] = str(int(self.last_adjustment))
            
            if self.system_metrics:
                latest = self.system_metrics[-1]
                response.headers["X-System-Load-CPU"] = f"{latest.cpu_percent:.1f}"
                response.headers["X-System-Load-Memory"] = f"{latest.memory_percent:.1f}"
        except Exception as e:
            logger.error(f"Error adding dynamic headers: {e}")
    
    def get_current_multiplier(self) -> float:
        """Get current rate limit multiplier."""
        return self.current_multiplier if self.enabled else 1.0
    
    def get_load_status(self) -> Dict[str, Any]:
        """Get current load status and metrics."""
        if not self.enabled:
            return {"enabled": False}
        
        latest_system = self.system_metrics[-1] if self.system_metrics else None
        latest_traffic = self.traffic_metrics[-1] if self.traffic_metrics else None
        
        return {
            "enabled": True,
            "current_load_level": self.current_load_level,
            "current_multiplier": self.current_multiplier,
            "last_adjustment": self.last_adjustment,
            "system_metrics": {
                "cpu_percent": latest_system.cpu_percent if latest_system else 0,
                "memory_percent": latest_system.memory_percent if latest_system else 0,
                "response_time_avg": latest_system.response_time_avg if latest_system else 0,
                "error_rate": latest_system.error_rate if latest_system else 0,
            } if latest_system else {},
            "traffic_metrics": {
                "requests_per_second": latest_traffic.requests_per_second if latest_traffic else 0,
                "concurrent_requests": self.concurrent_requests,
                "bandwidth_usage": latest_traffic.bandwidth_usage if latest_traffic else 0,
            } if latest_traffic else {},
            "load_levels": {name: level.description for name, level in self.load_levels.items()}
        }

# Utility function to add middleware to FastAPI app
def add_dynamic_rate_limiting_middleware(app):
    """Add dynamic rate limiting middleware to FastAPI app."""
    app.add_middleware(DynamicRateLimitingMiddleware)
    logger.info("Dynamic rate limiting middleware added to FastAPI app")
