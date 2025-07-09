"""
Circuit Breaker Pattern Implementation
Advanced error handling with circuit breakers and automatic recovery.
"""

import asyncio
import time
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Callable, Union
from enum import Enum
from dataclasses import dataclass, field
import threading
from functools import wraps

from app.logger_config import logger

class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Circuit is open, requests fail fast
    HALF_OPEN = "half_open"  # Testing if service is back

@dataclass
class CircuitBreakerConfig:
    """Circuit breaker configuration."""
    failure_threshold: int = 5          # Number of failures to open circuit
    recovery_timeout: int = 60          # Seconds before trying half-open
    success_threshold: int = 3          # Successes needed to close circuit
    timeout: float = 30.0               # Request timeout in seconds
    expected_exception: type = Exception # Exception type to count as failure

@dataclass
class CircuitBreakerStats:
    """Circuit breaker statistics."""
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    timeouts: int = 0
    circuit_opened_count: int = 0
    last_failure_time: Optional[datetime] = None
    last_success_time: Optional[datetime] = None

class CircuitBreaker:
    """Circuit breaker implementation."""
    
    def __init__(self, name: str, config: CircuitBreakerConfig = None):
        self.name = name
        self.config = config or CircuitBreakerConfig()
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time = None
        self.stats = CircuitBreakerStats()
        self.lock = threading.Lock()
        
    def __call__(self, func: Callable):
        """Decorator to wrap function with circuit breaker."""
        if asyncio.iscoroutinefunction(func):
            @wraps(func)
            async def async_wrapper(*args, **kwargs):
                return await self.call_async(func, *args, **kwargs)
            return async_wrapper
        else:
            @wraps(func)
            def sync_wrapper(*args, **kwargs):
                return self.call_sync(func, *args, **kwargs)
            return sync_wrapper
    
    async def call_async(self, func: Callable, *args, **kwargs):
        """Execute async function with circuit breaker protection."""
        with self.lock:
            self.stats.total_requests += 1
            
            # Check if circuit is open
            if self.state == CircuitState.OPEN:
                if self._should_attempt_reset():
                    self.state = CircuitState.HALF_OPEN
                    self.success_count = 0
                    logger.info(f"Circuit breaker {self.name} moved to HALF_OPEN")
                else:
                    logger.warning(f"Circuit breaker {self.name} is OPEN, failing fast")
                    raise CircuitBreakerOpenException(f"Circuit breaker {self.name} is open")
        
        try:
            # Execute function with timeout
            result = await asyncio.wait_for(func(*args, **kwargs), timeout=self.config.timeout)
            
            # Handle success
            with self.lock:
                self._on_success()
            
            return result
            
        except asyncio.TimeoutError:
            with self.lock:
                self.stats.timeouts += 1
                self._on_failure()
            raise CircuitBreakerTimeoutException(f"Function {func.__name__} timed out")
            
        except self.config.expected_exception as e:
            with self.lock:
                self._on_failure()
            raise
            
    def call_sync(self, func: Callable, *args, **kwargs):
        """Execute sync function with circuit breaker protection."""
        with self.lock:
            self.stats.total_requests += 1
            
            # Check if circuit is open
            if self.state == CircuitState.OPEN:
                if self._should_attempt_reset():
                    self.state = CircuitState.HALF_OPEN
                    self.success_count = 0
                    logger.info(f"Circuit breaker {self.name} moved to HALF_OPEN")
                else:
                    logger.warning(f"Circuit breaker {self.name} is OPEN, failing fast")
                    raise CircuitBreakerOpenException(f"Circuit breaker {self.name} is open")
        
        try:
            # Execute function
            result = func(*args, **kwargs)
            
            # Handle success
            with self.lock:
                self._on_success()
            
            return result
            
        except self.config.expected_exception as e:
            with self.lock:
                self._on_failure()
            raise
    
    def _on_success(self):
        """Handle successful execution."""
        self.stats.successful_requests += 1
        self.stats.last_success_time = datetime.utcnow()
        
        if self.state == CircuitState.HALF_OPEN:
            self.success_count += 1
            if self.success_count >= self.config.success_threshold:
                self.state = CircuitState.CLOSED
                self.failure_count = 0
                logger.info(f"Circuit breaker {self.name} moved to CLOSED")
        elif self.state == CircuitState.CLOSED:
            self.failure_count = 0
    
    def _on_failure(self):
        """Handle failed execution."""
        self.stats.failed_requests += 1
        self.stats.last_failure_time = datetime.utcnow()
        self.last_failure_time = time.time()
        self.failure_count += 1
        
        if (self.state == CircuitState.CLOSED and 
            self.failure_count >= self.config.failure_threshold):
            self.state = CircuitState.OPEN
            self.stats.circuit_opened_count += 1
            logger.warning(f"Circuit breaker {self.name} moved to OPEN after {self.failure_count} failures")
        elif self.state == CircuitState.HALF_OPEN:
            self.state = CircuitState.OPEN
            logger.warning(f"Circuit breaker {self.name} moved back to OPEN")
    
    def _should_attempt_reset(self) -> bool:
        """Check if circuit should attempt reset."""
        if self.last_failure_time is None:
            return True
        return time.time() - self.last_failure_time >= self.config.recovery_timeout
    
    def get_state(self) -> CircuitState:
        """Get current circuit state."""
        return self.state
    
    def get_stats(self) -> Dict[str, Any]:
        """Get circuit breaker statistics."""
        return {
            "name": self.name,
            "state": self.state.value,
            "failure_count": self.failure_count,
            "success_count": self.success_count,
            "stats": {
                "total_requests": self.stats.total_requests,
                "successful_requests": self.stats.successful_requests,
                "failed_requests": self.stats.failed_requests,
                "timeouts": self.stats.timeouts,
                "circuit_opened_count": self.stats.circuit_opened_count,
                "success_rate": (
                    self.stats.successful_requests / self.stats.total_requests * 100
                    if self.stats.total_requests > 0 else 0
                ),
                "last_failure_time": (
                    self.stats.last_failure_time.isoformat()
                    if self.stats.last_failure_time else None
                ),
                "last_success_time": (
                    self.stats.last_success_time.isoformat()
                    if self.stats.last_success_time else None
                )
            }
        }
    
    def reset(self):
        """Manually reset circuit breaker."""
        with self.lock:
            self.state = CircuitState.CLOSED
            self.failure_count = 0
            self.success_count = 0
            logger.info(f"Circuit breaker {self.name} manually reset")

class CircuitBreakerOpenException(Exception):
    """Exception raised when circuit breaker is open."""
    pass

class CircuitBreakerTimeoutException(Exception):
    """Exception raised when function times out."""
    pass

class CircuitBreakerManager:
    """Manages multiple circuit breakers."""
    
    def __init__(self):
        self.circuit_breakers: Dict[str, CircuitBreaker] = {}
        self.lock = threading.Lock()
    
    def get_circuit_breaker(self, name: str, config: CircuitBreakerConfig = None) -> CircuitBreaker:
        """Get or create circuit breaker."""
        with self.lock:
            if name not in self.circuit_breakers:
                self.circuit_breakers[name] = CircuitBreaker(name, config)
                logger.info(f"Created circuit breaker: {name}")
            return self.circuit_breakers[name]
    
    def get_all_stats(self) -> Dict[str, Any]:
        """Get statistics for all circuit breakers."""
        return {
            name: cb.get_stats()
            for name, cb in self.circuit_breakers.items()
        }
    
    def reset_all(self):
        """Reset all circuit breakers."""
        for cb in self.circuit_breakers.values():
            cb.reset()
        logger.info("All circuit breakers reset")
    
    def get_unhealthy_circuits(self) -> List[str]:
        """Get list of unhealthy circuit breakers."""
        unhealthy = []
        for name, cb in self.circuit_breakers.items():
            if cb.get_state() == CircuitState.OPEN:
                unhealthy.append(name)
        return unhealthy

# Decorator functions for easy use
def circuit_breaker(name: str, config: CircuitBreakerConfig = None):
    """Decorator to add circuit breaker to function."""
    cb = circuit_breaker_manager.get_circuit_breaker(name, config)
    return cb

def database_circuit_breaker(func):
    """Circuit breaker specifically for database operations."""
    config = CircuitBreakerConfig(
        failure_threshold=3,
        recovery_timeout=30,
        timeout=10.0
    )
    cb = circuit_breaker_manager.get_circuit_breaker("database", config)
    return cb(func)

def external_api_circuit_breaker(name: str):
    """Circuit breaker for external API calls."""
    def decorator(func):
        config = CircuitBreakerConfig(
            failure_threshold=5,
            recovery_timeout=60,
            timeout=30.0
        )
        cb = circuit_breaker_manager.get_circuit_breaker(f"external_api_{name}", config)
        return cb(func)
    return decorator

# Global circuit breaker manager
circuit_breaker_manager = CircuitBreakerManager()
