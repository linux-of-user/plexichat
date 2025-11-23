Prevents cascading failures by temporarily disabling failing services.
"""

logger = logging.getLogger(__name__)


class CircuitState(Enum):
    """Circuit breaker states."""

    CLOSED = "CLOSED"  # Normal operation
    OPEN = "OPEN"  # Circuit is open, calls are blocked
    HALF_OPEN = "HALF_OPEN"  # Testing if service has recovered


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker."""

    failure_threshold: int = 5  # Number of failures before opening
    timeout_seconds: int = 60  # Time to wait before trying again
    recovery_timeout: int = 30  # Time to wait in half-open state
    expected_exceptions: list[type[Exception]] | None = None
    success_threshold: int = 3  # Successes needed to close from half-open

    def __post_init__(self):
        if self.expected_exceptions is None:
            self.expected_exceptions = [Exception]


class CircuitBreakerStats:
    """Statistics for circuit breaker."""

    def __init__(self):
        self.total_calls = 0
        self.successful_calls = 0
        self.failed_calls = 0
        self.circuit_open_count = 0
        self.last_failure_time: float | None = None
        self.last_success_time: float | None = None
        self.consecutive_failures = 0
        self.consecutive_successes = 0


class CircuitBreakerError(Exception):
    """Raised when circuit breaker is open."""

    def __init__(self, message: str = "Circuit breaker is open"):
        super().__init__(message)
        self.message = message


class CircuitBreaker:
    """Advanced circuit breaker implementation."""

    def __init__(self, name: str, config: CircuitBreakerConfig | None = None):
        self.name = name
        self.config = config or CircuitBreakerConfig()
        self.state = CircuitState.CLOSED
        self.stats = CircuitBreakerStats()
        self.last_failure_time: float | None = None
        self.state_change_time = time.time()
        self._lock = asyncio.Lock()

    async def call(self, func: Callable, *args, **kwargs):
        """Execute function with circuit breaker protection."""
        async with self._lock:
            # Check if we should attempt the call
            if not self._should_attempt_call():
                self.stats.total_calls += 1
                raise CircuitBreakerError(f"Circuit breaker '{self.name}' is open")

            # Update state if needed
            await self._update_state()

        # Attempt the call
        self.stats.total_calls += 1
        time.time()

        try:
            if asyncio.iscoroutinefunction(func):
                result = await func(*args, **kwargs)
            else:
                result = func(*args, **kwargs)

            # Call succeeded
            await self._on_success()
            return result

        except Exception as e:
            # Check if this is an expected exception
            if self._is_expected_exception(e):
                await self._on_failure()
            raise e

    def _should_attempt_call(self) -> bool:
        """Check if we should attempt the call based on current state."""
        if self.state == CircuitState.CLOSED:
            return True
        elif self.state == CircuitState.OPEN:
            # Check if timeout has passed
            if time.time() - self.state_change_time >= self.config.timeout_seconds:
                return True
            return False
        elif self.state == CircuitState.HALF_OPEN:
            return True
        return False

    async def _update_state(self):
        """Update circuit breaker state based on current conditions."""
        current_time = time.time()

        if self.state == CircuitState.OPEN:
            if current_time - self.state_change_time >= self.config.timeout_seconds:
                self._transition_to_half_open()
        elif self.state == CircuitState.HALF_OPEN:
            if current_time - self.state_change_time >= self.config.recovery_timeout:
                # If we've been in half-open too long, go back to open
                self._transition_to_open()

    async def _on_success(self):
        """Handle successful call."""
        async with self._lock:
            self.stats.successful_calls += 1
            self.stats.consecutive_successes += 1
            self.stats.consecutive_failures = 0
            self.stats.last_success_time = time.time()

            if self.state == CircuitState.HALF_OPEN:
                if self.stats.consecutive_successes >= self.config.success_threshold:
                    self._transition_to_closed()

    async def _on_failure(self):
        """Handle failed call."""
        async with self._lock:
            self.stats.failed_calls += 1
            self.stats.consecutive_failures += 1
            self.stats.consecutive_successes = 0
            self.stats.last_failure_time = time.time()

            if self.state == CircuitState.CLOSED:
                if self.stats.consecutive_failures >= self.config.failure_threshold:
                    self._transition_to_open()
            elif self.state == CircuitState.HALF_OPEN:
                self._transition_to_open()

    def _transition_to_open(self):
        """Transition to OPEN state."""
        self.state = CircuitState.OPEN
        self.state_change_time = time.time()
        self.stats.circuit_open_count += 1
        logger.warning(f"Circuit breaker '{self.name}' opened")

    def _transition_to_half_open(self):
        """Transition to HALF_OPEN state."""
        self.state = CircuitState.HALF_OPEN
        self.state_change_time = time.time()
        self.stats.consecutive_successes = 0
        logger.info(f"Circuit breaker '{self.name}' half-opened")

    def _transition_to_closed(self):
        """Transition to CLOSED state."""
        self.state = CircuitState.CLOSED
        self.state_change_time = time.time()
        self.stats.consecutive_failures = 0
        logger.info(f"Circuit breaker '{self.name}' closed")

    def _is_expected_exception(self, exception: Exception) -> bool:
        """Check if exception is one we should count as a failure."""
        expected_exceptions = self.config.expected_exceptions or []
        return any(isinstance(exception, exc_type) for exc_type in expected_exceptions)

    def get_stats(self) -> dict[str, Any]:
        """Get circuit breaker statistics."""
        return {
            "name": self.name,
            "state": self.state.value,
            "total_calls": self.stats.total_calls,
            "successful_calls": self.stats.successful_calls,
            "failed_calls": self.stats.failed_calls,
            "success_rate": (
                self.stats.successful_calls / max(self.stats.total_calls, 1)
            )
            * 100,
            "consecutive_failures": self.stats.consecutive_failures,
            "consecutive_successes": self.stats.consecutive_successes,
            "circuit_open_count": self.stats.circuit_open_count,
            "last_failure_time": self.stats.last_failure_time,
            "last_success_time": self.stats.last_success_time,
            "state_change_time": self.state_change_time,
        }

    def reset(self):
        """Reset circuit breaker to initial state."""
        self.state = CircuitState.CLOSED
        self.stats = CircuitBreakerStats()
        self.state_change_time = time.time()
        logger.info(f"Circuit breaker '{self.name}' reset")

    def force_open(self):
        """Force circuit breaker to open state."""
        self._transition_to_open()
        logger.warning(f"Circuit breaker '{self.name}' forced open")

    def force_close(self):
        """Force circuit breaker to closed state."""
        self._transition_to_closed()
        logger.info(f"Circuit breaker '{self.name}' forced closed")


# Circuit breaker decorator
def circuit_breaker(name: str, config: CircuitBreakerConfig | None = None):
    """Decorator to apply circuit breaker to a function."""
    breaker = CircuitBreaker(name, config)

    def decorator(func):
        async def async_wrapper(*args, **kwargs):
            return await breaker.call(func, *args, **kwargs)

        def sync_wrapper(*args, **kwargs):
            return asyncio.run(breaker.call(func, *args, **kwargs))

        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper

    return decorator
