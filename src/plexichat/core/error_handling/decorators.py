import asyncio
import functools
import logging
import time
from typing import Any, Callable, List, Type

from .circuit_breaker import CircuitBreaker, CircuitBreakerConfig
from .crash_reporter import crash_reporter
from .error_manager import error_manager
from .error_recovery import RecoveryStrategy, recovery_manager
from .exceptions import ErrorCategory, ErrorSeverity


"""
PlexiChat Error Handling Decorators

Convenient decorators for applying error handling, circuit breakers,
retry logic, and crash reporting to functions and methods.
"""

logger = logging.getLogger(__name__, Optional)


def error_handler(
    severity: ErrorSeverity = ErrorSeverity.MEDIUM,
    category: ErrorCategory = ErrorCategory.UNKNOWN,
    component: Optional[str] = None,
    suppress_errors: bool = False,
    fallback_value: Optional[Any] = None,
    recovery_strategies: Optional[List[RecoveryStrategy]] = None,
):
    """
    Decorator for comprehensive error handling.

    Args:
        severity: Error severity level
        category: Error category
        component: Component name for tracking
        suppress_errors: Whether to suppress errors and return fallback
        fallback_value: Value to return if error is suppressed
        recovery_strategies: List of recovery strategies to attempt
    """

    def decorator(func: Callable):
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            try:
                if asyncio.iscoroutinefunction(func):
                    return await func(*args, **kwargs)
                else:
                    return func(*args, **kwargs)
            except Exception as e:
                # Import here to avoid circular imports
                context = {
                    "function_name": func.__name__,
                    "args": args,
                    "kwargs": kwargs,
                    "original_function": func,
                    "fallback_value": fallback_value,
                }

                # Handle the error
                await error_manager.handle_error(
                    exception=e,
                    context=context,
                    severity=severity,
                    category=category,
                    component=component or func.__name__,
                )

                # Attempt recovery if strategies are specified
                if recovery_strategies:
                    recovery_result = await recovery_manager.attempt_recovery(
                        exception=e,
                        context=context,
                        component=component or func.__name__,
                    )

                    if recovery_result["recovered"]:
                        return recovery_result["final_result"]

                # Handle error suppression
                if suppress_errors:
                    logger.warning(f"Error suppressed in {func.__name__}: {e}")
                    return fallback_value

                # Re-raise the exception
                raise e

        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            return asyncio.run(async_wrapper(*args, **kwargs))

        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper

    return decorator


def crash_handler(
    severity: ErrorSeverity = ErrorSeverity.CRITICAL,
    category: ErrorCategory = ErrorCategory.SYSTEM,
    component: Optional[str] = None,
    auto_restart: bool = False,
):
    """
    Decorator for crash reporting and handling.

    Args:
        severity: Crash severity level
        category: Crash category
        component: Component name
        auto_restart: Whether to attempt automatic restart
    """

    def decorator(func: Callable):
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            try:
                if asyncio.iscoroutinefunction(func):
                    return await func(*args, **kwargs)
                else:
                    return func(*args, **kwargs)
            except Exception as e:
                # Report crash
                crash_context = crash_reporter.report_crash(
                    exception=e,
                    severity=severity,
                    category=category,
                    component=component or func.__name__,
                    additional_context={
                        "function_name": func.__name__,
                        "args": str(args),
                        "kwargs": str(kwargs),
                    },
                )

                logger.critical(f"Crash in {func.__name__}: {crash_context.error_id}")

                # Attempt auto-restart if enabled
                if auto_restart:
                    logger.info(f"Attempting auto-restart for {func.__name__}")
                    try:
                        await asyncio.sleep(1)  # Brief delay
                        if asyncio.iscoroutinefunction(func):
                            return await func(*args, **kwargs)
                        else:
                            return func(*args, **kwargs)
                    except Exception as restart_error:
                        logger.error(f"Auto-restart failed: {restart_error}")

                raise e

        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            return asyncio.run(async_wrapper(*args, **kwargs))

        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper

    return decorator


def circuit_breaker(
    name: Optional[str] = None,
    failure_threshold: int = 5,
    timeout_seconds: int = 60,
    recovery_timeout: int = 30,
    expected_exceptions: Optional[List[Type[Exception]]] = None,
):
    """
    Decorator for circuit breaker pattern.

    Args:
        name: Circuit breaker name (defaults to function name)
        failure_threshold: Number of failures before opening
        timeout_seconds: Time to wait before trying again
        recovery_timeout: Time to wait in half-open state
        expected_exceptions: Exceptions that should trigger the circuit breaker
    """

    def decorator(func: Callable):
        breaker_name = name or f"{func.__module__}.{func.__name__}"
        config = CircuitBreakerConfig(
            failure_threshold=failure_threshold,
            timeout_seconds=timeout_seconds,
            recovery_timeout=recovery_timeout,
            expected_exceptions=expected_exceptions or [Exception],
        )
        breaker = CircuitBreaker(breaker_name, config)

        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            return await breaker.call(func, *args, **kwargs)

        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            return asyncio.run(breaker.call(func, *args, **kwargs))

        # Store breaker reference on function for external access
        wrapper = async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper
        wrapper._circuit_breaker = breaker

        return wrapper

    return decorator


def retry(
    max_attempts: int = 3,
    delay: float = 1.0,
    exponential_backoff: bool = True,
    backoff_multiplier: float = 2.0,
    max_delay: float = 60.0,
    retry_on: Optional[List[Type[Exception]]] = None,
    on_retry: Optional[Callable] = None,
):
    """
    Decorator for retry logic with exponential backoff.

    Args:
        max_attempts: Maximum number of retry attempts
        delay: Initial delay between retries
        exponential_backoff: Whether to use exponential backoff
        backoff_multiplier: Multiplier for exponential backoff
        max_delay: Maximum delay between retries
        retry_on: List of exceptions to retry on
        on_retry: Callback function called on each retry
    """
    if retry_on is None:
        retry_on = [Exception]

    def decorator(func: Callable):
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            last_exception = None

            for attempt in range(max_attempts):
                try:
                    if asyncio.iscoroutinefunction(func):
                        return await func(*args, **kwargs)
                    else:
                        return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e

                    # Check if we should retry on this exception
                    should_retry = any(isinstance(e, exc_type) for exc_type in retry_on)

                    if not should_retry or attempt == max_attempts - 1:
                        raise e

                    # Calculate delay
                    current_delay = delay
                    if exponential_backoff and attempt > 0:
                        current_delay *= backoff_multiplier**attempt
                    current_delay = min(current_delay, max_delay)

                    # Call retry callback if provided
                    if on_retry:
                        try:
                            if asyncio.iscoroutinefunction(on_retry):
                                await on_retry(attempt + 1, e, current_delay)
                            else:
                                on_retry(attempt + 1, e, current_delay)
                        except Exception as callback_error:
                            logger.error(f"Retry callback error: {callback_error}")

                    logger.warning(
                        f"Retry {attempt + 1}/{max_attempts} for {func.__name__} after {current_delay}s: {e}"
                    )
                    await asyncio.sleep(current_delay)

            # This should never be reached, but just in case
            if last_exception:
                raise last_exception

        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            return asyncio.run(async_wrapper(*args, **kwargs))

        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper

    return decorator


def timeout(
    seconds: float,
    timeout_exception: Optional[Type[Exception]] = None,
    timeout_message: Optional[str] = None,
):
    """
    Decorator for function timeout.

    Args:
        seconds: Timeout in seconds
        timeout_exception: Exception to raise on timeout
        timeout_message: Custom timeout message
    """
    if timeout_exception is None:
        timeout_exception = asyncio.TimeoutError

    if timeout_message is None:
        timeout_message = f"Function timed out after {seconds} seconds"

    def decorator(func: Callable):
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            try:
                if asyncio.iscoroutinefunction(func):
                    return await asyncio.wait_for(
                        func(*args, **kwargs), timeout=seconds
                    )
                else:
                    return await asyncio.wait_for(
                        asyncio.get_event_loop().run_in_executor(
                            None, func, *args, **kwargs
                        ),
                        timeout=seconds,
                    )
            except asyncio.TimeoutError:
                raise timeout_exception(timeout_message)

        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            return asyncio.run(async_wrapper(*args, **kwargs))

        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper

    return decorator


def rate_limit(calls_per_second: float = 1.0, burst_size: int = 1):
    """
    Decorator for rate limiting function calls.

    Args:
        calls_per_second: Maximum calls per second
        burst_size: Maximum burst size
    """

    def decorator(func: Callable):
        call_times = []

        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            now = time.time()

            # Remove old call times outside the window
            window_start = now - 1.0  # 1 second window
            call_times[:] = [t for t in call_times if t >= window_start]

            # Check rate limit
            if len(call_times) >= calls_per_second:
                sleep_time = 1.0 / calls_per_second
                await asyncio.sleep(sleep_time)
                now = time.time()

            # Check burst limit
            if len(call_times) >= burst_size:
                oldest_call = min(call_times)
                sleep_time = oldest_call + 1.0 - now
                if sleep_time > 0:
                    await asyncio.sleep(sleep_time)
                    now = time.time()

            call_times.append(now)

            if asyncio.iscoroutinefunction(func):
                return await func(*args, **kwargs)
            else:
                return func(*args, **kwargs)

        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            return asyncio.run(async_wrapper(*args, **kwargs))

        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper

    return decorator
