# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import json
import logging
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# Simple settings class for rate limiting
class Settings:
    def __init__(self):
        self.LOG_DIR = "logs"

settings = Settings()

class RateLimiter:
    """
    Advanced rate limiting with multiple algorithms and persistence.

    Supports:
    - Token bucket algorithm
    - Sliding window algorithm
    - Fixed window algorithm
    - Per-IP and per-user rate limiting
    - Persistent storage for rate limit data
    """

    def __init__(self, storage_file: Optional[str] = None):
        self.storage_file = storage_file or str(Path(settings.LOG_DIR) / "rate_limits.json")

        # In-memory storage for rate limiting data
        self.token_buckets: Dict[str, Dict] = {}
        self.sliding_windows: Dict[str, deque] = defaultdict(deque)
        self.fixed_windows: Dict[str, Dict] = {}
        self.attempt_counts: Dict[str, List[datetime]] = defaultdict(list)

        # Thread lock for thread safety
        self._lock = threading.Lock()

        # Load persistent data
        self._load_data()

        # Cleanup old data periodically
        self._last_cleanup = time.time()
        self._cleanup_interval = 300  # 5 minutes

    def _load_data(self):
        """Load rate limiting data from persistent storage."""
        try:
            storage_path = Path(self.storage_file)
            if storage_path.exists():
                with open(storage_path, 'r') as f:
                    data = json.load(f)

                # Convert datetime strings back to datetime objects
                for key, attempts in data.get('attempt_counts', {}).items():
                    self.attempt_counts[key] = [
                        datetime.fromisoformat(dt) for dt in attempts
                    ]

                logger.debug("Rate limiting data loaded from %s", self.storage_file)
        except Exception as e:
            logger.warning("Failed to load rate limiting data: %s", e)

    def _save_data(self):
        """Save rate limiting data to persistent storage."""
        try:
            # Convert datetime objects to strings for JSON serialization
            serializable_data = {
                'attempt_counts': {
                    key: [dt.isoformat() for dt in attempts]
                    for key, attempts in self.attempt_counts.items()
                }
            }

            storage_path = Path(self.storage_file)
            storage_path.parent.mkdir(parents=True, exist_ok=True)

            with open(storage_path, 'w') as f:
                json.dump(serializable_data, f, indent=2)

            logger.debug("Rate limiting data saved to %s", self.storage_file)
        except Exception as e:
            logger.warning("Failed to save rate limiting data: %s", e)

    def _cleanup_old_data(self):
        """Clean up old rate limiting data."""
        current_time = time.time()

        # Only cleanup every 5 minutes
        if current_time - self._last_cleanup < self._cleanup_interval:
            return

        with self._lock:
            cutoff_time = datetime.now(timezone.utc) - timedelta(hours=24)

            # Clean up attempt counts
            for key in list(self.attempt_counts.keys()):
                self.attempt_counts[key] = [
                    attempt for attempt in self.attempt_counts[key]
                    if attempt > cutoff_time
                ]

                # Remove empty entries
                if not self.attempt_counts[key]:
                    del self.attempt_counts[key]

            # Clean up sliding windows
            for key in list(self.sliding_windows.keys()):
                window = self.sliding_windows[key]
                while window and window[0] < current_time - 3600:  # 1 hour
                    window.popleft()

                if not window:
                    del self.sliding_windows[key]

            # Clean up token buckets (remove expired ones)
            for key in list(self.token_buckets.keys()):
                bucket = self.token_buckets[key]
                if current_time - bucket.get('last_refill', 0) > 3600:  # 1 hour
                    del self.token_buckets[key]

            self._last_cleanup = current_time

            # Save cleaned data
            self._save_data()

    def check_rate_limit(self, key: str, max_attempts: int, window_minutes: int,):
                        algorithm: str = "sliding_window") -> bool:
        """
        Check if a request should be rate limited.

        Args:
            key: Unique identifier for the rate limit (e.g., IP address, user ID)
            max_attempts: Maximum number of attempts allowed
            window_minutes: Time window in minutes
            algorithm: Rate limiting algorithm to use

        Returns:
            True if request is allowed, False if rate limited
        """
        self._cleanup_old_data()

        with self._lock:
            if algorithm == "token_bucket":
                return self._check_token_bucket(key, max_attempts, window_minutes)
            elif algorithm == "sliding_window":
                return self._check_sliding_window(key, max_attempts, window_minutes)
            elif algorithm == "fixed_window":
                return self._check_fixed_window(key, max_attempts, window_minutes)
            else:
                logger.warning("Unknown rate limiting algorithm: %s", algorithm)
                return True

    def _check_token_bucket(self, key: str, max_tokens: int, refill_minutes: int) -> bool:
        """Token bucket algorithm implementation."""
        current_time = time.time()

        if key not in self.token_buckets:
            self.token_buckets[key] = {
                'tokens': max_tokens,
                'last_refill': current_time,
                'max_tokens': max_tokens,
                'refill_rate': max_tokens / (refill_minutes * 60)  # tokens per second
            }

        bucket = self.token_buckets[key]

        # Refill tokens based on time elapsed
        time_elapsed = current_time - bucket['last_refill']
        tokens_to_add = time_elapsed * bucket['refill_rate']
        bucket['tokens'] = min(bucket['max_tokens'], bucket['tokens'] + tokens_to_add)
        bucket['last_refill'] = current_time

        # Check if we have tokens available
        if bucket['tokens'] >= 1:
            bucket['tokens'] -= 1
            return True

        return False

    def _check_sliding_window(self, key: str, max_attempts: int, window_minutes: int) -> bool:
        """Sliding window algorithm implementation."""
        current_time = time.time()
        window_seconds = window_minutes * 60
        cutoff_time = current_time - window_seconds

        # Get or create window for this key
        window = self.sliding_windows[key]

        # Remove old entries
        while window and window[0] < cutoff_time:
            window.popleft()

        # Check if we're under the limit
        if len(window) < max_attempts:
            window.append(current_time)
            return True

        return False

    def _check_fixed_window(self, key: str, max_attempts: int, window_minutes: int) -> bool:
        """Fixed window algorithm implementation."""
        current_time = time.time()
        window_seconds = window_minutes * 60
        window_start = (current_time // window_seconds) * window_seconds

        window_key = f"{key}:{window_start}"

        if window_key not in self.fixed_windows:
            self.fixed_windows[window_key] = {
                'count': 0,
                'window_start': window_start
            }

        window_data = self.fixed_windows[window_key]

        # Check if we're in a new window
        if current_time >= window_data['window_start'] + window_seconds:
            window_data['count'] = 0
            window_data['window_start'] = window_start

        # Check if we're under the limit
        if window_data['count'] < max_attempts:
            window_data['count'] += 1
            return True

        return False

    def record_attempt(self, key: str):
        """Record an attempt for rate limiting purposes."""
        with self._lock:
            self.attempt_counts[key].append(datetime.now(timezone.utc))
            self._save_data()

    def get_attempt_count(self, key: str, hours: int = 1) -> int:
        """Get the number of attempts for a key in the last N hours."""
        with self._lock:
            cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)
            return len([)
                attempt for attempt in self.attempt_counts[key]
                if attempt > cutoff_time
            ])

    def reset_attempts(self, key: str):
        """Reset attempt count for a key."""
        with self._lock:
            if key in self.attempt_counts:
                del self.attempt_counts[key]
            if key in self.token_buckets:
                del self.token_buckets[key]
            if key in self.sliding_windows:
                del self.sliding_windows[key]
            self._save_data()

    def get_stats(self) -> Dict:
        """Get rate limiting statistics."""
        with self._lock:
            return {
                'active_keys': len(self.attempt_counts),
                'token_buckets': len(self.token_buckets),
                'sliding_windows': len(self.sliding_windows),
                'fixed_windows': len(self.fixed_windows),
                'total_attempts': sum(len(attempts) for attempts in self.attempt_counts.values())
            }

# Global rate limiter instance
rate_limiter = RateLimiter()

def rate_limit(max_attempts: int = 10, window_minutes: int = 1, ):
              algorithm: str = "sliding_window", key_func: Optional[callable] = None):
    """Decorator for rate limiting functions."""
    def decorator(func):
        def wrapper(*args, **kwargs):
            # Generate rate limit key
            if key_func:
                key = key_func(*args, **kwargs)
            else:
                # Default key based on function name and first argument
                key = f"{func.__name__}:{args[0] if args else 'default'}"

            # Check rate limit
            if not rate_limiter.check_rate_limit(key, max_attempts, window_minutes, algorithm):
                raise Exception(f"Rate limit exceeded for {key}")

            # Record attempt
            rate_limiter.record_attempt(key)

            # Execute function
            return func(*args, **kwargs)

        return wrapper
    return decorator
