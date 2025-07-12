# app/utils/rate_limiting.py
"""
Advanced rate limiting system with multiple strategies and storage backends.
"""

import time
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict, deque
import threading
import json
from pathlib import Path

import logging

logger = logging.getLogger(__name__)

# Settings fallback
class Settings:
    LOG_DIR = "logs"

try:
    from plexichat.core.config.settings import settings
except ImportError:
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
    
    def check_rate_limit(self, key: str, max_attempts: int, window_minutes: int, 
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
        
        # Calculate current window start
        window_start = int(current_time // window_seconds) * window_seconds
        
        if key not in self.fixed_windows:
            self.fixed_windows[key] = {}
        
        window_data = self.fixed_windows[key]
        
        # Clean up old windows
        for window_time in list(window_data.keys()):
            if window_time < window_start:
                del window_data[window_time]
        
        # Get current window count
        current_count = window_data.get(window_start, 0)
        
        if current_count < max_attempts:
            window_data[window_start] = current_count + 1
            return True
        
        return False
    
    def record_attempt(self, key: str):
        """Record an attempt for tracking purposes."""
        with self._lock:
            self.attempt_counts[key].append(datetime.now(timezone.utc))
            
            # Keep only recent attempts (last 24 hours)
            cutoff_time = datetime.now(timezone.utc) - timedelta(hours=24)
            self.attempt_counts[key] = [
                attempt for attempt in self.attempt_counts[key]
                if attempt > cutoff_time
            ]
    
    def reset_attempts(self, key: str):
        """Reset attempts for a specific key."""
        with self._lock:
            # Clear from all tracking structures
            if key in self.attempt_counts:
                del self.attempt_counts[key]
            if key in self.sliding_windows:
                del self.sliding_windows[key]
            if key in self.token_buckets:
                del self.token_buckets[key]
            if key in self.fixed_windows:
                del self.fixed_windows[key]
    
    def get_attempt_count(self, key: str, window_minutes: int = 60) -> int:
        """Get the number of attempts for a key within a time window."""
        cutoff_time = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        
        attempts = self.attempt_counts.get(key, [])
        return len([attempt for attempt in attempts if attempt > cutoff_time])
    
    def get_remaining_attempts(self, key: str, max_attempts: int, window_minutes: int) -> int:
        """Get the number of remaining attempts for a key."""
        current_attempts = self.get_attempt_count(key, window_minutes)
        return max(0, max_attempts - current_attempts)
    
    def get_reset_time(self, key: str, window_minutes: int) -> Optional[datetime]:
        """Get the time when the rate limit will reset for a key."""
        attempts = self.attempt_counts.get(key, [])
        if not attempts:
            return None
        
        # Find the oldest attempt within the window
        cutoff_time = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        recent_attempts = [attempt for attempt in attempts if attempt > cutoff_time]
        
        if not recent_attempts:
            return None
        
        # Reset time is when the oldest attempt expires
        oldest_attempt = min(recent_attempts)
        return oldest_attempt + timedelta(minutes=window_minutes)
    
    def is_rate_limited(self, key: str, max_attempts: int, window_minutes: int) -> Tuple[bool, Dict]:
        """
        Check if a key is rate limited and return detailed information.
        
        Returns:
            Tuple of (is_limited, info_dict)
        """
        current_attempts = self.get_attempt_count(key, window_minutes)
        remaining = self.get_remaining_attempts(key, max_attempts, window_minutes)
        reset_time = self.get_reset_time(key, window_minutes)
        
        is_limited = current_attempts >= max_attempts
        
        info = {
            "is_limited": is_limited,
            "current_attempts": current_attempts,
            "max_attempts": max_attempts,
            "remaining_attempts": remaining,
            "window_minutes": window_minutes,
            "reset_time": reset_time.isoformat() if reset_time else None,
            "retry_after_seconds": int((reset_time - datetime.now(timezone.utc)).total_seconds()) if reset_time else 0
        }
        
        return is_limited, info
    
    def get_rate_limit_headers(self, key: str, max_attempts: int, window_minutes: int) -> Dict[str, str]:
        """Get HTTP headers for rate limiting information."""
        _, info = self.is_rate_limited(key, max_attempts, window_minutes)
        
        headers = {
            "X-RateLimit-Limit": str(max_attempts),
            "X-RateLimit-Remaining": str(info["remaining_attempts"]),
            "X-RateLimit-Window": str(window_minutes * 60),  # in seconds
        }
        
        if info["reset_time"]:
            headers["X-RateLimit-Reset"] = str(int(datetime.fromisoformat(info["reset_time"]).timestamp()))
        
        if info["is_limited"]:
            headers["Retry-After"] = str(info["retry_after_seconds"])
        
        return headers
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get rate limiting statistics."""
        with self._lock:
            return {
                "total_keys_tracked": len(self.attempt_counts),
                "active_token_buckets": len(self.token_buckets),
                "active_sliding_windows": len(self.sliding_windows),
                "active_fixed_windows": len(self.fixed_windows),
                "storage_file": self.storage_file,
                "last_cleanup": self._last_cleanup
            }
    
    def clear_all_data(self):
        """Clear all rate limiting data (use with caution)."""
        with self._lock:
            self.token_buckets.clear()
            self.sliding_windows.clear()
            self.fixed_windows.clear()
            self.attempt_counts.clear()
            
            # Remove storage file
            try:
                Path(self.storage_file).unlink(missing_ok=True)
            except Exception as e:
                logger.warning("Failed to remove rate limiting storage file: %s", e)
        
        logger.info("All rate limiting data cleared")


# Global rate limiter instance
rate_limiter = RateLimiter()
