"""
PlexiChat - Real-time Communication Platform
Copyright (C) 2025 PlexiChat Contributors

Rate Limiting Service
"""

import time
from collections import defaultdict, deque
from typing import Dict

from plexichat.core.logging import get_logger
from plexichat.core.config import get_config

logger = get_logger(__name__)
config = get_config()

class RateLimiter:
    """
    Token bucket rate limiter.
    """
    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests: Dict[str, deque] = defaultdict(lambda: deque())
        
    async def check_rate_limit(self, client_id: str) -> bool:
        """Check if client is within rate limits."""
        current_time = time.time()
        requests = self._requests[client_id]
        
        # Remove old requests outside window
        while requests and current_time - requests[0] > self.window_seconds:
            requests.popleft()
            
        # Check if under limit
        if len(requests) < self.max_requests:
            requests.append(current_time)
            return True
            
        return False
        
    async def reset_limit(self, client_id: str):
        """Reset rate limit for a client."""
        if client_id in self._requests:
            del self._requests[client_id]
            
# Global instance
rate_limiter = RateLimiter()
