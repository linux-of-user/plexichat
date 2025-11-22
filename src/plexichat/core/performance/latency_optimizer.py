"""
Centralized Latency Optimization System

This module provides a comprehensive latency optimization system that consolidates
performance improvements from various modules. It includes request preprocessing,
response compression, caching strategies, and database query optimization.
"""

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from functools import wraps
import gzip
import hashlib
import json
import time
from typing import (
    Any,
)
import zlib

try:
    from plexichat.core.logging import get_logger, performance_logger
except ImportError:
    # Fallback for backward compatibility
    try:
        from plexichat.core.logging import get_logger

        performance_logger = None
    except ImportError:
        import logging

        get_logger = logging.getLogger
        performance_logger = None


class CompressionType(Enum):
    """Supported compression algorithms."""

    NONE = "none"
    GZIP = "gzip"
    DEFLATE = "deflate"
    BROTLI = "brotli"


class CacheStrategy(Enum):
    """Cache eviction strategies."""

    LRU = "lru"
    LFU = "lfu"
    TTL = "ttl"
    FIFO = "fifo"


@dataclass
class PerformanceMetrics:
    """Container for performance metrics."""

    request_count: int = 0
    total_latency: float = 0.0
    min_latency: float = float("inf")
    max_latency: float = 0.0
    avg_latency: float = 0.0
    cache_hits: int = 0
    cache_misses: int = 0
    compression_ratio: float = 0.0
    db_query_count: int = 0
    db_query_time: float = 0.0
    errors: int = 0
    last_updated: datetime = field(default_factory=datetime.now)

    def update_latency(self, latency: float) -> None:
        """Update latency metrics."""
        self.request_count += 1
        self.total_latency += latency
        self.min_latency = min(self.min_latency, latency)
        self.max_latency = max(self.max_latency, latency)
        self.avg_latency = self.total_latency / self.request_count
        self.last_updated = datetime.now()

    def cache_hit(self) -> None:
        """Record a cache hit."""
        self.cache_hits += 1

    def cache_miss(self) -> None:
        """Record a cache miss."""
        self.cache_misses += 1

    @property
    def cache_hit_ratio(self) -> float:
        """Calculate cache hit ratio."""
        total = self.cache_hits + self.cache_misses
        return self.cache_hits / total if total > 0 else 0.0


class RequestPreprocessor:
    """Handles request preprocessing for optimal performance."""

    def __init__(self) -> None:
        self.logger = get_logger(__name__)
        self._validation_cache: dict[str, dict[str, Any]] = {}
        self._schema_cache: dict[str, Any] = {}

    async def preprocess_request(self, request_data: dict[str, Any]) -> dict[str, Any]:
        """
        Preprocess incoming request data for optimal performance.

        Args:
            request_data: Raw request data

        Returns:
            Preprocessed and optimized request data
        """
        start_time = time.perf_counter()

        try:
            # Normalize data structure
            normalized_data = self._normalize_data(request_data)

            # Remove unnecessary fields
            cleaned_data = self._clean_data(normalized_data)

            # Validate and transform
            validated_data = await self._validate_data(cleaned_data)

            # Apply optimizations
            optimized_data = self._optimize_data_structure(validated_data)

            processing_time = (time.perf_counter() - start_time) * 1_000_000
            self.logger.debug(
                f"Request preprocessing completed in {processing_time:.2f}us"
            )

            return optimized_data

        except Exception as e:
            self.logger.error(f"Request preprocessing failed: {e}")
            raise

    def _normalize_data(self, data: dict[str, Any]) -> dict[str, Any]:
        """Normalize data structure and types."""
        normalized = {}

        for key, value in data.items():
            # Normalize key names
            normalized_key = key.lower().strip()

            # Normalize values
            if isinstance(value, str):
                normalized[normalized_key] = value.strip()
            elif isinstance(value, dict):
                normalized[normalized_key] = self._normalize_data(value)
            elif isinstance(value, list):
                normalized[normalized_key] = [
                    self._normalize_data(item) if isinstance(item, dict) else item
                    for item in value
                ]
            else:
                normalized[normalized_key] = value

        return normalized

    def _clean_data(self, data: dict[str, Any]) -> dict[str, Any]:
        """Remove unnecessary or empty fields."""
        cleaned = {}

        for key, value in data.items():
            # Skip empty values
            if value is None or value == "" or value == []:
                continue

            # Skip internal/debug fields
            if key.startswith("_") or key in ["debug", "trace", "internal"]:
                continue

            if isinstance(value, dict):
                cleaned_value = self._clean_data(value)
                if cleaned_value:  # Only include non-empty dicts
                    cleaned[key] = cleaned_value
            else:
                cleaned[key] = value

        return cleaned

    async def _validate_data(self, data: dict[str, Any]) -> dict[str, Any]:
        """Validate data with caching for performance."""
        # Create a hash of the data structure for caching
        data_hash = hashlib.md5(json.dumps(data, sort_keys=True).encode()).hexdigest()

        if data_hash in self._validation_cache:
            return self._validation_cache[data_hash]

        # Perform validation (simplified example)
        validated_data = data.copy()

        # Cache the result
        self._validation_cache[data_hash] = validated_data

        # Limit cache size
        if len(self._validation_cache) > 1000:
            # Remove oldest entries
            oldest_keys = list(self._validation_cache.keys())[:100]
            for key in oldest_keys:
                del self._validation_cache[key]

        return validated_data

    def _optimize_data_structure(self, data: dict[str, Any]) -> dict[str, Any]:
        """Optimize data structure for faster processing."""
        # Convert to more efficient data structures where possible
        optimized = {}

        for key, value in data.items():
            if isinstance(value, list) and len(value) > 100:
                # Convert large lists to sets for faster lookups if appropriate
                if all(isinstance(item, (str, int, float)) for item in value):
                    optimized[key] = (
                        set(value) if len(set(value)) == len(value) else value
                    )
                else:
                    optimized[key] = value
            else:
                optimized[key] = value

        return optimized


class ResponseCompressor:
    """Handles response compression for reduced latency."""

    def __init__(self) -> None:
        self.logger = get_logger(__name__)
        self._compression_cache: dict[str, tuple[bytes, float]] = {}

    async def compress_response(
        self,
        data: str | bytes | dict[str, Any],
        compression_type: CompressionType = CompressionType.GZIP,
        min_size: int = 1024,
    ) -> tuple[bytes, float]:
        """
        Compress response data.

        Args:
            data: Data to compress
            compression_type: Compression algorithm to use
            min_size: Minimum size threshold for compression

        Returns:
            Tuple of (compressed_data, compression_ratio)
        """
        start_time = time.perf_counter()

        try:
            # Convert data to bytes if necessary
            if isinstance(data, dict):
                data_bytes = json.dumps(data).encode()
            elif isinstance(data, str):
                data_bytes = data.encode()
            else:
                data_bytes = data

            # Skip compression if data is too small
            if len(data_bytes) < min_size:
                return data_bytes, 1.0

            # Check cache
            cache_key = hashlib.md5(data_bytes).hexdigest() + str(
                compression_type.value
            )
            if cache_key in self._compression_cache:
                return self._compression_cache[cache_key]

            # Perform compression
            compressed_data = await self._compress_data(data_bytes, compression_type)

            compression_ratio = (
                len(compressed_data) / len(data_bytes) if len(data_bytes) > 0 else 1.0
            )

            # Cache result
            self._compression_cache[cache_key] = (compressed_data, compression_ratio)

            # Limit cache size
            if len(self._compression_cache) > 500:
                # Remove oldest entries
                oldest_keys = list(self._compression_cache.keys())[:50]
                for key in oldest_keys:
                    del self._compression_cache[key]

            processing_time = (time.perf_counter() - start_time) * 1_000_000
            self.logger.debug(
                f"Response compression completed in {processing_time:.2f}us (ratio: {compression_ratio:.3f})"
            )

            return compressed_data, compression_ratio

        except Exception as e:
            self.logger.error(f"Response compression failed: {e}")
            # Return original data if compression fails
            return data_bytes if isinstance(data, bytes) else data.encode(), 1.0

    async def _compress_data(
        self, data: bytes, compression_type: CompressionType
    ) -> bytes:
        """Perform actual compression based on type."""
        if compression_type == CompressionType.GZIP:
            return gzip.compress(data)
        elif compression_type == CompressionType.DEFLATE:
            return zlib.compress(data)
        elif compression_type == CompressionType.BROTLI:
            try:
                import brotli

                return brotli.compress(data)
            except ImportError:
                self.logger.warning("Brotli not available, falling back to gzip")
                return gzip.compress(data)
        else:
            return data


# Performance monitoring decorator
def monitor_performance(
    metric_name: str | None = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator to monitor function performance."""

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            start_time = time.perf_counter()
            try:
                result = await func(*args, **kwargs)
                latency = (time.perf_counter() - start_time) * 1000  # milliseconds

                if performance_logger:
                    performance_logger.info(
                        f"Function {func.__name__} completed in {latency:.2f}ms"
                    )

                return result
            except Exception as e:
                latency = (time.perf_counter() - start_time) * 1000

                if performance_logger:
                    performance_logger.error(
                        f"Function {func.__name__} failed after {latency:.2f}ms: {e}"
                    )

                raise

        @wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            start_time = time.perf_counter()
            try:
                result = func(*args, **kwargs)
                latency = (time.perf_counter() - start_time) * 1000  # milliseconds

                if performance_logger:
                    performance_logger.info(
                        f"Function {func.__name__} completed in {latency:.2f}ms"
                    )

                return result
            except Exception as e:
                latency = (time.perf_counter() - start_time) * 1000

                if performance_logger:
                    performance_logger.error(
                        f"Function {func.__name__} failed after {latency:.2f}ms: {e}"
                    )

                raise

        # Return appropriate wrapper based on whether function is async
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper

    return decorator


# Global instances
request_preprocessor = RequestPreprocessor()
response_compressor = ResponseCompressor()

__all__ = [
    "CacheStrategy",
    "CompressionType",
    "PerformanceMetrics",
    "RequestPreprocessor",
    "ResponseCompressor",
    "monitor_performance",
    "request_preprocessor",
    "response_compressor",
]
