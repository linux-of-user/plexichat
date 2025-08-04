"""
import http.client
Network Optimization Manager

Advanced network optimization with connection pooling, compression,
monitoring, and CDN integration for optimal performance.
"""

import asyncio
import gzip
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union
import aiohttp
import ssl

logger = logging.getLogger(__name__)


@dataclass
class ConnectionMetrics:
    """Connection performance metrics."""
    total_connections: int = 0
    active_connections: int = 0
    failed_connections: int = 0
    avg_connection_time: float = 0.0
    avg_response_time: float = 0.0
    bytes_sent: int = 0
    bytes_received: int = 0
    compression_ratio: float = 0.0
    last_updated: datetime = field(default_factory=datetime.now)


@dataclass
class NetworkConfig:
    """Network optimization configuration."""
    # Connection pooling
    max_connections: int = 100
    max_connections_per_host: int = 30
    connection_timeout: float = 30.0
    read_timeout: float = 60.0
    keepalive_timeout: float = 30.0

    # Compression
    enable_compression: bool = True
    compression_threshold: int = 1024  # bytes
    compression_level: int = 6

    # SSL/TLS
    ssl_verify: bool = True
    ssl_context: Optional[ssl.SSLContext] = None

    # CDN
    cdn_enabled: bool = False
    cdn_base_url: str = ""
    cdn_cache_ttl: int = 3600

    # Monitoring
    enable_monitoring: bool = True
    metrics_interval: int = 60


class NetworkOptimizer:
    """Advanced network optimization manager."""

    def __init__(self, config: Optional[NetworkConfig] = None):
        self.config = config or NetworkConfig()
        self.metrics = ConnectionMetrics()

        # Connection pools
        self.http_session: Optional[aiohttp.ClientSession] = None
        self.connection_pools: Dict[str, aiohttp.TCPConnector] = {}

        # Compression tracking
        self.compression_stats = {
            'requests_compressed': 0,
            'bytes_before_compression': 0,
            'bytes_after_compression': 0
        }

        # CDN integration
        self.cdn_session: Optional[aiohttp.ClientSession] = None
        self.cdn_cache: Dict[str, Any] = {}

        # Background tasks
        self._monitoring_task = None
        self._cleanup_task = None
        self._running = False

        logger.info("[WEB] Network Optimizer initialized")

    async def initialize(self) -> bool:
        """Initialize network optimization components."""
        try:
            # Create SSL context
            ssl_context = self._create_ssl_context()

            # Create main HTTP session with optimized connector
            connector = aiohttp.TCPConnector()
                limit=self.config.max_connections,
                limit_per_host=self.config.max_connections_per_host,
                ttl_dns_cache=300,
                use_dns_cache=True,
                keepalive_timeout=self.config.keepalive_timeout,
                enable_cleanup_closed=True,
                ssl=ssl_context if self.config.ssl_verify else False
            )

            timeout = aiohttp.ClientTimeout()
                total=self.config.connection_timeout,
                connect=self.config.connection_timeout,
                sock_read=self.config.read_timeout
            )

            self.http_session = aiohttp.ClientSession()
                connector=connector,
                timeout=timeout,
                headers={
                    'User-Agent': 'PlexiChat/1.0',
                    'Accept-Encoding': 'gzip, deflate' if self.config.enable_compression else 'identity'
                }
            )

            # Initialize CDN session if enabled
            if self.config.cdn_enabled:
                await self._initialize_cdn()

            # Start monitoring
            if self.config.enable_monitoring:
                await self.start_monitoring()

            logger.info("[START] Network optimization initialized")
            return True

        except Exception as e:
            logger.error(f"Network optimization initialization failed: {e}")
            return False

    async def shutdown(self):
        """Shutdown network optimizer."""
        try:
            self._running = False

            # Cancel background tasks
            if self._monitoring_task:
                self._monitoring_task.cancel()
            if self._cleanup_task:
                self._cleanup_task.cancel()

            # Close sessions
            if self.http_session:
                await self.http_session.close()

            if self.cdn_session:
                await self.cdn_session.close()

            # Close connection pools
            for pool in self.connection_pools.values():
                await pool.close()

            logger.info("[STOP] Network optimizer shutdown complete")

        except Exception as e:
            logger.error(f"Error during network optimizer shutdown: {e}")

    async def make_request(self, method: str, url: str, )
                          data: Optional[Union[str, bytes, Dict]] = None,
                          headers: Optional[Dict[str, str]] = None,
                          compress: bool = True) -> Dict[str, Any]:
        """Make optimized HTTP request with compression and monitoring."""
        start_time = time.time()

        try:
            # Prepare headers
            request_headers = headers or {}

            # Handle compression
            compressed_data = None
            if compress and data and self.config.enable_compression:
                compressed_data = await self._compress_data(data)
                if compressed_data and len(compressed_data) < len(str(data).encode()):
                    data = compressed_data
                    request_headers['Content-Encoding'] = 'gzip'
                    self.compression_stats['requests_compressed'] += 1

            # Make request
            async with self.http_session.request()
                method, url, data=data, headers=request_headers
            ) as response:

                # Read response
                response_data = await response.read()

                # Decompress if needed
                if response.headers.get('Content-Encoding') == 'gzip':
                    response_data = gzip.decompress(response_data)

                # Update metrics
                request_time = time.time() - start_time
                await self._update_request_metrics(request_time, len(str(data).encode()) if data else 0, len(response_data))

                return {}}
                    'status': response.status,
                    'headers': dict(response.headers),
                    'data': response_data,
                    'request_time': request_time
                }

        except Exception as e:
            self.metrics.failed_connections += 1
            logger.error(f"Request failed: {e}")
            raise

    async def _compress_data(self, data: Union[str, bytes, Dict]) -> Optional[bytes]:
        """Compress data if beneficial."""
        try:
            # Convert to bytes if needed
            if isinstance(data, dict):
                import json
                data_bytes = json.dumps(data).encode()
            elif isinstance(data, str):
                data_bytes = data.encode()
            else:
                data_bytes = data

            # Only compress if above threshold
            if len(data_bytes) < self.config.compression_threshold:
                return None

            # Compress
            compressed = gzip.compress(data_bytes, compresslevel=self.config.compression_level)

            # Update compression stats
            self.compression_stats['bytes_before_compression'] += len(data_bytes)
            self.compression_stats['bytes_after_compression'] += len(compressed)

            return compressed

        except Exception as e:
            logger.error(f"Compression failed: {e}")
            return None

    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create optimized SSL context."""
        if self.config.ssl_context:
            return self.config.ssl_context

        context = ssl.create_default_context()

        # Optimize SSL settings
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED if self.config.ssl_verify else ssl.CERT_NONE

        # Enable session reuse
        context.options |= ssl.OP_NO_SSLv2
        context.options |= ssl.OP_NO_SSLv3
        context.options |= ssl.OP_SINGLE_DH_USE
        context.options |= ssl.OP_SINGLE_ECDH_USE

        return context

    async def _initialize_cdn(self):
        """Initialize CDN integration."""
        try:
            cdn_connector = aiohttp.TCPConnector()
                limit=50,
                limit_per_host=20,
                ttl_dns_cache=600,  # Longer DNS cache for CDN
                use_dns_cache=True
            )

            self.cdn_session = aiohttp.ClientSession()
                connector=cdn_connector,
                timeout=aiohttp.ClientTimeout(total=30),
                headers={'User-Agent': 'PlexiChat-CDN/1.0'}
            )

            logger.info("[WORLD] CDN integration initialized")

        except Exception as e:
            logger.error(f"CDN initialization failed: {e}")

    async def start_monitoring(self):
        """Start network monitoring."""
        if self._running:
            return

        self._running = True
        self._monitoring_task = asyncio.create_task(self._monitoring_loop())
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())

        logger.info("[METRICS] Network monitoring started")

    async def _monitoring_loop(self):
        """Background monitoring loop."""
        while self._running:
            try:
                await self._collect_network_metrics()
                await asyncio.sleep(self.config.metrics_interval)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Monitoring loop error: {e}")
                await asyncio.sleep(30)

    async def _collect_network_metrics(self):
        """Collect network performance metrics."""
        try:
            # Update connection metrics from session
            if self.http_session and hasattr(self.http_session.connector, '_conns'):
                connector = self.http_session.connector
                self.metrics.active_connections = len(connector._conns)

            # Calculate compression ratio
            if self.compression_stats['bytes_before_compression'] > 0:
                self.metrics.compression_ratio = ()
                    1 - (self.compression_stats['bytes_after_compression'] / )
                         self.compression_stats['bytes_before_compression'])
                )

            self.metrics.last_updated = datetime.now()

        except Exception as e:
            logger.error(f"Error collecting network metrics: {e}")

    async def _update_request_metrics(self, request_time: float, bytes_sent: int, bytes_received: int):
        """Update request metrics."""
        self.metrics.total_connections += 1
        self.metrics.bytes_sent += bytes_sent
        self.metrics.bytes_received += bytes_received

        # Update average response time
        if self.metrics.total_connections > 1:
            self.metrics.avg_response_time = ()
                (self.metrics.avg_response_time * (self.metrics.total_connections - 1) + request_time) /
                self.metrics.total_connections
            )
        else:
            self.metrics.avg_response_time = request_time

    async def _cleanup_loop(self):
        """Background cleanup loop."""
        while self._running:
            try:
                # Clean up old CDN cache entries
                if self.cdn_cache:
                    cutoff_time = datetime.now() - timedelta(seconds=self.config.cdn_cache_ttl)
                    expired_keys = [
                        key for key, (data, timestamp) in self.cdn_cache.items()
                        if timestamp < cutoff_time
                    ]

                    for key in expired_keys:
                        del self.cdn_cache[key]

                await asyncio.sleep(300)  # Run every 5 minutes

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Cleanup loop error: {e}")
                await asyncio.sleep(60)

    def get_network_stats(self) -> Dict[str, Any]:
        """Get comprehensive network statistics."""
        return {}}
            'connections': {
                'total': self.metrics.total_connections,
                'active': self.metrics.active_connections,
                'failed': self.metrics.failed_connections,
                'success_rate': ()
                    (self.metrics.total_connections - self.metrics.failed_connections) /
                    self.metrics.total_connections
                ) if self.metrics.total_connections > 0 else 0
            },
            'performance': {
                'avg_response_time_ms': self.metrics.avg_response_time * 1000,
                'avg_connection_time_ms': self.metrics.avg_connection_time * 1000,
                'bytes_sent': self.metrics.bytes_sent,
                'bytes_received': self.metrics.bytes_received,
                'total_bandwidth': self.metrics.bytes_sent + self.metrics.bytes_received
            },
            'compression': {
                'enabled': self.config.enable_compression,
                'requests_compressed': self.compression_stats['requests_compressed'],
                'compression_ratio': self.metrics.compression_ratio,
                'bytes_saved': ()
                    self.compression_stats['bytes_before_compression'] -
                    self.compression_stats['bytes_after_compression']
                )
            },
            'cdn': {
                'enabled': self.config.cdn_enabled,
                'cache_entries': len(self.cdn_cache),
                'base_url': self.config.cdn_base_url
            },
            'ssl': {
                'verification_enabled': self.config.ssl_verify,
                'context_configured': self.config.ssl_context is not None
            }
        }

    async def optimize_request_routing(self, url: str) -> str:
        """Optimize request routing through CDN or direct connection."""
        if not self.config.cdn_enabled:
            return url

        # Check if request should go through CDN
        if self._should_use_cdn(url):
            cdn_url = f"{self.config.cdn_base_url.rstrip('/')}/{url.lstrip('/')}"

            # Check CDN cache
            cache_key = f"cdn:{url}"
            if cache_key in self.cdn_cache:
                cached_data, timestamp = self.cdn_cache[cache_key]
                if datetime.now() - timestamp < timedelta(seconds=self.config.cdn_cache_ttl):
                    return cached_data

            return cdn_url

        return url

    def _should_use_cdn(self, url: str) -> bool:
        """Determine if request should use CDN."""
        # Use CDN for static content
        static_extensions = ['.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico']
        return any(url.lower().endswith(ext) for ext in static_extensions)


# Global network optimizer instance
network_optimizer = NetworkOptimizer()
