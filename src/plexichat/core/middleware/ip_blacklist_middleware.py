#!/usr/bin/env python3
"""
IP Blacklist Middleware
Provides comprehensive IP blocking, geo-blocking, and automatic threat detection
"""

import asyncio
import ipaddress
import json
import logging
import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional, Set, Awaitable

from fastapi import HTTPException, Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

# Import configuration
try:
    from plexichat.core.rate_limit_config import (
        IPBlacklistConfig,
        get_rate_limiting_config,
    )
except ImportError as e:
    print(f"Import error in IP blacklist middleware: {e}")

    # Fallback
    def get_rate_limiting_config():
        return None


logger = logging.getLogger(__name__)


@dataclass
class IPThreatInfo:
    """Information about an IP threat."""

    ip_address: str
    threat_level: str  # low, medium, high, critical
    threat_types: List[str]  # brute_force, ddos, spam, malware, etc.
    first_seen: datetime
    last_seen: datetime
    request_count: int = 0
    blocked_count: int = 0
    countries: Set[str] = field(default_factory=set)
    user_agents: Set[str] = field(default_factory=set)
    endpoints_accessed: Set[str] = field(default_factory=set)


@dataclass
class RequestPattern:
    """Pattern analysis for suspicious requests."""

    ip_address: str
    timestamp: float
    endpoint: str
    user_agent: str
    status_code: int
    response_time: float
    payload_size: int = 0


class IPBlacklistMiddleware(BaseHTTPMiddleware):
    """Comprehensive IP blacklist and threat detection middleware."""

    def __init__(self, app: Any) -> None:
        super().__init__(app)

        # Configuration
        self.config = get_rate_limiting_config()
        if not self.config:
            logger.warning("Rate limiting config not available, using defaults")
            self.enabled = False
            return

        self.blacklist_config = self.config.ip_blacklist_config
        self.enabled = self.blacklist_config.enabled

        if not self.enabled:
            logger.info("IP blacklist is disabled")
            return

        # Blacklist storage
        self.permanent_blacklist: Set[str] = set(
            self.blacklist_config.permanent_blacklist
        )
        self.temporary_blacklist: Dict[str, int] = dict(
            self.blacklist_config.temporary_blacklist
        )
        self.whitelist: Set[str] = set(self.blacklist_config.whitelist)

        # Threat detection
        self.threat_info: Dict[str, IPThreatInfo] = {}
        self.request_patterns: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=1000)
        )
        self.suspicious_patterns: Dict[str, int] = defaultdict(int)

        # Auto-blacklist tracking
        self.request_counts: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.failed_attempts: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))

        # Geo-blocking (simplified - in production use GeoIP database)
        self.blocked_countries: Set[str] = set(self.blacklist_config.blocked_countries)
        self.country_cache: Dict[str, str] = {}

        # Cleanup task
        self._cleanup_task = None
        self._start_cleanup_task()

        logger.info(
            f"IP blacklist middleware initialized - "
            f"Permanent: {len(self.permanent_blacklist)}, "
            f"Temporary: {len(self.temporary_blacklist)}, "
            f"Whitelist: {len(self.whitelist)}"
        )

    def _start_cleanup_task(self):
        """Start background cleanup task."""

        async def cleanup_expired_entries():
            while True:
                try:
                    await asyncio.sleep(300)  # Cleanup every 5 minutes
                    await self._cleanup_expired_entries()
                except Exception as e:
                    logger.error(f"Error in cleanup task: {e}")

        if not self._cleanup_task or self._cleanup_task.done():
            self._cleanup_task = asyncio.create_task(cleanup_expired_entries())

    async def _cleanup_expired_entries(self):
        """Clean up expired blacklist entries and old data."""
        current_time = int(time.time())

        # Clean up expired temporary blacklist entries
        expired_ips = [
            ip
            for ip, expiry in self.temporary_blacklist.items()
            if expiry < current_time
        ]
        for ip in expired_ips:
            del self.temporary_blacklist[ip]
            logger.info(f"Removed expired blacklist entry: {ip}")

        # Clean up old request patterns (keep last hour)
        cutoff_time = current_time - 3600
        for ip in list(self.request_patterns.keys()):
            patterns = self.request_patterns[ip]
            while patterns and patterns[0].timestamp < cutoff_time:
                patterns.popleft()
            if not patterns:
                del self.request_patterns[ip]

        # Clean up old request counts
        for ip in list(self.request_counts.keys()):
            counts = self.request_counts[ip]
            while counts and counts[0] < cutoff_time:
                counts.popleft()
            if not counts:
                del self.request_counts[ip]

        # Update configuration with current state
        self.blacklist_config.temporary_blacklist = self.temporary_blacklist
        if self.config:
            self.config.save_config()

    async def dispatch(self, request: Request, call_next: Callable[..., Awaitable[Response]]) -> Response:
        """Main middleware dispatch method."""
        if not self.enabled:
            return await call_next(request)

        start_time = time.time()
        client_ip = self._get_client_ip(request)

        try:
            # Check whitelist first
            if self._is_whitelisted(client_ip):
                return await call_next(request)

            # Check blacklists
            blacklist_result = self._check_blacklists(client_ip)
            if blacklist_result["blocked"]:
                return self._create_blocked_response(
                    client_ip, blacklist_result["reason"]
                )

            # Check geo-blocking
            if self.blacklist_config.geo_blocking_enabled:
                geo_result = await self._check_geo_blocking(client_ip)
                if geo_result["blocked"]:
                    return self._create_blocked_response(
                        client_ip, geo_result["reason"]
                    )

            # Check for suspicious patterns
            if await self._is_suspicious_request(request, client_ip):
                return self._create_blocked_response(
                    client_ip, "Suspicious request pattern detected"
                )

            # Process request
            response = await call_next(request)
            end_time = time.time()

            # Record request pattern
            await self._record_request_pattern(
                request, response, client_ip, start_time, end_time
            )

            # Check for auto-blacklist conditions
            if self.blacklist_config.auto_blacklist_enabled:
                await self._check_auto_blacklist(client_ip, response.status_code)

            return response

        except Exception as e:
            # Record failed request
            await self._record_failed_request(client_ip, str(e))
            raise

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP address with proxy support."""
        # Check for forwarded headers
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            # Take the first IP in the chain
            ip = forwarded_for.split(",")[0].strip()
            if self._is_valid_ip(ip):
                return ip

        real_ip = request.headers.get("X-Real-IP")
        if real_ip and self._is_valid_ip(real_ip):
            return real_ip

        cf_connecting_ip = request.headers.get("CF-Connecting-IP")
        if cf_connecting_ip and self._is_valid_ip(cf_connecting_ip):
            return cf_connecting_ip

        return request.client.host if request.client else "unknown"

    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address format."""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def _is_whitelisted(self, ip: str) -> bool:
        """Check if IP is whitelisted."""
        if ip in self.whitelist:
            return True

        # Check for subnet matches
        try:
            ip_obj = ipaddress.ip_address(ip)
            for whitelist_entry in self.whitelist:
                try:
                    if "/" in whitelist_entry:
                        network = ipaddress.ip_network(whitelist_entry, strict=False)
                        if ip_obj in network:
                            return True
                except ValueError:
                    continue
        except ValueError:
            pass

        return False

    def _check_blacklists(self, ip: str) -> Dict[str, Any]:
        """Check if IP is in any blacklist."""
        # Check permanent blacklist
        if ip in self.permanent_blacklist:
            return {
                "blocked": True,
                "reason": "IP permanently blacklisted",
                "type": "permanent",
            }

        # Check temporary blacklist
        if ip in self.temporary_blacklist:
            expiry = self.temporary_blacklist[ip]
            if time.time() < expiry:
                return {
                    "blocked": True,
                    "reason": "IP temporarily blacklisted",
                    "type": "temporary",
                }
            else:
                # Remove expired entry
                del self.temporary_blacklist[ip]

        # Check for subnet matches in permanent blacklist
        try:
            ip_obj = ipaddress.ip_address(ip)
            for blacklist_entry in self.permanent_blacklist:
                try:
                    if "/" in blacklist_entry:
                        network = ipaddress.ip_network(blacklist_entry, strict=False)
                        if ip_obj in network:
                            return {
                                "blocked": True,
                                "reason": "IP in blacklisted subnet",
                                "type": "subnet",
                            }
                except ValueError:
                    continue
        except ValueError:
            pass

        return {"blocked": False, "reason": None, "type": None}

    async def _check_geo_blocking(self, ip: str) -> Dict[str, Any]:
        """Check geo-blocking rules."""
        if not self.blocked_countries:
            return {"blocked": False, "reason": None}

        # Get country for IP (simplified - in production use GeoIP database)
        country = await self._get_ip_country(ip)

        if country and country.upper() in [c.upper() for c in self.blocked_countries]:
            return {
                "blocked": True,
                "reason": f"Access blocked from country: {country}",
            }

        return {"blocked": False, "reason": None}

    async def _get_ip_country(self, ip: str) -> Optional[str]:
        """Get country for IP address (simplified implementation)."""
        # In production, this would use a GeoIP database like MaxMind
        # For now, return None (no geo-blocking)
        return None

    async def _is_suspicious_request(self, request: Request, ip: str) -> bool:
        """Check for suspicious request patterns."""
        current_time = time.time()

        # Check request rate
        recent_requests = [t for t in self.request_counts[ip] if t > current_time - 60]
        if len(recent_requests) > self.blacklist_config.auto_blacklist_threshold:
            logger.warning(
                f"High request rate from {ip}: {len(recent_requests)} requests/minute"
            )
            return True

        # Check for suspicious user agents
        user_agent = request.headers.get("User-Agent", "").lower()
        suspicious_agents = [
            "bot",
            "crawler",
            "spider",
            "scraper",
            "scanner",
            "hack",
            "exploit",
            "sqlmap",
            "nikto",
            "nmap",
            "masscan",
            "zap",
            "burp",
        ]

        if any(agent in user_agent for agent in suspicious_agents):
            if not any(
                allowed in user_agent
                for allowed in ["googlebot", "bingbot", "facebookexternalhit"]
            ):
                logger.warning(f"Suspicious user agent from {ip}: {user_agent}")
                return True

        # Check for suspicious endpoints
        path = request.url.path.lower()
        suspicious_paths = [
            "/admin",
            "/wp-admin",
            "/phpmyadmin",
            "/.env",
            "/config",
            "/backup",
            "/database",
            "/sql",
            "/shell",
            "/cmd",
        ]

        if any(suspicious_path in path for suspicious_path in suspicious_paths):
            if not request.headers.get("Authorization"):  # No auth for admin paths
                logger.warning(f"Unauthorized access attempt to {path} from {ip}")
                return True

        # Check for SQL injection patterns in query parameters
        query_string = str(request.query_params).lower()
        sql_patterns = [
            "union select",
            "drop table",
            "insert into",
            "delete from",
            "' or '1'='1",
            "' or 1=1",
            "'; drop",
            "' union",
        ]

        if any(pattern in query_string for pattern in sql_patterns):
            logger.warning(f"SQL injection attempt from {ip}: {query_string}")
            return True

        return False

    async def _record_request_pattern(
        self,
        request: Request,
        response: Response,
        ip: str,
        start_time: float,
        end_time: float,
    ):
        """Record request pattern for analysis."""
        pattern = RequestPattern(
            ip_address=ip,
            timestamp=start_time,
            endpoint=request.url.path,
            user_agent=request.headers.get("User-Agent", ""),
            status_code=response.status_code,
            response_time=(end_time - start_time) * 1000,  # Convert to ms
            payload_size=len(await request.body()) if hasattr(request, "body") else 0,
        )

        self.request_patterns[ip].append(pattern)
        self.request_counts[ip].append(start_time)

        # Update threat info
        if ip not in self.threat_info:
            self.threat_info[ip] = IPThreatInfo(
                ip_address=ip,
                threat_level="low",
                threat_types=[],
                first_seen=datetime.now(),
                last_seen=datetime.now(),
            )

        threat_info = self.threat_info[ip]
        threat_info.last_seen = datetime.now()
        threat_info.request_count += 1
        threat_info.user_agents.add(pattern.user_agent[:100])  # Limit length
        threat_info.endpoints_accessed.add(pattern.endpoint)

    async def _record_failed_request(self, ip: str, error: str):
        """Record failed request for threat analysis."""
        self.failed_attempts[ip].append(time.time())

        if ip in self.threat_info:
            self.threat_info[ip].threat_types.append("failed_request")

    async def _check_auto_blacklist(self, ip: str, status_code: int):
        """Check if IP should be auto-blacklisted."""
        current_time = time.time()

        # Count recent requests
        recent_requests = [t for t in self.request_counts[ip] if t > current_time - 60]

        # Auto-blacklist if threshold exceeded
        if len(recent_requests) >= self.blacklist_config.auto_blacklist_threshold:
            self.add_to_temporary_blacklist(
                ip,
                self.blacklist_config.auto_blacklist_duration,
                f"Auto-blacklisted: {len(recent_requests)} requests/minute",
            )
            logger.warning(
                f"Auto-blacklisted {ip} for {self.blacklist_config.auto_blacklist_duration}s"
            )

        # Check for repeated failed attempts
        recent_failures = [
            t for t in self.failed_attempts[ip] if t > current_time - 300
        ]  # 5 minutes
        if len(recent_failures) >= 10:  # 10 failures in 5 minutes
            self.add_to_temporary_blacklist(
                ip,
                3600,  # 1 hour
                f"Auto-blacklisted: {len(recent_failures)} failures in 5 minutes",
            )
            logger.warning(f"Auto-blacklisted {ip} for repeated failures")

    def add_to_permanent_blacklist(self, ip: str, reason: str = "Manual addition"):
        """Add IP to permanent blacklist."""
        self.permanent_blacklist.add(ip)
        self.blacklist_config.permanent_blacklist.append(ip)

        if self.config:
            self.config.save_config()

        logger.info(f"Added {ip} to permanent blacklist: {reason}")

    def add_to_temporary_blacklist(
        self, ip: str, duration: int, reason: str = "Temporary block"
    ):
        """Add IP to temporary blacklist."""
        expiry = int(time.time()) + duration
        self.temporary_blacklist[ip] = expiry
        self.blacklist_config.temporary_blacklist[ip] = expiry

        if self.config:
            self.config.save_config()

        logger.info(f"Added {ip} to temporary blacklist for {duration}s: {reason}")

    def remove_from_blacklist(self, ip: str):
        """Remove IP from all blacklists."""
        removed = False

        if ip in self.permanent_blacklist:
            self.permanent_blacklist.remove(ip)
            if ip in self.blacklist_config.permanent_blacklist:
                self.blacklist_config.permanent_blacklist.remove(ip)
            removed = True

        if ip in self.temporary_blacklist:
            del self.temporary_blacklist[ip]
            if ip in self.blacklist_config.temporary_blacklist:
                del self.blacklist_config.temporary_blacklist[ip]
            removed = True

        if removed:
            if self.config:
                self.config.save_config()
            logger.info(f"Removed {ip} from blacklists")

        return removed

    def add_to_whitelist(self, ip: str):
        """Add IP to whitelist."""
        self.whitelist.add(ip)
        if ip not in self.blacklist_config.whitelist:
            self.blacklist_config.whitelist.append(ip)

        if self.config:
            self.config.save_config()

        logger.info(f"Added {ip} to whitelist")

    def _create_blocked_response(self, ip: str, reason: str) -> JSONResponse:
        """Create response for blocked IP."""
        # Update threat info
        if ip in self.threat_info:
            self.threat_info[ip].blocked_count += 1

        return JSONResponse(
            status_code=403,
            content={
                "error": "Access denied",
                "message": "Your IP address has been blocked",
                "reason": reason,
                "ip_address": ip,
                "timestamp": datetime.now().isoformat(),
                "code": "IP_BLOCKED",
            },
            headers={
                "X-Blocked-IP": ip,
                "X-Block-Reason": reason,
                "X-Block-Timestamp": str(int(time.time())),
            },
        )

    def get_blacklist_status(self) -> Dict[str, Any]:
        """Get current blacklist status and statistics."""
        current_time = int(time.time())

        # Count active temporary blocks
        active_temp_blocks = sum(
            1 for expiry in self.temporary_blacklist.values() if expiry > current_time
        )

        return {
            "enabled": self.enabled,
            "permanent_blacklist_count": len(self.permanent_blacklist),
            "temporary_blacklist_count": len(self.temporary_blacklist),
            "active_temporary_blocks": active_temp_blocks,
            "whitelist_count": len(self.whitelist),
            "threat_ips_tracked": len(self.threat_info),
            "auto_blacklist_enabled": self.blacklist_config.auto_blacklist_enabled,
            "auto_blacklist_threshold": self.blacklist_config.auto_blacklist_threshold,
            "geo_blocking_enabled": self.blacklist_config.geo_blocking_enabled,
            "blocked_countries": list(self.blocked_countries),
        }


# Utility function to add middleware to FastAPI app
def add_ip_blacklist_middleware(app: Any) -> None:
    """Add IP blacklist middleware to FastAPI app."""
    app.add_middleware(IPBlacklistMiddleware)
    logger.info("IP blacklist middleware added to FastAPI app")
