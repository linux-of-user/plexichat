"""
Web Application Firewall (WAF) Middleware for PlexiChat

This module implements a comprehensive WAF middleware that provides:
- IP reputation checking with threat intelligence
- SQL injection detection
- XSS prevention
- Payload size validation
- Rate limiting integration
- Pattern matching for common attack vectors
"""

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import ipaddress
import json
import re
import time
from urllib.parse import unquote

from fastapi import Request, Response
from fastapi.responses import JSONResponse
import httpx


class ThreatLevel(Enum):
    """Threat level classification"""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AttackType(Enum):
    """Types of detected attacks"""

    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    LDAP_INJECTION = "ldap_injection"
    XXE = "xxe"
    SSRF = "ssrf"
    MALICIOUS_IP = "malicious_ip"
    PAYLOAD_TOO_LARGE = "payload_too_large"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    SUSPICIOUS_HEADERS = "suspicious_headers"


@dataclass
class WAFConfig:
    """WAF configuration settings"""

    enabled: bool = True
    max_payload_size: int = 10 * 1024 * 1024  # 10MB
    ip_reputation_enabled: bool = True
    ip_reputation_threshold: int = 50  # 0-100 scale
    rate_limiting_enabled: bool = True
    rate_limit_requests: int = 100
    rate_limit_window: int = 60  # seconds
    block_malicious_ips: bool = True
    log_all_requests: bool = False
    whitelist_ips: set[str] = field(default_factory=set)
    blacklist_ips: set[str] = field(default_factory=set)
    threat_intel_api_key: str | None = None
    threat_intel_timeout: int = 5  # seconds
    enable_learning_mode: bool = False  # Log but don't block


@dataclass
class ThreatDetection:
    """Represents a detected threat"""

    attack_type: AttackType
    threat_level: ThreatLevel
    description: str
    payload: str
    confidence: float
    timestamp: float = field(default_factory=time.time)


class AttackPatterns:
    """Collection of attack detection patterns"""

    # SQL Injection patterns
    SQL_INJECTION_PATTERNS = [
        re.compile(
            r"(?i)(union\s+select|select\s+\*\s+from|drop\s+table|delete\s+from)",
            re.IGNORECASE,
        ),
        re.compile(
            r"(?i)(insert\s+into|update\s+\w+\s+set|alter\s+table)", re.IGNORECASE
        ),
        re.compile(r"(?i)(\'\s*or\s*\'\s*=\s*\'|\'\s*or\s*1\s*=\s*1)", re.IGNORECASE),
        re.compile(r"(?i)(--|\#|\/\*|\*\/)", re.IGNORECASE),
        re.compile(r"(?i)(exec\s*\(|sp_|xp_)", re.IGNORECASE),
        re.compile(r"(?i)(information_schema|sysobjects|syscolumns)", re.IGNORECASE),
        re.compile(r"(?i)(load_file|into\s+outfile|into\s+dumpfile)", re.IGNORECASE),
    ]

    # XSS patterns
    XSS_PATTERNS = [
        re.compile(r"(?i)<script[^>]*>.*?</script>", re.IGNORECASE | re.DOTALL),
        re.compile(r"(?i)<iframe[^>]*>.*?</iframe>", re.IGNORECASE | re.DOTALL),
        re.compile(r"(?i)on\w+\s*=\s*[\"']?[^\"'>]*[\"']?", re.IGNORECASE),
        re.compile(r"(?i)javascript\s*:", re.IGNORECASE),
        re.compile(r"(?i)vbscript\s*:", re.IGNORECASE),
        re.compile(r"(?i)data\s*:\s*text/html", re.IGNORECASE),
        re.compile(r"(?i)<object[^>]*>.*?</object>", re.IGNORECASE | re.DOTALL),
        re.compile(r"(?i)<embed[^>]*>", re.IGNORECASE),
        re.compile(r"(?i)<applet[^>]*>.*?</applet>", re.IGNORECASE | re.DOTALL),
        re.compile(r"(?i)expression\s*\(", re.IGNORECASE),
    ]

    # Command injection patterns
    COMMAND_INJECTION_PATTERNS = [
        re.compile(r"(?i)(\|\s*\w+|\&\&\s*\w+|\;\s*\w+)", re.IGNORECASE),
        re.compile(r"(?i)(nc\s+-|netcat|wget\s+|curl\s+)", re.IGNORECASE),
        re.compile(r"(?i)(bash|sh|cmd|powershell|python|perl|ruby)\s", re.IGNORECASE),
        re.compile(r"(?i)(`|\$\(|\$\{)", re.IGNORECASE),
    ]

    # Path traversal patterns
    PATH_TRAVERSAL_PATTERNS = [
        re.compile(r"(?i)(\.\.\/|\.\.\\)", re.IGNORECASE),
        re.compile(r"(?i)(%2e%2e%2f|%2e%2e%5c)", re.IGNORECASE),
        re.compile(
            r"(?i)(\/etc\/passwd|\/etc\/shadow|\/windows\/system32)", re.IGNORECASE
        ),
        re.compile(r"(?i)(\.\.%2f|\.\.%5c)", re.IGNORECASE),
    ]

    # LDAP injection patterns
    LDAP_INJECTION_PATTERNS = [
        re.compile(r"(?i)(\*\)|\(\||\)\(|\&\()", re.IGNORECASE),
        re.compile(r"(?i)(objectclass=\*|cn=\*)", re.IGNORECASE),
    ]

    # XXE patterns
    XXE_PATTERNS = [
        re.compile(r"(?i)<!entity", re.IGNORECASE),
        re.compile(r"(?i)<!doctype.*\[", re.IGNORECASE | re.DOTALL),
        re.compile(r"(?i)system\s+[\"'][^\"']*[\"']", re.IGNORECASE),
    ]

    # SSRF patterns
    SSRF_PATTERNS = [
        re.compile(r"(?i)(localhost|127\.0\.0\.1|0\.0\.0\.0)", re.IGNORECASE),
        re.compile(
            r"(?i)(169\.254\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.)",
            re.IGNORECASE,
        ),
        re.compile(r"(?i)(file://|ftp://|gopher://|dict://)", re.IGNORECASE),
    ]

    # Suspicious headers
    SUSPICIOUS_HEADERS = [
        "x-forwarded-host",
        "x-original-url",
        "x-rewrite-url",
        "x-real-ip",
        "x-cluster-client-ip",
    ]


class IPReputationChecker:
    """Handles IP reputation checking with threat intelligence"""

    def __init__(self, config: WAFConfig):
        self.config = config
        self.cache: dict[str, tuple[bool, float]] = {}
        self.cache_ttl = 3600  # 1 hour

    async def check_ip_reputation(self, ip: str) -> tuple[bool, int]:
        """
        Check IP reputation against threat intelligence sources
        Returns (is_malicious, confidence_score)
        """
        if not self.config.ip_reputation_enabled:
            return False, 0

        # Check cache first
        if ip in self.cache:
            is_malicious, timestamp = self.cache[ip]
            if time.time() - timestamp < self.cache_ttl:
                return is_malicious, 100 if is_malicious else 0

        # Check whitelist/blacklist
        if ip in self.config.whitelist_ips:
            return False, 0
        if ip in self.config.blacklist_ips:
            return True, 100

        # Check if IP is private/local
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private or ip_obj.is_loopback:
                return False, 0
        except ValueError:
            return True, 50  # Invalid IP format is suspicious

        # Query external threat intelligence
        is_malicious, score = await self._query_threat_intelligence(ip)

        # Cache result
        self.cache[ip] = (is_malicious, time.time())

        return is_malicious, score

    async def _query_threat_intelligence(self, ip: str) -> tuple[bool, int]:
        """Query external threat intelligence APIs"""
        if not self.config.threat_intel_api_key:
            return False, 0

        try:
            # Example using AbuseIPDB API
            headers = {
                "Key": self.config.threat_intel_api_key,
                "Accept": "application/json",
            }
            params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""}

            async with httpx.AsyncClient(
                timeout=self.config.threat_intel_timeout
            ) as client:
                response = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers=headers,
                    params=params,
                )

                if response.status_code == 200:
                    data = response.json()
                    confidence = data.get("data", {}).get("abuseConfidenceScore", 0)
                    is_malicious = confidence >= self.config.ip_reputation_threshold
                    return is_malicious, confidence

        except Exception:
            # Log error but don't block on API failure
            pass

        return False, 0


class RateLimiter:
    """Rate limiting implementation"""

    def __init__(self, config: WAFConfig):
        self.config = config
        self.requests: dict[str, list[float]] = {}

    def is_rate_limited(self, ip: str) -> bool:
        """Check if IP is rate limited"""
        if not self.config.rate_limiting_enabled:
            return False

        current_time = time.time()
        window_start = current_time - self.config.rate_limit_window

        # Clean old requests
        if ip in self.requests:
            self.requests[ip] = [
                req_time for req_time in self.requests[ip] if req_time > window_start
            ]
        else:
            self.requests[ip] = []

        # Check rate limit
        if len(self.requests[ip]) >= self.config.rate_limit_requests:
            return True

        # Add current request
        self.requests[ip].append(current_time)
        return False


class WAFMiddleware:
    """Main WAF middleware class"""

    def __init__(self, config: WAFConfig = None):
        self.config = config or WAFConfig()
        self.ip_checker = IPReputationChecker(self.config)
        from plexichat.core.middleware.rate_limiting import get_rate_limiter

        self.rate_limiter_engine = get_rate_limiter()
        self.attack_patterns = AttackPatterns()

    async def __call__(self, request: Request, call_next):
        """Main middleware entry point"""
        if not self.config.enabled:
            return await call_next(request)

        try:
            # Extract client IP
            client_ip = self._get_client_ip(request)

            # Check rate limiting via unified engine
            allowed, _info = await self.rate_limiter_engine.check_ip_action(
                client_ip, "/waf"
            )
            if not allowed:
                return await self._handle_threat(
                    request,
                    ThreatDetection(
                        attack_type=AttackType.RATE_LIMIT_EXCEEDED,
                        threat_level=ThreatLevel.MEDIUM,
                        description=f"Rate limit exceeded for IP {client_ip}",
                        payload=f"IP: {client_ip}",
                        confidence=1.0,
                    ),
                )

            # Check IP reputation
            is_malicious_ip, confidence = await self.ip_checker.check_ip_reputation(
                client_ip
            )
            if is_malicious_ip and self.config.block_malicious_ips:
                return await self._handle_threat(
                    request,
                    ThreatDetection(
                        attack_type=AttackType.MALICIOUS_IP,
                        threat_level=ThreatLevel.HIGH,
                        description=f"Malicious IP detected: {client_ip}",
                        payload=f"IP: {client_ip}, Confidence: {confidence}%",
                        confidence=confidence / 100.0,
                    ),
                )

            # Check payload size
            content_length = request.headers.get("content-length")
            if content_length and int(content_length) > self.config.max_payload_size:
                return await self._handle_threat(
                    request,
                    ThreatDetection(
                        attack_type=AttackType.PAYLOAD_TOO_LARGE,
                        threat_level=ThreatLevel.MEDIUM,
                        description=f"Payload too large: {content_length} bytes",
                        payload=f"Size: {content_length}",
                        confidence=1.0,
                    ),
                )

            # Check suspicious headers
            threat = self._check_suspicious_headers(request)
            if threat:
                return await self._handle_threat(request, threat)

            # Analyze request content
            threat = await self._analyze_request_content(request)
            if threat:
                return await self._handle_threat(request, threat)

            # Request passed all checks
            response = await call_next(request)

            # Log clean request if configured
            if self.config.log_all_requests:
                await self._log_request(request, client_ip, "ALLOWED")

            return response

        except Exception as e:
            # Log error and allow request to proceed
            await self._log_error(f"WAF middleware error: {e!s}")
            return await call_next(request)

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP from request"""
        # Check X-Forwarded-For header first
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            # Take the first IP in the chain
            return forwarded_for.split(",")[0].strip()

        # Check X-Real-IP header
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip.strip()

        # Fall back to direct client IP
        return request.client.host if request.client else "unknown"

    def _check_suspicious_headers(self, request: Request) -> ThreatDetection | None:
        """Check for suspicious headers"""
        for header_name in self.attack_patterns.SUSPICIOUS_HEADERS:
            if header_name in request.headers:
                header_value = request.headers[header_name]
                if self._contains_malicious_patterns(header_value):
                    return ThreatDetection(
                        attack_type=AttackType.SUSPICIOUS_HEADERS,
                        threat_level=ThreatLevel.MEDIUM,
                        description=f"Suspicious header detected: {header_name}",
                        payload=f"{header_name}: {header_value}",
                        confidence=0.8,
                    )
        return None

    async def _analyze_request_content(
        self, request: Request
    ) -> ThreatDetection | None:
        """Analyze request content for attack patterns"""
        try:
            # Get request body
            body = await request.body()
            body_text = body.decode("utf-8", errors="ignore")

            # Get query parameters
            query_string = str(request.query_params)

            # Get URL path
            url_path = str(request.url.path)

            # Combine all content for analysis
            content_to_analyze = [
                ("body", body_text),
                ("query", query_string),
                ("path", url_path),
            ]

            # Check each content type
            for content_type, content in content_to_analyze:
                if not content:
                    continue

                # URL decode content
                decoded_content = unquote(content)

                # Check for various attack patterns
                threat = self._check_attack_patterns(decoded_content, content_type)
                if threat:
                    return threat

        except Exception as e:
            # Log error but don't block request
            await self._log_error(f"Error analyzing request content: {e!s}")

        return None

    def _check_attack_patterns(
        self, content: str, content_type: str
    ) -> ThreatDetection | None:
        """Check content against attack patterns"""
        # SQL Injection
        for pattern in self.attack_patterns.SQL_INJECTION_PATTERNS:
            if pattern.search(content):
                return ThreatDetection(
                    attack_type=AttackType.SQL_INJECTION,
                    threat_level=ThreatLevel.HIGH,
                    description=f"SQL injection detected in {content_type}",
                    payload=content[:500],  # Limit payload size in logs
                    confidence=0.9,
                )

        # XSS
        for pattern in self.attack_patterns.XSS_PATTERNS:
            if pattern.search(content):
                return ThreatDetection(
                    attack_type=AttackType.XSS,
                    threat_level=ThreatLevel.HIGH,
                    description=f"XSS attack detected in {content_type}",
                    payload=content[:500],
                    confidence=0.9,
                )

        # Command Injection
        for pattern in self.attack_patterns.COMMAND_INJECTION_PATTERNS:
            if pattern.search(content):
                return ThreatDetection(
                    attack_type=AttackType.COMMAND_INJECTION,
                    threat_level=ThreatLevel.CRITICAL,
                    description=f"Command injection detected in {content_type}",
                    payload=content[:500],
                    confidence=0.8,
                )

        # Path Traversal
        for pattern in self.attack_patterns.PATH_TRAVERSAL_PATTERNS:
            if pattern.search(content):
                return ThreatDetection(
                    attack_type=AttackType.PATH_TRAVERSAL,
                    threat_level=ThreatLevel.HIGH,
                    description=f"Path traversal detected in {content_type}",
                    payload=content[:500],
                    confidence=0.8,
                )

        # LDAP Injection
        for pattern in self.attack_patterns.LDAP_INJECTION_PATTERNS:
            if pattern.search(content):
                return ThreatDetection(
                    attack_type=AttackType.LDAP_INJECTION,
                    threat_level=ThreatLevel.HIGH,
                    description=f"LDAP injection detected in {content_type}",
                    payload=content[:500],
                    confidence=0.7,
                )

        # XXE
        for pattern in self.attack_patterns.XXE_PATTERNS:
            if pattern.search(content):
                return ThreatDetection(
                    attack_type=AttackType.XXE,
                    threat_level=ThreatLevel.HIGH,
                    description=f"XXE attack detected in {content_type}",
                    payload=content[:500],
                    confidence=0.8,
                )

        # SSRF
        for pattern in self.attack_patterns.SSRF_PATTERNS:
            if pattern.search(content):
                return ThreatDetection(
                    attack_type=AttackType.SSRF,
                    threat_level=ThreatLevel.HIGH,
                    description=f"SSRF attack detected in {content_type}",
                    payload=content[:500],
                    confidence=0.7,
                )

        return None

    def _contains_malicious_patterns(self, content: str) -> bool:
        """Quick check if content contains any malicious patterns"""
        all_patterns = (
            self.attack_patterns.SQL_INJECTION_PATTERNS
            + self.attack_patterns.XSS_PATTERNS
            + self.attack_patterns.COMMAND_INJECTION_PATTERNS
            + self.attack_patterns.PATH_TRAVERSAL_PATTERNS
        )

        for pattern in all_patterns:
            if pattern.search(content):
                return True
        return False

    async def _handle_threat(
        self, request: Request, threat: ThreatDetection
    ) -> Response:
        """Handle detected threat"""
        client_ip = self._get_client_ip(request)

        # Log the threat
        await self._log_threat(request, client_ip, threat)

        # In learning mode, log but don't block
        if self.config.enable_learning_mode:
            return JSONResponse(
                status_code=200,
                content={
                    "status": "learning_mode",
                    "threat_detected": threat.attack_type.value,
                    "message": "Request would be blocked in enforcement mode",
                },
            )

        # Block the request
        return JSONResponse(
            status_code=403,
            content={
                "error": "Request blocked by WAF",
                "threat_type": threat.attack_type.value,
                "message": "Your request has been blocked due to security policy",
                "request_id": self._generate_request_id(request),
            },
        )

    def _generate_request_id(self, request: Request) -> str:
        """Generate unique request ID for tracking"""
        content = f"{request.client.host}{request.url.path}{time.time()}"
        return hashlib.md5(content.encode()).hexdigest()[:12]

    async def _log_threat(
        self, request: Request, client_ip: str, threat: ThreatDetection
    ):
        """Log detected threat"""
        log_data = {
            "timestamp": threat.timestamp,
            "client_ip": client_ip,
            "attack_type": threat.attack_type.value,
            "threat_level": threat.threat_level.value,
            "description": threat.description,
            "confidence": threat.confidence,
            "url": str(request.url),
            "method": request.method,
            "user_agent": request.headers.get("user-agent", ""),
            "payload_preview": threat.payload[:200] if threat.payload else "",
            "request_id": self._generate_request_id(request),
        }

        # Integrate with unified logging system
        try:
            from plexichat.core.logging import get_logger

            logger = get_logger("plexichat.security.waf")
            logger.critical(f"WAF THREAT DETECTED: {json.dumps(log_data, indent=2)}")
        except Exception:
            # Fallback to print if logging system unavailable
            print(f"WAF THREAT DETECTED: {json.dumps(log_data, indent=2)}")

    async def _log_request(self, request: Request, client_ip: str, status: str):
        """Log request (for audit purposes)"""
        log_data = {
            "timestamp": time.time(),
            "client_ip": client_ip,
            "status": status,
            "url": str(request.url),
            "method": request.method,
            "user_agent": request.headers.get("user-agent", ""),
            "request_id": self._generate_request_id(request),
        }

        # Integrate with unified logging system
        try:
            from plexichat.core.logging import get_logger

            logger = get_logger("plexichat.security.waf")
            if self.config.log_all_requests:
                logger.info(f"WAF REQUEST: {json.dumps(log_data)}")
        except Exception:
            # Fallback to print if logging system unavailable
            if self.config.log_all_requests:
                print(f"WAF REQUEST: {json.dumps(log_data)}")

    async def _log_error(self, message: str):
        """Log WAF errors"""
        error_data = {
            "timestamp": time.time(),
            "level": "ERROR",
            "component": "WAF",
            "message": message,
        }

        # Integrate with unified logging system
        try:
            from plexichat.core.logging import get_logger

            logger = get_logger("plexichat.security.waf")
            logger.error(f"WAF ERROR: {json.dumps(error_data)}")
        except Exception:
            # Fallback to print if logging system unavailable
            print(f"WAF ERROR: {json.dumps(error_data)}")


# Factory function for easy integration
def create_waf_middleware(
    enabled: bool = True,
    max_payload_size: int = 10 * 1024 * 1024,
    ip_reputation_enabled: bool = True,
    rate_limiting_enabled: bool = True,
    threat_intel_api_key: str | None = None,
    whitelist_ips: list[str] | None = None,
    blacklist_ips: list[str] | None = None,
    enable_learning_mode: bool = False,
) -> WAFMiddleware:
    """
    Factory function to create WAF middleware with custom configuration

    Args:
        enabled: Enable/disable WAF
        max_payload_size: Maximum allowed payload size in bytes
        ip_reputation_enabled: Enable IP reputation checking
        rate_limiting_enabled: Enable rate limiting
        threat_intel_api_key: API key for threat intelligence service
        whitelist_ips: List of whitelisted IP addresses
        blacklist_ips: List of blacklisted IP addresses
        enable_learning_mode: Enable learning mode (log but don't block)

    Returns:
        Configured WAF middleware instance
    """
    config = WAFConfig(
        enabled=enabled,
        max_payload_size=max_payload_size,
        ip_reputation_enabled=ip_reputation_enabled,
        rate_limiting_enabled=rate_limiting_enabled,
        threat_intel_api_key=threat_intel_api_key,
        whitelist_ips=set(whitelist_ips or []),
        blacklist_ips=set(blacklist_ips or []),
        enable_learning_mode=enable_learning_mode,
    )

    return WAFMiddleware(config)


# Example usage and integration
"""
# Basic usage in FastAPI app:

from fastapi import FastAPI
from plexichat.core.security.waf_middleware import create_waf_middleware

app = FastAPI()

# Add WAF middleware
waf = create_waf_middleware(
    enabled=True,
    threat_intel_api_key="your_api_key_here",
    whitelist_ips=["192.168.1.100", "10.0.0.50"],
    enable_learning_mode=False
)

app.add_middleware(WAFMiddleware, waf)

# Or with custom configuration:

from plexichat.core.security.waf_middleware import WAFConfig, WAFMiddleware

config = WAFConfig(
    enabled=True,
    max_payload_size=5 * 1024 * 1024,  # 5MB
    ip_reputation_threshold=75,
    rate_limit_requests=50,
    rate_limit_window=60
)

app.add_middleware(WAFMiddleware, config)
"""
