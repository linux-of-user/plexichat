"""
Enhanced API Security Middleware - Enterprise-Grade API Protection
================================================================

This module provides enterprise-grade API security middleware with:
- Advanced authentication and authorization
- Rate limiting and DDoS protection
- CORS configuration and validation
- Input validation and sanitization
- Request/response encryption
- API key management
- Security headers enforcement
- Real-time threat detection
"""

import asyncio
import json
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable, Tuple
from dataclasses import dataclass
from enum import Enum
import hashlib
import hmac
import secrets
import re
from urllib.parse import urlparse

# FastAPI imports with fallbacks
try:
    from fastapi import Request, Response, HTTPException, status
    from fastapi.middleware.base import BaseHTTPMiddleware
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
    from starlette.middleware.base import RequestResponseEndpoint
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False
    Request = None
    Response = None
    HTTPException = None
    BaseHTTPMiddleware = None

from ..security.enhanced_security_manager import enhanced_security_manager
from ..logging.enhanced_logger import enhanced_logger

logger = logging.getLogger(__name__)

class SecurityLevel(Enum):
    """API security levels."""
    PUBLIC = "public"
    AUTHENTICATED = "authenticated"
    AUTHORIZED = "authorized"
    ADMIN = "admin"
    SYSTEM = "system"

class ThreatType(Enum):
    """API threat types."""
    BRUTE_FORCE = "brute_force"
    SQL_INJECTION = "sql_injection"
    XSS_ATTEMPT = "xss_attempt"
    DDOS = "ddos"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    MALFORMED_REQUEST = "malformed_request"
    SUSPICIOUS_PATTERN = "suspicious_pattern"

@dataclass
class APISecurityConfig:
    """API security configuration."""
    # Authentication
    require_authentication: bool = True
    jwt_secret_key: str = ""
    jwt_algorithm: str = "HS256"
    jwt_expiration_minutes: int = 15
    
    # Rate limiting
    enable_rate_limiting: bool = True
    default_rate_limit: int = 100  # requests per minute
    burst_limit: int = 200
    rate_limit_window: int = 60  # seconds
    
    # CORS
    enable_cors: bool = True
    allowed_origins: List[str] = None
    allowed_methods: List[str] = None
    allowed_headers: List[str] = None
    allow_credentials: bool = False
    
    # Security headers
    enable_security_headers: bool = True
    hsts_max_age: int = 31536000  # 1 year
    content_security_policy: str = "default-src 'self'"
    
    # Input validation
    enable_input_validation: bool = True
    max_request_size: int = 10 * 1024 * 1024  # 10MB
    max_json_depth: int = 10
    
    # Encryption
    enable_request_encryption: bool = False
    enable_response_encryption: bool = False
    encryption_key: str = ""
    
    # Monitoring
    enable_threat_detection: bool = True
    log_all_requests: bool = True
    log_security_events: bool = True

class EnhancedSecurityMiddleware(BaseHTTPMiddleware if FASTAPI_AVAILABLE else object):
    """Enhanced security middleware for API protection."""
    
    def __init__(self, app, config: APISecurityConfig = None):
        if FASTAPI_AVAILABLE:
            super().__init__(app)
        self.app = app
        self.config = config or APISecurityConfig()
        
        # Security state
        self.request_counts: Dict[str, List[float]] = {}
        self.blocked_ips: Dict[str, float] = {}
        self.api_keys: Dict[str, Dict[str, Any]] = {}
        self.threat_patterns: Dict[str, List[str]] = {}
        
        # Performance metrics
        self.request_metrics = {
            'total_requests': 0,
            'blocked_requests': 0,
            'authenticated_requests': 0,
            'failed_authentications': 0,
            'threats_detected': 0
        }
        
        # Initialize security components
        self._initialize_security()
        
        enhanced_logger.info("Enhanced API Security Middleware initialized")
    
    def _initialize_security(self):
        """Initialize security components."""
        # Initialize threat patterns
        self.threat_patterns = {
            'sql_injection': [
                r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)",
                r"(--|#|/\*|\*/)",
                r"(\b(OR|AND)\s+\d+\s*=\s*\d+)",
                r"(\bUNION\s+SELECT\b)",
            ],
            'xss': [
                r"<script[^>]*>.*?</script>",
                r"javascript:",
                r"vbscript:",
                r"on\w+\s*=",
                r"<iframe[^>]*>",
            ],
            'path_traversal': [
                r"\.\./",
                r"\.\.\\",
                r"%2e%2e%2f",
                r"%2e%2e%5c",
            ],
            'command_injection': [
                r"[;&|`$(){}[\]\\]",
                r"\b(rm|del|format|kill|shutdown)\b",
                r"(>|>>|<|\|)",
            ]
        }
        
        # Compile patterns for performance
        self.compiled_patterns = {}
        for threat_type, patterns in self.threat_patterns.items():
            self.compiled_patterns[threat_type] = [
                re.compile(pattern, re.IGNORECASE) for pattern in patterns
            ]
        
        # Initialize default API keys (in production, load from secure storage)
        self._initialize_api_keys()
    
    def _initialize_api_keys(self):
        """Initialize API keys."""
        # Generate a default admin API key
        admin_key = secrets.token_urlsafe(32)
        self.api_keys[admin_key] = {
            'name': 'admin',
            'permissions': ['admin', 'read', 'write'],
            'rate_limit': 1000,
            'created_at': datetime.now(),
            'last_used': None,
            'usage_count': 0
        }
        
        enhanced_logger.info(f"Generated admin API key: {admin_key[:8]}...")
    
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """Main middleware dispatch method."""
        start_time = time.time()
        client_ip = self._get_client_ip(request)
        
        try:
            # Update metrics
            self.request_metrics['total_requests'] += 1
            
            # Set logging context
            enhanced_logger.set_context(
                request_id=secrets.token_urlsafe(8),
                source_ip=client_ip,
                method=request.method,
                path=request.url.path
            )
            
            # Security checks
            security_result = await self._perform_security_checks(request, client_ip)
            if not security_result['allowed']:
                self.request_metrics['blocked_requests'] += 1
                enhanced_logger.security(
                    f"Request blocked: {security_result['reason']}",
                    source_ip=client_ip,
                    threat_level=security_result.get('threat_level', 'medium')
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=security_result['reason']
                )
            
            # Add security headers to request
            self._add_security_headers(request)
            
            # Process request
            response = await call_next(request)
            
            # Add security headers to response
            self._add_response_security_headers(response)
            
            # Log successful request
            execution_time = time.time() - start_time
            enhanced_logger.performance(
                f"Request processed successfully",
                execution_time=execution_time,
                status_code=response.status_code
            )
            
            return response
            
        except HTTPException:
            raise
        except Exception as e:
            enhanced_logger.error(f"Middleware error: {e}", source_ip=client_ip)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal server error"
            )
        finally:
            enhanced_logger.clear_context()
    
    async def _perform_security_checks(self, request: Request, client_ip: str) -> Dict[str, Any]:
        """Perform comprehensive security checks."""
        # Check if IP is blocked
        if client_ip in self.blocked_ips:
            if time.time() < self.blocked_ips[client_ip]:
                return {
                    'allowed': False,
                    'reason': 'IP temporarily blocked',
                    'threat_level': 'high'
                }
            else:
                del self.blocked_ips[client_ip]
        
        # Rate limiting
        if self.config.enable_rate_limiting:
            rate_limit_result = self._check_rate_limit(client_ip, request)
            if not rate_limit_result['allowed']:
                return rate_limit_result
        
        # Authentication check
        if self.config.require_authentication:
            auth_result = await self._check_authentication(request)
            if not auth_result['allowed']:
                return auth_result
        
        # Input validation
        if self.config.enable_input_validation:
            validation_result = await self._validate_input(request)
            if not validation_result['allowed']:
                return validation_result
        
        # Threat detection
        if self.config.enable_threat_detection:
            threat_result = await self._detect_threats(request)
            if not threat_result['allowed']:
                return threat_result
        
        return {'allowed': True}
    
    def _check_rate_limit(self, client_ip: str, request: Request) -> Dict[str, Any]:
        """Check rate limiting for client IP."""
        current_time = time.time()
        
        # Initialize request tracking for IP
        if client_ip not in self.request_counts:
            self.request_counts[client_ip] = []
        
        # Clean old requests
        window_start = current_time - self.config.rate_limit_window
        self.request_counts[client_ip] = [
            req_time for req_time in self.request_counts[client_ip]
            if req_time > window_start
        ]
        
        # Check rate limit
        current_requests = len(self.request_counts[client_ip])
        
        # Get rate limit for this request (could be API key specific)
        rate_limit = self._get_rate_limit_for_request(request)
        
        if current_requests >= rate_limit:
            # Block IP temporarily for repeated violations
            if current_requests >= self.config.burst_limit:
                self.blocked_ips[client_ip] = current_time + 3600  # Block for 1 hour
            
            return {
                'allowed': False,
                'reason': 'Rate limit exceeded',
                'threat_level': 'medium',
                'retry_after': self.config.rate_limit_window
            }
        
        # Add current request
        self.request_counts[client_ip].append(current_time)
        
        return {'allowed': True}
    
    def _get_rate_limit_for_request(self, request: Request) -> int:
        """Get rate limit for specific request (considering API key)."""
        # Check for API key in headers
        api_key = request.headers.get('X-API-Key')
        if api_key and api_key in self.api_keys:
            return self.api_keys[api_key].get('rate_limit', self.config.default_rate_limit)
        
        return self.config.default_rate_limit
    
    async def _check_authentication(self, request: Request) -> Dict[str, Any]:
        """Check request authentication."""
        # Skip authentication for public endpoints
        if self._is_public_endpoint(request.url.path):
            return {'allowed': True}
        
        # Check API key authentication
        api_key = request.headers.get('X-API-Key')
        if api_key:
            return self._validate_api_key(api_key)
        
        # Check JWT authentication
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header[7:]  # Remove 'Bearer ' prefix
            return await self._validate_jwt_token(token)
        
        # No valid authentication found
        self.request_metrics['failed_authentications'] += 1
        return {
            'allowed': False,
            'reason': 'Authentication required',
            'threat_level': 'low'
        }
    
    def _is_public_endpoint(self, path: str) -> bool:
        """Check if endpoint is public."""
        public_endpoints = [
            '/health',
            '/docs',
            '/openapi.json',
            '/auth/login',
            '/auth/register'
        ]
        return any(path.startswith(endpoint) for endpoint in public_endpoints)
    
    def _validate_api_key(self, api_key: str) -> Dict[str, Any]:
        """Validate API key."""
        if api_key in self.api_keys:
            key_info = self.api_keys[api_key]
            key_info['last_used'] = datetime.now()
            key_info['usage_count'] += 1
            
            self.request_metrics['authenticated_requests'] += 1
            return {
                'allowed': True,
                'auth_type': 'api_key',
                'permissions': key_info['permissions']
            }
        
        return {
            'allowed': False,
            'reason': 'Invalid API key',
            'threat_level': 'medium'
        }
    
    async def _validate_jwt_token(self, token: str) -> Dict[str, Any]:
        """Validate JWT token."""
        try:
            # Use the enhanced security manager's token validation
            payload = enhanced_security_manager.token_manager.verify_token(token)
            
            if payload:
                self.request_metrics['authenticated_requests'] += 1
                return {
                    'allowed': True,
                    'auth_type': 'jwt',
                    'user_id': payload.get('user_id'),
                    'permissions': payload.get('permissions', [])
                }
            else:
                return {
                    'allowed': False,
                    'reason': 'Invalid or expired token',
                    'threat_level': 'medium'
                }
                
        except Exception as e:
            enhanced_logger.error(f"JWT validation error: {e}")
            return {
                'allowed': False,
                'reason': 'Token validation failed',
                'threat_level': 'medium'
            }
