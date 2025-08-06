#!/usr/bin/env python3
"""
PlexiChat Enterprise API

Production-ready, enterprise-grade API with comprehensive security,
performance optimizations, and rate limiting for 10,000+ requests/minute.
"""

import asyncio
import hashlib
import hmac
import os
import secrets
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, Any, List, Set
import sys

# Add src to path
current_dir = Path(__file__).parent
src_dir = current_dir.parent.parent
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

# Import core systems
try:
    from plexichat.core.logging.unified_logger import setup_logging, get_logger, LogCategory
    from plexichat.core.config.simple_config import init_config, get_config
    CORE_SYSTEMS_AVAILABLE = True
except ImportError:
    CORE_SYSTEMS_AVAILABLE = False

# Import FastAPI and security libraries
try:
    from fastapi import FastAPI, Request, HTTPException, status, Depends, Header
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.middleware.trustedhost import TrustedHostMiddleware
    from fastapi.middleware.gzip import GZipMiddleware
    from fastapi.responses import JSONResponse
    from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
    import uvicorn
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False

# Enterprise Security Configuration
ENTERPRISE_CONFIG = {
    "security": {
        "api_key_required": True,
        "rate_limiting": True,
        "request_signing": True,
        "ip_whitelist_enabled": False,
        "cors_strict": True,
        "security_headers": True,
        "request_validation": True,
        "response_sanitization": True
    },
    "performance": {
        "compression": True,
        "caching": True,
        "connection_pooling": True,
        "async_processing": True,
        "request_timeout": 30,
        "max_request_size": 1048576,  # 1MB
        "max_concurrent_requests": 1000
    },
    "rate_limits": {
        "global_per_minute": 10000,
        "per_ip_per_minute": 100,
        "per_api_key_per_minute": 1000,
        "burst_allowance": 50,
        "rate_limit_window": 60
    }
}

# Global variables
app_config: Optional[Any] = None
logger: Optional[Any] = None
security_manager: Optional[Any] = None

# In-memory stores for production (replace with Redis in real deployment)
rate_limit_store: Dict[str, Dict[str, Any]] = {}
api_key_store: Set[str] = set()
request_cache: Dict[str, Dict[str, Any]] = {}
blocked_ips: Set[str] = set()

class EnterpriseSecurityManager:
    """Enterprise-grade security manager."""
        def __init__(self):
        self.api_keys = self._load_api_keys()
        self.signing_secret = os.environ.get("PLEXICHAT_SIGNING_SECRET", secrets.token_hex(32))
        self.request_id_store: Set[str] = set()
        
    def _load_api_keys(self) -> Set[str]:
        """Load API keys from environment or config."""
        # In production, load from secure key management system
        default_keys = {
            os.environ.get("PLEXICHAT_API_KEY", "plx_" + secrets.token_hex(32)),
            "plx_enterprise_demo_key_12345"  # Demo key for testing
        }
        return default_keys
    
    def validate_api_key(self, api_key: str) -> bool:
        """Validate API key."""
        if not api_key or not api_key.startswith("plx_"):
            return False
        return api_key in self.api_keys
    
    def validate_request_signature(self, request: Request, signature: str) -> bool:
        """Validate request signature for additional security."""
        if not ENTERPRISE_CONFIG["security"]["request_signing"]:
            return True
            
        try:
            # Get request data
            timestamp = request.headers.get("X-Timestamp", "")
            nonce = request.headers.get("X-Nonce", "")
            
            # Check timestamp (prevent replay attacks)
            if timestamp:
                request_time = float(timestamp)
                if abs(time.time() - request_time) > 300:  # 5 minutes
                    return False
            
            # Check nonce (prevent duplicate requests)
            if nonce in self.request_id_store:
                return False
            self.request_id_store.add(nonce)
            
            # Validate signature
            message = f"{request.method}{request.url.path}{timestamp}{nonce}"
            expected_signature = hmac.new(
                self.signing_secret.encode(),
                message.encode(),
                hashlib.sha256
            ).hexdigest()
            
            return hmac.compare_digest(signature, expected_signature)
            
        except Exception:
            return False
    
    def is_ip_allowed(self, ip: str) -> bool:
        """Check if IP is allowed."""
        if ip in blocked_ips:
            return False
            
        if ENTERPRISE_CONFIG["security"]["ip_whitelist_enabled"]:
            # In production, load from config
            allowed_ips = {"127.0.0.1", "::1"}
            return ip in allowed_ips
            
        return True

class EnterpriseRateLimiter:
    """Enterprise-grade rate limiter."""
        def __init__(self):
        self.limits = ENTERPRISE_CONFIG["rate_limits"]
        self.window_size = self.limits["rate_limit_window"]
    
    def _get_rate_limit_key(self, identifier: str, limit_type: str) -> str:
        """Generate rate limit key."""
        window = int(time.time() // self.window_size)
        return f"{limit_type}:{identifier}:{window}"
    
    def _cleanup_old_entries(self):
        """Clean up old rate limit entries."""
        current_time = time.time()
        current_window = int(current_time // self.window_size)
        
        keys_to_remove = []
        for key in rate_limit_store:
            if ":" in key:
                parts = key.split(":")
                if len(parts) >= 3:
                    try:
                        window = int(parts[-1])
                        if current_window - window > 2:  # Keep 2 windows
                            keys_to_remove.append(key)
                    except ValueError:
                        pass
        
        for key in keys_to_remove:
            rate_limit_store.pop(key, None)
    
    async def check_rate_limit(self, request: Request, api_key: str = None) -> bool:
        """Check if request is within rate limits."""
        current_time = time.time()
        client_ip = request.client.host if request.client else "unknown"
        
        # Cleanup old entries periodically
        if len(rate_limit_store) > 10000:
            self._cleanup_old_entries()
        
        # Check global rate limit
        global_key = self._get_rate_limit_key("global", "global")
        if global_key not in rate_limit_store:
            rate_limit_store[global_key] = {"count": 0, "reset_time": current_time + self.window_size}
        
        if rate_limit_store[global_key]["count"] >= self.limits["global_per_minute"]:
            return False
        
        # Check per-IP rate limit
        ip_key = self._get_rate_limit_key(client_ip, "ip")
        if ip_key not in rate_limit_store:
            rate_limit_store[ip_key] = {"count": 0, "reset_time": current_time + self.window_size}
        
        if rate_limit_store[ip_key]["count"] >= self.limits["per_ip_per_minute"]:
            return False
        
        # Check per-API-key rate limit
        if api_key:
            api_key_key = self._get_rate_limit_key(api_key, "api_key")
            if api_key_key not in rate_limit_store:
                rate_limit_store[api_key_key] = {"count": 0, "reset_time": current_time + self.window_size}
            
            if rate_limit_store[api_key_key]["count"] >= self.limits["per_api_key_per_minute"]:
                return False
        
        # Increment counters
        rate_limit_store[global_key]["count"] += 1
        rate_limit_store[ip_key]["count"] += 1
        if api_key:
            rate_limit_store[api_key_key]["count"] += 1
        
        return True
    
    def get_rate_limit_headers(self, request: Request, api_key: str = None) -> Dict[str, str]:
        """Get rate limit headers for response."""
        client_ip = request.client.host if request.client else "unknown"
        current_time = time.time()
        
        # Get current counts
        global_key = self._get_rate_limit_key("global", "global")
        ip_key = self._get_rate_limit_key(client_ip, "ip")
        
        global_count = rate_limit_store.get(global_key, {}).get("count", 0)
        ip_count = rate_limit_store.get(ip_key, {}).get("count", 0)
        
        headers = {
            "X-RateLimit-Limit-Global": str(self.limits["global_per_minute"]),
            "X-RateLimit-Remaining-Global": str(max(0, self.limits["global_per_minute"] - global_count)),
            "X-RateLimit-Limit-IP": str(self.limits["per_ip_per_minute"]),
            "X-RateLimit-Remaining-IP": str(max(0, self.limits["per_ip_per_minute"] - ip_count)),
            "X-RateLimit-Reset": str(int(current_time + self.window_size))
        }
        
        if api_key:
            api_key_key = self._get_rate_limit_key(api_key, "api_key")
            api_key_count = rate_limit_store.get(api_key_key, {}).get("count", 0)
            headers.update({
                "X-RateLimit-Limit-APIKey": str(self.limits["per_api_key_per_minute"]),
                "X-RateLimit-Remaining-APIKey": str(max(0, self.limits["per_api_key_per_minute"] - api_key_count))
            })
        
        return headers

# Initialize security components
if FASTAPI_AVAILABLE:
    security_manager = EnterpriseSecurityManager()
    rate_limiter = EnterpriseRateLimiter()
    security_scheme = HTTPBearer(auto_error=False)

async def get_api_key(credentials: HTTPAuthorizationCredentials = Depends(security_scheme)) -> str:
    """Extract and validate API key."""
    if not ENTERPRISE_CONFIG["security"]["api_key_required"]:
        return "demo_key"
    
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    api_key = credentials.credentials
    if not security_manager.validate_api_key(api_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    return api_key

async def validate_request_security(
    request: Request,
    api_key: str = Depends(get_api_key),
    x_signature: Optional[str] = Header(None, alias="X-Signature")
) -> Dict[str, Any]:
    """Comprehensive request security validation."""
    client_ip = request.client.host if request.client else "unknown"
    
    # Check IP allowlist
    if not security_manager.is_ip_allowed(client_ip):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="IP address not allowed"
        )
    
    # Check rate limits
    if ENTERPRISE_CONFIG["security"]["rate_limiting"]:
        if not await rate_limiter.check_rate_limit(request, api_key):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded",
                headers=rate_limiter.get_rate_limit_headers(request, api_key)
            )
    
    # Validate request signature
    if ENTERPRISE_CONFIG["security"]["request_signing"] and x_signature:
        if not security_manager.validate_request_signature(request, x_signature):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid request signature"
            )
    
    return {
        "api_key": api_key,
        "client_ip": client_ip,
        "request_id": str(uuid.uuid4()),
        "timestamp": time.time()
    }

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    global app_config, logger
    
    startup_start = time.time()
    
    try:
        # Initialize logging
        if CORE_SYSTEMS_AVAILABLE:
            logger = setup_logging()
            logger.info("Enterprise API startup initiated", LogCategory.STARTUP)
        
        # Load configuration
        if CORE_SYSTEMS_AVAILABLE:
            app_config = init_config()
            if logger:
                logger.info("Configuration loaded", LogCategory.STARTUP)
        
        startup_time = time.time() - startup_start
        if logger:
            logger.info(f"Enterprise API startup completed in {startup_time:.3f}s", LogCategory.STARTUP)
        
        yield
        
    except Exception as e:
        if logger:
            logger.error(f"Startup failed: {e}", LogCategory.STARTUP)
        raise
    
    finally:
        if logger:
            logger.info("Enterprise API shutdown completed", LogCategory.STARTUP)
            logger.flush()

# Create FastAPI application
if FASTAPI_AVAILABLE:
    app = FastAPI(
        title="PlexiChat Enterprise API",
        description="Production-ready enterprise chat API with advanced security and performance",
        version="1.0.0",
        lifespan=lifespan,
        docs_url=None,  # Disable docs in production
        redoc_url=None,  # Disable redoc in production
        openapi_url=None  # Disable OpenAPI schema in production
    )
    
    # Add security middleware
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["*"]  # Configure appropriately for production
    )
    
    # Add compression middleware
    if ENTERPRISE_CONFIG["performance"]["compression"]:
        app.add_middleware(GZipMiddleware, minimum_size=1000)
    
    # Add CORS middleware with strict settings
    if ENTERPRISE_CONFIG["security"]["cors_strict"]:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=[],  # No origins allowed by default
            allow_credentials=False,
            allow_methods=["GET", "POST"],
            allow_headers=["Authorization", "Content-Type", "X-Signature", "X-Timestamp", "X-Nonce"],
        )
else:
    app = None
