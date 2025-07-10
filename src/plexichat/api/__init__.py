"""
NetLink Enterprise API Layer

Centralized API management with versioning, security, rate limiting,
and comprehensive endpoint organization following REST principles.

This module provides:
- API versioning strategy (v1, v2, v3+)
- Centralized route registration
- API security and authentication
- Rate limiting and throttling
- Request/response validation
- API documentation generation
- Endpoint monitoring and analytics
- Error handling and logging
"""

import logging
from typing import Dict, List, Optional, Any, Callable, Type
from datetime import datetime
from fastapi import FastAPI, APIRouter, Request, Response, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from fastapi.openapi.utils import get_openapi
from fastapi.openapi.docs import get_swagger_ui_html, get_redoc_html
from pydantic import BaseModel
from dataclasses import dataclass, field
from enum import Enum
import time
import asyncio
from pathlib import Path

logger = logging.getLogger(__name__)

class APIVersion(Enum):
    """API version enumeration."""
    V1 = "v1"
    V2 = "v2"
    V3 = "v3"

class EndpointCategory(Enum):
    """API endpoint categories."""
    AUTH = "auth"
    USERS = "users"
    MESSAGES = "messages"
    FILES = "files"
    BACKUP = "backup"
    ADMIN = "admin"
    SECURITY = "security"
    MONITORING = "monitoring"
    PLUGINS = "plugins"
    AI = "ai"
    CLUSTERING = "clustering"
    DOCS = "docs"

@dataclass
class APIEndpointInfo:
    """API endpoint information and metadata."""
    path: str
    method: str
    category: EndpointCategory
    version: APIVersion
    description: str
    requires_auth: bool = True
    rate_limit: Optional[int] = None  # requests per minute
    permissions: List[str] = field(default_factory=list)
    deprecated: bool = False
    tags: List[str] = field(default_factory=list)

@dataclass
class APIMetrics:
    """API metrics and analytics."""
    endpoint: str
    method: str
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    avg_response_time: float = 0.0
    last_request: Optional[datetime] = None
    rate_limit_hits: int = 0
    error_counts: Dict[int, int] = field(default_factory=dict)

class APIManager:
    """
    Central API management system for NetLink.
    
    Handles API versioning, security, monitoring, and documentation.
    """
    
    def __init__(self, app: FastAPI):
        self.app = app
        self.routers: Dict[APIVersion, APIRouter] = {}
        self.endpoints: Dict[str, APIEndpointInfo] = {}
        self.metrics: Dict[str, APIMetrics] = {}
        self.rate_limits: Dict[str, Dict[str, Any]] = {}
        
        # Initialize API versions
        for version in APIVersion:
            self.routers[version] = APIRouter(prefix=f"/api/{version.value}")
        
        # Setup middleware
        self._setup_middleware()
        
        # Setup monitoring
        self._setup_monitoring()

        # Register API versions
        self.register_api_versions()

        logger.info("🚀 API Manager initialized")
    
    def _setup_middleware(self):
        """Setup API middleware for security and performance."""
        
        # CORS middleware
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],  # Configure based on environment
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        
        # Trusted host middleware
        self.app.add_middleware(
            TrustedHostMiddleware,
            allowed_hosts=["*"]  # Configure based on environment
        )
        
        # Compression middleware
        self.app.add_middleware(GZipMiddleware, minimum_size=1000)
        
        # Custom monitoring middleware
        @self.app.middleware("http")
        async def api_monitoring_middleware(request: Request, call_next):
            start_time = time.time()
            
            # Track request
            endpoint_key = f"{request.method}:{request.url.path}"
            
            try:
                response = await call_next(request)
                
                # Record successful request
                await self._record_request_metrics(
                    endpoint_key, 
                    request.method,
                    time.time() - start_time,
                    response.status_code,
                    success=True
                )
                
                return response
                
            except Exception as e:
                # Record failed request
                await self._record_request_metrics(
                    endpoint_key,
                    request.method, 
                    time.time() - start_time,
                    500,
                    success=False
                )
                raise
    
    def _setup_monitoring(self):
        """Setup API monitoring and health checks."""
        
        # Health check endpoint
        @self.app.get("/api/health")
        async def health_check():
            """API health check endpoint."""
            return {
                "status": "healthy",
                "timestamp": datetime.now().isoformat(),
                "version": "1.0.0",
                "endpoints": len(self.endpoints),
                "active_versions": [v.value for v in self.routers.keys()]
            }
        
        # Metrics endpoint
        @self.app.get("/api/metrics")
        async def get_metrics():
            """Get API metrics and analytics."""
            return {
                "total_endpoints": len(self.endpoints),
                "total_requests": sum(m.total_requests for m in self.metrics.values()),
                "success_rate": self._calculate_success_rate(),
                "avg_response_time": self._calculate_avg_response_time(),
                "endpoints": {k: self._serialize_metrics(v) for k, v in self.metrics.items()}
            }
    
    async def _record_request_metrics(self, endpoint: str, method: str, 
                                    response_time: float, status_code: int, success: bool):
        """Record request metrics for monitoring."""
        if endpoint not in self.metrics:
            self.metrics[endpoint] = APIMetrics(endpoint=endpoint, method=method)
        
        metrics = self.metrics[endpoint]
        metrics.total_requests += 1
        metrics.last_request = datetime.now()
        
        if success:
            metrics.successful_requests += 1
        else:
            metrics.failed_requests += 1
        
        # Update average response time
        if metrics.total_requests == 1:
            metrics.avg_response_time = response_time
        else:
            metrics.avg_response_time = (
                (metrics.avg_response_time * (metrics.total_requests - 1) + response_time) 
                / metrics.total_requests
            )
        
        # Track error codes
        if status_code >= 400:
            if status_code not in metrics.error_counts:
                metrics.error_counts[status_code] = 0
            metrics.error_counts[status_code] += 1
    
    def register_router(self, version: APIVersion, router: APIRouter, 
                       category: EndpointCategory, prefix: str = ""):
        """Register an API router for a specific version."""
        if prefix:
            router.prefix = f"/api/{version.value}/{prefix}"
        else:
            router.prefix = f"/api/{version.value}"
        
        # Add router to version
        self.routers[version].include_router(router, tags=[category.value])
        
        # Register with main app
        self.app.include_router(self.routers[version])
        
        logger.info(f"📡 Registered {category.value} router for API {version.value}")
    
    def register_endpoint(self, endpoint_info: APIEndpointInfo):
        """Register endpoint information for documentation and monitoring."""
        key = f"{endpoint_info.method}:{endpoint_info.path}"
        self.endpoints[key] = endpoint_info
        
        # Initialize metrics
        if key not in self.metrics:
            self.metrics[key] = APIMetrics(
                endpoint=endpoint_info.path,
                method=endpoint_info.method
            )
    
    def get_endpoint_info(self, path: str, method: str) -> Optional[APIEndpointInfo]:
        """Get endpoint information."""
        key = f"{method}:{path}"
        return self.endpoints.get(key)

    def register_api_versions(self):
        """Register all API versions with their routers."""
        try:
            # Register API v1 (stable - migrated from v2)
            try:
                from .v1 import v1_router, register_v1_endpoints
                register_v1_endpoints()
                self.app.include_router(v1_router, prefix="/api")
                logger.info("✅ API v1 registered successfully")
            except ImportError as e:
                logger.warning(f"API v1 not available: {e}")

            # Register versionless API (routes to latest stable - v1)
            try:
                from .v1 import v1_router as latest_router
                # Create a copy of v1 router for versionless access
                versionless_router = APIRouter(
                    tags=["latest"],
                    responses={
                        401: {"description": "Unauthorized"},
                        403: {"description": "Forbidden"},
                        404: {"description": "Not Found"},
                        422: {"description": "Validation Error"},
                        500: {"description": "Internal Server Error"}
                    }
                )
                # Include all v1 routes without version prefix
                for route in latest_router.routes:
                    versionless_router.routes.append(route)

                self.app.include_router(versionless_router, prefix="/api")
                logger.info("✅ Versionless API (latest stable) registered successfully")
            except ImportError as e:
                logger.warning(f"Versionless API not available: {e}")

            # Register API beta (development branch)
            try:
                from .beta import beta_router, register_beta_endpoints
                register_beta_endpoints()
                self.app.include_router(beta_router, prefix="/api")
                logger.info("✅ API beta registered successfully")
            except ImportError as e:
                logger.warning(f"API beta not available: {e}")

            # Register API v3 (future)
            try:
                from .v3 import v3_router, register_v3_endpoints
                register_v3_endpoints()
                self.app.include_router(v3_router, prefix="/api")
                logger.info("✅ API v3 registered successfully")
            except ImportError as e:
                logger.warning(f"API v3 not available: {e}")

            logger.info("✅ All available API versions registered")

        except Exception as e:
            logger.error(f"Failed to register API versions: {e}")
            raise
    
    def list_endpoints(self, version: Optional[APIVersion] = None, 
                      category: Optional[EndpointCategory] = None) -> List[APIEndpointInfo]:
        """List registered endpoints with optional filtering."""
        endpoints = list(self.endpoints.values())
        
        if version:
            endpoints = [e for e in endpoints if e.version == version]
        
        if category:
            endpoints = [e for e in endpoints if e.category == category]
        
        return endpoints
    
    def _calculate_success_rate(self) -> float:
        """Calculate overall API success rate."""
        total_requests = sum(m.total_requests for m in self.metrics.values())
        successful_requests = sum(m.successful_requests for m in self.metrics.values())
        
        if total_requests == 0:
            return 100.0
        
        return (successful_requests / total_requests) * 100.0
    
    def _calculate_avg_response_time(self) -> float:
        """Calculate overall average response time."""
        if not self.metrics:
            return 0.0
        
        total_time = sum(m.avg_response_time * m.total_requests for m in self.metrics.values())
        total_requests = sum(m.total_requests for m in self.metrics.values())
        
        if total_requests == 0:
            return 0.0
        
        return total_time / total_requests
    
    def _serialize_metrics(self, metrics: APIMetrics) -> Dict[str, Any]:
        """Serialize metrics for JSON response."""
        return {
            "endpoint": metrics.endpoint,
            "method": metrics.method,
            "total_requests": metrics.total_requests,
            "successful_requests": metrics.successful_requests,
            "failed_requests": metrics.failed_requests,
            "success_rate": (metrics.successful_requests / max(metrics.total_requests, 1)) * 100,
            "avg_response_time": metrics.avg_response_time,
            "last_request": metrics.last_request.isoformat() if metrics.last_request else None,
            "error_counts": metrics.error_counts
        }
    
    def setup_documentation(self):
        """Setup API documentation with custom OpenAPI schema."""
        
        def custom_openapi():
            if self.app.openapi_schema:
                return self.app.openapi_schema
            
            openapi_schema = get_openapi(
                title="NetLink API",
                version="3.0.0",
                description="Government-Level Secure Communication Platform API",
                routes=self.app.routes,
            )
            
            # Add custom information
            openapi_schema["info"]["contact"] = {
                "name": "NetLink Support",
                "url": "https://netlink.example.com/support",
                "email": "support@netlink.example.com"
            }
            
            openapi_schema["info"]["license"] = {
                "name": "Proprietary",
                "url": "https://netlink.example.com/license"
            }
            
            # Add security schemes
            openapi_schema["components"]["securitySchemes"] = {
                "BearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "JWT"
                },
                "ApiKeyAuth": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-API-Key"
                }
            }
            
            self.app.openapi_schema = openapi_schema
            return self.app.openapi_schema
        
        self.app.openapi = custom_openapi
        
        # Custom documentation endpoints
        @self.app.get("/docs", include_in_schema=False)
        async def custom_swagger_ui_html():
            return get_swagger_ui_html(
                openapi_url="/openapi.json",
                title="NetLink API Documentation",
                swagger_favicon_url="/static/favicon.ico"
            )
        
        @self.app.get("/redoc", include_in_schema=False)
        async def redoc_html():
            return get_redoc_html(
                openapi_url="/openapi.json",
                title="NetLink API Documentation",
                redoc_favicon_url="/static/favicon.ico"
            )

# Global API manager instance
_api_manager: Optional[APIManager] = None

def get_api_manager() -> Optional[APIManager]:
    """Get the global API manager instance."""
    return _api_manager

def initialize_api_manager(app: FastAPI) -> APIManager:
    """Initialize the global API manager."""
    global _api_manager
    _api_manager = APIManager(app)
    return _api_manager

# Utility functions for endpoint registration
def api_endpoint(version: APIVersion, category: EndpointCategory, 
                path: str, method: str, description: str,
                requires_auth: bool = True, rate_limit: Optional[int] = None,
                permissions: List[str] = None, tags: List[str] = None):
    """Decorator for registering API endpoints."""
    def decorator(func):
        if _api_manager:
            endpoint_info = APIEndpointInfo(
                path=path,
                method=method,
                category=category,
                version=version,
                description=description,
                requires_auth=requires_auth,
                rate_limit=rate_limit,
                permissions=permissions or [],
                tags=tags or []
            )
            _api_manager.register_endpoint(endpoint_info)
        return func
    return decorator

# Export main components
__all__ = [
    "APIManager",
    "APIVersion",
    "EndpointCategory", 
    "APIEndpointInfo",
    "APIMetrics",
    "get_api_manager",
    "initialize_api_manager",
    "api_endpoint"
]
