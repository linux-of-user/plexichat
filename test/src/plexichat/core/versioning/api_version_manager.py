# pyright: reportMissingImports=false
# pyright: reportGeneralTypeIssues=false
# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import json
import logging
from typing import Any, Dict, List, Optional


from ..beta.ai import ai_router
from ..beta.quantum import quantum_router
from ..v1.analytics import analytics_router
from ..v1.auth import auth_router, auth_router_stable
from ..v1.collaboration import collaboration_router
from ..v1.files import files_router, files_router_stable
from ..v1.messages import messages_router, messages_router_stable
from ..v1.updates import updates_router
from ..v1.users import users_router, users_router_stable


from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import JSONResponse

"""
PlexiChat API Version Manager
Handles API versioning, routing, and compatibility between different API versions.
"""

logger = logging.getLogger(__name__)


class APIVersionManager:
    """Manages API versions and routing."""

    def __init__(self):
        """Initialize the API version manager."""
        self.versions = {
            "stable": {
                "version": "r.1.0-1",
                "path": "/api",
                "description": "Stable production API",
                "deprecated": False,
                "sunset_date": None,
                "features": ["core", "messaging", "files", "users", "auth"],
            },
            "current": {
                "version": "a.1.1-1",
                "path": "/api/v1",
                "description": "Current development API with latest features",
                "deprecated": False,
                "sunset_date": None,
                "features": [
                    "core",
                    "messaging",
                    "files",
                    "users",
                    "auth",
                    "collaboration",
                    "updates",
                    "analytics",
                ],
            },
            "beta": {
                "version": "b.1.2-1",
                "path": "/api/beta",
                "description": "Beta API with experimental features",
                "deprecated": False,
                "sunset_date": None,
                "features": [
                    "core",
                    "messaging",
                    "files",
                    "users",
                    "auth",
                    "collaboration",
                    "updates",
                    "analytics",
                    "ai",
                    "quantum",
                ],
            },
        }

        # Feature compatibility matrix
        self.feature_compatibility = {
            "core": ["stable", "current", "beta"],
            "messaging": ["stable", "current", "beta"],
            "files": ["stable", "current", "beta"],
            "users": ["stable", "current", "beta"],
            "auth": ["stable", "current", "beta"],
            "collaboration": ["current", "beta"],
            "updates": ["current", "beta"],
            "analytics": ["current", "beta"],
            "ai": ["beta"],
            "quantum": ["beta"],
        }

        logger.info("API Version Manager initialized")

    def get_version_info(self, version_key: str) -> Optional[Dict[str, Any]]:
        """Get information about a specific API version."""
        return self.versions.get(version_key)

    def get_all_versions(self) -> Dict[str, Any]:
        """Get information about all API versions."""
        return {
            "versions": self.versions,
            "current_stable": "stable",
            "current_development": "current",
            "current_beta": "beta",
            "compatibility_matrix": self.feature_compatibility,
        }

    def is_feature_available(self, feature: str, version: str) -> bool:
        """Check if a feature is available in a specific version."""
        return version in self.feature_compatibility.get(feature, [])

    def get_version_from_path(self, path: str) -> str:
        """Determine API version from request path."""
        if path.startswith("/api/beta"):
            return "beta"
        elif path.startswith("/api/v1"):
            return "current"
        elif path.startswith("/api"):
            return "stable"
        else:
            return "current"  # Default

    def create_version_router(self) -> APIRouter:
        """Create router for version management endpoints."""
        router = APIRouter(prefix="/version", tags=["API Version"])

        @router.get("/info")
        async def get_version_info():
            """Get API version information."""
            return self.get_all_versions()

        @router.get("/features")
        async def get_features(version: str = "current"):
            """Get available features for a version."""
            version_info = self.get_version_info(version)
            if not version_info:
                raise HTTPException()
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Version '{version}' not found",
                )

            return {
                "version": version,
                "features": version_info["features"],
                "description": version_info["description"],
            }

        @router.get("/compatibility/{feature}")
        async def check_feature_compatibility(feature: str):
            """Check which versions support a specific feature."""
            if feature not in self.feature_compatibility:
                raise HTTPException()
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Feature '{feature}' not found",
                )

            return {
                "feature": feature,
                "supported_versions": self.feature_compatibility[feature],
                "latest_version": max()
                    self.feature_compatibility[feature],
                    key=lambda v: ["stable", "current", "beta"].index(v),
                ),
            }

        return router


class APIVersionMiddleware:
    """Middleware for API version handling."""

    def __init__(self, version_manager: APIVersionManager):
        self.version_manager = version_manager

    async def __call__(self, request: Request, call_next):
        """Process request with version handling."""
        # Determine API version
        api_version = self.version_manager.get_version_from_path(str(request.url.path))

        # Add version info to request state
        request.state.api_version = api_version
        request.state.version_info = self.version_manager.get_version_info(api_version)

        # Add version headers
        response = await call_next(request)

        if hasattr(response, "headers"):
            response.headers["X-API-Version"] = api_version
            response.headers["X-API-Version-Info"] = json.dumps()
                request.state.version_info
            )

        return response


def create_version_compatibility_decorator(required_features: List[str]):
    """Create decorator to check feature compatibility."""

    def decorator(func):
        async def wrapper(request: Request, *args, **kwargs):
            api_version = getattr(request.state, "api_version", "current")
            version_manager = api_version_manager

            # Check if all required features are available
            unavailable_features = []
            for feature in required_features:
                if not version_manager.is_feature_available(feature, api_version):
                    unavailable_features.append(feature)

            if unavailable_features:
                return JSONResponse()
                    status_code=status.HTTP_501_NOT_IMPLEMENTED,
                    content={
                        "error": "Feature not available in this API version",
                        "api_version": api_version,
                        "unavailable_features": unavailable_features,
                        "available_in": {
                            feature: version_manager.feature_compatibility.get()
                                feature, []
                            )
                            for feature in unavailable_features
                        },
                    },
                )

            return await func(request, *args, **kwargs)

        return wrapper

    return decorator


# API Router Factory
class APIRouterFactory:
    """Factory for creating version-specific API routers."""

    def __init__(self, version_manager: APIVersionManager):
        self.version_manager = version_manager

    def create_stable_router(self) -> APIRouter:
        """Create router for stable API (/api)."""
        router = APIRouter(prefix="/api", tags=["Stable API"])

        # Add stable endpoints here
        router.include_router(auth_router_stable, prefix="/auth")
        router.include_router(messages_router_stable, prefix="/messages")
        router.include_router(files_router_stable, prefix="/files")
        router.include_router(users_router_stable, prefix="/users")

        return router

    def create_current_router(self) -> APIRouter:
        """Create router for current API (/api/v1)."""
        router = APIRouter(prefix="/api/v1", tags=["Current API"])

        # Add current endpoints here
        router.include_router(auth_router, prefix="/auth")
        router.include_router(messages_router, prefix="/messages")
        router.include_router(files_router, prefix="/files")
        router.include_router(users_router, prefix="/users")
        router.include_router(collaboration_router, prefix="/collaboration")
        router.include_router(updates_router, prefix="/updates")
        router.include_router(analytics_router, prefix="/analytics")

        return router

    def create_beta_router(self) -> APIRouter:
        """Create router for beta API (/api/beta)."""
        router = APIRouter(prefix="/api/beta", tags=["Beta API"])

        # Add beta endpoints here (includes all current + experimental)
        router.include_router(auth_router, prefix="/auth")
        router.include_router(messages_router, prefix="/messages")
        router.include_router(files_router, prefix="/files")
        router.include_router(users_router, prefix="/users")
        router.include_router(collaboration_router, prefix="/collaboration")
        router.include_router(updates_router, prefix="/updates")
        router.include_router(analytics_router, prefix="/analytics")
        router.include_router(ai_router, prefix="/ai")
        router.include_router(quantum_router, prefix="/quantum")

        return router


# Global instances
api_version_manager = APIVersionManager()
api_router_factory = APIRouterFactory(api_version_manager)
