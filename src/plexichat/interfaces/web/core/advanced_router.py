# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
# pyright: reportMissingImports=false
# pyright: reportUndefinedVariable=false
# pyright: reportOptionalMemberAccess=false
# pyright: reportOptionalCall=false
# pyright: reportPossiblyUnboundVariable=false
# pyright: reportIndexIssue=false
# pyright: reportGeneralTypeIssues=false
import logging
from datetime import datetime
from typing import Any, Dict, FastAPI, HTTPException, List, Optional, Request, status


from plexichat.interfaces.web.core.config_manager import get_webui_config
from plexichat.core.testing import get_self_test_manager

# Use unified authentication system via FastAPI adapter
from plexichat.core.auth.fastapi_adapter import (
    get_current_user,
    get_optional_user,
    require_admin,
    get_auth_adapter,
    rate_limit
)

import uvicorn
from fastapi import Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

# Import the new CLI router
from plexichat.interfaces.web.routers.cli import router as cli_router

logger = logging.getLogger(__name__)

class EnhancedWebUIRouter:
    """Enhanced WebUI router with advanced features."""
    def __init__(self):
        self.config = get_webui_config()
        self.auth_adapter = get_auth_adapter()
        self.self_test_manager = get_self_test_manager()

        # Create FastAPI app
        self.app = FastAPI(
            title="PlexiChat WebUI",
            description="Enhanced PlexiChat Web User Interface",
            version="2.0.0",
            docs_url="/docs" if self.config.is_feature_enabled("api_docs") else None,
            redoc_url="/redoc" if self.config.is_feature_enabled("api_docs") else None
        )

        # Setup middleware
        self._setup_middleware()

        # Setup routes
        self._setup_routes()

        # Setup static files and templates
        self._setup_static_files()

        logger.info("Enhanced WebUI Router initialized")

    def _setup_middleware(self):
        """Setup middleware for the WebUI."""
        # CORS middleware
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],  # Configure appropriately for production
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

        # Custom middleware for security and logging
        @self.app.middleware("http")
        async def security_middleware(request: Request, call_next):
            start_time = datetime.utcnow()
            # Security headers
            response = await call_next(request)

            # Add security headers
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["X-XSS-Protection"] = "1; mode=block"
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
            response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"

            # Add custom headers
            response.headers["X-WebUI-Version"] = "2.0.0"
            response.headers["X-Process-Time"] = str((datetime.utcnow() - start_time).total_seconds())

            return response

    def _setup_routes(self):
        """Setup WebUI routes."""
        # Authentication routes
        self._setup_auth_routes()

        # Dashboard routes
        self._setup_dashboard_routes()

        # Admin routes
        self._setup_admin_routes()

        # Self-test routes
        self._setup_self_test_routes()

        # Feature management routes
        self._setup_feature_routes()

        # API proxy routes
        self._setup_api_routes()

        # Register CLI router
        self.app.include_router(cli_router)

    def _setup_static_files(self):
        """Setup static files and templates."""
        # Mount static files
        self.app.mount("/static", StaticFiles(directory="web/static"), name="static")

        # Setup templates
        self.templates = Jinja2Templates(directory="web/templates")

    def _setup_auth_routes(self):
        """Setup authentication routes."""

        @self.app.post("/auth/login")
        async def login(request: Request):
            """Enhanced login using unified authentication system."""
            try:
                data = await request.json()
                username = data.get("username")
                password = data.get("password")

                if not username or not password:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Username and password required"
                    )

                # Use unified authentication manager for login
                auth_manager = self.auth_adapter.auth_manager
                login_result = await auth_manager.authenticate_user(username, password)

                if not login_result.success:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail=login_result.message or "Authentication failed"
                    )

                # Create access token using unified auth system
                access_token = await self.auth_adapter.create_access_token(
                    login_result.user_id,
                    login_result.permissions
                )

                response_data = {
                    "access_token": access_token,
                    "token_type": "bearer",
                    "user_id": login_result.user_id,
                    "permissions": list(login_result.permissions),
                    "mfa_required": login_result.mfa_required,
                    "mfa_completed": login_result.mfa_completed
                }

                return JSONResponse(content=response_data)

            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"Login error: {e}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Login failed"
                )

        @self.app.post("/auth/logout")
        async def logout(current_user: Dict[str, Any] = Depends(get_current_user)):
            """Logout using unified authentication system."""
            try:
                # Invalidate user sessions using unified auth system
                user_id = current_user.get("user_id")
                if user_id:
                    await self.auth_adapter.invalidate_user_sessions(user_id)

                return JSONResponse(content={"success": True, "message": "Logged out successfully"})

            except Exception as e:
                logger.error(f"Logout error: {e}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Logout failed"
                )

    def _setup_dashboard_routes(self):
        """Setup dashboard routes."""

        @self.app.get("/", response_class=HTMLResponse)
        async def dashboard(request: Request, current_user: Optional[Dict[str, Any]] = Depends(get_optional_user)):
            """Main dashboard."""
            if not self.config.is_feature_enabled("dashboard"):
                raise HTTPException(status_code=404, detail="Dashboard disabled")

            return self.templates.TemplateResponse("dashboard.html", {
                "request": request,
                "features": self._get_enabled_features(),
                "system_status": await self._get_system_status(),
                "user": current_user
            })

        @self.app.get("/api/dashboard/status")
        @rate_limit("dashboard_status", 60, 60)  # 60 requests per minute
        async def dashboard_status(current_user: Dict[str, Any] = Depends(get_current_user)):
            """Get dashboard status."""
            return JSONResponse(content={
                "user": current_user.get("user_id"),
                "permissions": list(current_user.get("permissions", [])),
                "features": self._get_enabled_features(),
                "system_status": await self._get_system_status(),
                "timestamp": datetime.utcnow().isoformat()
            })

    def _setup_admin_routes(self):
        """Setup admin routes."""

        @self.app.get("/admin", response_class=HTMLResponse)
        async def admin_panel(request: Request, admin_user: Dict[str, Any] = Depends(require_admin)):
            """Admin panel."""
            if not self.config.is_feature_enabled("admin_panel", "admin"):
                raise HTTPException(status_code=403, detail="Admin panel disabled")

            return self.templates.TemplateResponse("admin.html", {
                "request": request,
                "admin_features": self._get_admin_features(),
                "system_config": self._get_system_config(),
                "user": admin_user
            })

        @self.app.get("/api/admin/config")
        @rate_limit("admin_config_get", 30, 60)  # 30 requests per minute
        async def get_admin_config(admin_user: Dict[str, Any] = Depends(require_admin)):
            """Get admin configuration."""
            if not self.config.is_feature_enabled("system_configuration", "admin"):
                raise HTTPException(status_code=403, detail="System configuration disabled")

            return JSONResponse(content=self._get_system_config())

        @self.app.post("/api/admin/config")
        @rate_limit("admin_config_update", 10, 60)  # 10 requests per minute
        async def update_admin_config(request: Request, admin_user: Dict[str, Any] = Depends(require_admin)):
            """Update admin configuration."""
            if not self.config.is_feature_enabled("system_configuration", "admin"):
                raise HTTPException(status_code=403, detail="System configuration disabled")

            try:
                data = await request.json()

                # Update configuration
                if "ports" in data:
                    self.config.update_port_config(**data["ports"])

                if "mfa" in data:
                    self.config.update_mfa_config(**data["mfa"])

                if "features" in data:
                    for feature, enabled in data["features"].items():
                        self.config.toggle_feature(feature, enabled)

                return JSONResponse(content={"success": True, "message": "Configuration updated"})

            except Exception as e:
                logger.error(f"Config update error: {e}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Configuration update failed"
                )

    def _setup_self_test_routes(self):
        """Setup self-test routes."""

        @self.app.get("/admin/tests", response_class=HTMLResponse)
        async def self_tests_page(request: Request, admin_user: Dict[str, Any] = Depends(require_admin)):
            """Self-tests page."""
            if not self.config.is_feature_enabled("system_monitoring", "admin"):
                raise HTTPException(status_code=403, detail="System monitoring disabled")

            return self.templates.TemplateResponse("self_tests.html", {
                "request": request,
                "test_categories": self.self_test_manager.test_registry.keys(),
                "latest_results": self.self_test_manager.get_latest_test_results(),
                "user": admin_user
            })

        @self.app.post("/api/admin/tests/run")
        @rate_limit("admin_tests_run", 5, 300)  # 5 requests per 5 minutes
        async def run_self_tests(request: Request, admin_user: Dict[str, Any] = Depends(require_admin)):
            """Run self-tests."""
            if not self.config.is_feature_enabled("system_monitoring", "admin"):
                raise HTTPException(status_code=403, detail="System monitoring disabled")

            try:
                data = await request.json()
                category = data.get("category", "all")

                if category == "all":
                    results = await self.self_test_manager.run_all_tests()
                else:
                    results = await self.self_test_manager.run_category_tests(category)

                return JSONResponse(content={
                    "suite_id": results.suite_id,
                    "status": "completed",
                    "summary": {
                        "total": results.total_tests,
                        "passed": results.passed_tests,
                        "failed": results.failed_tests,
                        "warnings": results.warning_tests
                    }
                })

            except Exception as e:
                logger.error(f"Self-test error: {e}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Self-test execution failed"
                )

        @self.app.get("/api/admin/tests/results/{suite_id}")
        async def get_test_results(suite_id: str, admin_user: Dict[str, Any] = Depends(require_admin)):
            """Get test results."""
            results = self.self_test_manager.get_test_results(suite_id)
            if not results:
                raise HTTPException(status_code=404, detail="Test results not found")

            return JSONResponse(content=results.__dict__)

    def _setup_feature_routes(self):
        """Setup feature management routes."""

        @self.app.get("/api/admin/features")
        async def get_features(admin_user: Dict[str, Any] = Depends(require_admin)):
            """Get feature configuration."""
            return JSONResponse(content={
                "enabled_features": self.config.feature_toggle_config.enabled_features,
                "disabled_features": self.config.feature_toggle_config.disabled_features,
                "beta_features": self.config.feature_toggle_config.beta_features,
                "admin_only_features": self.config.feature_toggle_config.admin_only_features
            })

        @self.app.post("/api/admin/features/toggle")
        @rate_limit("admin_feature_toggle", 20, 60)  # 20 requests per minute
        async def toggle_feature(request: Request, admin_user: Dict[str, Any] = Depends(require_admin)):
            """Toggle a feature."""
            if not self.config.is_feature_enabled("system_configuration", "admin"):
                raise HTTPException(status_code=403, detail="System configuration disabled")

            try:
                data = await request.json()
                feature = data.get("feature")
                enabled = data.get("enabled", True)

                self.config.toggle_feature(feature, enabled)

                return JSONResponse(content={"success": True, "feature": feature, "enabled": enabled})

            except Exception as e:
                logger.error(f"Feature toggle error: {e}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Feature toggle failed"
                )

    def _setup_api_routes(self):
        """Setup API proxy routes."""

        @self.app.get("/api/proxy/{path:path}")
        @rate_limit("api_proxy", 100, 60)  # 100 requests per minute
        async def api_proxy(path: str, request: Request, current_user: Dict[str, Any] = Depends(get_current_user)):
            """Proxy API requests."""
            # Proxy to internal API
            # This is a simplified implementation
            return JSONResponse(content={
                "message": f"API proxy for {path}", 
                "user": current_user.get("user_id"),
                "permissions": list(current_user.get("permissions", []))
            })

    def _get_enabled_features(self) -> List[str]:
        """Get list of enabled features."""
        return self.config.feature_toggle_config.enabled_features

    def _get_admin_features(self) -> List[str]:
        """Get list of admin features."""
        return self.config.feature_toggle_config.admin_only_features

    async def _get_system_status(self) -> Dict[str, Any]:
        """Get system status."""
        return {
            "auth_system": "unified",
            "auth_manager_active": self.auth_adapter.auth_manager is not None,
            "self_tests_enabled": self.config.is_self_test_enabled(),
            "timestamp": datetime.utcnow().isoformat()
        }

    def _get_system_config(self) -> Dict[str, Any]:
        """Get system configuration."""
        return {
            "ports": {
                "primary_port": self.config.port_config.primary_port,
                "admin_port": self.config.port_config.admin_port,
                "ssl_enabled": self.config.port_config.ssl_enabled
            },
            "mfa": {
                "enabled": self.config.mfa_config.enabled,
                "methods": self.config.mfa_config.methods,
                "require_mfa_for_admin": self.config.mfa_config.require_mfa_for_admin
            },
            "features": {
                "enabled": self.config.feature_toggle_config.enabled_features,
                "disabled": self.config.feature_toggle_config.disabled_features,
                "beta": self.config.feature_toggle_config.beta_features
            }
        }

    async def start_server(self):
        """Start the WebUI server."""
        config = uvicorn.Config(
            app=self.app,
            host="0.0.0.0",
            port=self.config.port_config.primary_port,
            ssl_keyfile=self.config.port_config.ssl_key_path if self.config.port_config.ssl_enabled else None,
            ssl_certfile=self.config.port_config.ssl_cert_path if self.config.port_config.ssl_enabled else None
        )

        server = uvicorn.Server(config)

        # Schedule self-tests
        await self.self_test_manager.schedule_tests()

        logger.info(f"Starting WebUI server on port {self.config.port_config.primary_port}")
        await server.serve()

# Global enhanced router instance
enhanced_webui_router = EnhancedWebUIRouter()

def get_enhanced_webui_router() -> EnhancedWebUIRouter:
    """Get the global enhanced WebUI router."""
    return enhanced_webui_router
