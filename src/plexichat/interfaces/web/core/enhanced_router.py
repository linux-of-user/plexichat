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


from .auth_storage import get_auth_storage
from .config_manager import get_webui_config
from .mfa_manager import get_mfa_manager
from .self_test_manager import get_self_test_manager


import uvicorn
from fastapi import Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

# Import the new CLI router
from src.plexichat.interfaces.web.routers.cli import router as cli_router

"""
import time
PlexiChat Enhanced WebUI Router

Enhanced WebUI routing system with configurable ports, MFA authentication,
distributed storage, self-tests, and feature toggles.
"""

logger = logging.getLogger(__name__)

# Security scheme
security = HTTPBearer()

class EnhancedWebUIRouter:
    """Enhanced WebUI router with advanced features."""

    def __init__(self):
        self.config = get_webui_config()
        self.mfa_manager = get_mfa_manager()
        self.auth_storage = get_auth_storage()
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
            """Enhanced login with MFA support."""
            try:
                data = await request.json()
                username = data.get("username")
                password = data.get("password")
                # mfa_code = data.get("mfa_code")

                if not username or not password:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Username and password required"
                    )

                # Get user from auth storage
                # This is a simplified implementation
                # In production, implement proper password hashing and verification

                # Create MFA session
                session = self.mfa_manager.create_mfa_session(
                    user_id=username,  # Simplified - use actual user ID
                    username=username,
                    ip_address=request.client.host,
                    user_agent=request.headers.get("user-agent", ""),
                    user_role="user"  # Determine actual role
                )

                response_data = {
                    "session_id": session.session_id,
                    "mfa_required": session.mfa_required,
                    "mfa_completed": session.mfa_completed
                }

                if session.mfa_required and not session.mfa_completed:
                    response_data["mfa_methods"] = self.mfa_manager.get_available_mfa_methods()

                return JSONResponse(content=response_data)

            except Exception as e:
                logger.error(f"Login error: {e}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Login failed"
                )

        @self.app.post("/auth/mfa/verify")
        async def verify_mfa(request: Request):
            """Verify MFA code."""
            try:
                data = await request.json()
                session_id = data.get("session_id")
                mfa_code = data.get("mfa_code")
                device_id = data.get("device_id")

                if not session_id or not mfa_code:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Session ID and MFA code required"
                    )

                session = self.mfa_manager.get_session(session_id)
                if not session:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Invalid session"
                    )

                # Verify MFA code
                if device_id:
                    verified = self.mfa_manager.verify_totp_code(session.user_id, device_id, mfa_code)
                else:
                    verified = self.mfa_manager.verify_backup_code(session.user_id, mfa_code)

                if verified:
                    self.mfa_manager.complete_mfa_for_session(session_id, "totp")
                    return JSONResponse(content={"success": True, "mfa_completed": True})
                else:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Invalid MFA code"
                    )

            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"MFA verification error: {e}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="MFA verification failed"
                )

        @self.app.post("/auth/mfa/setup")
        async def setup_mfa(request: Request, credentials: HTTPAuthorizationCredentials = Depends(security)):
            """Setup MFA for user."""
            try:
                # Verify session
                session = self._verify_session(credentials.credentials)

                data = await request.json()
                device_name = data.get("device_name", "Default Device")

                setup_data = self.mfa_manager.setup_totp_device(
                    session.user_id,
                    session.username,
                    device_name
                )

                return JSONResponse(content=setup_data)

            except Exception as e:
                logger.error(f"MFA setup error: {e}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="MFA setup failed"
                )

    def _setup_dashboard_routes(self):
        """Setup dashboard routes."""

        @self.app.get("/", response_class=HTMLResponse)
        async def dashboard(request: Request):
            """Main dashboard."""
            if not self.config.is_feature_enabled("dashboard"):
                raise HTTPException(status_code=404, detail="Dashboard disabled")

            return self.templates.TemplateResponse("dashboard.html", {
                "request": request,
                "features": self._get_enabled_features(),
                "system_status": await self._get_system_status()
            })

        @self.app.get("/api/dashboard/status")
        async def dashboard_status(credentials: HTTPAuthorizationCredentials = Depends(security)):
            """Get dashboard status."""
            session = self._verify_session(credentials.credentials)

            return JSONResponse(content={
                "user": session.username,
                "features": self._get_enabled_features(),
                "system_status": await self._get_system_status(),
                "timestamp": datetime.utcnow().isoformat()
            })

    def _setup_admin_routes(self):
        """Setup admin routes."""

        @self.app.get("/admin", response_class=HTMLResponse)
        async def admin_panel(request: Request, credentials: HTTPAuthorizationCredentials = Depends(security)):
            """Admin panel."""
            self._verify_session(credentials.credentials)

            if not self.config.is_feature_enabled("admin_panel", "admin"):
                raise HTTPException(status_code=403, detail="Admin access required")

            return self.templates.TemplateResponse("admin.html", {
                "request": request,
                "admin_features": self._get_admin_features(),
                "system_config": self._get_system_config()
            })

        @self.app.get("/api/admin/config")
        async def get_admin_config(credentials: HTTPAuthorizationCredentials = Depends(security)):
            """Get admin configuration."""
            self._verify_session(credentials.credentials)

            if not self.config.is_feature_enabled("system_configuration", "admin"):
                raise HTTPException(status_code=403, detail="Admin access required")

            return JSONResponse(content=self._get_system_config())

        @self.app.post("/api/admin/config")
        async def update_admin_config(request: Request, credentials: HTTPAuthorizationCredentials = Depends(security)):
            """Update admin configuration."""
            self._verify_session(credentials.credentials)

            if not self.config.is_feature_enabled("system_configuration", "admin"):
                raise HTTPException(status_code=403, detail="Admin access required")

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
        async def self_tests_page(request: Request, credentials: HTTPAuthorizationCredentials = Depends(security)):
            """Self-tests page."""
            self._verify_session(credentials.credentials)

            if not self.config.is_feature_enabled("system_monitoring", "admin"):
                raise HTTPException(status_code=403, detail="Admin access required")

            return self.templates.TemplateResponse("self_tests.html", {
                "request": request,
                "test_categories": self.self_test_manager.test_registry.keys(),
                "latest_results": self.self_test_manager.get_latest_test_results()
            })

        @self.app.post("/api/admin/tests/run")
        async def run_self_tests(request: Request, credentials: HTTPAuthorizationCredentials = Depends(security)):
            """Run self-tests."""
            self._verify_session(credentials.credentials)

            if not self.config.is_feature_enabled("system_monitoring", "admin"):
                raise HTTPException(status_code=403, detail="Admin access required")

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
        async def get_test_results(suite_id: str, credentials: HTTPAuthorizationCredentials = Depends(security)):
            """Get test results."""
            self._verify_session(credentials.credentials)

            results = self.self_test_manager.get_test_results(suite_id)
            if not results:
                raise HTTPException(status_code=404, detail="Test results not found")

            return JSONResponse(content=results.__dict__)

    def _setup_feature_routes(self):
        """Setup feature management routes."""

        @self.app.get("/api/admin/features")
        async def get_features(credentials: HTTPAuthorizationCredentials = Depends(security)):
            """Get feature configuration."""
            self._verify_session(credentials.credentials)

            return JSONResponse(content={
                "enabled_features": self.config.feature_toggle_config.enabled_features,
                "disabled_features": self.config.feature_toggle_config.disabled_features,
                "beta_features": self.config.feature_toggle_config.beta_features,
                "admin_only_features": self.config.feature_toggle_config.admin_only_features
            })

        @self.app.post("/api/admin/features/toggle")
        async def toggle_feature(request: Request, credentials: HTTPAuthorizationCredentials = Depends(security)):
            """Toggle a feature."""
            self._verify_session(credentials.credentials)

            if not self.config.is_feature_enabled("system_configuration", "admin"):
                raise HTTPException(status_code=403, detail="Admin access required")

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
        async def api_proxy(path: str, request: Request, credentials: HTTPAuthorizationCredentials = Depends(security)):
            """Proxy API requests."""
            session = self._verify_session(credentials.credentials)

            # Proxy to internal API
            # This is a simplified implementation
            return JSONResponse(content={"message": f"API proxy for {path}", "user": session.username})

    def _verify_session(self, session_id: str):
        """Verify session and return session object."""
        if not self.mfa_manager.is_session_valid(session_id):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired session"
            )

        return self.mfa_manager.get_session(session_id)

    def _get_enabled_features(self) -> List[str]:
        """Get list of enabled features."""
        return self.config.feature_toggle_config.enabled_features

    def _get_admin_features(self) -> List[str]:
        """Get list of admin features."""
        return self.config.feature_toggle_config.admin_only_features

    async def _get_system_status(self) -> Dict[str, Any]:
        """Get system status."""
        auth_health = await self.auth_storage.health_check()

        return {
            "auth_storage": auth_health,
            "mfa_enabled": self.mfa_manager.is_mfa_enabled(),
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
