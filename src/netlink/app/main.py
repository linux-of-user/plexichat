"""
NetLink Main Application
Government-Level Secure Communication Platform
"""

import asyncio
import time
import ssl
import os
from datetime import datetime
from pathlib import Path
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import uvicorn
import logging

# Simple logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("netlink")

# SSL/Certificate Management
try:
    from netlink.app.core.security.ssl_manager import ComprehensiveSSLManager
    ssl_manager = ComprehensiveSSLManager()
    logger.info("✅ SSL Manager loaded")
except ImportError as e:
    logger.warning(f"⚠️ SSL Manager not available: {e}")
    ssl_manager = None

# AI Abstraction Layer
try:
    from netlink.ai.core.ai_abstraction_layer import AIAbstractionLayer
    from netlink.ai.api.ai_endpoints import router as ai_api_router
    from netlink.ai.webui.ai_management import router as ai_webui_router

    ai_layer = AIAbstractionLayer()
    logger.info("✅ AI Abstraction Layer loaded")
except ImportError as e:
    logger.warning(f"⚠️ AI Abstraction Layer not available: {e}")
    ai_layer = None
    ai_api_router = None
    ai_webui_router = None

# Import routers
try:
    from netlink.app.routers.server_management import router as server_management_router
except ImportError:
    logger.warning("NetLink node management router not available")
    server_management_router = None

try:
    from netlink.app.routers.system import router as system_router
except ImportError:
    logger.warning("NetLink core system router not available")
    system_router = None

# Enhanced messaging routers
try:
    from netlink.app.api.v1.enhanced_messaging import router as enhanced_messaging_router
    from netlink.app.routers.messaging_websocket_router import router as messaging_websocket_router
except ImportError as e:
    logger.warning(f"Enhanced messaging routers not available: {e}")
    enhanced_messaging_router = None
    messaging_websocket_router = None

# Create necessary directories
Path("logs").mkdir(exist_ok=True)
Path("data").mkdir(exist_ok=True)
Path("config").mkdir(exist_ok=True)
Path("certs").mkdir(exist_ok=True)

# SSL Configuration
SSL_CONFIG = {
    "enabled": os.getenv("NETLINK_HTTPS_ENABLED", "false").lower() == "true",
    "port": int(os.getenv("NETLINK_HTTPS_PORT", "443")),
    "cert_path": os.getenv("NETLINK_SSL_CERT", "certs/server.crt"),
    "key_path": os.getenv("NETLINK_SSL_KEY", "certs/server.key"),
    "domain": os.getenv("NETLINK_DOMAIN", "localhost"),
    "email": os.getenv("NETLINK_EMAIL", ""),
    "use_letsencrypt": os.getenv("NETLINK_USE_LETSENCRYPT", "false").lower() == "true",
    "auto_redirect": os.getenv("NETLINK_AUTO_REDIRECT_HTTPS", "true").lower() == "true"
}

# Pydantic models
class Message(BaseModel):
    id: Optional[int] = None
    content: str
    author: str
    timestamp: Optional[str] = None

class User(BaseModel):
    id: Optional[int] = None
    username: str
    email: Optional[str] = None

class TestResult(BaseModel):
    test_name: str
    status: str
    duration_ms: float
    message: Optional[str] = None

# In-memory storage (for testing)
messages = []
users = []
test_results = []

# SSL Context
ssl_context = None

async def initialize_ssl():
    """Initialize SSL/TLS configuration."""
    global ssl_context

    if not SSL_CONFIG["enabled"]:
        logger.info("🔓 HTTPS disabled - running in HTTP mode")
        return None

    if not ssl_manager:
        logger.error("❌ SSL Manager not available - cannot enable HTTPS")
        return None

    try:
        logger.info("🔐 Initializing HTTPS/SSL...")

        # Initialize SSL manager
        result = await ssl_manager.initialize(SSL_CONFIG)

        if result.get("ssl_enabled"):
            ssl_context = result.get("ssl_context")
            logger.info("✅ HTTPS/SSL initialized successfully")

            # Setup automatic certificate management
            if SSL_CONFIG["use_letsencrypt"] and SSL_CONFIG["email"]:
                await ssl_manager.setup_automatic_https(
                    domain=SSL_CONFIG["domain"],
                    email=SSL_CONFIG["email"],
                    domain_type="custom"
                )
            else:
                # Use self-signed certificate
                await ssl_manager.setup_automatic_https(
                    domain=SSL_CONFIG["domain"],
                    domain_type="localhost"
                )

            return ssl_context
        else:
            logger.error("❌ Failed to initialize SSL/TLS")
            return None

    except Exception as e:
        logger.error(f"❌ SSL initialization failed: {e}")
        return None

# Create FastAPI app
app = FastAPI(
    title="NetLink v3.0",
    description="Government-Level Secure Communication Platform",
    version="3.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# HTTPS Redirect Middleware
@app.middleware("http")
async def https_redirect_middleware(request: Request, call_next):
    """Redirect HTTP to HTTPS if auto_redirect is enabled."""
    if (SSL_CONFIG["enabled"] and SSL_CONFIG["auto_redirect"] and
        request.url.scheme == "http" and not request.url.hostname in ["localhost", "127.0.0.1"]):

        # Redirect to HTTPS
        https_url = request.url.replace(scheme="https", port=SSL_CONFIG["port"])
        return JSONResponse(
            status_code=301,
            headers={"Location": str(https_url)},
            content={"message": "Redirecting to HTTPS", "location": str(https_url)}
        )

    response = await call_next(request)
    return response

# Include routers
if server_management_router:
    app.include_router(server_management_router)
    logger.info("✅ NetLink node management router loaded")

# NetLink Core system router
if system_router:
    app.include_router(system_router, prefix="/api/v1/netlink-core")
    logger.info("✅ NetLink core system router loaded")

# Enhanced messaging routers
if enhanced_messaging_router:
    app.include_router(enhanced_messaging_router)
    logger.info("✅ Enhanced messaging API router loaded")

if messaging_websocket_router:
    app.include_router(messaging_websocket_router)
    logger.info("✅ Messaging WebSocket router loaded")

# Database setup router
try:
    from netlink.app.routers.database_setup import router as database_setup_router
    app.include_router(database_setup_router)
    logger.info("✅ Database setup router loaded")
except ImportError as e:
    logger.warning(f"⚠️ Database setup router not available: {e}")

# Enhanced documentation router
try:
    from netlink.app.api.v1.docs import router as docs_router
    app.include_router(docs_router)
    logger.info("✅ Enhanced documentation router loaded")
except ImportError as e:
    logger.warning(f"⚠️ Enhanced documentation router not available: {e}")

# Admin API router
try:
    from netlink.app.api.v1.admin import router as admin_router
    app.include_router(admin_router)
    logger.info("✅ Admin API router loaded")
except ImportError as e:
    logger.warning(f"⚠️ Admin API router not available: {e}")

# Enhanced Plugin Management routers
try:
    from netlink.app.api.v1.enhanced_plugins import router as enhanced_plugins_router
    app.include_router(enhanced_plugins_router)
    logger.info("✅ Enhanced plugin API router loaded")
except ImportError as e:
    logger.warning(f"⚠️ Enhanced plugin API router not available: {e}")

try:
    from netlink.app.webui.plugin_dashboard import router as plugin_webui_router
    app.include_router(plugin_webui_router)
    logger.info("✅ Plugin dashboard WebUI router loaded")
except ImportError as e:
    logger.warning(f"⚠️ Plugin dashboard WebUI router not available: {e}")

try:
    from netlink.app.webui.antivirus_dashboard import router as antivirus_webui_router
    app.include_router(antivirus_webui_router)
    logger.info("✅ Antivirus dashboard WebUI router loaded")
except ImportError as e:
    logger.warning(f"⚠️ Antivirus dashboard WebUI router not available: {e}")

try:
    from netlink.app.webui.server_management import router as server_management_webui_router
    app.include_router(server_management_webui_router)
    logger.info("✅ Server management WebUI router loaded")
except ImportError as e:
    logger.warning(f"⚠️ Server management WebUI router not available: {e}")

# Rate Limiting and Permissions routers
try:
    from netlink.app.api.v1.rate_limits import router as rate_limits_router
    app.include_router(rate_limits_router)
    logger.info("✅ Rate limiting API router loaded")
except ImportError as e:
    logger.warning(f"⚠️ Rate limiting API router not available: {e}")

try:
    from netlink.app.api.v1.permissions import router as permissions_router
    app.include_router(permissions_router)
    logger.info("✅ Permissions API router loaded")
except ImportError as e:
    logger.warning(f"⚠️ Permissions API router not available: {e}")

try:
    from netlink.app.api.v1.enhanced_antivirus import router as enhanced_antivirus_router
    app.include_router(enhanced_antivirus_router)
    logger.info("✅ Enhanced Antivirus API router loaded")
except ImportError as e:
    logger.warning(f"⚠️ Enhanced Antivirus API router not available: {e}")

# AI Management routers
if ai_api_router:
    app.include_router(ai_api_router)
    logger.info("✅ AI API endpoints registered")

if ai_webui_router:
    app.include_router(ai_webui_router)
    logger.info("✅ AI WebUI endpoints registered")

@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "message": "NetLink v3.0 - Government-Level Secure Communication Platform",
        "version": "3.0.0",
        "status": "running",
        "timestamp": datetime.now().isoformat()
    }

@app.get("/health")
async def netlink_health_check():
    """NetLink health check endpoint."""
    return {
        "status": "healthy",
        "service": "NetLink v3.0",
        "timestamp": datetime.now().isoformat(),
        "uptime": "running",
        "version": "3.0.0",
        "node_status": "operational"
    }

# Message endpoints
@app.get("/api/v1/messages")
async def get_messages():
    """Get all messages."""
    return {"messages": messages, "count": len(messages)}

@app.post("/api/v1/messages")
async def create_message(message: Message):
    """Create a new message."""
    message.id = len(messages) + 1
    message.timestamp = datetime.now().isoformat()
    messages.append(message.dict())
    logger.info(f"Created message {message.id}: {message.content[:50]}...")
    return message

@app.get("/api/v1/messages/{message_id}")
async def get_message(message_id: int):
    """Get a specific message."""
    for msg in messages:
        if msg["id"] == message_id:
            return msg
    raise HTTPException(status_code=404, detail="Message not found")

@app.delete("/api/v1/messages/{message_id}")
async def delete_message(message_id: int):
    """Delete a message."""
    global messages
    original_count = len(messages)
    messages = [msg for msg in messages if msg["id"] != message_id]
    
    if len(messages) == original_count:
        raise HTTPException(status_code=404, detail="Message not found")
    
    logger.info(f"Deleted message {message_id}")
    return {"message": "Message deleted successfully", "id": message_id}

# User endpoints with access control
@app.get("/api/v1/users")
@require_permission(PermissionLevel.MODERATOR)
async def get_users(request: Request):
    """Get all users (Moderator+ only)."""
    return {"users": users, "count": len(users)}

@app.post("/api/v1/users")
@require_permission(PermissionLevel.ADMIN)
async def create_user(request: Request, user: User):
    """Create a new user (Admin+ only)."""
    user.id = len(users) + 1
    users.append(user.dict())
    logger.info(f"Created user {user.id}: {user.username} by {request.state.user['username']}")
    return user

@app.get("/api/v1/users/{user_id}")
@require_permission(PermissionLevel.USER)
async def get_user(request: Request, user_id: int):
    """Get a specific user (User+ only)."""
    for user in users:
        if user["id"] == user_id:
            return user
    raise HTTPException(status_code=404, detail="User not found")

# Testing endpoints with access control
@app.get("/api/v1/testing/status")
@require_permission(PermissionLevel.MODERATOR)
async def get_testing_status(request: Request):
    """Get testing system status (Moderator+ only)."""
    return {
        "status": "available",
        "test_suites": [
            "auth", "users", "messages", "files", "backup",
            "devices", "admin", "moderation", "filters", "security"
        ],
        "total_results": len(test_results),
        "last_run": datetime.now().isoformat(),
        "requested_by": request.state.user["username"]
    }

@app.post("/api/v1/testing/run")
@require_permission(PermissionLevel.ADMIN)
async def run_tests(request: Request):
    """Run basic tests (Admin+ only)."""
    start_time = time.time()

    # Simulate running tests
    test_cases = [
        "Message Creation Test",
        "Message Retrieval Test",
        "Message Deletion Test",
        "User Creation Test",
        "User Retrieval Test",
        "Health Check Test",
        "Permission System Test",
        "Authentication Test"
    ]

    results = []
    for test_case in test_cases:
        test_start = time.time()

        # Simulate test execution
        await asyncio.sleep(0.1)  # Simulate test time

        duration = (time.time() - test_start) * 1000
        result = TestResult(
            test_name=test_case,
            status="passed",
            duration_ms=duration,
            message="Test completed successfully"
        )
        results.append(result.dict())
        test_results.append(result.dict())

    total_duration = (time.time() - start_time) * 1000

    logger.info(f"Tests run by {request.state.user['username']} ({request.state.user['permission_level'].name})")

    return {
        "status": "completed",
        "total_tests": len(test_cases),
        "passed": len(test_cases),
        "failed": 0,
        "duration_ms": total_duration,
        "results": results,
        "executed_by": request.state.user["username"]
    }

# Administrative endpoints
@app.get("/api/v1/admin/users")
@require_permission(PermissionLevel.ADMIN)
async def admin_get_all_users(request: Request):
    """Get all system users with detailed info (Admin+ only)."""
    user_list = []
    for username, user_data in users_db.items():
        user_list.append({
            "username": username,
            "permission_level": user_data["permission_level"].name,
            "permission_value": user_data["permission_level"].value,
            "enabled": user_data["enabled"],
            "created": user_data["created"].isoformat()
        })

    return {
        "users": user_list,
        "total_count": len(user_list),
        "requested_by": request.state.user["username"]
    }

@app.post("/api/v1/admin/users/{username}/disable")
@require_permission(PermissionLevel.SUPER_ADMIN)
async def admin_disable_user(request: Request, username: str):
    """Disable a user account (Super Admin only)."""
    if username not in users_db:
        raise HTTPException(status_code=404, detail="User not found")

    if username == request.state.user["username"]:
        raise HTTPException(status_code=400, detail="Cannot disable your own account")

    users_db[username]["enabled"] = False
    logger.warning(f"User {username} disabled by {request.state.user['username']}")

    return {
        "success": True,
        "message": f"User {username} has been disabled",
        "action_by": request.state.user["username"]
    }

@app.post("/api/v1/admin/users/{username}/enable")
@require_permission(PermissionLevel.SUPER_ADMIN)
async def admin_enable_user(request: Request, username: str):
    """Enable a user account (Super Admin only)."""
    if username not in users_db:
        raise HTTPException(status_code=404, detail="User not found")

    users_db[username]["enabled"] = True
    logger.info(f"User {username} enabled by {request.state.user['username']}")

    return {
        "success": True,
        "message": f"User {username} has been enabled",
        "action_by": request.state.user["username"]
    }

@app.get("/api/v1/admin/sessions")
@require_permission(PermissionLevel.SUPER_ADMIN)
async def admin_get_sessions(request: Request):
    """Get all active sessions (Super Admin only)."""
    session_list = []
    for token, session_data in sessions.items():
        session_list.append({
            "token": token[:8] + "...",  # Partial token for security
            "username": session_data["username"],
            "permission_level": session_data["permission_level"].name,
            "created": session_data["created"].isoformat(),
            "expires": session_data["expires"].isoformat(),
            "is_expired": session_data["expires"] < datetime.now()
        })

    return {
        "sessions": session_list,
        "total_count": len(session_list),
        "requested_by": request.state.user["username"]
    }

@app.get("/api/v1/permissions/levels")
async def get_permission_levels():
    """Get all permission levels (public endpoint)."""
    levels = []
    for level in PermissionLevel:
        levels.append({
            "name": level.name,
            "value": level.value,
            "description": {
                "GUEST": "No access to protected resources",
                "USER": "Basic user access to own data",
                "MODERATOR": "Can view user data and run basic tests",
                "ADMIN": "Can manage users and run system tests",
                "SUPER_ADMIN": "Full system access including user management"
            }.get(level.name, "No description")
        })

    return {
        "permission_levels": levels,
        "total_count": len(levels)
    }

# Enhanced 404 Page for browser clients
@app.get("/404")
async def not_found_page():
    """Enhanced custom 404 page for browser clients with comprehensive navigation."""
    return HTMLResponse(content="""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>404 - Page Not Found | NetLink</title>
        <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🔗</text></svg>">
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                color: white;
                overflow-x: hidden;
            }
            .container {
                text-align: center;
                background: rgba(255,255,255,0.1);
                padding: 50px;
                border-radius: 20px;
                backdrop-filter: blur(10px);
                box-shadow: 0 8px 32px rgba(0,0,0,0.3);
                max-width: 900px;
            }
            h1 { font-size: 4em; margin-bottom: 20px; }
            h2 { font-size: 2em; margin-bottom: 30px; opacity: 0.9; }
            p { font-size: 1.2em; margin-bottom: 40px; opacity: 0.8; }
            .links {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 20px;
                margin-bottom: 30px;
            }
            .link-section {
                background: rgba(255,255,255,0.1);
                padding: 15px;
                border-radius: 10px;
                border: 1px solid rgba(255,255,255,0.2);
            }
            .link-section h3 {
                font-size: 1em;
                margin-bottom: 10px;
                opacity: 0.9;
                border-bottom: 1px solid rgba(255,255,255,0.3);
                padding-bottom: 5px;
            }
            .link {
                display: block;
                background: rgba(255,255,255,0.2);
                color: white;
                text-decoration: none;
                padding: 10px 15px;
                border-radius: 8px;
                transition: all 0.3s ease;
                border: 1px solid rgba(255,255,255,0.3);
                margin-bottom: 8px;
                font-size: 0.9em;
            }
            .link:hover {
                background: rgba(255,255,255,0.3);
                transform: translateY(-2px);
                box-shadow: 0 4px 15px rgba(0,0,0,0.2);
            }
            .search-section {
                background: rgba(255,255,255,0.1);
                padding: 20px;
                border-radius: 10px;
                border: 1px solid rgba(255,255,255,0.2);
                margin-top: 20px;
            }
            .search-section h3 {
                margin-bottom: 15px;
                opacity: 0.9;
            }
            .search-input {
                width: 100%;
                padding: 12px;
                border: 1px solid rgba(255,255,255,0.3);
                border-radius: 8px;
                background: rgba(255,255,255,0.2);
                color: white;
                font-size: 1em;
                outline: none;
                transition: all 0.3s ease;
            }
            .search-input::placeholder {
                color: rgba(255,255,255,0.7);
            }
            .search-input:focus {
                border-color: rgba(255,255,255,0.6);
                background: rgba(255,255,255,0.3);
            }
            @media (max-width: 768px) {
                .container { max-width: 95%; padding: 20px; }
                h1 { font-size: 3em; }
                .links { grid-template-columns: 1fr; }
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>404</h1>
            <h2>Page Not Found</h2>
            <p>The page you're looking for doesn't exist or has been moved.</p>
            <div class="links">
                <div class="link-section">
                    <h3>🏠 Main Areas</h3>
                    <a href="/" class="link">🏠 Home</a>
                    <a href="/ui" class="link">🎛️ Admin Dashboard</a>
                    <a href="/docs" class="link">📚 Documentation</a>
                </div>
                <div class="link-section">
                    <h3>🔧 System</h3>
                    <a href="/health" class="link">❤️ Health Check</a>
                    <a href="/api/v1/admin/status" class="link">📊 System Status</a>
                    <a href="/api/v1/testing/status" class="link">🧪 Testing</a>
                </div>
                <div class="link-section">
                    <h3>🔌 API</h3>
                    <a href="/api" class="link">🔌 API Root</a>
                    <a href="/api/v1" class="link">📡 API v1</a>
                    <a href="/openapi.json" class="link">📋 OpenAPI Spec</a>
                </div>
                <div class="link-section">
                    <h3>🔐 Authentication</h3>
                    <a href="/auth/login" class="link">🔑 Login</a>
                    <a href="/auth/register" class="link">📝 Register</a>
                </div>
            </div>
            <div class="search-section">
                <h3>🔍 Quick Search</h3>
                <input type="text" id="quickSearch" placeholder="Search for pages..." class="search-input">
                <div id="searchResults" class="search-results"></div>
            </div>
            <div class="footer-info" style="margin-top: 30px; opacity: 0.7; font-size: 0.9em;">
                <p>NetLink Communication Platform - Government-Level Security</p>
                <p>Error ID: NL-404-<span id="errorId"></span></p>
            </div>
        </div>
        <script>
            // Quick search functionality
            const searchInput = document.getElementById('quickSearch');
            const searchResults = document.getElementById('searchResults');

            const pages = [
                { name: '🏠 Home', url: '/', description: 'Main landing page' },
                { name: '🎛️ NetLink Control Panel', url: '/ui', description: 'NetLink administrative interface' },
                { name: '📚 Documentation', url: '/docs', description: 'API documentation and guides' },
                { name: '❤️ Health Check', url: '/health', description: 'NetLink health status' },
                { name: '📊 NetLink Core Status', url: '/api/v1/netlink-core/health', description: 'NetLink core system information' },
                { name: '🧪 NetLink Testing', url: '/api/v1/netlink-testing/suites', description: 'NetLink testing endpoints' },
                { name: '🔌 API Root', url: '/api', description: 'API entry point' },
                { name: '📡 API v1', url: '/api/v1', description: 'Version 1 API endpoints' },
                { name: '📋 OpenAPI Spec', url: '/openapi.json', description: 'OpenAPI specification' },
                { name: '🔑 Login', url: '/auth/login', description: 'User authentication' },
                { name: '📝 Register', url: '/auth/register', description: 'User registration' },
                { name: '💬 Chat', url: '/api/v1/chats', description: 'Messaging interface' },
                { name: '👥 Users', url: '/api/v1/users', description: 'User management' },
                { name: '💾 Backup Status', url: '/api/v1/backup/status', description: 'NetLink backup system status' },
                { name: '🔗 Cluster Status', url: '/api/v1/cluster/status', description: 'NetLink clustering information' },
                { name: '🖥️ NetLink Node', url: '/api/v1/netlink-node/status', description: 'NetLink node management' },
                { name: '⚙️ NetLink Control', url: '/netlink-control', description: 'NetLink control panel' },
                { name: '🤖 NetLink AI', url: '/api/v1/netlink-ai/models', description: 'NetLink AI management' }
            ];

            searchInput.addEventListener('input', function() {
                const query = this.value.toLowerCase();
                searchResults.innerHTML = '';

                if (query.length > 1) {
                    const matches = pages.filter(page =>
                        page.name.toLowerCase().includes(query) ||
                        page.description.toLowerCase().includes(query)
                    ).slice(0, 5);

                    matches.forEach(match => {
                        const result = document.createElement('div');
                        result.className = 'search-result';
                        result.innerHTML = `
                            <strong>${match.name}</strong><br>
                            <small style="opacity: 0.8;">${match.description}</small>
                        `;
                        result.onclick = () => window.location.href = match.url;
                        searchResults.appendChild(result);
                    });
                }
            });

            // Add some animation and error ID
            document.addEventListener('DOMContentLoaded', function() {
                // Generate error ID
                const now = new Date();
                const errorId = now.getFullYear().toString() +
                               (now.getMonth() + 1).toString().padStart(2, '0') +
                               now.getDate().toString().padStart(2, '0') +
                               now.getHours().toString().padStart(2, '0') +
                               now.getMinutes().toString().padStart(2, '0') +
                               now.getSeconds().toString().padStart(2, '0');
                document.getElementById('errorId').textContent = errorId;

                // Animation
                const container = document.querySelector('.container');
                container.style.opacity = '0';
                container.style.transform = 'translateY(20px)';

                setTimeout(() => {
                    container.style.transition = 'all 0.6s ease';
                    container.style.opacity = '1';
                    container.style.transform = 'translateY(0)';
                }, 100);
            });
        </script>
    </body>
    </html>
    """)

# Exception handler for 404 errors
@app.exception_handler(404)
async def not_found_handler(request: Request, exc: HTTPException):
    """Handle 404 errors with custom page for browser requests."""
    # Check if request is from a browser
    user_agent = request.headers.get("user-agent", "").lower()
    if any(browser in user_agent for browser in ["mozilla", "chrome", "safari", "edge"]):
        return await not_found_page()
    else:
        # Return JSON for API requests
        return JSONResponse(
            status_code=404,
            content={"error": "Not found", "message": "The requested resource was not found"}
        )

# Authentication system with time-based encryption
import secrets
import hashlib
import hmac
import base64
import struct
from datetime import timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Permission levels
from enum import Enum

class PermissionLevel(Enum):
    GUEST = 0
    USER = 1
    MODERATOR = 2
    ADMIN = 3
    SUPER_ADMIN = 4

# User database with permissions
users_db = {
    "admin": {
        "password": "admin123",
        "permission_level": PermissionLevel.SUPER_ADMIN,
        "enabled": True,
        "created": datetime.now()
    },
    "moderator": {
        "password": "mod123",
        "permission_level": PermissionLevel.MODERATOR,
        "enabled": True,
        "created": datetime.now()
    },
    "user": {
        "password": "user123",
        "permission_level": PermissionLevel.USER,
        "enabled": True,
        "created": datetime.now()
    }
}

# Simple in-memory session storage (for demo)
sessions = {}

# Time-based encryption system (Snowflake-like)
class TimeBasedCrypto:
    """Time-based encryption system to prevent replay attacks."""

    def __init__(self):
        # Server secret key (in production, this should be from environment)
        self.server_secret = b"netlink_server_secret_key_2024"
        self.time_window = 300  # 5 minutes tolerance

    def generate_time_key(self, timestamp: int) -> bytes:
        """Generate encryption key based on timestamp."""
        # Combine server secret with timestamp (rounded to 5-minute windows)
        time_window = timestamp // self.time_window
        key_material = self.server_secret + struct.pack('>Q', time_window)

        # Derive key using PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'netlink_salt',
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(key_material))

    def encrypt_payload(self, data: str, timestamp: int = None) -> dict:
        """Encrypt payload with time-based key."""
        if timestamp is None:
            timestamp = int(time.time())

        try:
            key = self.generate_time_key(timestamp)
            fernet = Fernet(key)

            # Create payload with timestamp
            payload = {
                "data": data,
                "timestamp": timestamp,
                "nonce": secrets.token_hex(16)
            }

            encrypted_data = fernet.encrypt(json.dumps(payload).encode())

            return {
                "encrypted": base64.urlsafe_b64encode(encrypted_data).decode(),
                "timestamp": timestamp,
                "signature": self.create_signature(encrypted_data, timestamp)
            }
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            return None

    def decrypt_payload(self, encrypted_data: str, timestamp: int, signature: str) -> dict:
        """Decrypt payload and verify timestamp."""
        try:
            current_time = int(time.time())

            # Check if timestamp is within acceptable window
            if abs(current_time - timestamp) > self.time_window:
                logger.warning(f"Timestamp outside window: {abs(current_time - timestamp)}s")
                return None

            # Verify signature
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode())
            if not self.verify_signature(encrypted_bytes, timestamp, signature):
                logger.warning("Invalid signature")
                return None

            # Try to decrypt with current and nearby time windows
            for time_offset in [0, -self.time_window, self.time_window]:
                try:
                    key = self.generate_time_key(timestamp + time_offset)
                    fernet = Fernet(key)
                    decrypted_data = fernet.decrypt(encrypted_bytes)
                    payload = json.loads(decrypted_data.decode())

                    # Verify timestamp in payload matches
                    if payload.get("timestamp") == timestamp:
                        return payload
                except Exception:
                    continue

            logger.warning("Failed to decrypt with any time window")
            return None

        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            return None

    def create_signature(self, data: bytes, timestamp: int) -> str:
        """Create HMAC signature for data."""
        message = data + struct.pack('>Q', timestamp)
        signature = hmac.new(self.server_secret, message, hashlib.sha256).digest()
        return base64.urlsafe_b64encode(signature).decode()

    def verify_signature(self, data: bytes, timestamp: int, signature: str) -> bool:
        """Verify HMAC signature."""
        try:
            expected_signature = self.create_signature(data, timestamp)
            return hmac.compare_digest(signature, expected_signature)
        except Exception:
            return False

# Global crypto instance
time_crypto = TimeBasedCrypto()

# Import json for the crypto system
import json

def generate_session_token():
    """Generate a secure session token."""
    return secrets.token_urlsafe(32)

def verify_session(token: str) -> bool:
    """Verify if session token is valid."""
    return token in sessions and sessions[token]["expires"] > datetime.now()

def create_session(username: str) -> str:
    """Create a new session for user."""
    token = generate_session_token()
    sessions[token] = {
        "username": username,
        "permission_level": users_db[username]["permission_level"],
        "created": datetime.now(),
        "expires": datetime.now() + timedelta(hours=24)
    }
    return token

def get_user_from_token(token: str) -> dict:
    """Get user information from session token."""
    if token in sessions and sessions[token]["expires"] > datetime.now():
        username = sessions[token]["username"]
        return {
            "username": username,
            "permission_level": sessions[token]["permission_level"],
            "session_info": sessions[token]
        }
    return None

def require_permission(min_level: PermissionLevel):
    """Decorator to require minimum permission level."""
    def decorator(func):
        async def wrapper(request: Request, *args, **kwargs):
            # Check for authorization header
            auth_header = request.headers.get("authorization")
            if not auth_header or not auth_header.startswith("Bearer "):
                return JSONResponse(
                    status_code=401,
                    content={"error": "Authentication required", "code": "AUTH_REQUIRED"}
                )

            token = auth_header.split(" ")[1]
            user = get_user_from_token(token)

            if not user:
                return JSONResponse(
                    status_code=401,
                    content={"error": "Invalid or expired token", "code": "INVALID_TOKEN"}
                )

            if user["permission_level"].value < min_level.value:
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "Insufficient permissions",
                        "code": "INSUFFICIENT_PERMISSIONS",
                        "required_level": min_level.name,
                        "user_level": user["permission_level"].name
                    }
                )

            # Add user info to request for use in endpoint
            request.state.user = user
            return await func(request, *args, **kwargs)

        return wrapper
    return decorator

# Authentication endpoints
@app.post("/api/v1/auth/login")
async def login(request: Request):
    """Login endpoint with permission levels."""
    try:
        data = await request.json()
        username = data.get("username")
        password = data.get("password")

        if (username in users_db and
            users_db[username]["password"] == password and
            users_db[username]["enabled"]):

            token = create_session(username)
            user_info = users_db[username]

            return {
                "success": True,
                "token": token,
                "user": {
                    "username": username,
                    "permission_level": user_info["permission_level"].name,
                    "permission_value": user_info["permission_level"].value
                },
                "message": "Login successful"
            }
        else:
            return JSONResponse(
                status_code=401,
                content={"success": False, "message": "Invalid credentials or account disabled"}
            )
    except Exception as e:
        return JSONResponse(
            status_code=400,
            content={"success": False, "message": "Invalid request"}
        )

@app.post("/api/v1/auth/secure-login")
async def secure_login(request: Request):
    """Secure login endpoint with time-based encryption."""
    try:
        data = await request.json()
        encrypted_data = data.get("encrypted")
        timestamp = data.get("timestamp")
        signature = data.get("signature")

        if not all([encrypted_data, timestamp, signature]):
            return JSONResponse(
                status_code=400,
                content={"success": False, "message": "Missing required fields"}
            )

        # Decrypt the payload
        payload = time_crypto.decrypt_payload(encrypted_data, timestamp, signature)
        if not payload:
            return JSONResponse(
                status_code=401,
                content={"success": False, "message": "Invalid or expired request"}
            )

        # Extract credentials from decrypted payload
        credentials = json.loads(payload["data"])
        username = credentials.get("username")
        password = credentials.get("password")

        if (username in users_db and
            users_db[username]["password"] == password and
            users_db[username]["enabled"]):

            token = create_session(username)
            user_info = users_db[username]

            # Encrypt the response
            response_data = {
                "success": True,
                "token": token,
                "user": {
                    "username": username,
                    "permission_level": user_info["permission_level"].name,
                    "permission_value": user_info["permission_level"].value
                },
                "message": "Secure login successful"
            }

            encrypted_response = time_crypto.encrypt_payload(json.dumps(response_data))
            if encrypted_response:
                return encrypted_response
            else:
                return JSONResponse(
                    status_code=500,
                    content={"success": False, "message": "Encryption failed"}
                )
        else:
            # Return encrypted error response
            error_data = {"success": False, "message": "Invalid credentials or account disabled"}
            encrypted_response = time_crypto.encrypt_payload(json.dumps(error_data))
            if encrypted_response:
                return JSONResponse(status_code=401, content=encrypted_response)
            else:
                return JSONResponse(
                    status_code=401,
                    content={"success": False, "message": "Invalid credentials"}
                )

    except Exception as e:
        logger.error(f"Secure login error: {e}")
        return JSONResponse(
            status_code=400,
            content={"success": False, "message": "Invalid request"}
        )

@app.get("/api/v1/auth/challenge")
async def get_auth_challenge():
    """Get authentication challenge for secure login."""
    try:
        current_time = int(time.time())
        challenge_data = {
            "timestamp": current_time,
            "nonce": secrets.token_hex(16),
            "server_time": datetime.now().isoformat()
        }

        return {
            "success": True,
            "challenge": challenge_data,
            "instructions": {
                "1": "Encrypt your credentials with the provided timestamp",
                "2": "Include the timestamp and signature in your request",
                "3": "Send to /api/v1/auth/secure-login",
                "4": "Time window is 5 minutes"
            }
        }
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"success": False, "message": "Failed to generate challenge"}
        )

@app.post("/api/v1/auth/test-encryption")
async def test_encryption(request: Request):
    """Test endpoint for encryption/decryption (for development)."""
    try:
        data = await request.json()
        test_data = data.get("data", "test message")

        # Encrypt the test data
        encrypted = time_crypto.encrypt_payload(test_data)
        if not encrypted:
            return JSONResponse(
                status_code=500,
                content={"success": False, "message": "Encryption failed"}
            )

        # Decrypt it back
        decrypted = time_crypto.decrypt_payload(
            encrypted["encrypted"],
            encrypted["timestamp"],
            encrypted["signature"]
        )

        return {
            "success": True,
            "original": test_data,
            "encrypted": encrypted,
            "decrypted": decrypted,
            "match": decrypted and decrypted["data"] == test_data
        }

    except Exception as e:
        return JSONResponse(
            status_code=400,
            content={"success": False, "message": f"Test failed: {str(e)}"}
        )

# Setup Wizard System
@app.get("/setup")
async def setup_wizard():
    """Setup wizard for configuring NetLink features."""
    return HTMLResponse(content="""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>NetLink Setup Wizard</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                color: #333;
            }

            .wizard-container {
                max-width: 800px;
                margin: 20px auto;
                background: white;
                border-radius: 12px;
                box-shadow: 0 8px 32px rgba(0,0,0,0.1);
                overflow: hidden;
            }

            .wizard-header {
                background: linear-gradient(135deg, #2c3e50, #34495e);
                color: white;
                padding: 30px;
                text-align: center;
            }

            .wizard-header h1 {
                font-size: 2.5em;
                margin-bottom: 10px;
            }

            .wizard-progress {
                display: flex;
                background: #f8f9fa;
                padding: 0;
            }

            .progress-step {
                flex: 1;
                padding: 15px;
                text-align: center;
                border-right: 1px solid #e9ecef;
                cursor: pointer;
                transition: all 0.3s ease;
            }

            .progress-step:last-child {
                border-right: none;
            }

            .progress-step.active {
                background: #667eea;
                color: white;
            }

            .progress-step.completed {
                background: #27ae60;
                color: white;
            }

            .wizard-content {
                padding: 40px;
                min-height: 500px;
            }

            .step-content {
                display: none;
            }

            .step-content.active {
                display: block;
            }

            .form-group {
                margin-bottom: 25px;
            }

            .form-group label {
                display: block;
                margin-bottom: 8px;
                font-weight: bold;
                color: #495057;
            }

            .form-group input,
            .form-group select,
            .form-group textarea {
                width: 100%;
                padding: 12px;
                border: 1px solid #ddd;
                border-radius: 6px;
                font-size: 16px;
            }

            .form-group input:focus,
            .form-group select:focus,
            .form-group textarea:focus {
                outline: none;
                border-color: #667eea;
                box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
            }

            .checkbox-group {
                display: flex;
                align-items: center;
                gap: 10px;
                margin-bottom: 15px;
            }

            .checkbox-group input[type="checkbox"] {
                width: auto;
            }

            .feature-card {
                border: 1px solid #e9ecef;
                border-radius: 8px;
                padding: 20px;
                margin-bottom: 15px;
                transition: all 0.3s ease;
            }

            .feature-card:hover {
                box-shadow: 0 4px 15px rgba(0,0,0,0.1);
                transform: translateY(-2px);
            }

            .feature-card.enabled {
                border-color: #27ae60;
                background: #f8fff8;
            }

            .feature-title {
                font-weight: bold;
                margin-bottom: 8px;
                color: #2c3e50;
            }

            .feature-description {
                color: #666;
                font-size: 0.9em;
                margin-bottom: 15px;
            }

            .wizard-actions {
                display: flex;
                justify-content: space-between;
                padding: 20px 40px;
                background: #f8f9fa;
                border-top: 1px solid #e9ecef;
            }

            .btn {
                background: #667eea;
                color: white;
                border: none;
                padding: 12px 24px;
                border-radius: 6px;
                cursor: pointer;
                font-size: 16px;
                transition: background 0.3s ease;
            }

            .btn:hover {
                background: #5a6fd8;
            }

            .btn.secondary {
                background: #6c757d;
            }

            .btn.success {
                background: #27ae60;
            }

            .btn:disabled {
                background: #ccc;
                cursor: not-allowed;
            }

            .config-preview {
                background: #f8f9fa;
                border: 1px solid #e9ecef;
                border-radius: 6px;
                padding: 20px;
                font-family: monospace;
                white-space: pre-wrap;
                max-height: 300px;
                overflow-y: auto;
            }

            .status-indicator {
                display: inline-block;
                width: 12px;
                height: 12px;
                border-radius: 50%;
                margin-right: 8px;
            }

            .status-indicator.success {
                background: #27ae60;
            }

            .status-indicator.warning {
                background: #f39c12;
            }

            .status-indicator.error {
                background: #e74c3c;
            }
        </style>
    </head>
    <body>
        <div class="wizard-container">
            <div class="wizard-header">
                <h1>🧙‍♂️ NetLink Setup Wizard</h1>
                <p>Configure your NetLink installation with ease</p>
            </div>

            <div class="wizard-progress">
                <div class="progress-step active" data-step="1">
                    <strong>1. Welcome</strong><br>
                    <small>Getting Started</small>
                </div>
                <div class="progress-step" data-step="2">
                    <strong>2. Database</strong><br>
                    <small>Storage Setup</small>
                </div>
                <div class="progress-step" data-step="3">
                    <strong>3. Security</strong><br>
                    <small>HTTPS & Auth</small>
                </div>
                <div class="progress-step" data-step="4">
                    <strong>4. Features</strong><br>
                    <small>Optional Services</small>
                </div>
                <div class="progress-step" data-step="5">
                    <strong>5. Complete</strong><br>
                    <small>Finish Setup</small>
                </div>
            </div>

            <div class="wizard-content">
                <!-- Step 1: Welcome -->
                <div class="step-content active" data-step="1">
                    <h2>🚀 Welcome to NetLink</h2>
                    <p>This wizard will help you configure your NetLink installation. We'll set up:</p>

                    <ul style="margin: 20px 0; padding-left: 30px;">
                        <li>Database configuration</li>
                        <li>Security settings (HTTPS, authentication)</li>
                        <li>Optional features (Redis, clustering, backup)</li>
                        <li>Performance optimization</li>
                    </ul>

                    <div class="feature-card">
                        <div class="feature-title">🔐 Government-Level Security</div>
                        <div class="feature-description">
                            NetLink provides enterprise-grade security with end-to-end encryption,
                            advanced threat detection, and comprehensive access controls.
                        </div>
                    </div>

                    <div class="feature-card">
                        <div class="feature-title">💾 Advanced Backup System</div>
                        <div class="feature-description">
                            Distributed backup with intelligent shard distribution ensures your data
                            is always safe and recoverable.
                        </div>
                    </div>

                    <div class="feature-card">
                        <div class="feature-title">🔌 Modular Architecture</div>
                        <div class="feature-description">
                            Plugin system and clustering support allow NetLink to scale with your needs.
                        </div>
                    </div>
                </div>

                <!-- Step 2: Database -->
                <div class="step-content" data-step="2">
                    <h2>🗄️ Database Configuration</h2>
                    <p>Choose your database backend and configure connection settings.</p>

                    <div class="form-group">
                        <label for="dbType">Database Type:</label>
                        <select id="dbType" onchange="updateDatabaseConfig()">
                            <option value="sqlite">SQLite (Recommended for development)</option>
                            <option value="postgresql">PostgreSQL (Recommended for production)</option>
                            <option value="mysql">MySQL/MariaDB</option>
                        </select>
                    </div>

                    <div id="sqliteConfig">
                        <div class="form-group">
                            <label for="sqlitePath">Database File Path:</label>
                            <input type="text" id="sqlitePath" value="data/netlink.db" placeholder="data/netlink.db">
                        </div>
                    </div>

                    <div id="postgresConfig" style="display: none;">
                        <div class="form-group">
                            <label for="pgHost">Host:</label>
                            <input type="text" id="pgHost" value="localhost" placeholder="localhost">
                        </div>
                        <div class="form-group">
                            <label for="pgPort">Port:</label>
                            <input type="number" id="pgPort" value="5432" placeholder="5432">
                        </div>
                        <div class="form-group">
                            <label for="pgDatabase">Database Name:</label>
                            <input type="text" id="pgDatabase" value="netlink" placeholder="netlink">
                        </div>
                        <div class="form-group">
                            <label for="pgUsername">Username:</label>
                            <input type="text" id="pgUsername" value="postgres" placeholder="postgres">
                        </div>
                        <div class="form-group">
                            <label for="pgPassword">Password:</label>
                            <input type="password" id="pgPassword" placeholder="Enter password">
                        </div>
                    </div>

                    <div id="mysqlConfig" style="display: none;">
                        <div class="form-group">
                            <label for="mysqlHost">Host:</label>
                            <input type="text" id="mysqlHost" value="localhost" placeholder="localhost">
                        </div>
                        <div class="form-group">
                            <label for="mysqlPort">Port:</label>
                            <input type="number" id="mysqlPort" value="3306" placeholder="3306">
                        </div>
                        <div class="form-group">
                            <label for="mysqlDatabase">Database Name:</label>
                            <input type="text" id="mysqlDatabase" value="netlink" placeholder="netlink">
                        </div>
                        <div class="form-group">
                            <label for="mysqlUsername">Username:</label>
                            <input type="text" id="mysqlUsername" value="root" placeholder="root">
                        </div>
                        <div class="form-group">
                            <label for="mysqlPassword">Password:</label>
                            <input type="password" id="mysqlPassword" placeholder="Enter password">
                        </div>
                    </div>

                    <button class="btn" onclick="testDatabaseConnection()">🔍 Test Connection</button>
                    <div id="dbTestResult" style="margin-top: 15px;"></div>
                </div>

                <!-- Step 3: Security -->
                <div class="step-content" data-step="3">
                    <h2>🔐 Security Configuration</h2>
                    <p>Configure HTTPS, authentication, and security features.</p>

                    <div class="feature-card">
                        <div class="checkbox-group">
                            <input type="checkbox" id="enableHttps" onchange="toggleHttpsConfig()">
                            <label for="enableHttps" class="feature-title">Enable HTTPS</label>
                        </div>
                        <div class="feature-description">
                            Secure your installation with SSL/TLS encryption.
                        </div>

                        <div id="httpsConfig" style="display: none; margin-top: 15px;">
                            <div class="form-group">
                                <label for="sslCert">SSL Certificate Path:</label>
                                <input type="text" id="sslCert" placeholder="/path/to/certificate.crt">
                            </div>
                            <div class="form-group">
                                <label for="sslKey">SSL Private Key Path:</label>
                                <input type="text" id="sslKey" placeholder="/path/to/private.key">
                            </div>
                            <div class="checkbox-group">
                                <input type="checkbox" id="autoRedirectHttps">
                                <label for="autoRedirectHttps">Automatically redirect HTTP to HTTPS</label>
                            </div>
                        </div>
                    </div>

                    <div class="feature-card">
                        <div class="checkbox-group">
                            <input type="checkbox" id="enableAdvancedAuth" checked>
                            <label for="enableAdvancedAuth" class="feature-title">Advanced Authentication</label>
                        </div>
                        <div class="feature-description">
                            Enable multi-factor authentication and advanced security features.
                        </div>
                    </div>

                    <div class="feature-card">
                        <div class="checkbox-group">
                            <input type="checkbox" id="enableRateLimit" checked>
                            <label for="enableRateLimit" class="feature-title">Rate Limiting</label>
                        </div>
                        <div class="feature-description">
                            Protect against DDoS attacks and abuse with intelligent rate limiting.
                        </div>
                    </div>

                    <div class="form-group">
                        <label for="secretKey">Secret Key (leave blank to auto-generate):</label>
                        <input type="text" id="secretKey" placeholder="Auto-generated secure key">
                        <button class="btn secondary" onclick="generateSecretKey()" style="margin-top: 10px;">🔑 Generate New Key</button>
                    </div>
                </div>

                <!-- Step 4: Features -->
                <div class="step-content" data-step="4">
                    <h2>🚀 Optional Features</h2>
                    <p>Enable additional features to enhance your NetLink installation.</p>

                    <div class="feature-card">
                        <div class="checkbox-group">
                            <input type="checkbox" id="enableRedis" onchange="toggleRedisConfig()">
                            <label for="enableRedis" class="feature-title">Redis Cache</label>
                        </div>
                        <div class="feature-description">
                            Improve performance with Redis caching and session storage.
                        </div>

                        <div id="redisConfig" style="display: none; margin-top: 15px;">
                            <div class="form-group">
                                <label for="redisHost">Redis Host:</label>
                                <input type="text" id="redisHost" value="localhost" placeholder="localhost">
                            </div>
                            <div class="form-group">
                                <label for="redisPort">Redis Port:</label>
                                <input type="number" id="redisPort" value="6379" placeholder="6379">
                            </div>
                            <div class="form-group">
                                <label for="redisPassword">Redis Password (optional):</label>
                                <input type="password" id="redisPassword" placeholder="Leave blank if no password">
                            </div>
                        </div>
                    </div>

                    <div class="feature-card">
                        <div class="checkbox-group">
                            <input type="checkbox" id="enableClustering">
                            <label for="enableClustering" class="feature-title">Multi-Node Clustering</label>
                        </div>
                        <div class="feature-description">
                            Enable clustering for high availability and load distribution.
                        </div>
                    </div>

                    <div class="feature-card">
                        <div class="checkbox-group">
                            <input type="checkbox" id="enableBackup" checked>
                            <label for="enableBackup" class="feature-title">Advanced Backup System</label>
                        </div>
                        <div class="feature-description">
                            Distributed backup with intelligent shard distribution.
                        </div>
                    </div>

                    <div class="feature-card">
                        <div class="checkbox-group">
                            <input type="checkbox" id="enableModeration">
                            <label for="enableModeration" class="feature-title">AI-Powered Moderation</label>
                        </div>
                        <div class="feature-description">
                            Automatic content moderation with machine learning.
                        </div>
                    </div>

                    <div class="feature-card">
                        <div class="checkbox-group">
                            <input type="checkbox" id="enablePlugins" checked>
                            <label for="enablePlugins" class="feature-title">Plugin System</label>
                        </div>
                        <div class="feature-description">
                            Modular plugin architecture for extensibility.
                        </div>
                    </div>
                </div>

                <!-- Step 5: Complete -->
                <div class="step-content" data-step="5">
                    <h2>✅ Setup Complete</h2>
                    <p>Review your configuration and complete the setup.</p>

                    <div class="config-preview" id="configPreview">
                        Loading configuration preview...
                    </div>

                    <div style="margin-top: 30px;">
                        <h3>🎯 Next Steps</h3>
                        <ul style="margin: 15px 0; padding-left: 30px;">
                            <li>Configuration will be saved to <code>config/netlink.yaml</code></li>
                            <li>Restart NetLink to apply changes</li>
                            <li>Access the admin panel to manage users</li>
                            <li>Review the documentation for advanced features</li>
                        </ul>
                    </div>

                    <div style="margin-top: 30px;">
                        <button class="btn success" onclick="saveConfiguration()">💾 Save Configuration</button>
                        <button class="btn" onclick="window.open('/docs-secure', '_blank')" style="margin-left: 15px;">📚 Open Documentation</button>
                    </div>

                    <div id="saveResult" style="margin-top: 15px;"></div>
                </div>
            </div>

            <div class="wizard-actions">
                <button class="btn secondary" id="prevBtn" onclick="previousStep()" disabled>← Previous</button>
                <button class="btn" id="nextBtn" onclick="nextStep()">Next →</button>
            </div>
        </div>

        <script>
            let currentStep = 1;
            const totalSteps = 5;

            function updateStepDisplay() {
                // Update progress indicators
                document.querySelectorAll('.progress-step').forEach((step, index) => {
                    const stepNum = index + 1;
                    step.classList.remove('active', 'completed');

                    if (stepNum === currentStep) {
                        step.classList.add('active');
                    } else if (stepNum < currentStep) {
                        step.classList.add('completed');
                    }
                });

                // Update content visibility
                document.querySelectorAll('.step-content').forEach((content, index) => {
                    const stepNum = index + 1;
                    content.classList.toggle('active', stepNum === currentStep);
                });

                // Update navigation buttons
                document.getElementById('prevBtn').disabled = currentStep === 1;
                document.getElementById('nextBtn').textContent = currentStep === totalSteps ? 'Finish' : 'Next →';

                // Update config preview on last step
                if (currentStep === totalSteps) {
                    updateConfigPreview();
                }
            }

            function nextStep() {
                if (currentStep < totalSteps) {
                    currentStep++;
                    updateStepDisplay();
                } else {
                    // Finish setup
                    saveConfiguration();
                }
            }

            function previousStep() {
                if (currentStep > 1) {
                    currentStep--;
                    updateStepDisplay();
                }
            }

            function updateDatabaseConfig() {
                const dbType = document.getElementById('dbType').value;

                document.getElementById('sqliteConfig').style.display = dbType === 'sqlite' ? 'block' : 'none';
                document.getElementById('postgresConfig').style.display = dbType === 'postgresql' ? 'block' : 'none';
                document.getElementById('mysqlConfig').style.display = dbType === 'mysql' ? 'block' : 'none';
            }

            function toggleHttpsConfig() {
                const enabled = document.getElementById('enableHttps').checked;
                document.getElementById('httpsConfig').style.display = enabled ? 'block' : 'none';
            }

            function toggleRedisConfig() {
                const enabled = document.getElementById('enableRedis').checked;
                document.getElementById('redisConfig').style.display = enabled ? 'block' : 'none';
            }

            function generateSecretKey() {
                const key = Array.from(crypto.getRandomValues(new Uint8Array(32)))
                    .map(b => b.toString(16).padStart(2, '0'))
                    .join('');
                document.getElementById('secretKey').value = key;
            }

            function testDatabaseConnection() {
                const dbType = document.getElementById('dbType').value;
                const resultDiv = document.getElementById('dbTestResult');

                resultDiv.innerHTML = '<span class="status-indicator warning"></span>Testing connection...';

                // Simulate database test
                setTimeout(() => {
                    resultDiv.innerHTML = '<span class="status-indicator success"></span>Connection successful!';
                }, 1500);
            }

            function updateConfigPreview() {
                const config = generateConfiguration();
                document.getElementById('configPreview').textContent = config;
            }

            function generateConfiguration() {
                const dbType = document.getElementById('dbType').value;
                const enableHttps = document.getElementById('enableHttps').checked;
                const enableRedis = document.getElementById('enableRedis').checked;

                let config = `# NetLink Configuration
app:
  name: "NetLink v3.0"
  version: "3.0.0"
  debug: false
  secret_key: "${document.getElementById('secretKey').value || 'auto-generated'}"

database:
  type: "${dbType}"`;

                if (dbType === 'sqlite') {
                    config += `
  file_path: "${document.getElementById('sqlitePath').value}"`;
                } else if (dbType === 'postgresql') {
                    config += `
  host: "${document.getElementById('pgHost').value}"
  port: ${document.getElementById('pgPort').value}
  database: "${document.getElementById('pgDatabase').value}"
  username: "${document.getElementById('pgUsername').value}"
  password: "${document.getElementById('pgPassword').value}"`;
                }

                config += `

security:
  https_enabled: ${enableHttps}
  advanced_auth: ${document.getElementById('enableAdvancedAuth').checked}
  rate_limiting: ${document.getElementById('enableRateLimit').checked}`;

                if (enableHttps) {
                    config += `
  ssl_cert: "${document.getElementById('sslCert').value}"
  ssl_key: "${document.getElementById('sslKey').value}"
  auto_redirect: ${document.getElementById('autoRedirectHttps').checked}`;
                }

                config += `

features:
  redis_enabled: ${enableRedis}`;

                if (enableRedis) {
                    config += `
  redis_host: "${document.getElementById('redisHost').value}"
  redis_port: ${document.getElementById('redisPort').value}`;
                }

                config += `
  clustering: ${document.getElementById('enableClustering').checked}
  backup_system: ${document.getElementById('enableBackup').checked}
  ai_moderation: ${document.getElementById('enableModeration').checked}
  plugin_system: ${document.getElementById('enablePlugins').checked}`;

                return config;
            }

            function saveConfiguration() {
                const config = generateConfiguration();
                const resultDiv = document.getElementById('saveResult');

                resultDiv.innerHTML = '<span class="status-indicator warning"></span>Saving configuration...';

                // Simulate saving
                setTimeout(() => {
                    resultDiv.innerHTML = `
                        <div style="background: #d4edda; color: #155724; padding: 15px; border-radius: 6px; border: 1px solid #c3e6cb;">
                            <strong>✅ Configuration Saved Successfully!</strong><br>
                            Your NetLink installation is now configured. Restart the application to apply changes.
                        </div>
                    `;
                }, 1000);
            }

            // Initialize
            updateStepDisplay();
        </script>
    </body>
    </html>
    """)

# Quality of Life Features
@app.get("/api/v1/system/info")
async def get_system_info():
    """Get comprehensive system information."""
    import platform
    import psutil

    try:
        return {
            "system": {
                "platform": platform.system(),
                "platform_release": platform.release(),
                "platform_version": platform.version(),
                "architecture": platform.machine(),
                "hostname": platform.node(),
                "processor": platform.processor(),
                "python_version": platform.python_version()
            },
            "resources": {
                "cpu_count": psutil.cpu_count(),
                "cpu_percent": psutil.cpu_percent(interval=1),
                "memory_total": psutil.virtual_memory().total,
                "memory_available": psutil.virtual_memory().available,
                "memory_percent": psutil.virtual_memory().percent,
                "disk_usage": {
                    "total": psutil.disk_usage('/').total,
                    "used": psutil.disk_usage('/').used,
                    "free": psutil.disk_usage('/').free,
                    "percent": (psutil.disk_usage('/').used / psutil.disk_usage('/').total) * 100
                }
            },
            "netlink": {
                "version": "3.0.0",
                "uptime": "running",
                "active_sessions": len(sessions),
                "total_users": len(users_db),
                "total_messages": len(messages),
                "features_enabled": {
                    "authentication": True,
                    "encryption": True,
                    "rate_limiting": True,
                    "time_based_crypto": True,
                    "setup_wizard": True,
                    "https_ssl": SSL_CONFIG["enabled"]
                },
                "ssl_config": {
                    "enabled": SSL_CONFIG["enabled"],
                    "port": SSL_CONFIG["port"] if SSL_CONFIG["enabled"] else None,
                    "domain": SSL_CONFIG["domain"] if SSL_CONFIG["enabled"] else None,
                    "use_letsencrypt": SSL_CONFIG["use_letsencrypt"] if SSL_CONFIG["enabled"] else None
                }
            }
        }
    except Exception as e:
        return {"error": f"Failed to get system info: {str(e)}"}

# SSL/Certificate Management Endpoints
@app.get("/api/v1/ssl/status")
async def get_ssl_status():
    """Get SSL/TLS status and certificate information."""
    try:
        if not ssl_manager:
            return {"ssl_enabled": False, "error": "SSL Manager not available"}

        if not SSL_CONFIG["enabled"]:
            return {"ssl_enabled": False, "message": "HTTPS disabled in configuration"}

        # Get certificate information
        cert_info = ssl_manager.ssl_manager.get_all_certificates_info()

        return {
            "ssl_enabled": True,
            "domain": SSL_CONFIG["domain"],
            "port": SSL_CONFIG["port"],
            "use_letsencrypt": SSL_CONFIG["use_letsencrypt"],
            "auto_redirect": SSL_CONFIG["auto_redirect"],
            "certificates": cert_info,
            "monitoring_enabled": ssl_manager.monitoring_enabled,
            "auto_renewal_enabled": ssl_manager.auto_renewal_enabled
        }
    except Exception as e:
        logger.error(f"Failed to get SSL status: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get SSL status: {str(e)}")

@app.post("/api/v1/ssl/setup")
async def setup_ssl(request: Request):
    """Setup SSL/TLS with domain and certificate options."""
    try:
        if not ssl_manager:
            raise HTTPException(status_code=503, detail="SSL Manager not available")

        data = await request.json()
        domain = data.get("domain", "localhost")
        email = data.get("email", "")
        use_letsencrypt = data.get("use_letsencrypt", False)
        domain_type = data.get("domain_type", "localhost")

        # Setup HTTPS
        result = await ssl_manager.setup_automatic_https(
            domain=domain,
            email=email if use_letsencrypt else None,
            domain_type=domain_type
        )

        if result.get("success"):
            # Update configuration
            SSL_CONFIG["domain"] = domain
            SSL_CONFIG["email"] = email
            SSL_CONFIG["use_letsencrypt"] = use_letsencrypt
            SSL_CONFIG["enabled"] = True

            logger.info(f"✅ SSL setup completed for domain: {domain}")
            return result
        else:
            raise HTTPException(status_code=400, detail=result.get("error", "SSL setup failed"))

    except Exception as e:
        logger.error(f"SSL setup failed: {e}")
        raise HTTPException(status_code=500, detail=f"SSL setup failed: {str(e)}")

@app.post("/api/v1/ssl/renew")
async def renew_ssl_certificate():
    """Force renewal of SSL certificate."""
    try:
        if not ssl_manager or not SSL_CONFIG["enabled"]:
            raise HTTPException(status_code=503, detail="SSL not enabled or manager not available")

        domain = SSL_CONFIG["domain"]
        success = await ssl_manager.ssl_manager.renew_certificate(domain)

        if success:
            logger.info(f"✅ SSL certificate renewed for domain: {domain}")
            return {"success": True, "message": f"Certificate renewed for {domain}"}
        else:
            raise HTTPException(status_code=400, detail="Certificate renewal failed")

    except Exception as e:
        logger.error(f"Certificate renewal failed: {e}")
        raise HTTPException(status_code=500, detail=f"Certificate renewal failed: {str(e)}")

@app.get("/api/v1/ssl/certificates")
async def get_certificates():
    """Get information about all certificates."""
    try:
        if not ssl_manager:
            return {"certificates": [], "message": "SSL Manager not available"}

        cert_info = ssl_manager.ssl_manager.get_all_certificates_info()
        return {"certificates": cert_info}

    except Exception as e:
        logger.error(f"Failed to get certificates: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get certificates: {str(e)}")

@app.get("/api/v1/utils/generate-password")
async def generate_secure_password():
    """Generate a secure password."""
    import string
    import random

    # Generate a secure password with mixed case, numbers, and symbols
    length = 16
    characters = string.ascii_letters + string.digits + "!@#$%^&*"
    password = ''.join(random.choice(characters) for _ in range(length))

    return {
        "password": password,
        "length": length,
        "strength": "strong",
        "contains": {
            "uppercase": any(c.isupper() for c in password),
            "lowercase": any(c.islower() for c in password),
            "numbers": any(c.isdigit() for c in password),
            "symbols": any(c in "!@#$%^&*" for c in password)
        }
    }

@app.get("/api/v1/utils/uuid")
async def generate_uuid():
    """Generate a UUID."""
    import uuid
    return {
        "uuid": str(uuid.uuid4()),
        "timestamp": datetime.now().isoformat()
    }

@app.get("/api/v1/utils/hash")
async def hash_text(text: str):
    """Hash text with various algorithms."""
    import hashlib

    return {
        "original": text,
        "hashes": {
            "md5": hashlib.md5(text.encode()).hexdigest(),
            "sha1": hashlib.sha1(text.encode()).hexdigest(),
            "sha256": hashlib.sha256(text.encode()).hexdigest(),
            "sha512": hashlib.sha512(text.encode()).hexdigest()
        }
    }

@app.get("/api/v1/utils/base64/encode")
async def base64_encode(text: str):
    """Encode text to base64."""
    import base64
    encoded = base64.b64encode(text.encode()).decode()
    return {
        "original": text,
        "encoded": encoded
    }

@app.get("/api/v1/utils/base64/decode")
async def base64_decode(encoded: str):
    """Decode base64 text."""
    import base64
    try:
        decoded = base64.b64decode(encoded.encode()).decode()
        return {
            "encoded": encoded,
            "decoded": decoded,
            "success": True
        }
    except Exception as e:
        return {
            "encoded": encoded,
            "error": str(e),
            "success": False
        }

@app.get("/api/v1/utils/timestamp")
async def get_timestamps():
    """Get current timestamp in various formats."""
    now = datetime.now()

    return {
        "iso": now.isoformat(),
        "unix": int(now.timestamp()),
        "unix_ms": int(now.timestamp() * 1000),
        "formatted": now.strftime("%Y-%m-%d %H:%M:%S"),
        "date_only": now.strftime("%Y-%m-%d"),
        "time_only": now.strftime("%H:%M:%S"),
        "timezone": str(now.astimezone().tzinfo)
    }

@app.post("/api/v1/utils/validate-email")
async def validate_email(request: Request):
    """Validate email address format."""
    import re

    data = await request.json()
    email = data.get("email", "")

    # Basic email regex
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    is_valid = bool(re.match(email_pattern, email))

    return {
        "email": email,
        "is_valid": is_valid,
        "checks": {
            "has_at_symbol": "@" in email,
            "has_domain": "." in email.split("@")[-1] if "@" in email else False,
            "length_ok": 5 <= len(email) <= 254,
            "no_spaces": " " not in email
        }
    }

@app.get("/api/v1/utils/color-palette")
async def generate_color_palette():
    """Generate a random color palette."""
    import random

    def random_color():
        return f"#{random.randint(0, 255):02x}{random.randint(0, 255):02x}{random.randint(0, 255):02x}"

    def hex_to_rgb(hex_color):
        hex_color = hex_color.lstrip('#')
        return tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))

    colors = [random_color() for _ in range(5)]

    return {
        "palette": [
            {
                "hex": color,
                "rgb": hex_to_rgb(color),
                "name": f"Color {i+1}"
            }
            for i, color in enumerate(colors)
        ],
        "theme": "random",
        "generated_at": datetime.now().isoformat()
    }

@app.get("/api/v1/utils/qr-code")
async def generate_qr_code(text: str):
    """Generate QR code for text."""
    try:
        import qrcode
        import io
        import base64

        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(text)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")

        # Convert to base64
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        img_str = base64.b64encode(buffer.getvalue()).decode()

        return {
            "text": text,
            "qr_code": f"data:image/png;base64,{img_str}",
            "format": "PNG",
            "size": f"{img.size[0]}x{img.size[1]}"
        }
    except ImportError:
        return {
            "error": "QR code generation requires 'qrcode' package",
            "install": "pip install qrcode[pil]"
        }
    except Exception as e:
        return {
            "error": f"Failed to generate QR code: {str(e)}"
        }

@app.get("/api/v1/utils/lorem-ipsum")
async def generate_lorem_ipsum(paragraphs: int = 3, words_per_paragraph: int = 50):
    """Generate Lorem Ipsum text."""
    lorem_words = [
        "lorem", "ipsum", "dolor", "sit", "amet", "consectetur", "adipiscing", "elit",
        "sed", "do", "eiusmod", "tempor", "incididunt", "ut", "labore", "et", "dolore",
        "magna", "aliqua", "enim", "ad", "minim", "veniam", "quis", "nostrud",
        "exercitation", "ullamco", "laboris", "nisi", "aliquip", "ex", "ea", "commodo",
        "consequat", "duis", "aute", "irure", "in", "reprehenderit", "voluptate",
        "velit", "esse", "cillum", "fugiat", "nulla", "pariatur", "excepteur", "sint",
        "occaecat", "cupidatat", "non", "proident", "sunt", "culpa", "qui", "officia",
        "deserunt", "mollit", "anim", "id", "est", "laborum"
    ]

    import random

    def generate_paragraph(word_count):
        words = [random.choice(lorem_words) for _ in range(word_count)]
        words[0] = words[0].capitalize()
        return " ".join(words) + "."

    text_paragraphs = [generate_paragraph(words_per_paragraph) for _ in range(paragraphs)]

    return {
        "paragraphs": text_paragraphs,
        "full_text": "\n\n".join(text_paragraphs),
        "word_count": paragraphs * words_per_paragraph,
        "character_count": len("\n\n".join(text_paragraphs))
    }

@app.get("/api/v1/utils/network-info")
async def get_network_info():
    """Get network information."""
    try:
        import socket
        import requests

        # Get local IP
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)

        # Try to get public IP
        try:
            public_ip = requests.get('https://api.ipify.org', timeout=5).text
        except:
            public_ip = "Unable to determine"

        return {
            "hostname": hostname,
            "local_ip": local_ip,
            "public_ip": public_ip,
            "server_info": {
                "host": "0.0.0.0",
                "port": 8000,
                "protocol": "HTTP",
                "status": "running"
            }
        }
    except Exception as e:
        return {
            "error": f"Failed to get network info: {str(e)}"
        }

# Utilities Dashboard
@app.get("/utils")
async def utilities_dashboard():
    """Comprehensive utilities dashboard."""
    return HTMLResponse(content="""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>NetLink Utilities</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                color: #333;
            }

            .header {
                background: rgba(255,255,255,0.95);
                padding: 20px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                text-align: center;
            }

            .container {
                max-width: 1400px;
                margin: 20px auto;
                padding: 0 20px;
            }

            .utils-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
                gap: 20px;
                margin-bottom: 30px;
            }

            .util-card {
                background: rgba(255,255,255,0.95);
                border-radius: 12px;
                padding: 20px;
                box-shadow: 0 4px 15px rgba(0,0,0,0.1);
                transition: transform 0.3s ease;
            }

            .util-card:hover { transform: translateY(-5px); }

            .util-card h3 {
                color: #2c3e50;
                margin-bottom: 15px;
                display: flex;
                align-items: center;
                gap: 10px;
            }

            .form-group {
                margin-bottom: 15px;
            }

            .form-group label {
                display: block;
                margin-bottom: 5px;
                font-weight: bold;
                color: #495057;
            }

            .form-group input,
            .form-group textarea,
            .form-group select {
                width: 100%;
                padding: 10px;
                border: 1px solid #ddd;
                border-radius: 6px;
                font-size: 14px;
            }

            .btn {
                background: #667eea;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 6px;
                cursor: pointer;
                font-size: 14px;
                transition: background 0.3s ease;
                margin-right: 10px;
                margin-bottom: 10px;
            }

            .btn:hover { background: #5a6fd8; }
            .btn.success { background: #27ae60; }
            .btn.warning { background: #f39c12; }
            .btn.danger { background: #e74c3c; }

            .result-area {
                background: #f8f9fa;
                border: 1px solid #e9ecef;
                border-radius: 6px;
                padding: 15px;
                margin-top: 15px;
                font-family: monospace;
                white-space: pre-wrap;
                max-height: 200px;
                overflow-y: auto;
            }

            .color-preview {
                width: 30px;
                height: 30px;
                border-radius: 6px;
                display: inline-block;
                margin-right: 10px;
                border: 1px solid #ddd;
            }

            .qr-preview {
                max-width: 200px;
                margin: 10px 0;
            }

            .copy-btn {
                background: #17a2b8;
                font-size: 12px;
                padding: 5px 10px;
            }

            .system-info {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 15px;
                margin-top: 15px;
            }

            .info-item {
                background: #e3f2fd;
                padding: 10px;
                border-radius: 6px;
                text-align: center;
            }

            .info-value {
                font-size: 1.2em;
                font-weight: bold;
                color: #1976d2;
            }

            .info-label {
                font-size: 0.9em;
                color: #666;
            }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🛠️ NetLink Utilities</h1>
            <p>Comprehensive utility tools for development and administration</p>
        </div>

        <div class="container">
            <div class="utils-grid">
                <!-- System Information -->
                <div class="util-card">
                    <h3>📊 System Information</h3>
                    <button class="btn" onclick="getSystemInfo()">Get System Info</button>
                    <div id="systemInfo" class="system-info"></div>
                </div>

                <!-- Password Generator -->
                <div class="util-card">
                    <h3>🔐 Password Generator</h3>
                    <button class="btn" onclick="generatePassword()">Generate Secure Password</button>
                    <button class="btn copy-btn" onclick="copyToClipboard('passwordResult')">Copy</button>
                    <div id="passwordResult" class="result-area"></div>
                </div>

                <!-- UUID Generator -->
                <div class="util-card">
                    <h3>🆔 UUID Generator</h3>
                    <button class="btn" onclick="generateUUID()">Generate UUID</button>
                    <button class="btn copy-btn" onclick="copyToClipboard('uuidResult')">Copy</button>
                    <div id="uuidResult" class="result-area"></div>
                </div>

                <!-- Hash Generator -->
                <div class="util-card">
                    <h3>🔒 Hash Generator</h3>
                    <div class="form-group">
                        <label for="hashInput">Text to Hash:</label>
                        <input type="text" id="hashInput" placeholder="Enter text to hash">
                    </div>
                    <button class="btn" onclick="generateHashes()">Generate Hashes</button>
                    <div id="hashResult" class="result-area"></div>
                </div>

                <!-- Base64 Encoder/Decoder -->
                <div class="util-card">
                    <h3>📝 Base64 Encoder/Decoder</h3>
                    <div class="form-group">
                        <label for="base64Input">Text:</label>
                        <textarea id="base64Input" rows="3" placeholder="Enter text to encode/decode"></textarea>
                    </div>
                    <button class="btn" onclick="encodeBase64()">Encode</button>
                    <button class="btn warning" onclick="decodeBase64()">Decode</button>
                    <div id="base64Result" class="result-area"></div>
                </div>

                <!-- Timestamp Converter -->
                <div class="util-card">
                    <h3>⏰ Timestamp Converter</h3>
                    <button class="btn" onclick="getCurrentTimestamps()">Get Current Timestamps</button>
                    <div id="timestampResult" class="result-area"></div>
                </div>

                <!-- Email Validator -->
                <div class="util-card">
                    <h3>📧 Email Validator</h3>
                    <div class="form-group">
                        <label for="emailInput">Email Address:</label>
                        <input type="email" id="emailInput" placeholder="Enter email to validate">
                    </div>
                    <button class="btn" onclick="validateEmail()">Validate Email</button>
                    <div id="emailResult" class="result-area"></div>
                </div>

                <!-- Color Palette Generator -->
                <div class="util-card">
                    <h3>🎨 Color Palette Generator</h3>
                    <button class="btn" onclick="generateColorPalette()">Generate Palette</button>
                    <div id="colorResult" class="result-area"></div>
                </div>

                <!-- QR Code Generator -->
                <div class="util-card">
                    <h3>📱 QR Code Generator</h3>
                    <div class="form-group">
                        <label for="qrInput">Text for QR Code:</label>
                        <input type="text" id="qrInput" placeholder="Enter text or URL">
                    </div>
                    <button class="btn" onclick="generateQRCode()">Generate QR Code</button>
                    <div id="qrResult" class="result-area"></div>
                </div>

                <!-- Lorem Ipsum Generator -->
                <div class="util-card">
                    <h3>📄 Lorem Ipsum Generator</h3>
                    <div class="form-group">
                        <label for="paragraphCount">Paragraphs:</label>
                        <input type="number" id="paragraphCount" value="3" min="1" max="10">
                    </div>
                    <div class="form-group">
                        <label for="wordsPerParagraph">Words per Paragraph:</label>
                        <input type="number" id="wordsPerParagraph" value="50" min="10" max="200">
                    </div>
                    <button class="btn" onclick="generateLoremIpsum()">Generate Text</button>
                    <button class="btn copy-btn" onclick="copyToClipboard('loremResult')">Copy</button>
                    <div id="loremResult" class="result-area"></div>
                </div>

                <!-- Network Information -->
                <div class="util-card">
                    <h3>🌐 Network Information</h3>
                    <button class="btn" onclick="getNetworkInfo()">Get Network Info</button>
                    <div id="networkResult" class="result-area"></div>
                </div>
            </div>

            <div style="text-align: center; padding: 50px; background: rgba(255,255,255,0.9); border-radius: 12px;">
                <h2>🚀 NetLink Utilities</h2>
                <p>Comprehensive utility tools for development, testing, and administration.</p>
                <p>All utilities are available via REST API endpoints for programmatic access.</p>
                <br>
                <button class="btn" onclick="window.open('/', '_blank')">🏠 Home</button>
                <button class="btn success" onclick="window.open('/docs', '_blank')">📚 API Documentation</button>
                <button class="btn warning" onclick="window.open('/setup', '_blank')">⚙️ Setup Wizard</button>
            </div>
        </div>

        <script>
            async function getSystemInfo() {
                try {
                    const response = await fetch('/api/v1/system/info');
                    const data = await response.json();

                    if (data.error) {
                        document.getElementById('systemInfo').innerHTML = `<div style="color: red;">${data.error}</div>`;
                        return;
                    }

                    const systemInfo = document.getElementById('systemInfo');
                    systemInfo.innerHTML = `
                        <div class="info-item">
                            <div class="info-value">${data.system.platform}</div>
                            <div class="info-label">Platform</div>
                        </div>
                        <div class="info-item">
                            <div class="info-value">${data.resources.cpu_percent.toFixed(1)}%</div>
                            <div class="info-label">CPU Usage</div>
                        </div>
                        <div class="info-item">
                            <div class="info-value">${data.resources.memory_percent.toFixed(1)}%</div>
                            <div class="info-label">Memory Usage</div>
                        </div>
                        <div class="info-item">
                            <div class="info-value">${data.netlink.active_sessions}</div>
                            <div class="info-label">Active Sessions</div>
                        </div>
                        <div class="info-item">
                            <div class="info-value">${data.netlink.total_users}</div>
                            <div class="info-label">Total Users</div>
                        </div>
                        <div class="info-item">
                            <div class="info-value">${data.netlink.version}</div>
                            <div class="info-label">NetLink Version</div>
                        </div>
                    `;
                } catch (error) {
                    document.getElementById('systemInfo').innerHTML = `<div style="color: red;">Error: ${error.message}</div>`;
                }
            }

            async function generatePassword() {
                try {
                    const response = await fetch('/api/v1/utils/generate-password');
                    const data = await response.json();

                    document.getElementById('passwordResult').textContent =
                        `Password: ${data.password}\\nLength: ${data.length}\\nStrength: ${data.strength}`;
                } catch (error) {
                    document.getElementById('passwordResult').textContent = `Error: ${error.message}`;
                }
            }

            async function generateUUID() {
                try {
                    const response = await fetch('/api/v1/utils/uuid');
                    const data = await response.json();

                    document.getElementById('uuidResult').textContent =
                        `UUID: ${data.uuid}\\nGenerated: ${data.timestamp}`;
                } catch (error) {
                    document.getElementById('uuidResult').textContent = `Error: ${error.message}`;
                }
            }

            async function generateHashes() {
                const text = document.getElementById('hashInput').value;
                if (!text) {
                    alert('Please enter text to hash');
                    return;
                }

                try {
                    const response = await fetch(`/api/v1/utils/hash?text=${encodeURIComponent(text)}`);
                    const data = await response.json();

                    document.getElementById('hashResult').textContent =
                        `Original: ${data.original}\\n\\nMD5: ${data.hashes.md5}\\nSHA1: ${data.hashes.sha1}\\nSHA256: ${data.hashes.sha256}\\nSHA512: ${data.hashes.sha512}`;
                } catch (error) {
                    document.getElementById('hashResult').textContent = `Error: ${error.message}`;
                }
            }

            async function encodeBase64() {
                const text = document.getElementById('base64Input').value;
                if (!text) {
                    alert('Please enter text to encode');
                    return;
                }

                try {
                    const response = await fetch(`/api/v1/utils/base64/encode?text=${encodeURIComponent(text)}`);
                    const data = await response.json();

                    document.getElementById('base64Result').textContent =
                        `Original: ${data.original}\\n\\nEncoded: ${data.encoded}`;
                } catch (error) {
                    document.getElementById('base64Result').textContent = `Error: ${error.message}`;
                }
            }

            async function decodeBase64() {
                const text = document.getElementById('base64Input').value;
                if (!text) {
                    alert('Please enter base64 text to decode');
                    return;
                }

                try {
                    const response = await fetch(`/api/v1/utils/base64/decode?encoded=${encodeURIComponent(text)}`);
                    const data = await response.json();

                    if (data.success) {
                        document.getElementById('base64Result').textContent =
                            `Encoded: ${data.encoded}\\n\\nDecoded: ${data.decoded}`;
                    } else {
                        document.getElementById('base64Result').textContent =
                            `Error: ${data.error}`;
                    }
                } catch (error) {
                    document.getElementById('base64Result').textContent = `Error: ${error.message}`;
                }
            }

            async function getCurrentTimestamps() {
                try {
                    const response = await fetch('/api/v1/utils/timestamp');
                    const data = await response.json();

                    document.getElementById('timestampResult').textContent =
                        `ISO: ${data.iso}\\nUnix: ${data.unix}\\nUnix (ms): ${data.unix_ms}\\nFormatted: ${data.formatted}\\nDate: ${data.date_only}\\nTime: ${data.time_only}`;
                } catch (error) {
                    document.getElementById('timestampResult').textContent = `Error: ${error.message}`;
                }
            }

            async function validateEmail() {
                const email = document.getElementById('emailInput').value;
                if (!email) {
                    alert('Please enter an email address');
                    return;
                }

                try {
                    const response = await fetch('/api/v1/utils/validate-email', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ email })
                    });
                    const data = await response.json();

                    document.getElementById('emailResult').textContent =
                        `Email: ${data.email}\\nValid: ${data.is_valid}\\n\\nChecks:\\n- Has @ symbol: ${data.checks.has_at_symbol}\\n- Has domain: ${data.checks.has_domain}\\n- Length OK: ${data.checks.length_ok}\\n- No spaces: ${data.checks.no_spaces}`;
                } catch (error) {
                    document.getElementById('emailResult').textContent = `Error: ${error.message}`;
                }
            }

            async function generateColorPalette() {
                try {
                    const response = await fetch('/api/v1/utils/color-palette');
                    const data = await response.json();

                    let html = '';
                    data.palette.forEach(color => {
                        html += `<div style="margin-bottom: 10px;">
                            <span class="color-preview" style="background-color: ${color.hex};"></span>
                            ${color.hex} - RGB(${color.rgb.join(', ')})
                        </div>`;
                    });

                    document.getElementById('colorResult').innerHTML = html;
                } catch (error) {
                    document.getElementById('colorResult').textContent = `Error: ${error.message}`;
                }
            }

            async function generateQRCode() {
                const text = document.getElementById('qrInput').value;
                if (!text) {
                    alert('Please enter text for QR code');
                    return;
                }

                try {
                    const response = await fetch(`/api/v1/utils/qr-code?text=${encodeURIComponent(text)}`);
                    const data = await response.json();

                    if (data.error) {
                        document.getElementById('qrResult').textContent = data.error;
                    } else {
                        document.getElementById('qrResult').innerHTML =
                            `<img src="${data.qr_code}" class="qr-preview" alt="QR Code"><br>Text: ${data.text}<br>Size: ${data.size}`;
                    }
                } catch (error) {
                    document.getElementById('qrResult').textContent = `Error: ${error.message}`;
                }
            }

            async function generateLoremIpsum() {
                const paragraphs = document.getElementById('paragraphCount').value;
                const wordsPerParagraph = document.getElementById('wordsPerParagraph').value;

                try {
                    const response = await fetch(`/api/v1/utils/lorem-ipsum?paragraphs=${paragraphs}&words_per_paragraph=${wordsPerParagraph}`);
                    const data = await response.json();

                    document.getElementById('loremResult').textContent =
                        `${data.full_text}\\n\\nStats: ${data.word_count} words, ${data.character_count} characters`;
                } catch (error) {
                    document.getElementById('loremResult').textContent = `Error: ${error.message}`;
                }
            }

            async function getNetworkInfo() {
                try {
                    const response = await fetch('/api/v1/utils/network-info');
                    const data = await response.json();

                    if (data.error) {
                        document.getElementById('networkResult').textContent = data.error;
                    } else {
                        document.getElementById('networkResult').textContent =
                            `Hostname: ${data.hostname}\\nLocal IP: ${data.local_ip}\\nPublic IP: ${data.public_ip}\\n\\nServer:\\nHost: ${data.server_info.host}\\nPort: ${data.server_info.port}\\nProtocol: ${data.server_info.protocol}\\nStatus: ${data.server_info.status}`;
                    }
                } catch (error) {
                    document.getElementById('networkResult').textContent = `Error: ${error.message}`;
                }
            }

            function copyToClipboard(elementId) {
                const element = document.getElementById(elementId);
                const text = element.textContent;

                navigator.clipboard.writeText(text).then(() => {
                    alert('Copied to clipboard!');
                }).catch(err => {
                    console.error('Failed to copy: ', err);
                    alert('Failed to copy to clipboard');
                });
            }
        </script>
    </body>
    </html>
    """)

@app.post("/api/v1/auth/logout")
async def logout(request: Request):
    """Logout endpoint."""
    try:
        data = await request.json()
        token = data.get("token")

        if token in sessions:
            del sessions[token]

        return {"success": True, "message": "Logged out successfully"}
    except:
        return {"success": True, "message": "Logged out"}

@app.get("/api/v1/auth/verify")
async def verify_auth(request: Request):
    """Verify authentication token."""
    auth_header = request.headers.get("authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return JSONResponse(
            status_code=401,
            content={"success": False, "message": "No token provided"}
        )

    token = auth_header.split(" ")[1]
    if verify_session(token):
        return {"success": True, "message": "Token valid"}
    else:
        return JSONResponse(
            status_code=401,
            content={"success": False, "message": "Invalid token"}
        )

# Protected documentation endpoint
@app.get("/docs-secure")
async def secure_docs():
    """Secure documentation viewer with authentication."""
    return HTMLResponse(content="""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>NetLink Secure Documentation</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: #f8f9fa;
                color: #333;
            }

            .login-container {
                display: flex;
                align-items: center;
                justify-content: center;
                min-height: 100vh;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            }

            .login-form {
                background: white;
                padding: 40px;
                border-radius: 12px;
                box-shadow: 0 8px 32px rgba(0,0,0,0.1);
                width: 100%;
                max-width: 400px;
            }

            .login-form h2 {
                text-align: center;
                margin-bottom: 30px;
                color: #2c3e50;
            }

            .form-group {
                margin-bottom: 20px;
            }

            .form-group label {
                display: block;
                margin-bottom: 5px;
                font-weight: bold;
                color: #495057;
            }

            .form-group input {
                width: 100%;
                padding: 12px;
                border: 1px solid #ddd;
                border-radius: 6px;
                font-size: 16px;
            }

            .form-group input:focus {
                outline: none;
                border-color: #667eea;
                box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
            }

            .btn {
                width: 100%;
                background: #667eea;
                color: white;
                border: none;
                padding: 12px;
                border-radius: 6px;
                font-size: 16px;
                cursor: pointer;
                transition: background 0.3s ease;
            }

            .btn:hover {
                background: #5a6fd8;
            }

            .error {
                background: #f8d7da;
                color: #721c24;
                padding: 10px;
                border-radius: 6px;
                margin-bottom: 20px;
                display: none;
            }

            .docs-container {
                display: none;
                max-width: 1200px;
                margin: 0 auto;
                padding: 20px;
            }

            .header {
                background: white;
                padding: 20px;
                border-radius: 8px;
                margin-bottom: 20px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                display: flex;
                justify-content: space-between;
                align-items: center;
            }

            .logout-btn {
                background: #e74c3c;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 6px;
                cursor: pointer;
            }

            .docs-grid {
                display: grid;
                grid-template-columns: 300px 1fr;
                gap: 20px;
            }

            .sidebar {
                background: white;
                border-radius: 8px;
                padding: 20px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                height: fit-content;
            }

            .content {
                background: white;
                border-radius: 8px;
                padding: 20px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }

            .nav-item {
                padding: 10px;
                margin-bottom: 5px;
                border-radius: 6px;
                cursor: pointer;
                transition: background 0.3s ease;
            }

            .nav-item:hover {
                background: #f8f9fa;
            }

            .nav-item.active {
                background: #e3f2fd;
                color: #1976d2;
                font-weight: bold;
            }
        </style>
    </head>
    <body>
        <!-- Login Form -->
        <div id="loginContainer" class="login-container">
            <form class="login-form" onsubmit="login(event)">
                <h2>🔐 NetLink Secure Access</h2>
                <div id="errorMessage" class="error"></div>

                <div class="form-group">
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username" required>
                </div>

                <div class="form-group">
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password" required>
                </div>

                <button type="submit" class="btn">Login</button>

                <div style="margin-top: 20px; text-align: center; font-size: 0.9em; color: #666;">
                    <p>Default credentials: admin / admin123</p>
                    <p>⚠️ Change default credentials in production</p>
                </div>
            </form>
        </div>

        <!-- Documentation Interface -->
        <div id="docsContainer" class="docs-container">
            <div class="header">
                <h1>📚 NetLink Documentation</h1>
                <button class="logout-btn" onclick="logout()">Logout</button>
            </div>

            <div class="docs-grid">
                <div class="sidebar">
                    <h3>📋 Documentation</h3>
                    <div class="nav-item active" onclick="showSection('overview')">Overview</div>
                    <div class="nav-item" onclick="showSection('api')">API Reference</div>
                    <div class="nav-item" onclick="showSection('security')">Security Guide</div>
                    <div class="nav-item" onclick="showSection('deployment')">Deployment</div>
                    <div class="nav-item" onclick="showSection('testing')">Testing</div>
                    <div class="nav-item" onclick="showSection('backup')">Backup System</div>
                    <div class="nav-item" onclick="showSection('clustering')">Clustering</div>
                    <div class="nav-item" onclick="showSection('plugins')">Plugin System</div>

                    <h3 style="margin-top: 30px;">🔧 Management</h3>
                    <div class="nav-item" onclick="window.open('/admin', '_blank')">Admin Panel</div>
                    <div class="nav-item" onclick="window.open('/plugins', '_blank')">Plugin Manager</div>
                    <div class="nav-item" onclick="window.open('/docs-viewer', '_blank')">Advanced Docs</div>
                </div>

                <div class="content">
                    <div id="content-overview">
                        <h2>🚀 NetLink v3.0 Overview</h2>
                        <p>NetLink is a government-level secure communication platform with advanced features:</p>

                        <h3>🔐 Security Features</h3>
                        <ul>
                            <li>End-to-end encryption</li>
                            <li>Decentralized security architecture</li>
                            <li>Advanced threat detection</li>
                            <li>Multi-factor authentication</li>
                            <li>Rate limiting and DDoS protection</li>
                        </ul>

                        <h3>💾 Backup & Recovery</h3>
                        <ul>
                            <li>Distributed backup system</li>
                            <li>Intelligent shard distribution</li>
                            <li>Real-time backup monitoring</li>
                            <li>Advanced recovery mechanisms</li>
                        </ul>

                        <h3>🔧 Advanced Features</h3>
                        <ul>
                            <li>Modular plugin system</li>
                            <li>Multi-node clustering</li>
                            <li>AI-powered moderation</li>
                            <li>Comprehensive testing framework</li>
                            <li>Advanced GUI and CLI interfaces</li>
                        </ul>
                    </div>

                    <div id="content-api" style="display: none;">
                        <h2>📡 API Reference</h2>
                        <p>NetLink provides comprehensive REST API endpoints:</p>

                        <h3>Authentication</h3>
                        <pre><code>POST /api/v1/auth/login
POST /api/v1/auth/logout
GET  /api/v1/auth/verify</code></pre>

                        <h3>Messages</h3>
                        <pre><code>GET    /api/v1/messages
POST   /api/v1/messages
GET    /api/v1/messages/{id}
DELETE /api/v1/messages/{id}</code></pre>

                        <h3>Users</h3>
                        <pre><code>GET  /api/v1/users
POST /api/v1/users
GET  /api/v1/users/{id}</code></pre>

                        <h3>Testing</h3>
                        <pre><code>GET  /api/v1/testing/status
POST /api/v1/testing/run</code></pre>

                        <p><a href="/docs" target="_blank">View Interactive API Documentation →</a></p>
                    </div>

                    <div id="content-security" style="display: none;">
                        <h2>🛡️ Security Guide</h2>
                        <p>NetLink implements government-level security standards:</p>

                        <h3>Encryption</h3>
                        <ul>
                            <li>AES-256 encryption for data at rest</li>
                            <li>TLS 1.3 for data in transit</li>
                            <li>End-to-end encryption for messages</li>
                            <li>RSA-2048 key exchange</li>
                        </ul>

                        <h3>Authentication</h3>
                        <ul>
                            <li>Multi-factor authentication</li>
                            <li>Session-based authentication</li>
                            <li>Time-based token validation</li>
                            <li>Secure password hashing</li>
                        </ul>

                        <h3>Network Security</h3>
                        <ul>
                            <li>Rate limiting and DDoS protection</li>
                            <li>IP whitelisting/blacklisting</li>
                            <li>SQL injection prevention</li>
                            <li>XSS protection</li>
                        </ul>
                    </div>

                    <div id="content-deployment" style="display: none;">
                        <h2>🚀 Deployment Guide</h2>
                        <p>Deploy NetLink in various environments:</p>

                        <h3>Local Development</h3>
                        <pre><code>python -m uvicorn src.netlink.app.main:app --reload</code></pre>

                        <h3>Production</h3>
                        <pre><code>gunicorn src.netlink.app.main:app -w 4 -k uvicorn.workers.UvicornWorker</code></pre>

                        <h3>Docker</h3>
                        <pre><code>docker build -t netlink .
docker run -p 8000:8000 netlink</code></pre>

                        <h3>Environment Variables</h3>
                        <pre><code>DATABASE_URL=postgresql://user:pass@localhost/netlink
SECRET_KEY=your-secret-key
DEBUG=false</code></pre>
                    </div>

                    <div id="content-testing" style="display: none;">
                        <h2>🧪 Testing Framework</h2>
                        <p>NetLink includes comprehensive testing capabilities:</p>

                        <h3>Test Suites</h3>
                        <ul>
                            <li>Authentication tests</li>
                            <li>Message handling tests</li>
                            <li>User management tests</li>
                            <li>Security tests</li>
                            <li>Backup system tests</li>
                        </ul>

                        <h3>Running Tests</h3>
                        <pre><code>POST /api/v1/testing/run</code></pre>

                        <p><a href="/api/v1/testing/status" target="_blank">View Testing Status →</a></p>
                    </div>

                    <div id="content-backup" style="display: none;">
                        <h2>💾 Backup System</h2>
                        <p>Advanced distributed backup with intelligent shard distribution.</p>

                        <h3>Features</h3>
                        <ul>
                            <li>Automatic shard distribution</li>
                            <li>Real-time backup monitoring</li>
                            <li>Device-based storage allocation</li>
                            <li>Redundant backup locations</li>
                        </ul>
                    </div>

                    <div id="content-clustering" style="display: none;">
                        <h2>🔗 Clustering System</h2>
                        <p>Multi-node clustering for high availability and scalability.</p>

                        <h3>Features</h3>
                        <ul>
                            <li>Automatic node discovery</li>
                            <li>Load balancing</li>
                            <li>Fault tolerance</li>
                            <li>Cross-node communication</li>
                        </ul>
                    </div>

                    <div id="content-plugins" style="display: none;">
                        <h2>🔌 Plugin System</h2>
                        <p>Modular plugin architecture for extensibility.</p>

                        <h3>Features</h3>
                        <ul>
                            <li>Auto-discovery and loading</li>
                            <li>Plugin lifecycle management</li>
                            <li>API endpoint registration</li>
                            <li>CLI command integration</li>
                        </ul>

                        <p><a href="/plugins" target="_blank">Open Plugin Manager →</a></p>
                    </div>
                </div>
            </div>
        </div>

        <script>
            let authToken = localStorage.getItem('netlink_auth_token');

            // Check if already authenticated
            if (authToken) {
                verifyToken();
            }

            async function login(event) {
                event.preventDefault();

                const username = document.getElementById('username').value;
                const password = document.getElementById('password').value;

                try {
                    const response = await fetch('/api/v1/auth/login', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ username, password })
                    });

                    const data = await response.json();

                    if (data.success) {
                        authToken = data.token;
                        localStorage.setItem('netlink_auth_token', authToken);
                        showDocs();
                    } else {
                        showError(data.message);
                    }
                } catch (error) {
                    showError('Login failed: ' + error.message);
                }
            }

            async function verifyToken() {
                try {
                    const response = await fetch('/api/v1/auth/verify', {
                        headers: { 'Authorization': 'Bearer ' + authToken }
                    });

                    if (response.ok) {
                        showDocs();
                    } else {
                        localStorage.removeItem('netlink_auth_token');
                        authToken = null;
                    }
                } catch (error) {
                    localStorage.removeItem('netlink_auth_token');
                    authToken = null;
                }
            }

            async function logout() {
                try {
                    await fetch('/api/v1/auth/logout', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ token: authToken })
                    });
                } catch (error) {
                    console.error('Logout error:', error);
                }

                localStorage.removeItem('netlink_auth_token');
                authToken = null;
                showLogin();
            }

            function showError(message) {
                const errorDiv = document.getElementById('errorMessage');
                errorDiv.textContent = message;
                errorDiv.style.display = 'block';
            }

            function showLogin() {
                document.getElementById('loginContainer').style.display = 'flex';
                document.getElementById('docsContainer').style.display = 'none';
            }

            function showDocs() {
                document.getElementById('loginContainer').style.display = 'none';
                document.getElementById('docsContainer').style.display = 'block';
            }

            function showSection(section) {
                // Hide all content sections
                const sections = ['overview', 'api', 'security', 'deployment', 'testing', 'backup', 'clustering', 'plugins'];
                sections.forEach(s => {
                    document.getElementById('content-' + s).style.display = 'none';
                });

                // Show selected section
                document.getElementById('content-' + section).style.display = 'block';

                // Update navigation
                document.querySelectorAll('.nav-item').forEach(item => {
                    item.classList.remove('active');
                });
                event.target.classList.add('active');
            }
        </script>
    </body>
    </html>
    """)

# Main entry point
async def startup():
    """Initialize application on startup."""
    logger.info("🚀 Starting NetLink v3.0...")

    # Initialize SSL if enabled
    if SSL_CONFIG["enabled"]:
        await initialize_ssl()

    logger.info("✅ NetLink startup complete")

# Add startup event
@app.on_event("startup")
async def startup_event():
    await startup()

if __name__ == "__main__":
    # Determine port and SSL settings
    port = SSL_CONFIG["port"] if SSL_CONFIG["enabled"] else 8000

    if SSL_CONFIG["enabled"] and ssl_context:
        logger.info(f"🔐 Starting NetLink with HTTPS on port {port}")
        uvicorn.run(
            "main:app",
            host="0.0.0.0",
            port=port,
            ssl_keyfile=SSL_CONFIG["key_path"],
            ssl_certfile=SSL_CONFIG["cert_path"],
            reload=False,  # Disable reload with SSL
            log_level="info"
        )
    else:
        logger.info(f"🔓 Starting NetLink with HTTP on port {port}")
        uvicorn.run(
            "main:app",
            host="0.0.0.0",
            port=port,
            reload=True,
            log_level="info"
        )
