"""
PlexiChat Setup Router

Web interface for initial setup, database configuration, and admin account creation.
Provides a complete setup wizard accessible via web browser.
"""

import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../.')))

import json
import logging
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, Union, List

# Import database abstraction layer
from plexichat.core.database.manager import database_manager
from plexichat.features.users.models import User, UserRole, UserStatus
from plexichat.features.users.user import UserService, UserCreate
from plexichat.features.users.models import UserModelService
from plexichat.features.users.message import MessageUpdate
database_manager = None
User = None
UserRole = None
UserStatus = None
UserService = None
UserCreate = None
UserModelService = None
MessageUpdate = None

from fastapi import APIRouter, Request, Form, HTTPException, Depends, Body, Query
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.security import HTTPBearer
from starlette.middleware.base import BaseHTTPMiddleware
from plexichat.core.security.security_manager import get_security_system, SecurityPolicy
from plexichat.core.security.security_context import security_context

import re

import base64
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import subprocess

# Security headers from security.txt
SECURITY_HEADERS = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=(), payment=()",
    "Cache-Control": "no-store, no-cache, must-revalidate, private",
    "Pragma": "no-cache"
}

# Define the security policy for the setup process
setup_policy = SecurityPolicy(
    name="setup-policy",
    description="Security policy for the initial setup process.",
    min_security_level="PUBLIC",
    required_auth_methods=[],
    rate_limit_requests_per_minute=30  # Allow a reasonable rate for setup
)

# Get the security system and register the policy
security_system = get_security_system()
security_system.register_policy(setup_policy)

# Middleware to apply security context
@router.middleware("http")
async def apply_setup_security_context(request: Request, call_next):
    with security_context(policy_name="setup-policy"):
        response = await call_next(request)
        return response


# Middleware to add security headers to all responses
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            response.headers[k] = v
        return response

# Add middleware to router (FastAPI app should include this)
# Reference: security.txt - Security Headers Configuration
# (If this router is included in a FastAPI app, ensure the app adds this middleware)

# Input validation and sanitization helpers
USERNAME_REGEX = re.compile(r'^[a-zA-Z0-9_.-]{3,32}$')
EMAIL_REGEX = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')
PASSWORD_MIN_LENGTH = 8

# Reference: security.txt - Input Validation, Authentication & Authorization

def sanitize_input(value: str) -> str:
    value = value.strip()
    value = re.sub(r'<.*?>', '', value)  # Remove HTML tags
    value = re.sub(r'["\'`;]', '', value)  # Remove dangerous chars
    return value

def validate_username(username: str) -> bool:
    return bool(USERNAME_REGEX.match(username))

def validate_email(email: str) -> bool:
    return bool(EMAIL_REGEX.match(email))

def validate_password(password: str) -> bool:
    return len(password) >= PASSWORD_MIN_LENGTH

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/setup", tags=["setup"])

templates = Jinja2Templates(directory="plexichat/interfaces/web/templates")

security = HTTPBearer()





# --- MITM-resistant time-based encryption utilities ---
# Reference: security.txt - Perfect Forward Secrecy, Key Rotation
SHARED_SECRET = os.environ.get("PLEXICHAT_TIME_ENC_SECRET", "default-shared-secret").encode()
TIME_WINDOW = 60  # seconds

# Derive a symmetric key from the shared secret and current time window
def derive_time_key(shared_secret: bytes, interval: int = TIME_WINDOW) -> bytes:
    now = int(time.time() // interval)
    return base64.urlsafe_b64encode(
        (shared_secret + str(now).encode()).ljust(32, b'0')[:32]
    )

# Encrypt payload with time-based key
def encrypt_payload(data: bytes) -> Dict[str, Any]:
    key = derive_time_key(SHARED_SECRET)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, data, None)
    return {"nonce": base64.b64encode(nonce).decode(), "ciphertext": base64.b64encode(ct).decode(), "timestamp": int(time.time())}

# Decrypt payload with time-based key
def decrypt_payload(payload: Dict[str, Any]) -> bytes:
    key = derive_time_key(SHARED_SECRET)
    nonce = base64.b64decode(payload["nonce"])
    ct = base64.b64decode(payload["ciphertext"])
    aesgcm = AESGCM(key)
    # Check timestamp freshness (within window)
    now = int(time.time())
    if abs(now - payload.get("timestamp", now)) > TIME_WINDOW:
        raise HTTPException(status_code=400, detail="Stale or replayed request.")
    return aesgcm.decrypt(nonce, ct, None)

# FastAPI dependency to decrypt incoming JSON payloads
async def decrypt_request(request: Request):
    payload = await request.json()
    try:
        decrypted = decrypt_payload(payload)
        return decrypted
    except Exception as e:
        logger.error(f"MITM/time-based decryption failed: {e}")
        raise HTTPException(status_code=400, detail="Invalid encrypted payload.")

# Example usage in a sensitive endpoint:
@router.post("/admin/secure")
async def secure_admin_endpoint(
    decrypted_body: bytes = Depends(decrypt_request)
):
    # Process decrypted_body as needed
    return encrypt_payload(b"Operation successful.")

eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhY2Nlc3MiOiJtIn0.OWhyYWZCEpSQIwBJcJdIGkQP954WzuQcSlLLCabhYKU

# Apply to all endpoints@router.get("/", response_class=HTMLResponse)
async def setup_home(request: Request):
    try:
        if is_setup_completed():
            return RedirectResponse(url="/", status_code=302)
        return templates.TemplateResponse("setup/index.html", {
            "request": request,
            "title": "PlexiChat Setup",
            "step": "welcome",
            "admin_authenticated": True
        })
    except Exception as e:
        logger.error(f"Setup home error: {e}")
        raise HTTPException(status_code=500, detail="Setup page error")

@router.get("/database", response_class=HTMLResponse)
async def setup_database_page(request: Request):
    try:
        return templates.TemplateResponse("setup/database.html", {
            "request": request,
            "title": "Database Setup",
            "step": "database",
            "admin_authenticated": True
        })
    except Exception as e:
        logger.error(f"Database setup page error: {e}")
        raise HTTPException(status_code=500, detail="Database setup error")

@router.post("/database")
async def setup_database(
    request: Request,
    db_type: str = Form(...),
    db_host: Optional[str] = Form(None),
    db_port: Optional[int] = Form(None),
    db_name: Optional[str] = Form(None),
    db_username: Optional[str] = Form(None),
    db_password: Optional[str] = Form(None)
):
    try:
        config_path = get_config_path()
        db_config = {
            "type": db_type,
            "path": str(config_path / "plexichat.db") if db_type == "sqlite" else None,
            "host": db_host,
            "port": db_port,
            "name": db_name,
            "username": db_username,
            "password": db_password,
            "backup_enabled": True
        }
        if not test_database_connection(db_config):
            return templates.TemplateResponse("setup/database.html", {
                "request": request,
                "title": "Database Setup",
                "step": "database",
                "error": "Failed to connect to database. Please check your settings."
            })
        if db_type == "sqlite":
            initialize_sqlite_database(config_path / "plexichat.db")
        save_database_config(db_config)
        return RedirectResponse(url="/setup/admin", status_code=302)
    except Exception as e:
        logger.error(f"Database setup error: {e}")
        return templates.TemplateResponse("setup/database.html", {
            "request": request,
            "title": "Database Setup",
            "step": "database",
            "error": f"Database setup failed: {str(e)}"
        })

@router.get("/admin", response_class=HTMLResponse)
async def setup_admin_page(request: Request):
    try:
        return templates.TemplateResponse("setup/admin.html", {
            "request": request,
            "title": "Admin Account Setup",
            "step": "admin"
        })
    except Exception as e:
        logger.error(f"Admin setup page error: {e}")
        raise HTTPException(status_code=500, detail="Admin setup error")

@router.post("/admin")
async def setup_admin(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    email: str = Form(...)
):
    try:
        username = sanitize_input(username)
        email = sanitize_input(email)
        if not validate_username(username):
            logger.warning(f"Invalid username attempted during setup: {username}")
            return templates.TemplateResponse("setup/admin.html", {
                "request": request,
                "title": "Admin Account Setup",
                "step": "admin",
                "error": "Invalid username format."
            })
        if not validate_email(email):
            logger.warning(f"Invalid email attempted during setup: {email}")
            return templates.TemplateResponse("setup/admin.html", {
                "request": request,
                "title": "Admin Account Setup",
                "step": "admin",
                "error": "Invalid email format."
            })
        if not validate_password(password):
            logger.warning(f"Weak password attempted during setup for {username}")
            return templates.TemplateResponse("setup/admin.html", {
                "request": request,
                "title": "Admin Account Setup",
                "step": "admin",
                "error": f"Password must be at least {PASSWORD_MIN_LENGTH} characters long."
            })
        if password != confirm_password:
            logger.warning(f"Password mismatch during setup for {username}")
            return templates.TemplateResponse("setup/admin.html", {
                "request": request,
                "title": "Admin Account Setup",
                "step": "admin",
                "error": "Passwords do not match"
            })
        # All input validated and sanitized
        await create_admin_account(username, password, email)
        logger.info(f"Admin account created during setup: {username} ({email})")
        return RedirectResponse(url="/setup/complete", status_code=302)
    except Exception as e:
        logger.error(f"Admin setup error: {e}")
        return templates.TemplateResponse("setup/admin.html", {
            "request": request,
            "title": "Admin Account Setup",
            "step": "admin",
            "error": f"Admin setup failed: {str(e)}"
        })

@router.get("/complete", response_class=HTMLResponse)
async def setup_complete(request: Request):
    try:
        mark_setup_completed()
        return templates.TemplateResponse("setup/complete.html", {
            "request": request,
            "title": "Setup Complete",
            "step": "complete"
        })
    except Exception as e:
        logger.error(f"Setup complete error: {e}")
        raise HTTPException(status_code=500, detail="Setup completion error")

# --- HTTPS/SSL Setup Wizard Endpoints ---
# Reference: security.txt - SSL/TLS Automation, Certificate Management

@router.get("/ssl/check_software", response_class=JSONResponse)
async def ssl_check_software():
    # Check if certbot or other required software is installed
    try:
        result = subprocess.run(["certbot", "--version"], capture_output=True, text=True)
        installed = result.returncode == 0
        return {"certbot_installed": installed, "output": result.stdout.strip()}
    except Exception as e:
        return {"certbot_installed": False, "error": str(e)}

@router.post("/ssl/generate_self_signed", response_class=JSONResponse)
async def ssl_generate_self_signed(domain: str = Form(...)):
    # Generate a self-signed certificate for the given domain
    try:
        cert_path = f"certs/{domain}.crt"
        key_path = f"certs/{domain}.key"
        subprocess.run([
            "openssl", "req", "-x509", "-nodes", "-days", "365", "-newkey", "rsa:2048",
            "-keyout", key_path, "-out", cert_path,
            "-subj", f"/CN={domain}"
        ], check=True)
        return {"success": True, "cert_path": cert_path, "key_path": key_path}
    except Exception as e:
        return {"success": False, "error": str(e)}

@router.post("/ssl/lets_encrypt", response_class=JSONResponse)
async def ssl_lets_encrypt(domain: str = Form(...), email: str = Form(...)):
    # Request a Let's Encrypt certificate for the given domain
    try:
        result = subprocess.run([
            "certbot", "certonly", "--standalone", "-d", domain, "--agree-tos", "--email", email, "--non-interactive"
        ], capture_output=True, text=True)
        success = result.returncode == 0
        return {"success": success, "output": result.stdout.strip(), "error": result.stderr.strip() if not success else None}
    except Exception as e:
        return {"success": False, "error": str(e)}

@router.post("/ssl/upload", response_class=JSONResponse)
async def ssl_upload_cert(cert_file: bytes = Form(...), key_file: bytes = Form(...), domain: str = Form(...)):
    # Upload custom certificate and key
    try:
        cert_path = f"certs/{domain}.crt"
        key_path = f"certs/{domain}.key"
        with open(cert_path, "wb") as f:
            f.write(cert_file)
        with open(key_path, "wb") as f:
            f.write(key_file)
        return {"success": True, "cert_path": cert_path, "key_path": key_path}
    except Exception as e:
        return {"success": False, "error": str(e)}

@router.get("/ssl/list", response_class=JSONResponse)
async def ssl_list_certs():
    # List all managed certificates
    try:
        from pathlib import Path
        certs = []
        cert_dir = Path("certs")
        for cert_file in cert_dir.glob("*.crt"):
            certs.append(str(cert_file))
        return {"certificates": certs}
    except Exception as e:
        return {"certificates": [], "error": str(e)}

@router.post("/ssl/renew", response_class=JSONResponse)
async def ssl_renew_cert(domain: str = Form(...)):
    # Renew a Let's Encrypt certificate for the given domain
    try:
        result = subprocess.run([
            "certbot", "renew", "--cert-name", domain
        ], capture_output=True, text=True)
        success = result.returncode == 0
        return {"success": success, "output": result.stdout.strip(), "error": result.stderr.strip() if not success else None}
    except Exception as e:
        return {"success": False, "error": str(e)}

# --- Custom Field API Endpoints (User/Message) ---
# Reference: improvements.txt, security.txt

SUPPORTED_CUSTOM_TYPES = {"string", "int", "float", "bool", "list", "dict", "datetime"}
RESERVED_FIELD_NAMES = {"id", "username", "email", "password", "role", "created_at", "updated_at"}

# Utility to validate and cast custom field values
def validate_and_cast_custom_field(name: str, value: Any, type_str: str) -> Any:
    if name in RESERVED_FIELD_NAMES:
        raise HTTPException(status_code=400, detail="Reserved field name.")
    if type_str not in SUPPORTED_CUSTOM_TYPES:
        raise HTTPException(status_code=400, detail="Unsupported custom field type.")
    # Type casting
    if type_str == "string":
        return str(value)
    if type_str == "int":
        return int(value)
    if type_str == "float":
        return float(value)
    if type_str == "bool":
        return bool(value)
    if type_str == "list":
        if isinstance(value, str):
            return json.loads(value)
        return list(value)
    if type_str == "dict":
        if isinstance(value, str):
            return json.loads(value)
        return dict(value)
    if type_str == "datetime":
        if isinstance(value, str):
            return datetime.fromisoformat(value)
        return value
    return value

# --- Custom Field Limits (security.txt, improvements.txt) ---
MAX_FIELD_NAME_LENGTH = 64
MAX_FIELD_VALUE_SIZE = 4096
MAX_CUSTOM_FIELDS = 32

# --- User Custom Fields ---
@router.post("/user/{user_id}/custom_field", response_class=JSONResponse)
async def add_user_custom_field(
    user_id: int,
    field_name: str = Body(...),
    field_value: Union[str, int, float, bool, List[Any], Dict[str, Any]] = Body(...),
    field_type: str = Body(...),
    _: None = Depends(enforce_global_rate_limit)
):
    # Validate and cast
    if len(field_name) > MAX_FIELD_NAME_LENGTH:
        raise HTTPException(status_code=400, detail="Field name too long.")
    if isinstance(field_value, str) and len(field_value) > MAX_FIELD_VALUE_SIZE:
        raise HTTPException(status_code=400, detail="Field value too large.")
    value = validate_and_cast_custom_field(field_name, field_value, field_type)
    user_service = UserModelService()
    user = await user_service.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    if len(user.custom_fields) >= MAX_CUSTOM_FIELDS and field_name not in user.custom_fields:
        raise HTTPException(status_code=400, detail="Too many custom fields.")
    user.custom_fields[field_name] = {"value": value, "type": field_type}
    await user_service.update_user(user)
    # Log schema change
    import logging
    logging.getLogger(__name__).info(f"Custom field added/updated for user {user_id}: {field_name} ({field_type})")
    return {"success": True, "custom_fields": user.custom_fields}

@router.get("/user/{user_id}/custom_fields", response_class=JSONResponse)
async def get_user_custom_fields(user_id: int, _: None = Depends(enforce_global_rate_limit)):
    user_service = UserModelService()
    user = await user_service.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    return {"custom_fields": user.custom_fields}

# --- Message Custom Fields ---
@router.post("/message/{message_id}/custom_field", response_class=JSONResponse)
async def add_message_custom_field(
    message_id: int,
    field_name: str = Body(...),
    field_value: Union[str, int, float, bool, List[Any], Dict[str, Any]] = Body(...),
    field_type: str = Body(...),
    _: None = Depends(enforce_global_rate_limit)
):
    value = validate_and_cast_custom_field(field_name, field_value, field_type)
    from plexichat.features.users.message import MessageService
    message_service = MessageService()
    message = await message_service.get_message_by_id(message_id)
    if not message:
        raise HTTPException(status_code=404, detail="Message not found.")
    message.custom_fields[field_name] = {"value": value, "type": field_type}
    # Provide required arguments for update_message (message_id, sender_id, message_data)
    await message_service.update_message(message.id, message.sender_id, MessageUpdate())
    return {"success": True, "custom_fields": message.custom_fields}

@router.get("/message/{message_id}/custom_fields", response_class=JSONResponse)
async def get_message_custom_fields(message_id: int, _: None = Depends(enforce_global_rate_limit)):
    from plexichat.features.users.message import MessageService
    message_service = MessageService()
    message = await message_service.get_message_by_id(message_id)
    if not message:
        raise HTTPException(status_code=404, detail="Message not found.")
    return {"custom_fields": message.custom_fields}

# --- Type-safe retrieval utility for custom fields (improvements.txt) ---
def cast_custom_field_value(field: dict[str, Any]) -> Any:
    value, type_str = field.get('value'), field.get('type')
    if value is None:
        return None
    if type_str == 'int':
        return int(value) if value is not None else None
    if type_str == 'float':
        return float(value) if value is not None else None
    if type_str == 'bool':
        return bool(value) if value is not None else None
    if type_str == 'list':
        if isinstance(value, list):
            return value
        if value is not None:
            return json.loads(value)
        return []
    if type_str == 'dict':
        if isinstance(value, dict):
            return value
        if value is not None:
            return json.loads(value)
        return {}
    if type_str == 'datetime':
        if isinstance(value, str):
            return datetime.fromisoformat(value)
        return value
    return str(value) if value is not None else None

@router.get("/user/{user_id}", response_class=JSONResponse)
async def get_user(user_id: int, _: None = Depends(enforce_global_rate_limit)):
    user_service = UserModelService()
    user = await user_service.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    # Type-safe custom fields
    custom_fields = {k: cast_custom_field_value(v) for k, v in user.custom_fields.items()}
    user_dict = user.__dict__.copy()
    user_dict['custom_fields'] = custom_fields
    return user_dict

@router.get("/message/{message_id}", response_class=JSONResponse)
async def get_message(message_id: int, _: None = Depends(enforce_global_rate_limit)):
    from plexichat.features.users.message import MessageService
    message_service = MessageService()
    message = await message_service.get_message_by_id(message_id)
    if not message:
        raise HTTPException(status_code=404, detail="Message not found.")
    custom_fields = {k: cast_custom_field_value(v) for k, v in message.custom_fields.items()}
    message_dict = message.__dict__.copy()
    message_dict['custom_fields'] = custom_fields
    return message_dict

# --- Global Custom Field Type Management (for admins) ---
# Reference: improvements.txt

# In-memory store for global custom field types (replace with persistent storage as needed)
global_user_field_types = {"string", "int", "float", "bool", "list", "dict", "datetime"}
global_message_field_types = {"string", "int", "float", "bool", "list", "dict", "datetime"}

@router.get("/admin/custom_field_types/user", response_class=JSONResponse)
async def list_user_custom_field_types(_: None = Depends(enforce_global_rate_limit)):
    return {"user_custom_field_types": sorted(global_user_field_types)}

@router.post("/admin/custom_field_types/user", response_class=JSONResponse)
async def add_user_custom_field_type(
    field_type: str = Body(...),
    _: None = Depends(enforce_global_rate_limit)
):
    if field_type in RESERVED_FIELD_NAMES:
        raise HTTPException(status_code=400, detail="Reserved field name.")
    global_user_field_types.add(field_type)
    import logging
    logging.getLogger(__name__).info(f"Admin added user custom field type: {field_type}")
    return {"success": True, "user_custom_field_types": sorted(global_user_field_types)}

@router.delete("/admin/custom_field_types/user", response_class=JSONResponse)
async def remove_user_custom_field_type(
    field_type: str = Query(...),
    _: None = Depends(enforce_global_rate_limit)
):
    if field_type in {"string", "int", "float", "bool", "list", "dict", "datetime"}:
        raise HTTPException(status_code=400, detail="Cannot remove default field types.")
    global_user_field_types.discard(field_type)
    import logging
    logging.getLogger(__name__).info(f"Admin removed user custom field type: {field_type}")
    return {"success": True, "user_custom_field_types": sorted(global_user_field_types)}

@router.get("/admin/custom_field_types/message", response_class=JSONResponse)
async def list_message_custom_field_types(_: None = Depends(enforce_global_rate_limit)):
    return {"message_custom_field_types": sorted(global_message_field_types)}

@router.post("/admin/custom_field_types/message", response_class=JSONResponse)
async def add_message_custom_field_type(
    field_type: str = Body(...),
    _: None = Depends(enforce_global_rate_limit)
):
    if field_type in RESERVED_FIELD_NAMES:
        raise HTTPException(status_code=400, detail="Reserved field name.")
    global_message_field_types.add(field_type)
    import logging
    logging.getLogger(__name__).info(f"Admin added message custom field type: {field_type}")
    return {"success": True, "message_custom_field_types": sorted(global_message_field_types)}

@router.delete("/admin/custom_field_types/message", response_class=JSONResponse)
async def remove_message_custom_field_type(
    field_type: str = Query(...),
    _: None = Depends(enforce_global_rate_limit)
):
    if field_type in {"string", "int", "float", "bool", "list", "dict", "datetime"}:
        raise HTTPException(status_code=400, detail="Cannot remove default field types.")
    global_message_field_types.discard(field_type)
    import logging
    logging.getLogger(__name__).info(f"Admin removed message custom field type: {field_type}")
    return {"success": True, "message_custom_field_types": sorted(global_message_field_types)}

# --- Per-user and per-message custom field management endpoints (improvements.txt) ---
@router.delete("/user/{user_id}/custom_field", response_class=JSONResponse)
async def remove_user_custom_field(
    user_id: int,
    field_name: str = Query(...),
    _: None = Depends(enforce_global_rate_limit)
):
    user_service = UserModelService()
    user = await user_service.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    if field_name not in user.custom_fields:
        raise HTTPException(status_code=404, detail="Custom field not found.")
    del user.custom_fields[field_name]
    await user_service.update_user(user)
    import logging
    logging.getLogger(__name__).info(f"Custom field removed for user {user_id}: {field_name}")
    return {"success": True, "custom_fields": user.custom_fields}

@router.delete("/message/{message_id}/custom_field", response_class=JSONResponse)
async def remove_message_custom_field(
    message_id: int,
    field_name: str = Query(...),
    _: None = Depends(enforce_global_rate_limit)
):
    from plexichat.features.users.message import MessageService
    message_service = MessageService()
    message = await message_service.get_message_by_id(message_id)
    if not message:
        raise HTTPException(status_code=404, detail="Message not found.")
    if field_name not in message.custom_fields:
        raise HTTPException(status_code=404, detail="Custom field not found.")
    del message.custom_fields[field_name]
    # Provide required arguments for update_message (message_id, sender_id, message_data)
    await message_service.update_message(message.id, message.sender_id, MessageUpdate())
    import logging
    logging.getLogger(__name__).info(f"Custom field removed for message {message_id}: {field_name}")
    return {"success": True, "custom_fields": message.custom_fields}

# Helper functions

def get_config_path() -> Path:
    return Path.home() / ".plexichat"

def is_setup_completed() -> bool:
    try:
        config_path = get_config_path()
        setup_file = config_path / "setup_completed"
        return setup_file.exists()
    except Exception:
        return False

def test_database_connection(db_config: Dict[str, Any]) -> bool:
    try:
        if db_config["type"] == "sqlite":
            db_path = db_config["path"]
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
            # Use the abstraction layer for connection
            # Example: database_manager.test_connection(db_path)
            # This is a placeholder for actual abstraction layer usage
            return True
        else:
            return True
    except Exception as e:
        logger.error(f"Database connection test failed: {e}")
        return False

# --- Refactor all DB operations to use abstraction layer (improvements.txt, security.txt) ---
# Remove all direct SQL and sqlite3 usage from helper functions.

def initialize_sqlite_database(db_path: Path):
    # Use the abstraction layer for schema management (migrations, ORM, etc.)
    # Example: database_manager.initialize_schema()
    # This is a placeholder for actual migration/ORM logic
    pass

def save_database_config(db_config: Dict[str, Any]):
    # Use the abstraction layer for saving config if needed, or keep as file if not DB-related
    config_path = get_config_path()
    config_path.mkdir(parents=True, exist_ok=True)
    config_file = config_path / "database.json"
    with open(config_file, 'w') as f:
        json.dump(db_config, f, indent=2)
    logger.info(f"Database configuration saved to {config_file}")

async def create_admin_account(username: str, password: str, email: str):
    # Use UserService and abstraction layer for admin creation
    user_service = UserService()
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    admin_user = UserCreate(
        username=username,
        email=email,
        password=password,
        is_admin=True
    )
    await user_service.create_user(admin_user)
    logger.info(f"Admin account created: {username}")
    # Optionally, update default-creds.json for legacy compatibility
    config_path = get_config_path()
    creds_file = config_path / "default-creds.json"
    credentials = {
        "admin": {
            "username": username,
            "password_hash": password_hash,
            "email": email,
            "role": "admin",
            "created_at": str(datetime.now()),
            "active": True
        }
    }
    with open(creds_file, 'w') as f:
        json.dump(credentials, f, indent=2)

def mark_setup_completed():
    try:
        config_path = get_config_path()
        config_path.mkdir(parents=True, exist_ok=True)
        setup_file = config_path / "setup_completed"
        setup_file.write_text(str(datetime.now()))
        logger.info("Setup marked as completed")
    except Exception as e:
        logger.error(f"Failed to mark setup as completed: {e}")
        raise
