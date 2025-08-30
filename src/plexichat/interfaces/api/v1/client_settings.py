import logging
import os
import json
import hashlib
import mimetypes
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel

from plexichat.core.auth.fastapi_adapter import get_current_user

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/client-settings", tags=["Client Settings"])

# Attempt to import a real repository/service and config if available in the application.
# Fall back to local mocks for standalone execution.
try:
    from plexichat.infrastructure.services.client_settings_service import client_settings_service as repository  # type: ignore
except Exception:
    # Mock repository for standalone execution or tests where the full app isn't available.
    class MockRepository:
        async def initialize(self): return False
        async def get_user_settings(self, user_id): return []
        async def get_setting(self, user_id, key): return None
        async def set_setting(self, user_id, key, data): return {
            "setting_key": key,
            "setting_value": data,
            "setting_type": "text" if not isinstance(data, dict) or "path" not in data else "image",
            "updated_at": datetime.utcnow()
        }
        async def delete_setting(self, user_id, key): return True
        async def bulk_update_settings(self, user_id, settings): return {"updated_count": len(settings)}
        async def get_user_images(self, user_id): return []
        async def get_user_stats(self, user_id): return {"total_settings": 0, "total_storage_bytes": 0}
        async def initialize_tables(self): return False
        async def log_audit(self, entry: Dict[str, Any]):
            # simple file-based audit fallback
            try:
                os.makedirs("logs", exist_ok=True)
                with open("logs/client_settings_audit.log", "a", encoding="utf-8") as f:
                    f.write(json.dumps(entry, default=str) + "\n")
            except Exception:
                pass
            return True

    repository = MockRepository()  # type: ignore

try:
    from plexichat.core.config_manager import get_config  # type: ignore
except Exception:
    # Fallback config reader
    def get_config(section: str):
        # Return minimal default configuration for client settings.
        if section == "client_settings":
            return {
                "storage_path": "data/client_settings/images",
                "max_image_size": 5 * 1024 * 1024,
                "allowed_image_types": ["image/jpeg", "image/png", "image/gif", "image/webp", "image/svg+xml"],
                "max_settings_per_user": 1000,
                "max_total_storage_per_user": 50 * 1024 * 1024,
                "max_bulk_update": 100
            }
        return {}

# Try to import the global security system for validation
_get_security_system = None
try:
    from plexichat.core.security.security_manager import get_security_system  # type: ignore
    _get_security_system = get_security_system
except Exception:
    _get_security_system = None

# Pydantic Models
class ClientSettingCreate(BaseModel):
    setting_key: str
    setting_value: Any

class ClientSettingResponse(BaseModel):
    setting_key: str
    setting_value: Any
    setting_type: Optional[str] = "text"
    updated_at: datetime
    size_bytes: Optional[int] = 0

class ClientSettingsBulkUpdate(BaseModel):
    settings: Dict[str, Any]

class ClientSettingsBulkResponse(BaseModel):
    updated_count: int
    errors: Optional[List[Dict[str, Any]]] = None

# Known schema for validation of well-known keys.
KNOWN_KEY_SCHEMAS = {
    "theme": {"type": "string", "allowed": ["light", "dark", "system"]},
    "language": {"type": "string", "allowed": None},
    "notifications.enabled": {"type": "boolean", "allowed": None},
    "notifications.sound": {"type": "boolean", "allowed": None},
}

# Load configuration (fall back to defaults if not present)
_client_settings_config = get_config("client_settings") or {}
STORAGE_PATH = _client_settings_config.get("storage_path", "data/client_settings/images")
MAX_IMAGE_SIZE = int(_client_settings_config.get("max_image_size", 5 * 1024 * 1024))
ALLOWED_IMAGE_TYPES = set(_client_settings_config.get("allowed_image_types", [
    "image/jpeg", "image/png", "image/gif", "image/webp", "image/svg+xml"
]))
MAX_SETTINGS_PER_USER = int(_client_settings_config.get("max_settings_per_user", 1000))
MAX_TOTAL_STORAGE_PER_USER = int(_client_settings_config.get("max_total_storage_per_user", 50 * 1024 * 1024))
MAX_BULK_UPDATE = int(_client_settings_config.get("max_bulk_update", 100))

# Ensure storage directory exists
try:
    os.makedirs(STORAGE_PATH, exist_ok=True)
except Exception as e:
    logger.warning(f"Unable to create storage path {STORAGE_PATH}: {e}")

# Virus scanning integration (optional). Attempt to use pyclamd if available.
def _scan_for_viruses(data: bytes) -> bool:
    """
    Scan bytes for viruses. Returns True if clean, False if infected.
    If no scanner is available, returns True but logs a warning.
    """
    try:
        import pyclamd  # type: ignore
        try:
            cd = pyclamd.ClamdAgnostic()
            if not cd.ping():
                logger.debug("Clamd not responding, skipping virus scan")
                return True
            scan_result = cd.scan_stream(data)
            if not scan_result:
                return True
            logger.warning(f"Virus scan detected issues: {scan_result}")
            return False
        except Exception as e:
            logger.warning(f"Virus scanning failed: {e}")
            return True
    except Exception:
        # No clamd available; optionally implement other scanners later.
        logger.debug("No virus scanning library available (pyclamd). Skipping deep scan.")
        return True

def _hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def _validate_setting_key(key: str) -> None:
    if not key or len(key) > 255:
        raise HTTPException(status_code=400, detail="Invalid setting key")
    if not all(c.isalnum() or c in "._-" for c in key):
        raise HTTPException(status_code=400, detail="Setting key contains invalid characters")

def _validate_known_key_value(key: str, value: Any) -> None:
    schema = KNOWN_KEY_SCHEMAS.get(key)
    if not schema:
        return
    t = schema.get("type")
    allowed = schema.get("allowed")
    if t == "string":
        if not isinstance(value, str):
            raise HTTPException(status_code=400, detail=f"{key} must be a string")
        if allowed and value not in allowed:
            raise HTTPException(status_code=400, detail=f"{key} must be one of {allowed}")
    elif t == "boolean":
        if not isinstance(value, bool):
            # allow truthy/falsy string conversion
            if isinstance(value, str) and value.lower() in ("true", "false", "1", "0"):
                return
            raise HTTPException(status_code=400, detail=f"{key} must be a boolean")

async def _ensure_tables():
    """
    Ensure that the required database tables exist.
    Prefer to use repository.initialize() or repository.initialize_tables() if available.
    """
    try:
        if hasattr(repository, "initialize"):
            try:
                await repository.initialize()
            except Exception:
                # Not critical; attempt table-specific initializer
                pass
        if hasattr(repository, "initialize_tables"):
            try:
                await repository.initialize_tables()
            except Exception:
                pass
    except Exception:
        # Best-effort; not fatal here.
        pass

async def _log_audit(user_id: str, action: str, setting_key: str, details: Optional[Dict[str, Any]] = None):
    """
    Record audit trail for client settings changes.
    Try to use repository.log_audit if available; otherwise append to a local logfile.
    """
    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "user_id": user_id,
        "action": action,
        "setting_key": setting_key,
        "details": details or {}
    }
    try:
        if hasattr(repository, "log_audit"):
            try:
                await repository.log_audit(entry)
                return
            except Exception as e:
                logger.debug(f"repository.log_audit failed: {e}")
        # Fallback to local log file
        os.makedirs("logs", exist_ok=True)
        with open("logs/client_settings_audit.log", "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, default=str) + "\n")
    except Exception as e:
        logger.warning(f"Failed to write audit log: {e}")

@router.on_event("startup")
async def _startup_init():
    await _ensure_tables()

@router.get("/", response_model=List[ClientSettingResponse])
async def get_all_settings(current_user: dict = Depends(get_current_user)):
    """Get all client settings for the current user."""
    user_id = current_user["user_id"]
    await _ensure_tables()
    try:
        settings = await repository.get_user_settings(user_id)
        # Normalize responses if needed (ensure updated_at is datetime)
        normalized = []
        for s in settings:
            # Support both dict and object shapes
            if isinstance(s, dict):
                updated_at = s.get("updated_at") or datetime.utcnow()
                if isinstance(updated_at, str):
                    try:
                        updated_at = datetime.fromisoformat(updated_at)
                    except Exception:
                        updated_at = datetime.utcnow()
                normalized.append(ClientSettingResponse(
                    setting_key=s.get("setting_key"),
                    setting_value=s.get("setting_value"),
                    setting_type=s.get("setting_type", "text"),
                    updated_at=updated_at,
                    size_bytes=s.get("size_bytes", 0)
                ))
            else:
                # best-effort
                normalized.append(ClientSettingResponse(
                    setting_key=getattr(s, "setting_key", ""),
                    setting_value=getattr(s, "setting_value", None),
                    setting_type=getattr(s, "setting_type", "text"),
                    updated_at=getattr(s, "updated_at", datetime.utcnow()),
                    size_bytes=getattr(s, "size_bytes", 0)
                ))
        return normalized
    except Exception as e:
        logger.error(f"Failed to fetch settings for user {user_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve settings")

@router.get("/{setting_key}", response_model=ClientSettingResponse)
async def get_setting(setting_key: str, current_user: dict = Depends(get_current_user)):
    """Get a specific client setting."""
    user_id = current_user["user_id"]
    _validate_setting_key(setting_key)
    await _ensure_tables()
    try:
        setting = await repository.get_setting(user_id, setting_key)
        if not setting:
            raise HTTPException(status_code=404, detail="Setting not found")
        updated_at = setting.get("updated_at") if isinstance(setting, dict) else getattr(setting, "updated_at", None)
        if isinstance(updated_at, str):
            try:
                updated_at = datetime.fromisoformat(updated_at)
            except Exception:
                updated_at = datetime.utcnow()
        response = ClientSettingResponse(
            setting_key=setting.get("setting_key", setting_key) if isinstance(setting, dict) else getattr(setting, "setting_key", setting_key),
            setting_value=setting.get("setting_value") if isinstance(setting, dict) else getattr(setting, "setting_value", None),
            setting_type=setting.get("setting_type", "text") if isinstance(setting, dict) else getattr(setting, "setting_type", "text"),
            updated_at=updated_at or datetime.utcnow(),
            size_bytes=setting.get("size_bytes", 0) if isinstance(setting, dict) else getattr(setting, "size_bytes", 0)
        )
        return response
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get setting {setting_key} for user {user_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to get setting")

@router.put("/{setting_key}", response_model=ClientSettingResponse)
async def set_setting(setting_key: str, data: ClientSettingCreate, current_user: dict = Depends(get_current_user)):
    """Set or update a client setting. For images, use the /images endpoint."""
    user_id = current_user["user_id"]
    _validate_setting_key(setting_key)
    await _ensure_tables()

    # Validate known keys
    try:
        _validate_known_key_value(setting_key, data.setting_value)
    except HTTPException:
        raise

    # Enforce quotas if repository provides stats
    try:
        stats = await repository.get_user_stats(user_id)
        total_settings = stats.get("total_settings", 0)
        total_storage = stats.get("total_storage_bytes", 0)
    except Exception:
        total_settings = 0
        total_storage = 0

    # Check if it's a new setting when storing (best-effort: check existing)
    try:
        existing = await repository.get_setting(user_id, setting_key)
        is_new = existing is None
    except Exception:
        is_new = False

    if is_new and total_settings >= MAX_SETTINGS_PER_USER:
        raise HTTPException(status_code=400, detail="Maximum number of settings exceeded for this user")

    # If the value is image-like dict with 'size' or 'path', ensure not exceeding storage quota
    size_candidate = 0
    if isinstance(data.setting_value, dict) and data.setting_value.get("size"):
        try:
            size_candidate = int(data.setting_value.get("size", 0))
        except Exception:
            size_candidate = 0

    if total_storage + size_candidate > MAX_TOTAL_STORAGE_PER_USER:
        raise HTTPException(status_code=400, detail="Storing this setting would exceed your total storage quota")

    try:
        result = await repository.set_setting(user_id, setting_key, data.setting_value)
        await _log_audit(user_id, "set", setting_key, {"value_preview": str(data.setting_value)[:200]})
        # Normalize result to ClientSettingResponse
        updated_at = result.get("updated_at") if isinstance(result, dict) else getattr(result, "updated_at", datetime.utcnow())
        if isinstance(updated_at, str):
            try:
                updated_at = datetime.fromisoformat(updated_at)
            except Exception:
                updated_at = datetime.utcnow()
        return ClientSettingResponse(
            setting_key=setting_key,
            setting_value=result.get("setting_value") if isinstance(result, dict) else getattr(result, "setting_value", None),
            setting_type=result.get("setting_type", "text") if isinstance(result, dict) else getattr(result, "setting_type", "text"),
            updated_at=updated_at,
            size_bytes=result.get("size_bytes", 0) if isinstance(result, dict) else getattr(result, "size_bytes", 0)
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to set setting {setting_key} for user {user_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to set setting")

@router.delete("/{setting_key}")
async def delete_setting(setting_key: str, current_user: dict = Depends(get_current_user)):
    """Delete a client setting."""
    user_id = current_user["user_id"]
    _validate_setting_key(setting_key)
    await _ensure_tables()
    try:
        success = await repository.delete_setting(user_id, setting_key)
        if not success:
            raise HTTPException(status_code=404, detail="Setting not found")
        await _log_audit(user_id, "delete", setting_key, {})
        return {"message": "Setting deleted"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete setting {setting_key} for user {user_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete setting")

@router.post("/bulk-update", response_model=ClientSettingsBulkResponse)
async def bulk_update_settings(data: ClientSettingsBulkUpdate, current_user: dict = Depends(get_current_user)):
    """Bulk update multiple client settings."""
    user_id = current_user["user_id"]
    await _ensure_tables()

    if not isinstance(data.settings, dict):
        raise HTTPException(status_code=400, detail="Invalid bulk payload")

    if len(data.settings) > MAX_BULK_UPDATE:
        raise HTTPException(status_code=400, detail=f"Too many settings in bulk update (max {MAX_BULK_UPDATE})")

    # Validate keys and known schemas first
    errors = []
    validated_updates = {}
    for key, value in data.settings.items():
        try:
            _validate_setting_key(key)
            _validate_known_key_value(key, value)
            validated_updates[key] = value
        except HTTPException as e:
            errors.append({"key": key, "error": e.detail})

    if errors and len(errors) == len(data.settings):
        # All failed
        raise HTTPException(status_code=400, detail={"errors": errors})

    try:
        result = await repository.bulk_update_settings(user_id, validated_updates)
        await _log_audit(user_id, "bulk_update", "bulk", {"updated_count": result.get("updated_count"), "errors": errors})
        response = {"updated_count": result.get("updated_count", 0)}
        if errors:
            response["errors"] = errors
        return response
    except Exception as e:
        logger.error(f"Bulk update failed for user {user_id}: {e}")
        raise HTTPException(status_code=500, detail="Bulk update failed")

@router.post("/images/{setting_key}", response_model=ClientSettingResponse)
async def upload_image_setting(setting_key: str, file: UploadFile = File(...), current_user: dict = Depends(get_current_user)):
    """
    Upload an image and store it as a client setting. The stored setting will contain
    metadata including storage path, content type, size and hash.
    This endpoint integrates with the SecuritySystem.validate_file_upload for
    filename sanitization and policy-driven validations.
    """
    user_id = current_user["user_id"]
    _validate_setting_key(setting_key)
    await _ensure_tables()

    # Read file bytes early to determine size; keep a copy for scanning/storing
    try:
        data = await file.read()
    except Exception as e:
        logger.error(f"Failed to read uploaded file for user {user_id}: {e}")
        raise HTTPException(status_code=400, detail="Failed to read uploaded file")

    size = len(data)
    if size == 0:
        raise HTTPException(status_code=400, detail="Empty file uploaded")
    if size > MAX_IMAGE_SIZE:
        raise HTTPException(status_code=400, detail=f"Image too large (max {MAX_IMAGE_SIZE} bytes)")

    # Determine content type
    content_type = (file.content_type or "").lower()

    # Use SecuritySystem for validation if available
    sanitized_filename_from_security = None
    if _get_security_system:
        try:
            security = _get_security_system()
            # Use the original uploaded filename for security validation to catch traversal attempts in user-supplied names.
            original_name = getattr(file, "filename", "") or ""
            allowed, message = security.validate_file_upload(original_name, content_type, size, policy_name="default")
            if not allowed:
                logger.warning(f"Security validation failed for upload by user {user_id}: {message}")
                # Log audit for security rejection
                try:
                    await _log_audit(user_id, "upload_image_rejected", setting_key, {"reason": message, "original_filename": original_name})
                except Exception:
                    pass
                raise HTTPException(status_code=400, detail=message)
            # Try to extract sanitized filename from message
            try:
                # message format: "File is valid. Sanitized filename: {sanitized}"
                marker = "Sanitized filename:"
                if marker in message:
                    sanitized_filename_from_security = message.split(marker, 1)[1].strip()
                else:
                    sanitized_filename_from_security = Path(original_name).name
            except Exception:
                sanitized_filename_from_security = Path(original_name).name
        except HTTPException:
            raise
        except Exception as e:
            logger.debug(f"Security system validation error: {e}")
            # fallback to local checks below
            sanitized_filename_from_security = None

    # Secondary validation: ensure content_type is acceptable for images (defensive)
    if content_type not in ALLOWED_IMAGE_TYPES:
        # If security system is present, it would have validated content type. If not, reject here.
        if not _get_security_system:
            raise HTTPException(status_code=400, detail=f"Unsupported image type: {content_type}")
        # If security system is present and allowed, continue regardless of ALLOWED_IMAGE_TYPES list.

    # Virus scan
    is_clean = _scan_for_viruses(data)
    if not is_clean:
        try:
            await _log_audit(user_id, "upload_image_rejected", setting_key, {"reason": "virus_scan_failed"})
        except Exception:
            pass
        raise HTTPException(status_code=400, detail="Uploaded file failed virus scan")

    # Quota check (best-effort)
    try:
        stats = await repository.get_user_stats(user_id)
        total_storage = stats.get("total_storage_bytes", 0)
    except Exception:
        total_storage = 0

    if total_storage + size > MAX_TOTAL_STORAGE_PER_USER:
        raise HTTPException(status_code=400, detail="Storing this image would exceed your total storage quota")

    # Compute a content-hash and create safe filename.
    hash_hex = _hash_bytes(data)

    # Determine extension to use for storage:
    # Prefer extension from security-sanitized filename if available; else try to derive from content_type; else fallback to original file extension.
    chosen_ext = ""
    try:
        if sanitized_filename_from_security:
            chosen_ext = Path(sanitized_filename_from_security).suffix or ""
        if not chosen_ext:
            guessed = mimetypes.guess_extension(content_type) or ""
            chosen_ext = guessed
        if not chosen_ext:
            # fallback to original UploadFile filename extension
            original_ext = Path(getattr(file, "filename", "") or "").suffix or ""
            chosen_ext = original_ext
    except Exception:
        chosen_ext = ""

    # Build stored filename with user and setting key to avoid collisions while preserving safe extension
    # Sanitize parts to be filesystem-safe (only allow limited chars)
    def _sanitize_part(p: str) -> str:
        if not isinstance(p, str):
            p = str(p)
        # Keep alnum, dot, dash, underscore
        safe = "".join(ch for ch in p if ch.isalnum() or ch in "._-")
        if safe == "":
            safe = "x"
        return safe

    safe_user = _sanitize_part(str(user_id))
    safe_key = _sanitize_part(setting_key)
    stored_filename = f"{safe_user}_{safe_key}_{hash_hex}{chosen_ext}"
    safe_user_dir = os.path.join(STORAGE_PATH, str(user_id))
    os.makedirs(safe_user_dir, exist_ok=True)
    file_path = os.path.join(safe_user_dir, stored_filename)

    # Ensure the resolved path remains within STORAGE_PATH (prevent path traversal via crafted user_id/setting_key)
    try:
        abspath_storage = os.path.abspath(STORAGE_PATH)
        abspath_file = os.path.abspath(file_path)
        if not abspath_file.startswith(abspath_storage):
            logger.error(f"Resolved file path is outside storage root: {abspath_file}")
            raise HTTPException(status_code=400, detail="Invalid storage path resolved for uploaded file")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to validate storage path for user {user_id}: {e}")
        raise HTTPException(status_code=500, detail="Server file storage configuration error")

    # Avoid overwrite if exact file exists; still update DB to point to it
    try:
        if not os.path.exists(file_path):
            # Write data to disk atomically (write to temp then rename)
            tmp_path = f"{file_path}.tmp"
            with open(tmp_path, "wb") as f:
                f.write(data)
            try:
                os.replace(tmp_path, file_path)
            except Exception:
                # fallback: try removing existing tmp and renaming
                try:
                    if os.path.exists(file_path):
                        os.remove(file_path)
                    os.replace(tmp_path, file_path)
                except Exception as e:
                    logger.error(f"Atomic rename failed storing uploaded image for user {user_id} at {file_path}: {e}")
                    # attempt direct write as last resort
                    with open(file_path, "wb") as f:
                        f.write(data)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to store uploaded image for user {user_id} at {file_path}: {e}")
        raise HTTPException(status_code=500, detail="Failed to store uploaded image")

    # Build metadata to store in settings
    metadata = {
        "path": file_path,
        "content_type": content_type,
        "size": size,
        "hash": hash_hex,
        "stored_at": datetime.utcnow().isoformat(),
        "original_filename": getattr(file, "filename", None),
        "sanitized_filename": sanitized_filename_from_security or Path(getattr(file, "filename", "") or "").name
    }

    try:
        result = await repository.set_setting(user_id, setting_key, metadata)
        await _log_audit(user_id, "upload_image", setting_key, {"path": file_path, "size": size})
        updated_at = result.get("updated_at") if isinstance(result, dict) else getattr(result, "updated_at", datetime.utcnow())
        if isinstance(updated_at, str):
            try:
                updated_at = datetime.fromisoformat(updated_at)
            except Exception:
                updated_at = datetime.utcnow()
        return ClientSettingResponse(
            setting_key=setting_key,
            setting_value=metadata,
            setting_type="image",
            updated_at=updated_at,
            size_bytes=size
        )
    except Exception as e:
        logger.error(f"Failed to save image setting record for user {user_id}: {e}")
        # Attempt to clean up stored file if repository save failed and file was created
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
        except Exception:
            pass
        raise HTTPException(status_code=500, detail="Failed to save image setting")

@router.get("/images/{setting_key}")
async def serve_image(setting_key: str, current_user: dict = Depends(get_current_user)):
    """
    Serve an image stored as a client setting. Access is limited to the setting owner.
    """
    user_id = current_user["user_id"]
    _validate_setting_key(setting_key)
    await _ensure_tables()
    try:
        setting = await repository.get_setting(user_id, setting_key)
        if not setting:
            raise HTTPException(status_code=404, detail="Image setting not found")
        # Expect stored metadata
        metadata = setting.get("setting_value") if isinstance(setting, dict) else getattr(setting, "setting_value", None)
        if not metadata or not isinstance(metadata, dict):
            raise HTTPException(status_code=404, detail="Image not found or invalid metadata")
        path = metadata.get("path")
        content_type = metadata.get("content_type", "application/octet-stream")
        if not path or not os.path.exists(path):
            raise HTTPException(status_code=404, detail="Stored image file not found")
        # Stream or return file response with proper headers
        try:
            await _log_audit(user_id, "serve_image", setting_key, {"path": path})
        except Exception:
            pass
        return FileResponse(path, media_type=content_type, filename=os.path.basename(path))
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to serve image for user {user_id} and key {setting_key}: {e}")
        raise HTTPException(status_code=500, detail="Failed to serve image")

if __name__ == '__main__':
    # Example of how to run this API with uvicorn
    import uvicorn
    from fastapi import FastAPI

    app = FastAPI()
    app.include_router(router)

    # uvicorn.run(app, host="0.0.0.0", port=8000)
