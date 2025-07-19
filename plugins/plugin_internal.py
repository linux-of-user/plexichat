# Auto-generated shared internal module for plugins
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Request, Depends
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from enum import Enum
from dataclasses import dataclass
# Add more shared imports as needed

# --- Plugin SDK: Standard Interfaces and Utilities ---

class PluginInterface:
    """Base interface for all plugins."""
    def get_metadata(self) -> Dict[str, Any]:
        raise NotImplementedError
    def get_required_permissions(self) -> 'ModulePermissions':
        raise NotImplementedError

@dataclass
class PluginMetadata:
    name: str
    version: str
    description: str
    author: str
    plugin_type: str
    entry_point: str = "main"
    dependencies: Optional[List[str]] = None
    permissions: Optional[List[str]] = None
    api_version: Optional[str] = None
    min_plexichat_version: Optional[str] = None
    enabled: bool = True
    category: Optional[str] = None
    tags: Optional[List[str]] = None
    homepage: Optional[str] = None
    repository: Optional[str] = None
    license: str = "Unknown"
    icon: Optional[str] = None
    screenshots: Optional[List[str]] = None
    changelog: Optional[List[Dict[str, Any]]] = None
    download_count: int = 0
    rating: float = 0.0
    last_updated: Optional[str] = None
    size_bytes: int = 0
    checksum: Optional[str] = None
    ui_pages: Optional[List[Dict[str, Any]]] = None
    api_endpoints: Optional[List[str]] = None
    webhooks: Optional[List[str]] = None
    settings_schema: Optional[Dict[str, Any]] = None
    auto_start: bool = False
    background_tasks: Optional[List[str]] = None

class PluginType(str, Enum):
    FEATURE = "feature"
    SECURITY_NODE = "security_node"
    CLIENT = "client"
    API = "api"
    ANALYTICS = "analytics"
    BACKUP = "backup"
    MONITORING = "monitoring"
    OTHER = "other"

class ModulePermissions:
    def __init__(self, capabilities: Optional[List[str]] = None, network_access: bool = False, file_system_access: bool = False, database_access: bool = False):
        self.capabilities = capabilities or []
        self.network_access = network_access
        self.file_system_access = file_system_access
        self.database_access = database_access

class ModuleCapability:
    MESSAGING = "messaging"
    FILE_SYSTEM_ACCESS = "file_system_access"
    NETWORK_ACCESS = "network_access"
    DATABASE_ACCESS = "database_access"
    AI_INTEGRATION = "ai_integration"
    ANALYTICS = "analytics"
    BACKUP = "backup"
    MONITORING = "monitoring"
    WEB_UI = "web_ui"
    NOTIFICATIONS = "notifications"
    OTHER = "other"

# --- Additional SDK Utilities ---

def plugin_logger(name: str) -> logging.Logger:
    """Get a logger for a plugin."""
    return logging.getLogger(f"plugin.{name}")

# Add more shared utilities, base classes, or helpers as needed for plugins
