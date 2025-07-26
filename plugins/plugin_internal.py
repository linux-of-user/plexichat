# Auto-generated shared internal module for plugins
import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Request, Depends
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from enum import Enum
from dataclasses import dataclass

# Plugin system enums and types
class PluginType(Enum):
    """Plugin type enumeration."""
    FEATURE = "feature"
    INTEGRATION = "integration"
    TESTING = "testing"
    SECURITY = "security"
    ANALYTICS = "analytics"
    UI = "ui"
    API = "api"
    MIDDLEWARE = "middleware"

class SecurityLevel(Enum):
    """Security level enumeration."""
    SANDBOXED = "sandboxed"
    TRUSTED = "trusted"
    SYSTEM = "system"

class PluginStatus(Enum):
    """Plugin status enumeration."""
    DISCOVERED = "discovered"
    LOADING = "loading"
    LOADED = "loaded"
    ENABLED = "enabled"
    DISABLED = "disabled"
    FAILED = "failed"
    UNLOADED = "unloaded"

class ModuleCapability(Enum):
    """Module capability enumeration."""
    NETWORK = "network"
    FILE_SYSTEM = "file_system"
    DATABASE = "database"
    WEB_UI = "web_ui"
    SYSTEM = "system"
    CRYPTO = "crypto"

@dataclass
class PluginMetadata:
    """Plugin metadata."""
    name: str
    version: str
    description: str
    author: str
    plugin_type: PluginType
    security_level: SecurityLevel = SecurityLevel.SANDBOXED
    priority: int = 5
    enabled: bool = False
    auto_load: bool = False
    checksum: Optional[str] = None
    homepage: Optional[str] = None
    repository: Optional[str] = None
    license: Optional[str] = None
    tags: List[str] = None
    min_plexichat_version: Optional[str] = None
    max_plexichat_version: Optional[str] = None
    config_schema: Optional[Dict[str, Any]] = None

    def __post_init__(self):
        if self.tags is None:
            self.tags = []

@dataclass
class ModulePermissions:
    """Module permissions."""
    capabilities: List[ModuleCapability]
    network_access: bool = False
    file_system_access: bool = False
    database_access: bool = False

class PluginInterface(ABC):
    """Base plugin interface."""

    def __init__(self, name: str, version: str = "1.0.0"):
        self.name = name
        self.version = version
        self.logger = logging.getLogger(f"plugin.{name}")
        self.config = {}
        self.manager = None

    @abstractmethod
    def get_metadata(self) -> PluginMetadata:
        """Get plugin metadata."""
        pass

    def get_required_permissions(self) -> ModulePermissions:
        """Get required permissions."""
        return ModulePermissions(capabilities=[])

    @abstractmethod
    async def initialize(self) -> bool:
        """Initialize the plugin."""
        pass

    async def cleanup(self) -> bool:
        """Cleanup plugin resources."""
        return True

    async def self_test(self) -> Dict[str, Any]:
        """Run plugin self-tests."""
        return {"success": True, "message": "No tests implemented"}

    def get_router(self) -> Optional[APIRouter]:
        """Get plugin API router."""
        return None

    async def handle_command(self, command: str, args: List[str]) -> Dict[str, Any]:
        """Handle CLI command."""
        return {"error": "Command not supported"}

# Export all the main classes and interfaces
__all__ = [
    "PluginType",
    "SecurityLevel",
    "PluginStatus",
    "ModuleCapability",
    "PluginMetadata",
    "ModulePermissions",
    "PluginInterface",
]
