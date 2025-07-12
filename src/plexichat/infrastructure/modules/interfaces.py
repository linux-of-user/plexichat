"""
PlexiChat Module Interfaces and Contracts - SINGLE SOURCE OF TRUTH

Defines strict interfaces and contracts for all modules/plugins to ensure:
- Loose coupling between modules and core system
- Predictable behavior and error handling
- Type safety and validation
- Consistent lifecycle management
- Security and permission boundaries
- Performance monitoring and resource management
"""

import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Any, Callable, Union, Protocol, runtime_checkable
import logging

from ...core_system.logging import get_logger

logger = get_logger(__name__)


class ModuleCapability(Enum):
    """Module capability types."""
    # Core capabilities
    MESSAGING = "messaging"
    USER_MANAGEMENT = "user_management"
    FILE_HANDLING = "file_handling"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"

    # Advanced capabilities
    AI_PROCESSING = "ai_processing"
    BACKUP_STORAGE = "backup_storage"
    CLUSTERING = "clustering"
    SECURITY_SCANNING = "security_scanning"
    ENCRYPTION = "encryption"

    # UI capabilities
    WEB_INTERFACE = "web_interface"
    API_ENDPOINTS = "api_endpoints"
    ADMIN_PANEL = "admin_panel"

    # Integration capabilities
    EXTERNAL_API = "external_api"
    DATABASE_ACCESS = "database_access"
    NETWORK_ACCESS = "network_access"
    FILE_SYSTEM_ACCESS = "file_system_access"

    # Monitoring capabilities
    LOGGING = "logging"
    METRICS = "metrics"
    HEALTH_CHECK = "health_check"

    # Enhanced system access capabilities
    SECURITY = "security"
    AI_SERVICES = "ai_services"
    BACKGROUND_TASKS = "background_tasks"
    CACHING = "caching"
    MONITORING = "monitoring"

    # AI-specific capabilities
    MODEL_MANAGEMENT = "model_management"
    INFERENCE_ENGINE = "inference_engine"
    MODEL_TRAINING = "model_training"
    HUGGINGFACE_INTEGRATION = "huggingface_integration"


class ModulePriority(Enum):
    """Module loading and execution priority."""
    CRITICAL = 1      # Core system modules (auth, database)
    HIGH = 2          # Important features (messaging, security)
    NORMAL = 3        # Standard features (plugins, extensions)
    LOW = 4           # Optional features (themes, cosmetic)
    BACKGROUND = 5    # Background tasks, cleanup


class ModuleState(Enum):
    """Module lifecycle states."""
    UNLOADED = "unloaded"
    LOADING = "loading"
    LOADED = "loaded"
    INITIALIZING = "initializing"
    ACTIVE = "active"
    PAUSED = "paused"
    ERROR = "error"
    UNLOADING = "unloading"
    FAILED = "failed"


@dataclass
class ModulePermissions:
    """Module permission requirements."""
    capabilities: List[ModuleCapability] = field(default_factory=list)
    network_access: bool = False
    file_system_access: bool = False
    database_access: bool = False
    admin_access: bool = False
    user_data_access: bool = False
    system_config_access: bool = False
    external_api_access: bool = False
    
    def requires_capability(self, capability: ModuleCapability) -> bool:
        """Check if module requires specific capability."""
        return capability in self.capabilities
    
    def is_privileged(self) -> bool:
        """Check if module requires privileged access."""
        return (self.admin_access or 
                self.system_config_access or 
                self.database_access)


@dataclass
class ModuleMetrics:
    """Module performance and usage metrics."""
    load_time: Optional[float] = None
    initialization_time: Optional[float] = None
    memory_usage_mb: float = 0.0
    cpu_usage_percent: float = 0.0
    api_calls_count: int = 0
    error_count: int = 0
    last_activity: Optional[datetime] = None
    uptime_seconds: float = 0.0
    
    def record_activity(self):
        """Record module activity."""
        self.last_activity = datetime.now(timezone.utc)
        self.api_calls_count += 1
    
    def record_error(self):
        """Record module error."""
        self.error_count += 1


@dataclass
class ModuleConfiguration:
    """Module configuration structure."""
    enabled: bool = True
    auto_start: bool = True
    priority: ModulePriority = ModulePriority.NORMAL
    timeout_seconds: int = 30
    max_memory_mb: int = 100
    max_cpu_percent: float = 50.0
    restart_on_failure: bool = True
    max_restart_attempts: int = 3
    health_check_interval: int = 60
    custom_config: Dict[str, Any] = field(default_factory=dict)


@runtime_checkable
class IModuleLifecycle(Protocol):
    """Module lifecycle interface."""
    
    async def initialize(self) -> bool:
        """Initialize the module. Return True if successful."""
        ...
    
    async def start(self) -> bool:
        """Start the module. Return True if successful."""
        ...
    
    async def stop(self) -> bool:
        """Stop the module. Return True if successful."""
        ...
    
    async def pause(self) -> bool:
        """Pause the module. Return True if successful."""
        ...
    
    async def resume(self) -> bool:
        """Resume the module. Return True if successful."""
        ...
    
    async def shutdown(self) -> bool:
        """Shutdown the module. Return True if successful."""
        ...
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check. Return status information."""
        ...


@runtime_checkable
class IModuleConfiguration(Protocol):
    """Module configuration interface."""
    
    def get_config_schema(self) -> Dict[str, Any]:
        """Get configuration schema for validation."""
        ...
    
    def validate_config(self, config: Dict[str, Any]) -> bool:
        """Validate configuration. Return True if valid."""
        ...
    
    def apply_config(self, config: Dict[str, Any]) -> bool:
        """Apply configuration. Return True if successful."""
        ...
    
    def get_current_config(self) -> Dict[str, Any]:
        """Get current configuration."""
        ...


@runtime_checkable
class IModuleAPI(Protocol):
    """Module API interface for inter-module communication."""
    
    def get_api_version(self) -> str:
        """Get API version."""
        ...
    
    def get_available_methods(self) -> List[str]:
        """Get list of available API methods."""
        ...
    
    async def call_method(self, method: str, **kwargs) -> Any:
        """Call module method."""
        ...
    
    def register_event_handler(self, event: str, handler: Callable) -> bool:
        """Register event handler."""
        ...
    
    def emit_event(self, event: str, data: Any) -> bool:
        """Emit event to other modules."""
        ...


@runtime_checkable
class IModuleSecurity(Protocol):
    """Module security interface."""
    
    def get_required_permissions(self) -> ModulePermissions:
        """Get required permissions."""
        ...
    
    def validate_permissions(self, granted_permissions: ModulePermissions) -> bool:
        """Validate if granted permissions are sufficient."""
        ...
    
    def get_security_context(self) -> Dict[str, Any]:
        """Get current security context."""
        ...
    
    async def security_scan(self) -> Dict[str, Any]:
        """Perform security self-scan."""
        ...


class BaseModule(ABC):
    """
    Base module class implementing core interfaces.
    
    All modules must inherit from this class to ensure
    consistent behavior and interface compliance.
    """
    
    def __init__(self, name: str, version: str = "1.0.0"):
        self.name = name
        self.version = version
        self.state = ModuleState.UNLOADED
        self.logger = get_logger(f"module.{name}")
        
        # Core properties
        self.manager: Optional[Any] = None
        self.configuration = ModuleConfiguration()
        self.permissions = ModulePermissions()
        self.metrics = ModuleMetrics()
        
        # Event system
        self.event_handlers: Dict[str, List[Callable]] = {}
        
        # Error tracking
        self.last_error: Optional[Exception] = None
        self.restart_count = 0
        
        # Lifecycle timestamps
        self.loaded_at: Optional[datetime] = None
        self.started_at: Optional[datetime] = None
    
    # Abstract methods that must be implemented
    @abstractmethod
    async def initialize(self) -> bool:
        """Initialize the module."""
        pass
    
    @abstractmethod
    def get_metadata(self) -> Dict[str, Any]:
        """Get module metadata."""
        pass
    
    @abstractmethod
    def get_required_permissions(self) -> ModulePermissions:
        """Get required permissions."""
        pass
    
    # Default implementations
    async def start(self) -> bool:
        """Start the module."""
        try:
            self.state = ModuleState.LOADING
            self.started_at = datetime.now(timezone.utc)
            
            # Perform startup logic
            success = await self._on_start()
            
            if success:
                self.state = ModuleState.ACTIVE
                self.logger.info(f"Module {self.name} started successfully")
                return True
            else:
                self.state = ModuleState.ERROR
                self.logger.error(f"Module {self.name} failed to start")
                return False
                
        except Exception as e:
            self.last_error = e
            self.state = ModuleState.FAILED
            self.metrics.record_error()
            self.logger.error(f"Module {self.name} start failed: {e}")
            return False
    
    async def stop(self) -> bool:
        """Stop the module."""
        try:
            self.state = ModuleState.UNLOADING
            
            # Perform shutdown logic
            success = await self._on_stop()
            
            if success:
                self.state = ModuleState.UNLOADED
                self.logger.info(f"Module {self.name} stopped successfully")
                return True
            else:
                self.state = ModuleState.ERROR
                self.logger.error(f"Module {self.name} failed to stop cleanly")
                return False
                
        except Exception as e:
            self.last_error = e
            self.state = ModuleState.FAILED
            self.metrics.record_error()
            self.logger.error(f"Module {self.name} stop failed: {e}")
            return False
    
    async def pause(self) -> bool:
        """Pause the module."""
        if self.state == ModuleState.ACTIVE:
            self.state = ModuleState.PAUSED
            await self._on_pause()
            return True
        return False
    
    async def resume(self) -> bool:
        """Resume the module."""
        if self.state == ModuleState.PAUSED:
            self.state = ModuleState.ACTIVE
            await self._on_resume()
            return True
        return False
    
    async def shutdown(self) -> bool:
        """Shutdown the module."""
        return await self.stop()
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check."""
        return {
            "name": self.name,
            "version": self.version,
            "state": self.state.value,
            "healthy": self.state == ModuleState.ACTIVE,
            "uptime": (datetime.now(timezone.utc) - self.started_at).total_seconds() if self.started_at else 0,
            "metrics": {
                "memory_usage_mb": self.metrics.memory_usage_mb,
                "cpu_usage_percent": self.metrics.cpu_usage_percent,
                "api_calls": self.metrics.api_calls_count,
                "errors": self.metrics.error_count
            },
            "last_error": str(self.last_error) if self.last_error else None
        }
    
    # Configuration interface
    def get_config_schema(self) -> Dict[str, Any]:
        """Get configuration schema."""
        return {
            "type": "object",
            "properties": {
                "enabled": {"type": "boolean", "default": True},
                "auto_start": {"type": "boolean", "default": True},
                "timeout_seconds": {"type": "integer", "minimum": 1, "default": 30},
                "max_memory_mb": {"type": "integer", "minimum": 1, "default": 100}
            }
        }
    
    def validate_config(self, config: Dict[str, Any]) -> bool:
        """Validate configuration."""
        try:
            # Basic validation - can be extended by subclasses
            if not isinstance(config, dict):
                return False
            
            # Check required fields exist and have correct types
            if "enabled" in config and not isinstance(config["enabled"], bool):
                return False
            
            if "timeout_seconds" in config and not isinstance(config["timeout_seconds"], int):
                return False
            
            return True
        except Exception:
            return False
    
    def apply_config(self, config: Dict[str, Any]) -> bool:
        """Apply configuration."""
        try:
            if not self.validate_config(config):
                return False
            
            # Apply configuration to module
            self.configuration.enabled = config.get("enabled", True)
            self.configuration.auto_start = config.get("auto_start", True)
            self.configuration.timeout_seconds = config.get("timeout_seconds", 30)
            self.configuration.max_memory_mb = config.get("max_memory_mb", 100)
            self.configuration.custom_config.update(config.get("custom", {}))
            
            return True
        except Exception as e:
            self.logger.error(f"Failed to apply config: {e}")
            return False
    
    def get_current_config(self) -> Dict[str, Any]:
        """Get current configuration."""
        return {
            "enabled": self.configuration.enabled,
            "auto_start": self.configuration.auto_start,
            "timeout_seconds": self.configuration.timeout_seconds,
            "max_memory_mb": self.configuration.max_memory_mb,
            "custom": self.configuration.custom_config
        }
    
    # Event system
    def register_event_handler(self, event: str, handler: Callable) -> bool:
        """Register event handler."""
        try:
            if event not in self.event_handlers:
                self.event_handlers[event] = []
            self.event_handlers[event].append(handler)
            return True
        except Exception:
            return False
    
    def emit_event(self, event: str, data: Any) -> bool:
        """Emit event."""
        try:
            if self.manager and hasattr(self.manager, 'emit_event'):
                self.manager.emit_event(event, data, source=self.name)
            return True
        except Exception:
            return False
    
    # Lifecycle hooks (can be overridden by subclasses)
    async def _on_start(self) -> bool:
        """Override for custom start logic."""
        return True
    
    async def _on_stop(self) -> bool:
        """Override for custom stop logic."""
        return True
    
    async def _on_pause(self) -> bool:
        """Override for custom pause logic."""
        return True
    
    async def _on_resume(self) -> bool:
        """Override for custom resume logic."""
        return True
    
    # Utility methods
    def is_healthy(self) -> bool:
        """Check if module is healthy."""
        return self.state == ModuleState.ACTIVE and self.metrics.error_count < 10
    
    def get_api_version(self) -> str:
        """Get API version."""
        return "1.0"
    
    def get_available_methods(self) -> List[str]:
        """Get available API methods."""
        return [
            "initialize", "start", "stop", "pause", "resume", 
            "shutdown", "health_check", "get_metadata"
        ]


# Export interfaces and base classes
__all__ = [
    "ModuleCapability",
    "ModulePriority", 
    "ModuleState",
    "ModulePermissions",
    "ModuleMetrics",
    "ModuleConfiguration",
    "IModuleLifecycle",
    "IModuleConfiguration", 
    "IModuleAPI",
    "IModuleSecurity",
    "BaseModule"
]
