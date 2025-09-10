"""
PlexiChat Plugin Security Manager

This module provides comprehensive security management for plugins, including:
- Advanced sandboxing with restricted builtins
- Permission request and approval system
- Secure import filtering
- Resource monitoring and limits
- Audit logging for all security events
- Integration with admin UI for permission management

Based on the Plugin API Access documentation, this manager implements
proper security controls to prevent malicious plugins from causing
system-wide damage while allowing legitimate plugins to function properly.
"""

import asyncio
import hashlib
import importlib.util
import json
import logging
import os
import resource
import signal
import sys
import threading
import time
import traceback
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union
from weakref import WeakSet

import psutil

# Core imports with fallbacks
from plexichat.core.security.security_manager import get_security_system

try:
    from plexichat.core.config_manager import (
        get_max_plugin_memory,
        get_plugin_sandbox_enabled,
        get_plugin_timeout,
    )
except ImportError:

    def get_plugin_timeout():
        return 30

    def get_max_plugin_memory():
        return 100 * 1024 * 1024

    def get_plugin_sandbox_enabled():
        return True


try:
    from plexichat.core.logging import get_logger
except ImportError:
    get_logger = logging.getLogger

try:
    from plexichat.core.database.manager import database_manager
    from plexichat.core.files import file_manager
except ImportError:
    database_manager = None
    file_manager = None

try:
    from plexichat.shared.exceptions import PluginError, SecurityError, ValidationError
except ImportError:

    class SecurityError(Exception):
        pass

    class PluginError(Exception):
        pass

    class ValidationError(Exception):
        pass


# ==============================================================================
# SAFE FILE MANAGER
# ==============================================================================


class SafeFileManager:
    """Provides controlled file access through the existing file manager."""

    def __init__(self, plugin_name: str, security_manager: "PluginSecurityManager"):
        self.plugin_name = plugin_name
        self.security_manager = security_manager
        self.logger = get_logger(f"plugin.{plugin_name}.safe_file")

    def open(self, filename: str, mode: str = "r", **kwargs):
        """Safe file open that checks permissions."""
        # Optional shared sanitization using core security system controlled by config
        try:
            from plexichat.core.config_manager import get_config

            sec_cfg = get_config("security", None)
            sanitation_enabled = (
                True
                if sec_cfg is None
                else bool(getattr(sec_cfg, "sanitation_enabled", True))
            )
            if (
                sanitation_enabled
                and hasattr(self.security_manager, "_core_security")
                and self.security_manager._core_security
            ):
                sanitizer = self.security_manager._core_security.input_sanitizer
                filename = sanitizer.sanitize_input(filename)
        except Exception:
            pass
        # Enforce strict sandbox if configured
        try:
            from plexichat.core.config_manager import get_config

            sec_cfg = get_config("security", None)
            strict = (
                False
                if sec_cfg is None
                else bool(getattr(sec_cfg, "plugin_sandbox_strict", True))
            )
            if strict and not self._has_permission("file_read"):
                raise PermissionError("File read not permitted by sandbox policy")
        except Exception:
            pass
        # Check if plugin has file access permission
        if "w" in mode or "a" in mode or "+" in mode:
            if not self.security_manager.has_permission(
                self.plugin_name, PermissionType.FILE_WRITE
            ):
                raise PermissionError(
                    f"Plugin {self.plugin_name} does not have file write permission"
                )
        else:
            if not self.security_manager.has_permission(
                self.plugin_name, PermissionType.FILE_READ
            ):
                raise PermissionError(
                    f"Plugin {self.plugin_name} does not have file read permission"
                )

        # Use the existing file manager for controlled access
        file_path = Path(filename).resolve()

        # Ensure path is within plugin's allowed directories
        plugin_data_dir = (
            Path(__file__).resolve().parents[4] / "plugins" / self.plugin_name / "data"
        )
        plugin_data_dir.mkdir(parents=True, exist_ok=True)

        try:
            file_path.relative_to(plugin_data_dir)
        except ValueError:
            raise PermissionError(
                f"Access to '{file_path}' is not allowed. Use plugin data directory: {plugin_data_dir}"
            )

        self.logger.debug(f"Safe file access: {file_path} (mode: {mode})")
        return open(filename, mode, **kwargs)

    async def upload_file(self, file_data: bytes, filename: str, **kwargs):
        """Upload file through the file manager."""
        if not self.security_manager.has_permission(
            self.plugin_name, PermissionType.FILE_WRITE
        ):
            raise PermissionError(
                f"Plugin {self.plugin_name} does not have file write permission"
            )

        if file_manager:
            # Use a dummy user ID for plugin uploads
            return await file_manager.upload_file(
                file_data, filename, uploaded_by=-1, **kwargs
            )
        else:
            raise RuntimeError("File manager not available")

    async def get_file_data(self, file_id: str):
        """Get file data through the file manager."""
        if not self.security_manager.has_permission(
            self.plugin_name, PermissionType.FILE_READ
        ):
            raise PermissionError(
                f"Plugin {self.plugin_name} does not have file read permission"
            )

        if file_manager:
            return await file_manager.get_file_data(file_id)
        else:
            raise RuntimeError("File manager not available")


# ==============================================================================
# NETWORK BROKER
# ==============================================================================


class NetworkBroker:
    """Provides brokered network access for plugins."""

    def __init__(self, plugin_name: str, security_manager: "PluginSecurityManager"):
        self.plugin_name = plugin_name
        self.security_manager = security_manager
        self.logger = get_logger(f"plugin.{plugin_name}.network")
        self._session = None

    def _check_network_permission(self):
        """Check if plugin has network access permission."""
        if not self.security_manager.has_permission(
            self.plugin_name, PermissionType.NETWORK_ACCESS
        ):
            raise PermissionError(
                f"Plugin {self.plugin_name} does not have network access permission"
            )

    async def get(self, url: str, **kwargs):
        """Make a GET request through the broker."""
        self._check_network_permission()

        try:
            import aiohttp
        except ImportError:
            raise RuntimeError("aiohttp not available for network access")

        if not self._session:
            timeout = aiohttp.ClientTimeout(total=30)  # 30 second timeout
            self._session = aiohttp.ClientSession(timeout=timeout)

        # Optional shared sanitization using core security system
        try:
            if (
                hasattr(self.security_manager, "_core_security")
                and self.security_manager._core_security
            ):
                sanitizer = self.security_manager._core_security.input_sanitizer
                url = sanitizer.sanitize_input(url)
                threats = (
                    self.security_manager._core_security.input_sanitizer.detect_threats(
                        url
                    )
                )
                if threats:
                    self.logger.warning(
                        f"Blocked suspicious URL by sanitizer", url=url, threats=threats
                    )
                    raise RuntimeError("Suspicious URL blocked")
        except Exception:
            pass

        self.logger.debug(f"Network GET request: {url}")

        # Log the network access
        if (
            hasattr(self.security_manager, "_sandboxes")
            and self.plugin_name in self.security_manager._sandboxes
        ):
            sandbox = self.security_manager._sandboxes[self.plugin_name]
            if hasattr(sandbox, "network_monitor"):
                from urllib.parse import urlparse

                parsed = urlparse(url)
                sandbox.network_monitor.log_connection(
                    parsed.hostname or "unknown", parsed.port or 80, "http"
                )

        async with self._session.get(url, **kwargs) as response:
            return await response.text()

    async def post(self, url: str, **kwargs):
        """Make a POST request through the broker."""
        self._check_network_permission()

        try:
            import aiohttp
        except ImportError:
            raise RuntimeError("aiohttp not available for network access")

        if not self._session:
            timeout = aiohttp.ClientTimeout(total=30)
            self._session = aiohttp.ClientSession(timeout=timeout)

        # Optional shared sanitization using core security system
        try:
            if (
                hasattr(self.security_manager, "_core_security")
                and self.security_manager._core_security
            ):
                sanitizer = self.security_manager._core_security.input_sanitizer
                url = sanitizer.sanitize_input(url)
                threats = (
                    self.security_manager._core_security.input_sanitizer.detect_threats(
                        url
                    )
                )
                if threats:
                    self.logger.warning(
                        f"Blocked suspicious URL by sanitizer", url=url, threats=threats
                    )
                    raise RuntimeError("Suspicious URL blocked")
        except Exception:
            pass

        self.logger.debug(f"Network POST request: {url}")

        async with self._session.post(url, **kwargs) as response:
            return await response.text()

    async def close(self):
        """Close the network session."""
        if self._session:
            await self._session.close()
            self._session = None


# ==============================================================================
# SECURITY ENUMS AND DATA CLASSES
# ==============================================================================


class PermissionType(Enum):
    """Types of permissions that plugins can request."""

    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    NETWORK_ACCESS = "network_access"
    DATABASE_READ = "database_read"
    DATABASE_WRITE = "database_write"
    SYSTEM_COMMANDS = "system_commands"
    PROCESS_SPAWN = "process_spawn"
    ENVIRONMENT_ACCESS = "environment_access"
    CORE_SERVICE_ACCESS = "core_service_access"
    USER_DATA_ACCESS = "user_data_access"
    CONFIGURATION_WRITE = "configuration_write"
    PLUGIN_MANAGEMENT = "plugin_management"
    ADMIN_FUNCTIONS = "admin_functions"
    EXTERNAL_API_ACCESS = "external_api_access"
    CRYPTO_OPERATIONS = "crypto_operations"


class PermissionStatus(Enum):
    """Status of permission requests."""

    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    REVOKED = "revoked"
    EXPIRED = "expired"


class SecurityThreatLevel(Enum):
    """Security threat levels for plugins."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AuditEventType(Enum):
    """Types of security audit events."""

    PERMISSION_REQUEST = "permission_request"
    PERMISSION_GRANTED = "permission_granted"
    PERMISSION_DENIED = "permission_denied"
    PERMISSION_REVOKED = "permission_revoked"
    SECURITY_VIOLATION = "security_violation"
    RESOURCE_LIMIT_EXCEEDED = "resource_limit_exceeded"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    SANDBOX_ESCAPE_ATTEMPT = "sandbox_escape_attempt"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    MALICIOUS_CODE_DETECTED = "malicious_code_detected"


@dataclass
class PermissionRequest:
    """Represents a permission request from a plugin."""

    plugin_name: str
    permission_type: PermissionType
    justification: str
    requested_at: datetime
    status: PermissionStatus = PermissionStatus.PENDING
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    additional_data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SecurityAuditEvent:
    """Represents a security audit event."""

    event_id: str
    plugin_name: str
    event_type: AuditEventType
    threat_level: SecurityThreatLevel
    description: str
    timestamp: datetime
    details: Dict[str, Any] = field(default_factory=dict)
    resolved: bool = False
    resolved_by: Optional[str] = None
    resolved_at: Optional[datetime] = None


@dataclass
class ResourceUsage:
    """Tracks resource usage for a plugin."""

    cpu_percent: float
    memory_bytes: int
    disk_io_bytes: int
    network_io_bytes: int
    file_handles: int
    thread_count: int
    timestamp: datetime


@dataclass
class SecurityPolicy:
    """Security policy configuration for plugins."""

    max_cpu_percent: float = 10.0
    max_memory_bytes: int = 100 * 1024 * 1024  # 100MB
    max_file_handles: int = 50
    max_thread_count: int = 10
    max_network_connections: int = 5
    allowed_file_paths: List[str] = field(default_factory=list)
    blocked_modules: Set[str] = field(default_factory=set)
    allowed_modules: Set[str] = field(default_factory=set)
    permission_auto_approve: Set[PermissionType] = field(default_factory=set)
    permission_auto_deny: Set[PermissionType] = field(default_factory=set)
    audit_all_actions: bool = True
    quarantine_on_violation: bool = True


# ==============================================================================
# SECURE SANDBOX ENVIRONMENT
# ==============================================================================


class SecureSandbox:
    """Provides a secure sandbox environment for plugin execution."""

    def __init__(self, plugin_name: str, security_policy: SecurityPolicy):
        self.plugin_name = plugin_name
        self.security_policy = security_policy
        self.logger = get_logger(f"plugin.{plugin_name}.sandbox")
        self.resource_monitor = ResourceMonitor(plugin_name, security_policy)
        self.file_access_monitor = FileAccessMonitor(plugin_name, security_policy)
        self.network_monitor = NetworkMonitor(plugin_name, security_policy)
        self._restricted_builtins = self._create_restricted_builtins()
        self._original_modules = {}
        self._sandbox_active = False

    def _create_restricted_builtins(self) -> Dict[str, Any]:
        """Create a restricted set of builtins for the sandbox based on PLUGIN_SECURITY.md whitelist."""
        # Safe modules that are always allowed (based on PLUGIN_SECURITY.md)
        self._safe_modules = {
            # Standard library (safe modules)
            "json",
            "datetime",
            "typing",
            "dataclasses",
            "enum",
            "logging",
            "pathlib",
            "uuid",
            "time",
            "base64",
            "mimetypes",
            "ast",
            "secrets",
            "io",
            "re",
            "hashlib",
            "copy",
            "functools",
            "itertools",
            "collections",
            "math",
            "random",
            "decimal",
            "fractions",
            "statistics",
            "heapq",
            "bisect",
            "array",
            "weakref",
            "types",
            "inspect",
            "traceback",
            "pprint",
            "pickle",
            "marshal",
            "struct",
            "csv",
            "configparser",
            "gettext",
            "locale",
            "calendar",
            "email",
            "email.mime",
            "html",
            "html.parser",
            "xml.etree.ElementTree",
            "string",
            "textwrap",
            "unicodedata",
            "codecs",
            "reprlib",
            "difflib",
            "operator",
            # Common third-party (safe)
            "cryptography.fernet",
            "jinja2.sandbox",
            "colorama",
            "rich",
        }

        # Dangerous modules that require explicit admin approval (based on PLUGIN_SECURITY.md)
        self._dangerous_modules = {
            # System access modules
            "os",
            "sys",
            "subprocess",
            "socket",
            "socketserver",
            "select",
            "signal",
            "atexit",
            "ctypes",
            "mmap",
            "resource",
            "shutil",
            "tempfile",
            "glob",
            "fnmatch",
            "linecache",
            "shlex",
            "platform",
            "getpass",
            "pwd",
            "grp",
            "termios",
            "tty",
            "pty",
            "fcntl",
            "pipes",
            "posix",
            "nt",
            "winreg",
            "winsound",
            "msvcrt",
            # Threading and multiprocessing
            "threading",
            "multiprocessing",
            "concurrent",
            "asyncio",
            "queue",
            # Import and execution control
            "importlib",
            "pkgutil",
            "modulefinder",
            "runpy",
            "keyword",
            "token",
            "tokenize",
            "tabnanny",
            "pyclbr",
            "py_compile",
            "compileall",
            "dis",
            "pickletools",
            "distutils",
            "ensurepip",
            "venv",
            "zipapp",
            # Network modules
            "requests",
            "urllib.request",
            "urllib.error",
            "http",
            "ftplib",
            "poplib",
            "imaplib",
            "nntplib",
            "smtplib",
            "telnetlib",
            "ssl",
            "hmac",
            # Database and compression
            "sqlite3",
            "dbm",
            "zlib",
            "gzip",
            "bz2",
            "lzma",
            "zipfile",
            "tarfile",
            # Third-party network/system modules
            "aiohttp",
            "fastapi",
            "requests",
            "psutil",
        }

        safe_builtins = {
            # Safe built-in functions
            "abs",
            "all",
            "any",
            "ascii",
            "bin",
            "bool",
            "bytearray",
            "bytes",
            "callable",
            "chr",
            "classmethod",
            "complex",
            "dict",
            "dir",
            "divmod",
            "enumerate",
            "filter",
            "float",
            "format",
            "frozenset",
            "getattr",
            "hasattr",
            "hash",
            "hex",
            "id",
            "int",
            "isinstance",
            "issubclass",
            "iter",
            "len",
            "list",
            "map",
            "max",
            "memoryview",
            "min",
            "next",
            "object",
            "oct",
            "ord",
            "pow",
            "property",
            "range",
            "repr",
            "reversed",
            "round",
            "set",
            "setattr",
            "slice",
            "sorted",
            "staticmethod",
            "str",
            "sum",
            "super",
            "tuple",
            "type",
            "vars",
            "zip",
            # Safe exceptions
            "ArithmeticError",
            "AssertionError",
            "AttributeError",
            "BaseException",
            "BufferError",
            "BytesWarning",
            "DeprecationWarning",
            "EOFError",
            "Exception",
            "FloatingPointError",
            "FutureWarning",
            "GeneratorExit",
            "ImportError",
            "ImportWarning",
            "IndentationError",
            "IndexError",
            "KeyError",
            "KeyboardInterrupt",
            "LookupError",
            "MemoryError",
            "NameError",
            "NotImplementedError",
            "OSError",
            "OverflowError",
            "PendingDeprecationWarning",
            "ReferenceError",
            "ResourceWarning",
            "RuntimeError",
            "RuntimeWarning",
            "StopAsyncIteration",
            "StopIteration",
            "SyntaxError",
            "SyntaxWarning",
            "SystemError",
            "SystemExit",
            "TabError",
            "TypeError",
            "UnboundLocalError",
            "UnicodeDecodeError",
            "UnicodeEncodeError",
            "UnicodeError",
            "UnicodeTranslateError",
            "UnicodeWarning",
            "UserWarning",
            "ValueError",
            "Warning",
            "ZeroDivisionError",
        }

        restricted_builtins = {}
        for name in safe_builtins:
            if hasattr(__builtins__, name):
                restricted_builtins[name] = getattr(__builtins__, name)

        # Add restricted versions of dangerous functions
        restricted_builtins.update(
            {
                "__import__": self._restricted_import,
                "open": self._restricted_open,
                "exec": self._restricted_exec,
                "eval": self._restricted_eval,
                "compile": self._restricted_compile,
                "input": self._restricted_input,
                "print": self._restricted_print,
                "__build_class__": __builtins__["__build_class__"],
                "__name__": "__sandbox__",
            }
        )

        return restricted_builtins

    def _restricted_import(self, name: str, *args, **kwargs):
        """Restricted import function that enforces module whitelisting based on PLUGIN_SECURITY.md."""
        # Check if module is explicitly blocked by security policy
        if name in self.security_policy.blocked_modules:
            self._log_security_violation(
                f"Attempted to import blocked module: {name}", SecurityThreatLevel.HIGH
            )
            raise ImportError(f"Module '{name}' is blocked by security policy")

        # Check if module is dangerous and requires explicit admin approval
        if name in self._dangerous_modules or any(
            name.startswith(dm + ".") for dm in self._dangerous_modules
        ):
            if not self._check_module_permission(name):
                self._log_security_violation(
                    f"Attempted to import dangerous module without permission: {name}",
                    SecurityThreatLevel.HIGH,
                )
                raise ImportError(
                    f"Module '{name}' requires admin approval. Contact administrator to request permission."
                )

        # Check if module is in safe list (always allowed)
        if name in self._safe_modules or any(
            name.startswith(sm + ".") for sm in self._safe_modules
        ):
            pass  # Always allowed
        elif name.startswith("plexichat."):
            # PlexiChat internal modules - only allow plugin-safe modules
            if not self._is_plexichat_module_safe(name):
                self._log_security_violation(
                    f"Attempted to import restricted PlexiChat module: {name}",
                    SecurityThreatLevel.MEDIUM,
                )
                raise ImportError(
                    f"PlexiChat module '{name}' is not available to plugins"
                )
        elif name.startswith("plugins_internal"):
            # Allow access to the generated plugin SDK
            pass
        else:
            # For any other module, check if it's in the allowed modules list
            if (
                self.security_policy.allowed_modules
                and name not in self.security_policy.allowed_modules
            ):
                self._log_security_violation(
                    f"Attempted to import non-whitelisted module: {name}",
                    SecurityThreatLevel.MEDIUM,
                )
                raise ImportError(
                    f"Module '{name}' not in whitelist. Contact administrator to request permission."
                )
            elif not self.security_policy.allowed_modules:
                # If no explicit whitelist, deny unknown modules by default
                self._log_security_violation(
                    f"Attempted to import unknown module: {name}",
                    SecurityThreatLevel.MEDIUM,
                )
                raise ImportError(
                    f"Module '{name}' not in safe module list. Contact administrator to request permission."
                )

        # Log the import for audit purposes
        self.logger.debug(f"Plugin importing module: {name}")

        try:
            return __import__(name, *args, **kwargs)
        except ImportError as e:
            self.logger.warning(f"Failed to import module {name}: {e}")
            raise

    def _check_module_permission(self, module_name: str) -> bool:
        """Check if plugin has permission to import a dangerous module."""
        if hasattr(self, "_security_manager"):
            # Check database for approved modules (async call made sync for sandbox)
            try:
                # Use a cached version for performance in sandbox
                if hasattr(self._security_manager, "_module_cache"):
                    cache_key = f"{self.plugin_name}:{module_name}"
                    return self._security_manager._module_cache.get(cache_key, False)
                return self._security_manager._is_module_approved_sync(
                    self.plugin_name, module_name
                )
            except Exception as e:
                self.logger.error(f"Error checking module permission: {e}")
                return False
        return False

    def _is_plexichat_module_safe(self, module_name: str) -> bool:
        """Check if a PlexiChat module is safe for plugin access."""
        # Only allow specific plugin-safe modules (based on PLUGIN_SECURITY.md)
        safe_plexichat_modules = {
            "plexichat.core.plugins.sdk",
            "plexichat.core.plugins.generated_sdk",
            "plexichat.shared.exceptions",
            "plexichat.shared.models",
            "plexichat.shared.utils",
            "plexichat.shared.types",
            "plugins_internal",  # Auto-generated SDK
        }
        return module_name in safe_plexichat_modules or module_name.startswith(
            "plugins_internal"
        )

    def _restricted_open(self, filename: str, mode: str = "r", *args, **kwargs):
        """Restricted file open function that uses SafeFileManager."""
        # Block direct file access - force use of SafeFileManager
        self._log_security_violation(
            f"Attempted direct file access: {filename} (mode: {mode})",
            SecurityThreatLevel.HIGH,
        )
        raise SecurityError(
            "Direct file access not allowed. Use the provided safe_file_manager instead."
        )

    def _restricted_exec(self, *args, **kwargs):
        """Restricted exec function - completely disabled."""
        self._log_security_violation(
            "Attempted to use exec() function", SecurityThreatLevel.CRITICAL
        )
        raise SecurityError("Dynamic code execution is not allowed in sandbox")

    def _restricted_eval(self, *args, **kwargs):
        """Restricted eval function - completely disabled."""
        self._log_security_violation(
            "Attempted to use eval() function", SecurityThreatLevel.CRITICAL
        )
        raise SecurityError("Dynamic code evaluation is not allowed in sandbox")

    def _restricted_compile(self, *args, **kwargs):
        """Restricted compile function - completely disabled."""
        self._log_security_violation(
            "Attempted to use compile() function", SecurityThreatLevel.HIGH
        )
        raise SecurityError("Code compilation is not allowed in sandbox")

    def _restricted_input(self, prompt: str = ""):
        """Restricted input function that logs all input requests."""
        self.logger.warning(f"Plugin requested user input: {prompt}")
        self._log_security_violation(
            f"Attempted to request user input: {prompt}", SecurityThreatLevel.MEDIUM
        )
        raise SecurityError("User input is not allowed in sandbox")

    def _restricted_print(self, *args, **kwargs):
        """Restricted print function that logs all output."""
        message = " ".join(str(arg) for arg in args)
        self.logger.info(f"Plugin output: {message}")
        # Allow print but log it for audit purposes
        print(f"[{self.plugin_name}]", *args, **kwargs)

    def _log_security_violation(
        self, description: str, threat_level: SecurityThreatLevel
    ):
        """Log a security violation."""
        event = SecurityAuditEvent(
            event_id=hashlib.sha256(
                f"{self.plugin_name}{description}{time.time()}".encode()
            ).hexdigest()[:16],
            plugin_name=self.plugin_name,
            event_type=AuditEventType.SECURITY_VIOLATION,
            threat_level=threat_level,
            description=description,
            timestamp=datetime.now(timezone.utc),
            details={
                "stack_trace": traceback.format_stack(),
                "thread_id": threading.current_thread().ident,
            },
        )

        # This would be handled by the main security manager
        if hasattr(self, "_security_manager"):
            asyncio.create_task(self._security_manager.log_audit_event(event))

    def get_safe_apis(self) -> Dict[str, Any]:
        """Get safe APIs that plugins can use."""
        return {
            "safe_file_manager": SafeFileManager(
                self.plugin_name, self._security_manager
            ),
            "network_broker": NetworkBroker(self.plugin_name, self._security_manager),
            "logger": get_logger(f"plugin.{self.plugin_name}"),
        }

    @contextmanager
    def activate(self):
        """Activate the sandbox environment."""
        if self._sandbox_active:
            yield
            return

        try:
            self._sandbox_active = True
            self.resource_monitor.start_monitoring()

            # Provide safe APIs to the plugin
            safe_apis = self.get_safe_apis()

            self.logger.info(f"Sandbox activated for plugin: {self.plugin_name}")
            yield safe_apis
        finally:
            self._sandbox_active = False
            self.resource_monitor.stop_monitoring()

            # Clean up network sessions
            if "network_broker" in locals():
                try:
                    import asyncio

                    loop = asyncio.get_event_loop()
                    if loop.is_running():
                        loop.create_task(safe_apis["network_broker"].close())
                except:
                    pass

            self.logger.info(f"Sandbox deactivated for plugin: {self.plugin_name}")


# ==============================================================================
# RESOURCE MONITORING
# ==============================================================================


class ResourceMonitor:
    """Monitors resource usage of plugins."""

    def __init__(self, plugin_name: str, security_policy: SecurityPolicy):
        self.plugin_name = plugin_name
        self.security_policy = security_policy
        self.logger = get_logger(f"plugin.{plugin_name}.resources")
        self._monitoring = False
        self._monitor_thread = None
        self._usage_history = deque(maxlen=100)
        self._violation_count = 0
        self._last_violation = None

    def start_monitoring(self):
        """Start resource monitoring."""
        if self._monitoring:
            return

        self._monitoring = True
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            name=f"ResourceMonitor-{self.plugin_name}",
            daemon=True,
        )
        self._monitor_thread.start()
        self.logger.debug("Resource monitoring started")

    def stop_monitoring(self):
        """Stop resource monitoring."""
        self._monitoring = False
        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=1.0)
        self.logger.debug("Resource monitoring stopped")

    def _monitor_loop(self):
        """Main monitoring loop."""
        while self._monitoring:
            try:
                usage = self._get_current_usage()
                self._usage_history.append(usage)
                self._check_violations(usage)
                time.sleep(1.0)  # Monitor every second
            except Exception as e:
                self.logger.error(f"Error in resource monitoring: {e}")
                time.sleep(5.0)  # Back off on error

    def _get_current_usage(self) -> ResourceUsage:
        """Get current resource usage."""
        try:
            process = psutil.Process()

            # Get CPU usage
            cpu_percent = process.cpu_percent()

            # Get memory usage
            memory_info = process.memory_info()
            memory_bytes = memory_info.rss

            # Get I/O stats
            try:
                io_counters = process.io_counters()
                disk_io_bytes = io_counters.read_bytes + io_counters.write_bytes
            except (psutil.AccessDenied, AttributeError):
                disk_io_bytes = 0

            # Network I/O is harder to track per-plugin, so we'll estimate
            network_io_bytes = 0

            # Get file handles
            try:
                file_handles = (
                    process.num_fds()
                    if hasattr(process, "num_fds")
                    else len(process.open_files())
                )
            except (psutil.AccessDenied, AttributeError):
                file_handles = 0

            # Get thread count
            thread_count = process.num_threads()

            return ResourceUsage(
                cpu_percent=cpu_percent,
                memory_bytes=memory_bytes,
                disk_io_bytes=disk_io_bytes,
                network_io_bytes=network_io_bytes,
                file_handles=file_handles,
                thread_count=thread_count,
                timestamp=datetime.now(timezone.utc),
            )
        except psutil.NoSuchProcess:
            # Process no longer exists
            return ResourceUsage(0, 0, 0, 0, 0, 0, datetime.now(timezone.utc))

    def _check_violations(self, usage: ResourceUsage):
        """Check for resource limit violations."""
        violations = []

        if usage.cpu_percent > self.security_policy.max_cpu_percent:
            violations.append(
                f"CPU usage ({usage.cpu_percent:.1f}%) exceeds limit ({self.security_policy.max_cpu_percent:.1f}%)"
            )

        if usage.memory_bytes > self.security_policy.max_memory_bytes:
            violations.append(
                f"Memory usage ({usage.memory_bytes / 1024 / 1024:.1f}MB) exceeds limit ({self.security_policy.max_memory_bytes / 1024 / 1024:.1f}MB)"
            )

        if usage.file_handles > self.security_policy.max_file_handles:
            violations.append(
                f"File handles ({usage.file_handles}) exceed limit ({self.security_policy.max_file_handles})"
            )

        if usage.thread_count > self.security_policy.max_thread_count:
            violations.append(
                f"Thread count ({usage.thread_count}) exceeds limit ({self.security_policy.max_thread_count})"
            )

        if violations:
            self._violation_count += 1
            self._last_violation = datetime.now(timezone.utc)

            for violation in violations:
                self.logger.warning(f"Resource violation: {violation}")

                # Log audit event
                if hasattr(self, "_security_manager"):
                    event = SecurityAuditEvent(
                        event_id=hashlib.sha256(
                            f"{self.plugin_name}{violation}{time.time()}".encode()
                        ).hexdigest()[:16],
                        plugin_name=self.plugin_name,
                        event_type=AuditEventType.RESOURCE_LIMIT_EXCEEDED,
                        threat_level=SecurityThreatLevel.MEDIUM,
                        description=violation,
                        timestamp=datetime.now(timezone.utc),
                        details={"usage": usage.__dict__},
                    )
                    asyncio.create_task(self._security_manager.log_audit_event(event))

    def get_usage_summary(self) -> Dict[str, Any]:
        """Get a summary of resource usage."""
        if not self._usage_history:
            return {}

        recent_usage = list(self._usage_history)[-10:]  # Last 10 measurements

        return {
            "current_cpu": recent_usage[-1].cpu_percent if recent_usage else 0,
            "avg_cpu": sum(u.cpu_percent for u in recent_usage) / len(recent_usage),
            "max_cpu": max(u.cpu_percent for u in recent_usage),
            "current_memory": recent_usage[-1].memory_bytes if recent_usage else 0,
            "avg_memory": sum(u.memory_bytes for u in recent_usage) / len(recent_usage),
            "max_memory": max(u.memory_bytes for u in recent_usage),
            "violation_count": self._violation_count,
            "last_violation": (
                self._last_violation.isoformat() if self._last_violation else None
            ),
        }


# ==============================================================================
# FILE ACCESS MONITORING
# ==============================================================================


class FileAccessMonitor:
    """Monitors file system access by plugins."""

    def __init__(self, plugin_name: str, security_policy: SecurityPolicy):
        self.plugin_name = plugin_name
        self.security_policy = security_policy
        self.logger = get_logger(f"plugin.{plugin_name}.filesystem")
        self._access_log = deque(maxlen=1000)
        self._allowed_paths = self._build_allowed_paths()

    def _build_allowed_paths(self) -> List[Path]:
        """Build list of allowed file paths for the plugin."""
        project_root = Path(__file__).resolve().parents[4]

        default_paths = [
            project_root / "plugins" / self.plugin_name / "data",
            project_root / "logs" / "plugin" / self.plugin_name,
            project_root / "temp" / "plugin" / self.plugin_name,
        ]

        # Create directories if they don't exist
        for path in default_paths:
            path.mkdir(parents=True, exist_ok=True)

        # Add configured paths
        configured_paths = [Path(p) for p in self.security_policy.allowed_file_paths]

        return default_paths + configured_paths

    def is_path_allowed(self, file_path: Path, mode: str) -> bool:
        """Check if access to a file path is allowed."""
        file_path = file_path.resolve()

        # Check if path is within allowed directories
        for allowed_path in self._allowed_paths:
            try:
                file_path.relative_to(allowed_path)
                return True
            except ValueError:
                continue

        # Special case: allow reading from Python standard library
        if "r" in mode and not any(char in mode for char in "wax+"):
            try:
                # Check if it's a Python standard library file
                if str(file_path).startswith(sys.prefix):
                    return True
            except:
                pass

        return False

    def log_file_access(self, file_path: Path, mode: str):
        """Log file access for audit purposes."""
        access_info = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "file_path": str(file_path),
            "mode": mode,
            "thread_id": threading.current_thread().ident,
        }

        self._access_log.append(access_info)
        self.logger.debug(f"File access: {file_path} (mode: {mode})")

    def get_access_summary(self) -> Dict[str, Any]:
        """Get a summary of file access activity."""
        if not self._access_log:
            return {"total_accesses": 0}

        recent_accesses = list(self._access_log)[-100:]  # Last 100 accesses

        file_counts = defaultdict(int)
        mode_counts = defaultdict(int)

        for access in recent_accesses:
            file_counts[access["file_path"]] += 1
            mode_counts[access["mode"]] += 1

        return {
            "total_accesses": len(self._access_log),
            "recent_accesses": len(recent_accesses),
            "most_accessed_files": dict(
                sorted(file_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            ),
            "access_modes": dict(mode_counts),
            "last_access": (
                recent_accesses[-1]["timestamp"] if recent_accesses else None
            ),
        }


# ==============================================================================
# NETWORK MONITORING
# ==============================================================================


class NetworkMonitor:
    """Monitors network access by plugins."""

    def __init__(self, plugin_name: str, security_policy: SecurityPolicy):
        self.plugin_name = plugin_name
        self.security_policy = security_policy
        self.logger = get_logger(f"plugin.{plugin_name}.network")
        self._connection_log = deque(maxlen=1000)
        self._active_connections = WeakSet()

    def log_connection(self, host: str, port: int, protocol: str = "tcp"):
        """Log a network connection attempt."""
        connection_info = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "host": host,
            "port": port,
            "protocol": protocol,
            "thread_id": threading.current_thread().ident,
        }

        self._connection_log.append(connection_info)
        self.logger.debug(f"Network connection: {host}:{port} ({protocol})")

    def check_connection_allowed(self, host: str, port: int) -> bool:
        """Check if a network connection is allowed."""
        # Check connection limits
        if (
            len(self._active_connections)
            >= self.security_policy.max_network_connections
        ):
            self.logger.warning(
                f"Network connection limit exceeded: {len(self._active_connections)}"
            )
            return False

        # Add additional checks here (blocked hosts, ports, etc.)
        return True

    def get_connection_summary(self) -> Dict[str, Any]:
        """Get a summary of network activity."""
        if not self._connection_log:
            return {"total_connections": 0}

        recent_connections = list(self._connection_log)[-100:]  # Last 100 connections

        host_counts = defaultdict(int)
        port_counts = defaultdict(int)

        for conn in recent_connections:
            host_counts[conn["host"]] += 1
            port_counts[conn["port"]] += 1

        return {
            "total_connections": len(self._connection_log),
            "recent_connections": len(recent_connections),
            "active_connections": len(self._active_connections),
            "most_contacted_hosts": dict(
                sorted(host_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            ),
            "most_used_ports": dict(
                sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            ),
            "last_connection": (
                recent_connections[-1]["timestamp"] if recent_connections else None
            ),
        }


# ==============================================================================
# MAIN PLUGIN SECURITY MANAGER
# ==============================================================================


class PluginSecurityManager:
    """Main plugin security manager that coordinates all security aspects."""

    def __init__(self):
        self.logger = get_logger("plugin.security")
        # Reference the core security system for shared sanitization/policies
        try:
            self._core_security = get_security_system()
        except Exception:
            self._core_security = None
        self._permission_requests: Dict[str, List[PermissionRequest]] = defaultdict(
            list
        )
        self._approved_permissions: Dict[str, Set[PermissionType]] = defaultdict(set)
        self._audit_events: List[SecurityAuditEvent] = []
        self._security_policies: Dict[str, SecurityPolicy] = {}
        self._sandboxes: Dict[str, SecureSandbox] = {}
        self._quarantined_plugins: Set[str] = set()
        self._disabled_plugins: Set[str] = set()  # Plugins disabled by default
        self._default_policy = SecurityPolicy()
        self._lock = threading.RLock()
        self._db_initialized = False
        self._module_cache: Dict[str, bool] = {}  # Cache for module permissions
        self._cache_expiry: Dict[str, datetime] = {}  # Cache expiry times

        # Enhanced default policy based on PLUGIN_SECURITY.md
        self._default_policy.permission_auto_deny = {
            PermissionType.SYSTEM_COMMANDS,
            PermissionType.PROCESS_SPAWN,
            PermissionType.ADMIN_FUNCTIONS,
            PermissionType.PLUGIN_MANAGEMENT,
            PermissionType.CONFIGURATION_WRITE,
        }

        # Initialize database tables if available
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.create_task(self._init_database())
            else:
                asyncio.run(self._init_database())
        except RuntimeError:
            # No event loop, will initialize later
            pass

    async def _init_database(self):
        """Initialize database tables for security data."""
        if not database_manager:
            self.logger.warning(
                "Database manager not available, using in-memory storage"
            )
            return

        try:
            # Initialize database manager
            await database_manager.initialize()

            # Run the plugin permissions migration to ensure tables exist
            try:
                from plexichat.core.database.migrations.add_plugin_permissions import (
                    apply_migration,
                )

                migration_success = await apply_migration(database_manager)
                if migration_success:
                    self.logger.info(
                        "Plugin permissions migration applied successfully"
                    )
                else:
                    self.logger.warning(
                        "Plugin permissions migration failed or was already applied"
                    )
            except ImportError:
                self.logger.warning(
                    "Plugin permissions migration not found, creating tables manually"
                )
                await self._create_tables_manually()

            # Load existing permissions from database
            await self._load_permissions_from_database()

            # Load module permissions cache
            await self._refresh_module_cache()

            self._db_initialized = True
            self.logger.info("Plugin security database initialized successfully")

        except Exception as e:
            self.logger.error(f"Failed to initialize security database: {e}")
            # Continue with in-memory storage
            self._db_initialized = False

    async def _create_tables_manually(self):
        """Create security tables manually if migration is not available."""
        try:
            # Create plugin_permissions table
            permissions_schema = {
                "id": "INTEGER PRIMARY KEY AUTOINCREMENT",
                "plugin_name": "TEXT NOT NULL",
                "permission_type": "TEXT NOT NULL",
                "status": "TEXT NOT NULL",
                "justification": "TEXT",
                "requested_at": "TIMESTAMP NOT NULL",
                "approved_by": "TEXT",
                "approved_at": "TIMESTAMP",
                "expires_at": "TIMESTAMP",
                "additional_data": "TEXT",
            }
            await database_manager.ensure_table_exists(
                "plugin_permissions", permissions_schema
            )

            # Create plugin_audit_events table
            audit_schema = {
                "id": "INTEGER PRIMARY KEY AUTOINCREMENT",
                "event_id": "TEXT UNIQUE NOT NULL",
                "plugin_name": "TEXT NOT NULL",
                "event_type": "TEXT NOT NULL",
                "threat_level": "TEXT NOT NULL",
                "description": "TEXT NOT NULL",
                "timestamp": "TIMESTAMP NOT NULL",
                "details": "TEXT",
                "resolved": "BOOLEAN DEFAULT 0",
                "resolved_by": "TEXT",
                "resolved_at": "TIMESTAMP",
            }
            await database_manager.ensure_table_exists(
                "plugin_audit_events", audit_schema
            )

            # Create plugin_approved_modules table
            modules_schema = {
                "id": "INTEGER PRIMARY KEY AUTOINCREMENT",
                "plugin_name": "TEXT NOT NULL",
                "module_name": "TEXT NOT NULL",
                "approved_by": "TEXT NOT NULL",
                "approved_at": "TIMESTAMP NOT NULL",
                "expires_at": "TIMESTAMP",
                "is_active": "BOOLEAN DEFAULT 1",
                "UNIQUE": "(plugin_name, module_name)",
            }
            await database_manager.ensure_table_exists(
                "plugin_approved_modules", modules_schema
            )

            # Create plugin_settings table for enable/disable state
            settings_schema = {
                "id": "INTEGER PRIMARY KEY AUTOINCREMENT",
                "plugin_name": "TEXT UNIQUE NOT NULL",
                "enabled": "BOOLEAN DEFAULT 0",  # Disabled by default
                "admin_approved": "BOOLEAN DEFAULT 0",
                "approved_by": "TEXT",
                "approved_at": "TIMESTAMP",
                "disabled_reason": "TEXT",
                "created_at": "TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
                "updated_at": "TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
            }
            await database_manager.ensure_table_exists(
                "plugin_settings", settings_schema
            )

            self.logger.info("Plugin security tables created manually")

        except Exception as e:
            self.logger.error(f"Failed to create security tables manually: {e}")
            raise

    async def _load_permissions_from_database(self):
        """Load existing permissions from database into memory."""
        if not database_manager or not self._db_initialized:
            return

        try:
            async with database_manager.get_session() as session:
                # Load approved permissions
                query = """
                    SELECT plugin_name, permission_type FROM plugin_permissions 
                    WHERE status = 'approved' 
                    AND (expires_at IS NULL OR expires_at > :now)
                """
                rows = await session.fetchall(
                    query, {"now": datetime.now(timezone.utc)}
                )

                for row in rows:
                    plugin_name = row["plugin_name"]
                    permission_type = PermissionType(row["permission_type"])
                    self._approved_permissions[plugin_name].add(permission_type)

                # Load disabled plugins
                disabled_query = """
                    SELECT plugin_name FROM plugin_settings 
                    WHERE enabled = 0 OR admin_approved = 0
                """
                disabled_rows = await session.fetchall(disabled_query)
                for row in disabled_rows:
                    self._disabled_plugins.add(row["plugin_name"])

                self.logger.info(
                    f"Loaded {len(rows)} permissions and {len(disabled_rows)} disabled plugins from database"
                )

        except Exception as e:
            self.logger.error(f"Failed to load permissions from database: {e}")

    async def _refresh_module_cache(self):
        """Refresh the module permissions cache."""
        if not database_manager or not self._db_initialized:
            return

        try:
            async with database_manager.get_session() as session:
                query = """
                    SELECT plugin_name, module_name FROM plugin_approved_modules 
                    WHERE is_active = 1 
                    AND (expires_at IS NULL OR expires_at > :now)
                """
                rows = await session.fetchall(
                    query, {"now": datetime.now(timezone.utc)}
                )

                # Clear old cache
                self._module_cache.clear()
                self._cache_expiry.clear()

                # Populate cache
                for row in rows:
                    cache_key = f"{row['plugin_name']}:{row['module_name']}"
                    self._module_cache[cache_key] = True
                    # Cache expires in 1 hour
                    self._cache_expiry[cache_key] = datetime.now(
                        timezone.utc
                    ) + timedelta(hours=1)

                self.logger.debug(f"Refreshed module cache with {len(rows)} entries")

        except Exception as e:
            self.logger.error(f"Failed to refresh module cache: {e}")

    def get_security_policy(self, plugin_name: str) -> SecurityPolicy:
        """Get security policy for a plugin."""
        with self._lock:
            return self._security_policies.get(plugin_name, self._default_policy)

    def set_security_policy(self, plugin_name: str, policy: SecurityPolicy):
        """Set security policy for a plugin."""
        with self._lock:
            self._security_policies[plugin_name] = policy
            self.logger.info(f"Security policy updated for plugin: {plugin_name}")

    def create_sandbox(self, plugin_name: str) -> SecureSandbox:
        """Create a secure sandbox for a plugin."""
        with self._lock:
            if plugin_name in self._sandboxes:
                return self._sandboxes[plugin_name]

            policy = self.get_security_policy(plugin_name)
            sandbox = SecureSandbox(plugin_name, policy)
            sandbox._security_manager = self  # Allow sandbox to log events
            self._sandboxes[plugin_name] = sandbox

            self.logger.info(f"Created sandbox for plugin: {plugin_name}")
            return sandbox

    def request_permission(
        self,
        plugin_name: str,
        permission_type: PermissionType,
        justification: str,
        additional_data: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Request a permission for a plugin."""
        with self._lock:
            request = PermissionRequest(
                plugin_name=plugin_name,
                permission_type=permission_type,
                justification=justification,
                requested_at=datetime.now(timezone.utc),
                additional_data=additional_data or {},
            )

            # Check auto-approval/denial policies
            policy = self.get_security_policy(plugin_name)
            if permission_type in policy.permission_auto_approve:
                request.status = PermissionStatus.APPROVED
                request.approved_at = datetime.now(timezone.utc)
                request.approved_by = "auto-policy"
                self._approved_permissions[plugin_name].add(permission_type)
            elif permission_type in policy.permission_auto_deny:
                request.status = PermissionStatus.DENIED

            self._permission_requests[plugin_name].append(request)

            # Log audit event
            asyncio.create_task(
                self.log_audit_event(
                    SecurityAuditEvent(
                        event_id=hashlib.sha256(
                            f"{plugin_name}{permission_type.value}{time.time()}".encode()
                        ).hexdigest()[:16],
                        plugin_name=plugin_name,
                        event_type=AuditEventType.PERMISSION_REQUEST,
                        threat_level=SecurityThreatLevel.LOW,
                        description=f"Requested permission: {permission_type.value}",
                        timestamp=datetime.now(timezone.utc),
                        details={
                            "permission_type": permission_type.value,
                            "justification": justification,
                            "status": request.status.value,
                        },
                    )
                )
            )

            request_id = f"{plugin_name}:{permission_type.value}:{request.requested_at.timestamp()}"
            self.logger.info(
                f"Permission requested: {plugin_name} -> {permission_type.value} (ID: {request_id})"
            )
            return request_id

    def approve_permission(
        self,
        plugin_name: str,
        permission_type: PermissionType,
        approved_by: str,
        expires_in_days: Optional[int] = None,
    ) -> bool:
        """Approve a permission request."""
        with self._lock:
            # Find the request
            requests = self._permission_requests.get(plugin_name, [])
            for request in requests:
                if (
                    request.permission_type == permission_type
                    and request.status == PermissionStatus.PENDING
                ):

                    request.status = PermissionStatus.APPROVED
                    request.approved_by = approved_by
                    request.approved_at = datetime.now(timezone.utc)

                    if expires_in_days:
                        request.expires_at = datetime.now(timezone.utc) + timedelta(
                            days=expires_in_days
                        )

                    self._approved_permissions[plugin_name].add(permission_type)

                    # Log audit event
                    asyncio.create_task(
                        self.log_audit_event(
                            SecurityAuditEvent(
                                event_id=hashlib.sha256(
                                    f"{plugin_name}{permission_type.value}approved{time.time()}".encode()
                                ).hexdigest()[:16],
                                plugin_name=plugin_name,
                                event_type=AuditEventType.PERMISSION_GRANTED,
                                threat_level=SecurityThreatLevel.LOW,
                                description=f"Permission approved: {permission_type.value}",
                                timestamp=datetime.now(timezone.utc),
                                details={
                                    "permission_type": permission_type.value,
                                    "approved_by": approved_by,
                                    "expires_at": (
                                        request.expires_at.isoformat()
                                        if request.expires_at
                                        else None
                                    ),
                                },
                            )
                        )
                    )

                    self.logger.info(
                        f"Permission approved: {plugin_name} -> {permission_type.value} by {approved_by}"
                    )
                    return True

            return False

    def deny_permission(
        self, plugin_name: str, permission_type: PermissionType, denied_by: str
    ) -> bool:
        """Deny a permission request."""
        with self._lock:
            # Find the request
            requests = self._permission_requests.get(plugin_name, [])
            for request in requests:
                if (
                    request.permission_type == permission_type
                    and request.status == PermissionStatus.PENDING
                ):

                    request.status = PermissionStatus.DENIED
                    request.approved_by = denied_by  # Store who denied it
                    request.approved_at = datetime.now(timezone.utc)

                    # Log audit event
                    asyncio.create_task(
                        self.log_audit_event(
                            SecurityAuditEvent(
                                event_id=hashlib.sha256(
                                    f"{plugin_name}{permission_type.value}denied{time.time()}".encode()
                                ).hexdigest()[:16],
                                plugin_name=plugin_name,
                                event_type=AuditEventType.PERMISSION_DENIED,
                                threat_level=SecurityThreatLevel.LOW,
                                description=f"Permission denied: {permission_type.value}",
                                timestamp=datetime.now(timezone.utc),
                                details={
                                    "permission_type": permission_type.value,
                                    "denied_by": denied_by,
                                },
                            )
                        )
                    )

                    self.logger.info(
                        f"Permission denied: {plugin_name} -> {permission_type.value} by {denied_by}"
                    )
                    return True

            return False

    def revoke_permission(
        self, plugin_name: str, permission_type: PermissionType, revoked_by: str
    ) -> bool:
        """Revoke a previously approved permission."""
        with self._lock:
            if permission_type in self._approved_permissions[plugin_name]:
                self._approved_permissions[plugin_name].remove(permission_type)

                # Update the request status
                requests = self._permission_requests.get(plugin_name, [])
                for request in requests:
                    if (
                        request.permission_type == permission_type
                        and request.status == PermissionStatus.APPROVED
                    ):
                        request.status = PermissionStatus.REVOKED
                        break

                # Log audit event
                asyncio.create_task(
                    self.log_audit_event(
                        SecurityAuditEvent(
                            event_id=hashlib.sha256(
                                f"{plugin_name}{permission_type.value}revoked{time.time()}".encode()
                            ).hexdigest()[:16],
                            plugin_name=plugin_name,
                            event_type=AuditEventType.PERMISSION_REVOKED,
                            threat_level=SecurityThreatLevel.MEDIUM,
                            description=f"Permission revoked: {permission_type.value}",
                            timestamp=datetime.now(timezone.utc),
                            details={
                                "permission_type": permission_type.value,
                                "revoked_by": revoked_by,
                            },
                        )
                    )
                )

                self.logger.warning(
                    f"Permission revoked: {plugin_name} -> {permission_type.value} by {revoked_by}"
                )
                return True

            return False

    def has_permission(self, plugin_name: str, permission_type: PermissionType) -> bool:
        """Check if a plugin has a specific permission."""
        with self._lock:
            if plugin_name in self._quarantined_plugins:
                return False

            # Check if permission is approved and not expired
            if permission_type in self._approved_permissions[plugin_name]:
                # Check for expiration
                requests = self._permission_requests.get(plugin_name, [])
                for request in requests:
                    if (
                        request.permission_type == permission_type
                        and request.status == PermissionStatus.APPROVED
                    ):
                        if (
                            request.expires_at
                            and datetime.now(timezone.utc) > request.expires_at
                        ):
                            # Permission expired
                            request.status = PermissionStatus.EXPIRED
                            self._approved_permissions[plugin_name].discard(
                                permission_type
                            )
                            return False
                        return True

            return False

    def quarantine_plugin(self, plugin_name: str, reason: str, quarantined_by: str):
        """Quarantine a plugin due to security violations."""
        with self._lock:
            self._quarantined_plugins.add(plugin_name)

            # Revoke all permissions
            self._approved_permissions[plugin_name].clear()

            # Log audit event
            asyncio.create_task(
                self.log_audit_event(
                    SecurityAuditEvent(
                        event_id=hashlib.sha256(
                            f"{plugin_name}quarantined{time.time()}".encode()
                        ).hexdigest()[:16],
                        plugin_name=plugin_name,
                        event_type=AuditEventType.SUSPICIOUS_ACTIVITY,
                        threat_level=SecurityThreatLevel.CRITICAL,
                        description=f"Plugin quarantined: {reason}",
                        timestamp=datetime.now(timezone.utc),
                        details={
                            "reason": reason,
                            "quarantined_by": quarantined_by,
                        },
                    )
                )
            )

            self.logger.critical(f"Plugin quarantined: {plugin_name} - {reason}")

    def release_from_quarantine(self, plugin_name: str, released_by: str):
        """Release a plugin from quarantine."""
        with self._lock:
            if plugin_name in self._quarantined_plugins:
                self._quarantined_plugins.remove(plugin_name)

                self.logger.warning(
                    f"Plugin released from quarantine: {plugin_name} by {released_by}"
                )
                return True

            return False

    def is_quarantined(self, plugin_name: str) -> bool:
        """Check if a plugin is quarantined."""
        with self._lock:
            return plugin_name in self._quarantined_plugins

    async def log_audit_event(self, event: SecurityAuditEvent):
        """Log a security audit event."""
        with self._lock:
            self._audit_events.append(event)

            # Log to file as well
            self.logger.info(
                f"AUDIT: {event.event_type.value} - {event.plugin_name} - {event.description}"
            )

            # Keep only recent events in memory (last 10000)
            if len(self._audit_events) > 10000:
                self._audit_events = self._audit_events[-5000:]

        # Store in database
        if database_manager and self._db_initialized:
            try:
                async with database_manager.get_session() as session:
                    audit_data = {
                        "event_id": event.event_id,
                        "plugin_name": event.plugin_name,
                        "event_type": event.event_type.value,
                        "threat_level": event.threat_level.value,
                        "description": event.description,
                        "timestamp": event.timestamp,
                        "details": json.dumps(event.details),
                        "resolved": event.resolved,
                        "resolved_by": event.resolved_by,
                        "resolved_at": event.resolved_at,
                    }
                    await session.insert("plugin_audit_events", audit_data)
                    await session.commit()
            except Exception as e:
                self.logger.error(f"Failed to store audit event in database: {e}")

    def _is_module_approved(self, plugin_name: str, module_name: str) -> bool:
        """Check if a module is approved for a plugin (async version)."""
        if not database_manager or not self._db_initialized:
            return False

        try:
            # Check cache first
            cache_key = f"{plugin_name}:{module_name}"
            if cache_key in self._module_cache:
                # Check if cache entry is still valid
                if (
                    cache_key in self._cache_expiry
                    and datetime.now(timezone.utc) < self._cache_expiry[cache_key]
                ):
                    return self._module_cache[cache_key]
                else:
                    # Cache expired, remove entry
                    self._module_cache.pop(cache_key, None)
                    self._cache_expiry.pop(cache_key, None)

            # Default to deny for safety if not in cache
            return False
        except Exception as e:
            self.logger.error(f"Failed to check module approval: {e}")
            return False

    def _is_module_approved_sync(self, plugin_name: str, module_name: str) -> bool:
        """Synchronous version for use in sandbox context."""
        cache_key = f"{plugin_name}:{module_name}"
        if cache_key in self._module_cache:
            # Check if cache entry is still valid
            if (
                cache_key in self._cache_expiry
                and datetime.now(timezone.utc) < self._cache_expiry[cache_key]
            ):
                return self._module_cache[cache_key]
        return False

    async def approve_module(
        self,
        plugin_name: str,
        module_name: str,
        approved_by: str,
        expires_in_days: Optional[int] = None,
    ) -> bool:
        """Approve a module for a plugin."""
        if not database_manager or not self._db_initialized:
            return False

        try:
            expires_at = None
            if expires_in_days:
                expires_at = datetime.now(timezone.utc) + timedelta(
                    days=expires_in_days
                )

            async with database_manager.get_session() as session:
                module_data = {
                    "plugin_name": plugin_name,
                    "module_name": module_name,
                    "approved_by": approved_by,
                    "approved_at": datetime.now(timezone.utc),
                    "expires_at": expires_at,
                    "is_active": True,
                }
                await session.insert("plugin_approved_modules", module_data)
                await session.commit()

            self.logger.info(
                f"Module approved: {plugin_name} -> {module_name} by {approved_by}"
            )
            return True

        except Exception as e:
            self.logger.error(f"Failed to approve module: {e}")
            return False

    async def revoke_module(
        self, plugin_name: str, module_name: str, revoked_by: str
    ) -> bool:
        """Revoke module approval for a plugin."""
        if not database_manager or not self._db_initialized:
            return False

        try:
            async with database_manager.get_session() as session:
                await session.update(
                    "plugin_approved_modules",
                    {"is_active": False},
                    {"plugin_name": plugin_name, "module_name": module_name},
                )
                await session.commit()

            self.logger.warning(
                f"Module approval revoked: {plugin_name} -> {module_name} by {revoked_by}"
            )
            return True

        except Exception as e:
            self.logger.error(f"Failed to revoke module approval: {e}")
            return False

    async def get_approved_modules(self, plugin_name: str) -> List[str]:
        """Get list of approved modules for a plugin."""
        if not database_manager or not self._db_initialized:
            return []

        try:
            async with database_manager.get_session() as session:
                query = """
                    SELECT module_name FROM plugin_approved_modules 
                    WHERE plugin_name = :plugin_name AND is_active = 1
                    AND (expires_at IS NULL OR expires_at > :now)
                """
                rows = await session.fetchall(
                    query,
                    {"plugin_name": plugin_name, "now": datetime.now(timezone.utc)},
                )
                return [row["module_name"] for row in rows]

        except Exception as e:
            self.logger.error(f"Failed to get approved modules: {e}")
            return []

    def get_security_warnings(self) -> List[Dict[str, Any]]:
        """Get security warnings for the admin UI."""
        warnings = []

        # Warning about plugins being disabled by default (always show)
        warnings.append(
            {
                "type": "info",
                "title": "Plugin Security Policy",
                "message": "All plugins are disabled by default and require explicit admin approval to enable. This is a security feature to prevent unauthorized code execution.",
                "severity": "medium",
                "action": "Review and approve plugins in the Plugin Management section.",
            }
        )

        # Check for disabled plugins awaiting approval
        if self._disabled_plugins:
            warnings.append(
                {
                    "type": "warning",
                    "title": "Plugins Awaiting Approval",
                    "message": f"{len(self._disabled_plugins)} plugin(s) are disabled and awaiting admin approval.",
                    "severity": "medium",
                    "details": list(self._disabled_plugins),
                    "action": "Review plugins in Plugin Management to approve or deny.",
                }
            )

        # Check for quarantined plugins
        if self._quarantined_plugins:
            warnings.append(
                {
                    "type": "error",
                    "title": "Quarantined Plugins",
                    "message": f"{len(self._quarantined_plugins)} plugin(s) are quarantined due to security violations.",
                    "severity": "high",
                    "details": list(self._quarantined_plugins),
                    "action": "Investigate security violations and decide whether to release or remove plugins.",
                }
            )

        # Check for pending permission requests
        pending_count = sum(
            len([r for r in requests if r.status == PermissionStatus.PENDING])
            for requests in self._permission_requests.values()
        )
        if pending_count > 0:
            warnings.append(
                {
                    "type": "info",
                    "title": "Pending Permission Requests",
                    "message": f"{pending_count} permission request(s) require admin review.",
                    "severity": "medium",
                    "action": "Review permission requests in the Security section.",
                }
            )

        # Check for recent critical security events
        recent_critical = [
            e
            for e in self._audit_events
            if e.threat_level == SecurityThreatLevel.CRITICAL
            and e.timestamp > datetime.now(timezone.utc) - timedelta(hours=24)
            and not e.resolved
        ]
        if recent_critical:
            warnings.append(
                {
                    "type": "error",
                    "title": "Critical Security Events",
                    "message": f"{len(recent_critical)} critical security event(s) in the last 24 hours require immediate attention.",
                    "severity": "critical",
                    "details": [
                        e.description for e in recent_critical[:5]
                    ],  # Show first 5
                    "action": "Review security events and take appropriate action to resolve threats.",
                }
            )

        # Check for plugins with excessive resource usage
        resource_violations = []
        for plugin_name, sandbox in self._sandboxes.items():
            if (
                hasattr(sandbox, "resource_monitor")
                and sandbox.resource_monitor._violation_count > 5
            ):
                resource_violations.append(plugin_name)

        if resource_violations:
            warnings.append(
                {
                    "type": "warning",
                    "title": "Resource Usage Violations",
                    "message": f"{len(resource_violations)} plugin(s) have exceeded resource limits multiple times.",
                    "severity": "medium",
                    "details": resource_violations,
                    "action": "Review resource usage and consider adjusting limits or quarantining plugins.",
                }
            )

        return warnings

    def get_pending_permission_requests(self) -> List[PermissionRequest]:
        """Get all pending permission requests."""
        with self._lock:
            pending = []
            for plugin_requests in self._permission_requests.values():
                pending.extend(
                    [r for r in plugin_requests if r.status == PermissionStatus.PENDING]
                )
            return pending

    def get_plugin_permissions(self, plugin_name: str) -> Dict[str, Any]:
        """Get all permissions for a plugin."""
        with self._lock:
            return {
                "approved_permissions": [
                    p.value for p in self._approved_permissions[plugin_name]
                ],
                "pending_requests": [
                    {
                        "permission_type": r.permission_type.value,
                        "justification": r.justification,
                        "requested_at": r.requested_at.isoformat(),
                        "status": r.status.value,
                    }
                    for r in self._permission_requests[plugin_name]
                    if r.status == PermissionStatus.PENDING
                ],
                "is_quarantined": plugin_name in self._quarantined_plugins,
            }

    def get_security_summary(self) -> Dict[str, Any]:
        """Get a summary of security status."""
        with self._lock:
            recent_events = [
                e
                for e in self._audit_events
                if e.timestamp > datetime.now(timezone.utc) - timedelta(hours=24)
            ]

            threat_counts = defaultdict(int)
            event_type_counts = defaultdict(int)

            for event in recent_events:
                threat_counts[event.threat_level.value] += 1
                event_type_counts[event.event_type.value] += 1

            return {
                "total_plugins_monitored": len(self._sandboxes),
                "quarantined_plugins": len(self._quarantined_plugins),
                "pending_permission_requests": sum(
                    len([r for r in requests if r.status == PermissionStatus.PENDING])
                    for requests in self._permission_requests.values()
                ),
                "recent_audit_events": len(recent_events),
                "threat_level_distribution": dict(threat_counts),
                "event_type_distribution": dict(event_type_counts),
                "last_24h_critical_events": len(
                    [
                        e
                        for e in recent_events
                        if e.threat_level == SecurityThreatLevel.CRITICAL
                    ]
                ),
            }

    def cleanup_expired_permissions(self):
        """Clean up expired permissions."""
        with self._lock:
            current_time = datetime.now(timezone.utc)

            for plugin_name, requests in self._permission_requests.items():
                for request in requests:
                    if (
                        request.status == PermissionStatus.APPROVED
                        and request.expires_at
                        and current_time > request.expires_at
                    ):

                        request.status = PermissionStatus.EXPIRED
                        self._approved_permissions[plugin_name].discard(
                            request.permission_type
                        )

                        self.logger.info(
                            f"Permission expired: {plugin_name} -> {request.permission_type.value}"
                        )

    def is_plugin_enabled(self, plugin_name: str) -> bool:
        """Check if a plugin is enabled and approved by admin."""
        with self._lock:
            return (
                plugin_name not in self._disabled_plugins
                and plugin_name not in self._quarantined_plugins
            )

    async def enable_plugin(self, plugin_name: str, approved_by: str) -> bool:
        """Enable a plugin with admin approval."""
        with self._lock:
            if plugin_name in self._quarantined_plugins:
                self.logger.warning(f"Cannot enable quarantined plugin: {plugin_name}")
                return False

            # Remove from disabled set
            self._disabled_plugins.discard(plugin_name)

            # Update database
            if database_manager and self._db_initialized:
                try:
                    async with database_manager.get_session() as session:
                        # Insert or update plugin settings
                        await session.execute(
                            """
                            INSERT OR REPLACE INTO plugin_settings 
                            (plugin_name, enabled, admin_approved, approved_by, approved_at, updated_at)
                            VALUES (:plugin_name, 1, 1, :approved_by, :approved_at, :updated_at)
                        """,
                            {
                                "plugin_name": plugin_name,
                                "approved_by": approved_by,
                                "approved_at": datetime.now(timezone.utc),
                                "updated_at": datetime.now(timezone.utc),
                            },
                        )
                        await session.commit()
                except Exception as e:
                    self.logger.error(
                        f"Failed to update plugin settings in database: {e}"
                    )

            # Log audit event
            await self.log_audit_event(
                SecurityAuditEvent(
                    event_id=hashlib.sha256(
                        f"{plugin_name}enabled{time.time()}".encode()
                    ).hexdigest()[:16],
                    plugin_name=plugin_name,
                    event_type=AuditEventType.PERMISSION_GRANTED,
                    threat_level=SecurityThreatLevel.LOW,
                    description=f"Plugin enabled by admin",
                    timestamp=datetime.now(timezone.utc),
                    details={"approved_by": approved_by, "action": "plugin_enabled"},
                )
            )

            self.logger.info(f"Plugin enabled: {plugin_name} by {approved_by}")
            return True

    async def disable_plugin(
        self, plugin_name: str, disabled_by: str, reason: str = "Admin decision"
    ) -> bool:
        """Disable a plugin."""
        with self._lock:
            # Add to disabled set
            self._disabled_plugins.add(plugin_name)

            # Update database
            if database_manager and self._db_initialized:
                try:
                    async with database_manager.get_session() as session:
                        await session.execute(
                            """
                            INSERT OR REPLACE INTO plugin_settings 
                            (plugin_name, enabled, admin_approved, disabled_reason, updated_at)
                            VALUES (:plugin_name, 0, 0, :reason, :updated_at)
                        """,
                            {
                                "plugin_name": plugin_name,
                                "reason": reason,
                                "updated_at": datetime.now(timezone.utc),
                            },
                        )
                        await session.commit()
                except Exception as e:
                    self.logger.error(
                        f"Failed to update plugin settings in database: {e}"
                    )

            # Log audit event
            await self.log_audit_event(
                SecurityAuditEvent(
                    event_id=hashlib.sha256(
                        f"{plugin_name}disabled{time.time()}".encode()
                    ).hexdigest()[:16],
                    plugin_name=plugin_name,
                    event_type=AuditEventType.PERMISSION_REVOKED,
                    threat_level=SecurityThreatLevel.LOW,
                    description=f"Plugin disabled: {reason}",
                    timestamp=datetime.now(timezone.utc),
                    details={
                        "disabled_by": disabled_by,
                        "reason": reason,
                        "action": "plugin_disabled",
                    },
                )
            )

            self.logger.info(
                f"Plugin disabled: {plugin_name} by {disabled_by} - {reason}"
            )
            return True

    async def periodic_cleanup(self):
        """Periodic cleanup task."""
        while True:
            try:
                self.cleanup_expired_permissions()
                await self._refresh_module_cache()  # Refresh cache periodically
                await asyncio.sleep(3600)  # Run every hour
            except Exception as e:
                self.logger.error(f"Error in periodic cleanup: {e}")
                await asyncio.sleep(300)  # Retry in 5 minutes


# ==============================================================================
# GLOBAL INSTANCE
# ==============================================================================

# Create global instance
plugin_security_manager = PluginSecurityManager()

# Start periodic cleanup task
try:
    loop = asyncio.get_event_loop()
    if loop.is_running():
        asyncio.create_task(plugin_security_manager.periodic_cleanup())
except RuntimeError:
    # No event loop running, will start later
    pass


# Convenience functions
def get_security_manager() -> PluginSecurityManager:
    """Get the global plugin security manager."""
    return plugin_security_manager


def create_plugin_sandbox(plugin_name: str) -> SecureSandbox:
    """Create a secure sandbox for a plugin."""
    return plugin_security_manager.create_sandbox(plugin_name)


def request_plugin_permission(
    plugin_name: str, permission_type: PermissionType, justification: str
) -> str:
    """Request a permission for a plugin."""
    return plugin_security_manager.request_permission(
        plugin_name, permission_type, justification
    )


def check_plugin_permission(plugin_name: str, permission_type: PermissionType) -> bool:
    """Check if a plugin has a specific permission."""
    return plugin_security_manager.has_permission(plugin_name, permission_type)


def is_plugin_enabled(plugin_name: str) -> bool:
    """Check if a plugin is enabled and approved."""
    return plugin_security_manager.is_plugin_enabled(plugin_name)


async def enable_plugin_with_approval(plugin_name: str, approved_by: str) -> bool:
    """Enable a plugin with admin approval."""
    return await plugin_security_manager.enable_plugin(plugin_name, approved_by)


async def disable_plugin_with_reason(
    plugin_name: str, disabled_by: str, reason: str = "Admin decision"
) -> bool:
    """Disable a plugin with reason."""
    return await plugin_security_manager.disable_plugin(
        plugin_name, disabled_by, reason
    )


def get_security_warnings_for_ui() -> List[Dict[str, Any]]:
    """Get security warnings for the admin UI."""
    return plugin_security_manager.get_security_warnings()


__all__ = [
    "PluginSecurityManager",
    "SecureSandbox",
    "ResourceMonitor",
    "FileAccessMonitor",
    "NetworkMonitor",
    "SafeFileManager",
    "NetworkBroker",
    "PermissionType",
    "PermissionStatus",
    "SecurityThreatLevel",
    "AuditEventType",
    "PermissionRequest",
    "SecurityAuditEvent",
    "ResourceUsage",
    "SecurityPolicy",
    "plugin_security_manager",
    "get_security_manager",
    "create_plugin_sandbox",
    "request_plugin_permission",
    "check_plugin_permission",
    "is_plugin_enabled",
    "enable_plugin_with_approval",
    "disable_plugin_with_reason",
    "get_security_warnings_for_ui",
]
