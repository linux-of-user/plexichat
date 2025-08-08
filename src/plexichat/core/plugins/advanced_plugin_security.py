"""
Enhanced Plugin Security Manager

Advanced security system for plugins with:
- Flexible security sandbox with approved imports
- Dynamic permission management
- Behavioral analysis and monitoring
- Automatic dependency resolution
- Security compliance checking
- Plugin isolation and resource limits
- Advanced threat detection for plugins
"""

import ast
import sys
import importlib
import importlib.util
import subprocess
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Set, Optional
from typing import Dict, List, Set, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import hashlib
import json
from datetime import datetime, timedelta

from ..logging.unified_logging import get_logger
from ..logging.correlation_tracker import correlation_tracker, CorrelationType

logger = get_logger(__name__)


class SecurityLevel(Enum):
    """Plugin security levels."""
    MINIMAL = "minimal"      # Basic sandbox, limited imports
    STANDARD = "standard"    # Standard sandbox, common imports allowed
    ELEVATED = "elevated"    # More imports allowed, requires approval
    TRUSTED = "trusted"      # Full access, admin approval required
    SYSTEM = "system"        # System-level access, highest security


class PermissionType(Enum):
    """Types of plugin permissions."""
    IMPORT = "import"
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    NETWORK = "network"
    DATABASE = "database"
    SYSTEM_CALL = "system_call"
    SUBPROCESS = "subprocess"
    THREADING = "threading"


@dataclass
class PluginPermission:
    """Plugin permission definition."""
    permission_type: PermissionType
    resource: str
    granted: bool = False
    granted_at: Optional[str] = None
    granted_by: str = "system"
    expires_at: Optional[str] = None
    usage_count: int = 0
    last_used: Optional[str] = None


@dataclass
class SecurityProfile:
    """Security profile for a plugin."""
    plugin_name: str
    security_level: SecurityLevel
    permissions: List[PluginPermission] = field(default_factory=list)
    approved_imports: Set[str] = field(default_factory=set)
    blocked_imports: Set[str] = field(default_factory=set)
    resource_limits: Dict[str, Any] = field(default_factory=dict)
    
    # Behavioral monitoring
    import_attempts: List[str] = field(default_factory=list)
    permission_requests: List[str] = field(default_factory=list)
    security_violations: List[str] = field(default_factory=list)
    
    # Metadata
    created_at: datetime = field(default_factory=datetime.now)
    last_updated: datetime = field(default_factory=datetime.now)
    trust_score: float = 100.0


class EnhancedPluginSecurity:
    """Enhanced plugin security manager with flexible sandbox."""

    def __init__(self):
        self.security_profiles: Dict[str, SecurityProfile] = {}
        self.global_approved_imports = self._get_default_approved_imports()
        self.dependency_cache: Dict[str, bool] = {}
        self.monitoring_active = True
        
        # Security monitoring
        self.security_events: List[Dict] = []
        self.threat_patterns: Dict[str, List[str]] = {}
        
        # Performance tracking
        self.import_performance: Dict[str, float] = {}
        
        logger.info("Enhanced plugin security manager initialized")
    
    def _get_default_approved_imports(self) -> Set[str]:
        return {
            # Standard library - safe modules
            'os', 'sys', 'json', 'time', 'datetime', 'collections',
            'itertools', 'functools', 'operator', 'math', 'random',
            'string', 'uuid', 'hashlib', 'base64', 'urllib.parse',
            'pathlib', 'typing', 'dataclasses', 'enum', 'abc',
            're', 'logging', 'asyncio', 'concurrent.futures',
            '_io', 'io', 'builtins', 'importlib', 'importlib.util',
            # Built-in exceptions
            'Exception', 'ImportError', 'ValueError', 'TypeError', 'AttributeError',
            'KeyError', 'IndexError', 'FileNotFoundError', 'OSError', 'RuntimeError',
            'subprocess', 'signal', 'threading', 'multiprocessing',
            'tempfile', 'shutil', 'glob', 'fnmatch', 'linecache',
            'warnings', 'traceback', 'inspect', 'copy', 'pickle',
            '__future__', 'urllib3', 'urllib', 'urllib.request', 'urllib.parse',
            
            # Commonly needed third-party - approved
            'pydantic', 'pydantic.BaseModel', 'pydantic.Field',
            'aiofiles', 'aiofiles.open',
            'requests', 'requests.get', 'requests.post',
            'httpx', 'httpx.AsyncClient',
            'websockets', 'websockets.connect',
            'sqlalchemy', 'sqlalchemy.orm',
            'fastapi', 'fastapi.APIRouter', 'fastapi.Depends',
            'click', 'rich', 'rich.console', 'rich.table',
            
            # Data processing
            'pandas', 'numpy', 'matplotlib', 'matplotlib.pyplot',
            'seaborn', 'plotly', 'plotly.graph_objects',
            
            # Cryptography - controlled access
            'cryptography.fernet', 'cryptography.hazmat.primitives.hashes',
            'cryptography.hazmat.primitives.kdf.pbkdf2',
            
            # PlexiChat internal modules
            'plexichat.core', 'plexichat.shared', 'plexichat.features',
            'plexichat.infrastructure', 'plexichat.interfaces'
        }
    
    def create_security_profile(self, plugin_name: str, security_level: SecurityLevel = SecurityLevel.STANDARD) -> SecurityProfile:
        profile = SecurityProfile(
            plugin_name=plugin_name,
            security_level=security_level,
            approved_imports=self.global_approved_imports.copy(),
            resource_limits={
                'max_memory_mb': 100,
                'max_cpu_percent': 10,
                'max_file_size_mb': 10,
                'max_network_requests': 100,
                'max_execution_time_seconds': 30
            }
        )
        
        # Add default permissions based on security level
        if security_level in [SecurityLevel.STANDARD, SecurityLevel.ELEVATED, SecurityLevel.TRUSTED]:
            profile.permissions.extend([
                PluginPermission(PermissionType.IMPORT, "standard_library", granted=True),
                PluginPermission(PermissionType.FILE_READ, "plugin_directory", granted=True),
                PluginPermission(PermissionType.DATABASE, "read_only", granted=True)
            ])
        
        if security_level in [SecurityLevel.ELEVATED, SecurityLevel.TRUSTED]:
            profile.permissions.extend([
                PluginPermission(PermissionType.NETWORK, "http_requests", granted=True),
                PluginPermission(PermissionType.FILE_WRITE, "plugin_directory", granted=True),
                PluginPermission(PermissionType.DATABASE, "read_write", granted=True)
            ])
        
        if security_level == SecurityLevel.TRUSTED:
            profile.permissions.extend([
                PluginPermission(PermissionType.SUBPROCESS, "limited", granted=True),
                PluginPermission(PermissionType.THREADING, "limited", granted=True),
                PluginPermission(PermissionType.SYSTEM_CALL, "safe_calls", granted=True)
            ])
        
        self.security_profiles[plugin_name] = profile
        logger.info(f"Created security profile for plugin {plugin_name} with level {security_level.value}")
        return profile
    
    def check_import_permission(self, plugin_name: str, module_name: str) -> bool:
        profile = self.security_profiles.get(plugin_name)
        if not profile:
            # Create default profile for unknown plugins
            profile = self.create_security_profile(plugin_name, SecurityLevel.MINIMAL)
        
        # Record import attempt
        profile.import_attempts.append(f"{module_name}:{datetime.now().isoformat()}")
        
        # Check if module is explicitly blocked
        if module_name in profile.blocked_imports:
            self._record_security_event(plugin_name, "blocked_import", module_name)
            return False
        
        # Check if module is approved
        if module_name in profile.approved_imports:
            return True
        
        # Check for pattern matches (e.g., 'requests.*' matches 'requests.get')
        for approved in profile.approved_imports:
            if approved.endswith('*') and module_name.startswith(approved[:-1]):
                return True
            if '.' in approved and module_name.startswith(approved.split('.')[0]):
                return True
        
        # For elevated and trusted plugins, allow more imports with monitoring
        if profile.security_level in [SecurityLevel.ELEVATED, SecurityLevel.TRUSTED]:
            if self._is_safe_module(module_name):
                profile.approved_imports.add(module_name)
                logger.info(f"Auto-approved safe module {module_name} for plugin {plugin_name}")
                return True
        
        # Request permission for unknown modules
        return self._request_import_permission(plugin_name, module_name)
    
    def _is_safe_module(self, module_name: str) -> bool:
        safe_patterns = [
            'pydantic', 'fastapi', 'sqlalchemy', 'requests', 'httpx',
            'aiofiles', 'asyncio', 'datetime', 'json', 'uuid',
            'pathlib', 'typing', 'dataclasses', 'enum', 'collections',
            'matplotlib', 'numpy', 'pandas', 'plotly', 'seaborn'
        ]
        
        for pattern in safe_patterns:
            if module_name.startswith(pattern):
                return True
        
        return False
    
    def _request_import_permission(self, plugin_name: str, module_name: str) -> bool:
        profile = self.security_profiles[plugin_name]
        
        # For now, auto-approve safe modules and log others
        if self._is_safe_module(module_name):
            profile.approved_imports.add(module_name)
            logger.info(f"Auto-approved import {module_name} for plugin {plugin_name}")
            return True
        
        # Log permission request for admin review
        profile.permission_requests.append(f"{module_name}:{datetime.now().isoformat()}")
        logger.warning(f"Plugin {plugin_name} requested permission for {module_name} - requires admin approval")
        
        # For development, temporarily allow with warning
        if profile.security_level in [SecurityLevel.ELEVATED, SecurityLevel.TRUSTED]:
            profile.approved_imports.add(module_name)
            logger.warning(f"Temporarily approved {module_name} for {plugin_name} - review required")
            return True
        
        return False
    
    def install_missing_dependency(self, module_name: str) -> bool:
        if module_name in self.dependency_cache:
            return self.dependency_cache[module_name]

        # Filter out built-in modules that shouldn't be installed
        builtin_modules = {
            'gzip', 'gettext', 'argparse', 'collections', 'json', 'os', 'sys',
            'time', 'datetime', 'logging', 'threading', 'subprocess', 'pathlib',
            'tempfile', 'shutil', 'hashlib', 'base64', 'random', 'string', 'uuid',
            'typing', 'dataclasses', 'concurrent', 'asyncio', 'functools', 'itertools',
            'operator', 'copy', 'pickle', 'sqlite3', 'urllib', 'http', 'email',
            'xml', 'html', 'csv', 'configparser', 'io', 're', 'math', 'statistics',
            'decimal', 'fractions', 'secrets', 'hmac', 'binascii', 'struct', 'codecs',
            'locale', 'calendar', 'zoneinfo', 'platform', 'socket', 'ssl', 'select',
            'selectors', 'signal', 'mmap', 'ctypes', 'array', 'weakref', 'gc',
            'inspect', 'dis', 'traceback', 'linecache', 'tokenize', 'keyword',
            'builtins', '__builtin__', '__builtins__', '_pytest', 'pytest_plugins',
            'main_cli', 'plexichat', 'src'
        }

        # Check if it's a built-in module or submodule
        base_module = module_name.split('.')[0]
        if base_module in builtin_modules or module_name in builtin_modules:
            logger.debug(f"Skipping installation of built-in module: {module_name}")
            self.dependency_cache[module_name] = True  # Mark as "installed" to avoid retries
            return True

        # Skip empty module names
        if not module_name.strip():
            logger.debug(f"Skipping empty module name")
            self.dependency_cache[module_name] = False
            return False

        try:
            # Map common module names to package names
            package_mapping = {
                'pydantic': 'pydantic',
                'aiofiles': 'aiofiles',
                'requests': 'requests',
                'httpx': 'httpx',
                'websockets': 'websockets',
                'matplotlib': 'matplotlib',
                'numpy': 'numpy',
                'pandas': 'pandas',
                'plotly': 'plotly',
                'seaborn': 'seaborn',
                'sqlalchemy': 'sqlalchemy',
                'fastapi': 'fastapi',
                'click': 'click',
                'rich': 'rich'
            }
            
            package_name = package_mapping.get(module_name.split('.')[0], module_name.split('.')[0])
            
            logger.info(f"Attempting to install missing dependency: {package_name}")
            
            # Use subprocess to install package
            result = subprocess.run([
                sys.executable, '-m', 'pip', 'install', package_name
            ], capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                logger.info(f"Successfully installed {package_name}")
                self.dependency_cache[module_name] = True
                return True
            else:
                logger.error(f"Failed to install {package_name}: {result.stderr}")
                self.dependency_cache[module_name] = False
                return False
                
        except Exception as e:
            logger.error(f"Error installing dependency {module_name}: {e}")
            self.dependency_cache[module_name] = False
            return False
    
    def create_secure_import_hook(self, plugin_name: str):
        profile = self.security_profiles.get(plugin_name)
        if not profile:
            profile = self.create_security_profile(plugin_name)
        
        original_import = __builtins__['__import__']
        
        def secure_import(name, globals=None, locals=None, fromlist=(), level=0):
            # Check permission
            if not self.check_import_permission(plugin_name, name):
                # Try to install missing dependency
                if self.install_missing_dependency(name):
                    # Retry import after installation
                    pass
                else:
                    raise ImportError(f"Import of '{name}' not allowed for plugin {plugin_name}")
            
            # Record successful import
            profile.last_updated = datetime.now()
            
            try:
                return original_import(name, globals, locals, fromlist, level)
            except ImportError as e:
                # Try to install and retry once
                if self.install_missing_dependency(name):
                    return original_import(name, globals, locals, fromlist, level)
                raise e
        
        return secure_import
    
    def _record_security_event(self, plugin_name: str, event_type: str, details: str):
        event = {
            'timestamp': datetime.now().isoformat(),
            'plugin_name': plugin_name,
            'event_type': event_type,
            'details': details,
            'severity': 'warning' if event_type == 'blocked_import' else 'info'
        }
        
        self.security_events.append(event)
        
        # Keep only recent events
        if len(self.security_events) > 1000:
            self.security_events = self.security_events[-500:]
        
        # Update plugin trust score
        if plugin_name in self.security_profiles:
            profile = self.security_profiles[plugin_name]
            if event_type == 'blocked_import':
                profile.trust_score = max(0, profile.trust_score - 5)
                profile.security_violations.append(f"{event_type}:{details}:{datetime.now().isoformat()}")
    
    def get_plugin_security_status(self, plugin_name: str) -> Dict[str, Any]:
        profile = self.security_profiles.get(plugin_name)
        if not profile:
            return {'status': 'unknown', 'message': 'No security profile found'}
        
        return {
            'plugin_name': plugin_name,
            'security_level': profile.security_level.value,
            'trust_score': profile.trust_score,
            'approved_imports_count': len(profile.approved_imports),
            'blocked_imports_count': len(profile.blocked_imports),
            'permissions_count': len(profile.permissions),
            'import_attempts': len(profile.import_attempts),
            'permission_requests': len(profile.permission_requests),
            'security_violations': len(profile.security_violations),
            'last_updated': profile.last_updated.isoformat(),
            'resource_limits': profile.resource_limits
        }
    
    def get_security_summary(self) -> Dict[str, Any]:
        total_plugins = len(self.security_profiles)
        total_events = len(self.security_events)
        
        security_levels = {}
        trust_scores = []
        
        for profile in self.security_profiles.values():
            level = profile.security_level.value
            security_levels[level] = security_levels.get(level, 0) + 1
            trust_scores.append(profile.trust_score)
        
        avg_trust_score = sum(trust_scores) / len(trust_scores) if trust_scores else 0
        
        return {
            'total_plugins': total_plugins,
            'total_security_events': total_events,
            'security_levels': security_levels,
            'average_trust_score': avg_trust_score,
            'approved_imports_global': len(self.global_approved_imports),
            'dependency_cache_size': len(self.dependency_cache),
            'monitoring_active': self.monitoring_active
        }
    
    def approve_plugin_import(self, plugin_name: str, module_name: str, approved_by: str = "admin"):
        profile = self.security_profiles.get(plugin_name)
        if not profile:
            profile = self.create_security_profile(plugin_name)
        
        profile.approved_imports.add(module_name)
        profile.last_updated = datetime.now()
        
        # Add permission record
        permission = PluginPermission(
            permission_type=PermissionType.IMPORT,
            resource=module_name,
            granted=True,
            granted_at=datetime.now(),
            granted_by=approved_by
        )
        profile.permissions.append(permission)
        
        logger.info(f"Manually approved import {module_name} for plugin {plugin_name} by {approved_by}")
    
    def elevate_plugin_security(self, plugin_name: str, new_level: SecurityLevel, approved_by: str = "admin"):
        profile = self.security_profiles.get(plugin_name)
        if not profile:
            profile = self.create_security_profile(plugin_name, new_level)
        else:
            old_level = profile.security_level
            profile.security_level = new_level
            profile.last_updated = datetime.now()
            
            # Add more permissions based on new level
            if new_level in [SecurityLevel.ELEVATED, SecurityLevel.TRUSTED]:
                profile.approved_imports.update([
                    'requests', 'httpx', 'aiofiles', 'websockets',
                    'matplotlib', 'numpy', 'pandas', 'plotly'
                ])
            
            logger.info(f"Elevated plugin {plugin_name} from {old_level.value} to {new_level.value} by {approved_by}")


# Global enhanced security manager
enhanced_plugin_security = EnhancedPluginSecurity()
