"""
PlexiChat Plugin SDK Generator

Automatically generates a secure plugin SDK that exposes only safe APIs to plugins.
Uses Jinja2 templates for code generation and includes security filtering.
"""

import ast
import inspect
import json
import logging
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from dataclasses import dataclass, field

try:
    import jinja2
except ImportError:
    jinja2 = None

logger = logging.getLogger(__name__)

# PlexiChat version for compatibility checks
PLEXICHAT_VERSION = "1.0.0"
SDK_VERSION = "1.0.0"

@dataclass
class APIMethod:
    """Represents an API method that can be exposed to plugins."""
    name: str
    module: str
    signature: str
    docstring: str
    is_async: bool
    is_safe: bool = False
    required_permissions: List[str] = field(default_factory=list)
    parameters: List[Dict[str, Any]] = field(default_factory=list)
    return_type: str = "Any"
    examples: List[str] = field(default_factory=list)

@dataclass
class APIModule:
    """Represents a module with safe APIs."""
    name: str
    description: str
    methods: List[APIMethod] = field(default_factory=list)
    classes: List[str] = field(default_factory=list)
    constants: Dict[str, Any] = field(default_factory=dict)

class PluginSDKGenerator:
    """Generates secure plugin SDK with template-based code generation."""
    
    def __init__(self, output_dir: Optional[Path] = None):
        self.logger = logging.getLogger(__name__)
        
        # Set output directory
        if output_dir is None:
            current_file = Path(__file__).resolve()
            self.output_dir = current_file.parent
        else:
            self.output_dir = Path(output_dir)
        
        self.output_file = self.output_dir / "generated_sdk.py"
        
        # Safe modules and methods that can be exposed to plugins
        self.safe_modules = {
            "database": {
                "description": "Safe database operations for plugins",
                "methods": [
                    "db_set_value", "db_get_value", "db_delete_value",
                    "cache_get", "cache_set", "cache_delete"
                ],
                "permissions": ["database_read", "database_write"]
            },
            "events": {
                "description": "Event system for plugin communication",
                "methods": ["emit_event", "register_event_handler"],
                "permissions": ["events_emit", "events_listen"]
            },
            "config": {
                "description": "Configuration management",
                "methods": ["get_config", "set_config"],
                "permissions": ["config_read", "config_write"]
            },
            "files": {
                "description": "Safe file operations",
                "methods": ["upload_file", "get_file_metadata", "delete_file"],
                "permissions": ["files_read", "files_write", "files_delete"]
            },
            "logging": {
                "description": "Logging utilities",
                "methods": ["info", "warning", "error", "debug"],
                "permissions": []
            }
        }
        
        # Dangerous patterns to filter out
        self.dangerous_patterns = [
            r"os\.",
            r"sys\.",
            r"subprocess\.",
            r"eval\(",
            r"exec\(",
            r"__import__",
            r"open\(",
            r"file\(",
            r"input\(",
            r"raw_input\(",
            r"compile\(",
            r"globals\(",
            r"locals\(",
            r"vars\(",
            r"dir\(",
            r"getattr\(",
            r"setattr\(",
            r"delattr\(",
            r"hasattr\(",
        ]
        
        # Initialize Jinja2 environment
        if jinja2:
            self.jinja_env = jinja2.Environment(
                loader=jinja2.BaseLoader(),
                trim_blocks=True,
                lstrip_blocks=True
            )
        else:
            self.jinja_env = None
            self.logger.warning("Jinja2 not available. Install with: pip install Jinja2")

    def _is_method_safe(self, method_name: str, method_obj: Any) -> bool:
        """Check if a method is safe to expose to plugins."""
        try:
            # Check if method is in safe list
            for module_info in self.safe_modules.values():
                if method_name in module_info["methods"]:
                    return True
            
            # Check method source for dangerous patterns
            if hasattr(method_obj, '__code__'):
                source = inspect.getsource(method_obj)
                for pattern in self.dangerous_patterns:
                    if re.search(pattern, source):
                        return False
            
            # Check for admin-only decorators or naming
            if method_name.startswith('_') or 'admin' in method_name.lower():
                return False
            
            # Check docstring for safety markers
            if hasattr(method_obj, '__doc__') and method_obj.__doc__:
                doc = method_obj.__doc__.lower()
                if 'plugin-safe' in doc:
                    return True
                if any(word in doc for word in ['admin', 'dangerous', 'unsafe', 'internal']):
                    return False
            
            return False
            
        except Exception as e:
            self.logger.debug(f"Error checking method safety for {method_name}: {e}")
            return False

    def _extract_method_info(self, method_name: str, method_obj: Any, module_name: str) -> Optional[APIMethod]:
        """Extract information about a method for SDK generation."""
        try:
            # Get signature
            try:
                sig = inspect.signature(method_obj)
                signature = f"{method_name}{sig}"
            except (ValueError, TypeError):
                signature = f"{method_name}(...)"
            
            # Get docstring
            docstring = inspect.getdoc(method_obj) or f"No documentation available for {method_name}"
            
            # Check if async
            is_async = inspect.iscoroutinefunction(method_obj)
            
            # Extract parameters
            parameters = []
            try:
                sig = inspect.signature(method_obj)
                for param_name, param in sig.parameters.items():
                    if param_name in ['self', 'cls']:
                        continue
                    
                    param_info = {
                        "name": param_name,
                        "type": str(param.annotation) if param.annotation != param.empty else "Any",
                        "default": str(param.default) if param.default != param.empty else None,
                        "required": param.default == param.empty
                    }
                    parameters.append(param_info)
            except Exception:
                pass
            
            # Get return type
            try:
                sig = inspect.signature(method_obj)
                return_type = str(sig.return_annotation) if sig.return_annotation != sig.empty else "Any"
            except Exception:
                return_type = "Any"
            
            # Determine required permissions
            required_permissions = []
            for module_info in self.safe_modules.values():
                if method_name in module_info["methods"]:
                    required_permissions = module_info["permissions"]
                    break
            
            # Generate examples
            examples = self._generate_method_examples(method_name, parameters, is_async)
            
            return APIMethod(
                name=method_name,
                module=module_name,
                signature=signature,
                docstring=docstring,
                is_async=is_async,
                is_safe=True,
                required_permissions=required_permissions,
                parameters=parameters,
                return_type=return_type,
                examples=examples
            )
            
        except Exception as e:
            self.logger.error(f"Error extracting method info for {method_name}: {e}")
            return None

    def _generate_method_examples(self, method_name: str, parameters: List[Dict[str, Any]], is_async: bool) -> List[str]:
        """Generate usage examples for a method."""
        examples = []
        
        try:
            # Basic example
            if parameters:
                param_examples = []
                for param in parameters:
                    if param["name"] in ["key", "name"]:
                        param_examples.append('"my_key"')
                    elif param["name"] in ["value", "data"]:
                        param_examples.append('"my_value"')
                    elif param["type"] == "int":
                        param_examples.append("123")
                    elif param["type"] == "bool":
                        param_examples.append("True")
                    elif param["type"] == "dict":
                        param_examples.append('{"key": "value"}')
                    elif param["type"] == "list":
                        param_examples.append('["item1", "item2"]')
                    else:
                        param_examples.append('"example"')
                
                params_str = ", ".join(param_examples)
            else:
                params_str = ""
            
            if is_async:
                examples.append(f'result = await api.{method_name}({params_str})')
            else:
                examples.append(f'result = api.{method_name}({params_str})')
            
            # Add specific examples based on method name
            if method_name == "db_set_value":
                examples.append('await api.db_set_value("user_preference", {"theme": "dark"})')
            elif method_name == "db_get_value":
                examples.append('theme = await api.db_get_value("user_preference", {"theme": "light"})')
            elif method_name == "emit_event":
                examples.append('await api.emit_event("user_action", {"action": "login", "user_id": 123})')
            elif method_name == "get_config":
                examples.append('timeout = await api.get_config("timeout", 30)')
            
        except Exception as e:
            self.logger.debug(f"Error generating examples for {method_name}: {e}")
        
        return examples

    def _scan_for_safe_apis(self) -> Dict[str, APIModule]:
        """Scan the codebase for safe APIs that can be exposed to plugins."""
        api_modules = {}
        
        try:
            # Import and scan the plugin manager for existing safe APIs
            from plexichat.core.plugins.manager import EnhancedPluginAPI
            
            # Scan EnhancedPluginAPI for safe methods
            api_methods = []
            for attr_name in dir(EnhancedPluginAPI):
                if attr_name.startswith('_'):
                    continue
                
                attr = getattr(EnhancedPluginAPI, attr_name)
                if callable(attr):
                    method_info = self._extract_method_info(attr_name, attr, "plugin_api")
                    if method_info and self._is_method_safe(attr_name, attr):
                        api_methods.append(method_info)
            
            if api_methods:
                api_modules["plugin_api"] = APIModule(
                    name="plugin_api",
                    description="Core plugin API methods",
                    methods=api_methods
                )
            
            # Scan database manager for safe methods
            try:
                from plexichat.core.database.manager import DatabaseSession
                
                db_methods = []
                safe_db_methods = ["insert", "update", "delete", "fetchone", "fetchall"]
                
                for method_name in safe_db_methods:
                    if hasattr(DatabaseSession, method_name):
                        method = getattr(DatabaseSession, method_name)
                        method_info = self._extract_method_info(method_name, method, "database")
                        if method_info:
                            db_methods.append(method_info)
                
                if db_methods:
                    api_modules["database"] = APIModule(
                        name="database",
                        description="Safe database operations",
                        methods=db_methods
                    )
                    
            except ImportError:
                self.logger.debug("Database manager not available for API scanning")
            
            # Scan file manager for safe methods
            try:
                from plexichat.core.files.file_manager import FileManager
                
                file_methods = []
                safe_file_methods = ["upload_file", "get_file_metadata", "delete_file"]
                
                for method_name in safe_file_methods:
                    if hasattr(FileManager, method_name):
                        method = getattr(FileManager, method_name)
                        method_info = self._extract_method_info(method_name, method, "files")
                        if method_info:
                            file_methods.append(method_info)
                
                if file_methods:
                    api_modules["files"] = APIModule(
                        name="files",
                        description="Safe file operations",
                        methods=file_methods
                    )
                    
            except ImportError:
                self.logger.debug("File manager not available for API scanning")
            
        except Exception as e:
            self.logger.error(f"Error scanning for safe APIs: {e}")
        
        return api_modules

    def _create_sdk_template(self) -> str:
        """Create the Jinja2 template for SDK generation."""
        return '''"""
PlexiChat Plugin SDK - Auto-Generated
=====================================

This SDK provides safe APIs for PlexiChat plugins.
Generated on: {{ generation_time }}
SDK Version: {{ sdk_version }}
PlexiChat Version: {{ plexichat_version }}

WARNING: This file is auto-generated. Do not edit manually!
"""

import asyncio
import json
import logging
from typing import Any, Dict, List, Optional, Union
from datetime import datetime

# Version information
SDK_VERSION = "{{ sdk_version }}"
PLEXICHAT_VERSION = "{{ plexichat_version }}"

class PluginSDKError(Exception):
    """Base exception for plugin SDK errors."""
    pass

class PermissionError(PluginSDKError):
    """Raised when plugin lacks required permissions."""
    pass

class PluginAPI:
    """
    Safe API interface for PlexiChat plugins.
    
    This class provides access to PlexiChat functionality while maintaining
    security through permission checks and sandboxing.
    """
    
    def __init__(self, plugin_name: str, permissions: List[str] = None):
        self.plugin_name = plugin_name
        self.permissions = set(permissions or [])
        self.logger = logging.getLogger(f"plugin.{plugin_name}")
    
    def _check_permission(self, required_permission: str) -> None:
        """Check if plugin has required permission."""
        if required_permission and required_permission not in self.permissions:
            raise PermissionError(f"Plugin '{self.plugin_name}' lacks permission: {required_permission}")
    
    def _log_api_call(self, method_name: str, *args, **kwargs) -> None:
        """Log API calls for auditing."""
        self.logger.debug(f"API call: {method_name} with args={args}, kwargs={kwargs}")

{% for module_name, module in api_modules.items() %}
    # {{ module.description }}
    # ============================================================================
    
{% for method in module.methods %}
    {% if method.is_async %}async {% endif %}def {{ method.name }}(self{% for param in method.parameters %}, {{ param.name }}{% if param.type != "Any" %}: {{ param.type }}{% endif %}{% if param.default %} = {{ param.default }}{% endif %}{% endfor %}) -> {{ method.return_type }}:
        """
        {{ method.docstring }}
        
        {% if method.required_permissions %}Required permissions: {{ method.required_permissions | join(", ") }}{% endif %}
        
        Parameters:
        {% for param in method.parameters %}
        - {{ param.name }} ({{ param.type }}): {% if param.required %}Required{% else %}Optional{% endif %}{% if param.default %}, default: {{ param.default }}{% endif %}
        {% endfor %}
        
        Returns:
        {{ method.return_type }}
        
        Examples:
        {% for example in method.examples %}
        >>> {{ example }}
        {% endfor %}
        """
        {% for permission in method.required_permissions %}
        self._check_permission("{{ permission }}")
        {% endfor %}
        self._log_api_call("{{ method.name }}"{% for param in method.parameters %}, {{ param.name }}{% endfor %})
        
        # Implementation would call the actual PlexiChat API
        # This is a placeholder for the generated SDK
        raise NotImplementedError("This method will be implemented by the plugin manager")

{% endfor %}
{% endfor %}

# Utility functions
def check_compatibility(required_version: str = None) -> bool:
    """
    Check if the current PlexiChat version is compatible with the plugin.
    
    Args:
        required_version: Minimum required PlexiChat version
    
    Returns:
        True if compatible, False otherwise
    """
    if not required_version:
        return True
    
    # Simple version comparison (major.minor.patch)
    try:
        current = tuple(map(int, PLEXICHAT_VERSION.split('.')))
        required = tuple(map(int, required_version.split('.')))
        return current >= required
    except (ValueError, AttributeError):
        return False

def get_sdk_info() -> Dict[str, str]:
    """Get SDK version information."""
    return {
        "sdk_version": SDK_VERSION,
        "plexichat_version": PLEXICHAT_VERSION,
        "generation_time": "{{ generation_time }}"
    }

# Available API modules
AVAILABLE_MODULES = {{ available_modules | tojson }}

# Required permissions for each API method
API_PERMISSIONS = {
{% for module_name, module in api_modules.items() %}
    {% for method in module.methods %}
    "{{ method.name }}": {{ method.required_permissions | tojson }},
    {% endfor %}
{% endfor %}
}

__all__ = [
    "PluginAPI",
    "PluginSDKError", 
    "PermissionError",
    "check_compatibility",
    "get_sdk_info",
    "SDK_VERSION",
    "PLEXICHAT_VERSION",
    "AVAILABLE_MODULES",
    "API_PERMISSIONS"
]
'''

    def generate_sdk(self) -> bool:
        """Generate the plugin SDK file."""
        try:
            if not self.jinja_env:
                self.logger.error("Jinja2 not available. Cannot generate SDK.")
                return False
            
            self.logger.info("Starting SDK generation...")
            
            # Scan for safe APIs
            api_modules = self._scan_for_safe_apis()
            
            if not api_modules:
                self.logger.warning("No safe APIs found. Generating minimal SDK.")
                api_modules = {
                    "core": APIModule(
                        name="core",
                        description="Core plugin functionality",
                        methods=[
                            APIMethod(
                                name="get_plugin_info",
                                module="core",
                                signature="get_plugin_info(self) -> Dict[str, Any]",
                                docstring="Get information about the current plugin",
                                is_async=False,
                                is_safe=True
                            )
                        ]
                    )
                }
            
            # Prepare template data
            template_data = {
                "generation_time": datetime.now().isoformat(),
                "sdk_version": SDK_VERSION,
                "plexichat_version": PLEXICHAT_VERSION,
                "api_modules": api_modules,
                "available_modules": list(api_modules.keys())
            }
            
            # Generate SDK content
            template_content = self._create_sdk_template()
            template = self.jinja_env.from_string(template_content)
            sdk_content = template.render(**template_data)
            
            # Write SDK file
            self.output_file.parent.mkdir(parents=True, exist_ok=True)
            self.output_file.write_text(sdk_content, encoding='utf-8')
            
            # Update .gitignore
            self._update_gitignore()
            
            self.logger.info(f"SDK generated successfully: {self.output_file}")
            self.logger.info(f"Generated {len(api_modules)} API modules with {sum(len(m.methods) for m in api_modules.values())} methods")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error generating SDK: {e}", exc_info=True)
            return False

    def _update_gitignore(self) -> None:
        """Update .gitignore to exclude generated SDK."""
        try:
            # Find project root
            current_dir = Path(__file__).resolve()
            project_root = None
            
            for parent in current_dir.parents:
                if (parent / ".git").exists() or (parent / ".gitignore").exists():
                    project_root = parent
                    break
            
            if not project_root:
                self.logger.debug("Could not find project root for .gitignore update")
                return
            
            gitignore_path = project_root / ".gitignore"
            
            # Read existing .gitignore
            if gitignore_path.exists():
                content = gitignore_path.read_text()
            else:
                content = ""
            
            # Add generated SDK to .gitignore if not already present
            sdk_pattern = "src/plexichat/core/plugins/generated_sdk.py"
            if sdk_pattern not in content:
                if content and not content.endswith('\n'):
                    content += '\n'
                content += f"\n# Auto-generated plugin SDK\n{sdk_pattern}\n"
                
                gitignore_path.write_text(content)
                self.logger.info("Updated .gitignore to exclude generated SDK")
            
        except Exception as e:
            self.logger.debug(f"Could not update .gitignore: {e}")

    def validate_sdk(self) -> bool:
        """Validate the generated SDK by attempting to import it."""
        try:
            if not self.output_file.exists():
                self.logger.error("SDK file does not exist")
                return False
            
            # Try to compile the generated SDK
            with open(self.output_file, 'r') as f:
                sdk_content = f.read()
            
            try:
                compile(sdk_content, str(self.output_file), 'exec')
                self.logger.info("SDK validation successful")
                return True
            except SyntaxError as e:
                self.logger.error(f"SDK syntax error: {e}")
                return False
            
        except Exception as e:
            self.logger.error(f"Error validating SDK: {e}")
            return False

    def get_generation_stats(self) -> Dict[str, Any]:
        """Get statistics about the last SDK generation."""
        try:
            if not self.output_file.exists():
                return {"error": "SDK not generated"}
            
            stat = self.output_file.stat()
            
            # Count lines and methods in generated SDK
            content = self.output_file.read_text()
            lines = len(content.splitlines())
            methods = len(re.findall(r'def \w+\(', content))
            
            return {
                "file_path": str(self.output_file),
                "file_size": stat.st_size,
                "lines_of_code": lines,
                "method_count": methods,
                "last_modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "sdk_version": SDK_VERSION,
                "plexichat_version": PLEXICHAT_VERSION
            }
            
        except Exception as e:
            self.logger.error(f"Error getting generation stats: {e}")
            return {"error": str(e)}

# Global SDK generator instance
sdk_generator = PluginSDKGenerator()

# Convenience functions
def generate_plugin_sdk() -> bool:
    """Generate the plugin SDK using the global generator."""
    return sdk_generator.generate_sdk()

def validate_plugin_sdk() -> bool:
    """Validate the generated plugin SDK."""
    return sdk_generator.validate_sdk()

def get_sdk_stats() -> Dict[str, Any]:
    """Get SDK generation statistics."""
    return sdk_generator.get_generation_stats()

# Auto-generate SDK on import if it doesn't exist
def _auto_generate_sdk():
    """Auto-generate SDK if it doesn't exist."""
    try:
        if not sdk_generator.output_file.exists():
            logger.info("Generated SDK not found. Auto-generating...")
            generate_plugin_sdk()
    except Exception as e:
        logger.debug(f"Auto-generation failed: {e}")

# Run auto-generation
_auto_generate_sdk()

__all__ = [
    "PluginSDKGenerator",
    "sdk_generator", 
    "generate_plugin_sdk",
    "validate_plugin_sdk",
    "get_sdk_stats",
    "APIMethod",
    "APIModule",
    "SDK_VERSION",
    "PLEXICHAT_VERSION"
]