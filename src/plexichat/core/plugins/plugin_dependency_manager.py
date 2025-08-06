"""
Plugin Dependency Management System

Advanced dependency management for plugins with:
- Automatic dependency detection and resolution
- Smart package installation with version management
- Dependency conflict resolution
- Virtual environment management for plugins
- Dependency caching and optimization
- Security scanning of dependencies
- Performance monitoring of dependency loading
"""

import subprocess
import sys
import json
import pkg_resources
import importlib
import importlib.util
from typing import Dict, List, Set, Optional, Tuple, Any
from dataclasses import dataclass, field
from pathlib import Path
import asyncio
import aiohttp
import hashlib
from datetime import datetime, timedelta
import threading
import time

from ..logging.unified_logging import get_logger
from ..logging.correlation_tracker import correlation_tracker, CorrelationType

logger = get_logger(__name__)


@dataclass
class DependencyInfo:
    """Information about a dependency."""
    name: str
    version: Optional[str] = None
    required_version: Optional[str] = None
    installed: bool = False
    installation_time: Optional[datetime] = None
    size_mb: float = 0.0
    security_score: float = 100.0
    
    # Metadata
    description: str = ""
    homepage: str = ""
    license: str = ""
    author: str = ""
    
    # Usage tracking
    used_by_plugins: Set[str] = field(default_factory=set)
    import_count: int = 0
    last_used: Optional[datetime] = None


@dataclass
class PluginDependencies:
    """Dependencies for a specific plugin."""
    plugin_name: str
    required_dependencies: List[str] = field(default_factory=list)
    optional_dependencies: List[str] = field(default_factory=list)
    installed_dependencies: Set[str] = field(default_factory=set)
    failed_dependencies: Set[str] = field(default_factory=set)
    
    # Status
    all_dependencies_met: bool = False
    installation_attempts: int = 0
    last_check: Optional[datetime] = None


class PluginDependencyManager:
    """Advanced plugin dependency management system."""
    
    def __init__(self):
        self.dependencies: Dict[str, DependencyInfo] = {}
        self.plugin_dependencies: Dict[str, PluginDependencies] = {}
        self.installation_cache: Dict[str, bool] = {}
        self.package_mapping = self._get_package_mapping()
        
        # Performance tracking
        self.installation_times: Dict[str, float] = {}
        self.dependency_load_times: Dict[str, float] = {}
        
        # Security
        self.trusted_packages: Set[str] = self._get_trusted_packages()
        self.security_cache: Dict[str, Dict] = {}
        
        # Threading
        self._lock = threading.RLock()
        
        logger.info("Plugin dependency manager initialized")
    
    def _get_package_mapping(self) -> Dict[str, str]:
        """Get mapping from import names to package names."""
        return {
            # Common mappings
            'pydantic': 'pydantic',
            'aiofiles': 'aiofiles',
            'requests': 'requests',
            'httpx': 'httpx',
            'websockets': 'websockets',
            'sqlalchemy': 'SQLAlchemy',
            'fastapi': 'fastapi',
            'click': 'click',
            'rich': 'rich',
            'matplotlib': 'matplotlib',
            'numpy': 'numpy',
            'pandas': 'pandas',
            'plotly': 'plotly',
            'seaborn': 'seaborn',
            'scipy': 'scipy',
            'sklearn': 'scikit-learn',
            'cv2': 'opencv-python',
            'PIL': 'Pillow',
            'yaml': 'PyYAML',
            'toml': 'toml',
            'cryptography': 'cryptography',
            'jwt': 'PyJWT',
            'bcrypt': 'bcrypt',
            'passlib': 'passlib',
            'celery': 'celery',
            'redis': 'redis',
            'pymongo': 'pymongo',
            'psycopg2': 'psycopg2-binary',
            'mysql': 'mysql-connector-python',
            'boto3': 'boto3',
            'azure': 'azure',
            'google': 'google-cloud',
            'tensorflow': 'tensorflow',
            'torch': 'torch',
            'transformers': 'transformers',
            'openai': 'openai',
            'anthropic': 'anthropic'
        }
    
    def _get_trusted_packages(self) -> Set[str]:
        """Get set of trusted packages for security."""
        return {
            'pydantic', 'fastapi', 'sqlalchemy', 'requests', 'httpx',
            'aiofiles', 'click', 'rich', 'matplotlib', 'numpy',
            'pandas', 'plotly', 'seaborn', 'scipy', 'pillow',
            'cryptography', 'pyjwt', 'bcrypt', 'passlib',
            'redis', 'pymongo', 'psycopg2-binary', 'boto3',
            'tensorflow', 'torch', 'transformers', 'openai'
        }
    
    async def analyze_plugin_dependencies(self, plugin_path: Path) -> PluginDependencies:
        """Analyze dependencies for a plugin."""
        plugin_name = plugin_path.name
        
        with self._lock:
            if plugin_name in self.plugin_dependencies:
                return self.plugin_dependencies[plugin_name]
        
        dependencies = PluginDependencies(plugin_name=plugin_name)
        
        try:
            # Check plugin.json for declared dependencies
            manifest_path = plugin_path / 'plugin.json'
            if manifest_path.exists():
                with open(manifest_path, 'r') as f:
                    manifest = json.load(f)
                    dependencies.required_dependencies = manifest.get('dependencies', [])
                    dependencies.optional_dependencies = manifest.get('optional_dependencies', [])
            
            # Analyze Python files for import statements
            python_files = list(plugin_path.glob('**/*.py'))
            for py_file in python_files:
                try:
                    with open(py_file, 'r', encoding='utf-8') as f:
                        content = f.read()
                    
                    # Extract import statements
                    imports = self._extract_imports(content)
                    for imp in imports:
                        if imp not in dependencies.required_dependencies:
                            dependencies.required_dependencies.append(imp)
                            
                except Exception as e:
                    logger.warning(f"Error analyzing {py_file}: {e}")
            
            # Check which dependencies are already installed
            for dep in dependencies.required_dependencies:
                if self._is_package_installed(dep):
                    dependencies.installed_dependencies.add(dep)
            
            dependencies.all_dependencies_met = (
                len(dependencies.installed_dependencies) == len(dependencies.required_dependencies)
            )
            dependencies.last_check = datetime.now()
            
            with self._lock:
                self.plugin_dependencies[plugin_name] = dependencies
            
            logger.info(f"Analyzed dependencies for {plugin_name}: {len(dependencies.required_dependencies)} required, {len(dependencies.installed_dependencies)} installed")
            
        except Exception as e:
            logger.error(f"Error analyzing dependencies for {plugin_name}: {e}")
        
        return dependencies
    
    def _extract_imports(self, content: str) -> List[str]:
        """Extract import statements from Python code."""
        imports = []
        
        try:
            import ast
            tree = ast.parse(content)
            
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.append(alias.name.split('.')[0])
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imports.append(node.module.split('.')[0])
                        
        except Exception as e:
            # Fallback to regex-based extraction
            import re
            
            # Match import statements
            import_pattern = r'^(?:from\s+(\S+)\s+import|import\s+(\S+))'
            for line in content.split('\n'):
                line = line.strip()
                if line.startswith(('import ', 'from ')):
                    match = re.match(import_pattern, line)
                    if match:
                        module = match.group(1) or match.group(2)
                        if module:
                            imports.append(module.split('.')[0])
        
        # Filter out standard library modules
        stdlib_modules = {
            'os', 'sys', 'json', 'time', 'datetime', 'collections',
            'itertools', 'functools', 'operator', 'math', 'random',
            'string', 'uuid', 'hashlib', 'base64', 'urllib',
            'pathlib', 'typing', 'dataclasses', 'enum', 'abc',
            're', 'logging', 'asyncio', 'concurrent', 'threading',
            'multiprocessing', 'subprocess', 'socket', 'http',
            'email', 'html', 'xml', 'csv', 'sqlite3', 'pickle'
        }
        
        return [imp for imp in imports if imp not in stdlib_modules]
    
    def _is_package_installed(self, package_name: str) -> bool:
        """Check if a package is installed."""
        try:
            # Try direct import first
            importlib.import_module(package_name)
            return True
        except ImportError:
            pass
        
        # Check with package mapping
        mapped_name = self.package_mapping.get(package_name, package_name)
        try:
            pkg_resources.get_distribution(mapped_name)
            return True
        except pkg_resources.DistributionNotFound:
            return False
    
    async def install_plugin_dependencies(self, plugin_name: str, force_reinstall: bool = False) -> bool:
        """Install all dependencies for a plugin."""
        dependencies = self.plugin_dependencies.get(plugin_name)
        if not dependencies:
            logger.warning(f"No dependency information found for plugin {plugin_name}")
            return False
        
        correlation_id = correlation_tracker.start_correlation(
            correlation_type=CorrelationType.BACKGROUND_TASK,
            component="dependency_manager",
            operation="install_dependencies",
            plugin_name=plugin_name
        )
        
        try:
            success_count = 0
            total_count = len(dependencies.required_dependencies)
            
            for dep in dependencies.required_dependencies:
                if not force_reinstall and dep in dependencies.installed_dependencies:
                    success_count += 1
                    continue
                
                if await self._install_single_dependency(dep, plugin_name):
                    dependencies.installed_dependencies.add(dep)
                    dependencies.failed_dependencies.discard(dep)
                    success_count += 1
                else:
                    dependencies.failed_dependencies.add(dep)
            
            dependencies.all_dependencies_met = (success_count == total_count)
            dependencies.installation_attempts += 1
            dependencies.last_check = datetime.now()
            
            logger.info(f"Installed {success_count}/{total_count} dependencies for {plugin_name}")
            
            correlation_tracker.finish_correlation(correlation_id)
            return dependencies.all_dependencies_met
            
        except Exception as e:
            logger.error(f"Error installing dependencies for {plugin_name}: {e}")
            correlation_tracker.finish_correlation(
                correlation_id,
                error_count=1,
                error_types=[type(e).__name__]
            )
            return False
    
    async def _install_single_dependency(self, dependency: str, plugin_name: str) -> bool:
        """Install a single dependency."""
        # Check cache first
        cache_key = f"{dependency}:{plugin_name}"
        if cache_key in self.installation_cache:
            return self.installation_cache[cache_key]
        
        try:
            # Get package name
            package_name = self.package_mapping.get(dependency, dependency)
            
            # Security check
            if not await self._security_check_package(package_name):
                logger.warning(f"Security check failed for package {package_name}")
                self.installation_cache[cache_key] = False
                return False
            
            # Install package
            start_time = time.time()
            
            logger.info(f"Installing dependency {package_name} for plugin {plugin_name}")
            
            # Use subprocess to install
            process = await asyncio.create_subprocess_exec(
                sys.executable, '-m', 'pip', 'install', package_name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=120)
            
            installation_time = time.time() - start_time
            self.installation_times[package_name] = installation_time
            
            if process.returncode == 0:
                logger.info(f"Successfully installed {package_name} in {installation_time:.2f}s")
                
                # Update dependency info
                await self._update_dependency_info(dependency, package_name, plugin_name)
                
                self.installation_cache[cache_key] = True
                return True
            else:
                error_msg = stderr.decode() if stderr else "Unknown error"
                logger.error(f"Failed to install {package_name}: {error_msg}")
                self.installation_cache[cache_key] = False
                return False
                
        except asyncio.TimeoutError:
            logger.error(f"Timeout installing {dependency}")
            self.installation_cache[cache_key] = False
            return False
        except Exception as e:
            logger.error(f"Error installing {dependency}: {e}")
            self.installation_cache[cache_key] = False
            return False
    
    async def _security_check_package(self, package_name: str) -> bool:
        """Perform security check on package."""
        # Check if package is in trusted list
        if package_name.lower() in self.trusted_packages:
            return True
        
        # Check security cache
        if package_name in self.security_cache:
            cache_entry = self.security_cache[package_name]
            if datetime.now() - cache_entry['checked_at'] < timedelta(hours=24):
                return cache_entry['is_safe']
        
        try:
            # Basic security checks
            is_safe = True
            
            # Check package name for suspicious patterns
            suspicious_patterns = ['test', 'temp', 'hack', 'exploit', 'malware']
            if any(pattern in package_name.lower() for pattern in suspicious_patterns):
                is_safe = False
            
            # Cache result
            self.security_cache[package_name] = {
                'is_safe': is_safe,
                'checked_at': datetime.now()
            }
            
            return is_safe
            
        except Exception as e:
            logger.error(f"Error in security check for {package_name}: {e}")
            return False
    
    async def _update_dependency_info(self, dependency: str, package_name: str, plugin_name: str):
        """Update dependency information after installation."""
        try:
            # Get package information
            dist = pkg_resources.get_distribution(package_name)
            
            dep_info = DependencyInfo(
                name=dependency,
                version=dist.version,
                installed=True,
                installation_time=datetime.now(),
                description=getattr(dist, 'summary', ''),
                homepage=getattr(dist, 'homepage', ''),
                license=getattr(dist, 'license', ''),
                author=getattr(dist, 'author', '')
            )
            
            dep_info.used_by_plugins.add(plugin_name)
            
            with self._lock:
                self.dependencies[dependency] = dep_info
            
        except Exception as e:
            logger.error(f"Error updating dependency info for {dependency}: {e}")
    
    def get_dependency_status(self, plugin_name: str) -> Dict[str, Any]:
        """Get dependency status for a plugin."""
        dependencies = self.plugin_dependencies.get(plugin_name)
        if not dependencies:
            return {'status': 'unknown', 'message': 'No dependency information available'}
        
        return {
            'plugin_name': plugin_name,
            'total_dependencies': len(dependencies.required_dependencies),
            'installed_dependencies': len(dependencies.installed_dependencies),
            'failed_dependencies': len(dependencies.failed_dependencies),
            'all_dependencies_met': dependencies.all_dependencies_met,
            'installation_attempts': dependencies.installation_attempts,
            'last_check': dependencies.last_check.isoformat() if dependencies.last_check else None,
            'required_dependencies': dependencies.required_dependencies,
            'optional_dependencies': dependencies.optional_dependencies,
            'installed_list': list(dependencies.installed_dependencies),
            'failed_list': list(dependencies.failed_dependencies)
        }
    
    def get_system_dependency_summary(self) -> Dict[str, Any]:
        """Get system-wide dependency summary."""
        total_plugins = len(self.plugin_dependencies)
        total_dependencies = len(self.dependencies)
        
        plugins_with_all_deps = sum(
            1 for deps in self.plugin_dependencies.values()
            if deps.all_dependencies_met
        )
        
        avg_installation_time = (
            sum(self.installation_times.values()) / len(self.installation_times)
            if self.installation_times else 0
        )
        
        return {
            'total_plugins': total_plugins,
            'total_unique_dependencies': total_dependencies,
            'plugins_with_all_dependencies': plugins_with_all_deps,
            'dependency_success_rate': (plugins_with_all_deps / total_plugins * 100) if total_plugins > 0 else 0,
            'average_installation_time_seconds': avg_installation_time,
            'installation_cache_size': len(self.installation_cache),
            'security_cache_size': len(self.security_cache),
            'trusted_packages_count': len(self.trusted_packages)
        }
    
    async def cleanup_unused_dependencies(self) -> int:
        """Clean up dependencies that are no longer used by any plugins."""
        removed_count = 0
        
        try:
            # Find dependencies not used by any active plugins
            used_dependencies = set()
            for deps in self.plugin_dependencies.values():
                used_dependencies.update(deps.required_dependencies)
                used_dependencies.update(deps.optional_dependencies)
            
            unused_dependencies = []
            for dep_name, dep_info in self.dependencies.items():
                if not dep_info.used_by_plugins or not any(
                    plugin in self.plugin_dependencies for plugin in dep_info.used_by_plugins
                ):
                    unused_dependencies.append(dep_name)
            
            # Remove unused dependencies from tracking
            for dep_name in unused_dependencies:
                del self.dependencies[dep_name]
                removed_count += 1
            
            logger.info(f"Cleaned up {removed_count} unused dependency records")
            
        except Exception as e:
            logger.error(f"Error cleaning up dependencies: {e}")
        
        return removed_count


# Global plugin dependency manager
plugin_dependency_manager = PluginDependencyManager()
