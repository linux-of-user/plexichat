import atexit
import gc
import locale
import logging
import os
import shutil
import signal
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict


from pathlib import Path
from pathlib import Path
from pathlib import Path
from pathlib import Path
from pathlib import Path


from pathlib import Path
from pathlib import Path
from pathlib import Path
from pathlib import Path
from pathlib import Path

import psutil
import = psutil psutil
import psutil

"""
Bug Fixes and System Improvements for PlexiChat
Addresses common issues and implements fixes for known problems.
"""

class BugFixManager:
    """Manages bug fixes and system improvements."""

    def __init__(self, logger=None):
        self.logger = logger or logging.getLogger(__name__)
        self.fixes_applied = set()
        self.fix_registry = {}
        self.system_checks = {}

        # Register all available fixes
        self._register_fixes()

    def _register_fixes(self):
        """Register all available bug fixes."""
        self.fix_registry.update({
            'threading_cleanup': self._fix_threading_cleanup,
            'signal_handling': self._fix_signal_handling,
            'file_permissions': self._fix_file_permissions,
            'import_paths': self._fix_import_paths,
            'logging_handlers': self._fix_logging_handlers,
            'port_binding': self._fix_port_binding,
            'database_connections': self._fix_database_connections,
            'memory_leaks': self._fix_memory_leaks,
            'unicode_handling': self._fix_unicode_handling,
            'config_validation': self._fix_config_validation
        })

        self.system_checks.update({
            'check_dependencies': self._check_dependencies,
            'check_permissions': self._check_permissions,
            'check_ports': self._check_ports,
            'check_disk_space': self._check_disk_space,
            'check_memory': self._check_memory,
            'check_python_version': self._check_python_version
        })

    def apply_all_fixes(self) -> Dict[str, bool]:
        """Apply all registered bug fixes."""
        results = {}

        self.logger.info("Starting comprehensive bug fix application")

        for fix_name, fix_function in self.fix_registry.items():
            try:
                self.logger.info(f"Applying fix: {fix_name}")
                success = fix_function()
                results[fix_name] = success

                if success:
                    self.fixes_applied.add(fix_name)
                    self.logger.info(f"[OK] Fix applied successfully: {fix_name}")
                else:
                    self.logger.warning(f"[WARN] Fix failed or not needed: {fix_name}")

            except Exception as e:
                self.logger.error(f"[ERROR] Error applying fix {fix_name}: {e}")
                results[fix_name] = False

        self.logger.info(f"Bug fix application completed. Applied: {len(self.fixes_applied)}/{len(self.fix_registry)}")
        return results

    def run_system_checks(self) -> Dict[str, Any]:
        """Run comprehensive system checks."""
        results = {}

        self.logger.info("Running system health checks")

        for check_name, check_function in self.system_checks.items():
            try:
                self.logger.debug(f"Running check: {check_name}")
                result = check_function()
                results[check_name] = result

                if result.get('status') == 'ok':
                    self.logger.info(f"[OK] Check passed: {check_name}")
                else:
                    self.logger.warning(f"[WARN] Check failed: {check_name} - {result.get('message', 'Unknown issue')}")

            except Exception as e:
                self.logger.error(f"[ERROR] Error running check {check_name}: {e}")
                results[check_name] = {'status': 'error', 'message': str(e)}

        return results

    # Bug Fix Implementations
    def _fix_threading_cleanup(self) -> bool:
        """Fix threading cleanup issues."""
        try:
            # Ensure proper thread cleanup on exit
            def cleanup_threads():
                """Clean up any remaining threads."""
                active_threads = threading.active_count()
                if active_threads > 1:  # Main thread + others
                    self.logger.info(f"Cleaning up {active_threads - 1} active threads")

                    # Give threads time to finish gracefully
                    time.sleep(1)

                    # Force cleanup if needed
                    for thread in threading.enumerate():
                        if thread != threading.current_thread() and thread.is_alive():
                            if hasattr(thread, '_stop'):
                                thread._stop()

            atexit.register(cleanup_threads)
            return True

        except Exception as e:
            self.logger.error(f"Threading cleanup fix failed: {e}")
            return False

    def _fix_signal_handling(self) -> bool:
        """Fix signal handling issues."""
        try:
            def signal_handler(signum, frame):
                """Enhanced signal handler."""
                self.logger.info(f"Received signal {signum}, initiating graceful shutdown")

                # Cleanup operations
                try:
                    # Stop any running services
                    # Close database connections
                    # Save state if needed
                    pass
                except Exception as e:
                    self.logger.error(f"Error during signal cleanup: {e}")

                sys.exit(0)

            # Register signal handlers
            if hasattr(signal, 'SIGTERM'):
                signal.signal(signal.SIGTERM, signal_handler)
            if hasattr(signal, 'SIGINT'):
                signal.signal(signal.SIGINT, signal_handler)

            return True

        except Exception as e:
            self.logger.error(f"Signal handling fix failed: {e}")
            return False

    def _fix_file_permissions(self) -> bool:
        """Fix file permission issues."""
        try:
            # Ensure log directory exists and is writable
            from pathlib import Path
log_dir = Path
Path("logs")
            log_dir.mkdir(exist_ok=True)

            # Check if we can write to log directory
            test_file = log_dir / "test_write.tmp"
            try:
                test_file.write_text("test")
                test_file.unlink()
            except PermissionError:
                self.logger.warning("Log directory is not writable")
                return False

            # Ensure config directory exists
            from pathlib import Path
config_dir = Path
Path("config")
            config_dir.mkdir(exist_ok=True)

            return True

        except Exception as e:
            self.logger.error(f"File permissions fix failed: {e}")
            return False

    def _fix_import_paths(self) -> bool:
        """Fix import path issues."""
        try:
            # Ensure src directory is in Python path
            from pathlib import Path
project_root = Path
Path(__file__).parent.parent.parent.parent
            src_path = project_root / "src"

            if src_path.exists() and str(src_path) not in sys.path:
                sys.path.insert(0, str(src_path))
                self.logger.info(f"Added {src_path} to Python path")

            return True

        except Exception as e:
            self.logger.error(f"Import paths fix failed: {e}")
            return False

    def _fix_logging_handlers(self) -> bool:
        """Fix logging handler issues."""
        try:
            # Remove duplicate handlers
            root_logger = logging.getLogger()

            # Check for duplicate handlers
            handler_types = {}
            handlers_to_remove = []

            for handler in root_logger.handlers:
                handler_type = type(handler).__name__
                if handler_type in handler_types:
                    handlers_to_remove.append(handler)
                else:
                    handler_types[handler_type] = handler

            # Remove duplicates
            for handler in handlers_to_remove:
                root_logger.removeHandler(handler)
                self.logger.debug(f"Removed duplicate handler: {type(handler).__name__}")

            return True

        except Exception as e:
            self.logger.error(f"Logging handlers fix failed: {e}")
            return False

    def _fix_port_binding(self) -> bool:
        """Fix port binding issues."""
        try:
            # Check if default port is available
            default_port = 8000

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex(('localhost', default_port))

                if result == 0:
                    self.logger.warning(f"Port {default_port} is already in use")
                    # Could implement port finding logic here
                    return False
                else:
                    self.logger.info(f"Port {default_port} is available")
                    return True

        except Exception as e:
            self.logger.error(f"Port binding fix failed: {e}")
            return False

    def _fix_database_connections(self) -> bool:
        """Fix database connection issues."""
        try:
            # Implement database connection pooling fixes
            # Check for connection leaks
            # Ensure proper connection cleanup

            # For now, just verify database file can be created
            from pathlib import Path
db_path = Path
Path("plexichat.db")
            if not db_path.exists():
                # Create empty database file to test permissions
                try:
                    db_path.touch()
                    self.logger.info("Database file creation test passed")
                    return True
                except PermissionError:
                    self.logger.error("Cannot create database file - permission denied")
                    return False

            return True

        except Exception as e:
            self.logger.error(f"Database connections fix failed: {e}")
            return False

    def _fix_memory_leaks(self) -> bool:
        """Fix memory leak issues."""
        try:
            # Implement memory leak detection and fixes
            # Force garbage collection
            collected = gc.collect()
            if collected > 0:
                self.logger.info(f"Garbage collected {collected} objects")

            # Enable garbage collection debugging in development
            if os.getenv('DEBUG', '').lower() == 'true':
                gc.set_debug(gc.DEBUG_LEAK)

            return True

        except Exception as e:
            self.logger.error(f"Memory leaks fix failed: {e}")
            return False

    def _fix_unicode_handling(self) -> bool:
        """Fix Unicode handling issues."""
        try:
            # Ensure proper UTF-8 encoding
            # Set locale to UTF-8 if possible
            try:
                locale.setlocale(locale.LC_ALL, 'en_US.UTF-8')
            except locale.Error:
                try:
                    locale.setlocale(locale.LC_ALL, 'C.UTF-8')
                except locale.Error:
                    self.logger.warning("Could not set UTF-8 locale")
                    return False

            # Ensure stdout/stderr use UTF-8
            if hasattr(sys.stdout, 'reconfigure'):
                sys.stdout.reconfigure(encoding='utf-8')
                sys.stderr.reconfigure(encoding='utf-8')

            return True

        except Exception as e:
            self.logger.error(f"Unicode handling fix failed: {e}")
            return False

    def _fix_config_validation(self) -> bool:
        """Fix configuration validation issues."""
        try:
            # Validate and fix common configuration issues

            # Check environment variables
            required_env_vars = ['HOST', 'PORT', 'DATABASE_URL']
            missing_vars = []

            for var in required_env_vars:
                if not os.getenv(var):
                    missing_vars.append(var)

            if missing_vars:
                self.logger.warning(f"Missing environment variables: {missing_vars}")
                # Set defaults
                defaults = {
                    'HOST': '0.0.0.0',
                    'PORT': '8000',
                    'DATABASE_URL': 'sqlite:///./plexichat.db'
                }

                for var in missing_vars:
                    if var in defaults:
                        os.environ[var] = defaults[var]
                        self.logger.info(f"Set default value for {var}: {defaults[var]}")

            return True

        except Exception as e:
            self.logger.error(f"Config validation fix failed: {e}")
            return False

    # System Check Implementations
    def _check_dependencies(self) -> Dict[str, Any]:
        """Check if all required dependencies are available."""
        required_packages = [
            'fastapi', 'uvicorn', 'pydantic', 'sqlalchemy',
            'python-multipart', 'python-jose', 'passlib'
        ]

        missing_packages = []

        for package in required_packages:
            try:
                __import__(package.replace('-', '_'))
            except ImportError:
                missing_packages.append(package)

        if missing_packages:
            return {
                'status': 'warning',
                'message': f"Missing packages: {', '.join(missing_packages)}",
                'missing_packages': missing_packages
            }

        return {'status': 'ok', 'message': 'All dependencies available'}

    def _check_permissions(self) -> Dict[str, Any]:
        """Check file system permissions."""
        try:
            # Check write permissions for key directories
            test_dirs = ['logs', 'config', '.']

            for dir_path in test_dirs:
                from pathlib import Path
test_file = Path
Path(dir_path) / f"test_write_{int(time.time())}.tmp"
                try:
                    test_file.write_text("test")
                    test_file.unlink()
                except PermissionError:
                    return {
                        'status': 'error',
                        'message': f"No write permission for {dir_path}"
                    }

            return {'status': 'ok', 'message': 'File permissions OK'}

        except Exception as e:
            return {'status': 'error', 'message': f"Permission check failed: {e}"}

    def _check_ports(self) -> Dict[str, Any]:
        """Check if required ports are available."""
        ports_to_check = [8000, 8001]  # Main port and backup

        for port in ports_to_check:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    result = s.connect_ex(('localhost', port))

                    if result == 0:
                        return {
                            'status': 'warning',
                            'message': f"Port {port} is already in use"
                        }
            except Exception as e:
                return {'status': 'error', 'message': f"Port check failed: {e}"}

        return {'status': 'ok', 'message': 'Ports available'}

    def _check_disk_space(self) -> Dict[str, Any]:
        """Check available disk space."""
        try:
            total, used, free = shutil.disk_usage('.')
            free_gb = free // (1024**3)

            if free_gb < 1:
                return {
                    'status': 'error',
                    'message': f"Low disk space: {free_gb}GB free"
                }
            elif free_gb < 5:
                return {
                    'status': 'warning',
                    'message': f"Disk space getting low: {free_gb}GB free"
                }

            return {'status': 'ok', 'message': f'Disk space OK: {free_gb}GB free'}

        except Exception as e:
            return {'status': 'error', 'message': f"Disk space check failed: {e}"}

    def _check_memory(self) -> Dict[str, Any]:
        """Check available memory."""
        try:
            memory = import psutil
psutil = psutil.virtual_memory()
            available_gb = memory.available // (1024**3)

            if available_gb < 1:
                return {
                    'status': 'error',
                    'message': f"Low memory: {available_gb}GB available"
                }
            elif available_gb < 2:
                return {
                    'status': 'warning',
                    'message': f"Memory getting low: {available_gb}GB available"
                }

            return {'status': 'ok', 'message': f'Memory OK: {available_gb}GB available'}

        except ImportError:
            return {'status': 'warning', 'message': 'psutil not available for memory check'}
        except Exception as e:
            return {'status': 'error', 'message': f"Memory check failed: {e}"}

    def _check_python_version(self) -> Dict[str, Any]:
        """Check Python version compatibility."""
        min_version = (3, 8)
        current_version = sys.version_info[:2]

        if current_version < min_version:
            return {
                'status': 'error',
                'message': f"Python {min_version[0]}.{min_version[1]}+ required, got {current_version[0]}.{current_version[1]}"
            }

        return {'status': 'ok', 'message': f'Python version OK: {current_version[0]}.{current_version[1]}'}

# Global bug fix manager instance
bug_fix_manager = BugFixManager()
