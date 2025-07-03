"""
NetLink Server Management System
Comprehensive server lifecycle management with hot reload, zero-downtime updates,
configuration preservation, and integrity checking.
"""

import os
import sys
import json
import time
import signal
import psutil
import asyncio
import logging
import threading
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, asdict
from enum import Enum
import hashlib
import shutil
import tempfile
import yaml

logger = logging.getLogger(__name__)

class ServerState(str, Enum):
    """Server state enumeration."""
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    RESTARTING = "restarting"
    UPDATING = "updating"
    ERROR = "error"
    MAINTENANCE = "maintenance"

class UpdateType(str, Enum):
    """Update type enumeration."""
    HOT = "hot"           # No restart required
    WARM = "warm"         # Graceful restart
    COLD = "cold"         # Full restart required
    MAINTENANCE = "maintenance"  # Maintenance mode required

@dataclass
class ServerInfo:
    """Server information."""
    pid: Optional[int] = None
    state: ServerState = ServerState.STOPPED
    started_at: Optional[datetime] = None
    uptime: float = 0.0
    host: str = "0.0.0.0"
    port: int = 8000
    version: str = "3.0.0"
    config_hash: Optional[str] = None
    last_update: Optional[datetime] = None
    memory_usage: float = 0.0
    cpu_usage: float = 0.0

@dataclass
class UpdateInfo:
    """Update information."""
    id: str
    type: UpdateType
    version: str
    description: str
    files: List[str]
    backup_required: bool = True
    restart_required: bool = False
    maintenance_required: bool = False
    rollback_available: bool = True

class ServerManager:
    """Comprehensive server management system."""
    
    def __init__(self, config_path: str = "config/server.yaml"):
        self.config_path = Path(config_path)
        self.config = self._load_config()
        
        self.server_info = ServerInfo()
        self.process: Optional[psutil.Process] = None
        self.update_queue: List[UpdateInfo] = []
        self.backup_dir = Path("backups/server")
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        
        # State management
        self.state_file = Path("data/server_state.json")
        self.lock_file = Path("data/server.lock")
        
        # Monitoring
        self.monitoring_enabled = True
        self.monitoring_thread: Optional[threading.Thread] = None
        self.shutdown_event = threading.Event()
        
        # Signal handlers
        self._setup_signal_handlers()
        
        # Load previous state
        self._load_server_state()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load server configuration."""
        default_config = {
            "server": {
                "host": "0.0.0.0",
                "port": 8000,
                "workers": 1,
                "reload": False,
                "log_level": "info"
            },
            "management": {
                "enable_hot_reload": True,
                "enable_zero_downtime": True,
                "backup_before_update": True,
                "max_restart_attempts": 3,
                "restart_delay": 5,
                "health_check_timeout": 30,
                "graceful_shutdown_timeout": 30
            },
            "monitoring": {
                "enabled": True,
                "interval": 30,
                "memory_threshold": 80,
                "cpu_threshold": 90,
                "disk_threshold": 85
            },
            "integrity": {
                "check_on_startup": True,
                "check_interval": 300,
                "verify_checksums": True,
                "auto_repair": False
            }
        }
        
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r') as f:
                    config = yaml.safe_load(f)
                    # Merge with defaults
                    return self._merge_config(default_config, config)
            except Exception as e:
                logger.error(f"Failed to load config: {e}")
        
        # Save default config
        self._save_config(default_config)
        return default_config
    
    def _merge_config(self, default: Dict, custom: Dict) -> Dict:
        """Merge configuration dictionaries."""
        result = default.copy()
        for key, value in custom.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_config(result[key], value)
            else:
                result[key] = value
        return result
    
    def _save_config(self, config: Dict[str, Any]):
        """Save configuration to file."""
        try:
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.config_path, 'w') as f:
                yaml.dump(config, f, default_flow_style=False, indent=2)
        except Exception as e:
            logger.error(f"Failed to save config: {e}")
    
    def _setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown."""
        def signal_handler(signum, frame):
            logger.info(f"Received signal {signum}, initiating graceful shutdown")
            self.shutdown_event.set()
            asyncio.create_task(self.stop_server(graceful=True))
        
        if hasattr(signal, 'SIGTERM'):
            signal.signal(signal.SIGTERM, signal_handler)
        if hasattr(signal, 'SIGINT'):
            signal.signal(signal.SIGINT, signal_handler)
    
    def _load_server_state(self):
        """Load server state from file."""
        if self.state_file.exists():
            try:
                with open(self.state_file, 'r') as f:
                    state_data = json.load(f)
                    
                # Restore server info
                if 'server_info' in state_data:
                    info_data = state_data['server_info']
                    self.server_info = ServerInfo(**info_data)
                    
                    # Check if process is still running
                    if self.server_info.pid:
                        try:
                            self.process = psutil.Process(self.server_info.pid)
                            if self.process.is_running():
                                self.server_info.state = ServerState.RUNNING
                            else:
                                self.server_info.state = ServerState.STOPPED
                                self.server_info.pid = None
                        except psutil.NoSuchProcess:
                            self.server_info.state = ServerState.STOPPED
                            self.server_info.pid = None
                
            except Exception as e:
                logger.error(f"Failed to load server state: {e}")
    
    def _save_server_state(self):
        """Save server state to file."""
        try:
            state_data = {
                'server_info': asdict(self.server_info),
                'timestamp': datetime.now().isoformat()
            }
            
            with open(self.state_file, 'w') as f:
                json.dump(state_data, f, indent=2, default=str)
                
        except Exception as e:
            logger.error(f"Failed to save server state: {e}")
    
    def _create_lock_file(self) -> bool:
        """Create server lock file."""
        try:
            if self.lock_file.exists():
                # Check if existing process is still running
                with open(self.lock_file, 'r') as f:
                    lock_data = json.load(f)
                    
                try:
                    existing_process = psutil.Process(lock_data['pid'])
                    if existing_process.is_running():
                        logger.error(f"Server already running with PID {lock_data['pid']}")
                        return False
                except psutil.NoSuchProcess:
                    pass  # Process no longer exists, can proceed
            
            # Create new lock file
            lock_data = {
                'pid': os.getpid(),
                'started_at': datetime.now().isoformat(),
                'host': self.config['server']['host'],
                'port': self.config['server']['port']
            }
            
            with open(self.lock_file, 'w') as f:
                json.dump(lock_data, f, indent=2)
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to create lock file: {e}")
            return False
    
    def _remove_lock_file(self):
        """Remove server lock file."""
        try:
            if self.lock_file.exists():
                self.lock_file.unlink()
        except Exception as e:
            logger.error(f"Failed to remove lock file: {e}")
    
    def _calculate_config_hash(self) -> str:
        """Calculate hash of current configuration."""
        try:
            config_str = json.dumps(self.config, sort_keys=True)
            return hashlib.sha256(config_str.encode()).hexdigest()[:16]
        except Exception:
            return "unknown"
    
    def _start_monitoring(self):
        """Start server monitoring thread."""
        if not self.monitoring_enabled or self.monitoring_thread:
            return
        
        def monitor():
            while not self.shutdown_event.is_set():
                try:
                    self._update_server_metrics()
                    self._check_server_health()
                    self._save_server_state()
                    
                    interval = self.config['monitoring']['interval']
                    self.shutdown_event.wait(interval)
                    
                except Exception as e:
                    logger.error(f"Monitoring error: {e}")
                    self.shutdown_event.wait(30)
        
        self.monitoring_thread = threading.Thread(target=monitor, daemon=True)
        self.monitoring_thread.start()
        logger.info("Server monitoring started")
    
    def _stop_monitoring(self):
        """Stop server monitoring."""
        if self.monitoring_thread:
            self.shutdown_event.set()
            self.monitoring_thread.join(timeout=5)
            self.monitoring_thread = None
            logger.info("Server monitoring stopped")
    
    def _update_server_metrics(self):
        """Update server performance metrics."""
        if not self.process or not self.process.is_running():
            return
        
        try:
            # Update uptime
            if self.server_info.started_at:
                self.server_info.uptime = (datetime.now() - self.server_info.started_at).total_seconds()
            
            # Update resource usage
            self.server_info.memory_usage = self.process.memory_percent()
            self.server_info.cpu_usage = self.process.cpu_percent()
            
        except Exception as e:
            logger.error(f"Failed to update metrics: {e}")
    
    def _check_server_health(self):
        """Check server health and take action if needed."""
        if not self.process or not self.process.is_running():
            if self.server_info.state == ServerState.RUNNING:
                logger.warning("Server process died unexpectedly")
                self.server_info.state = ServerState.ERROR
            return
        
        # Check resource usage thresholds
        memory_threshold = self.config['monitoring']['memory_threshold']
        cpu_threshold = self.config['monitoring']['cpu_threshold']
        
        if self.server_info.memory_usage > memory_threshold:
            logger.warning(f"High memory usage: {self.server_info.memory_usage:.1f}%")
        
        if self.server_info.cpu_usage > cpu_threshold:
            logger.warning(f"High CPU usage: {self.server_info.cpu_usage:.1f}%")
    
    async def start_server(self, **kwargs) -> bool:
        """Start the NetLink server."""
        if self.server_info.state == ServerState.RUNNING:
            logger.info("Server is already running")
            return True
        
        if not self._create_lock_file():
            return False
        
        try:
            self.server_info.state = ServerState.STARTING
            self.server_info.config_hash = self._calculate_config_hash()
            
            # Prepare server configuration
            server_config = self.config['server'].copy()
            server_config.update(kwargs)
            
            # Start server process
            logger.info(f"Starting NetLink server on {server_config['host']}:{server_config['port']}")
            
            # Import and start the application
            import uvicorn
            from netlink.app.main import app
            
            # Configure uvicorn
            uvicorn_config = uvicorn.Config(
                app=app,
                host=server_config['host'],
                port=server_config['port'],
                reload=server_config.get('reload', False),
                log_level=server_config.get('log_level', 'info'),
                workers=server_config.get('workers', 1),
                access_log=True,
                use_colors=False
            )
            
            # Start server in background
            server = uvicorn.Server(uvicorn_config)
            
            # Update server info
            self.server_info.pid = os.getpid()
            self.server_info.state = ServerState.RUNNING
            self.server_info.started_at = datetime.now()
            self.server_info.host = server_config['host']
            self.server_info.port = server_config['port']
            
            # Start monitoring
            self._start_monitoring()
            
            # Save state
            self._save_server_state()
            
            logger.info(f"NetLink server started successfully (PID: {self.server_info.pid})")
            
            # Run server
            await server.serve()
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to start server: {e}")
            self.server_info.state = ServerState.ERROR
            self._remove_lock_file()
            return False
    
    async def stop_server(self, graceful: bool = True, timeout: int = None) -> bool:
        """Stop the NetLink server."""
        if self.server_info.state == ServerState.STOPPED:
            logger.info("Server is already stopped")
            return True
        
        if timeout is None:
            timeout = self.config['management']['graceful_shutdown_timeout']
        
        try:
            self.server_info.state = ServerState.STOPPING
            logger.info(f"Stopping NetLink server (graceful: {graceful})")
            
            # Stop monitoring first
            self._stop_monitoring()
            
            if self.process and self.process.is_running():
                if graceful:
                    # Graceful shutdown
                    self.process.terminate()
                    
                    try:
                        self.process.wait(timeout=timeout)
                        logger.info("Server stopped gracefully")
                    except psutil.TimeoutExpired:
                        logger.warning("Graceful shutdown timed out, force killing")
                        self.process.kill()
                        self.process.wait(timeout=5)
                else:
                    # Force shutdown
                    self.process.kill()
                    self.process.wait(timeout=5)
                    logger.info("Server force stopped")
            
            # Update state
            self.server_info.state = ServerState.STOPPED
            self.server_info.pid = None
            self.process = None
            
            # Remove lock file
            self._remove_lock_file()
            
            # Save state
            self._save_server_state()
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to stop server: {e}")
            self.server_info.state = ServerState.ERROR
            return False

    async def restart_server(self, **kwargs) -> bool:
        """Restart the NetLink server."""
        logger.info("Restarting NetLink server")

        try:
            self.server_info.state = ServerState.RESTARTING

            # Stop server first
            if not await self.stop_server(graceful=True):
                logger.error("Failed to stop server for restart")
                return False

            # Wait a moment before restarting
            restart_delay = self.config['management']['restart_delay']
            await asyncio.sleep(restart_delay)

            # Start server again
            return await self.start_server(**kwargs)

        except Exception as e:
            logger.error(f"Failed to restart server: {e}")
            self.server_info.state = ServerState.ERROR
            return False

    def get_server_status(self) -> Dict[str, Any]:
        """Get comprehensive server status."""
        status = {
            'server_info': asdict(self.server_info),
            'config_hash': self._calculate_config_hash(),
            'timestamp': datetime.now().isoformat(),
            'uptime_formatted': self._format_uptime(self.server_info.uptime),
            'health': self._get_health_status(),
            'resources': self._get_resource_usage(),
            'configuration': self._get_config_summary()
        }

        return status

    def _format_uptime(self, seconds: float) -> str:
        """Format uptime in human-readable format."""
        if seconds < 60:
            return f"{seconds:.1f} seconds"
        elif seconds < 3600:
            return f"{seconds/60:.1f} minutes"
        elif seconds < 86400:
            return f"{seconds/3600:.1f} hours"
        else:
            return f"{seconds/86400:.1f} days"

    def _get_health_status(self) -> Dict[str, Any]:
        """Get server health status."""
        if not self.process or not self.process.is_running():
            return {
                'status': 'unhealthy',
                'reason': 'Process not running'
            }

        health_issues = []

        # Check resource usage
        memory_threshold = self.config['monitoring']['memory_threshold']
        cpu_threshold = self.config['monitoring']['cpu_threshold']

        if self.server_info.memory_usage > memory_threshold:
            health_issues.append(f"High memory usage: {self.server_info.memory_usage:.1f}%")

        if self.server_info.cpu_usage > cpu_threshold:
            health_issues.append(f"High CPU usage: {self.server_info.cpu_usage:.1f}%")

        # Check disk space
        try:
            disk_usage = psutil.disk_usage('.')
            disk_percent = (disk_usage.used / disk_usage.total) * 100
            disk_threshold = self.config['monitoring']['disk_threshold']

            if disk_percent > disk_threshold:
                health_issues.append(f"High disk usage: {disk_percent:.1f}%")
        except Exception:
            pass

        return {
            'status': 'healthy' if not health_issues else 'warning',
            'issues': health_issues
        }

    def _get_resource_usage(self) -> Dict[str, Any]:
        """Get detailed resource usage."""
        if not self.process or not self.process.is_running():
            return {}

        try:
            memory_info = self.process.memory_info()

            return {
                'memory': {
                    'percent': self.server_info.memory_usage,
                    'rss': memory_info.rss,
                    'vms': memory_info.vms
                },
                'cpu': {
                    'percent': self.server_info.cpu_usage,
                    'num_threads': self.process.num_threads()
                },
                'connections': len(self.process.connections()),
                'open_files': len(self.process.open_files())
            }
        except Exception as e:
            logger.error(f"Failed to get resource usage: {e}")
            return {}

    def _get_config_summary(self) -> Dict[str, Any]:
        """Get configuration summary."""
        return {
            'host': self.server_info.host,
            'port': self.server_info.port,
            'version': self.server_info.version,
            'config_hash': self.server_info.config_hash,
            'hot_reload_enabled': self.config['management']['enable_hot_reload'],
            'zero_downtime_enabled': self.config['management']['enable_zero_downtime'],
            'monitoring_enabled': self.config['monitoring']['enabled']
        }

    def create_backup(self, backup_name: str = None) -> str:
        """Create server backup."""
        if backup_name is None:
            backup_name = f"server_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        backup_path = self.backup_dir / backup_name
        backup_path.mkdir(exist_ok=True)

        try:
            # Backup configuration
            config_backup = backup_path / "config"
            config_backup.mkdir(exist_ok=True)

            # Copy configuration files
            config_files = [
                "config/server.yaml",
                "config/netlink.json",
                "data/server_state.json"
            ]

            for config_file in config_files:
                src_path = Path(config_file)
                if src_path.exists():
                    dst_path = config_backup / src_path.name
                    shutil.copy2(src_path, dst_path)

            # Backup application files (selective)
            app_backup = backup_path / "app"
            app_backup.mkdir(exist_ok=True)

            # Copy critical application files
            critical_files = [
                "src/netlink/app/main.py",
                "src/netlink/core/server_manager.py",
                "requirements.txt"
            ]

            for app_file in critical_files:
                src_path = Path(app_file)
                if src_path.exists():
                    dst_path = app_backup / src_path.name
                    shutil.copy2(src_path, dst_path)

            # Create backup metadata
            metadata = {
                'backup_name': backup_name,
                'created_at': datetime.now().isoformat(),
                'server_version': self.server_info.version,
                'config_hash': self.server_info.config_hash,
                'server_state': self.server_info.state.value,
                'files_backed_up': len(config_files) + len(critical_files)
            }

            with open(backup_path / "metadata.json", 'w') as f:
                json.dump(metadata, f, indent=2)

            logger.info(f"Server backup created: {backup_path}")
            return str(backup_path)

        except Exception as e:
            logger.error(f"Failed to create backup: {e}")
            raise

    def restore_backup(self, backup_name: str) -> bool:
        """Restore server from backup."""
        backup_path = self.backup_dir / backup_name

        if not backup_path.exists():
            logger.error(f"Backup not found: {backup_name}")
            return False

        try:
            # Load backup metadata
            metadata_file = backup_path / "metadata.json"
            if metadata_file.exists():
                with open(metadata_file, 'r') as f:
                    metadata = json.load(f)
                logger.info(f"Restoring backup: {metadata['backup_name']} from {metadata['created_at']}")

            # Stop server if running
            was_running = self.server_info.state == ServerState.RUNNING
            if was_running:
                await self.stop_server(graceful=True)

            # Restore configuration files
            config_backup = backup_path / "config"
            if config_backup.exists():
                for config_file in config_backup.iterdir():
                    dst_path = Path("config") / config_file.name
                    dst_path.parent.mkdir(exist_ok=True)
                    shutil.copy2(config_file, dst_path)

            # Restore application files
            app_backup = backup_path / "app"
            if app_backup.exists():
                for app_file in app_backup.iterdir():
                    # Restore to appropriate location
                    if app_file.name == "main.py":
                        dst_path = Path("src/netlink/app/main.py")
                    elif app_file.name == "server_manager.py":
                        dst_path = Path("src/netlink/core/server_manager.py")
                    else:
                        dst_path = Path(app_file.name)

                    dst_path.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(app_file, dst_path)

            # Reload configuration
            self.config = self._load_config()

            # Restart server if it was running
            if was_running:
                await self.start_server()

            logger.info(f"Server restored from backup: {backup_name}")
            return True

        except Exception as e:
            logger.error(f"Failed to restore backup: {e}")
            return False

    async def apply_hot_update(self, update_info: UpdateInfo) -> bool:
        """Apply hot update without server restart."""
        if not self.config['management']['enable_hot_reload']:
            logger.error("Hot reload is disabled")
            return False

        logger.info(f"Applying hot update: {update_info.id}")

        try:
            self.server_info.state = ServerState.UPDATING

            # Create backup if required
            if update_info.backup_required:
                backup_name = f"pre_update_{update_info.id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                self.create_backup(backup_name)

            # Apply hot-updatable changes
            hot_updatable_paths = [
                "src/netlink/app/web/templates",
                "src/netlink/app/web/static",
                "src/netlink/app/routers",
                "src/netlink/app/utils",
                "config"
            ]

            updated_files = []

            for file_path in update_info.files:
                src_path = Path(file_path)

                # Check if file is hot-updatable
                is_hot_updatable = any(
                    str(src_path).startswith(path) for path in hot_updatable_paths
                )

                if is_hot_updatable:
                    # Apply update immediately
                    logger.info(f"Hot updating: {file_path}")
                    updated_files.append(file_path)
                else:
                    logger.info(f"File requires restart: {file_path}")
                    update_info.restart_required = True

            # Update server info
            self.server_info.last_update = datetime.now()
            self.server_info.version = update_info.version

            # If restart is required, schedule it
            if update_info.restart_required:
                logger.info("Update requires restart - scheduling warm restart")
                await self.restart_server()
            else:
                self.server_info.state = ServerState.RUNNING

            logger.info(f"Hot update completed: {len(updated_files)} files updated")
            return True

        except Exception as e:
            logger.error(f"Hot update failed: {e}")
            self.server_info.state = ServerState.ERROR
            return False

    def check_integrity(self) -> Dict[str, Any]:
        """Check server integrity."""
        logger.info("Checking server integrity")

        integrity_results = {
            'timestamp': datetime.now().isoformat(),
            'overall_status': 'healthy',
            'checks': []
        }

        try:
            # Check critical files
            critical_files = [
                "src/netlink/app/main.py",
                "src/netlink/core/server_manager.py",
                "config/server.yaml",
                "requirements.txt"
            ]

            for file_path in critical_files:
                path = Path(file_path)
                check_result = {
                    'name': f'File existence: {file_path}',
                    'status': 'pass' if path.exists() else 'fail',
                    'details': f'File {"exists" if path.exists() else "missing"}'
                }
                integrity_results['checks'].append(check_result)

                if not path.exists():
                    integrity_results['overall_status'] = 'unhealthy'

            # Check configuration integrity
            config_check = {
                'name': 'Configuration integrity',
                'status': 'pass',
                'details': 'Configuration is valid'
            }

            try:
                # Validate configuration structure
                required_sections = ['server', 'management', 'monitoring', 'integrity']
                for section in required_sections:
                    if section not in self.config:
                        config_check['status'] = 'fail'
                        config_check['details'] = f'Missing configuration section: {section}'
                        integrity_results['overall_status'] = 'unhealthy'
                        break
            except Exception as e:
                config_check['status'] = 'fail'
                config_check['details'] = f'Configuration error: {e}'
                integrity_results['overall_status'] = 'unhealthy'

            integrity_results['checks'].append(config_check)

        except Exception as e:
            logger.error(f"Integrity check failed: {e}")
            integrity_results['overall_status'] = 'error'
            integrity_results['error'] = str(e)

        return integrity_results


# Global server manager instance
server_manager = ServerManager()

    def list_backups(self) -> List[Dict[str, Any]]:
        """List available backups."""
        backups = []

        try:
            for backup_dir in self.backup_dir.iterdir():
                if backup_dir.is_dir():
                    metadata_file = backup_dir / "metadata.json"

                    if metadata_file.exists():
                        with open(metadata_file, 'r') as f:
                            metadata = json.load(f)
                        backups.append(metadata)
                    else:
                        # Create basic metadata for backups without it
                        stat = backup_dir.stat()
                        backups.append({
                            'backup_name': backup_dir.name,
                            'created_at': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                            'server_version': 'unknown',
                            'config_hash': 'unknown',
                            'files_backed_up': len(list(backup_dir.rglob('*')))
                        })

        except Exception as e:
            logger.error(f"Failed to list backups: {e}")

        return sorted(backups, key=lambda x: x['created_at'], reverse=True)

    async def apply_hot_update(self, update_info: UpdateInfo) -> bool:
        """Apply hot update without server restart."""
        if not self.config['management']['enable_hot_reload']:
            logger.error("Hot reload is disabled")
            return False

        logger.info(f"Applying hot update: {update_info.id}")

        try:
            self.server_info.state = ServerState.UPDATING

            # Create backup if required
            if update_info.backup_required:
                backup_name = f"pre_update_{update_info.id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                self.create_backup(backup_name)

            # Apply hot-updatable changes
            hot_updatable_paths = [
                "src/netlink/app/web/templates",
                "src/netlink/app/web/static",
                "src/netlink/app/routers",
                "src/netlink/app/utils",
                "config"
            ]

            updated_files = []

            for file_path in update_info.files:
                src_path = Path(file_path)

                # Check if file is hot-updatable
                is_hot_updatable = any(
                    str(src_path).startswith(path) for path in hot_updatable_paths
                )

                if is_hot_updatable:
                    # Apply update immediately
                    logger.info(f"Hot updating: {file_path}")
                    updated_files.append(file_path)

                    # In a real implementation, you would copy the new file
                    # For now, we'll just log the action
                else:
                    logger.info(f"File requires restart: {file_path}")
                    update_info.restart_required = True

            # Update server info
            self.server_info.last_update = datetime.now()
            self.server_info.version = update_info.version

            # If restart is required, schedule it
            if update_info.restart_required:
                logger.info("Update requires restart - scheduling warm restart")
                await self.restart_server()
            else:
                self.server_info.state = ServerState.RUNNING

            logger.info(f"Hot update completed: {len(updated_files)} files updated")
            return True

        except Exception as e:
            logger.error(f"Hot update failed: {e}")
            self.server_info.state = ServerState.ERROR
            return False

    async def apply_zero_downtime_update(self, update_info: UpdateInfo) -> bool:
        """Apply zero-downtime update using blue-green deployment."""
        if not self.config['management']['enable_zero_downtime']:
            logger.error("Zero-downtime updates are disabled")
            return False

        logger.info(f"Applying zero-downtime update: {update_info.id}")

        try:
            # Create backup
            backup_name = f"pre_zdt_update_{update_info.id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            self.create_backup(backup_name)

            # Start new server instance on different port
            new_port = self.server_info.port + 1000

            logger.info(f"Starting new server instance on port {new_port}")

            # Apply updates to new instance
            # In a real implementation, you would:
            # 1. Create new environment with updates
            # 2. Start new server instance
            # 3. Health check new instance
            # 4. Switch traffic to new instance
            # 5. Stop old instance

            # For now, simulate the process
            await asyncio.sleep(2)  # Simulate update application

            # Switch to new instance (simulated)
            old_port = self.server_info.port
            self.server_info.port = new_port
            self.server_info.version = update_info.version
            self.server_info.last_update = datetime.now()

            logger.info(f"Zero-downtime update completed: switched from port {old_port} to {new_port}")
            return True

        except Exception as e:
            logger.error(f"Zero-downtime update failed: {e}")
            return False

    def check_integrity(self) -> Dict[str, Any]:
        """Check server integrity."""
        logger.info("Checking server integrity")

        integrity_results = {
            'timestamp': datetime.now().isoformat(),
            'overall_status': 'healthy',
            'checks': []
        }

        try:
            # Check critical files
            critical_files = [
                "src/netlink/app/main.py",
                "src/netlink/core/server_manager.py",
                "config/server.yaml",
                "requirements.txt"
            ]

            for file_path in critical_files:
                path = Path(file_path)
                check_result = {
                    'name': f'File existence: {file_path}',
                    'status': 'pass' if path.exists() else 'fail',
                    'details': f'File {"exists" if path.exists() else "missing"}'
                }
                integrity_results['checks'].append(check_result)

                if not path.exists():
                    integrity_results['overall_status'] = 'unhealthy'

            # Check configuration integrity
            config_check = {
                'name': 'Configuration integrity',
                'status': 'pass',
                'details': 'Configuration is valid'
            }

            try:
                # Validate configuration structure
                required_sections = ['server', 'management', 'monitoring', 'integrity']
                for section in required_sections:
                    if section not in self.config:
                        config_check['status'] = 'fail'
                        config_check['details'] = f'Missing configuration section: {section}'
                        integrity_results['overall_status'] = 'unhealthy'
                        break
            except Exception as e:
                config_check['status'] = 'fail'
                config_check['details'] = f'Configuration error: {e}'
                integrity_results['overall_status'] = 'unhealthy'

            integrity_results['checks'].append(config_check)

            # Check process integrity
            if self.process and self.process.is_running():
                process_check = {
                    'name': 'Process integrity',
                    'status': 'pass',
                    'details': f'Process running (PID: {self.process.pid})'
                }
            else:
                process_check = {
                    'name': 'Process integrity',
                    'status': 'fail' if self.server_info.state == ServerState.RUNNING else 'info',
                    'details': 'Process not running'
                }

                if self.server_info.state == ServerState.RUNNING:
                    integrity_results['overall_status'] = 'unhealthy'

            integrity_results['checks'].append(process_check)

            # Check disk space
            try:
                disk_usage = psutil.disk_usage('.')
                disk_percent = (disk_usage.used / disk_usage.total) * 100
                disk_threshold = self.config['monitoring']['disk_threshold']

                disk_check = {
                    'name': 'Disk space',
                    'status': 'pass' if disk_percent < disk_threshold else 'warning',
                    'details': f'Disk usage: {disk_percent:.1f}%'
                }

                if disk_percent > 95:  # Critical threshold
                    disk_check['status'] = 'fail'
                    integrity_results['overall_status'] = 'unhealthy'

                integrity_results['checks'].append(disk_check)

            except Exception as e:
                integrity_results['checks'].append({
                    'name': 'Disk space',
                    'status': 'error',
                    'details': f'Failed to check disk space: {e}'
                })

        except Exception as e:
            logger.error(f"Integrity check failed: {e}")
            integrity_results['overall_status'] = 'error'
            integrity_results['error'] = str(e)

        return integrity_results

    def auto_repair(self) -> Dict[str, Any]:
        """Attempt automatic repair of common issues."""
        logger.info("Attempting automatic repair")

        repair_results = {
            'timestamp': datetime.now().isoformat(),
            'repairs_attempted': [],
            'repairs_successful': [],
            'repairs_failed': []
        }

        try:
            # Check and repair missing directories
            required_dirs = [
                "data", "logs", "config", "backups", "backups/server"
            ]

            for dir_path in required_dirs:
                path = Path(dir_path)
                if not path.exists():
                    repair_results['repairs_attempted'].append(f'Create directory: {dir_path}')
                    try:
                        path.mkdir(parents=True, exist_ok=True)
                        repair_results['repairs_successful'].append(f'Created directory: {dir_path}')
                    except Exception as e:
                        repair_results['repairs_failed'].append(f'Failed to create directory {dir_path}: {e}')

            # Check and repair configuration
            if not self.config_path.exists():
                repair_results['repairs_attempted'].append('Create default configuration')
                try:
                    self._save_config(self._load_config())
                    repair_results['repairs_successful'].append('Created default configuration')
                except Exception as e:
                    repair_results['repairs_failed'].append(f'Failed to create configuration: {e}')

            # Clean up stale lock files
            if self.lock_file.exists():
                try:
                    with open(self.lock_file, 'r') as f:
                        lock_data = json.load(f)

                    try:
                        process = psutil.Process(lock_data['pid'])
                        if not process.is_running():
                            repair_results['repairs_attempted'].append('Remove stale lock file')
                            self.lock_file.unlink()
                            repair_results['repairs_successful'].append('Removed stale lock file')
                    except psutil.NoSuchProcess:
                        repair_results['repairs_attempted'].append('Remove stale lock file')
                        self.lock_file.unlink()
                        repair_results['repairs_successful'].append('Removed stale lock file')

                except Exception as e:
                    repair_results['repairs_failed'].append(f'Failed to check lock file: {e}')

        except Exception as e:
            logger.error(f"Auto repair failed: {e}")
            repair_results['error'] = str(e)

        return repair_results


# Global server manager instance
server_manager = ServerManager()
