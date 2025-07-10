"""
NetLink Instance Manager
Ensures only one instance of NetLink runs per device.
"""

import os
import sys
import time
import json
import socket
import psutil
import atexit
import signal
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any

class InstanceManager:
    """Manages single instance enforcement for NetLink."""
    
    def __init__(self, app_name: str = "netlink"):
        self.app_name = app_name
        self.lock_file = Path(f"{app_name}.lock")
        self.pid_file = Path(f"{app_name}.pid")
        self.socket_file = Path(f"{app_name}.sock")
        self.port_file = Path(f"{app_name}.port")
        self.current_pid = os.getpid()
        self.lock_socket = None
        self.is_primary = False
        
    def acquire_lock(self) -> bool:
        """Acquire exclusive lock for this instance."""
        try:
            # Check if lock file exists and process is still running
            if self.lock_file.exists():
                existing_instance = self.get_existing_instance()
                if existing_instance and self.is_process_running(existing_instance["pid"]):
                    return False
                else:
                    # Clean up stale lock
                    self.cleanup_stale_files()
            
            # Create lock file with instance info
            instance_info = {
                "pid": self.current_pid,
                "started_at": datetime.now().isoformat(),
                "port": self.get_server_port(),
                "host": self.get_server_host(),
                "version": self.get_app_version()
            }
            
            with open(self.lock_file, 'w') as f:
                json.dump(instance_info, f, indent=2)
            
            # Create PID file
            with open(self.pid_file, 'w') as f:
                f.write(str(self.current_pid))
            
            # Register cleanup on exit
            atexit.register(self.cleanup)
            signal.signal(signal.SIGTERM, self._signal_handler)
            signal.signal(signal.SIGINT, self._signal_handler)
            
            self.is_primary = True
            return True
            
        except Exception as e:
            print(f"Failed to acquire lock: {e}")
            return False
    
    def get_existing_instance(self) -> Optional[Dict[str, Any]]:
        """Get information about existing instance."""
        try:
            if not self.lock_file.exists():
                return None
            
            with open(self.lock_file, 'r') as f:
                return json.load(f)
        except Exception:
            return None
    
    def is_process_running(self, pid: int) -> bool:
        """Check if a process is still running."""
        try:
            return psutil.pid_exists(pid)
        except Exception:
            # Fallback method
            try:
                os.kill(pid, 0)
                return True
            except OSError:
                return False
    
    def get_server_port(self) -> int:
        """Get server port from configuration."""
        try:
            from app.logger_config import settings
            return getattr(settings, 'PORT', 8000)
        except ImportError:
            return int(os.getenv('PORT', 8000))
    
    def get_server_host(self) -> str:
        """Get server host from configuration."""
        try:
            from app.logger_config import settings
            return getattr(settings, 'HOST', '0.0.0.0')
        except ImportError:
            return os.getenv('HOST', '0.0.0.0')
    
    def get_app_version(self) -> str:
        """Get application version."""
        try:
            from app.logger_config import settings
            return getattr(settings, 'APP_VERSION', '1.0.0')
        except ImportError:
            return '1.0.0'
    
    def cleanup_stale_files(self):
        """Clean up stale lock files."""
        try:
            self.lock_file.unlink(missing_ok=True)
            self.pid_file.unlink(missing_ok=True)
            self.socket_file.unlink(missing_ok=True)
            self.port_file.unlink(missing_ok=True)
        except Exception:
            pass
    
    def cleanup(self):
        """Clean up instance files."""
        if self.is_primary:
            try:
                self.lock_file.unlink(missing_ok=True)
                self.pid_file.unlink(missing_ok=True)
                self.socket_file.unlink(missing_ok=True)
                self.port_file.unlink(missing_ok=True)
                
                if self.lock_socket:
                    self.lock_socket.close()
            except Exception:
                pass
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        self.cleanup()
        sys.exit(0)
    
    def check_port_available(self, port: int, host: str = "localhost") -> bool:
        """Check if port is available."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                result = sock.connect_ex((host, port))
                return result != 0  # Port is available if connection fails
        except Exception:
            return False
    
    def find_available_port(self, start_port: int = 8000, max_attempts: int = 100) -> int:
        """Find an available port starting from start_port."""
        for port in range(start_port, start_port + max_attempts):
            if self.check_port_available(port):
                return port
        
        raise RuntimeError(f"No available ports found in range {start_port}-{start_port + max_attempts}")
    
    def get_instance_status(self) -> Dict[str, Any]:
        """Get current instance status."""
        existing = self.get_existing_instance()
        
        if not existing:
            return {
                "running": False,
                "message": "No instance running"
            }
        
        pid = existing["pid"]
        is_running = self.is_process_running(pid)
        
        if not is_running:
            return {
                "running": False,
                "message": "Instance not running (stale lock file)",
                "stale_info": existing
            }
        
        # Check if server is responding
        port = existing.get("port", 8000)
        host = existing.get("host", "localhost")
        server_responding = not self.check_port_available(port, "localhost")
        
        return {
            "running": True,
            "pid": pid,
            "port": port,
            "host": host,
            "version": existing.get("version", "unknown"),
            "started_at": existing.get("started_at"),
            "server_responding": server_responding,
            "is_current_process": pid == self.current_pid
        }
    
    def terminate_existing_instance(self, force: bool = False) -> bool:
        """Terminate existing instance."""
        existing = self.get_existing_instance()
        
        if not existing:
            return True  # No instance to terminate
        
        pid = existing["pid"]
        
        if not self.is_process_running(pid):
            # Clean up stale files
            self.cleanup_stale_files()
            return True
        
        try:
            process = psutil.Process(pid)
            
            if not force:
                # Try graceful termination first
                process.terminate()
                
                # Wait for process to terminate
                try:
                    process.wait(timeout=10)
                    self.cleanup_stale_files()
                    return True
                except psutil.TimeoutExpired:
                    if not force:
                        return False  # Graceful termination failed
            
            # Force kill if graceful termination failed or force=True
            process.kill()
            process.wait(timeout=5)
            self.cleanup_stale_files()
            return True
            
        except psutil.NoSuchProcess:
            # Process already terminated
            self.cleanup_stale_files()
            return True
        except Exception as e:
            print(f"Failed to terminate existing instance: {e}")
            return False
    
    def ensure_single_instance(self, force_terminate: bool = False) -> bool:
        """Ensure only one instance is running."""
        # Check current status
        status = self.get_instance_status()
        
        if not status["running"]:
            # No instance running, we can proceed
            return self.acquire_lock()
        
        if status.get("is_current_process", False):
            # Current process already has the lock
            return True
        
        # Another instance is running
        if force_terminate:
            print(f"Terminating existing instance (PID: {status['pid']})...")
            if self.terminate_existing_instance(force=True):
                return self.acquire_lock()
            else:
                print("Failed to terminate existing instance")
                return False
        else:
            print(f"Another NetLink instance is already running (PID: {status['pid']})")
            print(f"Server: http://{status.get('host', 'localhost')}:{status.get('port', 8000)}")
            print("Use --force to terminate the existing instance")
            return False
    
    def create_ipc_socket(self) -> bool:
        """Create IPC socket for communication between instances."""
        try:
            if os.name == 'nt':  # Windows
                # Use named pipe on Windows
                import win32pipe
                import win32file
                
                pipe_name = f"\\\\.\\pipe\\{self.app_name}_ipc"
                self.lock_socket = win32pipe.CreateNamedPipe(
                    pipe_name,
                    win32pipe.PIPE_ACCESS_DUPLEX,
                    win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_WAIT,
                    1, 65536, 65536, 300, None
                )
                return True
            else:
                # Use Unix socket on Unix-like systems
                self.lock_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                
                # Remove existing socket file
                self.socket_file.unlink(missing_ok=True)
                
                self.lock_socket.bind(str(self.socket_file))
                self.lock_socket.listen(1)
                return True
                
        except Exception as e:
            print(f"Failed to create IPC socket: {e}")
            return False
    
    def send_command_to_instance(self, command: str) -> Optional[str]:
        """Send command to existing instance via IPC."""
        try:
            if os.name == 'nt':  # Windows
                import win32file
                
                pipe_name = f"\\\\.\\pipe\\{self.app_name}_ipc"
                handle = win32file.CreateFile(
                    pipe_name,
                    win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                    0, None,
                    win32file.OPEN_EXISTING,
                    0, None
                )
                
                win32file.WriteFile(handle, command.encode())
                result = win32file.ReadFile(handle, 4096)
                win32file.CloseHandle(handle)
                
                return result[1].decode()
            else:
                # Unix socket
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.connect(str(self.socket_file))
                sock.send(command.encode())
                response = sock.recv(4096).decode()
                sock.close()
                
                return response
                
        except Exception as e:
            print(f"Failed to send command to instance: {e}")
            return None

# Global instance manager
instance_manager = InstanceManager()
