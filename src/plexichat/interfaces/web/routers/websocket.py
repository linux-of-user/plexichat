import asyncio
import json
import logging
import queue
import shlex
import threading
from datetime import datetime
from typing import Any, Dict, List, Optional




                import platform

                
                

import jwt
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from fastapi.websockets import WebSocketState
            import psutil
                import psutil
                import psutil

from plexichat.features.users.user import User
from plexichat.infrastructure.utils.security import InputSanitizer
        from plexichat.features.users.user import User

"""
WebSocket endpoints for real-time communication.
Includes log streaming, CLI interface, and system monitoring.
"""

logger = logging.getLogger(__name__)
logging_manager = logging.getLogger(f"{__name__}.manager")
# settings import will be added when needed
router = APIRouter()

class ConnectionManager:
    """Manage WebSocket connections with authentication and channels."""
    
    def __init__(self):
        self.active_connections: Dict[str, List[WebSocket]] = {}
        self.user_connections: Dict[int, List[WebSocket]] = {}
        self.connection_info: Dict[WebSocket, Dict[str, Any]] = {}
        self.lock = threading.Lock()
    
    async def connect(self, websocket: WebSocket, channel: str, user: User):
        """Accept WebSocket connection and add to channel."""
        await websocket.accept()
        
        with self.lock:
            if channel not in self.active_connections:
                self.active_connections[channel] = []
            self.active_connections[channel].append(websocket)
            
            if user.id not in self.user_connections:
                self.user_connections[user.id] = []
            self.user_connections[user.id].append(websocket)
            
            self.connection_info[websocket] = {
                'user_id': user.id,
                'username': user.username,
                'channel': channel,
                'connected_at': from datetime import datetime
datetime.now(),
                'is_admin': user.is_admin
            }
        
        logger.info(f"WebSocket connected: user {user.username} to channel {channel}")
    
    def disconnect(self, websocket: WebSocket):
        """Remove WebSocket connection."""
        with self.lock:
            info = self.connection_info.get(websocket, {})
            channel = info.get('channel')
            user_id = info.get('user_id')
            
            if channel and websocket in self.active_connections.get(channel, []):
                self.active_connections[channel].remove(websocket)
                if not self.active_connections[channel]:
                    del self.active_connections[channel]
            
            if user_id and websocket in self.user_connections.get(user_id, []):
                self.user_connections[user_id].remove(websocket)
                if not self.user_connections[user_id]:
                    del self.user_connections[user_id]
            
            if websocket in self.connection_info:
                del self.connection_info[websocket]
        
        logger.info(f"WebSocket disconnected: {info.get('username', 'unknown')}")
    
    async def send_personal_message(self, message: str, websocket: WebSocket):
        """Send message to specific WebSocket."""
        try:
            if websocket.client_state == WebSocketState.CONNECTED:
                await websocket.send_text(message)
        except Exception as e:
            logger.error(f"Failed to send personal message: {e}")
    
    async def send_to_channel(self, message: str, channel: str):
        """Send message to all connections in a channel."""
        if channel not in self.active_connections:
            return
        
        disconnected = []
        for connection in self.active_connections[channel]:
            try:
                if connection.client_state == WebSocketState.CONNECTED:
                    await connection.send_text(message)
                else:
                    disconnected.append(connection)
            except Exception as e:
                logger.error(f"Failed to send to channel {channel}: {e}")
                disconnected.append(connection)
        
        # Clean up disconnected connections
        for conn in disconnected:
            self.disconnect(conn)
    
    async def send_to_user(self, message: str, user_id: int):
        """Send message to all connections of a specific user."""
        if user_id not in self.user_connections:
            return
        
        disconnected = []
        for connection in self.user_connections[user_id]:
            try:
                if connection.client_state == WebSocketState.CONNECTED:
                    await connection.send_text(message)
                else:
                    disconnected.append(connection)
            except Exception as e:
                logger.error(f"Failed to send to user {user_id}: {e}")
                disconnected.append(connection)
        
        # Clean up disconnected connections
        for conn in disconnected:
            self.disconnect(conn)
    
    def get_channel_stats(self) -> Dict[str, Any]:
        """Get statistics about active connections."""
        with self.lock:
            return {
                'total_connections': sum(len(conns) for conns in self.active_connections.values()),
                'channels': {
                    channel: len(connections) 
                    for channel, connections in self.active_connections.items()
                },
                'users_online': len(self.user_connections),
                'connection_details': [
                    {
                        'user': info['username'],
                        'channel': info['channel'],
                        'connected_at': info['connected_at'].isoformat(),
                        'is_admin': info['is_admin']
                    }
                    for info in self.connection_info.values()
                ]
            }

# Global connection manager
manager = ConnectionManager()

class CLIHandler:
    """Handle CLI commands via WebSocket."""
    
    def __init__(self):
        self.sanitizer = InputSanitizer()
        self.allowed_commands = {
            'help', 'status', 'logs', 'users', 'files', 'system', 'config',
            'selftest', 'restart', 'clear', 'history', 'version'
        }
    
    async def execute_command(self, command: str, user: User, websocket: WebSocket) -> Dict[str, Any]:
        """Execute CLI command and return result."""
        try:
            # Sanitize and parse command
            command = self.sanitizer.sanitize_input(command.strip())
            if not command:
                return {'error': 'Empty command'}
            
            parts = shlex.split(command)
            cmd = parts[0].lower()
            args = parts[1:] if len(parts) > 1 else []
            
            # Check if command is allowed
            if cmd not in self.allowed_commands:
                return {'error': f'Command not allowed: {cmd}'}
            
            # Execute command
            if cmd == 'help':
                return await self._cmd_help()
            elif cmd == 'status':
                return await self._cmd_status()
            elif cmd == 'logs':
                return await self._cmd_logs(args, user)
            elif cmd == 'users':
                return await self._cmd_users(args, user)
            elif cmd == 'files':
                return await self._cmd_files(args, user)
            elif cmd == 'system':
                return await self._cmd_system(args, user)
            elif cmd == 'config':
                return await self._cmd_config(user)
            elif cmd == 'selftest':
                return await self._cmd_selftest(args, user)
            elif cmd == 'restart':
                return await self._cmd_restart(user)
            elif cmd == 'clear':
                return {'action': 'clear'}
            elif cmd == 'version':
                return await self._cmd_version()
            else:
                return {'error': f'Command not implemented: {cmd}'}
                
        except Exception as e:
            logger.error(f"CLI command execution error: {e}")
            return {'error': f'Command execution failed: {str(e)}'}
    
    async def _cmd_help(self) -> Dict[str, Any]:
        """Show help information."""
        help_text = """
Available Commands:
  help                 - Show this help message
  status               - Show system status
  logs [level] [count] - Show recent logs
  users [action]       - User management
  files [action]       - File management
  system [info]        - System information
  config               - Show configuration
  selftest [type]      - Run self-tests
  restart              - Restart system (admin only)
  clear                - Clear terminal
  version              - Show version information

Examples:
  logs error 10        - Show last 10 error logs
  users list           - List all users
  system info          - Show system information
  selftest all         - Run all self-tests
        """
        return {'output': help_text.strip()}
    
    async def _cmd_status(self) -> Dict[str, Any]:
        """Show system status."""
        try:
            # Get basic system info
            cpu_percent = import psutil
psutil.cpu_percent(interval=0.1)
            memory = import psutil
psutil.virtual_memory()
            disk = import psutil
psutil.disk_usage('/')
            
            status_info = f"""
System Status:
  CPU Usage: {cpu_percent:.1f}%
  Memory Usage: {memory.percent:.1f}% ({memory.used // (1024**3):.1f}GB / {memory.total // (1024**3):.1f}GB)
  Disk Usage: {(disk.used / disk.total) * 100:.1f}% ({disk.used // (1024**3):.1f}GB / {disk.total // (1024**3):.1f}GB)
  
Application:
  Version: {from plexichat.core.config import settings
settings.API_VERSION}
  Debug Mode: {from plexichat.core.config import settings
settings.DEBUG}
  Log Level: {from plexichat.core.config import settings
settings.LOG_LEVEL}
  
WebSocket Connections: {manager.get_channel_stats()['total_connections']}
            """
            
            return {'output': status_info.strip()}
        except Exception as e:
            return {'error': f'Failed to get status: {e}'}
    
    async def _cmd_logs(self, args: List[str], user: User) -> Dict[str, Any]:
        """Show recent logs."""
        try:
            level_filter = args[0].upper() if args and args[0].upper() in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'] else None
            count = int(args[1]) if len(args) > 1 and args[1].isdigit() else 20
            count = min(count, 100)  # Limit to 100 logs
            
            if not logging_manager:
                return {'error': 'Logging system not available'}
            
            logs = logging_manager.get_recent_logs(count * 2)  # Get more to filter
            
            # Filter by level if specified
            if level_filter:
                logs = [log for log in logs if log.get('level') == level_filter]
            
            # Take only requested count
            logs = logs[-count:]
            
            if not logs:
                return {'output': 'No logs found'}
            
            log_output = []
            for log in logs:
                timestamp = log.get('timestamp', '')[:19]
                level = log.get('level', 'INFO')
                message = log.get('message', '')
                module = log.get('module', '')
                
                log_output.append(f"[{timestamp}] {level:<8} {module}: {message}")
            
            return {'output': '\n'.join(log_output)}
        except Exception as e:
            return {'error': f'Failed to get logs: {e}'}
    
    async def _cmd_users(self, args: List[str], user: User) -> Dict[str, Any]:
        """User management commands."""
        if not user.is_admin:
            return {'error': 'Admin privileges required'}
        
        action = args[0] if args else 'list'
        
        if action == 'list':
            # This would need database access - simplified for now
            return {'output': 'User list functionality would be implemented here'}
        else:
            return {'error': f'Unknown user action: {action}'}
    
    async def _cmd_files(self, args: List[str], user: User) -> Dict[str, Any]:
        """File management commands."""
        action = args[0] if args else 'stats'
        
        if action == 'stats':
            return {'output': 'File statistics would be shown here'}
        else:
            return {'error': f'Unknown file action: {action}'}
    
    async def _cmd_system(self, args: List[str], user: User) -> Dict[str, Any]:
        """System information commands."""
        if not user.is_admin:
            return {'error': 'Admin privileges required'}
        
        info_type = args[0] if args else 'info'
        
        if info_type == 'info':
            try:
                boot_time = datetime.fromtimestamp(import psutil
psutil.boot_time())
                uptime = from datetime import datetime
datetime.now() - boot_time
                
                system_info = f"""
System Information:
  Hostname: {platform.node()}
  Platform: {platform.system()} {platform.version()}
  Architecture: {platform.architecture()[0]}
  Python: {platform.python_version()}
  Uptime: {uptime.days}d {uptime.seconds//3600}h {(uptime.seconds//60)%60}m
                """
                return {'output': system_info.strip()}
            except Exception as e:
                return {'error': f'Failed to get system info: {e}'}
        else:
            return {'error': f'Unknown system command: {info_type}'}
    
    async def _cmd_config(self, user: User) -> Dict[str, Any]:
        """Show configuration."""
        if not user.is_admin:
            return {'error': 'Admin privileges required'}
        
        config_info = f"""
Configuration:
  API Version: {from plexichat.core.config import settings
settings.API_VERSION}
  Host: {from plexichat.core.config import settings
settings.HOST}:{from plexichat.core.config import settings
settings.PORT}
  Debug: {from plexichat.core.config import settings
settings.DEBUG}
  Log Level: {from plexichat.core.config import settings
settings.LOG_LEVEL}
  Database: {'Configured' if from plexichat.core.config import settings
settings.DATABASE_URL else 'Not configured'}
  SSL: {'Enabled' if from plexichat.core.config import settings
settings.SSL_CERTFILE else 'Disabled'}
        """
        return {'output': config_info.strip()}
    
    async def _cmd_selftest(self, args: List[str], user: User) -> Dict[str, Any]:
        """Run self-tests."""
        if not user.is_admin:
            return {'error': 'Admin privileges required'}
        
        test_type = args[0] if args else 'basic'
        return {'output': f'Self-test ({test_type}) would run here'}
    
    async def _cmd_restart(self, user: User) -> Dict[str, Any]:
        """Restart system."""
        if not user.is_admin:
            return {'error': 'Admin privileges required'}
        
        return {'output': 'System restart would be initiated here', 'warning': 'This would restart the server'}
    
    async def _cmd_version(self) -> Dict[str, Any]:
        """Show version information."""
        return {'output': f'Chat API Version {from plexichat.core.config import settings
settings.API_VERSION}'}

# Global CLI handler
cli_handler = CLIHandler()

async def authenticate_websocket(websocket: WebSocket, token: str) -> Optional[User]:
    """Authenticate WebSocket connection using JWT token."""
    try:
        payload = import jwt
jwt.decode(token, from plexichat.core.config import settings
settings.SECRET_KEY, algorithms=["HS256"])
        username = payload.get("sub")
        if not username:
            return None
        
        # In a real implementation, you'd get the user from database
        # For now, create a mock user
        user = User(id=1, username=username, is_admin=True)  # Mock user
        return user
        
    except jwt.JWTError:
        return None

@router.websocket("/logs")
async def websocket_logs(websocket: WebSocket, token: str):
    """WebSocket endpoint for real-time log streaming."""
    user = await authenticate_websocket(websocket, token)
    if not user:
        await websocket.close(code=1008, reason="Authentication failed")
        return
    
    await manager.connect(websocket, "logs", user)
    
    # Subscribe to log updates
    log_queue = queue.Queue(maxsize=100)
    if logging_manager:
        logging_manager.subscribe_to_logs(log_queue)
    
    try:
        # Send initial logs
        if logging_manager:
            recent_logs = logging_manager.get_recent_logs(50)
            for log in recent_logs:
                await manager.send_personal_message(json.dumps(log), websocket)
        
        # Stream new logs
        while True:
            try:
                if logging_manager:
                    log_entry = log_queue.get(timeout=1.0)
                    await manager.send_personal_message(json.dumps(log_entry), websocket)
                else:
                    await asyncio.sleep(1)
            except queue.Empty:
                # Send heartbeat
                await manager.send_personal_message(json.dumps({'type': 'heartbeat'}), websocket)
            except WebSocketDisconnect:
                break
                
    except WebSocketDisconnect:
        pass
    finally:
        if logging_manager:
            logging_manager.unsubscribe_from_logs(log_queue)
        manager.disconnect(websocket)

@router.websocket("/cli")
async def websocket_cli(websocket: WebSocket, token: str):
    """WebSocket endpoint for CLI interface."""
    user = await authenticate_websocket(websocket, token)
    if not user:
        await websocket.close(code=1008, reason="Authentication failed")
        return
    
    await manager.connect(websocket, "cli", user)
    
    try:
        # Send welcome message
        welcome = {
            'type': 'output',
            'data': f'Welcome to Chat API CLI, {user.username}!\nType "help" for available commands.'
        }
        await manager.send_personal_message(json.dumps(welcome), websocket)
        
        while True:
            # Receive command from client
            data = await websocket.receive_text()
            try:
                message = json.loads(data)
                if message.get('type') == 'command':
                    command = message.get('command', '')
                    
                    # Execute command
                    result = await cli_handler.execute_command(command, user, websocket)
                    
                    # Send result back
                    response = {
                        'type': 'result',
                        'command': command,
                        'data': result
                    }
                    await manager.send_personal_message(json.dumps(response), websocket)
                    
            except json.JSONDecodeError:
                error_response = {
                    'type': 'error',
                    'data': {'error': 'Invalid JSON message'}
                }
                await manager.send_personal_message(json.dumps(error_response), websocket)
                
    except WebSocketDisconnect:
        pass
    finally:
        manager.disconnect(websocket)

@router.websocket("/monitor")
async def websocket_monitor(websocket: WebSocket, token: str):
    """WebSocket endpoint for system monitoring."""
    user = await authenticate_websocket(websocket, token)
    if not user or not user.is_admin:
        await websocket.close(code=1008, reason="Admin access required")
        return
    
    await manager.connect(websocket, "monitor", user)
    
    try:
        while True:
            # Send system stats every 5 seconds
            try:
                stats = {
                    'type': 'system_stats',
                    'timestamp': from datetime import datetime
datetime.now().isoformat(),
                    'data': {
                        'cpu_percent': import psutil
psutil.cpu_percent(interval=0.1),
                        'memory_percent': import psutil
psutil.virtual_memory().percent,
                        'disk_percent': (import psutil
psutil.disk_usage('/').used / import psutil
psutil.disk_usage('/').total) * 100,
                        'connections': manager.get_channel_stats()['total_connections']
                    }
                }
                
                await manager.send_personal_message(json.dumps(stats), websocket)
                
            except Exception as e:
                logger.error(f"Monitor stats error: {e}")
            
            await asyncio.sleep(5)
            
    except WebSocketDisconnect:
        pass
    finally:
        manager.disconnect(websocket)

@router.get("/stats")
async def get_websocket_stats():
    """Get WebSocket connection statistics."""
    return manager.get_channel_stats()
