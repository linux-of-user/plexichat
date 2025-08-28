"""
Node Manager for PlexiChat Clustering System
Handles individual node lifecycle, health monitoring, and communication.
Provides secure node registration, heartbeat monitoring, and graceful shutdown procedures.
"""

import asyncio
import json
import logging
import secrets
import socket
import time
import uuid
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Callable, Union, Tuple
from pathlib import Path
import aiohttp
import psutil

from plexichat.src.plexichat.core.security.security_manager import (
    get_unified_security_system,
    SecurityContext,
    SecurityLevel,
    AuthenticationMethod
)

# Logging setup
logger = logging.getLogger(__name__)


class NodeType(Enum):
    """Types of cluster nodes."""
    NETWORKING = "networking"
    ENDPOINT = "endpoint"
    GENERAL = "general"
    STORAGE = "storage"
    COMPUTE = "compute"


class NodeStatus(Enum):
    """Node status states."""
    INITIALIZING = "initializing"
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    OFFLINE = "offline"
    SHUTTING_DOWN = "shutting_down"
    MAINTENANCE = "maintenance"


class NodeRole(Enum):
    """Node roles in the cluster."""
    LEADER = "leader"
    FOLLOWER = "follower"
    CANDIDATE = "candidate"
    OBSERVER = "observer"


@dataclass
class NodeCapabilities:
    """Node capabilities and features."""
    max_connections: int = 1000
    max_memory_mb: int = 4096
    max_cpu_cores: int = 4
    supports_storage: bool = True
    supports_compute: bool = True
    supports_networking: bool = True
    custom_capabilities: Dict[str, Any] = field(default_factory=dict)


@dataclass
class NodeMetrics:
    """Node performance and health metrics."""
    cpu_usage_percent: float = 0.0
    memory_usage_percent: float = 0.0
    disk_usage_percent: float = 0.0
    network_bytes_sent: int = 0
    network_bytes_received: int = 0
    active_connections: int = 0
    requests_per_second: float = 0.0
    response_time_ms: float = 0.0
    error_rate_percent: float = 0.0
    uptime_seconds: int = 0
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class NodeConfiguration:
    """Node-specific configuration."""
    node_id: str
    node_type: NodeType
    node_role: NodeRole = NodeRole.FOLLOWER
    host: str = "localhost"
    port: int = 8000
    api_port: int = 8001
    secure_port: int = 8443
    capabilities: NodeCapabilities = field(default_factory=NodeCapabilities)
    heartbeat_interval_seconds: int = 30
    health_check_timeout_seconds: int = 10
    max_missed_heartbeats: int = 3
    enable_ssl: bool = True
    ssl_cert_path: Optional[str] = None
    ssl_key_path: Optional[str] = None
    custom_config: Dict[str, Any] = field(default_factory=dict)


@dataclass
class NodeInfo:
    """Complete node information."""
    config: NodeConfiguration
    status: NodeStatus = NodeStatus.INITIALIZING
    metrics: NodeMetrics = field(default_factory=NodeMetrics)
    security_context: Optional[SecurityContext] = None
    registered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_heartbeat: Optional[datetime] = None
    last_health_check: Optional[datetime] = None
    missed_heartbeats: int = 0
    version: str = "1.0.0"
    tags: Set[str] = field(default_factory=set)


class NodeAuthenticator:
    """Handles node authentication and authorization."""
    
    def __init__(self, security_system):
        self.security_system = security_system
        self.node_tokens: Dict[str, str] = {}
        self.node_certificates: Dict[str, str] = {}
        
    async def authenticate_node(self, node_id: str, auth_token: str) -> Tuple[bool, Optional[SecurityContext]]:
        """Authenticate a node using its token."""
        try:
            # Verify the token
            is_valid, payload = self.security_system.token_manager.verify_token(auth_token)
            if not is_valid or not payload:
                logger.warning(f"Invalid token for node {node_id}")
                return False, None
            
            # Check if token is for this node
            if payload.get('user_id') != f"node:{node_id}":
                logger.warning(f"Token user mismatch for node {node_id}")
                return False, None
            
            # Create security context for the node
            context = SecurityContext(
                user_id=f"node:{node_id}",
                authenticated=True,
                security_level=SecurityLevel.SYSTEM,
                permissions={"cluster:join", "cluster:heartbeat", "cluster:metrics"}
            )
            
            return True, context
            
        except Exception as e:
            logger.error(f"Node authentication error for {node_id}: {e}")
            return False, None
    
    async def generate_node_token(self, node_id: str) -> str:
        """Generate authentication token for a node."""
        permissions = {"cluster:join", "cluster:heartbeat", "cluster:metrics"}
        token = self.security_system.token_manager.create_access_token(
            f"node:{node_id}", 
            permissions
        )
        self.node_tokens[node_id] = token
        return token
    
    async def revoke_node_token(self, node_id: str) -> bool:
        """Revoke authentication token for a node."""
        if node_id in self.node_tokens:
            token = self.node_tokens[node_id]
            success = self.security_system.token_manager.revoke_token(token)
            if success:
                del self.node_tokens[node_id]
            return success
        return False


class HealthMonitor:
    """Monitors node health and performance."""
    
    def __init__(self, node_config: NodeConfiguration):
        self.node_config = node_config
        self.start_time = time.time()
        
    async def collect_metrics(self) -> NodeMetrics:
        """Collect current node metrics."""
        try:
            # Get system metrics
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            network = psutil.net_io_counters()
            
            # Calculate uptime
            uptime = int(time.time() - self.start_time)
            
            metrics = NodeMetrics(
                cpu_usage_percent=cpu_percent,
                memory_usage_percent=memory.percent,
                disk_usage_percent=disk.percent,
                network_bytes_sent=network.bytes_sent,
                network_bytes_received=network.bytes_recv,
                uptime_seconds=uptime,
                last_updated=datetime.now(timezone.utc)
            )
            
            return metrics
            
        except Exception as e:
            logger.error(f"Error collecting metrics: {e}")
            return NodeMetrics()
    
    async def check_health(self) -> Tuple[NodeStatus, List[str]]:
        """Check node health and return status with issues."""
        issues = []
        
        try:
            metrics = await self.collect_metrics()
            
            # Check CPU usage
            if metrics.cpu_usage_percent > 90:
                issues.append("High CPU usage")
            
            # Check memory usage
            if metrics.memory_usage_percent > 90:
                issues.append("High memory usage")
            
            # Check disk usage
            if metrics.disk_usage_percent > 90:
                issues.append("High disk usage")
            
            # Determine status based on issues
            if not issues:
                return NodeStatus.HEALTHY, issues
            elif len(issues) <= 2:
                return NodeStatus.DEGRADED, issues
            else:
                return NodeStatus.UNHEALTHY, issues
                
        except Exception as e:
            logger.error(f"Health check error: {e}")
            return NodeStatus.UNHEALTHY, [f"Health check failed: {str(e)}"]


class HeartbeatManager:
    """Manages node heartbeat communication."""
    
    def __init__(self, node_config: NodeConfiguration, authenticator: NodeAuthenticator):
        self.node_config = node_config
        self.authenticator = authenticator
        self.heartbeat_task: Optional[asyncio.Task] = None
        self.is_running = False
        self.cluster_endpoints: List[str] = []
        
    async def start_heartbeat(self, cluster_endpoints: List[str]) -> None:
        """Start sending heartbeats to cluster."""
        self.cluster_endpoints = cluster_endpoints
        self.is_running = True
        self.heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        logger.info(f"Started heartbeat for node {self.node_config.node_id}")
    
    async def stop_heartbeat(self) -> None:
        """Stop sending heartbeats."""
        self.is_running = False
        if self.heartbeat_task:
            self.heartbeat_task.cancel()
            try:
                await self.heartbeat_task
            except asyncio.CancelledError:
                pass
        logger.info(f"Stopped heartbeat for node {self.node_config.node_id}")
    
    async def _heartbeat_loop(self) -> None:
        """Main heartbeat loop."""
        while self.is_running:
            try:
                await self._send_heartbeat()
                await asyncio.sleep(self.node_config.heartbeat_interval_seconds)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Heartbeat error: {e}")
                await asyncio.sleep(5)  # Brief pause before retry
    
    async def _send_heartbeat(self) -> None:
        """Send heartbeat to cluster endpoints."""
        if not self.cluster_endpoints:
            return
        
        # Get authentication token
        token = await self.authenticator.generate_node_token(self.node_config.node_id)
        
        heartbeat_data = {
            'node_id': self.node_config.node_id,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'status': NodeStatus.HEALTHY.value,
            'metrics': {}  # Would include current metrics
        }
        
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        
        # Send to all cluster endpoints
        for endpoint in self.cluster_endpoints:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        f"{endpoint}/cluster/heartbeat",
                        json=heartbeat_data,
                        headers=headers,
                        timeout=aiohttp.ClientTimeout(total=self.node_config.health_check_timeout_seconds)
                    ) as response:
                        if response.status == 200:
                            logger.debug(f"Heartbeat sent to {endpoint}")
                        else:
                            logger.warning(f"Heartbeat failed to {endpoint}: {response.status}")
            except Exception as e:
                logger.error(f"Failed to send heartbeat to {endpoint}: {e}")


class NodeManager:
    """
    Comprehensive node manager for PlexiChat clustering system.
    
    Handles:
    - Node lifecycle management
    - Health monitoring and metrics collection
    - Heartbeat communication
    - Security integration
    - Graceful shutdown procedures
    """
    
    def __init__(self, config: NodeConfiguration):
        self.config = config
        self.node_info = NodeInfo(config=config)
        
        # Initialize security integration
        self.security_system = get_unified_security_system()
        self.authenticator = NodeAuthenticator(self.security_system)
        
        # Initialize monitoring and communication
        self.health_monitor = HealthMonitor(config)
        self.heartbeat_manager = HeartbeatManager(config, self.authenticator)
        
        # State management
        self.is_running = False
        self.shutdown_event = asyncio.Event()
        self.monitoring_task: Optional[asyncio.Task] = None
        
        # Event callbacks
        self.status_change_callbacks: List[Callable[[NodeStatus, NodeStatus], None]] = []
        self.metrics_callbacks: List[Callable[[NodeMetrics], None]] = []
        
        logger.info(f"Node manager initialized for {config.node_id}")
    
    async def start(self, cluster_endpoints: Optional[List[str]] = None) -> bool:
        """Start the node manager."""
        try:
            logger.info(f"Starting node {self.config.node_id}")
            
            # Update status
            await self._update_status(NodeStatus.INITIALIZING)
            
            # Generate authentication token
            token = await self.authenticator.generate_node_token(self.config.node_id)
            logger.info(f"Generated authentication token for node {self.config.node_id}")
            
            # Start health monitoring
            self.monitoring_task = asyncio.create_task(self._monitoring_loop())
            
            # Start heartbeat if cluster endpoints provided
            if cluster_endpoints:
                await self.heartbeat_manager.start_heartbeat(cluster_endpoints)
            
            # Mark as running
            self.is_running = True
            await self._update_status(NodeStatus.HEALTHY)
            
            logger.info(f"Node {self.config.node_id} started successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start node {self.config.node_id}: {e}")
            await self._update_status(NodeStatus.OFFLINE)
            return False
    
    async def stop(self, graceful: bool = True) -> None:
        """Stop the node manager."""
        try:
            logger.info(f"Stopping node {self.config.node_id} (graceful={graceful})")
            
            # Update status
            await self._update_status(NodeStatus.SHUTTING_DOWN)
            
            # Stop heartbeat
            await self.heartbeat_manager.stop_heartbeat()
            
            # Stop monitoring
            if self.monitoring_task:
                self.monitoring_task.cancel()
                try:
                    await self.monitoring_task
                except asyncio.CancelledError:
                    pass
            
            # Revoke authentication token
            await self.authenticator.revoke_node_token(self.config.node_id)
            
            # Mark as stopped
            self.is_running = False
            await self._update_status(NodeStatus.OFFLINE)
            
            # Signal shutdown complete
            self.shutdown_event.set()
            
            logger.info(f"Node {self.config.node_id} stopped successfully")
            
        except Exception as e:
            logger.error(f"Error stopping node {self.config.node_id}: {e}")
    
    async def register_with_cluster(self, cluster_endpoint: str) -> bool:
        """Register this node with a cluster."""
        try:
            # Get authentication token
            token = await self.authenticator.generate_node_token(self.config.node_id)
            
            registration_data = {
                'node_info': asdict(self.node_info),
                'capabilities': asdict(self.config.capabilities),
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            
            headers = {
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json'
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{cluster_endpoint}/cluster/register",
                    json=registration_data,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    if response.status == 200:
                        result = await response.json()
                        logger.info(f"Node {self.config.node_id} registered with cluster")
                        return True
                    else:
                        logger.error(f"Registration failed: {response.status}")
                        return False
                        
        except Exception as e:
            logger.error(f"Failed to register with cluster: {e}")
            return False
    
    async def unregister_from_cluster(self, cluster_endpoint: str) -> bool:
        """Unregister this node from a cluster."""
        try:
            # Get authentication token
            token = self.authenticator.node_tokens.get(self.config.node_id)
            if not token:
                return False
            
            headers = {
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json'
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.delete(
                    f"{cluster_endpoint}/cluster/nodes/{self.config.node_id}",
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    if response.status == 200:
                        logger.info(f"Node {self.config.node_id} unregistered from cluster")
                        return True
                    else:
                        logger.error(f"Unregistration failed: {response.status}")
                        return False
                        
        except Exception as e:
            logger.error(f"Failed to unregister from cluster: {e}")
            return False
    
    async def update_configuration(self, new_config: Dict[str, Any]) -> bool:
        """Update node configuration."""
        try:
            # Validate configuration
            for key, value in new_config.items():
                if hasattr(self.config, key):
                    setattr(self.config, key, value)
                elif hasattr(self.config.capabilities, key):
                    setattr(self.config.capabilities, key, value)
                else:
                    self.config.custom_config[key] = value
            
            logger.info(f"Configuration updated for node {self.config.node_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to update configuration: {e}")
            return False
    
    async def get_status(self) -> Dict[str, Any]:
        """Get comprehensive node status."""
        return {
            'node_id': self.config.node_id,
            'node_type': self.config.node_type.value,
            'node_role': self.config.node_role.value,
            'status': self.node_info.status.value,
            'metrics': asdict(self.node_info.metrics),
            'uptime_seconds': self.node_info.metrics.uptime_seconds,
            'last_heartbeat': self.node_info.last_heartbeat.isoformat() if self.node_info.last_heartbeat else None,
            'missed_heartbeats': self.node_info.missed_heartbeats,
            'is_running': self.is_running,
            'capabilities': asdict(self.config.capabilities),
            'version': self.node_info.version,
            'tags': list(self.node_info.tags)
        }
    
    def add_status_change_callback(self, callback: Callable[[NodeStatus, NodeStatus], None]) -> None:
        """Add callback for status changes."""
        self.status_change_callbacks.append(callback)
    
    def add_metrics_callback(self, callback: Callable[[NodeMetrics], None]) -> None:
        """Add callback for metrics updates."""
        self.metrics_callbacks.append(callback)
    
    async def _update_status(self, new_status: NodeStatus) -> None:
        """Update node status and notify callbacks."""
        old_status = self.node_info.status
        self.node_info.status = new_status
        
        # Notify callbacks
        for callback in self.status_change_callbacks:
            try:
                callback(old_status, new_status)
            except Exception as e:
                logger.error(f"Status change callback error: {e}")
        
        logger.info(f"Node {self.config.node_id} status changed: {old_status.value} -> {new_status.value}")
    
    async def _monitoring_loop(self) -> None:
        """Main monitoring loop."""
        while self.is_running:
            try:
                # Collect metrics
                metrics = await self.health_monitor.collect_metrics()
                self.node_info.metrics = metrics
                
                # Check health
                status, issues = await self.health_monitor.check_health()
                if status != self.node_info.status:
                    await self._update_status(status)
                
                # Log issues if any
                if issues:
                    logger.warning(f"Node {self.config.node_id} health issues: {', '.join(issues)}")
                
                # Notify metrics callbacks
                for callback in self.metrics_callbacks:
                    try:
                        callback(metrics)
                    except Exception as e:
                        logger.error(f"Metrics callback error: {e}")
                
                # Wait before next check
                await asyncio.sleep(30)  # Check every 30 seconds
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Monitoring loop error: {e}")
                await asyncio.sleep(5)
    
    async def wait_for_shutdown(self) -> None:
        """Wait for node shutdown to complete."""
        await self.shutdown_event.wait()


# Factory functions for creating node managers
def create_networking_node(node_id: str, host: str = "localhost", port: int = 8000) -> NodeManager:
    """Create a networking node manager."""
    config = NodeConfiguration(
        node_id=node_id,
        node_type=NodeType.NETWORKING,
        host=host,
        port=port,
        capabilities=NodeCapabilities(
            max_connections=5000,
            supports_networking=True,
            supports_storage=False,
            supports_compute=False
        )
    )
    return NodeManager(config)


def create_endpoint_node(node_id: str, host: str = "localhost", port: int = 8000) -> NodeManager:
    """Create an endpoint node manager."""
    config = NodeConfiguration(
        node_id=node_id,
        node_type=NodeType.ENDPOINT,
        host=host,
        port=port,
        capabilities=NodeCapabilities(
            max_connections=2000,
            supports_networking=True,
            supports_storage=True,
            supports_compute=True
        )
    )
    return NodeManager(config)


def create_general_node(node_id: str, host: str = "localhost", port: int = 8000) -> NodeManager:
    """Create a general purpose node manager."""
    config = NodeConfiguration(
        node_id=node_id,
        node_type=NodeType.GENERAL,
        host=host,
        port=port,
        capabilities=NodeCapabilities(
            max_connections=1000,
            supports_networking=True,
            supports_storage=True,
            supports_compute=True
        )
    )
    return NodeManager(config)


__all__ = [
    "NodeManager",
    "NodeConfiguration",
    "NodeInfo",
    "NodeType",
    "NodeStatus",
    "NodeRole",
    "NodeCapabilities",
    "NodeMetrics",
    "NodeAuthenticator",
    "HealthMonitor",
    "HeartbeatManager",
    "create_networking_node",
    "create_endpoint_node",
    "create_general_node"
]