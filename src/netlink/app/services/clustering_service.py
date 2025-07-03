"""
Advanced Node Clustering System for NetLink.
Provides highly decentralized clustering with cross-node management,
advanced task distribution, and sophisticated load balancing.
"""

import asyncio
import json
import time
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import logging

try:
    import httpx
    import aiofiles
except ImportError:
    print("Missing dependencies. Install with: pip install httpx aiofiles")
    raise

from netlink.app.logger_config import logger


class NodeRole(Enum):
    """Node roles in the cluster."""
    COORDINATOR = "coordinator"
    WORKER = "worker"
    BACKUP = "backup"
    GATEWAY = "gateway"
    STORAGE = "storage"


class TaskStatus(Enum):
    """Task execution status."""
    PENDING = "pending"
    ASSIGNED = "assigned"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class NodeStatus(Enum):
    """Node status in cluster."""
    ONLINE = "online"
    OFFLINE = "offline"
    DEGRADED = "degraded"
    MAINTENANCE = "maintenance"


@dataclass
class ClusterNode:
    """Represents a node in the cluster."""
    node_id: str
    address: str
    port: int
    role: NodeRole
    status: NodeStatus
    capabilities: List[str]
    load_score: float = 0.0
    last_heartbeat: Optional[datetime] = None
    metadata: Optional[Dict[str, Any]] = None
    
    # Performance metrics
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    disk_usage: float = 0.0
    network_latency: float = 0.0
    
    # Cluster metrics
    tasks_completed: int = 0
    tasks_failed: int = 0
    uptime_seconds: int = 0
    
    def __post_init__(self):
        if self.last_heartbeat is None:
            self.last_heartbeat = datetime.now()


@dataclass
class ClusterTask:
    """Represents a task in the cluster."""
    task_id: str
    task_type: str
    payload: Dict[str, Any]
    priority: int = 1
    status: TaskStatus = TaskStatus.PENDING
    assigned_node: Optional[str] = None
    created_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    retry_count: int = 0
    max_retries: int = 3
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()


class LoadBalancer:
    """Advanced load balancing algorithms."""
    
    @staticmethod
    def weighted_round_robin(nodes: List[ClusterNode], weights: Optional[Dict[str, float]] = None) -> ClusterNode:
        """Weighted round-robin load balancing."""
        if not nodes:
            raise ValueError("No nodes available")
        
        # Filter online nodes
        online_nodes = [node for node in nodes if node.status == NodeStatus.ONLINE]
        if not online_nodes:
            raise ValueError("No online nodes available")
        
        # Calculate weights based on performance if not provided
        if weights is None:
            weights = {}
            for node in online_nodes:
                # Higher weight for better performance (lower load)
                weight = max(0.1, 1.0 - node.load_score)
                weights[node.node_id] = weight
        
        # Select node based on weighted probability
        total_weight = sum(weights.get(node.node_id, 1.0) for node in online_nodes)
        if total_weight == 0:
            return online_nodes[0]
        
        import random
        target = random.uniform(0, total_weight)
        current = 0
        
        for node in online_nodes:
            current += weights.get(node.node_id, 1.0)
            if current >= target:
                return node
        
        return online_nodes[-1]
    
    @staticmethod
    def least_connections(nodes: List[ClusterNode]) -> ClusterNode:
        """Least connections load balancing."""
        online_nodes = [node for node in nodes if node.status == NodeStatus.ONLINE]
        if not online_nodes:
            raise ValueError("No online nodes available")
        
        # Find node with lowest load score
        return min(online_nodes, key=lambda n: n.load_score)
    
    @staticmethod
    def resource_aware(nodes: List[ClusterNode], task_requirements: Dict[str, float]) -> ClusterNode:
        """Resource-aware load balancing based on task requirements."""
        online_nodes = [node for node in nodes if node.status == NodeStatus.ONLINE]
        if not online_nodes:
            raise ValueError("No online nodes available")
        
        # Score nodes based on available resources
        best_node = None
        best_score = float('inf')
        
        for node in online_nodes:
            # Calculate resource availability score
            cpu_available = max(0, 1.0 - node.cpu_usage)
            memory_available = max(0, 1.0 - node.memory_usage)
            
            # Check if node meets minimum requirements
            required_cpu = task_requirements.get('cpu', 0.1)
            required_memory = task_requirements.get('memory', 0.1)
            
            if cpu_available < required_cpu or memory_available < required_memory:
                continue
            
            # Calculate score (lower is better)
            score = (
                (required_cpu / cpu_available) * 0.4 +
                (required_memory / memory_available) * 0.4 +
                node.load_score * 0.2
            )
            
            if score < best_score:
                best_score = score
                best_node = node
        
        if best_node is None:
            # Fallback to least loaded node
            return min(online_nodes, key=lambda n: n.load_score)
        
        return best_node


class ClusteringService:
    """Advanced clustering service for NetLink."""
    
    def __init__(self, node_id: str, address: str, port: int, role: NodeRole = NodeRole.WORKER):
        self.node_id = node_id
        self.address = address
        self.port = port
        self.role = role
        
        # Cluster state
        self.nodes: Dict[str, ClusterNode] = {}
        self.tasks: Dict[str, ClusterTask] = {}
        self.is_coordinator = False
        self.coordinator_node: Optional[str] = None
        
        # Load balancer
        self.load_balancer = LoadBalancer()
        
        # Configuration
        self.heartbeat_interval = 30  # seconds
        self.task_timeout = 300  # seconds
        self.node_timeout = 90  # seconds
        
        # Background tasks
        self.background_tasks: Set[asyncio.Task] = set()
        
        # HTTP client for inter-node communication
        self.http_client = httpx.AsyncClient(timeout=30)
        
        # Initialize self as a node
        self.self_node = ClusterNode(
            node_id=node_id,
            address=address,
            port=port,
            role=role,
            status=NodeStatus.ONLINE,
            capabilities=self._get_node_capabilities()
        )
        self.nodes[node_id] = self.self_node
        
        logger.info(f"🌐 Clustering service initialized: {node_id} ({role.value})")
    
    def _get_node_capabilities(self) -> List[str]:
        """Get capabilities of this node."""
        capabilities = ["basic_tasks", "message_processing"]
        
        if self.role == NodeRole.COORDINATOR:
            capabilities.extend(["task_scheduling", "cluster_management"])
        elif self.role == NodeRole.STORAGE:
            capabilities.extend(["data_storage", "backup_management"])
        elif self.role == NodeRole.GATEWAY:
            capabilities.extend(["api_gateway", "load_balancing"])
        elif self.role == NodeRole.BACKUP:
            capabilities.extend(["backup_storage", "data_replication"])
        
        return capabilities
    
    async def start(self):
        """Start the clustering service."""
        logger.info(f"🚀 Starting clustering service for node {self.node_id}")
        
        # Start background tasks
        self.background_tasks.add(asyncio.create_task(self._heartbeat_loop()))
        self.background_tasks.add(asyncio.create_task(self._task_monitor_loop()))
        self.background_tasks.add(asyncio.create_task(self._node_monitor_loop()))
        
        # Try to discover existing cluster
        await self._discover_cluster()
        
        logger.info(f"✅ Clustering service started for node {self.node_id}")
    
    async def stop(self):
        """Stop the clustering service."""
        logger.info(f"🛑 Stopping clustering service for node {self.node_id}")
        
        # Cancel background tasks
        for task in self.background_tasks:
            task.cancel()
        
        # Wait for tasks to complete
        await asyncio.gather(*self.background_tasks, return_exceptions=True)
        
        # Close HTTP client
        await self.http_client.aclose()
        
        logger.info(f"✅ Clustering service stopped for node {self.node_id}")
    
    async def join_cluster(self, coordinator_address: str, coordinator_port: int) -> bool:
        """Join an existing cluster."""
        try:
            # Contact coordinator to join cluster
            response = await self.http_client.post(
                f"http://{coordinator_address}:{coordinator_port}/api/v1/cluster/join",
                json={
                    "node_id": self.node_id,
                    "address": self.address,
                    "port": self.port,
                    "role": self.role.value,
                    "capabilities": self.self_node.capabilities
                }
            )
            
            if response.status_code == 200:
                result = response.json()
                
                # Update cluster state
                cluster_nodes = result.get("cluster_nodes", {})
                for node_id, node_data in cluster_nodes.items():
                    if node_id != self.node_id:
                        self.nodes[node_id] = ClusterNode(**node_data)
                
                self.coordinator_node = result.get("coordinator_node")
                
                logger.info(f"✅ Successfully joined cluster with coordinator {coordinator_address}:{coordinator_port}")
                return True
            else:
                logger.error(f"❌ Failed to join cluster: HTTP {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"❌ Failed to join cluster: {e}")
            return False
    
    async def become_coordinator(self) -> bool:
        """Become the cluster coordinator."""
        try:
            self.is_coordinator = True
            self.coordinator_node = self.node_id
            self.self_node.role = NodeRole.COORDINATOR
            
            # Add coordinator capabilities
            if "task_scheduling" not in self.self_node.capabilities:
                self.self_node.capabilities.extend(["task_scheduling", "cluster_management"])
            
            logger.info(f"👑 Node {self.node_id} became cluster coordinator")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to become coordinator: {e}")
            return False
    
    async def submit_task(self, task_type: str, payload: Dict[str, Any], priority: int = 1) -> str:
        """Submit a task to the cluster."""
        task_id = f"task_{int(time.time() * 1000)}_{secrets.token_hex(4)}"
        
        task = ClusterTask(
            task_id=task_id,
            task_type=task_type,
            payload=payload,
            priority=priority
        )
        
        self.tasks[task_id] = task
        
        # If we're the coordinator, schedule the task
        if self.is_coordinator:
            await self._schedule_task(task)
        else:
            # Forward to coordinator
            await self._forward_task_to_coordinator(task)
        
        logger.info(f"📋 Submitted task {task_id} ({task_type})")
        return task_id
    
    async def _schedule_task(self, task: ClusterTask):
        """Schedule a task to an appropriate node."""
        try:
            # Find suitable nodes for this task
            suitable_nodes = self._find_suitable_nodes(task)
            
            if not suitable_nodes:
                logger.warning(f"⚠️ No suitable nodes found for task {task.task_id}")
                task.status = TaskStatus.FAILED
                task.error = "No suitable nodes available"
                return
            
            # Select best node using load balancing
            selected_node = self.load_balancer.resource_aware(
                suitable_nodes,
                task.payload.get('requirements', {})
            )
            
            # Assign task to node
            task.assigned_node = selected_node.node_id
            task.status = TaskStatus.ASSIGNED
            
            # Send task to node
            if selected_node.node_id == self.node_id:
                # Execute locally
                await self._execute_task_locally(task)
            else:
                # Send to remote node
                await self._send_task_to_node(task, selected_node)
            
            logger.info(f"📤 Scheduled task {task.task_id} to node {selected_node.node_id}")
            
        except Exception as e:
            logger.error(f"❌ Failed to schedule task {task.task_id}: {e}")
            task.status = TaskStatus.FAILED
            task.error = str(e)
    
    def _find_suitable_nodes(self, task: ClusterTask) -> List[ClusterNode]:
        """Find nodes suitable for executing a task."""
        suitable_nodes = []
        
        for node in self.nodes.values():
            if node.status != NodeStatus.ONLINE:
                continue
            
            # Check if node has required capabilities
            required_capabilities = task.payload.get('required_capabilities', [])
            if required_capabilities:
                if not all(cap in node.capabilities for cap in required_capabilities):
                    continue
            
            # Check resource requirements
            requirements = task.payload.get('requirements', {})
            if requirements:
                required_cpu = requirements.get('cpu', 0)
                required_memory = requirements.get('memory', 0)
                
                if (node.cpu_usage + required_cpu > 0.9 or 
                    node.memory_usage + required_memory > 0.9):
                    continue
            
            suitable_nodes.append(node)
        
        return suitable_nodes
    
    async def _send_task_to_node(self, task: ClusterTask, node: ClusterNode):
        """Send a task to a remote node for execution."""
        try:
            response = await self.http_client.post(
                f"http://{node.address}:{node.port}/api/v1/cluster/execute_task",
                json={
                    "task_id": task.task_id,
                    "task_type": task.task_type,
                    "payload": task.payload,
                    "priority": task.priority
                }
            )
            
            if response.status_code == 200:
                task.status = TaskStatus.RUNNING
                task.started_at = datetime.now()
                logger.info(f"✅ Task {task.task_id} sent to node {node.node_id}")
            else:
                logger.error(f"❌ Failed to send task {task.task_id} to node {node.node_id}: HTTP {response.status_code}")
                task.status = TaskStatus.FAILED
                task.error = f"Failed to send to node: HTTP {response.status_code}"
                
        except Exception as e:
            logger.error(f"❌ Failed to send task {task.task_id} to node {node.node_id}: {e}")
            task.status = TaskStatus.FAILED
            task.error = str(e)
    
    async def _execute_task_locally(self, task: ClusterTask):
        """Execute a task locally."""
        try:
            task.status = TaskStatus.RUNNING
            task.started_at = datetime.now()
            
            # Simulate task execution based on task type
            result = await self._process_task(task)
            
            task.status = TaskStatus.COMPLETED
            task.completed_at = datetime.now()
            task.result = result
            
            # Update node metrics
            self.self_node.tasks_completed += 1
            
            logger.info(f"✅ Task {task.task_id} completed locally")
            
        except Exception as e:
            logger.error(f"❌ Task {task.task_id} failed locally: {e}")
            task.status = TaskStatus.FAILED
            task.error = str(e)
            task.completed_at = datetime.now()
            
            # Update node metrics
            self.self_node.tasks_failed += 1
    
    async def _process_task(self, task: ClusterTask) -> Dict[str, Any]:
        """Process a specific task based on its type."""
        task_type = task.task_type
        payload = task.payload
        
        if task_type == "message_processing":
            # Simulate message processing
            await asyncio.sleep(0.1)
            return {
                "processed_messages": payload.get("message_count", 1),
                "processing_time": 0.1
            }
        
        elif task_type == "backup_creation":
            # Simulate backup creation
            await asyncio.sleep(0.5)
            return {
                "backup_size": payload.get("data_size", 1024),
                "backup_location": f"/backups/{task.task_id}.bak"
            }
        
        elif task_type == "data_analysis":
            # Simulate data analysis
            await asyncio.sleep(1.0)
            return {
                "analysis_results": {"trend": "positive", "confidence": 0.85},
                "data_points": payload.get("data_points", 100)
            }
        
        else:
            # Generic task processing
            await asyncio.sleep(0.2)
            return {
                "task_type": task_type,
                "processed": True,
                "payload_size": len(str(payload))
            }
    
    async def _heartbeat_loop(self):
        """Send periodic heartbeats to maintain cluster membership."""
        while True:
            try:
                await self._send_heartbeat()
                await asyncio.sleep(self.heartbeat_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"❌ Heartbeat error: {e}")
                await asyncio.sleep(5)
    
    async def _send_heartbeat(self):
        """Send heartbeat to coordinator and other nodes."""
        # Update self metrics
        self._update_self_metrics()
        
        # Send to coordinator if we're not the coordinator
        if not self.is_coordinator and self.coordinator_node:
            coordinator = self.nodes.get(self.coordinator_node)
            if coordinator:
                try:
                    await self.http_client.post(
                        f"http://{coordinator.address}:{coordinator.port}/api/v1/cluster/heartbeat",
                        json={
                            "node_id": self.node_id,
                            "status": self.self_node.status.value,
                            "load_score": self.self_node.load_score,
                            "cpu_usage": self.self_node.cpu_usage,
                            "memory_usage": self.self_node.memory_usage,
                            "tasks_completed": self.self_node.tasks_completed,
                            "tasks_failed": self.self_node.tasks_failed
                        }
                    )
                except Exception as e:
                    logger.warning(f"⚠️ Failed to send heartbeat to coordinator: {e}")
    
    def _update_self_metrics(self):
        """Update metrics for this node."""
        import psutil
        
        try:
            # Update system metrics
            self.self_node.cpu_usage = psutil.cpu_percent() / 100.0
            self.self_node.memory_usage = psutil.virtual_memory().percent / 100.0
            self.self_node.disk_usage = psutil.disk_usage('/').percent / 100.0
            
            # Calculate load score (0.0 = no load, 1.0 = maximum load)
            self.self_node.load_score = (
                self.self_node.cpu_usage * 0.4 +
                self.self_node.memory_usage * 0.4 +
                min(len([t for t in self.tasks.values() if t.assigned_node == self.node_id and t.status == TaskStatus.RUNNING]) / 10.0, 1.0) * 0.2
            )
            
            self.self_node.last_heartbeat = datetime.now()
            
        except ImportError:
            # psutil not available, use dummy values
            self.self_node.cpu_usage = 0.1
            self.self_node.memory_usage = 0.2
            self.self_node.load_score = 0.15
            self.self_node.last_heartbeat = datetime.now()
    
    async def _task_monitor_loop(self):
        """Monitor task execution and handle timeouts."""
        while True:
            try:
                await self._check_task_timeouts()
                await asyncio.sleep(30)  # Check every 30 seconds
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"❌ Task monitor error: {e}")
                await asyncio.sleep(10)
    
    async def _check_task_timeouts(self):
        """Check for timed out tasks and handle them."""
        current_time = datetime.now()
        
        for task in self.tasks.values():
            if task.status == TaskStatus.RUNNING and task.started_at:
                elapsed = (current_time - task.started_at).total_seconds()
                
                if elapsed > self.task_timeout:
                    logger.warning(f"⏰ Task {task.task_id} timed out after {elapsed:.1f}s")
                    task.status = TaskStatus.FAILED
                    task.error = f"Task timed out after {elapsed:.1f} seconds"
                    task.completed_at = current_time
                    
                    # Update node metrics
                    if task.assigned_node == self.node_id:
                        self.self_node.tasks_failed += 1
    
    async def _node_monitor_loop(self):
        """Monitor node health and handle failures."""
        while True:
            try:
                await self._check_node_health()
                await asyncio.sleep(60)  # Check every minute
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"❌ Node monitor error: {e}")
                await asyncio.sleep(30)
    
    async def _check_node_health(self):
        """Check health of all nodes in the cluster."""
        current_time = datetime.now()
        offline_nodes = []
        
        for node_id, node in self.nodes.items():
            if node_id == self.node_id:
                continue  # Skip self
            
            if node.last_heartbeat:
                elapsed = (current_time - node.last_heartbeat).total_seconds()
                
                if elapsed > self.node_timeout:
                    if node.status == NodeStatus.ONLINE:
                        logger.warning(f"📴 Node {node_id} went offline (no heartbeat for {elapsed:.1f}s)")
                        node.status = NodeStatus.OFFLINE
                        offline_nodes.append(node_id)
        
        # Handle offline nodes
        if offline_nodes and self.is_coordinator:
            await self._handle_offline_nodes(offline_nodes)
    
    async def _handle_offline_nodes(self, offline_nodes: List[str]):
        """Handle nodes that have gone offline."""
        for node_id in offline_nodes:
            # Reassign tasks from offline node
            failed_tasks = [
                task for task in self.tasks.values()
                if task.assigned_node == node_id and task.status in [TaskStatus.ASSIGNED, TaskStatus.RUNNING]
            ]
            
            for task in failed_tasks:
                logger.info(f"🔄 Reassigning task {task.task_id} from offline node {node_id}")
                task.assigned_node = None
                task.status = TaskStatus.PENDING
                task.retry_count += 1
                
                if task.retry_count <= task.max_retries:
                    await self._schedule_task(task)
                else:
                    logger.error(f"❌ Task {task.task_id} exceeded max retries")
                    task.status = TaskStatus.FAILED
                    task.error = "Exceeded maximum retry attempts"
    
    async def _discover_cluster(self):
        """Discover existing cluster nodes."""
        # This would typically involve service discovery mechanisms
        # For now, we'll implement a simple discovery process
        logger.info(f"🔍 Discovering cluster for node {self.node_id}")
        
        # If no coordinator is known, try to become one
        if not self.coordinator_node:
            await self.become_coordinator()
    
    async def _forward_task_to_coordinator(self, task: ClusterTask):
        """Forward a task to the cluster coordinator."""
        if not self.coordinator_node:
            logger.error(f"❌ No coordinator available to forward task {task.task_id}")
            task.status = TaskStatus.FAILED
            task.error = "No coordinator available"
            return
        
        coordinator = self.nodes.get(self.coordinator_node)
        if not coordinator:
            logger.error(f"❌ Coordinator node {self.coordinator_node} not found")
            task.status = TaskStatus.FAILED
            task.error = "Coordinator node not found"
            return
        
        try:
            response = await self.http_client.post(
                f"http://{coordinator.address}:{coordinator.port}/api/v1/cluster/submit_task",
                json={
                    "task_id": task.task_id,
                    "task_type": task.task_type,
                    "payload": task.payload,
                    "priority": task.priority
                }
            )
            
            if response.status_code == 200:
                logger.info(f"✅ Task {task.task_id} forwarded to coordinator")
            else:
                logger.error(f"❌ Failed to forward task {task.task_id}: HTTP {response.status_code}")
                task.status = TaskStatus.FAILED
                task.error = f"Failed to forward to coordinator: HTTP {response.status_code}"
                
        except Exception as e:
            logger.error(f"❌ Failed to forward task {task.task_id}: {e}")
            task.status = TaskStatus.FAILED
            task.error = str(e)
    
    def get_cluster_status(self) -> Dict[str, Any]:
        """Get current cluster status."""
        online_nodes = sum(1 for node in self.nodes.values() if node.status == NodeStatus.ONLINE)
        total_tasks = len(self.tasks)
        running_tasks = sum(1 for task in self.tasks.values() if task.status == TaskStatus.RUNNING)
        completed_tasks = sum(1 for task in self.tasks.values() if task.status == TaskStatus.COMPLETED)
        failed_tasks = sum(1 for task in self.tasks.values() if task.status == TaskStatus.FAILED)
        
        return {
            "cluster_id": f"cluster_{hashlib.md5(self.coordinator_node.encode() if self.coordinator_node else b'unknown').hexdigest()[:8]}",
            "coordinator_node": self.coordinator_node,
            "is_coordinator": self.is_coordinator,
            "node_id": self.node_id,
            "node_role": self.role.value,
            "cluster_size": len(self.nodes),
            "online_nodes": online_nodes,
            "offline_nodes": len(self.nodes) - online_nodes,
            "total_tasks": total_tasks,
            "running_tasks": running_tasks,
            "completed_tasks": completed_tasks,
            "failed_tasks": failed_tasks,
            "pending_tasks": total_tasks - running_tasks - completed_tasks - failed_tasks,
            "average_load": sum(node.load_score for node in self.nodes.values()) / len(self.nodes) if self.nodes else 0,
            "last_updated": datetime.now().isoformat()
        }


# Global clustering service instance
clustering_service: Optional[ClusteringService] = None
