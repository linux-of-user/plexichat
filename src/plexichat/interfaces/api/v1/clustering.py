from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel

from plexichat.app.logger_config import logger
from plexichat.app.main import cluster_manager
from plexichat.clustering import ClusterTask, TaskStatus
from plexichat.clustering.core.node_manager import NodeStatus

"""
Clustering API endpoints for PlexiChat.
Provides cluster management, task distribution, and node coordination.
"""

# Import global cluster manager
# Pydantic models for API
class NodeJoinRequest(BaseModel):
    node_id: str
    address: str
    port: int
    role: str
    capabilities: List[str]


class TaskSubmissionRequest(BaseModel):
    task_type: str
    payload: Dict[str, Any]
    priority: int = 1
    required_capabilities: Optional[List[str]] = None
    requirements: Optional[Dict[str, float]] = None


class TaskExecutionRequest(BaseModel):
    task_id: str
    task_type: str
    payload: Dict[str, Any]
    priority: int = 1


class HeartbeatRequest(BaseModel):
    node_id: str
    status: str
    load_score: float
    cpu_usage: float
    memory_usage: float
    tasks_completed: int
    tasks_failed: int


class ClusterConfigRequest(BaseModel):
    heartbeat_interval: Optional[int] = None
    task_timeout: Optional[int] = None
    node_timeout: Optional[int] = None


router = APIRouter(prefix="/api/v1/cluster", tags=["Clustering"])


@router.get("/status")
async def get_cluster_status():
    """Get current cluster status."""
    if not cluster_manager:
        raise HTTPException(status_code=503, detail="Clustering service not initialized")

    try:
        if not cluster_manager.initialized:
            await cluster_manager.initialize()

        status = await cluster_manager.get_cluster_status()
        return {
            "success": True,
            "cluster_status": status
        }
    except Exception as e:
        logger.error(f"Failed to get cluster status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/nodes")
async def list_cluster_nodes():
    """List all nodes in the cluster."""
    if not clustering_service:
        raise HTTPException(status_code=503, detail="Clustering service not initialized")
    
    try:
        nodes_info = []
        
        for node_id, node in clustering_service.nodes.items():
            nodes_info.append({
                "node_id": node_id,
                "address": node.address,
                "port": node.port,
                "role": node.role.value,
                "status": node.status.value,
                "capabilities": node.capabilities,
                "load_score": node.load_score,
                "cpu_usage": node.cpu_usage,
                "memory_usage": node.memory_usage,
                "disk_usage": node.disk_usage,
                "tasks_completed": node.tasks_completed,
                "tasks_failed": node.tasks_failed,
                "last_heartbeat": node.last_heartbeat.isoformat() if node.last_heartbeat else None,
                "uptime_seconds": node.uptime_seconds
            })
        
        return {
            "success": True,
            "nodes": nodes_info,
            "total_nodes": len(nodes_info)
        }
        
    except Exception as e:
        logger.error(f"Failed to list cluster nodes: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/nodes/{node_id}")
async def get_node_details(node_id: str):
    """Get detailed information about a specific node."""
    if not clustering_service:
        raise HTTPException(status_code=503, detail="Clustering service not initialized")
    
    try:
        node = clustering_service.nodes.get(node_id)
        if not node:
            raise HTTPException(status_code=404, detail="Node not found")
        
        # Get tasks assigned to this node
        node_tasks = [
            {
                "task_id": task.task_id,
                "task_type": task.task_type,
                "status": task.status.value,
                "priority": task.priority,
                "created_at": task.created_at.isoformat() if task.created_at else None,
                "started_at": task.started_at.isoformat() if task.started_at else None,
                "completed_at": task.completed_at.isoformat() if task.completed_at else None
            }
            for task in clustering_service.tasks.values()
            if task.assigned_node == node_id
        ]
        
        return {
            "success": True,
            "node": {
                "node_id": node_id,
                "address": node.address,
                "port": node.port,
                "role": node.role.value,
                "status": node.status.value,
                "capabilities": node.capabilities,
                "load_score": node.load_score,
                "cpu_usage": node.cpu_usage,
                "memory_usage": node.memory_usage,
                "disk_usage": node.disk_usage,
                "network_latency": node.network_latency,
                "tasks_completed": node.tasks_completed,
                "tasks_failed": node.tasks_failed,
                "uptime_seconds": node.uptime_seconds,
                "last_heartbeat": node.last_heartbeat.isoformat() if node.last_heartbeat else None,
                "metadata": node.metadata
            },
            "assigned_tasks": node_tasks,
            "task_count": len(node_tasks)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get node details for {node_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/join")
async def join_cluster(request: NodeJoinRequest):
    """Join a node to the cluster."""
    if not clustering_service:
        raise HTTPException(status_code=503, detail="Clustering service not initialized")
    
    if not clustering_service.is_coordinator:
        raise HTTPException(status_code=403, detail="Only coordinator can accept new nodes")
    
    try:
        # Validate role
        try:
            role = NodeRole(request.role)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid role: {request.role}")
        
        # Create new node
        new_node = ClusterNode(
            node_id=request.node_id,
            address=request.address,
            port=request.port,
            role=role,
            status=NodeStatus.ONLINE,
            capabilities=request.capabilities,
            last_heartbeat=from datetime import datetime
datetime.now()
        )
        
        # Add to cluster
        clustering_service.nodes[request.node_id] = new_node
        
        # Return cluster information to new node
        cluster_nodes = {}
        for node_id, node in clustering_service.nodes.items():
            cluster_nodes[node_id] = {
                "node_id": node_id,
                "address": node.address,
                "port": node.port,
                "role": node.role.value,
                "status": node.status.value,
                "capabilities": node.capabilities
            }
        
        logger.info(f" Node {request.node_id} joined cluster")
        
        return {
            "success": True,
            "message": f"Node {request.node_id} successfully joined cluster",
            "coordinator_node": clustering_service.coordinator_node,
            "cluster_nodes": cluster_nodes
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to join node {request.node_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/leave")
async def leave_cluster(node_id: str):
    """Remove a node from the cluster."""
    if not clustering_service:
        raise HTTPException(status_code=503, detail="Clustering service not initialized")
    
    if not clustering_service.is_coordinator:
        raise HTTPException(status_code=403, detail="Only coordinator can remove nodes")
    
    try:
        if node_id not in clustering_service.nodes:
            raise HTTPException(status_code=404, detail="Node not found")
        
        # Handle tasks assigned to this node
        affected_tasks = [
            task for task in clustering_service.tasks.values()
            if task.assigned_node == node_id and task.status in [TaskStatus.ASSIGNED, TaskStatus.RUNNING]
        ]
        
        for task in affected_tasks:
            logger.info(f" Reassigning task {task.task_id} from leaving node {node_id}")
            task.assigned_node = None
            task.status = TaskStatus.PENDING
            await clustering_service._schedule_task(task)
        
        # Remove node from cluster
        del clustering_service.nodes[node_id]
        
        logger.info(f" Node {node_id} left cluster")
        
        return {
            "success": True,
            "message": f"Node {node_id} successfully removed from cluster",
            "reassigned_tasks": len(affected_tasks)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to remove node {node_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/submit_task")
async def submit_task(request: TaskSubmissionRequest, background_tasks: BackgroundTasks):
    """Submit a task to the cluster."""
    if not clustering_service:
        raise HTTPException(status_code=503, detail="Clustering service not initialized")
    
    try:
        # Add requirements to payload
        if request.required_capabilities:
            request.payload["required_capabilities"] = request.required_capabilities
        if request.requirements:
            request.payload["requirements"] = request.requirements
        
        task_id = await clustering_service.submit_task(
            task_type=request.task_type,
            payload=request.payload,
            priority=request.priority
        )
        
        return {
            "success": True,
            "task_id": task_id,
            "message": "Task submitted successfully"
        }
        
    except Exception as e:
        logger.error(f"Failed to submit task: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/execute_task")
async def execute_task(request: TaskExecutionRequest, background_tasks: BackgroundTasks):
    """Execute a task on this node."""
    if not clustering_service:
        raise HTTPException(status_code=503, detail="Clustering service not initialized")
    
    try:
        # Create task object
        task = ClusterTask(
            task_id=request.task_id,
            task_type=request.task_type,
            payload=request.payload,
            priority=request.priority
        )
        
        # Add to local tasks
        clustering_service.tasks[request.task_id] = task
        
        # Execute task in background
        background_tasks.add_task(clustering_service._execute_task_locally, task)
        
        return {
            "success": True,
            "task_id": request.task_id,
            "message": "Task execution started"
        }
        
    except Exception as e:
        logger.error(f"Failed to execute task {request.task_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/tasks")
async def list_cluster_tasks():
    """List all tasks in the cluster."""
    if not clustering_service:
        raise HTTPException(status_code=503, detail="Clustering service not initialized")
    
    try:
        tasks_info = []
        
        for task_id, task in clustering_service.tasks.items():
            tasks_info.append({
                "task_id": task_id,
                "task_type": task.task_type,
                "status": task.status.value,
                "priority": task.priority,
                "assigned_node": task.assigned_node,
                "created_at": task.created_at.isoformat() if task.created_at else None,
                "started_at": task.started_at.isoformat() if task.started_at else None,
                "completed_at": task.completed_at.isoformat() if task.completed_at else None,
                "retry_count": task.retry_count,
                "error": task.error
            })
        
        return {
            "success": True,
            "tasks": tasks_info,
            "total_tasks": len(tasks_info)
        }
        
    except Exception as e:
        logger.error(f"Failed to list cluster tasks: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/tasks/{task_id}")
async def get_task_details(task_id: str):
    """Get detailed information about a specific task."""
    if not clustering_service:
        raise HTTPException(status_code=503, detail="Clustering service not initialized")
    
    try:
        task = clustering_service.tasks.get(task_id)
        if not task:
            raise HTTPException(status_code=404, detail="Task not found")
        
        return {
            "success": True,
            "task": {
                "task_id": task_id,
                "task_type": task.task_type,
                "status": task.status.value,
                "priority": task.priority,
                "assigned_node": task.assigned_node,
                "payload": task.payload,
                "result": task.result,
                "error": task.error,
                "retry_count": task.retry_count,
                "max_retries": task.max_retries,
                "created_at": task.created_at.isoformat() if task.created_at else None,
                "started_at": task.started_at.isoformat() if task.started_at else None,
                "completed_at": task.completed_at.isoformat() if task.completed_at else None
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get task details for {task_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/heartbeat")
async def receive_heartbeat(request: HeartbeatRequest):
    """Receive heartbeat from a cluster node."""
    if not clustering_service:
        raise HTTPException(status_code=503, detail="Clustering service not initialized")
    
    if not clustering_service.is_coordinator:
        raise HTTPException(status_code=403, detail="Only coordinator can receive heartbeats")
    
    try:
        node = clustering_service.nodes.get(request.node_id)
        if not node:
            raise HTTPException(status_code=404, detail="Node not found")
        
        # Update node information
        node.status = NodeStatus(request.status)
        node.load_score = request.load_score
        node.cpu_usage = request.cpu_usage
        node.memory_usage = request.memory_usage
        node.tasks_completed = request.tasks_completed
        node.tasks_failed = request.tasks_failed
        node.last_heartbeat = from datetime import datetime
datetime.now()
        
        return {
            "success": True,
            "message": "Heartbeat received"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to process heartbeat from {request.node_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/promote_coordinator")
async def promote_to_coordinator():
    """Promote this node to cluster coordinator."""
    if not clustering_service:
        raise HTTPException(status_code=503, detail="Clustering service not initialized")
    
    try:
        success = await clustering_service.become_coordinator()
        
        if success:
            return {
                "success": True,
                "message": f"Node {clustering_service.node_id} promoted to coordinator"
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to become coordinator")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to promote to coordinator: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/config")
async def update_cluster_config(request: ClusterConfigRequest):
    """Update cluster configuration."""
    if not clustering_service:
        raise HTTPException(status_code=503, detail="Clustering service not initialized")
    
    if not clustering_service.is_coordinator:
        raise HTTPException(status_code=403, detail="Only coordinator can update cluster config")
    
    try:
        updated_fields = []
        
        if request.heartbeat_interval is not None:
            clustering_service.heartbeat_interval = request.heartbeat_interval
            updated_fields.append("heartbeat_interval")
        
        if request.task_timeout is not None:
            clustering_service.task_timeout = request.task_timeout
            updated_fields.append("task_timeout")
        
        if request.node_timeout is not None:
            clustering_service.node_timeout = request.node_timeout
            updated_fields.append("node_timeout")
        
        return {
            "success": True,
            "message": "Cluster configuration updated",
            "updated_fields": updated_fields
        }
        
    except Exception as e:
        logger.error(f"Failed to update cluster config: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/metrics")
async def get_cluster_metrics():
    """Get cluster performance metrics."""
    if not clustering_service:
        raise HTTPException(status_code=503, detail="Clustering service not initialized")
    
    try:
        # Calculate cluster-wide metrics
        total_nodes = len(clustering_service.nodes)
        online_nodes = sum(1 for node in clustering_service.nodes.values() if node.status == NodeStatus.ONLINE)
        
        total_cpu = sum(node.cpu_usage for node in clustering_service.nodes.values())
        total_memory = sum(node.memory_usage for node in clustering_service.nodes.values())
        total_load = sum(node.load_score for node in clustering_service.nodes.values())
        
        avg_cpu = total_cpu / total_nodes if total_nodes > 0 else 0
        avg_memory = total_memory / total_nodes if total_nodes > 0 else 0
        avg_load = total_load / total_nodes if total_nodes > 0 else 0
        
        # Task metrics
        total_tasks = len(clustering_service.tasks)
        completed_tasks = sum(1 for task in clustering_service.tasks.values() if task.status == TaskStatus.COMPLETED)
        failed_tasks = sum(1 for task in clustering_service.tasks.values() if task.status == TaskStatus.FAILED)
        running_tasks = sum(1 for task in clustering_service.tasks.values() if task.status == TaskStatus.RUNNING)
        
        success_rate = (completed_tasks / total_tasks * 100) if total_tasks > 0 else 0
        
        return {
            "success": True,
            "metrics": {
                "cluster_health": {
                    "total_nodes": total_nodes,
                    "online_nodes": online_nodes,
                    "offline_nodes": total_nodes - online_nodes,
                    "availability_percentage": (online_nodes / total_nodes * 100) if total_nodes > 0 else 0
                },
                "resource_utilization": {
                    "average_cpu_usage": avg_cpu,
                    "average_memory_usage": avg_memory,
                    "average_load_score": avg_load
                },
                "task_performance": {
                    "total_tasks": total_tasks,
                    "completed_tasks": completed_tasks,
                    "failed_tasks": failed_tasks,
                    "running_tasks": running_tasks,
                    "pending_tasks": total_tasks - completed_tasks - failed_tasks - running_tasks,
                    "success_rate_percentage": success_rate
                },
                "timestamp": from datetime import datetime
datetime.now().isoformat()
            }
        }
        
    except Exception as e:
        logger.error(f"Failed to get cluster metrics: {e}")
        raise HTTPException(status_code=500, detail=str(e))
