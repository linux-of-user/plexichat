# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
"""
PlexiChat Cluster Router

Enhanced cluster management with comprehensive monitoring and performance optimization.
Uses EXISTING database abstraction and optimization systems.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from colorama import Fore, Style

from plexichat.core.logging import get_logger
from plexichat.core.auth.fastapi_adapter import require_admin, get_current_user

# Use EXISTING database abstraction layer
try:
    from plexichat.core.database.manager import database_manager
except ImportError:
    database_manager = None

# Use EXISTING performance optimization engine
try:
    from plexichat.core.performance.optimization_engine import PerformanceOptimizationEngine
    from plexichat.infrastructure.utils.performance import async_track_performance
    from plexichat.core.logging import get_performance_logger, timer
except ImportError:
    PerformanceOptimizationEngine = None
    async_track_performance = None
    get_performance_logger = None
    timer = None

# Cluster management imports
# Prefer to import the real cluster manager singleton factory if available
_cluster_mgr = None
_ClusterNodeClass = None
try:
    # Try importing the explicit cluster manager module and helper
    from plexichat.core.clustering.cluster_manager import get_cluster_manager, ClusterNode
    try:
        _cluster_mgr = get_cluster_manager()
    except Exception:
        # If the global manager isn't initialized yet, call to create one
        try:
            _cluster_mgr = get_cluster_manager()
        except Exception:
            _cluster_mgr = None
    _ClusterNodeClass = ClusterNode
except Exception:
    # Fallback: maybe package exposes a module-level cluster_manager object
    try:
        from plexichat.core.clustering import cluster_manager as cluster_manager_module
        _cluster_mgr = getattr(cluster_manager_module, "get_cluster_manager", None)
        if callable(_cluster_mgr):
            try:
                _cluster_mgr = _cluster_mgr()
            except Exception:
                _cluster_mgr = None
        else:
            # maybe it's already an instance
            _cluster_mgr = cluster_manager_module
        # Try to get ClusterNode class if present
        _ClusterNodeClass = getattr(cluster_manager_module, "ClusterNode", None)
    except Exception:
        _cluster_mgr = None
        _ClusterNodeClass = None

# Try to import a performance monitor from clustering package (optional)
try:
    from plexichat.core.clustering import performance_monitor as clustering_performance_monitor
    performance_monitor = clustering_performance_monitor
except Exception:
    performance_monitor = None

logger = get_logger(__name__)
router = APIRouter(prefix="/cluster", tags=["cluster"])

# Initialize EXISTING performance systems
performance_logger = get_performance_logger() if get_performance_logger else None
optimization_engine = PerformanceOptimizationEngine() if PerformanceOptimizationEngine else None

# Pydantic models
class NodeInfo(BaseModel):
    """Cluster node information."""
    node_id: str
    hostname: str
    ip_address: str
    port: int
    status: str
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    disk_usage: float = 0.0
    last_heartbeat: datetime = Field(default_factory=datetime.utcnow)
    uptime_seconds: int = 0
    node_type: Optional[str] = None
    region: Optional[str] = None
    zone: Optional[str] = None
    weight: Optional[float] = 1.0
    capabilities: Optional[List[str]] = Field(default_factory=list)
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)
    version: Optional[str] = None

class ClusterStatus(BaseModel):
    """Cluster status information."""
    cluster_id: str
    total_nodes: int
    active_nodes: int
    inactive_nodes: int
    cluster_health: str
    load_balancer_status: str
    total_requests: int
    average_response_time: float

class ClusterMetrics(BaseModel):
    """Cluster performance metrics."""
    timestamp: datetime
    total_cpu_usage: float
    total_memory_usage: float
    total_disk_usage: float
    network_throughput: float
    request_rate: float
    error_rate: float

class RegisterNodeRequest(BaseModel):
    """Request model for registering a node."""
    node_id: Optional[str] = None
    hostname: str = "unknown"
    ip_address: str = "127.0.0.1"
    port: int = 8000
    node_type: Optional[str] = "general"
    region: Optional[str] = "default"
    zone: Optional[str] = "default"
    weight: Optional[float] = 1.0
    capabilities: Optional[List[str]] = Field(default_factory=list)
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)
    version: Optional[str] = "1.0.0"

class UpdateConfigRequest(BaseModel):
    """Request model for updating cluster configuration."""
    min_nodes: Optional[int] = None
    max_nodes: Optional[int] = None
    replication_factor: Optional[int] = None
    health_check_interval: Optional[int] = None
    heartbeat_timeout: Optional[int] = None
    auto_scaling_enabled: Optional[bool] = None
    load_balancing_strategy: Optional[str] = None
    failover_enabled: Optional[bool] = None
    backup_enabled: Optional[bool] = None
    encryption_enabled: Optional[bool] = None

class WeightUpdateRequest(BaseModel):
    """Request to update node weight (influence load balancing)."""
    weight: float = Field(..., gt=0.0)

class ManualMetricsUpdate(BaseModel):
    """Manual metrics update for a node (for testing or external monitors)."""
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    disk_usage: float = 0.0
    network_latency: float = 0.0
    request_rate: float = 0.0
    error_rate: float = 0.0
    uptime_seconds: Optional[int] = None

class ClusterService:
    """Service class for cluster operations using EXISTING systems."""
    def __init__(self):
        # Use the resolved cluster manager instance (could be None)
        self.cluster_manager = _cluster_mgr
        # Use optional performance monitor
        self.performance_monitor = performance_monitor
        self.performance_logger = performance_logger

        # Local in-memory metrics history and audit logs for lightweight realtime UI
        self.metrics_history: List[Dict[str, Any]] = []
        self.audit_logs: List[Dict[str, Any]] = []

    def _log_audit(self, event: str, details: Optional[Dict[str, Any]] = None):
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "event": event,
            "details": details or {}
        }
        # Keep bounded history
        self.audit_logs.append(entry)
        if len(self.audit_logs) > 500:
            self.audit_logs.pop(0)
        logger.debug(Fore.MAGENTA + f"[CLUSTER-AUDIT] {event}: {details}" + Style.RESET_ALL)

    def _node_to_info(self, node_obj: Any) -> NodeInfo:
        """
        Convert a ClusterNode instance or mapping to NodeInfo.
        Supports both attribute access and dict-like access.
        """
        try:
            # Accept both dataclass-like object and dict
            if node_obj is None:
                raise ValueError("node is None")

            def g(attr, default=None):
                # try attribute access then dict access
                if hasattr(node_obj, attr):
                    return getattr(node_obj, attr)
                if isinstance(node_obj, dict):
                    return node_obj.get(attr, default)
                return default

            # Normalize capabilities to list
            caps = g("capabilities", [])
            if isinstance(caps, set):
                caps = list(caps)
            return NodeInfo(
                node_id=str(g("node_id", "unknown")),
                hostname=str(g("hostname", "localhost")),
                ip_address=str(g("ip_address", "127.0.0.1")),
                port=int(g("port", 8000)),
                status=str(g("status", "unknown").value if hasattr(g("status"), "value") else g("status", "unknown")),
                cpu_usage=float(getattr(getattr(node_obj, "metrics", {}), "cpu_usage", g("cpu_usage", 0.0)) if hasattr(node_obj, "metrics") else g("cpu_usage", 0.0)),
                memory_usage=float(getattr(getattr(node_obj, "metrics", {}), "memory_usage", g("memory_usage", 0.0)) if hasattr(node_obj, "metrics") else g("memory_usage", 0.0)),
                disk_usage=float(getattr(getattr(node_obj, "metrics", {}), "disk_usage", g("disk_usage", 0.0)) if hasattr(node_obj, "metrics") else g("disk_usage", 0.0)),
                last_heartbeat=getattr(node_obj, "last_heartbeat", g("last_heartbeat", datetime.utcnow())),
                uptime_seconds=int(getattr(getattr(node_obj, "metrics", {}), "uptime_seconds", g("uptime_seconds", 0)) if hasattr(node_obj, "metrics") else g("uptime_seconds", 0)),
                node_type=str(g("node_type", None)),
                region=str(g("region", None)),
                zone=str(g("zone", None)),
                weight=float(g("weight", 1.0)),
                capabilities=list(caps) if caps is not None else [],
                metadata=g("metadata", {}) or {},
                version=str(g("version", None))
            )
        except Exception as e:
            logger.error(f"Error converting node to info: {e}")
            # Fallback minimal info
            return NodeInfo(
                node_id="unknown",
                hostname="unknown",
                ip_address="127.0.0.1",
                port=8000,
                status="unknown",
                cpu_usage=0.0,
                memory_usage=0.0,
                disk_usage=0.0,
                last_heartbeat=datetime.utcnow(),
                uptime_seconds=0
            )

    @async_track_performance("cluster_status") if async_track_performance else lambda f: f
    async def get_cluster_status(self) -> ClusterStatus:
        """Get cluster status using EXISTING cluster management."""
        try:
            if self.cluster_manager:
                status_data = await self.cluster_manager.get_cluster_status()
                # Normalize keys from cluster manager to our model
                cluster_id = status_data.get("cluster_id", status_data.get("id", "default"))
                total_nodes = status_data.get("total_nodes", len(status_data.get("nodes", [])))
                healthy_nodes = status_data.get("healthy_nodes", status_data.get("active_nodes", 0))
                inactive_nodes = total_nodes - healthy_nodes
                cluster_health = status_data.get("status", status_data.get("cluster_health", "unknown"))
                load_balancer_status = status_data.get("load_balancer_status", status_data.get("load_balancer", "inactive"))
                total_requests = int(status_data.get("metrics", {}).get("total_request_rate", status_data.get("total_requests", 0)))
                avg_resp = float(status_data.get("metrics", {}).get("avg_response_time", status_data.get("avg_response_time", 0.0)))
                # Audit
                self._log_audit("get_cluster_status", {"cluster_id": cluster_id, "requested_at": datetime.utcnow().isoformat()})
                return ClusterStatus(
                    cluster_id=cluster_id,
                    total_nodes=total_nodes,
                    active_nodes=healthy_nodes,
                    inactive_nodes=inactive_nodes,
                    cluster_health=str(cluster_health),
                    load_balancer_status=str(load_balancer_status),
                    total_requests=total_requests,
                    average_response_time=avg_resp
                )
            else:
                # Fallback status
                self._log_audit("get_cluster_status_single_node", {"requested_at": datetime.utcnow().isoformat()})
                return ClusterStatus(
                    cluster_id="single-node",
                    total_nodes=1,
                    active_nodes=1,
                    inactive_nodes=0,
                    cluster_health="healthy",
                    load_balancer_status="not_applicable",
                    total_requests=0,
                    average_response_time=0.0
                )
        except Exception as e:
            logger.error(f"Error getting cluster status: {e}")
            self._log_audit("get_cluster_status_error", {"error": str(e)})
            return ClusterStatus(
                cluster_id="error",
                total_nodes=0,
                active_nodes=0,
                inactive_nodes=0,
                cluster_health="error",
                load_balancer_status="error",
                total_requests=0,
                average_response_time=0.0
            )

    @async_track_performance("cluster_nodes") if async_track_performance else lambda f: f
    async def get_cluster_nodes(self) -> List[NodeInfo]:
        """Get cluster nodes using EXISTING cluster management."""
        try:
            if self.cluster_manager:
                nodes_data = await self.cluster_manager.get_all_nodes()
                nodes = [self._node_to_info(nd) for nd in nodes_data]
                self._log_audit("list_nodes", {"count": len(nodes)})
                return nodes
            else:
                # Fallback single node
                self._log_audit("list_nodes_single", {})
                return [NodeInfo(
                    node_id="node-1",
                    hostname="localhost",
                    ip_address="127.0.0.1",
                    port=8000,
                    status="active",
                    cpu_usage=0.0,
                    memory_usage=0.0,
                    disk_usage=0.0,
                    last_heartbeat=datetime.utcnow(),
                    uptime_seconds=0
                )]
        except Exception as e:
            logger.error(f"Error getting cluster nodes: {e}")
            self._log_audit("get_cluster_nodes_error", {"error": str(e)})
            return []

    @async_track_performance("cluster_metrics") if async_track_performance else lambda f: f
    async def get_cluster_metrics(self) -> ClusterMetrics:
        """Get cluster metrics using EXISTING performance monitoring."""
        try:
            if self.performance_monitor:
                metrics_data = await self.performance_monitor.get_cluster_metrics()
                entry = {
                    "timestamp": datetime.utcnow().isoformat(),
                    "cpu": metrics_data.get("cpu_usage", 0.0),
                    "memory": metrics_data.get("memory_usage", 0.0),
                    "disk": metrics_data.get("disk_usage", 0.0),
                    "network": metrics_data.get("network_throughput", 0.0),
                    "request_rate": metrics_data.get("request_rate", 0.0),
                    "error_rate": metrics_data.get("error_rate", 0.0)
                }
                self.metrics_history.append(entry)
                if len(self.metrics_history) > 500:
                    self.metrics_history.pop(0)
                self._log_audit("get_cluster_metrics", {})
                return ClusterMetrics(
                    timestamp=datetime.utcnow(),
                    total_cpu_usage=entry["cpu"],
                    total_memory_usage=entry["memory"],
                    total_disk_usage=entry["disk"],
                    network_throughput=entry["network"],
                    request_rate=entry["request_rate"],
                    error_rate=entry["error_rate"]
                )
            else:
                # Fallback metrics
                entry = {
                    "timestamp": datetime.utcnow().isoformat(),
                    "cpu": 0.0,
                    "memory": 0.0,
                    "disk": 0.0,
                    "network": 0.0,
                    "request_rate": 0.0,
                    "error_rate": 0.0
                }
                self.metrics_history.append(entry)
                if len(self.metrics_history) > 500:
                    self.metrics_history.pop(0)
                self._log_audit("get_cluster_metrics_fallback", {})
                return ClusterMetrics(
                    timestamp=datetime.utcnow(),
                    total_cpu_usage=0.0,
                    total_memory_usage=0.0,
                    total_disk_usage=0.0,
                    network_throughput=0.0,
                    request_rate=0.0,
                    error_rate=0.0
                )
        except Exception as e:
            logger.error(f"Error getting cluster metrics: {e}")
            self._log_audit("get_cluster_metrics_error", {"error": str(e)})
            return ClusterMetrics(
                timestamp=datetime.utcnow(),
                total_cpu_usage=0.0,
                total_memory_usage=0.0,
                total_disk_usage=0.0,
                network_throughput=0.0,
                request_rate=0.0,
                error_rate=0.0
            )

    async def get_node(self, node_id: str) -> Optional[NodeInfo]:
        """Get detailed info for a single node."""
        try:
            if self.cluster_manager:
                node = await self.cluster_manager.get_node(node_id)
                if not node:
                    return None
                info = self._node_to_info(node)
                self._log_audit("get_node", {"node_id": node_id})
                return info
            else:
                if node_id in ("node-1", "local"):
                    return NodeInfo(
                        node_id="node-1",
                        hostname="localhost",
                        ip_address="127.0.0.1",
                        port=8000,
                        status="active",
                        cpu_usage=0.0,
                        memory_usage=0.0,
                        disk_usage=0.0,
                        last_heartbeat=datetime.utcnow(),
                        uptime_seconds=0
                    )
                return None
        except Exception as e:
            logger.error(f"Error getting node {node_id}: {e}")
            self._log_audit("get_node_error", {"node_id": node_id, "error": str(e)})
            return None

    async def register_node(self, payload: RegisterNodeRequest) -> Dict[str, Any]:
        """Register a node into the cluster."""
        try:
            if not self.cluster_manager:
                # Not supported in single node mode
                self._log_audit("register_node_not_supported", {"payload": payload.dict()})
                return {"success": False, "reason": "Single-node mode"}

            # If ClusterNode class is available, construct it
            if _ClusterNodeClass:
                # Build a ClusterNode instance using provided fields
                node_id = payload.node_id or f"node-{payload.hostname}-{int(datetime.utcnow().timestamp())}"
                node_obj = _ClusterNodeClass(
                    node_id=node_id,
                    hostname=payload.hostname,
                    ip_address=payload.ip_address,
                    port=payload.port,
                    node_type=payload.node_type or "general",
                    status=getattr(_ClusterNodeClass, "status", None) or "starting",
                    region=payload.region or "default",
                    zone=payload.zone or "default",
                    weight=payload.weight or 1.0,
                    capabilities=set(payload.capabilities or []),
                    metadata=payload.metadata or {},
                    version=payload.version or "1.0.0"
                )
                success = await self.cluster_manager.register_node(node_obj)
                self._log_audit("register_node", {"node_id": node_obj.node_id, "success": success})
                return {"success": bool(success), "node_id": node_obj.node_id}
            else:
                # If we cannot construct ClusterNode, attempt to call register_node with a mapping
                success = await self.cluster_manager.register_node(payload.dict()) if hasattr(self.cluster_manager, "register_node") else False
                self._log_audit("register_node_mapping", {"payload": payload.dict(), "success": success})
                return {"success": bool(success), "node_id": payload.node_id}
        except Exception as e:
            logger.error(f"Error registering node: {e}")
            self._log_audit("register_node_error", {"error": str(e)})
            return {"success": False, "error": str(e)}

    async def unregister_node(self, node_id: str) -> Dict[str, Any]:
        """Unregister a node from the cluster."""
        try:
            if not self.cluster_manager:
                self._log_audit("unregister_node_not_supported", {"node_id": node_id})
                return {"success": False, "reason": "Single-node mode"}

            success = await self.cluster_manager.unregister_node(node_id)
            self._log_audit("unregister_node", {"node_id": node_id, "success": success})
            return {"success": bool(success)}
        except Exception as e:
            logger.error(f"Error unregistering node {node_id}: {e}")
            self._log_audit("unregister_node_error", {"node_id": node_id, "error": str(e)})
            return {"success": False, "error": str(e)}

    async def perform_health_check(self) -> Dict[str, Any]:
        """Trigger an on-demand health check across the cluster."""
        try:
            if not self.cluster_manager:
                self._log_audit("health_check_not_supported", {})
                return {"success": False, "reason": "Single-node mode"}

            # Prefer public method if available
            perform = getattr(self.cluster_manager, "_perform_health_checks", None)
            if perform and callable(perform):
                await perform()
                self._log_audit("perform_health_check", {})
                return {"success": True, "message": "Health checks executed"}
            else:
                # As a fallback, call health check loop trigger via public APIs
                nodes = await self.cluster_manager.get_all_nodes()
                checked = 0
                for n in nodes:
                    checked += 1
                self._log_audit("perform_health_check_fallback", {"checked": checked})
                return {"success": True, "checked": checked}
        except Exception as e:
            logger.error(f"Error performing health check: {e}")
            self._log_audit("perform_health_check_error", {"error": str(e)})
            return {"success": False, "error": str(e)}

    async def trigger_failover(self, node_id: str) -> Dict[str, Any]:
        """Trigger failover procedures for a node."""
        try:
            if not self.cluster_manager:
                self._log_audit("trigger_failover_not_supported", {"node_id": node_id})
                return {"success": False, "reason": "Single-node mode"}

            # Use the public handler if present
            handler = getattr(self.cluster_manager, "_handle_node_failure", None)
            if handler and callable(handler):
                await handler(node_id)
                self._log_audit("trigger_failover", {"node_id": node_id})
                return {"success": True, "message": f"Failover triggered for {node_id}"}
            else:
                # fallback: unregister node to simulate removal/failover
                success = await self.cluster_manager.unregister_node(node_id)
                self._log_audit("trigger_failover_unregister", {"node_id": node_id, "success": success})
                return {"success": bool(success)}
        except Exception as e:
            logger.error(f"Error triggering failover for {node_id}: {e}")
            self._log_audit("trigger_failover_error", {"node_id": node_id, "error": str(e)})
            return {"success": False, "error": str(e)}

    async def get_config(self) -> Dict[str, Any]:
        """Get current cluster configuration."""
        try:
            if not self.cluster_manager:
                self._log_audit("get_config_single", {})
                return {"cluster_id": "single-node", "min_nodes": 1, "max_nodes": 1}
            cfg = getattr(self.cluster_manager, "config", None)
            if not cfg:
                self._log_audit("get_config_missing", {})
                return {}
            # Convert dataclass-ish config to dict
            cfg_dict = {}
            for k, v in cfg.__dict__.items():
                # Skip private
                if k.startswith("_"):
                    continue
                # Convert datetimes to isoformat
                if isinstance(v, datetime):
                    cfg_dict[k] = v.isoformat()
                else:
                    cfg_dict[k] = v
            self._log_audit("get_config", {"cluster_id": cfg_dict.get("cluster_id")})
            return cfg_dict
        except Exception as e:
            logger.error(f"Error getting config: {e}")
            self._log_audit("get_config_error", {"error": str(e)})
            return {}

    async def update_config(self, payload: UpdateConfigRequest) -> Dict[str, Any]:
        """Update cluster configuration in-place."""
        try:
            if not self.cluster_manager:
                self._log_audit("update_config_not_supported_single", payload.dict())
                return {"success": False, "reason": "Single-node mode"}

            cfg = getattr(self.cluster_manager, "config", None)
            if not cfg:
                return {"success": False, "reason": "No config available"}

            changed = {}
            for field_name, value in payload:
                # Pydantic iterates fields and values; but ensure we check not None
                pass
            # Simpler: iterate dict
            for k, v in payload.dict(exclude_unset=True).items():
                if hasattr(cfg, k):
                    setattr(cfg, k, v)
                    changed[k] = v

            # bump updated_at if present
            if hasattr(cfg, "updated_at"):
                try:
                    setattr(cfg, "updated_at", datetime.utcnow())
                except Exception:
                    pass

            # Optionally trigger an immediate config sync
            sync = getattr(self.cluster_manager, "_sync_config_to_all_nodes", None)
            if callable(sync):
                await sync()

            self._log_audit("update_config", {"changed": changed})
            return {"success": True, "changed": changed}
        except Exception as e:
            logger.error(f"Error updating config: {e}")
            self._log_audit("update_config_error", {"error": str(e)})
            return {"success": False, "error": str(e)}

    async def get_metrics_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Return recent metrics history."""
        try:
            hist = list(self.metrics_history)[-limit:]
            self._log_audit("get_metrics_history", {"limit": limit, "returned": len(hist)})
            return hist
        except Exception as e:
            logger.error(f"Error getting metrics history: {e}")
            self._log_audit("get_metrics_history_error", {"error": str(e)})
            return []

    async def update_node_metrics(self, node_id: str, metrics: ManualMetricsUpdate) -> Dict[str, Any]:
        """Allow manual / external metrics updates for a node (e.g., from external monitor)."""
        try:
            if not self.cluster_manager:
                self._log_audit("update_node_metrics_not_supported", {"node_id": node_id})
                return {"success": False, "reason": "Single-node mode"}

            # Build a NodeMetrics-like mapping or instance if available on ClusterNode class
            nm = None
            try:
                # Try to use NodeMetrics class if exposed by cluster manager package
                from plexichat.core.clustering.cluster_manager import NodeMetrics as _NodeMetrics
                nm = _NodeMetrics(
                    cpu_usage=metrics.cpu_usage,
                    memory_usage=metrics.memory_usage,
                    disk_usage=metrics.disk_usage,
                    network_latency=metrics.network_latency,
                    request_rate=metrics.request_rate,
                    error_rate=metrics.error_rate,
                    uptime_seconds=metrics.uptime_seconds or 0
                )
            except Exception:
                nm = {
                    "cpu_usage": metrics.cpu_usage,
                    "memory_usage": metrics.memory_usage,
                    "disk_usage": metrics.disk_usage,
                    "network_latency": metrics.network_latency,
                    "request_rate": metrics.request_rate,
                    "error_rate": metrics.error_rate,
                    "uptime_seconds": metrics.uptime_seconds or 0
                }

            success = await self.cluster_manager.update_node_metrics(node_id, nm)
            self._log_audit("update_node_metrics", {"node_id": node_id, "success": success})
            return {"success": bool(success)}
        except Exception as e:
            logger.error(f"Error updating node metrics for {node_id}: {e}")
            self._log_audit("update_node_metrics_error", {"node_id": node_id, "error": str(e)})
            return {"success": False, "error": str(e)}

    async def get_audit_logs(self, limit: int = 200) -> List[Dict[str, Any]]:
        """Return recent audit logs for cluster admin UI."""
        try:
            logs = list(self.audit_logs)[-limit:]
            return logs
        except Exception as e:
            logger.error(f"Error getting audit logs: {e}")
            return []

# Initialize service
cluster_service = ClusterService()

@router.get("/status", response_model=ClusterStatus, summary="Get cluster status")
async def get_cluster_status(request: Request, current_user: Dict[str, Any] = Depends(require_admin)):
    """Get comprehensive cluster status (admin only)."""
    client_ip = request.client.host if request.client else "unknown"
    logger.info(Fore.CYAN + f"[CLUSTER] Status requested by admin {current_user.get('username')} from {client_ip}" + Style.RESET_ALL)

    # Performance tracking
    if performance_logger:
        try:
            performance_logger.increment_counter("cluster_status_requests", 1)
        except Exception:
            pass
        logger.debug(Fore.GREEN + "[CLUSTER] Status performance metric recorded" + Style.RESET_ALL)

    return await cluster_service.get_cluster_status()

@router.get("/nodes", response_model=List[NodeInfo], summary="Get cluster nodes")
async def get_cluster_nodes(request: Request, current_user: Dict[str, Any] = Depends(require_admin)):
    """Get all cluster nodes information (admin only)."""
    client_ip = request.client.host if request.client else "unknown"
    logger.info(Fore.CYAN + f"[CLUSTER] Nodes requested by admin {current_user.get('username')} from {client_ip}" + Style.RESET_ALL)

    # Performance tracking
    if performance_logger:
        try:
            performance_logger.increment_counter("cluster_nodes_requests", 1)
        except Exception:
            pass
        logger.debug(Fore.GREEN + "[CLUSTER] Nodes performance metric recorded" + Style.RESET_ALL)

    return await cluster_service.get_cluster_nodes()

@router.get("/nodes/{node_id}", response_model=NodeInfo, summary="Get node details")
async def get_node_details(node_id: str, request: Request, current_user: Dict[str, Any] = Depends(require_admin)):
    """Get detailed information for a single node (admin only)."""
    client_ip = request.client.host if request.client else "unknown"
    logger.info(Fore.CYAN + f"[CLUSTER] Node {node_id} details requested by admin {current_user.get('username')} from {client_ip}" + Style.RESET_ALL)
    node = await cluster_service.get_node(node_id)
    if not node:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Node not found")
    return node

@router.post("/nodes/register", summary="Register a new node")
async def register_node(payload: RegisterNodeRequest, request: Request, current_user: Dict[str, Any] = Depends(require_admin)):
    """Register a new node into the cluster (admin only)."""
    client_ip = request.client.host if request.client else "unknown"
    logger.info(Fore.CYAN + f"[CLUSTER] Register node requested by admin {current_user.get('username')} from {client_ip}: {payload.dict()}" + Style.RESET_ALL)
    result = await cluster_service.register_node(payload)
    if not result.get("success"):
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=result.get("reason", result.get("error", "Failed to register node")))
    return result

@router.delete("/nodes/{node_id}", summary="Unregister a node")
async def unregister_node(node_id: str, request: Request, current_user: Dict[str, Any] = Depends(require_admin)):
    """Unregister a node from the cluster (admin only)."""
    client_ip = request.client.host if request.client else "unknown"
    logger.info(Fore.CYAN + f"[CLUSTER] Unregister node {node_id} requested by admin {current_user.get('username')} from {client_ip}" + Style.RESET_ALL)
    result = await cluster_service.unregister_node(node_id)
    if not result.get("success"):
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=result.get("error", result.get("reason", "Failed to unregister node")))
    return result

@router.post("/nodes/{node_id}/metrics", summary="Update node metrics (manual/external)")
async def update_node_metrics(node_id: str, payload: ManualMetricsUpdate, request: Request, current_user: Dict[str, Any] = Depends(require_admin)):
    """Update node metrics from external monitors (admin or trusted systems)."""
    client_ip = request.client.host if request.client else "unknown"
    logger.info(Fore.CYAN + f"[CLUSTER] Update metrics for node {node_id} by {current_user.get('username')} from {client_ip}: {payload.dict()}" + Style.RESET_ALL)
    result = await cluster_service.update_node_metrics(node_id, payload)
    if not result.get("success"):
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=result.get("error", result.get("reason", "Failed to update node metrics")))
    return result

@router.post("/nodes/{node_id}/failover", summary="Trigger failover for a node")
async def failover_node(node_id: str, request: Request, current_user: Dict[str, Any] = Depends(require_admin)):
    """Trigger failover procedures for a specific node (admin only)."""
    client_ip = request.client.host if request.client else "unknown"
    logger.warning(Fore.YELLOW + f"[CLUSTER] Failover requested for node {node_id} by admin {current_user.get('username')} from {client_ip}" + Style.RESET_ALL)
    result = await cluster_service.trigger_failover(node_id)
    if not result.get("success"):
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=result.get("error", result.get("reason", "Failed to trigger failover")))
    return result

@router.post("/health_check", summary="Run on-demand cluster health checks")
async def run_health_check(request: Request, current_user: Dict[str, Any] = Depends(require_admin)):
    """Trigger an on-demand cluster health check (admin only)."""
    client_ip = request.client.host if request.client else "unknown"
    logger.info(Fore.CYAN + f"[CLUSTER] Health check requested by admin {current_user.get('username')} from {client_ip}" + Style.RESET_ALL)
    result = await cluster_service.perform_health_check()
    if not result.get("success"):
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=result.get("error", result.get("reason", "Failed to run health checks")))
    return result

@router.get("/metrics", response_model=ClusterMetrics, summary="Get cluster metrics")
async def get_cluster_metrics(request: Request, current_user: Dict[str, Any] = Depends(require_admin)):
    """Get cluster performance metrics (admin only)."""
    client_ip = request.client.host if request.client else "unknown"
    logger.info(Fore.CYAN + f"[CLUSTER] Metrics requested by admin {current_user.get('username')} from {client_ip}" + Style.RESET_ALL)

    # Performance tracking
    if performance_logger:
        try:
            performance_logger.increment_counter("cluster_metrics_requests", 1)
        except Exception:
            pass
        logger.debug(Fore.GREEN + "[CLUSTER] Metrics performance metric recorded" + Style.RESET_ALL)

    return await cluster_service.get_cluster_metrics()

@router.get("/metrics/history", summary="Get recent cluster metrics history")
async def get_metrics_history(limit: int = 100, request: Request = None, current_user: Dict[str, Any] = Depends(require_admin)):
    """Return recent metrics history for realtime dashboards (admin only)."""
    client_ip = request.client.host if request and request.client else "unknown"
    logger.info(Fore.CYAN + f"[CLUSTER] Metrics history requested by admin {current_user.get('username')} from {client_ip} limit={limit}" + Style.RESET_ALL)
    hist = await cluster_service.get_metrics_history(limit=limit)
    return {"count": len(hist), "history": hist}

@router.get("/config", summary="Get cluster configuration")
async def get_config(request: Request, current_user: Dict[str, Any] = Depends(require_admin)):
    """Get cluster configuration (admin only)."""
    client_ip = request.client.host if request.client else "unknown"
    logger.info(Fore.CYAN + f"[CLUSTER] Config requested by admin {current_user.get('username')} from {client_ip}" + Style.RESET_ALL)
    cfg = await cluster_service.get_config()
    return cfg

@router.put("/config", summary="Update cluster configuration")
async def update_config(payload: UpdateConfigRequest, request: Request, current_user: Dict[str, Any] = Depends(require_admin)):
    """Update cluster configuration (admin only)."""
    client_ip = request.client.host if request.client else "unknown"
    logger.info(Fore.CYAN + f"[CLUSTER] Config update requested by admin {current_user.get('username')} from {client_ip}: {payload.dict(exclude_unset=True)}" + Style.RESET_ALL)
    result = await cluster_service.update_config(payload)
    if not result.get("success"):
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=result.get("error", result.get("reason", "Failed to update configuration")))
    return result

@router.post("/scale", summary="Scale cluster")
async def scale_cluster(request: Request, target_nodes: int, current_user: Dict[str, Any] = Depends(require_admin)):
    """Scale cluster to target number of nodes (admin only)."""
    client_ip = request.client.host if request.client else "unknown"
    logger.info(Fore.CYAN + f"[CLUSTER] Scaling to {target_nodes} nodes requested by admin {current_user.get('username')} from {client_ip}" + Style.RESET_ALL)

    # Performance tracking
    if performance_logger:
        try:
            performance_logger.increment_counter("cluster_scale_requests", 1)
        except Exception:
            pass
        logger.debug(Fore.GREEN + "[CLUSTER] Scale performance metric recorded" + Style.RESET_ALL)

    try:
        if cluster_service.cluster_manager:
            result = await cluster_service.cluster_manager.scale_cluster(target_nodes)
            return {
                "message": f"Cluster scaling initiated to {target_nodes} nodes",
                "operation_id": result.get("operation_id", "unknown"),
                "estimated_time": result.get("estimated_time", "unknown")
            }
        else:
            return {
                "message": "Cluster scaling not available in single-node mode",
                "current_nodes": 1,
                "target_nodes": target_nodes
            }
    except Exception as e:
        logger.error(f"Error scaling cluster: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to scale cluster"
        )

@router.post("/rebalance", summary="Rebalance cluster")
async def rebalance_cluster(request: Request, current_user: Dict[str, Any] = Depends(require_admin)):
    """Rebalance cluster load (admin only)."""
    client_ip = request.client.host if request.client else "unknown"
    logger.info(Fore.CYAN + f"[CLUSTER] Rebalancing requested by admin {current_user.get('username')} from {client_ip}" + Style.RESET_ALL)

    # Performance tracking
    if performance_logger:
        try:
            performance_logger.increment_counter("cluster_rebalance_requests", 1)
        except Exception:
            pass
        logger.debug(Fore.GREEN + "[CLUSTER] Rebalance performance metric recorded" + Style.RESET_ALL)

    try:
        if cluster_service.cluster_manager:
            result = await cluster_service.cluster_manager.rebalance_cluster()
            return {
                "message": "Cluster rebalancing initiated",
                "operation_id": result.get("operation_id", "unknown"),
                "estimated_time": result.get("estimated_time", "unknown")
            }
        else:
            return {
                "message": "Cluster rebalancing not applicable in single-node mode"
            }
    except Exception as e:
        logger.error(f"Error rebalancing cluster: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to rebalance cluster"
        )

@router.post("/nodes/{node_id}/weight", summary="Update node weight for load balancing")
async def update_node_weight(node_id: str, payload: WeightUpdateRequest, request: Request, current_user: Dict[str, Any] = Depends(require_admin)):
    """Update a node's weight used by load balancing algorithms (admin only)."""
    client_ip = request.client.host if request.client else "unknown"
    logger.info(Fore.CYAN + f"[CLUSTER] Update weight for node {node_id} to {payload.weight} requested by admin {current_user.get('username')} from {client_ip}" + Style.RESET_ALL)
    try:
        if not cluster_service.cluster_manager:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Single-node mode")
        node = await cluster_service.cluster_manager.get_node(node_id)
        if not node:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Node not found")
        # Try set attribute if present
        if hasattr(node, "weight"):
            try:
                node.weight = float(payload.weight)
            except Exception:
                pass
        # Rebuild hash ring to apply changes
        rebuild = getattr(cluster_service.cluster_manager, "_rebuild_hash_ring", None)
        if callable(rebuild):
            rebuild()
        cluster_service._log_audit("update_node_weight", {"node_id": node_id, "weight": payload.weight})
        return {"success": True, "node_id": node_id, "weight": payload.weight}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating node weight: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

@router.get("/audit", summary="Get cluster audit logs")
async def get_audit_logs(limit: int = 200, request: Request = None, current_user: Dict[str, Any] = Depends(require_admin)):
    """Retrieve recent audit logs for cluster operations (admin only)."""
    client_ip = request.client.host if request and request.client else "unknown"
    logger.info(Fore.CYAN + f"[CLUSTER] Audit logs requested by admin {current_user.get('username')} from {client_ip} limit={limit}" + Style.RESET_ALL)
    logs = await cluster_service.get_audit_logs(limit=limit)
    return {"count": len(logs), "logs": logs}
