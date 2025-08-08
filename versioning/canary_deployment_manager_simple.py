import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


class CanaryStrategy(Enum):
    """Canary deployment strategies."""
    PERCENTAGE = "percentage"
    FIXED_COUNT = "fixed_count"
    GEOGRAPHIC = "geographic"
    USER_BASED = "user_based"


class DeploymentPhase(Enum):
    """Deployment phases."""
    PREPARATION = "preparation"
    CANARY = "canary"
    MONITORING = "monitoring"
    EVALUATION = "evaluation"
    ROLLOUT = "rollout"
    COMPLETE = "complete"
    ROLLBACK = "rollback"


@dataclass
class CanaryNode:
    """Canary deployment node."""
    node_id: str
    endpoint: str
    region: str = "default"
    capacity: int = 100
    current_load: float = 0.0
    health_status: str = "healthy"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DeploymentPlan:
    """Canary deployment plan."""
    plan_id: str
    version: str
    strategy: CanaryStrategy
    phases: List[Dict[str, Any]] = field(default_factory=list)
    rollback_plan: Optional[Dict[str, Any]] = None
    health_checks: List[Dict[str, Any]] = field(default_factory=list)
    success_criteria: Dict[str, Any] = field(default_factory=dict)
    timeout_minutes: int = 60
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class DeploymentResult:
    """Deployment result."""
    deployment_id: str
    plan_id: str
    status: str
    phase: DeploymentPhase
    nodes_deployed: List[str] = field(default_factory=list)
    health_metrics: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None


class CanaryDeploymentManager:
    """Simplified canary deployment manager."""
    
    def __init__(self):
        self.active_deployments: Dict[str, DeploymentResult] = {}
        self.deployment_plans: Dict[str, DeploymentPlan] = {}
        self.available_nodes: List[CanaryNode] = []
        self.monitoring_tasks: Dict[str, asyncio.Task] = {}
        
    async def create_deployment_plan(self, version: str, strategy: CanaryStrategy,
                                   config: Optional[Dict[str, Any]] = None) -> DeploymentPlan:
        """Create a new deployment plan."""
        plan_id = f"plan_{int(time.time())}"
        
        plan = DeploymentPlan(
            plan_id=plan_id,
            version=version,
            strategy=strategy,
            phases=self._generate_phases(strategy, config or {}),
            rollback_plan=self._create_rollback_plan(version),
            health_checks=self._create_health_checks(config or {}),
            success_criteria=self._create_success_criteria(config or {}),
            timeout_minutes=config.get("timeout_minutes", 60) if config else 60
        )
        
        self.deployment_plans[plan_id] = plan
        logger.info(f"Created deployment plan {plan_id} for version {version}")
        return plan
    
    async def execute_deployment(self, plan_id: str) -> DeploymentResult:
        """Execute a deployment plan."""
        if plan_id not in self.deployment_plans:
            raise ValueError(f"Deployment plan {plan_id} not found")
        
        plan = self.deployment_plans[plan_id]
        deployment_id = f"deploy_{int(time.time())}"
        
        result = DeploymentResult(
            deployment_id=deployment_id,
            plan_id=plan_id,
            status="running",
            phase=DeploymentPhase.PREPARATION
        )
        
        self.active_deployments[deployment_id] = result
        
        try:
            # Execute deployment phases
            for phase_config in plan.phases:
                await self._execute_phase(result, phase_config)
                
                if result.status == "failed":
                    break
            
            if result.status != "failed":
                result.status = "completed"
                result.phase = DeploymentPhase.COMPLETE
                
        except Exception as e:
            logger.error(f"Deployment {deployment_id} failed: {e}")
            result.status = "failed"
            result.errors.append(str(e))
            
        result.completed_at = datetime.now(timezone.utc)
        logger.info(f"Deployment {deployment_id} completed with status: {result.status}")
        return result
    
    async def rollback_deployment(self, deployment_id: str) -> bool:
        """Rollback a deployment."""
        if deployment_id not in self.active_deployments:
            return False
        
        result = self.active_deployments[deployment_id]
        result.phase = DeploymentPhase.ROLLBACK
        
        try:
            # Stop monitoring
            if deployment_id in self.monitoring_tasks:
                self.monitoring_tasks[deployment_id].cancel()
                del self.monitoring_tasks[deployment_id]
            
            # Execute rollback
            await self._execute_rollback(result)
            
            result.status = "rolled_back"
            logger.info(f"Successfully rolled back deployment {deployment_id}")
            return True
            
        except Exception as e:
            logger.error(f"Rollback failed for deployment {deployment_id}: {e}")
            result.errors.append(f"Rollback failed: {e}")
            return False
    
    def _generate_phases(self, strategy: CanaryStrategy, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate deployment phases based on strategy."""
        phases = []
        
        if strategy == CanaryStrategy.PERCENTAGE:
            percentages = config.get("percentages", [10, 25, 50, 100])
            for percentage in percentages:
                phases.append({
                    "type": "canary",
                    "percentage": percentage,
                    "duration_minutes": config.get("phase_duration", 15)
                })
        
        elif strategy == CanaryStrategy.FIXED_COUNT:
            counts = config.get("node_counts", [1, 3, 5])
            for count in counts:
                phases.append({
                    "type": "canary",
                    "node_count": count,
                    "duration_minutes": config.get("phase_duration", 15)
                })
        
        return phases
    
    def _create_rollback_plan(self, version: str) -> Dict[str, Any]:
        """Create rollback plan."""
        return {
            "strategy": "immediate",
            "target_version": "previous",
            "timeout_minutes": 10
        }
    
    def _create_health_checks(self, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Create health check configurations."""
        return [
            {
                "type": "http",
                "endpoint": "/health",
                "expected_status": 200,
                "timeout_seconds": 5
            },
            {
                "type": "metrics",
                "metric": "error_rate",
                "threshold": 0.05
            }
        ]
    
    def _create_success_criteria(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Create success criteria."""
        return {
            "max_error_rate": config.get("max_error_rate", 0.05),
            "min_success_rate": config.get("min_success_rate", 0.95),
            "max_response_time": config.get("max_response_time", 1000)
        }
    
    async def _execute_phase(self, result: DeploymentResult, phase_config: Dict[str, Any]):
        """Execute a deployment phase."""
        logger.info(f"Executing phase: {phase_config}")
        
        # Select nodes for this phase
        nodes = await self._select_nodes_for_phase(phase_config)
        
        # Deploy to selected nodes
        await self._deploy_to_nodes(result, nodes)
        
        # Monitor health
        await self._monitor_phase_health(result, phase_config)
    
    async def _select_nodes_for_phase(self, phase_config: Dict[str, Any]) -> List[CanaryNode]:
        """Select nodes for deployment phase."""
        if "percentage" in phase_config:
            count = max(1, int(len(self.available_nodes) * phase_config["percentage"] / 100))
        elif "node_count" in phase_config:
            count = min(phase_config["node_count"], len(self.available_nodes))
        else:
            count = 1
        
        return self.available_nodes[:count]
    
    async def _deploy_to_nodes(self, result: DeploymentResult, nodes: List[CanaryNode]):
        """Deploy to selected nodes."""
        for node in nodes:
            try:
                # Simulate deployment
                await asyncio.sleep(0.1)
                result.nodes_deployed.append(node.node_id)
                logger.debug(f"Deployed to node {node.node_id}")
            except Exception as e:
                result.errors.append(f"Failed to deploy to {node.node_id}: {e}")
    
    async def _monitor_phase_health(self, result: DeploymentResult, phase_config: Dict[str, Any]):
        """Monitor health during phase."""
        duration = phase_config.get("duration_minutes", 15)
        end_time = datetime.now(timezone.utc) + timedelta(minutes=duration)
        
        while datetime.now(timezone.utc) < end_time:
            # Simulate health monitoring
            await asyncio.sleep(10)
            
            # Check if deployment should fail
            if len(result.errors) > 3:
                result.status = "failed"
                break
    
    async def _execute_rollback(self, result: DeploymentResult):
        """Execute rollback procedure."""
        for node_id in result.nodes_deployed:
            try:
                # Simulate rollback
                await asyncio.sleep(0.1)
                logger.debug(f"Rolled back node {node_id}")
            except Exception as e:
                result.errors.append(f"Failed to rollback {node_id}: {e}")
    
    def get_deployment_status(self, deployment_id: str) -> Optional[DeploymentResult]:
        """Get deployment status."""
        return self.active_deployments.get(deployment_id)
    
    def list_active_deployments(self) -> List[DeploymentResult]:
        """List all active deployments."""
        return list(self.active_deployments.values())
    
    async def cleanup_completed_deployments(self):
        """Cleanup completed deployments."""
        to_remove = []
        for deployment_id, result in self.active_deployments.items():
            if result.status in ["completed", "failed", "rolled_back"]:
                if result.completed_at and (datetime.now(timezone.utc) - result.completed_at).days > 7:
                    to_remove.append(deployment_id)
        
        for deployment_id in to_remove:
            del self.active_deployments[deployment_id]
            logger.info(f"Cleaned up deployment {deployment_id}")


# Global instance
_canary_manager: Optional[CanaryDeploymentManager] = None


def get_canary_deployment_manager() -> CanaryDeploymentManager:
    """Get the global canary deployment manager."""
    global _canary_manager
    if _canary_manager is None:
        _canary_manager = CanaryDeploymentManager()
    return _canary_manager
