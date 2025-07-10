"""
PlexiChat Canary Deployment Manager

Advanced canary deployment system for staged rollouts with:
- Intelligent node selection for canary deployments
- Real-time health monitoring during rollouts
- Automatic rollback on failure detection
- Progressive rollout strategies
- A/B testing capabilities
- Performance impact analysis
"""

import asyncio
import json
from enum import Enum
from typing import Dict, List, Optional, Any, Set, Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class CanaryStrategy(Enum):
    """Canary deployment strategies."""
    PERCENTAGE_BASED = "percentage_based"
    NODE_COUNT_BASED = "node_count_based"
    GEOGRAPHIC_BASED = "geographic_based"
    LOAD_BASED = "load_based"
    CUSTOM = "custom"


class CanaryPhase(Enum):
    """Phases of canary deployment."""
    PREPARING = "preparing"
    SELECTING_NODES = "selecting_nodes"
    DEPLOYING = "deploying"
    MONITORING = "monitoring"
    EVALUATING = "evaluating"
    EXPANDING = "expanding"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLING_BACK = "rolling_back"


class HealthCheckType(Enum):
    """Types of health checks."""
    HTTP_ENDPOINT = "http_endpoint"
    PERFORMANCE_METRICS = "performance_metrics"
    ERROR_RATE = "error_rate"
    RESPONSE_TIME = "response_time"
    RESOURCE_USAGE = "resource_usage"
    CUSTOM_METRIC = "custom_metric"


@dataclass
class CanaryNode:
    """Node selected for canary deployment."""
    node_id: str
    node_type: str
    region: str
    load_factor: float
    health_score: float
    deployment_time: Optional[datetime] = None
    health_checks: Dict[str, Any] = field(default_factory=dict)
    metrics: Dict[str, float] = field(default_factory=dict)
    
    @property
    def is_healthy(self) -> bool:
        """Check if node is healthy."""
        return self.health_score >= 0.8  # 80% health threshold


@dataclass
class HealthCheck:
    """Health check configuration."""
    check_type: HealthCheckType
    endpoint: Optional[str] = None
    metric_name: Optional[str] = None
    threshold: float = 0.0
    comparison: str = "greater_than"  # greater_than, less_than, equals
    timeout_seconds: int = 30
    interval_seconds: int = 60
    
    def evaluate(self, value: float) -> bool:
        """Evaluate health check."""
        if self.comparison == "greater_than":
            return value > self.threshold
        elif self.comparison == "less_than":
            return value < self.threshold
        elif self.comparison == "equals":
            return abs(value - self.threshold) < 0.001
        return False


@dataclass
class CanaryDeploymentPlan:
    """Canary deployment plan."""
    deployment_id: str
    update_id: str
    strategy: CanaryStrategy
    phases: List[Dict[str, Any]] = field(default_factory=list)
    health_checks: List[HealthCheck] = field(default_factory=list)
    success_criteria: Dict[str, float] = field(default_factory=dict)
    rollback_triggers: List[str] = field(default_factory=list)
    monitoring_duration_minutes: int = 30
    expansion_delay_minutes: int = 10
    
    def __post_init__(self):
        """Initialize default success criteria."""
        if not self.success_criteria:
            self.success_criteria = {
                "min_success_rate": 95.0,
                "max_error_rate": 1.0,
                "max_response_time_ms": 1000.0,
                "min_availability": 99.0
            }


@dataclass
class CanaryDeploymentResult:
    """Result of canary deployment."""
    deployment_id: str
    phase: CanaryPhase
    success: bool
    message: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    deployed_nodes: List[CanaryNode] = field(default_factory=list)
    health_metrics: Dict[str, float] = field(default_factory=dict)
    performance_impact: Dict[str, float] = field(default_factory=dict)
    rollback_performed: bool = False
    logs: List[str] = field(default_factory=list)
    
    def add_log(self, message: str, level: str = "INFO"):
        """Add log entry."""
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        self.logs.append(f"[{timestamp}] {level}: {message}")


class CanaryDeploymentManager:
    """Manages canary deployments with intelligent rollout strategies."""
    
    def __init__(self):
        self.active_deployments: Dict[str, CanaryDeploymentResult] = {}
        self.node_selector = None
        self.health_monitor = None
        self.cluster_manager = None
        
        # Default health checks
        self.default_health_checks = [
            HealthCheck(
                check_type=HealthCheckType.HTTP_ENDPOINT,
                endpoint="/api/v1/health",
                threshold=200,
                comparison="equals"
            ),
            HealthCheck(
                check_type=HealthCheckType.ERROR_RATE,
                metric_name="error_rate_percent",
                threshold=1.0,
                comparison="less_than"
            ),
            HealthCheck(
                check_type=HealthCheckType.RESPONSE_TIME,
                metric_name="avg_response_time_ms",
                threshold=1000.0,
                comparison="less_than"
            )
        ]
    
    async def initialize(self, cluster_manager=None):
        """Initialize canary deployment manager."""
        self.cluster_manager = cluster_manager
        
        # Initialize node selector
        from .canary_node_selector import CanaryNodeSelector
        self.node_selector = CanaryNodeSelector(cluster_manager)
        
        # Initialize health monitor
        from .canary_health_monitor import CanaryHealthMonitor
        self.health_monitor = CanaryHealthMonitor()
        
        await self.node_selector.initialize()
        await self.health_monitor.initialize()
        
        logger.info("Canary deployment manager initialized")
    
    async def create_deployment_plan(self, update_id: str, 
                                   strategy: CanaryStrategy = CanaryStrategy.PERCENTAGE_BASED,
                                   custom_config: Dict[str, Any] = None) -> CanaryDeploymentPlan:
        """Create canary deployment plan."""
        deployment_id = f"canary_{update_id}_{int(datetime.now().timestamp())}"
        
        plan = CanaryDeploymentPlan(
            deployment_id=deployment_id,
            update_id=update_id,
            strategy=strategy
        )
        
        # Apply custom configuration
        if custom_config:
            for key, value in custom_config.items():
                if hasattr(plan, key):
                    setattr(plan, key, value)
        
        # Set default health checks
        plan.health_checks = self.default_health_checks.copy()
        
        # Create deployment phases based on strategy
        await self._create_deployment_phases(plan)
        
        logger.info(f"Created canary deployment plan: {deployment_id}")
        return plan
    
    async def _create_deployment_phases(self, plan: CanaryDeploymentPlan):
        """Create deployment phases based on strategy."""
        if plan.strategy == CanaryStrategy.PERCENTAGE_BASED:
            # Progressive percentage rollout: 5% -> 25% -> 50% -> 100%
            plan.phases = [
                {"percentage": 5, "duration_minutes": 15},
                {"percentage": 25, "duration_minutes": 20},
                {"percentage": 50, "duration_minutes": 25},
                {"percentage": 100, "duration_minutes": 0}
            ]
        elif plan.strategy == CanaryStrategy.NODE_COUNT_BASED:
            # Progressive node count rollout
            total_nodes = await self._get_total_node_count()
            plan.phases = [
                {"node_count": max(1, total_nodes // 20), "duration_minutes": 15},
                {"node_count": max(2, total_nodes // 4), "duration_minutes": 20},
                {"node_count": max(3, total_nodes // 2), "duration_minutes": 25},
                {"node_count": total_nodes, "duration_minutes": 0}
            ]
        elif plan.strategy == CanaryStrategy.GEOGRAPHIC_BASED:
            # Region-by-region rollout
            regions = await self._get_available_regions()
            plan.phases = [
                {"regions": [regions[0]], "duration_minutes": 30} if regions else {},
                {"regions": regions[:len(regions)//2], "duration_minutes": 20} if len(regions) > 1 else {},
                {"regions": regions, "duration_minutes": 0}
            ]
            plan.phases = [phase for phase in plan.phases if phase]  # Remove empty phases
        
        logger.info(f"Created {len(plan.phases)} deployment phases")
    
    async def _get_total_node_count(self) -> int:
        """Get total number of available nodes."""
        if self.cluster_manager:
            nodes = await self.cluster_manager.get_all_nodes()
            return len(nodes)
        return 1  # Fallback for standalone mode
    
    async def _get_available_regions(self) -> List[str]:
        """Get available deployment regions."""
        if self.cluster_manager:
            nodes = await self.cluster_manager.get_all_nodes()
            regions = list(set(node.region for node in nodes if hasattr(node, 'region')))
            return regions
        return ["local"]  # Fallback for standalone mode
    
    async def execute_canary_deployment(self, plan: CanaryDeploymentPlan) -> CanaryDeploymentResult:
        """Execute canary deployment with progressive rollout."""
        result = CanaryDeploymentResult(
            deployment_id=plan.deployment_id,
            phase=CanaryPhase.PREPARING,
            success=False,
            message="Canary deployment started",
            started_at=datetime.now(timezone.utc)
        )
        
        self.active_deployments[plan.deployment_id] = result
        
        try:
            result.add_log("Starting canary deployment")
            
            # Execute each phase
            for phase_index, phase_config in enumerate(plan.phases):
                result.phase = CanaryPhase.SELECTING_NODES
                result.add_log(f"Starting phase {phase_index + 1}/{len(plan.phases)}")
                
                # Select nodes for this phase
                selected_nodes = await self._select_canary_nodes(plan, phase_config, result)
                if not selected_nodes:
                    raise Exception(f"No suitable nodes found for phase {phase_index + 1}")
                
                # Deploy to selected nodes
                result.phase = CanaryPhase.DEPLOYING
                deployment_success = await self._deploy_to_canary_nodes(
                    selected_nodes, plan, result
                )
                
                if not deployment_success:
                    raise Exception(f"Deployment failed in phase {phase_index + 1}")
                
                # Monitor health during phase
                result.phase = CanaryPhase.MONITORING
                monitoring_success = await self._monitor_canary_health(
                    selected_nodes, plan, result, phase_config.get("duration_minutes", 15)
                )
                
                if not monitoring_success:
                    raise Exception(f"Health monitoring failed in phase {phase_index + 1}")
                
                # Evaluate success criteria
                result.phase = CanaryPhase.EVALUATING
                evaluation_success = await self._evaluate_canary_success(
                    selected_nodes, plan, result
                )
                
                if not evaluation_success:
                    raise Exception(f"Success criteria not met in phase {phase_index + 1}")
                
                result.add_log(f"Phase {phase_index + 1} completed successfully")
                
                # Wait before next phase (except for last phase)
                if phase_index < len(plan.phases) - 1:
                    result.phase = CanaryPhase.EXPANDING
                    await asyncio.sleep(plan.expansion_delay_minutes * 60)
            
            result.phase = CanaryPhase.COMPLETED
            result.success = True
            result.message = "Canary deployment completed successfully"
            result.completed_at = datetime.now(timezone.utc)
            
            result.add_log("Canary deployment completed successfully")
            
        except Exception as e:
            logger.error(f"Canary deployment failed: {e}")
            result.success = False
            result.message = f"Canary deployment failed: {e}"
            result.phase = CanaryPhase.FAILED
            result.completed_at = datetime.now(timezone.utc)
            
            # Attempt rollback
            result.add_log("Attempting rollback due to failure")
            rollback_success = await self._rollback_canary_deployment(plan, result)
            result.rollback_performed = rollback_success
            
            if rollback_success:
                result.add_log("Rollback completed successfully")
            else:
                result.add_log("Rollback failed - manual intervention required", "ERROR")
        
        return result

    async def _select_canary_nodes(self, plan: CanaryDeploymentPlan,
                                 phase_config: Dict[str, Any],
                                 result: CanaryDeploymentResult) -> List[CanaryNode]:
        """Select nodes for canary deployment phase."""
        try:
            if self.node_selector:
                nodes = await self.node_selector.select_nodes(plan.strategy, phase_config)
                result.add_log(f"Selected {len(nodes)} nodes for canary deployment")
                return nodes
            else:
                # Fallback for standalone mode
                return [CanaryNode(
                    node_id="local",
                    node_type="standalone",
                    region="local",
                    load_factor=0.5,
                    health_score=1.0
                )]
        except Exception as e:
            logger.error(f"Node selection failed: {e}")
            result.add_log(f"Node selection failed: {e}", "ERROR")
            return []

    async def _deploy_to_canary_nodes(self, nodes: List[CanaryNode],
                                    plan: CanaryDeploymentPlan,
                                    result: CanaryDeploymentResult) -> bool:
        """Deploy update to canary nodes."""
        try:
            successful_deployments = 0

            for node in nodes:
                result.add_log(f"Deploying to node: {node.node_id}")

                # Simulate deployment (replace with actual deployment logic)
                deployment_success = await self._deploy_to_single_node(node, plan.update_id)

                if deployment_success:
                    node.deployment_time = datetime.now(timezone.utc)
                    result.deployed_nodes.append(node)
                    successful_deployments += 1
                    result.add_log(f"Successfully deployed to node: {node.node_id}")
                else:
                    result.add_log(f"Deployment failed for node: {node.node_id}", "ERROR")

            success_rate = (successful_deployments / len(nodes)) * 100
            result.add_log(f"Deployment success rate: {success_rate:.1f}%")

            # Require at least 80% success rate
            return success_rate >= 80.0

        except Exception as e:
            logger.error(f"Canary deployment failed: {e}")
            result.add_log(f"Canary deployment failed: {e}", "ERROR")
            return False

    async def _deploy_to_single_node(self, node: CanaryNode, update_id: str) -> bool:
        """Deploy update to a single node."""
        # Placeholder for actual deployment logic
        # This would integrate with the cluster manager or local deployment system
        await asyncio.sleep(1)  # Simulate deployment time
        return True  # Simulate successful deployment

    async def _monitor_canary_health(self, nodes: List[CanaryNode],
                                   plan: CanaryDeploymentPlan,
                                   result: CanaryDeploymentResult,
                                   duration_minutes: int) -> bool:
        """Monitor health of canary nodes during deployment."""
        try:
            result.add_log(f"Starting health monitoring for {duration_minutes} minutes")

            end_time = datetime.now(timezone.utc) + timedelta(minutes=duration_minutes)

            while datetime.now(timezone.utc) < end_time:
                # Check health of all nodes
                all_healthy = True

                for node in nodes:
                    health_data = await self._check_node_health(node, plan.health_checks)
                    node.health_checks = health_data

                    if not node.is_healthy:
                        all_healthy = False
                        result.add_log(f"Node {node.node_id} health degraded", "WARNING")

                if not all_healthy:
                    result.add_log("Health monitoring failed - unhealthy nodes detected", "ERROR")
                    return False

                # Wait before next health check
                await asyncio.sleep(30)  # Check every 30 seconds

            result.add_log("Health monitoring completed successfully")
            return True

        except Exception as e:
            logger.error(f"Health monitoring failed: {e}")
            result.add_log(f"Health monitoring failed: {e}", "ERROR")
            return False

    async def _check_node_health(self, node: CanaryNode, health_checks: List[HealthCheck]) -> Dict[str, Any]:
        """Check health of a single node."""
        health_data = {}

        for check in health_checks:
            try:
                if check.check_type == HealthCheckType.HTTP_ENDPOINT:
                    # Simulate HTTP health check
                    health_data[f"http_{check.endpoint}"] = {"status": 200, "healthy": True}
                elif check.check_type == HealthCheckType.ERROR_RATE:
                    # Simulate error rate check
                    error_rate = 0.5  # Simulate low error rate
                    health_data["error_rate"] = {"value": error_rate, "healthy": error_rate < check.threshold}
                elif check.check_type == HealthCheckType.RESPONSE_TIME:
                    # Simulate response time check
                    response_time = 150.0  # Simulate good response time
                    health_data["response_time"] = {"value": response_time, "healthy": response_time < check.threshold}

            except Exception as e:
                logger.error(f"Health check failed for {check.check_type}: {e}")
                health_data[f"error_{check.check_type.value}"] = {"error": str(e), "healthy": False}

        # Update node health score based on checks
        healthy_checks = sum(1 for check_data in health_data.values() if check_data.get("healthy", False))
        total_checks = len(health_data)
        node.health_score = healthy_checks / total_checks if total_checks > 0 else 0.0

        return health_data

    async def _evaluate_canary_success(self, nodes: List[CanaryNode],
                                     plan: CanaryDeploymentPlan,
                                     result: CanaryDeploymentResult) -> bool:
        """Evaluate if canary deployment meets success criteria."""
        try:
            result.add_log("Evaluating canary deployment success criteria")

            # Calculate overall metrics
            healthy_nodes = sum(1 for node in nodes if node.is_healthy)
            success_rate = (healthy_nodes / len(nodes)) * 100

            # Check against success criteria
            min_success_rate = plan.success_criteria.get("min_success_rate", 95.0)

            if success_rate >= min_success_rate:
                result.add_log(f"Success criteria met: {success_rate:.1f}% >= {min_success_rate}%")
                return True
            else:
                result.add_log(f"Success criteria not met: {success_rate:.1f}% < {min_success_rate}%", "ERROR")
                return False

        except Exception as e:
            logger.error(f"Success evaluation failed: {e}")
            result.add_log(f"Success evaluation failed: {e}", "ERROR")
            return False

    async def _rollback_canary_deployment(self, plan: CanaryDeploymentPlan,
                                        result: CanaryDeploymentResult) -> bool:
        """Rollback canary deployment."""
        try:
            result.phase = CanaryPhase.ROLLING_BACK
            result.add_log("Starting canary deployment rollback")

            rollback_success = True

            for node in result.deployed_nodes:
                result.add_log(f"Rolling back node: {node.node_id}")

                # Simulate rollback (replace with actual rollback logic)
                node_rollback_success = await self._rollback_single_node(node, plan.update_id)

                if node_rollback_success:
                    result.add_log(f"Successfully rolled back node: {node.node_id}")
                else:
                    result.add_log(f"Rollback failed for node: {node.node_id}", "ERROR")
                    rollback_success = False

            return rollback_success

        except Exception as e:
            logger.error(f"Canary rollback failed: {e}")
            result.add_log(f"Canary rollback failed: {e}", "ERROR")
            return False

    async def _rollback_single_node(self, node: CanaryNode, update_id: str) -> bool:
        """Rollback update on a single node."""
        # Placeholder for actual rollback logic
        await asyncio.sleep(0.5)  # Simulate rollback time
        return True  # Simulate successful rollback

    def get_deployment_status(self, deployment_id: str) -> Optional[CanaryDeploymentResult]:
        """Get status of canary deployment."""
        return self.active_deployments.get(deployment_id)

    async def cleanup(self):
        """Cleanup canary deployment manager resources."""
        if self.health_monitor:
            await self.health_monitor.cleanup()
        if self.node_selector:
            await self.node_selector.cleanup()


# Global canary deployment manager instance
canary_deployment_manager = CanaryDeploymentManager()
