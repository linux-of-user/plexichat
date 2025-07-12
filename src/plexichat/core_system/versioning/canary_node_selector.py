"""
PlexiChat Canary Node Selector

Intelligent node selection for canary deployments with:
- Load-based selection algorithms
- Geographic distribution awareness
- Health score evaluation
- Risk assessment and mitigation
- Custom selection strategies
"""

import asyncio
import random
from enum import Enum
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass
from datetime import datetime, timezone
import logging

from .canary_deployment_manager import CanaryNode, CanaryStrategy

logger = logging.getLogger(__name__)


class NodeSelectionCriteria(Enum):
    """Criteria for node selection."""
    LOWEST_LOAD = "lowest_load"
    HIGHEST_HEALTH = "highest_health"
    GEOGRAPHIC_SPREAD = "geographic_spread"
    RANDOM_SAMPLE = "random_sample"
    RISK_BALANCED = "risk_balanced"


@dataclass
class NodeMetrics:
    """Node performance and health metrics."""
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    disk_usage: float = 0.0
    network_latency: float = 0.0
    error_rate: float = 0.0
    uptime_percentage: float = 100.0
    last_updated: Optional[datetime] = None
    
    @property
    def load_score(self) -> float:
        """Calculate overall load score (0-1, lower is better)."""
        return (self.cpu_usage + self.memory_usage + self.disk_usage) / 3.0
    
    @property
    def health_score(self) -> float:
        """Calculate overall health score (0-1, higher is better)."""
        error_penalty = min(self.error_rate * 10, 0.5)  # Max 50% penalty for errors
        latency_penalty = min(self.network_latency / 1000, 0.3)  # Max 30% penalty for latency
        uptime_score = self.uptime_percentage / 100.0
        
        return max(0.0, uptime_score - error_penalty - latency_penalty)


class CanaryNodeSelector:
    """Selects optimal nodes for canary deployments."""
    
    def __init__(self, cluster_manager=None):
        self.cluster_manager = cluster_manager
        self.node_metrics: Dict[str, NodeMetrics] = {}
        self.node_history: Dict[str, List[Dict[str, Any]]] = {}
        self.blacklisted_nodes: Set[str] = set()
        
        # Selection preferences
        self.min_health_threshold = 0.7
        self.max_load_threshold = 0.8
        self.geographic_spread_factor = 0.3
        
    async def initialize(self):
        """Initialize node selector."""
        await self._load_node_metrics()
        await self._load_node_history()
        logger.info("Canary node selector initialized")
    
    async def select_nodes(self, strategy: CanaryStrategy, 
                          phase_config: Dict[str, Any]) -> List[CanaryNode]:
        """Select nodes based on strategy and phase configuration."""
        try:
            # Get all available nodes
            available_nodes = await self._get_available_nodes()
            
            if not available_nodes:
                logger.warning("No available nodes for canary deployment")
                return []
            
            # Filter out blacklisted and unhealthy nodes
            filtered_nodes = await self._filter_nodes(available_nodes)
            
            if not filtered_nodes:
                logger.warning("No suitable nodes after filtering")
                return []
            
            # Select nodes based on strategy
            if strategy == CanaryStrategy.PERCENTAGE_BASED:
                return await self._select_by_percentage(filtered_nodes, phase_config)
            elif strategy == CanaryStrategy.NODE_COUNT_BASED:
                return await self._select_by_count(filtered_nodes, phase_config)
            elif strategy == CanaryStrategy.GEOGRAPHIC_BASED:
                return await self._select_by_geography(filtered_nodes, phase_config)
            elif strategy == CanaryStrategy.LOAD_BASED:
                return await self._select_by_load(filtered_nodes, phase_config)
            else:
                return await self._select_by_percentage(filtered_nodes, phase_config)
                
        except Exception as e:
            logger.error(f"Node selection failed: {e}")
            return []
    
    async def _get_available_nodes(self) -> List[Dict[str, Any]]:
        """Get all available nodes from cluster manager."""
        if self.cluster_manager:
            try:
                cluster_nodes = await self.cluster_manager.get_all_nodes()
                return [
                    {
                        "node_id": node.node_id,
                        "node_type": getattr(node, 'node_type', 'unknown'),
                        "region": getattr(node, 'region', 'unknown'),
                        "capabilities": getattr(node, 'capabilities', {}),
                        "status": getattr(node, 'status', 'unknown')
                    }
                    for node in cluster_nodes
                    if getattr(node, 'status', 'unknown') == 'active'
                ]
            except Exception as e:
                logger.error(f"Failed to get cluster nodes: {e}")
                return []
        else:
            # Fallback for standalone mode
            return [{
                "node_id": "local",
                "node_type": "standalone",
                "region": "local",
                "capabilities": {"canary_deployment": True},
                "status": "active"
            }]
    
    async def _filter_nodes(self, nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Filter nodes based on health and suitability criteria."""
        filtered = []
        
        for node in nodes:
            node_id = node["node_id"]
            
            # Skip blacklisted nodes
            if node_id in self.blacklisted_nodes:
                logger.debug(f"Skipping blacklisted node: {node_id}")
                continue
            
            # Check if node supports canary deployments
            capabilities = node.get("capabilities", {})
            if not capabilities.get("canary_deployment", True):
                logger.debug(f"Skipping node without canary capability: {node_id}")
                continue
            
            # Check node health and load
            metrics = self.node_metrics.get(node_id, NodeMetrics())
            
            if metrics.health_score < self.min_health_threshold:
                logger.debug(f"Skipping unhealthy node: {node_id} (health: {metrics.health_score:.2f})")
                continue
            
            if metrics.load_score > self.max_load_threshold:
                logger.debug(f"Skipping overloaded node: {node_id} (load: {metrics.load_score:.2f})")
                continue
            
            filtered.append(node)
        
        logger.info(f"Filtered {len(filtered)} suitable nodes from {len(nodes)} total")
        return filtered
    
    async def _select_by_percentage(self, nodes: List[Dict[str, Any]], 
                                  config: Dict[str, Any]) -> List[CanaryNode]:
        """Select nodes by percentage."""
        percentage = config.get("percentage", 10)
        target_count = max(1, int(len(nodes) * percentage / 100))
        
        # Sort by health score and select top nodes
        sorted_nodes = sorted(
            nodes,
            key=lambda n: self.node_metrics.get(n["node_id"], NodeMetrics()).health_score,
            reverse=True
        )
        
        selected = sorted_nodes[:target_count]
        return [self._create_canary_node(node) for node in selected]
    
    async def _select_by_count(self, nodes: List[Dict[str, Any]], 
                             config: Dict[str, Any]) -> List[CanaryNode]:
        """Select specific number of nodes."""
        target_count = min(config.get("node_count", 1), len(nodes))
        
        # Use risk-balanced selection for count-based selection
        selected = await self._risk_balanced_selection(nodes, target_count)
        return [self._create_canary_node(node) for node in selected]
    
    async def _select_by_geography(self, nodes: List[Dict[str, Any]], 
                                 config: Dict[str, Any]) -> List[CanaryNode]:
        """Select nodes by geographic regions."""
        target_regions = config.get("regions", [])
        
        if not target_regions:
            # If no specific regions, select from all regions
            return await self._select_by_percentage(nodes, {"percentage": 10})
        
        selected = []
        for region in target_regions:
            region_nodes = [n for n in nodes if n.get("region") == region]
            if region_nodes:
                # Select best node from each region
                best_node = max(
                    region_nodes,
                    key=lambda n: self.node_metrics.get(n["node_id"], NodeMetrics()).health_score
                )
                selected.append(best_node)
        
        return [self._create_canary_node(node) for node in selected]
    
    async def _select_by_load(self, nodes: List[Dict[str, Any]], 
                            config: Dict[str, Any]) -> List[CanaryNode]:
        """Select nodes with lowest load."""
        target_count = config.get("node_count", max(1, len(nodes) // 10))
        
        # Sort by load score (ascending - lowest load first)
        sorted_nodes = sorted(
            nodes,
            key=lambda n: self.node_metrics.get(n["node_id"], NodeMetrics()).load_score
        )
        
        selected = sorted_nodes[:target_count]
        return [self._create_canary_node(node) for node in selected]
    
    async def _risk_balanced_selection(self, nodes: List[Dict[str, Any]], 
                                     target_count: int) -> List[Dict[str, Any]]:
        """Select nodes with balanced risk distribution."""
        if len(nodes) <= target_count:
            return nodes
        
        # Calculate risk scores for each node
        risk_scores = {}
        for node in nodes:
            node_id = node["node_id"]
            metrics = self.node_metrics.get(node_id, NodeMetrics())
            
            # Risk factors: high load, low health, recent failures
            load_risk = metrics.load_score
            health_risk = 1.0 - metrics.health_score
            history_risk = self._calculate_history_risk(node_id)
            
            risk_scores[node_id] = (load_risk + health_risk + history_risk) / 3.0
        
        # Select nodes with balanced risk (not all low-risk, not all high-risk)
        sorted_by_risk = sorted(nodes, key=lambda n: risk_scores[n["node_id"]])
        
        # Take a mix: 70% low-risk, 30% medium-risk
        low_risk_count = int(target_count * 0.7)
        medium_risk_count = target_count - low_risk_count
        
        selected = []
        selected.extend(sorted_by_risk[:low_risk_count])
        
        if medium_risk_count > 0:
            medium_start = len(sorted_by_risk) // 3
            medium_end = min(medium_start + medium_risk_count, len(sorted_by_risk))
            selected.extend(sorted_by_risk[medium_start:medium_end])
        
        return selected[:target_count]
    
    def _calculate_history_risk(self, node_id: str) -> float:
        """Calculate risk based on node's deployment history."""
        history = self.node_history.get(node_id, [])
        
        if not history:
            return 0.0  # No history = no additional risk
        
        # Look at recent deployments (last 10)
        recent_deployments = history[-10:]
        failures = sum(1 for deployment in recent_deployments if not deployment.get("success", True))
        
        failure_rate = failures / len(recent_deployments)
        return min(failure_rate * 2, 1.0)  # Cap at 100% risk
    
    def _create_canary_node(self, node_data: Dict[str, Any]) -> CanaryNode:
        """Create CanaryNode from node data."""
        node_id = node_data["node_id"]
        metrics = self.node_metrics.get(node_id, NodeMetrics())
        
        return CanaryNode(
            node_id=node_id,
            node_type=node_data.get("node_type", "unknown"),
            region=node_data.get("region", "unknown"),
            load_factor=metrics.load_score,
            health_score=metrics.health_score
        )
    
    async def _load_node_metrics(self):
        """Load current node metrics."""
        # Placeholder for loading actual metrics
        # This would integrate with monitoring systems
        pass
    
    async def _load_node_history(self):
        """Load node deployment history."""
        # Placeholder for loading deployment history
        # This would load from persistent storage
        pass
    
    def blacklist_node(self, node_id: str, reason: str = ""):
        """Add node to blacklist."""
        self.blacklisted_nodes.add(node_id)
        logger.warning(f"Node {node_id} blacklisted: {reason}")
    
    def whitelist_node(self, node_id: str):
        """Remove node from blacklist."""
        self.blacklisted_nodes.discard(node_id)
        logger.info(f"Node {node_id} removed from blacklist")
    
    async def cleanup(self):
        """Cleanup node selector resources."""
        pass
