from .antivirus_node import AntivirusClusterNode
from .gateway_node import GatewayClusterNode
from .main_node import MainClusterNode


"""
PlexiChat Specialized Cluster Nodes

Specialized cluster node implementations for different workload types:
- AntivirusClusterNode: Dedicated antivirus scanning operations
- GatewayClusterNode: SSL termination, load balancing, and routing
- MainClusterNode: Core application functionality and API processing
- BackupClusterNode: Backup operations and shard management
"""

__all__ = [
    'AntivirusClusterNode',
    'GatewayClusterNode', 
    'MainClusterNode'
]

# Node type registry for dynamic instantiation
NODE_TYPES = {
    'antivirus': AntivirusClusterNode,
    'gateway': GatewayClusterNode,
    'main': MainClusterNode
}

def create_specialized_node(node_type: str, node_id: str, cluster_config: dict):
    """
    Create a specialized cluster node based on type.
    
    Args:
        node_type: Type of node to create ('antivirus', 'gateway', 'main')
        node_id: Unique identifier for the node
        cluster_config: Configuration dictionary for the node
        
    Returns:
        Specialized cluster node instance
        
    Raises:
        ValueError: If node_type is not supported
    """
    if node_type not in NODE_TYPES:
        raise ValueError(f"Unsupported node type: {node_type}. Supported types: {list(NODE_TYPES.keys())}")
    
    node_class = NODE_TYPES[node_type]
    return node_class(node_id, cluster_config)
