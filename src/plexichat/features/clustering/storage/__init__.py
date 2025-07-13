"""
PlexiChat Distributed Storage Module

Provides distributed storage capabilities for the clustering system with:
- Intelligent data distribution across cluster nodes
- Automatic replication and redundancy
- Load balancing and performance optimization
- Data consistency and synchronization
- Storage monitoring and management
- Automatic failover and recovery
"""

from .distributed_storage_manager import (
    DataConsistency,
    DistributedStorageManager,
    StorageNode,
    StorageNodeType,
    StorageStrategy,
    StoredData,
    distributed_storage_manager,
)

__version__ = "1.0.0"
__all__ = [
    "DistributedStorageManager",
    "StorageNode", 
    "StoredData",
    "StorageNodeType",
    "StorageStrategy",
    "DataConsistency",
    "distributed_storage_manager"
]
