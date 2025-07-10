"""
Comprehensive test suite for PlexiChat clustering system.
Tests load balancing, failover, performance monitoring, and node management.
"""

import pytest
import asyncio
import tempfile
from unittest.mock import Mock, patch, AsyncMock
import time
from datetime import datetime, timedelta

# Import clustering system components
try:
    from plexichat.clustering.core.cluster_manager import ClusterManager
    from plexichat.clustering.core.node_manager import NodeManager, NodeType
    from plexichat.clustering.core.load_balancer import SmartLoadBalancer, LoadBalancingAlgorithm
    from plexichat.clustering.core.performance_monitor import RealTimePerformanceMonitor
    from plexichat.clustering.core.failover_manager import AutomaticFailoverManager
    from plexichat.clustering.models.cluster_models import ClusterNode, NodeStatus, PerformanceMetrics
    CLUSTERING_AVAILABLE = True
except ImportError:
    CLUSTERING_AVAILABLE = False


@pytest.mark.skipif(not CLUSTERING_AVAILABLE, reason="Clustering system not available")
class TestClusterManager:
    """Test cluster manager functionality."""
    
    @pytest.fixture
    async def cluster_manager(self):
        """Create a test cluster manager instance."""
        manager = ClusterManager(
            min_nodes=2,
            max_nodes=10,
            auto_scale=True
        )
        await manager.initialize()
        yield manager
        await manager.cleanup()
    
    @pytest.mark.asyncio
    async def test_cluster_initialization(self, cluster_manager):
        """Test cluster manager initialization."""
        assert cluster_manager.initialized
        assert cluster_manager.min_nodes == 2
        assert cluster_manager.max_nodes == 10
        assert cluster_manager.auto_scale_enabled
    
    @pytest.mark.asyncio
    async def test_node_addition(self, cluster_manager):
        """Test adding nodes to the cluster."""
        node = await cluster_manager.add_node(
            name="test-node-01",
            address="192.168.1.100:8000",
            node_type=NodeType.MAIN,
            encryption_enabled=True,
            max_connections=100
        )
        
        assert node is not None
        assert node.name == "test-node-01"
        assert node.address == "192.168.1.100:8000"
        assert node.node_type == NodeType.MAIN
        assert node.encryption_enabled
        assert node.status == NodeStatus.ACTIVE
    
    @pytest.mark.asyncio
    async def test_cluster_overview(self, cluster_manager):
        """Test getting cluster overview."""
        # Add some test nodes
        await cluster_manager.add_node("node-01", "192.168.1.101:8000", NodeType.MAIN)
        await cluster_manager.add_node("node-02", "192.168.1.102:8000", NodeType.GATEWAY)
        
        overview = await cluster_manager.get_cluster_overview()
        
        assert overview is not None
        assert overview.total_nodes >= 2
        assert overview.active_nodes >= 2
        assert hasattr(overview, 'cluster_load_percentage')
        assert hasattr(overview, 'performance_improvement_percentage')
    
    @pytest.mark.asyncio
    async def test_node_removal(self, cluster_manager):
        """Test removing nodes from the cluster."""
        # Add a node first
        node = await cluster_manager.add_node("temp-node", "192.168.1.200:8000", NodeType.MAIN)
        
        # Remove the node
        success = await cluster_manager.remove_node(node.node_id)
        assert success
        
        # Verify node is no longer active
        remaining_nodes = await cluster_manager.list_active_nodes()
        node_ids = [n.node_id for n in remaining_nodes]
        assert node.node_id not in node_ids


@pytest.mark.skipif(not CLUSTERING_AVAILABLE, reason="Clustering system not available")
class TestNodeManager:
    """Test intelligent node management."""
    
    @pytest.fixture
    async def node_manager(self):
        """Create a test node manager instance."""
        manager = NodeManager(
            max_nodes_per_type=5,
            health_check_interval=10
        )
        await manager.initialize()
        yield manager
        await manager.cleanup()
    
    @pytest.mark.asyncio
    async def test_specialized_node_types(self, node_manager):
        """Test management of specialized node types."""
        # Test different node types
        node_types = [
            (NodeType.MAIN, "main-node"),
            (NodeType.GATEWAY, "gateway-node"),
            (NodeType.ANTIVIRUS, "antivirus-node"),
            (NodeType.BACKUP, "backup-node")
        ]
        
        created_nodes = []
        for node_type, name in node_types:
            node = await node_manager.create_node(
                name=name,
                node_type=node_type,
                address=f"192.168.1.{len(created_nodes) + 10}:8000"
            )
            created_nodes.append(node)
            assert node.node_type == node_type
            assert node.name == name
        
        # Verify all node types are represented
        node_type_counts = await node_manager.get_node_type_distribution()
        for node_type, _ in node_types:
            assert node_type_counts.get(node_type.value, 0) >= 1
    
    @pytest.mark.asyncio
    async def test_node_health_monitoring(self, node_manager):
        """Test node health monitoring system."""
        # Create a test node
        node = await node_manager.create_node(
            name="health-test-node",
            node_type=NodeType.MAIN,
            address="192.168.1.50:8000"
        )
        
        # Simulate health check
        health_status = await node_manager.check_node_health(node.node_id)
        
        assert health_status is not None
        assert hasattr(health_status, 'is_healthy')
        assert hasattr(health_status, 'response_time_ms')
        assert hasattr(health_status, 'last_check_time')
    
    @pytest.mark.asyncio
    async def test_node_capacity_management(self, node_manager):
        """Test node capacity and resource allocation."""
        node = await node_manager.create_node(
            name="capacity-test-node",
            node_type=NodeType.MAIN,
            address="192.168.1.60:8000",
            max_connections=50,
            cpu_cores=4,
            memory_gb=8
        )
        
        # Test capacity allocation
        allocation = await node_manager.allocate_resources(
            node_id=node.node_id,
            connections_needed=10,
            cpu_needed=1.0,
            memory_needed_gb=2.0
        )
        
        assert allocation.success
        assert allocation.allocated_connections == 10
        assert allocation.allocated_cpu == 1.0
        assert allocation.allocated_memory_gb == 2.0


@pytest.mark.skipif(not CLUSTERING_AVAILABLE, reason="Clustering system not available")
class TestSmartLoadBalancer:
    """Test smart load balancing functionality."""
    
    @pytest.fixture
    async def load_balancer(self):
        """Create a test load balancer instance."""
        balancer = SmartLoadBalancer(
            algorithm=LoadBalancingAlgorithm.AI_OPTIMIZED,
            health_check_enabled=True
        )
        await balancer.initialize()
        yield balancer
        await balancer.cleanup()
    
    @pytest.mark.asyncio
    async def test_load_balancing_algorithms(self, load_balancer):
        """Test different load balancing algorithms."""
        # Add test nodes
        nodes = []
        for i in range(3):
            node = ClusterNode(
                node_id=f"node-{i}",
                name=f"test-node-{i}",
                address=f"192.168.1.{100+i}:8000",
                node_type=NodeType.MAIN,
                capacity=100,
                current_connections=i * 10  # Different loads
            )
            nodes.append(node)
            await load_balancer.add_node(node)
        
        # Test round robin
        await load_balancer.set_algorithm(LoadBalancingAlgorithm.ROUND_ROBIN)
        selections = []
        for _ in range(6):
            selected = await load_balancer.select_node()
            selections.append(selected.node_id)
        
        # Should cycle through nodes
        assert len(set(selections)) == 3
        
        # Test least connections
        await load_balancer.set_algorithm(LoadBalancingAlgorithm.LEAST_CONNECTIONS)
        selected = await load_balancer.select_node()
        # Should select node with least connections (node-0)
        assert selected.node_id == "node-0"
    
    @pytest.mark.asyncio
    async def test_weighted_load_balancing(self, load_balancer):
        """Test weighted load balancing based on node capacity."""
        # Add nodes with different capacities
        high_capacity_node = ClusterNode(
            node_id="high-capacity",
            name="high-capacity-node",
            address="192.168.1.110:8000",
            node_type=NodeType.MAIN,
            capacity=200
        )
        
        low_capacity_node = ClusterNode(
            node_id="low-capacity",
            name="low-capacity-node", 
            address="192.168.1.111:8000",
            node_type=NodeType.MAIN,
            capacity=50
        )
        
        await load_balancer.add_node(high_capacity_node)
        await load_balancer.add_node(low_capacity_node)
        await load_balancer.set_algorithm(LoadBalancingAlgorithm.WEIGHTED_ROUND_ROBIN)
        
        # Test selection distribution
        selections = []
        for _ in range(100):
            selected = await load_balancer.select_node()
            selections.append(selected.node_id)
        
        high_capacity_count = selections.count("high-capacity")
        low_capacity_count = selections.count("low-capacity")
        
        # High capacity node should be selected more often
        assert high_capacity_count > low_capacity_count
    
    @pytest.mark.asyncio
    async def test_ai_optimized_balancing(self, load_balancer):
        """Test AI-optimized load balancing."""
        await load_balancer.set_algorithm(LoadBalancingAlgorithm.AI_OPTIMIZED)
        
        # Add nodes with performance history
        for i in range(3):
            node = ClusterNode(
                node_id=f"ai-node-{i}",
                name=f"ai-test-node-{i}",
                address=f"192.168.1.{120+i}:8000",
                node_type=NodeType.MAIN,
                capacity=100
            )
            await load_balancer.add_node(node)
            
            # Simulate performance history
            await load_balancer.record_performance_metrics(
                node_id=node.node_id,
                response_time_ms=50 + (i * 10),  # Different performance levels
                success_rate=0.95 + (i * 0.01)
            )
        
        # AI should select the best performing node more often
        selections = []
        for _ in range(50):
            selected = await load_balancer.select_node()
            selections.append(selected.node_id)
        
        # Best performing node (ai-node-2) should be selected most
        best_node_count = selections.count("ai-node-2")
        worst_node_count = selections.count("ai-node-0")
        assert best_node_count >= worst_node_count


@pytest.mark.skipif(not CLUSTERING_AVAILABLE, reason="Clustering system not available")
class TestPerformanceMonitor:
    """Test real-time performance monitoring."""
    
    @pytest.fixture
    async def performance_monitor(self):
        """Create a test performance monitor instance."""
        monitor = RealTimePerformanceMonitor(
            collection_interval=1,
            retention_days=7
        )
        await monitor.initialize()
        yield monitor
        await monitor.cleanup()
    
    @pytest.mark.asyncio
    async def test_metrics_collection(self, performance_monitor):
        """Test performance metrics collection."""
        node_id = "perf-test-node"
        
        # Record test metrics
        await performance_monitor.record_metrics(
            node_id=node_id,
            response_time_ms=45.5,
            throughput_rps=150.0,
            cpu_usage_percent=65.2,
            memory_usage_percent=78.1,
            error_rate_percent=0.5
        )
        
        # Retrieve metrics
        metrics = await performance_monitor.get_current_metrics(node_id)
        
        assert metrics is not None
        assert metrics.response_time_ms == 45.5
        assert metrics.throughput_rps == 150.0
        assert metrics.cpu_usage_percent == 65.2
        assert metrics.memory_usage_percent == 78.1
        assert metrics.error_rate_percent == 0.5
    
    @pytest.mark.asyncio
    async def test_performance_trends(self, performance_monitor):
        """Test performance trend analysis."""
        node_id = "trend-test-node"
        
        # Record metrics over time
        base_time = datetime.now()
        for i in range(10):
            await performance_monitor.record_metrics(
                node_id=node_id,
                response_time_ms=50 + (i * 2),  # Increasing response time
                throughput_rps=100 - (i * 5),   # Decreasing throughput
                timestamp=base_time + timedelta(minutes=i)
            )
        
        # Analyze trends
        trends = await performance_monitor.analyze_trends(
            node_id=node_id,
            time_window_minutes=60
        )
        
        assert trends is not None
        assert trends.response_time_trend == "INCREASING"
        assert trends.throughput_trend == "DECREASING"
    
    @pytest.mark.asyncio
    async def test_performance_alerts(self, performance_monitor):
        """Test performance alerting system."""
        node_id = "alert-test-node"
        
        # Set alert thresholds
        await performance_monitor.set_alert_thresholds(
            node_id=node_id,
            max_response_time_ms=100,
            min_throughput_rps=50,
            max_error_rate_percent=5.0
        )
        
        # Record metrics that should trigger alerts
        await performance_monitor.record_metrics(
            node_id=node_id,
            response_time_ms=150,  # Above threshold
            throughput_rps=30,     # Below threshold
            error_rate_percent=8.0  # Above threshold
        )
        
        # Check for alerts
        alerts = await performance_monitor.get_active_alerts(node_id)
        
        assert len(alerts) >= 3  # Should have alerts for all three metrics
        alert_types = [alert.metric_type for alert in alerts]
        assert "response_time" in alert_types
        assert "throughput" in alert_types
        assert "error_rate" in alert_types


@pytest.mark.skipif(not CLUSTERING_AVAILABLE, reason="Clustering system not available")
class TestFailoverManager:
    """Test automatic failover functionality."""
    
    @pytest.fixture
    async def failover_manager(self):
        """Create a test failover manager instance."""
        manager = AutomaticFailoverManager(
            detection_timeout_seconds=5,
            recovery_timeout_seconds=30,
            max_failover_attempts=3
        )
        await manager.initialize()
        yield manager
        await manager.cleanup()
    
    @pytest.mark.asyncio
    async def test_failure_detection(self, failover_manager):
        """Test automatic failure detection."""
        # Register a test node
        node_id = "failover-test-node"
        await failover_manager.register_node(
            node_id=node_id,
            address="192.168.1.200:8000",
            node_type=NodeType.MAIN
        )
        
        # Simulate node failure
        await failover_manager.simulate_node_failure(node_id)
        
        # Wait for detection
        await asyncio.sleep(6)  # Wait longer than detection timeout
        
        # Check if failure was detected
        failed_nodes = await failover_manager.get_failed_nodes()
        assert node_id in [node.node_id for node in failed_nodes]
    
    @pytest.mark.asyncio
    async def test_automatic_recovery(self, failover_manager):
        """Test automatic failover and recovery."""
        # Set up primary and backup nodes
        primary_node = "primary-node"
        backup_node = "backup-node"
        
        await failover_manager.register_node(
            node_id=primary_node,
            address="192.168.1.210:8000",
            node_type=NodeType.MAIN,
            is_primary=True
        )
        
        await failover_manager.register_node(
            node_id=backup_node,
            address="192.168.1.211:8000", 
            node_type=NodeType.MAIN,
            is_backup=True
        )
        
        # Simulate primary node failure
        await failover_manager.simulate_node_failure(primary_node)
        
        # Wait for failover
        await asyncio.sleep(2)
        
        # Check if backup node became active
        active_nodes = await failover_manager.get_active_nodes()
        active_node_ids = [node.node_id for node in active_nodes]
        
        assert backup_node in active_node_ids
        assert primary_node not in active_node_ids
    
    @pytest.mark.asyncio
    async def test_failover_history(self, failover_manager):
        """Test failover event history tracking."""
        node_id = "history-test-node"
        
        # Register node and simulate failure
        await failover_manager.register_node(
            node_id=node_id,
            address="192.168.1.220:8000",
            node_type=NodeType.MAIN
        )
        
        await failover_manager.simulate_node_failure(node_id)
        await asyncio.sleep(1)
        
        # Get failover history
        history = await failover_manager.get_failover_history(limit=10)
        
        assert len(history) >= 1
        latest_event = history[0]
        assert latest_event.failed_node_id == node_id
        assert latest_event.event_type == "NODE_FAILURE"
        assert latest_event.timestamp is not None


@pytest.mark.skipif(not CLUSTERING_AVAILABLE, reason="Clustering system not available")
class TestClusteringIntegration:
    """Test integration between clustering components."""
    
    @pytest.mark.asyncio
    async def test_end_to_end_clustering(self):
        """Test complete clustering workflow."""
        # Initialize all components
        cluster_manager = ClusterManager()
        load_balancer = SmartLoadBalancer()
        performance_monitor = RealTimePerformanceMonitor()
        failover_manager = AutomaticFailoverManager()
        
        await cluster_manager.initialize()
        await load_balancer.initialize()
        await performance_monitor.initialize()
        await failover_manager.initialize()
        
        try:
            # Add nodes to cluster
            node1 = await cluster_manager.add_node(
                "integration-node-1", "192.168.1.100:8000", NodeType.MAIN
            )
            node2 = await cluster_manager.add_node(
                "integration-node-2", "192.168.1.101:8000", NodeType.MAIN
            )
            
            # Configure load balancer
            await load_balancer.add_node(node1)
            await load_balancer.add_node(node2)
            
            # Register nodes with failover manager
            await failover_manager.register_node(
                node1.node_id, node1.address, node1.node_type
            )
            await failover_manager.register_node(
                node2.node_id, node2.address, node2.node_type
            )
            
            # Simulate traffic and monitoring
            for _ in range(10):
                selected_node = await load_balancer.select_node()
                
                # Record performance metrics
                await performance_monitor.record_metrics(
                    node_id=selected_node.node_id,
                    response_time_ms=45.0,
                    throughput_rps=100.0,
                    cpu_usage_percent=60.0
                )
            
            # Verify integration
            cluster_overview = await cluster_manager.get_cluster_overview()
            assert cluster_overview.total_nodes == 2
            assert cluster_overview.active_nodes == 2
            
            # Test performance improvement calculation
            assert cluster_overview.performance_improvement_percentage >= 50.0
            
        finally:
            # Cleanup
            await cluster_manager.cleanup()
            await load_balancer.cleanup()
            await performance_monitor.cleanup()
            await failover_manager.cleanup()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
