"""
Integration tests for P2P Sharded Backup & Distribution system.
Tests end-to-end recovery workflows and system integration.
"""

import pytest
import asyncio
import tempfile
import json
from pathlib import Path
from unittest.mock import MagicMock, AsyncMock, patch
from typing import Dict, List, Any

from plexichat.features.backup.backup_engine import BackupEngine
from plexichat.features.backup.recovery_service import RecoveryService
from ..property.test_shard_distribution_simulation import (
    ShardDistributionSimulator,
    SimulatedPeer,
    SimulatedShard,
    AdversarialStrategy
)


class TestShardDistributionIntegration:
    """Integration tests for complete shard distribution workflows."""

    @pytest.fixture
    def mock_services(self):
        """Create mock services for integration testing."""
        storage_manager = MagicMock()
        storage_manager.store_shards_async = AsyncMock(return_value=[
            MagicMock(location="local://test", size_bytes=1024, checksum="test_checksum")
        ])
        storage_manager.retrieve_shards = AsyncMock(return_value=[
            {"data": b"test_shard_data", "metadata": {"shard_index": 0}}
        ])
        storage_manager.verify_backup_shards_async = AsyncMock(return_value={
            "all_shards_valid": True,
            "total_shards": 3,
            "valid_shards": 3
        })

        encryption_service = MagicMock()
        encryption_service.encrypt_data_async = AsyncMock(return_value=(
            b"encrypted_test_data",
            {"key_id": "test_key", "algorithm": "AES-256-GCM"}
        ))
        encryption_service.decrypt_data_async = AsyncMock(return_value=b"decrypted_test_data")
        encryption_service.get_key_hash = MagicMock(return_value="key_hash_123")

        return storage_manager, encryption_service

    def test_full_backup_and_recovery_workflow(self, mock_services):
        """Test complete backup creation and recovery workflow."""
        storage_manager, encryption_service = mock_services

        # Create backup engine
        config = {"shard_size": 1024}  # Small shards for testing
        engine = BackupEngine(
            storage_manager=storage_manager,
            encryption_service=encryption_service,
            config=config
        )

        # Test data
        test_data = {"messages": ["test message 1", "test message 2"], "users": ["user1", "user2"]}

        async def run_test():
            # Create backup
            backup_metadata = await engine.create_backup(
                data=test_data,
                backup_type=engine.BackupType.FULL,
                security_level=engine.SecurityLevel.STANDARD
            )

            assert backup_metadata.backup_id is not None
            assert backup_metadata.shard_count > 0
            assert backup_metadata.status == engine.BackupStatus.COMPLETED

            # Verify storage was called
            storage_manager.store_shards_async.assert_called_once()

            # Create recovery service
            recovery_service = RecoveryService(storage_manager, encryption_service)

            # Attempt recovery
            recovery_result = await recovery_service.recover_backup(
                backup_id=backup_metadata.backup_id,
                recovery_type="full"
            )

            assert recovery_result["status"] == "success"
            assert recovery_result["backup_id"] == backup_metadata.backup_id
            assert recovery_result["shards_used"] > 0

        asyncio.run(run_test())

    def test_partial_recovery_workflow(self, mock_services):
        """Test partial recovery workflow."""
        storage_manager, encryption_service = mock_services

        # Mock partial shard availability
        storage_manager.retrieve_shards = AsyncMock(return_value=[
            {"data": b'{"messages": ["msg1"], "users": ["user1"]}', "metadata": {"shard_index": 0}},
            {"data": b'{"messages": ["msg2"], "users": ["user2"]}', "metadata": {"shard_index": 1}}
        ])

        recovery_service = RecoveryService(storage_manager, encryption_service)

        async def run_test():
            recovery_result = await recovery_service.recover_backup(
                backup_id="test_partial_backup",
                recovery_type="partial"
            )

            assert recovery_result["status"] == "success"
            assert "recovery_type" in recovery_result
            assert recovery_result["recovery_type"] == "partial"

        asyncio.run(run_test())

    def test_emergency_recovery_workflow(self, mock_services):
        """Test emergency recovery workflow."""
        storage_manager, encryption_service = mock_services

        # Mock corrupted data that can't be parsed as JSON
        storage_manager.retrieve_shards = AsyncMock(return_value=[
            {"data": b"corrupted_binary_data_12345", "metadata": {"shard_index": 0}}
        ])

        recovery_service = RecoveryService(storage_manager, encryption_service)

        async def run_test():
            recovery_result = await recovery_service.recover_backup(
                backup_id="test_emergency_backup",
                recovery_type="emergency"
            )

            assert recovery_result["status"] == "success"
            assert recovery_result["recovery_type"] == "emergency"
            assert "raw_data_size" in recovery_result

        asyncio.run(run_test())

    def test_recovery_with_insufficient_shards(self, mock_services):
        """Test recovery failure with insufficient shards."""
        storage_manager, encryption_service = mock_services

        # Mock insufficient shards
        storage_manager.retrieve_shards = AsyncMock(return_value=[
            {"data": b"single_shard_data", "metadata": {"shard_index": 0}}
        ])

        recovery_service = RecoveryService(storage_manager, encryption_service)

        async def run_test():
            recovery_result = await recovery_service.recover_backup(
                backup_id="test_insufficient_backup",
                recovery_type="full"
            )

            assert recovery_result["status"] == "failed"
            assert "Insufficient shards" in recovery_result["error"]

        asyncio.run(run_test())


class TestAdversarialScenarioIntegration:
    """Integration tests for adversarial scenarios."""

    def test_adversarial_collection_prevention(self):
        """Test that adversarial peers cannot collect complementary shards."""
        simulator = ShardDistributionSimulator(initial_peers=0)

        # Add legitimate peers
        for i in range(5):
            simulator.add_peer(f"legit_{i}")

        # Add adversarial peer
        simulator.add_peer("adversary", AdversarialStrategy.COLLECTOR)

        # Create complementary shards
        shard1 = SimulatedShard(
            shard_id="comp_A",
            partition_id="test_partition",
            data=b"Data A" * 10
        )
        shard2 = SimulatedShard(
            shard_id="comp_B",
            partition_id="test_partition",
            data=b"Data B" * 10
        )

        # Make them complementary
        shard1.complementary_shard_ids.add("comp_B")
        shard2.complementary_shard_ids.add("comp_A")

        # Distribute shards
        success1 = simulator.distribute_shard(shard1)
        success2 = simulator.distribute_shard(shard2)

        assert success1, "Failed to distribute first complementary shard"
        assert success2, "Failed to distribute second complementary shard"

        # Check that no single peer has both shards
        for peer in simulator.peers.values():
            stored_shard_ids = set(peer.stored_shards.keys())
            has_both = "comp_A" in stored_shard_ids and "comp_B" in stored_shard_ids
            assert not has_both, f"Peer {peer.peer_id} has both complementary shards"

    def test_corruption_detection_and_recovery(self):
        """Test detection and recovery from corrupted shards."""
        simulator = ShardDistributionSimulator(initial_peers=6)

        # Add corrupting peer
        simulator.add_peer("corruptor", AdversarialStrategy.CORRUPTOR)

        # Create and distribute shard
        shard = SimulatedShard(
            shard_id="test_corruption",
            partition_id="test_partition",
            data=b"Original data" * 5
        )

        simulator.distribute_shard(shard)

        # Check data integrity
        intact, copies = simulator.check_data_integrity("test_corruption")

        # Should still have intact copies despite corruption
        assert copies >= 2, f"Insufficient intact copies: {copies}"
        assert intact, "Data integrity check failed"

    def test_dropping_peer_resilience(self):
        """Test system resilience when peers drop shards."""
        simulator = ShardDistributionSimulator(initial_peers=8)

        # Add dropping peer
        simulator.add_peer("dropper", AdversarialStrategy.DROPPER)

        # Create multiple shards
        shards = []
        for i in range(4):
            shard = SimulatedShard(
                shard_id=f"drop_test_{i}",
                partition_id=f"drop_partition_{i%2}",
                data=f"Drop test data {i}".encode() * 8
            )
            shards.append(shard)
            simulator.distribute_shard(shard)

        # Check overall system health
        total_shards = len(shards)
        adequately_replicated = sum(1 for s in shards if s.is_sufficiently_replicated())

        replication_ratio = adequately_replicated / total_shards
        assert replication_ratio > 0.75, f"Poor replication resilience: {replication_ratio}"


class TestNetworkFailureIntegration:
    """Integration tests for network failure scenarios."""

    def test_partition_recovery_integration(self):
        """Test recovery from network partitions."""
        simulator = ShardDistributionSimulator(initial_peers=10)

        # Create shards
        for i in range(6):
            shard = SimulatedShard(
                shard_id=f"partition_test_{i}",
                partition_id=f"pt_partition_{i%3}",
                data=f"Partition test data {i}".encode() * 6
            )
            simulator.distribute_shard(shard)

        # Create partition
        partition_peers = ["peer_0", "peer_1", "peer_2"]
        simulator.create_network_partition("major_partition", partition_peers)

        # Check pre-recovery status
        affected_shards = set()
        for peer_id in partition_peers:
            if peer_id in simulator.peers:
                affected_shards.update(simulator.peers[peer_id].stored_shards.keys())

        # Verify some shards are affected
        assert len(affected_shards) > 0, "No shards affected by partition"

        # Heal partition
        simulator.heal_network_partition("major_partition")

        # Verify recovery
        for peer_id in partition_peers:
            if peer_id in simulator.peers:
                peer = simulator.peers[peer_id]
                assert peer.state.name == "ONLINE", f"Peer {peer_id} not recovered"
                assert peer.network_partition is None, f"Peer {peer_id} still partitioned"

    def test_cascading_failure_handling(self):
        """Test handling of cascading peer failures."""
        simulator = ShardDistributionSimulator(initial_peers=12)

        # Create highly replicated shards
        for i in range(4):
            shard = SimulatedShard(
                shard_id=f"cascade_test_{i}",
                partition_id=f"cascade_partition_{i%2}",
                data=f"Cascade test data {i}".encode() * 10,
                replication_count=5  # High replication for resilience
            )
            simulator.distribute_shard(shard)

        # Simulate cascading failures
        failed_peers = []
        for i in range(4):  # Fail 4 out of 12 peers
            if simulator.peers:
                peer_to_fail = list(simulator.peers.keys())[i]
                failed_peers.append(peer_to_fail)
                simulator.remove_peer(peer_to_fail)

        # Check system stability
        surviving_shards = sum(1 for shard in simulator.shards.values()
                              if len(shard.assignments) >= shard.replication_count)

        total_shards = len(simulator.shards)
        survival_rate = surviving_shards / total_shards if total_shards > 0 else 0

        assert survival_rate > 0.5, f"Poor cascading failure resilience: {survival_rate}"


class TestPerformanceAndScalabilityIntegration:
    """Integration tests for performance and scalability."""

    def test_large_scale_distribution(self):
        """Test distribution with large number of peers and shards."""
        # Use smaller numbers for testing but simulate scale
        simulator = ShardDistributionSimulator(initial_peers=15)

        # Create multiple shards
        shards_created = 0
        for i in range(10):
            shard = SimulatedShard(
                shard_id=f"scale_test_{i}",
                partition_id=f"scale_partition_{i%4}",
                data=f"Scale test data {i}".encode() * 5
            )

            if simulator.distribute_shard(shard):
                shards_created += 1

        # Verify successful distribution
        assert shards_created >= 8, f"Failed to distribute enough shards: {shards_created}/10"

        # Check load distribution
        peer_loads = [len(peer.stored_shards) for peer in simulator.peers.values()]
        avg_load = sum(peer_loads) / len(peer_loads)
        max_load = max(peer_loads)

        # Load should be reasonably balanced
        assert max_load <= avg_load * 2.5, f"Poor load balancing: max={max_load}, avg={avg_load}"

    def test_high_churn_environment(self):
        """Test system behavior in high churn environment."""
        simulator = ShardDistributionSimulator(initial_peers=10)

        # Initial distribution
        for i in range(5):
            shard = SimulatedShard(
                shard_id=f"churn_test_{i}",
                partition_id=f"churn_partition_{i%2}",
                data=f"Churn test data {i}".encode() * 7
            )
            simulator.distribute_shard(shard)

        # Simulate high churn period
        for step in range(20):
            # High departure rate
            if simulator.peers and len(simulator.peers) > 5:  # Keep minimum peers
                departing_peer = list(simulator.peers.keys())[0]
                simulator.remove_peer(departing_peer)

            # Moderate join rate
            if step % 3 == 0:
                new_peer_id = f"churn_peer_{step}"
                simulator.add_peer(new_peer_id)

        # Check final system state
        final_shards = len(simulator.shards)
        surviving_replications = sum(1 for shard in simulator.shards.values()
                                    if len(shard.assignments) >= 2)  # Minimum 2 copies

        survival_rate = surviving_replications / final_shards if final_shards > 0 else 0
        assert survival_rate > 0.6, f"Poor high-churn survival: {survival_rate}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])