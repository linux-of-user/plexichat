"""
Pytest fixtures and configuration for property-based tests.
"""

import pytest
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, AsyncMock
from typing import Dict, List, Any

from .test_shard_distribution_simulation import (
    ShardDistributionSimulator,
    SimulatedPeer,
    SimulatedShard,
    AdversarialStrategy,
    PeerState
)


@pytest.fixture
def mock_encryption_service():
    """Create mock encryption service for testing."""
    service = MagicMock()
    service.encrypt_data_async = AsyncMock(return_value=(b"encrypted_data", {"key_id": "test_key"}))
    service.decrypt_data_async = AsyncMock(return_value=b"decrypted_data")
    service.get_key_hash = MagicMock(return_value="key_hash_123")
    return service


@pytest.fixture
def mock_storage_manager():
    """Create mock storage manager for testing."""
    manager = MagicMock()
    manager.store_shards_async = AsyncMock(return_value=[MagicMock(location="s3://test")])
    manager.retrieve_shards = AsyncMock(return_value=[])
    manager.verify_backup_shards_async = AsyncMock(return_value={"all_shards_valid": True})
    return manager


@pytest.fixture
def basic_simulator():
    """Create basic shard distribution simulator."""
    return ShardDistributionSimulator(initial_peers=5)


@pytest.fixture
def adversarial_simulator():
    """Create simulator with adversarial peers."""
    simulator = ShardDistributionSimulator(initial_peers=0)

    # Add legitimate peers
    for i in range(6):
        simulator.add_peer(f"legit_peer_{i}")

    # Add adversarial peers
    simulator.add_peer("mal_peer_1", AdversarialStrategy.COLLECTOR)
    simulator.add_peer("mal_peer_2", AdversarialStrategy.DROPPER)

    return simulator


@pytest.fixture
def partitioned_simulator():
    """Create simulator with network partitions."""
    simulator = ShardDistributionSimulator(initial_peers=8)

    # Create partition affecting some peers
    partition_peers = ["peer_0", "peer_1", "peer_2"]
    simulator.create_network_partition("partition_1", partition_peers, duration=600)

    return simulator


@pytest.fixture
def mock_peer_network():
    """Create mock peer network for testing."""
    peers = {}
    for i in range(10):
        peer = SimulatedPeer(
            peer_id=f"peer_{i}",
            capacity=50 * 1024 * 1024,  # 50MB
            reputation_score=0.9
        )
        peers[peer.peer_id] = peer

    return peers


@pytest.fixture
def mock_shard_data():
    """Create mock shard data for testing."""
    shards = {}
    for i in range(5):
        shard = SimulatedShard(
            shard_id=f"shard_{i}",
            partition_id=f"partition_{i % 2}",
            data=f"Test data for shard {i}".encode() * 10
        )

        # Create complementary relationships
        if i % 2 == 0 and i + 1 < 5:
            shard.complementary_shard_ids.add(f"shard_{i+1}")

        shards[shard.shard_id] = shard

    return shards


@pytest.fixture
def temp_test_directory():
    """Create temporary directory for test files."""
    temp_dir = tempfile.mkdtemp()
    yield Path(temp_dir)

    # Cleanup
    import shutil
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def mock_backup_metadata():
    """Create mock backup metadata."""
    return {
        "backup_id": "test_backup_123",
        "backup_type": "full",
        "security_level": "standard",
        "original_size": 1024000,
        "compressed_size": 512000,
        "encrypted_size": 512000,
        "shard_count": 5,
        "checksum": "test_checksum_123",
        "recovery_info": {
            "key_hash": "key_hash_456",
            "algorithm": "AES-256-GCM"
        }
    }


@pytest.fixture
def mock_adversarial_peer():
    """Create mock adversarial peer."""
    peer = SimulatedPeer(
        peer_id="adversarial_peer",
        capacity=100 * 1024 * 1024,
        reputation_score=0.3,  # Low reputation
        adversarial_strategy=AdversarialStrategy.COLLECTOR
    )
    return peer


@pytest.fixture
def mock_distribution_strategy():
    """Create mock distribution strategy configuration."""
    return {
        "min_replication_factor": 3,
        "max_replication_factor": 5,
        "geographic_distribution_required": True,
        "complementary_separation_required": True,
        "adversarial_detection_enabled": True,
        "churn_tolerance_factor": 0.2,
        "network_partition_tolerance": 0.3
    }


@pytest.fixture
def mock_recovery_scenario():
    """Create mock recovery scenario data."""
    return {
        "total_shards": 5,
        "available_shards": 4,
        "corrupted_shards": 1,
        "min_recovery_shards": 3,
        "recovery_type": "partial",
        "expected_success": True,
        "estimated_recovery_time": 300  # seconds
    }


@pytest.fixture
def mock_threat_model_config():
    """Create mock threat model configuration."""
    return {
        "reconstruction_attack_prevention": True,
        "collusion_attack_detection": True,
        "sybil_attack_mitigation": True,
        "metadata_leakage_protection": True,
        "timing_attack_protection": False,  # Not implemented yet
        "side_channel_protection": False,   # Not implemented yet
        "quantum_resistance": False         # Not implemented yet
    }


@pytest.fixture
def performance_test_config():
    """Create configuration for performance testing."""
    return {
        "max_test_duration": 300,  # 5 minutes
        "max_memory_usage": 512 * 1024 * 1024,  # 512MB
        "concurrency_level": 10,
        "network_latency_simulation": 50,  # ms
        "churn_event_frequency": 30,  # seconds
        "adversarial_action_frequency": 60  # seconds
    }


@pytest.fixture
def compliance_test_config():
    """Create configuration for compliance testing."""
    return {
        "gdpr_compliance_required": True,
        "hipaa_compliance_required": False,
        "sox_compliance_required": False,
        "iso27001_compliance_required": True,
        "data_retention_days": 2555,  # 7 years
        "audit_trail_required": True,
        "anonymization_required": True
    }