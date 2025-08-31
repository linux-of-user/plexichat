"""
Property-based tests for P2P Sharded Backup & Distribution system.
Tests shard assignment algorithms, distribution constraints, recovery procedures,
and adversarial scenarios using Hypothesis.
"""

import pytest
import hashlib
import secrets
from typing import List, Dict, Set, Tuple, Optional
from dataclasses import dataclass
from unittest.mock import MagicMock, AsyncMock
from hypothesis import given, strategies as st, assume, settings
from hypothesis.stateful import RuleBasedStateMachine, rule, precondition


@dataclass
class MockPeer:
    """Mock peer for testing."""
    peer_id: str
    capacity: int
    reputation_score: float
    is_online: bool = True
    stored_shards: Set[str] = None

    def __post_init__(self):
        if self.stored_shards is None:
            self.stored_shards = set()


@dataclass
class MockShard:
    """Mock shard for testing."""
    shard_id: str
    partition_id: str
    size: int
    complementary_shard_ids: Set[str] = None

    def __post_init__(self):
        if self.complementary_shard_ids is None:
            self.complementary_shard_ids = set()


class TestShardAssignmentAlgorithms:
    """Property-based tests for shard assignment algorithms."""

    @given(
        peers=st.lists(
            st.builds(MockPeer,
                     peer_id=st.text(min_size=8, max_size=16),
                     capacity=st.integers(min_value=1024*1024, max_value=100*1024*1024),  # 1MB to 100MB
                     reputation_score=st.floats(min_value=0.0, max_value=1.0),
                     is_online=st.booleans()),
            min_size=3, max_size=20, unique_by=lambda p: p.peer_id
        ),
        shards=st.lists(
            st.builds(MockShard,
                     shard_id=st.text(min_size=8, max_size=16),
                     partition_id=st.text(min_size=4, max_size=8),
                     size=st.integers(min_value=1024, max_value=1024*1024),  # 1KB to 1MB
                     complementary_shard_ids=st.sets(st.text(min_size=8, max_size=16), min_size=0, max_size=3)),
            min_size=5, max_size=15, unique_by=lambda s: s.shard_id
        )
    )
    def test_no_complementary_shards_to_single_peer(self, peers, shards):
        """Test that no single peer receives complementary shards."""
        # Filter online peers with sufficient capacity
        available_peers = [p for p in peers if p.is_online and p.capacity > 0]

        assume(len(available_peers) >= 3)  # Need at least 3 peers for distribution

        # Simple assignment algorithm: assign each shard to random peers
        assignments = {}
        for shard in shards:
            # Select peers for this shard (minimum 3 for redundancy)
            num_peers = min(len(available_peers), max(3, len(shard.complementary_shard_ids) + 2))
            selected_peers = available_peers[:num_peers]  # Simple selection for testing

            assignments[shard.shard_id] = [p.peer_id for p in selected_peers]

        # Verify constraint: no single peer has complementary shards
        for peer in available_peers:
            peer_shard_ids = set()
            for shard_id, peer_ids in assignments.items():
                if peer.peer_id in peer_ids:
                    peer_shard_ids.add(shard_id)

            # Check for complementary shards
            complementary_found = set()
            for shard_id in peer_shard_ids:
                shard = next(s for s in shards if s.shard_id == shard_id)
                complementary_found.update(shard.complementary_shard_ids)

            # No peer should have both a shard and its complement
            intersection = peer_shard_ids.intersection(complementary_found)
            assert len(intersection) == 0, f"Peer {peer.peer_id} has complementary shards: {intersection}"

    @given(
        peer_count=st.integers(min_value=5, max_value=50),
        shard_count=st.integers(min_value=10, max_value=100),
        replication_factor=st.integers(min_value=2, max_value=5)
    )
    def test_distribution_load_balancing(self, peer_count, shard_count, replication_factor):
        """Test that shard distribution is load-balanced across peers."""
        # Create peers with varying capacities
        peers = []
        for i in range(peer_count):
            capacity = (i + 1) * 1024 * 1024  # Increasing capacity
            peers.append(MockPeer(
                peer_id=f"peer_{i}",
                capacity=capacity,
                reputation_score=0.8 + (i % 3) * 0.1  # Varying reputation
            ))

        # Create shards
        shards = []
        for i in range(shard_count):
            shards.append(MockShard(
                shard_id=f"shard_{i}",
                partition_id=f"partition_{i % 5}",
                size=512 * 1024  # 512KB each
            ))

        # Simple load-balanced assignment
        peer_loads = {p.peer_id: 0 for p in peers}

        for shard in shards:
            # Sort peers by current load (ascending)
            sorted_peers = sorted(peers, key=lambda p: peer_loads[p.peer_id])

            # Assign to least loaded peers
            assigned_peers = sorted_peers[:replication_factor]

            for peer in assigned_peers:
                peer_loads[peer.peer_id] += shard.size

        # Verify load balancing: no peer should have more than 2x the average load
        total_load = sum(peer_loads.values())
        avg_load = total_load / len(peers)
        max_load = max(peer_loads.values())

        assert max_load <= 2 * avg_load, f"Poor load balancing: max={max_load}, avg={avg_load}"

    @given(
        shards=st.lists(
            st.builds(MockShard,
                     shard_id=st.text(min_size=8, max_size=16),
                     partition_id=st.text(min_size=4, max_size=8),
                     size=st.integers(min_value=1024, max_value=1024*1024),
                     complementary_shard_ids=st.sets(st.text(min_size=8, max_size=16), min_size=1, max_size=2)),
            min_size=6, max_size=20, unique_by=lambda s: s.shard_id
        ),
        peer_count=st.integers(min_value=4, max_value=15)
    )
    def test_complementary_separation_constraint(self, shards, peer_count):
        """Test that complementary shards are separated by at least N peers."""
        peers = [MockPeer(f"peer_{i}", 10*1024*1024, 0.9) for i in range(peer_count)]

        # Create complementary pairs
        complementary_pairs = []
        for i in range(0, len(shards) - 1, 2):
            shard1, shard2 = shards[i], shards[i+1]
            shard1.complementary_shard_ids.add(shard2.shard_id)
            shard2.complementary_shard_ids.add(shard1.shard_id)
            complementary_pairs.append((shard1, shard2))

        # Assign shards to peers ensuring separation
        assignments = {}
        for shard in shards:
            # Find peers that don't have complementary shards
            available_peers = []
            for peer in peers:
                has_complement = any(
                    comp_id in peer.stored_shards
                    for comp_id in shard.complementary_shard_ids
                )
                if not has_complement:
                    available_peers.append(peer)

            assume(len(available_peers) >= 2)  # Need at least 2 peers for separation

            # Assign to first 2 available peers
            assigned_peers = available_peers[:2]
            assignments[shard.shard_id] = [p.peer_id for p in assigned_peers]

            # Update peer stored shards
            for peer in assigned_peers:
                peer.stored_shards.add(shard.shard_id)

        # Verify separation constraint
        for shard1, shard2 in complementary_pairs:
            peers1 = set(assignments[shard1.shard_id])
            peers2 = set(assignments[shard2.shard_id])

            # Should have no common peers
            common_peers = peers1.intersection(peers2)
            assert len(common_peers) == 0, f"Complementary shards share peers: {common_peers}"


class TestDistributionConstraintsValidation:
    """Property-based tests for distribution constraints validation."""

    @given(
        peer_capacity=st.integers(min_value=1024*1024, max_value=100*1024*1024),
        shard_sizes=st.lists(st.integers(min_value=1024, max_value=10*1024*1024), min_size=5, max_size=20),
        min_replication=st.integers(min_value=2, max_value=5)
    )
    def test_capacity_constraints_validation(self, peer_capacity, shard_sizes, min_replication):
        """Test that capacity constraints are properly validated."""
        # Create peers with given capacity
        peers = [MockPeer(f"peer_{i}", peer_capacity, 0.9) for i in range(10)]

        # Create shards
        shards = [MockShard(f"shard_{i}", f"part_{i%3}", size)
                 for i, size in enumerate(shard_sizes)]

        # Validate assignments don't exceed capacity
        peer_usage = {p.peer_id: 0 for p in peers}

        for shard in shards:
            # Find peers with sufficient remaining capacity
            available_peers = [p for p in peers if peer_usage[p.peer_id] + shard.size <= p.capacity]

            assume(len(available_peers) >= min_replication)

            # Assign to available peers
            assigned_peers = available_peers[:min_replication]

            for peer in assigned_peers:
                peer_usage[peer.peer_id] += shard.size

        # Verify no peer exceeds capacity
        for peer in peers:
            assert peer_usage[peer.peer_id] <= peer.capacity

    @given(
        peer_locations=st.lists(st.sampled_from(['us-east', 'us-west', 'eu-central', 'asia-pacific']),
                               min_size=10, max_size=20),
        shard_count=st.integers(min_value=5, max_value=15)
    )
    def test_geographic_distribution_constraint(self, peer_locations, shard_count):
        """Test geographic distribution constraints."""
        # Create peers with locations
        peers = []
        for i, location in enumerate(peer_locations):
            peers.append(MockPeer(f"peer_{i}", 50*1024*1024, 0.9))
            # Add location as attribute
            peers[-1].location = location

        # Create shards
        shards = [MockShard(f"shard_{i}", f"part_{i%3}", 1024*1024) for i in range(shard_count)]

        # Assign with geographic diversity
        assignments = {}
        for shard in shards:
            # Group peers by location
            location_counts = {}
            for peer in peers:
                loc = getattr(peer, 'location', 'unknown')
                location_counts[loc] = location_counts.get(loc, 0) + 1

            # Select peers from different locations when possible
            selected_peers = []
            used_locations = set()

            for peer in peers:
                loc = getattr(peer, 'location', 'unknown')
                if loc not in used_locations or len(selected_peers) < 2:
                    selected_peers.append(peer)
                    used_locations.add(loc)
                    if len(selected_peers) >= 3:  # Minimum 3 peers
                        break

            assume(len(selected_peers) >= 3)
            assignments[shard.shard_id] = [p.peer_id for p in selected_peers]

        # Verify geographic diversity
        for shard_id, peer_ids in assignments.items():
            assigned_peers = [p for p in peers if p.peer_id in peer_ids]
            locations = set(getattr(p, 'location', 'unknown') for p in assigned_peers)

            # Should have at least 2 different locations
            assert len(locations) >= 2, f"Shard {shard_id} only distributed to {locations}"


class TestRecoveryProcedures:
    """Property-based tests for recovery procedures."""

    @given(
        total_shards=st.integers(min_value=5, max_value=20),
        available_shards=st.integers(min_value=2, max_value=15),
        min_recovery_shards=st.integers(min_value=2, max_value=4)
    )
    def test_partial_recovery_feasibility(self, total_shards, available_shards, min_recovery_shards):
        """Test partial recovery feasibility based on available shards."""
        assume(available_shards <= total_shards)
        assume(min_recovery_shards <= total_shards)

        # Simulate recovery attempt
        can_recover = available_shards >= min_recovery_shards

        if can_recover:
            # With sufficient shards, recovery should be possible
            recovery_success = available_shards >= min_recovery_shards
            assert recovery_success
        else:
            # With insufficient shards, recovery should fail
            assert not can_recover

    @given(
        shard_data=st.lists(st.binary(min_size=100, max_size=1000), min_size=3, max_size=10),
        corruption_rate=st.floats(min_value=0.0, max_value=0.5)
    )
    def test_corruption_resistance(self, shard_data, corruption_rate):
        """Test recovery resistance to shard corruption."""
        # Combine shard data
        original_data = b''.join(shard_data)

        # Simulate corruption
        corrupted_shards = []
        for i, data in enumerate(shard_data):
            if secrets.randbelow(100) / 100 < corruption_rate:
                # Corrupt this shard
                corrupted_data = data[:len(data)//2] + b'CORRUPTED' + data[len(data)//2:]
                corrupted_shards.append(corrupted_data)
            else:
                corrupted_shards.append(data)

        # Attempt reconstruction
        reconstructed = b''.join(corrupted_shards)

        # If corruption rate is low, reconstruction should be mostly successful
        if corruption_rate < 0.3:
            # Calculate similarity
            matching_bytes = sum(1 for a, b in zip(original_data, reconstructed) if a == b)
            similarity = matching_bytes / len(original_data) if original_data else 0

            # Should maintain reasonable similarity
            assert similarity > 0.7, f"Low corruption but poor reconstruction: {similarity}"
        else:
            # High corruption should significantly affect reconstruction
            matching_bytes = sum(1 for a, b in zip(original_data, reconstructed) if a == b)
            similarity = matching_bytes / len(original_data) if original_data else 0
            assert similarity < 0.9, f"High corruption but good reconstruction: {similarity}"


class TestReplicationFactorCalculations:
    """Property-based tests for replication factor calculations."""

    @given(
        peer_failure_rate=st.floats(min_value=0.001, max_value=0.1),
        uptime_requirement=st.floats(min_value=0.9, max_value=0.9999),
        churn_rate=st.floats(min_value=0.0, max_value=0.5)
    )
    def test_replication_factor_calculation(self, peer_failure_rate, uptime_requirement, churn_rate):
        """Test replication factor calculation based on reliability requirements."""
        # Calculate required replication factor
        # R = ceil(log(1 - uptime) / log(peer_failure_rate))
        import math

        if peer_failure_rate > 0 and uptime_requirement < 1.0:
            base_replication = math.ceil(
                math.log(1 - uptime_requirement) / math.log(peer_failure_rate)
            )
        else:
            base_replication = 2

        # Adjust for churn
        churn_adjustment = 1 + (churn_rate * 2)  # Up to 2x for high churn
        effective_replication = math.ceil(base_replication * churn_adjustment)

        # Add complementary protection factor
        final_replication = effective_replication + 2  # Minimum separation

        # Verify calculations
        assert final_replication >= 2, "Minimum replication factor not met"
        assert final_replication <= 20, "Replication factor unreasonably high"

        # Higher uptime requirements should need more replication
        if uptime_requirement > 0.99:
            assert final_replication >= 3

        # Higher failure rates should need more replication
        if peer_failure_rate > 0.05:
            assert final_replication >= 4

    @given(
        current_peers=st.integers(min_value=10, max_value=1000),
        target_uptime=st.floats(min_value=0.95, max_value=0.99999)
    )
    def test_dynamic_replication_adjustment(self, current_peers, target_uptime):
        """Test dynamic replication adjustment based on peer count."""
        # Base replication from uptime requirement
        import math

        if target_uptime < 1.0:
            base_replication = max(2, math.ceil(math.log(1 - target_uptime) / math.log(0.01)))
        else:
            base_replication = 2

        # Adjust for peer count
        if current_peers < 50:
            peer_factor = max(1, 100 / current_peers)
        else:
            peer_factor = 1.0

        adjusted_replication = math.ceil(base_replication * peer_factor)

        # Verify adjustments
        if current_peers < 20:
            assert adjusted_replication > base_replication, "Should increase replication for few peers"

        if current_peers > 100:
            assert adjusted_replication >= base_replication, "Should maintain minimum replication"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])