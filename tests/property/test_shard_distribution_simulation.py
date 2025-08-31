"""
Simulation harness for P2P Sharded Backup & Distribution system.
Tests node churn, adversarial peers, network partitions, and redistribution procedures.
"""

import pytest
import asyncio
import random
import time
from typing import List, Dict, Set, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from unittest.mock import MagicMock, AsyncMock
from hypothesis import given, strategies as st, settings
from hypothesis.stateful import RuleBasedStateMachine, rule, precondition, invariant


class PeerState(Enum):
    """States a peer can be in."""
    ONLINE = "online"
    OFFLINE = "offline"
    MALICIOUS = "malicious"
    PARTITIONED = "partitioned"


class AdversarialStrategy(Enum):
    """Types of adversarial behavior."""
    PASSIVE = "passive"  # Just stores shards normally
    COLLECTOR = "collector"  # Tries to collect complementary shards
    DROPPER = "dropper"  # Drops shards to cause failures
    CORRUPTOR = "corruptor"  # Corrupts stored shards
    ISOLATOR = "isolator"  # Tries to isolate other peers


@dataclass
class SimulatedPeer:
    """Simulated peer for distribution testing."""
    peer_id: str
    state: PeerState = PeerState.ONLINE
    capacity: int = 100 * 1024 * 1024  # 100MB
    used_capacity: int = 0
    stored_shards: Dict[str, bytes] = field(default_factory=dict)
    reputation_score: float = 1.0
    adversarial_strategy: Optional[AdversarialStrategy] = None
    join_time: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    network_partition: Optional[str] = None

    def can_store_shard(self, shard_size: int) -> bool:
        """Check if peer can store a shard."""
        return (self.state == PeerState.ONLINE and
                self.used_capacity + shard_size <= self.capacity and
                self.network_partition is None)

    def store_shard(self, shard_id: str, shard_data: bytes) -> bool:
        """Store a shard (with potential adversarial behavior)."""
        if not self.can_store_shard(len(shard_data)):
            return False

        # Apply adversarial behavior
        if self.adversarial_strategy == AdversarialStrategy.DROPPER:
            if random.random() < 0.3:  # 30% chance to drop
                return False
        elif self.adversarial_strategy == AdversarialStrategy.CORRUPTOR:
            if random.random() < 0.2:  # 20% chance to corrupt
                shard_data = shard_data[:len(shard_data)//2] + b'CORRUPTED' + shard_data[len(shard_data)//2:]

        self.stored_shards[shard_id] = shard_data
        self.used_capacity += len(shard_data)
        return True

    def retrieve_shard(self, shard_id: str) -> Optional[bytes]:
        """Retrieve a shard."""
        if self.state != PeerState.ONLINE or self.network_partition is not None:
            return None
        return self.stored_shards.get(shard_id)

    def has_complementary_shard(self, shard_id: str, complementary_ids: Set[str]) -> bool:
        """Check if peer has complementary shards."""
        return any(comp_id in self.stored_shards for comp_id in complementary_ids)


@dataclass
class SimulatedShard:
    """Simulated shard with metadata."""
    shard_id: str
    partition_id: str
    data: bytes
    complementary_shard_ids: Set[str] = field(default_factory=set)
    replication_count: int = 3
    assignments: Dict[str, SimulatedPeer] = field(default_factory=dict)  # peer_id -> peer

    def is_sufficiently_replicated(self) -> bool:
        """Check if shard has sufficient replication."""
        online_assignments = sum(1 for peer in self.assignments.values()
                               if peer.state == PeerState.ONLINE and peer.network_partition is None)
        return online_assignments >= self.replication_count


@dataclass
class NetworkPartition:
    """Represents a network partition."""
    partition_id: str
    affected_peers: Set[str]
    start_time: float = field(default_factory=time.time)
    duration: float = 300.0  # 5 minutes default


class ShardDistributionSimulator:
    """Simulator for shard distribution scenarios."""

    def __init__(self, initial_peers: int = 10):
        self.peers: Dict[str, SimulatedPeer] = {}
        self.shards: Dict[str, SimulatedShard] = {}
        self.network_partitions: List[NetworkPartition] = []
        self.current_time: float = time.time()
        self.churn_events: List[Dict] = []

        # Initialize peers
        for i in range(initial_peers):
            self.add_peer(f"peer_{i}")

    def add_peer(self, peer_id: str, adversarial_strategy: Optional[AdversarialStrategy] = None) -> SimulatedPeer:
        """Add a new peer to the network."""
        peer = SimulatedPeer(
            peer_id=peer_id,
            adversarial_strategy=adversarial_strategy
        )
        self.peers[peer_id] = peer
        self.churn_events.append({
            'type': 'join',
            'peer_id': peer_id,
            'time': self.current_time,
            'strategy': adversarial_strategy.value if adversarial_strategy else None
        })
        return peer

    def remove_peer(self, peer_id: str):
        """Remove a peer from the network."""
        if peer_id in self.peers:
            peer = self.peers[peer_id]
            # Redistribute shards from this peer
            affected_shards = list(peer.stored_shards.keys())
            del self.peers[peer_id]

            self.churn_events.append({
                'type': 'leave',
                'peer_id': peer_id,
                'time': self.current_time,
                'affected_shards': affected_shards
            })

            # Trigger redistribution for affected shards
            self._redistribute_affected_shards(affected_shards)

    def create_network_partition(self, partition_id: str, affected_peer_ids: List[str], duration: float = 300.0):
        """Create a network partition affecting specific peers."""
        partition = NetworkPartition(
            partition_id=partition_id,
            affected_peers=set(affected_peer_ids),
            duration=duration
        )
        self.network_partitions.append(partition)

        # Update peer states
        for peer_id in affected_peer_ids:
            if peer_id in self.peers:
                self.peers[peer_id].network_partition = partition_id
                self.peers[peer_id].state = PeerState.PARTITIONED

    def heal_network_partition(self, partition_id: str):
        """Heal a network partition."""
        self.network_partitions = [p for p in self.network_partitions if p.partition_id != partition_id]

        # Update peer states
        for peer in self.peers.values():
            if peer.network_partition == partition_id:
                peer.network_partition = None
                peer.state = PeerState.ONLINE

    def distribute_shard(self, shard: SimulatedShard) -> bool:
        """Distribute a shard according to constraints."""
        available_peers = [p for p in self.peers.values() if p.can_store_shard(len(shard.data))]

        # Apply complementary shard constraint
        suitable_peers = []
        for peer in available_peers:
            if not peer.has_complementary_shard(shard.shard_id, shard.complementary_shard_ids):
                suitable_peers.append(peer)

        if len(suitable_peers) < shard.replication_count:
            return False  # Cannot satisfy constraints

        # Select peers (prioritize non-malicious for legitimate distribution)
        legitimate_peers = [p for p in suitable_peers if p.adversarial_strategy is None]
        if len(legitimate_peers) >= shard.replication_count:
            selected_peers = legitimate_peers[:shard.replication_count]
        else:
            selected_peers = suitable_peers[:shard.replication_count]

        # Assign shard to selected peers
        for peer in selected_peers:
            if peer.store_shard(shard.shard_id, shard.data):
                shard.assignments[peer.peer_id] = peer

        self.shards[shard.shard_id] = shard
        return len(shard.assignments) >= shard.replication_count

    def _redistribute_affected_shards(self, affected_shard_ids: List[str]):
        """Redistribute shards affected by peer departure."""
        for shard_id in affected_shard_ids:
            if shard_id in self.shards:
                shard = self.shards[shard_id]
                # Find peers that still have this shard
                surviving_assignments = {
                    pid: peer for pid, peer in shard.assignments.items()
                    if pid in self.peers and peer.state == PeerState.ONLINE
                }

                # If we don't have enough replicas, create new ones
                if len(surviving_assignments) < shard.replication_count:
                    needed = shard.replication_count - len(surviving_assignments)
                    available_peers = [
                        p for p in self.peers.values()
                        if p.can_store_shard(len(shard.data)) and
                        p.peer_id not in shard.assignments and
                        not p.has_complementary_shard(shard.shard_id, shard.complementary_shard_ids)
                    ]

                    for peer in available_peers[:needed]:
                        if peer.store_shard(shard.shard_id, shard.data):
                            shard.assignments[peer.peer_id] = peer

    def check_data_integrity(self, shard_id: str) -> Tuple[bool, int]:
        """Check integrity of a shard across all assignments."""
        if shard_id not in self.shards:
            return False, 0

        shard = self.shards[shard_id]
        intact_copies = 0
        total_assignments = len(shard.assignments)

        for peer in shard.assignments.values():
            retrieved_data = peer.retrieve_shard(shard_id)
            if retrieved_data is not None and retrieved_data == shard.data:
                intact_copies += 1

        return intact_copies >= shard.replication_count, intact_copies

    def simulate_adversarial_collection_attempt(self, target_shard_id: str) -> bool:
        """Simulate an adversarial peer trying to collect complementary shards."""
        if target_shard_id not in self.shards:
            return False

        target_shard = self.shards[target_shard_id]
        complementary_ids = target_shard.complementary_shard_ids

        if not complementary_ids:
            return False  # No complementary shards to collect

        # Find malicious peers
        malicious_peers = [p for p in self.peers.values() if p.adversarial_strategy == AdversarialStrategy.COLLECTOR]

        for malicious_peer in malicious_peers:
            collected_complements = 0
            for comp_id in complementary_ids:
                if comp_id in malicious_peer.stored_shards:
                    collected_complements += 1

            # If malicious peer has both target and complement, reconstruction is possible
            if target_shard_id in malicious_peer.stored_shards and collected_complements > 0:
                return True  # Security breach detected

        return False


class TestNodeChurnSimulation:
    """Tests for node churn scenarios."""

    @given(
        initial_peers=st.integers(min_value=5, max_value=20),
        churn_rate=st.floats(min_value=0.1, max_value=0.8),
        simulation_steps=st.integers(min_value=10, max_value=50)
    )
    def test_churn_resilience(self, initial_peers, churn_rate, simulation_steps):
        """Test system resilience under various churn rates."""
        simulator = ShardDistributionSimulator(initial_peers)

        # Create some shards
        shards = []
        for i in range(5):
            shard_data = f"Test data for shard {i}".encode() * 10
            shard = SimulatedShard(
                shard_id=f"shard_{i}",
                partition_id=f"partition_{i%2}",
                data=shard_data
            )
            # Make some shards complementary
            if i % 2 == 0 and i + 1 < 5:
                shard.complementary_shard_ids.add(f"shard_{i+1}")
                simulator.shards[f"shard_{i+1}"] = SimulatedShard(
                    shard_id=f"shard_{i+1}",
                    partition_id=f"partition_{(i+1)%2}",
                    data=f"Complementary data {i+1}".encode() * 10
                )
                simulator.shards[f"shard_{i+1}"].complementary_shard_ids.add(f"shard_{i}")

            shards.append(shard)
            simulator.distribute_shard(shard)

        # Simulate churn
        for step in range(simulation_steps):
            # Random peer departure
            if random.random() < churn_rate and simulator.peers:
                departing_peer = random.choice(list(simulator.peers.keys()))
                simulator.remove_peer(departing_peer)

            # Random peer join
            if random.random() < churn_rate * 0.5:  # Lower join rate
                new_peer_id = f"new_peer_{step}"
                simulator.add_peer(new_peer_id)

        # Check that system maintains basic functionality
        total_shards = len(simulator.shards)
        adequately_replicated = sum(1 for shard in simulator.shards.values() if shard.is_sufficiently_replicated())

        # Should maintain reasonable replication even under churn
        replication_ratio = adequately_replicated / total_shards if total_shards > 0 else 0
        assert replication_ratio > 0.6, f"Poor replication under churn: {replication_ratio}"

    @given(
        peer_count=st.integers(min_value=8, max_value=25),
        malicious_ratio=st.floats(min_value=0.1, max_value=0.4)
    )
    def test_adversarial_peer_detection(self, peer_count, malicious_ratio):
        """Test detection and handling of adversarial peers."""
        simulator = ShardDistributionSimulator(0)  # Start with no peers

        # Add legitimate peers
        legitimate_count = int(peer_count * (1 - malicious_ratio))
        for i in range(legitimate_count):
            simulator.add_peer(f"legit_peer_{i}")

        # Add malicious peers
        malicious_count = peer_count - legitimate_count
        for i in range(malicious_count):
            strategy = random.choice(list(AdversarialStrategy))
            simulator.add_peer(f"mal_peer_{i}", strategy)

        # Create shards with complementary relationships
        for i in range(0, 6, 2):
            shard1_data = f"Data A{i}".encode() * 20
            shard2_data = f"Data B{i}".encode() * 20

            shard1 = SimulatedShard(
                shard_id=f"comp_shard_{i}",
                partition_id=f"comp_partition_{i//2}",
                data=shard1_data
            )
            shard2 = SimulatedShard(
                shard_id=f"comp_shard_{i+1}",
                partition_id=f"comp_partition_{i//2}",
                data=shard2_data
            )

            # Make them complementary
            shard1.complementary_shard_ids.add(shard2.shard_id)
            shard2.complementary_shard_ids.add(shard1.shard_id)

            simulator.distribute_shard(shard1)
            simulator.distribute_shard(shard2)

        # Check for security breaches
        breach_detected = False
        for shard_id in simulator.shards:
            if simulator.simulate_adversarial_collection_attempt(shard_id):
                breach_detected = True
                break

        # With proper distribution, breaches should be rare
        if malicious_ratio < 0.3:
            assert not breach_detected, "Security breach detected with low malicious ratio"
        else:
            # High malicious ratio might lead to breaches
            pass  # Acceptable for high adversarial presence


class TestNetworkPartitionSimulation:
    """Tests for network partition scenarios."""

    @given(
        total_peers=st.integers(min_value=10, max_value=30),
        partition_size=st.integers(min_value=2, max_value=8),
        partition_duration=st.integers(min_value=60, max_value=1800)  # 1 min to 30 min
    )
    def test_partition_recovery(self, total_peers, partition_size, partition_duration):
        """Test recovery from network partitions."""
        simulator = ShardDistributionSimulator(total_peers)

        # Create and distribute shards
        shards = []
        for i in range(8):
            shard = SimulatedShard(
                shard_id=f"partition_test_shard_{i}",
                partition_id=f"pt_partition_{i%3}",
                data=f"Partition test data {i}".encode() * 15
            )
            simulator.distribute_shard(shard)
            shards.append(shard)

        # Create partition
        all_peer_ids = list(simulator.peers.keys())
        partition_peer_ids = random.sample(all_peer_ids, min(partition_size, len(all_peer_ids)))
        simulator.create_network_partition("test_partition", partition_peer_ids, partition_duration)

        # Check initial impact
        affected_shards = set()
        for peer_id in partition_peer_ids:
            if peer_id in simulator.peers:
                affected_shards.update(simulator.peers[peer_id].stored_shards.keys())

        # Verify affected shards still have minimum replication
        for shard_id in affected_shards:
            if shard_id in simulator.shards:
                shard = simulator.shards[shard_id]
                online_assignments = sum(1 for peer in shard.assignments.values()
                                       if peer.state == PeerState.ONLINE)
                # Should still have at least some replication
                assert online_assignments >= 1, f"Shard {shard_id} lost all replicas during partition"

        # Heal partition
        simulator.heal_network_partition("test_partition")

        # Verify recovery
        for peer_id in partition_peer_ids:
            if peer_id in simulator.peers:
                assert simulator.peers[peer_id].state == PeerState.ONLINE
                assert simulator.peers[peer_id].network_partition is None


class TestRedistributionProcedures:
    """Tests for shard redistribution procedures."""

    @given(
        initial_peers=st.integers(min_value=8, max_value=20),
        departure_count=st.integers(min_value=1, max_size=5)
    )
    def test_graceful_redistribution(self, initial_peers, departure_count):
        """Test graceful redistribution when peers depart."""
        simulator = ShardDistributionSimulator(initial_peers)

        # Create shards
        for i in range(6):
            shard = SimulatedShard(
                shard_id=f"redist_shard_{i}",
                partition_id=f"redist_partition_{i%2}",
                data=f"Redistribution test data {i}".encode() * 12
            )
            simulator.distribute_shard(shard)

        # Record initial replication status
        initial_replication = {}
        for shard_id, shard in simulator.shards.items():
            initial_replication[shard_id] = len(shard.assignments)

        # Simulate peer departures
        departed_peers = []
        for _ in range(min(departure_count, len(simulator.peers) - 3)):  # Keep at least 3 peers
            if simulator.peers:
                departing_peer = random.choice(list(simulator.peers.keys()))
                departed_peers.append(departing_peer)
                simulator.remove_peer(departing_peer)

        # Check redistribution effectiveness
        for shard_id, shard in simulator.shards.items():
            current_assignments = len(shard.assignments)
            initial_assignments = initial_replication[shard_id]

            # Should maintain minimum replication
            assert current_assignments >= shard.replication_count, \
                f"Shard {shard_id} lost replication: {current_assignments} < {shard.replication_count}"

            # Should not have excessive replication loss
            loss_ratio = (initial_assignments - current_assignments) / initial_assignments
            assert loss_ratio < 0.5, f"Excessive replication loss for {shard_id}: {loss_ratio}"

    @given(
        peer_count=st.integers(min_value=10, max_value=25),
        failure_rate=st.floats(min_value=0.1, max_value=0.5)
    )
    def test_failure_scenario_redistribution(self, peer_count, failure_rate):
        """Test redistribution under failure scenarios."""
        simulator = ShardDistributionSimulator(peer_count)

        # Create shards with higher replication for resilience
        for i in range(5):
            shard = SimulatedShard(
                shard_id=f"failure_shard_{i}",
                partition_id=f"failure_partition_{i%2}",
                data=f"Failure test data {i}".encode() * 10,
                replication_count=4  # Higher replication for failure testing
            )
            simulator.distribute_shard(shard)

        # Simulate failures
        failed_peers = []
        for peer_id, peer in list(simulator.peers.items()):
            if random.random() < failure_rate:
                failed_peers.append(peer_id)
                simulator.remove_peer(peer_id)

        # Check system resilience
        total_shards = len(simulator.shards)
        surviving_shards = sum(1 for shard in simulator.shards.values()
                              if len(shard.assignments) >= shard.replication_count)

        survival_rate = surviving_shards / total_shards if total_shards > 0 else 0

        # With higher replication, should maintain better survival
        if failure_rate < 0.3:
            assert survival_rate > 0.8, f"Poor survival with low failure rate: {survival_rate}"
        elif failure_rate > 0.4:
            # High failure rate might cause some losses but shouldn't be catastrophic
            assert survival_rate > 0.4, f"Catastrophic failure with high rate: {survival_rate}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])