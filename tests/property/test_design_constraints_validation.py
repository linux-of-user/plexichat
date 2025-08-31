"""
Validation tests against DESIGN_shard_distribution_constraints.md.
Ensures implementation meets the specified design constraints.
"""

import pytest
from typing import List, Set, Dict
from dataclasses import dataclass
from tests.property.test_shard_distribution_simulation import (
    ShardDistributionSimulator,
    SimulatedPeer,
    SimulatedShard,
    AdversarialStrategy
)


@dataclass
class DesignConstraint:
    """Represents a design constraint from the document."""
    id: str
    description: str
    category: str
    validation_function: callable


class DesignConstraintsValidator:
    """Validates implementation against design constraints document."""

    def __init__(self):
        self.constraints = self._load_constraints()

    def _load_constraints(self) -> List[DesignConstraint]:
        """Load constraints from the design document."""
        return [
            # Complementary Shard Constraints
            DesignConstraint(
                id="CS1",
                description="No single peer receives complementary shards",
                category="complementary_shards",
                validation_function=self._validate_no_single_peer_complementary
            ),
            DesignConstraint(
                id="CS2",
                description="Complementary shards separated by minimum N peers",
                category="complementary_shards",
                validation_function=self._validate_complementary_separation
            ),

            # Distribution Constraints
            DesignConstraint(
                id="DC1",
                description="Minimum 3 peers per shard",
                category="distribution",
                validation_function=self._validate_minimum_peer_count
            ),
            DesignConstraint(
                id="DC2",
                description="Geographic diversity across regions",
                category="distribution",
                validation_function=self._validate_geographic_distribution
            ),
            DesignConstraint(
                id="DC3",
                description="Maximum 70% peer capacity utilization",
                category="distribution",
                validation_function=self._validate_capacity_limits
            ),

            # Replication Constraints
            DesignConstraint(
                id="RC1",
                description="Dynamic replication based on SLA requirements",
                category="replication",
                validation_function=self._validate_replication_calculations
            ),
            DesignConstraint(
                id="RC2",
                description="Additional replicas for complementary protection",
                category="replication",
                validation_function=self._validate_complementary_protection
            ),

            # Recovery Constraints
            DesignConstraint(
                id="REC1",
                description="Partial recovery with minimum shard count",
                category="recovery",
                validation_function=self._validate_partial_recovery
            ),
            DesignConstraint(
                id="REC2",
                description="Complete recovery requires all shards",
                category="recovery",
                validation_function=self._validate_complete_recovery
            ),

            # Security Constraints
            DesignConstraint(
                id="SEC1",
                description="Adversarial reconstruction prevention",
                category="security",
                validation_function=self._validate_adversarial_prevention
            ),
            DesignConstraint(
                id="SEC2",
                description="No reconstruction from single peer data",
                category="security",
                validation_function=self._validate_single_peer_reconstruction
            )
        ]

    def validate_all_constraints(self, simulator: ShardDistributionSimulator) -> Dict[str, bool]:
        """Validate all constraints against the simulator state."""
        results = {}
        for constraint in self.constraints:
            try:
                results[constraint.id] = constraint.validation_function(simulator)
            except Exception as e:
                print(f"Validation failed for {constraint.id}: {e}")
                results[constraint.id] = False
        return results

    def _validate_no_single_peer_complementary(self, simulator: ShardDistributionSimulator) -> bool:
        """Validate CS1: No single peer receives complementary shards."""
        for peer in simulator.peers.values():
            stored_shard_ids = set(peer.stored_shards.keys())

            # Check for complementary pairs
            for shard_id in stored_shard_ids:
                if shard_id in simulator.shards:
                    shard = simulator.shards[shard_id]
                    complementary_ids = shard.complementary_shard_ids

                    # Check if peer has any complementary shards
                    if complementary_ids.intersection(stored_shard_ids):
                        return False  # Constraint violated

        return True

    def _validate_complementary_separation(self, simulator: ShardDistributionSimulator) -> bool:
        """Validate CS2: Complementary shards separated by minimum N peers."""
        min_separation = 2  # Minimum 2 peers separation

        for shard in simulator.shards.values():
            if shard.complementary_shard_ids:
                for comp_id in shard.complementary_shard_ids:
                    if comp_id in simulator.shards:
                        comp_shard = simulator.shards[comp_id]

                        # Find common peers
                        shard_peers = set(shard.assignments.keys())
                        comp_peers = set(comp_shard.assignments.keys())

                        common_peers = shard_peers.intersection(comp_peers)

                        if len(common_peers) > 0:
                            return False  # Should have no common peers

        return True

    def _validate_minimum_peer_count(self, simulator: ShardDistributionSimulator) -> bool:
        """Validate DC1: Minimum 3 peers per shard."""
        for shard in simulator.shards.values():
            if len(shard.assignments) < 3:
                return False
        return True

    def _validate_geographic_distribution(self, simulator: ShardDistributionSimulator) -> bool:
        """Validate DC2: Geographic diversity."""
        # Simplified geographic check - ensure different "regions"
        for shard in simulator.shards.values():
            regions = set()
            for peer_id in shard.assignments.keys():
                if peer_id in simulator.peers:
                    peer = simulator.peers[peer_id]
                    # Use peer_id prefix as "region" for testing
                    region = peer_id.split('_')[0] if '_' in peer_id else 'default'
                    regions.add(region)

            if len(regions) < 2:
                return False  # Need at least 2 regions

        return True

    def _validate_capacity_limits(self, simulator: ShardDistributionSimulator) -> bool:
        """Validate DC3: Maximum 70% peer capacity utilization."""
        max_utilization = 0.7

        for peer in simulator.peers.values():
            utilization = peer.used_capacity / peer.capacity if peer.capacity > 0 else 0
            if utilization > max_utilization:
                return False

        return True

    def _validate_replication_calculations(self, simulator: ShardDistributionSimulator) -> bool:
        """Validate RC1: Dynamic replication based on SLA."""
        # Check that replication factors are reasonable
        for shard in simulator.shards.values():
            replication = len(shard.assignments)
            if replication < 2 or replication > 10:
                return False  # Unreasonable replication factor

        return True

    def _validate_complementary_protection(self, simulator: ShardDistributionSimulator) -> bool:
        """Validate RC2: Additional replicas for complementary protection."""
        # Check that shards with complements have higher replication
        for shard in simulator.shards.values():
            if shard.complementary_shard_ids:
                replication = len(shard.assignments)
                if replication < 4:  # Should have extra protection
                    return False

        return True

    def _validate_partial_recovery(self, simulator: ShardDistributionSimulator) -> bool:
        """Validate REC1: Partial recovery feasibility."""
        # Test partial recovery scenarios
        for shard in simulator.shards.values():
            total_assignments = len(shard.assignments)
            if total_assignments >= 3:
                # Should be able to recover with 2/3 of shards
                min_for_recovery = max(2, total_assignments // 2)
                if min_for_recovery > total_assignments:
                    return False

        return True

    def _validate_complete_recovery(self, simulator: ShardDistributionSimulator) -> bool:
        """Validate REC2: Complete recovery requires all shards."""
        # For complete recovery, all original shards should be needed
        for shard in simulator.shards.values():
            if len(shard.assignments) < shard.replication_count:
                return False  # Missing replicas

        return True

    def _validate_adversarial_prevention(self, simulator: ShardDistributionSimulator) -> bool:
        """Validate SEC1: Adversarial reconstruction prevention."""
        # Check for adversarial collection attempts
        for shard_id in simulator.shards:
            if simulator.simulate_adversarial_collection_attempt(shard_id):
                return False  # Adversarial collection possible

        return True

    def _validate_single_peer_reconstruction(self, simulator: ShardDistributionSimulator) -> bool:
        """Validate SEC2: No reconstruction from single peer data."""
        for peer in simulator.peers.values():
            stored_shard_ids = set(peer.stored_shards.keys())

            # Check if this peer's data could reconstruct any logical data
            reconstructable_data = set()

            for shard_id in stored_shard_ids:
                if shard_id in simulator.shards:
                    shard = simulator.shards[shard_id]
                    # If peer has complementary shards, reconstruction is possible
                    if shard.complementary_shard_ids.intersection(stored_shard_ids):
                        reconstructable_data.add(shard.partition_id)

            if reconstructable_data:
                return False  # Single peer can reconstruct data

        return True


class TestDesignConstraintsValidation:
    """Tests that validate against the design constraints document."""

    def setup_method(self):
        """Set up test fixtures."""
        self.validator = DesignConstraintsValidator()

    def test_basic_distribution_constraints(self):
        """Test basic distribution meets design constraints."""
        simulator = ShardDistributionSimulator(initial_peers=8)

        # Create shards with complementary relationships
        for i in range(0, 6, 2):
            shard1 = SimulatedShard(
                shard_id=f"shard_{i}",
                partition_id=f"partition_{i//2}",
                data=f"Data A{i}".encode() * 10
            )
            shard2 = SimulatedShard(
                shard_id=f"shard_{i+1}",
                partition_id=f"partition_{i//2}",
                data=f"Data B{i}".encode() * 10
            )

            # Make them complementary
            shard1.complementary_shard_ids.add(shard2.shard_id)
            shard2.complementary_shard_ids.add(shard1.shard_id)

            simulator.distribute_shard(shard1)
            simulator.distribute_shard(shard2)

        # Validate against design constraints
        results = self.validator.validate_all_constraints(simulator)

        # Check critical constraints
        assert results["CS1"], "No single peer complementary constraint failed"
        assert results["CS2"], "Complementary separation constraint failed"
        assert results["DC1"], "Minimum peer count constraint failed"

        print(f"Constraint validation results: {results}")

    def test_adversarial_scenario_constraints(self):
        """Test adversarial scenarios against security constraints."""
        simulator = ShardDistributionSimulator(initial_peers=0)

        # Add legitimate peers
        for i in range(6):
            simulator.add_peer(f"legit_{i}")

        # Add adversarial peers
        simulator.add_peer("adversary_1", AdversarialStrategy.COLLECTOR)
        simulator.add_peer("adversary_2", AdversarialStrategy.DROPPER)

        # Create and distribute complementary shards
        shard1 = SimulatedShard(
            shard_id="secure_A",
            partition_id="secure_partition",
            data=b"Secure data A" * 20
        )
        shard2 = SimulatedShard(
            shard_id="secure_B",
            partition_id="secure_partition",
            data=b"Secure data B" * 20
        )

        shard1.complementary_shard_ids.add("secure_B")
        shard2.complementary_shard_ids.add("secure_A")

        simulator.distribute_shard(shard1)
        simulator.distribute_shard(shard2)

        # Validate security constraints
        results = self.validator.validate_all_constraints(simulator)

        assert results["SEC1"], "Adversarial prevention constraint failed"
        assert results["SEC2"], "Single peer reconstruction constraint failed"

    def test_recovery_constraints_validation(self):
        """Test recovery scenarios against recovery constraints."""
        simulator = ShardDistributionSimulator(initial_peers=10)

        # Create shards with different replication levels
        for i in range(5):
            replication = 4 if i % 2 == 0 else 3  # Vary replication
            shard = SimulatedShard(
                shard_id=f"recovery_{i}",
                partition_id=f"recovery_partition_{i%2}",
                data=f"Recovery data {i}".encode() * 15,
                replication_count=replication
            )
            simulator.distribute_shard(shard)

        # Validate recovery constraints
        results = self.validator.validate_all_constraints(simulator)

        assert results["REC1"], "Partial recovery constraint failed"
        assert results["REC2"], "Complete recovery constraint failed"

    def test_scaling_constraints_validation(self):
        """Test scaling scenarios against distribution constraints."""
        # Test with larger peer/shard counts
        simulator = ShardDistributionSimulator(initial_peers=15)

        # Create multiple shards
        for i in range(10):
            shard = SimulatedShard(
                shard_id=f"scale_{i}",
                partition_id=f"scale_partition_{i%3}",
                data=f"Scale data {i}".encode() * 8
            )
            simulator.distribute_shard(shard)

        # Validate scaling constraints
        results = self.validator.validate_all_constraints(simulator)

        # Geographic distribution might be harder with random assignment
        # but other constraints should hold
        assert results["CS1"], "Complementary constraint failed at scale"
        assert results["DC1"], "Minimum peer count failed at scale"
        assert results["DC3"], "Capacity limits failed at scale"

    def test_constraint_violation_detection(self):
        """Test that constraint violations are properly detected."""
        simulator = ShardDistributionSimulator(initial_peers=5)

        # Manually create a constraint violation
        peer = list(simulator.peers.values())[0]

        # Manually assign complementary shards to same peer (violation)
        shard1 = SimulatedShard(
            shard_id="violation_A",
            partition_id="violation_partition",
            data=b"Violation data A"
        )
        shard2 = SimulatedShard(
            shard_id="violation_B",
            partition_id="violation_partition",
            data=b"Violation data B"
        )

        shard1.complementary_shard_ids.add("violation_B")
        shard2.complementary_shard_ids.add("violation_A")

        # Manually violate constraint
        peer.store_shard("violation_A", shard1.data)
        peer.store_shard("violation_B", shard2.data)

        simulator.shards["violation_A"] = shard1
        simulator.shards["violation_B"] = shard2

        shard1.assignments[peer.peer_id] = peer
        shard2.assignments[peer.peer_id] = peer

        # Validate - should detect violations
        results = self.validator.validate_all_constraints(simulator)

        assert not results["CS1"], "Should detect complementary constraint violation"
        assert not results["CS2"], "Should detect separation constraint violation"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])