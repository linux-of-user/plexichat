"""
Decentralized Security Architecture for PlexiChat.
Implements distributed consensus, security validation, and resilient network topology.
"""

import hashlib
import json
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from plexichat.app.logger_config import logger


class SecurityLevel(Enum):
    """Security levels for different operations."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ConsensusType(Enum):
    """Types of consensus mechanisms."""
    SIMPLE_MAJORITY = "simple_majority"
    SUPER_MAJORITY = "super_majority"
    UNANIMOUS = "unanimous"
    WEIGHTED = "weighted"


@dataclass
class SecurityNode:
    """Represents a security node in the network."""
    node_id: str
    public_key: str
    trust_score: float
    last_seen: datetime
    capabilities: List[str]
    reputation: int = 100
    is_validator: bool = False
    stake: int = 0


@dataclass
class SecurityProposal:
    """Security proposal for consensus."""
    proposal_id: str
    proposer_id: str
    proposal_type: str
    data: Dict[str, Any]
    timestamp: datetime
    required_consensus: ConsensusType
    votes: Dict[str, bool] = None
    status: str = "pending"
    
    def __post_init__(self):
        if self.votes is None:
            self.votes = {}


@dataclass
class SecurityEvent:
    """Security event for monitoring and response."""
    event_id: str
    event_type: str
    severity: SecurityLevel
    source_node: str
    target_node: Optional[str]
    data: Dict[str, Any]
    timestamp: datetime
    verified: bool = False
    consensus_reached: bool = False


class DecentralizedSecurityManager:
    """Manages decentralized security architecture."""
    
    def __init__(self, node_id: str = None):
        self.node_id = node_id or self._generate_node_id()
        self.private_key = None
        self.public_key = None
        self.nodes: Dict[str, SecurityNode] = {}
        self.proposals: Dict[str, SecurityProposal] = {}
        self.security_events: Dict[str, SecurityEvent] = {}
        self.trust_network: Dict[str, Dict[str, float]] = {}
        self.consensus_threshold = 0.67  # 67% for super majority
        
        # Initialize cryptographic keys
        self._initialize_keys()
        
        # Security policies
        self.security_policies = {
            "min_validators": 3,
            "max_trust_score": 1.0,
            "min_trust_score": 0.1,
            "reputation_decay_rate": 0.01,
            "consensus_timeout": 300,  # 5 minutes
            "key_rotation_interval": 86400,  # 24 hours
            "max_failed_validations": 5
        }
        
        logger.info(f"🔐 Decentralized security manager initialized: {self.node_id}")
    
    def _generate_node_id(self) -> str:
        """Generate unique node ID."""
        return hashlib.sha256(
            f"{time.time()}{secrets.token_hex(16)}".encode()
        ).hexdigest()[:16]
    
    def _initialize_keys(self):
        """Initialize cryptographic key pair."""
        try:
            # Generate RSA key pair
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            self.public_key = self.private_key.public_key()
            
            logger.info("🔑 Cryptographic keys initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize keys: {e}")
            raise
    
    def get_public_key_pem(self) -> str:
        """Get public key in PEM format."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
    
    def sign_data(self, data: bytes) -> bytes:
        """Sign data with private key."""
        try:
            signature = self.private_key.sign(
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return signature
        except Exception as e:
            logger.error(f"Failed to sign data: {e}")
            raise
    
    def verify_signature(self, data: bytes, signature: bytes, public_key_pem: str) -> bool:
        """Verify signature with public key."""
        try:
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode(),
                backend=default_backend()
            )
            
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
    
    def register_node(self, node_id: str, public_key: str, capabilities: List[str]) -> bool:
        """Register a new security node."""
        try:
            if node_id in self.nodes:
                logger.warning(f"Node already registered: {node_id}")
                return False
            
            # Validate node registration
            if not self._validate_node_registration(node_id, public_key, capabilities):
                return False
            
            # Create security node
            node = SecurityNode(
                node_id=node_id,
                public_key=public_key,
                trust_score=0.5,  # Start with medium trust
                last_seen=datetime.now(),
                capabilities=capabilities,
                reputation=100
            )
            
            self.nodes[node_id] = node
            self.trust_network[node_id] = {}
            
            # Create registration proposal for consensus
            self._create_proposal(
                "node_registration",
                {"node_id": node_id, "public_key": public_key, "capabilities": capabilities},
                ConsensusType.SIMPLE_MAJORITY
            )
            
            logger.info(f"🔐 Node registered: {node_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to register node {node_id}: {e}")
            return False
    
    def _validate_node_registration(self, node_id: str, public_key: str, capabilities: List[str]) -> bool:
        """Validate node registration request."""
        try:
            # Validate node ID format
            if len(node_id) != 16 or not all(c in '0123456789abcdef' for c in node_id):
                return False
            
            # Validate public key
            try:
                serialization.load_pem_public_key(
                    public_key.encode(),
                    backend=default_backend()
                )
            except Exception:
                return False
            
            # Validate capabilities
            valid_capabilities = [
                "validator", "storage", "relay", "monitor", "backup"
            ]
            if not all(cap in valid_capabilities for cap in capabilities):
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Node validation failed: {e}")
            return False
    
    def _create_proposal(self, proposal_type: str, data: Dict[str, Any], 
                        consensus_type: ConsensusType) -> SecurityProposal:
        """Create a new security proposal."""
        proposal_id = hashlib.sha256(
            f"{proposal_type}{json.dumps(data, sort_keys=True)}{time.time()}".encode()
        ).hexdigest()[:16]
        
        proposal = SecurityProposal(
            proposal_id=proposal_id,
            proposer_id=self.node_id,
            proposal_type=proposal_type,
            data=data,
            timestamp=datetime.now(),
            required_consensus=consensus_type
        )
        
        self.proposals[proposal_id] = proposal
        return proposal
    
    def vote_on_proposal(self, proposal_id: str, vote: bool, voter_id: str) -> bool:
        """Vote on a security proposal."""
        try:
            if proposal_id not in self.proposals:
                logger.error(f"Proposal not found: {proposal_id}")
                return False
            
            proposal = self.proposals[proposal_id]
            
            # Check if voter is authorized
            if voter_id not in self.nodes:
                logger.error(f"Unauthorized voter: {voter_id}")
                return False
            
            # Record vote
            proposal.votes[voter_id] = vote
            
            # Check if consensus is reached
            if self._check_consensus(proposal):
                proposal.status = "approved" if self._proposal_passed(proposal) else "rejected"
                self._execute_proposal(proposal)
            
            logger.info(f"Vote recorded: {voter_id} -> {vote} on {proposal_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to vote on proposal {proposal_id}: {e}")
            return False
    
    def _check_consensus(self, proposal: SecurityProposal) -> bool:
        """Check if consensus is reached for a proposal."""
        total_validators = len([n for n in self.nodes.values() if n.is_validator])
        
        if total_validators < self.security_policies["min_validators"]:
            return False
        
        votes_count = len(proposal.votes)
        
        if proposal.required_consensus == ConsensusType.UNANIMOUS:
            return votes_count == total_validators
        elif proposal.required_consensus == ConsensusType.SUPER_MAJORITY:
            return votes_count >= total_validators * self.consensus_threshold
        elif proposal.required_consensus == ConsensusType.SIMPLE_MAJORITY:
            return votes_count > total_validators / 2
        elif proposal.required_consensus == ConsensusType.WEIGHTED:
            return self._check_weighted_consensus(proposal)
        
        return False
    
    def _proposal_passed(self, proposal: SecurityProposal) -> bool:
        """Check if proposal passed based on votes."""
        yes_votes = sum(1 for vote in proposal.votes.values() if vote)
        total_votes = len(proposal.votes)
        
        if proposal.required_consensus == ConsensusType.UNANIMOUS:
            return yes_votes == total_votes
        elif proposal.required_consensus == ConsensusType.SUPER_MAJORITY:
            return yes_votes >= total_votes * self.consensus_threshold
        elif proposal.required_consensus == ConsensusType.SIMPLE_MAJORITY:
            return yes_votes > total_votes / 2
        elif proposal.required_consensus == ConsensusType.WEIGHTED:
            return self._check_weighted_approval(proposal)
        
        return False
    
    def _check_weighted_consensus(self, proposal: SecurityProposal) -> bool:
        """Check weighted consensus based on trust scores and stakes."""
        total_weight = 0
        voted_weight = 0
        
        for node_id, node in self.nodes.items():
            if node.is_validator:
                weight = node.trust_score * (1 + node.stake / 1000)
                total_weight += weight
                
                if node_id in proposal.votes:
                    voted_weight += weight
        
        return voted_weight >= total_weight * self.consensus_threshold
    
    def _check_weighted_approval(self, proposal: SecurityProposal) -> bool:
        """Check weighted approval for proposal."""
        total_weight = 0
        yes_weight = 0
        
        for node_id, vote in proposal.votes.items():
            if node_id in self.nodes:
                node = self.nodes[node_id]
                weight = node.trust_score * (1 + node.stake / 1000)
                total_weight += weight
                
                if vote:
                    yes_weight += weight
        
        return yes_weight >= total_weight * self.consensus_threshold
    
    def _execute_proposal(self, proposal: SecurityProposal):
        """Execute approved proposal."""
        try:
            if proposal.status != "approved":
                return
            
            if proposal.proposal_type == "node_registration":
                self._execute_node_registration(proposal.data)
            elif proposal.proposal_type == "node_removal":
                self._execute_node_removal(proposal.data)
            elif proposal.proposal_type == "trust_update":
                self._execute_trust_update(proposal.data)
            elif proposal.proposal_type == "security_policy":
                self._execute_security_policy(proposal.data)
            
            logger.info(f"Proposal executed: {proposal.proposal_id}")
            
        except Exception as e:
            logger.error(f"Failed to execute proposal {proposal.proposal_id}: {e}")
    
    def _execute_node_registration(self, data: Dict[str, Any]):
        """Execute node registration."""
        node_id = data["node_id"]
        if node_id in self.nodes:
            self.nodes[node_id].is_validator = True
            logger.info(f"Node promoted to validator: {node_id}")
    
    def _execute_node_removal(self, data: Dict[str, Any]):
        """Execute node removal."""
        node_id = data["node_id"]
        if node_id in self.nodes:
            del self.nodes[node_id]
            if node_id in self.trust_network:
                del self.trust_network[node_id]
            logger.info(f"Node removed: {node_id}")
    
    def _execute_trust_update(self, data: Dict[str, Any]):
        """Execute trust score update."""
        node_id = data["node_id"]
        new_trust = data["trust_score"]
        
        if node_id in self.nodes:
            self.nodes[node_id].trust_score = max(
                self.security_policies["min_trust_score"],
                min(self.security_policies["max_trust_score"], new_trust)
            )
            logger.info(f"Trust updated for {node_id}: {new_trust}")
    
    def _execute_security_policy(self, data: Dict[str, Any]):
        """Execute security policy update."""
        policy_name = data["policy"]
        policy_value = data["value"]
        
        if policy_name in self.security_policies:
            self.security_policies[policy_name] = policy_value
            logger.info(f"Security policy updated: {policy_name} = {policy_value}")
    
    def report_security_event(self, event_type: str, severity: SecurityLevel, 
                            target_node: str = None, data: Dict[str, Any] = None) -> str:
        """Report a security event."""
        try:
            event_id = hashlib.sha256(
                f"{event_type}{self.node_id}{time.time()}".encode()
            ).hexdigest()[:16]
            
            event = SecurityEvent(
                event_id=event_id,
                event_type=event_type,
                severity=severity,
                source_node=self.node_id,
                target_node=target_node,
                data=data or {},
                timestamp=datetime.now()
            )
            
            self.security_events[event_id] = event
            
            # Create proposal for critical events
            if severity == SecurityLevel.CRITICAL:
                self._create_proposal(
                    "security_response",
                    {"event_id": event_id, "response": "immediate_action"},
                    ConsensusType.SUPER_MAJORITY
                )
            
            logger.warning(f"Security event reported: {event_type} ({severity.value})")
            return event_id
            
        except Exception as e:
            logger.error(f"Failed to report security event: {e}")
            return ""
    
    def validate_security_event(self, event_id: str, validator_id: str) -> bool:
        """Validate a security event."""
        try:
            if event_id not in self.security_events:
                return False
            
            if validator_id not in self.nodes:
                return False
            
            event = self.security_events[event_id]
            
            # Implement validation logic based on event type
            is_valid = self._perform_event_validation(event)
            
            if is_valid:
                event.verified = True
                # Update trust scores based on validation
                self._update_trust_scores(event, validator_id)
            
            return is_valid
            
        except Exception as e:
            logger.error(f"Failed to validate security event {event_id}: {e}")
            return False
    
    def _perform_event_validation(self, event: SecurityEvent) -> bool:
        """Perform actual validation of security event."""
        # Implement specific validation logic for different event types
        validation_methods = {
            "malicious_activity": self._validate_malicious_activity,
            "node_compromise": self._validate_node_compromise,
            "data_integrity": self._validate_data_integrity,
            "unauthorized_access": self._validate_unauthorized_access
        }
        
        validator = validation_methods.get(event.event_type)
        if validator:
            return validator(event)
        
        return True  # Default to valid for unknown event types
    
    def _validate_malicious_activity(self, event: SecurityEvent) -> bool:
        """Validate malicious activity report."""
        # Check patterns, signatures, and behavioral analysis
        return True  # Simplified for now
    
    def _validate_node_compromise(self, event: SecurityEvent) -> bool:
        """Validate node compromise report."""
        # Check cryptographic signatures and behavioral patterns
        return True  # Simplified for now
    
    def _validate_data_integrity(self, event: SecurityEvent) -> bool:
        """Validate data integrity event."""
        # Check checksums, hashes, and data consistency
        return True  # Simplified for now
    
    def _validate_unauthorized_access(self, event: SecurityEvent) -> bool:
        """Validate unauthorized access report."""
        # Check access patterns and authentication logs
        return True  # Simplified for now
    
    def _update_trust_scores(self, event: SecurityEvent, validator_id: str):
        """Update trust scores based on event validation."""
        try:
            # Increase trust for accurate reporting
            if event.source_node in self.nodes:
                source_node = self.nodes[event.source_node]
                source_node.trust_score = min(
                    self.security_policies["max_trust_score"],
                    source_node.trust_score + 0.01
                )
                source_node.reputation += 1
            
            # Increase trust for validator
            if validator_id in self.nodes:
                validator_node = self.nodes[validator_id]
                validator_node.trust_score = min(
                    self.security_policies["max_trust_score"],
                    validator_node.trust_score + 0.005
                )
                validator_node.reputation += 1
            
            # Decrease trust for target if malicious
            if event.target_node and event.event_type == "malicious_activity":
                if event.target_node in self.nodes:
                    target_node = self.nodes[event.target_node]
                    target_node.trust_score = max(
                        self.security_policies["min_trust_score"],
                        target_node.trust_score - 0.1
                    )
                    target_node.reputation -= 10
            
        except Exception as e:
            logger.error(f"Failed to update trust scores: {e}")
    
    def get_network_security_status(self) -> Dict[str, Any]:
        """Get comprehensive network security status."""
        try:
            total_nodes = len(self.nodes)
            validators = len([n for n in self.nodes.values() if n.is_validator])
            avg_trust = sum(n.trust_score for n in self.nodes.values()) / total_nodes if total_nodes > 0 else 0
            
            recent_events = len([
                e for e in self.security_events.values()
                if e.timestamp > datetime.now() - timedelta(hours=24)
            ])
            
            critical_events = len([
                e for e in self.security_events.values()
                if e.severity == SecurityLevel.CRITICAL and not e.verified
            ])
            
            pending_proposals = len([
                p for p in self.proposals.values()
                if p.status == "pending"
            ])
            
            return {
                "network_health": "healthy" if critical_events == 0 else "at_risk",
                "total_nodes": total_nodes,
                "validator_nodes": validators,
                "average_trust_score": round(avg_trust, 3),
                "recent_security_events": recent_events,
                "critical_unverified_events": critical_events,
                "pending_proposals": pending_proposals,
                "consensus_threshold": self.consensus_threshold,
                "security_policies": self.security_policies,
                "last_updated": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to get network security status: {e}")
            return {"error": str(e)}
    
    def perform_security_audit(self) -> Dict[str, Any]:
        """Perform comprehensive security audit."""
        try:
            audit_results = {
                "audit_timestamp": datetime.now().isoformat(),
                "node_analysis": {},
                "trust_network_analysis": {},
                "security_events_analysis": {},
                "consensus_analysis": {},
                "recommendations": []
            }
            
            # Analyze nodes
            for node_id, node in self.nodes.items():
                audit_results["node_analysis"][node_id] = {
                    "trust_score": node.trust_score,
                    "reputation": node.reputation,
                    "is_validator": node.is_validator,
                    "last_seen": node.last_seen.isoformat(),
                    "capabilities": node.capabilities,
                    "risk_level": self._assess_node_risk(node)
                }
            
            # Analyze trust network
            audit_results["trust_network_analysis"] = {
                "total_connections": sum(len(connections) for connections in self.trust_network.values()),
                "average_trust": avg_trust if (avg_trust := sum(
                    sum(connections.values()) for connections in self.trust_network.values()
                ) / max(1, sum(len(connections) for connections in self.trust_network.values()))) else 0,
                "isolated_nodes": [
                    node_id for node_id, connections in self.trust_network.items()
                    if len(connections) == 0
                ]
            }
            
            # Analyze security events
            event_types = {}
            for event in self.security_events.values():
                event_types[event.event_type] = event_types.get(event.event_type, 0) + 1
            
            audit_results["security_events_analysis"] = {
                "total_events": len(self.security_events),
                "event_types": event_types,
                "verified_events": len([e for e in self.security_events.values() if e.verified]),
                "critical_events": len([e for e in self.security_events.values() if e.severity == SecurityLevel.CRITICAL])
            }
            
            # Analyze consensus
            audit_results["consensus_analysis"] = {
                "total_proposals": len(self.proposals),
                "approved_proposals": len([p for p in self.proposals.values() if p.status == "approved"]),
                "rejected_proposals": len([p for p in self.proposals.values() if p.status == "rejected"]),
                "pending_proposals": len([p for p in self.proposals.values() if p.status == "pending"])
            }
            
            # Generate recommendations
            audit_results["recommendations"] = self._generate_security_recommendations(audit_results)
            
            return audit_results
            
        except Exception as e:
            logger.error(f"Security audit failed: {e}")
            return {"error": str(e)}
    
    def _assess_node_risk(self, node: SecurityNode) -> str:
        """Assess risk level for a node."""
        if node.trust_score < 0.3 or node.reputation < 50:
            return "high"
        elif node.trust_score < 0.6 or node.reputation < 80:
            return "medium"
        else:
            return "low"
    
    def _generate_security_recommendations(self, audit_results: Dict[str, Any]) -> List[str]:
        """Generate security recommendations based on audit."""
        recommendations = []
        
        # Check validator count
        validator_count = sum(1 for analysis in audit_results["node_analysis"].values() if analysis["is_validator"])
        if validator_count < self.security_policies["min_validators"]:
            recommendations.append(f"Increase validator count to at least {self.security_policies['min_validators']}")
        
        # Check high-risk nodes
        high_risk_nodes = [
            node_id for node_id, analysis in audit_results["node_analysis"].items()
            if analysis["risk_level"] == "high"
        ]
        if high_risk_nodes:
            recommendations.append(f"Review high-risk nodes: {', '.join(high_risk_nodes)}")
        
        # Check isolated nodes
        isolated_nodes = audit_results["trust_network_analysis"]["isolated_nodes"]
        if isolated_nodes:
            recommendations.append(f"Integrate isolated nodes: {', '.join(isolated_nodes)}")
        
        # Check critical events
        if audit_results["security_events_analysis"]["critical_events"] > 0:
            recommendations.append("Address unverified critical security events")
        
        return recommendations


# Global decentralized security manager instance
decentralized_security = DecentralizedSecurityManager()


def get_decentralized_security() -> DecentralizedSecurityManager:
    """Get the global decentralized security manager."""
    return decentralized_security


def initialize_decentralized_security():
    """Initialize the decentralized security system."""
    try:
        logger.info("🔐 Decentralized security system initialized")
        return True
    except Exception as e:
        logger.error(f"Failed to initialize decentralized security: {e}")
        return False
