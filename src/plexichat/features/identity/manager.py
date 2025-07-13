import hashlib
import json
import logging
import secrets
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set


"""
PlexiChat Decentralized Identity & Self-Sovereign Identity (SSI) System

Implements verifiable credentials, decentralized identifiers (DIDs),
and Zero-Trust Network Access (ZTNA) for all PlexiChat resources.
"""

logger = logging.getLogger(__name__)


class CredentialType(Enum):
    """Types of verifiable credentials."""
    IDENTITY = "identity"
    AUTHORIZATION = "authorization"
    CERTIFICATION = "certification"
    MEMBERSHIP = "membership"
    SKILL = "skill"
    EDUCATION = "education"
    EMPLOYMENT = "employment"


class TrustLevel(Enum):
    """Trust levels for Zero-Trust Network Access."""
    UNTRUSTED = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class DecentralizedIdentifier:
    """Decentralized Identifier (DID) implementation."""
    method: str
    identifier: str
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    @property
    def did(self) -> str:
        """Full DID string."""
        return f"did:{self.method}:{self.identifier}"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "did": self.did,
            "method": self.method,
            "identifier": self.identifier,
            "created_at": self.created_at.isoformat()
        }


@dataclass
class VerifiableCredential:
    """W3C Verifiable Credential implementation."""
    id: str
    type: List[str]
    issuer: str
    issuance_date: datetime
    expiration_date: Optional[datetime]
    credential_subject: Dict[str, Any]
    proof: Dict[str, Any]
    
    def is_valid(self) -> bool:
        """Check if credential is still valid."""
        now = datetime.now(timezone.utc)
        if self.expiration_date and now > self.expiration_date:
            return False
        return True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to W3C VC format."""
        vc = {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://plexichat.local/credentials/v1"
            ],
            "id": self.id,
            "type": self.type,
            "issuer": self.issuer,
            "issuanceDate": self.issuance_date.isoformat(),
            "credentialSubject": self.credential_subject,
            "proof": self.proof
        }
        
        if self.expiration_date:
            vc["expirationDate"] = self.expiration_date.isoformat()
        
        return vc


@dataclass
class ZeroTrustPolicy:
    """Zero-Trust Network Access policy."""
    policy_id: str
    resource: str
    required_credentials: List[str]
    min_trust_level: TrustLevel
    conditions: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def evaluate(self, user_credentials: List[VerifiableCredential], 
                trust_score: float, context: Dict[str, Any]) -> bool:
        """Evaluate if access should be granted."""
        # Check trust level
        if trust_score < self.min_trust_level.value:
            return False
        
        # Check required credentials
        user_cred_types = set()
        for cred in user_credentials:
            if cred.is_valid():
                user_cred_types.update(cred.type)
        
        required_set = set(self.required_credentials)
        if not required_set.issubset(user_cred_types):
            return False
        
        # Check additional conditions
        for condition, value in self.conditions.items():
            if condition == "time_range":
                current_hour = from datetime import datetime
datetime.now().hour
                if not (value["start"] <= current_hour <= value["end"]):
                    return False
            elif condition == "location":
                user_location = context.get("location")
                if user_location not in value["allowed_locations"]:
                    return False
            elif condition == "device_trust":
                device_trust = context.get("device_trust", 0)
                if device_trust < value["min_device_trust"]:
                    return False
        
        return True


class DIDManager:
    """Manages Decentralized Identifiers."""
    
    def __init__(self):
        self.method = "plexichat"
        self.dids: Dict[str, DecentralizedIdentifier] = {}
        self.did_documents: Dict[str, Dict[str, Any]] = {}
    
    def create_did(self, user_id: str) -> DecentralizedIdentifier:
        """Create a new DID for a user."""
        # Generate unique identifier
        identifier = hashlib.sha256(f"{user_id}_{secrets.token_hex(16)}".encode()).hexdigest()[:32]
        
        did = DecentralizedIdentifier(
            method=self.method,
            identifier=identifier
        )
        
        # Create DID Document
        did_document = {
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://plexichat.local/did/v1"
            ],
            "id": did.did,
            "controller": did.did,
            "created": did.created_at.isoformat(),
            "verificationMethod": [{
                "id": f"{did.did}#key-1",
                "type": "Ed25519VerificationKey2020",
                "controller": did.did,
                "publicKeyMultibase": self._generate_public_key()
            }],
            "authentication": [f"{did.did}#key-1"],
            "assertionMethod": [f"{did.did}#key-1"],
            "service": [{
                "id": f"{did.did}#plexichat-service",
                "type": "PlexiChatService",
                "serviceEndpoint": "https://plexichat.local/api/v1/did"
            }]
        }
        
        self.dids[did.did] = did
        self.did_documents[did.did] = did_document
        
        logger.info(f"Created DID: {did.did}")
        return did
    
    def resolve_did(self, did: str) -> Optional[Dict[str, Any]]:
        """Resolve DID to DID Document."""
        return self.did_documents.get(did)
    
    def _generate_public_key(self) -> str:
        """Generate a public key (simplified)."""
        return secrets.token_hex(32)


class CredentialIssuer:
    """Issues and manages verifiable credentials."""
    
    def __init__(self, issuer_did: str):
        self.issuer_did = issuer_did
        self.issued_credentials: Dict[str, VerifiableCredential] = {}
        self.revoked_credentials: Set[str] = set()
    
    def issue_credential(self, subject_did: str, credential_type: CredentialType,
                        claims: Dict[str, Any], validity_days: int = 365) -> VerifiableCredential:
        """Issue a verifiable credential."""
        credential_id = f"urn:uuid:{uuid.uuid4()}"
        
        # Create credential
        credential = VerifiableCredential(
            id=credential_id,
            type=["VerifiableCredential", credential_type.value.title() + "Credential"],
            issuer=self.issuer_did,
            issuance_date=datetime.now(timezone.utc),
            expiration_date=datetime.now(timezone.utc) + timedelta(days=validity_days),
            credential_subject={
                "id": subject_did,
                **claims
            },
            proof=self._create_proof(credential_id, subject_did, claims)
        )
        
        self.issued_credentials[credential_id] = credential
        logger.info(f"Issued {credential_type.value} credential: {credential_id}")
        
        return credential
    
    def revoke_credential(self, credential_id: str) -> bool:
        """Revoke a credential."""
        if credential_id in self.issued_credentials:
            self.revoked_credentials.add(credential_id)
            logger.info(f"Revoked credential: {credential_id}")
            return True
        return False
    
    def is_revoked(self, credential_id: str) -> bool:
        """Check if credential is revoked."""
        return credential_id in self.revoked_credentials
    
    def _create_proof(self, credential_id: str, subject_did: str, claims: Dict[str, Any]) -> Dict[str, Any]:
        """Create cryptographic proof for credential."""
        # Simplified proof (in production, use proper digital signatures)
        proof_value = hashlib.sha256(
            f"{credential_id}{subject_did}{json.dumps(claims, sort_keys=True)}".encode()
        ).hexdigest()
        
        return {
            "type": "Ed25519Signature2020",
            "created": datetime.now(timezone.utc).isoformat(),
            "verificationMethod": f"{self.issuer_did}#key-1",
            "proofPurpose": "assertionMethod",
            "proofValue": proof_value
        }


class ZeroTrustAccessManager:
    """Zero-Trust Network Access management."""
    
    def __init__(self):
        self.policies: Dict[str, ZeroTrustPolicy] = {}
        self.trust_scores: Dict[str, float] = {}
        self.access_logs: List[Dict[str, Any]] = []
        
        # Initialize default policies
        self._create_default_policies()
    
    def _create_default_policies(self):
        """Create default ZTNA policies."""
        # Admin access policy
        admin_policy = ZeroTrustPolicy(
            policy_id="admin_access",
            resource="/admin/*",
            required_credentials=["AdminCredential"],
            min_trust_level=TrustLevel.HIGH,
            conditions={
                "time_range": {"start": 6, "end": 22},  # 6 AM to 10 PM
                "device_trust": {"min_device_trust": 0.8}
            }
        )
        self.policies["admin_access"] = admin_policy
        
        # User data access policy
        user_policy = ZeroTrustPolicy(
            policy_id="user_data_access",
            resource="/api/user/*",
            required_credentials=["IdentityCredential"],
            min_trust_level=TrustLevel.MEDIUM
        )
        self.policies["user_data_access"] = user_policy
        
        # Sensitive operations policy
        sensitive_policy = ZeroTrustPolicy(
            policy_id="sensitive_operations",
            resource="/api/sensitive/*",
            required_credentials=["IdentityCredential", "AuthorizationCredential"],
            min_trust_level=TrustLevel.HIGH,
            conditions={
                "device_trust": {"min_device_trust": 0.9}
            }
        )
        self.policies["sensitive_operations"] = sensitive_policy
    
    def evaluate_access(self, user_did: str, resource: str, 
                       credentials: List[VerifiableCredential],
                       context: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate access request using Zero-Trust principles."""
        # Find applicable policy
        applicable_policy = None
        for policy in self.policies.values():
            if self._resource_matches(resource, policy.resource):
                applicable_policy = policy
                break
        
        if not applicable_policy:
            return {
                "access_granted": False,
                "reason": "No applicable policy found",
                "policy_id": None
            }
        
        # Get user trust score
        trust_score = self.trust_scores.get(user_did, 0.0)
        
        # Evaluate policy
        access_granted = applicable_policy.evaluate(credentials, trust_score, context)
        
        # Log access attempt
        access_log = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "user_did": user_did,
            "resource": resource,
            "policy_id": applicable_policy.policy_id,
            "access_granted": access_granted,
            "trust_score": trust_score,
            "context": context
        }
        self.access_logs.append(access_log)
        
        # Update trust score based on behavior
        self._update_trust_score(user_did, access_granted, context)
        
        return {
            "access_granted": access_granted,
            "policy_id": applicable_policy.policy_id,
            "trust_score": trust_score,
            "required_credentials": applicable_policy.required_credentials
        }
    
    def _resource_matches(self, resource: str, pattern: str) -> bool:
        """Check if resource matches policy pattern."""
        if pattern.endswith("*"):
            return resource.startswith(pattern[:-1])
        return resource == pattern
    
    def _update_trust_score(self, user_did: str, access_granted: bool, context: Dict[str, Any]):
        """Update user trust score based on behavior."""
        current_score = self.trust_scores.get(user_did, 2.0)  # Start with medium trust
        
        if access_granted:
            # Successful access slightly increases trust
            current_score = min(4.0, current_score + 0.1)
        else:
            # Failed access decreases trust
            current_score = max(0.0, current_score - 0.2)
        
        # Factor in device trust
        device_trust = context.get("device_trust", 0.5)
        if device_trust < 0.5:
            current_score = max(0.0, current_score - 0.1)
        
        self.trust_scores[user_did] = current_score
    
    def add_policy(self, policy: ZeroTrustPolicy):
        """Add a new ZTNA policy."""
        self.policies[policy.policy_id] = policy
        logger.info(f"Added ZTNA policy: {policy.policy_id}")
    
    def get_access_logs(self, user_did: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Get access logs."""
        logs = self.access_logs
        
        if user_did:
            logs = [log for log in logs if log["user_did"] == user_did]
        
        return logs[-limit:]


class DecentralizedIdentityManager:
    """Main decentralized identity management system."""
    
    def __init__(self):
        self.did_manager = DIDManager()
        self.credential_issuer = CredentialIssuer("did:plexichat:system")
        self.ztna_manager = ZeroTrustAccessManager()
        
        # User identity registry
        self.user_identities: Dict[str, Dict[str, Any]] = {}
    
    def create_user_identity(self, user_id: str, profile_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create complete decentralized identity for user."""
        # Create DID
        did = self.did_manager.create_did(user_id)
        
        # Issue identity credential
        identity_credential = self.credential_issuer.issue_credential(
            subject_did=did.did,
            credential_type=CredentialType.IDENTITY,
            claims={
                "name": profile_data.get("name", ""),
                "email": profile_data.get("email", ""),
                "verified": False
            }
        )
        
        # Store user identity
        self.user_identities[user_id] = {
            "did": did.did,
            "credentials": [identity_credential.id],
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        
        logger.info(f"Created decentralized identity for user: {user_id}")
        
        return {
            "did": did.did,
            "identity_credential": identity_credential.to_dict(),
            "did_document": self.did_manager.resolve_did(did.did)
        }
    
    def verify_access(self, user_id: str, resource: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Verify access using Zero-Trust principles."""
        user_identity = self.user_identities.get(user_id)
        if not user_identity:
            return {"access_granted": False, "reason": "User identity not found"}
        
        # Get user credentials
        user_credentials = []
        for cred_id in user_identity["credentials"]:
            if cred_id in self.credential_issuer.issued_credentials:
                credential = self.credential_issuer.issued_credentials[cred_id]
                if not self.credential_issuer.is_revoked(cred_id):
                    user_credentials.append(credential)
        
        # Evaluate access
        return self.ztna_manager.evaluate_access(
            user_identity["did"], resource, user_credentials, context
        )
    
    def get_identity_status(self) -> Dict[str, Any]:
        """Get decentralized identity system status."""
        return {
            "decentralized_identity": {
                "total_dids": len(self.did_manager.dids),
                "total_credentials": len(self.credential_issuer.issued_credentials),
                "revoked_credentials": len(self.credential_issuer.revoked_credentials),
                "ztna_policies": len(self.ztna_manager.policies),
                "user_identities": len(self.user_identities)
            }
        }


# Global decentralized identity manager
decentralized_identity_manager = DecentralizedIdentityManager()
