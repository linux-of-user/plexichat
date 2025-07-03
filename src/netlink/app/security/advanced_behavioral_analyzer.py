"""
Advanced Behavioral Analysis System with Anti-Hijacking Measures

This system provides:
- Machine learning-based behavioral pattern detection
- Cryptographic integrity protection against tampering
- Advanced fingerprinting and anomaly detection
- Real-time threat correlation and adaptation
- Anti-hijacking measures with tamper detection
"""

import asyncio
import time
import hmac
import secrets
import hashlib
import json
import numpy as np
import pickle
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, field
from collections import defaultdict, deque
from enum import Enum
import psutil
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN

from app.logger_config import logger

class BehavioralThreatType(Enum):
    """Types of behavioral threats."""
    NORMAL = "normal"
    ANOMALOUS_PATTERN = "anomalous_pattern"
    COORDINATED_ATTACK = "coordinated_attack"
    BOT_BEHAVIOR = "bot_behavior"
    SCRAPING_ATTEMPT = "scraping_attempt"
    BRUTE_FORCE = "brute_force"
    RECONNAISSANCE = "reconnaissance"
    EVASION_ATTEMPT = "evasion_attempt"
    HIJACKING_ATTEMPT = "hijacking_attempt"

@dataclass
class BehavioralFingerprint:
    """Behavioral fingerprint for an entity (IP, user, session)."""
    entity_id: str
    entity_type: str  # 'ip', 'user', 'session'
    first_seen: datetime
    last_seen: datetime
    
    # Request patterns
    request_intervals: List[float] = field(default_factory=list)
    endpoint_sequence: List[str] = field(default_factory=list)
    user_agent_variations: Set[str] = field(default_factory=set)
    header_patterns: Dict[str, List[str]] = field(default_factory=dict)
    
    # Behavioral metrics
    avg_request_interval: float = 0.0
    request_variance: float = 0.0
    endpoint_diversity: float = 0.0
    session_duration: float = 0.0
    
    # ML features
    feature_vector: Optional[np.ndarray] = None
    anomaly_score: float = 0.0
    cluster_id: int = -1
    
    # Security metrics
    integrity_hash: Optional[str] = None
    tamper_detected: bool = False
    trust_score: float = 1.0

@dataclass
class BehavioralAssessment:
    """Result of behavioral analysis."""
    entity_id: str
    timestamp: datetime
    threat_type: BehavioralThreatType
    confidence: float
    anomaly_score: float
    risk_level: int  # 0-10
    
    # Analysis details
    patterns_detected: List[str] = field(default_factory=list)
    ml_predictions: Dict[str, float] = field(default_factory=dict)
    correlation_data: Dict[str, Any] = field(default_factory=dict)
    
    # Anti-hijacking
    integrity_verified: bool = True
    signature_valid: bool = True
    tamper_indicators: List[str] = field(default_factory=list)

class AdvancedBehavioralAnalyzer:
    """Advanced behavioral analysis with anti-hijacking protection."""
    
    def __init__(self, secret_key: Optional[str] = None):
        # Cryptographic protection
        self.secret_key = secret_key or secrets.token_urlsafe(32)
        self.cipher_suite = self._initialize_encryption()
        self.integrity_salt = secrets.token_bytes(32)
        
        # Behavioral tracking
        self.fingerprints: Dict[str, BehavioralFingerprint] = {}
        self.request_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        
        # Machine learning models
        self.anomaly_detector = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100
        )
        self.scaler = StandardScaler()
        self.clusterer = DBSCAN(eps=0.5, min_samples=5)
        
        # Model state tracking
        self.model_trained = False
        self.model_version = 1
        self.last_training = None
        self.training_data = deque(maxlen=10000)
        
        # Anti-hijacking measures
        self.system_integrity_hash = self._calculate_system_integrity()
        self.component_signatures = {}
        self.tamper_detection_enabled = True
        
        # Behavioral patterns
        self.known_patterns = {
            'bot_indicators': [
                'consistent_intervals', 'no_javascript', 'automated_user_agent',
                'sequential_access', 'no_cookies', 'rapid_succession'
            ],
            'scraping_patterns': [
                'systematic_crawling', 'robots_txt_ignore', 'high_frequency',
                'pattern_following', 'no_referrer', 'bulk_requests'
            ],
            'attack_patterns': [
                'parameter_fuzzing', 'error_probing', 'privilege_escalation',
                'injection_attempts', 'bypass_attempts', 'reconnaissance'
            ]
        }
        
        # Correlation rules
        self.correlation_rules = {
            'coordinated_attack': {
                'min_ips': 3,
                'time_window': 300,  # 5 minutes
                'similarity_threshold': 0.8
            },
            'distributed_scraping': {
                'min_ips': 5,
                'time_window': 600,  # 10 minutes
                'pattern_match_threshold': 0.7
            }
        }
        
        logger.info("Advanced Behavioral Analyzer initialized with anti-hijacking protection")
    
    def _initialize_encryption(self) -> Fernet:
        """Initialize encryption for sensitive data protection."""
        password = self.secret_key.encode()
        salt = b'netlink_behavioral_salt'  # In production, use random salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return Fernet(key)
    
    def _calculate_system_integrity(self) -> str:
        """Calculate system integrity hash for tamper detection."""
        # Hash critical system components
        components = [
            self.__class__.__name__,
            str(self.known_patterns),
            str(self.correlation_rules),
            # Add more critical components
        ]
        
        integrity_data = ''.join(components).encode()
        return hashlib.sha256(integrity_data).hexdigest()
    
    def _verify_integrity(self) -> bool:
        """Verify system integrity hasn't been compromised."""
        if not self.tamper_detection_enabled:
            return True
            
        current_hash = self._calculate_system_integrity()
        if current_hash != self.system_integrity_hash:
            logger.critical("System integrity violation detected! Possible hijacking attempt.")
            return False
        return True
    
    def _sign_data(self, data: str) -> str:
        """Create HMAC signature for data integrity."""
        return hmac.new(
            self.secret_key.encode(),
            data.encode(),
            hashlib.sha256
        ).hexdigest()
    
    def _verify_signature(self, data: str, signature: str) -> bool:
        """Verify HMAC signature."""
        expected_signature = self._sign_data(data)
        return hmac.compare_digest(expected_signature, signature)
    
    async def analyze_request_behavior(self, 
                                     entity_id: str,
                                     entity_type: str,
                                     request_data: Dict[str, Any]) -> BehavioralAssessment:
        """
        Analyze behavioral patterns in request data.
        
        Args:
            entity_id: Unique identifier (IP, user ID, session ID)
            entity_type: Type of entity ('ip', 'user', 'session')
            request_data: Request information and metadata
            
        Returns:
            BehavioralAssessment with threat analysis
        """
        # Verify system integrity first
        if not self._verify_integrity():
            return BehavioralAssessment(
                entity_id=entity_id,
                timestamp=datetime.now(timezone.utc),
                threat_type=BehavioralThreatType.HIJACKING_ATTEMPT,
                confidence=1.0,
                anomaly_score=1.0,
                risk_level=10,
                integrity_verified=False,
                tamper_indicators=["system_integrity_violation"]
            )
        
        current_time = datetime.now(timezone.utc)
        
        # Update or create behavioral fingerprint
        fingerprint = await self._update_behavioral_fingerprint(
            entity_id, entity_type, request_data, current_time
        )
        
        # Extract behavioral features
        features = self._extract_behavioral_features(fingerprint, request_data)
        
        # Perform ML-based anomaly detection
        anomaly_score = await self._detect_anomalies(features)
        
        # Pattern-based threat detection
        threat_patterns = self._detect_threat_patterns(fingerprint, request_data)
        
        # Correlation analysis
        correlation_data = await self._perform_correlation_analysis(
            entity_id, entity_type, current_time
        )
        
        # Determine threat type and risk level
        threat_type, confidence, risk_level = self._assess_threat_level(
            anomaly_score, threat_patterns, correlation_data
        )
        
        # Create assessment
        assessment = BehavioralAssessment(
            entity_id=entity_id,
            timestamp=current_time,
            threat_type=threat_type,
            confidence=confidence,
            anomaly_score=anomaly_score,
            risk_level=risk_level,
            patterns_detected=threat_patterns,
            correlation_data=correlation_data,
            integrity_verified=True,
            signature_valid=True
        )
        
        # Store for future analysis and model training
        await self._store_analysis_result(assessment, features)
        
        # Trigger model retraining if needed
        if len(self.training_data) % 1000 == 0 and len(self.training_data) > 0:
            asyncio.create_task(self._retrain_models())
        
        return assessment
    
    async def _update_behavioral_fingerprint(self,
                                           entity_id: str,
                                           entity_type: str,
                                           request_data: Dict[str, Any],
                                           current_time: datetime) -> BehavioralFingerprint:
        """Update behavioral fingerprint for entity."""
        if entity_id not in self.fingerprints:
            self.fingerprints[entity_id] = BehavioralFingerprint(
                entity_id=entity_id,
                entity_type=entity_type,
                first_seen=current_time,
                last_seen=current_time
            )
        
        fingerprint = self.fingerprints[entity_id]
        fingerprint.last_seen = current_time
        
        # Update request patterns
        if fingerprint.request_intervals:
            last_request_time = fingerprint.last_seen - timedelta(
                seconds=fingerprint.request_intervals[-1] if fingerprint.request_intervals else 0
            )
            interval = (current_time - last_request_time).total_seconds()
            fingerprint.request_intervals.append(interval)
            
            # Keep only recent intervals
            if len(fingerprint.request_intervals) > 100:
                fingerprint.request_intervals = fingerprint.request_intervals[-100:]
        else:
            fingerprint.request_intervals.append(0.0)
        
        # Update endpoint sequence
        endpoint = request_data.get('endpoint', '')
        fingerprint.endpoint_sequence.append(endpoint)
        if len(fingerprint.endpoint_sequence) > 50:
            fingerprint.endpoint_sequence = fingerprint.endpoint_sequence[-50:]
        
        # Update user agent variations
        user_agent = request_data.get('user_agent', '')
        if user_agent:
            fingerprint.user_agent_variations.add(user_agent)
            # Limit stored variations
            if len(fingerprint.user_agent_variations) > 10:
                fingerprint.user_agent_variations = set(
                    list(fingerprint.user_agent_variations)[-10:]
                )
        
        # Update header patterns
        headers = request_data.get('headers', {})
        for header, value in headers.items():
            if header not in fingerprint.header_patterns:
                fingerprint.header_patterns[header] = []
            fingerprint.header_patterns[header].append(str(value))
            # Keep only recent values
            if len(fingerprint.header_patterns[header]) > 20:
                fingerprint.header_patterns[header] = fingerprint.header_patterns[header][-20:]
        
        # Calculate behavioral metrics
        if len(fingerprint.request_intervals) > 1:
            fingerprint.avg_request_interval = np.mean(fingerprint.request_intervals)
            fingerprint.request_variance = np.var(fingerprint.request_intervals)
        
        fingerprint.endpoint_diversity = len(set(fingerprint.endpoint_sequence)) / max(len(fingerprint.endpoint_sequence), 1)
        fingerprint.session_duration = (current_time - fingerprint.first_seen).total_seconds()
        
        # Calculate integrity hash
        fingerprint_data = json.dumps({
            'entity_id': fingerprint.entity_id,
            'intervals': fingerprint.request_intervals[-10:],  # Last 10 for consistency
            'endpoints': fingerprint.endpoint_sequence[-10:],
            'metrics': {
                'avg_interval': fingerprint.avg_request_interval,
                'variance': fingerprint.request_variance,
                'diversity': fingerprint.endpoint_diversity
            }
        }, sort_keys=True)
        
        fingerprint.integrity_hash = self._sign_data(fingerprint_data)
        
        return fingerprint

    def _extract_behavioral_features(self,
                                   fingerprint: BehavioralFingerprint,
                                   request_data: Dict[str, Any]) -> np.ndarray:
        """Extract numerical features for ML analysis."""
        features = []

        # Timing features
        features.extend([
            fingerprint.avg_request_interval,
            fingerprint.request_variance,
            len(fingerprint.request_intervals),
            fingerprint.session_duration
        ])

        # Diversity features
        features.extend([
            fingerprint.endpoint_diversity,
            len(fingerprint.user_agent_variations),
            len(fingerprint.header_patterns),
            len(set(fingerprint.endpoint_sequence))
        ])

        # Pattern features
        features.extend([
            self._calculate_regularity_score(fingerprint.request_intervals),
            self._calculate_entropy(fingerprint.endpoint_sequence),
            self._calculate_user_agent_consistency(fingerprint.user_agent_variations),
            self._calculate_header_anomaly_score(fingerprint.header_patterns)
        ])

        # Request-specific features
        current_endpoint = request_data.get('endpoint', '')
        features.extend([
            len(current_endpoint),
            current_endpoint.count('/'),
            current_endpoint.count('?'),
            current_endpoint.count('&')
        ])

        # Convert to numpy array
        feature_vector = np.array(features, dtype=np.float32)

        # Handle NaN values
        feature_vector = np.nan_to_num(feature_vector, nan=0.0, posinf=1.0, neginf=-1.0)

        fingerprint.feature_vector = feature_vector
        return feature_vector

    def _calculate_regularity_score(self, intervals: List[float]) -> float:
        """Calculate how regular the request intervals are (0=random, 1=perfectly regular)."""
        if len(intervals) < 3:
            return 0.0

        # Calculate coefficient of variation
        mean_interval = np.mean(intervals)
        if mean_interval == 0:
            return 0.0

        cv = np.std(intervals) / mean_interval
        # Convert to regularity score (inverse of variation)
        return max(0.0, 1.0 - min(cv, 1.0))

    def _calculate_entropy(self, sequence: List[str]) -> float:
        """Calculate Shannon entropy of a sequence."""
        if not sequence:
            return 0.0

        # Count occurrences
        counts = {}
        for item in sequence:
            counts[item] = counts.get(item, 0) + 1

        # Calculate entropy
        total = len(sequence)
        entropy = 0.0
        for count in counts.values():
            p = count / total
            if p > 0:
                entropy -= p * np.log2(p)

        return entropy

    def _calculate_user_agent_consistency(self, user_agents: Set[str]) -> float:
        """Calculate consistency score for user agents (0=highly variable, 1=consistent)."""
        if not user_agents:
            return 1.0

        # Single user agent = perfectly consistent
        if len(user_agents) == 1:
            return 1.0

        # Multiple user agents = less consistent
        return max(0.0, 1.0 - (len(user_agents) - 1) * 0.2)

    def _calculate_header_anomaly_score(self, header_patterns: Dict[str, List[str]]) -> float:
        """Calculate anomaly score based on header patterns."""
        if not header_patterns:
            return 0.0

        anomaly_score = 0.0

        # Check for suspicious headers
        suspicious_headers = ['x-forwarded-for', 'x-real-ip', 'x-originating-ip']
        for header in suspicious_headers:
            if header.lower() in [h.lower() for h in header_patterns.keys()]:
                anomaly_score += 0.2

        # Check for header value variations
        for header, values in header_patterns.items():
            unique_values = len(set(values))
            if unique_values > 5:  # High variation in header values
                anomaly_score += 0.1

        return min(anomaly_score, 1.0)

    async def _detect_anomalies(self, features: np.ndarray) -> float:
        """Detect anomalies using ML models."""
        if not self.model_trained:
            # Not enough data for anomaly detection yet
            return 0.0

        try:
            # Normalize features
            features_scaled = self.scaler.transform(features.reshape(1, -1))

            # Get anomaly score
            anomaly_score = self.anomaly_detector.decision_function(features_scaled)[0]

            # Convert to 0-1 range (lower scores = more anomalous)
            normalized_score = max(0.0, min(1.0, (anomaly_score + 1) / 2))

            # Invert so higher scores = more anomalous
            return 1.0 - normalized_score

        except Exception as e:
            logger.warning(f"Anomaly detection failed: {e}")
            return 0.0

    def _detect_threat_patterns(self,
                              fingerprint: BehavioralFingerprint,
                              request_data: Dict[str, Any]) -> List[str]:
        """Detect known threat patterns."""
        detected_patterns = []

        # Bot behavior detection
        if self._is_bot_behavior(fingerprint, request_data):
            detected_patterns.append('bot_behavior')

        # Scraping detection
        if self._is_scraping_behavior(fingerprint, request_data):
            detected_patterns.append('scraping_behavior')

        # Brute force detection
        if self._is_brute_force_behavior(fingerprint, request_data):
            detected_patterns.append('brute_force')

        # Reconnaissance detection
        if self._is_reconnaissance_behavior(fingerprint, request_data):
            detected_patterns.append('reconnaissance')

        # Evasion attempts
        if self._is_evasion_attempt(fingerprint, request_data):
            detected_patterns.append('evasion_attempt')

        return detected_patterns

    def _is_bot_behavior(self, fingerprint: BehavioralFingerprint, request_data: Dict[str, Any]) -> bool:
        """Detect bot-like behavior patterns."""
        # Check for consistent intervals (typical of bots)
        if len(fingerprint.request_intervals) > 5:
            regularity = self._calculate_regularity_score(fingerprint.request_intervals)
            if regularity > 0.8:  # Very regular intervals
                return True

        # Check user agent
        user_agent = request_data.get('user_agent', '').lower()
        bot_indicators = ['bot', 'crawler', 'spider', 'scraper', 'curl', 'wget', 'python']
        if any(indicator in user_agent for indicator in bot_indicators):
            return True

        # Check for lack of typical browser headers
        headers = request_data.get('headers', {})
        browser_headers = ['accept-language', 'accept-encoding', 'dnt', 'upgrade-insecure-requests']
        missing_headers = sum(1 for h in browser_headers if h not in [k.lower() for k in headers.keys()])
        if missing_headers >= 3:
            return True

        return False

    def _is_scraping_behavior(self, fingerprint: BehavioralFingerprint, request_data: Dict[str, Any]) -> bool:
        """Detect web scraping behavior."""
        # High frequency requests
        if len(fingerprint.request_intervals) > 10:
            avg_interval = fingerprint.avg_request_interval
            if avg_interval < 2.0:  # Less than 2 seconds between requests
                return True

        # Sequential endpoint access
        endpoints = fingerprint.endpoint_sequence[-20:]  # Last 20 requests
        if len(endpoints) > 10:
            # Check for systematic patterns
            unique_endpoints = len(set(endpoints))
            if unique_endpoints / len(endpoints) > 0.8:  # High diversity = systematic crawling
                return True

        # No referrer headers (common in scrapers)
        headers = request_data.get('headers', {})
        if 'referer' not in [k.lower() for k in headers.keys()] and len(fingerprint.request_intervals) > 5:
            return True

        return False

    def _is_brute_force_behavior(self, fingerprint: BehavioralFingerprint, request_data: Dict[str, Any]) -> bool:
        """Detect brute force attack patterns."""
        endpoint = request_data.get('endpoint', '')

        # Check for login/auth endpoints
        auth_endpoints = ['/login', '/auth', '/signin', '/api/auth']
        if not any(auth_ep in endpoint.lower() for auth_ep in auth_endpoints):
            return False

        # High frequency on auth endpoints
        auth_requests = sum(1 for ep in fingerprint.endpoint_sequence
                           if any(auth_ep in ep.lower() for auth_ep in auth_endpoints))

        if auth_requests > 10 and len(fingerprint.request_intervals) > 5:
            avg_interval = fingerprint.avg_request_interval
            if avg_interval < 5.0:  # Less than 5 seconds between auth attempts
                return True

        return False

    def _is_reconnaissance_behavior(self, fingerprint: BehavioralFingerprint, request_data: Dict[str, Any]) -> bool:
        """Detect reconnaissance/probing behavior."""
        endpoints = fingerprint.endpoint_sequence[-50:]  # Recent endpoints

        # Check for probing patterns
        probe_patterns = [
            '/admin', '/.env', '/config', '/backup', '/test',
            '/debug', '/api/v', '/swagger', '/docs', '/.git'
        ]

        probe_count = sum(1 for ep in endpoints
                         for pattern in probe_patterns
                         if pattern in ep.lower())

        if probe_count > 5:
            return True

        # Check for error-inducing requests (404 probing)
        # This would need integration with response codes
        return False

    def _is_evasion_attempt(self, fingerprint: BehavioralFingerprint, request_data: Dict[str, Any]) -> bool:
        """Detect attempts to evade security measures."""
        # Frequent user agent changes
        if len(fingerprint.user_agent_variations) > 3 and len(fingerprint.request_intervals) < 100:
            return True

        # Suspicious header manipulation
        headers = request_data.get('headers', {})
        evasion_headers = ['x-forwarded-for', 'x-real-ip', 'x-originating-ip', 'client-ip']
        if any(header.lower() in [h.lower() for h in headers.keys()] for header in evasion_headers):
            return True

        # Encoding/obfuscation attempts
        endpoint = request_data.get('endpoint', '')
        if '%' in endpoint and endpoint.count('%') > 3:  # URL encoding
            return True

        return False

    async def _perform_correlation_analysis(self,
                                          entity_id: str,
                                          entity_type: str,
                                          current_time: datetime) -> Dict[str, Any]:
        """Perform correlation analysis across entities."""
        correlation_data = {
            'coordinated_attack': False,
            'distributed_scraping': False,
            'similar_entities': [],
            'attack_cluster_size': 0
        }

        if entity_type != 'ip':
            return correlation_data

        # Find similar behavioral patterns in recent time window
        time_window = timedelta(minutes=10)
        recent_entities = []

        for eid, fingerprint in self.fingerprints.items():
            if (eid != entity_id and
                fingerprint.entity_type == entity_type and
                current_time - fingerprint.last_seen < time_window):
                recent_entities.append(fingerprint)

        if len(recent_entities) < 2:
            return correlation_data

        # Calculate behavioral similarity
        current_fingerprint = self.fingerprints.get(entity_id)
        if not current_fingerprint or current_fingerprint.feature_vector is None:
            return correlation_data

        similar_entities = []
        for other_fingerprint in recent_entities:
            if other_fingerprint.feature_vector is not None:
                similarity = self._calculate_behavioral_similarity(
                    current_fingerprint.feature_vector,
                    other_fingerprint.feature_vector
                )
                if similarity > 0.7:  # High similarity threshold
                    similar_entities.append({
                        'entity_id': other_fingerprint.entity_id,
                        'similarity': similarity,
                        'last_seen': other_fingerprint.last_seen.isoformat()
                    })

        correlation_data['similar_entities'] = similar_entities
        correlation_data['attack_cluster_size'] = len(similar_entities) + 1

        # Check for coordinated attack
        if len(similar_entities) >= self.correlation_rules['coordinated_attack']['min_ips']:
            correlation_data['coordinated_attack'] = True

        # Check for distributed scraping
        if len(similar_entities) >= self.correlation_rules['distributed_scraping']['min_ips']:
            # Additional check for scraping patterns
            scraping_entities = sum(1 for entity in similar_entities
                                  if self._has_scraping_patterns(entity['entity_id']))
            if scraping_entities >= 3:
                correlation_data['distributed_scraping'] = True

        return correlation_data

    def _calculate_behavioral_similarity(self, features1: np.ndarray, features2: np.ndarray) -> float:
        """Calculate similarity between two behavioral feature vectors."""
        try:
            # Normalize features
            norm1 = np.linalg.norm(features1)
            norm2 = np.linalg.norm(features2)

            if norm1 == 0 or norm2 == 0:
                return 0.0

            # Cosine similarity
            similarity = np.dot(features1, features2) / (norm1 * norm2)
            return max(0.0, similarity)

        except Exception:
            return 0.0

    def _has_scraping_patterns(self, entity_id: str) -> bool:
        """Check if entity has scraping patterns."""
        fingerprint = self.fingerprints.get(entity_id)
        if not fingerprint:
            return False

        # Quick scraping check
        if len(fingerprint.request_intervals) > 10:
            avg_interval = fingerprint.avg_request_interval
            if avg_interval < 3.0 and fingerprint.endpoint_diversity > 0.5:
                return True

        return False

    def _assess_threat_level(self,
                           anomaly_score: float,
                           threat_patterns: List[str],
                           correlation_data: Dict[str, Any]) -> Tuple[BehavioralThreatType, float, int]:
        """Assess overall threat level and type."""
        # Start with base scores
        base_confidence = 0.0
        risk_level = 0
        threat_type = BehavioralThreatType.NORMAL

        # Anomaly contribution
        if anomaly_score > 0.8:
            base_confidence += 0.4
            risk_level += 3
        elif anomaly_score > 0.6:
            base_confidence += 0.2
            risk_level += 2
        elif anomaly_score > 0.4:
            base_confidence += 0.1
            risk_level += 1

        # Pattern-based assessment
        if 'bot_behavior' in threat_patterns:
            threat_type = BehavioralThreatType.BOT_BEHAVIOR
            base_confidence += 0.3
            risk_level += 2

        if 'scraping_behavior' in threat_patterns:
            threat_type = BehavioralThreatType.SCRAPING_ATTEMPT
            base_confidence += 0.3
            risk_level += 3

        if 'brute_force' in threat_patterns:
            threat_type = BehavioralThreatType.BRUTE_FORCE
            base_confidence += 0.4
            risk_level += 4

        if 'reconnaissance' in threat_patterns:
            threat_type = BehavioralThreatType.RECONNAISSANCE
            base_confidence += 0.3
            risk_level += 3

        if 'evasion_attempt' in threat_patterns:
            threat_type = BehavioralThreatType.EVASION_ATTEMPT
            base_confidence += 0.4
            risk_level += 4

        # Correlation-based escalation
        if correlation_data.get('coordinated_attack'):
            threat_type = BehavioralThreatType.COORDINATED_ATTACK
            base_confidence += 0.3
            risk_level += 3

        if correlation_data.get('distributed_scraping'):
            threat_type = BehavioralThreatType.SCRAPING_ATTEMPT
            base_confidence += 0.2
            risk_level += 2

        # Multiple patterns increase confidence
        if len(threat_patterns) > 1:
            base_confidence += 0.1 * (len(threat_patterns) - 1)
            risk_level += len(threat_patterns) - 1

        # Cap values
        confidence = min(1.0, base_confidence)
        risk_level = min(10, risk_level)

        return threat_type, confidence, risk_level

    async def _store_analysis_result(self, assessment: BehavioralAssessment, features: np.ndarray):
        """Store analysis result for model training and historical analysis."""
        # Create training sample
        training_sample = {
            'features': features.tolist(),
            'label': 1 if assessment.threat_type != BehavioralThreatType.NORMAL else 0,
            'threat_type': assessment.threat_type.value,
            'confidence': assessment.confidence,
            'risk_level': assessment.risk_level,
            'timestamp': assessment.timestamp.isoformat(),
            'patterns': assessment.patterns_detected
        }

        # Encrypt sensitive data
        encrypted_sample = self.cipher_suite.encrypt(
            json.dumps(training_sample).encode()
        )

        # Store in training data queue
        self.training_data.append({
            'encrypted_data': encrypted_sample,
            'timestamp': assessment.timestamp,
            'label': training_sample['label']
        })

        # Log significant threats
        if assessment.risk_level > 5:
            logger.warning(f"High-risk behavioral threat detected: {assessment.threat_type.value} "
                         f"(confidence: {assessment.confidence:.2f}, risk: {assessment.risk_level})")

    async def _retrain_models(self):
        """Retrain ML models with new data."""
        if len(self.training_data) < 100:  # Need minimum samples
            return

        try:
            logger.info("Starting behavioral analysis model retraining...")

            # Decrypt and prepare training data
            features_list = []
            labels_list = []

            for sample in list(self.training_data):
                try:
                    decrypted_data = self.cipher_suite.decrypt(sample['encrypted_data'])
                    sample_data = json.loads(decrypted_data.decode())

                    features_list.append(sample_data['features'])
                    labels_list.append(sample_data['label'])
                except Exception as e:
                    logger.warning(f"Failed to decrypt training sample: {e}")
                    continue

            if len(features_list) < 50:
                logger.warning("Insufficient valid training samples")
                return

            # Convert to numpy arrays
            X = np.array(features_list)
            y = np.array(labels_list)

            # Fit scaler
            self.scaler.fit(X)
            X_scaled = self.scaler.transform(X)

            # Train anomaly detector
            self.anomaly_detector.fit(X_scaled)

            # Train clustering model
            clusters = self.clusterer.fit_predict(X_scaled)

            # Update model state
            self.model_trained = True
            self.model_version += 1
            self.last_training = datetime.now(timezone.utc)

            logger.info(f"Model retraining completed. Version: {self.model_version}, "
                       f"Samples: {len(features_list)}, Clusters: {len(set(clusters))}")

        except Exception as e:
            logger.error(f"Model retraining failed: {e}")

    def get_system_status(self) -> Dict[str, Any]:
        """Get current system status and statistics."""
        return {
            'enabled': True,
            'integrity_verified': self._verify_integrity(),
            'model_trained': self.model_trained,
            'model_version': self.model_version,
            'last_training': self.last_training.isoformat() if self.last_training else None,
            'tracked_entities': len(self.fingerprints),
            'training_samples': len(self.training_data),
            'anti_hijacking_enabled': self.tamper_detection_enabled,
            'system_integrity_hash': self.system_integrity_hash[:16] + "...",  # Partial hash for security
            'statistics': {
                'total_fingerprints': len(self.fingerprints),
                'active_entities_1h': sum(1 for fp in self.fingerprints.values()
                                        if (datetime.now(timezone.utc) - fp.last_seen).total_seconds() < 3600),
                'high_risk_entities': sum(1 for fp in self.fingerprints.values()
                                        if fp.trust_score < 0.5),
                'tamper_detections': sum(1 for fp in self.fingerprints.values()
                                       if fp.tamper_detected)
            }
        }

    async def reset_entity_profile(self, entity_id: str) -> bool:
        """Reset behavioral profile for an entity (admin function)."""
        if not self._verify_integrity():
            logger.critical("Cannot reset profile: system integrity compromised")
            return False

        if entity_id in self.fingerprints:
            del self.fingerprints[entity_id]
            if entity_id in self.request_history:
                del self.request_history[entity_id]

            logger.info(f"Reset behavioral profile for entity: {entity_id}")
            return True

        return False

    def enable_tamper_detection(self, enabled: bool = True):
        """Enable or disable tamper detection."""
        self.tamper_detection_enabled = enabled
        if enabled:
            self.system_integrity_hash = self._calculate_system_integrity()
        logger.info(f"Tamper detection {'enabled' if enabled else 'disabled'}")

# Global instance
advanced_behavioral_analyzer = AdvancedBehavioralAnalyzer()
