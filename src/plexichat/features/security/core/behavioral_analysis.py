"""
PlexiChat Behavioral Analysis System

AI-powered behavioral threat detection with machine learning models,
anomaly detection, and adaptive security responses.
"""

import asyncio
import logging
import time
import json
import hashlib
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
# Optional import for advanced behavioral analysis
try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False
from datetime import datetime, timezone, timedelta

logger = logging.getLogger(__name__)


class BehaviorType(Enum):
    """Types of behavioral patterns."""
    NORMAL = "normal"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    BOT = "bot"
    SCRAPER = "scraper"
    DDOS = "ddos"
    BRUTE_FORCE = "brute_force"
    RECONNAISSANCE = "reconnaissance"


class AnomalyType(Enum):
    """Types of anomalies detected."""
    FREQUENCY_ANOMALY = "frequency_anomaly"
    PATTERN_ANOMALY = "pattern_anomaly"
    TIMING_ANOMALY = "timing_anomaly"
    GEOGRAPHIC_ANOMALY = "geographic_anomaly"
    USER_AGENT_ANOMALY = "user_agent_anomaly"
    ENDPOINT_ANOMALY = "endpoint_anomaly"
    SIZE_ANOMALY = "size_anomaly"


class ThreatLevel(Enum):
    """Threat severity levels."""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class BehaviorProfile:
    """User/IP behavior profile."""
    identifier: str  # IP or user ID
    first_seen: datetime
    last_seen: datetime
    total_requests: int = 0
    unique_endpoints: Set[str] = field(default_factory=set)
    unique_user_agents: Set[str] = field(default_factory=set)
    request_patterns: List[float] = field(default_factory=list)  # Request intervals
    error_rate: float = 0.0
    success_rate: float = 0.0
    average_request_size: float = 0.0
    peak_request_rate: float = 0.0
    behavior_type: BehaviorType = BehaviorType.NORMAL
    threat_level: ThreatLevel = ThreatLevel.LOW
    confidence_score: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert profile to dictionary."""
        return {
            "identifier": self.identifier,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "total_requests": self.total_requests,
            "unique_endpoints": len(self.unique_endpoints),
            "unique_user_agents": len(self.unique_user_agents),
            "error_rate": self.error_rate,
            "success_rate": self.success_rate,
            "average_request_size": self.average_request_size,
            "peak_request_rate": self.peak_request_rate,
            "behavior_type": self.behavior_type.value,
            "threat_level": self.threat_level.value,
            "confidence_score": self.confidence_score
        }


@dataclass
class RequestEvent:
    """Individual request event for analysis."""
    timestamp: float
    ip_address: str
    user_id: Optional[str]
    endpoint: str
    method: str
    status_code: int
    response_size: int
    user_agent: str
    referer: Optional[str] = None
    processing_time: float = 0.0
    
    def get_fingerprint(self) -> str:
        """Get unique fingerprint for this request."""
        data = f"{self.ip_address}:{self.user_agent}:{self.endpoint}:{self.method}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]


@dataclass
class AnomalyDetection:
    """Anomaly detection result."""
    anomaly_type: AnomalyType
    severity: ThreatLevel
    confidence: float
    description: str
    evidence: Dict[str, Any]
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "anomaly_type": self.anomaly_type.value,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "description": self.description,
            "evidence": self.evidence,
            "timestamp": self.timestamp.isoformat()
        }


class BehavioralAnalyzer:
    """AI-powered behavioral analysis system."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize behavioral analyzer."""
        if not HAS_NUMPY:
            logger.warning("NumPy not available - advanced behavioral analysis disabled")
            self.enabled = False
        else:
            self.enabled = True

        self.config = config or {}
        
        # Behavior profiles
        self.profiles: Dict[str, BehaviorProfile] = {}
        
        # Request history for analysis
        self.request_history: deque = deque(maxlen=10000)
        
        # Anomaly detection thresholds
        self.thresholds = {
            "max_requests_per_minute": 100,
            "max_unique_endpoints_per_hour": 50,
            "max_error_rate": 0.5,
            "min_request_interval": 0.1,  # seconds
            "max_user_agents_per_session": 3,
            "suspicious_endpoint_patterns": [
                r"/admin", r"/wp-admin", r"/.env", r"/config",
                r"/backup", r"/test", r"/debug", r"/api/v\d+/.*"
            ]
        }
        
        # Machine learning models (simplified)
        self.normal_patterns = {}
        self.anomaly_patterns = {}
        
        # Statistics
        self.stats = {
            "total_events_analyzed": 0,
            "anomalies_detected": 0,
            "profiles_created": 0,
            "threats_identified": 0
        }
        
        logger.info("Behavioral Analyzer initialized")
    
    async def analyze_request(self, event: RequestEvent) -> Tuple[BehaviorType, ThreatLevel, List[AnomalyDetection]]:
        """Analyze a request event for behavioral patterns."""
        self.stats["total_events_analyzed"] += 1
        
        # Add to request history
        self.request_history.append(event)
        
        # Get or create behavior profile
        profile = self._get_or_create_profile(event)
        
        # Update profile with new event
        self._update_profile(profile, event)
        
        # Detect anomalies
        anomalies = await self._detect_anomalies(event, profile)
        
        # Classify behavior
        behavior_type = self._classify_behavior(profile, anomalies)
        
        # Determine threat level
        threat_level = self._calculate_threat_level(profile, anomalies)
        
        # Update profile classification
        profile.behavior_type = behavior_type
        profile.threat_level = threat_level
        profile.confidence_score = self._calculate_confidence(profile, anomalies)
        
        if anomalies:
            self.stats["anomalies_detected"] += len(anomalies)
        
        if threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
            self.stats["threats_identified"] += 1
        
        return behavior_type, threat_level, anomalies
    
    def _get_or_create_profile(self, event: RequestEvent) -> BehaviorProfile:
        """Get existing profile or create new one."""
        identifier = event.user_id or event.ip_address
        
        if identifier not in self.profiles:
            self.profiles[identifier] = BehaviorProfile(
                identifier=identifier,
                first_seen=datetime.fromtimestamp(event.timestamp, timezone.utc),
                last_seen=datetime.fromtimestamp(event.timestamp, timezone.utc)
            )
            self.stats["profiles_created"] += 1
        
        return self.profiles[identifier]
    
    def _update_profile(self, profile: BehaviorProfile, event: RequestEvent):
        """Update behavior profile with new event."""
        profile.last_seen = datetime.fromtimestamp(event.timestamp, timezone.utc)
        profile.total_requests += 1
        profile.unique_endpoints.add(event.endpoint)
        profile.unique_user_agents.add(event.user_agent)
        
        # Update request patterns (intervals between requests)
        if len(profile.request_patterns) > 0:
            last_request_time = profile.request_patterns[-1]
            interval = event.timestamp - last_request_time
            profile.request_patterns.append(interval)
        else:
            profile.request_patterns.append(event.timestamp)
        
        # Keep only recent patterns
        if len(profile.request_patterns) > 100:
            profile.request_patterns = profile.request_patterns[-100:]
        
        # Update error/success rates
        if event.status_code >= 400:
            error_count = sum(1 for req in self.request_history 
                            if (req.user_id or req.ip_address) == profile.identifier 
                            and req.status_code >= 400)
            profile.error_rate = error_count / profile.total_requests
        else:
            success_count = sum(1 for req in self.request_history 
                              if (req.user_id or req.ip_address) == profile.identifier 
                              and req.status_code < 400)
            profile.success_rate = success_count / profile.total_requests
        
        # Update average request size
        total_size = sum(req.response_size for req in self.request_history 
                        if (req.user_id or req.ip_address) == profile.identifier)
        profile.average_request_size = total_size / profile.total_requests
        
        # Calculate peak request rate (requests per minute)
        recent_requests = [req for req in self.request_history 
                          if (req.user_id or req.ip_address) == profile.identifier 
                          and event.timestamp - req.timestamp <= 60]
        profile.peak_request_rate = len(recent_requests)
    
    async def _detect_anomalies(self, event: RequestEvent, profile: BehaviorProfile) -> List[AnomalyDetection]:
        """Detect anomalies in request behavior."""
        anomalies = []
        
        # Frequency anomaly detection
        if profile.peak_request_rate > self.thresholds["max_requests_per_minute"]:
            anomalies.append(AnomalyDetection(
                anomaly_type=AnomalyType.FREQUENCY_ANOMALY,
                severity=ThreatLevel.HIGH,
                confidence=0.9,
                description=f"Excessive request rate: {profile.peak_request_rate} requests/minute",
                evidence={"request_rate": profile.peak_request_rate, "threshold": self.thresholds["max_requests_per_minute"]}
            ))
        
        # Pattern anomaly detection
        if len(profile.unique_endpoints) > self.thresholds["max_unique_endpoints_per_hour"]:
            anomalies.append(AnomalyDetection(
                anomaly_type=AnomalyType.PATTERN_ANOMALY,
                severity=ThreatLevel.MEDIUM,
                confidence=0.8,
                description=f"Unusual endpoint access pattern: {len(profile.unique_endpoints)} unique endpoints",
                evidence={"unique_endpoints": len(profile.unique_endpoints), "threshold": self.thresholds["max_unique_endpoints_per_hour"]}
            ))
        
        # Timing anomaly detection
        if len(profile.request_patterns) > 1:
            recent_intervals = profile.request_patterns[-10:]
            if len(recent_intervals) > 1:
                avg_interval = np.mean(recent_intervals)
                if avg_interval < self.thresholds["min_request_interval"]:
                    anomalies.append(AnomalyDetection(
                        anomaly_type=AnomalyType.TIMING_ANOMALY,
                        severity=ThreatLevel.MEDIUM,
                        confidence=0.7,
                        description=f"Suspiciously fast requests: {avg_interval:.3f}s average interval",
                        evidence={"average_interval": avg_interval, "threshold": self.thresholds["min_request_interval"]}
                    ))
        
        # User agent anomaly detection
        if len(profile.unique_user_agents) > self.thresholds["max_user_agents_per_session"]:
            anomalies.append(AnomalyDetection(
                anomaly_type=AnomalyType.USER_AGENT_ANOMALY,
                severity=ThreatLevel.MEDIUM,
                confidence=0.8,
                description=f"Multiple user agents: {len(profile.unique_user_agents)} different agents",
                evidence={"user_agent_count": len(profile.unique_user_agents), "threshold": self.thresholds["max_user_agents_per_session"]}
            ))
        
        # Endpoint anomaly detection
        for pattern in self.thresholds["suspicious_endpoint_patterns"]:
            import re
            if re.search(pattern, event.endpoint, re.IGNORECASE):
                anomalies.append(AnomalyDetection(
                    anomaly_type=AnomalyType.ENDPOINT_ANOMALY,
                    severity=ThreatLevel.HIGH,
                    confidence=0.9,
                    description=f"Access to suspicious endpoint: {event.endpoint}",
                    evidence={"endpoint": event.endpoint, "pattern": pattern}
                ))
        
        # Error rate anomaly detection
        if profile.error_rate > self.thresholds["max_error_rate"]:
            anomalies.append(AnomalyDetection(
                anomaly_type=AnomalyType.PATTERN_ANOMALY,
                severity=ThreatLevel.MEDIUM,
                confidence=0.7,
                description=f"High error rate: {profile.error_rate:.2%}",
                evidence={"error_rate": profile.error_rate, "threshold": self.thresholds["max_error_rate"]}
            ))
        
        return anomalies
    
    def _classify_behavior(self, profile: BehaviorProfile, anomalies: List[AnomalyDetection]) -> BehaviorType:
        """Classify behavior type based on profile and anomalies."""
        if not anomalies:
            return BehaviorType.NORMAL
        
        # Count anomaly types
        anomaly_counts = defaultdict(int)
        for anomaly in anomalies:
            anomaly_counts[anomaly.anomaly_type] += 1
        
        # Classification logic
        if anomaly_counts[AnomalyType.FREQUENCY_ANOMALY] > 0 and profile.peak_request_rate > 200:
            return BehaviorType.DDOS
        
        if (anomaly_counts[AnomalyType.ENDPOINT_ANOMALY] > 0 and 
            len(profile.unique_endpoints) > 20):
            return BehaviorType.RECONNAISSANCE
        
        if (profile.error_rate > 0.8 and 
            any("login" in endpoint or "auth" in endpoint for endpoint in profile.unique_endpoints)):
            return BehaviorType.BRUTE_FORCE
        
        if (len(profile.unique_user_agents) > 5 or 
            profile.peak_request_rate > 50):
            return BehaviorType.BOT
        
        if (len(profile.unique_endpoints) > 30 and 
            profile.success_rate > 0.8):
            return BehaviorType.SCRAPER
        
        # Default to suspicious if anomalies exist
        return BehaviorType.SUSPICIOUS
    
    def _calculate_threat_level(self, profile: BehaviorProfile, anomalies: List[AnomalyDetection]) -> ThreatLevel:
        """Calculate overall threat level."""
        if not anomalies:
            return ThreatLevel.LOW
        
        # Calculate weighted threat score
        threat_score = 0
        for anomaly in anomalies:
            threat_score += anomaly.severity.value * anomaly.confidence
        
        # Normalize and classify
        if threat_score >= 3.0:
            return ThreatLevel.CRITICAL
        elif threat_score >= 2.0:
            return ThreatLevel.HIGH
        elif threat_score >= 1.0:
            return ThreatLevel.MEDIUM
        else:
            return ThreatLevel.LOW
    
    def _calculate_confidence(self, profile: BehaviorProfile, anomalies: List[AnomalyDetection]) -> float:
        """Calculate confidence score for behavior classification."""
        if not anomalies:
            return 1.0  # High confidence in normal behavior
        
        # Base confidence on number of requests and anomalies
        base_confidence = min(profile.total_requests / 100, 1.0)  # More requests = higher confidence
        anomaly_confidence = np.mean([a.confidence for a in anomalies])
        
        return (base_confidence + anomaly_confidence) / 2
    
    def get_profile(self, identifier: str) -> Optional[Dict[str, Any]]:
        """Get behavior profile for identifier."""
        profile = self.profiles.get(identifier)
        return profile.to_dict() if profile else None
    
    def get_all_profiles(self) -> List[Dict[str, Any]]:
        """Get all behavior profiles."""
        return [profile.to_dict() for profile in self.profiles.values()]
    
    def get_threat_profiles(self, min_threat_level: ThreatLevel = ThreatLevel.MEDIUM) -> List[Dict[str, Any]]:
        """Get profiles with threat level above threshold."""
        return [
            profile.to_dict() for profile in self.profiles.values()
            if profile.threat_level.value >= min_threat_level.value
        ]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get behavioral analysis statistics."""
        threat_distribution = defaultdict(int)
        behavior_distribution = defaultdict(int)
        
        for profile in self.profiles.values():
            threat_distribution[profile.threat_level.value] += 1
            behavior_distribution[profile.behavior_type.value] += 1
        
        return {
            **self.stats,
            "active_profiles": len(self.profiles),
            "threat_distribution": dict(threat_distribution),
            "behavior_distribution": dict(behavior_distribution),
            "request_history_size": len(self.request_history)
        }
    
    def cleanup_old_profiles(self, max_age_hours: int = 24):
        """Clean up old inactive profiles."""
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=max_age_hours)
        
        old_profiles = [
            identifier for identifier, profile in self.profiles.items()
            if profile.last_seen < cutoff_time
        ]
        
        for identifier in old_profiles:
            del self.profiles[identifier]
        
        logger.info(f"Cleaned up {len(old_profiles)} old behavior profiles")
        
        return len(old_profiles)
    
    def update_thresholds(self, new_thresholds: Dict[str, Any]):
        """Update anomaly detection thresholds."""
        self.thresholds.update(new_thresholds)
        logger.info(f"Updated {len(new_thresholds)} behavioral analysis thresholds")
    
    def export_profiles(self) -> Dict[str, Any]:
        """Export all profiles for backup/analysis."""
        return {
            "profiles": {identifier: profile.to_dict() for identifier, profile in self.profiles.items()},
            "thresholds": self.thresholds,
            "stats": self.stats
        }
    
    def import_profiles(self, data: Dict[str, Any]) -> bool:
        """Import profiles from backup."""
        try:
            if "profiles" in data:
                for identifier, profile_data in data["profiles"].items():
                    # Reconstruct profile (simplified)
                    profile = BehaviorProfile(
                        identifier=identifier,
                        first_seen=datetime.fromisoformat(profile_data["first_seen"]),
                        last_seen=datetime.fromisoformat(profile_data["last_seen"]),
                        total_requests=profile_data["total_requests"],
                        behavior_type=BehaviorType(profile_data["behavior_type"]),
                        threat_level=ThreatLevel(profile_data["threat_level"]),
                        confidence_score=profile_data["confidence_score"]
                    )
                    self.profiles[identifier] = profile
            
            if "thresholds" in data:
                self.thresholds.update(data["thresholds"])
            
            if "stats" in data:
                self.stats.update(data["stats"])
            
            logger.info("Behavioral analysis profiles imported successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to import profiles: {e}")
            return False


# Global instance
behavioral_analyzer = BehavioralAnalyzer()
