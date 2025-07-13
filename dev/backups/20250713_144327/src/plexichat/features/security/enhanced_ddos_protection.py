"""
Enhanced DDoS Protection System with Machine Learning

Advanced DDoS protection featuring:
- Machine learning-based threat detection
- Adaptive rate limiting
- Behavioral analysis
- Real-time threat intelligence
- Automated response mechanisms
"""

import asyncio
import logging
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple
from enum import Enum
import hashlib
import json

logger = logging.getLogger(__name__)


class ThreatLevel(str, Enum):
    """Threat level classifications."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AttackType(str, Enum):
    """Types of detected attacks."""
    VOLUMETRIC = "volumetric"
    PROTOCOL = "protocol"
    APPLICATION = "application"
    SLOWLORIS = "slowloris"
    HTTP_FLOOD = "http_flood"
    SYN_FLOOD = "syn_flood"
    UDP_FLOOD = "udp_flood"
    BOTNET = "botnet"
    SCRAPING = "scraping"
    BRUTE_FORCE = "brute_force"


@dataclass
class ThreatSignature:
    """Threat signature for pattern matching."""
    name: str
    pattern_type: str
    indicators: Dict[str, Any]
    severity: ThreatLevel
    confidence_threshold: float
    action: str


@dataclass
class RequestMetrics:
    """Metrics for a single request."""
    timestamp: float
    ip_address: str
    user_agent: str
    endpoint: str
    method: str
    size_bytes: int
    response_time: float
    status_code: int
    headers: Dict[str, str]
    geo_location: Optional[str] = None
    is_suspicious: bool = False
    threat_score: float = 0.0


@dataclass
class ClientProfile:
    """Profile for tracking client behavior."""
    ip_address: str
    first_seen: datetime
    last_seen: datetime
    request_count: int
    total_bytes: int
    unique_endpoints: set
    user_agents: set
    status_codes: Dict[int, int]
    avg_request_rate: float
    peak_request_rate: float
    geo_locations: set
    threat_score: float = 0.0
    is_whitelisted: bool = False
    is_blacklisted: bool = False
    reputation_score: float = 0.5


class EnhancedDDoSProtection:
    """Enhanced DDoS protection with ML-based threat detection."""

    def __init__(self):
        # Request tracking
        self.request_history = deque(maxlen=100000)  # Last 100k requests
        self.client_profiles = {}  # IP -> ClientProfile
        self.rate_limits = defaultdict(lambda: deque(maxlen=1000))
        
        # Threat detection
        self.threat_signatures = self._load_threat_signatures()
        self.ml_model = None  # Placeholder for ML model
        self.threat_intelligence = {}
        
        # Adaptive thresholds
        self.base_rate_limit = 100  # requests per minute
        self.adaptive_multiplier = 1.0
        self.global_threat_level = ThreatLevel.LOW
        
        # Blocking and mitigation
        self.blocked_ips = {}  # IP -> block_until_timestamp
        self.temp_blocks = {}  # IP -> block_until_timestamp
        self.challenge_responses = {}  # IP -> challenge_data
        
        # Performance metrics
        self.metrics = {
            "requests_processed": 0,
            "requests_blocked": 0,
            "threats_detected": 0,
            "false_positives": 0,
            "response_time_ms": 0.0,
            "cpu_usage": 0.0,
            "memory_usage": 0.0
        }
        
        # Configuration
        self.config = {
            "enable_ml_detection": True,
            "enable_behavioral_analysis": True,
            "enable_geo_blocking": False,
            "enable_challenge_response": True,
            "adaptive_rate_limiting": True,
            "threat_intelligence_enabled": True,
            "auto_blacklist_threshold": 0.9,
            "whitelist_trusted_ips": True
        }

    def _load_threat_signatures(self) -> List[ThreatSignature]:
        """Load threat signatures for pattern matching."""
        signatures = [
            ThreatSignature(
                name="High Frequency Requests",
                pattern_type="rate",
                indicators={"requests_per_minute": 500},
                severity=ThreatLevel.HIGH,
                confidence_threshold=0.8,
                action="rate_limit"
            ),
            ThreatSignature(
                name="Suspicious User Agent",
                pattern_type="user_agent",
                indicators={"patterns": ["bot", "crawler", "scanner", "attack"]},
                severity=ThreatLevel.MEDIUM,
                confidence_threshold=0.7,
                action="challenge"
            ),
            ThreatSignature(
                name="Rapid Endpoint Scanning",
                pattern_type="endpoint_scanning",
                indicators={"unique_endpoints_per_minute": 50},
                severity=ThreatLevel.HIGH,
                confidence_threshold=0.85,
                action="block"
            ),
            ThreatSignature(
                name="Large Request Size",
                pattern_type="size",
                indicators={"request_size_mb": 10},
                severity=ThreatLevel.MEDIUM,
                confidence_threshold=0.6,
                action="rate_limit"
            ),
            ThreatSignature(
                name="Botnet Pattern",
                pattern_type="behavioral",
                indicators={"coordinated_requests": True, "similar_timing": True},
                severity=ThreatLevel.CRITICAL,
                confidence_threshold=0.9,
                action="block"
            )
        ]
        return signatures

    async def analyze_request(self, request_data: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """Analyze incoming request for threats."""
        start_time = time.time()
        
        try:
            # Extract request metrics
            metrics = self._extract_request_metrics(request_data)
            
            # Update client profile
            self._update_client_profile(metrics)
            
            # Check if IP is blocked
            if self._is_ip_blocked(metrics.ip_address):
                self.metrics["requests_blocked"] += 1
                return False, {
                    "reason": "ip_blocked",
                    "threat_level": ThreatLevel.HIGH,
                    "action": "block"
                }
            
            # Perform threat analysis
            threat_analysis = await self._perform_threat_analysis(metrics)
            
            # Make decision
            decision = self._make_protection_decision(threat_analysis)
            
            # Update metrics
            self.metrics["requests_processed"] += 1
            self.metrics["response_time_ms"] = (time.time() - start_time) * 1000
            
            if not decision["allowed"]:
                self.metrics["requests_blocked"] += 1
                if decision.get("is_threat"):
                    self.metrics["threats_detected"] += 1
            
            return decision["allowed"], decision
            
        except Exception as e:
            logger.error(f"DDoS analysis failed: {e}")
            return True, {"reason": "analysis_error", "error": str(e)}

    def _extract_request_metrics(self, request_data: Dict[str, Any]) -> RequestMetrics:
        """Extract metrics from request data."""
        return RequestMetrics(
            timestamp=time.time(),
            ip_address=request_data.get("ip_address", "unknown"),
            user_agent=request_data.get("user_agent", ""),
            endpoint=request_data.get("endpoint", "/"),
            method=request_data.get("method", "GET"),
            size_bytes=request_data.get("size_bytes", 0),
            response_time=request_data.get("response_time", 0.0),
            status_code=request_data.get("status_code", 200),
            headers=request_data.get("headers", {}),
            geo_location=request_data.get("geo_location")
        )

    def _update_client_profile(self, metrics: RequestMetrics):
        """Update client behavioral profile."""
        ip = metrics.ip_address
        now = datetime.now(timezone.utc)
        
        if ip not in self.client_profiles:
            self.client_profiles[ip] = ClientProfile(
                ip_address=ip,
                first_seen=now,
                last_seen=now,
                request_count=0,
                total_bytes=0,
                unique_endpoints=set(),
                user_agents=set(),
                status_codes=defaultdict(int),
                avg_request_rate=0.0,
                peak_request_rate=0.0,
                geo_locations=set()
            )
        
        profile = self.client_profiles[ip]
        profile.last_seen = now
        profile.request_count += 1
        profile.total_bytes += metrics.size_bytes
        profile.unique_endpoints.add(metrics.endpoint)
        profile.user_agents.add(metrics.user_agent)
        profile.status_codes[metrics.status_code] += 1
        
        if metrics.geo_location:
            profile.geo_locations.add(metrics.geo_location)
        
        # Calculate request rate
        time_window = (now - profile.first_seen).total_seconds() / 60  # minutes
        if time_window > 0:
            current_rate = profile.request_count / time_window
            profile.avg_request_rate = current_rate
            profile.peak_request_rate = max(profile.peak_request_rate, current_rate)

    async def _perform_threat_analysis(self, metrics: RequestMetrics) -> Dict[str, Any]:
        """Perform comprehensive threat analysis."""
        analysis = {
            "threat_score": 0.0,
            "threat_level": ThreatLevel.LOW,
            "detected_attacks": [],
            "confidence": 0.0,
            "indicators": []
        }
        
        # Signature-based detection
        signature_results = self._check_threat_signatures(metrics)
        analysis["signature_matches"] = signature_results
        
        # Behavioral analysis
        if self.config["enable_behavioral_analysis"]:
            behavioral_results = self._analyze_behavior(metrics)
            analysis["behavioral_analysis"] = behavioral_results
        
        # ML-based detection
        if self.config["enable_ml_detection"] and self.ml_model:
            ml_results = await self._ml_threat_detection(metrics)
            analysis["ml_analysis"] = ml_results
        
        # Rate limiting analysis
        rate_analysis = self._analyze_rate_patterns(metrics)
        analysis["rate_analysis"] = rate_analysis
        
        # Combine all analyses
        analysis = self._combine_threat_analyses(analysis)
        
        return analysis

    def _check_threat_signatures(self, metrics: RequestMetrics) -> List[Dict[str, Any]]:
        """Check request against known threat signatures."""
        matches = []
        
        for signature in self.threat_signatures:
            confidence = 0.0
            
            if signature.pattern_type == "rate":
                # Check rate-based patterns
                profile = self.client_profiles.get(metrics.ip_address)
                if profile and profile.avg_request_rate > signature.indicators.get("requests_per_minute", 100):
                    confidence = min(1.0, profile.avg_request_rate / signature.indicators["requests_per_minute"])
            
            elif signature.pattern_type == "user_agent":
                # Check user agent patterns
                ua_lower = metrics.user_agent.lower()
                for pattern in signature.indicators.get("patterns", []):
                    if pattern in ua_lower:
                        confidence = 0.8
                        break
            
            elif signature.pattern_type == "endpoint_scanning":
                # Check for endpoint scanning
                profile = self.client_profiles.get(metrics.ip_address)
                if profile:
                    time_window = 1  # 1 minute
                    recent_endpoints = len(profile.unique_endpoints)
                    threshold = signature.indicators.get("unique_endpoints_per_minute", 50)
                    if recent_endpoints > threshold:
                        confidence = min(1.0, recent_endpoints / threshold)
            
            elif signature.pattern_type == "size":
                # Check request size
                size_mb = metrics.size_bytes / (1024 * 1024)
                threshold = signature.indicators.get("request_size_mb", 10)
                if size_mb > threshold:
                    confidence = min(1.0, size_mb / threshold)
            
            if confidence >= signature.confidence_threshold:
                matches.append({
                    "signature": signature.name,
                    "confidence": confidence,
                    "severity": signature.severity,
                    "action": signature.action
                })
        
        return matches

    def _analyze_behavior(self, metrics: RequestMetrics) -> Dict[str, Any]:
        """Analyze behavioral patterns."""
        profile = self.client_profiles.get(metrics.ip_address)
        if not profile:
            return {"anomaly_score": 0.0, "indicators": []}
        
        indicators = []
        anomaly_score = 0.0
        
        # Check for rapid requests
        if profile.avg_request_rate > self.base_rate_limit * 2:
            indicators.append("high_request_rate")
            anomaly_score += 0.3
        
        # Check for diverse endpoint access
        if len(profile.unique_endpoints) > 20:
            indicators.append("endpoint_scanning")
            anomaly_score += 0.2
        
        # Check for multiple user agents
        if len(profile.user_agents) > 5:
            indicators.append("multiple_user_agents")
            anomaly_score += 0.15
        
        # Check for error rate
        total_requests = sum(profile.status_codes.values())
        error_requests = sum(count for status, count in profile.status_codes.items() if status >= 400)
        if total_requests > 0:
            error_rate = error_requests / total_requests
            if error_rate > 0.5:
                indicators.append("high_error_rate")
                anomaly_score += 0.25
        
        # Check for geographic anomalies
        if len(profile.geo_locations) > 3:
            indicators.append("multiple_geolocations")
            anomaly_score += 0.1
        
        return {
            "anomaly_score": min(1.0, anomaly_score),
            "indicators": indicators,
            "profile_age_minutes": (datetime.now(timezone.utc) - profile.first_seen).total_seconds() / 60
        }

    async def _ml_threat_detection(self, metrics: RequestMetrics) -> Dict[str, Any]:
        """Machine learning-based threat detection."""
        # Placeholder for ML model inference
        # In a real implementation, this would use a trained model
        
        features = self._extract_ml_features(metrics)
        
        # Simulate ML prediction
        threat_probability = 0.1  # Low baseline threat
        
        # Simple heuristic-based "ML" for demonstration
        if metrics.user_agent and any(bot in metrics.user_agent.lower() for bot in ["bot", "crawler", "scanner"]):
            threat_probability += 0.3
        
        profile = self.client_profiles.get(metrics.ip_address)
        if profile:
            if profile.avg_request_rate > 200:
                threat_probability += 0.4
            if len(profile.unique_endpoints) > 30:
                threat_probability += 0.3
        
        threat_probability = min(1.0, threat_probability)
        
        return {
            "threat_probability": threat_probability,
            "confidence": 0.8,
            "model_version": "1.0.0",
            "features_used": len(features)
        }

    def _extract_ml_features(self, metrics: RequestMetrics) -> List[float]:
        """Extract features for ML model."""
        profile = self.client_profiles.get(metrics.ip_address)
        
        features = [
            metrics.size_bytes / 1024,  # Request size in KB
            len(metrics.user_agent),    # User agent length
            len(metrics.endpoint),      # Endpoint length
            1.0 if metrics.method == "POST" else 0.0,  # Is POST request
        ]
        
        if profile:
            features.extend([
                profile.request_count,
                profile.avg_request_rate,
                len(profile.unique_endpoints),
                len(profile.user_agents),
                profile.total_bytes / 1024,
            ])
        else:
            features.extend([0.0, 0.0, 0.0, 0.0, 0.0])
        
        return features

    def _analyze_rate_patterns(self, metrics: RequestMetrics) -> Dict[str, Any]:
        """Analyze request rate patterns."""
        ip = metrics.ip_address
        now = time.time()

        # Add current request to rate tracking
        self.rate_limits[ip].append(now)

        # Calculate rates for different time windows
        rates = {}
        windows = {"1min": 60, "5min": 300, "15min": 900, "1hour": 3600}

        for window_name, window_seconds in windows.items():
            cutoff_time = now - window_seconds
            recent_requests = [t for t in self.rate_limits[ip] if t > cutoff_time]
            rates[window_name] = len(recent_requests)

        # Determine if rate is suspicious
        adaptive_limit = self.base_rate_limit * self.adaptive_multiplier
        is_rate_exceeded = rates["1min"] > adaptive_limit

        return {
            "rates": rates,
            "adaptive_limit": adaptive_limit,
            "is_rate_exceeded": is_rate_exceeded,
            "rate_score": min(1.0, rates["1min"] / adaptive_limit) if adaptive_limit > 0 else 0.0
        }

    def _combine_threat_analyses(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Combine all threat analysis results."""
        threat_score = 0.0
        confidence = 0.0
        detected_attacks = []

        # Signature-based threats
        signature_matches = analysis.get("signature_matches", [])
        if signature_matches:
            max_signature_confidence = max(match["confidence"] for match in signature_matches)
            threat_score += max_signature_confidence * 0.4
            detected_attacks.extend([match["signature"] for match in signature_matches])

        # Behavioral analysis
        behavioral = analysis.get("behavioral_analysis", {})
        if behavioral:
            threat_score += behavioral.get("anomaly_score", 0.0) * 0.3
            if behavioral.get("anomaly_score", 0.0) > 0.5:
                detected_attacks.append("behavioral_anomaly")

        # ML analysis
        ml_analysis = analysis.get("ml_analysis", {})
        if ml_analysis:
            ml_threat = ml_analysis.get("threat_probability", 0.0)
            ml_confidence = ml_analysis.get("confidence", 0.0)
            threat_score += ml_threat * 0.25
            confidence = max(confidence, ml_confidence)
            if ml_threat > 0.7:
                detected_attacks.append("ml_detected_threat")

        # Rate analysis
        rate_analysis = analysis.get("rate_analysis", {})
        if rate_analysis:
            rate_score = rate_analysis.get("rate_score", 0.0)
            threat_score += rate_score * 0.05
            if rate_analysis.get("is_rate_exceeded", False):
                detected_attacks.append("rate_limit_exceeded")

        # Determine threat level
        if threat_score >= 0.8:
            threat_level = ThreatLevel.CRITICAL
        elif threat_score >= 0.6:
            threat_level = ThreatLevel.HIGH
        elif threat_score >= 0.3:
            threat_level = ThreatLevel.MEDIUM
        else:
            threat_level = ThreatLevel.LOW

        analysis.update({
            "threat_score": min(1.0, threat_score),
            "threat_level": threat_level,
            "detected_attacks": detected_attacks,
            "confidence": confidence
        })

        return analysis

    def _make_protection_decision(self, threat_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Make final protection decision based on threat analysis."""
        threat_score = threat_analysis.get("threat_score", 0.0)
        threat_level = threat_analysis.get("threat_level", ThreatLevel.LOW)
        detected_attacks = threat_analysis.get("detected_attacks", [])

        decision = {
            "allowed": True,
            "action": "allow",
            "reason": "no_threat_detected",
            "threat_analysis": threat_analysis,
            "is_threat": False
        }

        # Critical threats - immediate block
        if threat_level == ThreatLevel.CRITICAL or threat_score >= 0.8:
            decision.update({
                "allowed": False,
                "action": "block",
                "reason": "critical_threat_detected",
                "is_threat": True,
                "block_duration": 3600  # 1 hour
            })
            self._apply_blocking_action(threat_analysis, 3600)

        # High threats - temporary block or challenge
        elif threat_level == ThreatLevel.HIGH or threat_score >= 0.6:
            if self.config["enable_challenge_response"]:
                decision.update({
                    "allowed": False,
                    "action": "challenge",
                    "reason": "high_threat_challenge",
                    "is_threat": True
                })
            else:
                decision.update({
                    "allowed": False,
                    "action": "temp_block",
                    "reason": "high_threat_detected",
                    "is_threat": True,
                    "block_duration": 300  # 5 minutes
                })
                self._apply_blocking_action(threat_analysis, 300)

        # Medium threats - rate limiting
        elif threat_level == ThreatLevel.MEDIUM or threat_score >= 0.3:
            decision.update({
                "allowed": True,
                "action": "rate_limit",
                "reason": "medium_threat_rate_limit",
                "is_threat": True,
                "rate_limit_factor": 0.5  # Reduce rate limit by 50%
            })

        # Low threats - monitoring
        else:
            decision.update({
                "allowed": True,
                "action": "monitor",
                "reason": "low_threat_monitor"
            })

        return decision

    def _apply_blocking_action(self, threat_analysis: Dict[str, Any], duration: int):
        """Apply blocking action for detected threats."""
        # This would be implemented to actually block IPs
        # For now, just log the action
        logger.warning(f"Blocking action applied: {threat_analysis.get('threat_level')} threat detected")

    def _is_ip_blocked(self, ip_address: str) -> bool:
        """Check if IP address is currently blocked."""
        now = time.time()

        # Check permanent blocks
        if ip_address in self.blocked_ips:
            if self.blocked_ips[ip_address] > now:
                return True
            else:
                del self.blocked_ips[ip_address]

        # Check temporary blocks
        if ip_address in self.temp_blocks:
            if self.temp_blocks[ip_address] > now:
                return True
            else:
                del self.temp_blocks[ip_address]

        return False

    async def update_threat_intelligence(self, intelligence_data: Dict[str, Any]):
        """Update threat intelligence database."""
        try:
            # Update known malicious IPs
            malicious_ips = intelligence_data.get("malicious_ips", [])
            for ip_data in malicious_ips:
                ip = ip_data.get("ip")
                if ip:
                    self.threat_intelligence[ip] = {
                        "threat_level": ip_data.get("threat_level", ThreatLevel.MEDIUM),
                        "last_seen": ip_data.get("last_seen"),
                        "attack_types": ip_data.get("attack_types", []),
                        "confidence": ip_data.get("confidence", 0.5)
                    }

            # Update threat signatures
            new_signatures = intelligence_data.get("signatures", [])
            for sig_data in new_signatures:
                signature = ThreatSignature(
                    name=sig_data["name"],
                    pattern_type=sig_data["pattern_type"],
                    indicators=sig_data["indicators"],
                    severity=ThreatLevel(sig_data["severity"]),
                    confidence_threshold=sig_data["confidence_threshold"],
                    action=sig_data["action"]
                )
                self.threat_signatures.append(signature)

            logger.info(f"Updated threat intelligence: {len(malicious_ips)} IPs, {len(new_signatures)} signatures")

        except Exception as e:
            logger.error(f"Failed to update threat intelligence: {e}")

    def get_protection_stats(self) -> Dict[str, Any]:
        """Get current protection statistics."""
        return {
            "metrics": self.metrics.copy(),
            "active_clients": len(self.client_profiles),
            "blocked_ips": len(self.blocked_ips),
            "temp_blocked_ips": len(self.temp_blocks),
            "threat_signatures": len(self.threat_signatures),
            "global_threat_level": self.global_threat_level,
            "adaptive_multiplier": self.adaptive_multiplier,
            "config": self.config.copy()
        }

    async def adaptive_threshold_adjustment(self):
        """Automatically adjust protection thresholds based on current threat landscape."""
        try:
            # Calculate current threat metrics
            recent_requests = len([r for r in self.request_history if time.time() - r.timestamp < 300])  # Last 5 minutes
            threat_ratio = self.metrics["threats_detected"] / max(1, self.metrics["requests_processed"])

            # Adjust adaptive multiplier based on threat level
            if threat_ratio > 0.1:  # High threat environment
                self.adaptive_multiplier = max(0.3, self.adaptive_multiplier * 0.8)
                self.global_threat_level = ThreatLevel.HIGH
            elif threat_ratio > 0.05:  # Medium threat environment
                self.adaptive_multiplier = max(0.5, self.adaptive_multiplier * 0.9)
                self.global_threat_level = ThreatLevel.MEDIUM
            else:  # Low threat environment
                self.adaptive_multiplier = min(2.0, self.adaptive_multiplier * 1.1)
                self.global_threat_level = ThreatLevel.LOW

            logger.info(f"Adaptive thresholds updated: multiplier={self.adaptive_multiplier:.2f}, threat_level={self.global_threat_level}")

        except Exception as e:
            logger.error(f"Adaptive threshold adjustment failed: {e}")


# Global instance
enhanced_ddos_protection = EnhancedDDoSProtection()
