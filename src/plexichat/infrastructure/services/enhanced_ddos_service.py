# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import logging
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from app.security.advanced_behavioral_analyzer import (



import psutil
import = psutil psutil
import psutil
import = psutil psutil

    IP,
    DDoS,
    Dynamic,
    Enhanced,
    Integrates,
    Integration,
    Intelligent,
    Progressive,
    Protection,
    Real-time,
    Service,
    """,
    -,
    =,
    __name__,
    adaptation,
    and,
    based,
    blocking,
    detection,
    escalation,
    import,
    limiting,
    load,
    logger,
    logging.getLogger,
    monitoring,
    multiple,
    on,
    protection,
    psutil,
    rate,
    re,
    security,
    service,
    system,
    systems,
    threat,
    with,
    with:,
)

# Import advanced behavioral analyzer
try:
        BehavioralAssessment,
        BehavioralThreatType,
        advanced_behavioral_analyzer,
    )
    BEHAVIORAL_ANALYZER_AVAILABLE = True
except ImportError:
    BEHAVIORAL_ANALYZER_AVAILABLE = False
    logger.warning("Advanced behavioral analyzer not available")

class ThreatLevel(Enum):
    """DDoS threat levels."""
    CLEAN = 0
    SUSPICIOUS = 1
    MODERATE = 2
    HIGH = 3
    CRITICAL = 4

class BlockType(Enum):
    """Types of IP blocks."""
    NONE = "none"
    RATE_LIMITED = "rate_limited"
    TEMPORARILY_BLOCKED = "temporarily_blocked"
    PROGRESSIVELY_BLOCKED = "progressively_blocked"
    PERMANENTLY_BLOCKED = "permanently_blocked"

@dataclass
class DDoSMetrics:
    """DDoS protection metrics."""
    total_requests: int = 0
    blocked_requests: int = 0
    suspicious_requests: int = 0
    unique_ips: int = 0
    avg_requests_per_ip: float = 0.0
    system_load: float = 0.0
    memory_usage: float = 0.0
    cpu_usage: float = 0.0
    active_blocks: int = 0
    threat_level: ThreatLevel = ThreatLevel.CLEAN
    last_update: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

@dataclass
class IPThreatProfile:
    """Threat profile for an IP address."""
    ip: str
    first_seen: datetime
    last_seen: datetime
    total_requests: int = 0
    blocked_requests: int = 0
    violation_count: int = 0
    threat_level: ThreatLevel = ThreatLevel.CLEAN
    block_type: BlockType = BlockType.NONE
    block_expires: Optional[datetime] = None
    user_agent_patterns: List[str] = field(default_factory=list)
    request_patterns: List[str] = field(default_factory=list)
    geographic_info: Dict[str, Any] = field(default_factory=dict)

class EnhancedDDoSProtectionService:
    """
    Enhanced DDoS protection service with intelligent threat detection.

    Features:
    - Dynamic rate limiting based on system load
    - Progressive blocking with escalation levels
    - Behavioral analysis and pattern detection
    - Integration with security service
    - Real-time metrics and monitoring
    - Adaptive thresholds based on traffic patterns
    """

    def __init__(self):
        # Core protection settings
        self.enabled = True
        self.base_rate_limit = 100  # requests per minute per IP
        self.burst_allowance = 20   # additional requests allowed in burst

        # Dynamic thresholds
        self.dynamic_thresholds = {
            "low_load": {"multiplier": 1.5, "threshold": 0.3},      # < 30% load
            "normal_load": {"multiplier": 1.0, "threshold": 0.7},   # 30-70% load
            "high_load": {"multiplier": 0.6, "threshold": 0.9},     # 70-90% load
            "critical_load": {"multiplier": 0.3, "threshold": 1.0}  # > 90% load
        }

        # IP tracking and profiling
        self.ip_profiles: Dict[str, IPThreatProfile] = {}
        self.request_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))

        # Progressive blocking configuration
        self.progressive_blocks = {
            1: 60,      # 1 minute
            3: 300,     # 5 minutes
            5: 900,     # 15 minutes
            10: 3600,   # 1 hour
            20: 86400,  # 24 hours
            50: 604800  # 1 week
        }

        # System metrics
        self.metrics = DDoSMetrics()
        self.metrics_history = deque(maxlen=1440)  # 24 hours of minute-by-minute data

        # Pattern detection
        self.suspicious_patterns = {
            "user_agents": [
                "bot", "crawler", "spider", "scraper", "scanner",
                "curl", "wget", "python-requests", "go-http-client"
            ],
            "request_patterns": [
                r"/\.env", r"/admin", r"/wp-admin", r"/phpmyadmin",
                r"\.php$", r"\.asp$", r"\.jsp$", r"/api/v\d+/.*"
            ]
        }

        # Start background tasks
        self._start_background_tasks()

        logger.info(" Enhanced DDoS Protection Service initialized")

    async def check_request(self, ip: str, user_agent: str = "",
                          endpoint: str = "", method: str = "GET") -> Tuple[bool, str, Dict[str, Any]]:
        """
        Check if request should be allowed through DDoS protection.

        Args:
            ip: Client IP address
            user_agent: User agent string
            endpoint: Request endpoint
            method: HTTP method

        Returns:
            Tuple of (allowed, reason, metadata)
        """
        if not self.enabled:
            return True, "ddos_protection_disabled", {}

        current_time = datetime.now(timezone.utc)

        # Update or create IP profile
        profile = self._update_ip_profile(ip, user_agent, endpoint, current_time)

        # Check if IP is blocked
        if profile.block_type != BlockType.NONE:
            if profile.block_expires and current_time < profile.block_expires:
                return False, f"ip_blocked_{profile.block_type.value}", {
                    "block_type": profile.block_type.value,
                    "block_expires": profile.block_expires.isoformat(),
                    "violation_count": profile.violation_count
                }
            else:
                # Block expired, reset
                profile.block_type = BlockType.NONE
                profile.block_expires = None

        # Get current system load and adjust thresholds
        current_load = self._get_system_load()
        adjusted_limit = self._get_adjusted_rate_limit(current_load)

        # Check rate limiting
        recent_requests = self._count_recent_requests(ip, window_seconds=60)

        if recent_requests > adjusted_limit:
            # Rate limit exceeded
            self._handle_rate_limit_violation(profile, current_time)

            return False, "rate_limit_exceeded", {
                "requests_in_window": recent_requests,
                "limit": adjusted_limit,
                "system_load": current_load,
                "violation_count": profile.violation_count
            }

        # Check for suspicious patterns
        suspicion_score = self._calculate_suspicion_score(profile, user_agent, endpoint)

        # Advanced behavioral analysis
        behavioral_assessment = None
        if BEHAVIORAL_ANALYZER_AVAILABLE:
            try:
                request_data = {
                    'endpoint': endpoint,
                    'method': method,
                    'user_agent': user_agent,
                    'headers': {},  # Would need to be passed from middleware
                    'client_ip': ip
                }
                behavioral_assessment = await advanced_behavioral_analyzer.analyze_request_behavior(
                    ip, 'ip', request_data
                )

                # Integrate behavioral analysis with suspicion score
                if behavioral_assessment.risk_level > 6:
                    suspicion_score = max(suspicion_score, behavioral_assessment.confidence)

            except Exception as e:
                logger.warning(f"Behavioral analysis failed: {e}")

        if suspicion_score > 0.8:  # High suspicion threshold
            self._handle_suspicious_activity(profile, current_time, suspicion_score, behavioral_assessment)

            response_data = {
                "suspicion_score": suspicion_score,
                "threat_level": profile.threat_level.value,
                "patterns_detected": self._get_detected_patterns(user_agent, endpoint)
            }

            # Add behavioral analysis data if available
            if behavioral_assessment:
                response_data.update({
                    "behavioral_threat_type": behavioral_assessment.threat_type.value,
                    "behavioral_confidence": behavioral_assessment.confidence,
                    "behavioral_risk_level": behavioral_assessment.risk_level,
                    "behavioral_patterns": behavioral_assessment.patterns_detected
                })

            return False, "suspicious_activity", response_data

        # Request allowed
        self._record_successful_request(profile, current_time)

        return True, "allowed", {
            "requests_in_window": recent_requests,
            "limit": adjusted_limit,
            "system_load": current_load,
            "threat_level": profile.threat_level.value
        }

    def _update_ip_profile(self, ip: str, user_agent: str, endpoint: str,
                          current_time: datetime) -> IPThreatProfile:
        """Update or create IP threat profile."""
        if ip not in self.ip_profiles:
            self.ip_profiles[ip] = IPThreatProfile(
                ip=ip,
                first_seen=current_time,
                last_seen=current_time
            )

        profile = self.ip_profiles[ip]
        profile.last_seen = current_time
        profile.total_requests += 1

        # Update patterns
        if user_agent and user_agent not in profile.user_agent_patterns:
            profile.user_agent_patterns.append(user_agent)
            # Keep only last 10 user agents
            profile.user_agent_patterns = profile.user_agent_patterns[-10:]

        if endpoint and endpoint not in profile.request_patterns:
            profile.request_patterns.append(endpoint)
            # Keep only last 20 endpoints
            profile.request_patterns = profile.request_patterns[-20:]

        # Record request timestamp
        self.request_history[ip].append(current_time.timestamp())

        return profile

    def _get_system_load(self) -> float:
        """Get current system load average."""
        try:
            # Get CPU usage
            cpu_percent = import psutil
psutil = psutil.cpu_percent(interval=0.1)

            # Get memory usage
            memory = import psutil
psutil = psutil.virtual_memory()
            memory_percent = memory.percent

            # Calculate combined load (weighted average)
            combined_load = (cpu_percent * 0.6 + memory_percent * 0.4) / 100.0

            # Update metrics
            self.metrics.cpu_usage = cpu_percent
            self.metrics.memory_usage = memory_percent
            self.metrics.system_load = combined_load

            return combined_load

        except Exception as e:
            logger.error(f"Error getting system load: {e}")
            return 0.5  # Default to moderate load

    def _get_adjusted_rate_limit(self, system_load: float) -> int:
        """Get rate limit adjusted for current system load."""
        # Determine load category
        if system_load < self.dynamic_thresholds["low_load"]["threshold"]:
            multiplier = self.dynamic_thresholds["low_load"]["multiplier"]
        elif system_load < self.dynamic_thresholds["normal_load"]["threshold"]:
            multiplier = self.dynamic_thresholds["normal_load"]["multiplier"]
        elif system_load < self.dynamic_thresholds["high_load"]["threshold"]:
            multiplier = self.dynamic_thresholds["high_load"]["multiplier"]
        else:
            multiplier = self.dynamic_thresholds["critical_load"]["multiplier"]

        return int(self.base_rate_limit * multiplier)

    def _count_recent_requests(self, ip: str, window_seconds: int = 60) -> int:
        """Count requests from IP in recent time window."""
        if ip not in self.request_history:
            return 0

        current_time = time.time()
        cutoff_time = current_time - window_seconds

        # Count requests after cutoff time
        return sum(1 for timestamp in self.request_history[ip] if timestamp > cutoff_time)

    def _calculate_suspicion_score(self, profile: IPThreatProfile,
                                 user_agent: str, endpoint: str) -> float:
        """Calculate suspicion score for request."""
        score = 0.0

        # Check user agent patterns
        for pattern in self.suspicious_patterns["user_agents"]:
            if pattern.lower() in user_agent.lower():
                score += 0.3

        # Check endpoint patterns
        for pattern in self.suspicious_patterns["request_patterns"]:
            if re.search(pattern, endpoint, re.IGNORECASE):
                score += 0.4

        # Check request frequency
        recent_requests = self._count_recent_requests(profile.ip, 60)
        if recent_requests > self.base_rate_limit * 0.8:
            score += 0.3

        # Check violation history
        if profile.violation_count > 5:
            score += 0.2

        # Check diversity of requests (low diversity = suspicious)
        if len(profile.request_patterns) < 3 and profile.total_requests > 50:
            score += 0.2

        return min(score, 1.0)  # Cap at 1.0

    def _handle_rate_limit_violation(self, profile: IPThreatProfile, current_time: datetime):
        """Handle rate limit violation with progressive blocking."""
        profile.violation_count += 1
        profile.blocked_requests += 1

        # Determine block duration based on violation count
        block_duration = 60  # Default 1 minute
        for threshold, duration in self.progressive_blocks.items():
            if profile.violation_count >= threshold:
                block_duration = duration

        # Apply block
        profile.block_type = BlockType.PROGRESSIVELY_BLOCKED
        profile.block_expires = current_time + timedelta(seconds=block_duration)

        # Update threat level
        if profile.violation_count >= 20:
            profile.threat_level = ThreatLevel.CRITICAL
        elif profile.violation_count >= 10:
            profile.threat_level = ThreatLevel.HIGH
        elif profile.violation_count >= 5:
            profile.threat_level = ThreatLevel.MODERATE
        else:
            profile.threat_level = ThreatLevel.SUSPICIOUS

        logger.warning(f"Progressive block applied to {profile.ip}: "
                      f"violations={profile.violation_count}, "
                      f"duration={block_duration}s, "
                      f"threat_level={profile.threat_level.value}")

    def _handle_suspicious_activity(self, profile: IPThreatProfile,
                                  current_time: datetime, suspicion_score: float,
                                  behavioral_assessment: Optional['BehavioralAssessment'] = None):
        """Handle suspicious activity detection with behavioral analysis integration."""
        profile.violation_count += 1
        profile.blocked_requests += 1

        # Calculate block duration based on suspicion score and behavioral analysis
        base_duration = int(300 * suspicion_score)  # 0-5 minutes based on suspicion

        # Enhance duration based on behavioral assessment
        if behavioral_assessment:
            if behavioral_assessment.threat_type == BehavioralThreatType.COORDINATED_ATTACK:
                base_duration *= 3  # Longer blocks for coordinated attacks
            elif behavioral_assessment.threat_type == BehavioralThreatType.BRUTE_FORCE:
                base_duration *= 2  # Longer blocks for brute force
            elif behavioral_assessment.risk_level > 8:
                base_duration = int(base_duration * 1.5)

        profile.block_type = BlockType.TEMPORARILY_BLOCKED
        profile.block_expires = current_time + timedelta(seconds=base_duration)

        # Update threat level with behavioral input
        final_threat_level = ThreatLevel.MODERATE

        if behavioral_assessment and behavioral_assessment.risk_level > 8:
            final_threat_level = ThreatLevel.CRITICAL
        elif suspicion_score > 0.9 or (behavioral_assessment and behavioral_assessment.risk_level > 6):
            final_threat_level = ThreatLevel.CRITICAL
        elif suspicion_score > 0.7 or (behavioral_assessment and behavioral_assessment.risk_level > 4):
            final_threat_level = ThreatLevel.HIGH
        else:
            final_threat_level = ThreatLevel.MODERATE

        profile.threat_level = final_threat_level

        # Log enhanced threat information
        if behavioral_assessment:
            logger.warning(f"Enhanced threat detection for {profile.ip}: "
                         f"suspicion={suspicion_score:.2f}, "
                         f"behavioral_type={behavioral_assessment.threat_type.value}, "
                         f"risk_level={behavioral_assessment.risk_level}, "
                         f"block_duration={base_duration}s")

        logger.warning(f"Suspicious activity block applied to {profile.ip}: "
                      f"suspicion_score={suspicion_score:.2f}, "
                      f"duration={block_duration}s")

    def _record_successful_request(self, profile: IPThreatProfile, current_time: datetime):
        """Record successful request and potentially reduce threat level."""
        # Gradually reduce violation count for good behavior
        if profile.violation_count > 0 and profile.total_requests % 10 == 0:
            profile.violation_count = max(0, profile.violation_count - 1)

        # Reduce threat level over time with good behavior
        if profile.total_requests % 50 == 0 and profile.violation_count < 3:
            if profile.threat_level.value > 0:
                profile.threat_level = ThreatLevel(profile.threat_level.value - 1)

    def _get_detected_patterns(self, user_agent: str, endpoint: str) -> List[str]:
        """Get list of detected suspicious patterns."""
        patterns = []

        for pattern in self.suspicious_patterns["user_agents"]:
            if pattern.lower() in user_agent.lower():
                patterns.append(f"suspicious_user_agent:{pattern}")

        for pattern in self.suspicious_patterns["request_patterns"]:
            if re.search(pattern, endpoint, re.IGNORECASE):
                patterns.append(f"suspicious_endpoint:{pattern}")

        return patterns

    def _start_background_tasks(self):
        """Start background maintenance tasks."""
        # This would typically be started by the application
        # For now, just log that it should be started
        logger.info("DDoS protection background tasks should be started by application")

    def get_metrics(self) -> DDoSMetrics:
        """Get current DDoS protection metrics."""
        # Update metrics
        self.metrics.unique_ips = len(self.ip_profiles)
        self.metrics.active_blocks = sum(
            1 for profile in self.ip_profiles.values()
            if profile.block_type != BlockType.NONE
        )

        if self.metrics.unique_ips > 0:
            self.metrics.avg_requests_per_ip = (
                sum(profile.total_requests for profile in self.ip_profiles.values()) /
                self.metrics.unique_ips
            )

        # Determine overall threat level
        threat_counts = defaultdict(int)
        for profile in self.ip_profiles.values():
            threat_counts[profile.threat_level] += 1

        if threat_counts[ThreatLevel.CRITICAL] > 5:
            self.metrics.threat_level = ThreatLevel.CRITICAL
        elif threat_counts[ThreatLevel.HIGH] > 10:
            self.metrics.threat_level = ThreatLevel.HIGH
        elif threat_counts[ThreatLevel.MODERATE] > 20:
            self.metrics.threat_level = ThreatLevel.MODERATE
        elif threat_counts[ThreatLevel.SUSPICIOUS] > 50:
            self.metrics.threat_level = ThreatLevel.SUSPICIOUS
        else:
            self.metrics.threat_level = ThreatLevel.CLEAN

        self.metrics.last_update = datetime.now(timezone.utc)
        return self.metrics

# Global enhanced DDoS protection service
enhanced_ddos_service = EnhancedDDoSProtectionService()
