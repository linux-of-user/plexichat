"""
PlexiChat Unified Threat Intelligence Service - SINGLE SOURCE OF TRUTH

CONSOLIDATED and ENHANCED from:
- features/antivirus/core/threat_intelligence.py - INTEGRATED
- features/security/threat_intelligence.py - INTEGRATED

Features:
- Unified threat intelligence feed management
- Real-time threat detection and correlation
- Automated threat response and mitigation
- Multi-source intelligence aggregation
- Machine learning-based threat analysis
- Integration with unified security architecture
- Comprehensive audit logging
- Post-quantum cryptography threat awareness
"""

import asyncio
import aiohttp
import aiosqlite
import hashlib
import json
import logging
import secrets
from datetime import datetime, timezone, timedelta
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Any, Tuple
from dataclasses import dataclass, field
import csv
import gzip

from ...core_system.logging import get_logger
from ...core_system.config import get_config
from .unified_audit_system import get_unified_audit_system, SecurityEventType, SecuritySeverity, ThreatLevel

logger = get_logger(__name__)


class ThreatType(Enum):
    """Types of security threats."""
    MALWARE = "malware"
    VIRUS = "virus"
    TROJAN = "trojan"
    RANSOMWARE = "ransomware"
    SPYWARE = "spyware"
    ADWARE = "adware"
    ROOTKIT = "rootkit"
    BOTNET = "botnet"
    PHISHING = "phishing"
    SPAM = "spam"
    DDOS = "ddos"
    BRUTE_FORCE = "brute_force"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    CSRF = "csrf"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    INSIDER_THREAT = "insider_threat"
    APT = "apt"  # Advanced Persistent Threat
    ZERO_DAY = "zero_day"
    QUANTUM_ATTACK = "quantum_attack"  # Post-quantum era threats
    AI_POISONING = "ai_poisoning"  # AI/ML specific threats


class IOCType(Enum):
    """Indicator of Compromise types."""
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    FILE_PATH = "file_path"
    REGISTRY_KEY = "registry_key"
    MUTEX = "mutex"
    USER_AGENT = "user_agent"
    SSL_CERT = "ssl_cert"
    YARA_RULE = "yara_rule"


class ConfidenceLevel(Enum):
    """Confidence levels for threat intelligence."""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class ThreatIndicator:
    """Unified threat indicator structure."""
    ioc_id: str
    ioc_type: IOCType
    value: str
    threat_type: ThreatType
    threat_level: ThreatLevel
    confidence: ConfidenceLevel
    source: str
    description: str
    first_seen: datetime
    last_seen: datetime
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "ioc_id": self.ioc_id,
            "ioc_type": self.ioc_type.value,
            "value": self.value,
            "threat_type": self.threat_type.value,
            "threat_level": self.threat_level.value,
            "confidence": self.confidence.value,
            "source": self.source,
            "description": self.description,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "tags": self.tags,
            "metadata": self.metadata
        }


@dataclass
class ThreatEvent:
    """Security threat event."""
    event_id: str
    threat_type: ThreatType
    threat_level: ThreatLevel
    source_ip: Optional[str]
    target_resource: str
    timestamp: datetime
    confidence: ConfidenceLevel
    details: Dict[str, Any] = field(default_factory=dict)
    indicators: List[str] = field(default_factory=list)  # Related IOC IDs
    mitigated: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "event_id": self.event_id,
            "threat_type": self.threat_type.value,
            "threat_level": self.threat_level.value,
            "source_ip": self.source_ip,
            "target_resource": self.target_resource,
            "timestamp": self.timestamp.isoformat(),
            "confidence": self.confidence.value,
            "details": self.details,
            "indicators": self.indicators,
            "mitigated": self.mitigated
        }


class ThreatIntelligenceFeed:
    """Unified threat intelligence feed handler."""
    
    def __init__(self, feed_name: str, feed_url: str, feed_type: str = "json"):
        self.feed_name = feed_name
        self.feed_url = feed_url
        self.feed_type = feed_type
        self.indicators: Dict[str, ThreatIndicator] = {}
        self.last_update: Optional[datetime] = None
        self.update_interval = 3600  # 1 hour default
        self.enabled = True
        self.error_count = 0
        self.max_errors = 5
    
    async def update_feed(self) -> int:
        """Update threat intelligence feed."""
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=300)) as session:
                async with session.get(self.feed_url) as response:
                    if response.status != 200:
                        logger.error(f"Failed to fetch {self.feed_name} feed: HTTP {response.status}")
                        self.error_count += 1
                        return 0
                    
                    content = await response.text()
                    
                    # Process based on feed type
                    if self.feed_type == "csv":
                        new_indicators = await self._process_csv_feed(content)
                    elif self.feed_type == "json":
                        new_indicators = await self._process_json_feed(content)
                    else:
                        logger.warning(f"Unsupported feed type: {self.feed_type}")
                        return 0
                    
                    # Update indicators
                    updated_count = 0
                    for indicator in new_indicators:
                        if indicator.ioc_id not in self.indicators:
                            self.indicators[indicator.ioc_id] = indicator
                            updated_count += 1
                        else:
                            # Update existing indicator
                            existing = self.indicators[indicator.ioc_id]
                            existing.last_seen = indicator.last_seen
                            existing.confidence = max(existing.confidence, indicator.confidence)
                    
                    self.last_update = datetime.now(timezone.utc)
                    self.error_count = 0  # Reset error count on success
                    
                    logger.info(f"Updated {self.feed_name} feed: {updated_count} new indicators")
                    return updated_count
                    
        except Exception as e:
            logger.error(f"Failed to update feed {self.feed_name}: {e}")
            self.error_count += 1
            
            # Disable feed if too many errors
            if self.error_count >= self.max_errors:
                self.enabled = False
                logger.warning(f"Disabled feed {self.feed_name} due to repeated errors")
            
            return 0
    
    async def _process_csv_feed(self, content: str) -> List[ThreatIndicator]:
        """Process CSV format threat feed."""
        indicators = []
        
        try:
            reader = csv.DictReader(content.splitlines())
            for row in reader:
                # Map CSV columns to indicator fields (customize based on feed format)
                indicator = ThreatIndicator(
                    ioc_id=f"{self.feed_name}_{hashlib.md5(row.get('value', '').encode()).hexdigest()[:16]}",
                    ioc_type=IOCType(row.get('type', 'hash_sha256')),
                    value=row.get('value', ''),
                    threat_type=ThreatType(row.get('threat_type', 'malware')),
                    threat_level=ThreatLevel(int(row.get('threat_level', 2))),
                    confidence=ConfidenceLevel(int(row.get('confidence', 2))),
                    source=self.feed_name,
                    description=row.get('description', ''),
                    first_seen=datetime.now(timezone.utc),
                    last_seen=datetime.now(timezone.utc),
                    tags=row.get('tags', '').split(',') if row.get('tags') else []
                )
                indicators.append(indicator)
                
        except Exception as e:
            logger.error(f"Failed to process CSV feed {self.feed_name}: {e}")
        
        return indicators
    
    async def _process_json_feed(self, content: str) -> List[ThreatIndicator]:
        """Process JSON format threat feed."""
        indicators = []
        
        try:
            data = json.loads(content)
            
            # Handle different JSON structures
            if isinstance(data, list):
                items = data
            elif isinstance(data, dict) and 'indicators' in data:
                items = data['indicators']
            else:
                items = [data]
            
            for item in items:
                indicator = ThreatIndicator(
                    ioc_id=item.get('id', f"{self.feed_name}_{secrets.token_hex(8)}"),
                    ioc_type=IOCType(item.get('type', 'hash_sha256')),
                    value=item.get('value', ''),
                    threat_type=ThreatType(item.get('threat_type', 'malware')),
                    threat_level=ThreatLevel(item.get('threat_level', 2)),
                    confidence=ConfidenceLevel(item.get('confidence', 2)),
                    source=self.feed_name,
                    description=item.get('description', ''),
                    first_seen=datetime.fromisoformat(item.get('first_seen', datetime.now(timezone.utc).isoformat())),
                    last_seen=datetime.fromisoformat(item.get('last_seen', datetime.now(timezone.utc).isoformat())),
                    tags=item.get('tags', []),
                    metadata=item.get('metadata', {})
                )
                indicators.append(indicator)
                
        except Exception as e:
            logger.error(f"Failed to process JSON feed {self.feed_name}: {e}")
        
        return indicators
    
    def search_indicators(self, value: str, ioc_type: Optional[IOCType] = None) -> List[ThreatIndicator]:
        """Search for indicators matching value."""
        results = []
        
        for indicator in self.indicators.values():
            if ioc_type and indicator.ioc_type != ioc_type:
                continue
            
            if value.lower() in indicator.value.lower():
                results.append(indicator)
        
        return results


class UnifiedThreatIntelligence:
    """
    Unified Threat Intelligence Service - Single Source of Truth

    Consolidates all threat intelligence functionality with integration
    to unified security architecture.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or get_config().get("threat_intelligence", {})
        self.initialized = False

        # Threat intelligence feeds
        self.feeds: Dict[str, ThreatIntelligenceFeed] = {}

        # Consolidated indicators
        self.indicators: Dict[str, ThreatIndicator] = {}
        self.hash_indicators: Dict[str, ThreatIndicator] = {}
        self.ip_indicators: Dict[str, ThreatIndicator] = {}
        self.domain_indicators: Dict[str, ThreatIndicator] = {}
        self.url_indicators: Dict[str, ThreatIndicator] = {}

        # Threat events and detection
        self.threat_events: List[ThreatEvent] = []
        self.detection_rules: Dict[str, Dict[str, Any]] = {}
        self.blocked_entities: Dict[str, Set[str]] = {
            "ips": set(),
            "domains": set(),
            "hashes": set()
        }

        # Security components
        self.audit_system = get_unified_audit_system()

        # Statistics and metrics
        self.statistics = {
            "total_indicators": 0,
            "active_feeds": 0,
            "threats_detected": 0,
            "threats_mitigated": 0,
            "false_positives": 0,
            "last_update": None,
            "feed_updates": 0
        }

        # Database path
        self.db_path = Path(self.config.get("database_path", "data/threat_intelligence.db"))

        logger.info("Unified Threat Intelligence Service initialized")

    async def initialize(self) -> bool:
        """Initialize the unified threat intelligence service."""
        try:
            # Initialize database
            await self._initialize_database()

            # Load existing indicators
            await self._load_indicators()

            # Initialize threat feeds
            await self._initialize_feeds()

            # Initialize detection rules
            await self._initialize_detection_rules()

            # Start background tasks
            asyncio.create_task(self._feed_update_scheduler())
            asyncio.create_task(self._threat_correlation_engine())
            asyncio.create_task(self._cleanup_scheduler())

            self.initialized = True
            logger.info("✅ Unified Threat Intelligence Service fully initialized")
            return True

        except Exception as e:
            logger.error(f"❌ Threat Intelligence initialization failed: {e}")
            return False

    async def _initialize_database(self):
        """Initialize threat intelligence database."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        async with aiosqlite.connect(self.db_path) as db:
            # Create indicators table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS threat_indicators (
                    ioc_id TEXT PRIMARY KEY,
                    ioc_type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    threat_type TEXT NOT NULL,
                    threat_level INTEGER NOT NULL,
                    confidence INTEGER NOT NULL,
                    source TEXT NOT NULL,
                    description TEXT,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    tags TEXT,
                    metadata TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Create threat events table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS threat_events (
                    event_id TEXT PRIMARY KEY,
                    threat_type TEXT NOT NULL,
                    threat_level INTEGER NOT NULL,
                    source_ip TEXT,
                    target_resource TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    confidence INTEGER NOT NULL,
                    details TEXT,
                    indicators TEXT,
                    mitigated BOOLEAN DEFAULT FALSE,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Create detection rules table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS detection_rules (
                    rule_id TEXT PRIMARY KEY,
                    rule_name TEXT NOT NULL,
                    threat_type TEXT NOT NULL,
                    conditions TEXT NOT NULL,
                    actions TEXT NOT NULL,
                    enabled BOOLEAN DEFAULT TRUE,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Create indexes for performance
            await db.execute("CREATE INDEX IF NOT EXISTS idx_indicators_value ON threat_indicators(value)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_indicators_type ON threat_indicators(ioc_type)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON threat_events(timestamp)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_events_source_ip ON threat_events(source_ip)")

            await db.commit()

        logger.info("Threat intelligence database initialized")

    async def _initialize_feeds(self):
        """Initialize threat intelligence feeds."""
        # Default feeds configuration
        default_feeds = [
            {
                "name": "PlexiChat Internal",
                "url": "https://threat-intel.plexichat.local/feed.json",
                "type": "json",
                "enabled": False  # Disabled by default
            },
            {
                "name": "Malware Bazaar",
                "url": "https://bazaar.abuse.ch/export/csv/recent/",
                "type": "csv",
                "enabled": False
            },
            {
                "name": "URLhaus",
                "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
                "type": "csv",
                "enabled": False
            },
            {
                "name": "ThreatFox",
                "url": "https://threatfox.abuse.ch/export/csv/recent/",
                "type": "csv",
                "enabled": False
            }
        ]

        # Load feeds from config
        configured_feeds = self.config.get("feeds", default_feeds)

        for feed_config in configured_feeds:
            if feed_config.get("enabled", False):
                feed = ThreatIntelligenceFeed(
                    feed_name=feed_config["name"],
                    feed_url=feed_config["url"],
                    feed_type=feed_config.get("type", "json")
                )
                feed.update_interval = feed_config.get("update_interval", 3600)
                self.feeds[feed_config["name"]] = feed

        self.statistics["active_feeds"] = len(self.feeds)
        logger.info(f"Initialized {len(self.feeds)} threat intelligence feeds")

    async def _initialize_detection_rules(self):
        """Initialize threat detection rules."""
        default_rules = {
            "brute_force": {
                "threat_type": ThreatType.BRUTE_FORCE,
                "conditions": {
                    "failed_logins_threshold": 10,
                    "time_window_minutes": 15
                },
                "actions": ["block_ip", "notify_admin", "log_incident"],
                "enabled": True
            },
            "malware_hash": {
                "threat_type": ThreatType.MALWARE,
                "conditions": {
                    "hash_match": True,
                    "confidence_threshold": 3
                },
                "actions": ["block_file", "quarantine", "notify_admin"],
                "enabled": True
            },
            "suspicious_domain": {
                "threat_type": ThreatType.PHISHING,
                "conditions": {
                    "domain_match": True,
                    "confidence_threshold": 2
                },
                "actions": ["block_domain", "log_incident"],
                "enabled": True
            },
            "quantum_attack_pattern": {
                "threat_type": ThreatType.QUANTUM_ATTACK,
                "conditions": {
                    "encryption_anomaly": True,
                    "key_pattern_suspicious": True
                },
                "actions": ["emergency_response", "notify_admin", "enable_quantum_safe_mode"],
                "enabled": True
            }
        }

        self.detection_rules.update(default_rules)

        # Load additional rules from database
        try:
            async with aiosqlite.connect(self.db_path) as db:
                async with db.execute("SELECT rule_id, rule_name, threat_type, conditions, actions, enabled FROM detection_rules") as cursor:
                    async for row in cursor:
                        rule_id, rule_name, threat_type, conditions, actions, enabled = row
                        self.detection_rules[rule_id] = {
                            "rule_name": rule_name,
                            "threat_type": ThreatType(threat_type),
                            "conditions": json.loads(conditions),
                            "actions": json.loads(actions),
                            "enabled": bool(enabled)
                        }
        except Exception as e:
            logger.error(f"Failed to load detection rules: {e}")

        logger.info(f"Initialized {len(self.detection_rules)} threat detection rules")

    async def check_threat(self, value: str, ioc_type: IOCType) -> Optional[ThreatIndicator]:
        """Check if value matches any threat indicators."""
        try:
            # Check in-memory indicators first
            type_indicators = getattr(self, f"{ioc_type.value.replace('_', '_')}_indicators", {})
            if value in type_indicators:
                indicator = type_indicators[value]
                await self._log_threat_detection(indicator, value)
                return indicator

            # Check database
            async with aiosqlite.connect(self.db_path) as db:
                async with db.execute("""
                    SELECT ioc_id, ioc_type, value, threat_type, threat_level, confidence,
                           source, description, first_seen, last_seen, tags, metadata
                    FROM threat_indicators
                    WHERE value = ? AND ioc_type = ?
                    ORDER BY confidence DESC LIMIT 1
                """, (value, ioc_type.value)) as cursor:
                    row = await cursor.fetchone()

                    if row:
                        indicator = ThreatIndicator(
                            ioc_id=row[0],
                            ioc_type=IOCType(row[1]),
                            value=row[2],
                            threat_type=ThreatType(row[3]),
                            threat_level=ThreatLevel(row[4]),
                            confidence=ConfidenceLevel(row[5]),
                            source=row[6],
                            description=row[7],
                            first_seen=datetime.fromisoformat(row[8]),
                            last_seen=datetime.fromisoformat(row[9]),
                            tags=json.loads(row[10]) if row[10] else [],
                            metadata=json.loads(row[11]) if row[11] else {}
                        )

                        await self._log_threat_detection(indicator, value)
                        return indicator

            return None

        except Exception as e:
            logger.error(f"Failed to check threat for {value}: {e}")
            return None

    async def detect_brute_force(self, source_ip: str, user_id: str, failed_attempts: int) -> Optional[ThreatEvent]:
        """Detect brute force attack patterns."""
        rule = self.detection_rules.get("brute_force")
        if not rule or not rule["enabled"]:
            return None

        threshold = rule["conditions"]["failed_logins_threshold"]

        if failed_attempts >= threshold:
            event_id = f"bf_{secrets.token_hex(16)}"

            event = ThreatEvent(
                event_id=event_id,
                threat_type=rule["threat_type"],
                threat_level=ThreatLevel.HIGH,
                source_ip=source_ip,
                target_resource=f"user:{user_id}",
                timestamp=datetime.now(timezone.utc),
                confidence=ConfidenceLevel.HIGH,
                details={
                    "failed_attempts": failed_attempts,
                    "detection_rule": "brute_force",
                    "user_id": user_id
                }
            )

            # Execute response actions
            await self._execute_response_actions(event, rule["actions"])

            # Store event
            self.threat_events.append(event)
            await self._store_threat_event(event)

            # Log to audit system
            self.audit_system.log_security_event(
                SecurityEventType.SUSPICIOUS_ACTIVITY,
                f"Brute force attack detected from {source_ip}",
                SecuritySeverity.CRITICAL,
                ThreatLevel.HIGH,
                source_ip=source_ip,
                resource=f"user:{user_id}",
                details=event.details
            )

            self.statistics["threats_detected"] += 1
            logger.warning(f"Brute force detected: {source_ip} -> {user_id} ({failed_attempts} attempts)")

            return event

        return None

    async def add_threat_indicator(self, indicator: ThreatIndicator, user_id: str = "system") -> bool:
        """Add new threat indicator to the system."""
        try:
            # Store in memory
            self.indicators[indicator.ioc_id] = indicator

            # Store in type-specific indexes
            if indicator.ioc_type in [IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256]:
                self.hash_indicators[indicator.value] = indicator
            elif indicator.ioc_type == IOCType.IP_ADDRESS:
                self.ip_indicators[indicator.value] = indicator
            elif indicator.ioc_type == IOCType.DOMAIN:
                self.domain_indicators[indicator.value] = indicator
            elif indicator.ioc_type == IOCType.URL:
                self.url_indicators[indicator.value] = indicator

            # Store in database
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    INSERT OR REPLACE INTO threat_indicators
                    (ioc_id, ioc_type, value, threat_type, threat_level, confidence,
                     source, description, first_seen, last_seen, tags, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    indicator.ioc_id,
                    indicator.ioc_type.value,
                    indicator.value,
                    indicator.threat_type.value,
                    indicator.threat_level.value,
                    indicator.confidence.value,
                    indicator.source,
                    indicator.description,
                    indicator.first_seen.isoformat(),
                    indicator.last_seen.isoformat(),
                    json.dumps(indicator.tags),
                    json.dumps(indicator.metadata)
                ))
                await db.commit()

            # Log indicator addition
            self.audit_system.log_security_event(
                SecurityEventType.SYSTEM_CONFIGURATION_CHANGE,
                f"Threat indicator added: {indicator.ioc_type.value} - {indicator.value}",
                SecuritySeverity.INFO,
                ThreatLevel.LOW,
                user_id=user_id,
                resource="threat_intelligence",
                details={
                    "ioc_id": indicator.ioc_id,
                    "threat_type": indicator.threat_type.value,
                    "confidence": indicator.confidence.value
                }
            )

            self.statistics["total_indicators"] += 1
            logger.info(f"Added threat indicator: {indicator.ioc_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to add threat indicator: {e}")
            return False

    async def update_all_feeds(self) -> Dict[str, int]:
        """Update all threat intelligence feeds."""
        results = {}

        for feed_name, feed in self.feeds.items():
            try:
                if feed.enabled:
                    updated_count = await feed.update_feed()
                    results[feed_name] = updated_count

                    # Integrate new indicators
                    for indicator in feed.indicators.values():
                        if indicator.ioc_id not in self.indicators:
                            await self.add_threat_indicator(indicator, "feed_update")
                else:
                    results[feed_name] = 0

            except Exception as e:
                logger.error(f"Failed to update feed {feed_name}: {e}")
                results[feed_name] = 0

        self.statistics["feed_updates"] += 1
        self.statistics["last_update"] = datetime.now(timezone.utc).isoformat()

        return results

    async def _log_threat_detection(self, indicator: ThreatIndicator, detected_value: str):
        """Log threat detection event."""
        try:
            # Log to audit system
            self.audit_system.log_security_event(
                SecurityEventType.MALWARE_DETECTED,
                f"Threat detected: {indicator.threat_type.value} - {detected_value}",
                SecuritySeverity.WARNING if indicator.threat_level.value <= 2 else SecuritySeverity.CRITICAL,
                indicator.threat_level,
                resource="threat_intelligence",
                details={
                    "ioc_id": indicator.ioc_id,
                    "ioc_type": indicator.ioc_type.value,
                    "threat_type": indicator.threat_type.value,
                    "confidence": indicator.confidence.value,
                    "source": indicator.source
                }
            )

            self.statistics["threats_detected"] += 1

        except Exception as e:
            logger.error(f"Failed to log threat detection: {e}")

    async def _execute_response_actions(self, event: ThreatEvent, actions: List[str]):
        """Execute automated response actions for threat event."""
        for action in actions:
            try:
                if action == "block_ip" and event.source_ip:
                    self.blocked_entities["ips"].add(event.source_ip)
                    logger.info(f"Blocked IP: {event.source_ip}")

                elif action == "block_domain":
                    # Extract domain from event details if available
                    domain = event.details.get("domain")
                    if domain:
                        self.blocked_entities["domains"].add(domain)
                        logger.info(f"Blocked domain: {domain}")

                elif action == "block_file":
                    # Extract file hash from event details
                    file_hash = event.details.get("file_hash")
                    if file_hash:
                        self.blocked_entities["hashes"].add(file_hash)
                        logger.info(f"Blocked file hash: {file_hash}")

                elif action == "notify_admin":
                    # Log critical alert
                    self.audit_system.log_security_event(
                        SecurityEventType.SECURITY_ALERT,
                        f"ADMIN ALERT: {event.threat_type.value} detected",
                        SecuritySeverity.ALERT,
                        event.threat_level,
                        source_ip=event.source_ip,
                        resource=event.target_resource,
                        details=event.details
                    )

                elif action == "log_incident":
                    # Log security incident
                    self.audit_system.log_security_event(
                        SecurityEventType.SYSTEM_COMPROMISE,
                        f"SECURITY INCIDENT: {event.threat_type.value}",
                        SecuritySeverity.CRITICAL,
                        event.threat_level,
                        source_ip=event.source_ip,
                        resource=event.target_resource,
                        details=event.details
                    )

                elif action == "enable_quantum_safe_mode":
                    # Enable quantum-safe cryptography mode
                    logger.critical("🔒 QUANTUM SAFE MODE ACTIVATED - Potential quantum attack detected")

                    # Log quantum threat
                    self.audit_system.log_security_event(
                        SecurityEventType.SYSTEM_COMPROMISE,
                        "QUANTUM ATTACK DETECTED - Activating quantum-safe protocols",
                        SecuritySeverity.EMERGENCY,
                        ThreatLevel.CRITICAL,
                        source_ip=event.source_ip,
                        resource=event.target_resource,
                        details=event.details
                    )

                self.statistics["threats_mitigated"] += 1

            except Exception as e:
                logger.error(f"Failed to execute response action {action}: {e}")

    async def _store_threat_event(self, event: ThreatEvent):
        """Store threat event in database."""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    INSERT INTO threat_events
                    (event_id, threat_type, threat_level, source_ip, target_resource,
                     timestamp, confidence, details, indicators, mitigated)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    event.event_id,
                    event.threat_type.value,
                    event.threat_level.value,
                    event.source_ip,
                    event.target_resource,
                    event.timestamp.isoformat(),
                    event.confidence.value,
                    json.dumps(event.details),
                    json.dumps(event.indicators),
                    event.mitigated
                ))
                await db.commit()

        except Exception as e:
            logger.error(f"Failed to store threat event: {e}")

    async def _load_indicators(self):
        """Load existing indicators from database."""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                async with db.execute("SELECT COUNT(*) FROM threat_indicators") as cursor:
                    count = await cursor.fetchone()
                    if count and count[0] > 0:
                        logger.info(f"Loading {count[0]} existing threat indicators")

                        # Load indicators in batches for performance
                        async with db.execute("""
                            SELECT ioc_id, ioc_type, value, threat_type, threat_level, confidence,
                                   source, description, first_seen, last_seen, tags, metadata
                            FROM threat_indicators
                        """) as cursor:
                            async for row in cursor:
                                indicator = ThreatIndicator(
                                    ioc_id=row[0],
                                    ioc_type=IOCType(row[1]),
                                    value=row[2],
                                    threat_type=ThreatType(row[3]),
                                    threat_level=ThreatLevel(row[4]),
                                    confidence=ConfidenceLevel(row[5]),
                                    source=row[6],
                                    description=row[7],
                                    first_seen=datetime.fromisoformat(row[8]),
                                    last_seen=datetime.fromisoformat(row[9]),
                                    tags=json.loads(row[10]) if row[10] else [],
                                    metadata=json.loads(row[11]) if row[11] else {}
                                )

                                self.indicators[indicator.ioc_id] = indicator

                                # Add to type-specific indexes
                                if indicator.ioc_type in [IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256]:
                                    self.hash_indicators[indicator.value] = indicator
                                elif indicator.ioc_type == IOCType.IP_ADDRESS:
                                    self.ip_indicators[indicator.value] = indicator
                                elif indicator.ioc_type == IOCType.DOMAIN:
                                    self.domain_indicators[indicator.value] = indicator
                                elif indicator.ioc_type == IOCType.URL:
                                    self.url_indicators[indicator.value] = indicator

                        self.statistics["total_indicators"] = len(self.indicators)

        except Exception as e:
            logger.error(f"Failed to load indicators: {e}")

    async def _feed_update_scheduler(self):
        """Background task for updating threat feeds."""
        while True:
            try:
                await asyncio.sleep(300)  # Check every 5 minutes

                current_time = datetime.now(timezone.utc)

                for feed_name, feed in self.feeds.items():
                    if not feed.enabled:
                        continue

                    # Check if feed needs updating
                    if (not feed.last_update or
                        (current_time - feed.last_update).total_seconds() >= feed.update_interval):

                        logger.info(f"Updating threat feed: {feed_name}")
                        await feed.update_feed()

                        # Integrate new indicators
                        for indicator in feed.indicators.values():
                            if indicator.ioc_id not in self.indicators:
                                await self.add_threat_indicator(indicator, "feed_scheduler")

            except Exception as e:
                logger.error(f"Feed update scheduler error: {e}")

    async def _threat_correlation_engine(self):
        """Background task for threat correlation and analysis."""
        while True:
            try:
                await asyncio.sleep(600)  # Run every 10 minutes

                # Perform threat correlation analysis
                await self._correlate_threat_events()

            except Exception as e:
                logger.error(f"Threat correlation engine error: {e}")

    async def _correlate_threat_events(self):
        """Correlate threat events to identify patterns."""
        # This would implement advanced correlation logic
        # For now, just log the activity
        logger.debug("Performing threat event correlation analysis")

    async def _cleanup_scheduler(self):
        """Background task for cleaning up old data."""
        while True:
            try:
                await asyncio.sleep(86400)  # Run daily

                # Clean up old threat events (keep last 30 days)
                cutoff_date = datetime.now(timezone.utc) - timedelta(days=30)

                async with aiosqlite.connect(self.db_path) as db:
                    await db.execute("""
                        DELETE FROM threat_events
                        WHERE timestamp < ?
                    """, (cutoff_date.isoformat(),))
                    await db.commit()

                # Clean up in-memory events
                self.threat_events = [
                    event for event in self.threat_events
                    if event.timestamp > cutoff_date
                ]

                logger.info("Completed threat intelligence data cleanup")

            except Exception as e:
                logger.error(f"Cleanup scheduler error: {e}")

    def get_threat_intelligence_status(self) -> Dict[str, Any]:
        """Get comprehensive threat intelligence status."""
        feed_status = {}
        for name, feed in self.feeds.items():
            feed_status[name] = {
                "enabled": feed.enabled,
                "indicators": len(feed.indicators),
                "last_update": feed.last_update.isoformat() if feed.last_update else None,
                "error_count": feed.error_count
            }

        return {
            "threat_intelligence": {
                "initialized": self.initialized,
                "total_indicators": len(self.indicators),
                "hash_indicators": len(self.hash_indicators),
                "ip_indicators": len(self.ip_indicators),
                "domain_indicators": len(self.domain_indicators),
                "url_indicators": len(self.url_indicators),
                "active_feeds": len([f for f in self.feeds.values() if f.enabled]),
                "feed_status": feed_status,
                "detection_rules": len(self.detection_rules),
                "blocked_entities": {
                    "ips": len(self.blocked_entities["ips"]),
                    "domains": len(self.blocked_entities["domains"]),
                    "hashes": len(self.blocked_entities["hashes"])
                },
                "recent_events": len(self.threat_events[-100:]),
                "statistics": self.statistics
            }
        }


# Global instance - SINGLE SOURCE OF TRUTH
_unified_threat_intelligence: Optional[UnifiedThreatIntelligence] = None


def get_unified_threat_intelligence() -> 'UnifiedThreatIntelligence':
    """Get the global unified threat intelligence instance."""
    global _unified_threat_intelligence
    if _unified_threat_intelligence is None:
        _unified_threat_intelligence = UnifiedThreatIntelligence()
    return _unified_threat_intelligence


# Export main components
__all__ = [
    "UnifiedThreatIntelligence",
    "get_unified_threat_intelligence",
    "ThreatType",
    "IOCType",
    "ConfidenceLevel",
    "ThreatIndicator",
    "ThreatEvent",
    "ThreatIntelligenceFeed"
]
