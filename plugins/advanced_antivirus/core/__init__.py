from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


"""
PlexiChat Antivirus Core Components

Core antivirus scanning and detection engines.
"""


class ThreatLevel(Enum):
    """Threat severity levels."""

    CLEAN = 0
    SUSPICIOUS = 1
    LOW_RISK = 2
    MEDIUM_RISK = 3
    HIGH_RISK = 4
    CRITICAL = 5

    def __lt__(self, other):
        if self.__class__ is other.__class__:
            return self.value < other.value
        return NotImplemented

    def __le__(self, other):
        if self.__class__ is other.__class__:
            return self.value <= other.value
        return NotImplemented

    def __gt__(self, other):
        if self.__class__ is other.__class__:
            return self.value > other.value
        return NotImplemented

    def __ge__(self, other):
        if self.__class__ is other.__class__:
            return self.value >= other.value
        return NotImplemented


class ScanType(Enum):
    """Types of scans performed."""

    QUICK_SCAN = "quick"
    FULL_SCAN = "full"
    HASH_SCAN = "hash"
    BEHAVIORAL_SCAN = "behavioral"
    LINK_SCAN = "link"
    FILENAME_SCAN = "filename"


class ThreatType(Enum):
    """Types of threats detected."""

    CLEAN = "clean"
    VIRUS = "virus"
    MALWARE = "malware"
    TROJAN = "trojan"
    RANSOMWARE = "ransomware"
    SPYWARE = "spyware"
    ADWARE = "adware"
    SUSPICIOUS_BEHAVIOR = "suspicious_behavior"
    PHISHING = "phishing"
    PHISHING_LINK = "phishing_link"
    MALICIOUS_FILENAME = "malicious_filename"
    UNKNOWN_THREAT = "unknown_threat"


@dataclass
class ScanResult:
    """Result of an antivirus scan."""

    file_path: str
    file_hash: str
    threat_level: ThreatLevel
    threat_type: Optional[ThreatType]
    threat_name: Optional[str]
    scan_type: ScanType
    scan_duration: float
    detected_at: datetime
    confidence_score: float
    details: Dict[str, Any]
    quarantined: bool = False
    cleaned: bool = False


@dataclass
class ThreatSignature:
    """Threat signature for detection."""

    signature_id: str
    signature_type: str  # 'hash', 'url', 'file', 'pattern'
    threat_name: str
    threat_type: ThreatType
    threat_level: ThreatLevel
    hash_md5: Optional[str] = None
    hash_sha256: Optional[str] = None
    hash_sha512: Optional[str] = None
    pattern: Optional[str] = None
    url_pattern: Optional[str] = None
    file_pattern: Optional[str] = None
    confidence_score: float = 0.5
    source: str = "unknown"
    description: str = ""
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


# Antivirus configuration constants
MAX_FILE_SIZE_SCAN = 100 * 1024 * 1024  # 100MB
MAX_FILENAME_LENGTH = 255
SUSPICIOUS_EXTENSIONS = [
    ".exe",
    ".bat",
    ".cmd",
    ".com",
    ".pif",
    ".scr",
    ".vbs",
    ".js",
    ".jar",
    ".app",
    ".deb",
    ".rpm",
    ".dmg",
    ".pkg",
    ".msi",
]

SUSPICIOUS_FILENAME_PATTERNS = [
    r".*\.(exe|bat|cmd|com|pif|scr|vbs|js)$",
    r".*virus.*",
    r".*malware.*",
    r".*trojan.*",
    r".*keylog.*",
    r".*crack.*",
    r".*hack.*",
    r".*exploit.*",
]

# Hash database update intervals
HASH_DB_UPDATE_INTERVAL = 3600  # 1 hour
THREAT_INTEL_UPDATE_INTERVAL = 1800  # 30 minutes


@dataclass
class ScanRequest:
    """Request for file scanning."""

    request_id: str
    file_path: str
    scan_types: List[ScanType]
    priority: int
    requester: str
    created_at: datetime
    status: str = "pending"


@dataclass
class QuarantineEntry:
    """Entry for quarantined files."""

    entry_id: str
    original_path: str
    quarantine_path: str
    threat_name: str
    threat_type: ThreatType
    threat_level: ThreatLevel
    scan_results: List[ScanResult]
    quarantined_at: datetime
    can_restore: bool = True
