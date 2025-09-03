"""
Message Antivirus Scanner for PlexiChat
Scans message content for malicious patterns and threats.
"""

import asyncio
import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import (
    ScanResult,
    ScanType,
    ThreatLevel,
    ThreatType,
    SUSPICIOUS_FILENAME_PATTERNS,
)


class MessageAntivirusScanner:
    """
    Scanner for message content to detect malicious patterns, links, and threats.
    """

    def __init__(self, data_path: Path):
        self.data_path = data_path
        self.threat_patterns = self._load_threat_patterns()

    def _load_threat_patterns(self) -> List[Dict[str, Any]]:
        """Load threat detection patterns."""
        return [
            {
                "name": "SQL Injection Pattern",
                "pattern": r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)",
                "threat_type": ThreatType.MALWARE,
                "threat_level": ThreatLevel.HIGH_RISK,
                "description": "Potential SQL injection attempt"
            },
            {
                "name": "XSS Pattern",
                "pattern": r"<script[^>]*>.*?</script>",
                "threat_type": ThreatType.MALWARE,
                "threat_level": ThreatLevel.HIGH_RISK,
                "description": "Potential XSS script injection"
            },
            {
                "name": "Suspicious URL",
                "pattern": r"(bit\.ly|tinyurl\.com|goo\.gl)/[a-zA-Z0-9]+",
                "threat_type": ThreatType.PHISHING,
                "threat_level": ThreatLevel.MEDIUM_RISK,
                "description": "Shortened URL that may hide malicious content"
            },
            {
                "name": "Malicious Filename",
                "pattern": r".*\.(exe|bat|cmd|com|pif|scr|vbs|js|jar)$",
                "threat_type": ThreatType.MALWARE,
                "threat_level": ThreatLevel.MEDIUM_RISK,
                "description": "Executable file attachment"
            }
        ]

    async def scan_message(self, content: str, sender_info: Dict[str, str]) -> ScanResult:
        """
        Scan message content for threats.

        Args:
            content: Message content to scan
            sender_info: Information about the sender (ip, user_agent, etc.)

        Returns:
            ScanResult with threat assessment
        """
        start_time = datetime.now(timezone.utc)

        # Calculate content hash
        content_hash = hashlib.sha256(content.encode()).hexdigest()

        # Initialize scan result
        result = ScanResult(
            file_path=f"message_{content_hash[:16]}",
            file_hash=content_hash,
            threat_level=ThreatLevel.CLEAN,
            threat_type=ThreatType.CLEAN,
            threat_name=None,
            scan_type=ScanType.FULL_SCAN,
            scan_duration=0.0,
            detected_at=start_time,
            confidence_score=1.0,
            details={"sender_ip": sender_info.get("ip", "unknown")}
        )

        # Check for threats
        threats_found = []
        max_threat_level = ThreatLevel.CLEAN
        max_confidence = 0.0

        for pattern in self.threat_patterns:
            if re.search(pattern["pattern"], content, re.IGNORECASE):
                threats_found.append(pattern)
                if pattern["threat_level"].value > max_threat_level.value:
                    max_threat_level = pattern["threat_level"]
                    result.threat_type = pattern["threat_type"]
                    result.threat_name = pattern["name"]
                    result.confidence_score = 0.8
                    max_confidence = 0.8

        # Additional checks
        if len(content) > 10000:  # Very long message
            if max_threat_level.value < ThreatLevel.SUSPICIOUS.value:
                max_threat_level = ThreatLevel.SUSPICIOUS
                result.threat_type = ThreatType.SUSPICIOUS_BEHAVIOR
                result.threat_name = "Unusually long message"
                result.confidence_score = 0.6

        # Check for excessive special characters
        special_chars = sum(1 for c in content if not c.isalnum() and not c.isspace())
        if special_chars / max(1, len(content)) > 0.5:
            if max_threat_level.value < ThreatLevel.SUSPICIOUS.value:
                max_threat_level = ThreatLevel.SUSPICIOUS
                result.threat_type = ThreatType.SUSPICIOUS_BEHAVIOR
                result.threat_name = "High special character ratio"
                result.confidence_score = 0.5

        result.threat_level = max_threat_level
        result.details.update({
            "threats_found": len(threats_found),
            "content_length": len(content),
            "special_chars_ratio": special_chars / max(1, len(content)),
            "scan_completed": True
        })

        # Calculate scan duration
        end_time = datetime.now(timezone.utc)
        result.scan_duration = (end_time - start_time).total_seconds()

        return result