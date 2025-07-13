import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from . import (
from pathlib import Path

from pathlib import Path

    MAX_FILENAME_LENGTH,
    SUSPICIOUS_EXTENSIONS,
    SUSPICIOUS_FILENAME_PATTERNS,
    Analyzer,
    Analyzes,
    Filename,
    ScanResult,
    ScanType,
    ThreatLevel,
    ThreatType,
    """,
    and,
    characteristics,
    content.,
    extensions,
    filenames,
    for,
    indicate,
    malicious,
    may,
    patterns,
    suspicious,
    that,
)

logger = logging.getLogger(__name__)


class FilenameAnalyzer:
    """
    Analyzes filenames for suspicious characteristics.

    Detects:
    - Suspicious file extensions
    - Malicious filename patterns
    - Double extensions
    - Unicode/encoding tricks
    - Excessively long filenames
    - Social engineering patterns
    """

    def __init__(self):
        # Compile regex patterns for efficiency
        self.suspicious_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in SUSPICIOUS_FILENAME_PATTERNS]

        # Additional suspicious patterns
        self.advanced_patterns = [
            re.compile(r'.*\.(exe|bat|cmd|com|pif|scr|vbs|js)\.(txt|doc|pdf|jpg|png)$', re.IGNORECASE),  # Double extensions
            re.compile(r'.*update.*\.(exe|bat|cmd)$', re.IGNORECASE),  # Fake updates
            re.compile(r'.*install.*\.(exe|bat|cmd)$', re.IGNORECASE),  # Fake installers
            re.compile(r'.*setup.*\.(exe|bat|cmd)$', re.IGNORECASE),  # Fake setup files
            re.compile(r'.*patch.*\.(exe|bat|cmd)$', re.IGNORECASE),  # Fake patches
            re.compile(r'.*crack.*\.(exe|bat|cmd)$', re.IGNORECASE),  # Cracks/keygens
            re.compile(r'.*keygen.*\.(exe|bat|cmd)$', re.IGNORECASE),  # Keygens
            re.compile(r'.*loader.*\.(exe|bat|cmd)$', re.IGNORECASE),  # Loaders
            re.compile(r'.*activator.*\.(exe|bat|cmd)$', re.IGNORECASE),  # Activators
            re.compile(r'.*\d{4}-\d{2}-\d{2}.*\.(exe|zip|rar)$', re.IGNORECASE),  # Date-based naming
        ]

        # Social engineering keywords
        self.social_engineering_keywords = [
            'urgent', 'important', 'invoice', 'receipt', 'payment', 'refund',
            'security', 'alert', 'warning', 'suspended', 'verify', 'confirm',
            'click', 'download', 'install', 'update', 'upgrade', 'free',
            'winner', 'congratulations', 'prize', 'lottery', 'bitcoin',
            'cryptocurrency', 'investment', 'opportunity'
        ]

        # Legitimate software patterns (lower suspicion)
        self.legitimate_patterns = [
            re.compile(r'.*\.(txt|doc|docx|pdf|jpg|jpeg|png|gif|mp3|mp4|avi)$', re.IGNORECASE),
            re.compile(r'^[a-zA-Z0-9_\-\.]+\.(exe|msi)$'),  # Simple, clean executable names
        ]

        self.analysis_stats = {
            'total_analyzed': 0,
            'suspicious_found': 0,
            'double_extensions': 0,
            'social_engineering': 0,
            'excessive_length': 0
        }

    async def analyze_filename(self, file_path: str) -> ScanResult:
        """
        Analyze filename for suspicious characteristics.

        Args:
            file_path: Full path to the file

        Returns:
            ScanResult with filename analysis results
        """
        start_time = datetime.now(timezone.utc)
        from pathlib import Path
path = Path
Path(file_path)
        filename = path.name

        logger.debug(f"Analyzing filename: {filename}")

        threat_level = ThreatLevel.CLEAN
        threat_type = None
        threat_name = None
        confidence = 0.1
        details = {}

        # Check filename length
        if len(filename) > MAX_FILENAME_LENGTH:
            threat_level = ThreatLevel.SUSPICIOUS
            details['excessive_length'] = True
            confidence += 0.2
            self.analysis_stats['excessive_length'] += 1

        # Check for suspicious extensions
        extension_risk = self._check_suspicious_extensions(filename)
        if extension_risk > 0:
            threat_level = max(threat_level, ThreatLevel.SUSPICIOUS)
            details['suspicious_extension'] = True
            confidence += extension_risk

        # Check for double extensions
        if self._has_double_extension(filename):
            threat_level = ThreatLevel.MEDIUM_RISK
            threat_type = ThreatType.SUSPICIOUS_BEHAVIOR
            threat_name = "Double Extension Detected"
            details['double_extension'] = True
            confidence += 0.4
            self.analysis_stats['double_extensions'] += 1

        # Check suspicious patterns
        pattern_risk = self._check_suspicious_patterns(filename)
        if pattern_risk > 0:
            threat_level = max(threat_level, ThreatLevel.MEDIUM_RISK)
            threat_type = ThreatType.SUSPICIOUS_BEHAVIOR
            threat_name = "Suspicious Filename Pattern"
            details['suspicious_pattern'] = True
            confidence += pattern_risk

        # Check for social engineering
        social_risk = self._check_social_engineering(filename)
        if social_risk > 0:
            threat_level = max(threat_level, ThreatLevel.SUSPICIOUS)
            details['social_engineering'] = True
            confidence += social_risk
            self.analysis_stats['social_engineering'] += 1

        # Check for Unicode/encoding tricks
        encoding_risk = self._check_encoding_tricks(filename)
        if encoding_risk > 0:
            threat_level = max(threat_level, ThreatLevel.MEDIUM_RISK)
            details['encoding_tricks'] = True
            confidence += encoding_risk

        # Check for legitimate patterns (reduce suspicion)
        if self._is_likely_legitimate(filename):
            confidence = max(0.1, confidence - 0.3)
            details['likely_legitimate'] = True

        # Ensure confidence doesn't exceed 1.0
        confidence = min(1.0, confidence)

        # Update statistics
        self.analysis_stats['total_analyzed'] += 1
        if threat_level.value > ThreatLevel.CLEAN.value:
            self.analysis_stats['suspicious_found'] += 1

        scan_duration = (datetime.now(timezone.utc) - start_time).total_seconds()

        return ScanResult(
            file_path=file_path,
            file_hash="",  # Not calculated for filename analysis
            threat_level=threat_level,
            threat_type=threat_type,
            threat_name=threat_name,
            scan_type=ScanType.FILENAME_SCAN,
            scan_duration=scan_duration,
            detected_at=start_time,
            confidence_score=confidence,
            details=details
        )

    def _check_suspicious_extensions(self, filename: str) -> float:
        """Check for suspicious file extensions."""
        lower_filename = filename.lower()

        # High-risk extensions
        high_risk_extensions = ['.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs', '.js']
        for ext in high_risk_extensions:
            if lower_filename.endswith(ext):
                return 0.5

        # Medium-risk extensions
        medium_risk_extensions = ['.jar', '.app', '.deb', '.rpm', '.dmg', '.pkg', '.msi']
        for ext in medium_risk_extensions:
            if lower_filename.endswith(ext):
                return 0.3

        return 0.0

    def _has_double_extension(self, filename: str) -> bool:
        """Check for double file extensions (e.g., file.txt.exe)."""
        parts = filename.split('.')
        if len(parts) < 3:
            return False

        # Check if the second-to-last part looks like a file extension
        second_ext = parts[-2].lower()
        common_extensions = ['txt', 'doc', 'pdf', 'jpg', 'png', 'gif', 'mp3', 'mp4', 'zip', 'rar']

        return second_ext in common_extensions and parts[-1].lower() in ['exe', 'bat', 'cmd', 'com', 'scr']

    def _check_suspicious_patterns(self, filename: str) -> float:
        """Check filename against suspicious patterns."""
        max_risk = 0.0

        # Check basic suspicious patterns
        for pattern in self.suspicious_patterns:
            if pattern.match(filename):
                max_risk = max(max_risk, 0.4)

        # Check advanced patterns
        for pattern in self.advanced_patterns:
            if pattern.match(filename):
                max_risk = max(max_risk, 0.6)

        return max_risk

    def _check_social_engineering(self, filename: str) -> float:
        """Check for social engineering keywords."""
        lower_filename = filename.lower()
        keyword_count = 0

        for keyword in self.social_engineering_keywords:
            if keyword in lower_filename:
                keyword_count += 1

        if keyword_count >= 2:
            return 0.5
        elif keyword_count == 1:
            return 0.2

        return 0.0

    def _check_encoding_tricks(self, filename: str) -> float:
        """Check for Unicode/encoding tricks."""
        risk = 0.0

        # Check for non-ASCII characters in executable files
        if not filename.isascii() and any(filename.lower().endswith(ext) for ext in SUSPICIOUS_EXTENSIONS):
            risk += 0.3

        # Check for right-to-left override characters
        if '\u202e' in filename:  # Right-to-left override
            risk += 0.7

        # Check for zero-width characters
        zero_width_chars = ['\u200b', '\u200c', '\u200d', '\ufeff']
        if any(char in filename for char in zero_width_chars):
            risk += 0.4

        return risk

    def _is_likely_legitimate(self, filename: str) -> bool:
        """Check if filename matches legitimate software patterns."""
        for pattern in self.legitimate_patterns:
            if pattern.match(filename):
                return True

        return False

    async def get_statistics(self) -> Dict[str, Any]:
        """Get filename analysis statistics."""
        return self.analysis_stats.copy()

    def add_suspicious_pattern(self, pattern: str) -> bool:
        """Add a new suspicious filename pattern."""
        try:
            compiled_pattern = re.compile(pattern, re.IGNORECASE)
            self.advanced_patterns.append(compiled_pattern)
            logger.info(f"Added suspicious pattern: {pattern}")
            return True
        except re.error as e:
            logger.error(f"Invalid regex pattern '{pattern}': {e}")
            return False

    def add_social_engineering_keyword(self, keyword: str) -> bool:
        """Add a new social engineering keyword."""
        if keyword.lower() not in self.social_engineering_keywords:
            self.social_engineering_keywords.append(keyword.lower())
            logger.info(f"Added social engineering keyword: {keyword}")
            return True
        return False
