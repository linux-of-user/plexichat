"""
PlexiChat Message Antivirus Scanner

Specialized antivirus scanner for message content with:
- Real-time message content scanning
- SQL injection pattern detection
- Malicious link detection
- Suspicious content analysis
- Integration with threat intelligence
"""

import re
import hashlib
import logging
import asyncio
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

class MessageThreatType(Enum):
    """Types of threats that can be found in messages."""
    CLEAN = "clean"
    SQL_INJECTION = "sql_injection"
    XSS_ATTEMPT = "xss_attempt"
    MALICIOUS_LINK = "malicious_link"
    PHISHING_ATTEMPT = "phishing_attempt"
    SPAM_CONTENT = "spam_content"
    MALWARE_LINK = "malware_link"
    SUSPICIOUS_PATTERN = "suspicious_pattern"

class MessageThreatLevel(Enum):
    """Threat severity levels."""
    CLEAN = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

@dataclass
class MessageScanResult:
    """Result of message content scanning."""
    message_hash: str
    threat_type: MessageThreatType
    threat_level: MessageThreatLevel
    confidence_score: float
    description: str
    detected_patterns: List[str]
    scan_duration_ms: int
    timestamp: datetime
    metadata: Dict[str, Any]
    recommended_action: str

class MessageAntivirusScanner:
    """
    Advanced message content scanner for detecting threats in text messages.
    
    Features:
    - SQL injection detection with context awareness
    - XSS pattern detection
    - Malicious URL scanning
    - Phishing attempt detection
    - Spam content analysis
    - Suspicious pattern recognition
    """
    
    def __init__(self, data_dir: Path):
        self.data_dir = Path(data_dir)
        self.scanner_dir = self.data_dir / "message_scanner"
        self.scanner_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize pattern databases
        self._initialize_threat_patterns()
        self._initialize_whitelist_patterns()
        
        # Scanning statistics
        self.scan_stats = {
            "total_scans": 0,
            "threats_detected": 0,
            "false_positives": 0,
            "scan_time_total": 0
        }
        
        logger.info("🔍 Message Antivirus Scanner initialized")
    
    def _initialize_threat_patterns(self):
        """Initialize threat detection patterns."""
        # SQL injection patterns (enhanced from security service)
        self.sql_patterns = [
            # Basic SQL commands
            r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)",
            # Boolean-based injection
            r"(\b(OR|AND)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?)",
            # Quote-based injection
            r"(['\"];?\s*(DROP|DELETE|INSERT|UPDATE)\s+)",
            # Union-based injection
            r"(\bUNION\s+(ALL\s+)?SELECT\b)",
            # Stored procedure execution
            r"(\b(EXEC|EXECUTE)\s*\()",
            # SQL comments
            r"(--|\#|\/\*|\*\/)",
            # SQL functions commonly used in injection
            r"(\b(CHAR|ASCII|SUBSTRING|LENGTH|USER|DATABASE|VERSION)\s*\()",
            # Time-based injection
            r"(\b(WAITFOR|DELAY)\s+)",
            # Type conversion functions
            r"(\b(CAST|CONVERT)\s*\()",
            # Information schema access
            r"(\b(INFORMATION_SCHEMA|SYSOBJECTS|SYSCOLUMNS)\b)",
        ]
        
        # XSS patterns
        self.xss_patterns = [
            r"<script[^>]*>.*?</script>",
            r"javascript:",
            r"vbscript:",
            r"onload\s*=",
            r"onerror\s*=",
            r"onclick\s*=",
            r"onmouseover\s*=",
            r"<iframe[^>]*>",
            r"<object[^>]*>",
            r"<embed[^>]*>",
            r"eval\s*\(",
            r"document\.cookie",
            r"document\.write",
        ]
        
        # Malicious URL patterns
        self.malicious_url_patterns = [
            r"bit\.ly/[a-zA-Z0-9]+",  # Shortened URLs (suspicious)
            r"tinyurl\.com/[a-zA-Z0-9]+",
            r"t\.co/[a-zA-Z0-9]+",
            r"goo\.gl/[a-zA-Z0-9]+",
            r"[a-zA-Z0-9]+\.tk/",  # Free domains often used maliciously
            r"[a-zA-Z0-9]+\.ml/",
            r"[a-zA-Z0-9]+\.ga/",
            r"[a-zA-Z0-9]+\.cf/",
        ]
        
        # Phishing patterns
        self.phishing_patterns = [
            r"verify\s+your\s+account",
            r"click\s+here\s+to\s+login",
            r"suspended\s+account",
            r"urgent\s+action\s+required",
            r"confirm\s+your\s+identity",
            r"update\s+payment\s+information",
            r"security\s+alert",
            r"account\s+will\s+be\s+closed",
        ]
        
        # Spam patterns
        self.spam_patterns = [
            r"buy\s+now",
            r"limited\s+time\s+offer",
            r"act\s+now",
            r"free\s+money",
            r"make\s+money\s+fast",
            r"work\s+from\s+home",
            r"no\s+experience\s+required",
            r"guaranteed\s+income",
        ]
    
    def _initialize_whitelist_patterns(self):
        """Initialize patterns that should be allowed."""
        # Quoted SQL patterns (legitimate use)
        self.whitelist_patterns = [
            r'\"?\[.*?\]\"?',  # "[SQL]" format
            r'\"?\{.*?\}\"?',  # "{SQL}" format
            r'```sql\n.*?\n```',  # Code blocks
            r'`.*?`',  # Inline code
        ]
    
    async def scan_message(self, message_content: str, sender_info: Optional[Dict] = None) -> MessageScanResult:
        """
        Scan message content for threats.
        
        Args:
            message_content: The message text to scan
            sender_info: Optional sender information for context
            
        Returns:
            MessageScanResult with threat analysis
        """
        start_time = datetime.now(timezone.utc)
        message_hash = hashlib.sha256(message_content.encode()).hexdigest()[:16]
        
        try:
            self.scan_stats["total_scans"] += 1
            
            # Check whitelist first
            if self._is_whitelisted_content(message_content):
                return self._create_clean_result(message_hash, message_content, start_time)
            
            # Perform threat detection
            threats = []
            
            # SQL injection detection
            sql_threats = self._detect_sql_injection(message_content)
            threats.extend(sql_threats)
            
            # XSS detection
            xss_threats = self._detect_xss(message_content)
            threats.extend(xss_threats)
            
            # Malicious URL detection
            url_threats = await self._detect_malicious_urls(message_content)
            threats.extend(url_threats)
            
            # Phishing detection
            phishing_threats = self._detect_phishing(message_content)
            threats.extend(phishing_threats)
            
            # Spam detection
            spam_threats = self._detect_spam(message_content)
            threats.extend(spam_threats)
            
            # Determine overall threat level
            if not threats:
                return self._create_clean_result(message_hash, message_content, start_time)
            
            # Find highest threat level
            highest_threat = max(threats, key=lambda t: t['level'].value)
            
            scan_duration = int((datetime.now(timezone.utc) - start_time).total_seconds() * 1000)
            self.scan_stats["scan_time_total"] += scan_duration
            
            if highest_threat['level'].value >= MessageThreatLevel.MEDIUM.value:
                self.scan_stats["threats_detected"] += 1
            
            return MessageScanResult(
                message_hash=message_hash,
                threat_type=highest_threat['type'],
                threat_level=highest_threat['level'],
                confidence_score=highest_threat['confidence'],
                description=highest_threat['description'],
                detected_patterns=highest_threat['patterns'],
                scan_duration_ms=scan_duration,
                timestamp=start_time,
                metadata={
                    "all_threats": threats,
                    "message_length": len(message_content),
                    "sender_info": sender_info or {}
                },
                recommended_action=self._get_recommended_action(highest_threat['level'])
            )
            
        except Exception as e:
            logger.error(f"Error scanning message: {e}")
            return self._create_error_result(message_hash, str(e), start_time)
    
    def _is_whitelisted_content(self, content: str) -> bool:
        """Check if content matches whitelist patterns."""
        for pattern in self.whitelist_patterns:
            if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
                return True
        return False
    
    def _detect_sql_injection(self, content: str) -> List[Dict]:
        """Detect SQL injection patterns in message content."""
        threats = []
        detected_patterns = []
        
        for pattern in self.sql_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                detected_patterns.extend([str(match) for match in matches])
        
        if detected_patterns:
            confidence = min(0.9, len(detected_patterns) * 0.3)  # Max 90% confidence
            threats.append({
                'type': MessageThreatType.SQL_INJECTION,
                'level': MessageThreatLevel.HIGH,
                'confidence': confidence,
                'description': f"SQL injection patterns detected: {len(detected_patterns)} patterns",
                'patterns': detected_patterns
            })
        
        return threats
    
    def _detect_xss(self, content: str) -> List[Dict]:
        """Detect XSS patterns in message content."""
        threats = []
        detected_patterns = []
        
        for pattern in self.xss_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE | re.DOTALL)
            if matches:
                detected_patterns.extend(matches)
        
        if detected_patterns:
            confidence = min(0.85, len(detected_patterns) * 0.4)
            threats.append({
                'type': MessageThreatType.XSS_ATTEMPT,
                'level': MessageThreatLevel.HIGH,
                'confidence': confidence,
                'description': f"XSS patterns detected: {len(detected_patterns)} patterns",
                'patterns': detected_patterns
            })
        
        return threats
    
    async def _detect_malicious_urls(self, content: str) -> List[Dict]:
        """Detect malicious URLs in message content."""
        threats = []
        detected_patterns = []
        
        # Extract URLs
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        urls = re.findall(url_pattern, content)
        
        for url in urls:
            for pattern in self.malicious_url_patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    detected_patterns.append(url)
        
        if detected_patterns:
            confidence = min(0.7, len(detected_patterns) * 0.5)
            threats.append({
                'type': MessageThreatType.MALICIOUS_LINK,
                'level': MessageThreatLevel.MEDIUM,
                'confidence': confidence,
                'description': f"Suspicious URLs detected: {len(detected_patterns)} URLs",
                'patterns': detected_patterns
            })
        
        return threats
    
    def _detect_phishing(self, content: str) -> List[Dict]:
        """Detect phishing patterns in message content."""
        threats = []
        detected_patterns = []
        
        for pattern in self.phishing_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                detected_patterns.extend(matches)
        
        if detected_patterns:
            confidence = min(0.75, len(detected_patterns) * 0.3)
            threats.append({
                'type': MessageThreatType.PHISHING_ATTEMPT,
                'level': MessageThreatLevel.MEDIUM,
                'confidence': confidence,
                'description': f"Phishing patterns detected: {len(detected_patterns)} patterns",
                'patterns': detected_patterns
            })
        
        return threats
    
    def _detect_spam(self, content: str) -> List[Dict]:
        """Detect spam patterns in message content."""
        threats = []
        detected_patterns = []
        
        for pattern in self.spam_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                detected_patterns.extend(matches)
        
        if detected_patterns:
            confidence = min(0.6, len(detected_patterns) * 0.2)
            threats.append({
                'type': MessageThreatType.SPAM_CONTENT,
                'level': MessageThreatLevel.LOW,
                'confidence': confidence,
                'description': f"Spam patterns detected: {len(detected_patterns)} patterns",
                'patterns': detected_patterns
            })
        
        return threats
    
    def _create_clean_result(self, message_hash: str, content: str, start_time: datetime) -> MessageScanResult:
        """Create a clean scan result."""
        scan_duration = int((datetime.now(timezone.utc) - start_time).total_seconds() * 1000)
        
        return MessageScanResult(
            message_hash=message_hash,
            threat_type=MessageThreatType.CLEAN,
            threat_level=MessageThreatLevel.CLEAN,
            confidence_score=1.0,
            description="Message content is clean",
            detected_patterns=[],
            scan_duration_ms=scan_duration,
            timestamp=start_time,
            metadata={"message_length": len(content)},
            recommended_action="allow"
        )
    
    def _create_error_result(self, message_hash: str, error: str, start_time: datetime) -> MessageScanResult:
        """Create an error scan result."""
        scan_duration = int((datetime.now(timezone.utc) - start_time).total_seconds() * 1000)
        
        return MessageScanResult(
            message_hash=message_hash,
            threat_type=MessageThreatType.SUSPICIOUS_PATTERN,
            threat_level=MessageThreatLevel.MEDIUM,
            confidence_score=0.5,
            description=f"Scan error: {error}",
            detected_patterns=[],
            scan_duration_ms=scan_duration,
            timestamp=start_time,
            metadata={"error": error},
            recommended_action="review"
        )
    
    def _get_recommended_action(self, threat_level: MessageThreatLevel) -> str:
        """Get recommended action based on threat level."""
        actions = {
            MessageThreatLevel.CLEAN: "allow",
            MessageThreatLevel.LOW: "allow_with_warning",
            MessageThreatLevel.MEDIUM: "quarantine",
            MessageThreatLevel.HIGH: "block",
            MessageThreatLevel.CRITICAL: "block_and_report"
        }
        return actions.get(threat_level, "review")
    
    def get_scan_statistics(self) -> Dict[str, Any]:
        """Get scanning statistics."""
        avg_scan_time = (
            self.scan_stats["scan_time_total"] / self.scan_stats["total_scans"]
            if self.scan_stats["total_scans"] > 0 else 0
        )
        
        return {
            "total_scans": self.scan_stats["total_scans"],
            "threats_detected": self.scan_stats["threats_detected"],
            "false_positives": self.scan_stats["false_positives"],
            "average_scan_time_ms": round(avg_scan_time, 2),
            "threat_detection_rate": (
                self.scan_stats["threats_detected"] / self.scan_stats["total_scans"]
                if self.scan_stats["total_scans"] > 0 else 0
            )
        }
