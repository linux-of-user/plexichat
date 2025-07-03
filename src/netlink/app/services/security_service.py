"""
Comprehensive Security & Anti-Virus System for NetLink.
Implements file scanning, link safety checking, SQL injection detection,
and multi-layer input sanitization with witty responses.
"""

import re
import hashlib
import time
import json
import urllib.parse
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, asdict
from enum import Enum
import logging

from netlink.app.logger_config import logger


class ThreatLevel(Enum):
    """Security threat levels."""
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatType(Enum):
    """Types of security threats."""
    MALWARE = "malware"
    VIRUS = "virus"
    TROJAN = "trojan"
    PHISHING = "phishing"
    SPAM = "spam"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    MALICIOUS_LINK = "malicious_link"
    SUSPICIOUS_FILE = "suspicious_file"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    BRUTE_FORCE = "brute_force"
    UNAUTHORIZED_ACCESS = "unauthorized_access"


@dataclass
class SecurityThreat:
    """Represents a detected security threat."""
    threat_id: str
    threat_type: ThreatType
    threat_level: ThreatLevel
    source: str  # IP, user_id, file_hash, etc.
    description: str
    detected_at: datetime
    blocked: bool = True
    metadata: Optional[Dict[str, Any]] = None
    witty_response: Optional[str] = None


@dataclass
class FileSignature:
    """File signature for malware detection."""
    signature_id: str
    name: str
    pattern: bytes
    threat_type: ThreatType
    threat_level: ThreatLevel
    description: str


class SecurityService:
    """Comprehensive security and anti-virus service."""
    
    def __init__(self):
        self.detected_threats: Dict[str, SecurityThreat] = {}
        self.blocked_ips: Set[str] = set()
        self.blocked_domains: Set[str] = set()
        self.file_signatures: Dict[str, FileSignature] = {}
        self.rate_limits: Dict[str, List[float]] = {}  # IP -> list of timestamps
        
        # Security configuration
        self.max_requests_per_minute = 60
        self.max_requests_per_hour = 1000
        self.block_duration_minutes = 30
        
        # Initialize security components
        self._initialize_file_signatures()
        self._initialize_malicious_domains()
        self._initialize_witty_responses()
        
        logger.info("🛡️ Security service initialized")
    
    def _initialize_file_signatures(self):
        """Initialize file signatures for malware detection."""
        # Common malware signatures (simplified for demo)
        signatures = [
            {
                "signature_id": "eicar_test",
                "name": "EICAR Test File",
                "pattern": b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
                "threat_type": ThreatType.VIRUS,
                "threat_level": ThreatLevel.HIGH,
                "description": "EICAR antivirus test file"
            },
            {
                "signature_id": "suspicious_exe",
                "name": "Suspicious Executable",
                "pattern": b"\\x4D\\x5A.*\\x50\\x45\\x00\\x00",  # PE header pattern
                "threat_type": ThreatType.SUSPICIOUS_FILE,
                "threat_level": ThreatLevel.MEDIUM,
                "description": "Potentially suspicious executable file"
            },
            {
                "signature_id": "script_injection",
                "name": "Script Injection",
                "pattern": b"<script[^>]*>.*</script>",
                "threat_type": ThreatType.XSS,
                "threat_level": ThreatLevel.HIGH,
                "description": "Potential script injection attempt"
            }
        ]
        
        for sig_data in signatures:
            signature = FileSignature(**sig_data)
            self.file_signatures[signature.signature_id] = signature
    
    def _initialize_malicious_domains(self):
        """Initialize list of known malicious domains."""
        # Known malicious domains (simplified list)
        malicious_domains = [
            "malware.com",
            "phishing-site.net",
            "virus-download.org",
            "suspicious-link.co",
            "fake-bank.com",
            "scam-site.net"
        ]
        
        self.blocked_domains.update(malicious_domains)
    
    def _initialize_witty_responses(self):
        """Initialize witty responses for different threat types."""
        self.witty_responses = {
            ThreatType.SQL_INJECTION: [
                "Nice try, Bobby Tables! 🍽️ Your SQL injection attempt has been logged and laughed at.",
                "DROP TABLE? More like DROP your hacking career! 😂 SQL injection blocked.",
                "SELECT * FROM hackers WHERE skill_level > 0; -- 0 rows returned. Try again! 🤖",
                "Your SQL injection is about as effective as a chocolate teapot! ☕ Blocked.",
                "Error 418: I'm a teapot, not a database! Your injection attempt failed spectacularly. 🫖"
            ],
            ThreatType.XSS: [
                "Cross-site scripting? More like cross-site NOPE! 🚫 Your XSS attempt blocked.",
                "Alert('You tried!'); But our XSS protection says otherwise! 🛡️",
                "Your script injection has been sanitized faster than hand sanitizer in 2020! 🧴",
                "XSS blocked! Maybe try learning legitimate web development instead? 📚"
            ],
            ThreatType.MALWARE: [
                "Malware detected! Our antivirus is more effective than your virus! 🦠➡️🗑️",
                "File quarantined! Your malware is now in digital jail. Do not pass GO. 🚔",
                "Virus blocked! Even our AI thinks your code is infectious... in a bad way! 🤖"
            ],
            ThreatType.PHISHING: [
                "Phishing attempt detected! We're not biting your bait! 🎣❌",
                "Nice try, but we don't fall for phishing hooks! 🐟 Blocked.",
                "Your phishing attempt is fishier than a seafood market! 🐠 Blocked."
            ],
            ThreatType.BRUTE_FORCE: [
                "Brute force attack detected! Your password guessing game is weaker than your WiFi signal! 📶",
                "Too many failed attempts! Take a break and maybe read a book on cybersecurity ethics! 📖",
                "Brute force blocked! Your attack is more predictable than a rom-com ending! 🎬"
            ]
        }
    
    def _generate_threat_id(self) -> str:
        """Generate a unique threat ID."""
        return f"threat_{int(time.time() * 1000)}_{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}"
    
    def _get_witty_response(self, threat_type: ThreatType) -> str:
        """Get a random witty response for a threat type."""
        import random
        responses = self.witty_responses.get(threat_type, ["Security threat detected and blocked! 🛡️"])
        return random.choice(responses)
    
    def scan_file_content(self, file_content: bytes, filename: str) -> Tuple[bool, Optional[SecurityThreat]]:
        """Scan file content for malware and threats."""
        try:
            # Check file size (basic protection)
            if len(file_content) > 100 * 1024 * 1024:  # 100MB limit
                threat = SecurityThreat(
                    threat_id=self._generate_threat_id(),
                    threat_type=ThreatType.SUSPICIOUS_FILE,
                    threat_level=ThreatLevel.MEDIUM,
                    source=filename,
                    description=f"File too large: {len(file_content)} bytes",
                    detected_at=datetime.now(),
                    witty_response="File rejected! That's bigger than my attention span! 📏"
                )
                return False, threat
            
            # Check against known signatures
            for signature in self.file_signatures.values():
                if re.search(signature.pattern, file_content, re.IGNORECASE | re.DOTALL):
                    threat = SecurityThreat(
                        threat_id=self._generate_threat_id(),
                        threat_type=signature.threat_type,
                        threat_level=signature.threat_level,
                        source=filename,
                        description=f"Matched signature: {signature.name}",
                        detected_at=datetime.now(),
                        metadata={"signature_id": signature.signature_id},
                        witty_response=self._get_witty_response(signature.threat_type)
                    )
                    
                    self.detected_threats[threat.threat_id] = threat
                    logger.warning(f"🚨 Malware detected in {filename}: {signature.name}")
                    return False, threat
            
            # Check file extension against dangerous types
            dangerous_extensions = ['.exe', '.bat', '.cmd', '.scr', '.pif', '.com', '.vbs', '.js']
            file_ext = filename.lower().split('.')[-1] if '.' in filename else ''
            
            if f'.{file_ext}' in dangerous_extensions:
                threat = SecurityThreat(
                    threat_id=self._generate_threat_id(),
                    threat_type=ThreatType.SUSPICIOUS_FILE,
                    threat_level=ThreatLevel.MEDIUM,
                    source=filename,
                    description=f"Potentially dangerous file extension: .{file_ext}",
                    detected_at=datetime.now(),
                    witty_response="Executable file blocked! We don't run random programs here! 🏃‍♂️❌"
                )
                
                self.detected_threats[threat.threat_id] = threat
                logger.warning(f"⚠️ Suspicious file extension: {filename}")
                return False, threat
            
            # File appears safe
            logger.info(f"✅ File scan passed: {filename}")
            return True, None
            
        except Exception as e:
            logger.error(f"Error scanning file {filename}: {e}")
            threat = SecurityThreat(
                threat_id=self._generate_threat_id(),
                threat_type=ThreatType.SUSPICIOUS_FILE,
                threat_level=ThreatLevel.MEDIUM,
                source=filename,
                description=f"Scan error: {str(e)}",
                detected_at=datetime.now(),
                witty_response="File scan failed! When in doubt, block it out! 🚫"
            )
            return False, threat
    
    def check_link_safety(self, url: str) -> Tuple[bool, Optional[SecurityThreat]]:
        """Check if a URL is safe."""
        try:
            parsed_url = urllib.parse.urlparse(url)
            domain = parsed_url.netloc.lower()
            
            # Remove www. prefix for checking
            if domain.startswith('www.'):
                domain = domain[4:]
            
            # Check against blocked domains
            if domain in self.blocked_domains:
                threat = SecurityThreat(
                    threat_id=self._generate_threat_id(),
                    threat_type=ThreatType.MALICIOUS_LINK,
                    threat_level=ThreatLevel.HIGH,
                    source=url,
                    description=f"Known malicious domain: {domain}",
                    detected_at=datetime.now(),
                    witty_response=self._get_witty_response(ThreatType.PHISHING)
                )
                
                self.detected_threats[threat.threat_id] = threat
                logger.warning(f"🚨 Malicious link blocked: {url}")
                return False, threat
            
            # Check for suspicious patterns
            suspicious_patterns = [
                r'bit\.ly/[a-zA-Z0-9]+',  # Shortened URLs
                r'tinyurl\.com',
                r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # IP addresses
                r'[a-zA-Z0-9]+-[a-zA-Z0-9]+-[a-zA-Z0-9]+\.(tk|ml|ga|cf)',  # Suspicious TLDs
            ]
            
            for pattern in suspicious_patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    threat = SecurityThreat(
                        threat_id=self._generate_threat_id(),
                        threat_type=ThreatType.MALICIOUS_LINK,
                        threat_level=ThreatLevel.MEDIUM,
                        source=url,
                        description=f"Suspicious URL pattern detected",
                        detected_at=datetime.now(),
                        witty_response="Suspicious link detected! We don't click on sketchy links here! 🔗❌"
                    )
                    
                    self.detected_threats[threat.threat_id] = threat
                    logger.warning(f"⚠️ Suspicious link pattern: {url}")
                    return False, threat
            
            # URL appears safe
            logger.info(f"✅ Link safety check passed: {url}")
            return True, None
            
        except Exception as e:
            logger.error(f"Error checking link safety for {url}: {e}")
            threat = SecurityThreat(
                threat_id=self._generate_threat_id(),
                threat_type=ThreatType.MALICIOUS_LINK,
                threat_level=ThreatLevel.MEDIUM,
                source=url,
                description=f"Link check error: {str(e)}",
                detected_at=datetime.now(),
                witty_response="Link check failed! Better safe than sorry! 🔒"
            )
            return False, threat
    
    def detect_sql_injection(self, input_text: str, source: str = "unknown") -> Tuple[bool, Optional[SecurityThreat]]:
        """Detect SQL injection attempts."""
        try:
            # Common SQL injection patterns
            sql_patterns = [
                r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)",
                r"(\b(OR|AND)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?)",
                r"(['\"];?\s*(DROP|DELETE|INSERT|UPDATE)\s+)",
                r"(\bUNION\s+(ALL\s+)?SELECT\b)",
                r"(\b(EXEC|EXECUTE)\s*\()",
                r"(--|\#|\/\*|\*\/)",
                r"(\b(CHAR|ASCII|SUBSTRING|LENGTH|USER|DATABASE|VERSION)\s*\()",
                r"(\b(WAITFOR|DELAY)\s+)",
                r"(\b(CAST|CONVERT)\s*\()",
                r"(\b(INFORMATION_SCHEMA|SYSOBJECTS|SYSCOLUMNS)\b)"
            ]
            
            detected_patterns = []
            for pattern in sql_patterns:
                if re.search(pattern, input_text, re.IGNORECASE):
                    detected_patterns.append(pattern)
            
            if detected_patterns:
                threat = SecurityThreat(
                    threat_id=self._generate_threat_id(),
                    threat_type=ThreatType.SQL_INJECTION,
                    threat_level=ThreatLevel.HIGH,
                    source=source,
                    description=f"SQL injection patterns detected: {len(detected_patterns)} patterns",
                    detected_at=datetime.now(),
                    metadata={"patterns": detected_patterns, "input": input_text[:100]},
                    witty_response=self._get_witty_response(ThreatType.SQL_INJECTION)
                )
                
                self.detected_threats[threat.threat_id] = threat
                logger.warning(f"🚨 SQL injection detected from {source}")
                return True, threat
            
            return False, None
            
        except Exception as e:
            logger.error(f"Error detecting SQL injection: {e}")
            return False, None
    
    def sanitize_input(self, input_text: str, allow_html: bool = False) -> str:
        """Multi-layer input sanitization."""
        try:
            if not input_text:
                return ""
            
            # Remove null bytes
            sanitized = input_text.replace('\x00', '')
            
            # HTML sanitization
            if not allow_html:
                # Escape HTML characters
                html_escape_table = {
                    "&": "&amp;",
                    "<": "&lt;",
                    ">": "&gt;",
                    '"': "&quot;",
                    "'": "&#x27;",
                    "/": "&#x2F;",
                }
                
                for char, escape in html_escape_table.items():
                    sanitized = sanitized.replace(char, escape)
            
            # Remove potentially dangerous patterns
            dangerous_patterns = [
                r'javascript:',
                r'vbscript:',
                r'data:',
                r'file:',
                r'ftp:',
                r'<script[^>]*>.*?</script>',
                r'<iframe[^>]*>.*?</iframe>',
                r'<object[^>]*>.*?</object>',
                r'<embed[^>]*>.*?</embed>',
                r'<link[^>]*>',
                r'<meta[^>]*>',
                r'<style[^>]*>.*?</style>',
                r'on\w+\s*=',  # Event handlers like onclick, onload, etc.
            ]
            
            for pattern in dangerous_patterns:
                sanitized = re.sub(pattern, '', sanitized, flags=re.IGNORECASE | re.DOTALL)
            
            # Limit length
            max_length = 10000  # 10KB limit
            if len(sanitized) > max_length:
                sanitized = sanitized[:max_length] + "... [truncated]"
            
            return sanitized
            
        except Exception as e:
            logger.error(f"Error sanitizing input: {e}")
            return ""
    
    def check_rate_limit(self, identifier: str, max_per_minute: Optional[int] = None) -> Tuple[bool, Optional[SecurityThreat]]:
        """Check rate limiting for an identifier (IP, user_id, etc.)."""
        try:
            current_time = time.time()
            max_requests = max_per_minute or self.max_requests_per_minute
            
            # Initialize if not exists
            if identifier not in self.rate_limits:
                self.rate_limits[identifier] = []
            
            # Clean old timestamps (older than 1 minute)
            self.rate_limits[identifier] = [
                timestamp for timestamp in self.rate_limits[identifier]
                if current_time - timestamp < 60
            ]
            
            # Check if limit exceeded
            if len(self.rate_limits[identifier]) >= max_requests:
                threat = SecurityThreat(
                    threat_id=self._generate_threat_id(),
                    threat_type=ThreatType.RATE_LIMIT_EXCEEDED,
                    threat_level=ThreatLevel.MEDIUM,
                    source=identifier,
                    description=f"Rate limit exceeded: {len(self.rate_limits[identifier])} requests in last minute",
                    detected_at=datetime.now(),
                    witty_response="Slow down there, Speed Racer! 🏎️ Rate limit exceeded."
                )
                
                self.detected_threats[threat.threat_id] = threat
                logger.warning(f"⚠️ Rate limit exceeded for {identifier}")
                return False, threat
            
            # Add current timestamp
            self.rate_limits[identifier].append(current_time)
            return True, None
            
        except Exception as e:
            logger.error(f"Error checking rate limit: {e}")
            return True, None  # Allow on error
    
    def block_ip(self, ip_address: str, duration_minutes: Optional[int] = None):
        """Block an IP address."""
        try:
            self.blocked_ips.add(ip_address)
            duration = duration_minutes or self.block_duration_minutes
            
            logger.warning(f"🚫 Blocked IP address: {ip_address} for {duration} minutes")
            
            # In a real implementation, you might want to store this in a database
            # with expiration times and implement automatic unblocking
            
        except Exception as e:
            logger.error(f"Error blocking IP {ip_address}: {e}")
    
    def is_ip_blocked(self, ip_address: str) -> bool:
        """Check if an IP address is blocked."""
        return ip_address in self.blocked_ips
    
    def get_security_statistics(self) -> Dict[str, Any]:
        """Get security statistics."""
        try:
            # Count threats by type
            threat_counts = {}
            for threat in self.detected_threats.values():
                threat_type = threat.threat_type.value
                threat_counts[threat_type] = threat_counts.get(threat_type, 0) + 1
            
            # Count threats by level
            level_counts = {}
            for threat in self.detected_threats.values():
                level = threat.threat_level.value
                level_counts[level] = level_counts.get(level, 0) + 1
            
            # Recent threats (last 24 hours)
            recent_threats = [
                threat for threat in self.detected_threats.values()
                if datetime.now() - threat.detected_at < timedelta(hours=24)
            ]
            
            return {
                "total_threats_detected": len(self.detected_threats),
                "recent_threats_24h": len(recent_threats),
                "blocked_ips": len(self.blocked_ips),
                "blocked_domains": len(self.blocked_domains),
                "threat_counts_by_type": threat_counts,
                "threat_counts_by_level": level_counts,
                "file_signatures_loaded": len(self.file_signatures),
                "rate_limited_identifiers": len(self.rate_limits),
                "last_updated": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to get security statistics: {e}")
            return {}
    
    def get_recent_threats(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent security threats."""
        try:
            # Sort threats by detection time (newest first)
            sorted_threats = sorted(
                self.detected_threats.values(),
                key=lambda t: t.detected_at,
                reverse=True
            )
            
            recent_threats = []
            for threat in sorted_threats[:limit]:
                recent_threats.append({
                    "threat_id": threat.threat_id,
                    "type": threat.threat_type.value,
                    "level": threat.threat_level.value,
                    "source": threat.source,
                    "description": threat.description,
                    "detected_at": threat.detected_at.isoformat(),
                    "blocked": threat.blocked,
                    "witty_response": threat.witty_response,
                    "metadata": threat.metadata
                })
            
            return recent_threats
            
        except Exception as e:
            logger.error(f"Failed to get recent threats: {e}")
            return []


# Global security service instance
security_service = SecurityService()
