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

        # SQL injection tracking for progressive blocking
        self.sql_injection_attempts: Dict[str, List[datetime]] = {}  # IP -> list of attempt times
        self.sql_injection_blocks: Dict[str, datetime] = {}  # IP -> block time
        self.sql_injection_escalation: Dict[str, int] = {}  # IP -> escalation level

        # Security configuration
        self.max_requests_per_minute = 60
        self.max_requests_per_hour = 1000
        self.block_duration_minutes = 30
        self.sql_injection_escalation_thresholds = [3, 6, 10]  # Attempts before escalation
        self.sql_injection_block_durations = [300, 1800, 7200, 86400]  # 5min, 30min, 2hr, 24hr

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
            ThreatType.SQL_INJECTION: {
                'level_0': [  # First few attempts
                    "SQL injection failed, try a longer needle! 🪡 To send SQL safely, wrap it in quotes and brackets like: \"[SELECT * FROM table]\"",
                    "Nice try, Bobby Tables! 🍽️ Your SQL injection has been logged. Use quotes and brackets for legitimate SQL: \"[YOUR SQL HERE]\"",
                    "DROP TABLE? More like DROP your hacking career! 😂 For real SQL, use: \"[SELECT example]\"",
                    "SELECT * FROM hackers WHERE skill_level > 0; -- 0 rows returned. Try \"[SQL]\" format instead! 🤖",
                    "Your SQL injection is about as effective as a chocolate teapot! ☕ Use \"[SQL]\" for legitimate queries."
                ],
                'level_1': [  # After a few attempts
                    "Still trying SQL injection? 🙄 We've explained the \"[SQL]\" format multiple times now!",
                    "Error 418: I'm a teapot, not a vulnerable database! Use \"[SQL]\" or give up! 🫖",
                    "Your persistence is admirable but misguided. Use \"[SQL]\" format for legitimate queries! 🎯",
                    "SQL injection attempt #N detected. Maybe try learning proper syntax instead? \"[SQL]\" works! 📚",
                    "Still fishing for vulnerabilities? 🎣 Use \"[SQL]\" format or find a new hobby!"
                ],
                'level_2': [  # Getting annoying
                    "Right, this is quite enough now, stop hacking us! 😤 Final warning before timeout!",
                    "Seriously? Still trying? 🤦‍♂️ You're about to get a timeout for being persistently annoying!",
                    "Your SQL injection attempts are more repetitive than elevator music! 🎵 Last chance!",
                    "We're running out of patience faster than your creativity! 😮‍💨 Stop or face consequences!",
                    "This is your final warning before we show you the digital door! 🚪"
                ],
                'level_3': [  # Blocked
                    "That's it! You're blocked for being persistently annoying! 🚫 Come back when you've learned manners!",
                    "Congratulations! You've won a timeout! 🏆 Maybe use this time to learn legitimate programming!",
                    "Access denied! Your hacking attempts have earned you a digital time-out! ⏰",
                    "Blocked! Your SQL injection skills are matched only by your inability to take a hint! 🛑",
                    "You've been temporarily banned for excessive hackery! 🔨 Try being less suspicious next time!"
                ]
            },
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
    
    def _get_witty_response(self, threat_type: ThreatType, source: str = "unknown", escalation_level: int = 0) -> str:
        """Get a random witty response for a threat type with escalation support."""
        import random

        responses = self.witty_responses.get(threat_type, ["Security threat detected and blocked! 🛡️"])

        # Handle SQL injection escalation
        if threat_type == ThreatType.SQL_INJECTION and isinstance(responses, dict):
            level_key = f'level_{min(escalation_level, 3)}'
            level_responses = responses.get(level_key, responses.get('level_0', ["SQL injection blocked! 🛡️"]))
            response = random.choice(level_responses)

            # Replace #N with actual attempt count if present
            if source in self.sql_injection_attempts:
                attempt_count = len(self.sql_injection_attempts[source])
                response = response.replace('#N', f'#{attempt_count}')

            return response

        # Handle other threat types (legacy format)
        if isinstance(responses, list):
            return random.choice(responses)

        return "Security threat detected and blocked! 🛡️"
    
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
        """
        Enhanced SQL injection detection with progressive blocking and quoted SQL support.

        Features:
        - Detects SQL injection patterns
        - Allows quoted SQL in format: "[SQL QUERY]" or "[SQL QUERY]"
        - Progressive blocking with escalating responses
        - Automatic IP blocking after repeated attempts
        """
        try:
            # Check if IP is currently blocked
            if source in self.sql_injection_blocks:
                block_time = self.sql_injection_blocks[source]
                if datetime.now() < block_time:
                    # Still blocked
                    remaining_time = (block_time - datetime.now()).total_seconds()
                    threat = SecurityThreat(
                        threat_id=self._generate_threat_id(),
                        threat_type=ThreatType.SQL_INJECTION,
                        threat_level=ThreatLevel.CRITICAL,
                        source=source,
                        description=f"Blocked IP attempting SQL injection. Block expires in {int(remaining_time)}s",
                        detected_at=datetime.now(),
                        metadata={"blocked_until": block_time.isoformat(), "remaining_seconds": int(remaining_time)},
                        witty_response="You're still blocked! ⏰ Maybe use this time for self-reflection?"
                    )
                    return True, threat
                else:
                    # Block expired, remove from blocked list
                    del self.sql_injection_blocks[source]
                    self.sql_injection_escalation[source] = 0  # Reset escalation

            # Check for properly quoted SQL (allowed format)
            quoted_sql_patterns = [
                r'\"?\[.*?\]\"?',  # "[SQL]" or "[SQL]"
                r'\"?\{.*?\}\"?',  # "{SQL}" or "{SQL}"
            ]

            # If input matches quoted format, it's allowed
            for pattern in quoted_sql_patterns:
                if re.fullmatch(pattern, input_text.strip(), re.DOTALL):
                    logger.info(f"✅ Properly quoted SQL allowed from {source}: {input_text[:50]}...")
                    return False, None

            # Enhanced SQL injection patterns
            sql_patterns = [
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
                # Additional dangerous patterns
                r"(\b(LOAD_FILE|INTO\s+OUTFILE|INTO\s+DUMPFILE)\b)",
                r"(\b(BENCHMARK|SLEEP)\s*\()",
                r"(\b(HEX|UNHEX|MD5|SHA1)\s*\()",
                # Blind injection patterns
                r"(\b(IF|CASE|WHEN)\s*\(.*?=.*?\))",
                # Error-based injection
                r"(\b(EXTRACTVALUE|UPDATEXML)\s*\()",
            ]

            detected_patterns = []
            for pattern in sql_patterns:
                matches = re.findall(pattern, input_text, re.IGNORECASE)
                if matches:
                    detected_patterns.extend(matches)

            if detected_patterns:
                # Track attempt
                current_time = datetime.now()
                if source not in self.sql_injection_attempts:
                    self.sql_injection_attempts[source] = []

                self.sql_injection_attempts[source].append(current_time)

                # Clean old attempts (older than 1 hour)
                hour_ago = current_time - timedelta(hours=1)
                self.sql_injection_attempts[source] = [
                    attempt for attempt in self.sql_injection_attempts[source]
                    if attempt > hour_ago
                ]

                # Determine escalation level
                attempt_count = len(self.sql_injection_attempts[source])
                escalation_level = 0
                for i, threshold in enumerate(self.sql_injection_escalation_thresholds):
                    if attempt_count >= threshold:
                        escalation_level = i + 1

                # Update escalation tracking
                self.sql_injection_escalation[source] = escalation_level

                # Check if should block
                if escalation_level >= len(self.sql_injection_escalation_thresholds):
                    # Block the IP
                    block_duration = self.sql_injection_block_durations[min(escalation_level, len(self.sql_injection_block_durations) - 1)]
                    block_until = current_time + timedelta(seconds=block_duration)
                    self.sql_injection_blocks[source] = block_until

                    logger.critical(f"🚫 IP {source} blocked for SQL injection attempts until {block_until}")

                # Create threat with escalation-aware response
                threat = SecurityThreat(
                    threat_id=self._generate_threat_id(),
                    threat_type=ThreatType.SQL_INJECTION,
                    threat_level=ThreatLevel.HIGH if escalation_level < 2 else ThreatLevel.CRITICAL,
                    source=source,
                    description=f"SQL injection patterns detected: {len(detected_patterns)} patterns (attempt #{attempt_count})",
                    detected_at=current_time,
                    metadata={
                        "patterns": [str(p) for p in detected_patterns],
                        "input": input_text[:100],
                        "attempt_count": attempt_count,
                        "escalation_level": escalation_level,
                        "blocked": source in self.sql_injection_blocks
                    },
                    witty_response=self._get_witty_response(ThreatType.SQL_INJECTION, source, escalation_level)
                )

                self.detected_threats[threat.threat_id] = threat
                logger.warning(f"🚨 SQL injection detected from {source} (attempt #{attempt_count}, level {escalation_level})")
                return True, threat

            return False, None

        except Exception as e:
            logger.error(f"Error detecting SQL injection: {e}")
            return False, None

    def is_sql_injection_blocked(self, source: str) -> Tuple[bool, Optional[datetime], int]:
        """
        Check if a source is blocked for SQL injection attempts.

        Returns:
            Tuple of (is_blocked, block_expiry_time, escalation_level)
        """
        if source in self.sql_injection_blocks:
            block_time = self.sql_injection_blocks[source]
            if datetime.now() < block_time:
                escalation_level = self.sql_injection_escalation.get(source, 0)
                return True, block_time, escalation_level
            else:
                # Block expired, clean up
                del self.sql_injection_blocks[source]
                self.sql_injection_escalation[source] = 0

        return False, None, self.sql_injection_escalation.get(source, 0)

    def get_sql_injection_stats(self, source: str) -> Dict[str, Any]:
        """Get SQL injection attempt statistics for a source."""
        current_time = datetime.now()
        attempts = self.sql_injection_attempts.get(source, [])

        # Clean old attempts
        hour_ago = current_time - timedelta(hours=1)
        recent_attempts = [attempt for attempt in attempts if attempt > hour_ago]

        is_blocked, block_expiry, escalation_level = self.is_sql_injection_blocked(source)

        return {
            "total_attempts": len(recent_attempts),
            "escalation_level": escalation_level,
            "is_blocked": is_blocked,
            "block_expiry": block_expiry.isoformat() if block_expiry else None,
            "next_escalation_threshold": next(
                (threshold for threshold in self.sql_injection_escalation_thresholds
                 if threshold > len(recent_attempts)),
                None
            )
        }

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
