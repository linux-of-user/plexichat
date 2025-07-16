# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import hashlib
import json
import logging
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from urllib.parse import parse_qs, urlparse

import aiohttp
import aiosqlite

from . import ScanResult, ScanType, ThreatLevel, ThreatType

from pathlib import Path

from pathlib import Path

"""
Link Safety Scanner

Analyzes URLs and links for safety, checking against known malicious domains,
suspicious patterns, and using threat intelligence feeds.
"""

logger = logging.getLogger(__name__)


class LinkSafetyScanner:
    """
    Link safety scanner that checks URLs for:
    - Known malicious domains
    - Suspicious URL patterns
    - Phishing indicators
    - Shortened URL expansion
    - Domain reputation checking
    """
    
    def __init__(self, data_dir: Path):
        self.from pathlib import Path
data_dir = Path()(data_dir)
        self.link_db_path = self.data_dir / "link_safety.db"
        
        # Known malicious domains (would be populated from threat feeds)
        self.malicious_domains: Set[str] = set()
        self.suspicious_domains: Set[str] = set()
        self.safe_domains: Set[str] = set()
        
        # URL shorteners to expand
        self.url_shorteners = {
            'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
            'short.link', 'tiny.cc', 'is.gd', 'buff.ly', 'ift.tt'
        }
        
        # Suspicious URL patterns
        self.suspicious_patterns = [
            re.compile(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'),  # IP addresses
            re.compile(r'[a-z0-9]{20,}\.com'),  # Long random domains
            re.compile(r'[a-z0-9]+-[a-z0-9]+-[a-z0-9]+\.'),  # Multiple hyphens
            re.compile(r'(login|secure|account|verify|update|confirm).*\.(tk|ml|ga|cf)'),  # Phishing patterns
            re.compile(r'[0-9]+[a-z]+[0-9]+\.'),  # Mixed numbers and letters
            re.compile(r'(paypal|amazon|google|microsoft|apple|facebook).*[0-9]+\.'),  # Brand impersonation
        ]
        
        # Phishing keywords
        self.phishing_keywords = [
            'verify', 'suspend', 'urgent', 'immediate', 'confirm',
            'update', 'secure', 'login', 'account', 'billing',
            'payment', 'expired', 'limited', 'restricted'
        ]
        
        # Safe TLDs (generally more trustworthy)
        self.safe_tlds = {
            '.edu', '.gov', '.mil', '.org', '.com', '.net',
            '.co.uk', '.ac.uk', '.gov.uk'
        }
        
        # Suspicious TLDs
        self.suspicious_tlds = {
            '.tk', '.ml', '.ga', '.cf', '.pw', '.cc', '.ws',
            '.info', '.biz', '.click', '.download', '.zip'
        }
        
        self.scan_stats = {
            'total_urls_scanned': 0,
            'malicious_found': 0,
            'suspicious_found': 0,
            'phishing_detected': 0,
            'shortened_urls_expanded': 0,
            'cache_hits': 0
        }
        
        self._initialized = False

    async def initialize(self):
        """Initialize the link safety scanner."""
        if self._initialized:
            return
        
        logger.info("Initializing Link Safety Scanner")
        
        # Initialize database
        await self._initialize_database()
        
        # Load known domains
        await self._load_domain_lists()
        
        # Load scan statistics
        await self._load_scan_statistics()
        
        self._initialized = True
        logger.info("Link Safety Scanner initialized")

    async def _initialize_database(self):
        """Initialize the link safety database."""
        async with aiosqlite.connect(self.link_db_path) as db:
            # URL scan results table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS url_scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT NOT NULL,
                    url_hash TEXT NOT NULL,
                    domain TEXT,
                    threat_level TEXT NOT NULL,
                    threat_type TEXT,
                    threat_name TEXT,
                    confidence_score REAL,
                    scan_details TEXT,
                    scanned_at TEXT NOT NULL,
                    expires_at TEXT
                )
            """)
            
            # Domain reputation table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS domain_reputation (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT UNIQUE NOT NULL,
                    reputation_score INTEGER,
                    category TEXT,
                    last_seen TEXT,
                    threat_indicators TEXT,
                    updated_at TEXT NOT NULL
                )
            """)
            
            # Malicious domains table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS malicious_domains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT UNIQUE NOT NULL,
                    threat_type TEXT,
                    source TEXT,
                    confidence INTEGER,
                    added_at TEXT NOT NULL
                )
            """)
            
            await db.commit()

    async def scan_url(self, url: str) -> ScanResult:
        """
        Scan a URL for safety.
        
        Args:
            url: URL to scan
            
        Returns:
            ScanResult with URL safety analysis
        """
        start_time = datetime.now(timezone.utc)
        
        if not url or not url.strip():
            return ScanResult(
                file_path=url,
                file_hash="",
                threat_level=ThreatLevel.CLEAN,
                threat_type=None,
                threat_name=None,
                scan_type=ScanType.LINK_SCAN,
                scan_duration=0.0,
                detected_at=start_time,
                confidence_score=0.0,
                details={"error": "Empty URL"}
            )
        
        logger.debug(f"Scanning URL: {url}")
        
        # Calculate URL hash for caching
        url_hash = hashlib.sha256(url.encode()).hexdigest()
        
        # Check cache first
        cached_result = await self._check_url_cache(url_hash)
        if cached_result:
            self.scan_stats['cache_hits'] += 1
            return cached_result
        
        # Parse URL
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()
        except Exception as e:
            logger.error(f"Failed to parse URL {url}: {e}")
            return self._create_error_result(url, "Invalid URL format", start_time)
        
        # Expand shortened URLs
        if domain in self.url_shorteners:
            expanded_url = await self._expand_shortened_url(url)
            if expanded_url and expanded_url != url:
                self.scan_stats['shortened_urls_expanded'] += 1
                # Recursively scan the expanded URL
                return await self.scan_url(expanded_url)
        
        # Perform various safety checks
        threat_level = ThreatLevel.CLEAN
        threat_type = None
        threat_name = None
        confidence = 0.1
        details = {
            'domain': domain,
            'scheme': parsed_url.scheme,
            'path': parsed_url.path,
            'query_params': len(parse_qs(parsed_url.query))
        }
        
        # Check against known malicious domains
        if domain in self.malicious_domains:
            threat_level = ThreatLevel.HIGH_RISK
            threat_type = ThreatType.MALWARE
            threat_name = "Known Malicious Domain"
            confidence = 0.9
            self.scan_stats['malicious_found'] += 1
        
        # Check against suspicious domains
        elif domain in self.suspicious_domains:
            threat_level = ThreatLevel.MEDIUM_RISK
            threat_type = ThreatType.SUSPICIOUS_BEHAVIOR
            threat_name = "Suspicious Domain"
            confidence = 0.7
            self.scan_stats['suspicious_found'] += 1
        
        # Pattern-based analysis
        else:
            pattern_result = self._analyze_url_patterns(url, parsed_url)
            if pattern_result['risk_level'] > 0:
                if pattern_result['risk_level'] >= 0.7:
                    threat_level = ThreatLevel.HIGH_RISK
                    threat_type = ThreatType.PHISHING
                    threat_name = "Phishing URL Pattern"
                    self.scan_stats['phishing_detected'] += 1
                elif pattern_result['risk_level'] >= 0.4:
                    threat_level = ThreatLevel.MEDIUM_RISK
                    threat_type = ThreatType.SUSPICIOUS_BEHAVIOR
                    threat_name = "Suspicious URL Pattern"
                    self.scan_stats['suspicious_found'] += 1
                else:
                    threat_level = ThreatLevel.SUSPICIOUS
                    threat_type = ThreatType.SUSPICIOUS_BEHAVIOR
                    threat_name = "Potentially Suspicious URL"
                
                confidence = pattern_result['risk_level']
                details.update(pattern_result['details'])
        
        # Domain reputation check
        reputation_result = await self._check_domain_reputation(domain)
        if reputation_result:
            details['domain_reputation'] = reputation_result
            if reputation_result['reputation_score'] < 30:  # Low reputation
                threat_level = max(threat_level, ThreatLevel.MEDIUM_RISK)
                confidence = max(confidence, 0.6)
        
        # Create scan result
        result = ScanResult(
            file_path=url,
            file_hash=url_hash,
            threat_level=threat_level,
            threat_type=threat_type,
            threat_name=threat_name,
            scan_type=ScanType.LINK_SCAN,
            scan_duration=(datetime.now(timezone.utc) - start_time).total_seconds(),
            detected_at=start_time,
            confidence_score=confidence,
            details=details
        )
        
        # Cache the result
        await self._cache_url_result(result)
        
        # Update statistics
        self.scan_stats['total_urls_scanned'] += 1
        
        logger.debug(f"URL scan completed: {url} - {threat_level.name}")
        return result

    def _analyze_url_patterns(self, url: str, parsed_url) -> Dict[str, Any]:
        """Analyze URL for suspicious patterns."""
        risk_level = 0.0
        details = {}
        
        domain = parsed_url.netloc.lower()
        path = parsed_url.path.lower()
        query = parsed_url.query.lower()
        
        # Check for IP address instead of domain
        if self.suspicious_patterns[0].match(domain):
            risk_level += 0.4
            details['ip_address_domain'] = True
        
        # Check for long random domain names
        if self.suspicious_patterns[1].match(domain):
            risk_level += 0.3
            details['random_domain'] = True
        
        # Check for multiple hyphens
        if self.suspicious_patterns[2].search(domain):
            risk_level += 0.2
            details['multiple_hyphens'] = True
        
        # Check for phishing patterns
        if self.suspicious_patterns[3].search(domain):
            risk_level += 0.6
            details['phishing_pattern'] = True
        
        # Check for mixed numbers and letters
        if self.suspicious_patterns[4].search(domain):
            risk_level += 0.2
            details['mixed_chars'] = True
        
        # Check for brand impersonation
        if self.suspicious_patterns[5].search(domain):
            risk_level += 0.5
            details['brand_impersonation'] = True
        
        # Check TLD
        tld = '.' + domain.split('.')[-1] if '.' in domain else ''
        if tld in self.suspicious_tlds:
            risk_level += 0.3
            details['suspicious_tld'] = tld
        elif tld in self.safe_tlds:
            risk_level = max(0, risk_level - 0.1)
            details['safe_tld'] = tld
        
        # Check for phishing keywords in path/query
        phishing_keyword_count = 0
        for keyword in self.phishing_keywords:
            if keyword in path or keyword in query:
                phishing_keyword_count += 1
        
        if phishing_keyword_count >= 2:
            risk_level += 0.4
            details['phishing_keywords'] = phishing_keyword_count
        elif phishing_keyword_count == 1:
            risk_level += 0.2
            details['phishing_keywords'] = phishing_keyword_count
        
        # Check URL length (very long URLs can be suspicious)
        if len(url) > 200:
            risk_level += 0.1
            details['excessive_length'] = True
        
        # Check for URL encoding tricks
        if '%' in url and url.count('%') > 5:
            risk_level += 0.2
            details['excessive_encoding'] = True
        
        return {
            'risk_level': min(1.0, risk_level),
            'details': details
        }

    async def _expand_shortened_url(self, url: str) -> Optional[str]:
        """Expand shortened URLs to get the real destination."""
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                async with session.head(url, allow_redirects=True) as response:
                    return str(response.url)
        except Exception as e:
            logger.debug(f"Failed to expand shortened URL {url}: {e}")
            return None

    async def _check_url_cache(self, url_hash: str) -> Optional[ScanResult]:
        """Check if URL scan result is cached and still valid."""
        try:
            async with aiosqlite.connect(self.link_db_path) as db:
                async with db.execute("""
                    SELECT url, threat_level, threat_type, threat_name,
                           confidence_score, scan_details, scanned_at, expires_at
                    FROM url_scans
                    WHERE url_hash = ? AND (expires_at IS NULL OR expires_at > ?)
                    ORDER BY scanned_at DESC LIMIT 1
                """, (url_hash, datetime.now(timezone.utc).isoformat())) as cursor:
                    row = await cursor.fetchone()

                    if row:
                        return ScanResult(
                            file_path=row[0],
                            file_hash=url_hash,
                            threat_level=ThreatLevel[row[1]],
                            threat_type=ThreatType[row[2]] if row[2] else None,
                            threat_name=row[3],
                            scan_type=ScanType.LINK_SCAN,
                            scan_duration=0.0,
                            detected_at=datetime.fromisoformat(row[6]),
                            confidence_score=row[4],
                            details=json.loads(row[5]) if row[5] else {}
                        )
            return None
        except Exception as e:
            logger.error(f"Failed to check URL cache: {e}")
            return None

    async def _cache_url_result(self, result: ScanResult):
        """Cache URL scan result."""
        try:
            # Cache for 24 hours for clean URLs, 1 hour for suspicious/malicious
            cache_hours = 24 if result.threat_level == ThreatLevel.CLEAN else 1
            expires_at = datetime.now(timezone.utc) + timedelta(hours=cache_hours)

            async with aiosqlite.connect(self.link_db_path) as db:
                await db.execute("""
                    INSERT OR REPLACE INTO url_scans
                    (url, url_hash, domain, threat_level, threat_type, threat_name,
                     confidence_score, scan_details, scanned_at, expires_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    result.file_path,
                    result.file_hash,
                    result.details.get('domain', ''),
                    result.threat_level.name,
                    result.threat_type.name if result.threat_type else None,
                    result.threat_name,
                    result.confidence_score,
                    json.dumps(result.details),
                    result.detected_at.isoformat(),
                    expires_at.isoformat()
                ))
                await db.commit()
        except Exception as e:
            logger.error(f"Failed to cache URL result: {e}")

    async def _check_domain_reputation(self, domain: str) -> Optional[Dict[str, Any]]:
        """Check domain reputation from database."""
        try:
            async with aiosqlite.connect(self.link_db_path) as db:
                async with db.execute("""
                    SELECT reputation_score, category, threat_indicators, updated_at
                    FROM domain_reputation WHERE domain = ?
                """, (domain,)) as cursor:
                    row = await cursor.fetchone()

                    if row:
                        return {
                            'reputation_score': row[0],
                            'category': row[1],
                            'threat_indicators': json.loads(row[2]) if row[2] else [],
                            'last_updated': row[3]
                        }
            return None
        except Exception as e:
            logger.error(f"Failed to check domain reputation: {e}")
            return None

    async def _load_domain_lists(self):
        """Load known malicious and suspicious domains from database."""
        try:
            async with aiosqlite.connect(self.link_db_path) as db:
                # Load malicious domains
                async with db.execute("SELECT domain FROM malicious_domains") as cursor:
                    async for row in cursor:
                        self.malicious_domains.add(row[0])

                # Load domains with low reputation as suspicious
                async with db.execute("""
                    SELECT domain FROM domain_reputation
                    WHERE reputation_score < 50 AND reputation_score >= 20
                """) as cursor:
                    async for row in cursor:
                        self.suspicious_domains.add(row[0])

                # Load domains with high reputation as safe
                async with db.execute("""
                    SELECT domain FROM domain_reputation
                    WHERE reputation_score >= 80
                """) as cursor:
                    async for row in cursor:
                        self.safe_domains.add(row[0])

            logger.info(f"Loaded {len(self.malicious_domains)} malicious domains, "
                       f"{len(self.suspicious_domains)} suspicious domains, "
                       f"{len(self.safe_domains)} safe domains")
        except Exception as e:
            logger.error(f"Failed to load domain lists: {e}")

    async def _load_scan_statistics(self):
        """Load scan statistics from database."""
        try:
            async with aiosqlite.connect(self.link_db_path) as db:
                # Total URLs scanned
                async with db.execute("SELECT COUNT(*) FROM url_scans") as cursor:
                    row = await cursor.fetchone()
                    self.scan_stats['total_urls_scanned'] = row[0] if row else 0

                # Malicious URLs found
                async with db.execute("""
                    SELECT COUNT(*) FROM url_scans WHERE threat_level = 'HIGH_RISK'
                """) as cursor:
                    row = await cursor.fetchone()
                    self.scan_stats['malicious_found'] = row[0] if row else 0

                # Suspicious URLs found
                async with db.execute("""
                    SELECT COUNT(*) FROM url_scans
                    WHERE threat_level IN ('MEDIUM_RISK', 'SUSPICIOUS')
                """) as cursor:
                    row = await cursor.fetchone()
                    self.scan_stats['suspicious_found'] = row[0] if row else 0

                # Phishing URLs detected
                async with db.execute("""
                    SELECT COUNT(*) FROM url_scans WHERE threat_type = 'PHISHING'
                """) as cursor:
                    row = await cursor.fetchone()
                    self.scan_stats['phishing_detected'] = row[0] if row else 0

        except Exception as e:
            logger.error(f"Failed to load scan statistics: {e}")

    def _create_error_result(self, url: str, error_message: str, start_time: datetime) -> ScanResult:
        """Create an error scan result."""
        return ScanResult(
            file_path=url,
            file_hash="",
            threat_level=ThreatLevel.CLEAN,
            threat_type=None,
            threat_name=None,
            scan_type=ScanType.LINK_SCAN,
            scan_duration=(datetime.now(timezone.utc) - start_time).total_seconds(),
            detected_at=start_time,
            confidence_score=0.0,
            details={"error": error_message}
        )

    async def add_malicious_domain(self, domain: str, threat_type: str = "malware",
                                 source: str = "manual", confidence: int = 90):
        """Add a domain to the malicious domains list."""
        try:
            async with aiosqlite.connect(self.link_db_path) as db:
                await db.execute("""
                    INSERT OR REPLACE INTO malicious_domains
                    (domain, threat_type, source, confidence, added_at)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    domain.lower(),
                    threat_type,
                    source,
                    confidence,
                    datetime.now(timezone.utc).isoformat()
                ))
                await db.commit()

            self.malicious_domains.add(domain.lower())
            logger.info(f"Added malicious domain: {domain}")
        except Exception as e:
            logger.error(f"Failed to add malicious domain {domain}: {e}")

    async def update_domain_reputation(self, domain: str, reputation_score: int,
                                     category: str = "unknown", threat_indicators: Optional[List[str]] = None):
        """Update domain reputation information."""
        try:
            async with aiosqlite.connect(self.link_db_path) as db:
                await db.execute("""
                    INSERT OR REPLACE INTO domain_reputation
                    (domain, reputation_score, category, last_seen, threat_indicators, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    domain.lower(),
                    reputation_score,
                    category,
                    datetime.now(timezone.utc).isoformat(),
                    json.dumps(threat_indicators or []),
                    datetime.now(timezone.utc).isoformat()
                ))
                await db.commit()

            # Update in-memory sets
            if reputation_score < 20:
                self.malicious_domains.add(domain.lower())
            elif reputation_score < 50:
                self.suspicious_domains.add(domain.lower())
            elif reputation_score >= 80:
                self.safe_domains.add(domain.lower())

        except Exception as e:
            logger.error(f"Failed to update domain reputation for {domain}: {e}")

    def get_scan_statistics(self) -> Dict[str, Any]:
        """Get link scanning statistics."""
        return {
            'total_urls_scanned': self.scan_stats['total_urls_scanned'],
            'malicious_found': self.scan_stats['malicious_found'],
            'suspicious_found': self.scan_stats['suspicious_found'],
            'phishing_detected': self.scan_stats['phishing_detected'],
            'shortened_urls_expanded': self.scan_stats['shortened_urls_expanded'],
            'cache_hits': self.scan_stats['cache_hits'],
            'malicious_domains_count': len(self.malicious_domains),
            'suspicious_domains_count': len(self.suspicious_domains),
            'safe_domains_count': len(self.safe_domains),
            'detection_rate': (
                (self.scan_stats['malicious_found'] + self.scan_stats['suspicious_found']) /
                max(1, self.scan_stats['total_urls_scanned'])
            ) * 100
        }
