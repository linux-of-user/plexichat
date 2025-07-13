import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Set

import aiosqlite

from . import ScanResult, ScanType, ThreatLevel, ThreatSignature, ThreatType


"""
Hash-Based Scanner

Scans files using hash-based detection against public virus databases
and PlexiChat's internal threat intelligence database.
"""

logger = logging.getLogger(__name__)


class HashBasedScanner:
    """
    Hash-based virus scanner that checks file hashes against:
    - Public virus databases (VirusTotal-like APIs)
    - Internal PlexiChat threat database
    - Community-reported threats
    """
    
    def __init__(self, data_dir: Path):
        self.data_dir = from pathlib import Path
Path(data_dir)
        self.hash_db_path = self.data_dir / "hash_database.db"
        self.known_threats: Dict[str, ThreatSignature] = {}
        self.clean_hashes: Set[str] = set()
        self.suspicious_hashes: Set[str] = set()
        
        # Public API configurations (would need real API keys)
        self.public_apis = {
            'virustotal': {
                'url': 'https://www.virustotal.com/vtapi/v2/file/report',
                'api_key': 'your_virustotal_api_key',
                'enabled': False  # Disabled by default
            },
            'malwarebytes': {
                'url': 'https://api.malwarebytes.com/v1/hash/lookup',
                'api_key': 'your_malwarebytes_api_key', 
                'enabled': False
            }
        }
        
        self.scan_stats = {
            'total_hash_scans': 0,
            'threats_found': 0,
            'api_queries': 0,
            'cache_hits': 0,
            'last_db_update': None
        }
        
        self._initialized = False
    
    async def initialize(self):
        """Initialize hash scanner and database."""
        if self._initialized:
            return
        
        logger.info("Initializing Hash-Based Scanner")
        
        await self._initialize_database()
        await self._load_threat_signatures()
        
        self._initialized = True
        logger.info("Hash-Based Scanner initialized")
    
    async def scan_hash(self, file_hash: str, file_path: str) -> ScanResult:
        """
        Scan a file hash for threats.
        
        Args:
            file_hash: SHA-512 hash of the file
            file_path: Path to the file being scanned
            
        Returns:
            ScanResult with threat detection details
        """
        start_time = datetime.now(timezone.utc)
        
        # Check local database first
        local_result = await self._check_local_database(file_hash)
        if local_result:
            self.scan_stats['cache_hits'] += 1
            return self._create_scan_result(file_path, file_hash, local_result, start_time)
        
        # Check public APIs if enabled
        api_result = await self._check_public_apis(file_hash)
        if api_result:
            # Cache the result
            await self._cache_threat_result(file_hash, api_result)
            return self._create_scan_result(file_path, file_hash, api_result, start_time)
        
        # Check PlexiChat community database
        community_result = await self._check_community_database(file_hash)
        if community_result:
            return self._create_scan_result(file_path, file_hash, community_result, start_time)
        
        # Hash not found in any database - mark as clean
        await self._mark_hash_clean(file_hash)
        
        self.scan_stats['total_hash_scans'] += 1
        
        return ScanResult(
            file_path=file_path,
            file_hash=file_hash,
            threat_level=ThreatLevel.CLEAN,
            threat_type=None,
            threat_name=None,
            scan_type=ScanType.HASH_SCAN,
            scan_duration=(datetime.now(timezone.utc) - start_time).total_seconds(),
            detected_at=start_time,
            confidence_score=0.9,
            details={"hash_status": "clean", "databases_checked": ["local", "public", "community"]}
        )
    
    async def update_database(self) -> bool:
        """Update hash database from various sources."""
        logger.info("Updating hash database")
        
        try:
            updated = False
            
            # Update from public feeds (if available)
            if await self._update_from_public_feeds():
                updated = True
            
            # Update from PlexiChat network
            if await self._update_from_plexichat_network():
                updated = True
            
            # Clean old entries
            await self._cleanup_old_entries()
            
            if updated:
                self.scan_stats['last_db_update'] = datetime.now(timezone.utc).isoformat()
                logger.info("Hash database updated successfully")
            
            return updated
            
        except Exception as e:
            logger.error(f"Failed to update hash database: {e}")
            return False
    
    async def report_threat(self, file_hash: str, threat_name: str, threat_type: ThreatType, 
                          confidence: float = 0.8) -> bool:
        """Report a new threat to the community database."""
        try:
            signature = ThreatSignature(
                signature_id=f"community_{file_hash[:16]}",
                threat_name=threat_name,
                threat_type=threat_type,
                hash_md5=None,
                hash_sha256=None,
                hash_sha512=file_hash,
                pattern=None,
                description=f"Community reported threat: {threat_name}",
                severity=ThreatLevel.MEDIUM_RISK,
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc)
            )
            
            await self._save_threat_signature(signature)
            self.known_threats[file_hash] = signature
            
            logger.info(f"Threat reported to community database: {threat_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to report threat: {e}")
            return False
    
    async def get_statistics(self) -> Dict[str, Any]:
        """Get hash scanner statistics."""
        return {
            **self.scan_stats,
            'known_threats': len(self.known_threats),
            'clean_hashes': len(self.clean_hashes),
            'suspicious_hashes': len(self.suspicious_hashes)
        }
    
    async def _initialize_database(self):
        """Initialize hash database."""
        async with aiosqlite.connect(self.hash_db_path) as db:
            # Threat signatures table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS threat_signatures (
                    signature_id TEXT PRIMARY KEY,
                    threat_name TEXT NOT NULL,
                    threat_type TEXT NOT NULL,
                    hash_md5 TEXT,
                    hash_sha256 TEXT,
                    hash_sha512 TEXT,
                    pattern TEXT,
                    description TEXT,
                    severity INTEGER NOT NULL,
                    confidence REAL DEFAULT 0.8,
                    source TEXT DEFAULT 'unknown',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)
            
            # Clean hashes table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS clean_hashes (
                    hash_value TEXT PRIMARY KEY,
                    verified_at TEXT NOT NULL,
                    verification_source TEXT,
                    scan_count INTEGER DEFAULT 1
                )
            """)
            
            # Hash scan history
            await db.execute("""
                CREATE TABLE IF NOT EXISTS hash_scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_hash TEXT NOT NULL,
                    scan_result TEXT NOT NULL,
                    threat_detected BOOLEAN DEFAULT FALSE,
                    scanned_at TEXT NOT NULL,
                    source_api TEXT
                )
            """)
            
            await db.commit()
    
    async def _load_threat_signatures(self):
        """Load threat signatures from database."""
        async with aiosqlite.connect(self.hash_db_path) as db:
            async with db.execute("""
                SELECT signature_id, threat_name, threat_type, hash_md5, hash_sha256, 
                       hash_sha512, pattern, description, severity, created_at, updated_at
                FROM threat_signatures
            """) as cursor:
                async for row in cursor:
                    signature = ThreatSignature(
                        signature_id=row[0],
                        threat_name=row[1],
                        threat_type=ThreatType(row[2]),
                        hash_md5=row[3],
                        hash_sha256=row[4],
                        hash_sha512=row[5],
                        pattern=row[6],
                        description=row[7],
                        severity=ThreatLevel(row[8]),
                        created_at=datetime.fromisoformat(row[9]),
                        updated_at=datetime.fromisoformat(row[10])
                    )
                    
                    # Index by all available hashes
                    for hash_val in [row[3], row[4], row[5]]:
                        if hash_val:
                            self.known_threats[hash_val] = signature
        
        # Load clean hashes
        async with aiosqlite.connect(self.hash_db_path) as db:
            async with db.execute("SELECT hash_value FROM clean_hashes") as cursor:
                async for row in cursor:
                    self.clean_hashes.add(row[0])
        
        logger.info(f"Loaded {len(self.known_threats)} threat signatures and {len(self.clean_hashes)} clean hashes")
    
    async def _check_local_database(self, file_hash: str) -> Optional[ThreatSignature]:
        """Check local threat database."""
        return self.known_threats.get(file_hash)
    
    async def _check_public_apis(self, file_hash: str) -> Optional[ThreatSignature]:
        """Check public virus databases via APIs."""
        for api_name, api_config in self.public_apis.items():
            if not api_config['enabled']:
                continue
            
            try:
                result = await self._query_public_api(api_name, api_config, file_hash)
                if result:
                    self.scan_stats['api_queries'] += 1
                    return result
            except Exception as e:
                logger.warning(f"Failed to query {api_name} API: {e}")
        
        return None
