"""
Threat Intelligence Engine

Manages threat intelligence feeds, updates virus databases, and provides
real-time threat information for the antivirus system.
"""

import asyncio
import logging
import json
import aiohttp
import aiosqlite
import hashlib
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set, Any, Tuple
import gzip
import csv

from . import ThreatLevel, ThreatType, ThreatSignature

logger = logging.getLogger(__name__)


class ThreatIntelligenceEngine:
    """
    Threat intelligence engine that manages:
    - Virus signature databases
    - Threat intelligence feeds
    - Community threat reports
    - Real-time threat updates
    - Threat correlation and analysis
    """
    
    def __init__(self, data_dir: Path):
        self.data_dir = Path(data_dir)
        self.threat_db_path = self.data_dir / "threat_intelligence.db"
        self.signatures_dir = self.data_dir / "signatures"
        self.signatures_dir.mkdir(parents=True, exist_ok=True)
        
        # Threat intelligence feeds (would be configured with real feeds)
        self.threat_feeds = {
            'malware_bazaar': {
                'url': 'https://bazaar.abuse.ch/export/csv/recent/',
                'format': 'csv',
                'enabled': False,  # Disabled by default
                'update_interval': 3600  # 1 hour
            },
            'urlhaus': {
                'url': 'https://urlhaus.abuse.ch/downloads/csv_recent/',
                'format': 'csv',
                'enabled': False,
                'update_interval': 1800  # 30 minutes
            },
            'threatfox': {
                'url': 'https://threatfox.abuse.ch/export/csv/recent/',
                'format': 'csv',
                'enabled': False,
                'update_interval': 3600
            }
        }
        
        # Local threat signatures
        self.threat_signatures: Dict[str, ThreatSignature] = {}
        self.hash_signatures: Dict[str, ThreatSignature] = {}
        self.url_signatures: Dict[str, ThreatSignature] = {}
        
        # Statistics
        self.intelligence_stats = {
            'total_signatures': 0,
            'hash_signatures': 0,
            'url_signatures': 0,
            'last_update': None,
            'feeds_updated': 0,
            'threats_detected': 0,
            'false_positives': 0
        }
        
        self._initialized = False
        self._update_tasks: List[asyncio.Task] = []

    async def initialize(self):
        """Initialize the threat intelligence engine."""
        if self._initialized:
            return
        
        logger.info("Initializing Threat Intelligence Engine")
        
        # Initialize database
        await self._initialize_database()
        
        # Load existing signatures
        await self._load_threat_signatures()
        
        # Load statistics
        await self._load_intelligence_statistics()
        
        # Start background update tasks
        for feed_name, feed_config in self.threat_feeds.items():
            if feed_config['enabled']:
                task = asyncio.create_task(self._feed_update_task(feed_name, feed_config))
                self._update_tasks.append(task)
        
        self._initialized = True
        logger.info("Threat Intelligence Engine initialized")

    async def _initialize_database(self):
        """Initialize the threat intelligence database."""
        async with aiosqlite.connect(self.threat_db_path) as db:
            # Threat signatures table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS threat_signatures (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    signature_id TEXT UNIQUE NOT NULL,
                    signature_type TEXT NOT NULL,
                    threat_name TEXT NOT NULL,
                    threat_type TEXT NOT NULL,
                    threat_level TEXT NOT NULL,
                    hash_value TEXT,
                    url_pattern TEXT,
                    file_pattern TEXT,
                    confidence_score REAL,
                    source TEXT,
                    description TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)
            
            # Threat intelligence feeds table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS threat_feeds (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    feed_name TEXT NOT NULL,
                    feed_url TEXT,
                    last_update TEXT,
                    update_status TEXT,
                    records_processed INTEGER DEFAULT 0,
                    errors_count INTEGER DEFAULT 0,
                    next_update TEXT
                )
            """)
            
            # Threat detections table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS threat_detections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    signature_id TEXT NOT NULL,
                    target_hash TEXT,
                    target_url TEXT,
                    detection_time TEXT NOT NULL,
                    confidence_score REAL,
                    false_positive BOOLEAN DEFAULT FALSE,
                    verified BOOLEAN DEFAULT FALSE
                )
            """)
            
            await db.commit()

    async def check_hash_threat(self, file_hash: str) -> Optional[ThreatSignature]:
        """Check if a file hash matches any known threats."""
        # Check local signatures first
        if file_hash in self.hash_signatures:
            signature = self.hash_signatures[file_hash]
            await self._log_threat_detection(signature.signature_id, target_hash=file_hash)
            return signature
        
        # Check database
        try:
            async with aiosqlite.connect(self.threat_db_path) as db:
                async with db.execute("""
                    SELECT signature_id, threat_name, threat_type, threat_level,
                           confidence_score, source, description
                    FROM threat_signatures 
                    WHERE hash_value = ? AND signature_type = 'hash'
                """, (file_hash,)) as cursor:
                    row = await cursor.fetchone()
                    
                    if row:
                        signature = ThreatSignature(
                            signature_id=row[0],
                            threat_name=row[1],
                            threat_type=ThreatType[row[2]],
                            threat_level=ThreatLevel[row[3]],
                            confidence_score=row[4],
                            source=row[5],
                            description=row[6],
                            hash_value=file_hash
                        )
                        
                        # Cache for future lookups
                        self.hash_signatures[file_hash] = signature
                        
                        await self._log_threat_detection(signature.signature_id, target_hash=file_hash)
                        return signature
        except Exception as e:
            logger.error(f"Failed to check hash threat for {file_hash}: {e}")
        
        return None

    async def check_url_threat(self, url: str) -> Optional[ThreatSignature]:
        """Check if a URL matches any known threats."""
        url_lower = url.lower()
        
        # Check exact URL matches
        if url_lower in self.url_signatures:
            signature = self.url_signatures[url_lower]
            await self._log_threat_detection(signature.signature_id, target_url=url)
            return signature
        
        # Check pattern matches in database
        try:
            async with aiosqlite.connect(self.threat_db_path) as db:
                async with db.execute("""
                    SELECT signature_id, threat_name, threat_type, threat_level,
                           confidence_score, source, description, url_pattern
                    FROM threat_signatures 
                    WHERE signature_type = 'url' AND ? LIKE url_pattern
                    ORDER BY confidence_score DESC LIMIT 1
                """, (url_lower,)) as cursor:
                    row = await cursor.fetchone()
                    
                    if row:
                        signature = ThreatSignature(
                            signature_id=row[0],
                            threat_name=row[1],
                            threat_type=ThreatType[row[2]],
                            threat_level=ThreatLevel[row[3]],
                            confidence_score=row[4],
                            source=row[5],
                            description=row[6],
                            url_pattern=row[7]
                        )
                        
                        await self._log_threat_detection(signature.signature_id, target_url=url)
                        return signature
        except Exception as e:
            logger.error(f"Failed to check URL threat for {url}: {e}")
        
        return None

    async def add_threat_signature(self, signature: ThreatSignature) -> bool:
        """Add a new threat signature to the database."""
        try:
            async with aiosqlite.connect(self.threat_db_path) as db:
                await db.execute("""
                    INSERT OR REPLACE INTO threat_signatures 
                    (signature_id, signature_type, threat_name, threat_type, threat_level,
                     hash_value, url_pattern, file_pattern, confidence_score, source,
                     description, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    signature.signature_id,
                    signature.signature_type,
                    signature.threat_name,
                    signature.threat_type.name,
                    signature.threat_level.name,
                    signature.hash_value,
                    signature.url_pattern,
                    signature.file_pattern,
                    signature.confidence_score,
                    signature.source,
                    signature.description,
                    signature.created_at.isoformat() if signature.created_at else datetime.now(timezone.utc).isoformat(),
                    datetime.now(timezone.utc).isoformat()
                ))
                await db.commit()
            
            # Update in-memory cache
            if signature.hash_value:
                self.hash_signatures[signature.hash_value] = signature
            if signature.url_pattern:
                self.url_signatures[signature.url_pattern.lower()] = signature
            
            self.intelligence_stats['total_signatures'] += 1
            if signature.hash_value:
                self.intelligence_stats['hash_signatures'] += 1
            if signature.url_pattern:
                self.intelligence_stats['url_signatures'] += 1
            
            logger.debug(f"Added threat signature: {signature.signature_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add threat signature {signature.signature_id}: {e}")
            return False

    async def _load_threat_signatures(self):
        """Load threat signatures from database into memory."""
        try:
            async with aiosqlite.connect(self.threat_db_path) as db:
                async with db.execute("""
                    SELECT signature_id, signature_type, threat_name, threat_type, threat_level,
                           hash_value, url_pattern, file_pattern, confidence_score, source,
                           description, created_at
                    FROM threat_signatures
                """) as cursor:
                    async for row in cursor:
                        signature = ThreatSignature(
                            signature_id=row[0],
                            signature_type=row[1],
                            threat_name=row[2],
                            threat_type=ThreatType[row[3]],
                            threat_level=ThreatLevel[row[4]],
                            hash_value=row[5],
                            url_pattern=row[6],
                            file_pattern=row[7],
                            confidence_score=row[8],
                            source=row[9],
                            description=row[10],
                            created_at=datetime.fromisoformat(row[11]) if row[11] else None
                        )
                        
                        self.threat_signatures[signature.signature_id] = signature
                        
                        if signature.hash_value:
                            self.hash_signatures[signature.hash_value] = signature
                        if signature.url_pattern:
                            self.url_signatures[signature.url_pattern.lower()] = signature
            
            logger.info(f"Loaded {len(self.threat_signatures)} threat signatures")
        except Exception as e:
            logger.error(f"Failed to load threat signatures: {e}")

    async def _load_intelligence_statistics(self):
        """Load threat intelligence statistics."""
        try:
            async with aiosqlite.connect(self.threat_db_path) as db:
                # Total signatures
                async with db.execute("SELECT COUNT(*) FROM threat_signatures") as cursor:
                    row = await cursor.fetchone()
                    self.intelligence_stats['total_signatures'] = row[0] if row else 0
                
                # Hash signatures
                async with db.execute("""
                    SELECT COUNT(*) FROM threat_signatures WHERE signature_type = 'hash'
                """) as cursor:
                    row = await cursor.fetchone()
                    self.intelligence_stats['hash_signatures'] = row[0] if row else 0
                
                # URL signatures
                async with db.execute("""
                    SELECT COUNT(*) FROM threat_signatures WHERE signature_type = 'url'
                """) as cursor:
                    row = await cursor.fetchone()
                    self.intelligence_stats['url_signatures'] = row[0] if row else 0
                
                # Last update time
                async with db.execute("""
                    SELECT MAX(last_update) FROM threat_feeds
                """) as cursor:
                    row = await cursor.fetchone()
                    if row and row[0]:
                        self.intelligence_stats['last_update'] = row[0]
                
                # Threat detections
                async with db.execute("SELECT COUNT(*) FROM threat_detections") as cursor:
                    row = await cursor.fetchone()
                    self.intelligence_stats['threats_detected'] = row[0] if row else 0
                
                # False positives
                async with db.execute("""
                    SELECT COUNT(*) FROM threat_detections WHERE false_positive = 1
                """) as cursor:
                    row = await cursor.fetchone()
                    self.intelligence_stats['false_positives'] = row[0] if row else 0
                    
        except Exception as e:
            logger.error(f"Failed to load intelligence statistics: {e}")

    async def _log_threat_detection(self, signature_id: str, target_hash: str = None, target_url: str = None):
        """Log a threat detection."""
        try:
            async with aiosqlite.connect(self.threat_db_path) as db:
                signature = self.threat_signatures.get(signature_id)
                confidence = signature.confidence_score if signature else 0.5
                
                await db.execute("""
                    INSERT INTO threat_detections 
                    (signature_id, target_hash, target_url, detection_time, confidence_score)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    signature_id,
                    target_hash,
                    target_url,
                    datetime.now(timezone.utc).isoformat(),
                    confidence
                ))
                await db.commit()
            
            self.intelligence_stats['threats_detected'] += 1
        except Exception as e:
            logger.error(f"Failed to log threat detection: {e}")

    async def _feed_update_task(self, feed_name: str, feed_config: Dict[str, Any]):
        """Background task to update threat intelligence feeds."""
        while True:
            try:
                await asyncio.sleep(feed_config['update_interval'])
                
                logger.info(f"Updating threat intelligence feed: {feed_name}")
                success = await self._update_threat_feed(feed_name, feed_config)
                
                if success:
                    self.intelligence_stats['feeds_updated'] += 1
                    self.intelligence_stats['last_update'] = datetime.now(timezone.utc).isoformat()
                
            except Exception as e:
                logger.error(f"Error in feed update task for {feed_name}: {e}")

    async def _update_threat_feed(self, feed_name: str, feed_config: Dict[str, Any]) -> bool:
        """Update a specific threat intelligence feed."""
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=300)) as session:
                async with session.get(feed_config['url']) as response:
                    if response.status != 200:
                        logger.error(f"Failed to fetch {feed_name} feed: HTTP {response.status}")
                        return False
                    
                    content = await response.text()
                    
                    # Process based on format
                    if feed_config['format'] == 'csv':
                        processed = await self._process_csv_feed(feed_name, content)
                    else:
                        logger.warning(f"Unsupported feed format: {feed_config['format']}")
                        return False
                    
                    # Update feed status
                    await self._update_feed_status(feed_name, processed, True)
                    
                    logger.info(f"Updated {feed_name} feed: {processed} records processed")
                    return True
                    
        except Exception as e:
            logger.error(f"Failed to update {feed_name} feed: {e}")
            await self._update_feed_status(feed_name, 0, False)
            return False

    async def _process_csv_feed(self, feed_name: str, content: str) -> int:
        """Process CSV format threat intelligence feed."""
        processed_count = 0
        
        try:
            lines = content.strip().split('\n')
            if not lines:
                return 0
            
            # Skip header if present
            if lines[0].startswith('#') or 'hash' in lines[0].lower():
                lines = lines[1:]
            
            for line in lines:
                if not line.strip() or line.startswith('#'):
                    continue
                
                try:
                    # Basic CSV parsing (would need more sophisticated parsing for real feeds)
                    parts = [part.strip('"') for part in line.split(',')]
                    
                    if len(parts) >= 3:
                        # Assume format: hash, threat_name, threat_type
                        hash_value = parts[0].strip()
                        threat_name = parts[1].strip()
                        threat_type_str = parts[2].strip()
                        
                        if hash_value and threat_name:
                            # Map threat type
                            threat_type = ThreatType.MALWARE
                            if 'phish' in threat_type_str.lower():
                                threat_type = ThreatType.PHISHING
                            elif 'trojan' in threat_type_str.lower():
                                threat_type = ThreatType.TROJAN
                            
                            signature = ThreatSignature(
                                signature_id=f"{feed_name}_{hash_value[:16]}",
                                signature_type="hash",
                                threat_name=threat_name,
                                threat_type=threat_type,
                                threat_level=ThreatLevel.HIGH_RISK,
                                hash_value=hash_value,
                                confidence_score=0.8,
                                source=feed_name,
                                description=f"Threat from {feed_name} feed"
                            )
                            
                            await self.add_threat_signature(signature)
                            processed_count += 1
                            
                except Exception as e:
                    logger.debug(f"Failed to process feed line: {line[:100]}... - {e}")
                    continue
            
        except Exception as e:
            logger.error(f"Failed to process CSV feed {feed_name}: {e}")
        
        return processed_count

    async def _update_feed_status(self, feed_name: str, records_processed: int, success: bool):
        """Update feed status in database."""
        try:
            async with aiosqlite.connect(self.threat_db_path) as db:
                now = datetime.now(timezone.utc).isoformat()
                next_update = (datetime.now(timezone.utc) + 
                             timedelta(seconds=self.threat_feeds[feed_name]['update_interval'])).isoformat()
                
                await db.execute("""
                    INSERT OR REPLACE INTO threat_feeds 
                    (feed_name, feed_url, last_update, update_status, records_processed, next_update)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    feed_name,
                    self.threat_feeds[feed_name]['url'],
                    now,
                    'success' if success else 'failed',
                    records_processed,
                    next_update
                ))
                await db.commit()
        except Exception as e:
            logger.error(f"Failed to update feed status for {feed_name}: {e}")

    def get_intelligence_statistics(self) -> Dict[str, Any]:
        """Get threat intelligence statistics."""
        return {
            'total_signatures': self.intelligence_stats['total_signatures'],
            'hash_signatures': self.intelligence_stats['hash_signatures'],
            'url_signatures': self.intelligence_stats['url_signatures'],
            'last_update': self.intelligence_stats['last_update'],
            'feeds_updated': self.intelligence_stats['feeds_updated'],
            'threats_detected': self.intelligence_stats['threats_detected'],
            'false_positives': self.intelligence_stats['false_positives'],
            'active_feeds': len([f for f in self.threat_feeds.values() if f['enabled']]),
            'detection_accuracy': (
                (self.intelligence_stats['threats_detected'] - self.intelligence_stats['false_positives']) /
                max(1, self.intelligence_stats['threats_detected'])
            ) * 100 if self.intelligence_stats['threats_detected'] > 0 else 0
        }

    async def cleanup(self):
        """Cleanup resources and stop background tasks."""
        for task in self._update_tasks:
            task.cancel()
        
        try:
            await asyncio.gather(*self._update_tasks, return_exceptions=True)
        except Exception:
            pass
        
        self._update_tasks.clear()
        logger.info("Threat Intelligence Engine cleanup completed")
