import asyncio
import hashlib
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import aiofiles
import aiosqlite

from . import MAX_FILE_SIZE_SCAN, SUSPICIOUS_EXTENSIONS, ScanResult, ScanType, ThreatLevel
from .behavioral_analyzer import BehavioralAnalyzer
from .filename_analyzer import FilenameAnalyzer
from .hash_scanner import HashBasedScanner
from .link_scanner import LinkSafetyScanner
from .threat_intelligence import ThreatIntelligenceEngine

from pathlib import Path
from pathlib import Path
from pathlib import Path

from pathlib import Path
from pathlib import Path
from pathlib import Path

"""
Advanced Antivirus Engine

Main antivirus engine that coordinates all scanning components
and provides comprehensive threat detection capabilities.
"""

logger = logging.getLogger(__name__)


class AdvancedAntivirusEngine:
    """
    Advanced antivirus engine with multiple detection methods.
    
    Features:
    - Hash-based detection against public databases
    - Behavioral analysis and heuristics
    - Link safety checking
    - Filename pattern analysis
    - Real-time threat intelligence
    - Quarantine and cleanup capabilities
    """
    
    def __init__(self, data_dir: Path):
        self.data_dir = from pathlib import Path
Path(data_dir)
        self.antivirus_dir = self.data_dir / "antivirus"
        self.quarantine_dir = self.antivirus_dir / "quarantine"
        self.db_path = self.antivirus_dir / "antivirus.db"
        
        # Create directories
        self.antivirus_dir.mkdir(parents=True, exist_ok=True)
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize scanning components
        self.hash_scanner = HashBasedScanner(self.antivirus_dir)
        self.behavioral_analyzer = BehavioralAnalyzer(self.antivirus_dir)
        self.link_scanner = LinkSafetyScanner(self.antivirus_dir)
        self.filename_analyzer = FilenameAnalyzer()
        self.threat_intelligence = ThreatIntelligenceEngine(self.antivirus_dir)
        
        # Scan statistics
        self.scan_stats = {
            'total_scans': 0,
            'threats_detected': 0,
            'files_quarantined': 0,
            'false_positives': 0,
            'last_update': None
        }
        
        self._initialized = False
    
    async def initialize(self):
        """Initialize the antivirus engine and all components."""
        if self._initialized:
            return
        
        logger.info("Initializing Advanced Antivirus Engine")
        
        # Initialize database
        await self._initialize_database()
        
        # Initialize all scanning components
        await self.hash_scanner.initialize()
        await self.behavioral_analyzer.initialize()
        await self.link_scanner.initialize()
        await self.threat_intelligence.initialize()
        
        # Load scan statistics
        await self._load_scan_statistics()
        
        # Start background tasks
        asyncio.create_task(self._background_update_task())
        
        self._initialized = True
        logger.info("Advanced Antivirus Engine initialized successfully")
    
    async def scan_file(self, file_path: str, scan_type: ScanType = ScanType.FULL_SCAN) -> ScanResult:
        """
        Perform comprehensive scan of a file.
        
        Args:
            file_path: Path to file to scan
            scan_type: Type of scan to perform
            
        Returns:
            ScanResult with detection details
        """
        start_time = time.time()
        file_path = from pathlib import Path
Path(file_path)
        
        logger.debug(f"Scanning file: {file_path} with {scan_type.value} scan")
        
        # Basic file checks
        if not file_path.exists():
            return self._create_error_result(str(file_path), "File not found", start_time)
        
        if file_path.stat().st_size > MAX_FILE_SIZE_SCAN:
            return self._create_warning_result(
                str(file_path), 
                f"File too large for scanning ({file_path.stat().st_size} bytes)", 
                start_time
            )
        
        # Calculate file hash
        file_hash = await self._calculate_file_hash(file_path)
        
        # Perform different types of scans based on scan_type
        scan_results = []
        
        if scan_type in [ScanType.FULL_SCAN, ScanType.HASH_SCAN]:
            # Hash-based scanning
            hash_result = await self.hash_scanner.scan_hash(file_hash, str(file_path))
            scan_results.append(hash_result)
        
        if scan_type in [ScanType.FULL_SCAN, ScanType.FILENAME_SCAN]:
            # Filename analysis
            filename_result = await self.filename_analyzer.analyze_filename(str(file_path))
            scan_results.append(filename_result)
        
        if scan_type in [ScanType.FULL_SCAN, ScanType.BEHAVIORAL_SCAN]:
            # Behavioral analysis (for executable files)
            if file_path.suffix.lower() in SUSPICIOUS_EXTENSIONS:
                behavioral_result = await self.behavioral_analyzer.analyze_file(str(file_path))
                scan_results.append(behavioral_result)
        
        # Combine results and determine final threat level
        final_result = self._combine_scan_results(scan_results, file_hash, start_time)
        
        # Handle threats
        if final_result.threat_level.value >= ThreatLevel.MEDIUM_RISK.value:
            await self._handle_threat(final_result)
        
        # Update statistics
        await self._update_scan_statistics(final_result)
        
        # Log scan to database
        await self._log_scan_result(final_result)
        
        scan_duration = time.time() - start_time
        final_result.scan_duration = scan_duration
        
        logger.info(f"Scan completed: {file_path} - {final_result.threat_level.name} in {scan_duration:.2f}s")
        return final_result
    
    async def scan_link(self, url: str) -> ScanResult:
        """Scan a URL for safety."""
        start_time = time.time()
        logger.debug(f"Scanning link: {url}")
        
        result = await self.link_scanner.scan_url(url)
        result.scan_duration = time.time() - start_time
        
        await self._update_scan_statistics(result)
        await self._log_scan_result(result)
        
        return result
    
    async def get_scan_statistics(self) -> Dict[str, Any]:
        """Get comprehensive scan statistics."""
        return {
            **self.scan_stats,
            'hash_scanner_stats': await self.hash_scanner.get_statistics(),
            'behavioral_stats': await self.behavioral_analyzer.get_statistics(),
            'link_scanner_stats': await self.link_scanner.get_statistics(),
            'threat_intel_stats': await self.threat_intelligence.get_statistics()
        }
    
    async def update_threat_databases(self) -> bool:
        """Update all threat databases."""
        logger.info("Updating threat databases")
        
        try:
            # Update hash database
            hash_updated = await self.hash_scanner.update_database()
            
            # Update threat intelligence
            intel_updated = await self.threat_intelligence.update_feeds()
            
            # Update behavioral patterns
            behavioral_updated = await self.behavioral_analyzer.update_patterns()
            
            self.scan_stats['last_update'] = datetime.now(timezone.utc).isoformat()
            
            logger.info(f"Database update completed - Hash: {hash_updated}, Intel: {intel_updated}, Behavioral: {behavioral_updated}")
            return hash_updated or intel_updated or behavioral_updated
            
        except Exception as e:
            logger.error(f"Failed to update threat databases: {e}")
            return False

    async def _initialize_database(self):
        """Initialize antivirus database."""
        async with aiosqlite.connect(self.db_path) as db:
            # Scan results table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS scan_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_path TEXT NOT NULL,
                    file_hash TEXT NOT NULL,
                    threat_level INTEGER NOT NULL,
                    threat_type TEXT,
                    threat_name TEXT,
                    scan_type TEXT NOT NULL,
                    scan_duration REAL NOT NULL,
                    detected_at TEXT NOT NULL,
                    confidence_score REAL NOT NULL,
                    quarantined BOOLEAN DEFAULT FALSE,
                    cleaned BOOLEAN DEFAULT FALSE,
                    details TEXT
                )
            """)

            # Quarantine log table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS quarantine_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_path TEXT NOT NULL,
                    original_location TEXT NOT NULL,
                    quarantine_location TEXT NOT NULL,
                    threat_name TEXT,
                    quarantined_at TEXT NOT NULL,
                    restored_at TEXT,
                    deleted_at TEXT
                )
            """)

            # Statistics table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS scan_statistics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    total_scans INTEGER DEFAULT 0,
                    threats_detected INTEGER DEFAULT 0,
                    files_quarantined INTEGER DEFAULT 0,
                    false_positives INTEGER DEFAULT 0,
                    last_update TEXT,
                    updated_at TEXT NOT NULL
                )
            """)

            await db.commit()

    async def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA-512 hash of file."""
        hash_sha512 = hashlib.sha512()

        async with aiofiles.open(file_path, 'rb') as f:
            while chunk := await f.read(8192):
                hash_sha512.update(chunk)

        return hash_sha512.hexdigest()

    def _create_error_result(self, file_path: str, error_msg: str, start_time: float) -> ScanResult:
        """Create error scan result."""
        return ScanResult(
            file_path=file_path,
            file_hash="",
            threat_level=ThreatLevel.CLEAN,
            threat_type=None,
            threat_name=None,
            scan_type=ScanType.QUICK_SCAN,
            scan_duration=time.time() - start_time,
            detected_at=datetime.now(timezone.utc),
            confidence_score=0.0,
            details={"error": error_msg}
        )

    def _create_warning_result(self, file_path: str, warning_msg: str, start_time: float) -> ScanResult:
        """Create warning scan result."""
        return ScanResult(
            file_path=file_path,
            file_hash="",
            threat_level=ThreatLevel.SUSPICIOUS,
            threat_type=None,
            threat_name=None,
            scan_type=ScanType.QUICK_SCAN,
            scan_duration=time.time() - start_time,
            detected_at=datetime.now(timezone.utc),
            confidence_score=0.3,
            details={"warning": warning_msg}
        )

    def _combine_scan_results(self, results: List[ScanResult], file_hash: str, start_time: float) -> ScanResult:
        """Combine multiple scan results into final result."""
        if not results:
            return ScanResult(
                file_path="unknown",
                file_hash=file_hash,
                threat_level=ThreatLevel.CLEAN,
                threat_type=None,
                threat_name=None,
                scan_type=ScanType.FULL_SCAN,
                scan_duration=time.time() - start_time,
                detected_at=datetime.now(timezone.utc),
                confidence_score=1.0,
                details={"status": "clean"}
            )

        # Find highest threat level
        max_threat_level = max(result.threat_level for result in results)
        highest_threat_result = next(result for result in results if result.threat_level == max_threat_level)

        # Combine confidence scores
        avg_confidence = sum(result.confidence_score for result in results) / len(results)

        # Combine details
        combined_details = {}
        for result in results:
            combined_details.update(result.details)

        return ScanResult(
            file_path=highest_threat_result.file_path,
            file_hash=file_hash,
            threat_level=max_threat_level,
            threat_type=highest_threat_result.threat_type,
            threat_name=highest_threat_result.threat_name,
            scan_type=ScanType.FULL_SCAN,
            scan_duration=time.time() - start_time,
            detected_at=datetime.now(timezone.utc),
            confidence_score=avg_confidence,
            details=combined_details
        )

    async def _handle_threat(self, scan_result: ScanResult):
        """Handle detected threat."""
        if scan_result.threat_level.value >= ThreatLevel.HIGH_RISK.value:
            # Quarantine high-risk files
            await self._quarantine_file(scan_result)

        # Log threat
        logger.warning(f"Threat detected: {scan_result.threat_name} in {scan_result.file_path}")

    async def _quarantine_file(self, scan_result: ScanResult):
        """Quarantine a threatening file."""
        try:
            source_path = from pathlib import Path
Path(scan_result.file_path)
            if not source_path.exists():
                return

            # Create quarantine filename
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            quarantine_filename = f"{timestamp}_{source_path.name}"
            quarantine_path = self.quarantine_dir / quarantine_filename

            # Move file to quarantine
            source_path.rename(quarantine_path)

            # Log quarantine action
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    INSERT INTO quarantine_log
                    (file_path, original_location, quarantine_location, threat_name, quarantined_at)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    source_path.name,
                    str(source_path),
                    str(quarantine_path),
                    scan_result.threat_name,
                    datetime.now(timezone.utc).isoformat()
                ))
                await db.commit()

            scan_result.quarantined = True
            self.scan_stats['files_quarantined'] += 1

            logger.info(f"File quarantined: {source_path} -> {quarantine_path}")

        except Exception as e:
            logger.error(f"Failed to quarantine file {scan_result.file_path}: {e}")

    async def _update_scan_statistics(self, scan_result: ScanResult):
        """Update scan statistics."""
        self.scan_stats['total_scans'] += 1

        if scan_result.threat_level.value >= ThreatLevel.MEDIUM_RISK.value:
            self.scan_stats['threats_detected'] += 1

    async def _log_scan_result(self, scan_result: ScanResult):
        """Log scan result to database."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                INSERT INTO scan_results
                (file_path, file_hash, threat_level, threat_type, threat_name,
                 scan_type, scan_duration, detected_at, confidence_score,
                 quarantined, cleaned, details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_result.file_path,
                scan_result.file_hash,
                scan_result.threat_level.value,
                scan_result.threat_type.value if scan_result.threat_type else None,
                scan_result.threat_name,
                scan_result.scan_type.value,
                scan_result.scan_duration,
                scan_result.detected_at.isoformat(),
                scan_result.confidence_score,
                scan_result.quarantined,
                scan_result.cleaned,
                str(scan_result.details)
            ))
            await db.commit()

    async def _load_scan_statistics(self):
        """Load scan statistics from database."""
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute("""
                SELECT total_scans, threats_detected, files_quarantined,
                       false_positives, last_update
                FROM scan_statistics
                ORDER BY updated_at DESC LIMIT 1
            """) as cursor:
                row = await cursor.fetchone()
                if row:
                    self.scan_stats.update({
                        'total_scans': row[0],
                        'threats_detected': row[1],
                        'files_quarantined': row[2],
                        'false_positives': row[3],
                        'last_update': row[4]
                    })

    async def _background_update_task(self):
        """Background task for updating threat databases."""
        while True:
            try:
                await asyncio.sleep(3600)  # Update every hour
                await self.update_threat_databases()
            except Exception as e:
                logger.error(f"Background update task failed: {e}")
                await asyncio.sleep(300)  # Wait 5 minutes before retry
