import hashlib
import json
import logging
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import aiosqlite
import magic
import pefile

from . import ScanResult, ScanType, ThreatLevel, ThreatType

from pathlib import Path
from pathlib import Path

from pathlib import Path
from pathlib import Path

"""
Behavioral Analyzer

Analyzes file behavior and characteristics to detect suspicious patterns
and potential malware through heuristic analysis.
"""

logger = logging.getLogger(__name__)


class BehavioralAnalyzer:
    """
    Behavioral analysis engine for detecting suspicious file characteristics.
    
    Features:
    - PE file analysis for Windows executables
    - Archive content analysis
    - File entropy analysis
    - Packer detection
    - Suspicious API imports detection
    - File structure anomalies
    """
    
    def __init__(self, data_dir: Path):
        self.from pathlib import Path
data_dir = Path()(data_dir)
        self.behavioral_db_path = self.data_dir / "behavioral_analysis.db"
        
        # Suspicious API imports that malware commonly uses
        self.suspicious_apis = {
            'high_risk': [
                'CreateRemoteThread', 'WriteProcessMemory', 'VirtualAllocEx',
                'SetWindowsHookEx', 'GetProcAddress', 'LoadLibrary',
                'RegCreateKey', 'RegSetValue', 'CreateService',
                'CryptEncrypt', 'CryptDecrypt', 'InternetOpen',
                'URLDownloadToFile', 'WinExec', 'ShellExecute'
            ],
            'medium_risk': [
                'CreateProcess', 'CreateFile', 'WriteFile', 'ReadFile',
                'FindFirstFile', 'GetSystemDirectory', 'GetWindowsDirectory',
                'GetTempPath', 'CreateMutex', 'OpenProcess'
            ]
        }
        
        # Suspicious section names in PE files
        self.suspicious_sections = [
            '.upx0', '.upx1', '.upx2',  # UPX packer
            '.aspack', '.adata',        # ASPack packer
            '.petite', '.pdata',        # PEtite packer
            '.themida', '.winlice',     # Themida/WinLicense
            '.vmp0', '.vmp1',           # VMProtect
            '.enigma1', '.enigma2'      # Enigma Protector
        ]
        
        # File entropy thresholds
        self.entropy_thresholds = {
            'low': 3.0,      # Likely text/data
            'medium': 6.0,   # Compressed/encrypted
            'high': 7.5,     # Highly compressed/encrypted
            'suspicious': 7.8 # Potentially packed/encrypted malware
        }
        
        self.analysis_stats = {
            'total_analyzed': 0,
            'pe_files_analyzed': 0,
            'archives_analyzed': 0,
            'suspicious_found': 0,
            'high_entropy_files': 0,
            'packed_files_detected': 0,
            'suspicious_apis_found': 0
        }
        
        self._initialized = False

    async def initialize(self):
        """Initialize the behavioral analyzer."""
        if self._initialized:
            return
        
        logger.info("Initializing Behavioral Analyzer")
        
        # Initialize database
        await self._initialize_database()
        
        # Load analysis statistics
        await self._load_analysis_statistics()
        
        self._initialized = True
        logger.info("Behavioral Analyzer initialized")

    async def _initialize_database(self):
        """Initialize the behavioral analysis database."""
        async with aiosqlite.connect(self.behavioral_db_path) as db:
            # Behavioral analysis results table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS behavioral_analysis (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_path TEXT NOT NULL,
                    file_hash TEXT NOT NULL,
                    file_type TEXT,
                    file_size INTEGER,
                    entropy_score REAL,
                    is_packed BOOLEAN DEFAULT FALSE,
                    suspicious_apis TEXT,
                    suspicious_sections TEXT,
                    threat_level TEXT NOT NULL,
                    confidence_score REAL,
                    analysis_details TEXT,
                    analyzed_at TEXT NOT NULL
                )
            """)
            
            # PE file analysis table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS pe_analysis (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_hash TEXT NOT NULL,
                    pe_type TEXT,
                    entry_point TEXT,
                    sections_count INTEGER,
                    imports_count INTEGER,
                    exports_count INTEGER,
                    suspicious_imports TEXT,
                    suspicious_sections TEXT,
                    is_packed BOOLEAN DEFAULT FALSE,
                    compiler_info TEXT,
                    analyzed_at TEXT NOT NULL
                )
            """)
            
            await db.commit()

    async def analyze_file(self, file_path: str) -> ScanResult:
        """
        Perform behavioral analysis on a file.
        
        Args:
            file_path: Path to the file to analyze
            
        Returns:
            ScanResult with behavioral analysis results
        """
        start_time = datetime.now(timezone.utc)
        from pathlib import Path

        path = Path()(file_path)
        
        if not path.exists():
            return ScanResult(
                file_path=file_path,
                file_hash="",
                threat_level=ThreatLevel.CLEAN,
                threat_type=None,
                threat_name=None,
                scan_type=ScanType.BEHAVIORAL_SCAN,
                scan_duration=0.0,
                detected_at=start_time,
                confidence_score=0.0,
                details={"error": "File not found"}
            )
        
        logger.debug(f"Performing behavioral analysis on: {file_path}")
        
        # Calculate file hash
        file_hash = await self._calculate_file_hash(path)
        
        # Get file information
        file_info = await self._get_file_info(path)
        
        # Perform different analyses based on file type
        analysis_results = []
        
        # Entropy analysis
        entropy_result = await self._analyze_entropy(path)
        analysis_results.append(entropy_result)
        
        # File type specific analysis
        if file_info['mime_type'].startswith('application/x-executable') or path.suffix.lower() in ['.exe', '.dll', '.sys']:
            pe_result = await self._analyze_pe_file(path)
            if pe_result:
                analysis_results.append(pe_result)
        
        elif file_info['mime_type'].startswith('application/zip') or path.suffix.lower() in ['.zip', '.rar', '.7z']:
            archive_result = await self._analyze_archive(path)
            if archive_result:
                analysis_results.append(archive_result)
        
        # Combine analysis results
        final_result = self._combine_behavioral_results(analysis_results, file_path, file_hash, file_info, start_time)
        
        # Store analysis results
        await self._store_analysis_result(final_result, file_info)
        
        # Update statistics
        self.analysis_stats['total_analyzed'] += 1
        if final_result.threat_level.value > ThreatLevel.CLEAN.value:
            self.analysis_stats['suspicious_found'] += 1
        
        scan_duration = (datetime.now(timezone.utc) - start_time).total_seconds()
        final_result.scan_duration = scan_duration
        
        logger.debug(f"Behavioral analysis completed: {file_path} - {final_result.threat_level.name}")
        return final_result

    async def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA-512 hash of file."""
        hash_sha512 = hashlib.sha512()
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha512.update(chunk)
            return hash_sha512.hexdigest()
        except Exception as e:
            logger.error(f"Failed to calculate hash for {file_path}: {e}")
            return ""

    async def _get_file_info(self, file_path: Path) -> Dict[str, Any]:
        """Get basic file information."""
        try:
            stat_info = file_path.stat()
            
            # Try to get MIME type
            mime_type = "unknown"
            try:
                mime_type = magic.from_file(str(file_path), mime=True)
            except Exception:
                # Fallback to extension-based detection
                ext = file_path.suffix.lower()
                if ext in ['.exe', '.dll', '.sys']:
                    mime_type = 'application/x-executable'
                elif ext in ['.zip']:
                    mime_type = 'application/zip'
                elif ext in ['.txt']:
                    mime_type = 'text/plain'
            
            return {
                'size': stat_info.st_size,
                'mime_type': mime_type,
                'created': datetime.fromtimestamp(stat_info.st_ctime, timezone.utc),
                'modified': datetime.fromtimestamp(stat_info.st_mtime, timezone.utc),
                'permissions': oct(stat_info.st_mode)[-3:]
            }
        except Exception as e:
            logger.error(f"Failed to get file info for {file_path}: {e}")
            return {'size': 0, 'mime_type': 'unknown'}

    async def _analyze_entropy(self, file_path: Path) -> Dict[str, Any]:
        """Analyze file entropy to detect packing/encryption."""
        try:
            with open(file_path, 'rb') as f:
                data = f.read(min(1024 * 1024, file_path.stat().st_size))  # Read up to 1MB
            
            if not data:
                return {'entropy': 0.0, 'risk_level': 'clean'}
            
            # Calculate Shannon entropy
            entropy = self._calculate_shannon_entropy(data)
            
            # Determine risk level based on entropy
            if entropy >= self.entropy_thresholds['suspicious']:
                risk_level = 'high'
                self.analysis_stats['high_entropy_files'] += 1
            elif entropy >= self.entropy_thresholds['high']:
                risk_level = 'medium'
            elif entropy >= self.entropy_thresholds['medium']:
                risk_level = 'low'
            else:
                risk_level = 'clean'
            
            return {
                'entropy': entropy,
                'risk_level': risk_level,
                'analysis_type': 'entropy'
            }
            
        except Exception as e:
            logger.error(f"Failed to analyze entropy for {file_path}: {e}")
            return {'entropy': 0.0, 'risk_level': 'clean', 'error': str(e)}

    def _calculate_shannon_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0
        
        # Count byte frequencies
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * (probability.bit_length() - 1)
        
        return entropy

    async def _analyze_pe_file(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """Analyze PE (Portable Executable) files."""
        try:
            pe = pefile.PE(str(file_path))
            
            analysis = {
                'analysis_type': 'pe_analysis',
                'pe_type': 'unknown',
                'suspicious_imports': [],
                'suspicious_sections': [],
                'is_packed': False,
                'risk_level': 'clean'
            }
            
            # Determine PE type
            if pe.is_exe():
                analysis['pe_type'] = 'executable'
            elif pe.is_dll():
                analysis['pe_type'] = 'dll'
            elif pe.is_driver():
                analysis['pe_type'] = 'driver'
            
            # Check for suspicious imports
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='ignore').lower()
                    for imp in entry.imports:
                        if imp.name:
                            import_name = imp.name.decode('utf-8', errors='ignore')
                            
                            if import_name in self.suspicious_apis['high_risk']:
                                analysis['suspicious_imports'].append(f"{dll_name}:{import_name}")
                                analysis['risk_level'] = 'high'
                            elif import_name in self.suspicious_apis['medium_risk']:
                                analysis['suspicious_imports'].append(f"{dll_name}:{import_name}")
                                if analysis['risk_level'] == 'clean':
                                    analysis['risk_level'] = 'medium'
            
            # Check for suspicious sections
            for section in pe.sections:
                section_name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
                if section_name in self.suspicious_sections:
                    analysis['suspicious_sections'].append(section_name)
                    analysis['is_packed'] = True
                    analysis['risk_level'] = 'high'
            
            # Check for packing indicators
            if self._detect_packing(pe):
                analysis['is_packed'] = True
                if analysis['risk_level'] == 'clean':
                    analysis['risk_level'] = 'medium'
                self.analysis_stats['packed_files_detected'] += 1
            
            if analysis['suspicious_imports']:
                self.analysis_stats['suspicious_apis_found'] += 1
            
            self.analysis_stats['pe_files_analyzed'] += 1
            
            pe.close()
            return analysis
            
        except Exception as e:
            logger.debug(f"PE analysis failed for {file_path}: {e}")
            return None

    def _detect_packing(self, pe) -> bool:
        """Detect if PE file is packed."""
        try:
            # Check entry point in last section (common packing indicator)
            entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            
            for section in pe.sections:
                if (section.VirtualAddress <= entry_point < 
                    section.VirtualAddress + section.Misc_VirtualSize):
                    # Entry point is in this section
                    if section == pe.sections[-1]:  # Last section
                        return True
                    break
            
            # Check for low number of imports (packed files often have few imports)
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                import_count = sum(len(entry.imports) for entry in pe.DIRECTORY_ENTRY_IMPORT)
                if import_count < 10:  # Very few imports
                    return True
            
            # Check section characteristics
            executable_sections = 0
            for section in pe.sections:
                if section.Characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
                    executable_sections += 1
            
            if executable_sections == 1:  # Only one executable section
                return True
            
            return False
            
        except Exception:
            return False

    async def _analyze_archive(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """Analyze archive files for suspicious content."""
        try:
            analysis = {
                'analysis_type': 'archive_analysis',
                'file_count': 0,
                'suspicious_files': [],
                'risk_level': 'clean'
            }
            
            if file_path.suffix.lower() == '.zip':
                with zipfile.ZipFile(file_path, 'r') as zf:
                    file_list = zf.namelist()
                    analysis['file_count'] = len(file_list)
                    
                    for filename in file_list:
                        if self._is_suspicious_archive_file(filename):
                            analysis['suspicious_files'].append(filename)
                            analysis['risk_level'] = 'medium'
            
            self.analysis_stats['archives_analyzed'] += 1
            return analysis
            
        except Exception as e:
            logger.debug(f"Archive analysis failed for {file_path}: {e}")
            return None

    def _is_suspicious_archive_file(self, filename: str) -> bool:
        """Check if archived file is suspicious."""
        lower_name = filename.lower()
        
        # Check for executable files in archives
        suspicious_extensions = ['.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs', '.js']
        for ext in suspicious_extensions:
            if lower_name.endswith(ext):
                return True
        
        # Check for double extensions
        if lower_name.count('.') >= 2:
            return True
        
        return False

    def _combine_behavioral_results(self, analysis_results: List[Dict[str, Any]],
                                  file_path: str, file_hash: str, file_info: Dict[str, Any],
                                  start_time: datetime) -> ScanResult:
        """Combine multiple behavioral analysis results."""
        threat_level = ThreatLevel.CLEAN
        threat_type = None
        threat_name = None
        confidence = 0.1
        details = {}

        # Process each analysis result
        for result in analysis_results:
            risk_level = result.get('risk_level', 'clean')

            if risk_level == 'high':
                threat_level = max(threat_level, ThreatLevel.HIGH_RISK)
                confidence += 0.4
                if result.get('analysis_type') == 'pe_analysis':
                    threat_type = ThreatType.MALWARE
                    threat_name = "Suspicious PE File Characteristics"
                elif result.get('analysis_type') == 'entropy':
                    threat_type = ThreatType.SUSPICIOUS_BEHAVIOR
                    threat_name = "High Entropy Content (Possible Packing/Encryption)"

            elif risk_level == 'medium':
                threat_level = max(threat_level, ThreatLevel.MEDIUM_RISK)
                confidence += 0.3
                if not threat_type:
                    threat_type = ThreatType.SUSPICIOUS_BEHAVIOR
                    threat_name = "Suspicious File Characteristics"

            elif risk_level == 'low':
                threat_level = max(threat_level, ThreatLevel.SUSPICIOUS)
                confidence += 0.2

            # Add specific details
            if result.get('analysis_type') == 'entropy':
                details['entropy_score'] = result.get('entropy', 0.0)
            elif result.get('analysis_type') == 'pe_analysis':
                details['pe_analysis'] = {
                    'pe_type': result.get('pe_type'),
                    'is_packed': result.get('is_packed', False),
                    'suspicious_imports_count': len(result.get('suspicious_imports', [])),
                    'suspicious_sections_count': len(result.get('suspicious_sections', []))
                }
            elif result.get('analysis_type') == 'archive_analysis':
                details['archive_analysis'] = {
                    'file_count': result.get('file_count', 0),
                    'suspicious_files_count': len(result.get('suspicious_files', []))
                }

        # Add file information to details
        details['file_info'] = file_info

        # Ensure confidence doesn't exceed 1.0
        confidence = min(1.0, confidence)

        return ScanResult(
            file_path=file_path,
            file_hash=file_hash,
            threat_level=threat_level,
            threat_type=threat_type,
            threat_name=threat_name,
            scan_type=ScanType.BEHAVIORAL_SCAN,
            scan_duration=0.0,  # Will be set later
            detected_at=start_time,
            confidence_score=confidence,
            details=details
        )

    async def _store_analysis_result(self, result: ScanResult, file_info: Dict[str, Any]):
        """Store behavioral analysis result in database."""
        try:
            async with aiosqlite.connect(self.behavioral_db_path) as db:
                await db.execute("""
                    INSERT INTO behavioral_analysis
                    (file_path, file_hash, file_type, file_size, entropy_score,
                     is_packed, suspicious_apis, suspicious_sections, threat_level,
                     confidence_score, analysis_details, analyzed_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    result.file_path,
                    result.file_hash,
                    file_info.get('mime_type', 'unknown'),
                    file_info.get('size', 0),
                    result.details.get('entropy_score', 0.0),
                    result.details.get('pe_analysis', {}).get('is_packed', False),
                    json.dumps(result.details.get('pe_analysis', {}).get('suspicious_imports', [])),
                    json.dumps(result.details.get('pe_analysis', {}).get('suspicious_sections', [])),
                    result.threat_level.name,
                    result.confidence_score,
                    json.dumps(result.details),
                    result.detected_at.isoformat()
                ))
                await db.commit()
        except Exception as e:
            logger.error(f"Failed to store behavioral analysis result: {e}")

    async def _load_analysis_statistics(self):
        """Load analysis statistics from database."""
        try:
            async with aiosqlite.connect(self.behavioral_db_path) as db:
                # Total analyzed files
                async with db.execute("SELECT COUNT(*) FROM behavioral_analysis") as cursor:
                    row = await cursor.fetchone()
                    self.analysis_stats['total_analyzed'] = row[0] if row else 0

                # PE files analyzed
                async with db.execute("""
                    SELECT COUNT(*) FROM behavioral_analysis
                    WHERE file_type LIKE '%executable%'
                """) as cursor:
                    row = await cursor.fetchone()
                    self.analysis_stats['pe_files_analyzed'] = row[0] if row else 0

                # Archives analyzed
                async with db.execute("""
                    SELECT COUNT(*) FROM behavioral_analysis
                    WHERE file_type LIKE '%zip%' OR file_type LIKE '%archive%'
                """) as cursor:
                    row = await cursor.fetchone()
                    self.analysis_stats['archives_analyzed'] = row[0] if row else 0

                # Suspicious files found
                async with db.execute("""
                    SELECT COUNT(*) FROM behavioral_analysis
                    WHERE threat_level != 'CLEAN'
                """) as cursor:
                    row = await cursor.fetchone()
                    self.analysis_stats['suspicious_found'] = row[0] if row else 0

                # High entropy files
                async with db.execute("""
                    SELECT COUNT(*) FROM behavioral_analysis
                    WHERE entropy_score >= ?
                """, (self.entropy_thresholds['suspicious'],)) as cursor:
                    row = await cursor.fetchone()
                    self.analysis_stats['high_entropy_files'] = row[0] if row else 0

                # Packed files
                async with db.execute("""
                    SELECT COUNT(*) FROM behavioral_analysis
                    WHERE is_packed = 1
                """) as cursor:
                    row = await cursor.fetchone()
                    self.analysis_stats['packed_files_detected'] = row[0] if row else 0

        except Exception as e:
            logger.error(f"Failed to load analysis statistics: {e}")

    def get_analysis_statistics(self) -> Dict[str, Any]:
        """Get behavioral analysis statistics."""
        return {
            'total_analyzed': self.analysis_stats['total_analyzed'],
            'pe_files_analyzed': self.analysis_stats['pe_files_analyzed'],
            'archives_analyzed': self.analysis_stats['archives_analyzed'],
            'suspicious_found': self.analysis_stats['suspicious_found'],
            'high_entropy_files': self.analysis_stats['high_entropy_files'],
            'packed_files_detected': self.analysis_stats['packed_files_detected'],
            'suspicious_apis_found': self.analysis_stats['suspicious_apis_found'],
            'detection_rate': (
                self.analysis_stats['suspicious_found'] / max(1, self.analysis_stats['total_analyzed'])
            ) * 100
        }
