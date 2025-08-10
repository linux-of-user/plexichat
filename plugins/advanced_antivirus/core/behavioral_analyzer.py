from plugins_internal import EnhancedPluginAPI
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import re

from . import ScanResult, ScanType, ThreatLevel, ThreatType

class BehavioralAnalyzer:
    """
    Analyzes file behavior using heuristics and patterns, with persistence via the Plugin SDK.
    """

    def __init__(self, api: EnhancedPluginAPI):
        self.api = api
        self.logger = api.logger
        self.scan_stats = {
            "total_files_analyzed": 0,
            "suspicious_behaviors_found": 0,
        }
        self._initialized = False
        self.patterns = []

    async def initialize(self):
        """Initializes the behavioral analyzer by loading patterns from the database."""
        if self._initialized:
            return
        self.logger.info("Initializing Behavioral Analyzer (SDK-based).")
        await self._load_patterns()
        self._initialized = True

    async def _load_patterns(self):
        """Loads behavioral patterns from the unified database."""
        patterns_data = await self.api.db_get_value("behavioral_patterns")
        if isinstance(patterns_data, list):
            self.patterns = patterns_data
            self.logger.info(f"Loaded {len(self.patterns)} behavioral patterns.")
        else:
            self.logger.info("No behavioral patterns found in database. Using defaults.")
            # Using some default patterns if none are in the DB
            self.patterns = [
                {"pattern": r"CreateProcess\(.*\.exe\)", "score": 8, "description": "Creates executable process"},
                {"pattern": r"RegSetValue\(.*\\Run\)", "score": 9, "description": "Modifies registry run key"},
                {"pattern": r"Socket\(.*\)", "score": 5, "description": "Opens network socket"},
            ]
            await self.update_patterns(self.patterns)


    async def analyze_file(self, file_path: str) -> ScanResult:
        """Analyzes a file for suspicious behaviors."""
        start_time = datetime.now(timezone.utc)
        self.scan_stats["total_files_analyzed"] += 1
        total_score = 0
        findings = []

        try:
            # In a real implementation, this would involve sandboxing and monitoring
            # system calls made by the file. Here, we simulate by reading file content.
            with open(file_path, "r", errors="ignore") as f:
                content = f.read(1024 * 1024) # Read up to 1MB

            for p in self.patterns:
                if re.search(p["pattern"], content, re.IGNORECASE):
                    total_score += p["score"]
                    findings.append(p["description"])

        except Exception as e:
            self.logger.warning(f"Could not analyze file content for behavior: {file_path}, Error: {e}")

        threat_level = self._score_to_threat_level(total_score)
        if threat_level.value > ThreatLevel.CLEAN.value:
            self.scan_stats["suspicious_behaviors_found"] += 1

        return ScanResult(
            file_path=file_path,
            threat_level=threat_level,
            threat_type=ThreatType.SUSPICIOUS_BEHAVIOR if findings else None,
            threat_name="Suspicious Behavior" if findings else None,
            scan_type=ScanType.BEHAVIORAL_SCAN,
            scan_duration=(datetime.now(timezone.utc) - start_time).total_seconds(),
            detected_at=start_time,
            confidence_score=min(total_score / 15.0, 1.0), # Normalize score
            details={"behaviors_matched": findings, "score": total_score}
        )

    async def update_patterns(self, new_patterns: List[Dict[str, Any]]) -> bool:
        """Updates the behavioral patterns in the database."""
        self.logger.info(f"Updating behavioral patterns with {len(new_patterns)} new patterns.")
        self.patterns = new_patterns
        return await self.api.db_set_value("behavioral_patterns", self.patterns)

    def _score_to_threat_level(self, score: int) -> ThreatLevel:
        """Converts a behavior score to a threat level."""
        if score >= 15:
            return ThreatLevel.CRITICAL
        elif score >= 10:
            return ThreatLevel.HIGH_RISK
        elif score >= 5:
            return ThreatLevel.MEDIUM_RISK
        elif score > 0:
            return ThreatLevel.SUSPICIOUS
        else:
            return ThreatLevel.CLEAN

    async def get_statistics(self) -> Dict[str, Any]:
        """Gets behavioral analyzer statistics."""
        return self.scan_stats
