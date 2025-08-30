try:
    # Prefer the namespaced import if running inside the package
    from plexichat.plugins_internal import PluginAPI as EnhancedPluginAPI, FileScanResult as SDKFileScanResult
except Exception:
    try:
        # Fallback to legacy top-level module name
        from plugins_internal import PluginAPI as EnhancedPluginAPI, FileScanResult as SDKFileScanResult
    except Exception:
        # As a last resort, provide safe fallbacks so this module can still be imported
        from typing import Any
        EnhancedPluginAPI = Any
        SDKFileScanResult = None

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
        findings: List[str] = []

        try:
            # In a real implementation, this would involve sandboxing and monitoring
            # system calls made by the file. Here, we simulate by reading file content.
            with open(file_path, "r", errors="ignore") as f:
                content = f.read(1024 * 1024)  # Read up to 1MB

            for p in self.patterns:
                # Use case-insensitive search for pattern matches
                if re.search(p["pattern"], content, re.IGNORECASE):
                    total_score += p.get("score", 0)
                    findings.append(p.get("description", p.get("pattern")))

        except Exception as e:
            self.logger.warning(f"Could not analyze file content for behavior: {file_path}, Error: {e}")

        threat_level = self._score_to_threat_level(total_score)
        if getattr(threat_level, "value", None) is not None:
            # Compare enum values if available
            try:
                if threat_level.value > ThreatLevel.CLEAN.value:
                    self.scan_stats["suspicious_behaviors_found"] += 1
            except Exception:
                # Fallback: compare by equality
                if threat_level != ThreatLevel.CLEAN:
                    self.scan_stats["suspicious_behaviors_found"] += 1
        else:
            # If threat_level is not an enum, assume non-clean indicates suspicion
            if threat_level != ThreatLevel.CLEAN:
                self.scan_stats["suspicious_behaviors_found"] += 1

        # Prepare common metadata to include in result details so we can use simpler SDK result constructors
        scan_duration = (datetime.now(timezone.utc) - start_time).total_seconds()
        confidence_score = min(total_score / 15.0, 1.0)  # Normalize score

        # If an SDK FileScanResult is available, prefer it (it has a file_path parameter).
        # The SDK FileScanResult has the signature:
        #   FileScanResult(file_path: str, is_safe: bool = True, threat_level: str = "none", details: str = "", virus_name: str = None)
        if SDKFileScanResult is not None:
            is_safe = threat_level == ThreatLevel.CLEAN
            # Ensure threat_level is serializable to string for the SDK
            try:
                tl_str = threat_level.name if hasattr(threat_level, "name") else str(threat_level)
            except Exception:
                tl_str = str(threat_level)

            details = {
                "behaviors_matched": findings,
                "score": total_score,
                "confidence_score": confidence_score,
                "scan_duration": scan_duration,
                "detected_at": start_time.isoformat(),
                "scan_type": getattr(ScanType, "BEHAVIORAL_SCAN", str(ScanType)) if ScanType is not None else "behavioral",
                "threat_name": "Suspicious Behavior" if findings else None,
                "threat_type": getattr(ThreatType, "SUSPICIOUS_BEHAVIOR", None) if ThreatType is not None else None,
            }

            try:
                return SDKFileScanResult(
                    file_path=file_path,
                    is_safe=is_safe,
                    threat_level=tl_str,
                    details=details
                )
            except TypeError:
                # If the SDK class has a different signature, fall back to the generic ScanResult below
                self.logger.debug("SDKFileScanResult constructor didn't accept expected args; falling back to local ScanResult.")

        # Fallback: construct the local ScanResult (original behavior).
        # Keep original keywords but also fold extra metadata into details dict to avoid missing-arg errors.
        try:
            return ScanResult(
                file_path=file_path,
                threat_level=threat_level,
                threat_type=ThreatType.SUSPICIOUS_BEHAVIOR if findings else None,
                threat_name="Suspicious Behavior" if findings else None,
                scan_type=ScanType.BEHAVIORAL_SCAN,
                scan_duration=scan_duration,
                detected_at=start_time,
                confidence_score=confidence_score,
                details={"behaviors_matched": findings, "score": total_score}
            )
        except TypeError:
            # As a very defensive fallback (if ScanResult signature differs), return a minimal ScanResult-like object
            # that matches the SDK ScanResult shape (is_safe, threat_level, details).
            is_safe_minimal = (threat_level == ThreatLevel.CLEAN)
            details_minimal = {
                "behaviors_matched": findings,
                "score": total_score,
                "confidence_score": confidence_score,
                "scan_duration": scan_duration,
                "detected_at": start_time.isoformat(),
            }
            # Try to create the SDK-like ScanResult if available in imports
            try:
                # If the imported ScanResult is the SDK one with signature (is_safe, threat_level, details)
                return ScanResult(is_safe_minimal, getattr(threat_level, "name", str(threat_level)), details_minimal)
            except Exception:
                # If everything fails, raise to signal the plugin couldn't produce a valid result
                raise RuntimeError("Failed to construct a ScanResult object with available constructors.")

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
