# app/utils/self_tests/results_reporter.py
"""
Comprehensive results reporting and analysis for self-tests.
Provides detailed tables, summaries, and trend analysis.
"""

import json
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum

from app.logger_config import settings, selftest_logger


class TestStatus(Enum):
    """Test execution status."""
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"
    SKIP = "SKIP"
    TIMEOUT = "TIMEOUT"


@dataclass
class TestResult:
    """Individual test result."""
    name: str
    status: TestStatus
    duration_ms: float
    message: str = ""
    details: Dict[str, Any] = None
    timestamp: str = ""
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.utcnow().isoformat() + "Z"
        if self.details is None:
            self.details = {}


@dataclass
class TestSuiteResult:
    """Complete test suite result."""
    suite_name: str
    start_time: str
    end_time: str
    duration_ms: float
    total_tests: int
    passed: int
    failed: int
    errors: int
    skipped: int
    timeouts: int
    tests: List[TestResult]
    summary: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.summary is None:
            self.summary = self._generate_summary()
    
    def _generate_summary(self) -> Dict[str, Any]:
        """Generate test suite summary."""
        success_rate = (self.passed / self.total_tests * 100) if self.total_tests > 0 else 0
        return {
            "success_rate": round(success_rate, 2),
            "avg_duration_ms": round(self.duration_ms / self.total_tests, 2) if self.total_tests > 0 else 0,
            "status": "HEALTHY" if success_rate >= 90 else "DEGRADED" if success_rate >= 70 else "CRITICAL"
        }


class ResultsReporter:
    """Comprehensive results reporting and analysis."""
    
    def __init__(self):
        self.results_dir = Path(settings.SELFTEST_RESULTS_DIR)
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.history_file = self.results_dir / "test_history.jsonl"
        self.summary_file = self.results_dir / "latest_summary.json"
    
    def report_suite_results(self, suite_result: TestSuiteResult) -> None:
        """Report complete test suite results."""
        try:
            # Log detailed results
            self._log_detailed_results(suite_result)
            
            # Generate and log summary table
            self._log_summary_table(suite_result)
            
            # Save to history
            self._save_to_history(suite_result)
            
            # Update latest summary
            self._update_latest_summary(suite_result)
            
            # Check for alerts
            self._check_alerts(suite_result)
            
        except Exception as e:
            selftest_logger.error("Failed to report suite results: %s", e)
    
    def _log_detailed_results(self, suite_result: TestSuiteResult) -> None:
        """Log detailed test results in a formatted table."""
        selftest_logger.info("=" * 80)
        selftest_logger.info("SELF-TEST RESULTS - %s", suite_result.suite_name.upper())
        selftest_logger.info("=" * 80)
        selftest_logger.info("Start Time: %s", suite_result.start_time)
        selftest_logger.info("End Time: %s", suite_result.end_time)
        selftest_logger.info("Duration: %.2f seconds", suite_result.duration_ms / 1000)
        selftest_logger.info("-" * 80)
        
        # Test results table
        selftest_logger.info("%-30s %-8s %-10s %s", "TEST NAME", "STATUS", "DURATION", "MESSAGE")
        selftest_logger.info("-" * 80)
        
        for test in suite_result.tests:
            duration_str = f"{test.duration_ms:.0f}ms"
            message = test.message[:40] + "..." if len(test.message) > 40 else test.message
            selftest_logger.info("%-30s %-8s %-10s %s", 
                               test.name[:30], test.status.value, duration_str, message)
        
        selftest_logger.info("-" * 80)
        selftest_logger.info("SUMMARY: %d total, %d passed, %d failed, %d errors, %d skipped", 
                           suite_result.total_tests, suite_result.passed, 
                           suite_result.failed, suite_result.errors, suite_result.skipped)
        selftest_logger.info("Success Rate: %.1f%% | Status: %s", 
                           suite_result.summary["success_rate"], suite_result.summary["status"])
        selftest_logger.info("=" * 80)
    
    def _log_summary_table(self, suite_result: TestSuiteResult) -> None:
        """Log a concise summary table."""
        status_counts = {
            "PASS": suite_result.passed,
            "FAIL": suite_result.failed,
            "ERROR": suite_result.errors,
            "SKIP": suite_result.skipped,
            "TIMEOUT": suite_result.timeouts
        }
        
        selftest_logger.info("QUICK SUMMARY: %s", " | ".join([
            f"{status}: {count}" for status, count in status_counts.items() if count > 0
        ]))
    
    def _save_to_history(self, suite_result: TestSuiteResult) -> None:
        """Save results to history file."""
        try:
            history_entry = {
                "timestamp": suite_result.start_time,
                "suite": asdict(suite_result)
            }
            
            with open(self.history_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(history_entry) + "\n")
                
        except Exception as e:
            selftest_logger.error("Failed to save to history: %s", e)
    
    def _update_latest_summary(self, suite_result: TestSuiteResult) -> None:
        """Update latest summary file."""
        try:
            summary = {
                "last_run": suite_result.start_time,
                "status": suite_result.summary["status"],
                "success_rate": suite_result.summary["success_rate"],
                "total_tests": suite_result.total_tests,
                "passed": suite_result.passed,
                "failed": suite_result.failed,
                "errors": suite_result.errors,
                "duration_ms": suite_result.duration_ms
            }
            
            with open(self.summary_file, "w", encoding="utf-8") as f:
                json.dump(summary, f, indent=2)
                
        except Exception as e:
            selftest_logger.error("Failed to update summary: %s", e)
    
    def _check_alerts(self, suite_result: TestSuiteResult) -> None:
        """Check if alerts should be triggered."""
        if not settings.SELFTEST_ALERT_ON_FAILURE:
            return
        
        if suite_result.failed + suite_result.errors >= settings.SELFTEST_FAILURE_THRESHOLD:
            selftest_logger.warning("ALERT: Self-test failure threshold exceeded!")
            selftest_logger.warning("Failed/Error tests: %d (threshold: %d)", 
                                   suite_result.failed + suite_result.errors,
                                   settings.SELFTEST_FAILURE_THRESHOLD)
    
    def get_trend_analysis(self, hours: int = 24) -> Dict[str, Any]:
        """Get trend analysis for the specified time period."""
        try:
            cutoff_time = datetime.utcnow() - timedelta(hours=hours)
            recent_results = []
            
            if self.history_file.exists():
                with open(self.history_file, "r", encoding="utf-8") as f:
                    for line in f:
                        try:
                            entry = json.loads(line.strip())
                            entry_time = datetime.fromisoformat(entry["timestamp"].replace("Z", "+00:00"))
                            if entry_time >= cutoff_time:
                                recent_results.append(entry["suite"])
                        except (json.JSONDecodeError, KeyError, ValueError):
                            continue
            
            if not recent_results:
                return {"status": "NO_DATA", "message": "No recent test data available"}
            
            # Calculate trends
            success_rates = [r["summary"]["success_rate"] for r in recent_results]
            avg_success_rate = sum(success_rates) / len(success_rates)
            
            return {
                "status": "OK",
                "period_hours": hours,
                "total_runs": len(recent_results),
                "avg_success_rate": round(avg_success_rate, 2),
                "trend": "IMPROVING" if success_rates[-1] > avg_success_rate else "DECLINING",
                "latest_success_rate": success_rates[-1] if success_rates else 0
            }
            
        except Exception as e:
            selftest_logger.error("Failed to generate trend analysis: %s", e)
            return {"status": "ERROR", "message": str(e)}


# Global reporter instance
results_reporter = ResultsReporter()
