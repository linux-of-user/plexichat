"""Static analysis reporter for Ruff and MyPy outputs."""

import asyncio
import json
from pathlib import Path
from typing import Any, Dict, List

from .structured_logging import log_error, log_info, log_warning


class StaticAnalysisReporter:
    """Reporter for static analysis results from Ruff and MyPy."""

    def __init__(self, error_threshold: int = 0, warning_threshold: int = 10) -> None:
        """Initialize the reporter with error and warning thresholds."""
        self.error_threshold = error_threshold
        self.warning_threshold = warning_threshold
        self.ruff_categories = {
            "E": "error",  # pycodestyle errors
            "F": "error",  # pyflakes
            "I": "info",  # isort
            "ASYNC": "warning",
            "C4": "warning",
            "N": "warning",
        }

    async def report_errors(
        self, ruff_json_path: str | Path, mypy_json_path: str | Path
    ) -> Dict[str, int]:
        """Parse Ruff and MyPy JSON outputs and report errors.

        Args:
            ruff_json_path: Path to Ruff JSON output file
            mypy_json_path: Path to MyPy JSON output file

        Returns:
            Dictionary with error counts by severity

        Raises:
            ValueError: If error thresholds are exceeded
        """
        ruff_path = Path(ruff_json_path)
        mypy_path = Path(mypy_json_path)

        # Parse Ruff output
        ruff_errors: List[Dict[str, Any]] = []
        if ruff_path.exists():
            with open(ruff_path, "r", encoding="utf-8") as f:
                ruff_data = json.load(f)
                if isinstance(ruff_data, list):
                    ruff_errors = ruff_data
                else:
                    ruff_errors = ruff_data.get("results", [])
        else:
            await log_warning("Ruff JSON file not found", {"path": str(ruff_path)})

        # Parse MyPy output
        mypy_errors: List[Dict[str, Any]] = []
        if mypy_path.exists():
            with open(mypy_path, "r", encoding="utf-8") as f:
                mypy_data = json.load(f)
                if isinstance(mypy_data, list):
                    mypy_errors = mypy_data
        else:
            await log_warning("MyPy JSON file not found", {"path": str(mypy_path)})

        # Analyze Ruff errors
        ruff_counts = self._analyze_ruff_errors(ruff_errors)

        # Analyze MyPy errors
        mypy_counts = self._analyze_mypy_errors(mypy_errors)

        # Combine counts
        total_counts = {
            "errors": ruff_counts["errors"] + mypy_counts["errors"],
            "warnings": ruff_counts["warnings"] + mypy_counts["warnings"],
            "info": ruff_counts.get("info", 0) + mypy_counts.get("info", 0),
            "files_checked": len(
                set(
                    e.get("location", {}).get("path", "")
                    for e in ruff_errors + mypy_errors
                    if e.get("location", {}).get("path", "")
                )
            ),
            "ruff": ruff_counts,
            "mypy": mypy_counts,
        }

        # Log results
        await self._log_results(total_counts, ruff_errors, mypy_errors)

        # Check thresholds
        if total_counts["errors"] > self.error_threshold:
            error_msg = f"Static analysis failed: {total_counts['errors']} errors found (threshold: {self.error_threshold})"
            await log_error(
                error_msg,
                {
                    "errors": total_counts["errors"],
                    "warnings": total_counts["warnings"],
                    "threshold": self.error_threshold,
                },
            )
            raise ValueError(error_msg)

        if total_counts["warnings"] > self.warning_threshold:
            warning_msg = f"Static analysis warnings exceed threshold: {total_counts['warnings']} warnings (threshold: {self.warning_threshold})"
            await log_warning(
                warning_msg,
                {
                    "warnings": total_counts["warnings"],
                    "threshold": self.warning_threshold,
                },
            )

        await log_info("Static analysis passed", total_counts)
        return total_counts

    def _analyze_ruff_errors(self, errors: List[Dict[str, Any]]) -> Dict[str, int]:
        """Analyze Ruff errors and categorize by severity."""
        counts = {"errors": 0, "warnings": 0, "info": 0}

        for error in errors:
            code = error.get("code", "")
            if not code:
                continue

            # Get first character to determine category
            category = code[0] if code else ""
            severity = self.ruff_categories.get(category, "warning")

            counts[severity] += 1

        return counts

    def _analyze_mypy_errors(self, errors: List[Dict[str, Any]]) -> Dict[str, int]:
        """Analyze MyPy errors and categorize by severity."""
        counts = {"errors": 0, "warnings": 0, "info": 0}

        for error in errors:
            severity = error.get("severity", {}).get("description", "error").lower()
            if severity in counts:
                counts[severity] += 1
            else:
                # Default to error for unknown severity
                counts["errors"] += 1

        return counts

    async def _log_results(
        self,
        counts: Dict[str, int],
        ruff_errors: List[Dict[str, Any]],
        mypy_errors: List[Dict[str, Any]],
    ) -> None:
        """Log detailed analysis results."""
        await log_info(
            "Static analysis results",
            {
                "total_errors": counts["errors"],
                "total_warnings": counts["warnings"],
                "total_info": counts["info"],
                "files_checked": counts["files_checked"],
                "ruff_errors": counts["ruff"]["errors"],
                "ruff_warnings": counts["ruff"]["warnings"],
                "mypy_errors": counts["mypy"]["errors"],
                "mypy_warnings": counts["mypy"]["warnings"],
            },
        )

        # Log top error files
        ruff_file_counts = {}
        for error in ruff_errors[:10]:  # Top 10
            path = error.get("location", {}).get("path", "unknown")
            ruff_file_counts[path] = ruff_file_counts.get(path, 0) + 1

        mypy_file_counts = {}
        for error in mypy_errors[:10]:  # Top 10
            path = error.get("file", "unknown")
            mypy_file_counts[path] = mypy_file_counts.get(path, 0) + 1

        if ruff_file_counts:
            await log_warning("Top Ruff error files", ruff_file_counts)
        if mypy_file_counts:
            await log_warning("Top MyPy error files", mypy_file_counts)


async def main() -> None:
    """CLI entrypoint for the static analysis reporter."""
    from pathlib import Path
    import sys

    if len(sys.argv) != 3:
        print(
            "Usage: python -m infrastructure.utils.static_analysis_reporter <ruff.json> <mypy.json>"
        )
        sys.exit(1)

    ruff_path = Path(sys.argv[1])
    mypy_path = Path(sys.argv[2])

    if not ruff_path.exists():
        print(f"Ruff JSON file not found: {ruff_path}")
        sys.exit(1)

    if not mypy_path.exists():
        print(f"MyPy JSON file not found: {mypy_path}")
        sys.exit(1)

    reporter = StaticAnalysisReporter(error_threshold=0, warning_threshold=5)
    await reporter.report_errors(ruff_path, mypy_path)


if __name__ == "__main__":
    asyncio.run(main())
