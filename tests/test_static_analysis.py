"""Tests for static analysis reporter."""

import asyncio
import json
import pytest
import tempfile
from pathlib import Path
from typing import Dict, Any, List
from unittest.mock import patch, AsyncMock, MagicMock

from src.plexichat.infrastructure.utils.static_analysis_reporter import (
    StaticAnalysisReporter,
)


@pytest.fixture
def sample_ruff_json() -> Dict[str, Any]:
    """Sample Ruff JSON output fixture."""
    return {
        "results": [
            {
                "code": "E501",
                "location": {"path": "src/file1.py", "row": 10, "column": 80},
                "message": "Line too long (82 > 88 characters)",
                "fix": None,
            },
            {
                "code": "F401",
                "location": {"path": "src/file1.py", "row": 15, "column": 1},
                "message": "'os' imported but unused",
                "fix": None,
            },
            {
                "code": "I001",
                "location": {"path": "src/file2.py", "row": 5, "column": 1},
                "message": "Import 'requests' should be before 'json'",
                "fix": None,
            },
            {
                "code": "ASYNC100",
                "location": {"path": "src/async_file.py", "row": 20, "column": 5},
                "message": "Use 'async with' instead of 'with' for async context manager",
                "fix": None,
            },
            {
                "code": "C401",
                "location": {"path": "src/comprehensions.py", "row": 30, "column": 10},
                "message": "Unnecessary list comprehension - rewrite as list()",
                "fix": None,
            },
        ]
    }


@pytest.fixture
def sample_mypy_json() -> List[Dict[str, Any]]:
    """Sample MyPy JSON output fixture."""
    return [
        {
            "file": "src/file1.py",
            "line": 10,
            "column": 5,
            "severity": {"description": "error"},
            "message": "Missing type annotation",
            "code": "missing-annotation",
        },
        {
            "file": "src/file1.py",
            "line": 15,
            "column": 3,
            "severity": {"description": "error"},
            "message": "Argument 1 to 'authenticate' has incompatible type",
            "code": "arg-type",
        },
        {
            "file": "src/file2.py",
            "line": 8,
            "column": 1,
            "severity": {"description": "warning"},
            "message": "Optional used in a non-optional context",
            "code": "optional-context",
        },
        {
            "file": "src/cython_file.pyx",
            "line": 5,
            "column": 1,
            "severity": {"description": "error"},
            "message": "Cython type not recognized",
            "code": "cython-type",
        },
    ]


@pytest.fixture
def empty_ruff_json() -> Dict[str, Any]:
    """Empty Ruff JSON output fixture."""
    return {"results": []}


@pytest.fixture
def empty_mypy_json() -> List[Dict[str, Any]]:
    """Empty MyPy JSON output fixture."""
    return []


@pytest.mark.asyncio
async def test_report_errors_no_files(tmp_path: Path, sample_ruff_json: Dict[str, Any], sample_mypy_json: List[Dict[str, Any]]) -> None:
    """Test reporter when JSON files don't exist."""
    reporter = StaticAnalysisReporter(error_threshold=0)
    
    ruff_path = tmp_path / "ruff_nonexistent.json"
    mypy_path = tmp_path / "mypy_nonexistent.json"
    
    with patch("src.plexichat.infrastructure.utils.static_analysis_reporter.log_warning", new_callable=AsyncMock) as mock_log_warning:
        counts = await reporter.report_errors(ruff_path, mypy_path)
    
    assert counts["errors"] == 0
    assert counts["warnings"] == 0
    assert counts["info"] == 0
    assert mock_log_warning.call_count == 2


@pytest.mark.asyncio
async def test_report_errors_successful_parsing(tmp_path: Path, sample_ruff_json: Dict[str, Any], sample_mypy_json: List[Dict[str, Any]]) -> None:
    """Test successful parsing of both Ruff and MyPy JSON files."""
    reporter = StaticAnalysisReporter(error_threshold=5)
    
    # Create temporary JSON files
    ruff_path = tmp_path / "ruff.json"
    with open(ruff_path, "w", encoding="utf-8") as f:
        json.dump(sample_ruff_json, f)
    
    mypy_path = tmp_path / "mypy.json"
    with open(mypy_path, "w", encoding="utf-8") as f:
        json.dump(sample_mypy_json, f)
    
    with patch("src.plexichat.infrastructure.utils.static_analysis_reporter.log_info", new_callable=AsyncMock) as mock_log_info:
        counts = await reporter.report_errors(ruff_path, mypy_path)
    
    # Verify counts
    assert counts["errors"] == 4  # 2 Ruff (E501, F401) + 2 MyPy errors
    assert counts["warnings"] == 3  # 1 Ruff ASYNC + 1 Ruff C4 + 1 MyPy warning
    assert counts["info"] == 1  # 1 Ruff I001
    assert counts["files_checked"] == 4  # file1.py, file2.py, async_file.py, comprehensions.py, cython_file.pyx
    
    # Verify detailed counts
    assert counts["ruff"]["errors"] == 2
    assert counts["ruff"]["warnings"] == 2
    assert counts["ruff"]["info"] == 1
    assert counts["mypy"]["errors"] == 2
    assert counts["mypy"]["warnings"] == 1
    
    mock_log_info.assert_called()


@pytest.mark.asyncio
async def test_error_threshold_exceeded(tmp_path: Path, sample_ruff_json: Dict[str, Any], sample_mypy_json: List[Dict[str, Any]]) -> None:
    """Test that ValueError is raised when error threshold is exceeded."""
    reporter = StaticAnalysisReporter(error_threshold=2)
    
    ruff_path = tmp_path / "ruff.json"
    with open(ruff_path, "w", encoding="utf-8") as f:
        json.dump(sample_ruff_json, f)
    
    mypy_path = tmp_path / "mypy.json"
    with open(mypy_path, "w", encoding="utf-8") as f:
        json.dump(sample_mypy_json, f)
    
    with pytest.raises(ValueError, match="Static analysis failed: 4 errors found"):
        await reporter.report_errors(ruff_path, mypy_path)


@pytest.mark.asyncio
async def test_warning_threshold_exceeded(tmp_path: Path, sample_ruff_json: Dict[str, Any], sample_mypy_json: List[Dict[str, Any]]) -> None:
    """Test warning threshold logging without raising error."""
    reporter = StaticAnalysisReporter(error_threshold=5, warning_threshold=2)
    
    ruff_path = tmp_path / "ruff.json"
    with open(ruff_path, "w", encoding="utf-8") as f:
        json.dump(sample_ruff_json, f)
    
    mypy_path = tmp_path / "mypy.json"
    with open(mypy_path, "w", encoding="utf-8") as f:
        json.dump(sample_mypy_json, f)
    
    with patch("src.plexichat.infrastructure.utils.static_analysis_reporter.log_warning", new_callable=AsyncMock) as mock_log_warning:
        counts = await reporter.report_errors(ruff_path, mypy_path)
    
    assert mock_log_warning.call_count >= 1  # Should log warning threshold exceeded
    assert "warnings exceed threshold" in mock_log_warning.call_args[0][0]


@pytest.mark.asyncio
async def test_ruff_error_categorization(sample_ruff_json: Dict[str, Any]) -> None:
    """Test Ruff error categorization by code prefix."""
    reporter = StaticAnalysisReporter()
    
    # Create temp file
    with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False, encoding="utf-8") as f:
        json.dump(sample_ruff_json, f)
        ruff_path = Path(f.name)
    
    try:
        with patch("builtins.open", mock_open(read_data=json.dumps(sample_ruff_json))) as mock_file:
            with patch("src.plexichat.infrastructure.utils.static_analysis_reporter.log_info", new_callable=AsyncMock):
                counts = await reporter.report_errors(ruff_path, Path("dummy_mypy.json"))
        
        # Verify Ruff categorization
        ruff_counts = counts["ruff"]
        assert ruff_counts["errors"] == 2  # E501, F401
        assert ruff_counts["warnings"] == 2  # ASYNC100, C401
        assert ruff_counts["info"] == 1  # I001
    finally:
        ruff_path.unlink()


@pytest.mark.asyncio
async def test_mypy_error_categorization(sample_mypy_json: List[Dict[str, Any]]) -> None:
    """Test MyPy error categorization by severity."""
    reporter = StaticAnalysisReporter()
    
    # Create temp file
    with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False, encoding="utf-8") as f:
        json.dump(sample_mypy_json, f)
        mypy_path = Path(f.name)
    
    try:
        with patch("builtins.open", mock_open(read_data=json.dumps(sample_mypy_json))) as mock_file:
            with patch("src.plexichat.infrastructure.utils.static_analysis_reporter.log_info", new_callable=AsyncMock):
                counts = await reporter.report_errors(Path("dummy_ruff.json"), mypy_path)
        
        # Verify MyPy categorization
        mypy_counts = counts["mypy"]
        assert mypy_counts["errors"] == 2  # Two error severity items
        assert mypy_counts["warnings"] == 1  # One warning severity item
        assert mypy_counts["info"] == 0
    finally:
        mypy_path.unlink()


@pytest.mark.parametrize(
    "ruff_json,mypy_json,expected_errors,expected_warnings,expected_info",
    [
        # No errors
        ({"results": []}, [], 0, 0, 0),
        # Only Ruff errors
        (
            {
                "results": [
                    {"code": "E501", "location": {"path": "test.py"}},
                    {"code": "I001", "location": {"path": "test.py"}},
                ]
            },
            [],
            1,
            0,
            1,
        ),
        # Only MyPy errors
        (
            {"results": []},
            [
                {"severity": {"description": "error"}, "file": "test.py"},
                {"severity": {"description": "warning"}, "file": "test.py"},
            ],
            1,
            1,
            0,
        ),
        # Mixed errors with different severities
        (
            {
                "results": [
                    {"code": "E501", "location": {"path": "file1.py"}},  # error
                    {"code": "ASYNC100", "location": {"path": "file2.py"}},  # warning
                    {"code": "I001", "location": {"path": "file3.py"}},  # info
                ]
            },
            [
                {"severity": {"description": "error"}, "file": "file4.py"},
                {"severity": {"description": "warning"}, "file": "file5.py"},
            ],
            2,  # E501 + MyPy error
            2,  # ASYNC100 + MyPy warning
            1,  # I001
        ),
    ],
)
@pytest.mark.asyncio
async def test_various_error_combinations(
    tmp_path: Path,
    ruff_json: Dict[str, Any],
    mypy_json: List[Dict[str, Any]],
    expected_errors: int,
    expected_warnings: int,
    expected_info: int,
) -> None:
    """Test various combinations of Ruff and MyPy errors."""
    reporter = StaticAnalysisReporter(error_threshold=10)
    
    # Create JSON files
    ruff_path = tmp_path / "ruff.json"
    with open(ruff_path, "w", encoding="utf-8") as f:
        json.dump(ruff_json, f)
    
    mypy_path = tmp_path / "mypy.json"
    with open(mypy_path, "w", encoding="utf-8") as f:
        json.dump(mypy_json, f)
    
    with patch("src.plexichat.infrastructure.utils.static_analysis_reporter.log_info", new_callable=AsyncMock):
        counts = await reporter.report_errors(ruff_path, mypy_path)
    
    assert counts["errors"] == expected_errors
    assert counts["warnings"] == expected_warnings
    assert counts["info"] == expected_info


@pytest.mark.asyncio
async def test_file_count_calculation(tmp_path: Path) -> None:
    """Test that files_checked counts unique files correctly."""
    reporter = StaticAnalysisReporter()
    
    ruff_json = {
        "results": [
            {"location": {"path": "src/utils.py"}},
            {"location": {"path": "src/utils.py"}},  # Duplicate
            {"location": {"path": "tests/test_utils.py"}},
            {"location": {"path": None}},  # No path
        ]
    }
    
    mypy_json = [
        {"file": "src/utils.py"},  # Duplicate
        {"file": "src/main.py"},
        {"file": None},  # No file
    ]
    
    ruff_path = tmp_path / "ruff.json"
    with open(ruff_path, "w", encoding="utf-8") as f:
        json.dump(ruff_json, f)
    
    mypy_path = tmp_path / "mypy.json"
    with open(mypy_path, "w", encoding="utf-8") as f:
        json.dump(mypy_json, f)
    
    with patch("src.plexichat.infrastructure.utils.static_analysis_reporter.log_info", new_callable=AsyncMock):
        counts = await reporter.report_errors(ruff_path, mypy_path)
    
    # Should count 4 unique files: utils.py, test_utils.py, main.py (3 unique paths)
    # Wait, actually: src/utils.py, tests/test_utils.py, src/main.py = 3 files
    assert counts["files_checked"] == 3


@pytest.mark.asyncio
async def test_invalid_json_files(tmp_path: Path) -> None:
    """Test handling of invalid JSON files."""
    reporter = StaticAnalysisReporter()
    
    # Create invalid JSON files
    ruff_path = tmp_path / "ruff_invalid.json"
    with open(ruff_path, "w", encoding="utf-8") as f:
        f.write("invalid json {")
    
    mypy_path = tmp_path / "mypy_invalid.json"
    with open(mypy_path, "w", encoding="utf-8") as f:
        f.write("{invalid: json}")
    
    with pytest.raises(json.JSONDecodeError):
        await reporter.report_errors(ruff_path, mypy_path)


@pytest.mark.asyncio
async def test_cli_entrypoint() -> None:
    """Test the CLI entrypoint function."""
    from src.plexichat.infrastructure.utils.static_analysis_reporter import main
    
    # Create temporary valid JSON files
    with tempfile.TemporaryDirectory() as tmp_dir:
        ruff_path = Path(tmp_dir) / "ruff.json"
        with open(ruff_path, "w", encoding="utf-8") as f:
            json.dump({"results": []}, f)
        
        mypy_path = Path(tmp_dir) / "mypy.json"
        with open(mypy_path, "w", encoding="utf-8") as f:
            json.dump([], f)
        
        # Patch sys.argv
        with patch("sys.argv", ["module", str(ruff_path), str(mypy_path)]):
            with patch("src.plexichat.infrastructure.utils.static_analysis_reporter.StaticAnalysisReporter") as mock_reporter:
                mock_instance = MagicMock()
                mock_reporter.return_value = mock_instance
                mock_instance.report_errors = AsyncMock()
                
                await main()
                
                mock_instance.report_errors.assert_called_once_with(ruff_path, mypy_path)


@pytest.mark.asyncio
async def test_missing_cli_arguments() -> None:
    """Test CLI entrypoint with missing arguments."""
    from src.plexichat.infrastructure.utils.static_analysis_reporter import main
    
    # Patch sys.argv with insufficient arguments
    with patch("sys.argv", ["module"]):
        with pytest.raises(SystemExit, match="1"):
            await main()
    
    with patch("sys.argv", ["module", "only_one_arg"]):
        with pytest.raises(SystemExit, match="1"):
            await main()


@pytest.mark.asyncio
async def test_nonexistent_cli_files() -> None:
    """Test CLI entrypoint with non-existent files."""
    from src.plexichat.infrastructure.utils.static_analysis_reporter import main
    
    with patch("sys.argv", ["module", "/nonexistent/ruff.json", "/nonexistent/mypy.json"]):
        with patch("sys.stdout") as mock_stdout:
            with pytest.raises(SystemExit, match="1"):
                await main()
            
            mock_stdout.write.assert_any_call("Ruff JSON file not found")


def test_ruff_analyzer_isolation() -> None:
    """Test Ruff analyzer in isolation (synchronous)."""
    reporter = StaticAnalysisReporter()
    
    # Test case 1: Error codes (E, F)
    errors = [
        {"code": "E501", "location": {"path": "test.py"}},
        {"code": "F401", "location": {"path": "test.py"}},
    ]
    counts = reporter._analyze_ruff_errors(errors)
    assert counts["errors"] == 2
    assert counts["warnings"] == 0
    assert counts["info"] == 0
    
    # Test case 2: Warning codes (ASYNC, C4)
    errors = [
        {"code": "ASYNC100", "location": {"path": "async.py"}},
        {"code": "C401", "location": {"path": "comp.py"}},
    ]
    counts = reporter._analyze_ruff_errors(errors)
    assert counts["errors"] == 0
    assert counts["warnings"] == 2
    assert counts["info"] == 0
    
    # Test case 3: Info codes (I)
    errors = [
        {"code": "I001", "location": {"path": "imports.py"}},
    ]
    counts = reporter._analyze_ruff_errors(errors)
    assert counts["errors"] == 0
    assert counts["warnings"] == 0
    assert counts["info"] == 1
    
    # Test case 4: Unknown code (defaults to warning)
    errors = [
        {"code": "UNKNOWN123", "location": {"path": "unknown.py"}},
    ]
    counts = reporter._analyze_ruff_errors(errors)
    assert counts["errors"] == 0
    assert counts["warnings"] == 1
    assert counts["info"] == 0
    
    # Test case 5: No code field
    errors = [
        {"location": {"path": "no_code.py"}},
    ]
    counts = reporter._analyze_ruff_errors(errors)
    assert counts["errors"] == 0
    assert counts["warnings"] == 0
    assert counts["info"] == 0


def test_mypy_analyzer_isolation() -> None:
    """Test MyPy analyzer in isolation (synchronous)."""
    reporter = StaticAnalysisReporter()
    
    # Test case 1: Standard severities
    errors = [
        {"severity": {"description": "error"}, "file": "test.py"},
        {"severity": {"description": "warning"}, "file": "test.py"},
        {"severity": {"description": "note"}, "file": "test.py"},
    ]
    counts = reporter._analyze_mypy_errors(errors)
    assert counts["errors"] == 1
    assert counts["warnings"] == 1
    assert counts["info"] == 1  # "note" maps to "info"
    
    # Test case 2: Missing severity (defaults to error)
    errors = [
        {"file": "no_severity.py"},
    ]
    counts = reporter._analyze_mypy_errors(errors)
    assert counts["errors"] == 1
    assert counts["warnings"] == 0
    assert counts["info"] == 0
    
    # Test case 3: Unknown severity (defaults to error)
    errors = [
        {"severity": {"description": "unknown"}, "file": "unknown.py"},
    ]
    counts = reporter._analyze_mypy_errors(errors)
    assert counts["errors"] == 1
    assert counts["warnings"] == 0
    assert counts["info"] == 0
    
    # Test case 4: Empty list
    counts = reporter._analyze_mypy_errors([])
    assert counts["errors"] == 0
    assert counts["warnings"] == 0
    assert counts["info"] == 0


@pytest.mark.asyncio
async def test_log_results_called(tmp_path: Path) -> None:
    """Test that _log_results is called with correct data."""
    reporter = StaticAnalysisReporter()
    
    ruff_json = {"results": [{"code": "E501", "location": {"path": "test.py"}}]}
    mypy_json = [{"severity": {"description": "error"}, "file": "test.py"}]
    
    ruff_path = tmp_path / "ruff.json"
    with open(ruff_path, "w", encoding="utf-8") as f:
        json.dump(ruff_json, f)
    
    mypy_path = tmp_path / "mypy.json"
    with open(mypy_path, "w", encoding="utf-8") as f:
        json.dump(mypy_json, f)
    
    with patch.object(reporter, "_log_results", new_callable=AsyncMock) as mock_log_results:
        await reporter.report_errors(ruff_path, mypy_path)
    
    mock_log_results.assert_called_once()
    call_args = mock_log_results.call_args[0]
    counts, ruff_errors, mypy_errors = call_args
    
    assert counts["errors"] == 2
    assert len(ruff_errors) == 1
    assert len(mypy_errors) == 1


class TestStaticAnalysisReporterCoverage:
    """Additional tests to ensure good coverage of the reporter."""
    
    @pytest.mark.asyncio
    async def test_report_errors_with_empty_results(self) -> None:
        """Test with empty results from both tools."""
        reporter = StaticAnalysisReporter()
        
        ruff_json = {"results": []}
        mypy_json = []
        
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False, encoding="utf-8") as f:
            json.dump(ruff_json, f)
            ruff_path = Path(f.name)
        
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False, encoding="utf-8") as f:
            json.dump(mypy_json, f)
            mypy_path = Path(f.name)
        
        try:
            with patch("src.plexichat.infrastructure.utils.static_analysis_reporter.log_info", new_callable=AsyncMock):
                counts = await reporter.report_errors(ruff_path, mypy_path)
            
            assert counts["errors"] == 0
            assert counts["warnings"] == 0
            assert counts["info"] == 0
            assert counts["files_checked"] == 0
        finally:
            ruff_path.unlink()
            mypy_path.unlink()
    
    @pytest.mark.asyncio
    async def test_report_errors_with_file_removal(self, tmp_path: Path) -> None:
        """Test that files are not left behind after analysis."""
        reporter = StaticAnalysisReporter()
        
        ruff_path = tmp_path / "temp_ruff.json"
        mypy_path = tmp_path / "temp_mypy.json"
        
        # Create files
        ruff_path.write_text('{"results": []}')
        mypy_path.write_text('[]')
        
        assert ruff_path.exists()
        assert mypy_path.exists()
        
        await reporter.report_errors(ruff_path, mypy_path)
        
        # Files should still exist (we don't delete them)
        assert ruff_path.exists()
        assert mypy_path.exists()
    
    def test_category_lookup_edge_cases(self) -> None:
        """Test edge cases in Ruff category lookup."""
        reporter = StaticAnalysisReporter()
        
        # Test single character codes
        assert reporter.ruff_categories["E"] == "error"
        assert reporter.ruff_categories["F"] == "error"
        assert reporter.ruff_categories["I"] == "info"
        
        # Test multi-character codes
        assert reporter.ruff_categories["ASYNC"] == "warning"
        assert reporter.ruff_categories["C4"] == "warning"
        assert reporter.ruff_categories["N"] == "warning"
        
        # Test unknown category (should default to warning in analysis)
        errors = [{"code": "Z999", "location": {"path": "test.py"}}]
        counts = reporter._analyze_ruff_errors(errors)
        assert counts["warnings"] == 1  # Unknown defaults to warning