import ast
import json
import re
import tempfile
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

import aiofiles

from ..core.logging import get_logger

from pathlib import Path

from pathlib import Path

"""
Plugin Validation System for PlexiChat Marketplace

Comprehensive validation system for plugins including security scanning,
code quality checks, compatibility validation, and metadata verification.
"""

logger = get_logger(__name__)


class ValidationSeverity(Enum):
    """Validation issue severity levels."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class ValidationCategory(Enum):
    """Validation categories."""
    SECURITY = "security"
    COMPATIBILITY = "compatibility"
    CODE_QUALITY = "code_quality"
    METADATA = "metadata"
    PERFORMANCE = "performance"
    DEPENDENCIES = "dependencies"


@dataclass
class ValidationIssue:
    """Validation issue details."""
    category: ValidationCategory
    severity: ValidationSeverity
    code: str
    message: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    suggestion: Optional[str] = None


@dataclass
class ValidationResult:
    """Plugin validation result."""
    plugin_id: str
    plugin_name: str
    plugin_version: str
    is_valid: bool
    score: float  # 0-100 validation score
    issues: List[ValidationIssue] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    validated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class PluginValidator:
    """Comprehensive plugin validation system."""

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or self._load_default_config()

        # Security patterns to detect
        self.security_patterns = [
            (r'eval\s*\(', "Use of eval() function detected", ValidationSeverity.CRITICAL),
            (r'exec\s*\(', "Use of exec() function detected", ValidationSeverity.CRITICAL),
            (r'__import__\s*\(', "Dynamic import detected", ValidationSeverity.WARNING),
            (r'subprocess\.|os\.system|os\.popen', "System command execution detected", ValidationSeverity.ERROR),
            (r'open\s*\([^)]*[\'"]w[\'"]', "File write operation detected", ValidationSeverity.WARNING),
            (r'socket\.|urllib\.|requests\.|http\.', "Network operation detected", ValidationSeverity.INFO),
            (r'pickle\.loads?|marshal\.loads?', "Unsafe deserialization detected", ValidationSeverity.CRITICAL),
            (r'input\s*\(|raw_input\s*\(', "User input function detected", ValidationSeverity.WARNING)
        ]

        # Required metadata fields
        self.required_metadata = [
            "name", "version", "description", "author", "plexichat_version"
        ]

        # Compatibility checks
        self.min_plexichat_version = "3.0.0"
        self.supported_python_versions = ["3.8", "3.9", "3.10", "3.11", "3.12"]

        logger.info(" Plugin Validator initialized")

    def _load_default_config(self) -> Dict[str, Any]:
        """Load default validation configuration."""
        return {
            "max_plugin_size": 50 * 1024 * 1024,  # 50MB
            "max_files": 1000,
            "allowed_extensions": [".py", ".json", ".yaml", ".yml", ".txt", ".md", ".rst"],
            "blocked_modules": ["os", "subprocess", "sys", "importlib"],
            "max_line_length": 120,
            "min_validation_score": 70.0,
            "enable_security_scan": True,
            "enable_code_quality": True,
            "enable_compatibility_check": True
        }

    async def validate_plugin(self, plugin_path: str) -> ValidationResult:
        """Validate a plugin package comprehensively."""
        try:
            logger.info(f" Starting validation for plugin: {plugin_path}")

            # Initialize result
            result = ValidationResult(
                plugin_id="unknown",
                plugin_name="unknown",
                plugin_version="unknown",
                is_valid=False,
                score=0.0
            )

            # Extract and analyze plugin
            with tempfile.TemporaryDirectory() as temp_dir:
                from pathlib import Path
extract_path = Path
Path(temp_dir) / "plugin"

                # Extract plugin archive
                if not await self._extract_plugin(plugin_path, extract_path):
                    result.issues.append(ValidationIssue(
                        category=ValidationCategory.METADATA,
                        severity=ValidationSeverity.CRITICAL,
                        code="EXTRACT_FAILED",
                        message="Failed to extract plugin archive"
                    ))
                    return result

                # Load and validate metadata
                metadata = await self._load_plugin_metadata(extract_path)
                if metadata:
                    result.plugin_id = metadata.get("id", "unknown")
                    result.plugin_name = metadata.get("name", "unknown")
                    result.plugin_version = metadata.get("version", "unknown")
                    result.metadata = metadata

                # Run validation checks
                await self._validate_metadata(result, metadata)
                await self._validate_structure(result, extract_path)
                await self._validate_security(result, extract_path)
                await self._validate_code_quality(result, extract_path)
                await self._validate_compatibility(result, extract_path, metadata)
                await self._validate_dependencies(result, extract_path)

                # Calculate final score and validity
                result.score = self._calculate_validation_score(result)
                result.is_valid = (
                    result.score >= self.config["min_validation_score"] and
                    not any(issue.severity == ValidationSeverity.CRITICAL for issue in result.issues)
                )

            logger.info(f" Validation completed: {result.plugin_name} (Score: {result.score:.1f})")
            return result

        except Exception as e:
            logger.error(f" Validation failed: {e}")
            result = ValidationResult(
                plugin_id="unknown",
                plugin_name="unknown",
                plugin_version="unknown",
                is_valid=False,
                score=0.0
            )
            result.issues.append(ValidationIssue(
                category=ValidationCategory.METADATA,
                severity=ValidationSeverity.CRITICAL,
                code="VALIDATION_ERROR",
                message=f"Validation process failed: {str(e)}"
            ))
            return result

    async def _extract_plugin(self, plugin_path: str, extract_path: Path) -> bool:
        """Extract plugin archive to temporary directory."""
        try:
            extract_path.mkdir(parents=True, exist_ok=True)

            with zipfile.ZipFile(plugin_path, 'r') as zip_file:
                # Check archive size and file count
                total_size = sum(info.file_size for info in zip_file.infolist())
                if total_size > self.config["max_plugin_size"]:
                    return False

                if len(zip_file.infolist()) > self.config["max_files"]:
                    return False

                # Extract files
                zip_file.extractall(extract_path)

            return True

        except Exception as e:
            logger.error(f"Failed to extract plugin: {e}")
            return False

    async def _load_plugin_metadata(self, plugin_path: Path) -> Optional[Dict[str, Any]]:
        """Load plugin metadata from plugin.json or setup.py."""
        try:
            # Try plugin.json first
            metadata_file = plugin_path / "plugin.json"
            if metadata_file.exists():
                async with aiofiles.open(metadata_file, 'r') as f:
                    return json.loads(await f.read())

            # Try manifest.json
            manifest_file = plugin_path / "manifest.json"
            if manifest_file.exists():
                async with aiofiles.open(manifest_file, 'r') as f:
                    return json.loads(await f.read())

            # Try setup.py parsing (basic)
            setup_file = plugin_path / "setup.py"
            if setup_file.exists():
                return await self._parse_setup_py(setup_file)

            return None

        except Exception as e:
            logger.error(f"Failed to load plugin metadata: {e}")
            return None

    async def _parse_setup_py(self, setup_file: Path) -> Dict[str, Any]:
        """Parse basic metadata from setup.py."""
        try:
            async with aiofiles.open(setup_file, 'r') as f:
                content = await f.read()

            # Simple regex-based parsing
            metadata = {}

            name_match = re.search(r'name\s*=\s*[\'"]([^\'"]+)[\'"]', content)
            if name_match:
                metadata["name"] = name_match.group(1)

            version_match = re.search(r'version\s*=\s*[\'"]([^\'"]+)[\'"]', content)
            if version_match:
                metadata["version"] = version_match.group(1)

            description_match = re.search(r'description\s*=\s*[\'"]([^\'"]+)[\'"]', content)
            if description_match:
                metadata["description"] = description_match.group(1)

            author_match = re.search(r'author\s*=\s*[\'"]([^\'"]+)[\'"]', content)
            if author_match:
                metadata["author"] = author_match.group(1)

            return metadata

        except Exception as e:
            logger.error(f"Failed to parse setup.py: {e}")
            return {}

    async def _validate_metadata(self, result: ValidationResult, metadata: Optional[Dict[str, Any]]):
        """Validate plugin metadata."""
        if not metadata:
            result.issues.append(ValidationIssue(
                category=ValidationCategory.METADATA,
                severity=ValidationSeverity.CRITICAL,
                code="NO_METADATA",
                message="Plugin metadata not found",
                suggestion="Add plugin.json or manifest.json file"
            ))
            return

        # Check required fields
        for field in self.required_metadata:
            if field not in metadata or not metadata[field]:
                result.issues.append(ValidationIssue(
                    category=ValidationCategory.METADATA,
                    severity=ValidationSeverity.ERROR,
                    code="MISSING_FIELD",
                    message=f"Required metadata field missing: {field}",
                    suggestion=f"Add '{field}' field to plugin metadata"
                ))

        # Validate version format
        version = metadata.get("version", "")
        if not re.match(r'^\d+\.\d+\.\d+', version):
            result.issues.append(ValidationIssue(
                category=ValidationCategory.METADATA,
                severity=ValidationSeverity.WARNING,
                code="INVALID_VERSION",
                message="Version should follow semantic versioning (x.y.z)",
                suggestion="Use semantic versioning format like '1.0.0'"
            ))

    async def _validate_structure(self, result: ValidationResult, plugin_path: Path):
        """Validate plugin file structure."""
        # Check for main plugin file
        main_files = ["__init__.py", "main.py", "plugin.py"]
        has_main = any((plugin_path / f).exists() for f in main_files)

        if not has_main:
            result.issues.append(ValidationIssue(
                category=ValidationCategory.METADATA,
                severity=ValidationSeverity.ERROR,
                code="NO_MAIN_FILE",
                message="No main plugin file found",
                suggestion="Add __init__.py, main.py, or plugin.py"
            ))

        # Check file extensions
        for file_path in plugin_path.rglob("*"):
            if file_path.is_file():
                if file_path.suffix not in self.config["allowed_extensions"]:
                    result.issues.append(ValidationIssue(
                        category=ValidationCategory.SECURITY,
                        severity=ValidationSeverity.WARNING,
                        code="SUSPICIOUS_FILE",
                        message=f"Suspicious file extension: {file_path.suffix}",
                        file_path=str(file_path.relative_to(plugin_path))
                    ))

    async def _validate_security(self, result: ValidationResult, plugin_path: Path):
        """Perform security validation."""
        if not self.config["enable_security_scan"]:
            return

        # Scan Python files for security issues
        for py_file in plugin_path.rglob("*.py"):
            try:
                async with aiofiles.open(py_file, 'r', encoding='utf-8') as f:
                    content = await f.read()

                # Check security patterns
                lines = content.split('\n')
                for line_num, line in enumerate(lines, 1):
                    for pattern, message, severity in self.security_patterns:
                        if re.search(pattern, line, re.IGNORECASE):
                            result.issues.append(ValidationIssue(
                                category=ValidationCategory.SECURITY,
                                severity=severity,
                                code="SECURITY_PATTERN",
                                message=message,
                                file_path=str(py_file.relative_to(plugin_path)),
                                line_number=line_num,
                                suggestion="Review and ensure safe usage"
                            ))

            except Exception as e:
                logger.warning(f"Failed to scan file {py_file}: {e}")

    async def _validate_code_quality(self, result: ValidationResult, plugin_path: Path):
        """Validate code quality."""
        if not self.config["enable_code_quality"]:
            return

        for py_file in plugin_path.rglob("*.py"):
            try:
                async with aiofiles.open(py_file, 'r', encoding='utf-8') as f:
                    content = await f.read()

                # Check syntax
                try:
                    ast.parse(content)
                except SyntaxError as e:
                    result.issues.append(ValidationIssue(
                        category=ValidationCategory.CODE_QUALITY,
                        severity=ValidationSeverity.ERROR,
                        code="SYNTAX_ERROR",
                        message=f"Syntax error: {e.msg}",
                        file_path=str(py_file.relative_to(plugin_path)),
                        line_number=e.lineno
                    ))

                # Check line length
                lines = content.split('\n')
                for line_num, line in enumerate(lines, 1):
                    if len(line) > self.config["max_line_length"]:
                        result.issues.append(ValidationIssue(
                            category=ValidationCategory.CODE_QUALITY,
                            severity=ValidationSeverity.WARNING,
                            code="LONG_LINE",
                            message=f"Line too long ({len(line)} > {self.config['max_line_length']})",
                            file_path=str(py_file.relative_to(plugin_path)),
                            line_number=line_num,
                            suggestion="Break long lines for better readability"
                        ))

            except Exception as e:
                logger.warning(f"Failed to check code quality for {py_file}: {e}")

    async def _validate_compatibility(self, result: ValidationResult, plugin_path: Path, metadata: Optional[Dict[str, Any]]):
        """Validate PlexiChat compatibility."""
        if not self.config["enable_compatibility_check"]:
            return

        if metadata:
            # Check PlexiChat version compatibility
            required_version = metadata.get("plexichat_version", "")
            if required_version and required_version < self.min_plexichat_version:
                result.issues.append(ValidationIssue(
                    category=ValidationCategory.COMPATIBILITY,
                    severity=ValidationSeverity.WARNING,
                    code="OLD_PLEXICHAT_VERSION",
                    message=f"Plugin requires old PlexiChat version: {required_version}",
                    suggestion=f"Update to support PlexiChat {self.min_plexichat_version}+"
                ))

    async def _validate_dependencies(self, result: ValidationResult, plugin_path: Path):
        """Validate plugin dependencies."""
        # Check requirements.txt
        requirements_file = plugin_path / "requirements.txt"
        if requirements_file.exists():
            try:
                async with aiofiles.open(requirements_file, 'r') as f:
                    requirements = await f.read()

                # Basic dependency validation
                for line in requirements.strip().split('\n'):
                    if line.strip() and not line.startswith('#'):
                        # Check for potentially dangerous packages
                        package_name = line.split('==')[0].split('>=')[0].split('<=')[0].strip()
                        if package_name.lower() in ['os', 'sys', 'subprocess']:
                            result.issues.append(ValidationIssue(
                                category=ValidationCategory.DEPENDENCIES,
                                severity=ValidationSeverity.WARNING,
                                code="SUSPICIOUS_DEPENDENCY",
                                message=f"Potentially dangerous dependency: {package_name}",
                                suggestion="Review dependency necessity"
                            ))

            except Exception as e:
                logger.warning(f"Failed to validate requirements.txt: {e}")

    def _calculate_validation_score(self, result: ValidationResult) -> float:
        """Calculate overall validation score (0-100)."""
        base_score = 100.0

        # Deduct points based on issue severity
        for issue in result.issues:
            if issue.severity == ValidationSeverity.CRITICAL:
                base_score -= 25.0
            elif issue.severity == ValidationSeverity.ERROR:
                base_score -= 10.0
            elif issue.severity == ValidationSeverity.WARNING:
                base_score -= 5.0
            elif issue.severity == ValidationSeverity.INFO:
                base_score -= 1.0

        return max(0.0, base_score)


# Global validator instance
_plugin_validator: Optional[PluginValidator] = None


def get_plugin_validator() -> PluginValidator:
    """Get the global plugin validator instance."""
    global _plugin_validator
    if _plugin_validator is None:
        _plugin_validator = PluginValidator()
    return _plugin_validator


async def validate_plugin_package(plugin_path: str) -> ValidationResult:
    """Validate a plugin package."""
    validator = get_plugin_validator()
    return await validator.validate_plugin(plugin_path)
