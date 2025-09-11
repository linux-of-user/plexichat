"""
Content Validation System for PlexiChat
Advanced content validation with threat detection and file security.

Features:
- SQL injection detection with smart filtering
- XSS prevention
- File hash checking for malicious files
- Message size and content validation
- Configurable security rules
- Plugin extensibility
"""

from dataclasses import dataclass, field
import hashlib
from pathlib import Path
import re
import time
from typing import Any

from plexichat.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class ValidationRule:
    """Security validation rule."""

    name: str
    pattern: str
    threat_level: str
    description: str
    enabled: bool = True
    compiled_pattern: re.Pattern | None = None

    def __post_init__(self):
        """Compile regex pattern."""
        if self.pattern:
            try:
                self.compiled_pattern = re.compile(
                    self.pattern, re.IGNORECASE | re.MULTILINE
                )
            except re.error as e:
                logger.error(f"Invalid regex pattern in rule {self.name}: {e}")


@dataclass
class FileHashEntry:
    """File hash database entry."""

    hash_value: str
    filename: str
    threat_level: str
    description: str
    reported_by: str | None = None
    timestamp: float = field(default_factory=time.time)


class ContentValidationSystem:
    """
    Advanced content validation system with multiple security layers.

    Features:
    - SQL injection detection with code block handling
    - XSS prevention
    - File hash validation
    - Content type verification
    - Size limits and validation
    - Configurable security rules
    """

    def __init__(self, config: dict[str, Any]):
        self.config = config
        self.enabled = config.get("enabled", True)

        if not self.enabled:
            logger.info("Content validation is disabled")
            return

        # Initialize validation rules
        self.sql_injection_rules = self._initialize_sql_rules()
        self.xss_rules = self._initialize_xss_rules()
        self.command_injection_rules = self._initialize_command_rules()
        self.path_traversal_rules = self._initialize_path_traversal_rules()

        # File hash database
        self.file_hash_db: dict[str, FileHashEntry] = {}
        self._load_file_hash_database()

        # Content type mappings
        self.content_type_mappings = self._initialize_content_type_mappings()

        # Validation metrics
        self.metrics = {
            "validations_total": 0,
            "validations_passed": 0,
            "validations_failed": 0,
            "sql_detections": 0,
            "xss_detections": 0,
            "file_blocks": 0,
            "size_limit_hits": 0,
        }

        logger.info("Content validation system initialized")

    def _initialize_sql_rules(self) -> list[ValidationRule]:
        """Initialize SQL injection detection rules."""
        return [
            ValidationRule(
                name="SQL Command Injection",
                pattern=r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|TRUNCATE)\b",
                threat_level="high",
                description="Detects SQL command keywords",
            ),
            ValidationRule(
                name="SQL Tautology",
                pattern=r"(\b(OR|AND)\s+\d+\s*=\s*\d+)",
                threat_level="high",
                description="Detects SQL tautology attacks",
            ),
            ValidationRule(
                name="SQL Comment",
                pattern=r"(--|#|/\*|\*/)",
                threat_level="medium",
                description="Detects SQL comment patterns",
            ),
            ValidationRule(
                name="SQL Union Select",
                pattern=r"(\bUNION\s+SELECT\b)",
                threat_level="high",
                description="Detects UNION SELECT attacks",
            ),
            ValidationRule(
                name="SQL Function",
                pattern=r"(\b(USER|DATABASE|VERSION|SYSTEM_USER)\s*\()",
                threat_level="high",
                description="Detects SQL system function calls",
            ),
            ValidationRule(
                name="SQL Load File",
                pattern=r"(\bLOAD_FILE|INTO\s+OUTFILE|INTO\s+DUMPFILE)",
                threat_level="critical",
                description="Detects file system access attempts",
            ),
        ]

    def _initialize_xss_rules(self) -> list[ValidationRule]:
        """Initialize XSS detection rules."""
        return [
            ValidationRule(
                name="Script Tag",
                pattern=r"<script[^>]*>.*?</script>",
                threat_level="high",
                description="Detects script tag injection",
            ),
            ValidationRule(
                name="Javascript Protocol",
                pattern=r"javascript:",
                threat_level="high",
                description="Detects javascript protocol",
            ),
            ValidationRule(
                name="Event Handler",
                pattern=r"on\w+\s*=",
                threat_level="medium",
                description="Detects event handler attributes",
            ),
            ValidationRule(
                name="Iframe Tag",
                pattern=r"<iframe[^>]*>",
                threat_level="high",
                description="Detects iframe injection",
            ),
            ValidationRule(
                name="Object Tag",
                pattern=r"<object[^>]*>",
                threat_level="high",
                description="Detects object tag injection",
            ),
            ValidationRule(
                name="Embed Tag",
                pattern=r"<embed[^>]*>",
                threat_level="high",
                description="Detects embed tag injection",
            ),
        ]

    def _initialize_command_rules(self) -> list[ValidationRule]:
        """Initialize command injection detection rules."""
        return [
            ValidationRule(
                name="Shell Commands",
                pattern=r"\b(rm|del|format|fdisk|kill|shutdown|reboot|halt)\b",
                threat_level="critical",
                description="Detects dangerous shell commands",
            ),
            ValidationRule(
                name="Network Commands",
                pattern=r"\b(wget|curl|nc|netcat|telnet|ssh)\b",
                threat_level="high",
                description="Detects network utility commands",
            ),
            ValidationRule(
                name="System Commands",
                pattern=r"\b(chmod|chown|sudo|su)\b",
                threat_level="high",
                description="Detects system privilege commands",
            ),
            ValidationRule(
                name="Command Chaining",
                pattern=r"[;&|`$(){}[\]\\]",
                threat_level="high",
                description="Detects command chaining operators",
            ),
        ]

    def _initialize_path_traversal_rules(self) -> list[ValidationRule]:
        """Initialize path traversal detection rules."""
        return [
            ValidationRule(
                name="Directory Traversal",
                pattern=r"\.\./",
                threat_level="high",
                description="Detects directory traversal attempts",
            ),
            ValidationRule(
                name="Encoded Traversal",
                pattern=r"%2e%2e%2f",
                threat_level="high",
                description="Detects URL-encoded traversal",
            ),
            ValidationRule(
                name="Windows Traversal",
                pattern=r"\.\.\\",
                threat_level="high",
                description="Detects Windows path traversal",
            ),
        ]

    def _initialize_content_type_mappings(self) -> dict[str, set[str]]:
        """Initialize content type to extension mappings."""
        return {
            "text/plain": {".txt", ".md", ".log"},
            "text/html": {".html", ".htm"},
            "application/json": {".json"},
            "application/pdf": {".pdf"},
            "image/jpeg": {".jpg", ".jpeg"},
            "image/png": {".png"},
            "image/gif": {".gif"},
            "image/webp": {".webp"},
            "application/zip": {".zip"},
            "application/x-rar-compressed": {".rar"},
            "text/csv": {".csv"},
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document": {
                ".docx"
            },
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": {
                ".xlsx"
            },
        }

    def _load_file_hash_database(self):
        """Load file hash database from storage."""
        # In production, this would load from a database or file
        # For now, initialize with some known malicious hashes
        self.file_hash_db = {
            # Example malicious file hashes (these are fake for demonstration)
            "malicious_hash_1": FileHashEntry(
                hash_value="malicious_hash_1",
                filename="malicious.exe",
                threat_level="critical",
                description="Known malware",
                reported_by="system",
            )
        }

    async def validate_content(self, content: Any, context: Any) -> dict[str, Any]:
        """
        Validate content for security threats.

        Args:
            content: Content to validate
            context: Security context

        Returns:
            Dict with validation results
        """
        if not self.enabled:
            return {
                "valid": True,
                "message": "Validation disabled",
                "threat_level": "none",
            }

        self.metrics["validations_total"] += 1

        try:
            # Convert content to string for analysis
            if isinstance(content, bytes):
                content_str = content.decode("utf-8", errors="ignore")
            elif isinstance(content, str):
                content_str = content
            else:
                content_str = str(content)

            # Check for SQL in code blocks first
            sql_in_code_block = self._check_sql_in_code_blocks(content_str)

            # Perform threat detection
            threats = await self._detect_threats(content_str, sql_in_code_block)

            if threats:
                self.metrics["validations_failed"] += 1
                highest_threat = max(
                    threats, key=lambda x: self._threat_level_score(x["threat_level"])
                )

                return {
                    "valid": False,
                    "message": highest_threat["description"],
                    "threat_level": highest_threat["threat_level"],
                    "detected_threats": threats,
                }

            self.metrics["validations_passed"] += 1
            return {
                "valid": True,
                "message": "Content validated successfully",
                "threat_level": "none",
            }

        except Exception as e:
            logger.error(f"Error in content validation: {e}")
            return {
                "valid": False,
                "message": f"Validation error: {e!s}",
                "threat_level": "unknown",
            }

    def _check_sql_in_code_blocks(self, content: str) -> bool:
        """Check if SQL is wrapped in code blocks."""
        sql_pattern = re.compile(r"\[sql\](.*?)\[/sql\]", re.DOTALL | re.IGNORECASE)
        return bool(sql_pattern.search(content))

    async def _detect_threats(
        self, content: str, sql_in_code_block: bool = False
    ) -> list[dict[str, Any]]:
        """Detect security threats in content."""
        threats = []

        # Skip SQL injection checks if SQL is in code blocks
        if not sql_in_code_block:
            # Check SQL injection
            for rule in self.sql_injection_rules:
                if (
                    rule.enabled
                    and rule.compiled_pattern
                    and rule.compiled_pattern.search(content)
                ):
                    threats.append(
                        {
                            "type": "sql_injection",
                            "threat_level": rule.threat_level,
                            "description": rule.description,
                            "rule_name": rule.name,
                        }
                    )
                    self.metrics["sql_detections"] += 1

        # Check XSS
        for rule in self.xss_rules:
            if (
                rule.enabled
                and rule.compiled_pattern
                and rule.compiled_pattern.search(content)
            ):
                threats.append(
                    {
                        "type": "xss",
                        "threat_level": rule.threat_level,
                        "description": rule.description,
                        "rule_name": rule.name,
                    }
                )
                self.metrics["xss_detections"] += 1

        # Check command injection
        for rule in self.command_injection_rules:
            if (
                rule.enabled
                and rule.compiled_pattern
                and rule.compiled_pattern.search(content)
            ):
                threats.append(
                    {
                        "type": "command_injection",
                        "threat_level": rule.threat_level,
                        "description": rule.description,
                        "rule_name": rule.name,
                    }
                )

        # Check path traversal
        for rule in self.path_traversal_rules:
            if (
                rule.enabled
                and rule.compiled_pattern
                and rule.compiled_pattern.search(content)
            ):
                threats.append(
                    {
                        "type": "path_traversal",
                        "threat_level": rule.threat_level,
                        "description": rule.description,
                        "rule_name": rule.name,
                    }
                )

        return threats

    def _threat_level_score(self, level: str) -> int:
        """Get numeric score for threat level."""
        scores = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        return scores.get(level.lower(), 0)

    async def validate_message_content(
        self, content: str, context: Any
    ) -> dict[str, Any]:
        """
        Validate message content specifically.

        Args:
            content: Message content to validate
            context: Security context

        Returns:
            Dict with validation results
        """
        if not self.enabled:
            return {"valid": True, "message": "Validation disabled"}

        # Check size limits
        max_size = self.config.get("max_message_size", 10000)
        if len(content) > max_size:
            self.metrics["size_limit_hits"] += 1
            return {
                "valid": False,
                "message": f"Message size {len(content)} exceeds maximum allowed size {max_size}",
                "threat_level": "medium",
            }

        # Perform general content validation
        return await self.validate_content(content, context)

    async def check_file_hash(
        self, file_content: bytes, filename: str
    ) -> dict[str, Any]:
        """
        Check file hash against malicious file database.

        Args:
            file_content: File content as bytes
            filename: Original filename

        Returns:
            Dict with hash check results
        """
        if not self.enabled or not self.config.get("file_hash_checking", True):
            return {"allowed": True, "message": "Hash checking disabled"}

        try:
            # Calculate file hash
            file_hash = hashlib.sha256(file_content).hexdigest()

            # Check against database
            if file_hash in self.file_hash_db:
                entry = self.file_hash_db[file_hash]
                self.metrics["file_blocks"] += 1

                return {
                    "allowed": False,
                    "message": f"File blocked: {entry.description}",
                    "threat_level": entry.threat_level,
                    "hash": file_hash,
                    "filename": entry.filename,
                }

            return {
                "allowed": True,
                "message": "File hash not in malicious database",
                "hash": file_hash,
            }

        except Exception as e:
            logger.error(f"Error checking file hash: {e}")
            return {"allowed": True, "message": f"Hash check error: {e!s}"}

    def validate_content_type(self, filename: str, content_type: str) -> dict[str, Any]:
        """
        Validate content type against filename extension.

        Args:
            filename: Filename to check
            content_type: Content type from upload

        Returns:
            Dict with validation results
        """
        if not self.enabled:
            return {"valid": True, "message": "Validation disabled"}

        try:
            # Extract file extension
            file_ext = Path(filename).suffix.lower()
            if not file_ext:
                return {"valid": False, "message": "File must have an extension"}

            # Check if content type is allowed for this extension
            allowed_types = self.content_type_mappings.get(content_type, set())
            if file_ext in allowed_types:
                return {
                    "valid": True,
                    "message": f"Content type {content_type} is valid for {file_ext} files",
                }

            # Check for reasonable content type matches
            if content_type.startswith("text/") and file_ext in {
                ".txt",
                ".md",
                ".json",
                ".csv",
            }:
                return {
                    "valid": True,
                    "message": f"Text content type is reasonable for {file_ext} files",
                }

            if content_type.startswith("image/") and file_ext in {
                ".jpg",
                ".jpeg",
                ".png",
                ".gif",
                ".webp",
            }:
                return {
                    "valid": True,
                    "message": f"Image content type is reasonable for {file_ext} files",
                }

            return {
                "valid": False,
                "message": f"Content type {content_type} is not valid for {file_ext} files",
            }

        except Exception as e:
            logger.error(f"Error validating content type: {e}")
            return {
                "valid": False,
                "message": f"Content type validation error: {e!s}",
            }

    def add_malicious_file_hash(
        self,
        file_hash: str,
        filename: str,
        threat_level: str,
        description: str,
        reported_by: str | None = None,
    ):
        """Add a malicious file hash to the database."""
        entry = FileHashEntry(
            hash_value=file_hash,
            filename=filename,
            threat_level=threat_level,
            description=description,
            reported_by=reported_by,
        )

        self.file_hash_db[file_hash] = entry
        logger.info(f"Added malicious file hash: {file_hash} ({filename})")

    def remove_malicious_file_hash(self, file_hash: str):
        """Remove a hash from the malicious file database."""
        if file_hash in self.file_hash_db:
            del self.file_hash_db[file_hash]
            logger.info(f"Removed malicious file hash: {file_hash}")

    def get_validation_stats(self) -> dict[str, Any]:
        """Get content validation statistics."""
        if not self.enabled:
            return {"enabled": False}

        return {
            "enabled": True,
            "metrics": self.metrics.copy(),
            "rules_count": {
                "sql_injection": len(
                    [r for r in self.sql_injection_rules if r.enabled]
                ),
                "xss": len([r for r in self.xss_rules if r.enabled]),
                "command_injection": len(
                    [r for r in self.command_injection_rules if r.enabled]
                ),
                "path_traversal": len(
                    [r for r in self.path_traversal_rules if r.enabled]
                ),
            },
            "malicious_hashes_count": len(self.file_hash_db),
            "content_types_supported": len(self.content_type_mappings),
        }

    def update_config(self, new_config: dict[str, Any]):
        """Update content validation configuration."""
        if not self.enabled:
            return

        self.config.update(new_config)
        logger.info("Content validation configuration updated")

    async def shutdown(self):
        """Shutdown the content validation system."""
        logger.info("Content validation system shut down")


__all__ = ["ContentValidationSystem", "FileHashEntry", "ValidationRule"]
