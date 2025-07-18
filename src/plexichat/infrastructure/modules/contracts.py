# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import inspect
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Type, get_type_hints

import jsonschema

from ...core.logging import get_logger
from .interfaces import ()
import os
import time
import warnings


    BaseModule,
    Contracts,
    IModuleAPI,
    IModuleConfiguration,
    IModuleLifecycle,
    IModuleSecurity,
    Module,
    ModulePermissions,
    PlexiChat,
    Provides,
    System,
    Validation,
    """,
    all,
    and,
    checking,
    compliance,
    contract,
    ensure,
    for,
    interface,
    meet,
    modules,
    requirements,
    security,
    standards.,
    they,
    to,
    type,
    validation,
    verification,
)

logger = get_logger(__name__)


@dataclass
class ContractViolation:
    """Represents a contract violation."""
    severity: str  # "error", "warning", "info"
    category: str  # "interface", "security", "performance", "configuration"
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ContractValidationResult:
    """Result of contract validation."""
    is_valid: bool
    violations: List[ContractViolation] = field(default_factory=list)
    warnings: List[ContractViolation] = field(default_factory=list)
    score: float = 0.0  # Compliance score 0-100

    def add_violation(self, severity: str, category: str, message: str, details: Dict[str, Any] = None):
        """Add a contract violation."""
        violation = ContractViolation()
            severity=severity,
            category=category,
            message=message,
            details=details or {}
        )

        if severity == "error":
            self.violations.append(violation)
            self.is_valid = False
        elif severity == "warning":
            self.warnings.append(violation)

    def calculate_score(self):
        """Calculate compliance score."""
        total_issues = len(self.violations) + len(self.warnings)
        if total_issues == 0:
            self.score = 100.0
        else:
            # Errors are weighted more heavily than warnings
            error_weight = len(self.violations) * 10
            warning_weight = len(self.warnings) * 2
            total_weight = error_weight + warning_weight
            self.score = max(0.0, 100.0 - total_weight)


class ModuleContractValidator:
    """
    Validates modules against defined contracts and interfaces.

    Ensures modules comply with:
    - Interface requirements
    - Security standards
    - Performance constraints
    - Configuration schemas
    - API contracts
    """

    def __init__(self):
        self.required_interfaces = [
            IModuleLifecycle,
            IModuleConfiguration
        ]

        self.optional_interfaces = [
            IModuleAPI,
            IModuleSecurity
        ]

        # Configuration schema for modules
        self.base_config_schema = {
            "type": "object",
            "properties": {
                "name": {"type": "string", "minLength": 1},
                "version": {"type": "string", "pattern": r"^\d+\.\d+\.\d+$"},
                "description": {"type": "string"},
                "author": {"type": "string"},
                "license": {"type": "string"},
                "api_version": {"type": "string"},
                "min_plexichat_version": {"type": "string"},
                "capabilities": {
                    "type": "array",
                    "items": {"type": "string"}
                },
                "permissions": {
                    "type": "object",
                    "properties": {
                        "network_access": {"type": "boolean"},
                        "file_system_access": {"type": "boolean"},
                        "database_access": {"type": "boolean"},
                        "admin_access": {"type": "boolean"}
                    }
                }
            },
            "required": ["name", "version"]
        }

    async def validate_module(self, module: Any, module_class: Optional[Type] = None) -> ContractValidationResult:
        """Validate a module against all contracts."""
        result = ContractValidationResult()

        try:
            # 1. Interface compliance validation
            await self._validate_interfaces(module, result)

            # 2. Method signature validation
            await self._validate_method_signatures(module, result)

            # 3. Security validation
            await self._validate_security_compliance(module, result)

            # 4. Configuration validation
            await self._validate_configuration_compliance(module, result)

            # 5. Performance constraints validation
            await self._validate_performance_constraints(module, result)

            # 6. API contract validation
            await self._validate_api_contracts(module, result)

            # 7. Documentation validation
            await self._validate_documentation(module, result)

            # Calculate final compliance score
            result.calculate_score()

            logger.info(f"Module validation completed: {result.score:.1f}% compliance")

        except Exception as e:
            result.add_violation()
                "error",
                "validation",
                f"Validation process failed: {str(e)}"
            )
            logger.error(f"Module validation failed: {e}")

        return result

    async def _validate_interfaces(self, module: Any, result: ContractValidationResult):
        """Validate interface compliance."""
        # Check if module inherits from BaseModule
        if not isinstance(module, BaseModule):
            result.add_violation()
                "error",
                "interface",
                "Module must inherit from BaseModule",
                {"module_type": type(module).__name__}
            )

        # Check required interfaces
        for interface in self.required_interfaces:
            if not isinstance(module, interface):
                result.add_violation()
                    "error",
                    "interface",
                    f"Module must implement {interface.__name__}",
                    {"interface": interface.__name__}
                )

        # Check optional interfaces (warnings only)
        for interface in self.optional_interfaces:
            if not isinstance(module, interface):
                result.add_violation()
                    "warning",
                    "interface",
                    f"Module should consider implementing {interface.__name__}",
                    {"interface": interface.__name__}
                )

    async def _validate_method_signatures(self, module: Any, result: ContractValidationResult):
        """Validate method signatures match interface requirements."""
        required_methods = {
            "initialize": {"return_type": bool, "async": True},
            "start": {"return_type": bool, "async": True},
            "stop": {"return_type": bool, "async": True},
            "shutdown": {"return_type": bool, "async": True},
            "health_check": {"return_type": dict, "async": True},
            "get_metadata": {"return_type": dict, "async": False},
            "get_required_permissions": {"return_type": ModulePermissions, "async": False}
        }

        for method_name, requirements in required_methods.items():
            if not hasattr(module, method_name):
                result.add_violation()
                    "error",
                    "interface",
                    f"Missing required method: {method_name}"
                )
                continue

            method = getattr(module, method_name)

            # Check if method is callable
            if not callable(method):
                result.add_violation()
                    "error",
                    "interface",
                    f"Method {method_name} is not callable"
                )
                continue

            # Check if method is async when required
            if requirements["async"] and not inspect.iscoroutinefunction(method):
                result.add_violation()
                    "error",
                    "interface",
                    f"Method {method_name} must be async"
                )

            # Check return type hints (if available)
            try:
                type_hints = get_type_hints(method)
                if "return" in type_hints:
                    expected_type = requirements["return_type"]
                    actual_type = type_hints["return"]

                    # Basic type checking (can be enhanced)
                    if expected_type != actual_type and not issubclass(actual_type, expected_type):
                        result.add_violation()
                            "warning",
                            "interface",
                            f"Method {method_name} return type mismatch",
                            {
                                "expected": str(expected_type),
                                "actual": str(actual_type)
                            }
                        )
            except Exception:
                # Type hints not available or invalid
                pass

    async def _validate_security_compliance(self, module: Any, result: ContractValidationResult):
        """Validate security compliance."""
        # Check if module declares required permissions
        if hasattr(module, "get_required_permissions"):
            try:
                permissions = module.get_required_permissions()
                if not isinstance(permissions, ModulePermissions):
                    result.add_violation()
                        "error",
                        "security",
                        "get_required_permissions must return ModulePermissions instance"
                    )
                else:
                    # Validate permission declarations
                    if permissions.is_privileged():
                        result.add_violation()
                            "warning",
                            "security",
                            "Module requires privileged access - ensure proper justification",
                            {"permissions": permissions.__dict__}
                        )

                    # Check for excessive permissions
                    if len(permissions.capabilities) > 10:
                        result.add_violation()
                            "warning",
                            "security",
                            "Module declares many capabilities - consider reducing scope",
                            {"capability_count": len(permissions.capabilities)}
                        )
            except Exception as e:
                result.add_violation()
                    "error",
                    "security",
                    f"Failed to get required permissions: {str(e)}"
                )

        # Check for security-sensitive method names
        sensitive_methods = ["exec", "eval", "open", "subprocess", "os.system"]
        module_methods = [name for name in dir(module) if callable(getattr(module, name))]

        for method in module_methods:
            if any(sensitive in method.lower() for sensitive in sensitive_methods):
                result.add_violation()
                    "warning",
                    "security",
                    f"Method name '{method}' suggests potentially unsafe operations",
                    {"method": method}
                )

    async def _validate_configuration_compliance(self, module: Any, result: ContractValidationResult):
        """Validate configuration compliance."""
        if hasattr(module, "get_config_schema"):
            try:
                schema = module.get_config_schema()

                # Validate schema is valid JSON Schema
                try:
                    jsonschema.Draft7Validator.check_schema(schema)
                except jsonschema.SchemaError as e:
                    result.add_violation()
                        "error",
                        "configuration",
                        f"Invalid configuration schema: {str(e)}"
                    )

                # Check for required configuration fields
                if "properties" not in schema:
                    result.add_violation()
                        "warning",
                        "configuration",
                        "Configuration schema should define properties"
                    )

            except Exception as e:
                result.add_violation()
                    "error",
                    "configuration",
                    f"Failed to get configuration schema: {str(e)}"
                )

        # Test configuration validation
        if hasattr(module, "validate_config"):
            try:
                # Test with empty config
                if not module.validate_config({}):
                    result.add_violation()
                        "info",
                        "configuration",
                        "Module rejects empty configuration (may be expected)"
                    )

                # Test with invalid config
                if module.validate_config("invalid"):
                    result.add_violation()
                        "warning",
                        "configuration",
                        "Module accepts invalid configuration type"
                    )

            except Exception as e:
                result.add_violation()
                    "error",
                    "configuration",
                    f"Configuration validation method failed: {str(e)}"
                )

    async def _validate_performance_constraints(self, module: Any, result: ContractValidationResult):
        """Validate performance constraints."""
        # Check for performance-related attributes
        if hasattr(module, "configuration"):
            config = module.configuration

            # Check timeout settings
            if hasattr(config, "timeout_seconds"):
                if config.timeout_seconds > 300:  # 5 minutes
                    result.add_violation()
                        "warning",
                        "performance",
                        "Module timeout is very high - may impact system responsiveness",
                        {"timeout": config.timeout_seconds}
                    )

            # Check memory limits
            if hasattr(config, "max_memory_mb"):
                if config.max_memory_mb > 1000:  # 1GB
                    result.add_violation()
                        "warning",
                        "performance",
                        "Module memory limit is very high",
                        {"memory_limit": config.max_memory_mb}
                    )

        # Check for blocking operations in async methods
        async_methods = [name for name in dir(module)
                        if callable(getattr(module, name)) and
                        inspect.iscoroutinefunction(getattr(module, name))]

        if len(async_methods) == 0:
            result.add_violation()
                "warning",
                "performance",
                "Module has no async methods - may block event loop"
            )

    async def _validate_api_contracts(self, module: Any, result: ContractValidationResult):
        """Validate API contracts."""
        if hasattr(module, "get_available_methods"):
            try:
                methods = module.get_available_methods()
                if not isinstance(methods, list):
                    result.add_violation()
                        "error",
                        "interface",
                        "get_available_methods must return a list"
                    )
                else:
                    # Check if declared methods actually exist
                    for method_name in methods:
                        if not hasattr(module, method_name):
                            result.add_violation()
                                "error",
                                "interface",
                                f"Declared method '{method_name}' does not exist"
                            )
            except Exception as e:
                result.add_violation()
                    "error",
                    "interface",
                    f"Failed to get available methods: {str(e)}"
                )

    async def _validate_documentation(self, module: Any, result: ContractValidationResult):
        """Validate documentation compliance."""
        # Check for docstrings
        if not module.__doc__:
            result.add_violation()
                "warning",
                "documentation",
                "Module class lacks documentation"
            )

        # Check for method documentation
        methods_without_docs = []
        for name in dir(module):
            if (callable(getattr(module, name)) and)
                not name.startswith('_') and
                not getattr(module, name).__doc__):
                methods_without_docs.append(name)

        if methods_without_docs:
            result.add_violation()
                "warning",
                "documentation",
                f"Methods lack documentation: {', '.join(methods_without_docs[:5])}"
            )

    def generate_compliance_report(self, result: ContractValidationResult) -> str:
        """Generate a human-readable compliance report."""
        report = []
        report.append("=" * 60)
        report.append("MODULE COMPLIANCE REPORT")
        report.append("=" * 60)
        report.append(f"Overall Score: {result.score:.1f}%")
        report.append(f"Status: {'COMPLIANT' if result.is_valid else 'NON-COMPLIANT'}")
        report.append("")

        if result.violations:
            report.append("ERRORS:")
            for violation in result.violations:
                report.append(f"   [{violation.category.upper()}] {violation.message}")
            report.append("")

        if result.warnings:
            report.append("WARNINGS:")
            for warning in result.warnings:
                report.append(f"    [{warning.category.upper()}] {warning.message}")
            report.append("")

        if result.is_valid and not result.warnings:
            report.append(" Module fully compliant with all contracts!")

        return "\n".join(report)


# Global validator instance
_contract_validator: Optional[ModuleContractValidator] = None


def get_contract_validator() -> ModuleContractValidator:
    """Get the global contract validator instance."""
    global _contract_validator
    if _contract_validator is None:
        _contract_validator = ModuleContractValidator()
    return _contract_validator


# Export main components
__all__ = [
    "ContractViolation",
    "ContractValidationResult",
    "ModuleContractValidator",
    "get_contract_validator"
]
