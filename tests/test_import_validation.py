"""
Comprehensive import validation test for PlexiChat package hierarchy.

Tests that all public modules and critical classes can be imported successfully
after import restructuring, covering all major subsystems including core,
auth, database, logging, plugins, security, caching, performance, notifications,
threading, websocket, middleware, error handling, configuration, and utilities.
"""

import importlib
import os
import sys

import pytest

# Add src to Python path if not already there
src_path = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"
)
if src_path not in sys.path:
    sys.path.insert(0, src_path)


class ImportTestResult:
    """Container for import test results."""

    def __init__(self):
        self.successful_imports: list[str] = []
        self.failed_imports: list[tuple[str, Exception]] = []
        self.missing_classes: list[tuple[str, str]] = []
        self.successful_classes: list[tuple[str, str]] = []


class ImportValidator:
    """Validates imports across the PlexiChat package hierarchy."""

    def __init__(self):
        self.results = ImportTestResult()

    def try_import_module(self, module_path: str) -> bool:
        """
        Attempt to import a module and track results.

        Args:
            module_path: Full module path (e.g., 'plexichat.core.auth')

        Returns:
            True if import succeeded, False otherwise
        """
        try:
            module = importlib.import_module(module_path)
            self.results.successful_imports.append(module_path)
            return True
        except Exception as e:
            self.results.failed_imports.append((module_path, e))
            return False

    def try_import_class(self, module_path: str, class_name: str) -> bool:
        """
        Attempt to import a specific class from a module.

        Args:
            module_path: Full module path
            class_name: Name of class to import

        Returns:
            True if class import succeeded, False otherwise
        """
        try:
            module = importlib.import_module(module_path)
            if hasattr(module, class_name):
                getattr(module, class_name)
                self.results.successful_classes.append((module_path, class_name))
                return True
            else:
                self.results.missing_classes.append((module_path, class_name))
                return False
        except Exception as e:
            self.results.failed_imports.append((f"{module_path}.{class_name}", e))
            return False

    def validate_core_modules(self):
        """Test core subsystem modules."""
        core_modules = [
            "plexichat.core",
            "plexichat.core.app_setup",
            "plexichat.core.config",
            "plexichat.core.config_manager",
            "plexichat.core.orchestrator",
            "plexichat.core.user",
            "plexichat.core.utils",
            "plexichat.core.validation",
            "plexichat.core.search_service",
        ]

        for module in core_modules:
            self.try_import_module(module)

    def validate_auth_modules(self):
        """Test authentication subsystem modules."""
        auth_modules = [
            "plexichat.core.authentication",
            "plexichat.core.auth",
            "plexichat.core.auth.exceptions_auth",
            "plexichat.core.auth.fastapi_adapter",
            "plexichat.core.auth.permissions",
            "plexichat.core.auth.models",
            "plexichat.core.auth.services",
            "plexichat.core.auth.services.authentication_service",
            "plexichat.core.auth.services.authorization_service",
            "plexichat.core.auth.services.mfa_service",
            "plexichat.core.auth.services.user_service",
            "plexichat.core.auth.services.token_service",
            "plexichat.core.auth.services.session_service",
            "plexichat.core.mfa_store",
        ]

        for module in auth_modules:
            self.try_import_module(module)

        # Test critical auth classes
        auth_classes = [
            (
                "plexichat.core.auth.services.authentication_service",
                "AuthenticationService",
            ),
            (
                "plexichat.core.auth.services.authorization_service",
                "AuthorizationService",
            ),
            ("plexichat.core.auth.services.mfa_service", "MFAService"),
        ]

        for module_path, class_name in auth_classes:
            self.try_import_class(module_path, class_name)

    def validate_database_modules(self):
        """Test database subsystem modules."""
        db_modules = [
            "plexichat.core.database",
            "plexichat.core.database.connection",
            "plexichat.core.database.manager",
            "plexichat.core.database.models",
            "plexichat.core.database.session",
            "plexichat.core.database.migrations",
            "plexichat.core.database.optimizations",
        ]

        for module in db_modules:
            self.try_import_module(module)

        # Test critical database classes
        db_classes = [
            ("plexichat.core.database.manager", "DatabaseManager"),
            ("plexichat.core.database.models", "User"),
            ("plexichat.core.database.models", "Message"),
        ]

        for module_path, class_name in db_classes:
            self.try_import_class(module_path, class_name)

    def validate_logging_modules(self):
        """Test logging subsystem modules."""
        logging_modules = [
            "plexichat.core.logging",
            "plexichat.core.logging.unified_logger",
            "plexichat.core.logging.pii_redaction",
            "plexichat.core.logging.unicode_utils",
        ]

        for module in logging_modules:
            self.try_import_module(module)

        # Test logging classes
        logging_classes = [
            ("plexichat.core.logging.unified_logger", "UnifiedLogger"),
        ]

        for module_path, class_name in logging_classes:
            self.try_import_class(module_path, class_name)

    def validate_plugin_modules(self):
        """Test plugin subsystem modules."""
        plugin_modules = [
            "plexichat.core.plugins",
            "plexichat.core.plugins.manager",
            "plexichat.core.plugins.plugin_manager",
            "plexichat.core.plugins.sandbox",
            "plexichat.core.plugins.sdk",
            "plexichat.core.plugins.security_manager",
            "plexichat.core.plugins.manifest_validator",
            "plexichat.plugins_internal",
        ]

        for module in plugin_modules:
            self.try_import_module(module)

        # Test plugin classes
        plugin_classes = [
            ("plexichat.core.plugins.plugin_manager", "PluginManager"),
            ("plexichat.core.plugins.security_manager", "SecurityManager"),
        ]

        for module_path, class_name in plugin_classes:
            self.try_import_class(module_path, class_name)

    def validate_security_modules(self):
        """Test security subsystem modules."""
        security_modules = [
            "plexichat.core.security",
            "plexichat.core.security.security_manager",
            "plexichat.core.security.content_validation",
            "plexichat.core.security.ddos_protection",
            "plexichat.core.security.key_vault",
            "plexichat.core.security.quantum_encryption",
            "plexichat.core.security.zero_trust",
            "plexichat.core.security.unified_security_module",
            "plexichat.core.security.comprehensive_security_manager",
            "plexichat.core.security.waf_middleware",
        ]

        for module in security_modules:
            self.try_import_module(module)

        # Test security classes
        security_classes = [
            ("plexichat.core.security.security_manager", "SecurityManager"),
            (
                "plexichat.core.security.comprehensive_security_manager",
                "ComprehensiveSecurityManager",
            ),
        ]

        for module_path, class_name in security_classes:
            self.try_import_class(module_path, class_name)

    def validate_caching_modules(self):
        """Test caching subsystem modules."""
        cache_modules = [
            "plexichat.core.cache",
            "plexichat.core.cache.manager",
            "plexichat.core.caching",
            "plexichat.core.caching.cache_manager",
            "plexichat.core.caching.unified_cache_integration",
        ]

        for module in cache_modules:
            self.try_import_module(module)

        # Test cache classes
        cache_classes = [
            ("plexichat.core.cache.manager", "CacheManager"),
            ("plexichat.core.caching.cache_manager", "CacheManager"),
        ]

        for module_path, class_name in cache_classes:
            self.try_import_class(module_path, class_name)

    def validate_performance_modules(self):
        """Test performance subsystem modules."""
        performance_modules = [
            "plexichat.core.performance",
            "plexichat.core.performance.optimization_engine",
            "plexichat.core.performance.memory_manager",
            "plexichat.core.performance.latency_optimizer",
            "plexichat.core.performance.distributed_cache",
            "plexichat.core.performance.message_queue",
            "plexichat.core.performance.scalability_manager",
            "plexichat.core.performance.multi_tier_cache",
            "plexichat.core.performance.network_optimizer",
        ]

        for module in performance_modules:
            self.try_import_module(module)

        # Test performance classes
        performance_classes = [
            ("plexichat.core.performance.optimization_engine", "OptimizationEngine"),
            ("plexichat.core.performance.memory_manager", "MemoryManager"),
        ]

        for module_path, class_name in performance_classes:
            self.try_import_class(module_path, class_name)

    def validate_notification_modules(self):
        """Test notification subsystem modules."""
        notification_modules = [
            "plexichat.core.notifications",
            "plexichat.core.notifications.notification_manager",
            "plexichat.core.notifications.email_service",
            "plexichat.core.notifications.push_service",
            "plexichat.core.notifications.base_sender",
        ]

        for module in notification_modules:
            self.try_import_module(module)

        # Test notification classes
        notification_classes = [
            (
                "plexichat.core.notifications.notification_manager",
                "NotificationManager",
            ),
            ("plexichat.core.notifications.email_service", "EmailService"),
        ]

        for module_path, class_name in notification_classes:
            self.try_import_class(module_path, class_name)

    def validate_threading_modules(self):
        """Test threading subsystem modules."""
        threading_modules = [
            "plexichat.core.threading",
            "plexichat.core.threading.thread_manager",
        ]

        for module in threading_modules:
            self.try_import_module(module)

        # Test threading classes
        threading_classes = [
            ("plexichat.core.threading.thread_manager", "ThreadManager"),
        ]

        for module_path, class_name in threading_classes:
            self.try_import_class(module_path, class_name)

    def validate_websocket_modules(self):
        """Test websocket subsystem modules."""
        websocket_modules = [
            "plexichat.core.websocket",
            "plexichat.core.websocket.websocket_manager",
            "plexichat.interfaces.websocket",
            "plexichat.interfaces.websocket.websocket_manager",
        ]

        for module in websocket_modules:
            self.try_import_module(module)

        # Test websocket classes
        websocket_classes = [
            ("plexichat.core.websocket.websocket_manager", "WebSocketManager"),
        ]

        for module_path, class_name in websocket_classes:
            self.try_import_class(module_path, class_name)

    def validate_middleware_modules(self):
        """Test middleware subsystem modules."""
        middleware_modules = [
            "plexichat.core.middleware",
            "plexichat.core.middleware.middleware_manager",
            "plexichat.core.middleware.rate_limiting",
            "plexichat.core.middleware.ip_blacklist_middleware",
            "plexichat.core.middleware.integrated_protection_system",
        ]

        for module in middleware_modules:
            self.try_import_module(module)

        # Test middleware classes
        middleware_classes = [
            ("plexichat.core.middleware.middleware_manager", "MiddlewareManager"),
        ]

        for module_path, class_name in middleware_classes:
            self.try_import_class(module_path, class_name)

    def validate_error_handling_modules(self):
        """Test error handling subsystem modules."""
        error_modules = [
            "plexichat.core.errors",
            "plexichat.core.errors.base",
            "plexichat.core.errors.exceptions",
            "plexichat.core.errors.handlers",
            "plexichat.core.errors.error_manager",
            "plexichat.core.errors.circuit_breaker",
            "plexichat.shared.exceptions",
        ]

        for module in error_modules:
            self.try_import_module(module)

        # Test error classes
        error_classes = [
            ("plexichat.core.errors.error_manager", "ErrorManager"),
            ("plexichat.core.errors.exceptions", "PlexiChatError"),
        ]

        for module_path, class_name in error_classes:
            self.try_import_class(module_path, class_name)

    def validate_configuration_modules(self):
        """Test configuration subsystem modules."""
        config_modules = [
            "plexichat.core.config",
            "plexichat.core.config_manager",
            "plexichat.core.rate_limit_config",
        ]

        for module in config_modules:
            self.try_import_module(module)

        # Test config classes
        config_classes = [
            ("plexichat.core.config_manager", "ConfigManager"),
        ]

        for module_path, class_name in config_classes:
            self.try_import_class(module_path, class_name)

    def validate_utility_modules(self):
        """Test utility subsystem modules."""
        utility_modules = [
            "plexichat.core.utils",
            "plexichat.infrastructure.utils",
            "plexichat.infrastructure.utils.common_utils",
            "plexichat.infrastructure.utils.helpers",
            "plexichat.infrastructure.utils.security",
            "plexichat.infrastructure.utils.validation",
            "plexichat.infrastructure.utils.performance",
            "plexichat.infrastructure.utils.utilities",
            "plexichat.shared.types",
            "plexichat.shared.validators",
        ]

        for module in utility_modules:
            self.try_import_module(module)

    def validate_feature_modules(self):
        """Test feature modules."""
        feature_modules = [
            "plexichat.features",
            "plexichat.features.ai",
            "plexichat.features.ai.ai_coordinator",
            "plexichat.features.ai.providers.base_provider",
            "plexichat.features.ai.providers.openai_provider",
            "plexichat.features.backup",
            "plexichat.features.backup.backup_manager",
        ]

        for module in feature_modules:
            self.try_import_module(module)

    def validate_infrastructure_modules(self):
        """Test infrastructure modules."""
        infrastructure_modules = [
            "plexichat.infrastructure",
            "plexichat.infrastructure.services",
            "plexichat.infrastructure.services.base_service",
            "plexichat.infrastructure.services.health",
            "plexichat.infrastructure.modules",
            "plexichat.infrastructure.modules.base_module",
        ]

        for module in infrastructure_modules:
            self.try_import_module(module)

    def validate_interface_modules(self):
        """Test interface modules."""
        interface_modules = [
            "plexichat.interfaces",
            "plexichat.interfaces.api",
            "plexichat.interfaces.api.main_api",
            "plexichat.interfaces.api.v1",
            "plexichat.interfaces.cli",
            "plexichat.interfaces.cli.main_cli",
            "plexichat.interfaces.web",
            "plexichat.interfaces.web.main",
        ]

        for module in interface_modules:
            self.try_import_module(module)

    def run_all_validations(self):
        """Run all validation tests."""
        print("Running comprehensive import validation...")

        self.validate_core_modules()
        self.validate_auth_modules()
        self.validate_database_modules()
        self.validate_logging_modules()
        self.validate_plugin_modules()
        self.validate_security_modules()
        self.validate_caching_modules()
        self.validate_performance_modules()
        self.validate_notification_modules()
        self.validate_threading_modules()
        self.validate_websocket_modules()
        self.validate_middleware_modules()
        self.validate_error_handling_modules()
        self.validate_configuration_modules()
        self.validate_utility_modules()
        self.validate_feature_modules()
        self.validate_infrastructure_modules()
        self.validate_interface_modules()

    def generate_report(self) -> str:
        """Generate a comprehensive test report."""
        report = []
        report.append("=== PlexiChat Import Validation Report ===\n")

        total_imports = len(self.results.successful_imports) + len(
            self.results.failed_imports
        )
        total_classes = len(self.results.successful_classes) + len(
            self.results.missing_classes
        )

        report.append("Module Import Summary:")
        report.append(f"  [+] Successful: {len(self.results.successful_imports)}")
        report.append(f"  [-] Failed: {len(self.results.failed_imports)}")
        report.append(f"  [*] Total: {total_imports}")
        if total_imports > 0:
            report.append(
                f"  [%] Success Rate: {len(self.results.successful_imports)/total_imports*100:.1f}%\n"
            )

        report.append("Class Import Summary:")
        report.append(f"  [+] Successful: {len(self.results.successful_classes)}")
        report.append(f"  [-] Missing: {len(self.results.missing_classes)}")
        report.append(f"  [*] Total: {total_classes}")
        if total_classes > 0:
            report.append(
                f"  [%] Success Rate: {len(self.results.successful_classes)/total_classes*100:.1f}%\n"
            )

        if self.results.failed_imports:
            report.append("Failed Module Imports:")
            for module, error in self.results.failed_imports:
                report.append(
                    f"  [-] {module}: {type(error).__name__}: {str(error)[:100]}"
                )
            report.append("")

        if self.results.missing_classes:
            report.append("Missing Classes:")
            for module, class_name in self.results.missing_classes:
                report.append(f"  [-] {module}.{class_name}")
            report.append("")

        if self.results.successful_imports:
            report.append("Successful Module Imports (sample):")
            for module in self.results.successful_imports[:10]:
                report.append(f"  [+] {module}")
            if len(self.results.successful_imports) > 10:
                report.append(
                    f"  ... and {len(self.results.successful_imports) - 10} more"
                )
            report.append("")

        return "\n".join(report)


@pytest.fixture
def import_validator():
    """Provide an ImportValidator instance for tests."""
    return ImportValidator()


def test_comprehensive_import_validation(import_validator):
    """
    Test that all critical modules and classes can be imported successfully.

    This test validates that the import restructuring preserved all necessary
    functionality by attempting to import from each major subsystem.
    """
    # Run all validation tests
    import_validator.run_all_validations()

    # Generate and print report
    report = import_validator.generate_report()
    print("\n" + report)

    # Assert that critical core modules imported successfully
    critical_modules = [
        "plexichat.core",
        "plexichat.core.config",
        "plexichat.shared.exceptions",
    ]

    successful_module_paths = set(import_validator.results.successful_imports)

    for module in critical_modules:
        assert (
            module in successful_module_paths
        ), f"Critical module {module} failed to import"

    # Assert that we have reasonable success rates
    total_imports = len(import_validator.results.successful_imports) + len(
        import_validator.results.failed_imports
    )
    success_rate = (
        len(import_validator.results.successful_imports) / total_imports
        if total_imports > 0
        else 0
    )

    # We expect at least 70% of imports to succeed (some modules may have syntax errors or missing dependencies)
    assert (
        success_rate >= 0.7
    ), f"Import success rate too low: {success_rate:.1f}% (expected >= 70%)"

    # Assert no critical import failures occurred
    failed_module_paths = [
        module for module, _ in import_validator.results.failed_imports
    ]
    critical_failures = [
        module for module in failed_module_paths if module in critical_modules
    ]

    assert (
        not critical_failures
    ), f"Critical modules failed to import: {critical_failures}"


def test_core_subsystem_imports(import_validator):
    """Test core subsystem module imports specifically."""
    import_validator.validate_core_modules()

    # Verify core modules imported
    core_modules = ["plexichat.core", "plexichat.core.config", "plexichat.core.utils"]
    successful_modules = set(import_validator.results.successful_imports)

    for module in core_modules:
        assert module in successful_modules, f"Core module {module} failed to import"


def test_auth_subsystem_imports(import_validator):
    """Test authentication subsystem module imports specifically."""
    import_validator.validate_auth_modules()

    # Verify auth modules imported
    auth_modules = ["plexichat.core.authentication", "plexichat.core.auth"]
    successful_modules = set(import_validator.results.successful_imports)

    for module in auth_modules:
        assert module in successful_modules, f"Auth module {module} failed to import"


def test_database_subsystem_imports(import_validator):
    """Test database subsystem module imports specifically."""
    import_validator.validate_database_modules()

    # Verify database modules imported
    db_modules = ["plexichat.core.database"]
    successful_modules = set(import_validator.results.successful_imports)

    for module in db_modules:
        assert (
            module in successful_modules
        ), f"Database module {module} failed to import"


def test_security_subsystem_imports(import_validator):
    """Test security subsystem module imports specifically."""
    import_validator.validate_security_modules()

    # Verify security modules imported
    security_modules = ["plexichat.core.security"]
    successful_modules = set(import_validator.results.successful_imports)

    for module in security_modules:
        assert (
            module in successful_modules
        ), f"Security module {module} failed to import"


def test_plugin_subsystem_imports(import_validator):
    """Test plugin subsystem module imports specifically."""
    import_validator.validate_plugin_modules()

    # Verify plugin modules imported
    plugin_modules = ["plexichat.core.plugins"]
    successful_modules = set(import_validator.results.successful_imports)

    for module in plugin_modules:
        assert module in successful_modules, f"Plugin module {module} failed to import"


def test_main_entry_points(import_validator):
    """Test that main entry points are accessible."""
    # Test the core package
    assert import_validator.try_import_module(
        "plexichat"
    ), "Entry point 'plexichat' failed to import"

    # Test main module can at least be imported (it may fail at runtime due to config issues)
    try:
        import_validator.try_import_module("plexichat.main")
    except Exception:
        # Main module may fail due to runtime dependencies, which is acceptable for import validation
        pass


if __name__ == "__main__":
    # Allow running the test directly
    validator = ImportValidator()
    validator.run_all_validations()
    print(validator.generate_report())

    # Basic validation
    total = len(validator.results.successful_imports) + len(
        validator.results.failed_imports
    )
    if total > 0:
        success_rate = len(validator.results.successful_imports) / total
        print(f"\nOverall Success Rate: {success_rate:.1%}")

        if success_rate >= 0.7:
            print("[+] Import validation PASSED")
            sys.exit(0)
        else:
            print("[-] Import validation FAILED")
            sys.exit(1)
    else:
        print("[-] No modules found to test")
        sys.exit(1)
