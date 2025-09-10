# Logging Refactor Plan

## Overview

### Problem Statement
The logging module in `src/plexichat/core/logging/` suffers from significant code duplication across four files: `__init__.py`, `unified_logger.py`, `pii_redaction.py`, and `unicode_utils.py`. Key duplicated elements include:
- Sanitization functions: `redact_pii()` and `sanitize_for_logging()`.
- Formatter classes: `ColoredFormatter` and `StructuredFormatter`.
- Handler setup: `RotatingFileHandler` configurations.

This duplication leads to inconsistent logging behavior, potential security leaks (e.g., inconsistent PII redaction), and maintenance challenges. The goal is to consolidate all shared functionality into `unified_logger.py` as the single source of truth, reducing redundancy while preserving all existing features such as PII redaction, Unicode sanitization, colored console output, and structured JSON formatting.

### Verification of Consolidation Benefits
Consolidating into `unified_logger.py` improves consistency by centralizing redaction and formatting logic in one place, ensuring uniform application across the codebase. This avoids breaking existing logger usage, as other files will import from `unified_logger.py` instead of duplicating code. Color output (ANSI codes) will be maintained via the `ColoredFormatter`. The refactor is estimated to reduce code by approximately 300 lines by eliminating repeated definitions and setups. Maintenance is centralized (e.g., one `redact_pii` function to update for security patches), with no new bugs introduced if migrations preserve exact functionality equivalence.

### Scope and Non-Functional Requirements
- **Preserve Functionality**: All features remain equivalent—no loss of PII redaction, Unicode handling, colored console logging, JSON-structured output, or plugin-specific handlers in `unified_logger.py`.
- **No Breaking Changes**: Existing logger calls (e.g., `logger.info()`) continue to work without modification outside logging/.
- **Centralization**: `unified_logger.py` will include a handler factory function for shared setups, utility methods for sanitization, and formatter classes.
- **Dependencies**: Ensure no circular imports by making utils independent (e.g., import utils from `unified_logger.py`).

This plan focuses solely on planning; implementation will occur in a subsequent mode (e.g., Code mode).

## File-by-File Changes

### logging/__init__.py
- **Current Issues**: Duplicated formatter classes (`ColoredFormatter`, `StructuredFormatter`) and basic handler setups (e.g., `RotatingFileHandler` initialization).
- **Replacements**:
  - Remove duplicated `ColoredFormatter` and `StructuredFormatter` classes.
  - Remove any inline `redact_pii()` or `sanitize_for_logging()` implementations.
  - Replace handler setups with imports from `unified_logger.py`, e.g., use `unified_logger.get_handler_factory(level='INFO', rotation_max_bytes=10*1024*1024)`.
- **Migration Steps**:
  - Add imports: `from .unified_logger import get_logger, ColoredFormatter, StructuredFormatter, get_handler_factory, redact_pii, sanitize_for_logging`.
  - Update `__init__.py` to expose these as module-level: `get_logger = unified_logger.get_logger`.
  - Ensure `__init__.py` only handles module initialization and re-exports, not duplicating logic.
- **Expected Impact**: Reduces file size by ~100 lines; becomes a thin wrapper for unified access.

### unified_logger.py
- **Current Issues**: Acts as partial source but lacks full consolidation; may have some duplicated sanitization or formatters.
- **Replacements**:
  - Add missing `redact_pii()` and `sanitize_for_logging()` as standalone functions or class methods.
  - Ensure `ColoredFormatter` and `StructuredFormatter` are defined here if not already (or consolidate from others).
  - Centralize handler setup in a factory function: `def get_handler_factory(level='INFO', format_type='colored', rotation_max_bytes=10*1024*1024, backup_count=5):` returning configured `RotatingFileHandler`.
- **Migration Steps**:
  - Integrate code from other files: Copy `redact_pii` logic from `pii_redaction.py` and `sanitize_for_logging` from `unicode_utils.py`.
  - Update logger setup to apply sanitization in the formatter pipeline, e.g., `formatter = ColoredFormatter(sanitize_func=redact_pii)`.
  - Preserve plugin-specific handlers (e.g., for analytics or security plugins) by making the factory extensible: `get_handler_factory(plugin_mode='analytics')`.
  - Add docstrings for all centralized functions/classes to document usage.
- **Expected Impact**: Grows by ~150 lines with consolidated code but eliminates the need for duplication elsewhere; becomes the core module.

### pii_redaction.py
- **Current Issues**: Standalone `redact_pii()` function, potentially duplicated elsewhere.
- **Replacements**:
  - Remove the entire `redact_pii()` function definition.
  - Remove any related imports or tests specific to this file's implementation.
- **Migration Steps**:
  - Move `redact_pii` implementation to `unified_logger.py` as `def redact_pii(message: str, patterns: list = None) -> str:`.
  - In this file, add import: `from .unified_logger import redact_pii`.
  - If the file has additional PII-specific logic (e.g., pattern configurations), migrate those as constants in `unified_logger.py` (e.g., `DEFAULT_PII_PATTERNS`).
  - Delete the file if it becomes empty after migration; otherwise, repurpose as a thin wrapper if needed for legacy.
- **Expected Impact**: Reduces file to minimal or eliminates it (~80 lines saved); all calls now import from unified.

### unicode_utils.py
- **Current Issues**: Standalone `sanitize_for_logging()` for Unicode handling, duplicated in other places.
- **Replacements**:
  - Remove the entire `sanitize_for_logging()` function definition.
  - Remove any Unicode-specific handler or formatter snippets.
- **Migration Steps**:
  - Move `sanitize_for_logging` to `unified_logger.py` as `def sanitize_for_logging(message: str) -> str:` integrating with redaction pipeline.
  - In this file, add import: `from .unified_logger import sanitize_for_logging`.
  - If additional Unicode utils exist (e.g., encoding fallbacks), consolidate as helper methods in `unified_logger.py`.
  - Delete the file if empty post-migration.
- **Expected Impact**: Reduces file to minimal or eliminates it (~70 lines saved); ensures consistent Unicode handling centrally.

## Risk Mitigation

- **Overall Risk Level**: Medium. Logging affects all core modules (e.g., auth, database, plugins), so inconsistencies could lead to missed security events or crashes. Impact limited to 4 files, but propagation via imports could affect broader codebase.
- **File-Specific Risks and Mitigations**:
  - **__init__.py**: Risk of import errors post-removal. Mitigation: Use relative imports (`from .unified_logger import ...`); verify no circular dependencies by running `python -m src.plexichat.core.logging` in isolation.
  - **unified_logger.py**: Risk of over-consolidation breaking plugin handlers. Mitigation: Make factory extensible with optional params; preserve backward-compatible signatures (e.g., `get_logger(name='default')` unchanged).
  - **pii_redaction.py**: Risk of incomplete PII patterns leading to leaks. Mitigation: Audit patterns during migration; add unit tests for equivalence (e.g., input-output matching pre/post-refactor).
  - **unicode_utils.py**: Risk of Unicode errors on Windows/Linux. Mitigation: Test sanitization with diverse inputs (e.g., emojis, non-ASCII); ensure ANSI color compatibility via `colorama` if needed.
- **General Mitigations**:
  - **Security**: Centralization reduces leak risks by ensuring uniform redaction; validate no bypassed sanitization paths.
  - **Compatibility**: Maintain ANSI colors for console (use `ColoredFormatter` with term detection); support JSON via `StructuredFormatter` without format changes.
  - **Dependencies**: Make utils independent—no imports back to other logging files; use type hints for clarity.
  - **Rollback**: Git branch for refactor; if issues, revert to duplicated state.
  - **Performance**: Handler factory caching to avoid recreation overhead.

## Testing Steps

1. **Unit Tests**:
   - Write/add tests in `tests/unit/test_logging.py` for each centralized function: e.g., `test_redact_pii` with sample PII inputs, `test_sanitize_for_logging` with Unicode strings.
   - Test formatters: `test_colored_formatter` verifies ANSI output equivalence; `test_structured_formatter` checks JSON structure.
   - Test handler factory: `test_get_handler_factory` ensures rotation and level configs match pre-refactor.

2. **Integration Tests**:
   - In `tests/integration/test_core_logging.py`, simulate logger usage across modules (e.g., log from auth service) and verify output consistency (redacted, colored, rotated files).
   - Cross-platform: Run tests on Windows/Linux to confirm color/Unicode handling (use pytest-xdist for parallel).

3. **End-to-End Tests**:
   - In `tests/e2e/test_plexichat_logging.py`, trigger app logs (e.g., via API calls) and inspect output files/console for equivalence to current behavior.
   - Security-focused: Test for PII leaks by logging sensitive data and asserting redaction.

4. **Manual Verification**:
   - Run app locally: `python -m src.plexichat` and check console/logs for colors, structure, no errors.
   - Pytest coverage: Ensure >90% for logging module; run `pytest --cov=src/plexichat/core/logging`.

5. **Post-Refactor Checks**:
   - Line count reduction: Verify ~300 lines saved via `git diff --stat`.
   - No new bugs: Run full test suite (`pytest`); check for import errors or runtime logging failures.
   - Commit: `git add . && git commit -m "Refactor logging: consolidate duplication into unified_logger.py"`.

This plan ensures a safe, functional refactor. Implementation should follow this exactly.