# Errors Refactor Plan

## Overview

### Problem Statement
The `src/plexichat/core/errors/` directory contains four files with significant duplication:
- **error_codes.py** (700 lines): Comprehensive error system with `ErrorCategory`, `ErrorSeverity` enums, `PlexiChatErrorCode`, mappings, `ErrorResponse`, `PlexiChatException`, and functions like `create_error_response`, `handle_exception` (not present, but related helpers).
- **error_manager.py** (292 lines): Error management with its own `create_error_response` and `handle_exception`.
- **exceptions.py** (215 lines): Duplicated simpler `ErrorSeverity`, `ErrorCategory`, base exceptions, and `create_error_response`, `handle_exception`.
- **handlers.py** (67 lines): FastAPI error handlers (404, 500) without duplication but reliant on error responses.

Duplications lead to inconsistent error responses (e.g., different formats for JSON/HTML), maintenance overhead, and potential bugs from divergent implementations. Total lines: ~1274. Refactor goal: Consolidate into a single base system, reducing by ~150-200 lines while preserving all functionality.

### Verification of Change
Centralizing enums and functions into a new `base.py` improves consistency (one source for severity/category mappings), reduces bugs (no divergent implementations), and maintains existing usage (via imports). No breaking changes: All enums/functions remain equivalent; handlers.py's HTML/JSON responses preserved by integrating with base error creation. Line reduction: Remove duplicated enums (~50 lines in exceptions.py), redundant functions (~100 lines across files). Centralized maintenance: Update enums/mappings in one place. No new bugs: Preserve response formats (e.g., user vs. technical messages).

### Scope and Non-Functional Requirements
- Do not remove functionality: Retain all error codes, exception classes, response formats.
- Preserve integrations: FastAPI handlers in handlers.py unchanged externally; internal calls updated to base.
- Output: This plan only; no code execution.

## File-by-File Changes

Create new `src/plexichat/core/errors/base.py` (new file, ~400 lines) consolidating:
- Enums: Use comprehensive versions from error_codes.py (ErrorCategory with 14 values, ErrorSeverity with 4 levels).
- Core classes: `PlexiChatErrorCode`, `ErrorCodeMapping`, `ErrorResponse`, `PlexiChatException`.
- Functions: Unified `create_error_response` (from error_codes.py, supporting details/context/correlation_id), `handle_exception` (integrate from exceptions.py and error_manager.py, returning ErrorContext and logging).
- Additional: `log_error` from error_codes.py; specialized creators (e.g., `create_validation_error_response`).

Migration strategy: Replace duplicates with imports from `base.py`; update calls to unified functions.

### error_codes.py
- **What to replace**: No major removals; this file is the most comprehensive. Remove or deprecate minor overlaps if any (none found). Add import: `from .base import ErrorCategory, ErrorSeverity` (already internal, but ensure consistency).
- **How to migrate**: Keep as primary source. Update any internal calls to use base functions if inconsistencies exist (e.g., ensure `create_error_response` calls base version). Remove `make_error_response` if redundant with base (consolidate into base). Expected reduction: ~20 lines (minor cleanups).
- **File-specific details**: Retain all 100+ error codes and mappings. No impact on external usage.

### error_manager.py
- **What to replace**: Duplicated `create_error_response` (lines 283-292), `handle_exception` (lines 278-281). `ErrorContext` dataclass is unique; keep but import enums from base.
- **How to migrate**: Add `from .base import ErrorCategory, ErrorSeverity, create_error_response, handle_exception, PlexiChatException`. Replace local `create_error_response` with base version. Update `handle_exception` to call base `handle_exception` and integrate with `ErrorManager.handle_error`. In `ErrorManager`, use base enums for severity/category. Expected reduction: ~50 lines.
- **File-specific details**: Preserve async background tasks, metrics, circuit breakers. Ensure `ErrorContext` uses base enums (e.g., `severity: str` updated to `ErrorSeverity`).

### exceptions.py
- **What to replace**: Duplicated `ErrorSeverity` (lines 13-19, simpler 4 values), `ErrorCategory` (lines 21-31, 8 values vs. 14 in base), `create_error_response` (lines 197-205), `handle_exception` (lines 166-195).
- **How to migrate**: Add `from .base import ErrorSeverity, ErrorCategory, create_error_response, handle_exception, PlexiChatException`. Remove local enums and functions. Update exception classes (e.g., `BaseAPIException`) to inherit from `PlexiChatException` where possible; set `self.severity = ErrorSeverity.HIGH` using enum. Update `to_dict` to match base `ErrorResponse.to_dict`. Expected reduction: ~100 lines.
- **File-specific details**: Keep specific exceptions (e.g., `AuthenticationError`); map to base error codes (e.g., raise `PlexiChatException(PlexiChatErrorCode.AUTH_INVALID_CREDENTIALS)`). Preserve `details` handling.

### handlers.py
- **What to replace**: No direct duplications, but error responses (e.g., in `internal_error_handler`) are simplistic. Import base for consistency.
- **How to migrate**: Add `from .base import create_error_response`. Update `internal_error_handler` to: `return JSONResponse(status_code=500, content=create_error_response(PlexiChatErrorCode.SYSTEM_INTERNAL_ERROR))`. For `not_found_handler`, use base for JSON: `content=create_error_response(PlexiChatErrorCode.FILE_NOT_FOUND, details={"path": str(request.url.path)})`; keep HTML as-is for user-friendliness. Expected reduction: ~10 lines (inline simplifications).
- **File-specific details**: Preserve HTML response for 404 (non-breaking). Ensure FastAPI integration unchanged externally.

Overall: Create `base.py` first, then update files with imports. Use relative imports (`from .base import ...`) to avoid circular imports.

## Risk Mitigation

- **Low risk overall**: errors/ is isolated; no external dependencies shown. Impact limited to 4 files.
- **Circular imports**: Risk from mutual imports (e.g., error_manager importing base, base using manager). Mitigation: Design base as pure (no manager deps); use forward refs or type hints. Test with `mypy src/plexichat/core/errors/` post-refactor.
- **Functionality loss**: Enums expanded (base has more categories); ensure no breaking by mapping old to new (e.g., exceptions.py's `ErrorCategory.AUTH` -> base `AUTHENTICATION`). Mitigation: Unit tests verify equivalence (e.g., `assert old_create_error_response() == base_create_error_response()`).
- **Response format changes**: Handlers.py HTML preserved; JSON unified. Mitigation: Test FastAPI endpoints (e.g., raise exceptions, check responses match pre-refactor).
- **Performance**: Background tasks in error_manager unchanged. Mitigation: Profile with `cProfile` if needed.
- **File-specific risks**:
  - error_codes.py: Minimal; just cleanups.
  - error_manager.py: Async tasks; test `handle_error` integration.
  - exceptions.py: Exception inheritance; test raising/handling.
  - handlers.py: FastAPI; test 404/500 responses in dev server.

General: Version control branch (`git checkout -b refactor-errors`); commit per file.

## Testing Steps

1. **Unit Tests**: Add/update tests in `tests/unit/test_errors/`:
   - Test enums equivalence: `assert ErrorSeverity.LOW == "low"`.
   - Test functions: `assert create_error_response(code) has keys ['success', 'error']`; compare old vs. new outputs.
   - Exception raising: `with pytest.raises(PlexiChatException): raise ValidationError(...)`; verify `to_dict()`.
   - Coverage: Aim 90%+ for errors/ (use `pytest --cov=src/plexichat/core/errors`).

2. **Integration Tests**: In `tests/integration/`:
   - Mock FastAPI app; test handlers.py: `client.get("/nonexistent")` returns 404 with correct JSON/HTML.
   - Test error_manager: `handle_exception(Exception())` updates metrics.

3. **Static Analysis**: Run `mypy`, `flake8`, `black` on errors/. Fix circular imports.

4. **Manual/End-to-End**: Run app (`uvicorn`); trigger errors (e.g., invalid auth); verify logs/responses. Use `pytest tests/e2e/` for API flows.

5. **Regression**: Compare pre/post line counts; ensure no new warnings in `pytest -v`.

This plan reduces duplication, centralizes maintenance, and preserves functionality with minimal risk.