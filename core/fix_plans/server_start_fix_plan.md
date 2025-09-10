# Server Start Fix Plan: NameError 'dataclass' not defined

## Overview

The error "NameError: name 'dataclass' is not defined" occurs during server startup when running `python run.py`, specifically during imports of core modules. This is caused by the use of the `@dataclass` decorator or `dataclass` references without proper backporting for Python versions below 3.7, where dataclasses are natively available. The refactors likely introduced or expanded dataclass usage in core files (e.g., for structured error handling and notifications).

**Fix Approach:** Add `from __future__ import dataclass` at the top of each affected file. This provides a backport for Python 3.6+ compatibility without requiring a Python upgrade, preserving all refactored functionality. No features will be removed; dataclasses remain in use for better code structure in errors and notifications. Impact on refactors: Minimal, as this is a non-breaking import addition. The fix enables server start without bloat (single-line import) or new bugs, assuming no version-specific conflicts.

**Commit Message:** "Fix server start: add __future__.dataclasses imports to core files for Python 3.6+ compatibility"

## Affected Files

A scan of core/ Python files revealed dataclass usage in the following 3 files (no usage found in monitoring/ as initially suspected):

1. **core/errors/base.py** (Lines 2, 36, 80): Uses `from dataclasses import dataclass, field` and defines `@dataclass` classes `ErrorCodeMapping` and `ErrorResponse`. Likely a primary culprit during error module imports.

2. **core/errors/error_manager.py** (Lines 4, 18): Uses `from dataclasses import dataclass` and defines `@dataclass` class `ErrorContext`.

3. **core/notifications/notification_manager.py** (Lines 3, 21): Uses `from dataclasses import dataclass` and defines `@dataclass` class `QueuedNotification`.

These files are part of the core error handling and notification systems, which are imported early in `run.py`. Adding the __future__ import to each ensures consistent backporting.

## Fix Steps

1. **Update core/errors/base.py**: Insert `from __future__ import dataclass` as the very first import line (before any other imports). Retain existing `from dataclasses import dataclass, field` for compatibility.

2. **Update core/errors/error_manager.py**: Insert `from __future__ import dataclass` as the first import line. Retain `from dataclasses import dataclass`.

3. **Update core/notifications/notification_manager.py**: Insert `from __future__ import dataclass` as the first import line. Retain `from dataclasses import dataclass`.

4. **Verify run.py imports**: No changes needed to `run.py`, as the fix is localized to the affected modules. Ensure no circular imports are introduced (unlikely, as this is just an import addition).

5. **Git commit**: After changes, commit with the message: "Fix server start: add __future__.dataclasses imports to core files for Python 3.6+ compatibility".

No other files require changes, as the scan confirmed no additional dataclass usage in core/.

## Risk Mitigation

- **Risk Level:** Low. The __future__ import is a standard, non-intrusive backport that doesn't alter runtime behavior in Python 3.7+. It resolves the NameError without side effects.

- **Potential Issues:**
  - **Python 3.6 Compatibility:** If running on Python <3.6, the backport won't work (dataclasses require 3.6+). Mitigation: Add a version check in `run.py` (e.g., `import sys; if sys.version_info < (3, 6): raise RuntimeError("Python 3.6+ required")`) to fail early with a clear message.
  - **Import Order Conflicts:** __future__ must be first; placing it correctly avoids syntax errors. Mitigation: Manually verify import order post-change.
  - **Impact on Refactors:** Refactors in errors/ and notifications/ rely on dataclasses for structure; this preserves them. No functionality loss, but if any file uses dataclass features not backported (rare), it could fail—mitigate by testing.
  - **Broader Core Impact:** If other core/ files import these affected modules, the error would propagate; this fix resolves at the source. No scanning needed beyond core/, as the error is import-time.

- **General Mitigation:** 
  - Test on Python 3.6 and 3.7+ environments (e.g., via CI or local virtualenvs).
  - Add a warning in `run.py` if Python <3.7: `if sys.version_info < (3, 7): print("Warning: Using dataclass backport; consider upgrading to 3.7+")`.
  - No performance overhead from the import.

## Testing Steps

1. **Local Startup Test:** Run `python run.py` on current Python version. Verify no NameError and server starts successfully (check logs for clean imports).

2. **Version-Specific Tests:**
   - Python 3.6: Create a virtualenv with Python 3.6, install deps, run `python run.py`. Confirm server starts and dataclasses function (e.g., instantiate ErrorResponse).
   - Python 3.7+: Run on native setup; ensure no regressions.

3. **Functionality Smoke Tests:**
   - Trigger an error (e.g., via API call) to test error handling/dataclasses in base.py and error_manager.py.
   - Send a notification to test QueuedNotification in notification_manager.py.
   - Verify refactors remain intact: Check that all 9 prior refactors (e.g., fallbacks, unified monitoring) load without issues.

4. **Full Integration:** Once server starts, proceed to curl/manual WebUI/pentest as per parent task. If issues arise, rollback commit and investigate Python version.

5. **CI/CD:** Add to CI pipeline: Test startup on multiple Python versions, fail if <3.6 or import errors occur.

This plan ensures a robust fix, enabling the server for testing while maintaining compatibility and refactor integrity.