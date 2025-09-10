# Notifications Refactor Plan

## Overview

### Problem Statement
The notifications/ directory contains three key files: `email_service.py`, `push_service.py`, and `notification_manager.py`. These files exhibit significant code duplication, particularly in template rendering via `_render_template()`, error handling for sending notifications, and async methods like `_send_*_notification()` (estimated at ~150 lines of repeated logic). This duplication leads to maintenance challenges, increased risk of inconsistencies, and inefficient code. The refactor aims to introduce a base `NotificationSender` class to centralize shared logic while preserving all existing functionality, such as platform-specific sending (e.g., SMTP for email, FCM for push), async operations, TTL for pushes, bulk sending in email, and queue processing in the manager.

### Proposed Solution
Create a new base class `NotificationSender` in a new file `notifications/base_sender.py`. This class will handle:
- Shared template rendering (`_render_template()` method).
- Common error handling for sending (e.g., retry logic, logging exceptions).
- Generic async sending skeleton (`async def _send_notification(self, ...)`).

Specific senders will inherit from this base:
- `EmailNotificationSender` for email_service.py (override `_send_via_smtp`).
- `PushNotificationSender` for push_service.py (override `_send_via_fcm` or platform-specific clients).
- `NotificationManager` will use instances of these senders, maintaining its queue logic.

### Verification of Improvement
- **Consistency Check**: The base class improves consistency by centralizing rendering and error handling without breaking platform-specific logic. For example, email retains SMTP configuration, push retains FCM and multi-platform support (e.g., APNS fallback). Async nature is preserved via `asyncio` methods in the base.
- **Code Reduction**: Estimated ~150 lines removed by eliminating duplicates; base class adds ~50-70 lines of shared code, netting a reduction. Shared logic (rendering, errors) is centralized in one place.
- **No New Bugs**: Maintain async sending with `await` in overrides; preserve TTL by passing it through base methods. All features remain: email templates, bulk sending (loop in override), push multi-platform, manager queue.
- **No Functionality Loss**: Equivalent behavior ensured by overriding only platform-specific parts; e.g., bulk sending in email uses base rendering but custom SMTP batching.

This refactor aligns with the larger PlexiChat duplication elimination effort, following patterns from previous plans (e.g., errors/, logging/).

## File-by-File Changes

### 1. New File: notifications/base_sender.py
- **Purpose**: Introduce `NotificationSender` abstract base class.
- **What to Add**:
  - Import necessary modules: `asyncio`, `logging`, template engine (e.g., Jinja2 if used).
  - Define `async def _render_template(self, template_name, context): ...` – central rendering logic.
  - Define `async def _send_notification(self, notification_data): ...` – skeleton with error handling (try/except, logging, retries).
  - Abstract methods: `async def _send_via_platform(self, rendered_content): ...` (to be overridden).
- **Migration**: Create from scratch; no existing code to replace.
- **Impact**: Low; new file isolated to notifications/.

### 2. email_service.py
- **What to Replace**:
  - Remove duplicated `_render_template()` (~30 lines).
  - Remove repeated error handling in `_send_email_notification()` (~50 lines).
  - Replace class definition with inheritance: `class EmailNotificationSender(NotificationSender):`.
- **How to Migrate**:
  - Add import: `from notifications.base_sender import NotificationSender`.
  - Override `async def _send_via_platform(self, rendered_content, recipient): ...` – implement SMTP sending using existing config.
  - Update public methods (e.g., `send_email()`) to call base `_send_notification()` with data, preserving bulk sending via a loop that uses the base.
  - Retain email-specific features: template paths, attachments if present.
- **Impact**: Medium; core sending logic refactored, but SMTP details unchanged. Estimated lines reduced: ~80.

### 3. push_service.py
- **What to Replace**:
  - Remove duplicated `_render_template()` (~30 lines).
  - Remove error handling in `_send_push_notification()` (~50 lines).
  - Replace class with `class PushNotificationSender(NotificationSender):`.
- **How to Migrate**:
  - Add import: `from notifications.base_sender import NotificationSender`.
  - Override `async def _send_via_platform(self, rendered_content, device_token): ...` – implement FCM/APNS logic, including `_get_platform_client()` for multi-platform.
  - Preserve TTL by passing to base or handling in override.
  - Update methods to use base rendering and sending, maintaining multi-platform routing.
- **Impact**: Medium; platform clients (FCM) unchanged, but shared logic centralized. Estimated lines reduced: ~80.

### 4. notification_manager.py
- **What to Replace**:
  - Minor: Update sender instantiation to use new subclasses (e.g., `email_sender = EmailNotificationSender()` instead of direct `EmailService()`).
  - No major duplication here, but ensure queue processing uses the refactored senders.
- **How to Migrate**:
  - Add imports for new senders.
  - In queue processing (`process_notification_queue()`), inject or instantiate senders and call their `send_notification()` methods, which now leverage base logic.
  - Preserve all queue features: prioritization, retries at manager level.
- **Impact**: Low; mostly import and instantiation changes. No line reduction here, but benefits from sender improvements.

### Overall Changes
- Total files affected: 4 (3 existing + 1 new).
- No circular imports: Base in `base_sender.py`, imported by services.
- Preserve async: All methods remain `async def`.

## Risk Mitigation

### Risks Identified
- **Low Overall Risk**: Changes isolated to notifications/; no impact on core app, auth, or other modules. Duplication is internal to sending logic.
- **File-Specific Risks**:
  - **email_service.py**: SMTP config breakage – mitigate by unit testing send success with mock SMTP.
  - **push_service.py**: FCM credential or TTL loss – mitigate by verifying multi-platform flows; test with mock FCM responses.
  - **notification_manager.py**: Queue incompatibility – mitigate by ensuring sender interfaces remain the same (e.g., `send(notification_data)` signature unchanged).
- **General Risks**: Regression in async handling or error propagation; potential import issues if base placement wrong.
- **Impact Assessment**: Affects only notification sending; failure would log errors but not crash app (existing fallbacks). No data loss.

### Mitigation Strategies
- **Import Safety**: Place base in `notifications/base_sender.py`; use absolute imports (e.g., `from .base_sender import ...`).
- **No Breaking Changes**: Keep public APIs identical; overrides only internal.
- **Version Control**: Commit incrementally (e.g., add base, refactor email, then push, then manager).
- **Dependency Check**: Ensure no external deps added; use existing (e.g., smtplib, firebase-admin).
- **Rollback Plan**: Revert to original by removing inheritance and restoring duplicated code.

## Testing Steps

### Unit Tests
- Add/update tests in `tests/unit/` for each sender:
  - Test base `_render_template()` with sample context.
  - Mock `_send_via_platform` to test base error handling (e.g., retry on exception).
  - For email: pytest mock SMTP, verify bulk send renders correctly.
  - For push: Mock FCM, test TTL and multi-platform routing.
  - Coverage goal: 90%+ for notifications/.

### Integration Tests
- In `tests/integration/`:
  - Full flow: Manager queues notification → sender processes → verify rendered/send success.
  - Async testing: Use `pytest-asyncio` for concurrent sends.
  - Error scenarios: Simulate SMTP/FCM failures, check error logging without crashes.

### End-to-End Tests
- In `tests/e2e/`:
  - Trigger notifications via API (e.g., user signup), verify delivery (mock external services).
  - Performance: Test queue throughput under load.

### Manual Verification
- Run app, send test notifications (email/push), check logs for no errors.
- Measure code reduction: Use `cloc` or manual count pre/post.
- Pytest suite: `pytest tests/unit/test_notifications.py -v` should pass 100%.

### Tools and Commands
- Pre-refactor: `git diff --stat` to baseline lines.
- Post-refactor: Run linters (e.g., black, mypy) and tests.
- If issues: Use `pdb` or logs to debug.

This plan ensures a clean, maintainable refactor with minimal risk.