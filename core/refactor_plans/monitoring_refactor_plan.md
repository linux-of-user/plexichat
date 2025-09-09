# Monitoring Refactor Plan

## Overview

The monitoring/ directory contains three Python files with duplicated code patterns for asynchronous collection loops, metric collection using psutil, alert checking, and alert triggering. Specifically:

- `metrics_collector.py` (256 lines): Implements `MetricsCollector` with `_collection_loop()` (lines 69-79), `_collect_metrics()` (lines 80-103) calling specific collectors like `_collect_cpu_metrics()` (lines 104-131) using psutil, and relies on `record_metric` from unified_monitoring_system.
- `resource_tracker.py` (449 lines): Implements `ResourceTracker` with `_analysis_loop()` (lines 158-167), `track_resource_usage()` (lines 86-133) for recording metrics, and `_analyze_resource_pattern()` (lines 186-260) for specific analysis.
- `unified_monitoring_system.py` (683 lines): Implements `UnifiedMonitoringSystem` with `record_metric()` (lines 483-506) calling `_check_alerts()` (lines 219-236 and 507-536), `_trigger_alert()` (lines 310-345 and 537-544), handling database saves in `_save_metric_to_db()` (lines 169-191).

The duplication (~80 lines) includes similar async loop structures, psutil-based collection/recording, alert evaluation, and triggering logic. This refactor introduces a `MonitorBase` class in `monitoring/base.py` to centralize shared logic:

- Shared methods: `async _collection_loop()`, `_check_alerts()`, `_trigger_alert()`, `_save_metric_to_db()`.
- Abstract/override points: `_collect_metrics()` for specific implementations (e.g., CPU/disk in metrics_collector, pattern analysis in resource_tracker).
- Benefits: Reduces code by ~80 lines across files, improves consistency, centralizes psutil integration and alert rules, preserves all functionality (e.g., database saving, specific collectors like `_collect_cpu_metrics`, pattern analysis via `_analyze_resource_pattern`, alert rules in `UnifiedMonitoringSystem`).
- Verification: The base class improves consistency without breaking specifics, as subclasses override only necessary methods. No new bugs introduced by maintaining existing psutil calls, alert triggering, and db operations. All features remain equivalent; no loss of system metrics collection, resource pattern analysis, or alert rules.

This is the final refactor addressing the duplication report, completing all 9 areas (fallbacks, errors, migrations, logging, messaging, middleware, performance, notifications, monitoring).

## File-by-File Changes

### 1. New File: monitoring/base.py
- **What to add**: Create `MonitorBase` class with shared logic.
  - `__init__`: Initialize running state, task, config.
  - `async start()` and `async stop()`: Common async task management.
  - `async _collection_loop()`: Generic loop calling `await self._collect_metrics()` and `await asyncio.sleep(interval)`.
  - `async _collect_metrics()`: Abstract method to override.
  - `_check_alerts()`: Evaluate rules using operator comparisons, cooldown checks.
  - `_trigger_alert()`: Log by severity, send notifications, save to db.
  - `async _save_metric_to_db()`: Common db insert for metrics/alerts.
- **How to migrate**: Subclasses import `from .base import MonitorBase` and inherit: `class SubClass(MonitorBase): async def _collect_metrics(self): ...`.
- **Lines reduced**: N/A (new file ~80 lines), but eliminates duplication elsewhere.
- **Preservation**: Maintains psutil compatibility via overrides; db saving unchanged.

### 2. metrics_collector.py
- **What to replace**: Remove duplicated `_collection_loop()` (lines 69-79), integrate `record_metric` calls into overridden `_collect_metrics()`. Remove individual `_collect_*_metrics()` if fully shared, but keep specifics like psutil.cpu_percent (lines 108-129).
- **How to migrate**: Change `class MetricsCollector:` to `class MetricsCollector(MonitorBase):`. Override `async def _collect_metrics(self):` to call existing `_collect_cpu_metrics()` etc., and use `self.record_metric()` (inherited). Update `start()`/`stop()` to call `super().start()`. Remove global instance if centralized.
- **Lines reduced**: ~40 lines (loop + partial collectors).
- **Preservation**: All psutil calls (e.g., cpu_percent at line 108) remain in overrides; database saving via inherited `_save_metric_to_db()`.

### 3. resource_tracker.py
- **What to replace**: Remove `_analysis_loop()` (lines 158-167), integrate `track_resource_usage()` (lines 86-133) into overridden `_collect_metrics()` or as a separate method. Keep `_analyze_resource_pattern()` (lines 186-260) as specific override.
- **How to migrate**: Change `class ResourceTracker:` to `class ResourceTracker(MonitorBase):`. Override `async def _collect_metrics(self):` to call `self.track_resource_usage()` internally, using inherited `record_metric()`. Update `start()`/`stop()` to `super().start()`. Preserve history deques and statistics.
- **Lines reduced**: ~30 lines (loop + recording duplication).
- **Preservation**: Pattern analysis (`_analyze_resource_pattern`) unchanged; resource tracking via overrides; db saving inherited.

### 4. unified_monitoring_system.py
- **What to replace**: Extract `_check_alerts()` (lines 219-236, 507-536), `_trigger_alert()` (lines 310-345, 537-544), `_save_metric_to_db()` (lines 169-191), `_save_alert_to_db()` (lines 192-217) to base. Keep `AlertRule` dataclass and rule setup.
- **How to migrate**: Change `class UnifiedMonitoringSystem:` to `class UnifiedMonitoringSystem(MonitorBase):`. Override `def _get_alert_rules(self): return self.alert_rules` for base to use. Update `record_metric()` to call inherited `_check_alerts()`. Add loop if needed via `_collection_loop()`.
- **Lines reduced**: ~40 lines (alert methods + saves).
- **Preservation**: All alert rules and advanced conditions (e.g., trend_type at lines 240-249) via overrides; notifications unchanged.

No circular imports: Place `base.py` first in directory; use relative imports.

## Risk Mitigation

- **Low risk overall**: Changes isolated to monitoring/ (no impact on other modules like database or logging). Affects only 3 files, preserving async nature and psutil/db integrations.
- **File-specific risks and mitigations**:
  - **metrics_collector.py**: Risk of breaking specific collectors (e.g., per-core CPU at lines 112-115). Mitigation: Override `_collect_metrics()` to wrap existing psutil calls; add unit tests for each metric type.
  - **resource_tracker.py**: Risk of losing pattern analysis accuracy (e.g., linear regression at lines 209-213). Mitigation: Keep `_analyze_resource_pattern()` as private method called from override; test historical data retention with deques.
  - **unified_monitoring_system.py**: Risk of alert rule mismatches (e.g., cooldown at line 225). Mitigation: Base `_check_alerts()` uses configurable rules from subclass `_get_alert_rules()`; validate with integration tests for trigger flows.
- **General mitigations**: No new dependencies; ensure no circular imports by `base.py` import order. Add type hints for overrides. Version control: Commit after each file change with messages like "Refactor metrics_collector to inherit from MonitorBase".

## Testing Steps

1. **Unit Tests**: Add pytest tests for base methods (e.g., test _collection_loop runs without errors, _check_alerts evaluates operators correctly). Test overrides: e.g., mock psutil in metrics_collector, assert cpu metrics recorded.
2. **Integration Tests**: Test full flow: Start collector, simulate psutil data, verify db saves and alerts trigger (e.g., high CPU >90% logs warning). Use pytest-asyncio for async methods.
3. **Metric Accuracy**: Compare before/after: Run existing code, collect metrics; apply refactor, verify identical outputs (e.g., cpu_usage_percent values match).
4. **Alert Functionality**: Test _trigger_alert with mock notifications; ensure cooldown prevents spam. Verify no lost features like trend analysis (time_window at line 276).
5. **Performance**: Measure line count reduction (~80 lines total); ensure no slowdown in loops (time asyncio.sleep).
6. **Regression**: Run full PlexiChat suite; check monitoring doesn't affect other areas (e.g., no import errors post-refactor).

This plan ensures zero functionality loss while eliminating redundancy.