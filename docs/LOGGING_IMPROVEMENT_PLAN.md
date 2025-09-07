# Logging Improvement Plan

This plan unifies logging across PlexiChat, improves manageability, and enforces clean, ASCII-only logs with strict levels.

## Objectives
- One logging system for all components (core, API, WebUI, plugins)
- No Unicode in logs; enforce ASCII-only sanitization filters
- Descriptive logs with levels (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- Stack traces are only emitted at DEBUG level (never on INFO/WARNING)
- Plugin-specific log files under `logs/plugins/{plugin_name}.log`
- Main log is `logs/latest.txt` (text format), written in real time
- On startup, roll previous latest.txt to a timestamped archive and zip it
- Configurable retention: delete old archives beyond configured age
- WebUI log viewer: can filter by log level and file; tail mode
- Crash logs: if run.py detects app crash, write a crash log that includes the logs plus a crash trailer; crash logs are never auto-deleted

## Design

### 1. Centralized Logger
- Keep the existing unified logger (src/plexichat/core/logging/unified_logger.py) as the single authority
- Add a sanitization filter to force ASCII-only and redact password/token/api_key/secret
- Ensure stack traces are attached only at DEBUG; at ERROR/CRITICAL, include sanitized error summary without trace
- Provide `get_logger(component, category)` to all consumers

### 2. Handlers and Files
- Main file: `logs/latest.txt`, text format (timestamp level component message)
- On startup:
  - If `logs/latest.txt` exists, rename to `logs/{YYYYmmdd_HHMMSS}.log` and zip as `logs/{YYYYmmdd_HHMMSS}.zip`
- Plugin logs:
  - Each plugin gets a dedicated file handler: `logs/plugins/{plugin_name}.log`
  - Handlers created dynamically on plugin load; closed on unload
- Error-only channel (optional): `logs/errors.txt` for ERROR+ if configured

### 3. Retention Policy
- Config: `logging.retention_days` (integer)
- On startup and periodically (daily job): delete archived logs older than `retention_days`
- Crash logs are excluded from deletion (pattern: `logs/crash/*.log`)

### 4. Crash Logs
- If `run.py` detects a crash (non-zero exit or exception), write `logs/crash/{YYYYmmdd_HHMMSS}.crash.log` containing:
  - The last N KB of `logs/latest.txt` (tail) for context
  - A crash trailer: time, exception summary, optional lightweight stack trace
- Crash logs are not auto-deleted by retention

### 5. WebUI Log Viewer
- Route: `/admin/logs` (auth + admin required)
- Features:
  - Select log file (latest, plugin files, errors)
  - Filter by level (DEBUG/INFO/WARNING/ERROR/CRITICAL)
  - Live tail mode (websocket)
  - Download log archive

### 6. Configuration Additions
- `logging.format = text|json` (default: text for readability in latest.txt)
- `logging.retention_days = 14`
- `logging.plugins.enabled = true`
- `logging.crash.enabled = true`

### 7. Implementation Steps
1. Rotation at startup in run.py
   - If `logs/latest.txt` exists -> rotate and zip
   - Create fresh `logs/latest.txt` handler with text formatter
2. Add plugin file handlers on plugin load/unload
3. Add retention job (daily) honoring `logging.retention_days`
4. Add crash log writer in run.py exception handling
5. Add WebUI log viewer (admin router + template) with level filtering

### 8. Quality Controls
- Unit tests: sanitization filter, rotation/zip, retention delete except crash logs
- Manual tests: plugin loading/unloading handlers, WebUI viewer, crash scenario

### 9. Backward Compatibility
- Keep existing console logging and security/performance logs as-is if configured
- Provide migration note: latest.txt replaces plexichat.log as the default consolidated file

