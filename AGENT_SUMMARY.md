# Agent Summary: PlexiChat Modernization and Hardening

This document gives a high-signal, current-state summary so any agent/engineer can continue immediately.

Last updated: now

## Objectives (from conversation requirements)
- Unify and harden rate limiting across the codebase (no duplicates; single module under middleware)
- Improve logging: ASCII-only, level discipline, per-plugin log files, latest.txt rotation, retention, crash logs, and WebUI viewer
- Strengthen auth and MFA (already integrated with MFA store and TOTP secrets; backup codes hashed)
- Introduce core cache module with strong encryption (AES-GCM via distributed key manager)
- Supervisor with backoff: monitor/restart websocket service and plugin manager; log structured metrics
- Remove duplicate systems and helpers across layers; keep interfaces thin and delegate to core
- Large config expansion (after current phase): everything configurable with schema/validation
- Keep run.py as server entrypoint; keep clean logs; no placeholders; no Unicode in logs

## Current State
- Rate Limiting
  - Canonical: `src/plexichat/core/middleware/rate_limiting/engine.py`
  - Features: strategies (global/ip/user/route/method/ua), algorithms (sliding/token/fixed), endpoint overrides, tier multipliers, concurrency and bandwidth enforcement, `check_user_action`/`check_ip_action`, headers on 429
  - Old modules removed: unified_rate_limiter.py, rate_limiter.py, dynamic/account/global middlewares, security/rate_limiting.py, infra/utils/rate_limiting.py
  - Security modules migrated (comprehensive, unified module, HSM, WAF); setup router migrated

- Logging
  - Unified logger writes to `logs/latest.txt`; ASCII-only sanitization; stack traces suppressed unless DEBUG
  - Per-plugin file handlers under `logs/plugins/<plugin>/<plugin>.log`
  - run.py: rotation (latest.txt -> timestamp log -> zipped), retention thread (configurable), crash logs (latest tail + crash trailer)
  - WebUI logs viewer: `/admin/logs` page (HTML), `/admin/logs/files` (JSON), `/admin/logs/view` (text) with level filter and tail

- Cache
  - Canonical: `plexichat.core.cache` (AES-GCM encryption using `distributed_key_manager` keys per security level); TTL/evictions; compression

- Supervisor
  - Structured metrics in main supervisor; configurable interval; restart/backoff path present and being finalized

- Dedup
  - Major duplicates removed or refactored to core modules; any stragglers being swept

## In-Flight Work (updated)
- Supervisor controlled restarts with exponential backoff: configuration integrated; restart paths present
- Full dedup sweep and cleanup
- Config expansion underway: logging/supervisor/caching integrated; next: security and rate limit schema wiring

## Immediate Next Steps
1) Supervisor: finalize restart/backoff and guards (main.py)
2) Dedup cleanup pass (remove remaining stragglers; verify no legacy imports)
3) Config expansion: add schemas and wire keys (logging.*, supervisor.*, cache.*, rate_limit.*, security.*)
4) WebUI log viewer polish (optional UI improvements)

## How to Run
- `python run.py` (server entrypoint)
- Logs under `logs/latest.txt` and `logs/plugins/*`

## Safety/Quality
- No placeholders; ASCII-only logs; stack traces only in DEBUG
- Rate limiting enforced centrally; security integrations tested along flows

## References
- TASKS_BACKLOG.md
- docs/LOGGING_IMPROVEMENT_PLAN.md
