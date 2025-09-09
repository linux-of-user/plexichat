# PlexiChat: Execution Task List (Authoritative Backlog)

This backlog is designed so another engineer/agent can continue seamlessly. It contains precise steps, file paths, acceptance checks, and commit suggestions. All code changes must keep logs ASCII-only and avoid placeholders.

Sections:
- A. Immediate next tasks
- B. In progress
- C. Completed (reference)
- D. Upcoming: Configuration expansion (high priority)
- E. Deduplication cleanup targets
- F. Verification and QA checklist
- G. Commit message templates

---

## A. Immediate next tasks (updated)

1) Finish migrating `interfaces/web/routers/setup.py` to unified rate limiter  ✅
   - File: `src/plexichat/interfaces/web/routers/setup.py`
   - Replace calls:
     - `stats = rate_limiter.get_stats()` -> `rl = get_rate_limiter(); stats = rl.get_stats()` (all occurrences)
     - `rate_limiter.check_rate_limit("global", ...)` and `rate_limiter.record_attempt("global")` -> `allowed, _info = await rl.check_user_action("global", "/setup/global"); if not allowed: raise 429`
     - Any other `rate_limiter.check_rate_limit(key, ...)` -> `allowed, _info = await rl.check_user_action(str(user_id_or_key), "/setup/user")`
   - Acceptance:
     - No imports from `plexichat.infrastructure.utils.rate_limiting`
     - All rate limit operations go through unified engine

2) Supervisor: ensure restart/backoff is robust  ✅ (interval/backoff configurable; restart paths present)
   - File: `src/plexichat/main.py`
   - Verify supervisor loop includes:
     - WebSocket service restart with exponential backoff (present)
     - Plugin manager shutdown/initialize with backoff (present)
     - Rate limiter reconfigure on failure (present)
   - Add TODO markers removed; no TODO/placeholder comments should remain.
   - Acceptance: Supervisor logs structured metrics and only ASCII text; runs without raising in normal conditions.

3) WebUI Log Viewer (admin)  ✅ (router implemented and included; needs UI polish)
   - File: `src/plexichat/interfaces/web/routers/admin.py`
   - Implement a log viewer that reads from:
     - `logs/latest.txt` (main)
     - `logs/plugins/<plugin>/<plugin>.log`
   - Add endpoints:
     - `GET /admin/logs/files` -> list available log files (main + plugins). JSON
     - `GET /admin/logs/view?file=<name>&level=<LEVEL>&tail_kb=<n>` -> returns filtered log content (server-side level filter; ASCII only). JSON or text
   - Template (optional if router returns JSON): `src/plexichat/interfaces/web/templates/admin/logs.html` already exists; augment as needed.
   - Acceptance: Able to fetch main log and per-plugin log text with level filter and tail size.

4) Dedup cleanup pass  ✅ (legacy infra rate limiter removed; further sweep ongoing)
5) WebUI logs UI page  ✅ (admin/logs HTML page with level filter and tail control)
   - Remove or neutralize unused rate limiting helper logic in `src/plexichat/infrastructure/utils/rate_limiting.py` after all references are migrated.
   - Confirm no imports of legacy modules exist for cache or rate limiting.
   - Acceptance: `grep` for old imports returns no matches.

---

## B. In progress

- Logging rotation/retention/crash logs: run.py changes are in place. Verify with runtime.
- Unified logger alignment: latest.txt handler, sanitization filter, stack-trace gating are in.
- Supervisor structured metrics and restarts: present; validate once more.

---

## C. Completed (reference)

- Unified rate limiting at `core/middleware/rate_limiting` with concurrency and bandwidth enforcement.
- Security modules migrated to unified engine: comprehensive manager, unified module, HSM, WAF.
- Cache module `core/cache` with AES-GCM, using keys from key manager.
- Plugin logging routed to per-plugin files via unified logger.
- `.gitignore` updated for logs, crash logs, and standard artifacts.
- `docs/LOGGING_IMPROVEMENT_PLAN.md` added.

---

## D. Configuration expansion (in progress)

Add new config keys with schema/validation and wire them:

- logging.*
  - logging.level (global and per handler), logging.format (text|json)
  - logging.retention_days (default 14)
  - logging.rotation.on_startup (bool, default true)
  - logging.rotation.compress (bool, default true)
  - logging.file.main (default "logs/latest.txt")
  - logging.plugins.enabled (default true)
  - logging.plugins.level (default INFO)
  - logging.debug_stacktraces (default false)
  - logging.crash.enabled (default true)
  - logging.crash.tail_kb (default 256)

- supervisor.*
  - supervisor.enabled (default true)
  - supervisor.interval_seconds (default 30)
  - supervisor.backoff_initial_seconds (default 5)
  - supervisor.backoff_max_seconds (default 300)

- cache.*
  - cache.max_size_mb, cache.default_ttl_seconds, cache.compression_enabled
  - cache.default_security_level (PUBLIC..TOP_SECRET)

- rate_limit.*
  - endpoint_overrides (map), user_tier_multipliers (map)

- security.*
  - sanitizer toggles; MFA requirements; plugin sandbox strictness

Process:
- Add schemas to config manager (logging/supervisor/caching/security/rate_limit done); wire remaining consumers
- Replace hard-coded defaults across modules
- Add docs in `docs/CONFIG_EXPANSION_PLAN.md`

---

## E. Deduplication cleanup targets

- `src/plexichat/infrastructure/utils/rate_limiting.py`: leave thin decorator that delegates to unified engine or remove if no longer used.
- WebSocket managers: ensure interface layer is a thin facade over `core/websocket` manager.
- Remove any lingering legacy cache/rate limiting files (already done).
- Confirm static assets canonical path `interfaces/web/static`.

---

## F. Verification and QA checklist

- Start via `python run.py`:
  - On startup: logs/latest.txt rotation and zip; new latest.txt created.
  - Retention thread running; no exceptions in logs.
  - Supervisor logs `[SUPERVISOR_METRICS]` entries.
  - Web and API endpoints respond; WAF fallback integrated as configured.
- Rate limiting:
  - Unified engine headers appear on 429 responses; concurrency and bandwidth limits enforced.
- Security:
  - WAF and security managers operational; no exceptions.
- Cache:
  - AES-GCM get/set works; entries evicted under pressure; no NotImplemented paths.
- Logging:
  - ASCII-only log lines, no stack traces unless DEBUG.
  - Plugin logs present at `logs/plugins/<plugin>/<plugin>.log`.
- WebUI Log Viewer:
  - `/admin/logs` loads
  - `/admin/logs/files` lists files
  - `/admin/logs/view` returns filtered content

---

## G. Commit message templates

- feat(supervisor): add controlled restarts with backoff for websocket service and plugin manager; structured metrics
- refactor(setup): migrate setup router to unified rate limiter (stats and checks)
- chore(dedup): remove unused infra rate limiting logic; ensure unified imports
- feat(admin/logs): implement WebUI log viewer API for latest.txt and plugin logs with level filtering
- feat(config): add logging.* and supervisor.* config keys with schema and validation
- chore(config): parameterize hard-coded values across modules (phase 1)
- docs(config): add CONFIG_EXPANSION_PLAN with key definitions and defaults
