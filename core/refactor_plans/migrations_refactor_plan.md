# Migrations Refactor Plan: Consolidating Duplicated Migration Patterns

## Overview

### Problem Statement
The database migrations in `src/plexichat/core/database/migrations/` exhibit significant code duplication across three files: `add_new_schemas.py` (429 lines), `add_plugin_permissions.py` (600 lines), and `add_search_indexes.py` (135 lines). Each file implements similar async `up()` and `down()` (or equivalent `upgrade()`/`downgrade()`) functions with repeated patterns including:
- Database session management using `database_manager.get_session()`.
- Dialect-aware SQL generation for SQLite, PostgreSQL, and MySQL (e.g., `CREATE TABLE IF NOT EXISTS`, `SERIAL` vs. `AUTOINCREMENT`).
- Index creation with `CREATE INDEX IF NOT EXISTS`.
- Migration tracking (e.g., `schema_migrations` or `migrations` tables for recording applied versions).
- Error handling, logging with `logger.info/error`, and rollback SQL generation.
- Validation and verification functions (e.g., `validate_table_data()`, `verify_migration()`).
- CLI entry points for running `up`/`down`/`verify`.

This duplication (~100-200 lines per file of boilerplate) leads to maintenance challenges, such as inconsistent dialect support, repeated bug fixes, and difficulty in adding new features like advanced constraints or multi-database compatibility.

### Proposed Solution
Introduce a base `Migration` class in a new file `src/plexichat/core/database/migrations/base.py` to centralize common functionality. Subclasses for each migration will inherit from this base, overriding specific methods like `_get_tables()`, `_get_indexes()`, and `_get_constraints()` to define unique schema elements. The base class will handle:
- Generic `up()` and `down()` methods with session management, dialect detection, and migration recording.
- Helper methods: `_create_table()`, `_create_index()`, `_add_constraints()`, `_record_migration()`, `_rollback()`.
- Common patterns: Async/await preservation, SQL injection safety via parameterized queries, and rollback statement collection.

### Benefits and Verification
- **Maintainability Improvement**: Centralizes ~150 lines of duplicated code (table creation logic, index building, dialect handling), reducing each file by ~80 lines (e.g., `add_new_schemas.py` from 429 to ~250 lines). Common changes (e.g., adding a new DB dialect) are made in one place.
- **No Functionality Loss**: Existing migrations remain equivalent; specific indexes/foreign keys (e.g., `fk_client_settings_user_id` in `add_new_schemas.py`) are preserved via overrides. No new bugs introduced by maintaining async/await and exact SQL semantics.
- **Compatibility**: Supports all current dialects without breaking existing up/down methods. Low risk as migrations are isolated and run sequentially.
- **Code Reduction Estimate**: Total reduction ~240 lines across files (80 per file), verified by extracting shared helpers while keeping migration-specific schemas/indexes intact.

This refactor makes sense as it follows DRY principles without altering migration semantics, improving long-term schema evolution in PlexiChat.

## File-by-File Changes

The refactor affects three files. A new `base.py` will be created first. Each existing file will be refactored to inherit from `base.Migration`, removing duplicated code and overriding specifics. No functionality is removed; all tables, indexes, foreign keys, and constraints are preserved.

### 1. New File: `src/plexichat/core/database/migrations/base.py`
- **Purpose**: Define the base `Migration` class.
- **What to Add**:
  - Class `Migration` with attributes: `MIGRATION_VERSION`, `MIGRATION_DESCRIPTION`.
  - Abstract methods to override: `_get_tables()` (returns dict of table_name: schema), `_get_indexes()` (returns dict of table_name: list of (name, columns, unique)), `_get_foreign_keys()` (returns dict of table_name: list of (name, local_col, ref_table, ref_col, on_delete, on_update)), `_get_check_constraints()` (returns dict of table_name: list of (name, condition)).
  - `up()` method: Ensures migration table exists, checks if applied, creates tables/indexes/constraints via helpers, records migration with rollback SQL.
  - `down()` method: Retrieves rollback SQL from tracking table, executes drops, removes record.
  - Helpers: `_create_table_with_constraints()`, `_create_indexes()`, `_add_foreign_keys()`, `_add_check_constraints()`, `_record_migration()`, `_is_applied()`, `_get_dialect_sql()` (for dialect-specific queries).
  - CLI `main()` for `up`/`down`/`verify`.
- **Lines Added**: ~200 (centralized logic).
- **Migration Approach**: Write complete file content using `write_to_file`.

### 2. `src/plexichat/core/database/migrations/add_new_schemas.py`
- **Current Issues**: Comprehensive but verbose (~429 lines); duplicates table creation, index building, constraint addition, migration tracking, and verification logic. Uses global constants for schemas/indexes/FKs/checks.
- **What to Replace/Modify**:
  - Remove duplicated helpers: `create_table_with_constraints()`, `create_migration_tracking_table()`, `is_migration_applied()`, `record_migration()`, `validate_table_data()`, `run_migration()`, `rollback_migration()`, `verify_migration()`, `main()`.
  - Refactor to class `AddNewSchemasMigration(Migration)`:
    - Set `MIGRATION_VERSION = "001_add_new_schemas"`, `MIGRATION_DESCRIPTION = "Add client settings, plugin permissions, cluster nodes, and backup metadata schemas"`.
    - Override `_get_tables()`: Return `NEW_TABLES` dict (e.g., {"client_settings": CLIENT_SETTINGS_SCHEMA, ...}).
    - Override `_get_indexes()`: Return `INDEXES` dict.
    - Override `_get_foreign_keys()`: Return `FOREIGN_KEYS` dict.
    - Override `_get_check_constraints()`: Return `CHECK_CONSTRAINTS` dict.
    - In `up()`: Call `super().up()` then add specific post-creation logic if needed (e.g., `self._create_specific_indexes()` for any unique handling).
    - Keep imports and constants (schemas, etc.); remove global functions.
  - Preserve: All specific schemas, indexes (e.g., `idx_client_settings_user_id`), FKs (e.g., `fk_client_settings_user_id`), checks (e.g., `chk_client_settings_value_type`).
- **How to Migrate**: Use `apply_diff` to replace the entire class body and functions with inheritance-based structure. Remove ~180 lines of boilerplate.
- **Expected Reduction**: From 429 to ~249 lines.

### 3. `src/plexichat/core/database/migrations/add_plugin_permissions.py`
- **Current Issues**: Class-based but still duplicates dialect-specific table creation across 5 tables (`_create_plugin_permissions_table()`, etc.), index creation (`_create_indexes()`), migration tracking (`_ensure_migrations_table()`, `_record_migration()`), and drop logic. Verbose SQL strings (~600 lines).
- **What to Replace/Modify**:
  - Remove duplicated methods: All `_create_*_table()` methods, `_create_indexes()`, `_ensure_migrations_table()`, `_record_migration()`, `_remove_migration_record()`, `_drop_table()`, `is_applied()`, `upgrade()`, `downgrade()`.
  - Refactor to class `AddPluginPermissionsMigration(Migration)`:
    - Set `MIGRATION_VERSION = "001_add_plugin_permissions"`, `MIGRATION_DESCRIPTION = "Add Plugin Permissions"`.
    - Override `_get_tables()`: Define schemas inline or via constants for plugin_permissions, plugin_audit_events, plugin_settings, plugin_approved_modules, client_settings (dialect-agnostic dicts; base handles dialect conversion).
    - Override `_get_indexes()`: Return list/dict of all indexes from current `_create_indexes()` (e.g., {"plugin_permissions": [("idx_plugin_permissions_plugin_name", ["plugin_name"]), ...]}).
    - No FKs/checks in current file, so defaults suffice; override if adding.
    - In `up()`: `super().up()`; add any specific validation.
  - Preserve: All table schemas (e.g., plugin_permissions columns like `plugin_name VARCHAR(255) NOT NULL`), indexes (e.g., `idx_plugin_permissions_status`).
- **How to Migrate**: Use `apply_diff` for multiple blocks: Replace class methods with overrides, consolidate SQL into `_get_tables()`. Harmonize migration table name to `schema_migrations` for consistency.
- **Expected Reduction**: From 600 to ~350 lines (major savings from removing per-table dialect SQL).

### 4. `src/plexichat/core/database/migrations/add_search_indexes.py`
- **Current Issues**: Simpler index-only migration (~135 lines); duplicates session management, error handling, and basic tracking. No tables/FKs, just indexes on existing tables.
- **What to Replace/Modify**:
  - Remove: `up()`, `down()`, global index lists, metadata.
  - Refactor to class `AddSearchIndexesMigration(Migration)`:
    - Set `MIGRATION_VERSION = "add_search_indexes"`, `MIGRATION_DESCRIPTION = "Add database indexes for improved search performance"`.
    - Override `_get_indexes()`: Return dict with empty tables but full index list (e.g., {"messages": [("idx_messages_user_id", ["user_id"]), ...], "users": [...], ...}). Base `up()` will create them without tables.
    - No `_get_tables()` override needed (empty).
    - In `down()`: `super().down()` handles index drops.
  - Preserve: All indexes (e.g., `idx_messages_channel_id`, `idx_users_username`).
- **How to Migrate**: Use `apply_diff` to replace functions with class inheritance. Add migration tracking if missing (base provides).
- **Expected Reduction**: From 135 to ~55 lines.

## Risk Mitigation

- **Overall Risk Level**: Low. Migrations are isolated (run one-by-one via CLI), no runtime dependencies on other modules, and changes are backward-compatible (existing DBs unaffected if migration not re-run). No circular imports as files are standalone.
- **File-Specific Impacts**:
  - `add_new_schemas.py`: Medium impact due to complex constraints; risk of dialect mismatches in FK/checks. Mitigation: Base class uses conditional SQL based on `db_type`; test each constraint addition separately.
  - `add_plugin_permissions.py`: High line count but modular; risk of schema inconsistencies from dialect-specific strings. Mitigation: Centralize schema defs in overrides; validate SQL generation in base helpers.
  - `add_search_indexes.py`: Low impact (indexes only); risk of partial index creation. Mitigation: Base handles "IF NOT EXISTS" universally; rollback drops all.
- **General Risks and Mitigations**:
  - **Breaking Existing Migrations**: Risk of altering up/down semantics. Mitigation: Ensure subclasses call `super().up()`; preserve all specific SQL via overrides. No features lost (e.g., unique composites like `idx_client_settings_user_key`).
  - **Database Compatibility**: SQLite limited FK support. Mitigation: Base detects dialect and skips unsupported features with warnings (as in current code).
  - **Rollback Failures**: Incomplete rollback SQL. Mitigation: Base collects all DROP statements dynamically.
  - **New Bugs**: Async issues or SQL errors. Mitigation: No new code paths; unit test helpers in base.
  - **Impact on Larger Refactor**: Part of PlexiChat duplication cleanup; no conflicts with prior plans (e.g., errors_refactor_plan.md).

## Testing Steps

1. **Unit Tests for Base Class** (`tests/unit/test_migrations_base.py`):
   - Test `_create_table()` with mock sessions for each dialect; verify generated SQL matches current files.
   - Test `_get_dialect_sql()` for schema conversion (e.g., `SERIAL` for PostgreSQL).
   - Test migration tracking: Mock `insert`/`select` to verify recording/checking.
   - Edge cases: Table exists (skip), index exists, FK unsupported in SQLite.

2. **Integration Tests for Refactored Migrations** (`tests/integration/test_migrations.py`):
   - Use pytest with in-memory SQLite/PostgreSQL (via testcontainers); run `up()` on each refactored migration.
   - Verify schema: Query `PRAGMA table_info(table)` (SQLite) or `information_schema` to check columns/indexes/FKs match originals.
   - Run `down()` and confirm tables/indexes removed; re-run `up()` to ensure idempotency.
   - File-specific: For `add_new_schemas.py`, test constraint enforcement (e.g., insert invalid data fails); for `add_plugin_permissions.py`, test multi-table creation order.

3. **SQL Syntax Validation**:
   - Use `sqlite3` CLI to execute generated SQL from base helpers: `echo "SQL" | sqlite3 :memory:` for each dialect snippet.
   - For PostgreSQL/MySQL, use Docker containers to validate.

4. **End-to-End Migration Testing**:
   - Sequential run: Apply all three migrations in order on test DB; verify final schema.
   - Rollback test: Apply one, rollback, reapply; check no data loss.
   - Performance: Time index creation; ensure no regressions.

5. **Manual Verification**:
   - Compare line counts pre/post-refactor.
   - Diff generated SQL from old vs. new `up()` outputs.
   - Run CLI: `python migration.py up`/`down`/`verify` for each.

All tests must pass 100% before merging; add to CI pipeline.