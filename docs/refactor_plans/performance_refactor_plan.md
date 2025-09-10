# Performance Refactor Plan

## Overview

The performance/ directory contains duplicated caching logic across `auth_cache.py` and `cache_cluster_manager.py`, including cache key generation using hashlib.sha256, TTL calculations, performance stats tracking (hits/misses), and an async `_health_check_loop()` method with psutil calls for system monitoring. This duplication spans approximately 100 lines of repeated code, leading to maintenance overhead and potential inconsistencies.

The proposed refactor introduces a shared `CacheBase` abstract base class in a new `performance/cache_base.py` file to centralize common functionality. This class will handle:
- `_generate_cache_key(data: dict) -> str`: Standardized SHA256 hashing of cache data.
- `_calculate_ttl(expiry: datetime) -> int`: TTL computation in seconds from expiry timestamps.
- Stats tracking via a `CacheStats` dataclass for hits, misses, and evictions.
- `async _health_check_loop(self)`: Async loop using psutil to monitor CPU/memory usage and log health metrics.

Specific implementations will inherit from `CacheBase` and override tailored methods (e.g., auth-specific TTL for JWTs, cluster-specific hash ring building). This approach reduces code duplication by ~100 lines, improves consistency, and preserves all existing features like JWT revocation and node health monitoring. The refactor aligns with previous efforts (e.g., logging_refactor_plan.md) by promoting modular, shared components without introducing new dependencies or bugs.

### Benefits
- **Consistency**: Single source of truth for cache operations.
- **Maintainability**: Changes to core logic (e.g., updating hash algorithm) apply globally.
- **Line Reduction**: Extract ~50 lines per file of duplicated code into base class.
- **No Functionality Loss**: All methods remain equivalent; overrides ensure specificity.

### Assumptions
- Both files use similar data structures for caching (dict-based keys/values).
- psutil is already a dependency; no new installs needed.
- Refactor occurs in isolation; no immediate impact on other modules like core/cache/.

## File-by-File Changes

### 1. New File: performance/cache_base.py
- **Purpose**: Define `CacheBase` as an abstract base class.
- **Content Outline**:
  - Import necessary modules: `from abc import ABC, abstractmethod; import hashlib; from datetime import datetime; import psutil; from dataclasses import dataclass`.
  - Define `@dataclass` class `CacheStats`: `hits: int = 0; misses: int = 0; evictions: int = 0`.
  - Class `CacheBase(ABC)`:
    - `stats: CacheStats = CacheStats()`.
    - `def _generate_cache_key(self, data: dict) -> str`: `key_str = json.dumps(data, sort_keys=True); return hashlib.sha256(key_str.encode()).hexdigest()`.
    - `def _calculate_ttl(self, expiry: datetime) -> int`: `return int((expiry - datetime.utcnow()).total_seconds())`.
    - `@abstractmethod def _get_cache_store(self) -> Any`: Placeholder for specific store (e.g., Redis, in-memory).
    - `async def _health_check_loop(self)`: Async loop every 60s: `while True: cpu = psutil.cpu_percent(); mem = psutil.virtual_memory().percent; self.stats.log_health(cpu, mem); await asyncio.sleep(60)`.
    - Methods for `get/set/delete` using base logic, incrementing stats on hits/misses.
- **Migration**: Create this file first; import in other performance/ files.
- **Impact**: ~80 lines of new, centralized code; enables extraction from existing files.

### 2. auth_cache.py
- **Current Issues**: Duplicated key generation, TTL calc for tokens, stats tracking, and full `_health_check_loop()` (~50 lines). Specific features: JWT handling, `revoke_token_by_jti(jti: str)`.
- **Changes**:
  - Add `from performance.cache_base import CacheBase`.
  - Change `class AuthCache` to `class AuthCache(CacheBase):`.
  - Remove duplicated methods: Delete `_generate_cache_key`, `_calculate_ttl`, stats fields, and `_health_check_loop`.
  - Override specifics: `def _calculate_token_ttl(self, token: str) -> int`: Custom logic for JWT expiry parsing (e.g., from payload).
  - Integrate base: In `get_token`, use `super()._generate_cache_key(token_data)` and `super().stats.hits += 1`.
  - Preserve: Keep `revoke_token_by_jti` unchanged, but use base `delete` for cache invalidation.
- **Migration Steps**:
  1. Extract common methods to `CacheBase`.
  2. Update inheritance and method calls.
  3. Remove ~50 lines of duplication.
- **Preservation**: JWT-specific TTL and revocation logic remains; health checks now centralized but triggered via base.

### 3. cache_cluster_manager.py
- **Current Issues**: Similar duplication (~50 lines) for key gen, TTL, stats, health loop. Specific: Hash ring for node distribution, `_build_hash_ring(nodes: list)`.
- **Changes**:
  - Add `from performance.cache_base import CacheBase`.
  - Change `class CacheClusterManager` to `class CacheClusterManager(CacheBase):`.
  - Remove duplicated: Delete `_generate_cache_key`, `_calculate_ttl`, stats, `_health_check_loop`.
  - Override: `def _get_nodes(self) -> list`: Return cluster nodes; integrate with base for distributed gets/sets.
  - Integrate: Use `super()._generate_cache_key` in ring lookups; base stats for cluster-wide metrics.
  - Preserve: Keep `_build_hash_ring` and node health per base loop.
- **Migration Steps**:
  1. Ensure base handles distributed aspects (e.g., abstract `_route_to_node(key: str) -> str`).
  2. Update class to inherit and call super() where appropriate.
  3. Remove ~50 lines.
- **Preservation**: Hash ring and node-specific health monitoring intact; metrics aggregated via base.

### Overall Code Reduction
- Total: ~100 lines removed (50 per file); net gain from base class but overall reduction in duplication.
- No new files beyond cache_base.py; no changes to imports that could cause cycles (base in same package).

## Risk Mitigation

- **Risk Level**: Low. Performance/ is isolated; changes affect only caching internals, not external APIs. No shared state with other modules (e.g., core/auth/ uses AuthCache instance but not internals).
- **Potential Issues**:
  - **Breaking Specific Features**: JWT TTL in auth_cache.py or hash ring in cache_cluster_manager.py could mismatch if overrides incorrect. Mitigation: Detailed overrides; unit tests verify equivalence (e.g., same TTL output).
  - **Performance Degradation**: Centralized health loop might add overhead. Mitigation: Benchmark before/after (e.g., time `_health_check_loop` iterations); ensure async non-blocking.
  - **Circular Imports**: Base in performance/ imported by siblings. Mitigation: Place in `performance/base.py`? No, task specifies cache_base.py; use forward refs or restructure if needed, but same-package imports safe.
  - **Stats Inconsistency**: Hits/misses tracking. Mitigation: Base class ensures uniform logging; add debug logs during migration.
- **File Impact**:
  - auth_cache.py: Medium risk (auth-critical); test token caching end-to-end.
  - cache_cluster_manager.py: Low risk (clustering optional); verify ring distribution unchanged.
- **General**: Version control branch for refactor; rollback if benchmarks show >5% degradation.

## Testing Steps

1. **Unit Tests**:
   - Existing: Run `pytest tests/unit/test_auth_cache.py` and `test_cache_cluster_manager.py`; ensure 100% pass rate post-refactor.
   - New: Add tests for `CacheBase` methods (e.g., `test_generate_cache_key_hash_consistency`, `test_calculate_ttl_accuracy`).
   - Specific: `test_auth_token_ttl_override` (verify JWT-specific calc matches old); `test_cluster_hash_ring_integration` (base routing doesn't break ring).

2. **Integration Tests**:
   - `tests/integration/test_performance_caching.py`: Simulate cache operations across both classes; verify hits/misses stats aggregate correctly.
   - Mock psutil in `_health_check_loop` tests to avoid real system calls.

3. **Performance Benchmarks**:
   - Use `pytest-benchmark`: Measure cache get/set latency before/after; target <1% regression.
   - Health loop: `async def benchmark_health_check():` time 100 iterations; ensure no blocking.

4. **End-to-End**:
   - Run full app: `python -m plexichat`; test auth flows (login/logout) and clustering (multi-node sim).
   - Monitor: Check logs for consistent metrics; use `pytest tests/performance/` for load tests.

5. **Coverage & Static Analysis**:
   - `pytest --cov=src/plexichat/core/performance`: Ensure >90% coverage.
   - `flake8 performance/` and `mypy performance/`: No new errors.
   - Manual: Diff old/new outputs for key gen/TTL to confirm equivalence.

6. **Rollback Criteria**: If any test fails or benchmarks degrade >5%, revert and adjust overrides.

This plan ensures a safe, effective refactor preserving all functionality while eliminating duplication.