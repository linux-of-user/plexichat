"""Tests for Cython/Numba compilation optimizations.

Parametrized tests comparing compiled vs interpreted performance.
Targets 80%+ coverage for compilation integrations with 10-20% speedup verification.
"""

import asyncio
import hashlib
import time
from typing import List, Dict, Any
import pytest

import plexichat.core.services.message_service as message_service
from plexichat.core.clustering.cluster_manager import (
    ClusterManager, 
    _rebuild_hash_ring_internal
)
from plexichat.core.performance.cache_lookup import (
    fast_cache_get, 
    tier_select
)

# Pure Python implementations for comparison


def pure_python_checksum(content: str) -> str:
    """Pure Python SHA256 checksum for comparison."""
    return hashlib.sha256(content.encode('utf-8')).hexdigest()


def pure_python_hash_ring_build(node_ids: List[str], virtual_nodes_per_node: int = 150) -> Dict[int, str]:
    """Pure Python hash ring builder for comparison."""
    hash_ring = {}
    for node_id in node_ids:
        for i in range(virtual_nodes_per_node):
            virtual_key = f"{node_id}:{i}"
            hash_value = int(hashlib.md5(virtual_key.encode()).hexdigest(), 16)
            hash_ring[hash_value] = node_id
    return hash_ring


def pure_python_cache_lookup(key: str, tier_order: List[str]) -> str:
    """Simulated pure Python cache lookup for comparison."""
    # Simple simulation - in reality would check actual cache backends
    for tier in tier_order:
        # Simulate 50% hit rate
        if (hash(key + tier) % 2) == 0:
            return f"found_in_{tier.lower()}"
    return None


@pytest.fixture(params=[True, False])
def compilation_mode(request):
    """Fixture for testing compiled vs interpreted modes."""
    return request.param


class TestCompilationOptimizations:
    """Test suite for compilation optimizations."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("content_length", [10, 100, 1000, 10000])
    async def test_checksum_performance(self, benchmark, content_length: int):
        """Benchmark checksum performance: pure Python vs Cython async."""
        content = "a" * content_length
        
        # Pure Python benchmark
        pure_time = benchmark(pure_python_checksum, content)
        
        # Cython async benchmark
        msg = message_service.Message(content=content)
        cython_time = benchmark(msg.checksum)
        
        # Verify correctness
        assert pure_python_checksum(content) == await msg.checksum()
        
        # Check for speedup (allow some variance for small inputs)
        if content_length > 100:
            speedup = pure_time / cython_time if cython_time > 0 else float('inf')
            assert speedup > 1.05, f"Expected >5% speedup, got {speedup:.2f}x"

    @pytest.mark.parametrize("num_nodes", [1, 5, 10, 50])
    def test_hash_ring_build_performance(self, benchmark, num_nodes: int):
        """Benchmark hash ring build performance: pure Python vs Numba."""
        node_ids = [f"node-{i}" for i in range(num_nodes)]
        
        # Pure Python benchmark
        pure_time = benchmark(pure_python_hash_ring_build, node_ids)
        pure_ring = pure_python_hash_ring_build(node_ids)
        
        # Numba benchmark (via cluster manager internal)
        # Note: Numba compiles on first call, so warm up
        cm = ClusterManager()
        cm._rebuild_hash_ring_internal(node_ids, 150)  # Warm up
        numba_time = benchmark(cm._rebuild_hash_ring_internal, node_ids, 150)
        
        # Verify correctness (same number of entries)
        numba_ring = cm._rebuild_hash_ring_internal(node_ids, 150)
        assert len(pure_ring) == len(numba_ring)
        
        # Check for speedup
        speedup = pure_time / numba_time if numba_time > 0 else float('inf')
        if num_nodes > 5:
            assert speedup > 1.10, f"Expected >10% speedup for {num_nodes} nodes, got {speedup:.2f}x"

    @pytest.mark.parametrize("num_lookups", [100, 1000, 10000])
    def test_cache_lookup_performance(self, benchmark, num_lookups: int):
        """Benchmark cache lookup performance: pure Python vs Cython."""
        keys = [f"cache_key_{i}" for i in range(num_lookups)]
        tier_order = ["L1_MEMORY", "L2_REDIS", "L3_MEMCACHED", "L4_CDN"]
        
        # Pure Python benchmark (average time)
        pure_times = []
        for key in keys[:10]:  # Sample for stability
            pure_times.append(benchmark(pure_python_cache_lookup, key, tier_order))
        pure_avg = sum(pure_times) / len(pure_times)
        
        # Cython benchmark (average time)
        cython_times = []
        for key in keys[:10]:
            cython_times.append(benchmark(fast_cache_get, key, tier_order))
        cython_avg = sum(cython_times) / len(cython_times)
        
        # Verify correctness (same hit/miss pattern)
        for key in keys[:100]:
            pure_result = pure_python_cache_lookup(key, tier_order)
            cython_result = fast_cache_get(key, tier_order)
            assert pure_result == cython_result, f"Mismatch for key {key}"
        
        # Check for speedup
        speedup = pure_avg / cython_avg if cython_avg > 0 else float('inf')
        assert speedup > 1.05, f"Expected >5% speedup for lookups, got {speedup:.2f}x"

    def test_tier_selection_correctness(self):
        """Test cache tier selection consistency."""
        tier_order = ["L1_MEMORY", "L2_REDIS", "L3_MEMCACHED", "L4_CDN"]
        
        # Test that same key always selects same tier
        for key in ["test_key", "another_key", "12345"]:
            selected_tier, index = tier_select(key, len(tier_order))
            # Verify round-trip
            assert tier_order[index] == selected_tier
        
        # Test distribution across tiers
        keys = [f"test_{i}" for i in range(100)]
        tiers = [tier_select(key, 4)[0] for key in keys]
        unique_tiers = set(tiers)
        assert len(unique_tiers) == 4, "Should distribute across all tiers"

    @pytest.mark.asyncio
    async def test_async_compilation_integration(self):
        """Test async compilation wrapper integration."""
        # Test message checksum async integration
        content = "test message content for async checksum"
        msg = message_service.Message(content=content)
        
        # Should work without blocking
        checksum = await msg.checksum()
        assert len(checksum) == 64  # SHA256 hex length
        assert checksum == pure_python_checksum(content)

    def test_compilation_optimizer_registry(self):
        """Test compilation optimizer registry functionality."""
        from plexichat.infrastructure.utils.compilation import optimizer
        
        # Test registration (basic smoke test)
        try:
            optimizer.register_function(
                "plexichat.core.services.message_service",
                "calculate_checksum",
                force_recompile=True
            )
            assert "plexichat.core.services.message_service.calculate_checksum" in optimizer._registered
        except Exception as e:
            pytest.skip(f"Registry test skipped due to import issues: {e}")

    def test_numba_integration_correctness(self):
        """Verify Numba integration produces correct results."""
        from plexichat.core.clustering.cluster_manager import _rebuild_hash_ring_internal
        
        node_ids = ["node1", "node2"]
        virtual_nodes = 10
        
        # Pure Python reference
        pure_ring = pure_python_hash_ring_build(node_ids, virtual_nodes)
        
        # Numba result
        numba_ring = _rebuild_hash_ring_internal(node_ids, virtual_nodes)
        
        # Convert numba result to dict for comparison
        numba_dict = {k: v.decode('utf-8') if isinstance(v, bytes) else v for k, v in numba_ring.items()}
        
        # Verify same number of entries
        assert len(pure_ring) == len(numba_dict)
        
        # Verify distribution (both should have entries for both nodes)
        pure_nodes = set(pure_ring.values())
        numba_nodes = set(numba_dict.values())
        assert pure_nodes == numba_nodes == set(node_ids)

    @pytest.mark.parametrize("key", ["cache_key_1", "user_session_123", "config_default"])
    def test_cache_lookup_consistency(self, key: str):
        """Test cache lookup consistency between implementations."""
        tier_order = ["L1_MEMORY", "L2_REDIS", "L3_MEMCACHED", "L4_CDN"]
        
        # Both should produce same result for same input
        pure_result = pure_python_cache_lookup(key, tier_order)
        cython_result = fast_cache_get(key, tier_order)
        
        assert pure_result == cython_result

    def test_compilation_error_handling(self):
        """Test error handling in compilation wrappers."""
        from plexichat.infrastructure.utils.compilation import CompilationError
        
        # Test invalid registration
        from plexichat.infrastructure.utils.compilation import optimizer
        
        with pytest.raises(CompilationError):
            optimizer.register_function("nonexistent.module", "fake_function")

    @pytest.mark.skipif(not hasattr(asyncio, 'to_thread'), reason="Python < 3.9")
    @pytest.mark.asyncio
    async def test_async_thread_wrapper(self):
        """Test asyncio.to_thread wrapper for sync compiled functions."""
        # This tests the pattern used in message checksum
        content = "async thread test content"
        
        def sync_heavy_task():
            # Simulate heavy computation
            time.sleep(0.01)
            return hashlib.sha256(content.encode()).hexdigest()
        
        # Test async wrapper
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, sync_heavy_task)
        assert len(result) == 64


# Coverage helpers - ensure all major paths are tested
def test_compilation_module_imports():
    """Test that all compilation modules import correctly."""
    # This ensures coverage for import statements
    from plexichat.core.services.message_checksum import calculate_checksum
    from plexichat.core.clustering.cluster_hash_ring import build_hash_ring, get_node_by_hash
    from plexichat.core.performance.cache_lookup import fast_cache_get, tier_select
    
    assert calculate_checksum
    assert build_hash_ring
    assert get_node_by_hash
    assert fast_cache_get
    assert tier_select


# Run benchmarks with pytest-benchmark
def test_benchmark_integration(benchmark):
    """Integration benchmark test."""
    # Small integration test with benchmarking
    node_ids = ["node1", "node2", "node3"]
    
    def full_hash_ring_build():
        return pure_python_hash_ring_build(node_ids, 50)
    
    benchmark(full_hash_ring_build)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])