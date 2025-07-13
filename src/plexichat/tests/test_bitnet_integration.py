"""
BitNet 1-bit LLM Integration Test

Tests the AI module's capability to run 1-bit LLMs like BitNet locally
using specialized kernels and optimized inference.
"""

import asyncio
import logging
import os
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from plexichat.features.ai.core.ai_abstraction_layer import AIAbstractionLayer
from plexichat.features.ai.providers.base_provider import AIRequest, AIResponse
from plexichat.features.ai.providers.bitnet_provider import BitNetProvider, BitNetConfig

logger = logging.getLogger(__name__)


class TestBitNetIntegration(unittest.TestCase):
    """Test BitNet 1-bit LLM integration."""

    def setUp(self):
        """Set up test environment."""
        self.test_dir = Path(tempfile.mkdtemp())
        self.ai_layer = None
        self.bitnet_provider = None

    def tearDown(self):
        """Clean up test environment."""
        import shutil
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir)

    async def async_setUp(self):
        """Async setup for AI components."""
        try:
            # Initialize AI abstraction layer
            self.ai_layer = AIAbstractionLayer()
            await self.ai_layer.initialize()
            
            # Configure BitNet provider
            bitnet_config = BitNetConfig(
                base_url="http://localhost:11434",
                api_key="",
                model_path=str(self.test_dir / "models"),
                use_gpu=True,
                quantization_bits=1,
                kernel_optimization=True,
                memory_mapping=True,
                batch_size=1
            )
            
            self.bitnet_provider = BitNetProvider(bitnet_config)
            
        except Exception as e:
            logger.error(f"Async setup failed: {e}")
            raise

    def test_bitnet_provider_exists(self):
        """Test that BitNet provider class exists and is importable."""
        try:
            from plexichat.features.ai.providers.bitnet_provider import BitNetProvider, BitNetConfig
            self.assertTrue(True, "BitNet provider imported successfully")
        except ImportError as e:
            self.fail(f"BitNet provider not found: {e}")

    def test_bitnet_config_validation(self):
        """Test BitNet configuration validation."""
        # Valid config
        config = BitNetConfig(
            base_url="http://localhost:11434",
            model_path="/tmp/models",
            quantization_bits=1,
            kernel_optimization=True
        )
        self.assertEqual(config.quantization_bits, 1)
        self.assertTrue(config.kernel_optimization)
        
        # Invalid quantization bits
        with self.assertRaises(ValueError):
            BitNetConfig(
                base_url="http://localhost:11434",
                quantization_bits=16  # Should be 1 for BitNet
            )

    async def test_bitnet_model_loading(self):
        """Test BitNet model loading and initialization."""
        await self.async_setUp()
        
        # Mock model file
        model_file = self.test_dir / "models" / "bitnet-1b.bin"
        model_file.parent.mkdir(parents=True, exist_ok=True)
        model_file.write_bytes(b"mock_model_data")
        
        # Test model loading
        result = await self.bitnet_provider.load_model("bitnet-1b")
        self.assertTrue(result.get("success", False))
        self.assertIn("model_loaded", result)

    async def test_bitnet_inference(self):
        """Test BitNet inference capabilities."""
        await self.async_setUp()
        
        # Mock successful model loading
        with patch.object(self.bitnet_provider, 'load_model', return_value={"success": True}):
            await self.bitnet_provider.load_model("bitnet-1b")
            
            # Create test request
            request = AIRequest(
                model_id="bitnet-1b",
                prompt="Hello, how are you?",
                max_tokens=50,
                temperature=0.7
            )
            
            # Mock inference
            with patch.object(self.bitnet_provider, '_run_inference') as mock_inference:
                mock_inference.return_value = {
                    "text": "Hello! I'm doing well, thank you for asking.",
                    "tokens_used": 12,
                    "inference_time_ms": 45
                }
                
                response = await self.bitnet_provider.generate(request)
                
                self.assertIsInstance(response, AIResponse)
                self.assertTrue(response.success)
                self.assertGreater(len(response.content), 0)
                self.assertEqual(response.model_id, "bitnet-1b")

    async def test_bitnet_kernel_optimization(self):
        """Test BitNet kernel optimization features."""
        await self.async_setUp()
        
        # Test kernel compilation
        result = await self.bitnet_provider.compile_kernels()
        self.assertTrue(result.get("success", False))
        
        # Test optimized inference
        with patch.object(self.bitnet_provider, '_run_optimized_inference') as mock_optimized:
            mock_optimized.return_value = {
                "text": "Optimized response",
                "speedup_factor": 3.2,
                "memory_usage_mb": 512
            }
            
            request = AIRequest(
                model_id="bitnet-1b",
                prompt="Test optimized inference",
                use_optimization=True
            )
            
            response = await self.bitnet_provider.generate(request)
            self.assertTrue(response.success)
            self.assertIn("speedup_factor", response.metadata)

    async def test_bitnet_memory_efficiency(self):
        """Test BitNet memory efficiency with 1-bit quantization."""
        await self.async_setUp()
        
        # Test memory usage
        memory_info = await self.bitnet_provider.get_memory_usage()
        
        # BitNet should use significantly less memory than full precision
        expected_memory_reduction = 0.125  # 1/8 of full precision (1-bit vs 8-bit)
        self.assertLess(
            memory_info.get("memory_usage_ratio", 1.0),
            expected_memory_reduction * 2  # Allow some overhead
        )

    async def test_bitnet_performance_benchmarks(self):
        """Test BitNet performance benchmarks."""
        await self.async_setUp()
        
        # Run performance benchmark
        benchmark_results = await self.bitnet_provider.run_benchmark()
        
        required_metrics = [
            "tokens_per_second",
            "latency_ms",
            "memory_usage_mb",
            "energy_efficiency"
        ]
        
        for metric in required_metrics:
            self.assertIn(metric, benchmark_results)
            self.assertIsInstance(benchmark_results[metric], (int, float))

    async def test_bitnet_ai_layer_integration(self):
        """Test BitNet integration with AI abstraction layer."""
        await self.async_setUp()
        
        # Register BitNet provider with AI layer
        await self.ai_layer.register_provider("bitnet", self.bitnet_provider)
        
        # Test model availability
        available_models = await self.ai_layer.get_available_models()
        bitnet_models = [m for m in available_models if m.provider == "bitnet"]
        self.assertGreater(len(bitnet_models), 0)
        
        # Test inference through AI layer
        response = await self.ai_layer.generate_text(
            prompt="Test BitNet through AI layer",
            model_preference="bitnet",
            max_tokens=30
        )
        
        self.assertTrue(response.get("success", False))
        self.assertIn("content", response)

    def test_bitnet_kernel_compilation(self):
        """Test BitNet kernel compilation for optimization."""
        # Mock kernel compilation
        with patch('subprocess.run') as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "Kernel compiled successfully"
            
            from plexichat.features.ai.providers.bitnet_provider import compile_bitnet_kernels
            
            result = compile_bitnet_kernels()
            self.assertTrue(result.get("success", False))
            self.assertIn("kernel_path", result)

    async def test_bitnet_streaming_inference(self):
        """Test BitNet streaming inference capabilities."""
        await self.async_setUp()
        
        request = AIRequest(
            model_id="bitnet-1b",
            prompt="Generate a story about AI",
            stream=True,
            max_tokens=100
        )
        
        # Mock streaming response
        async def mock_stream():
            tokens = ["Once", " upon", " a", " time", "..."]
            for token in tokens:
                yield {"token": token, "done": False}
            yield {"token": "", "done": True}
        
        with patch.object(self.bitnet_provider, 'stream_generate', return_value=mock_stream()):
            stream = await self.bitnet_provider.stream_generate(request)
            
            tokens = []
            async for chunk in stream:
                if not chunk.get("done", False):
                    tokens.append(chunk.get("token", ""))
            
            self.assertGreater(len(tokens), 0)
            self.assertEqual(tokens[0], "Once")

    async def test_bitnet_error_handling(self):
        """Test BitNet error handling and recovery."""
        await self.async_setUp()
        
        # Test invalid model
        with self.assertRaises(Exception):
            await self.bitnet_provider.load_model("nonexistent-model")
        
        # Test inference without loaded model
        request = AIRequest(
            model_id="unloaded-model",
            prompt="Test"
        )
        
        response = await self.bitnet_provider.generate(request)
        self.assertFalse(response.success)
        self.assertIn("error", response.metadata)

    def test_bitnet_system_requirements(self):
        """Test BitNet system requirements check."""
        from plexichat.features.ai.providers.bitnet_provider import check_system_requirements
        
        requirements = check_system_requirements()
        
        required_checks = [
            "cpu_support",
            "memory_available",
            "disk_space",
            "python_version",
            "dependencies"
        ]
        
        for check in required_checks:
            self.assertIn(check, requirements)


class TestBitNetKernelOptimization(unittest.TestCase):
    """Test BitNet kernel optimization features."""

    def test_kernel_compilation_detection(self):
        """Test detection of available kernel compilation tools."""
        from plexichat.features.ai.providers.bitnet_provider import detect_compilation_tools
        
        tools = detect_compilation_tools()
        
        # Should detect common compilation tools
        expected_tools = ["gcc", "clang", "nvcc", "cmake"]
        for tool in expected_tools:
            self.assertIn(tool, tools)

    def test_gpu_optimization_detection(self):
        """Test GPU optimization capability detection."""
        from plexichat.features.ai.providers.bitnet_provider import detect_gpu_capabilities
        
        gpu_info = detect_gpu_capabilities()
        
        self.assertIn("cuda_available", gpu_info)
        self.assertIn("gpu_memory_gb", gpu_info)
        self.assertIn("compute_capability", gpu_info)

    def test_bitnet_kernel_performance(self):
        """Test BitNet kernel performance optimization."""
        # Mock optimized kernel
        with patch('ctypes.CDLL') as mock_cdll:
            mock_lib = MagicMock()
            mock_lib.bitnet_inference.return_value = 0
            mock_cdll.return_value = mock_lib
            
            from plexichat.features.ai.providers.bitnet_provider import BitNetKernel
            
            kernel = BitNetKernel()
            result = kernel.run_inference(
                input_data=b"mock_input",
                model_weights=b"mock_weights"
            )
            
            self.assertIsNotNone(result)


def run_bitnet_tests():
    """Run all BitNet integration tests."""
    # Create test suite
    suite = unittest.TestSuite()
    
    # Add test cases
    suite.addTest(unittest.makeSuite(TestBitNetIntegration))
    suite.addTest(unittest.makeSuite(TestBitNetKernelOptimization))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result.wasSuccessful()


async def run_async_tests():
    """Run async BitNet tests."""
    test_instance = TestBitNetIntegration()
    test_instance.setUp()
    
    try:
        await test_instance.async_setUp()
        
        # Run async tests
        await test_instance.test_bitnet_model_loading()
        await test_instance.test_bitnet_inference()
        await test_instance.test_bitnet_kernel_optimization()
        await test_instance.test_bitnet_memory_efficiency()
        await test_instance.test_bitnet_performance_benchmarks()
        await test_instance.test_bitnet_ai_layer_integration()
        await test_instance.test_bitnet_streaming_inference()
        await test_instance.test_bitnet_error_handling()
        
        print("✅ All async BitNet tests passed!")
        return True
        
    except Exception as e:
        print(f"❌ Async BitNet tests failed: {e}")
        return False
    finally:
        test_instance.tearDown()


if __name__ == "__main__":
    print("🧪 Running BitNet 1-bit LLM Integration Tests...")
    
    # Run sync tests
    sync_success = run_bitnet_tests()
    
    # Run async tests
    async_success = asyncio.run(run_async_tests())
    
    if sync_success and async_success:
        print("🎉 All BitNet tests completed successfully!")
        sys.exit(0)
    else:
        print("💥 Some BitNet tests failed!")
        sys.exit(1)
