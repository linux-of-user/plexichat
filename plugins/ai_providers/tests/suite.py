"""
AI Providers Test Suite

Comprehensive test suite for AI providers plugin.
"""

import asyncio
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class TestSuite:
    """AI Providers test suite."""
    
    def __init__(self, plugin):
        self.plugin = plugin
        self.tests = {}
        self.results = {}
    
    async def initialize(self):
        """Initialize test suite."""
        try:
            # Register tests
            self.tests = {
                "test_bitnet": self.test_bitnet_provider,
                "test_llama": self.test_llama_provider,
                "test_hf": self.test_hf_provider,
                "test_inference": self.test_inference_performance,
                "test_memory": self.test_memory_efficiency,
                "test_streaming": self.test_streaming_inference,
                "test_model_loading": self.test_model_loading,
                "test_kernel_optimization": self.test_kernel_optimization
            }
            
            logger.info("AI Providers test suite initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize test suite: {e}")
    
    async def run_all(self) -> Dict[str, Any]:
        """Run all tests."""
        results = {
            "total_tests": len(self.tests),
            "passed": 0,
            "failed": 0,
            "skipped": 0,
            "tests": {},
            "summary": "",
            "duration_ms": 0
        }
        
        start_time = time.time()
        
        for test_name, test_func in self.tests.items():
            try:
                logger.info(f"Running test: {test_name}")
                result = await test_func()
                
                results["tests"][test_name] = result
                
                if result["status"] == "passed":
                    results["passed"] += 1
                elif result["status"] == "failed":
                    results["failed"] += 1
                else:
                    results["skipped"] += 1
                
            except Exception as e:
                logger.error(f"Test {test_name} error: {e}")
                results["tests"][test_name] = {
                    "status": "failed",
                    "message": f"Test error: {str(e)}",
                    "duration_ms": 0
                }
                results["failed"] += 1
        
        results["duration_ms"] = (time.time() - start_time) * 1000
        results["summary"] = f"{results['passed']}/{results['total_tests']} tests passed"
        
        return results
    
    async def test_bitnet_provider(self) -> Dict[str, Any]:
        """Test BitNet provider."""
        start_time = time.time()
        
        try:
            if not self.plugin.bitnet:
                return {
                    "status": "skipped",
                    "message": "BitNet provider not available",
                    "duration_ms": 0
                }
            
            # Test initialization
            if not hasattr(self.plugin.bitnet, 'config'):
                return {
                    "status": "failed",
                    "message": "BitNet provider not properly initialized",
                    "duration_ms": (time.time() - start_time) * 1000
                }
            
            # Test model loading
            load_result = await self.plugin.bitnet.load_model("test-bitnet-1b")
            if not load_result.get("success"):
                return {
                    "status": "failed",
                    "message": f"Model loading failed: {load_result.get('error')}",
                    "duration_ms": (time.time() - start_time) * 1000
                }
            
            # Test inference
            from plugin_internal import AIRequest
            request = AIRequest(
                model_id="test-bitnet-1b",
                prompt="Test BitNet inference",
                max_tokens=10
            )
            
            response = await self.plugin.bitnet.generate(request)
            if not response.success:
                return {
                    "status": "failed",
                    "message": f"Inference failed: {response.metadata.get('error')}",
                    "duration_ms": (time.time() - start_time) * 1000
                }
            
            # Test memory efficiency
            memory_info = await self.plugin.bitnet.get_memory_usage()
            if memory_info.get("ratio_vs_full", 1.0) > 0.2:  # Should be much less than 20%
                return {
                    "status": "warning",
                    "message": f"Memory efficiency lower than expected: {memory_info.get('ratio_vs_full', 1.0):.3f}",
                    "duration_ms": (time.time() - start_time) * 1000
                }
            
            return {
                "status": "passed",
                "message": "BitNet provider working correctly",
                "duration_ms": (time.time() - start_time) * 1000,
                "details": {
                    "model_loaded": True,
                    "inference_working": True,
                    "memory_efficient": True,
                    "latency_ms": response.latency_ms
                }
            }
            
        except Exception as e:
            return {
                "status": "failed",
                "message": f"BitNet test error: {str(e)}",
                "duration_ms": (time.time() - start_time) * 1000
            }
    
    async def test_llama_provider(self) -> Dict[str, Any]:
        """Test Llama provider."""
        start_time = time.time()
        
        try:
            if not self.plugin.llama:
                return {
                    "status": "skipped",
                    "message": "Llama provider not available",
                    "duration_ms": 0
                }
            
            # Test model loading
            load_result = await self.plugin.llama.load_model("test-llama-7b")
            if not load_result.get("success"):
                return {
                    "status": "failed",
                    "message": f"Llama model loading failed: {load_result.get('error')}",
                    "duration_ms": (time.time() - start_time) * 1000
                }
            
            # Test inference
            from plugin_internal import AIRequest
            request = AIRequest(
                model_id="test-llama-7b",
                prompt="Test Llama inference",
                max_tokens=10
            )
            
            response = await self.plugin.llama.generate(request)
            if not response.success:
                return {
                    "status": "failed",
                    "message": f"Llama inference failed: {response.metadata.get('error')}",
                    "duration_ms": (time.time() - start_time) * 1000
                }
            
            return {
                "status": "passed",
                "message": "Llama provider working correctly",
                "duration_ms": (time.time() - start_time) * 1000,
                "details": {
                    "model_loaded": True,
                    "inference_working": True,
                    "latency_ms": response.latency_ms
                }
            }
            
        except Exception as e:
            return {
                "status": "failed",
                "message": f"Llama test error: {str(e)}",
                "duration_ms": (time.time() - start_time) * 1000
            }
    
    async def test_hf_provider(self) -> Dict[str, Any]:
        """Test HuggingFace provider."""
        start_time = time.time()
        
        try:
            if not self.plugin.hf:
                return {
                    "status": "skipped",
                    "message": "HuggingFace provider not available",
                    "duration_ms": 0
                }
            
            # Test model loading
            load_result = await self.plugin.hf.load_model("gpt2")
            if not load_result.get("success"):
                return {
                    "status": "failed",
                    "message": f"HF model loading failed: {load_result.get('error')}",
                    "duration_ms": (time.time() - start_time) * 1000
                }
            
            # Test inference
            from plugin_internal import AIRequest
            request = AIRequest(
                model_id="gpt2",
                prompt="Test HuggingFace inference",
                max_tokens=10
            )
            
            response = await self.plugin.hf.generate(request)
            if not response.success:
                return {
                    "status": "failed",
                    "message": f"HF inference failed: {response.metadata.get('error')}",
                    "duration_ms": (time.time() - start_time) * 1000
                }
            
            return {
                "status": "passed",
                "message": "HuggingFace provider working correctly",
                "duration_ms": (time.time() - start_time) * 1000,
                "details": {
                    "model_loaded": True,
                    "inference_working": True,
                    "latency_ms": response.latency_ms
                }
            }
            
        except Exception as e:
            return {
                "status": "failed",
                "message": f"HuggingFace test error: {str(e)}",
                "duration_ms": (time.time() - start_time) * 1000
            }
    
    async def test_inference_performance(self) -> Dict[str, Any]:
        """Test inference performance across providers."""
        start_time = time.time()
        
        try:
            results = {}
            
            # Test each provider
            for provider_name in ["bitnet", "llama", "hf"]:
                provider = getattr(self.plugin, provider_name, None)
                if not provider:
                    continue
                
                # Run benchmark
                benchmark = await provider.benchmark()
                results[provider_name] = benchmark
            
            if not results:
                return {
                    "status": "skipped",
                    "message": "No providers available for performance testing",
                    "duration_ms": 0
                }
            
            # Check performance thresholds
            performance_ok = True
            for provider_name, metrics in results.items():
                if metrics.get("latency_ms", 0) > 5000:  # 5 second threshold
                    performance_ok = False
                    break
            
            return {
                "status": "passed" if performance_ok else "warning",
                "message": "Performance test completed",
                "duration_ms": (time.time() - start_time) * 1000,
                "details": results
            }
            
        except Exception as e:
            return {
                "status": "failed",
                "message": f"Performance test error: {str(e)}",
                "duration_ms": (time.time() - start_time) * 1000
            }
    
    async def test_memory_efficiency(self) -> Dict[str, Any]:
        """Test memory efficiency."""
        start_time = time.time()
        
        try:
            memory_results = {}
            
            # Test BitNet memory efficiency
            if self.plugin.bitnet:
                bitnet_memory = await self.plugin.bitnet.get_memory_usage()
                memory_results["bitnet"] = bitnet_memory
                
                # BitNet should use significantly less memory
                if bitnet_memory.get("ratio_vs_full", 1.0) > 0.2:
                    return {
                        "status": "failed",
                        "message": f"BitNet memory efficiency too low: {bitnet_memory.get('ratio_vs_full', 1.0):.3f}",
                        "duration_ms": (time.time() - start_time) * 1000
                    }
            
            return {
                "status": "passed",
                "message": "Memory efficiency test passed",
                "duration_ms": (time.time() - start_time) * 1000,
                "details": memory_results
            }
            
        except Exception as e:
            return {
                "status": "failed",
                "message": f"Memory test error: {str(e)}",
                "duration_ms": (time.time() - start_time) * 1000
            }
    
    async def test_streaming_inference(self) -> Dict[str, Any]:
        """Test streaming inference."""
        start_time = time.time()
        
        try:
            streaming_results = {}
            
            from plugin_internal import AIRequest
            request = AIRequest(
                model_id="test-model",
                prompt="Test streaming",
                max_tokens=5,
                stream=True
            )
            
            # Test each provider's streaming
            for provider_name in ["bitnet", "llama", "hf"]:
                provider = getattr(self.plugin, provider_name, None)
                if not provider:
                    continue
                
                tokens_received = 0
                async for chunk in provider.stream_generate(request):
                    tokens_received += 1
                    if chunk.get("done"):
                        break
                
                streaming_results[provider_name] = {
                    "tokens_received": tokens_received,
                    "streaming_working": tokens_received > 0
                }
            
            return {
                "status": "passed",
                "message": "Streaming inference test passed",
                "duration_ms": (time.time() - start_time) * 1000,
                "details": streaming_results
            }
            
        except Exception as e:
            return {
                "status": "failed",
                "message": f"Streaming test error: {str(e)}",
                "duration_ms": (time.time() - start_time) * 1000
            }
    
    async def test_model_loading(self) -> Dict[str, Any]:
        """Test model loading capabilities."""
        start_time = time.time()
        
        try:
            loading_results = {}
            
            # Test model discovery
            for provider_name in ["bitnet", "llama", "hf"]:
                provider = getattr(self.plugin, provider_name, None)
                if not provider:
                    continue
                
                models = await provider.get_available_models()
                loading_results[provider_name] = {
                    "models_discovered": len(models),
                    "models": [m.get("name", "unknown") for m in models[:3]]  # First 3
                }
            
            return {
                "status": "passed",
                "message": "Model loading test passed",
                "duration_ms": (time.time() - start_time) * 1000,
                "details": loading_results
            }
            
        except Exception as e:
            return {
                "status": "failed",
                "message": f"Model loading test error: {str(e)}",
                "duration_ms": (time.time() - start_time) * 1000
            }
    
    async def test_kernel_optimization(self) -> Dict[str, Any]:
        """Test kernel optimization."""
        start_time = time.time()
        
        try:
            if not self.plugin.bitnet:
                return {
                    "status": "skipped",
                    "message": "BitNet provider not available for kernel testing",
                    "duration_ms": 0
                }
            
            # Test kernel compilation
            kernel_compiled = self.plugin.bitnet.kernel.compiled
            
            return {
                "status": "passed" if kernel_compiled else "warning",
                "message": f"Kernel optimization {'enabled' if kernel_compiled else 'disabled'}",
                "duration_ms": (time.time() - start_time) * 1000,
                "details": {
                    "kernel_compiled": kernel_compiled,
                    "optimization_available": True
                }
            }
            
        except Exception as e:
            return {
                "status": "failed",
                "message": f"Kernel optimization test error: {str(e)}",
                "duration_ms": (time.time() - start_time) * 1000
            }


__all__ = ["TestSuite"]
