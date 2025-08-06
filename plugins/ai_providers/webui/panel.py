"""
AI Providers WebUI Panel

Web interface for managing AI providers, models, and performance monitoring.
"""

import asyncio
import json
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

from plugin_internal import AIRequest


class AIPanel:
    """AI Providers WebUI panel."""
    
    def __init__(self, plugin):
        self.plugin = plugin
        self.routes = {}
    
    async def initialize(self):
        """Initialize WebUI panel."""
        try:
            # Register routes
            self.routes = {
                "/ai-providers": self.main_panel,
                "/ai-providers/status": self.get_status,
                "/ai-providers/models": self.get_models,
                "/ai-providers/load-model": self.load_model,
                "/ai-providers/benchmark": self.run_benchmark,
                "/ai-providers/test": self.run_test,
                "/ai-providers/memory": self.get_memory_usage,
                "/ai-providers/inference": self.run_inference
            }
            
            logger.info("AI Providers WebUI panel initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize WebUI panel: {e}")
    
    def get_routes(self) -> Dict[str, Any]:
        """Get WebUI routes."""
        return self.routes
    
    async def main_panel(self, request) -> Dict[str, Any]:
        """Main AI providers panel."""
        try:
            # Get provider status
            status = await self.plugin.get_status()
            
            # Get available models
            models = {}
            if self.plugin.bitnet:
                models["bitnet"] = await self.plugin.bitnet.get_available_models()
            if self.plugin.llama:
                models["llama"] = await self.plugin.llama.get_available_models()
            if self.plugin.hf:
                models["hf"] = await self.plugin.hf.get_available_models()
            
            # Get memory usage
            memory = await self.plugin.get_memory_usage() if hasattr(self.plugin, 'get_memory_usage') else {}
            
            return {
                "success": True,
                "data": {
                    "title": "AI Providers",
                    "providers": status,
                    "models": models,
                    "memory": memory,
                    "features": [
                        {
                            "name": "BitNet 1-bit LLM",
                            "description": "Ultra-efficient 1-bit quantized models",
                            "enabled": status.get("bitnet", {}).get("enabled", False),
                            "benefits": ["87.5% memory savings", "3.2x speedup", "Local inference"]
                        },
                        {
                            "name": "Llama.cpp",
                            "description": "High-performance Llama models",
                            "enabled": status.get("llama", {}).get("enabled", False),
                            "benefits": ["CPU/GPU acceleration", "GGUF support", "Streaming inference"]
                        },
                        {
                            "name": "HuggingFace",
                            "description": "Transformers library integration",
                            "enabled": status.get("hf", {}).get("enabled", False),
                            "benefits": ["Thousands of models", "Easy deployment", "Community support"]
                        }
                    ]
                },
                "template": self._get_main_template()
            }
            
        except Exception as e:
            logger.error(f"Main panel error: {e}")
            return {"success": False, "error": str(e)}
    
    async def get_status(self, request) -> Dict[str, Any]:
        """Get provider status."""
        try:
            status = await self.plugin.get_status()
            return {"success": True, "data": status}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def get_models(self, request) -> Dict[str, Any]:
        """Get available models."""
        try:
            models = {}
            
            if self.plugin.bitnet:
                models["bitnet"] = await self.plugin.bitnet.get_available_models()
            
            if self.plugin.llama:
                models["llama"] = await self.plugin.llama.get_available_models()
            
            if self.plugin.hf:
                models["hf"] = await self.plugin.hf.get_available_models()
            
            return {"success": True, "data": models}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def load_model(self, request) -> Dict[str, Any]:
        """Load a model."""
        try:
            data = await request.json()
            provider = data.get("provider")
            model_name = data.get("model")
            
            if not provider or not model_name:
                return {"success": False, "error": "Provider and model name required"}
            
            result = None
            if provider == "bitnet" and self.plugin.bitnet:
                result = await self.plugin.bitnet.load_model(model_name)
            elif provider == "llama" and self.plugin.llama:
                result = await self.plugin.llama.load_model(model_name)
            elif provider == "hf" and self.plugin.hf:
                result = await self.plugin.hf.load_model(model_name)
            else:
                return {"success": False, "error": f"Provider {provider} not available"}
            
            return {"success": True, "data": result}
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def run_benchmark(self, request) -> Dict[str, Any]:
        """Run performance benchmark."""
        try:
            results = await self.plugin.benchmark()
            return {"success": True, "data": results}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def run_test(self, request) -> Dict[str, Any]:
        """Run plugin tests."""
        try:
            results = await self.plugin.run_tests()
            return {"success": True, "data": results}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def get_memory_usage(self, request) -> Dict[str, Any]:
        """Get memory usage."""
        try:
            if hasattr(self.plugin, 'get_memory_usage'):
                usage = await self.plugin.get_memory_usage()
                return {"success": True, "data": usage}
            else:
                return {"success": False, "error": "Memory usage not available"}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def run_inference(self, request) -> Dict[str, Any]:
        """Run inference test."""
        try:
            data = await request.json()
            provider = data.get("provider")
            model = data.get("model")
            prompt = data.get("prompt", "Hello, how are you?")
            
            if not provider or not model:
                return {"success": False, "error": "Provider and model required"}
            
            # Create request
            ai_request = AIRequest(
                model_id=model,
                prompt=prompt,
                max_tokens=50,
                temperature=0.7
            )
            
            # Run inference
            result = None
            if provider == "bitnet" and self.plugin.bitnet:
                result = await self.plugin.bitnet.generate(ai_request)
            elif provider == "llama" and self.plugin.llama:
                result = await self.plugin.llama.generate(ai_request)
            elif provider == "hf" and self.plugin.hf:
                result = await self.plugin.hf.generate(ai_request)
            else:
                return {"success": False, "error": f"Provider {provider} not available"}
            
            return {
                "success": True,
                "data": {
                    "content": result.content,
                    "latency_ms": result.latency_ms,
                    "usage": result.usage,
                    "metadata": result.metadata
                }
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _get_main_template(self) -> str:
        """Get main panel HTML template."""
        return """
        <div class="ai-providers-panel">
            <div class="header">
                <h2><i class="fas fa-brain"></i> AI Providers</h2>
                <p>Manage local AI models and providers</p>
            </div>
            
            <div class="providers-grid">
                <div class="provider-card bitnet">
                    <h3><i class="fas fa-microchip"></i> BitNet 1-bit LLM</h3>
                    <p>Ultra-efficient 1-bit quantized models</p>
                    <div class="status" id="bitnet-status">Loading...</div>
                    <div class="benefits">
                        <span class="benefit">87.5% memory savings</span>
                        <span class="benefit">3.2x speedup</span>
                        <span class="benefit">Local inference</span>
                    </div>
                    <button onclick="loadProvider('bitnet')" class="btn-primary">Manage</button>
                </div>
                
                <div class="provider-card llama">
                    <h3><i class="fas fa-rocket"></i> Llama.cpp</h3>
                    <p>High-performance Llama models</p>
                    <div class="status" id="llama-status">Loading...</div>
                    <div class="benefits">
                        <span class="benefit">CPU/GPU acceleration</span>
                        <span class="benefit">GGUF support</span>
                        <span class="benefit">Streaming inference</span>
                    </div>
                    <button onclick="loadProvider('llama')" class="btn-primary">Manage</button>
                </div>
                
                <div class="provider-card hf">
                    <h3><i class="fas fa-hugging-face"></i> HuggingFace</h3>
                    <p>Transformers library integration</p>
                    <div class="status" id="hf-status">Loading...</div>
                    <div class="benefits">
                        <span class="benefit">Thousands of models</span>
                        <span class="benefit">Easy deployment</span>
                        <span class="benefit">Community support</span>
                    </div>
                    <button onclick="loadProvider('hf')" class="btn-primary">Manage</button>
                </div>
            </div>
            
            <div class="actions">
                <button onclick="runBenchmark()" class="btn-secondary">
                    <i class="fas fa-chart-line"></i> Run Benchmark
                </button>
                <button onclick="runTests()" class="btn-secondary">
                    <i class="fas fa-vial"></i> Run Tests
                </button>
                <button onclick="showMemoryUsage()" class="btn-secondary">
                    <i class="fas fa-memory"></i> Memory Usage
                </button>
            </div>
            
            <div id="results-panel" class="results-panel" style="display: none;">
                <h3>Results</h3>
                <pre id="results-content"></pre>
            </div>
        </div>
        
        <style>
        .ai-providers-panel {
            padding: 20px;
            max-width: 1200px;
            margin: 0 auto;
        }
        
        .providers-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        
        .provider-card {
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 20px;
            background: #f9f9f9;
        }
        
        .provider-card h3 {
            margin: 0 0 10px 0;
            color: #333;
        }
        
        .status {
            padding: 5px 10px;
            border-radius: 4px;
            font-size: 12px;
            margin: 10px 0;
        }
        
        .benefits {
            display: flex;
            flex-wrap: wrap;
            gap: 5px;
            margin: 10px 0;
        }
        
        .benefit {
            background: #e3f2fd;
            color: #1976d2;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 11px;
        }
        
        .actions {
            text-align: center;
            margin: 30px 0;
        }
        
        .btn-primary, .btn-secondary {
            padding: 10px 20px;
            margin: 0 10px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }
        
        .btn-primary {
            background: #1976d2;
            color: white;
        }
        
        .btn-secondary {
            background: #757575;
            color: white;
        }
        
        .results-panel {
            margin-top: 20px;
            padding: 20px;
            background: #f5f5f5;
            border-radius: 8px;
        }
        </style>
        
        <script>
        async function loadProvider(provider) {
            // Implementation for provider management
            console.log('Loading provider:', provider);
        }
        
        async function runBenchmark() {
            const response = await fetch('/ai-providers/benchmark');
            const data = await response.json();
            showResults(JSON.stringify(data, null, 2));
        }
        
        async function runTests() {
            const response = await fetch('/ai-providers/test');
            const data = await response.json();
            showResults(JSON.stringify(data, null, 2));
        }
        
        async function showMemoryUsage() {
            const response = await fetch('/ai-providers/memory');
            const data = await response.json();
            showResults(JSON.stringify(data, null, 2));
        }
        
        function showResults(content) {
            document.getElementById('results-content').textContent = content;
            document.getElementById('results-panel').style.display = 'block';
        }
        
        // Load initial status
        async function loadStatus() {
            try {
                const response = await fetch('/ai-providers/status');
                const data = await response.json();
                
                if (data.success) {
                    const providers = data.data;
                    
                    for (const [name, info] of Object.entries(providers)) {
                        const statusEl = document.getElementById(name + '-status');
                        if (statusEl) {
                            statusEl.textContent = info.enabled ? 'Available' : 'Disabled';
                            statusEl.className = 'status ' + (info.enabled ? 'enabled' : 'disabled');
                        }
                    }
                }
            } catch (error) {
                console.error('Failed to load status:', error);
            }
        }
        
        // Load status on page load
        document.addEventListener('DOMContentLoaded', loadStatus);
        </script>
        """
    
    async def shutdown(self):
        """Shutdown WebUI panel."""
        logger.info("AI Providers WebUI panel shutdown")


__all__ = ["AIPanel"]
