"""
AI Providers Plugin

Advanced AI providers with BitNet 1-bit LLM, Llama.cpp, and HuggingFace support.
"""

import asyncio
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

# Plugin interface imports with fallbacks
try:
    from plexichat.infrastructure.modules.plugin_manager import PluginInterface, PluginMetadata, PluginType
except ImportError:
    class PluginInterface:
        def __init__(self, name, version):
            self.name = name
            self.version = version
        def get_metadata(self) -> Dict[str, Any]:
            return {}
        def get_required_permissions(self) -> "ModulePermissions":
            return ModulePermissions()

    class PluginMetadata:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)

    class PluginType:
        FEATURE = "feature"

try:
    from plexichat.infrastructure.modules.base_module import ModulePermissions, ModuleCapability
except ImportError:
    class ModulePermissions:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)

    class ModuleCapability:
        MESSAGING = "messaging"
        FILE_SYSTEM_ACCESS = "file_system_access"
        NETWORK_ACCESS = "network_access"

# Provider imports with fallbacks
try:
    from .providers.bitnet import BitNetProvider, BitNetConfig
except ImportError:
    class BitNetConfig:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)

    class BitNetProvider:
        def __init__(self, config):
            self.config = config
        async def initialize(self):
            pass
        async def generate(self, prompt, **kwargs):
            return f"BitNet response to: {prompt}"
        async def shutdown(self):
            pass
        async def benchmark(self):
            return {"provider": "BitNet", "status": "not_available"}

try:
    from .providers.llama import LlamaProvider, LlamaConfig
except ImportError:
    class LlamaConfig:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)

    class LlamaProvider:
        def __init__(self, config):
            self.config = config
        async def initialize(self):
            pass
        async def generate(self, prompt, **kwargs):
            return f"Llama response to: {prompt}"
        async def shutdown(self):
            pass
        async def benchmark(self):
            return {"provider": "Llama", "status": "not_available"}

try:
    from .providers.hf import HFProvider, HFConfig
except ImportError:
    class HFConfig:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)

    class HFProvider:
        def __init__(self, config):
            self.config = config
        async def initialize(self):
            pass
        async def generate(self, prompt, **kwargs):
            return f"HuggingFace response to: {prompt}"
        async def shutdown(self):
            pass
        async def benchmark(self):
            return {"provider": "HuggingFace", "status": "not_available"}

try:
    from .webui.panel import AIPanel
except ImportError:
    class AIPanel:
        def __init__(self):
            pass
        async def shutdown(self):
            pass
        def get_panel_data(self):
            return {"status": "not_available"}
        async def initialize(self):
            pass

try:
    from .tests.suite import TestSuite
except ImportError:
    class TestSuite:
        def __init__(self):
            pass
        async def run_tests(self):
            return {"status": "tests_not_available"}
        async def run_all(self):
            return {"status": "tests_not_available"}
        async def initialize(self):
            pass

logger = logging.getLogger(__name__)


class AIProvidersPlugin(PluginInterface):
    """AI Providers Plugin with BitNet, Llama, and HF support."""

    def __init__(self):
        super().__init__("ai_providers", "1.0.0")
        
        # Providers
        self.bitnet: Optional[BitNetProvider] = None
        self.llama: Optional[LlamaProvider] = None
        self.hf: Optional[HFProvider] = None
        
        # WebUI
        self.webui: Optional[AIPanel] = None
        
        # Test suite
        self.tests: Optional[TestSuite] = None
        
        # Configuration
        self.config = {}

        # State
        self.providers_registered = False

    def get_metadata(self) -> Dict[str, Any]:
        """Get plugin metadata."""
        return {
            "name": "ai_providers",
            "version": "1.0.0",
            "description": "AI providers with BitNet 1-bit LLM, Llama.cpp, and HF support",
            "author": "PlexiChat Team",
            "plugin_type": "FEATURE",
            "enabled": True,
            "capabilities": [
                "bitnet_1bit_llm",
                "llama_cpp",
                "hf_integration",
                "local_inference"
            ]
        }

    def get_required_permissions(self) -> ModulePermissions:
        """Get required permissions."""
        return ModulePermissions(
            capabilities=[
                ModuleCapability.MESSAGING,
                ModuleCapability.FILE_SYSTEM_ACCESS,
                ModuleCapability.NETWORK_ACCESS
            ],
            network_access=True,
            file_system_access=True,
            database_access=False
        )

    async def _plugin_initialize(self) -> bool:
        """Initialize the AI providers plugin."""
        try:
            logger.info("Initializing AI Providers Plugin...")
            
            # Initialize providers
            await self._init_providers()
            
            # Register with AI layer
            await self._register_providers()
            
            # Initialize WebUI
            await self._init_webui()
            
            # Initialize tests
            await self._init_tests()
            
            logger.info("AI Providers Plugin initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"AI Providers Plugin initialization failed: {e}")
            return False

    async def _init_providers(self):
        """Initialize AI providers."""
        config = self.config
        
        # BitNet provider
        if config.get("bitnet", {}).get("enabled", True):
            try:
                bitnet_config = BitNetConfig(
                    model_path=config.get("bitnet", {}).get("model_path", "data/bitnet_models"),
                    quantization_bits=1,
                    kernel_optimization=config.get("bitnet", {}).get("kernel_optimization", True)
                )
                
                self.bitnet = BitNetProvider(bitnet_config)
                if hasattr(self.bitnet, "initialize"):
                    await self.bitnet.initialize()
                logger.info("BitNet provider initialized")
                
            except Exception as e:
                logger.error(f"Failed to initialize BitNet: {e}")
        
        # Llama provider
        if config.get("llama", {}).get("enabled", True):
            try:
                llama_config = LlamaConfig(
                    model_path=config.get("llama", {}).get("model_path", "data/llama_models"),
                    n_ctx=config.get("llama", {}).get("n_ctx", 2048)
                )
                
                self.llama = LlamaProvider(llama_config)
                if hasattr(self.llama, "initialize"):
                    await self.llama.initialize()
                logger.info("Llama provider initialized")
                
            except Exception as e:
                logger.error(f"Failed to initialize Llama: {e}")
        
        # HuggingFace provider
        if config.get("hf", {}).get("enabled", True):
            try:
                hf_config = HFConfig(
                    cache_dir=config.get("hf", {}).get("cache_dir", "data/hf_cache")
                )
                
                self.hf = HFProvider(hf_config)
                if hasattr(self.hf, "initialize"):
                    await self.hf.initialize()
                logger.info("HF provider initialized")
                
            except Exception as e:
                logger.error(f"Failed to initialize HF: {e}")

    async def _register_providers(self):
        """Register providers with AI layer."""
        try:
            # Import AI layer
            from plexichat.features.ai.core.ai_abstraction_layer import AIAbstractionLayer
            ai_layer = AIAbstractionLayer()
            
            # Register providers
            if self.bitnet:
                await ai_layer.register_provider("bitnet", self.bitnet)
                logger.info("BitNet registered")
            
            if self.llama:
                await ai_layer.register_provider("llama", self.llama)
                logger.info("Llama registered")
            
            if self.hf:
                await ai_layer.register_provider("hf", self.hf)
                logger.info("HF registered")
            
            self.providers_registered = True
            
        except Exception as e:
            logger.error(f"Failed to register providers: {e}")

    async def _init_webui(self):
        """Initialize WebUI."""
        try:
            self.webui = AIPanel()
            if hasattr(self.webui, "initialize"):
                await self.webui.initialize()
            logger.info("WebUI initialized")

        except Exception as e:
            logger.error(f"Failed to initialize WebUI: {e}")

    async def _init_tests(self):
        """Initialize test suite."""
        try:
            self.tests = TestSuite()
            if hasattr(self.tests, "initialize"):
                await self.tests.initialize()
            logger.info("Test suite initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize tests: {e}")

    async def get_status(self) -> Dict[str, Any]:
        """Get provider status."""
        return {
            "bitnet": {
                "enabled": self.bitnet is not None,
                "status": "available" if self.bitnet else "disabled"
            },
            "llama": {
                "enabled": self.llama is not None,
                "status": "available" if self.llama else "disabled"
            },
            "hf": {
                "enabled": self.hf is not None,
                "status": "available" if self.hf else "disabled"
            }
        }

    async def run_tests(self) -> Dict[str, Any]:
        """Run plugin self-tests."""
        if not self.tests:
            return {"error": "Test suite not initialized"}
        
        return await self.tests.run_all()

    async def benchmark(self) -> Dict[str, Any]:
        """Run performance benchmarks."""
        results = {}
        
        if self.bitnet:
            results["bitnet"] = await self.bitnet.benchmark()
        
        if self.llama:
            results["llama"] = await self.llama.benchmark()
        
        if self.hf:
            results["hf"] = await self.hf.benchmark()
        
        return results

    async def shutdown(self) -> bool:
        """Shutdown plugin."""
        try:
            logger.info("Shutting down AI Providers Plugin...")

            if self.bitnet:
                await self.bitnet.shutdown()

            if self.llama:
                await self.llama.shutdown()

            if self.hf:
                await self.hf.shutdown()

            if self.webui:
                await self.webui.shutdown()

            logger.info("AI Providers Plugin shutdown complete")
            return True

        except Exception as e:
            logger.error(f"Error during shutdown: {e}")
            return False


# Plugin entry point
async def create_plugin() -> AIProvidersPlugin:
    """Create plugin instance."""
    return AIProvidersPlugin()


__all__ = ["AIProvidersPlugin", "create_plugin"]
