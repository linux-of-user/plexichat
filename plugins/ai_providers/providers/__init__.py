"""
AI Providers Package

This package contains various AI provider implementations for the PlexiChat system.
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Try to import available providers
try:
    from .bitnet import BitNetProvider, BitNetConfig
    bitnet_available = True
except ImportError as e:
    logger.warning(f"BitNet provider not available: {e}")
    bitnet_available = False
    BitNetProvider = None
    BitNetConfig = None

try:
    from .llama import LlamaProvider, LlamaConfig
    llama_available = True
except ImportError as e:
    logger.warning(f"Llama provider not available: {e}")
    llama_available = False
    LlamaProvider = None
    LlamaConfig = None

try:
    from .huggingface import HuggingFaceProvider, HFConfig
    hf_available = True
except ImportError as e:
    logger.warning(f"HuggingFace provider not available: {e}")
    hf_available = False
    HuggingFaceProvider = None
    HFConfig = None

# Export available providers
__all__ = []

if bitnet_available:
    __all__.extend(['BitNetProvider', 'BitNetConfig'])

if llama_available:
    __all__.extend(['LlamaProvider', 'LlamaConfig'])

if hf_available:
    __all__.extend(['HuggingFaceProvider', 'HFConfig'])

def get_available_providers():
    """Get list of available AI providers."""
    providers = []
    if bitnet_available:
        providers.append('bitnet')
    if llama_available:
        providers.append('llama')
    if hf_available:
        providers.append('huggingface')
    return providers

def create_provider(provider_name: str, config: Optional[dict] = None):
    """Create an AI provider instance by name."""
    config = config or {}

    if provider_name.lower() == 'bitnet' and bitnet_available and BitNetProvider is not None:
        return BitNetProvider(BitNetConfig(**config))
    elif provider_name.lower() == 'llama' and llama_available and LlamaProvider is not None:
        return LlamaProvider(LlamaConfig(**config))
    elif provider_name.lower() == 'huggingface' and hf_available and HuggingFaceProvider is not None:
        return HuggingFaceProvider(HFConfig(**config))
    else:
        raise ValueError(f"Provider '{provider_name}' not available or not supported")
