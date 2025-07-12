#!/usr/bin/env python3
"""
AI Node Plugin Setup Script
Installs dependencies and configures the AI node
"""

import os
import sys
import subprocess
import json
from pathlib import Path

def install_dependencies():
    """Install plugin dependencies."""
    print("🔧 Installing AI Node dependencies...")
    
    requirements_file = Path(__file__).parent / "requirements.txt"
    
    try:
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", "-r", str(requirements_file)
        ])
        print("✅ Dependencies installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install dependencies: {e}")
        return False

def setup_directories():
    """Setup required directories."""
    print("📁 Setting up directories...")
    
    plugin_dir = Path(__file__).parent
    
    directories = [
        plugin_dir / "models",
        plugin_dir / "cache",
        plugin_dir / "logs"
    ]
    
    for directory in directories:
        directory.mkdir(exist_ok=True)
        print(f"✅ Created directory: {directory}")

def create_default_config():
    """Create default configuration."""
    print("⚙️ Creating default configuration...")
    
    config_file = Path(__file__).parent / "config.json"
    
    if config_file.exists():
        print("ℹ️ Configuration file already exists")
        return
    
    default_config = {
        "max_models": 10,
        "model_cache_size_gb": 50,
        "inference_timeout": 30,
        "enable_gpu": True,
        "enable_quantization": True,
        "web_ui_port": 8080,
        "default_models": [
            "microsoft/DialoGPT-medium",
            "sentence-transformers/all-MiniLM-L6-v2"
        ]
    }
    
    with open(config_file, 'w') as f:
        json.dump(default_config, f, indent=2)
    
    print("✅ Default configuration created")

def check_gpu_support():
    """Check for GPU support."""
    print("🔍 Checking GPU support...")
    
    try:
        import torch
        if torch.cuda.is_available():
            gpu_count = torch.cuda.device_count()
            gpu_name = torch.cuda.get_device_name(0)
            print(f"✅ GPU support available: {gpu_count} GPU(s)")
            print(f"   Primary GPU: {gpu_name}")
            return True
        else:
            print("⚠️ No GPU support detected, will use CPU")
            return False
    except ImportError:
        print("⚠️ PyTorch not installed, cannot check GPU support")
        return False

def main():
    """Main setup function."""
    print("🤖 AI Node Plugin Setup")
    print("=" * 40)
    
    # Install dependencies
    if not install_dependencies():
        print("❌ Setup failed: Could not install dependencies")
        return False
    
    # Setup directories
    setup_directories()
    
    # Create default configuration
    create_default_config()
    
    # Check GPU support
    gpu_available = check_gpu_support()
    
    print("\n🎉 AI Node Plugin setup complete!")
    print("\nNext steps:")
    print("1. Start PlexiChat with the AI Node plugin enabled")
    print("2. Access the web UI at http://localhost:8080")
    print("3. Install models from HuggingFace using the web interface")
    
    if gpu_available:
        print("4. GPU acceleration is available for faster inference")
    else:
        print("4. Consider installing CUDA for GPU acceleration")
    
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
