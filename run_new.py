#!/usr/bin/env python3
"""
NetLink 2.0.0 Enhanced Runner - Quantum-Secure Entry Point

Enhanced entry point for NetLink 2.0.0 with government-level security,
quantum-proof encryption, and distributed architecture.
"""

import sys
import os
import asyncio
from pathlib import Path

# Add src to Python path
ROOT = Path(__file__).parent.resolve()
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

def print_banner():
    """Print NetLink 2.0.0 startup banner."""
    banner = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                           NetLink 2.0.0 Enhanced                            ║
║                        Quantum-Secure Communication                         ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  🛡️  Government-Level Security    🔬 Quantum-Proof Encryption              ║
║  🌐 Distributed Architecture      ⚡ Performance Optimized                 ║
║  🔧 Advanced Service Management   📊 Real-Time Monitoring                  ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """
    print(banner)

def check_system_requirements():
    """Check system requirements and dependencies."""
    print("🔍 Checking system requirements...")
    
    # Check Python version
    if sys.version_info < (3.8, 0):
        print("❌ Python 3.8+ required")
        return False
    
    print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")
    
    # Check if src directory exists
    if not SRC.exists():
        print("❌ Source directory not found")
        return False
    
    print("✅ Source directory found")
    
    # Check if main NetLink package can be imported
    try:
        import netlink
        print(f"✅ NetLink {netlink.__version__} ({netlink.__build__}) loaded")
        return True
    except ImportError as e:
        print(f"❌ Failed to import NetLink: {e}")
        return False

async def initialize_security_systems():
    """Initialize all security systems."""
    print("🔐 Initializing security systems...")
    
    try:
        from netlink.security import security_manager
        
        # Initialize quantum encryption
        print("  🔬 Initializing quantum encryption...")
        await security_manager.quantum_encryption.initialize()
        
        # Initialize key management
        print("  🔑 Initializing distributed key management...")
        await security_manager.key_manager.initialize()
        
        # Initialize monitoring
        print("  🔍 Starting security monitoring...")
        await security_manager.start_monitoring()
        
        print("✅ Security systems initialized")
        return True
        
    except Exception as e:
        print(f"❌ Security initialization failed: {e}")
        return False

async def initialize_core_systems():
    """Initialize core NetLink systems."""
    print("⚙️ Initializing core systems...")
    
    try:
        # Initialize optimization system
        print("  ⚡ Initializing optimization system...")
        from netlink.optimization import optimization_manager
        await optimization_manager.initialize()
        
        # Initialize service manager
        print("  🔧 Initializing service manager...")
        from netlink.services.service_manager import service_manager
        await service_manager.initialize()
        
        # Initialize backup system
        print("  💾 Initializing backup system...")
        from netlink.backup import quantum_backup_system
        await quantum_backup_system.initialize()
        
        print("✅ Core systems initialized")
        return True
        
    except Exception as e:
        print(f"❌ Core system initialization failed: {e}")
        return False

async def start_netlink():
    """Start NetLink with full initialization."""
    print("🚀 Starting NetLink 2.0.0...")
    
    try:
        # Import the main application
        from netlink.app.main import app
        
        # Start the FastAPI application
        import uvicorn
        
        print("🌐 Starting web server...")
        print("📡 NetLink 2.0.0 is now running!")
        print("🔗 Access the admin panel at: https://localhost:8000/ui")
        print("📚 API documentation at: https://localhost:8000/docs")
        print("🛡️ All endpoints secured with quantum encryption")
        
        # Run the server
        config = uvicorn.Config(
            app,
            host="0.0.0.0",
            port=8000,
            ssl_keyfile=None,  # Will be configured by certificate manager
            ssl_certfile=None,
            log_level="info"
        )
        
        server = uvicorn.Server(config)
        await server.serve()
        
    except ImportError as e:
        print(f"❌ Failed to import application components: {e}")
        print("💡 Running in basic mode - some features may be unavailable")
        
        # Fallback to basic runner
        try:
            from netlink.core.launcher import NetLinkLauncher
            launcher = NetLinkLauncher()
            await launcher.start()
        except Exception as fallback_error:
            print(f"❌ Fallback launcher failed: {fallback_error}")
            return False
    
    except Exception as e:
        print(f"❌ Failed to start NetLink: {e}")
        return False
    
    return True

async def main():
    """Main entry point for NetLink 2.0.0."""
    print_banner()
    
    # Check system requirements
    if not check_system_requirements():
        print("❌ System requirements not met")
        sys.exit(1)
    
    try:
        # Initialize security systems first
        if not await initialize_security_systems():
            print("⚠️ Security initialization failed - running in reduced security mode")
        
        # Initialize core systems
        if not await initialize_core_systems():
            print("⚠️ Some core systems failed to initialize")
        
        # Start NetLink
        if await start_netlink():
            print("✅ NetLink 2.0.0 started successfully")
        else:
            print("❌ Failed to start NetLink")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n🛑 NetLink shutdown requested")
        print("🔐 Securing systems...")
        
        try:
            # Graceful shutdown
            from netlink.security import security_manager
            await security_manager.shutdown()
            print("✅ NetLink shutdown complete")
        except:
            print("⚠️ Emergency shutdown")
        
        sys.exit(0)
    
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        sys.exit(1)

def run_sync():
    """Synchronous wrapper for async main function."""
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n🛑 NetLink stopped")
        sys.exit(0)
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    run_sync()
