#!/usr/bin/env python3
"""
PlexiChat Standalone Backup Node

A simple, standalone backup node that can be run independently of the main PlexiChat application.
This provides distributed backup storage with government-level security and intelligent shard management.

Usage:
    python standalone_backup_node.py --port 8001 --storage-path ./backup_storage --max-storage-gb 100
    python standalone_backup_node.py --config backup_node_config.yaml
"""

import asyncio
import sys
import argparse
import yaml
import json
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent / "src"))

try:
    from plexichat.app.backup.backup_node_system import BackupNodeSystem, BackupNodeConfig, NodeMode
except ImportError:
    print("❌ Error: Could not import PlexiChat backup system.")
    print("Make sure you're running this from the PlexiChat root directory.")
    sys.exit(1)

def load_config(config_path: str) -> BackupNodeConfig:
    """Load configuration from file."""
    try:
        config_file = Path(config_path)
        if not config_file.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
        
        with open(config_file, 'r') as f:
            if config_path.endswith('.yaml') or config_path.endswith('.yml'):
                config_data = yaml.safe_load(f)
            else:
                config_data = json.load(f)
        
        return BackupNodeConfig(**config_data)
        
    except Exception as e:
        print(f"❌ Error loading configuration: {e}")
        sys.exit(1)

def create_default_config(config_path: str, args):
    """Create a default configuration file."""
    config = {
        "node_id": f"backup_node_{args.node_id or 'standalone'}",
        "node_name": "PlexiChat Standalone Backup Node",
        "node_mode": "standalone",
        "host": "0.0.0.0",
        "port": args.port,
        "storage_path": args.storage_path,
        "max_storage_gb": args.max_storage_gb,
        "cleanup_threshold_percent": 85,
        "shard_replication_factor": 2,
        "max_concurrent_operations": 10,
        "health_check_interval": 30,
        "sync_interval": 300,
        "compression_enabled": True,
        "encryption_enabled": True,
        "require_authentication": True,
        "cluster_enabled": True,
        "auto_discovery": True,
        "allowed_nodes": [],
        "cluster_nodes": []
    }
    
    try:
        with open(config_path, 'w') as f:
            if config_path.endswith('.yaml') or config_path.endswith('.yml'):
                yaml.dump(config, f, default_flow_style=False, indent=2)
            else:
                json.dump(config, f, indent=2)
        
        print(f"✅ Created default configuration: {config_path}")
        return BackupNodeConfig(**config)
        
    except Exception as e:
        print(f"❌ Error creating configuration: {e}")
        sys.exit(1)

def print_banner():
    """Print startup banner."""
    print("=" * 60)
    print("🚀 PlexiChat Standalone Backup Node v3.0.0")
    print("   Government-Grade Distributed Backup Storage")
    print("=" * 60)

def print_node_info(config: BackupNodeConfig):
    """Print node information."""
    print(f"🆔 Node ID: {config.node_id}")
    print(f"📁 Storage Path: {config.storage_path}")
    print(f"💾 Max Storage: {config.max_storage_gb} GB")
    print(f"🌐 Listen Address: {config.host}:{config.port}")
    print(f"🔐 Encryption: {'Enabled' if config.encryption_enabled else 'Disabled'}")
    print(f"🗜️ Compression: {'Enabled' if config.compression_enabled else 'Disabled'}")
    print(f"🌍 Clustering: {'Enabled' if config.cluster_enabled else 'Disabled'}")
    print(f"🔍 Auto Discovery: {'Enabled' if config.auto_discovery else 'Disabled'}")
    print("=" * 60)

async def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="PlexiChat Standalone Backup Node",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Start with default settings
  python standalone_backup_node.py
  
  # Start with custom settings
  python standalone_backup_node.py --port 8001 --storage-path ./backup --max-storage-gb 50
  
  # Start with configuration file
  python standalone_backup_node.py --config backup_node.yaml
  
  # Create default configuration file
  python standalone_backup_node.py --create-config backup_node.yaml
        """
    )
    
    parser.add_argument("--config", type=str, help="Configuration file path (YAML or JSON)")
    parser.add_argument("--create-config", type=str, help="Create default configuration file")
    parser.add_argument("--node-id", type=str, help="Unique node identifier")
    parser.add_argument("--port", type=int, default=8001, help="Port to listen on (default: 8001)")
    parser.add_argument("--storage-path", type=str, default="./backup_storage", 
                       help="Storage directory path (default: ./backup_storage)")
    parser.add_argument("--max-storage-gb", type=int, default=100, 
                       help="Maximum storage in GB (default: 100)")
    parser.add_argument("--host", type=str, default="0.0.0.0", 
                       help="Host to bind to (default: 0.0.0.0)")
    parser.add_argument("--no-encryption", action="store_true", 
                       help="Disable encryption (not recommended)")
    parser.add_argument("--no-compression", action="store_true", 
                       help="Disable compression")
    parser.add_argument("--no-clustering", action="store_true", 
                       help="Disable clustering")
    parser.add_argument("--verbose", "-v", action="store_true", 
                       help="Enable verbose logging")
    
    args = parser.parse_args()
    
    # Handle create-config option
    if args.create_config:
        create_default_config(args.create_config, args)
        return
    
    print_banner()
    
    # Load or create configuration
    if args.config:
        config = load_config(args.config)
    else:
        # Create configuration from command line arguments
        config = BackupNodeConfig(
            node_id=args.node_id or f"backup_node_standalone",
            node_mode=NodeMode.STANDALONE,
            host=args.host,
            port=args.port,
            storage_path=args.storage_path,
            max_storage_gb=args.max_storage_gb,
            encryption_enabled=not args.no_encryption,
            compression_enabled=not args.no_compression,
            cluster_enabled=not args.no_clustering
        )
    
    print_node_info(config)
    
    # Create storage directory
    storage_path = Path(config.storage_path)
    storage_path.mkdir(parents=True, exist_ok=True)
    
    # Create and start backup node
    backup_node = BackupNodeSystem(config)
    
    try:
        print("🚀 Starting backup node...")
        await backup_node.start_standalone()
        
    except KeyboardInterrupt:
        print("\n🛑 Received shutdown signal")
        
    except Exception as e:
        print(f"❌ Error starting backup node: {e}")
        sys.exit(1)
        
    finally:
        print("🔄 Shutting down...")
        await backup_node.stop()
        print("✅ Backup node stopped")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        sys.exit(1)
