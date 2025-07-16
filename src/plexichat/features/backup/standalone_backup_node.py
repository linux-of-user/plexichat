# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import argparse
import asyncio
import json
import sys
from pathlib import Path

import yaml


from pathlib import Path
from pathlib import Path
from pathlib import Path


from pathlib import Path
from pathlib import Path
from pathlib import Path

from plexichat.app.backup.backup_node_system import BackupNodeConfig, BackupNodeSystem, NodeMode
import logging
from typing import Optional


#!/usr/bin/env python3
"""
PlexiChat Standalone Backup Node

A simple, standalone backup node that can be run independently of the main PlexiChat application.
This provides distributed backup storage with government-level security and intelligent shard management.

Usage:
    python standalone_backup_node.py --port 8001 --storage-path ./backup_storage --max-storage-gb 100
    python standalone_backup_node.py --config backup_node_config.yaml
"""

# Add src to path for imports
sys.path.insert(0, str(from pathlib import Path
Path(__file__).parent / "src"))

try:
except ImportError:
    logger.info(" Error: Could not import PlexiChat backup system.")
    logger.info("Make sure you're running this from the PlexiChat root directory.")
    sys.exit(1)

logger = logging.getLogger(__name__)
def load_config(config_path: str) -> BackupNodeConfig:
    """Load configuration from file."""
    try:
        from pathlib import Path
config_file = Path
Path(config_path)
        if not config_file.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")

        with open(config_file, 'r') as f:
            if config_path.endswith('.yaml') or config_path.endswith('.yml'):
                config_data = yaml.safe_load(f)
            else:
                config_data = json.load(f)

        return BackupNodeConfig(**config_data)

    except Exception as e:
        logger.info(f" Error loading configuration: {e}")
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

        logger.info(f" Created default configuration: {config_path}")
        return BackupNodeConfig(**config)

    except Exception as e:
        logger.info(f" Error creating configuration: {e}")
        sys.exit(1)

def print_banner():
    """Print startup banner."""
    logger.info("=" * 60)
    logger.info(" PlexiChat Standalone Backup Node v3.0.0")
    logger.info("   Government-Grade Distributed Backup Storage")
    logger.info("=" * 60)

def print_node_info(config: BackupNodeConfig):
    """Print node information."""
    logger.info(f" Node ID: {config.node_id}")
    logger.info(f" Storage Path: {config.storage_path}")
    logger.info(f" Max Storage: {config.max_storage_gb} GB")
    logger.info(f" Listen Address: {config.host}:{config.port}")
    logger.info(f" Encryption: {'Enabled' if config.encryption_enabled else 'Disabled'}")
    logger.info(f" Compression: {'Enabled' if config.compression_enabled else 'Disabled'}")
    logger.info(f" Clustering: {'Enabled' if config.cluster_enabled else 'Disabled'}")
    logger.info(f" Auto Discovery: {'Enabled' if config.auto_discovery else 'Disabled'}")
    logger.info("=" * 60)

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
            node_id=args.node_id or "backup_node_standalone",
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
    from pathlib import Path
storage_path = Path
Path(config.storage_path)
    storage_path.mkdir(parents=True, exist_ok=True)

    # Create and start backup node
    backup_node = BackupNodeSystem(config)

    try:
        logger.info(" Starting backup node...")
        await backup_node.start_standalone()

    except KeyboardInterrupt:
        logger.info("\n Received shutdown signal")

    except Exception as e:
        logger.info(f" Error starting backup node: {e}")
        sys.exit(1)

    finally:
        logger.info(" Shutting down...")
        await if backup_node and hasattr(backup_node, "stop"): backup_node.stop()
        logger.info(" Backup node stopped")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("\n Goodbye!")
    except Exception as e:
        logger.info(f" Fatal error: {e}")
        sys.exit(1)
