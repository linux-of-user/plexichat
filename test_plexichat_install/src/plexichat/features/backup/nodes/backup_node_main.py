#!/usr/bin/env python3
"""
import time
PlexiChat Backup Node Main

Main entry point for running PlexiChat backup nodes.
Provides distributed backup storage with clustering and redundancy.
"""

import asyncio
import argparse
import json
import logging
import signal
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any
import os

try:
    from plexichat.features.backup.core.backup_node_server import BackupNodeServer, BackupNodeConfig
    from plexichat.features.backup.nodes.backup_node_client import BackupNodeManager
    from plexichat.app.logger_config import get_logger
    from plexichat.core.config import settings
except ImportError:
    # Fallback imports
    BackupNodeServer = None
    BackupNodeConfig = None
    BackupNodeManager = None
    get_logger = logging.getLogger
    settings = {}

logger = get_logger(__name__)

class BackupNodeMain:
    """Main backup node application."""

    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path
        self.config = self._load_config()
        self.server: Optional[BackupNodeServer] = None
        self.manager: Optional[BackupNodeManager] = None
        self.running = False

        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file or create default."""
        default_config = {
            "node_id": f"backup_node_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "storage_path": "./backup_storage",
            "max_storage_gb": 100,
            "port": 8001,
            "main_node_address": "localhost",
            "main_node_port": 8000,
            "auto_cleanup_enabled": True,
            "verification_interval_hours": 6,
            "seeding_enabled": True,
            "max_concurrent_transfers": 20,
            "bandwidth_limit_mbps": None,
            "cluster_enabled": True,
            "heartbeat_interval": 30,
            "node_timeout": 90,
            "replication_factor": 3,
            "encryption_enabled": True,
            "quantum_resistant": True,
            "geographic_location": "unknown"
        }

        # Prefer config in ./data/backup_nodes/ or user home
        config_dir = os.path.join(os.getcwd(), 'data', 'backup_nodes')
        os.makedirs(config_dir, exist_ok=True)
        default_config_path = os.path.join(config_dir, 'config.json')
        config_path = self.config_path or default_config_path

        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Failed to load backup node config: {e}")
                return default_config
        else:
            try:
                with open(config_path, 'w') as f:
                    json.dump(default_config, f, indent=2)
                logger.info(f"Generated default backup node config at {config_path}")
            except Exception as e:
                logger.error(f"Failed to write default backup node config: {e}")
            return default_config

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        logger.info(f"Received signal {signum}, initiating shutdown...")
        self.running = False

    async def start(self) -> bool:
        """Start the backup node."""
        try:
            logger.info("🚀 Starting PlexiChat Backup Node")
            logger.info(f"Node ID: {self.config['node_id']}")
            logger.info(f"Storage Path: {self.config['storage_path']}")
            logger.info(f"Max Storage: {self.config['max_storage_gb']} GB")
            logger.info(f"Port: {self.config['port']}")

            # Create backup node configuration
            if BackupNodeConfig:
                node_config = BackupNodeConfig(**self.config)

                # Create and start server
                self.server = BackupNodeServer(node_config)

                # Start background tasks
                asyncio.create_task(self._health_monitor())
                asyncio.create_task(self._cleanup_task())
                asyncio.create_task(self._verification_task())

                self.running = True

                # Start the server
                await self.server.start()

            else:
                logger.error("BackupNodeServer not available")
                return False

            return True

        except Exception as e:
            logger.error(f"Error starting backup node: {e}")
            return False

    async def stop(self) -> bool:
        """Stop the backup node."""
        try:
            logger.info("🛑 Stopping PlexiChat Backup Node")

            self.running = False

            if self.server:
                await self.server.stop()

            if self.manager:
                await self.manager.close_all()

            logger.info("✅ Backup node stopped successfully")
            return True

        except Exception as e:
            logger.error(f"Error stopping backup node: {e}")
            return False

    async def status(self) -> Dict[str, Any]:
        """Get backup node status."""
        try:
            status_info = {
                "node_id": self.config["node_id"],
                "running": self.running,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "config": self.config
            }

            if self.server:
                # Get server status
                server_status = await self.server.get_status()
                status_info.update(server_status)

            return status_info

        except Exception as e:
            logger.error(f"Error getting status: {e}")
            return {"error": str(e)}

    async def _health_monitor(self):
        """Background health monitoring task."""
        while self.running:
            try:
                if self.server:
                    # Perform health checks
                    health_status = await self.server.health_check()

                    if not health_status.get("healthy", False):
                        logger.warning("Health check failed")
                        # Could trigger alerts or recovery actions

                await asyncio.sleep(self.config.get("heartbeat_interval", 30))

            except Exception as e:
                logger.error(f"Error in health monitor: {e}")
                await asyncio.sleep(60)  # Wait longer on error

    async def _cleanup_task(self):
        """Background cleanup task."""
        while self.running:
            try:
                if self.server and self.config.get("auto_cleanup_enabled", True):
                    await self.server.cleanup_old_shards()

                # Run cleanup every hour
                await asyncio.sleep(3600)

            except Exception as e:
                logger.error(f"Error in cleanup task: {e}")
                await asyncio.sleep(3600)

    async def _verification_task(self):
        """Background verification task."""
        while self.running:
            try:
                if self.server:
                    await self.server.verify_all_shards()

                # Run verification based on config interval
                interval_hours = self.config.get("verification_interval_hours", 6)
                await asyncio.sleep(interval_hours * 3600)

            except Exception as e:
                logger.error(f"Error in verification task: {e}")
                await asyncio.sleep(3600)

async def main():
    """Main entry point."""
    parser = argparse.ArgumentParser()
    parser.description = "PlexiChat Backup Node"
    parser.formatter_class = argparse.RawDescriptionHelpFormatter
    parser.epilog = """
Examples:
  python backup_node_main.py start                    # Start with default config
  python backup_node_main.py start --config config.json  # Start with custom config
  python backup_node_main.py status                   # Check status
  python backup_node_main.py stop                     # Stop the node
    """

    parser.add_argument("command", choices=["start", "stop", "status", "restart"], help="Command to execute")

    parser.add_argument("--config", "-c", help="Configuration file path")

    parser.add_argument("--port", "-p", type=int, help="Override port number")

    parser.add_argument("--storage-path", "-s", help="Override storage path")

    parser.add_argument("--max-storage-gb", "-m", type=int, help="Override maximum storage in GB")

    parser.add_argument("--node-id", "-n", help="Override node ID")

    parser.add_argument("--daemon", "-d", action="store_true", help="Run as daemon (background process)")

    args = parser.parse_args()

    # Create backup node instance
    backup_node = BackupNodeMain(args.config)

    # Apply command line overrides
    if args.port:
        backup_node.config["port"] = args.port
    if args.storage_path:
        backup_node.config["storage_path"] = args.storage_path
    if args.max_storage_gb:
        backup_node.config["max_storage_gb"] = args.max_storage_gb
    if args.node_id:
        backup_node.config["node_id"] = args.node_id

    try:
        if args.command == "start":
            logger.info("Starting backup node...")
            success = await backup_node.start()
            if not success:
                sys.exit(1)

        elif args.command == "stop":
            logger.info("Stopping backup node...")
            success = await backup_node.stop()
            if not success:
                sys.exit(1)

        elif args.command == "status":
            status = await backup_node.status()
            print(json.dumps(status, indent=2))

        elif args.command == "restart":
            logger.info("Restarting backup node...")
            await backup_node.stop()
            await asyncio.sleep(2)
            success = await backup_node.start()
            if not success:
                sys.exit(1)

    except KeyboardInterrupt:
        logger.info("Received interrupt signal")
        await backup_node.stop()
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nShutdown complete.")
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)
