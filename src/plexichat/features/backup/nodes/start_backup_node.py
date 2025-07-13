#!/usr/bin/env python3
"""
PlexiChat Backup Node Startup Script
Provides easy startup and management for the backup node.
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


def check_dependencies():
    """Check if required dependencies are installed."""
    required_packages = [
        'fastapi',
        'uvicorn',
        'httpx',
        'aiofiles'
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print("❌ Missing required dependencies:")
        for package in missing_packages:
            print(f"   - {package}")
        print("\nInstall with: pip install -r requirements.txt")
        print("(All dependencies are now consolidated in the root requirements.txt)")
        return False
    
    return True


def create_directories():
    """Create necessary directories."""
    directories = [
        "backup_node/storage",
        "backup_node/logs",
        "backup_node/temp"
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"📁 Created directory: {directory}")


def setup_config(args):
    """Setup configuration based on arguments."""
    config_file = Path("config/backup_node.json")

    if config_file.exists() and not args.force_config:
        print(f"⚙️ Using existing config: {config_file}")
        return

    # Ensure config directory exists
    config_file.parent.mkdir(exist_ok=True)

    config = {
        "node_id": args.node_id or f"backup_node_{os.urandom(4).hex()}",
        "storage_path": args.storage_path or "backups/node_storage",
        "max_storage_gb": args.max_storage or 100,
        "port": args.port or 8001,
        "main_node_address": args.main_address,
        "main_node_port": args.main_port,
        "auto_cleanup_enabled": True,
        "verification_interval_hours": 24,
        "seeding_enabled": True,
        "max_concurrent_transfers": 10,
        "bandwidth_limit_mbps": args.bandwidth_limit
    }
    
    with open(config_file, 'w') as f:
        json.dump(config, f, indent=2)
    
    print(f"⚙️ Created config file: {config_file}")
    print(f"🆔 Node ID: {config['node_id']}")
    print(f"💾 Storage Limit: {config['max_storage_gb']} GB")
    print(f"🌐 Port: {config['port']}")


def start_backup_node(args):
    """Start the backup node."""
    print("🚀 Starting PlexiChat Backup Node...")
    
    # Check dependencies
    if not check_dependencies():
        sys.exit(1)
    
    # Create directories
    create_directories()
    
    # Setup configuration
    setup_config(args)
    
    # Start the backup node
    try:
        if args.dev_mode:
            # Development mode with auto-reload
            cmd = [
                sys.executable, "-m", "uvicorn",
                "src.plexichat.backup.core.backup_node_server:app",
                "--host", "0.0.0.0",
                "--port", str(args.port or 8001),
                "--reload",
                "--log-level", "debug"
            ]
        else:
            # Production mode - use consolidated backup system
            cmd = [
                sys.executable, "-c",
                "from src.plexichat.backup.core.backup_node_server import BackupNodeServer; import asyncio; asyncio.run(BackupNodeServer().start())"
            ]
        
        print(f"🔧 Running command: {' '.join(cmd)}")
        subprocess.run(cmd, check=True)
        
    except KeyboardInterrupt:
        print("\n🛑 Backup node stopped by user")
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to start backup node: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        sys.exit(1)


def show_status():
    """Show backup node status."""
    import httpx
    
    try:
        # Try to connect to backup node
        response = httpx.get("http://localhost:8001/health", timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            print("✅ Backup Node Status: RUNNING")
            print(f"🆔 Node ID: {data.get('node_status', {}).get('node_id', 'Unknown')}")
            
            storage = data.get('node_status', {}).get('storage', {})
            if storage:
                used_gb = storage.get('used_bytes', 0) / (1024**3)
                max_gb = storage.get('max_bytes', 0) / (1024**3)
                usage_pct = storage.get('used_percentage', 0)
                
                print(f"💾 Storage: {used_gb:.2f} GB / {max_gb:.2f} GB ({usage_pct:.1f}%)")
            
            shards = data.get('node_status', {}).get('shards', {})
            if shards:
                print(f"📦 Shards: {shards.get('total_count', 0)}")
            
            network = data.get('node_status', {}).get('network', {})
            if network:
                print(f"🌐 Connected Nodes: {network.get('connected_nodes', 0)}")
        else:
            print("❌ Backup Node Status: ERROR")
            print(f"HTTP {response.status_code}: {response.text}")
            
    except httpx.ConnectError:
        print("❌ Backup Node Status: OFFLINE")
        print("The backup node is not running or not accessible")
    except Exception as e:
        print(f"❌ Failed to check status: {e}")


def stop_backup_node():
    """Stop the backup node."""
    print("🛑 Stopping backup node...")
    
    try:
        # Try to find and kill the process
        import psutil
        
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                cmdline = proc.info['cmdline']
                if cmdline and 'backup_node_main.py' in ' '.join(cmdline):
                    proc.terminate()
                    print(f"🛑 Terminated backup node process (PID: {proc.info['pid']})")
                    return
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        print("⚠️ No backup node process found")
        
    except ImportError:
        print("⚠️ psutil not available, cannot stop process automatically")
        print("Please stop the backup node manually (Ctrl+C)")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="PlexiChat Backup Node Management",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python start_backup_node.py start                    # Start with default settings
  python start_backup_node.py start --port 8002        # Start on custom port
  python start_backup_node.py start --max-storage 200  # Set storage limit to 200GB
  python start_backup_node.py status                   # Check node status
  python start_backup_node.py stop                     # Stop the node
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Start command
    start_parser = subparsers.add_parser('start', help='Start the backup node')
    start_parser.add_argument('--node-id', help='Custom node ID')
    start_parser.add_argument('--port', type=int, help='Port to listen on (default: 8001)')
    start_parser.add_argument('--storage-path', help='Storage directory path')
    start_parser.add_argument('--max-storage', type=int, help='Maximum storage in GB (default: 100)')
    start_parser.add_argument('--main-address', help='Main node address')
    start_parser.add_argument('--main-port', type=int, help='Main node port')
    start_parser.add_argument('--bandwidth-limit', type=int, help='Bandwidth limit in Mbps')
    start_parser.add_argument('--dev-mode', action='store_true', help='Enable development mode')
    start_parser.add_argument('--force-config', action='store_true', help='Force recreate config file')
    
    # Status command
    subparsers.add_parser('status', help='Show backup node status')
    
    # Stop command
    subparsers.add_parser('stop', help='Stop the backup node')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    print("🔧 PlexiChat Backup Node Manager")
    print("=" * 40)
    
    if args.command == 'start':
        start_backup_node(args)
    elif args.command == 'status':
        show_status()
    elif args.command == 'stop':
        stop_backup_node()


if __name__ == "__main__":
    main()
