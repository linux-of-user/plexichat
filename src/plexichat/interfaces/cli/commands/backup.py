#!/usr/bin/env python3
"""
PlexiChat Backup CLI Commands

Command-line interface for backup management and operations.
"""

import asyncio
import click
import json
import sys
from pathlib import Path
from typing import Optional

try:
    from plexichat.features.backup.core.backup_manager import backup_manager
    from plexichat.features.backup.nodes.backup_node_client import BackupNodeManager
    from plexichat.features.backup.nodes.backup_node_main import BackupNodeMain
    from plexichat.app.logger_config import get_logger
except ImportError:
    backup_manager = None
    BackupNodeManager = None
    BackupNodeMain = None
    get_logger = lambda name: print

logger = get_logger(__name__)

@click.group()
def backup():
    """PlexiChat Backup Management Commands."""
    pass

@backup.command()
@click.option('--output-dir', '-o', default='./backups', help='Backup output directory')
@click.option('--include-files', '-f', is_flag=True, help='Include uploaded files in backup')
@click.option('--include-logs', '-l', is_flag=True, help='Include log files in backup')
@click.option('--compress', '-c', is_flag=True, help='Compress backup files')
def create(output_dir: str, include_files: bool, include_logs: bool, compress: bool):
    """Create a full system backup."""
    try:
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        click.echo(f"🔄 Creating backup in {output_path}...")
        
        if backup_manager:
            result = asyncio.run(backup_manager.create_full_backup(
                output_dir=output_path,
                include_files=include_files,
                include_logs=include_logs,
                compress=compress
            ))
            
            if result.success:
                click.echo(f"✅ Backup created successfully!")
                click.echo(f"📁 Location: {result.backup_path}")
                click.echo(f"📊 Size: {result.backup_size}")
                click.echo(f"⏱️  Duration: {result.duration}s")
            else:
                click.echo(f"❌ Backup failed: {result.error}")
                sys.exit(1)
        else:
            click.echo("❌ Backup manager not available")
            sys.exit(1)
            
    except Exception as e:
        click.echo(f"❌ Error creating backup: {e}")
        sys.exit(1)

@backup.command()
@click.argument('backup_path')
@click.option('--target-dir', '-t', default='./', help='Restore target directory')
@click.option('--force', '-f', is_flag=True, help='Force restore without confirmation')
def restore(backup_path: str, target_dir: str, force: bool):
    """Restore from backup."""
    try:
        backup_file = Path(backup_path)
        if not backup_file.exists():
            click.echo(f"❌ Backup file not found: {backup_path}")
            sys.exit(1)
        
        target_path = Path(target_dir)
        
        if not force:
            if not click.confirm(f"Restore backup to {target_path}? This may overwrite existing data."):
                click.echo("Operation cancelled")
                return
        
        click.echo(f"🔄 Restoring backup from {backup_file}...")
        
        if backup_manager:
            result = asyncio.run(backup_manager.restore_backup(
                backup_path=backup_file,
                target_dir=target_path
            ))
            
            if result.success:
                click.echo(f"✅ Backup restored successfully!")
                click.echo(f"📁 Restored to: {target_path}")
                click.echo(f"⏱️  Duration: {result.duration}s")
            else:
                click.echo(f"❌ Restore failed: {result.error}")
                sys.exit(1)
        else:
            click.echo("❌ Backup manager not available")
            sys.exit(1)
            
    except Exception as e:
        click.echo(f"❌ Error restoring backup: {e}")
        sys.exit(1)

@backup.command()
@click.option('--limit', '-l', default=10, help='Number of backups to list')
def list(limit: int):
    """List available backups."""
    try:
        if backup_manager:
            backups = asyncio.run(backup_manager.list_backups(limit=limit))
            
            if backups:
                click.echo("Available Backups:")
                click.echo("=" * 50)
                for backup in backups:
                    click.echo(f"📁 {backup['name']}")
                    click.echo(f"   📅 Created: {backup['created_at']}")
                    click.echo(f"   📊 Size: {backup['size']}")
                    click.echo(f"   📍 Path: {backup['path']}")
                    click.echo()
            else:
                click.echo("No backups found")
        else:
            click.echo("❌ Backup manager not available")
            
    except Exception as e:
        click.echo(f"❌ Error listing backups: {e}")

@backup.command()
@click.argument('backup_name')
@click.option('--confirm', '-c', is_flag=True, help='Confirm deletion without prompt')
def delete(backup_name: str, confirm: bool):
    """Delete a backup."""
    try:
        if not confirm:
            if not click.confirm(f"Are you sure you want to delete backup '{backup_name}'?"):
                click.echo("Operation cancelled")
                return
        
        if backup_manager:
            result = asyncio.run(backup_manager.delete_backup(backup_name))
            
            if result.success:
                click.echo(f"✅ Backup '{backup_name}' deleted successfully!")
            else:
                click.echo(f"❌ Failed to delete backup: {result.error}")
                sys.exit(1)
        else:
            click.echo("❌ Backup manager not available")
            sys.exit(1)
            
    except Exception as e:
        click.echo(f"❌ Error deleting backup: {e}")
        sys.exit(1)

@backup.command()
def status():
    """Show backup system status."""
    try:
        click.echo("Backup System Status")
        click.echo("=" * 30)
        
        if backup_manager:
            status_info = asyncio.run(backup_manager.get_status())
            
            click.echo(f"✅ Backup Manager: Online")
            click.echo(f"📊 Total Backups: {status_info.get('total_backups', 0)}")
            click.echo(f"💾 Storage Used: {status_info.get('storage_used', 'Unknown')}")
            click.echo(f"🕐 Last Backup: {status_info.get('last_backup', 'Never')}")
            click.echo(f"⚙️  Auto Backup: {'Enabled' if status_info.get('auto_backup_enabled') else 'Disabled'}")
        else:
            click.echo("❌ Backup Manager: Offline")
        
        # Check backup nodes
        try:
            if BackupNodeManager:
                node_manager = BackupNodeManager()
                nodes = asyncio.run(node_manager.get_available_nodes())
                click.echo(f"🌐 Backup Nodes: {len(nodes)} available")
            else:
                click.echo("🌐 Backup Nodes: Not available")
        except Exception:
            click.echo("🌐 Backup Nodes: Error checking status")
            
    except Exception as e:
        click.echo(f"❌ Error getting backup status: {e}")

@backup.command()
@click.option('--port', '-p', default=8001, help='Backup node port')
@click.option('--storage-path', '-s', default='./backup_storage', help='Storage directory')
@click.option('--max-storage-gb', '-m', default=100, help='Maximum storage in GB')
def start_node(port: int, storage_path: str, max_storage_gb: int):
    """Start a backup node."""
    try:
        click.echo(f"🚀 Starting backup node on port {port}...")
        
        if BackupNodeMain:
            config = {
                "port": port,
                "storage_path": storage_path,
                "max_storage_gb": max_storage_gb
            }
            
            node = BackupNodeMain()
            node.config.update(config)
            
            asyncio.run(node.start())
        else:
            click.echo("❌ Backup node not available")
            sys.exit(1)
            
    except KeyboardInterrupt:
        click.echo("\n🛑 Backup node stopped by user")
    except Exception as e:
        click.echo(f"❌ Error starting backup node: {e}")
        sys.exit(1)

@backup.command()
@click.option('--schedule', '-s', help='Backup schedule (cron format)')
@click.option('--enable/--disable', default=True, help='Enable or disable auto backup')
def auto(schedule: Optional[str], enable: bool):
    """Configure automatic backups."""
    try:
        if backup_manager:
            if enable:
                result = asyncio.run(backup_manager.enable_auto_backup(schedule=schedule))
                if result.success:
                    click.echo("✅ Automatic backups enabled")
                    if schedule:
                        click.echo(f"📅 Schedule: {schedule}")
                else:
                    click.echo(f"❌ Failed to enable auto backup: {result.error}")
            else:
                result = asyncio.run(backup_manager.disable_auto_backup())
                if result.success:
                    click.echo("✅ Automatic backups disabled")
                else:
                    click.echo(f"❌ Failed to disable auto backup: {result.error}")
        else:
            click.echo("❌ Backup manager not available")
            
    except Exception as e:
        click.echo(f"❌ Error configuring auto backup: {e}")

@backup.command()
@click.argument('backup_path')
def verify(backup_path: str):
    """Verify backup integrity."""
    try:
        backup_file = Path(backup_path)
        if not backup_file.exists():
            click.echo(f"❌ Backup file not found: {backup_path}")
            sys.exit(1)
        
        click.echo(f"🔍 Verifying backup: {backup_file}")
        
        if backup_manager:
            result = asyncio.run(backup_manager.verify_backup(backup_file))
            
            if result.valid:
                click.echo("✅ Backup verification successful!")
                click.echo(f"📊 Files verified: {result.files_verified}")
                click.echo(f"🔐 Checksum: Valid")
            else:
                click.echo("❌ Backup verification failed!")
                click.echo(f"🚨 Issues found: {len(result.issues)}")
                for issue in result.issues:
                    click.echo(f"   • {issue}")
                sys.exit(1)
        else:
            click.echo("❌ Backup manager not available")
            sys.exit(1)
            
    except Exception as e:
        click.echo(f"❌ Error verifying backup: {e}")
        sys.exit(1)

@backup.command()
@click.option('--output', '-o', help='Output file for backup report')
def report(output: Optional[str]):
    """Generate backup report."""
    try:
        if backup_manager:
            report_data = asyncio.run(backup_manager.generate_report())
            
            if output:
                output_file = Path(output)
                with open(output_file, 'w') as f:
                    json.dump(report_data, f, indent=2)
                click.echo(f"📄 Report saved to: {output_file}")
            else:
                click.echo("Backup System Report")
                click.echo("=" * 40)
                click.echo(json.dumps(report_data, indent=2))
        else:
            click.echo("❌ Backup manager not available")
            
    except Exception as e:
        click.echo(f"❌ Error generating report: {e}")

if __name__ == '__main__':
    backup()
