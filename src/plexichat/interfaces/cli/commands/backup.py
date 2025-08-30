import asyncio
import click
import sys
import json
import logging
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone, timedelta

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# Try to import the advanced BackupManager if available.
try:
    from plexichat.features.backup.backup_manager import (
        BackupManager as RealBackupManager,
        BackupStrategy as RealBackupStrategy,
        BackupType as RealBackupType,
        RecoveryMode as RealRecoveryMode,
    )
except Exception:
    RealBackupManager = None
    RealBackupStrategy = None
    RealBackupType = None
    RealRecoveryMode = None


# Lightweight fallback manager used when the real BackupManager isn't available.
class SimpleFileBackupManager:
    """
    Simple synchronous fallback backup manager for CLI use when the real
    backup subsystem is not available. This manager creates placeholder
    backup files and stores simple JSON metadata alongside them.
    """

    def __init__(self, storage_dir: Path = Path("./backups")):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.metadata_dir = self.storage_dir / "metadata"
        self.metadata_dir.mkdir(parents=True, exist_ok=True)

    async def create_backup(self,
                            data: Any,
                            backup_type: str = "full",
                            user_id: Optional[str] = None,
                            data_source: Optional[str] = None,
                            tags: Optional[List[str]] = None,
                            retention_days: Optional[int] = 90,
                            metadata: Optional[Dict[str, Any]] = None,
                            output_dir: Optional[Path] = None) -> Dict[str, Any]:
        ts = int(datetime.now(timezone.utc).timestamp() * 1000)
        backup_id = f"backup_{ts}"
        output_dir = Path(output_dir) if output_dir else self.storage_dir
        output_dir.mkdir(parents=True, exist_ok=True)
        backup_filename = output_dir / f"{backup_id}.bin"
        # Write a simple placeholder representation
        if isinstance(data, (dict, list)):
            payload = json.dumps(data).encode("utf-8")
        elif isinstance(data, str):
            payload = data.encode("utf-8")
        elif isinstance(data, bytes):
            payload = data
        else:
            payload = str(data).encode("utf-8")

        backup_filename.write_bytes(payload)

        meta = {
            "backup_id": backup_id,
            "name": backup_filename.name,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "backup_type": backup_type,
            "user_id": user_id,
            "data_source": data_source,
            "size": len(payload),
            "retention_days": retention_days or 90,
            "tags": tags or [],
            "metadata": metadata or {},
        }
        meta_path = self.metadata_dir / f"{backup_id}.json"
        meta_path.write_text(json.dumps(meta, default=str))
        return meta

    async def create_incremental_backup(self, *args, **kwargs):
        # For the simple manager, incremental behaves like a full backup.
        return await self.create_backup(*args, **kwargs)

    async def list_backups(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        metas = []
        for p in sorted(self.metadata_dir.glob("backup_*.json"), reverse=True):
            try:
                metas.append(json.loads(p.read_text()))
            except Exception:
                continue
        return metas[offset: offset + limit]

    async def delete_backup(self, backup_id: str) -> Dict[str, Any]:
        meta_path = self.metadata_dir / f"{backup_id}.json"
        data_path = self.storage_dir / f"{backup_id}.bin"
        deleted = False
        if meta_path.exists():
            meta_path.unlink()
            deleted = True
        if data_path.exists():
            data_path.unlink()
            deleted = True
        return {"success": deleted}

    async def restore_backup(self, backup_id: str, target_dir: Optional[Path] = None, dry_run: bool = False) -> Dict[str, Any]:
        meta_path = self.metadata_dir / f"{backup_id}.json"
        data_path = self.storage_dir / f"{backup_id}.bin"
        if not meta_path.exists() or not data_path.exists():
            return {"success": False, "error": "backup_not_found"}
        if dry_run:
            return {"success": True, "restored_bytes": 0, "dry_run": True}
        target_dir = Path(target_dir) if target_dir else Path(".")
        target_dir.mkdir(parents=True, exist_ok=True)
        # Write the data out as-is
        out_path = target_dir / f"restored_{backup_id}.bin"
        out_path.write_bytes(data_path.read_bytes())
        return {"success": True, "restored_path": str(out_path)}

    async def verify_backup(self, backup_id: str, deep_verify: bool = False) -> Dict[str, Any]:
        meta_path = self.metadata_dir / f"{backup_id}.json"
        data_path = self.storage_dir / f"{backup_id}.bin"
        if not meta_path.exists() or not data_path.exists():
            return {"status": "failed", "issues": ["missing_files"]}
        # Simple verification: check size > 0
        size = data_path.stat().st_size
        status = "passed" if size > 0 else "failed"
        return {"status": status, "size": size, "deep_verify": deep_verify}

    async def create_backup_schedule(self, *args, **kwargs):
        # Scheduling is not supported in the simple manager.
        raise NotImplementedError("scheduling not supported in fallback manager")

    async def get_backup_statistics(self) -> Dict[str, Any]:
        backups = await self.list_backups(limit=1000)
        total = len(backups)
        total_size = sum(b.get("size", 0) for b in backups)
        return {
            "total_backups": total,
            "total_size": total_size,
            "stored_on": str(self.storage_dir),
        }


# Instantiate the best available manager
if RealBackupManager:
    try:
        backup_manager = RealBackupManager()
        USING_REAL_MANAGER = True
    except Exception:
        logger.exception("Failed to initialize real BackupManager, falling back to simple manager.")
        backup_manager = SimpleFileBackupManager()
        USING_REAL_MANAGER = False
else:
    backup_manager = SimpleFileBackupManager()
    USING_REAL_MANAGER = False


# Helper to run async functions from click commands
def run_async(coro):
    try:
        return asyncio.run(coro)
    except RuntimeError:
        # If an event loop is already running (rare in CLI), create new loop
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()


def format_backup(meta: Dict[str, Any]) -> str:
    created = meta.get("created_at", "")
    btype = meta.get("backup_type", "unknown")
    size = meta.get("size", 0)
    name = meta.get("name", meta.get("backup_id", "unknown"))
    data_source = meta.get("data_source", "")
    retention = meta.get("retention_days", "")
    return f"{name} | id={meta.get('backup_id')} | type={btype} | size={size} | created={created} | source={data_source} | retention_days={retention}"


@click.group()
def backup():
    """PlexiChat Backup Management Commands."""
    pass


@backup.command()
@click.option('--output-dir', '-o', default='./backups', help='Backup output directory.')
@click.option('--type', '-t', 'backup_type', type=click.Choice(['full', 'incremental', 'differential']), default='full', help='Backup type to create.')
@click.option('--data-source', '-s', 'data_source', default=None, help='Logical data source identifier (required for incremental/differential).')
@click.option('--user-id', '-u', 'user_id', default=None, help='User id associated with backup.')
@click.option('--tags', '-g', multiple=True, help='Tags to attach to backup.')
@click.option('--retention-days', '-r', default=90, type=int, help='Retention period in days.')
@click.option('--metadata', '-m', default=None, help='Additional JSON metadata.')
def create(output_dir: str, backup_type: str, data_source: Optional[str], user_id: Optional[str], tags: List[str], retention_days: int, metadata: Optional[str]):
    """Create a backup (full / incremental / differential)."""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    # Prepare metadata payload
    try:
        meta_obj = json.loads(metadata) if metadata else {}
    except Exception:
        click.echo("Invalid JSON provided for --metadata", err=True)
        sys.exit(2)

    click.echo(f"Creating {backup_type} backup...")

    # Dispatch to the appropriate async method depending on manager capabilities
    if USING_REAL_MANAGER:
        # Map names to real enums if available
        try:
            btype_enum = getattr(RealBackupType, backup_type.upper()) if RealBackupType else backup_type
        except Exception:
            btype_enum = backup_type

        # SecurityLevel is optional in newer manager; use defaults
        try:
            result = run_async(
                backup_manager.create_backup(
                    data={"generated_by": "cli", "timestamp": datetime.now(timezone.utc).isoformat()},
                    backup_strategy=(RealBackupStrategy.SCHEDULED if RealBackupStrategy else None),
                    backup_type=btype_enum,
                    security_level=None,
                    user_id=user_id,
                    data_source=data_source,
                    tags=list(tags),
                    retention_days=retention_days,
                    metadata=meta_obj
                )
            )
        except Exception as e:
            click.echo(f"Backup creation failed: {e}", err=True)
            logger.exception("create backup failed")
            sys.exit(1)
    else:
        # Fallback simple manager
        try:
            result = run_async(
                backup_manager.create_backup(
                    data={"generated_by": "cli", "timestamp": datetime.now(timezone.utc).isoformat()},
                    backup_type=backup_type,
                    user_id=user_id,
                    data_source=data_source,
                    tags=list(tags),
                    retention_days=retention_days,
                    metadata=meta_obj,
                    output_dir=output_path
                )
            )
        except Exception as e:
            click.echo(f"Backup creation failed: {e}", err=True)
            logger.exception("create backup failed (fallback)")
            sys.exit(1)

    click.echo(f"Backup created: {result.get('backup_id', result.get('backup_path', 'unknown'))}")


@backup.command()
@click.argument('backup_id', required=False)
@click.option('--target-dir', '-t', default='.', help='Directory to restore backup into.')
@click.option('--dry-run', is_flag=True, default=False, help='Simulate the restore without writing data.')
def restore(backup_id: Optional[str], target_dir: str, dry_run: bool):
    """Restore a backup. If BACKUP_ID is omitted and manager supports recovery plans, a recovery plan will be used."""
    try:
        if USING_REAL_MANAGER:
            # If backup_id given, use direct restore via engine if available
            if backup_id:
                # Try to call restore directly
                engine_restore = getattr(backup_manager, "backup_engine", None)
                if engine_restore and hasattr(engine_restore, "restore_backup"):
                    result = run_async(engine_restore.restore_backup(backup_id=backup_id, target_dir=Path(target_dir), dry_run=dry_run))
                    if result.get("success"):
                        click.echo(f"Restore completed. Target: {result.get('restored_path', target_dir)}")
                    else:
                        click.echo(f"Restore failed: {result}", err=True)
                        sys.exit(1)
                else:
                    # Use create_recovery_plan + execute_recovery to restore specific backup
                    plan_id = run_async(backup_manager.create_recovery_plan(
                        name=f"cli-temp-restore-{int(datetime.now().timestamp())}",
                        recovery_mode=(RealRecoveryMode.FULL_RESTORE if RealRecoveryMode else None),
                        backup_sources=[backup_id],
                        target_location=str(target_dir),
                        estimated_time=60
                    ))
                    result = run_async(backup_manager.execute_recovery(plan_id=plan_id, backup_id=backup_id, dry_run=dry_run))
                    if result.get("status") == "success":
                        click.echo(f"Restore completed via recovery plan. Details: {result}")
                    else:
                        click.echo(f"Restore failed: {result}", err=True)
                        sys.exit(1)
            else:
                # No backup id: attempt to run a recovery plan that selects the latest backup
                # Create minimal plan and execute
                plan_id = run_async(backup_manager.create_recovery_plan(
                    name=f"cli-temp-restore-latest-{int(datetime.now().timestamp())}",
                    recovery_mode=(RealRecoveryMode.FULL_RESTORE if RealRecoveryMode else None),
                    backup_sources=[],  # allow manager to find latest
                    target_location=str(target_dir),
                    estimated_time=60
                ))
                result = run_async(backup_manager.execute_recovery(plan_id=plan_id, dry_run=dry_run))
                if result.get("status") == "success":
                    click.echo(f"Restore completed via recovery plan. Details: {result}")
                else:
                    click.echo(f"Restore failed: {result}", err=True)
                    sys.exit(1)
        else:
            # Simple fallback restore requires backup_id
            if not backup_id:
                click.echo("Backup ID is required for restore when using the fallback manager.", err=True)
                sys.exit(2)
            result = run_async(backup_manager.restore_backup(backup_id=backup_id, target_dir=Path(target_dir), dry_run=dry_run))
            if result.get("success"):
                click.echo(f"Restore completed. Restored to: {result.get('restored_path', target_dir)}")
            else:
                click.echo(f"Restore failed: {result}", err=True)
                sys.exit(1)

    except Exception as e:
        logger.exception("restore failed")
        click.echo(f"Restore failed: {e}", err=True)
        sys.exit(1)


@backup.command(name="list")
@click.option('--limit', '-l', default=100, help='Maximum number of backups to list.')
@click.option('--offset', default=0, help='Offset into result set.')
@click.option('--data-source', '-s', default=None, help='Filter by data source.')
def list_backups(limit: int, offset: int, data_source: Optional[str]):
    """List available backups."""
    try:
        results = run_async(backup_manager.list_backups(limit=limit, offset=offset))
    except Exception as e:
        logger.exception("list_backups failed")
        click.echo(f"Failed to list backups: {e}", err=True)
        sys.exit(1)

    filtered = []
    for b in results:
        if data_source:
            if b.get("data_source") != data_source:
                continue
        filtered.append(b)

    if not filtered:
        click.echo("No backups found.")
        return

    for b in filtered:
        click.echo(format_backup(b))


@backup.command()
@click.argument('backup_id')
def verify(backup_id: str):
    """Verify backup integrity (lightweight by default)."""
    try:
        if USING_REAL_MANAGER:
            result = run_async(backup_manager.verify_backup(backup_id, deep_verify=False))
        else:
            result = run_async(backup_manager.verify_backup(backup_id, deep_verify=False))
        click.echo(f"Verification result for {backup_id}: {result.get('status')}")
        if result.get("issues"):
            click.echo("Issues:")
            for issue in result.get("issues", []):
                click.echo(f"- {issue}")
    except Exception as e:
        logger.exception("verify failed")
        click.echo(f"Verification failed: {e}", err=True)
        sys.exit(1)


@backup.command()
@click.option('--name', '-n', required=True, help='Name of the schedule.')
@click.option('--cron', '-c', required=True, help='Cron expression for schedule (simple parser expected by manager).')
@click.option('--data-sources', '-s', multiple=True, required=True, help='One or more data source identifiers to back up.')
@click.option('--backup-type', '-t', type=click.Choice(['full', 'incremental', 'differential']), default='incremental', help='Type of backups to create for schedule.')
@click.option('--retention-days', '-r', default=90, help='Retention period for scheduled backups.')
def schedule(name: str, cron: str, data_sources: List[str], backup_type: str, retention_days: int):
    """Create an automated backup schedule."""
    if not USING_REAL_MANAGER:
        click.echo("Automated scheduling is only available when the full backup subsystem is present.", err=True)
        sys.exit(2)

    try:
        # Map backup_type to real enum if available
        try:
            btype_enum = getattr(RealBackupType, backup_type.upper()) if RealBackupType else backup_type
        except Exception:
            btype_enum = backup_type

        schedule_id = run_async(backup_manager.create_backup_schedule(
            name=name,
            cron_expression=cron,
            data_sources=list(data_sources),
            backup_strategy=(RealBackupStrategy.SCHEDULED if RealBackupStrategy else None),
            backup_type=btype_enum,
            security_level=None,
            retention_days=retention_days,
            target_nodes=None,
            tags=[],
            metadata={"created_by": "cli"}
        ))
        click.echo(f"Schedule created: {schedule_id}")
    except NotImplementedError:
        click.echo("Scheduling is not implemented by the current backup manager.", err=True)
        sys.exit(2)
    except Exception as e:
        logger.exception("schedule creation failed")
        click.echo(f"Failed to create schedule: {e}", err=True)
        sys.exit(1)


@backup.command()
@click.option('--days', '-d', required=True, type=int, help='Delete backups older than this many days.')
@click.option('--dry-run', is_flag=True, default=False, help='Show what would be deleted without deleting.')
def prune(days: int, dry_run: bool):
    """Delete backups older than X days (retention enforcement)."""
    try:
        threshold = datetime.now(timezone.utc) - timedelta(days=days)
        backups = run_async(backup_manager.list_backups(limit=10000))
        to_delete = []
        for b in backups:
            created = b.get("created_at")
            if not created:
                continue
            try:
                created_dt = datetime.fromisoformat(created)
            except Exception:
                # If parse fails, skip
                continue
            if created_dt < threshold:
                to_delete.append(b.get("backup_id"))

        if not to_delete:
            click.echo("No backups older than threshold.")
            return

        click.echo(f"Backups to delete ({len(to_delete)}):")
        for bid in to_delete:
            click.echo(f"- {bid}")

        if dry_run:
            click.echo("Dry run enabled - no backups were deleted.")
            return

        deleted_count = 0
        for bid in to_delete:
            # Try manager-level delete
            delete_fn = getattr(backup_manager, "delete_backup", None)
            engine = getattr(backup_manager, "backup_engine", None)
            if callable(delete_fn):
                res = run_async(delete_fn(bid))
            elif engine and hasattr(engine, "delete_backup"):
                res = run_async(engine.delete_backup(bid))
            else:
                # Best-effort for fallback manager handled inside
                try:
                    res = run_async(backup_manager.delete_backup(bid))
                except Exception:
                    res = {"success": False}
            if res and res.get("success"):
                deleted_count += 1

        click.echo(f"Deleted {deleted_count} backups.")
    except Exception as e:
        logger.exception("prune failed")
        click.echo(f"Prune operation failed: {e}", err=True)
        sys.exit(1)


@backup.command()
@click.argument('backup_id')
def delete(backup_id: str):
    """Delete a specific backup."""
    if not click.confirm(f"Are you sure you want to delete backup '{backup_id}'?"):
        click.echo("Cancelled.")
        return
    try:
        delete_fn = getattr(backup_manager, "delete_backup", None)
        engine = getattr(backup_manager, "backup_engine", None)
        if callable(delete_fn):
            res = run_async(delete_fn(backup_id))
        elif engine and hasattr(engine, "delete_backup"):
            res = run_async(engine.delete_backup(backup_id))
        else:
            res = run_async(backup_manager.delete_backup(backup_id))
        if res and res.get("success"):
            click.echo(f"Backup '{backup_id}' deleted.")
        else:
            click.echo(f"Failed to delete backup '{backup_id}': {res}", err=True)
            sys.exit(1)
    except Exception as e:
        logger.exception("delete failed")
        click.echo(f"Delete failed: {e}", err=True)
        sys.exit(1)


@backup.command()
def status():
    """Show backup system status and statistics."""
    try:
        stats_fn = getattr(backup_manager, "get_backup_statistics", None)
        if callable(stats_fn):
            stats = run_async(stats_fn())
            click.echo("Backup Status:")
            for k, v in stats.items():
                click.echo(f"- {k.replace('_', ' ').title()}: {v}")
        else:
            # Provide simple status info for fallback manager
            backups = run_async(backup_manager.list_backups(limit=1000))
            click.echo(f"Backup subsystem: {'real' if USING_REAL_MANAGER else 'fallback'}")
            click.echo(f"Total backups: {len(backups)}")
    except Exception as e:
        logger.exception("status failed")
        click.echo(f"Failed to retrieve status: {e}", err=True)
        sys.exit(1)


if __name__ == '__main__':
    backup()
