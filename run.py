import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import sys
if sys.version_info < (3, 7):
    print("Warning: Python <3.7 detected; dataclasses not natively supported, using __future__ imports")
import tarfile
import urllib.request
import venv
import zipfile
from pathlib import Path
from typing import Dict, List, Tuple

VENV_DIR = Path("venv")
REQUIREMENTS_FILE = Path("requirements.txt")
GITHUB_REPO = "linux-of-user/plexichat"

def get_current_version() -> str:
    if Path("version.json").exists():
        with open(Path("version.json"), "r") as f:
            return json.load(f).get("version", "0.0.0")
    return "0.0.0"

import re

def parse_version(version_str: str) -> Tuple[str, int, int, int]:
    """Parse version string like 'b.1.1-91' into components."""
    match = re.match(r'([a-zA-Z]*)\.?(\d+)\.(\d+)-(\d+)', version_str)
    if match:
        prefix, major, minor, build = match.groups()
        return prefix, int(major), int(minor), int(build)
    return "unknown", 0, 0, 0

def compare_versions(v1: str, v2: str) -> int:
    """Compare two version strings. Returns -1, 0, or 1."""
    p1, maj1, min1, b1 = parse_version(v1)
    p2, maj2, min2, b2 = parse_version(v2)

    if p1 != p2 and (p1 in "ab" and p2 == "r"):
        return -1
    if p1 != p2 and (p2 in "ab" and p1 == "r"):
        return 1

    for a, b in [(maj1, maj2), (min1, min2), (b1, b2)]:
        if a < b:
            return -1
        elif a > b:
            return 1
    return 0

def update_version_json(new_version: str):
    """Updates the version.json file."""
    with open(Path("version.json"), "w") as f:
        json.dump({"version": new_version}, f, indent=4)
    # Use basic logging since project logger may not be available yet
    import logging
    logging.getLogger("plexichat").info(f"Updated version.json to {new_version}")

def fetch_github_releases(repo: str) -> List[Dict]:
    """Fetches release information from GitHub."""
    api_url = f"https://api.github.com/repos/{repo}/releases"
    try:
        with urllib.request.urlopen(api_url) as response:
            if response.status == 200:
                return json.loads(response.read().decode())
            else:
                import logging
                logging.getLogger("plexichat").error(f"Error fetching releases: HTTP {response.status}")
                return []
    except Exception as e:
        import logging
        logging.getLogger("plexichat").error(f"An error occurred: {e}")
        return []

def download_and_extract(url: str, dest_path: Path):
    """Downloads and extracts a tar.gz or zip file."""
    import logging
    logger = logging.getLogger("plexichat")

    dest_path.mkdir(parents=True, exist_ok=True)
    filename = Path(url.split("/")[-1])
    download_path = dest_path / filename

    logger.info(f"Downloading {url}...")
    try:
        with urllib.request.urlopen(url) as response, open(download_path, "wb") as out_file:
            shutil.copyfileobj(response, out_file)
    except Exception as e:
        logger.error(f"Failed to download {url}: {e}")
        return

    logger.info(f"Extracting {filename}...")
    if str(filename).endswith(".tar.gz"):
        with tarfile.open(download_path, "r:gz") as tar:
            tar.extractall(path=dest_path)
    elif str(filename).endswith(".zip"):
        with zipfile.ZipFile(download_path, "r") as zip_ref:
            zip_ref.extractall(path=dest_path)
    else:
        logger.error(f"Unsupported archive format: {filename}")
        return

    # Move contents from the extracted folder to the destination path
    extracted_dirs = [d for d in dest_path.iterdir() if d.is_dir() and GITHUB_REPO.split('/')[1] in d.name]
    if extracted_dirs:
        extracted_dir = extracted_dirs[0]
        for item in extracted_dir.iterdir():
            shutil.move(str(item), str(dest_path))
        extracted_dir.rmdir()

    download_path.unlink()
    logger.info("Extraction complete.")

def handle_clean(args):
    import logging
    logger = logging.getLogger("plexichat")

    logger.info("Cleaning project...")
    paths_to_clean = [
        Path.home() / ".cache" / "plexichat",
        Path(".cache"),
        Path("__pycache__"),
    ]
    for p in Path("src").rglob("__pycache__"):
        paths_to_clean.append(p)

    for path in paths_to_clean:
        if path.exists():
            print(f"Removing {path}...")
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink()

    if args.all:
        logger.warning("Performing full clean, including virtual environment...")
        if VENV_DIR.exists():
            logger.info(f"Removing virtual environment at {VENV_DIR}...")
            shutil.rmtree(VENV_DIR)

    logger.info("Clean complete.")

def handle_setup(args):
    """Installs dependencies based on requirements.txt."""
    import logging
    logger = logging.getLogger("plexichat")

    logger.info("Setting up environment...")
    if not REQUIREMENTS_FILE.exists():
        logger.error(f"{REQUIREMENTS_FILE} not found. Please run 'install' first.")
        return

    if not VENV_DIR.exists():
        logger.info("Creating virtual environment...")
        venv.create(VENV_DIR, with_pip=True)

    pip_executable = str(VENV_DIR / "bin" / "pip")
    if platform.system() == "Windows":
        pip_executable = str(VENV_DIR / "Scripts" / "pip.exe")

    # Parse requirements.txt
    with open(REQUIREMENTS_FILE, "r") as f:
        lines = f.readlines()

    sections = {
        "minimal": [],
        "full": [],
        "developer": [],
    }
    current_section = "minimal"
    for line in lines:
        line = line.strip()
        if line.startswith("# === MINIMAL INSTALLATION ==="):
            current_section = "minimal"
        elif line.startswith("# === FULL INSTALLATION ==="):
            current_section = "full"
        elif line.startswith("# === DEVELOPMENT INSTALLATION ==="):
            current_section = "developer"
        elif not line.startswith("#") and line:
            sections[current_section].append(line)

    packages = sections["minimal"]
    if args.level in ["full", "developer"]:
        packages.extend(sections["full"])
    if args.level == "developer":
        packages.extend(sections["developer"])

    logger.info(f"Installing {args.level} dependencies...")
    try:
        subprocess.check_call([pip_executable, "install"] + packages)
        logger.info("Setup complete.")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to install dependencies: {e}")

def handle_install(args):
    """Downloads the application code from GitHub."""
    logger.info("Installing PlexiChat...")
    releases = fetch_github_releases(args.repo)
    if not releases:
        return

    version = args.version
    if not version or version == "latest":
        version = releases[0]["tag_name"]

    release = next((r for r in releases if r["tag_name"] == version), None)
    if not release:
        logger.error(f"Version {version} not found.")
        return

    logger.info(f"Installing version {version}...")
    download_url = release.get("tarball_url") or release.get("zipball_url")
    if not download_url:
        logger.error("No downloadable archive found for this release.")
        return

    download_and_extract(download_url, Path("."))
    update_version_json(version)
    logger.info("Installation complete. Please run 'setup' command.")

def handle_update(args):
    """Updates the application to the latest or a specific version."""
    logger.info("Updating PlexiChat...")
    releases = fetch_github_releases(args.repo)
    if not releases:
        return

    version = args.version
    if not version or version == "latest":
        version = releases[0]["tag_name"]

    current_version = get_current_version()
    if compare_versions(current_version, version) >= 0 and not args.force:
        logger.info(f"Already at version {current_version} or newer.")
        return

    handle_install(argparse.Namespace(version=version, repo=args.repo))
    logger.info("Update complete. Please run 'setup' command if needed.")

def handle_generate_keys(args):
    """Generates and distributes the master key shares."""
    from pathlib import Path
    try:
        # Import deferred until actually needed so --help or other commands don't trigger heavy imports.
        from plexichat.core.security.key_vault import DistributedKeyManager
    except Exception as e:
        logger.error("Failed to import key vault manager. Ensure dependencies are installed.")
        logger.debug(f"Import error: {e}", exc_info=True)
        return

    vaults_dir = Path("vaults")
    num_vaults = 5
    threshold = 3

    logger.info(f"Generating master key with {num_vaults} shares and a threshold of {threshold}...")
    key_manager = DistributedKeyManager(vaults_dir, num_vaults, threshold)
    key_manager.generate_and_distribute_master_key()
    logger.info(f"Master key shares generated successfully in {vaults_dir}.")

# Ensure minimal logging is available immediately without importing project logging
import logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("plexichat")

# Logging helpers: rotation, retention, crash logs
from datetime import timedelta

_LOG_DIR = Path("logs")
_CRASH_DIR = _LOG_DIR / "crash"
_LATEST_FILE = _LOG_DIR / "latest.txt"

def _rotate_latest_log() -> None:
    try:
        _LOG_DIR.mkdir(parents=True, exist_ok=True)
        _CRASH_DIR.mkdir(parents=True, exist_ok=True)
        if _LATEST_FILE.exists():
            ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            archived = _LOG_DIR / f"{ts}.log"
            _LATEST_FILE.replace(archived)
            # Compress archived file
            try:
                import zipfile
                zip_path = _LOG_DIR / f"{ts}.zip"
                with zipfile.ZipFile(zip_path, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
                    zf.write(archived, arcname=archived.name)
                archived.unlink(missing_ok=True)
            except Exception as e:
                logger.warning(f"Could not compress archived log: {e}")
    except Exception as e:
        logger.warning(f"Log rotation encountered an issue: {e}")

_retention_thread = None
_retention_stop = None

def _start_log_retention(retention_days: int = 14) -> None:
    """Start a background thread to delete old logs (excluding crash and plugin logs)."""
    import threading
    global _retention_thread, _retention_stop
    if _retention_thread and _retention_thread.is_alive():
        return
    _retention_stop = threading.Event()

    def _retention_loop():
        try:
            while not _retention_stop.is_set():
                cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
                try:
                    for p in _LOG_DIR.iterdir():
                        try:
                            if p.is_dir():
                                # Skip plugin and crash directories
                                if p.name in ("plugins", "crash"):
                                    continue
                                # Optionally remove empty dirs
                                continue
                            # Only consider .log or .zip
                            if not (p.suffix.lower() in (".log", ".zip")):
                                continue
                            # Parse timestamp from filename like 20240101_120000.log
                            try:
                                ts_str = p.stem  # e.g., 20240101_120000
                                dt = datetime.strptime(ts_str, "%Y%m%d_%H%M%S").replace(tzinfo=timezone.utc)
                                if dt < cutoff:
                                    p.unlink(missing_ok=True)
                            except Exception:
                                # Non-archived files skipped
                                pass
                        except Exception:
                            continue
                except Exception:
                    pass
                # Sleep for a day
                _retention_stop.wait(86400)
        finally:
            pass

    _retention_thread = threading.Thread(target=_retention_loop, daemon=True)
    _retention_thread.start()

def _stop_log_retention(timeout: float = 5.0) -> None:
    global _retention_thread, _retention_stop
    try:
        if _retention_stop:
            _retention_stop.set()
        if _retention_thread:
            _retention_thread.join(timeout=timeout)
    except Exception:
        pass
    _retention_thread = None
    _retention_stop = None

def _write_crash_log(exc_type, exc_value, exc_tb) -> None:
    try:
        _CRASH_DIR.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        crash_path = _CRASH_DIR / f"{ts}.crash.log"
        tail_kb = 256
        try:
            # If config is available, try to read crash.tail_kb
            if 'get_config' in globals() and callable(get_config):
                cfg = get_config("logging", {}) if 'get_config' in globals() else {}
                if isinstance(cfg, dict):
                    tail_kb = int(cfg.get("crash.tail_kb", 256))
        except Exception:
            tail_kb = 256
        # Tail last N KB of latest.txt
        tail_bytes = tail_kb * 1024
        tail = b""
        try:
            if _LATEST_FILE.exists():
                with open(_LATEST_FILE, 'rb') as f:
                    f.seek(0, os.SEEK_END)
                    size = f.tell()
                    f.seek(max(0, size - tail_bytes), os.SEEK_SET)
                    tail = f.read()
        except Exception:
            tail = b""
        # Compose crash log
        with open(crash_path, 'wb') as out:
            out.write(tail)
            out.write(b"\n\n--- CRASH REPORT ---\n")
            line = f"Time: {datetime.now(timezone.utc).isoformat()}\n"
            out.write(line.encode('ascii', errors='replace'))
            out.write(f"Type: {getattr(exc_type, '__name__', str(exc_type))}\n".encode('ascii', errors='replace'))
            out.write(f"Message: {str(exc_value)}\n".encode('ascii', errors='replace'))
            # Only include stack trace if configured for debug
            try:
                debug_traces = False
                if 'get_config' in globals() and callable(get_config):
                    cfg = get_config("logging", {}) if 'get_config' in globals() else {}
                    if isinstance(cfg, dict):
                        debug_traces = bool(cfg.get("debug_stacktraces", False))
                if debug_traces:
                    import traceback
                    out.write(b"Stack Trace:\n")
                    tb_str = ''.join(traceback.format_exception(exc_type, exc_value, exc_tb))
                    out.write(tb_str.encode('ascii', errors='replace'))
            except Exception:
                pass
    except Exception:
        pass


# Add src to python path to allow imports when necessary (deferred imports will use this)
sys.path.insert(0, str(Path("src").resolve()))

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="PlexiChat Runner and Management Script.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python run.py                          # Start API server, WebUI, and CLI (default)
  python run.py --nowebui --nocli        # Start API server only
  python run.py --noserver --nocli       # Start WebUI only
  python run.py setup --level full       # Install required packages for full installation
  python run.py install --repo user/repo # Install from a custom GitHub repository
  python run.py clean --all              # Clean caches and remove virtualenv
  python run.py update                   # Update to the latest version
Notes:
  Use subcommand --help (e.g., 'python run.py install --help') to see options for a specific command.
"""
    )
    parser.add_argument("--version", action="version", version=f"PlexiChat {get_current_version()}")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    clean_parser = subparsers.add_parser("clean", help="Clean cache and temporary files.")
    clean_parser.add_argument("--all", action="store_true", help="Clean everything including the venv.")
    clean_parser.set_defaults(func=handle_clean)

    # Setup command
    setup_parser = subparsers.add_parser("setup", help="Set up the environment and install dependencies.")
    setup_parser.add_argument("--level", type=str, default="minimal", choices=["minimal", "full", "developer"], help="Installation level.")
    setup_parser.set_defaults(func=handle_setup)

    # Install command
    install_parser = subparsers.add_parser("install", help="Download and install PlexiChat.")
    install_parser.add_argument("--version", type=str, default="latest", help="Version to install (e.g., v1.2.3, latest).")
    install_parser.add_argument("--repo", type=str, default=GITHUB_REPO, help="GitHub repository to install from.")
    install_parser.set_defaults(func=handle_install)

    # Update command
    update_parser = subparsers.add_parser("update", help="Update PlexiChat.")
    update_parser.add_argument("--version", type=str, default="latest", help="Version to update to.")
    update_parser.add_argument("--force", action="store_true", help="Force update even if versions match.")
    update_parser.add_argument("--repo", type=str, default=GITHUB_REPO, help="GitHub repository to update from.")
    update_parser.set_defaults(func=handle_update)

    # Generate Keys command
    keys_parser = subparsers.add_parser("generate-keys", help="Generate and distribute master key shares.")
    keys_parser.set_defaults(func=handle_generate_keys)

    parser.add_argument("--noserver", action="store_true", help="Do not run the API server.")
    parser.add_argument("--nowebui", action="store_true", help="Do not run the WebUI.")
    parser.add_argument("--nocli", action="store_true", help="Do not run the interactive CLI.")

    return parser

# Global runtime components - will be set during initialization if available
_db_manager = None
_security_manager = None
_cluster_manager = None
_backup_manager = None
_plugin_manager = None

# System metrics and monitoring globals (thread-based collector for simplicity)
_system_metrics: Dict[str, any] = {}
_metrics_thread = None
_metrics_stop_event = None

# Helper async initialization and shutdown sequences
import asyncio
import signal
import threading
import time
from datetime import datetime, timezone

async def _initialize_database():
    global _db_manager
    try:
        # Try common import paths for database manager
        try:
            from plexichat.core.database.manager import database_manager as dbm
            _db_manager = dbm
        except Exception:
            # Fallback: try to import a DatabaseManager class
            try:
                from plexichat.core.database.manager import DatabaseManager
                _db_manager = DatabaseManager()
            except Exception:
                _db_manager = None

        if _db_manager is None:
            logger.warning("Database manager not available; continuing without DB (reduced functionality).")
            return False

        # Prefer async initialize() if available
        if hasattr(_db_manager, "initialize"):
            res = _db_manager.initialize()
            if asyncio.iscoroutine(res):
                res = await res
            logger.info("Database initialized.")
        # Some implementations may use 'connect' or 'start'
        elif hasattr(_db_manager, "connect"):
            res = _db_manager.connect()
            if asyncio.iscoroutine(res):
                res = await res
            logger.info("Database connected.")
        else:
            logger.warning("Database manager has no initialize/connect method; assuming available.")
            res = True

        # After DB connection, run migrations if possible
        try:
            # Preferred: db manager exposes run_migrations
            if hasattr(_db_manager, "run_migrations"):
                run_res = _db_manager.run_migrations()
                if asyncio.iscoroutine(run_res):
                    await run_res
                logger.info("Database migrations executed via _db_manager.run_migrations().")
            else:
                # Try module-level migration entrypoints
                try:
                    from plexichat.core.database.manager import run_migrations as run_migs
                    run_res = run_migs()
                    if asyncio.iscoroutine(run_res):
                        await run_res
                    logger.info("Database migrations executed via manager.run_migrations().")
                except Exception:
                    try:
                        import plexichat.core.database.migrations as db_migrations
                        # Common names: migrate_all, run_all_migrations, apply_migrations
                        for candidate in ("migrate_all", "run_all_migrations", "apply_migrations", "migrate"):
                            if hasattr(db_migrations, candidate):
                                func = getattr(db_migrations, candidate)
                                mig_res = func()
                                if asyncio.iscoroutine(mig_res):
                                    await mig_res
                                logger.info(f"Database migrations executed via plexichat.core.database.migrations.{candidate}().")
                                break
                    except Exception:
                        logger.debug("No database migration runner found; skipping migrations.")
        except Exception as e:
            logger.warning(f"Database migrations failed or could not be run: {e}", exc_info=True)

        return True if res is not False else False
    except Exception as e:
        logger.error(f"Database initialization failed: {e}", exc_info=True)
        _db_manager = None
        return False

async def _shutdown_database():
    global _db_manager
    if not _db_manager:
        return
    try:
        if hasattr(_db_manager, "shutdown"):
            res = _db_manager.shutdown()
            if asyncio.iscoroutine(res):
                await res
            logger.info("Database shutdown complete.")
        elif hasattr(_db_manager, "close"):
            res = _db_manager.close()
            if asyncio.iscoroutine(res):
                await res
            logger.info("Database connection closed.")
    except Exception as e:
        logger.error(f"Error during database shutdown: {e}", exc_info=True)

async def _initialize_security():
    global _security_manager
    try:
        # Try multiple possible module names due to refactors
        try:
            from plexichat.core.security.security_manager import security_manager as secm
            _security_manager = secm
        except Exception:
            try:
                from plexichat.core.security.unified_security_system import unified_security_system as secm
                _security_manager = secm
            except Exception:
                # Try class-based import
                try:
                    from plexichat.core.security.security_manager import SecurityManager
                    _security_manager = SecurityManager()
                except Exception:
                    # Try core security module getter
                    try:
                        from plexichat.core.security.security_manager import get_security_system
                        # get_security_system may be async or sync
                        res = get_security_system()
                        if asyncio.iscoroutine(res):
                            _security_manager = await res
                        else:
                            _security_manager = res
                    except Exception:
                        _security_manager = None

        if _security_manager is None:
            logger.warning("Security manager not available; continuing with reduced security features.")
            return False

        # Prefer initialize() if present
        if hasattr(_security_manager, "initialize"):
            res = _security_manager.initialize()
            if asyncio.iscoroutine(res):
                res = await res
            logger.info("Security manager initialized.")
            return True if res is not False else False
        else:
            # Some implementations use initialize_security_system function
            try:
                from plexichat.core.security.security_manager import initialize_security_system
                res = initialize_security_system()
                if asyncio.iscoroutine(res):
                    await res
                logger.info("Security manager initialized via initialize_security_system().")
                return True
            except Exception:
                logger.warning("Security manager has no initialize() method; assumed ready.")
                return True
    except Exception as e:
        logger.error(f"Security initialization failed: {e}", exc_info=True)
        _security_manager = None
        return False

async def _shutdown_security():
    global _security_manager
    if not _security_manager:
        return
    try:
        if hasattr(_security_manager, "shutdown"):
            res = _security_manager.shutdown()
            if asyncio.iscoroutine(res):
                await res
            logger.info("Security manager shut down.")
        else:
            # Try module-level shutdown
            try:
                from plexichat.core.security.security_manager import shutdown_security_system
                res = shutdown_security_system()
                if asyncio.iscoroutine(res):
                    await res
                logger.info("Security manager shut down via shutdown_security_system().")
            except Exception:
                logger.debug("No explicit security shutdown found; skipping.")
    except Exception as e:
        logger.error(f"Error during security shutdown: {e}", exc_info=True)

async def _initialize_cluster():
    global _cluster_manager
    try:
        # Use the provided initializer from clustering module if available
        try:
            from plexichat.core.clustering.cluster_manager import initialize_cluster_manager, get_cluster_manager
            # initialize_cluster_manager may accept config; call without args
            cm = await initialize_cluster_manager()
            _cluster_manager = cm
            logger.info("Cluster manager initialized and started.")
            return True
        except Exception:
            # Try to import a ClusterManager class and start it
            from plexichat.core.clustering.cluster_manager import ClusterManager, get_cluster_manager
            _cluster_manager = ClusterManager()
            if hasattr(_cluster_manager, "start"):
                res = _cluster_manager.start()
                if asyncio.iscoroutine(res):
                    await res
            logger.info("Cluster manager started (fallback path).")
            return True
    except Exception as e:
        logger.error(f"Cluster manager initialization failed: {e}", exc_info=True)
        _cluster_manager = None
        return False

async def _shutdown_cluster():
    global _cluster_manager
    try:
        # Prefer shutdown_cluster_manager function if available
        try:
            from plexichat.core.clustering.cluster_manager import shutdown_cluster_manager
            await shutdown_cluster_manager()
            logger.info("Cluster manager shutdown via shutdown_cluster_manager().")
            _cluster_manager = None
            return
        except Exception:
            pass

        if _cluster_manager:
            if hasattr(_cluster_manager, "stop"):
                res = _cluster_manager.stop()
                if asyncio.iscoroutine(res):
                    await res
                logger.info("Cluster manager stopped.")
            _cluster_manager = None
    except Exception as e:
        logger.error(f"Error during cluster shutdown: {e}", exc_info=True)

async def _initialize_backup():
    global _backup_manager, _cluster_manager
    try:
        # Import BackupManager from standard location
        try:
            from plexichat.features.backup.backup_manager import BackupManager
            # Inject global cluster manager if available to ensure consistent state
            if _cluster_manager is not None:
                try:
                    _backup_manager = BackupManager(cluster_manager=_cluster_manager)
                    logger.debug("BackupManager instantiated with injected cluster_manager.")
                except TypeError:
                    # Older BackupManager signature - instantiate without injection
                    _backup_manager = BackupManager()
                    logger.debug("BackupManager instantiated without injection (signature mismatch).")
            else:
                _backup_manager = BackupManager()
        except Exception:
            # Try alternative import path
            try:
                from plexichat.features.backup import backup_manager as bm_mod
                if hasattr(bm_mod, "BackupManager"):
                    BackupManagerClass = bm_mod.BackupManager
                    if _cluster_manager is not None:
                        try:
                            _backup_manager = BackupManagerClass(cluster_manager=_cluster_manager)
                            logger.debug("BackupManager (alt) instantiated with injected cluster_manager.")
                        except TypeError:
                            _backup_manager = BackupManagerClass()
                            logger.debug("BackupManager (alt) instantiated without injection.")
                    else:
                        _backup_manager = BackupManagerClass()
            except Exception:
                _backup_manager = None

        if _backup_manager is None:
            logger.warning("Backup manager not available; backups disabled.")
            return False

        # Start background tasks
        if hasattr(_backup_manager, "start"):
            res = _backup_manager.start()
            if asyncio.iscoroutine(res):
                await res
            logger.info("Backup manager started.")
            return True
        else:
            logger.warning("Backup manager has no start() method; assuming ready.")
            return True
    except Exception as e:
        logger.error(f"Backup manager initialization failed: {e}", exc_info=True)
        _backup_manager = None
        return False

async def _shutdown_backup():
    global _backup_manager
    if not _backup_manager:
        return
    try:
        if hasattr(_backup_manager, "stop"):
            res = _backup_manager.stop()
            if asyncio.iscoroutine(res):
                await res
            logger.info("Backup manager stopped.")
    except Exception as e:
        logger.error(f"Error during backup manager shutdown: {e}", exc_info=True)
    _backup_manager = None

async def _initialize_plugins():
    global _plugin_manager
    try:
        # Ensure plugins_internal.py SDK exists before importing plugin manager
        try:
            from plexichat.core.plugins.sdk_generator import sdk_generator
            try:
                regenerated = sdk_generator.regenerate_if_needed()
                if asyncio.iscoroutine(regenerated):
                    regenerated = await regenerated
                logger.info(f"Plugin SDK generation status: {regenerated}")
            except Exception as e:
                logger.warning(f"Could not auto-generate plugin SDK before plugin manager initialization: {e}")
        except Exception:
            logger.debug("SDK generator not available; plugin SDK generation skipped.")

        # Import unified plugin manager
        try:
            from plexichat.core.plugins.manager import unified_plugin_manager as upm
            _plugin_manager = upm
        except Exception:
            # fallback name
            try:
                from plexichat.core.plugins.manager import UnifiedPluginManager
                _plugin_manager = UnifiedPluginManager()
            except Exception:
                _plugin_manager = None

        if _plugin_manager is None:
            logger.warning("Plugin manager not available; plugins disabled.")
            return False

        if hasattr(_plugin_manager, "initialize"):
            res = _plugin_manager.initialize()
            if asyncio.iscoroutine(res):
                await res
            logger.info("Plugin manager initialized.")
            return True
        else:
            logger.warning("Plugin manager has no initialize() method; assuming loaded.")
            return True
    except Exception as e:
        logger.error(f"Plugin manager initialization failed: {e}", exc_info=True)
        _plugin_manager = None
        return False

async def _shutdown_plugins():
    global _plugin_manager
    if not _plugin_manager:
        return
    try:
        if hasattr(_plugin_manager, "shutdown"):
            res = _plugin_manager.shutdown()
            if asyncio.iscoroutine(res):
                await res
            logger.info("Plugin manager shut down.")
    except Exception as e:
        logger.error(f"Error during plugin manager shutdown: {e}", exc_info=True)
    _plugin_manager = None

async def _startup_health_check():
    """Perform basic health checks to ensure critical systems are up."""
    checks = {}
    try:
        checks['database'] = _db_manager is not None
    except Exception:
        checks['database'] = False
    try:
        checks['security'] = _security_manager is not None
    except Exception:
        checks['security'] = False
    try:
        checks['cluster'] = _cluster_manager is not None
    except Exception:
        checks['cluster'] = False
    try:
        checks['backup'] = _backup_manager is not None
    except Exception:
        checks['backup'] = False
    try:
        checks['plugins'] = _plugin_manager is not None
    except Exception:
        checks['plugins'] = False

    # Log the status; decide if system is healthy enough to start servers.
    for name, ok in checks.items():
        if ok:
            logger.info(f"Health check: {name} OK")
        else:
            logger.warning(f"Health check: {name} NOT OK")

    # Basic policy: allow startup in degraded mode for testing
    # Only abort if ALL systems are down (which shouldn't happen)
    all_down = not any(checks.values())
    if all_down:
        logger.error("All systems are unavailable. Aborting startup.")
        return False

    # Log warnings for missing systems but allow startup
    missing_systems = [name for name, ok in checks.items() if not ok]
    if missing_systems:
        logger.warning(f"Starting in degraded mode - missing systems: {', '.join(missing_systems)}")

    return True

async def initialize_all_systems():
    """Initialize systems in order: database -> security -> clustering -> backup -> plugins."""
    logger.info("Starting system initialization sequence (database -> security -> clustering -> backup -> plugins).")
    results = {
        "database": False,
        "security": False,
        "cluster": False,
        "backup": False,
        "plugins": False
    }

    try:
        results['database'] = await _initialize_database()
    except Exception as e:
        logger.error(f"Database initialization error: {e}", exc_info=True)
        results['database'] = False

    try:
        results['security'] = await _initialize_security()
    except Exception as e:
        logger.error(f"Security initialization error: {e}", exc_info=True)
        results['security'] = False

    try:
        results['cluster'] = await _initialize_cluster()
    except Exception as e:
        logger.error(f"Cluster initialization error: {e}", exc_info=True)
        results['cluster'] = False

    try:
        results['backup'] = await _initialize_backup()
    except Exception as e:
        logger.error(f"Backup initialization error: {e}", exc_info=True)
        results['backup'] = False

    # Before initializing plugins, ensure plugins_internal is generated and validated
    try:
        from plexichat.core.plugins.sdk_generator import sdk_generator
        try:
            sdk_ok = sdk_generator.regenerate_if_needed()
            if asyncio.iscoroutine(sdk_ok):
                sdk_ok = await sdk_ok
            if sdk_ok:
                valid = sdk_generator.validate_plugins_internal()
                if asyncio.iscoroutine(valid):
                    valid = await valid
                logger.info(f"Plugin SDK generation/validation: generated={sdk_ok}, valid={valid}")
            else:
                logger.warning("Plugin SDK was not generated successfully.")
        except Exception as e:
            logger.warning(f"Plugin SDK generation/validation failed: {e}", exc_info=True)
    except Exception:
        logger.debug("SDK generator not present; skipping explicit SDK generation step.")

    try:
        results['plugins'] = await _initialize_plugins()
    except Exception as e:
        logger.error(f"Plugin manager initialization error: {e}", exc_info=True)
        results['plugins'] = False

    healthy = await _startup_health_check()
    if not healthy:
        # If critical systems unavailable, propagate an error to caller.
        raise RuntimeError("Critical system health checks failed during startup.")

    logger.info("System initialization sequence completed with results: " + ", ".join(f"{k}={v}" for k, v in results.items()))
    return results

async def shutdown_all_systems():
    """Shutdown all systems in reverse order, best-effort."""
    logger.info("Commencing graceful shutdown of all systems.")

    # Stop metrics collector first to avoid race while components shutdown
    try:
        _stop_system_metrics()
    except Exception as e:
        logger.debug(f"Error stopping system metrics collector: {e}")

    # Plugins
    try:
        await _shutdown_plugins()
    except Exception as e:
        logger.error(f"Error shutting down plugins: {e}", exc_info=True)
    # Backup
    try:
        await _shutdown_backup()
    except Exception as e:
        logger.error(f"Error shutting down backup manager: {e}", exc_info=True)
    # Cluster
    try:
        await _shutdown_cluster()
    except Exception as e:
        logger.error(f"Error shutting down cluster manager: {e}", exc_info=True)
    # Security
    try:
        await _shutdown_security()
    except Exception as e:
        logger.error(f"Error shutting down security manager: {e}", exc_info=True)
    # Database
    try:
        await _shutdown_database()
    except Exception as e:
        logger.error(f"Error shutting down database manager: {e}", exc_info=True)

    logger.info("Shutdown sequence complete. Exiting.")

# Signal handling - ensure graceful shutdown on SIGINT/SIGTERM
_shutdown_in_progress = False
def _signal_handler(signum, frame):
    global _shutdown_in_progress
    if _shutdown_in_progress:
        logger.warning("Shutdown already in progress; forcing exit.")
        try:
            sys.exit(1)
        except Exception:
            os._exit(1)
    _shutdown_in_progress = True
    logger.info(f"Received signal {signum}. Initiating graceful shutdown.")
    # Run the async shutdown in a new event loop to ensure we don't interfere with running loops
    try:
        asyncio.run(shutdown_all_systems())
    except Exception as e:
        logger.error(f"Error during shutdown: {e}", exc_info=True)
    finally:
        try:
            sys.exit(0)
        except Exception:
            os._exit(0)

# Register signal handlers for Unix and Windows
try:
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)
except Exception as e:
    logger.warning(f"Could not register OS signal handlers: {e}")

# System metrics collector (thread-based for simplicity)
def _metrics_collector_loop(stop_event: threading.Event):
    """Background thread that collects basic system metrics periodically."""
    try:
        try:
            import psutil
        except Exception:
            psutil = None
            logger.debug("psutil not available; system metrics will be limited.")

        logger.info("System metrics collector started.")
        while not stop_event.is_set():
            try:
                timestamp = datetime.now(timezone.utc).isoformat()
                if psutil:
                    cpu = psutil.cpu_percent(interval=1)
                    mem = psutil.virtual_memory()
                    disk = psutil.disk_usage('/')
                    _system_metrics['cpu_percent'] = cpu
                    _system_metrics['memory_percent'] = mem.percent
                    _system_metrics['disk_percent'] = disk.percent
                    _system_metrics['boot_time'] = getattr(psutil, "boot_time", None) and datetime.fromtimestamp(psutil.boot_time(), timezone.utc).isoformat()
                else:
                    # Basic fallback using os.getloadavg if available
                    try:
                        load = os.getloadavg()
                        _system_metrics['load_avg'] = load
                    except Exception:
                        _system_metrics['load_avg'] = None
                _system_metrics['timestamp'] = timestamp
                # Sleep a bit to avoid tight loop; psutil.cpu_percent already sleeps 1 sec
                time.sleep(4)
            except Exception as e:
                logger.debug(f"Metrics collector iteration error: {e}")
                time.sleep(2)
    finally:
        logger.info("System metrics collector stopped.")

def _start_system_metrics():
    """Start the background system metrics collector thread if not already running."""
    global _metrics_thread, _metrics_stop_event
    if _metrics_thread and _metrics_thread.is_alive():
        logger.debug("System metrics collector already running.")
        return
    _metrics_stop_event = threading.Event()
    _metrics_thread = threading.Thread(target=_metrics_collector_loop, args=(_metrics_stop_event,), daemon=True)
    _metrics_thread.start()
    logger.info("Started system metrics collector thread.")

def _stop_system_metrics(timeout: float = 5.0):
    """Stop the background system metrics collector thread."""
    global _metrics_thread, _metrics_stop_event
    if _metrics_stop_event:
        _metrics_stop_event.set()
    if _metrics_thread:
        _metrics_thread.join(timeout=timeout)
        if _metrics_thread.is_alive():
            logger.debug("Metrics thread did not stop within timeout.")
        else:
            logger.info("Metrics thread stopped.")
    _metrics_thread = None
    _metrics_stop_event = None

def validate_configuration(get_config_callable):
    """
    Basic configuration validation to catch common misconfigurations early.
    This function is conservative and will only warn, not abort, unless critical issues found.
    """
    try:
        cfg_api = {}
        cfg_webui = {}
        cfg_network = {}
        try:
            cfg_api = get_config_callable("api", {})
            cfg_webui = get_config_callable("webui", {})
            cfg_network = get_config_callable("network", {})
        except Exception as e:
            logger.warning(f"Could not read config sections for validation: {e}")
            return True

        # Validate API port
        api_port = cfg_api.get("port") if isinstance(cfg_api, dict) else None
        if api_port is not None:
            try:
                api_port_val = int(api_port)
                if not (1 <= api_port_val <= 65535):
                    logger.error(f"API port {api_port_val} out of valid range (1-65535).")
                    return False
            except Exception:
                logger.error(f"Invalid API port value: {api_port}")
                return False

        # Validate network keepalive
        timeout = getattr(cfg_network, "timeout_keep_alive", None) if not isinstance(cfg_network, dict) else cfg_network.get("timeout_keep_alive")
        if timeout is not None:
            try:
                t = int(timeout)
                if t <= 0:
                    logger.warning("Network timeout_keep_alive is non-positive; resetting to default.")
            except Exception:
                logger.warning("Network timeout_keep_alive invalid; using default.")

        return True
    except Exception as e:
        logger.debug(f"Configuration validation error: {e}")
        return True

def main():
    # Build and parse args first to ensure help and subcommand help exit before heavy imports.
    parser = build_arg_parser()
    try:
        args = parser.parse_args()
    except SystemExit:
        # argparse already handled -h or invalid args and printed help/error. Exit early without heavy imports.
        raise

    # If a subcommand was provided, execute its handler and exit. Handlers may import heavy modules as needed.
    if hasattr(args, "func"):
        try:
            args.func(args)
        except Exception:
            # Write crash log for subcommand failures as well
            exc_type, exc_value, exc_tb = sys.exc_info()
            _write_crash_log(exc_type, exc_value, exc_tb)
            logger.error(f"Command '{getattr(args, 'command', 'unknown')}' failed", exc_info=True)
            sys.exit(1)
        return

    # Default action: run the application (API server, WebUI, CLI)
    # Validate project setup early

    # Rotate logs at startup and start retention job
    try:
        _rotate_latest_log()
        # Start retention with default 14 days; will be overridden when config loads
        _start_log_retention(14)
    except Exception as e:
        logger.warning(f"Log rotation/retention initialization error: {e}")
    if not (VENV_DIR.exists() and Path("src").exists()):
        import logging
        logging.getLogger("plexichat").error("Project not set up. Please run 'install' and 'setup'.")
        sys.exit(1)

    # Attempt to replace logger with project's logging if available
    try:
        from plexichat.core.logging import setup_logging  # deferred heavy import
        project_logger = setup_logging()
        # Replace the module-level logger with project's logger where possible
        if project_logger:
            logger = project_logger
            logger.debug("Replaced bootstrap logger with project logger.")
    except Exception as e:
        # Keep using the basic logger; give user actionable advice
        import logging
        logger = logging.getLogger("plexichat")
        logger.warning("Could not set up project-specific logging. Continuing with basic logging.")
        logger.debug(f"Logging import error: {e}", exc_info=True)

    # Now import the heavy components required to run the server and UI
    try:
        from plexichat.main import app as main_app
        from plexichat.interfaces.web.main import app as webui_app
        # get_config name moved in refactor; try common names
        try:
            from plexichat.core.unified_config import get_config
        except Exception:
            try:
                from plexichat.core.config_manager import get_config
            except Exception:
                # fallback: minimal config loader
                def get_config(k, default=None):
                    return default or {}
        import uvicorn
        import threading
    except ImportError as e:
        logger.error(f"Failed to import necessary modules to run the application: {e}")
        logger.warning("Make sure you've run 'python run.py setup' to install dependencies and that 'src' is present.")
        logger.debug("Detailed import error:", exc_info=True)
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error during startup imports: {e}")
        logger.debug("Detailed startup error:", exc_info=True)
        sys.exit(1)

    # Load configurations
    try:
        api_config = get_config("api", {})
    except Exception:
        api_config = {}
        logger.warning("Failed to load 'api' configuration; using defaults.")

    # Update retention days from config if available
    try:
        logging_cfg = get_config("logging", None)
        rd = int(getattr(logging_cfg, "retention_days", 14))
        _stop_log_retention()
        _start_log_retention(rd)
    except Exception as e:
        logger.debug(f"Retention config error: {e}")
    try:
        webui_config = get_config("webui", {})
    except Exception:
        webui_config = {}
        logger.warning("Failed to load 'webui' configuration; using defaults.")

    api_host = api_config.get("host", "0.0.0.0") if isinstance(api_config, dict) else "0.0.0.0"
    api_port = api_config.get("port", 8000) if isinstance(api_config, dict) else 8000
    webui_host = webui_config.get("host", "0.0.0.0") if isinstance(webui_config, dict) else "0.0.0.0"
    webui_port = webui_config.get("port", 8080) if isinstance(webui_config, dict) else 8080

    def run_server(app, host, port, network_config, ssl_config=None):
        if ssl_config and ssl_config.get("enabled"):
            import ssl

            protocol_map = {
                "TLSv1.2": ssl.PROTOCOL_TLSv1_2,
                "TLSv1.3": ssl.PROTOCOL_TLS,
            }
            ssl_version = protocol_map.get(ssl_config.get("version"), ssl.PROTOCOL_TLS)

            uvicorn.run(
                app,
                host=host,
                port=port,
                ssl_keyfile=ssl_config.get("key_path"),
                ssl_certfile=ssl_config.get("cert_path"),
                ssl_version=ssl_version,
                ssl_ciphers=ssl_config.get("ciphers"),
                timeout_keep_alive=network_config.timeout_keep_alive,
            )
        else:
            uvicorn.run(app, host=host, port=port, timeout_keep_alive=network_config.timeout_keep_alive)

    threads = []

    try:
        network_config = get_config("network")
    except Exception:
        # Provide a minimal fallback object with expected attributes to avoid AttributeError
        class _NetCfg:
            timeout_keep_alive = 60
            ssl_enabled = False
            ssl_key_path = None
            ssl_cert_path = None
            tls_version = None
            tls_ciphers = None
        network_config = _NetCfg()
        logger.warning("Using fallback network configuration.")

    ssl_settings = {
        "enabled": getattr(network_config, "ssl_enabled", False),
        "key_path": getattr(network_config, "ssl_key_path", None),
        "cert_path": getattr(network_config, "ssl_cert_path", None),
        "version": getattr(network_config, "tls_version", None),
        "ciphers": getattr(network_config, "tls_ciphers", None),
    }

    # Validate configuration early
    try:
        valid_cfg = validate_configuration(get_config)
        if not valid_cfg:
            logger.error("Configuration validation failed. Aborting startup.")
            sys.exit(1)
    except Exception as e:
        logger.warning(f"Configuration validation encountered an error but will continue: {e}")

    # Ensure plugin SDK generation occurs before any plugin loading
    try:
        from plexichat.core.plugins.sdk_generator import sdk_generator
        try:
            sdk_generated = sdk_generator.regenerate_if_needed()
            if asyncio.iscoroutine(sdk_generated):
                sdk_generated = asyncio.run(sdk_generated)
            if sdk_generated:
                valid = sdk_generator.validate_plugins_internal()
                if asyncio.iscoroutine(valid):
                    valid = asyncio.run(valid)
                if not valid:
                    logger.warning("Generated plugins_internal.py failed validation.")
                else:
                    logger.info("Plugin SDK generated and validated before plugin loading.")
            else:
                logger.warning("Plugin SDK generation did not complete successfully before plugin loading.")
        except Exception as e:
            logger.warning(f"Attempt to generate plugin SDK before startup failed: {e}", exc_info=True)
    except Exception:
        logger.debug("SDK generator import failed or not available; continuing without explicit SDK generation step.")

    # Initialize core systems before starting servers so plugin routes and commands are available
    logger.info("Initializing core systems before starting servers...")
    try:
        init_results = asyncio.run(initialize_all_systems())
        logger.info("Core systems initialization finished.")
    except Exception as e:
        logger.error(f"Critical error during system initialization: {e}", exc_info=True)
        # If initialization failed critically, try to shutdown any partially started systems and exit.
        try:
            asyncio.run(shutdown_all_systems())
        except Exception:
            pass
        logger.critical("Startup failed due to critical errors. Exiting.")
        sys.exit(1)

    # Start system metrics collector (thread-based) after successful initialization
    try:
        _start_system_metrics()
    except Exception as e:
        logger.warning(f"Failed to start system metrics collector: {e}")

    # At this point, even if some systems failed, we proceed in degraded mode per requirements.

    if not getattr(args, "noserver", False):
        logger.info(f"Starting API server in background on {api_host}:{api_port}...")
        server_thread = threading.Thread(target=run_server, args=(main_app, api_host, api_port, network_config, ssl_settings), daemon=True)
        threads.append(server_thread)
        server_thread.start()

    if not getattr(args, "nowebui", False):
        logger.info(f"Starting WebUI in background on {webui_host}:{webui_port}...")
        webui_thread = threading.Thread(target=run_server, args=(webui_app, webui_host, webui_port, network_config, ssl_settings), daemon=True)
        threads.append(webui_thread)
        webui_thread.start()

    # Initialize CLI and ensure plugin manager commands are available to API and CLI
    if not getattr(args, "nocli", False):
        logger.info("Starting interactive CLI...")
        try:
            # Use the modern cli manager name (may have been refactored)
            try:
                from plexichat.interfaces.cli.cli_manager import CLI as UnifiedCLIClass
                UnifiedCLI = UnifiedCLIClass
            except Exception:
                try:
                    from plexichat.interfaces.cli.unified_cli import UnifiedCLI
                except Exception:
                    UnifiedCLI = None

            # Ensure plugin manager is available to CLI - _plugin_manager set in initialization
            if _plugin_manager is None:
                # Attempt a late import/initialize (best-effort)
                try:
                    from plexichat.core.plugins.manager import unified_plugin_manager as upm
                    _plugin_manager_local = upm
                    if hasattr(_plugin_manager_local, "initialize"):
                        try:
                            asyncio.run(_plugin_manager_local.initialize())
                        except Exception as ie:
                            logger.warning(f"Plugin manager late initialization failed: {ie}")
                    _plugin_manager_local = upm
                except Exception as e:
                    logger.warning(f"Plugin manager not available for CLI: {e}")
            else:
                logger.debug("Plugin manager already initialized for CLI.")

            # Create the main CLI application if CLI class is available
            if UnifiedCLI:
                cli_builder = UnifiedCLI()
                try:
                    cli_app = cli_builder.build_cli()
                except Exception as e:
                    logger.error(f"Failed to build CLI application: {e}", exc_info=True)
                    cli_app = None

                # Get and add plugin commands
                try:
                    plugin_commands = getattr(_plugin_manager, "plugin_commands", None)
                    if plugin_commands:
                        logger.info(f"Found {len(plugin_commands)} plugin commands. Adding to CLI.")
                        # cli_app may expose add_command or similar
                        if cli_app and hasattr(cli_app, "add_command"):
                            for name, command in plugin_commands.items():
                                try:
                                    cli_app.add_command(command, name=name)
                                except Exception as e:
                                    logger.warning(f"Failed to add plugin command {name}: {e}")
                        else:
                            logger.debug("CLI application does not support adding commands programmatically.")
                    else:
                        logger.info("No plugin commands found.")
                except Exception as e:
                    logger.debug(f"Error while loading plugin commands: {e}", exc_info=True)

                # Run the CLI if we have a callable cli_app
                if cli_app and callable(cli_app):
                    try:
                        cli_app()
                    except Exception as e:
                        logger.error(f"CLI exited with an error: {e}", exc_info=True)
                else:
                    # If no interactive CLI available, fall back to waiting for servers
                    if not threads:
                        parser.print_help()
                        logger.warning("Nothing to run. Use --noserver, --nowebui, or run the CLI.")
                    else:
                        logger.info("Servers running. Press Ctrl+C to shut down.")
                        try:
                            for t in threads:
                                t.join()
                        except KeyboardInterrupt:
                            logger.info("\nShutting down...")
            else:
                logger.warning("No CLI implementation found. Running servers only.")
                if not threads:
                    parser.print_help()
                    logger.warning("Nothing to run. Use --noserver, --nowebui.")
                else:
                    logger.info("Servers running. Press Ctrl+C to shut down.")
                    try:
                        for t in threads:
                            t.join()
                    except KeyboardInterrupt:
                        logger.info("\nShutting down...")
        except Exception as e:
            logger.error(f"CLI exited with an error: {e}", exc_info=True)
    else:
        # No CLI requested - keep servers running until signal
        if not threads:
            parser.print_help()
            logger.warning("Nothing to run. Use --noserver, --nowebui, or run the CLI.")
        else:
            logger.info("Servers running. Press Ctrl+C to shut down.")
            try:
                for t in threads:
                    t.join()
            except KeyboardInterrupt:
                logger.info("\nShutting down...")

    # When main execution path completes (CLI exit or servers stopped), ensure graceful shutdown of systems.
    try:
        asyncio.run(shutdown_all_systems())
    except Exception:
        exc_type, exc_value, exc_tb = sys.exc_info()
        _write_crash_log(exc_type, exc_value, exc_tb)
        logger.error("Error during final shutdown", exc_info=True)

if __name__ == "__main__":
    main()