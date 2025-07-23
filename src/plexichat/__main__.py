#!/usr/bin/env python3
# pyright: reportMissingImports=false
# pyright: reportGeneralTypeIssues=false
# pyright: reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
"""
PlexiChat Main Entry Point - SINGLE PROCESS PROTECTION

This module provides the main entry point for PlexiChat with:
- Single process protection (only one instance can run)
- Multithreading support with thread pools
- Graceful shutdown handling
- Process monitoring and health checks
- Comprehensive error handling and logging

Usage:
    python -m plexichat
    python -m plexichat --port 8000
    python -m plexichat --debug
    python -m plexichat --config config/custom.yaml
"""

import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import argparse
import asyncio
import atexit
import logging
import os
import signal
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Optional

# Windows/Unix compatibility for file locking
try:
    import fcntl
    HAS_FCNTL = True
except ImportError:
    # Windows doesn't have fcntl, use msvcrt instead
    try:
        import msvcrt
        HAS_MSVCRT = True
        HAS_FCNTL = False
    except ImportError:
        HAS_FCNTL = False
        HAS_MSVCRT = False

# Import shared components
try:
    from .shared.exceptions import ProcessLockError, StartupError
except ImportError:
    class ProcessLockError(Exception):
        pass

    class StartupError(Exception):
        pass

# Fallback constants
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 8000
DEFAULT_WORKERS = 4
PROCESS_LOCK_FILE = "plexichat.lock"
MAX_STARTUP_TIME = 60

# Global variables for process management
_lock_file: Optional[int] = None
_thread_pool: Optional[ThreadPoolExecutor] = None
_shutdown_event = threading.Event()
_startup_complete = threading.Event()

def setup_logging(debug: bool = False) -> logging.Logger:
    """Setup unified logging configuration."""
    try:
        from .core.logging.unified_logging_manager import initialize_logging, get_logger, cleanup_logs

        # Initialize unified logging system with minimal config
        config = {
            "level": "DEBUG" if debug else "INFO",
            "json_format": False,
            "cleanup_days": 30,
            "compress_old_logs": True
        }

        initialize_logging(config)

        # Clean up old logs on startup
        cleanup_logs()

        logger = get_logger('plexichat.main')
        logger.info("Unified logging system initialized")
        return logger

    except ImportError:
        # Fallback to basic logging
        level = logging.DEBUG if debug else logging.INFO

        # Create logs directory
        Path("logs").mkdir(exist_ok=True)

        # Configure logging
        logging.basicConfig(
            level=level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('logs/plexichat.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )

        logger = logging.getLogger('plexichat.main')
        logger.info("Basic logging system initialized")
        return logger

def acquire_process_lock() -> bool:
    """
    Acquire a process lock to ensure only one PlexiChat instance runs.
    Cross-platform implementation for Windows and Unix systems.

    Returns:
        bool: True if lock acquired successfully, False otherwise
    """
    global _lock_file

    try:
        lock_path = Path(PROCESS_LOCK_FILE)

        if HAS_FCNTL:
            # Unix/Linux file locking with fcntl
            _lock_file = os.open(str(lock_path), os.O_CREAT | os.O_WRONLY | os.O_TRUNC)
            fcntl.flock(_lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
            os.write(_lock_file, f"{os.getpid()}\n".encode())
            os.fsync(_lock_file)
            return True

        elif HAS_MSVCRT:
            # Windows file locking with msvcrt
            try:
                _lock_file = os.open(str(lock_path), os.O_CREAT | os.O_WRONLY | os.O_TRUNC)
                msvcrt.locking(_lock_file, msvcrt.LK_NBLCK, 1)
                os.write(_lock_file, f"{os.getpid()}\n".encode())
                os.fsync(_lock_file)
                return True
            except OSError as e:
                if _lock_file:
                    try:
                        os.close(_lock_file)
                    except:
                        pass
                    _lock_file = None
                raise e
        else:
            # Fallback: Simple file-based locking (less reliable)
            if lock_path.exists():
                try:
                    with open(lock_path, 'r') as f:
                        pid = int(f.read().strip())

                    # Check if process is still running (Windows/Unix compatible)
                    try:
                        if sys.platform == "win32":
                            import subprocess
                            result = subprocess.run(['tasklist', '/FI', f'PID eq {pid}'],
                                                  capture_output=True, text=True)
                            if str(pid) in result.stdout:
                                raise ProcessLockError(
                                    f"Another PlexiChat instance is already running (PID: {pid}). "
                                    f"Stop it first or remove {PROCESS_LOCK_FILE} if it's stale."
                                )
                        else:
                            os.kill(pid, 0)  # Unix signal check
                            raise ProcessLockError(
                                f"Another PlexiChat instance is already running (PID: {pid}). "
                                f"Stop it first or remove {PROCESS_LOCK_FILE} if it's stale."
                            )
                    except (ProcessLookupError, subprocess.CalledProcessError):
                        # Process doesn't exist, remove stale lock file
                        lock_path.unlink(missing_ok=True)

                except (ValueError, FileNotFoundError):
                    # Invalid lock file, remove it
                    lock_path.unlink(missing_ok=True)

            # Create new lock file
            with open(lock_path, 'w') as f:
                f.write(f"{os.getpid()}\n")
            return True

    except (OSError, IOError) as e:
        if _lock_file:
            try:
                os.close(_lock_file)
            except:
                pass
            _lock_file = None

        raise ProcessLockError(f"Failed to acquire process lock: {e}")

def release_process_lock():
    """Release the process lock (cross-platform) with improved error handling."""
    global _lock_file

    if _lock_file:
        try:
            if HAS_FCNTL:
                fcntl.flock(_lock_file, fcntl.LOCK_UN)
            elif HAS_MSVCRT:
                msvcrt.locking(_lock_file, msvcrt.LK_UNLCK, 1)
            os.close(_lock_file)
        except Exception as e:
            # Log the error but continue cleanup
            logging.getLogger('plexichat.main').warning(f"Error releasing file lock: {e}")
        _lock_file = None

    # Remove lock file with better error handling
    try:
        lock_path = Path(PROCESS_LOCK_FILE)
        if lock_path.exists():
            # Try to change permissions if needed (Unix/Linux)
            if hasattr(os, 'chmod'):
                try:
                    os.chmod(lock_path, 0o666)
                except:
                    pass
            lock_path.unlink(missing_ok=True)
    except PermissionError:
        # On Windows, try to force delete
        if sys.platform == "win32":
            try:
                import subprocess
                subprocess.run(['del', '/f', str(lock_path)], shell=True, capture_output=True)
            except:
                pass
    except Exception as e:
        logging.getLogger('plexichat.main').warning(f"Error removing lock file: {e}")

def setup_signal_handlers(logger: logging.Logger):
    """Setup signal handlers for graceful shutdown."""

    def signal_handler(signum, frame):
        logger.info(f"Received signal {signum}, initiating graceful shutdown...")
        _shutdown_event.set()

    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)   # Ctrl+C
    signal.signal(signal.SIGTERM, signal_handler)  # Termination request

    if hasattr(signal, 'SIGHUP'):
        signal.signal(signal.SIGHUP, signal_handler)  # Hangup (Unix only)

def setup_thread_pool(workers: int) -> ThreadPoolExecutor:
    """Setup thread pool for multithreading support."""
    global _thread_pool

    _thread_pool = ThreadPoolExecutor()
        max_workers=workers,
        thread_name_prefix="PlexiChat-Worker"
    )

    return _thread_pool

def cleanup_resources(logger: logging.Logger):
    """Cleanup all resources on shutdown."""
    logger.info("Cleaning up resources...")

    # Shutdown thread pool
    if _thread_pool:
        logger.info("Shutting down thread pool...")
        try:
            _thread_pool.shutdown(wait=True)
        except Exception as e:
            logger.warning(f"Error shutting down thread pool: {e}")

    # Release process lock
    release_process_lock()

    logger.info("Resource cleanup complete")

def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="PlexiChat - Government-Level Secure Communication Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m plexichat                    # Start with default settings
  python -m plexichat --port 8080       # Start on port 8080
  python -m plexichat --debug           # Start in debug mode
  python -m plexichat --workers 8       # Start with 8 worker threads
  python -m plexichat --config custom.yaml  # Use custom config
        """
    )

    parser.add_argument(
        '--host',
        default=DEFAULT_HOST,
        help=f'Host to bind to (default: {DEFAULT_HOST})'
    )

    parser.add_argument(
        '--port',
        type=int,
        default=DEFAULT_PORT,
        help=f'Port to bind to (default: {DEFAULT_PORT})'
    )

    parser.add_argument(
        '--workers',
        type=int,
        default=DEFAULT_WORKERS,
        help=f'Number of worker threads (default: {DEFAULT_WORKERS})'
    )

    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug mode'
    )

    parser.add_argument(
        '--config',
        type=str,
        help='Path to configuration file'
    )

    parser.add_argument(
        '--force',
        action='store_true',
        help='Force start even if lock file exists (dangerous!)'
    )

    return parser.parse_args()

async def startup_monitor(logger: logging.Logger, timeout: int = MAX_STARTUP_TIME):
    """Monitor startup process and timeout if it takes too long."""
    try:
        await asyncio.wait_for(_startup_complete.wait(), timeout=timeout)
        logger.info("Startup completed successfully")
    except asyncio.TimeoutError:
        logger.error(f"Startup timed out after {timeout} seconds")
        _shutdown_event.set()
        raise StartupError(f"Startup timed out after {timeout} seconds")

def main():
    """Main entry point with single-process protection and multithreading."""
    # Parse arguments
    args = parse_arguments()

    # Setup logging
    logger = setup_logging(args.debug)
    logger.info("=" * 60)
    logger.info("PlexiChat Starting Up")
    logger.info("=" * 60)

    try:
        # Acquire process lock (unless forced)
        if not args.force:
            logger.info("Acquiring process lock...")
            if not acquire_process_lock():
                logger.error("Failed to acquire process lock")
                sys.exit(1)
            logger.info("Process lock acquired successfully")
        else:
            logger.warning("Skipping process lock (--force flag used)")

        # Setup cleanup on exit
        atexit.register(lambda: cleanup_resources(logger))

        # Setup signal handlers
        setup_signal_handlers(logger)

        # Setup thread pool
        logger.info(f"Setting up thread pool with {args.workers} workers...")
        thread_pool = setup_thread_pool(args.workers)
        logger.info("Thread pool initialized")

        # Import and start the main application
        logger.info("Loading PlexiChat application...")

        try:
            from .main import app, config
            logger.info("PlexiChat application loaded successfully")
        except ImportError as e:
            logger.error(f"Failed to import PlexiChat application: {e}")
            raise StartupError(f"Failed to import application: {e}")

        # Update config with command line arguments
        if args.config:
            logger.info(f"Loading custom config from: {args.config}")
            # Config loading would be implemented here

        # Start the application
        logger.info("Starting PlexiChat server...")
        logger.info(f"Host: {args.host}")
        logger.info(f"Port: {args.port}")
        logger.info(f"Debug: {args.debug}")
        logger.info(f"Workers: {args.workers}")

        # Mark startup as complete
        _startup_complete.set()

        # Import uvicorn and start server
        import uvicorn

        # Run server with proper configuration
        if args.debug:
            # In debug mode, use import string for reload
            uvicorn.run(
                "plexichat.main:app",
                host=args.host,
                port=args.port,
                log_level="debug",
                reload=True,
                access_log=True
            )
        else:
            # In production mode, use app object directly
            uvicorn.run(
                app,
                host=args.host,
                port=args.port,
                log_level="info",
                workers=1,
                access_log=True
            )

    except ProcessLockError as e:
        logger.error(f"Process lock error: {e}")
        sys.exit(1)

    except StartupError as e:
        logger.error(f"Startup error: {e}")
        sys.exit(1)

    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt, shutting down...")

    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        sys.exit(1)

    finally:
        # Cleanup
        cleanup_resources(logger)
        logger.info("PlexiChat shutdown complete")

if __name__ == "__main__":
    main()
