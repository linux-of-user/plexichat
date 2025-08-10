import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import urllib.request
import venv
import zipfile
from pathlib import Path
from typing import Dict, List

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
    logger.info(f"Updated version.json to {new_version}")

def fetch_github_releases(repo: str) -> List[Dict]:
    """Fetches release information from GitHub."""
    api_url = f"https://api.github.com/repos/{repo}/releases"
    try:
        with urllib.request.urlopen(api_url) as response:
            if response.status == 200:
                return json.loads(response.read().decode())
            else:
                logger.error(f"Error fetching releases: HTTP {response.status}")
                return []
    except Exception as e:
        logger.error(f"An error occurred: {e}")
        return []

def download_and_extract(url: str, dest_path: Path):
    """Downloads and extracts a tar.gz or zip file."""
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
    download_url = release["tarball_url"]
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

def main():
    # Add src to python path to allow imports
    sys.path.insert(0, str(Path("src").resolve()))
    try:
        from plexichat.core.logging import setup_logging
        logger = setup_logging()
    except ImportError:
        import logging
        logger = logging.getLogger("plexichat")
        logger.warning("Could not set up custom logging.")

    parser = argparse.ArgumentParser(
        description="PlexiChat Runner and Management Script.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python run.py                          # Start API server, WebUI, and CLI
  python run.py --nowebui --nocli        # Start API server only
  python run.py --noserver --nocli       # Start WebUI only
  python run.py setup --level full       # Setup full environment
  python run.py install --repo user/repo # Install from a custom repository
  python run.py clean --all              # Clean everything including the venv
  python run.py update                   # Update to the latest version
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

    parser.add_argument("--noserver", action="store_true", help="Do not run the API server.")
    parser.add_argument("--nowebui", action="store_true", help="Do not run the WebUI.")
    parser.add_argument("--nocli", action="store_true", help="Do not run the interactive CLI.")

    args = parser.parse_args()

    if hasattr(args, "func"):
        args.func(args)
    else:
        # Default action: run the application
        if not (VENV_DIR.exists() and Path("src").exists()):
            logger.error("Project not set up. Please run 'install' and 'setup'.")
            sys.exit(1)

        # Add src to python path to allow imports
        sys.path.insert(0, str(Path("src").resolve()))

        # Wrap imports in try...except
        try:
            from plexichat.main import app as main_app
            from plexichat.interfaces.web.main import app as webui_app
            from plexichat.core.unified_config import get_config
            import uvicorn
            import threading
        except ImportError as e:
            logger.error(f"Failed to import necessary modules: {e}")
            logger.warning("Please run 'python run.py setup' to install dependencies.")
            sys.exit(1)

        # Load configurations
        api_config = get_config("api", {})
        webui_config = get_config("webui", {})
        api_host = api_config.get("host", "0.0.0.0")
        api_port = api_config.get("port", 8000)
        webui_host = webui_config.get("host", "0.0.0.0")
        webui_port = webui_config.get("port", 8080)

        def run_server(app, host, port):
            uvicorn.run(app, host=host, port=port)

        threads = []

        if not args.noserver:
            logger.info(f"Starting API server in background on {api_host}:{api_port}...")
            server_thread = threading.Thread(target=run_server, args=(main_app, api_host, api_port), daemon=True)
            threads.append(server_thread)
            server_thread.start()

        if not args.nowebui:
            logger.info(f"Starting WebUI in background on {webui_host}:{webui_port}...")
            webui_thread = threading.Thread(target=run_server, args=(webui_app, webui_host, webui_port), daemon=True)
            threads.append(webui_thread)
            webui_thread.start()

        if not args.nocli:
            logger.info("Starting interactive CLI...")
            try:
                from plexichat.interfaces.cli.unified_cli import UnifiedCLI
                from plexichat.core.plugins.unified_plugin_manager import unified_plugin_manager
                import asyncio

                # Initialize plugin manager
                logger.info("Initializing plugin manager for CLI commands...")
                asyncio.run(unified_plugin_manager.initialize())

                # Create the main CLI application
                cli_builder = UnifiedCLI()
                cli_app = cli_builder.build_cli()

                # Get and add plugin commands
                logger.info("Loading plugin commands...")
                plugin_commands = unified_plugin_manager.plugin_commands
                if plugin_commands:
                    logger.info(f"Found {len(plugin_commands)} plugin commands. Adding to CLI.")
                    for name, command in plugin_commands.items():
                        cli_app.add_command(command, name=name)
                else:
                    logger.info("No plugin commands found.")

                # Run the CLI
                cli_app()

            except Exception as e:
                logger.error(f"CLI exited with an error: {e}", exc_info=True)
        else:
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

if __name__ == "__main__":
    main()