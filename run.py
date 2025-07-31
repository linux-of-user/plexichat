#!/usr/bin/env python3
"""
PlexiChat - Comprehensive Run Script
===================================

Advanced run script with intelligent environment setup, package manager fallbacks,
and comprehensive dependency management.
"""

import os
import sys
import subprocess
import argparse
import logging
import platform
import shutil
import venv
import json
import re
import tempfile
import urllib.request
import urllib.error
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from urllib.parse import urlparse

# Add the src directory to Python path
sys.path.insert(0, str(Path(__file__).parent / "src"))

# Version information
VERSION = "b.1.1-91"  # beta api v1 minor 1 build 91
GITHUB_REPO = "linux-of-user/plexichat"  # Actual GitHub repository
GITHUB_API_BASE = "https://api.github.com/repos"
GITHUB_RAW_BASE = "https://raw.githubusercontent.com"

class Colors:
    """ANSI color codes for terminal output."""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

class GitHubManager:
    """Manage GitHub operations for PlexiChat."""

    def __init__(self, repo: str = GITHUB_REPO):
        self.repo = repo
        self.api_base = f"{GITHUB_API_BASE}/{repo}"
        self.raw_base = f"{GITHUB_RAW_BASE}/{repo}"

    def get_latest_releases(self, limit: int = 10) -> List[Dict]:
        """Get latest releases from GitHub."""
        try:
            url = f"{self.api_base}/releases?per_page={limit}"

            # Create request with proper headers
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'PlexiChat-Installer/1.0')
            req.add_header('Accept', 'application/vnd.github.v3+json')

            with urllib.request.urlopen(req, timeout=10) as response:
                data = json.loads(response.read().decode())
                return data
        except urllib.error.HTTPError as e:
            print_colored(f"❌ HTTP Error {e.code}: {e.reason}", Colors.RED)
            return []
        except urllib.error.URLError as e:
            print_colored(f"❌ URL Error: {e.reason}", Colors.RED)
            return []
        except Exception as e:
            print_colored(f"❌ Failed to fetch releases: {e}", Colors.RED)
            return []

    def download_file(self, file_path: str, branch: str = "main", save_path: Optional[Path] = None) -> Optional[Path]:
        """Download a file from GitHub repository."""
        try:
            url = f"{self.raw_base}/{branch}/{file_path}"

            if save_path is None:
                save_path = Path(file_path).name

            print_colored(f"📥 Downloading {file_path} from GitHub...", Colors.BLUE)

            # Create request with proper headers
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'PlexiChat-Installer/1.0')

            with urllib.request.urlopen(req, timeout=30) as response:
                content = response.read()

            with open(save_path, 'wb') as f:
                f.write(content)

            print_colored(f"✅ Downloaded to {save_path}", Colors.GREEN)
            return Path(save_path)

        except urllib.error.HTTPError as e:
            print_colored(f"❌ HTTP Error {e.code}: {e.reason} for {file_path}", Colors.RED)
            return None
        except urllib.error.URLError as e:
            print_colored(f"❌ URL Error: {e.reason} for {file_path}", Colors.RED)
            return None
        except Exception as e:
            print_colored(f"❌ Failed to download {file_path}: {e}", Colors.RED)
            return None

    def get_release_by_tag(self, tag: str) -> Optional[Dict]:
        """Get specific release by tag."""
        try:
            url = f"{self.api_base}/releases/tags/{tag}"

            # Create request with proper headers
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'PlexiChat-Installer/1.0')
            req.add_header('Accept', 'application/vnd.github.v3+json')

            with urllib.request.urlopen(req, timeout=10) as response:
                return json.loads(response.read().decode())
        except urllib.error.HTTPError as e:
            print_colored(f"❌ HTTP Error {e.code}: {e.reason} for release {tag}", Colors.RED)
            return None
        except urllib.error.URLError as e:
            print_colored(f"❌ URL Error: {e.reason} for release {tag}", Colors.RED)
            return None
        except Exception as e:
            print_colored(f"❌ Failed to fetch release {tag}: {e}", Colors.RED)
            return None

class VersionManager:
    """Manage version information and comparisons."""

    @staticmethod
    def parse_version(version_str: str) -> Tuple[str, int, int, int]:
        """Parse version string like 'b.1.1-91' into components."""
        # Format: [prefix].[major].[minor]-[build]
        match = re.match(r'([a-zA-Z]*)\.?(\d+)\.(\d+)-(\d+)', version_str)
        if match:
            prefix, major, minor, build = match.groups()
            return prefix, int(major), int(minor), int(build)
        else:
            # Fallback parsing
            return "unknown", 0, 0, 0

    @staticmethod
    def compare_versions(v1: str, v2: str) -> int:
        """Compare two version strings. Returns -1, 0, or 1."""
        p1, maj1, min1, b1 = VersionManager.parse_version(v1)
        p2, maj2, min2, b2 = VersionManager.parse_version(v2)

        # Compare components in order
        for a, b in [(maj1, maj2), (min1, min2), (b1, b2)]:
            if a < b:
                return -1
            elif a > b:
                return 1
        return 0

    @staticmethod
    def get_current_version() -> str:
        """Get current version."""
        return VERSION

class InstallManager:
    """Manage installation of PlexiChat."""

    def __init__(self):
        self.github = GitHubManager()
        self.version_manager = VersionManager()

    def get_install_paths(self) -> Dict[str, Path]:
        """Get available installation paths."""
        paths = {}

        # Local directory (current directory)
        paths['local'] = Path.cwd()

        # User-specific paths
        if platform.system() == "Windows":
            paths['user'] = Path.home() / "AppData" / "Local" / "PlexiChat"
            paths['system'] = Path("C:") / "Program Files" / "PlexiChat"
        elif platform.system() == "Darwin":  # macOS
            paths['user'] = Path.home() / "Applications" / "PlexiChat"
            paths['system'] = Path("/Applications") / "PlexiChat"
        else:  # Linux
            paths['user'] = Path.home() / ".local" / "bin" / "plexichat"
            paths['system'] = Path("/usr/local/bin") / "plexichat"

        return paths

    def interactive_install(self) -> bool:
        """Interactive installation process."""
        print_colored("🚀 PlexiChat Interactive Installer", Colors.BLUE, bold=True)
        print_colored("=" * 50, Colors.CYAN)

        # Get available releases
        print_colored("📡 Fetching available versions from GitHub...", Colors.BLUE)
        releases = self.github.get_latest_releases(10)

        if not releases:
            print_colored("❌ No releases found. Using current version.", Colors.YELLOW)
            selected_version = VERSION
        else:
            print_colored("\n📋 Available versions:", Colors.GREEN, bold=True)
            for i, release in enumerate(releases):
                tag = release['tag_name']
                name = release['name']
                published = release['published_at'][:10]  # Just date
                print_colored(f"  {i+1}. {tag} - {name} (Published: {published})", Colors.CYAN)

            print_colored(f"  {len(releases)+1}. Current version ({VERSION})", Colors.YELLOW)

            while True:
                try:
                    choice = input(f"\n{Colors.BLUE}Select version (1-{len(releases)+1}): {Colors.END}")
                    choice_num = int(choice)

                    if 1 <= choice_num <= len(releases):
                        selected_version = releases[choice_num - 1]['tag_name']
                        break
                    elif choice_num == len(releases) + 1:
                        selected_version = VERSION
                        break
                    else:
                        print_colored("❌ Invalid choice. Please try again.", Colors.RED)
                except ValueError:
                    print_colored("❌ Please enter a valid number.", Colors.RED)

        # Get installation path
        paths = self.get_install_paths()
        print_colored(f"\n📁 Installation options:", Colors.GREEN, bold=True)
        path_options = list(paths.keys())

        for i, (key, path) in enumerate(paths.items()):
            status = "✅" if path.exists() or key == 'local' else "📁"
            print_colored(f"  {i+1}. {key.title()} - {path} {status}", Colors.CYAN)

        while True:
            try:
                choice = input(f"\n{Colors.BLUE}Select installation location (1-{len(paths)}): {Colors.END}")
                choice_num = int(choice)

                if 1 <= choice_num <= len(paths):
                    selected_path_key = path_options[choice_num - 1]
                    selected_path = paths[selected_path_key]
                    break
                else:
                    print_colored("❌ Invalid choice. Please try again.", Colors.RED)
            except ValueError:
                print_colored("❌ Please enter a valid number.", Colors.RED)

        # Confirm installation
        print_colored(f"\n📋 Installation Summary:", Colors.BLUE, bold=True)
        print_colored(f"  Version: {selected_version}", Colors.CYAN)
        print_colored(f"  Location: {selected_path}", Colors.CYAN)

        confirm = input(f"\n{Colors.YELLOW}Proceed with installation? (y/N): {Colors.END}")
        if confirm.lower() not in ['y', 'yes']:
            print_colored("❌ Installation cancelled.", Colors.YELLOW)
            return False

        # Perform installation
        return self._perform_install(selected_version, selected_path)

    def _perform_install(self, version: str, install_path: Path) -> bool:
        """Perform the actual installation."""
        try:
            # Create installation directory
            install_path.mkdir(parents=True, exist_ok=True)

            # Download run.py
            run_py_path = install_path / "run.py"

            if version == VERSION:
                # Copy current run.py
                import shutil
                current_run_py = Path(__file__)
                shutil.copy2(current_run_py, run_py_path)
                print_colored(f"✅ Copied current run.py to {run_py_path}", Colors.GREEN)
            else:
                # Download from GitHub
                downloaded = self.github.download_file("run.py", version, run_py_path)
                if not downloaded:
                    return False

            # Make executable on Unix systems
            if platform.system() != "Windows":
                os.chmod(run_py_path, 0o755)

            # Download requirements.txt if it doesn't exist
            req_path = install_path / "requirements.txt"
            if not req_path.exists():
                self.github.download_file("requirements.txt", version, req_path)

            print_colored(f"🎉 Installation completed successfully!", Colors.GREEN, bold=True)
            print_colored(f"📁 Installed to: {install_path}", Colors.CYAN)
            print_colored(f"🚀 Run with: python {run_py_path}", Colors.CYAN)

            return True

        except Exception as e:
            print_colored(f"❌ Installation failed: {e}", Colors.RED)
            return False

class PackageManager:
    """Intelligent package manager with OS-specific fallbacks."""

    def __init__(self):
        self.os_type = platform.system().lower()
        self.python_executable = sys.executable
        self.pip_commands = self._detect_pip_commands()
        self.system_package_managers = self._detect_system_package_managers()

    def _detect_pip_commands(self) -> List[str]:
        """Detect available pip commands in order of preference."""
        commands = []

        # Try different pip variations
        pip_variants = [
            f"{self.python_executable} -m pip",
            "pip3",
            "pip",
            "python3 -m pip",
            "python -m pip"
        ]

        for cmd in pip_variants:
            try:
                result = subprocess.run(
                    f"{cmd} --version",
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0:
                    commands.append(cmd)
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue

        return commands

    def _detect_system_package_managers(self) -> Dict[str, str]:
        """Detect available system package managers."""
        managers = {}

        # Common package managers by OS
        if self.os_type == "linux":
            linux_managers = {
                "apt": "apt-get install -y",
                "dnf": "dnf install -y",
                "yum": "yum install -y",
                "pacman": "pacman -S --noconfirm",
                "zypper": "zypper install -y",
                "apk": "apk add"
            }

            for manager, install_cmd in linux_managers.items():
                if shutil.which(manager):
                    managers[manager] = install_cmd

        elif self.os_type == "darwin":  # macOS
            if shutil.which("brew"):
                managers["brew"] = "brew install"
            if shutil.which("port"):
                managers["port"] = "port install"

        elif self.os_type == "windows":
            if shutil.which("choco"):
                managers["choco"] = "choco install -y"
            if shutil.which("winget"):
                managers["winget"] = "winget install"

        return managers

def setup_logging(verbose: bool = False):
    """Setup comprehensive logging."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format=f'{Colors.CYAN}%(asctime)s{Colors.END} - {Colors.BOLD}%(name)s{Colors.END} - %(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    )
    return logging.getLogger("PlexiChat")

def print_colored(message: str, color: str = Colors.WHITE, bold: bool = False):
    """Print colored message to terminal."""
    style = Colors.BOLD if bold else ""
    print(f"{style}{color}{message}{Colors.END}")

def check_python_version():
    """Check if Python version is compatible."""
    if sys.version_info < (3, 8):
        print_colored("❌ Error: Python 3.8 or higher is required", Colors.RED, bold=True)
        print_colored(f"   Current version: {sys.version}", Colors.YELLOW)
        sys.exit(1)

    print_colored(f"✅ Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro} detected", Colors.GREEN)

class RequirementsParser:
    """Parse requirements.txt with section markers and OS-specific fallbacks."""

    def __init__(self, requirements_file: Path):
        self.requirements_file = requirements_file
        self.sections = {}
        self.os_fallbacks = {}
        self._parse_requirements()

    def _parse_requirements(self):
        """Parse requirements file into sections."""
        if not self.requirements_file.exists():
            print_colored(f"❌ Requirements file not found: {self.requirements_file}", Colors.RED)
            return

        current_section = "default"
        current_os_manager = None

        with open(self.requirements_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()

                # Skip empty lines
                if not line:
                    continue

                # Check for section markers
                if line.startswith("# === ") and line.endswith(" ==="):
                    section_name = line.replace("# === ", "").replace(" ===", "").lower()
                    current_section = section_name
                    self.sections[current_section] = []
                    continue

                # Check for OS-specific fallback sections
                if line.startswith("# [") and "]" in line:
                    match = re.match(r"# \[(\w+)\]", line)
                    if match:
                        current_os_manager = match.group(1)
                        if current_os_manager not in self.os_fallbacks:
                            self.os_fallbacks[current_os_manager] = []
                        continue

                # Skip other comments
                if line.startswith("#"):
                    # Check if it's an OS fallback package
                    if current_os_manager and not line.startswith("# ==="):
                        package = line.lstrip("# ").strip()
                        if package:
                            self.os_fallbacks[current_os_manager].append(package)
                    continue

                # Add package to current section
                if current_section not in self.sections:
                    self.sections[current_section] = []

                # Handle conditional packages (platform-specific)
                if ";" in line:
                    package, condition = line.split(";", 1)
                    package = package.strip()
                    condition = condition.strip()

                    # Evaluate platform condition
                    if self._evaluate_platform_condition(condition):
                        self.sections[current_section].append(package)
                else:
                    self.sections[current_section].append(line)

    def _evaluate_platform_condition(self, condition: str) -> bool:
        """Evaluate platform-specific conditions."""
        current_platform = platform.system()

        if "platform_system" in condition:
            if "!=" in condition:
                excluded_platform = condition.split("!=")[1].strip().strip('"\'')
                return current_platform != excluded_platform
            elif "==" in condition:
                required_platform = condition.split("==")[1].strip().strip('"\'')
                return current_platform == required_platform

        return True

    def get_packages_for_level(self, level: str) -> List[str]:
        """Get packages for installation level."""
        packages = []

        # Always include default packages
        if "default" in self.sections:
            packages.extend(self.sections["default"])

        # Add minimal packages
        if "minimal installation" in self.sections:
            packages.extend(self.sections["minimal installation"])

        # Add full packages if requested
        if level in ["full", "developer"] and "full installation" in self.sections:
            packages.extend(self.sections["full installation"])

        # Add developer packages if requested
        if level == "developer" and "developer installation" in self.sections:
            packages.extend(self.sections["developer installation"])

        return list(set(packages))  # Remove duplicates

class EnvironmentManager:
    """Manage Python virtual environments."""

    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.venv_path = project_root / "venv"
        self.package_manager = PackageManager()

    def create_virtual_environment(self) -> bool:
        """Create virtual environment if it doesn't exist."""
        if self.venv_path.exists():
            print_colored("✅ Virtual environment already exists", Colors.GREEN)
            return True

        print_colored("🔧 Creating virtual environment...", Colors.BLUE, bold=True)

        try:
            venv.create(self.venv_path, with_pip=True)
            print_colored("✅ Virtual environment created successfully", Colors.GREEN)
            return True
        except Exception as e:
            print_colored(f"❌ Failed to create virtual environment: {e}", Colors.RED)
            return False

    def activate_virtual_environment(self):
        """Activate virtual environment by updating sys.path and executable."""
        if not self.venv_path.exists():
            return False

        # Update Python executable path
        if platform.system() == "Windows":
            python_exe = self.venv_path / "Scripts" / "python.exe"
            pip_exe = self.venv_path / "Scripts" / "pip.exe"
        else:
            python_exe = self.venv_path / "bin" / "python"
            pip_exe = self.venv_path / "bin" / "pip"

        if python_exe.exists():
            # Update package manager to use venv pip
            self.package_manager.python_executable = str(python_exe)
            self.package_manager.pip_commands = [f"{python_exe} -m pip", str(pip_exe)]

            print_colored("✅ Virtual environment activated", Colors.GREEN)
            return True

        return False
class DependencyInstaller:
    """Install dependencies with intelligent fallbacks."""

    def __init__(self, env_manager: EnvironmentManager, requirements_parser: RequirementsParser):
        self.env_manager = env_manager
        self.requirements_parser = requirements_parser
        self.package_manager = env_manager.package_manager
        self.failed_packages = []
        self.installed_packages = []

    def install_dependencies(self, level: str = "minimal", force: bool = False) -> bool:
        """Install dependencies for specified level."""
        print_colored(f"📦 Installing {level} dependencies...", Colors.BLUE, bold=True)

        packages = self.requirements_parser.get_packages_for_level(level)

        if not packages:
            print_colored("⚠️  No packages found to install", Colors.YELLOW)
            return True

        print_colored(f"Found {len(packages)} packages to install", Colors.CYAN)

        success = True
        for package in packages:
            if not self._install_single_package(package, force):
                success = False

        # Try to install failed packages using system package manager
        if self.failed_packages:
            print_colored(f"🔄 Attempting to install {len(self.failed_packages)} failed packages using system package manager...", Colors.YELLOW)
            self._install_system_fallbacks()

        # Final summary
        self._print_installation_summary()

        return success and len(self.failed_packages) == 0

    def _install_single_package(self, package: str, force: bool = False) -> bool:
        """Install a single package with retry logic."""
        package_name = package.split(">=")[0].split("==")[0].split("[")[0].strip()

        print_colored(f"  Installing {package_name}...", Colors.CYAN)

        for pip_cmd in self.package_manager.pip_commands:
            try:
                cmd = f"{pip_cmd} install {package}"
                if force:
                    cmd += " --force-reinstall"

                result = subprocess.run(
                    cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=300  # 5 minute timeout per package
                )

                if result.returncode == 0:
                    self.installed_packages.append(package_name)
                    print_colored(f"    ✅ {package_name} installed successfully", Colors.GREEN)
                    return True
                else:
                    print_colored(f"    ❌ Failed with {pip_cmd}: {result.stderr.strip()}", Colors.RED)

            except subprocess.TimeoutExpired:
                print_colored(f"    ⏰ Timeout installing {package_name} with {pip_cmd}", Colors.YELLOW)
            except Exception as e:
                print_colored(f"    ❌ Error with {pip_cmd}: {e}", Colors.RED)

        self.failed_packages.append(package_name)
        return False

    def _install_system_fallbacks(self):
        """Install packages using system package managers."""
        if not self.package_manager.system_package_managers:
            print_colored("⚠️  No system package managers available", Colors.YELLOW)
            return

        # Try to map failed packages to system packages
        for manager, install_cmd in self.package_manager.system_package_managers.items():
            if manager in self.requirements_parser.os_fallbacks:
                system_packages = self.requirements_parser.os_fallbacks[manager]

                print_colored(f"🔧 Trying {manager} package manager...", Colors.BLUE)

                for package in system_packages:
                    try:
                        cmd = f"sudo {install_cmd} {package}"
                        result = subprocess.run(
                            cmd,
                            shell=True,
                            capture_output=True,
                            text=True,
                            timeout=120
                        )

                        if result.returncode == 0:
                            print_colored(f"    ✅ {package} installed via {manager}", Colors.GREEN)
                        else:
                            print_colored(f"    ❌ Failed to install {package} via {manager}", Colors.RED)

                    except Exception as e:
                        print_colored(f"    ❌ Error installing {package} via {manager}: {e}", Colors.RED)

    def _print_installation_summary(self):
        """Print installation summary."""
        print_colored("\n📊 Installation Summary:", Colors.BLUE, bold=True)
        print_colored(f"  ✅ Successfully installed: {len(self.installed_packages)}", Colors.GREEN)
        print_colored(f"  ❌ Failed to install: {len(self.failed_packages)}", Colors.RED)

        if self.failed_packages:
            print_colored("  Failed packages:", Colors.YELLOW)
            for package in self.failed_packages:
                print_colored(f"    - {package}", Colors.RED)
def check_dependencies(env_manager: EnvironmentManager) -> bool:
    """Check if required dependencies are installed."""
    print_colored("🔍 Checking core dependencies...", Colors.BLUE)

    # Activate virtual environment for checking
    env_manager.activate_virtual_environment()

    required_packages = ["fastapi", "uvicorn"]
    missing_packages = []

    for package in required_packages:
        try:
            __import__(package)
            print_colored(f"  ✅ {package} is available", Colors.GREEN)
        except ImportError:
            missing_packages.append(package)
            print_colored(f"  ❌ {package} is missing", Colors.RED)

    if missing_packages:
        print_colored(f"⚠️  Missing {len(missing_packages)} required packages", Colors.YELLOW)
        return False

    print_colored("✅ All core dependencies are available", Colors.GREEN)
    return True

def handle_cache_command(args):
    """Handle cache management commands."""
    print_colored("🗂️  Cache Management", Colors.BLUE, bold=True)

    cache_dirs = [
        Path.home() / ".cache" / "plexichat",
        Path(__file__).parent / ".cache",
        Path(__file__).parent / "__pycache__",
        Path(__file__).parent / "src" / "__pycache__"
    ]

    if args.clear:
        print_colored("🧹 Clearing caches...", Colors.YELLOW)
        total_cleared = 0

        for cache_dir in cache_dirs:
            if cache_dir.exists():
                try:
                    if cache_dir.is_file():
                        cache_dir.unlink()
                        total_cleared += 1
                    else:
                        import shutil
                        shutil.rmtree(cache_dir)
                        total_cleared += 1
                    print_colored(f"  ✅ Cleared {cache_dir}", Colors.GREEN)
                except Exception as e:
                    print_colored(f"  ❌ Failed to clear {cache_dir}: {e}", Colors.RED)

        # Clear Python bytecode
        for root, dirs, files in os.walk(Path(__file__).parent):
            for file in files:
                if file.endswith('.pyc'):
                    try:
                        os.remove(Path(root) / file)
                        total_cleared += 1
                    except:
                        pass

        print_colored(f"🎉 Cleared {total_cleared} cache items", Colors.GREEN, bold=True)

    elif args.size:
        print_colored("📊 Cache sizes:", Colors.CYAN)
        total_size = 0

        for cache_dir in cache_dirs:
            if cache_dir.exists():
                size = get_directory_size(cache_dir)
                total_size += size
                print_colored(f"  {cache_dir}: {format_size(size)}", Colors.CYAN)

        print_colored(f"Total cache size: {format_size(total_size)}", Colors.BLUE, bold=True)

def handle_doctor_command(args):
    """Handle system diagnostics."""
    print_colored("🩺 PlexiChat System Diagnostics", Colors.BLUE, bold=True)
    print_colored("=" * 50, Colors.CYAN)

    issues = []

    # Check Python version
    print_colored("🐍 Checking Python version...", Colors.BLUE)
    if sys.version_info >= (3, 8):
        print_colored(f"  ✅ Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}", Colors.GREEN)
    else:
        issues.append("Python version too old (need 3.8+)")
        print_colored(f"  ❌ Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro} (need 3.8+)", Colors.RED)

    # Check required directories
    print_colored("📁 Checking directory structure...", Colors.BLUE)
    required_dirs = ["src", "src/plexichat"]
    for dir_name in required_dirs:
        dir_path = Path(__file__).parent / dir_name
        if dir_path.exists():
            print_colored(f"  ✅ {dir_name}/", Colors.GREEN)
        else:
            issues.append(f"Missing directory: {dir_name}")
            print_colored(f"  ❌ {dir_name}/ (missing)", Colors.RED)

    # Check requirements.txt
    print_colored("📋 Checking requirements.txt...", Colors.BLUE)
    req_file = Path(__file__).parent / "requirements.txt"
    if req_file.exists():
        print_colored("  ✅ requirements.txt found", Colors.GREEN)
    else:
        issues.append("requirements.txt missing")
        print_colored("  ❌ requirements.txt missing", Colors.RED)

    # Check virtual environment
    print_colored("🔧 Checking virtual environment...", Colors.BLUE)
    venv_path = Path(__file__).parent / "venv"
    if venv_path.exists():
        print_colored("  ✅ Virtual environment found", Colors.GREEN)
    else:
        print_colored("  ⚠️  No virtual environment (run 'python run.py setup')", Colors.YELLOW)

    # Check core dependencies
    print_colored("📦 Checking core dependencies...", Colors.BLUE)
    core_deps = ["fastapi", "uvicorn"]
    for dep in core_deps:
        try:
            __import__(dep)
            print_colored(f"  ✅ {dep}", Colors.GREEN)
        except ImportError:
            issues.append(f"Missing dependency: {dep}")
            print_colored(f"  ❌ {dep} (not installed)", Colors.RED)

    # Summary
    print_colored(f"\n📊 Diagnostic Summary:", Colors.BLUE, bold=True)
    if not issues:
        print_colored("🎉 All checks passed! System is healthy.", Colors.GREEN, bold=True)
    else:
        print_colored(f"⚠️  Found {len(issues)} issues:", Colors.YELLOW, bold=True)
        for issue in issues:
            print_colored(f"  • {issue}", Colors.RED)

        if args.fix:
            print_colored("\n🔧 Attempting to fix issues...", Colors.BLUE, bold=True)
            # Add auto-fix logic here
            print_colored("💡 Run 'python run.py setup --level full' to fix most issues", Colors.CYAN)

def get_directory_size(path: Path) -> int:
    """Get total size of directory in bytes."""
    total = 0
    try:
        for entry in path.rglob('*'):
            if entry.is_file():
                total += entry.stat().st_size
    except:
        pass
    return total

def format_size(bytes_size: int) -> str:
    """Format bytes into human readable format."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_size < 1024:
            return f"{bytes_size:.1f} {unit}"
        bytes_size /= 1024
    return f"{bytes_size:.1f} TB"

def handle_test_command(args, env_manager):
    """Handle test execution."""
    print_colored("🧪 Running PlexiChat Tests", Colors.BLUE, bold=True)

    # Activate virtual environment
    env_manager.activate_virtual_environment()

    test_commands = {
        'unit': ['python', '-m', 'pytest', 'tests/unit/', '-v'],
        'integration': ['python', '-m', 'pytest', 'tests/integration/', '-v'],
        'security': ['python', 'pentest.py'],
        'all': ['python', '-m', 'pytest', 'tests/', '-v']
    }

    if args.coverage:
        if args.type in ['unit', 'integration', 'all']:
            test_commands[args.type].extend(['--cov=src', '--cov-report=html', '--cov-report=term'])

    cmd = test_commands.get(args.type, test_commands['all'])

    print_colored(f"🚀 Running {args.type} tests...", Colors.CYAN)
    print_colored(f"Command: {' '.join(cmd)}", Colors.YELLOW)

    try:
        result = subprocess.run(cmd, cwd=Path(__file__).parent)
        if result.returncode == 0:
            print_colored("✅ All tests passed!", Colors.GREEN, bold=True)
        else:
            print_colored("❌ Some tests failed", Colors.RED, bold=True)

        if args.coverage and args.type != 'security':
            coverage_dir = Path(__file__).parent / "htmlcov"
            if coverage_dir.exists():
                print_colored(f"📊 Coverage report: {coverage_dir / 'index.html'}", Colors.CYAN)

    except FileNotFoundError:
        print_colored("❌ Test runner not found. Install with: pip install pytest pytest-cov", Colors.RED)
    except Exception as e:
        print_colored(f"❌ Test execution failed: {e}", Colors.RED)

def start_server(host="0.0.0.0", port=8000, reload=True):
    """Start the PlexiChat server."""
    print_colored("🚀 Starting PlexiChat Server...", Colors.BLUE, bold=True)
    print_colored(f"   Host: {host}", Colors.CYAN)
    print_colored(f"   Port: {port}", Colors.CYAN)
    print_colored(f"   Reload: {reload}", Colors.CYAN)
    print()

    try:
        # Change to the directory containing the src folder
        os.chdir(Path(__file__).parent)

        # Start the server using uvicorn
        cmd = [
            sys.executable, "-m", "uvicorn",
            "src.plexichat.main:app",
            "--host", host,
            "--port", str(port),
        ]

        if reload:
            cmd.append("--reload")

        print_colored("📡 Server starting...", Colors.GREEN, bold=True)
        print_colored(f"🔗 Access the API at: http://{host}:{port}", Colors.CYAN)
        print_colored(f"📚 API Documentation: http://{host}:{port}/docs", Colors.CYAN)
        print()

        # Run the command
        subprocess.run(cmd)

    except KeyboardInterrupt:
        print_colored("\n🛑 Server stopped by user", Colors.YELLOW, bold=True)
    except Exception as e:
        print_colored(f"❌ Error starting server: {e}", Colors.RED, bold=True)
        sys.exit(1)

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description=f"PlexiChat Server v{VERSION} - Comprehensive Environment Setup and Server Management",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run.py                          # Start server with minimal setup
  python run.py setup --level full       # Setup full environment
  python run.py setup --level developer  # Setup developer environment
  python run.py install                  # Interactive installation from GitHub
  python run.py version                  # Show version information
  python run.py cache --clear            # Clear all caches
  python run.py --host 127.0.0.1 --port 8080  # Start on custom host/port
        """
    )

    # Subcommands
    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Install command
    install_parser = subparsers.add_parser('install', help='Interactive installation from GitHub')
    install_parser.add_argument('--version', help='Specific version to install')
    install_parser.add_argument('--path', help='Installation path')
    install_parser.add_argument('--force', action='store_true', help='Force installation')

    # Setup command
    setup_parser = subparsers.add_parser('setup', help='Setup Python environment and dependencies')
    setup_parser.add_argument('--level', choices=['minimal', 'full', 'developer'],
                             default='minimal', help='Installation level')
    setup_parser.add_argument('--force', action='store_true',
                             help='Force reinstall all packages')
    setup_parser.add_argument('--no-venv', action='store_true',
                             help='Skip virtual environment creation')
    setup_parser.add_argument('--clean', action='store_true',
                             help='Clean install (remove existing venv first)')

    # Version command
    version_parser = subparsers.add_parser('version', help='Show version information')
    version_parser.add_argument('--check', action='store_true', help='Check for updates')

    # Cache command
    cache_parser = subparsers.add_parser('cache', help='Manage caches')
    cache_parser.add_argument('--clear', action='store_true', help='Clear all caches')
    cache_parser.add_argument('--size', action='store_true', help='Show cache sizes')

    # Test command
    test_parser = subparsers.add_parser('test', help='Run tests')
    test_parser.add_argument('--type', choices=['unit', 'integration', 'security', 'all'],
                           default='all', help='Type of tests to run')
    test_parser.add_argument('--coverage', action='store_true', help='Generate coverage report')

    # Doctor command (system diagnostics)
    doctor_parser = subparsers.add_parser('doctor', help='Run system diagnostics')
    doctor_parser.add_argument('--fix', action='store_true', help='Attempt to fix issues')

    # Server arguments (for default command)
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind to")
    parser.add_argument("--no-reload", action="store_true", help="Disable auto-reload")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--version", action="version", version=f"PlexiChat {VERSION}")

    args = parser.parse_args()

    # Setup logging
    logger = setup_logging(args.verbose)

    # Handle commands that don't need full initialization first
    if args.command == 'install':
        install_manager = InstallManager()
        success = install_manager.interactive_install()
        sys.exit(0 if success else 1)

    elif args.command == 'version':
        print_colored(f"PlexiChat {VERSION}", Colors.BLUE, bold=True)
        if hasattr(args, 'check') and args.check:
            github = GitHubManager()
            releases = github.get_latest_releases(1)
            if releases:
                latest = releases[0]['tag_name']
                comparison = VersionManager.compare_versions(VERSION, latest)
                if comparison < 0:
                    print_colored(f"🆕 Update available: {latest}", Colors.GREEN)
                elif comparison > 0:
                    print_colored(f"🚀 You're ahead: {latest} is the latest release", Colors.YELLOW)
                else:
                    print_colored(f"✅ You're up to date!", Colors.GREEN)
        sys.exit(0)

    elif args.command == 'cache':
        handle_cache_command(args)
        sys.exit(0)

    elif args.command == 'doctor':
        handle_doctor_command(args)
        sys.exit(0)

    # Check Python version for commands that need it
    check_python_version()

    # Initialize managers
    project_root = Path(__file__).parent
    requirements_file = project_root / "requirements.txt"

    env_manager = EnvironmentManager(project_root)
    requirements_parser = RequirementsParser(requirements_file)

    if args.command == 'setup':
        print_colored("🔧 Setting up PlexiChat environment...", Colors.BLUE, bold=True)

        # Clean install if requested
        if hasattr(args, 'clean') and args.clean:
            print_colored("🧹 Performing clean install...", Colors.YELLOW)
            venv_path = env_manager.venv_path
            if venv_path.exists():
                import shutil
                shutil.rmtree(venv_path)
                print_colored("  ✅ Removed existing virtual environment", Colors.GREEN)

        # Create virtual environment
        if not args.no_venv:
            if not env_manager.create_virtual_environment():
                print_colored("❌ Failed to create virtual environment", Colors.RED)
                sys.exit(1)

            if not env_manager.activate_virtual_environment():
                print_colored("❌ Failed to activate virtual environment", Colors.RED)
                sys.exit(1)

        # Install dependencies
        installer = DependencyInstaller(env_manager, requirements_parser)
        if not installer.install_dependencies(args.level, args.force):
            print_colored("⚠️  Some packages failed to install, but continuing...", Colors.YELLOW)

        print_colored("🎉 Environment setup completed!", Colors.GREEN, bold=True)
        print_colored("Run 'python run.py' to start the server", Colors.CYAN)

    elif args.command == 'test':
        handle_test_command(args, env_manager)
        sys.exit(0)

    else:
        # Default: start server
        # Activate virtual environment if it exists
        env_manager.activate_virtual_environment()

        # Check dependencies
        if not check_dependencies(env_manager):
            print_colored("💡 Run 'python run.py setup' to install dependencies", Colors.CYAN)
            sys.exit(1)

        start_server(
            host=args.host,
            port=args.port,
            reload=not args.no_reload
        )

if __name__ == "__main__":
    main()