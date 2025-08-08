import argparse
import json
import os
import re
import subprocess
import venv

from pathlib import Path

from src.plexichat.infrastructure.utils.utilities import ConfigManager
from src.plexichat.core.logging import Colors

VERSION = "1.0.0"
GITHUB_REPO = "user/repo"
config_manager = ConfigManager()


class GitHubManager:
    """Manage GitHub repository."""

    def __init__(self, repo: str):
        self.raw_base = f"https://raw.githubusercontent.com/{repo}/main"
        self.api_base = f"https://api.github.com/{repo}/releases"

    def get_latest_releases(self, count: int) -> list[dict]:
        """Get latest releases from GitHub."""
        try:
            url = f"{self.api_base}/releases?per_page={count}"

            # Create request with proper headers
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'PlexiChat-Installer/1.0')

            with urllib.request.urlopen(req, timeout=10) as response:
                data = json.loads(response.read().decode())
                return data
        except urllib.error.HTTPError as e:
            print_colored(f"[ERROR] HTTP Error {e.code}: {e.reason}", Colors.RED)
            return []
        except urllib.error.URLError as e:
            print_colored(f"[ERROR] URL Error: {e.reason}", Colors.RED)
            return []
        except Exception as e:
            print_colored(f"[ERROR] Failed to fetch releases: {e}", Colors.RED)
            return []

    def download_file(self, file_path: str, branch: str = "main", save_path: Optional[Path] = None) -> Optional[Path]:
        """Download a file from GitHub repository."""
        try:
            url = f"{self.raw_base}/{branch}/{file_path}"

            if save_path is None:
                save_path = Path(file_path).name

            print_colored(f"[DOWNLOAD] Downloading {file_path} from GitHub...", Colors.BLUE)

            # Create request with proper headers
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'PlexiChat-Installer/1.0')

            with urllib.request.urlopen(req, timeout=30) as response:
                content = response.read()

            with open(save_path, 'wb') as f:
                f.write(content)

            print_colored(f"[OK] Downloaded to {save_path}", Colors.GREEN)
            return Path(save_path)

        except urllib.error.HTTPError as e:
            print_colored(f"[ERROR] HTTP Error {e.code}: {e.reason} for {file_path}", Colors.RED)
            return None
        except urllib.error.URLError as e:
            print_colored(f"[ERROR] URL Error: {e.reason} for {file_path}", Colors.RED)
            return None
        except Exception as e:
            print_colored(f"[ERROR] Failed to download {file_path}: {e}", Colors.RED)
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
            print_colored(f"[ERROR] HTTP Error {e.code}: {e.reason} for release {tag}", Colors.RED)
            return None
        except urllib.error.URLError as e:
            print_colored(f"[ERROR] URL Error: {e.reason} for release {tag}", Colors.RED)
            return None
        except Exception as e:
            print_colored(f"[ERROR] Failed to fetch release {tag}: {e}", Colors.RED)
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

    def __init__(self, repo: str = GITHUB_REPO):
        self.github = GitHubManager(repo)
        self.version_manager = VersionManager()
        self.repo = repo

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

    def interactive_install(self, version: Optional[str] = None, path: Optional[str] = None,
                           branch: str = "main", force: bool = False) -> bool:
        """Interactive installation process."""
        print_colored("[START] PlexiChat Interactive Installer", Colors.BLUE, bold=True)
        print_colored("=" * 50, Colors.CYAN)
        print_colored(f"[PACKAGE] Repository: {self.repo}", Colors.CYAN)
        print_colored(f"[BRANCH] Branch: {branch}", Colors.CYAN)

        # Get available releases
        print_colored("[FETCH] Fetching available versions from GitHub...", Colors.BLUE)
        releases = self.github.get_latest_releases(10)

        if not releases:
            print_colored("[ERROR] No releases found. Using current version.", Colors.YELLOW)
            selected_version = VERSION
        else:
            print_colored("\n[LIST] Available versions:", Colors.GREEN, bold=True)
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
                        print_colored("[ERROR] Invalid choice. Please try again.", Colors.RED)
                except ValueError:
                    print_colored("[ERROR] Please enter a valid number.", Colors.RED)

        # Get installation path
        paths = self.get_install_paths()
        print_colored(f"\n[FOLDER] Installation options:", Colors.GREEN, bold=True)
        path_options = list(paths.keys())

        for i, (key, path) in enumerate(paths.items()):
            status = "[OK]" if path.exists() or key == 'local' else "[FOLDER]"
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
                    print_colored("[ERROR] Invalid choice. Please try again.", Colors.RED)
            except ValueError:
                print_colored("[ERROR] Please enter a valid number.", Colors.RED)

        # Confirm installation
        print_colored(f"\n[LIST] Installation Summary:", Colors.BLUE, bold=True)
        print_colored(f"  Version: {selected_version}", Colors.CYAN)
        print_colored(f"  Location: {selected_path}", Colors.CYAN)

        confirm = input(f"\n{Colors.YELLOW}Proceed with installation? (y/N): {Colors.END}")
        if confirm.lower() not in ['y', 'yes']:
            print_colored("[ERROR] Installation cancelled.", Colors.YELLOW)
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
                print_colored(f"[OK] Copied current run.py to {run_py_path}", Colors.GREEN)
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

            print_colored(f"[SUCCESS] Installation completed successfully!", Colors.GREEN, bold=True)
            print_colored(f"[FOLDER] Installed to: {install_path}", Colors.CYAN)
            print_colored(f"[START] Run with: python {run_py_path}", Colors.CYAN)

            return True

        except Exception as e:
            print_colored(f"[ERROR] Installation failed: {e}", Colors.RED)
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
    """Setup comprehensive logging with colorization."""
    try:
        # Try to import the unified logging system
        sys.path.insert(0, str(Path(__file__).parent / "src"))
        from plexichat.core.logging import get_logger, initialize_logging

        # Initialize the unified logging system
        config = {
            "level": "DEBUG" if verbose else "INFO",
            "console_colors": True,
            "console_enabled": True,
            "file_enabled": True
        }
        initialize_logging(config)

        return get_logger("PlexiChat.run")

    except ImportError:
        # Fallback to basic logging with colors
        level = logging.DEBUG if verbose else logging.INFO

        # Create a custom formatter with colors
        class ColoredFormatter(logging.Formatter):
            COLORS = {
                'DEBUG': Colors.CYAN,
                'INFO': Colors.GREEN,
                'WARNING': Colors.YELLOW,
                'ERROR': Colors.RED,
                'CRITICAL': Colors.MAGENTA
            }

            def format(self, record):
                color = self.COLORS.get(record.levelname, Colors.WHITE)
                record.levelname = f"{color}{record.levelname}{Colors.END}"
                record.name = f"{Colors.BOLD}{record.name}{Colors.END}"
                return super().format(record)

        # Setup basic logging with colors
        handler = logging.StreamHandler()
        handler.setFormatter(ColoredFormatter(
            fmt=f'{Colors.CYAN}%(asctime)s{Colors.END} - %(name)s - %(levelname)s - %(message)s',
            datefmt='%H:%M:%S'
        ))

        logger = logging.getLogger("PlexiChat")
        logger.setLevel(level)
        logger.addHandler(handler)

        return logger

def print_colored(message: str, color: str = Colors.WHITE, bold: bool = False):
    """Print colored message to terminal using logging system."""
    # Get the logger
    logger = logging.getLogger("PlexiChat.run")

    # Map colors to log levels
    if color == Colors.RED:
        logger.error(message)
    elif color == Colors.YELLOW:
        logger.warning(message)
    elif color == Colors.GREEN:
        logger.info(message)
    elif color == Colors.BLUE or color == Colors.CYAN:
        logger.info(message)
    else:
        logger.info(message)

def check_python_version():
    """Check if Python version is compatible."""
    if sys.version_info < (3, 8):
        print_colored("[ERROR] Error: Python 3.8 or higher is required", Colors.RED, bold=True)
        print_colored(f"   Current version: {sys.version}", Colors.YELLOW)
        sys.exit(1)

    print_colored(f"[OK] Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro} detected", Colors.GREEN)

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
            print_colored(f"[ERROR] Requirements file not found: {self.requirements_file}", Colors.RED)
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
            print_colored("[OK] Virtual environment already exists", Colors.GREEN)
            return True

        print_colored("[SETUP] Creating virtual environment...", Colors.BLUE, bold=True)

        try:
            venv.create(self.venv_path, with_pip=True)
            print_colored("[OK] Virtual environment created successfully", Colors.GREEN)
            return True
        except Exception as e:
            print_colored(f"[ERROR] Failed to create virtual environment: {e}", Colors.RED)
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

            print_colored("[OK] Virtual environment activated", Colors.GREEN)
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
        print_colored(f"[PACKAGE] Installing {level} dependencies...", Colors.BLUE, bold=True)

        packages = self.requirements_parser.get_packages_for_level(level)

        if not packages:
            print_colored("[WARNING]  No packages found to install", Colors.YELLOW)
            return True

        print_colored(f"Found {len(packages)} packages to install", Colors.CYAN)

        success = True
        for package in packages:
            if not self._install_single_package(package, force):
                success = False

        # Try to install failed packages using system package manager
        if self.failed_packages:
            print_colored(f"[UPDATE] Attempting to install {len(self.failed_packages)} failed packages using system package manager...", Colors.YELLOW)
            self._install_system_fallbacks()

        # Final summary
        self._print_installation_summary()

        return success and len(self.failed_packages) == 0

    def _install_single_package(self, package: str, force: bool = False) -> bool:
        """Install a single package with retry logic."""
        # Better package name parsing to avoid creating junk directories
        import re

        # Extract package name more carefully
        package_name = re.split(r'[>=<!=\[\s]', package.strip())[0].strip()

        # Skip empty or invalid package names
        if not package_name or package_name.isdigit() or len(package_name) < 2:
            print_colored(f"  [SKIP] Invalid package name: {package}", Colors.YELLOW)
            return True

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
                    timeout=300,  # 5 minute timeout per package
                    cwd=self.env_manager.project_root  # Ensure we're in the right directory
                )

                if result.returncode == 0:
                    self.installed_packages.append(package_name)
                    print_colored(f"    [OK] {package_name} installed successfully", Colors.GREEN)
                    return True
                else:
                    print_colored(f"    [ERROR] Failed with {pip_cmd}: {result.stderr.strip()}", Colors.RED)

            except subprocess.TimeoutExpired:
                print_colored(f"    [TIMEOUT] Timeout installing {package_name} with {pip_cmd}", Colors.YELLOW)
            except Exception as e:
                print_colored(f"    [ERROR] Error with {pip_cmd}: {e}", Colors.RED)

        self.failed_packages.append(package_name)
        return False

    def _install_system_fallbacks(self):
        """Install packages using system package managers."""
        if not self.package_manager.system_package_managers:
            print_colored("[WARNING]  No system package managers available", Colors.YELLOW)
            return

        # Try to map failed packages to system packages
        for manager, install_cmd in self.package_manager.system_package_managers.items():
            if manager in self.requirements_parser.os_fallbacks:
                system_packages = self.requirements_parser.os_fallbacks[manager]

                print_colored(f"[SETUP] Trying {manager} package manager...", Colors.BLUE)

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
                            print_colored(f"    [OK] {package} installed via {manager}", Colors.GREEN)
                        else:
                            print_colored(f"    [ERROR] Failed to install {package} via {manager}", Colors.RED)

                    except Exception as e:
                        print_colored(f"    [ERROR] Error installing {package} via {manager}: {e}", Colors.RED)

    def _print_installation_summary(self):
        """Print installation summary."""
        print_colored("\n[STATS] Installation Summary:", Colors.BLUE, bold=True)
        print_colored(f"  [OK] Successfully installed: {len(self.installed_packages)}", Colors.GREEN)
        print_colored(f"  [ERROR] Failed to install: {len(self.failed_packages)}", Colors.RED)

        if self.failed_packages:
            print_colored("  Failed packages:", Colors.YELLOW)
            for package in self.failed_packages:
                print_colored(f"    - {package}", Colors.RED)
def check_dependencies(env_manager: EnvironmentManager) -> bool:
    """Check if required dependencies are installed."""
    print_colored("[CHECK] Checking core dependencies...", Colors.BLUE)

    # Activate virtual environment for checking
    env_manager.activate_virtual_environment()

    required_packages = ["fastapi", "uvicorn"]
    missing_packages = []

    for package in required_packages:
        try:
            __import__(package)
            print_colored(f"  [OK] {package} is available", Colors.GREEN)
        except ImportError:
            missing_packages.append(package)
            print_colored(f"  [ERROR] {package} is missing", Colors.RED)

    if missing_packages:
        print_colored(f"[WARNING]  Missing {len(missing_packages)} required packages", Colors.YELLOW)
        return False

    print_colored("[OK] All core dependencies are available", Colors.GREEN)
    return True

def handle_clean_command(args):
    """Handle clean command."""
    print_colored("[CLEAN] PlexiChat Cleanup", Colors.BLUE, bold=True)

    cache_dirs = [
        Path.home() / ".cache" / "plexichat",
        Path(__file__).parent / ".cache",
        Path(__file__).parent / "__pycache__",
        Path(__file__).parent / "src" / "__pycache__"
    ]

    print_colored("[CLEAR]  Clearing caches and temporary files...", Colors.YELLOW)
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
                print_colored(f"  [OK] Cleared {cache_dir}", Colors.GREEN)
            except Exception as e:
                print_colored(f"  [ERROR] Failed to clear {cache_dir}: {e}", Colors.RED)

    # Clear Python bytecode
    for root, dirs, files in os.walk(Path(__file__).parent):
        for file in files:
            if file.endswith('.pyc'):
                try:
                    os.remove(Path(root) / file)
                    total_cleared += 1
                except:
                    pass

    if args.all:
        print_colored("[REMOVE] Performing complete cleanup (including virtual environment)...", Colors.RED)
        venv_path = Path(__file__).parent / "venv"
        if venv_path.exists():
            try:
                import shutil
                shutil.rmtree(venv_path)
                print_colored("  [OK] Removed virtual environment", Colors.GREEN)
                print_colored("  [WARNING]  You'll need to run 'python run.py setup' again", Colors.YELLOW)
                total_cleared += 1
            except Exception as e:
                print_colored(f"  [ERROR] Failed to remove virtual environment: {e}", Colors.RED)

    print_colored(f"[SUCCESS] Cleanup completed! Cleared {total_cleared} items", Colors.GREEN, bold=True)

def handle_update_command(args):
    """Handle update command."""
    print_colored("[UPDATE] PlexiChat Update Manager", Colors.BLUE, bold=True)

    # Check if we're in a full installation or just run.py
    project_root = Path(__file__).parent
    is_full_install = (project_root / "src").exists() and (project_root / ".git").exists()

    if not is_full_install:
        print_colored("[WARNING]  Update command is designed for full installations.", Colors.YELLOW)
        print_colored("[TIP] Use 'python run.py install' to get the latest version instead.", Colors.CYAN)
        return

    print_colored("[CHECK] Checking for updates...", Colors.BLUE)

    # Get current and latest versions
    current_version = VERSION
    github = GitHubManager(args.repo if hasattr(args, 'repo') else GITHUB_REPO)
    releases = github.get_latest_releases(1)

    if not releases:
        print_colored("[ERROR] Failed to check for updates", Colors.RED)
        return

    latest_version = releases[0]['tag_name']

    print_colored(f"[LIST] Current version: {current_version}", Colors.CYAN)
    print_colored(f"[LIST] Latest version: {latest_version}", Colors.CYAN)

    if not args.force and VersionManager.compare_versions(current_version, latest_version) >= 0:
        print_colored("[OK] You're already up to date!", Colors.GREEN)
        return

    print_colored(f"[START] Updating to {latest_version}...", Colors.GREEN)

    # Update version.json and changelog
    update_version_files(latest_version)

    # Git operations
    try:
        subprocess.run(["git", "fetch", "origin"], check=True, cwd=project_root)
        subprocess.run(["git", "checkout", args.branch], check=True, cwd=project_root)
        subprocess.run(["git", "pull", "origin", args.branch], check=True, cwd=project_root)
        print_colored("[OK] Update completed successfully!", Colors.GREEN, bold=True)
    except subprocess.CalledProcessError as e:
        print_colored(f"[ERROR] Update failed: {e}", Colors.RED)



def update_version_files(version: str):
    """Update version.json and changelog files."""
    project_root = Path(__file__).parent

    # Update version.json
    version_file = project_root / "version.json"
    if version_file.exists():
        try:
            with open(version_file, 'r') as f:
                version_data = json.load(f)
            version_data['version'] = version
            with open(version_file, 'w') as f:
                json.dump(version_data, f, indent=2)
            print_colored(f"[OK] Updated version.json to {version}", Colors.GREEN)
        except Exception as e:
            print_colored(f"[WARNING]  Failed to update version.json: {e}", Colors.YELLOW)

    # Update changelog
    changelog_file = project_root / "changelog.json"
    if changelog_file.exists():
        try:
            with open(changelog_file, 'r') as f:
                changelog_data = json.load(f)

            # Add new entry
            new_entry = {
                "version": version,
                "date": "2025-07-31",  # You might want to use actual date
                "changes": [f"Updated to version {version}"]
            }

            if 'releases' not in changelog_data:
                changelog_data['releases'] = []

            changelog_data['releases'].insert(0, new_entry)

            with open(changelog_file, 'w') as f:
                json.dump(changelog_data, f, indent=2)
            print_colored(f"[OK] Updated changelog.json", Colors.GREEN)
        except Exception as e:
            print_colored(f"[WARNING]  Failed to update changelog.json: {e}", Colors.YELLOW)

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

def setup_project_structure():
    """Setup project directory structure."""
    try:
        directories = [
            "config",
            "data/config",
            "data/logs",
            "data/uploads",
            "data/cache",
            "data/backups",
            "data/runtime",
            "data/storage",
            "logs",
            "tests/reports",
            "tests/fixtures",
            "plugins/installed",
            "plugins/cache",
            "temp",
            "certs"
        ]

        for directory in directories:
            Path(directory).mkdir(parents=True, exist_ok=True)

        print_colored("[SETUP] Created project directory structure", Colors.GREEN)

        # Create initial config files if they don't exist
        config_files = {
            "data/config/rate_limits.json": {
                "enabled": True,
                "per_ip_requests_per_minute": 60,
                "per_user_requests_per_minute": 120,
                "global_requests_per_minute": 10000
            },
            "data/config/security.json": {
                "csrf_protection": True,
                "xss_protection": True,
                "rate_limiting": True
            }
        }

        for config_file, default_config in config_files.items():
            config_path = Path(config_file)
            if not config_path.exists():
                import json
                with open(config_path, 'w') as f:
                    json.dump(default_config, f, indent=2)
                print_colored(f"  [OK] Created {config_file}", Colors.GREEN)

    except Exception as e:
        print_colored(f"[WARN] Failed to setup project structure: {e}", Colors.YELLOW)

def verify_installation(env_manager):
    """Verify the installation is working correctly."""
    print_colored("[VERIFY] Verifying installation...", Colors.BLUE)

    try:
        # Test Python version
        result = env_manager.run_command([env_manager.python_path, '--version'])
        if result.returncode == 0:
            version = result.stdout.strip()
            print_colored(f"  [OK] Python: {version}", Colors.GREEN)

        # Test critical imports
        critical_imports = [
            'fastapi',
            'uvicorn',
            'pydantic',
            'bcrypt',
            'psutil'
        ]

        for module in critical_imports:
            try:
                result = env_manager.run_command([
                    env_manager.python_path, '-c', f'import {module}; print(f"{module} imported successfully")'
                ])
                if result.returncode == 0:
                    print_colored(f"  [OK] {module} import successful", Colors.GREEN)
                else:
                    print_colored(f"  [WARN] {module} import failed", Colors.YELLOW)
            except Exception:
                print_colored(f"  [ERROR] {module} import error", Colors.RED)

        print_colored("[VERIFY] Installation verification completed", Colors.GREEN)

    except Exception as e:
        print_colored(f"[WARN] Installation verification failed: {e}", Colors.YELLOW)

def handle_test_command(args, env_manager):
    """Handle test execution."""
    print_colored("[TEST] Running PlexiChat Tests", Colors.BLUE, bold=True)

    # Activate virtual environment
    env_manager.activate_virtual_environment()

    test_commands = {
        'basic': ['python', 'src/plexichat/tests/test_basic_functionality.py'],
        'unit': ['python', '-m', 'pytest', 'tests/unit/', '-v'],
        'integration': ['python', '-m', 'pytest', 'tests/integration/', '-v'],
        'security': ['python', 'src/plexichat/tests/security/test_comprehensive_security.py'],
        'protection': ['python', 'src/plexichat/tests/test_protection_simple.py'],
        'performance': ['python', 'src/plexichat/tests/performance/test_rate_limiting_performance.py'],
        'simple': ['python', 'src/plexichat/tests/simple_security_test.py'],
        'all': ['python', '-m', 'pytest', 'tests/', '-v']
    }

    if args.coverage:
        if args.type in ['unit', 'integration', 'all']:
            test_commands[args.type].extend(['--cov=src', '--cov-report=html', '--cov-report=term'])

    cmd = test_commands.get(args.type, test_commands['all'])

    print_colored(f"[START] Running {args.type} tests...", Colors.CYAN)
    print_colored(f"Command: {' '.join(cmd)}", Colors.YELLOW)

    try:
        result = subprocess.run(cmd, cwd=Path(__file__).parent)
        if result.returncode == 0:
            print_colored("[OK] All tests passed!", Colors.GREEN, bold=True)
        else:
            print_colored("[ERROR] Some tests failed", Colors.RED, bold=True)

        if args.coverage and args.type != 'security':
            coverage_dir = Path(__file__).parent / "htmlcov"
            if coverage_dir.exists():
                print_colored(f"[STATS] Coverage report: {coverage_dir / 'index.html'}", Colors.CYAN)

    except FileNotFoundError:
        print_colored("[ERROR] Test runner not found. Install with: pip install pytest pytest-cov", Colors.RED)
    except Exception as e:
        print_colored(f"[ERROR] Test execution failed: {e}", Colors.RED)

def start_server(host="0.0.0.0", port=8000, reload=True):
    """Start the PlexiChat API server."""
    print_colored("[START] Starting PlexiChat API Server...", Colors.BLUE, bold=True)
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

        print_colored("[FETCH] API Server starting...", Colors.GREEN, bold=True)
        print_colored(f"[LINK] Access the API at: http://{host}:{port}", Colors.CYAN)
        print_colored(f"[DOCS] API Documentation: http://{host}:{port}/docs", Colors.CYAN)
        print()

        # Run the command
        try:
            subprocess.run(cmd)
        except KeyboardInterrupt:
            print_colored("\n[STOP] Server stopped by user", Colors.YELLOW, bold=True)
            sys.exit(0)

    except KeyboardInterrupt:
        print_colored("\n[STOP] Server stopped by user", Colors.YELLOW, bold=True)
    except Exception as e:
        print_colored(f"[ERROR] Error starting server: {e}", Colors.RED, bold=True)
        sys.exit(1)

def start_webui_server(host="0.0.0.0", port=8080):
    """Start the PlexiChat WebUI server."""
    print_colored("[WEB] Starting PlexiChat WebUI Server...", Colors.BLUE, bold=True)
    print_colored(f"   Host: {host}", Colors.CYAN)
    print_colored(f"   Port: {port}", Colors.CYAN)
    print()

    try:
        # Change to the directory containing the src folder
        os.chdir(Path(__file__).parent)

        # Start the WebUI server
        cmd = [
            sys.executable, "-m", "uvicorn",
            "src.plexichat.interfaces.web.main:app",
            "--host", host,
            "--port", str(port),
        ]

        print_colored("[WEB] WebUI Server starting...", Colors.GREEN, bold=True)
        print_colored(f"[LINK] Access the WebUI at: http://{host}:{port}", Colors.CYAN)
        print()

        # Run the command
        try:
            subprocess.run(cmd)
        except KeyboardInterrupt:
            print_colored("\n[STOP] WebUI Server stopped by user", Colors.YELLOW, bold=True)
            sys.exit(0)

    except KeyboardInterrupt:
        print_colored("\n[STOP] WebUI Server stopped by user", Colors.YELLOW, bold=True)
    except Exception as e:
        print_colored(f"[ERROR] Error starting WebUI server: {e}", Colors.RED, bold=True)
        sys.exit(1)

def start_cli():
    """Start the PlexiChat CLI system."""
    print_colored("[CLI]  Starting Interactive CLI...", Colors.GREEN)
    print_colored("[TIP] Type 'help' for available commands, 'exit' to quit", Colors.CYAN)
    print()

    try:
        # Import and start the CLI system
        sys.path.insert(0, str(Path(__file__).parent / "src"))
        from plexichat.interfaces.cli.main_cli import main as cli_main
        cli_main()
    except ImportError as e:
        print_colored(f"[WARNING]  CLI system not available: {e}", Colors.YELLOW)
        print_colored("[LIST] Use 'python run.py --help' for other options.", Colors.CYAN)
    except Exception as e:
        print_colored(f"[ERROR] CLI error: {e}", Colors.RED)
        print_colored("[LIST] Use 'python run.py --help' for other options.", Colors.CYAN)

def start_servers(host="0.0.0.0", port=8000, webui_port=8080, reload=True):
    """Start both API server and WebUI server."""
    print_colored("[START] Starting PlexiChat with API Server and WebUI", Colors.BLUE, bold=True)
    print_colored(f"   API Host: {host}:{port}", Colors.CYAN)
    print_colored(f"   WebUI Host: {host}:{webui_port}", Colors.CYAN)
    print_colored(f"   Reload: {reload}", Colors.CYAN)
    print()

    import threading
    import time

    try:
        # Change to the directory containing the src folder
        os.chdir(Path(__file__).parent)

        # Start API server in background thread
        def start_api():
            cmd = [
                sys.executable, "-m", "uvicorn",
                "src.plexichat.main:app",
                "--host", host,
                "--port", str(port),
            ]
            if reload:
                cmd.append("--reload")
            try:
                subprocess.run(cmd)
            except KeyboardInterrupt:
                print_colored("\n[STOP] API Server stopped by user", Colors.YELLOW, bold=True)
                return

        # Start WebUI server in background thread
        def start_webui():
            time.sleep(2)  # Give API server time to start
            cmd = [
                sys.executable, "-m", "uvicorn",
                "src.plexichat.interfaces.web.main:app",
                "--host", host,
                "--port", str(webui_port),
            ]
            try:
                subprocess.run(cmd)
            except KeyboardInterrupt:
                print_colored("\n[STOP] WebUI Server stopped by user", Colors.YELLOW, bold=True)
                return

        print_colored("[FETCH] Starting API Server...", Colors.GREEN)
        api_thread = threading.Thread(target=start_api, daemon=True)
        api_thread.start()

        print_colored("[WEB] Starting WebUI Server...", Colors.GREEN)
        webui_thread = threading.Thread(target=start_webui, daemon=True)
        webui_thread.start()

        print_colored(f"[LINK] API Server: http://{host}:{port}", Colors.CYAN)
        print_colored(f"[DOCS] API Documentation: http://{host}:{port}/docs", Colors.CYAN)
        print_colored(f"[WEB] WebUI: http://{host}:{webui_port}", Colors.CYAN)
        print()

        # Keep main thread alive
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print_colored("\n[STOP] Servers stopped by user", Colors.YELLOW, bold=True)

    except Exception as e:
        print_colored(f"[ERROR] Error starting servers: {e}", Colors.RED, bold=True)
        sys.exit(1)

def start_full_system(host="0.0.0.0", port=8000, webui_port=8080, reload=True, enable_cli=True):
    """Start API server, WebUI server, and interactive CLI."""
    print_colored("[START] Starting PlexiChat Full System", Colors.BLUE, bold=True)
    print_colored(f"   API Host: {host}:{port}", Colors.CYAN)
    print_colored(f"   WebUI Host: {host}:{webui_port}", Colors.CYAN)
    print_colored(f"   Interactive CLI: {'Enabled' if enable_cli else 'Disabled'}", Colors.CYAN)
    print_colored(f"   Reload: {reload}", Colors.CYAN)
    print()

    import threading
    import time

    try:
        # Change to the directory containing the src folder
        os.chdir(Path(__file__).parent)

        # Start API server in background thread
        def start_api():
            cmd = [
                sys.executable, "-m", "uvicorn",
                "src.plexichat.main:app",
                "--host", host,
                "--port", str(port),
            ]
            if reload:
                cmd.append("--reload")
            try:
                subprocess.run(cmd)
            except KeyboardInterrupt:
                print_colored("\n[STOP] API Server stopped by user", Colors.YELLOW, bold=True)
                return

        # Start WebUI server in background thread
        def start_webui():
            time.sleep(2)  # Give API server time to start
            cmd = [
                sys.executable, "-m", "uvicorn",
                "src.plexichat.interfaces.web.main:app",
                "--host", host,
                "--port", str(webui_port),
            ]
            try:
                subprocess.run(cmd)
            except KeyboardInterrupt:
                print_colored("\n[STOP] WebUI Server stopped by user", Colors.YELLOW, bold=True)
                return

        # Start CLI in main thread
        def start_cli():
            time.sleep(3)  # Give servers time to start
            try:
                # Import and start the CLI system
                sys.path.insert(0, str(Path(__file__).parent / "src"))
                from plexichat.interfaces.cli.main_cli import main as cli_main
                print_colored("[CLI]  Starting Interactive CLI...", Colors.GREEN)
                print_colored("[TIP] Type 'help' for available commands, 'exit' to quit", Colors.CYAN)
                print()
                cli_main()
            except ImportError as e:
                print_colored(f"[WARNING]  CLI system not available: {e}", Colors.YELLOW)
                print_colored("[LIST] Servers are running. Press Ctrl+C to stop.", Colors.CYAN)
                try:
                    while True:
                        time.sleep(1)
                except KeyboardInterrupt:
                    pass
            except Exception as e:
                print_colored(f"[ERROR] CLI error: {e}", Colors.RED)
                print_colored("[LIST] Servers are running. Press Ctrl+C to stop.", Colors.CYAN)
                try:
                    while True:
                        time.sleep(1)
                except KeyboardInterrupt:
                    pass

        print_colored("[FETCH] Starting API Server...", Colors.GREEN)
        api_thread = threading.Thread(target=start_api, daemon=True)
        api_thread.start()

        print_colored("[WEB] Starting WebUI Server...", Colors.GREEN)
        webui_thread = threading.Thread(target=start_webui, daemon=True)
        webui_thread.start()

        print_colored(f"[LINK] API Server: http://{host}:{port}", Colors.CYAN)
        print_colored(f"[DOCS] API Documentation: http://{host}:{port}/docs", Colors.CYAN)
        print_colored(f"[WEB] WebUI: http://{host}:{webui_port}", Colors.CYAN)
        print()

        if enable_cli:
            # Start CLI in main thread
            start_cli()
        else:
            # Keep main thread alive
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print_colored("\n[STOP] System stopped by user", Colors.YELLOW, bold=True)

    except KeyboardInterrupt:
        print_colored("\n[STOP] System stopped by user", Colors.YELLOW, bold=True)
    except Exception as e:
        print_colored(f"[ERROR] Error starting system: {e}", Colors.RED, bold=True)
        sys.exit(1)

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description=f"PlexiChat Server v{VERSION} - Comprehensive Environment Setup and Server Management",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run.py                          # Start API server and WebUI
  python run.py --nowebui                # Start API server only
  python run.py --noserver               # Start WebUI only
  python run.py setup --level full       # Setup full environment
  python run.py install                  # Interactive installation from GitHub
  python run.py install --repo user/repo # Install from custom repository
  python run.py clean                    # Clean caches and temporary files
  python run.py clean --all              # Clean everything including venv
  python run.py update                   # Update to latest version

  python run.py --host 127.0.0.1 --port 8080 --webui-port 8081  # Custom ports
        """
    )

    # Subcommands
    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Install command
    install_parser = subparsers.add_parser('install', help='Interactive installation from GitHub')
    install_parser.add_argument('--version', help='Specific version to install')
    install_parser.add_argument('--path', help='Installation path')
    install_parser.add_argument('--repo', default=config_manager.get("github.repo"),
                               help=f'GitHub repository (default: {config_manager.get("github.repo")})')
    install_parser.add_argument('--branch', default=config_manager.get("github.default_branch"),
                               help=f'Git branch to use (default: {config_manager.get("github.default_branch")})')
    install_parser.add_argument('--force', action='store_true', help='Force installation')

    # Setup command
    setup_parser = subparsers.add_parser('setup', help='Setup Python environment and dependencies')
    setup_parser.add_argument('--level', choices=['minimal', 'full', 'developer', 'testing'],
                             default=config_manager.get("installation.default_level"), help='Installation level')
    setup_parser.add_argument('--force', action='store_true',
                             help='Force reinstall all packages')
    setup_parser.add_argument('--clean', action='store_true',
                             help='Clean install (remove existing venv)')
    setup_parser.add_argument('--test-deps', action='store_true',
                             help='Install testing dependencies')
    setup_parser.add_argument('--security-deps', action='store_true',
                             help='Install security testing dependencies')
    setup_parser.add_argument('--performance-deps', action='store_true',
                             help='Install performance testing dependencies')
    setup_parser.add_argument('--no-venv', action='store_true',
                             help='Skip virtual environment creation')

    # Version command
    version_parser = subparsers.add_parser('version', help='Show version information')
    version_parser.add_argument('--check', action='store_true', help='Check for updates')

    # Clean command (replaces cache)
    clean_parser = subparsers.add_parser('clean', help='Clean caches and temporary files')
    clean_parser.add_argument('--all', action='store_true', help='Clean everything including virtual environment')

    # Update command
    update_parser = subparsers.add_parser('update', help='Update PlexiChat to latest version')
    update_parser.add_argument('--version', help='Specific version to update to')
    update_parser.add_argument('--repo', default=config_manager.get("github.repo"), help='GitHub repository')
    update_parser.add_argument('--branch', default=config_manager.get("github.default_branch"), help='Git branch to use')
    update_parser.add_argument('--force', action='store_true', help='Force update even if same version')





    # Test command
    test_parser = subparsers.add_parser('test', help='Run tests')
    test_parser.add_argument('--type', choices=['basic', 'unit', 'integration', 'security', 'protection', 'performance', 'simple', 'all'],
                           default='basic', help='Type of tests to run')
    test_parser.add_argument('--coverage', action='store_true', help='Generate coverage report')

    # Load configuration from YAML file
    yaml_config = load_yaml_config()
    network_config = yaml_config.get('network', {})
    default_host = network_config.get('host', 'localhost')
    default_api_port = network_config.get('api_port', 8000)
    default_web_port = network_config.get('web_port', 8080)

    # Server arguments (for default command)
    parser.add_argument("--host", default=default_host, help=f"Host to bind to (default: {default_host})")
    parser.add_argument("--port", type=int, default=default_api_port, help=f"API server port (default: {default_api_port})")
    parser.add_argument("--webui-port", type=int, default=default_web_port, help=f"WebUI port (default: {default_web_port})")
    parser.add_argument("--no-reload", action="store_true", help="Disable auto-reload")
    parser.add_argument("--noserver", action="store_true", help="Don't start API server")
    parser.add_argument("--nowebui", action="store_true", help="Don't start WebUI server")
    parser.add_argument("--nocli", action="store_true", help="Don't start interactive CLI")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--version", action="version", version=f"PlexiChat {VERSION}")

    args = parser.parse_args()

    # Setup logging
    logger = setup_logging(args.verbose)

    # Handle commands that don't need full initialization first
    if args.command == 'install':
        install_manager = InstallManager(args.repo if hasattr(args, 'repo') else GITHUB_REPO)
        success = install_manager.interactive_install(
            version=getattr(args, 'version', None),
            path=getattr(args, 'path', None),
            branch=getattr(args, 'branch', 'main'),
            force=getattr(args, 'force', False)
        )
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
                    print_colored(f"[NEW] Update available: {latest}", Colors.GREEN)
                elif comparison > 0:
                    print_colored(f"[START] You're ahead: {latest} is the latest release", Colors.YELLOW)
                else:
                    print_colored(f"[OK] You're up to date!", Colors.GREEN)
        sys.exit(0)

    elif args.command == 'clean':
        handle_clean_command(args)
        sys.exit(0)

    elif args.command == 'update':
        handle_update_command(args)
        sys.exit(0)





    # Check Python version for commands that need it
    check_python_version()

    # Initialize managers
    project_root = Path(__file__).parent
    requirements_file = project_root / "requirements.txt"

    env_manager = EnvironmentManager(project_root)
    requirements_parser = RequirementsParser(requirements_file)

    if args.command == 'setup':
        print_colored("[SETUP] Setting up PlexiChat environment...", Colors.BLUE, bold=True)

        # Clean install if requested
        if hasattr(args, 'clean') and args.clean:
            print_colored("[CLEAN] Performing clean install...", Colors.YELLOW)
            venv_path = env_manager.venv_path
            if venv_path.exists():
                import shutil
                shutil.rmtree(venv_path)
                print_colored("  [OK] Removed existing virtual environment", Colors.GREEN)

        # Create virtual environment
        if not args.no_venv:
            if not env_manager.create_virtual_environment():
                print_colored("[ERROR] Failed to create virtual environment", Colors.RED)
                sys.exit(1)

            if not env_manager.activate_virtual_environment():
                print_colored("[ERROR] Failed to activate virtual environment", Colors.RED)
                sys.exit(1)

        # Install dependencies
        installer = DependencyInstaller(env_manager, requirements_parser)
        if not installer.install_dependencies(args.level, args.force):
            print_colored("[WARNING]  Some packages failed to install, but continuing...", Colors.YELLOW)

        # Install additional dependencies based on flags
        additional_packages = []

        if hasattr(args, 'test_deps') and args.test_deps:
            print_colored("[SETUP] Installing testing dependencies...", Colors.BLUE)
            additional_packages.extend([
                'pytest>=7.0.0',
                'pytest-asyncio>=0.21.0',
                'pytest-cov>=4.0.0',
                'httpx>=0.24.0',  # For FastAPI testing
                'faker>=18.0.0'   # For generating test data
            ])

        if hasattr(args, 'security_deps') and args.security_deps:
            print_colored("[SETUP] Installing security testing dependencies...", Colors.BLUE)
            additional_packages.extend([
                'bandit>=1.7.0',      # Security linter
                'safety>=2.3.0',      # Vulnerability scanner
                'semgrep>=1.0.0'      # Static analysis
            ])

        if hasattr(args, 'performance_deps') and args.performance_deps:
            print_colored("[SETUP] Installing performance testing dependencies...", Colors.BLUE)
            additional_packages.extend([
                'locust>=2.0.0',      # Load testing
                'memory-profiler>=0.60.0',  # Memory profiling
                'py-spy>=0.3.0'       # Performance profiling
            ])

        # Install additional packages
        if additional_packages:
            for package in additional_packages:
                try:
                    result = env_manager.run_command([env_manager.pip_path, 'install', package])
                    if result.returncode == 0:
                        print_colored(f"  [OK] Installed {package}", Colors.GREEN)
                    else:
                        print_colored(f"  [WARN] Failed to install {package}", Colors.YELLOW)
                except Exception as e:
                    print_colored(f"  [ERROR] Error installing {package}: {e}", Colors.RED)

                # Setup directories and initial configuration
        setup_project_structure()

        print_colored("[SUCCESS] Environment setup completed!", Colors.GREEN, bold=True)
        print_colored("Run 'python run.py' to start the server", Colors.CYAN)
        print_colored("Run 'python run.py test' to run tests", Colors.CYAN)

    elif args.command == 'test':
        handle_test_command(args, env_manager)
        sys.exit(0)

    else:
        # Default: start server and WebUI
        # Activate virtual environment if it exists
        env_manager.activate_virtual_environment()

        # Check dependencies
        if not check_dependencies(env_manager):
            print_colored("[TIP] Run 'python run.py setup' to install dependencies", Colors.CYAN)
            sys.exit(1)

        # Start servers and CLI based on flags
        if not args.noserver and not args.nowebui and not args.nocli:
            print_colored("[START] Starting PlexiChat with API server, WebUI, and CLI", Colors.BLUE, bold=True)
            start_full_system(
                host=args.host,
                port=args.port,
                webui_port=args.webui_port,
                reload=not args.no_reload,
                enable_cli=True
            )
        elif not args.noserver and not args.nowebui:
            print_colored("[START] Starting PlexiChat with API server and WebUI", Colors.BLUE, bold=True)