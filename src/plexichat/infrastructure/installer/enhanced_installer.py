import logging
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple

            import tempfile

#!/usr/bin/env python3
"""
PlexiChat Enhanced Dependency Installer

Multi-system, multi-Python version compatible installer with fallback options.
Supports installation from:
- PyPI (primary)
- System package repositories (fallback)
- Source installation (last resort)
- Conda/Mamba (if available)

Features:
- Cross-platform compatibility (Windows, Linux, macOS)
- Multiple Python version support (3.8+)
- Intelligent fallback mechanisms
- User prompts for alternative installation methods
- Dependency conflict resolution
- Installation verification
"""

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class InstallMethod(Enum):
    """Available installation methods."""
    PYPI = "pypi"
    SYSTEM = "system"
    CONDA = "conda"
    SOURCE = "source"


class PlatformType(Enum):
    """Supported platforms."""
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    UNKNOWN = "unknown"


@dataclass
class PackageInfo:
    """Information about a package and its installation options."""
    name: str
    pypi_name: str
    version: Optional[str] = None
    system_packages: Dict[str, str] = None  # platform -> package name
    conda_name: Optional[str] = None
    source_url: Optional[str] = None
    required: bool = True
    description: str = ""


class EnhancedInstaller:
    """Enhanced dependency installer with multiple fallback options."""
    
    def __init__(self):
        self.platform = self._detect_platform()
        self.python_version = sys.version_info
        self.package_managers = self._detect_package_managers()
        self.failed_packages = []
        self.installed_packages = []
        
    def _detect_platform(self) -> PlatformType:
        """Detect the current platform."""
        system = platform.system().lower()
        if system == "windows":
            return PlatformType.WINDOWS
        elif system == "linux":
            return PlatformType.LINUX
        elif system == "darwin":
            return PlatformType.MACOS
        else:
            return PlatformType.UNKNOWN
    
    def _detect_package_managers(self) -> Dict[str, bool]:
        """Detect available package managers."""
        managers = {
            'pip': shutil.which('pip') is not None,
            'conda': shutil.which('conda') is not None,
            'mamba': shutil.which('mamba') is not None,
            'apt': shutil.which('apt-get') is not None,
            'yum': shutil.which('yum') is not None,
            'dnf': shutil.which('dnf') is not None,
            'pacman': shutil.which('pacman') is not None,
            'brew': shutil.which('brew') is not None,
            'choco': shutil.which('choco') is not None,
            'winget': shutil.which('winget') is not None,
        }
        
        logger.info(f"Detected package managers: {[k for k, v in managers.items() if v]}")
        return managers
    
    def _run_command(self, cmd: List[str], capture_output: bool = True, timeout: int = 300) -> Tuple[bool, str]:
        """Run a command and return success status and output."""
        try:
            result = subprocess.run(
                cmd, 
                capture_output=capture_output, 
                text=True, 
                timeout=timeout,
                check=False
            )
            return result.returncode == 0, result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            logger.error(f"Command timed out: {' '.join(cmd)}")
            return False, "Command timed out"
        except Exception as e:
            logger.error(f"Command failed: {' '.join(cmd)} - {e}")
            return False, str(e)
    
    def _check_python_compatibility(self) -> bool:
        """Check if Python version is compatible."""
        if self.python_version < (3, 8):
            logger.error(f"Python 3.8+ required, found {self.python_version}")
            return False
        
        logger.info(f"Python {self.python_version} is compatible")
        return True
    
    def _install_via_pip(self, package: PackageInfo) -> bool:
        """Install package via pip."""
        if not self.package_managers.get('pip', False):
            return False
        
        package_spec = package.pypi_name
        if package.version:
            package_spec += f"=={package.version}"
        
        cmd = [sys.executable, '-m', 'pip', 'install', package_spec]
        success, output = self._run_command(cmd)
        
        if success:
            logger.info(f"Successfully installed {package.name} via pip")
            return True
        else:
            logger.warning(f"Failed to install {package.name} via pip: {output}")
            return False
    
    def _install_via_system(self, package: PackageInfo) -> bool:
        """Install package via system package manager."""
        if not package.system_packages:
            return False
        
        platform_key = self.platform.value
        if platform_key not in package.system_packages:
            return False
        
        system_package = package.system_packages[platform_key]
        
        # Try different package managers based on platform
        if self.platform == PlatformType.LINUX:
            if self.package_managers.get('apt'):
                cmd = ['sudo', 'apt-get', 'install', '-y', system_package]
            elif self.package_managers.get('dnf'):
                cmd = ['sudo', 'dnf', 'install', '-y', system_package]
            elif self.package_managers.get('yum'):
                cmd = ['sudo', 'yum', 'install', '-y', system_package]
            elif self.package_managers.get('pacman'):
                cmd = ['sudo', 'pacman', '-S', '--noconfirm', system_package]
            else:
                return False
        elif self.platform == PlatformType.MACOS:
            if self.package_managers.get('brew'):
                cmd = ['brew', 'install', system_package]
            else:
                return False
        elif self.platform == PlatformType.WINDOWS:
            if self.package_managers.get('choco'):
                cmd = ['choco', 'install', '-y', system_package]
            elif self.package_managers.get('winget'):
                cmd = ['winget', 'install', system_package]
            else:
                return False
        else:
            return False
        
        success, output = self._run_command(cmd)
        
        if success:
            logger.info(f"Successfully installed {package.name} via system package manager")
            return True
        else:
            logger.warning(f"Failed to install {package.name} via system: {output}")
            return False
    
    def _install_via_conda(self, package: PackageInfo) -> bool:
        """Install package via conda/mamba."""
        conda_cmd = None
        if self.package_managers.get('mamba'):
            conda_cmd = 'mamba'
        elif self.package_managers.get('conda'):
            conda_cmd = 'conda'
        else:
            return False
        
        package_name = package.conda_name or package.pypi_name
        cmd = [conda_cmd, 'install', '-y', package_name]
        
        success, output = self._run_command(cmd)
        
        if success:
            logger.info(f"Successfully installed {package.name} via {conda_cmd}")
            return True
        else:
            logger.warning(f"Failed to install {package.name} via {conda_cmd}: {output}")
            return False
    
    def _install_from_source(self, package: PackageInfo) -> bool:
        """Install package from source."""
        if not package.source_url:
            return False
        
        logger.info(f"Attempting to install {package.name} from source: {package.source_url}")
        
        # This is a simplified source installation
        # In practice, you'd need more sophisticated handling
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                # Clone or download source
                if package.source_url.endswith('.git'):
                    cmd = ['git', 'clone', package.source_url, temp_dir]
                    success, _ = self._run_command(cmd)
                    if not success:
                        return False
                
                # Install from source
                setup_py = from pathlib import Path
Path(temp_dir) / 'setup.py'
                if setup_py.exists():
                    cmd = [sys.executable, str(setup_py), 'install']
                    success, output = self._run_command(cmd, timeout=600)
                    
                    if success:
                        logger.info(f"Successfully installed {package.name} from source")
                        return True
                    else:
                        logger.warning(f"Failed to install {package.name} from source: {output}")
                        return False
        except Exception as e:
            logger.error(f"Source installation failed for {package.name}: {e}")
            return False
        
        return False
    
    def _prompt_user_for_alternative(self, package: PackageInfo, failed_methods: List[InstallMethod]) -> Optional[InstallMethod]:
        """Prompt user to try alternative installation methods."""
        available_methods = []
        
        if InstallMethod.SYSTEM not in failed_methods and package.system_packages:
            available_methods.append(InstallMethod.SYSTEM)
        
        if InstallMethod.CONDA not in failed_methods and (self.package_managers.get('conda') or self.package_managers.get('mamba')):
            available_methods.append(InstallMethod.CONDA)
        
        if InstallMethod.SOURCE not in failed_methods and package.source_url:
            available_methods.append(InstallMethod.SOURCE)
        
        if not available_methods:
            return None
        
        print(f"\n Failed to install {package.name} ({package.description})")
        print("Would you like to try an alternative installation method?")
        
        for i, method in enumerate(available_methods, 1):
            method_desc = {
                InstallMethod.SYSTEM: f"System package manager ({self._get_system_package_manager()})",
                InstallMethod.CONDA: "Conda/Mamba",
                InstallMethod.SOURCE: "Install from source code"
            }
            print(f"  {i}. {method_desc[method]}")
        
        print(f"  {len(available_methods) + 1}. Skip this package")
        print(f"  {len(available_methods) + 2}. Abort installation")
        
        while True:
            try:
                choice = input(f"\nEnter your choice (1-{len(available_methods) + 2}): ").strip()
                choice_num = int(choice)
                
                if 1 <= choice_num <= len(available_methods):
                    return available_methods[choice_num - 1]
                elif choice_num == len(available_methods) + 1:
                    return None  # Skip
                elif choice_num == len(available_methods) + 2:
                    sys.exit(1)  # Abort
                else:
                    print("Invalid choice. Please try again.")
            except (ValueError, KeyboardInterrupt):
                print("Invalid input. Please enter a number.")
    
    def _get_system_package_manager(self) -> str:
        """Get the name of the system package manager."""
        if self.platform == PlatformType.LINUX:
            if self.package_managers.get('apt'):
                return "apt"
            elif self.package_managers.get('dnf'):
                return "dnf"
            elif self.package_managers.get('yum'):
                return "yum"
            elif self.package_managers.get('pacman'):
                return "pacman"
        elif self.platform == PlatformType.MACOS:
            if self.package_managers.get('brew'):
                return "brew"
        elif self.platform == PlatformType.WINDOWS:
            if self.package_managers.get('choco'):
                return "chocolatey"
            elif self.package_managers.get('winget'):
                return "winget"
        
        return "unknown"

    def install_package(self, package: PackageInfo) -> bool:
        """Install a single package with fallback options."""
        logger.info(f"Installing {package.name}: {package.description}")

        failed_methods = []

        # Try pip first (primary method)
        if self._install_via_pip(package):
            self.installed_packages.append(package.name)
            return True
        failed_methods.append(InstallMethod.PYPI)

        # Try alternative methods with user prompts
        while True:
            method = self._prompt_user_for_alternative(package, failed_methods)

            if method is None:
                # User chose to skip
                logger.warning(f"Skipping {package.name}")
                if package.required:
                    self.failed_packages.append(package.name)
                return False

            success = False
            if method == InstallMethod.SYSTEM:
                success = self._install_via_system(package)
            elif method == InstallMethod.CONDA:
                success = self._install_via_conda(package)
            elif method == InstallMethod.SOURCE:
                success = self._install_from_source(package)

            if success:
                self.installed_packages.append(package.name)
                return True
            else:
                failed_methods.append(method)
                if len(failed_methods) >= 4:  # All methods failed
                    break

        # All methods failed
        logger.error(f"Failed to install {package.name} using all available methods")
        if package.required:
            self.failed_packages.append(package.name)
        return False

    def install_packages(self, packages: List[PackageInfo]) -> bool:
        """Install multiple packages."""
        if not self._check_python_compatibility():
            return False

        logger.info(f"Starting installation of {len(packages)} packages")
        logger.info(f"Platform: {self.platform.value}")
        logger.info(f"Python: {self.python_version}")

        total_packages = len(packages)
        for i, package in enumerate(packages, 1):
            logger.info(f"[{i}/{total_packages}] Processing {package.name}")
            self.install_package(package)

        # Summary
        print(f"\n{'='*60}")
        print("INSTALLATION SUMMARY")
        print(f"{'='*60}")
        print(f" Successfully installed: {len(self.installed_packages)} packages")
        if self.installed_packages:
            for pkg in self.installed_packages:
                print(f"   - {pkg}")

        if self.failed_packages:
            print(f"\n Failed to install: {len(self.failed_packages)} packages")
            for pkg in self.failed_packages:
                print(f"   - {pkg}")
            print("\n  Some required packages failed to install.")
            print("The application may not work correctly.")
            return False
        else:
            print("\n All packages installed successfully!")
            return True


def get_plexichat_packages() -> List[PackageInfo]:
    """Get the list of PlexiChat packages with installation options."""
    return [
        PackageInfo(
            name="FastAPI",
            pypi_name="fastapi",
            version="0.115.12",
            system_packages={
                "linux": "python3-fastapi",
                "macos": "fastapi",
            },
            conda_name="fastapi",
            description="Modern web framework for building APIs"
        ),
        PackageInfo(
            name="Uvicorn",
            pypi_name="uvicorn[standard]",
            version="0.31.0",
            system_packages={
                "linux": "python3-uvicorn",
                "macos": "uvicorn",
            },
            conda_name="uvicorn",
            description="ASGI server for FastAPI"
        ),
        PackageInfo(
            name="SQLAlchemy",
            pypi_name="sqlalchemy",
            version="2.0.31",
            system_packages={
                "linux": "python3-sqlalchemy",
                "macos": "sqlalchemy",
            },
            conda_name="sqlalchemy",
            description="SQL toolkit and ORM"
        ),
        PackageInfo(
            name="Pydantic",
            pypi_name="pydantic[email]",
            version="2.5.3",
            system_packages={
                "linux": "python3-pydantic",
                "macos": "pydantic",
            },
            conda_name="pydantic",
            description="Data validation using Python type hints"
        ),
        PackageInfo(
            name="Cryptography",
            pypi_name="cryptography",
            version="42.0.5",
            system_packages={
                "linux": "python3-cryptography",
                "macos": "cryptography",
                "windows": "cryptography"
            },
            conda_name="cryptography",
            description="Cryptographic library for Python"
        ),
        PackageInfo(
            name="Requests",
            pypi_name="requests",
            version="2.32.3",
            system_packages={
                "linux": "python3-requests",
                "macos": "requests",
            },
            conda_name="requests",
            description="HTTP library for Python"
        ),
        PackageInfo(
            name="PyYAML",
            pypi_name="pyyaml",
            version="6.0.1",
            system_packages={
                "linux": "python3-yaml",
                "macos": "pyyaml",
            },
            conda_name="pyyaml",
            description="YAML parser and emitter"
        ),
        PackageInfo(
            name="Rich",
            pypi_name="rich",
            version="13.7.1",
            system_packages={
                "linux": "python3-rich",
                "macos": "rich",
            },
            conda_name="rich",
            description="Rich text and beautiful formatting"
        ),
        PackageInfo(
            name="Typer",
            pypi_name="typer[all]",
            version="0.9.0",
            conda_name="typer",
            description="CLI framework based on type hints"
        ),
        PackageInfo(
            name="Psutil",
            pypi_name="psutil",
            version="5.9.8",
            system_packages={
                "linux": "python3-psutil",
                "macos": "psutil",
            },
            conda_name="psutil",
            description="System and process utilities"
        ),
    ]


def main():
    """Main entry point for the enhanced installer."""
    print(" PlexiChat Enhanced Dependency Installer")
    print("=" * 50)

    installer = EnhancedInstaller()
    packages = get_plexichat_packages()

    success = installer.install_packages(packages)

    if success:
        print("\n Installation completed successfully!")
        print("You can now run PlexiChat with: python run.py")
        sys.exit(0)
    else:
        print("\n Installation completed with errors.")
        print("Some packages failed to install. Check the logs above.")
        sys.exit(1)


if __name__ == "__main__":
    main()
