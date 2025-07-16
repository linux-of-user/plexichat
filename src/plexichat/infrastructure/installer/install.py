# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import json
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen, urlretrieve

from pathlib import Path
from pathlib import Path

from pathlib import Path
from pathlib import Path
import logging
from typing import Optional


#!/usr/bin/env python3
"""
PlexiChat GitHub Installer
Downloads and installs PlexiChat from GitHub repository.
"""

logger = logging.getLogger(__name__)
class PlexiChatInstaller:
    """GitHub-based PlexiChat installer."""
    
    def __init__(self, repo_owner: Optional[str] = None, repo_name: Optional[str] = None):
        self.repo_owner = repo_owner or os.getenv("PLEXICHAT_REPO_OWNER", "linux-of-user")
        self.repo_name = repo_name or os.getenv("PLEXICHAT_REPO_NAME", "plexichat")
        self.github_api_url = f"https://api.github.com/repos/{self.repo_owner}/{self.repo_name}"
        self.install_dir = Path.cwd() / "plexichat"
        
    def print_header(self):
        """Print installer header."""
        logger.info("=" * 60)
        logger.info(" PlexiChat Installer")
        logger.info("Modern Distributed Communication Platform")
        logger.info("=" * 60)
        print()
    
    def check_requirements(self):
        """Check system requirements."""
        logger.info(" Checking system requirements...")
        
        # Check Python version
        if sys.version_info < (3, 8):
            logger.info(" Python 3.8+ required")
            return False
        
        logger.info(f" Python {sys.version.split()[0]} found")
        
        # Check internet connection
        try:
            urlopen("https://github.com", timeout=5)
            logger.info(" Internet connection available")
        except URLError:
            logger.info(" No internet connection")
            return False
        
        return True
    
    def get_latest_release(self):
        """Get latest release information from GitHub."""
        logger.info(" Checking for latest PlexiChat release...")
        
        try:
            with urlopen(f"{self.github_api_url}/releases/latest", timeout=10) as response:
                release_data = json.loads(response.read().decode())
            
            version = release_data["tag_name"].lstrip('v')
            download_url = release_data["zipball_url"]
            
            logger.info(f" Latest version: {version}")
            return {
                "version": version,
                "download_url": download_url,
                "release_notes": release_data.get("body", "")
            }
            
        except Exception as e:
            logger.info(f" Failed to get release info: {e}")
            # Fallback to main branch
            return {
                "version": "latest",
                "download_url": f"https://github.com/{self.repo_owner}/{self.repo_name}/archive/main.zip",
                "release_notes": "Latest development version"
            }
    
    def choose_install_directory(self):
        """Let user choose installation directory."""
        logger.info(f" Installation directory: {self.install_dir}")
        
        while True:
            choice = input("Use this directory? [Y/n/custom]: ").strip().lower()
            
            if choice in ['', 'y', 'yes']:
                break
            elif choice in ['n', 'no']:
                new_dir = input("Enter installation directory: ").strip()
                self.from pathlib import Path
install_dir = Path()(new_dir).expanduser().resolve()
                break
            elif choice == 'custom':
                new_dir = input("Enter custom path: ").strip()
                self.from pathlib import Path
install_dir = Path()(new_dir).expanduser().resolve()
                break
            else:
                logger.info("Please enter Y, n, or custom")
        
        logger.info(f" Installing to: {self.install_dir}")
        
        # Check if directory exists
        if self.install_dir.exists() if self.install_dir else False:
            if any(self.install_dir.iterdir()):
                logger.info("  Directory is not empty")
                choice = input("Continue anyway? [y/N]: ").strip().lower()
                if choice not in ['y', 'yes']:
                    logger.info("Installation cancelled")
                    return False
        
        return True
    
    def download_plexichat(self, download_url):
        """Download PlexiChat from GitHub."""
        logger.info("  Downloading PlexiChat...")
        
        # Create temporary file
        temp_file = tempfile.NamedTemporaryFile(suffix='.zip', delete=False)
        temp_path = temp_file.name
        temp_file.close()
        
        try:
            def progress_hook(block_num, block_size, total_size):
                if total_size > 0:
                    percent = min(100, (block_num * block_size * 100) // total_size)
                    logger.info(f"\r  Downloading... {percent}%", end="", flush=True)
            
            urlretrieve(download_url, temp_path, progress_hook)
            logger.info("\n Download completed")
            
            return temp_path
            
        except Exception as e:
            logger.info(f"\n Download failed: {e}")
            if os.path.exists(temp_path):
                os.unlink(temp_path)
            return None
    
    def extract_plexichat(self, zip_path):
        """Extract PlexiChat archive."""
        logger.info(" Extracting PlexiChat...")
        
        try:
            # Create installation directory
            self.install_dir.mkdir(parents=True, exist_ok=True)
            
            with zipfile.ZipFile(zip_path, 'r') as zip_file:
                # Find the root directory in the zip
                names = zip_file.namelist()
                root_dir = names[0].split('/')[0] if names else None
                
                # Extract all files
                zip_file.extractall(self.install_dir.parent)
                
                # Move files from extracted directory to install directory
                if root_dir:
                    extracted_path = self.install_dir.parent / root_dir
                    
                    # If install_dir exists and is different from extracted_path
                    if extracted_path != self.install_dir:
                        if self.install_dir.exists() if self.install_dir else False:
                            shutil.rmtree(self.install_dir)
                        extracted_path.rename(self.install_dir)
            
            logger.info(" Extraction completed")
            return True
            
        except Exception as e:
            logger.info(f" Extraction failed: {e}")
            return False
        finally:
            # Clean up zip file
            if os.path.exists(zip_path):
                os.unlink(zip_path)
    
    def install_dependencies(self):
        """Install Python dependencies."""
        logger.info(" Installing dependencies...")
        
        requirements_file = self.install_dir / "requirements.txt"
        if not requirements_file.exists():
            logger.info("  No requirements.txt found, skipping dependency installation")
            return True
        
        try:
            result = subprocess.run([
                sys.executable, "-m", "pip", "install", "-r", str(requirements_file)
            ], capture_output=True, text=True, cwd=self.install_dir)
            
            if result.returncode == 0:
                logger.info(" Dependencies installed successfully")
                return True
            else:
                logger.info(f" Dependency installation failed: {result.stderr}")
                return False
                
        except Exception as e:
            logger.info(f" Dependency installation error: {e}")
            return False
    
    def create_shortcuts(self):
        """Create convenient shortcuts."""
        logger.info(" Creating shortcuts...")
        
        try:
            # Create run script for current platform
            if os.name == 'nt':  # Windows
                script_content = f"""@echo off
cd /d "{self.install_dir}"
python run.py %*
"""
                script_path = self.install_dir.parent / "plexichat.bat"
                with open(script_path, 'w') as f:
                    f.write(script_content)
                logger.info(f" Created: {script_path}")
                
            else:  # Unix-like
                script_content = f"""#!/bin/bash
cd "{self.install_dir}"
python run.py "$@"
"""
                script_path = self.install_dir.parent / "plexichat"
                with open(script_path, 'w') as f:
                    f.write(script_content)
                os.chmod(script_path, 0o755)
                logger.info(f" Created: {script_path}")
            
            return True
            
        except Exception as e:
            logger.info(f"  Failed to create shortcuts: {e}")
            return False
    
    def run_initial_setup(self):
        """Run initial PlexiChat setup."""
        logger.info("  Running initial setup...")
        
        try:
            # Change to install directory
            os.chdir(self.install_dir)
            
            # Run validation
            result = subprocess.run([
                sys.executable, "run.py", "--validate"
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                logger.info(" Initial setup completed")
                return True
            else:
                logger.info(f"  Setup validation warnings: {result.stderr}")
                return True  # Continue anyway
                
        except Exception as e:
            logger.info(f"  Setup error: {e}")
            return True  # Continue anyway
    
    def show_completion_info(self):
        """Show installation completion information."""
        logger.info("\n" + "=" * 60)
        logger.info(" PlexiChat Installation Complete!")
        logger.info("=" * 60)
        print()
        logger.info(f" Installed to: {self.install_dir}")
        print()
        logger.info(" Quick Start:")
        logger.info(f"   cd {self.install_dir}")
        logger.info("   python run.py")
        print()
        logger.info(" Access Points:")
        logger.info("   Web Interface: http://localhost:8000")
        logger.info("   Admin Panel:   http://localhost:8000/admin")
        logger.info("   API Docs:      http://localhost:8000/docs")
        print()
        logger.info(" Default Login:")
        logger.info("   Username: admin")
        logger.info("   Password: admin123")
        print()
        logger.info(" Documentation:")
        logger.info(f"   {self.install_dir}/README.md")
        logger.info(f"   {self.install_dir}/docs/")
        print()
        logger.info(" Need Help?")
        logger.info("   python run.py --help")
        logger.info("   python run.py --validate")
        print()
    
    def install(self):
        """Run the complete installation process."""
        self.print_header()
        
        # Check requirements
        if not self.check_requirements():
            return False
        
        # Get latest release
        release_info = self.get_latest_release()
        if not release_info:
            return False
        
        logger.info(f" Installing PlexiChat {release_info['version']}")
        if release_info['release_notes']:
            logger.info(f" Release notes: {release_info['release_notes'][:100]}...")
        print()
        
        # Choose directory
        if not self.choose_install_directory():
            return False
        
        # Download
        zip_path = self.download_plexichat(release_info['download_url'])
        if not zip_path:
            return False
        
        # Extract
        if not self.extract_plexichat(zip_path):
            return False
        
        # Install dependencies
        if not self.install_dependencies():
            logger.info("  Continuing without dependencies (you can install them later)")
        
        # Create shortcuts
        self.create_shortcuts()
        
        # Initial setup
        self.run_initial_setup()
        
        # Show completion info
        self.show_completion_info()
        
        return True

def run_installer():
    """Run the PlexiChat installer."""
    installer = PlexiChatInstaller()
    
    try:
        success = installer.install()
        return 0 if success else 1
    except KeyboardInterrupt:
        logger.info("\n\n Installation cancelled by user")
        return 1
    except Exception as e:
        logger.info(f"\n Installation failed: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(run_installer())
