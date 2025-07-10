#!/usr/bin/env python3
"""
NetLink GitHub Installer
Downloads and installs NetLink from GitHub repository.
"""

import os
import sys
import json
import shutil
import zipfile
import tempfile
import subprocess
from pathlib import Path
from urllib.request import urlopen, urlretrieve
from urllib.error import URLError

class NetLinkInstaller:
    """GitHub-based NetLink installer."""
    
    def __init__(self, repo_owner: str = None, repo_name: str = None):
        self.repo_owner = repo_owner or os.getenv("NETLINK_REPO_OWNER", "linux-of-user")
        self.repo_name = repo_name or os.getenv("NETLINK_REPO_NAME", "netlink")
        self.github_api_url = f"https://api.github.com/repos/{self.repo_owner}/{self.repo_name}"
        self.install_dir = Path.cwd() / "netlink"
        
    def print_header(self):
        """Print installer header."""
        print("=" * 60)
        print("🚀 NetLink Installer")
        print("Modern Distributed Communication Platform")
        print("=" * 60)
        print()
    
    def check_requirements(self):
        """Check system requirements."""
        print("📋 Checking system requirements...")
        
        # Check Python version
        if sys.version_info < (3, 8):
            print("❌ Python 3.8+ required")
            return False
        
        print(f"✅ Python {sys.version.split()[0]} found")
        
        # Check internet connection
        try:
            urlopen("https://github.com", timeout=5)
            print("✅ Internet connection available")
        except URLError:
            print("❌ No internet connection")
            return False
        
        return True
    
    def get_latest_release(self):
        """Get latest release information from GitHub."""
        print("🔍 Checking for latest NetLink release...")
        
        try:
            with urlopen(f"{self.github_api_url}/releases/latest", timeout=10) as response:
                release_data = json.loads(response.read().decode())
            
            version = release_data["tag_name"].lstrip('v')
            download_url = release_data["zipball_url"]
            
            print(f"✅ Latest version: {version}")
            return {
                "version": version,
                "download_url": download_url,
                "release_notes": release_data.get("body", "")
            }
            
        except Exception as e:
            print(f"❌ Failed to get release info: {e}")
            # Fallback to main branch
            return {
                "version": "latest",
                "download_url": f"https://github.com/{self.repo_owner}/{self.repo_name}/archive/main.zip",
                "release_notes": "Latest development version"
            }
    
    def choose_install_directory(self):
        """Let user choose installation directory."""
        print(f"📁 Installation directory: {self.install_dir}")
        
        while True:
            choice = input("Use this directory? [Y/n/custom]: ").strip().lower()
            
            if choice in ['', 'y', 'yes']:
                break
            elif choice in ['n', 'no']:
                new_dir = input("Enter installation directory: ").strip()
                self.install_dir = Path(new_dir).expanduser().resolve()
                break
            elif choice == 'custom':
                new_dir = input("Enter custom path: ").strip()
                self.install_dir = Path(new_dir).expanduser().resolve()
                break
            else:
                print("Please enter Y, n, or custom")
        
        print(f"📁 Installing to: {self.install_dir}")
        
        # Check if directory exists
        if self.install_dir.exists():
            if any(self.install_dir.iterdir()):
                print("⚠️  Directory is not empty")
                choice = input("Continue anyway? [y/N]: ").strip().lower()
                if choice not in ['y', 'yes']:
                    print("Installation cancelled")
                    return False
        
        return True
    
    def download_netlink(self, download_url):
        """Download NetLink from GitHub."""
        print("⬇️  Downloading NetLink...")
        
        # Create temporary file
        temp_file = tempfile.NamedTemporaryFile(suffix='.zip', delete=False)
        temp_path = temp_file.name
        temp_file.close()
        
        try:
            def progress_hook(block_num, block_size, total_size):
                if total_size > 0:
                    percent = min(100, (block_num * block_size * 100) // total_size)
                    print(f"\r⬇️  Downloading... {percent}%", end="", flush=True)
            
            urlretrieve(download_url, temp_path, progress_hook)
            print("\n✅ Download completed")
            
            return temp_path
            
        except Exception as e:
            print(f"\n❌ Download failed: {e}")
            if os.path.exists(temp_path):
                os.unlink(temp_path)
            return None
    
    def extract_netlink(self, zip_path):
        """Extract NetLink archive."""
        print("📦 Extracting NetLink...")
        
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
                        if self.install_dir.exists():
                            shutil.rmtree(self.install_dir)
                        extracted_path.rename(self.install_dir)
            
            print("✅ Extraction completed")
            return True
            
        except Exception as e:
            print(f"❌ Extraction failed: {e}")
            return False
        finally:
            # Clean up zip file
            if os.path.exists(zip_path):
                os.unlink(zip_path)
    
    def install_dependencies(self):
        """Install Python dependencies."""
        print("📦 Installing dependencies...")
        
        requirements_file = self.install_dir / "requirements.txt"
        if not requirements_file.exists():
            print("⚠️  No requirements.txt found, skipping dependency installation")
            return True
        
        try:
            result = subprocess.run([
                sys.executable, "-m", "pip", "install", "-r", str(requirements_file)
            ], capture_output=True, text=True, cwd=self.install_dir)
            
            if result.returncode == 0:
                print("✅ Dependencies installed successfully")
                return True
            else:
                print(f"❌ Dependency installation failed: {result.stderr}")
                return False
                
        except Exception as e:
            print(f"❌ Dependency installation error: {e}")
            return False
    
    def create_shortcuts(self):
        """Create convenient shortcuts."""
        print("🔗 Creating shortcuts...")
        
        try:
            # Create run script for current platform
            if os.name == 'nt':  # Windows
                script_content = f"""@echo off
cd /d "{self.install_dir}"
python run.py %*
"""
                script_path = self.install_dir.parent / "netlink.bat"
                with open(script_path, 'w') as f:
                    f.write(script_content)
                print(f"✅ Created: {script_path}")
                
            else:  # Unix-like
                script_content = f"""#!/bin/bash
cd "{self.install_dir}"
python run.py "$@"
"""
                script_path = self.install_dir.parent / "netlink"
                with open(script_path, 'w') as f:
                    f.write(script_content)
                os.chmod(script_path, 0o755)
                print(f"✅ Created: {script_path}")
            
            return True
            
        except Exception as e:
            print(f"⚠️  Failed to create shortcuts: {e}")
            return False
    
    def run_initial_setup(self):
        """Run initial NetLink setup."""
        print("⚙️  Running initial setup...")
        
        try:
            # Change to install directory
            os.chdir(self.install_dir)
            
            # Run validation
            result = subprocess.run([
                sys.executable, "run.py", "--validate"
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                print("✅ Initial setup completed")
                return True
            else:
                print(f"⚠️  Setup validation warnings: {result.stderr}")
                return True  # Continue anyway
                
        except Exception as e:
            print(f"⚠️  Setup error: {e}")
            return True  # Continue anyway
    
    def show_completion_info(self):
        """Show installation completion information."""
        print("\n" + "=" * 60)
        print("🎉 NetLink Installation Complete!")
        print("=" * 60)
        print()
        print(f"📁 Installed to: {self.install_dir}")
        print()
        print("🚀 Quick Start:")
        print(f"   cd {self.install_dir}")
        print("   python run.py")
        print()
        print("🌐 Access Points:")
        print("   Web Interface: http://localhost:8000")
        print("   Admin Panel:   http://localhost:8000/admin")
        print("   API Docs:      http://localhost:8000/docs")
        print()
        print("🔑 Default Login:")
        print("   Username: admin")
        print("   Password: admin123")
        print()
        print("📚 Documentation:")
        print(f"   {self.install_dir}/README.md")
        print(f"   {self.install_dir}/docs/")
        print()
        print("🆘 Need Help?")
        print("   python run.py --help")
        print("   python run.py --validate")
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
        
        print(f"📋 Installing NetLink {release_info['version']}")
        if release_info['release_notes']:
            print(f"📝 Release notes: {release_info['release_notes'][:100]}...")
        print()
        
        # Choose directory
        if not self.choose_install_directory():
            return False
        
        # Download
        zip_path = self.download_netlink(release_info['download_url'])
        if not zip_path:
            return False
        
        # Extract
        if not self.extract_netlink(zip_path):
            return False
        
        # Install dependencies
        if not self.install_dependencies():
            print("⚠️  Continuing without dependencies (you can install them later)")
        
        # Create shortcuts
        self.create_shortcuts()
        
        # Initial setup
        self.run_initial_setup()
        
        # Show completion info
        self.show_completion_info()
        
        return True

def run_installer():
    """Run the NetLink installer."""
    installer = NetLinkInstaller()
    
    try:
        success = installer.install()
        return 0 if success else 1
    except KeyboardInterrupt:
        print("\n\n🛑 Installation cancelled by user")
        return 1
    except Exception as e:
        print(f"\n❌ Installation failed: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(run_installer())
