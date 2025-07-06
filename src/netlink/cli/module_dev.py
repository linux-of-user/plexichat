#!/usr/bin/env python3
"""
NetLink Module Development CLI

Command-line tools for creating, testing, and managing NetLink modules.
"""

import argparse
import sys
import os
import shutil
import subprocess
import json
import yaml
from pathlib import Path
from typing import Dict, Any, List, Optional

# Add the parent directory to the path so we can import from the app
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from app.modules.base import ModuleDeveloper, module_registry
    from app.logger_config import logger
except ImportError as e:
    print(f"Warning: Could not import NetLink modules: {e}")
    logger = None

class ModuleDevCLI:
    """CLI for module development operations."""
    
    def __init__(self):
        self.developer = ModuleDeveloper() if 'ModuleDeveloper' in globals() else None
    
    def create_module(self, name: str, output_dir: str = "modules", template: str = "basic") -> bool:
        """Create a new module from template."""
        try:
            if not self.developer:
                print("❌ Module development tools not available")
                return False
            
            print(f"🚀 Creating module '{name}' in '{output_dir}'...")
            
            # Create module directory
            module_path = self.developer.create_module_template(name, output_dir)
            
            print(f"✅ Module '{name}' created successfully!")
            print(f"📁 Location: {module_path}")
            print("\n📋 Next steps:")
            print(f"   1. cd {module_path}")
            print("   2. Edit module.py to implement your functionality")
            print("   3. Update config.yaml with your settings")
            print("   4. Run tests: pytest tests/")
            print("   5. Install: python -m netlink.cli module install")
            
            return True
            
        except Exception as e:
            print(f"❌ Failed to create module: {e}")
            return False
    
    def validate_module(self, module_path: str) -> bool:
        """Validate a module structure and configuration."""
        try:
            module_dir = Path(module_path)
            if not module_dir.exists():
                print(f"❌ Module directory not found: {module_path}")
                return False
            
            print(f"🔍 Validating module at {module_path}...")
            
            # Check required files
            required_files = [
                "module.py",
                "config.yaml",
                "__init__.py"
            ]
            
            missing_files = []
            for file in required_files:
                if not (module_dir / file).exists():
                    missing_files.append(file)
            
            if missing_files:
                print(f"❌ Missing required files: {', '.join(missing_files)}")
                return False
            
            # Validate configuration
            config_file = module_dir / "config.yaml"
            try:
                with open(config_file, 'r') as f:
                    config = yaml.safe_load(f)
                
                required_config = ["module_name", "module_version"]
                missing_config = [key for key in required_config if key not in config]
                
                if missing_config:
                    print(f"❌ Missing required config keys: {', '.join(missing_config)}")
                    return False
                
            except Exception as e:
                print(f"❌ Invalid config.yaml: {e}")
                return False
            
            # Check Python syntax
            module_file = module_dir / "module.py"
            try:
                with open(module_file, 'r') as f:
                    compile(f.read(), str(module_file), 'exec')
            except SyntaxError as e:
                print(f"❌ Syntax error in module.py: {e}")
                return False
            
            print("✅ Module validation passed!")
            return True
            
        except Exception as e:
            print(f"❌ Validation failed: {e}")
            return False
    
    def test_module(self, module_path: str) -> bool:
        """Run tests for a module."""
        try:
            module_dir = Path(module_path)
            if not module_dir.exists():
                print(f"❌ Module directory not found: {module_path}")
                return False
            
            print(f"🧪 Running tests for module at {module_path}...")
            
            # Check if tests directory exists
            tests_dir = module_dir / "tests"
            if not tests_dir.exists():
                print("⚠️  No tests directory found")
                return True
            
            # Run pytest
            try:
                result = subprocess.run([
                    sys.executable, "-m", "pytest", 
                    str(tests_dir), 
                    "-v", 
                    "--tb=short"
                ], capture_output=True, text=True, cwd=module_dir)
                
                print(result.stdout)
                if result.stderr:
                    print("Errors:", result.stderr)
                
                if result.returncode == 0:
                    print("✅ All tests passed!")
                    return True
                else:
                    print("❌ Some tests failed")
                    return False
                    
            except FileNotFoundError:
                print("❌ pytest not found. Install with: pip install pytest")
                return False
            
        except Exception as e:
            print(f"❌ Test execution failed: {e}")
            return False
    
    def package_module(self, module_path: str, output_file: Optional[str] = None) -> bool:
        """Package a module for distribution."""
        try:
            module_dir = Path(module_path)
            if not module_dir.exists():
                print(f"❌ Module directory not found: {module_path}")
                return False
            
            # Validate first
            if not self.validate_module(module_path):
                print("❌ Module validation failed. Fix issues before packaging.")
                return False
            
            print(f"📦 Packaging module at {module_path}...")
            
            # Get module name from config
            config_file = module_dir / "config.yaml"
            with open(config_file, 'r') as f:
                config = yaml.safe_load(f)
            
            module_name = config["module_name"]
            module_version = config.get("module_version", "1.0.0")
            
            # Create output filename if not provided
            if not output_file:
                output_file = f"{module_name}-{module_version}.zip"
            
            # Create zip file
            import zipfile
            
            with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for root, dirs, files in os.walk(module_dir):
                    # Skip __pycache__ and .git directories
                    dirs[:] = [d for d in dirs if d not in ['__pycache__', '.git', '.pytest_cache']]
                    
                    for file in files:
                        if file.endswith(('.pyc', '.pyo')):
                            continue
                        
                        file_path = Path(root) / file
                        arc_path = file_path.relative_to(module_dir.parent)
                        zipf.write(file_path, arc_path)
            
            print(f"✅ Module packaged successfully: {output_file}")
            return True
            
        except Exception as e:
            print(f"❌ Packaging failed: {e}")
            return False
    
    def list_templates(self) -> bool:
        """List available module templates."""
        templates = {
            "basic": "Basic module with API endpoints and background tasks",
            "api": "API-focused module with comprehensive endpoint examples",
            "webui": "WebUI module with frontend components",
            "integration": "Integration module for external services",
            "background": "Background processing module with scheduled tasks"
        }
        
        print("📋 Available module templates:")
        for name, description in templates.items():
            print(f"   {name:12} - {description}")
        
        return True
    
    def install_module(self, module_file: str) -> bool:
        """Install a packaged module."""
        try:
            if not Path(module_file).exists():
                print(f"❌ Module file not found: {module_file}")
                return False
            
            print(f"📥 Installing module from {module_file}...")
            
            # Extract to modules directory
            import zipfile
            modules_dir = Path("src/netlink/modules")
            modules_dir.mkdir(parents=True, exist_ok=True)
            
            with zipfile.ZipFile(module_file, 'r') as zipf:
                zipf.extractall(modules_dir)
            
            print("✅ Module installed successfully!")
            print("🔄 Restart NetLink to load the new module")
            
            return True
            
        except Exception as e:
            print(f"❌ Installation failed: {e}")
            return False
    
    def hot_reload_module(self, module_name: str) -> bool:
        """Hot reload a module during development."""
        try:
            if not module_registry:
                print("❌ Module registry not available")
                return False
            
            print(f"🔄 Hot reloading module '{module_name}'...")
            
            module = module_registry.get(module_name)
            if not module:
                print(f"❌ Module '{module_name}' not found")
                return False
            
            # Reload the module
            import asyncio
            asyncio.run(module.reload())
            
            print(f"✅ Module '{module_name}' reloaded successfully!")
            return True
            
        except Exception as e:
            print(f"❌ Hot reload failed: {e}")
            return False

def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="NetLink Module Development CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Create a new module
  python -m netlink.cli.module_dev create my_module

  # Validate a module
  python -m netlink.cli.module_dev validate modules/my_module

  # Run module tests
  python -m netlink.cli.module_dev test modules/my_module

  # Package a module
  python -m netlink.cli.module_dev package modules/my_module

  # Install a packaged module
  python -m netlink.cli.module_dev install my_module-1.0.0.zip

  # Hot reload a module
  python -m netlink.cli.module_dev reload my_module
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Create command
    create_parser = subparsers.add_parser('create', help='Create a new module')
    create_parser.add_argument('name', help='Module name')
    create_parser.add_argument('--output', '-o', default='modules', help='Output directory')
    create_parser.add_argument('--template', '-t', default='basic', help='Module template')
    
    # Validate command
    validate_parser = subparsers.add_parser('validate', help='Validate a module')
    validate_parser.add_argument('path', help='Module directory path')
    
    # Test command
    test_parser = subparsers.add_parser('test', help='Run module tests')
    test_parser.add_argument('path', help='Module directory path')
    
    # Package command
    package_parser = subparsers.add_parser('package', help='Package a module')
    package_parser.add_argument('path', help='Module directory path')
    package_parser.add_argument('--output', '-o', help='Output file name')
    
    # Templates command
    templates_parser = subparsers.add_parser('templates', help='List available templates')
    
    # Install command
    install_parser = subparsers.add_parser('install', help='Install a packaged module')
    install_parser.add_argument('file', help='Module package file')
    
    # Reload command
    reload_parser = subparsers.add_parser('reload', help='Hot reload a module')
    reload_parser.add_argument('name', help='Module name')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    cli = ModuleDevCLI()
    
    try:
        if args.command == 'create':
            success = cli.create_module(args.name, args.output, args.template)
        elif args.command == 'validate':
            success = cli.validate_module(args.path)
        elif args.command == 'test':
            success = cli.test_module(args.path)
        elif args.command == 'package':
            success = cli.package_module(args.path, args.output)
        elif args.command == 'templates':
            success = cli.list_templates()
        elif args.command == 'install':
            success = cli.install_module(args.file)
        elif args.command == 'reload':
            success = cli.hot_reload_module(args.name)
        else:
            print(f"❌ Unknown command: {args.command}")
            return 1
        
        return 0 if success else 1
        
    except KeyboardInterrupt:
        print("\n⚠️  Operation cancelled by user")
        return 1
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
