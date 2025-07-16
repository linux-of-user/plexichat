# pyright: reportArgumentType=false
# pyright: reportCallIssue=false
# pyright: reportAttributeAccessIssue=false
# pyright: reportAssignmentType=false
# pyright: reportReturnType=false
import json
import sys
from pathlib import Path

from pathlib import Path
from pathlib import Path
from pathlib import Path
from pathlib import Path
from pathlib import Path

from pathlib import Path
from pathlib import Path
from pathlib import Path
from pathlib import Path
from pathlib import Path
import logging
from typing import Optional


#!/usr/bin/env python3
"""
PlexiChat Auto-Setup Script
Automatically creates necessary directories and files on first install.
This ensures only source code stays in /src while everything else is auto-created.
"""

logger = logging.getLogger(__name__)
def create_directory_structure():
    """Create the complete directory structure for PlexiChat."""

    # Get the project root (parent of scripts directory)
    from pathlib import Path
project_root = Path
Path(__file__).parent.parent

    # Directory structure to create
    directories = [
        # Configuration directories
        "config",
        "config/certificates",
        "config/plugins",
        "config/themes",

        # Data directories
        "data",
        "data/users",
        "data/sessions",
        "data/cache",
        "data/temp",

        # Backup directories
        "backups",
        "backups/shards",
        "backups/metadata",
        "backups/cluster",
        "backups/temp",

        # Log directories
        "logs",
        "logs/crashes",
        "logs/selftest",
        "logs/archive",

        # Plugin directories
        "plugins",
        "plugins/installed",
        "plugins/temp",
        "plugins/quarantine",

        # Database directories
        "databases",
        "databases/backups",

        # Static web content
        "static",
        "static/themes",
        "static/uploads",
        "static/assets",

        # Runtime directories
        "runtime",
        "runtime/pids",
        "runtime/sockets",
        "runtime/locks",

        # GUI application data
        "gui/data",
        "gui/themes",
        "gui/cache",

        # Backup node storage
        "backup_node/storage",
        "backup_node/logs",
        "backup_node/temp",

        # Documentation build
        "docs/build",
        "docs/cache",

        # Test results
        "tests/results",
        "tests/coverage",

        # Installer cache
        "installer/cache",
        "installer/temp"
    ]

    logger.info("Creating PlexiChat directory structure...")

    created_dirs = []
    for directory in directories:
        dir_path = project_root / directory
        if not dir_path.exists():
            dir_path.mkdir(parents=True, exist_ok=True)
            created_dirs.append(str(directory))

    if created_dirs:
        logger.info(f"Created {len(created_dirs)} directories:")
        for dir_name in created_dirs[:10]:  # Show first 10
            logger.info(f"   - {dir_name}")
        if len(created_dirs) > 10:
            logger.info(f"   ... and {len(created_dirs) - 10} more")
    else:
        logger.info("All directories already exist")

    return created_dirs


def create_default_config_files():
    """Create default configuration files."""

    from pathlib import Path
project_root = Path
Path(__file__).parent.parent

    # Default configurations
    configs = {
        "config/plexichat.json": {
            "server": {
                "host": "0.0.0.0",
                "port": 8000,
                "debug": False,
                "auto_reload": False
            },
            "security": {
                "encryption_enabled": True,
                "government_level": True,
                "auto_generated_credentials": True,
                "require_2fa": True,
                "session_timeout_minutes": 60
            },
            "backup": {
                "enabled": True,
                "auto_backup": True,
                "backup_interval_hours": 6,
                "replication_factor": 5,
                "shard_size_mb": 50,
                "retention_days": 90
            },
            "clustering": {
                "enabled": True,
                "heartbeat_interval": 30,
                "node_timeout": 90,
                "auto_discovery": True
            },
            "logging": {
                "level": "INFO",
                "max_file_size_mb": 100,
                "backup_count": 10,
                "log_rotation": True
            }
        },

        "config/database.yaml": """
# PlexiChat Database Configuration
database:
  type: sqlite  # sqlite, postgresql, mysql

  # SQLite Configuration (default)
  sqlite:
    path: databases/plexichat.db
    backup_path: databases/backups/

  # PostgreSQL Configuration (optional)
  postgresql:
    host: localhost
    port: 5432
    database: plexichat
    username: plexichat_user
    password: ""  # Set via environment variable

  # Connection settings
  connection:
    pool_size: 10
    max_overflow: 20
    pool_timeout: 30
    pool_recycle: 3600

  # Encryption settings
  encryption:
    enabled: true
    key_rotation_days: 90
""",

        "config/server.yaml": """
# PlexiChat Server Configuration
server:
  # Basic settings
  name: PlexiChat Server
  description: Government-Grade Secure Communication Platform
  version: "2.0.0"

  # Network settings
  network:
    bind_address: "0.0.0.0"
    port: 8000
    max_connections: 1000
    timeout_seconds: 30

  # SSL/TLS settings
  ssl:
    enabled: false
    auto_cert: true
    cert_path: config/certificates/
    domains: []

  # Performance settings
  performance:
    workers: 4
    max_requests: 10000
    keepalive_timeout: 65

  # Security settings
  security:
    cors_enabled: true
    cors_origins: ["*"]
    rate_limiting: true
    ddos_protection: true
""",

        "backup_node/config.json": {
            "node_id": "auto-generated",
            "storage_path": "backup_node/storage",
            "max_storage_gb": 100,
            "port": 8001,
            "cluster_enabled": True,
            "encryption_enabled": True,
            "replication_factor": 5,
            "heartbeat_interval": 30,
            "capabilities": ["backup", "replication", "seeding"]
        }
    }

    logger.info("Creating default configuration files...")

    created_files = []
    for file_path, content in configs.items():
        full_path = project_root / file_path

        if not full_path.exists():
            # Ensure parent directory exists
            full_path.parent.mkdir(parents=True, exist_ok=True)

            # Write content
            if isinstance(content, dict):
                with open(full_path, 'w') as f:
                    json.dump(content, f, indent=2)
            else:
                with open(full_path, 'w') as f:
                    f.write(content)

            created_files.append(str(file_path))

    if created_files:
        logger.info(f"Created {len(created_files)} configuration files:")
        for file_name in created_files:
            logger.info(f"   - {file_name}")
    else:
        logger.info("All configuration files already exist")

    return created_files


def create_gitignore():
    """Create or update .gitignore file."""

    from pathlib import Path
project_root = Path
Path(__file__).parent.parent
    gitignore_path = project_root / ".gitignore"

    # Directories and files to ignore
    ignore_patterns = [
        "# PlexiChat Auto-Generated Directories",
        "config/",
        "data/",
        "backups/",
        "logs/",
        "databases/",
        "static/uploads/",
        "runtime/",
        "gui/data/",
        "gui/cache/",
        "backup_node/storage/",
        "backup_node/logs/",
        "tests/results/",
        "tests/coverage/",
        "installer/cache/",
        "installer/temp/",
        "",
        "# Python",
        "__pycache__/",
        "*.py[cod]",
        "*$py.class",
        "*.so",
        ".Python",
        "build/",
        "develop-eggs/",
        "dist/",
        "downloads/",
        "eggs/",
        ".eggs/",
        "lib/",
        "lib64/",
        "parts/",
        "sdist/",
        "var/",
        "wheels/",
        "*.egg-info/",
        ".installed.cfg",
        "*.egg",
        "",
        "# Virtual environments",
        "venv/",
        "env/",
        "ENV/",
        ".venv/",
        "",
        "# IDE",
        ".vscode/",
        ".idea/",
        "*.swp",
        "*.swo",
        "*~",
        "",
        "# OS",
        ".DS_Store",
        "Thumbs.db",
        "",
        "# Temporary files",
        "*.tmp",
        "*.temp",
        "*.log",
        "",
        "# Security",
        "*.key",
        "*.pem",
        "*.crt",
        "secrets.json",
        ".env",
        "",
        "# Keep important files",
        "!src/",
        "!gui/plexichat_admin_gui.py",
        "!gui/launch_gui.py",
        "!gui/requirements.txt",
        "!backup_node/*.py",
        "!backup_node/README.md",
        "!backup_node/requirements.txt",
        "!docs/*.md",
        "!scripts/",
        "!tests/*.py",
        "!installer/",
        "!requirements.txt",
        "!run.py",
        "!start.sh",
        "!start.ps1",
        "!README.md"
    ]

    logger.info("Creating/updating .gitignore...")

    with open(gitignore_path, 'w') as f:
        f.write('\n'.join(ignore_patterns))

    logger.info(".gitignore updated")
    return True


def create_startup_validation():
    """Create startup validation to ensure directories exist."""

    from pathlib import Path
project_root = Path
Path(__file__).parent.parent
    validation_path = project_root / "scripts" / "startup_validation.py"

    validation_code = '''#!/usr/bin/env python3
"""
PlexiChat Startup Validation
Ensures all required directories exist before starting the application.
"""

def validate_directory_structure():
    """Validate that all required directories exist."""

    from pathlib import Path
project_root = Path
Path(__file__).parent.parent

    required_dirs = [
        "config", "data", "backups", "logs", "plugins",
        "databases", "static", "runtime"
    ]

    missing_dirs = []
    for dir_name in required_dirs:
        if not (project_root / dir_name).exists():
            missing_dirs.append(dir_name)

    if missing_dirs:
        logger.info("ERROR: Missing required directories:")
        for dir_name in missing_dirs:
            logger.info(f"   - {dir_name}")
        logger.info("\\nRun 'python scripts/auto_setup.py' to create missing directories")
        return False

    return True

if __name__ == "__main__":
    if not validate_directory_structure():
        sys.exit(1)
    logger.info("SUCCESS: Directory structure validation passed")
'''

    with open(validation_path, 'w') as f:
        f.write(validation_code)

    logger.info("Created startup validation script")
    return True


def main():
    """Main setup function."""

    logger.info("PlexiChat Auto-Setup Starting...")
    logger.info("=" * 50)

    try:
        # Create directory structure
        created_dirs = create_directory_structure()

        # Create default config files
        created_files = create_default_config_files()

        # Create/update .gitignore
        create_gitignore()

        # Create startup validation
        create_startup_validation()

        logger.info("=" * 50)
        logger.info("SUCCESS: PlexiChat Auto-Setup Complete!")
        logger.info(f"Created {len(created_dirs)} directories")
        logger.info(f"Created {len(created_files)} configuration files")
        logger.info("Updated .gitignore for clean repository")
        logger.info("Created startup validation")
        logger.info("\nPlexiChat is ready to run!")
        logger.info("   Run: python run.py")

    except Exception as e:
        logger.info(f"ERROR: Setup failed: {e}")
        return False

    return True


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
