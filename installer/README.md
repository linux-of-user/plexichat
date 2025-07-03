# NetLink Installer

Simple, automated installation of NetLink from GitHub.

## Quick Install

### One-Line Install (Linux/macOS)
```bash
curl -sSL https://raw.githubusercontent.com/linux-of-user/netlink/main/installer/install.sh | bash
```

### One-Line Install (Windows PowerShell)
```powershell
iwr -useb https://raw.githubusercontent.com/linux-of-user/netlink/main/installer/install.ps1 | iex
```

### Manual Download & Install

#### Linux/macOS
```bash
# Download installer
curl -O https://raw.githubusercontent.com/linux-of-user/netlink/main/installer/install.sh
chmod +x install.sh

# Run installer
./install.sh
```

#### Windows
```powershell
# Download installer
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/linux-of-user/netlink/main/installer/install.ps1" -OutFile "install.ps1"

# Run installer
.\install.ps1
```

#### Python (Cross-platform)
```bash
# Download Python installer
curl -O https://raw.githubusercontent.com/linux-of-user/netlink/main/installer/install.py

# Run installer
python install.py
```

## What the Installer Does

1. **System Check**: Validates Python 3.8+ and internet connection
2. **Download**: Gets latest NetLink release from GitHub
3. **Extract**: Unpacks NetLink to chosen directory
4. **Dependencies**: Installs Python requirements automatically
5. **Setup**: Runs initial system validation
6. **Shortcuts**: Creates convenient launch scripts

## Installation Options

### Custom Installation Directory
```bash
# Linux/macOS
./install.sh --install-path /opt/netlink

# Windows
.\install.ps1 -InstallPath "C:\Tools\NetLink"

# Python
python install.py --install-path /custom/path
```

### Force Installation
```bash
# Overwrite existing installation
./install.sh --force
.\install.ps1 -Force
python install.py --force
```

## After Installation

### Quick Start
```bash
cd netlink
python run.py
```

### Access NetLink
- **Web Interface**: http://localhost:8000
- **Admin Panel**: http://localhost:8000/admin
- **API Docs**: http://localhost:8000/docs

### Default Login
- **Username**: admin
- **Password**: admin123

## Troubleshooting

### Python Not Found
Install Python 3.8+ from:
- **Linux**: `sudo apt install python3 python3-pip` (Ubuntu/Debian)
- **macOS**: `brew install python3` or download from python.org
- **Windows**: Download from python.org

### Permission Denied (Linux/macOS)
```bash
chmod +x install.sh
sudo ./install.sh  # If installing to system directory
```

### Execution Policy (Windows)
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Internet Connection Issues
- Check firewall settings
- Try using a VPN if GitHub is blocked
- Download manually and use offline installation

## Manual Installation

If automated installation fails, you can install manually:

1. **Download**: Get the latest release from GitHub
2. **Extract**: Unzip to desired location
3. **Dependencies**: Run `pip install -r requirements.txt`
4. **Start**: Run `python run.py`

## Uninstallation

To remove NetLink:

1. **Stop NetLink**: `python run.py --shutdown` or Ctrl+C
2. **Remove Directory**: Delete the NetLink installation folder
3. **Remove Shortcuts**: Delete any created shortcuts/scripts

## Support

- **Documentation**: See `docs/` folder after installation
- **Issues**: Report at https://github.com/linux-of-user/netlink/issues
- **Help**: Run `python run.py --help` after installation
