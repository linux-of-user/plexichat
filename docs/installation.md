# Installation Guide

## System Requirements

- Python 3.8 or higher
- 4GB RAM minimum (8GB recommended)
- 10GB disk space
- Network connectivity

## Quick Installation

### Option 1: Setup Wizard (Recommended)

1. Download PlexiChat from the repository
2. Run the setup wizard:
   ```bash
   python setup_wizard.py
   ```
3. Follow the guided installation process

### Option 2: Manual Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your-org/plexichat.git
   cd plexichat
   ```

2. Create virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Run initial setup:
   ```bash
   python -m plexichat.setup
   ```

5. Start the application:
   ```bash
   python run.py
   ```

## Configuration

The system will create default configuration files in the `config/` directory.
You can modify these files or use the web interface for configuration.

## First Login

- Default username: `admin`
- Default password: `PlexiChat2025!`
- **Important**: Change the default password after first login!

## Troubleshooting

### Common Issues

1. **Port already in use**: Change the port in configuration
2. **Permission denied**: Run with appropriate permissions
3. **Module not found**: Ensure all dependencies are installed

### Getting Help

- Check the logs in `logs/` directory
- Run system diagnostics: `python -m plexichat.diagnostics`
- Contact support with error details
