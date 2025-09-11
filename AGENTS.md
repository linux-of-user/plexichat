# PlexiChat Development Guide

## Setup Commands
```bash
# Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\activate  # Windows PowerShell
# source .venv/bin/activate  # Linux/macOS

# Install dependencies
pip install -r requirements.txt
pip install -e .[dev]  # Install with dev dependencies
```

## Development Commands
```bash
# Build
python -m build

# Lint
ruff check src/ tests/
black --check src/ tests/
isort --check-only src/ tests/

# Format
ruff check --fix src/ tests/
black src/ tests/
isort src/ tests/

# Tests
pytest

# Dev server
python -m uvicorn plexichat.main:app --reload --port 8000
```

## Tech Stack
- **Backend**: FastAPI with async support
- **Database**: SQLAlchemy with AsyncPG (PostgreSQL)
- **Authentication**: JWT with passlib/bcrypt
- **Caching**: Redis
- **Testing**: pytest with async support
- **Code Quality**: ruff, black, isort, pyright

## Architecture
Plugin-based architecture with modular core system. Main directories:
- `src/plexichat/core/` - Core functionality (auth, db, logging, etc.)
- `src/plexichat/plugins/` - Plugin system
- `src/plexichat/interfaces/` - API interfaces
- `src/plexichat/infrastructure/` - Infrastructure components

## Code Style
- Line length: 88 characters
- Import sorting: isort with black profile
- Type hints required for public APIs
- Async/await patterns for I/O operations