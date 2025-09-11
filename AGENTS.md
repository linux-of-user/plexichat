# PlexiChat Development Guide

## Setup
```bash
# Create and activate virtual environment (.venv preferred based on .gitignore)
python -m venv .venv
# Activate: .venv\Scripts\activate (Windows) or source .venv/bin/activate (Unix)

# Install dependencies
pip install -e .                    # Install project in editable mode  
pip install -e ".[dev]"            # Install with dev dependencies
# Alternative: python run.py setup --level developer
```

## Commands
- **Setup**: `python run.py setup --level developer`
- **Build**: `python run.py build` or `python -m build`
- **Lint**: `ruff check src/` and `black --check src/`
- **Test**: `pytest tests/` or `python -m pytest`
- **Dev server**: `python -m uvicorn src.plexichat.main:app --reload`
- **Documentation**: `make docs-serve`

## Tech Stack
- **Backend**: FastAPI + Pydantic + SQLAlchemy + AsyncIO
- **Database**: PostgreSQL (production), SQLite (development)
- **Cache**: Redis
- **Frontend**: Plugin-based architecture
- **Auth**: JWT + bcrypt + 2FA support

## Architecture
- `src/plexichat/core/` - Core business logic
- `src/plexichat/infrastructure/` - Database, external services
- `src/plexichat/interfaces/` - HTTP/WebSocket APIs
- `src/plexichat/plugins/` - Plugin system
- `tests/` - Test suite

## Code Style
- Line length: 88 characters
- Imports: isort with black profile
- Type hints required
- Async/await for I/O operations