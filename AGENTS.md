# PlexiChat Agent Guide

## Setup Commands
```bash
# Create virtual environment
python -m venv venv
# Windows: venv\Scripts\activate
source venv/bin/activate  # Linux/macOS
python run.py setup --level minimal  # or full/developer
```

## Development Commands
- **Build**: `python -m build` or `make docs`
- **Lint**: `ruff check src/ && black --check src/ && mypy src/`
- **Test**: `pytest tests/`
- **Dev Server**: `python run.py serve`

## Tech Stack
- **Backend**: FastAPI + SQLAlchemy + PostgreSQL/SQLite
- **Async**: Uvicorn, asyncio, aiofiles
- **Auth**: Passlib, Python-JOSE, bcrypt
- **Monitoring**: Prometheus, structlog
- **Testing**: pytest, pytest-asyncio, pytest-cov

## Architecture
- `src/plexichat/core/` - Core business logic
- `src/plexichat/interfaces/` - API endpoints
- `src/plexichat/infrastructure/` - Database, auth, monitoring
- `src/plexichat/plugins/` - Plugin system
- `tests/` - Test suite

## Code Style
- **Formatter**: Black (88 chars)
- **Linter**: Ruff + Pyright/MyPy
- **Import Order**: isort (black profile)
- **Type Hints**: Required for all functions
- **Async/Await**: Preferred over sync patterns