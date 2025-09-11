# PlexiChat Development Guide

## Initial Setup
```bash
python -m venv .venv
.venv\Scripts\activate  # Windows
source .venv/bin/activate  # Linux/Mac
pip install -e ".[dev,test]"
```

## Commands

### Build
```bash
python -m build
```

### Lint
```bash
ruff check src tests
black --check src tests
pyright src
```

### Tests
```bash
pytest
```

### Dev Server
```bash
python run.py
```

## Tech Stack
- **Framework**: FastAPI with async/await
- **Database**: SQLAlchemy with asyncpg (PostgreSQL)
- **Plugin System**: Dynamic plugin loading with sandboxing
- **Authentication**: JWT with passlib/bcrypt
- **Monitoring**: Prometheus metrics, structured logging

## Architecture
- `src/plexichat/core/` - Core business logic and domain models
- `src/plexichat/infrastructure/` - External dependencies (database, cache, etc.)
- `src/plexichat/interfaces/` - API endpoints and external interfaces
- `src/plexichat/plugins/` - Plugin system and built-in plugins
- `src/plexichat/features/` - Feature modules
- `src/plexichat/shared/` - Shared utilities and common code

## Code Style
- Line length: 88 characters
- Type hints required for all public APIs
- Use async/await for I/O operations
- Follow existing naming conventions (snake_case)