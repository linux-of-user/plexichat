# PlexiChat Agent Guide

## Commands

### Setup
```bash
python -m venv .venv                  # Create virtual environment
.venv\Scripts\activate               # Activate virtual environment (Windows)
pip install -e ".[dev]"             # Install with development dependencies
```

### Development
```bash
make docs-serve                      # Serve documentation (port 8000)
ruff check src/ --fix               # Run linter with fixes
black src/                          # Format code
pytest tests/                       # Run tests
uvicorn plexichat.main:app --reload # Run dev server
```

## Tech Stack
- **Backend**: FastAPI with async/await, SQLAlchemy 2.0
- **Database**: PostgreSQL (production), SQLite (development)
- **Testing**: pytest with asyncio support
- **Code Quality**: Ruff (linting), Black (formatting), MyPy (types)

## Architecture
```
src/plexichat/
├── core/           # Core business logic
├── infrastructure/ # Database, external services
├── interfaces/     # API endpoints, CLI
├── plugins/        # Plugin system
└── shared/         # Shared utilities
```

## Conventions
- Use `async def` for all I/O operations
- Type hints required for all functions
- Follow Black formatting (88 char line length)
- Test coverage minimum 80%