# PlexiChat Agent Development Guide

## Setup Commands
```bash
# Create and activate virtual environment (.venv preferred based on .gitignore)
python -m venv .venv
# Activate: .venv\Scripts\activate (Windows) or source .venv/bin/activate (Unix)

# Install dependencies
pip install -e .                    # Install project in editable mode  
pip install -e ".[dev]"            # Install with dev dependencies
# Alternative: python run.py setup --level developer
```

## Development Commands
```bash
# Build
python run.py build                    # Build the application

# Build documentation
make docs

# Linting
ruff check src tests               # Fast Python linter
black --check src tests           # Code formatting check
isort --check-only src tests      # Import sorting check

# Type checking
pyright                           # Static type analysis
mypy src/                         # Type checking

# Test  
python -m pytest                      # Run all tests
python -m pytest tests/unit/          # Run unit tests only
python -m pytest --cov=src/plexichat  # Run with coverage

# Dev Server
python run.py                    # Start all services (API, WebUI, CLI)
python run.py --nowebui --nocli  # API server only
uvicorn plexichat.main:app --reload  # Alternative FastAPI dev server
```

## Tech Stack & Architecture
- **Backend**: FastAPI + SQLAlchemy + Alembic + Redis + AsyncPG
- **Structure**: Clean architecture with core/features/infrastructure/plugins
- **Security**: Distributed key management, JWT auth, bcrypt passwords
- **Database**: PostgreSQL with async support
- **Monitoring**: Prometheus metrics, structured logging (structlog)

## Code Style
- **Format**: Black (88 chars), isort for imports
- **Quality**: Ruff linter, Pyright type checker  
- **Standards**: Python 3.11+, async/await patterns, Pydantic models
- Line length: 88 characters
- Use type hints for all functions
- Follow async/await patterns for I/O operations
- Plugin system for extensibility