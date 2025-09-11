# PlexiChat Development Guide

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

## Build & Quality Commands

```bash
# Build documentation
make docs

# Linting
ruff check src tests               # Fast Python linter
black --check src tests           # Code formatting check
isort --check-only src tests      # Import sorting check

# Type checking
pyright                           # Static type analysis

# Testing  
pytest                           # Run all tests
pytest --cov=src/plexichat       # With coverage
```

## Development Server

```bash
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