# PlexiChat Development Guide

## Setup Commands

```bash
# Virtual environment setup
python -m venv .venv                    # Create virtual environment
.venv\Scripts\activate                  # Activate (Windows)
source .venv/bin/activate              # Activate (Unix)

# Install dependencies
pip install -r requirements.txt        # Core dependencies
pip install -e ".[dev]"               # Development dependencies
```

## Development Commands

```bash
# Build & Lint
ruff check .                          # Linting
black .                              # Code formatting
pyright                              # Type checking
make lint                            # Run all linting tasks

# Testing
pytest                               # Run tests
pytest --cov                         # Run with coverage

# Development Server
python run.py                        # Start full application
python run.py --nowebui --nocli      # API server only
uvicorn plexichat.main:app --reload  # FastAPI dev server
```

## Tech Stack
- **Backend**: FastAPI, SQLAlchemy, Redis
- **Database**: PostgreSQL (async via asyncpg)
- **Testing**: pytest, pytest-asyncio, pytest-cov
- **Code Quality**: ruff, black, pyright, pre-commit

## Architecture
Plugin-based architecture with core modules in `src/plexichat/core/` and plugins in `src/plexichat/plugins/`. Follows async patterns with FastAPI and SQLAlchemy.