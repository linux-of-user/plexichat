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
python run.py setup --level minimal    # Core dependencies
python run.py setup --level full       # Full feature set
python run.py setup --level developer  # All deps + dev tools
```

## Development Commands

```bash
# Build & Lint
ruff check .                          # Linting
ruff check src/                       # Lint src directory
black .                              # Code formatting
black --check src/                   # Check src formatting
isort --check-only src/              # Check import sorting
pyright                              # Type checking
make lint                            # Run all linting tasks
python -m build                      # Build package

# Testing
pytest                               # Run tests
pytest --cov                         # Run with coverage

# Development Server
python run.py                        # Start full application
python run.py --nowebui --nocli      # API server only
uvicorn plexichat.main:app --reload  # FastAPI dev server
```

## Tech Stack & Architecture
- **Backend**: FastAPI with async/await, SQLAlchemy, Redis
- **Database**: PostgreSQL (async via asyncpg), SQLite
- **Structure**: Clean architecture with core/infrastructure/interfaces layers
- **Plugins**: Dynamic plugin system with SDK generation
- **Testing**: pytest, pytest-asyncio, pytest-cov
- **Code Quality**: ruff, black, pyright, pre-commit

## Code Style
- Line length: 88 characters
- Tools: Black, isort, Ruff for formatting/linting
- Type hints required for all public functions
- Follow existing patterns in src/plexichat/
- Plugin-based architecture with core modules in `src/plexichat/core/` and plugins in `src/plexichat/plugins/`