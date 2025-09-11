# PlexiChat Development Guide

## Setup & Commands

### Initial Setup
```bash
python run.py setup --level developer    # Full dev environment with linting/testing tools
python -m venv venv                      # Creates virtual env in ./venv (see .gitignore)
# On Windows: venv\Scripts\activate
# On Unix/macOS: source venv/bin/activate
pip install -r requirements.txt
```

### Build & Development
```bash
python run.py                            # Start API server, WebUI, and CLI
make docs                               # Build documentation 
make docs-serve                         # Serve docs locally (port 8000)
```

### Code Quality
```bash
ruff check src/                         # Lint code
ruff format src/                        # Format code 
mypy src/                              # Type checking
black src/                             # Code formatting
pyright src/                           # Additional type checking
```

### Testing
```bash
pytest                                  # Run all tests
pytest -m unit                         # Unit tests only
pytest --cov=plexichat --cov-report=html  # With coverage
pytest tests/                          # Run from tests directory
```

## Tech Stack

**Backend**: FastAPI, SQLAlchemy, Redis, PostgreSQL/SQLite  
**Frontend**: FastAPI + WebUI  
**Architecture**: Plugin-based modular system with core/plugins/infrastructure layers  
**Auth**: JWT + bcrypt, 2FA support, unified auth manager  
**Caching**: Redis (L2) + Memcached (L3) + in-memory (L1)
**Plugins**: Dynamic loading system with SDK generation

## Code Style

- **Python 3.11+** with type hints (required)
- **Line length**: 88 chars (Black)
- **Import order**: stdlib → third-party → first-party (isort)
- **Docstrings**: Google style for public APIs
- **No comments** in simple code, prefer descriptive names
- Use `ruff` for linting and `black` for formatting
- Follow async/await patterns for I/O operations
- Use structured logging with `structlog`
- Plugin API follows generated `plugins_internal.py` SDK