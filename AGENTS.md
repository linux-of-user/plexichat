# PlexiChat - Agent Development Guide

## Commands

### Initial Setup
```bash
python -m venv venv                    # Create virtual environment
source venv/bin/activate               # Activate (Linux/Mac)
# OR venv\Scripts\activate             # Activate (Windows)
pip install -e .                      # Install package in editable mode
pip install -e .[dev,test]             # Install with dev/test dependencies
```

### Build & Test
```bash
make docs                              # Build documentation
make docs-serve                       # Serve docs locally (port 8000)
python -m pytest                      # Run tests
python -m pytest --cov=src/plexichat  # Run tests with coverage
ruff check src/                       # Run linter
black src/                            # Format code
```

### Development Server
```bash
python run.py                         # Start full stack (API + WebUI + CLI)
python run.py --nowebui --nocli       # API server only
python run.py --noserver --nocli      # WebUI only
```

## Tech Stack & Architecture

**Backend**: FastAPI, SQLAlchemy, Alembic, Redis, asyncpg  
**Frontend**: WebUI components (details in `/interfaces`)  
**Database**: PostgreSQL with Redis caching  
**Security**: Cryptography, PassLib, python-jose  
**Monitoring**: Prometheus, structlog  

**Structure**: Clean architecture with `/src/plexichat` containing `core/`, `features/`, `infrastructure/`, `interfaces/`, and `plugins/`

## Code Style

- **Python 3.11+** required
- **Black** formatter (88 char line length)
- **Ruff** linter with comprehensive rules
- **Type hints** required (pyright/mypy)
- **Async/await** patterns preferred
- Import order: stdlib, third-party, first-party

