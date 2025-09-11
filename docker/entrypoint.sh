#!/bin/bash
set -e

# PlexiChat Docker entrypoint script
# Handles initialization for dev/prod environments

echo "[INFO] Starting PlexiChat container entrypoint..."

# Check if we're in development mode (passed as first argument)
if [ "$1" = "dev" ]; then
    echo "[INFO] Running in development mode"
    # Ensure Cython extensions are built
    if [ ! -f "build/compilation.cpython-311-x86_64-linux-gnu.so" ] && [ ! -f "build/compilation.cp311-win_amd64.pyd" ]; then
        echo "[INFO] Building Cython extensions for development..."
        make cythonize
    fi
    
    # Run any database migrations if needed
    if command -v alembic &> /dev/null; then
        echo "[INFO] Running database migrations..."
        alembic upgrade head || echo "[WARNING] Alembic migrations skipped (not configured)"
    fi
    
    # Start with the original command
    exec "$@"
else
    echo "[INFO] Running in production mode"
    
    # For production, ensure compiled extensions exist
    if [ ! -f "build/compilation*.so" ] && [ ! -f "build/compilation*.pyd" ]; then
        echo "[ERROR] Compiled Cython extensions not found in build/ directory"
        echo "Please ensure the development stage was built correctly"
        exit 1
    fi
    
    # Production readiness checks
    if [ -z "$POSTGRES_URL" ] && [ -z "$DATABASE_URL" ]; then
        echo "[WARNING] No database URL configured - using SQLite"
    fi
    
    # Run migrations in production too
    if command -v alembic &> /dev/null; then
        echo "[INFO] Running production database migrations..."
        alembic upgrade head || echo "[WARNING] Alembic migrations skipped"
    fi
    
    # Execute the main command
    exec "$@"
fi

echo "[INFO] Entrypoint completed successfully"