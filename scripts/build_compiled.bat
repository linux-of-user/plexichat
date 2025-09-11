@echo off
REM Windows-compatible compilation pipeline for Cython/Numba optimizations
REM Run this before benchmarks or production builds to compile extensions and warm up JIT

echo Building Cython/Numba optimizations for PlexiChat...
echo ====================================================

REM Check if Python is available
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: Python not found. Please ensure Python 3.11+ is in PATH.
    exit /b 1
)

REM Create cache directory
if not exist ".cython_cache" mkdir .cython_cache

REM Compile Cython files
echo Compiling Cython extensions...
python -c "
from Cython.Build import cythonize
from setuptools.extension import Extension
from Cython.Distutils import build_ext
import glob
import os

# Find all .pyx files
pyx_files = glob.glob('src/plexichat/**/*.pyx', recursive=True)

if pyx_files:
    extensions = [
        Extension(
            os.path.splitext(os.path.basename(pyx))[0],
            [pyx],
            language='c++'
        ) for pyx in pyx_files
    ]
    
    # Build extensions
    setup_kwargs = {
        'ext_modules': cythonize(extensions, compiler_directives={'language_level': '3'}),
        'cmdclass': {'build_ext': build_ext},
        'script_args': ['build_ext', '--inplace']
    }
    
    from setuptools import setup
    setup(**setup_kwargs)
    print('Cython compilation completed successfully')
else:
    print('No .pyx files found to compile')
"

if %errorlevel% neq 0 (
    echo Warning: Cython compilation had issues, continuing...
)

REM Warm up Numba JIT functions
echo Warming up Numba JIT compilation...
python -c "
import numba
from plexichat.core.clustering.cluster_manager import _rebuild_hash_ring_internal

# Warm up Numba functions
try:
    node_ids = [b'node1', b'node2']
    _rebuild_hash_ring_internal(node_ids, 10)
    print('Numba JIT warm-up completed')
except Exception as e:
    print(f'Numba warm-up warning: {e}')
"

REM Verify compilation
echo Verifying compilation artifacts...
python -c "
try:
    from plexichat.core.services.message_checksum import calculate_checksum
    from plexichat.core.clustering.cluster_hash_ring import build_hash_ring
    from plexichat.core.performance.cache_lookup import fast_cache_get
    print('All compiled modules import successfully')
except ImportError as e:
    print(f'Import warning - some modules may need manual compilation: {e}')
"

REM Update __pycache__ timestamps
echo Updating cache timestamps...
for /r src/plexichat %%f in (*.py) do (
    touch "%%f"
)

echo.
echo ====================================================
echo Compilation pipeline completed!
echo.
echo To run benchmarks: pytest tests/test_compilation.py -v --benchmark-compare
echo To run full tests: pytest tests/ --cov=src/plexichat --cov-report=html
echo.
echo Note: Cython .so/.pyd files are in source directories for development.
echo For production, use 'pip install -e .' after compilation.