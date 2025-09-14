"""Compilation optimizer registry for Cython and Numba integration.

Provides a registry to compile pure Python functions to Cython/Numba for performance.
Supports async wrappers using asyncio.to_thread for compiled calls.
"""

import asyncio
from collections.abc import Callable
from enum import Enum
import importlib
import inspect
from pathlib import Path
from typing import Any, TypeVar

try:
    import cython
    from Cython.Build import cythonize

    CYTHON_AVAILABLE = True
except ImportError:
    CYTHON_AVAILABLE = False

try:
    from numba import jit, njit

    NUMBA_AVAILABLE = True
except ImportError:
    NUMBA_AVAILABLE = False

T = TypeVar("T")


class CompilerType(Enum):
    """Enum for supported compilers."""

    CYTHON = "cython"
    NUMBA = "numba"


class CompilationError(Exception):
    """Raised when compilation fails."""


class CompilationOptimizer:
    """Registry for compiling functions with Cython or Numba.

    Registers functions for compilation and provides async-compatible wrappers.
    """

    def __init__(self) -> None:
        self._registered: dict[str, dict[str, Any]] = {}
        self._compiled_cache: dict[str, Any] = {}

    def register_function(
        self,
        module_path: str,
        function_name: str,
        compiler: CompilerType = CompilerType.NUMBA,
        *,
        force_recompile: bool = False,
        cache_dir: Path | None = None,
    ) -> None:
        """Register a function for compilation.

        Args:
            module_path: Path to the module (e.g., 'plexichat.core.services').
            function_name: Name of the function to compile.
            compiler: Compiler to use (default: NUMBA).
            force_recompile: If True, recompile even if cached.
            cache_dir: Directory for compiled artifacts (default: .cython_cache).

        Raises:
            CompilationError: If compiler is unavailable or registration fails.
        """
        key = f"{module_path}.{function_name}"

        if compiler == CompilerType.CYTHON and not CYTHON_AVAILABLE:
            raise CompilationError("Cython not available. Install with pip.")
        if compiler == CompilerType.NUMBA and not NUMBA_AVAILABLE:
            raise CompilationError("Numba not available. Install with pip.")

        try:
            module = importlib.import_module(module_path)
            func = getattr(module, function_name)
            if not callable(func):
                raise CompilationError(f"{function_name} is not callable.")

            # Inspect function signature for type hints
            sig = inspect.signature(func)

            self._registered[key] = {
                "module": module,
                "function": func,
                "compiler": compiler,
                "signature": sig,
                "force_recompile": force_recompile,
                "cache_dir": cache_dir or Path(".cython_cache"),
            }

            # Auto-compile if not cached
            if force_recompile or key not in self._compiled_cache:
                self._compile_single(key)

        except ImportError as e:
            raise CompilationError(f"Failed to import {module_path}: {e}")
        except AttributeError as e:
            raise CompilationError(
                f"Function {function_name} not found in {module_path}: {e}"
            )

    def _compile_single(self, key: str) -> None:
        """Compile a single registered function."""
        reg = self._registered[key]
        compiler = reg["compiler"]
        func = reg["function"]

        if compiler == CompilerType.NUMBA:
            compiled_func = self._compile_with_numba(func)
        else:  # CYTHON
            compiled_func = self._compile_with_cython(key, reg)

        self._compiled_cache[key] = compiled_func

    def _compile_with_numba(self, func: Callable) -> Callable:
        """Compile function with Numba JIT."""
        if inspect.iscoroutinefunction(func):
            raise CompilationError("Numba does not support async functions directly.")

        # Use njit for numerical functions, jit otherwise
        is_numerical = any(
            arg.annotation in (int, float, complex)
            for arg in inspect.signature(func).parameters.values()
        )
        decorator = njit if is_numerical else jit

        try:
            return decorator(func)
        except Exception as e:
            raise CompilationError(f"Numba compilation failed: {e}")

    def _compile_with_cython(self, key: str, reg: dict[str, Any]) -> Callable:
        """Compile function with Cython (requires .pyx file)."""
        # For prototype, assume .pyx exists or create inline
        # In full impl, this would build extension modules
        module_path = reg["module"].__file__
        if not module_path:
            raise CompilationError("Module has no __file__ attribute.")

        pyx_path = Path(module_path).with_suffix(".pyx")
        if not pyx_path.exists():
            raise CompilationError(f"Cython source {pyx_path} not found.")

        cache_dir = reg["cache_dir"]
        cache_dir.mkdir(exist_ok=True)

        try:
            # Cythonize the .pyx file
            cythonize(
                str(pyx_path),
                compiler_directives={"language_level": "3"},
                build_dir=str(cache_dir),
            )

            # Import the compiled module
            compiled_module_name = f"{key}_cython"
            compiled_module = importlib.import_module(compiled_module_name)

            return getattr(compiled_module, reg["function"].__name__)

        except Exception as e:
            raise CompilationError(f"Cython compilation failed for {key}: {e}")

    async def compile_all(self) -> dict[str, bool]:
        """Compile all registered functions asynchronously.

        Returns:
            Dict of function keys to success status.
        """
        tasks = []
        results = {}

        for key in self._registered:
            if key not in self._compiled_cache:
                task = asyncio.create_task(self._async_compile(key))
                tasks.append((key, task))

        if tasks:
            compiled_results = await asyncio.gather(
                *[task for _, task in tasks], return_exceptions=True
            )

            for (key, _), success in zip(tasks, compiled_results, strict=False):
                if isinstance(success, Exception):
                    results[key] = False
                else:
                    results[key] = True
                    self._compiled_cache[key] = success

        # Compile already registered but uncompiled
        for key in self._registered:
            if key not in self._compiled_cache:
                results[key] = False

        return results

    async def _async_compile(self, key: str) -> Callable:
        """Compile a single function in thread to avoid blocking."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, lambda: self._compile_single(key))

    def get_compiled(
        self, module_path: str, function_name: str, default: Callable = None
    ) -> Callable | None:
        """Get compiled version of a function.

        Args:
            module_path: Module path.
            function_name: Function name.
            default: Fallback if not compiled.

        Returns:
            Compiled function or default.
        """
        key = f"{module_path}.{function_name}"
        return self._compiled_cache.get(key, default)

    async def call_compiled(
        self,
        module_path: str,
        function_name: str,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        """Async wrapper to call compiled functions.

        Uses asyncio.to_thread for sync compiled funcs, direct call for async.
        """
        key = f"{module_path}.{function_name}"
        if key not in self._compiled_cache:
            raise CompilationError(f"Function {key} not compiled.")

        compiled = self._compiled_cache[key]

        if inspect.iscoroutinefunction(compiled):
            return await compiled(*args, **kwargs)
        else:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, lambda: compiled(*args, **kwargs))

    def clear_cache(self) -> None:
        """Clear compiled cache."""
        self._compiled_cache.clear()


# Global singleton instance
optimizer = CompilationOptimizer()


__all__ = [
    "CompilationOptimizer",
    "CompilerType",
    "optimizer",
]
