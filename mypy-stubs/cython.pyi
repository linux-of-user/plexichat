"""Type stubs for Cython"""

from typing import Any, Callable, TypeVar, overload

T = TypeVar("T")

@overload
def cythonize(
    modules: str | list[str],
    compiler_directives: dict[str, Any] | None = None,
    **kwargs: Any,
) -> list[str]: ...

@overload
def cythonize(
    modules: Callable[[], list[str]],
    compiler_directives: dict[str, Any] | None = None,
    **kwargs: Any,
) -> list[str]: ...

def compile(
    source: str,
    modname: str,
    output_dir: str | None = None,
    extensions: list[str] | None = None,
    compiler_directives: dict[str, Any] | None = None,
    include_path: list[str] | None = None,
) -> None: ...

class locals:
    """Cython locals() directive"""
    pass

class cclass:
    """Cython cdef class decorator"""
    def __init__(self, base_type: type | None = None, **kwargs: Any) -> None: ...
    def __call__(self, cls: type) -> type: ...

def cfunc(
    sig: str,
    result_type: type | None = None,
    locals: dict[str, type] | None = None,
    **kwargs: Any,
) -> Callable: ...