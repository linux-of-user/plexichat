"""Type stubs for Numba"""

from typing import Any, Callable, TypeVar, overload, Union, Sequence

T = TypeVar("T")

def jit(
    nopython: bool = True,
    cache: bool = False,
    parallel: bool = False,
    fastmath: bool = False,
    error_model: str | None = None,
    **kwargs: Any,
) -> Callable[[Callable], Callable]: ...

def njit(
    cache: bool = False,
    parallel: bool = False,
    fastmath: bool = False,
    error_model: str | None = None,
    **kwargs: Any,
) -> Callable[[Callable], Callable]: ...

def vectorize(
    nopython: bool = True,
    cache: bool = False,
    target: str = "cpu",
    **kwargs: Any,
) -> Callable: ...

def guvectorize(
    sig: str,
    layout: str,
    nopython: bool = True,
    cache: bool = False,
    target: str = "cpu",
    **kwargs: Any,
) -> Callable: ...

class typed:
    def __init__(self, pos: int = 0) -> None: ...
    def __call__(self, func: Callable) -> Callable: ...

class int64:
    def __init__(self, value: int) -> None: ...
    @property
    def value(self) -> int: ...

class float64:
    def __init__(self, value: float) -> None: ...
    @property
    def value(self) -> float: ...

class boolean:
    def __init__(self, value: bool) -> None: ...
    @property
    def value(self) -> bool: ...