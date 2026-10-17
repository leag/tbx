"""Bounded memoization for immutable analysis snapshots."""

from collections import OrderedDict
from collections.abc import Callable
from functools import wraps
from typing import TypeVar

_T = TypeVar("_T")
_R = TypeVar("_R")


def identity_cache(function: Callable[[_T], _R]) -> Callable[[_T], _R]:
    """Cache the last 32 inputs by identity without hashing their contents.

    Inputs must be immutable. Keeping each input beside its result prevents
    object ID reuse from returning an unrelated cached result.
    """
    cache: OrderedDict[int, tuple[_T, _R]] = OrderedDict()

    @wraps(function)
    def cached(value: _T) -> _R:
        key = id(value)
        entry = cache.get(key)
        if entry is not None:
            cache.move_to_end(key)
            return entry[1]
        result = function(value)
        cache[key] = (value, result)
        if len(cache) > 32:
            cache.popitem(last=False)
        return result

    return cached
