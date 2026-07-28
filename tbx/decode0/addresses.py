"""Which statement owns which physical address.

The decoder tracks this so the line table and jump targets survive folding: a
statement moved into a body loses its slot in ``addrs``, but the address it
owned still has to be findable.

That mapping used to be a plain dict keyed by ``id(statement)``, holding no
reference to the statement. Folding discards statements constantly and CPython
reuses the ids of freed objects, so a statement created after a fold could land
on a freed one's id and inherit its address. Nothing in the corpus triggers it
-- that is a property of which objects happen to be alive, not of the design,
and the symptom would be one wrong line number in one wild program.

:class:`AddressOwnership` keeps the statement alive alongside its address, so
the id cannot be recycled while the claim stands. Identity is still the key,
deliberately: two equal statements on different source lines own different
addresses, so equality would merge them.
"""

from __future__ import annotations

from typing import Any


class AddressOwnership:
    """Identity-keyed statement -> physical address, holding its statements.

    The ``__getitem__``/``get`` shim accepts a raw ``id()`` so the existing
    call sites keep working while they migrate to :meth:`claim` and
    :meth:`address_of`.
    """

    __slots__ = ("_by_id",)

    def __init__(self) -> None:
        # id -> (address, statement). The statement is retained solely to keep
        # its id from being reused; nothing reads it back.
        self._by_id: dict[int, tuple[Any, Any]] = {}

    def claim(self, statement: Any, address: Any) -> None:
        """Record that ``statement`` owns ``address``."""
        self._by_id[id(statement)] = (address, statement)

    def address_of(self, statement: Any) -> Any:
        """The address ``statement`` owns, or None."""
        found = self._by_id.get(id(statement))
        return None if found is None else found[0]

    # -- mapping shim for the id-keyed call sites -------------------------

    def __setitem__(self, key: int, address: Any) -> None:
        raise TypeError(
            "assign through claim(statement, address): a raw id cannot keep "
            "its statement alive, which is the bug this class removes"
        )

    def __getitem__(self, key: int) -> Any:
        found = self._by_id.get(key)
        if found is None:
            raise KeyError(key)
        return found[0]

    def get(self, key: int, default: Any = None) -> Any:
        found = self._by_id.get(key)
        return default if found is None else found[0]

    def __contains__(self, key: int) -> bool:
        return key in self._by_id

    def __bool__(self) -> bool:
        return bool(self._by_id)

    def __len__(self) -> int:
        return len(self._by_id)

    def pop(self, key: int, default: Any = None) -> Any:
        """Release a claim and return the address it held.

        Folding rebuilds a statement and moves its address to the replacement;
        releasing the old claim also drops the reference keeping it alive,
        which is the point at which its id may safely be reused.
        """
        found = self._by_id.pop(key, None)
        return default if found is None else found[0]

    def values(self):
        """The claimed addresses, for the callers that scan them."""
        return [address for address, _ in self._by_id.values()]
