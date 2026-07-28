"""Address ownership must not depend on an id staying unique.

`stmt_addr` maps a statement to the physical address it owns, keyed by
`id(statement)` and holding no reference to it. Folding discards statements
constantly, and CPython reuses the ids of freed objects -- so a statement
created after a fold can land on a freed one's id and inherit its address.

Nothing in the corpus triggers it today. That is a property of which objects
happen to be alive, not of the design, and it is the kind of bug that appears
as one wrong line number in one wild program. Keeping the statement alive
alongside its address removes the possibility.
"""

import gc
import weakref

from tbx import ir
from tbx.decode0.addresses import AddressOwnership


def test_an_address_can_be_read_back():
    owner = AddressOwnership()
    stmt = ir.End()

    owner.claim(stmt, 0x1234)

    assert owner.address_of(stmt) == 0x1234


def test_an_unclaimed_statement_owns_no_address():
    assert AddressOwnership().address_of(ir.End()) is None


def test_claiming_keeps_the_statement_alive():
    """The property that makes id reuse impossible."""
    owner = AddressOwnership()
    stmt = ir.Goto(1)
    ref = weakref.ref(stmt)

    owner.claim(stmt, 0x10)
    del stmt
    gc.collect()

    assert ref() is not None, "a claimed statement must not be collectable"


def test_a_plain_id_keyed_dict_does_not_keep_it_alive():
    """Contrast, so the reason for the class is on the record."""
    table = {}
    stmt = ir.Goto(2)
    ref = weakref.ref(stmt)

    table[id(stmt)] = 0x10
    del stmt
    gc.collect()

    assert ref() is None
    # The entry survives its statement, which is exactly the stale key that a
    # recycled id would collide with.
    assert table


def test_two_equal_statements_own_their_addresses_separately():
    # Equality is not identity here: two identical PRINTs on different source
    # lines own different addresses.
    owner = AddressOwnership()
    first, second = ir.End(), ir.End()

    owner.claim(first, 0x10)
    owner.claim(second, 0x20)

    assert first == second
    assert owner.address_of(first) == 0x10
    assert owner.address_of(second) == 0x20


def test_a_later_claim_replaces_an_earlier_one():
    owner = AddressOwnership()
    stmt = ir.End()

    owner.claim(stmt, 0x10)
    owner.claim(stmt, 0x20)

    assert owner.address_of(stmt) == 0x20


def test_reads_still_accept_a_raw_id():
    # Call sites read with `.get(id(s))`; that is safe, because a read cannot
    # create a claim that outlives its statement.
    owner = AddressOwnership()
    stmt = ir.End()
    owner.claim(stmt, 0x10)

    assert owner.get(id(stmt)) == 0x10
    assert owner.get(id(ir.Goto(1))) is None


def test_assigning_by_raw_id_is_refused():
    """Writing by id is the bug, so the shim must not offer it.

    A raw id cannot keep its statement alive, which is precisely how a stale
    claim outlives its owner and a recycled id inherits an address.
    """
    import pytest

    owner = AddressOwnership()

    with pytest.raises(TypeError, match="assign through claim"):
        owner[id(ir.End())] = 0x10
