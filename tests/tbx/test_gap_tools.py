import pytest

from tbx.tools.compare_gap_reports import compare


def report(hits=(), failures=()):
    return {
        "schema_version": 1,
        "corpus_fingerprint": "same",
        "hits": [{"name": n} for n in hits],
        "failures": [{"name": n, "signature": s} for n, s in failures],
    }


def test_compare_classifies_progress_and_regression():
    old = report(hits=("regress.exe",), failures=(("done.exe", "old"), ("advance.exe", "a")))
    new = report(hits=("done.exe",), failures=(("regress.exe", "r"), ("advance.exe", "b")))
    result = compare(old, new)
    assert result["newly_decoded"] == ["done.exe"]
    assert result["regressed"] == ["regress.exe"]
    assert result["advanced"] == ["advance.exe"]


def test_compare_rejects_different_corpus():
    old = report()
    new = report()
    new["corpus_fingerprint"] = "different"
    with pytest.raises(ValueError, match="different corpus"):
        compare(old, new)
