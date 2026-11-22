from urllib.parse import parse_qs, urlsplit

import pytest

from emule_test_harness.rust_rest_contract import iter_library_files, iter_library_locations, iter_library_roots


def test_library_pages_keep_filters_and_continue_without_total_cap():
    calls = []
    def fetch(path):
        calls.append(path)
        cursor = parse_qs(urlsplit(path).query).get("cursor", [None])[0]
        index = 1 if cursor else 0
        return {"data": [{"hash": f"{index + 1:032x}", "displayName": "Sample.bin"}],
                "meta": {"hasMore": not index, "nextCursor": None if index else "next"}}
    rows = list(iter_library_files(fetch, view="shared", search="Sample", root_id="7", count_total=True))
    assert [row["hash"] for row in rows] == [f"{n:032x}" for n in (1, 2)]
    assert len(calls) == 2
    for path in calls:
        query = parse_qs(urlsplit(path).query)
        assert {key: query[key] for key in ("view", "q", "rootId", "limit", "countTotal")} == {
            "view": ["shared"], "q": ["Sample"], "rootId": ["7"], "limit": ["200"], "countTotal": ["true"]}


def test_library_locations_use_separate_cached_pages():
    paths = []
    def fetch(path):
        paths.append(path)
        return {"data": [{"path": "/library/Sample.bin", "present": False}],
                "meta": {"hasMore": False, "nextCursor": None}}
    assert list(iter_library_locations(fetch, "41" * 16)) == [{"path": "/library/Sample.bin", "present": False}]
    assert paths == [f"/library/files/{'41' * 16}/locations?limit=200"]


def test_shared_paging_owner_preserves_identity_order_and_refuses_stalled_cursor():
    def roots(_):
        return {"data": [{"id": "2"}, {"id": "1"}], "meta": {"hasMore": False, "nextCursor": None}}
    with pytest.raises(RuntimeError, match="immutable identities"):
        list(iter_library_roots(roots))
    def files(_):
        return {"data": [{"hash": "41" * 16, "displayName": "Sample.bin"}],
                "meta": {"hasMore": True, "nextCursor": "same"}}
    with pytest.raises(RuntimeError, match="continuation did not advance"):
        list(iter_library_files(files))
