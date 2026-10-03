"""Unit tests for stateless BGP announcement auditing."""

from __future__ import annotations

import ipaddress

import pytest

from app.bgpaudit import BgpAuditError, audit, fold_as_path


class R:
    def __init__(self, **kw):
        self.__dict__.update(kw)


class A:
    def __init__(self, **kw):
        self.__dict__.update(kw)


def c2p(customer, provider):
    return R(type="customer_provider", customer=customer, provider=provider)


def peer(a, b):
    return R(type="peer", a=a, b=b)


def ann(id, prefix, as_path):
    return A(id=id, prefix=prefix, as_path=as_path)


# ---------------------------------------------------------------------------
# Folding and loops
# ---------------------------------------------------------------------------


def test_fold_collapses_only_consecutive_duplicates():
    assert fold_as_path([1, 1, 2, 2, 2, 3, 3]) == [1, 2, 3]
    assert fold_as_path([1, 2, 1]) == [1, 2, 1]
    assert fold_as_path([7]) == [7]


def test_consecutive_prepending_is_folded_and_valid():
    result = audit(
        [c2p(10, 20), c2p(20, 30)],
        [ann("a", "10.0.0.0/24", [10, 10, 10, 20, 20, 30])],
    )["results"]
    assert result[0]["as_path"] == [10, 20, 30]
    assert result[0]["status"] == "valid"
    assert result[0]["origin"] == 30


def test_non_consecutive_repeat_is_as_loop():
    result = audit(
        [c2p(10, 20), c2p(30, 20)],
        [ann("a", "10.0.0.0/24", [10, 20, 20, 10])],
    )["results"]
    assert result[0]["as_path"] == [10, 20, 10]
    assert result[0]["status"] == "as_loop"
    assert result[0]["flags"] == []
    assert result[0]["violating_hop"] is None


def test_single_asn_path_is_valid():
    result = audit([], [ann("a", "10.0.0.0/24", [65000])])["results"]
    assert result[0]["status"] == "valid"
    assert result[0]["as_path"] == [65000]


# ---------------------------------------------------------------------------
# Valley-free shape
# ---------------------------------------------------------------------------


def test_customer_provider_climb_is_valid():
    result = audit(
        [c2p(10, 20), c2p(20, 30), c2p(30, 40)],
        [ann("a", "10.0.0.0/24", [10, 20, 30, 40])],
    )["results"]
    assert result[0]["status"] == "valid"
    assert result[0]["violating_hop"] is None


def test_provider_customer_descent_is_valid():
    # Viewed from 40: 40->30->20->10 is all provider->customer.
    result = audit(
        [c2p(10, 20), c2p(20, 30), c2p(30, 40)],
        [ann("a", "10.0.0.0/24", [40, 30, 20, 10])],
    )["results"]
    assert result[0]["status"] == "valid"


def test_up_peer_down_is_valid():
    result = audit(
        [c2p(10, 100), peer(100, 200), c2p(300, 200)],
        [ann("a", "10.0.0.0/24", [10, 100, 200, 300])],
    )["results"]
    assert result[0]["status"] == "valid"


def test_peer_only_is_valid():
    result = audit(
        [peer(100, 200)],
        [ann("a", "10.0.0.0/24", [100, 200])],
    )["results"]
    assert result[0]["status"] == "valid"


def test_two_peers_in_a_row_invalid_at_second_peer():
    result = audit(
        [peer(100, 200), peer(200, 300)],
        [ann("a", "10.0.0.0/24", [100, 200, 300])],
    )["results"]
    assert result[0]["status"] == "invalid_path"
    assert result[0]["violating_hop"] == {"hop": 1, "from_asn": 200, "to_asn": 300}


def test_up_edge_after_peer_is_first_violation():
    result = audit(
        [c2p(10, 100), peer(100, 200), c2p(200, 300)],
        [ann("a", "10.0.0.0/24", [10, 100, 200, 300])],
    )["results"]
    assert result[0]["status"] == "invalid_path"
    assert result[0]["violating_hop"] == {"hop": 2, "from_asn": 200, "to_asn": 300}


def test_up_edge_after_descent_is_first_violation():
    # 10->100 up, 100->200 down, 200->300 up: valley at hop 2.
    result = audit(
        [c2p(10, 100), c2p(200, 100), c2p(200, 300)],
        [ann("a", "10.0.0.0/24", [10, 100, 200, 300])],
    )["results"]
    assert result[0]["status"] == "invalid_path"
    assert result[0]["violating_hop"] == {"hop": 2, "from_asn": 200, "to_asn": 300}


def test_first_violation_reported_not_later_ones():
    # Path 10->20->30->40->50: hop 0 is a valid descent; hop 1 is an ascent
    # after that descent and is the first violation, even though the peer
    # edge at hop 2 would also be illegal once descending.
    result = audit(
        [
            c2p(20, 10),   # 10->20 is provider->customer (down)
            c2p(20, 30),   # 20->30 is customer->provider (up) -- violation
            peer(30, 40),
            c2p(50, 40),
        ],
        [ann("a", "10.0.0.0/24", [10, 20, 30, 40, 50])],
    )["results"]
    assert result[0]["violating_hop"] == {"hop": 1, "from_asn": 20, "to_asn": 30}


def test_unknown_adjacent_relationship_is_422():
    with pytest.raises(BgpAuditError) as exc:
        audit([c2p(10, 100)], [ann("a", "10.0.0.0/24", [10, 100, 999])])
    assert exc.value.code == "as_relation_unknown"
    assert "a" in exc.value.detail
    assert "hop 1" in exc.value.detail


def test_as_loop_when_unknown_edge_comes_after_the_repeat():
    # Edges are checked hop by hop.  The path repeats AS 10 at hop 1 with
    # both edges declared, so it is an as_loop and the undeclared hop 2 is
    # never reached.
    result = audit(
        [c2p(20, 10)],
        [ann("a", "10.0.0.0/24", [10, 20, 10, 30])],
    )["results"]
    assert result[0]["status"] == "as_loop"


def test_unknown_edge_before_repeat_is_422_not_loop():
    # The unknown edge at hop 1 is reached before the path would loop back to
    # AS 10 at hop 2, so the request fails.
    with pytest.raises(BgpAuditError) as exc:
        audit([c2p(20, 10)], [ann("a", "10.0.0.0/24", [10, 20, 30, 10])])
    assert exc.value.code == "as_relation_unknown"
    assert "hop 1" in exc.value.detail


def test_unknown_relationship_422_points_at_first_unknown_hop():
    with pytest.raises(BgpAuditError) as exc:
        audit([c2p(20, 10)], [ann("a", "10.0.0.0/24", [10, 20, 30, 40])])
    assert exc.value.code == "as_relation_unknown"
    assert "hop 1" in exc.value.detail
    assert "AS 20" in exc.value.detail and "AS 30" in exc.value.detail


def test_loop_short_circuits_valley_check():
    # Once the repeat (10) is reached at hop 1 the path is a loop and the
    # walk stops, so the later undeclared edge never triggers a 422; the
    # valley-free shape is not evaluated for looped paths.
    result = audit(
        [c2p(10, 100), peer(100, 50)],
        [ann("a", "10.0.0.0/24", [10, 100, 10, 999])],
    )["results"]
    assert result[0]["status"] == "as_loop"


# ---------------------------------------------------------------------------
# Relationship declaration conflicts
# ---------------------------------------------------------------------------


def test_peer_vs_transit_conflict_is_422():
    with pytest.raises(BgpAuditError) as exc:
        audit([peer(100, 200), c2p(100, 200)], [])
    assert exc.value.code == "as_relation_conflict"


def test_transit_claimed_both_directions_is_422():
    with pytest.raises(BgpAuditError) as exc:
        audit([c2p(100, 200), c2p(200, 100)], [])
    assert exc.value.code == "as_relation_conflict"


def test_self_relationship_is_422():
    with pytest.raises(BgpAuditError) as exc:
        audit([peer(100, 100)], [])
    assert exc.value.code == "invalid_as_relation"
    with pytest.raises(BgpAuditError) as exc:
        audit([c2p(100, 100)], [])
    assert exc.value.code == "invalid_as_relation"


def test_identical_duplicate_declarations_are_allowed():
    result = audit(
        [peer(100, 200), peer(200, 100), c2p(10, 20), c2p(10, 20)],
        [ann("a", "10.0.0.0/24", [100, 200])],
    )["results"]
    assert result[0]["status"] == "valid"


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


def test_invalid_prefix_is_422():
    with pytest.raises(BgpAuditError) as exc:
        audit([], [ann("a", "10.0.0.5/24", [10])])
    assert exc.value.code == "invalid_prefix"


def test_ipv6_prefix_is_422():
    with pytest.raises(BgpAuditError) as exc:
        audit([], [ann("a", "2001:db8::/32", [10])])
    assert exc.value.code == "invalid_prefix"


def test_empty_as_path_is_422():
    with pytest.raises(BgpAuditError) as exc:
        audit([], [ann("a", "10.0.0.0/24", [])])
    assert exc.value.code == "invalid_as_path"


def test_duplicate_announcement_id_is_422():
    with pytest.raises(BgpAuditError) as exc:
        audit(
            [peer(10, 20)],
            [ann("a", "10.0.0.0/24", [10, 20]), ann("a", "10.0.1.0/24", [10])],
        )
    assert exc.value.code == "duplicate_announcement_id"


# ---------------------------------------------------------------------------
# MOAS and origin-change comparison
# ---------------------------------------------------------------------------


def _basic_relations():
    # 10->100, 20->100 up; 100 peers 50; 50->60 down (60 customer of 50).
    return [c2p(10, 100), c2p(20, 100), peer(100, 50), c2p(60, 50)]


def test_same_prefix_multiple_origins_flagged_moas():
    results = audit(
        _basic_relations(),
        [
            ann("a", "203.0.113.0/24", [10, 100]),
            ann("b", "203.0.113.0/24", [20, 100]),
            ann("c", "203.0.113.0/24", [50]),
        ],
    )["results"]
    # All three have distinct origins -> all flagged.
    assert {r["id"]: r["flags"] for r in results} == {
        "a": ["moas"],
        "b": ["moas"],
        "c": ["moas"],
    }


def test_same_prefix_same_origin_is_not_moas():
    results = audit(
        _basic_relations(),
        [
            ann("a", "203.0.113.0/24", [10, 100]),
            ann("b", "203.0.113.0/24", [20, 100]),
        ],
    )["results"]
    assert all(r["flags"] == [] for r in results)


def test_more_specific_with_different_origin_flagged_origin_change():
    results = audit(
        _basic_relations(),
        [
            ann("cover", "203.0.113.0/24", [10, 100]),       # origin 100
            ann("spec", "203.0.113.0/25", [100, 50, 60]),   # origin 60
        ],
    )["results"]
    flags = {r["id"]: r["flags"] for r in results}
    assert flags["spec"] == ["origin_change"]
    assert flags["cover"] == []


def test_more_specific_with_same_origin_not_flagged():
    results = audit(
        _basic_relations(),
        [
            ann("cover", "203.0.113.0/24", [10, 100]),
            ann("spec", "203.0.113.128/25", [20, 100]),
        ],
    )["results"]
    assert all(r["flags"] == [] for r in results)


def test_nearest_covering_prefix_wins():
    # /22 origin 900, /24 origin 100, /25 origin 60.  The /25 is compared to
    # its nearest cover (the /24, origin 100), not the more distant /22;
    # the /24 is compared to the /22 and, having a different origin, is also
    # flagged.
    relations = _basic_relations() + [c2p(900, 50)]
    results = audit(
        relations,
        [
            ann("wide", "203.0.112.0/22", [900, 50]),
            ann("mid", "203.0.113.0/24", [10, 100]),
            ann("spec", "203.0.113.0/25", [100, 50, 60]),
        ],
    )["results"]
    flags = {r["id"]: r["flags"] for r in results}
    assert flags["wide"] == []
    assert flags["mid"] == ["origin_change"]  # 100 vs covering /22 origin 900
    assert flags["spec"] == ["origin_change"]  # 60 vs nearest /24 origin 100


def test_nearest_cover_matches_but_outer_differs_not_flagged():
    # /22 origin 900 and /24 origin 60 differ (so /24 is flagged), but the
    # /25 origin 60 matches its *nearest* cover (the /24): no origin_change
    # on /25 despite differing from the distant /22.
    relations = _basic_relations() + [c2p(900, 50)]
    results = audit(
        relations,
        [
            ann("wide", "203.0.112.0/22", [900, 50]),
            ann("mid", "203.0.113.0/24", [100, 50, 60]),  # origin 60
            ann("spec", "203.0.113.0/25", [100, 50, 60]),  # origin 60
        ],
    )["results"]
    flags = {r["id"]: r["flags"] for r in results}
    assert flags["mid"] == ["origin_change"]
    assert flags["spec"] == []


def test_non_covering_prefix_does_not_trigger_origin_change():
    results = audit(
        _basic_relations(),
        [
            ann("a", "203.0.113.0/25", [10, 100]),
            ann("b", "203.0.113.128/25", [100, 50, 60]),
        ],
    )["results"]
    assert all(r["flags"] == [] for r in results)


def test_equal_length_prefix_not_a_cover():
    results = audit(
        _basic_relations(),
        [
            ann("a", "203.0.113.0/24", [10, 100]),
            ann("b", "203.0.114.0/24", [100, 50, 60]),
        ],
    )["results"]
    assert all(r["flags"] == [] for r in results)


def test_failed_path_announcements_excluded_from_comparison():
    # A looped and an invalid announcement of the same prefix never produce
    # MOAS; the single valid announcement is unflagged.
    results = audit(
        _basic_relations() + [c2p(50, 70)],
        [
            ann("ok", "203.0.113.0/24", [10, 100]),
            ann("loop", "203.0.113.0/24", [10, 100, 10]),
            ann("valley", "203.0.113.128/25", [100, 50, 70]),  # peer then up
        ],
    )["results"]
    by_id = {r["id"]: r for r in results}
    assert by_id["ok"]["flags"] == []
    assert by_id["loop"]["flags"] == []
    assert by_id["valley"]["status"] == "invalid_path"
    assert by_id["valley"]["violating_hop"] == {"hop": 1, "from_asn": 50, "to_asn": 70}
    assert by_id["valley"]["flags"] == []


def test_failed_path_does_not_cover_for_origin_change():
    # The only covering announcement is looped, so the valid more-specific is
    # not compared against it.
    results = audit(
        _basic_relations(),
        [
            ann("loop", "203.0.113.0/24", [10, 100, 10]),
            ann("spec", "203.0.113.0/25", [100, 50, 60]),
        ],
    )["results"]
    by_id = {r["id"]: r for r in results}
    assert by_id["spec"]["flags"] == []


def test_moas_and_origin_change_can_both_apply():
    # /24 has two origins (moas on both): 100 and 900; the /25 origin 60
    # differs from both covering origins.
    relations = _basic_relations() + [c2p(900, 100)]
    results = audit(
        relations,
        [
            ann("m1", "203.0.113.0/24", [10, 100]),
            ann("m2", "203.0.113.0/24", [900]),
            ann("spec", "203.0.113.0/25", [100, 50, 60]),
        ],
    )["results"]
    by_id = {r["id"]: r for r in results}
    assert set(by_id["m1"]["flags"]) == {"moas"}
    assert set(by_id["m2"]["flags"]) == {"moas"}
    assert set(by_id["spec"]["flags"]) == {"origin_change"}


def test_moas_cover_origin_matching_one_origin_is_not_change():
    # The covering /24 is MOAS with origins 100 and 900; the /25 origin is
    # 100, which is one of the covering origins -> no origin_change.
    relations = _basic_relations() + [c2p(900, 100)]
    results = audit(
        relations,
        [
            ann("m1", "203.0.113.0/24", [10, 100]),
            ann("m2", "203.0.113.0/24", [900]),
            ann("spec", "203.0.113.0/25", [20, 100]),
        ],
    )["results"]
    by_id = {r["id"]: r for r in results}
    assert by_id["spec"]["flags"] == []


# ---------------------------------------------------------------------------
# Ordering and response shape
# ---------------------------------------------------------------------------


def test_results_sorted_by_network_address_prefixlen_and_id():
    results = audit(
        _basic_relations(),
        [
            ann("z", "10.0.1.0/24", [10, 100]),
            ann("a", "10.0.0.0/24", [10, 100]),
            ann("b", "203.0.113.0/25", [10, 100]),
            ann("c", "203.0.113.0/26", [10, 100]),
            ann("a2", "10.0.0.0/24", [20, 100]),
        ],
    )["results"]
    assert [(r["prefix"], r["id"]) for r in results] == [
        ("10.0.0.0/24", "a"),
        ("10.0.0.0/24", "a2"),
        ("10.0.1.0/24", "z"),
        ("203.0.113.0/25", "b"),
        ("203.0.113.0/26", "c"),
    ]


def test_prefix_is_canonicalised():
    results = audit(
        [],
        [ann("a", "203.0.113.1/32", [10])],
    )["results"]
    assert results[0]["prefix"] == "203.0.113.1/32"


def test_every_result_carries_full_shape():
    results = audit(
        _basic_relations() + [c2p(50, 70)],
        [
            ann("ok", "10.0.0.0/24", [10, 100]),
            ann("bad", "10.0.1.0/24", [100, 50, 70]),  # peer then up
        ],
    )["results"]
    by_id = {r["id"]: r for r in results}
    ok = by_id["ok"]
    assert set(ok) == {"id", "prefix", "as_path", "origin", "status", "flags", "violating_hop"}
    assert ok["status"] == "valid"
    assert ok["origin"] == 100
    bad = by_id["bad"]
    assert bad["status"] == "invalid_path"
    assert bad["violating_hop"] == {"hop": 1, "from_asn": 50, "to_asn": 70}
