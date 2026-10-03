"""Unit tests for the CIDR set arithmetic."""

from __future__ import annotations

import pytest

from app.cidrmath import compute_free, delegation_fragments, lowest_aligned, parse_network


def n(addr: str):
    return parse_network(addr)


def test_full_pool_free():
    assert compute_free(n("10.0.0.0/24"), []) == [n("10.0.0.0/24")]


def test_exclusion_in_middle_splits_to_minimal_cidrs():
    # Removing .128/26: the lower remainder is a whole /25; the upper one a /26.
    free = compute_free(n("10.0.0.0/24"), [n("10.0.0.128/26")])
    assert free == [n("10.0.0.0/25"), n("10.0.0.192/26")]


def test_exclusion_middle_merges_minimal_cidrs():
    # 10.0.0.0/24 minus 10.0.0.128/25 => one /25 block
    free = compute_free(n("10.0.0.0/24"), [n("10.0.0.128/25")])
    assert free == [n("10.0.0.0/25")]


def test_release_merges_back_to_simplest():
    free = compute_free(
        n("10.0.0.0/24"),
        [n("10.0.0.0/25"), n("10.0.0.128/25")],
    )
    assert free == []


def test_lowest_aligned_prefers_lowest_address():
    free = compute_free(n("10.0.0.0/24"), [n("10.0.0.0/26")])
    # free: 10.0.0.64/26, 10.0.0.128/25
    chosen = lowest_aligned(free, 26)
    assert chosen == n("10.0.0.64/26")


def test_lowest_aligned_supernet_selection():
    # free space: 10.0.0.0/26 and 10.0.0.128/25; request /25 must
    # come out of the larger, higher block, not the tiny low one.
    free = [n("10.0.0.0/26"), n("10.0.0.128/25")]
    assert lowest_aligned(free, 25) == n("10.0.0.128/25")


def test_lowest_aligned_fragmented_fit():
    # 10.0.0.0/24 with .0/26 and .128/26 excluded; free is .64/26 + .192/26
    free = compute_free(n("10.0.0.0/24"), [n("10.0.0.0/26"), n("10.0.0.128/26")])
    assert lowest_aligned(free, 26) == n("10.0.0.64/26")
    # no block large enough for a /25
    assert lowest_aligned(free, 25) is None


def test_lowest_aligned_no_space():
    assert lowest_aligned([n("10.0.0.0/30")], 24) is None


def test_allocations_never_overlap_exclusions_or_each_other():
    blocked = [n("10.0.0.8/30"), n("10.0.0.0/29"), n("10.0.0.64/26")]
    free = compute_free(n("10.0.0.0/24"), blocked)
    picked = lowest_aligned(free, 27)
    assert picked is not None
    for b in blocked:
        assert not picked.overlaps(b)
    # Lowest aligned /27 after .0/29+8/30 is .32/27 (not .16, which only has a /28).
    assert picked == n("10.0.0.32/27")


def test_collapse_after_allocation_release_sequence():
    # /28 = .0..15.  Allocate the two low /30s, then release them one by one;
    # the free set must collapse to the minimal CIDR representation.
    pool = n("192.168.0.0/28")
    allocated = [n("192.168.0.8/30"), n("192.168.0.12/30")]
    free = compute_free(pool, allocated)
    assert free == [n("192.168.0.0/29")]

    free = compute_free(pool, [n("192.168.0.8/30")])
    # .0..7 and .12..15 collapse to a /29 each
    assert free == [n("192.168.0.0/29"), n("192.168.0.12/30")]


def test_strict_cidr_rejects_host_bits():
    with pytest.raises(ValueError):
        parse_network("10.0.0.5/24")


def test_single_address_pool():
    free = compute_free(n("10.0.0.1/32"), [])
    assert free == [n("10.0.0.1/32")]
    assert lowest_aligned(free, 32) == n("10.0.0.1/32")


def test_delegation_fragments_tagged_subnet_is_unsplit():
    # Subnets smaller than a /24 live inside one /24: one tagged fragment.
    assert delegation_fragments(n("192.0.2.64/26")) == [n("192.0.2.64/26")]
    assert delegation_fragments(n("192.0.2.0/25")) == [n("192.0.2.0/25")]
    assert delegation_fragments(n("192.0.2.1/32")) == [n("192.0.2.1/32")]


def test_delegation_fragments_octet_boundary_is_unsplit():
    assert delegation_fragments(n("192.0.2.0/24")) == [n("192.0.2.0/24")]
    assert delegation_fragments(n("192.0.0.0/16")) == [n("192.0.0.0/16")]
    assert delegation_fragments(n("10.0.0.0/8")) == [n("10.0.0.0/8")]


def test_delegation_fragments_split_at_next_octet_boundary():
    # /23 straddling a /24 boundary becomes two covering, disjoint /24s.
    assert delegation_fragments(n("192.0.2.0/23")) == [
        n("192.0.2.0/24"),
        n("192.0.3.0/24"),
    ]
    # /22 becomes four /24s.
    assert delegation_fragments(n("192.0.4.0/22")) == [
        n("192.0.4.0/24"),
        n("192.0.5.0/24"),
        n("192.0.6.0/24"),
        n("192.0.7.0/24"),
    ]
    # /15 becomes two /16s; /7 becomes two /8s.
    assert delegation_fragments(n("192.0.0.0/15")) == [
        n("192.0.0.0/16"),
        n("192.1.0.0/16"),
    ]
    assert delegation_fragments(n("8.0.0.0/7")) == [
        n("8.0.0.0/8"),
        n("9.0.0.0/8"),
    ]


def test_delegation_fragments_cover_without_overlap():
    boundaries = (8, 16, 24)
    for cidr in (
        "192.0.2.0/23",
        "192.0.0.0/15",
        "172.16.0.0/13",
        "10.0.0.0/9",
        "0.0.0.0/0",
    ):
        net = n(cidr)
        fragments = delegation_fragments(net)
        # Minimal: every fragment is aligned to the next octet boundary
        # below the original prefix (so no coarser valid split exists).
        if net.prefixlen < 24 and net.prefixlen not in boundaries:
            boundary = min(b for b in boundaries if b > net.prefixlen)
            assert all(f.prefixlen == boundary for f in fragments)
        # Covering: the union equals the original network.
        assert sum(f.num_addresses for f in fragments) == net.num_addresses
        # Disjoint.
        for i, a in enumerate(fragments):
            for b in fragments[i + 1 :]:
                assert not a.overlaps(b)
            assert a.subnet_of(net)


def test_delegation_fragments_stable_order():
    fragments = delegation_fragments(n("10.0.0.0/12"))
    assert fragments == sorted(fragments, key=lambda x: int(x.network_address))
