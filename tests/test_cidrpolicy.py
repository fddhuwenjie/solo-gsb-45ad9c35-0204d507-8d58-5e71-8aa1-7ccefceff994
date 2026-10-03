"""Unit tests for first-match CIDR policy compilation."""

from __future__ import annotations

import ipaddress

import pytest

from app.cidrpolicy import PolicyError, compile_policy


def compile_list(scope, default_action, rules):
    _, segments = compile_policy(scope, default_action, rules)
    return [(str(net), action) for net, action in segments]


def _assert_partition(scope, segments):
    scope_net = ipaddress.ip_network(scope)
    networks = [net for net, _ in segments]
    # Disjoint ...
    for i, net in enumerate(networks):
        for other in networks[i + 1 :]:
            assert not net.overlaps(other)
        assert net.subnet_of(scope_net)
    # ... covering the whole scope, with no address gaps.
    covered = sum(net.num_addresses for net in networks)
    assert covered == scope_net.num_addresses
    # ... and sorted by network address.
    assert networks == sorted(networks, key=lambda n: int(n.network_address))


def test_no_rules_returns_scope_with_default_action():
    _, segments = compile_policy("10.0.0.0/24", "deny", [])
    assert segments == [(ipaddress.ip_network("10.0.0.0/24"), "deny")]


def test_rule_covering_whole_scope_replaces_default():
    result = compile_list("10.0.0.0/24", "deny", [("10.0.0.0/24", "allow")])
    assert result == [("10.0.0.0/24", "allow")]


def test_first_match_narrow_rule_wins_when_declared_first():
    # /30 allow declared before a broad /26 deny: the /30 keeps allow while
    # the remainder of the /26 is deny; outside is default deny.
    result = compile_list(
        "10.0.0.0/24",
        "deny",
        [("10.0.0.0/30", "allow"), ("10.0.0.0/26", "deny")],
    )
    assert result[0] == ("10.0.0.0/30", "allow")
    assert ("10.0.0.4/30", "deny") in result
    assert ("10.0.0.8/29", "deny") in result
    assert ("10.0.0.16/28", "deny") in result
    assert ("10.0.0.32/27", "deny") in result
    assert ("10.0.0.64/26", "deny") in result
    assert ("10.0.0.128/25", "deny") in result


def test_nested_rule_declared_second_is_shadowed():
    # First-match: a broad first rule swallows every later rule inside it,
    # so the nested allow never changes anything.
    result = compile_list(
        "10.0.0.0/24",
        "allow",
        [("10.0.0.0/26", "deny"), ("10.0.0.0/30", "allow")],
    )
    assert result == [
        ("10.0.0.0/26", "deny"),
        ("10.0.0.64/26", "allow"),
        ("10.0.0.128/25", "allow"),
    ]


def test_later_nested_rule_never_overrides_first_match():
    # First rule allow-everything makes every later rule unreachable.
    result = compile_list(
        "10.0.0.0/24", "deny", [("10.0.0.0/24", "allow"), ("10.0.0.0/26", "deny")]
    )
    assert result == [("10.0.0.0/24", "allow")]


def test_same_action_siblings_merge_to_parent():
    # Two /27 halves of 10.0.0.64/26 both allow -> one /26; the default deny
    # around it must not join in.
    result = compile_list(
        "10.0.0.0/24",
        "deny",
        [("10.0.0.64/27", "allow"), ("10.0.0.96/27", "allow")],
    )
    assert result == [
        ("10.0.0.0/26", "deny"),
        ("10.0.0.64/26", "allow"),
        ("10.0.0.128/25", "deny"),
    ]


def test_different_action_siblings_do_not_merge():
    result = compile_list(
        "10.0.0.0/24",
        "deny",
        [("10.0.0.64/27", "allow"), ("10.0.0.96/27", "deny")],
    )
    assert result == [
        ("10.0.0.0/26", "deny"),
        ("10.0.0.64/27", "allow"),
        ("10.0.0.96/27", "deny"),
        ("10.0.0.128/25", "deny"),
    ]


def test_non_sibling_same_action_blocks_do_not_merge():
    # .1/32 and .2/32 share an action but are not halves of one prefix.
    result = compile_list(
        "10.0.0.0/30", "deny", [("10.0.0.1/32", "allow"), ("10.0.0.2/32", "allow")]
    )
    assert result == [
        ("10.0.0.0/32", "deny"),
        ("10.0.0.1/32", "allow"),
        ("10.0.0.2/32", "allow"),
        ("10.0.0.3/32", "deny"),
    ]


def test_action_from_rule_merges_with_same_default_action_sibling():
    # The upper /25 is default allow; the lower /25 rule also allows, so the
    # two siblings collapse back to the scope regardless of action origin.
    result = compile_list("10.0.0.0/24", "allow", [("10.0.0.128/25", "allow")])
    assert result == [("10.0.0.0/24", "allow")]


def test_siblings_under_partial_cover_split_but_uniform_halves_merge():
    # /23 allow followed by /24 allow inside the second half: the second /23
    # half splits (2.0/24 allow, 3.0/24 deny); it must not merge with the
    # first uniform /23 across the /23 boundary.
    result = compile_list(
        "192.168.0.0/22",
        "deny",
        [("192.168.0.0/23", "allow"), ("192.168.2.0/24", "allow")],
    )
    assert result == [
        ("192.168.0.0/23", "allow"),
        ("192.168.2.0/24", "allow"),
        ("192.168.3.0/24", "deny"),
    ]


def test_zero_scope_expands_rule_to_minimal_complement():
    result = compile_list("0.0.0.0/0", "deny", [("10.0.0.0/8", "allow")])
    _, segments = compile_policy("0.0.0.0/0", "deny", [("10.0.0.0/8", "allow")])
    assert ("10.0.0.0/8", "allow") in result
    assert len(result) == 9  # minimal complement of a /8 inside /0
    _assert_partition("0.0.0.0/0", segments)


def test_duplicate_and_overlapping_rules_are_allowed():
    result = compile_list(
        "10.0.0.0/24",
        "deny",
        [("10.0.0.0/26", "allow"), ("10.0.0.0/26", "allow"), ("10.0.0.192/26", "allow")],
    )
    assert result == [
        ("10.0.0.0/26", "allow"),
        ("10.0.0.64/26", "deny"),
        ("10.0.0.128/26", "deny"),
        ("10.0.0.192/26", "allow"),
    ]


def test_order_changes_first_match_outcome():
    # Narrow-first denies the /30 then allows the rest of the /26; broad-first
    # allows the whole /26 and the later /30 deny is shadowed there.
    narrow_first = [("10.0.0.0/30", "deny"), ("10.0.0.0/26", "allow")]
    broad_first = [("10.0.0.0/26", "allow"), ("10.0.0.0/30", "deny")]
    a = dict(compile_list("10.0.0.0/24", "deny", narrow_first))
    b = dict(compile_list("10.0.0.0/24", "deny", broad_first))
    assert a["10.0.0.0/30"] == "deny"
    assert a["10.0.0.4/30"] == "allow"
    assert b["10.0.0.0/26"] == "allow"


def test_invalid_scope_rejected():
    with pytest.raises(PolicyError) as exc:
        compile_policy("10.0.0.5/24", "deny", [])
    assert exc.value.code == "invalid_cidr"


def test_invalid_rule_cidr_rejected():
    with pytest.raises(PolicyError) as exc:
        compile_policy("10.0.0.0/24", "deny", [("10.0.0.0/128", "allow")])
    assert exc.value.code == "invalid_cidr"


def test_rule_outside_scope_rejected():
    with pytest.raises(PolicyError) as exc:
        compile_policy("10.0.0.0/24", "deny", [("10.1.0.0/24", "allow")])
    assert exc.value.code == "rule_outside_scope"


def test_ipv6_scope_rejected():
    with pytest.raises(PolicyError) as exc:
        compile_policy("2001:db8::/32", "deny", [])
    assert exc.value.code == "invalid_cidr"


@pytest.mark.parametrize(
    "scope,rules",
    [
        ("10.0.0.0/24", []),
        ("10.0.0.0/24", [("10.0.0.128/25", "allow")]),
        ("10.0.0.0/23", [("10.0.0.0/25", "allow"), ("10.0.1.64/26", "deny")]),
        ("172.16.0.0/13", [("172.20.0.0/16", "deny"), ("172.20.5.0/24", "allow")]),
        ("0.0.0.0/0", [("10.0.0.0/8", "allow"), ("192.168.0.0/16", "deny")]),
    ],
)
def test_result_is_sorted_disjoint_partition_with_coverage(scope, rules):
    _, segments = compile_policy(scope, "deny", rules)
    _assert_partition(scope, segments)
    # Sibling-merge minimality: no segment's two equal halves both occur as
    # same-action segments in the list.
    by_net = dict(segments)
    for net, action in segments:
        if net.prefixlen < 32:
            left, right = net.subnets()
            assert not (
                by_net.get(left) == action and by_net.get(right) == action
            ), f"{left} and {right} should have merged into {net}"
