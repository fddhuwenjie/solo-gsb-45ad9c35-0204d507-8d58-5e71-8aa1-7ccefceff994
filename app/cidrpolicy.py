"""Compile first-match CIDR allow/deny rules into disjoint policy segments.

Rules are evaluated in declaration order against every address: the first
rule whose network contains the address decides the action, and addresses
matched by no rule receive the default action.  The compiled result is a
partition of the whole *scope* into disjoint, sorted CIDR segments.

Two adjacent segments are collapsed into their parent prefix **only** when
they are the two equal-sized siblings of that prefix *and* carry the same
action; the source of the action (a rule or the default) is irrelevant for
merging.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from .cidrmath import parse_network

# A segment is a network together with the action applied to every address
# inside it.
Segment = tuple[ipaddress.IPv4Network, str]


class PolicyError(Exception):
    """A policy input that cannot be compiled."""

    def __init__(self, detail: str, code: str):
        super().__init__(detail)
        self.detail = detail
        self.code = code


@dataclass(frozen=True)
class Rule:
    network: ipaddress.IPv4Network
    action: str


def compile_policy(
    scope_value: str,
    default_action: str,
    raw_rules: list[tuple[str, str]],
) -> tuple[ipaddress.IPv4Network, list[Segment]]:
    """Validate inputs and compile ``raw_rules`` over ``scope_value``.

    ``raw_rules`` is the ordered list of ``(cidr, action)`` pairs; its order
    is the first-match priority.  Returns the parsed scope network and the
    minimal, disjoint, address-ordered segments covering the whole scope.

    Raises :class:`PolicyError` for a malformed scope/rule CIDR or for a
    rule that is not contained in the scope.
    """

    try:
        scope = parse_network(scope_value)
    except ValueError as exc:
        raise PolicyError(
            f"invalid scope CIDR {scope_value!r}: {exc}", code="invalid_cidr"
        )

    rules: list[Rule] = []
    for cidr_value, action in raw_rules:
        try:
            network = parse_network(cidr_value)
        except ValueError as exc:
            raise PolicyError(
                f"invalid rule CIDR {cidr_value!r}: {exc}", code="invalid_cidr"
            )
        if not network.subnet_of(scope):
            raise PolicyError(
                f"rule {network} is not inside scope {scope}",
                code="rule_outside_scope",
            )
        rules.append(Rule(network=network, action=action))

    segments = _compile_region(scope, rules, default_action)
    return scope, segments


def _compile_region(
    region: ipaddress.IPv4Network,
    active: list[Rule],
    default_action: str,
) -> list[Segment]:
    """Compile the segments covering ``region``.

    ``active`` holds the rules that reach this region (i.e. overlap it or an
    ancestor), kept in declaration order.  The first such rule that overlaps
    the region decides what happens next:

    * if it contains the whole region the region is uniformly acted upon;
    * otherwise it cuts through the region, which is split into its two
      halves so the earlier rule still wins wherever it applies;
    * if no rule touches the region every address gets the default action.
    """

    for rule in active:
        if not rule.network.overlaps(region):
            continue
        if region.subnet_of(rule.network):
            return [(region, rule.action)]
        # The first matching rule only partially covers the region; split at
        # the next prefix.  At /32 any overlap is a containment, so this is
        # only reachable above prefix length 32.
        left, right = region.subnets()
        left_segments = _compile_region(
            left, [r for r in active if r.network.overlaps(left)], default_action
        )
        right_segments = _compile_region(
            right, [r for r in active if r.network.overlaps(right)], default_action
        )
        return _join_siblings(region, left_segments, right_segments)

    return [(region, default_action)]


def _join_siblings(
    parent: ipaddress.IPv4Network,
    left_segments: list[Segment],
    right_segments: list[Segment],
) -> list[Segment]:
    """Merge the two halves only when each is one uniform, equal-action block.

    A child that returns a single segment covers its whole half by
    construction (the compiled segments partition the region), so merging
    only needs both halves uniform with the same action.
    """

    if (
        len(left_segments) == 1
        and len(right_segments) == 1
        and left_segments[0][1] == right_segments[0][1]
    ):
        return [(parent, left_segments[0][1])]
    return left_segments + right_segments
