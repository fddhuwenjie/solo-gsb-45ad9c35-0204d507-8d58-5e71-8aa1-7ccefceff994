"""Stateless BGP announcement auditing against declared AS relationships.

The input is a set of AS relationships -- either ``customer -> provider``
(transit) or ``peer`` -- and a batch of announcements, each carrying a unique
``id``, an IPv4 ``prefix`` and an ``as_path`` ordered from the vantage point
toward the origin.  Nothing here touches the database.

Per-announcement path audit:

* Only consecutive duplicate ASNs are collapsed (AS_PATH prepending).  Any
  non-consecutive repeat after folding is an ``as_loop``.
* Every pair of adjacent ASNs must have a declared relationship; if not, the
  whole request fails with 422 (``as_relation_unknown``).
* A valley-free path climbs zero or more customer->provider edges, crosses at
  most one peer edge, then descends zero or more provider->customer edges.
  The first hop breaking this shape is reported as an ``invalid_path``.

Only announcements whose path passed the audit take part in the comparison:

* the same prefix originated by more than one AS is flagged ``moas``;
* a more-specific prefix whose origin differs from the nearest (longest)
  covering announcement is flagged ``origin_change``.

Results are ordered by network address, then prefix length, then id.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from .cidrmath import parse_network

# Largest 32-bit AS number (AS 4294967295); bounds are enforced by pydantic.
MAX_ASN = (1 << 32) - 1

# Canonical relationship descriptor:
#   ("c2p", customer, provider)  -- orientation matters
#   ("peer", low_asn, high_asn)  -- symmetric, stored with ordered endpoints
Relation = tuple[str, int, int]


class BgpAuditError(Exception):
    """An input that makes the audit impossible; mapped to HTTP 422."""

    def __init__(self, detail: str, code: str):
        super().__init__(detail)
        self.detail = detail
        self.code = code


def _pair_key(a: int, b: int) -> tuple[int, int]:
    return (a, b) if a < b else (b, a)


def build_relation_map(raw_relations) -> dict[tuple[int, int], Relation]:
    """Index declared relationships by unordered AS pair.

    Identical repeated declarations are allowed; contradictory declarations
    for the same AS pair (peer vs transit, or transit claimed in both
    orientations), or a relationship from an AS to itself, raise
    :class:`BgpAuditError`.
    """

    relations: dict[tuple[int, int], Relation] = {}
    for rel in raw_relations:
        if rel.type == "customer_provider":
            customer, provider = rel.customer, rel.provider
            if customer == provider:
                raise BgpAuditError(
                    f"AS {customer} cannot be its own customer and provider",
                    code="invalid_as_relation",
                )
            descriptor: Relation = ("c2p", customer, provider)
            key = _pair_key(customer, provider)
        else:
            a, b = rel.a, rel.b
            if a == b:
                raise BgpAuditError(
                    f"AS {a} cannot peer with itself",
                    code="invalid_as_relation",
                )
            key = _pair_key(a, b)
            descriptor = ("peer", key[0], key[1])

        existing = relations.get(key)
        if existing is not None and existing != descriptor:
            raise BgpAuditError(
                f"AS pair {key[0]}/{key[1]} has conflicting relationship "
                "declarations",
                code="as_relation_conflict",
            )
        relations[key] = descriptor
    return relations


def fold_as_path(path: list[int]) -> list[int]:
    """Collapse consecutive duplicate ASNs only (AS_PATH prepending)."""

    folded: list[int] = []
    for asn in path:
        if not folded or folded[-1] != asn:
            folded.append(asn)
    return folded


def _edge_kind(a: int, b: int, relations: dict[tuple[int, int], Relation]):
    """Classify the ``a -> b`` edge.

    Returns ``"up"`` for customer->provider, ``"down"`` for
    provider->customer, ``"peer"`` for peering, or ``None`` when no
    relationship is declared for the pair.
    """

    descriptor = relations.get(_pair_key(a, b))
    if descriptor is None:
        return None
    if descriptor[0] == "peer":
        return "peer"
    _, customer, provider = descriptor
    return "up" if a == customer and b == provider else "down"


def _first_valley_free_violation(
    announcement_id: str,
    folded: list[int],
    relations: dict[tuple[int, int], Relation],
) -> dict | None:
    """Walk the folded path vantage-point -> origin.

    The allowed phase progresses monotonically ``up -> peer -> down``: zero or
    more customer->provider edges, at most one peer edge, then zero or more
    provider->customer edges.  Returns the first violating hop descriptor, or
    ``None`` when the path is valley-free.  An adjacent pair without a
    declared relationship is a request-level 422.
    """

    phase = "up"
    for hop, (a, b) in enumerate(zip(folded, folded[1:])):
        kind = _edge_kind(a, b, relations)
        if kind is None:
            raise BgpAuditError(
                f"announcement {announcement_id!r} hop {hop}: no relationship "
                f"declared between AS {a} and AS {b}",
                code="as_relation_unknown",
            )
        # An "up" edge is only legal before the peer/descent; a peer edge is
        # only legal while still climbing; "down" edges are always legal and
        # fix the phase.
        allowed = kind == "down" or (phase == "up")
        if not allowed:
            return {"hop": hop, "from_asn": a, "to_asn": b}
        if kind == "peer":
            phase = "peer"
        elif kind == "down":
            phase = "down"
    return None


def _path_loop_or_violation(
    announcement_id: str,
    folded: list[int],
    relations: dict[tuple[int, int], Relation],
) -> tuple[str, dict | None]:
    """Classify a folded path hop by hop.

    At every hop the edge must have a declared relationship (otherwise the
    whole request fails 422); if the destination ASN has already appeared,
    the path is an ``as_loop`` and the walk stops there.  Paths without a loop
    are then checked against the valley-free shape.
    """

    seen: set[int] = {folded[0]}
    for hop, (a, b) in enumerate(zip(folded, folded[1:])):
        if _edge_kind(a, b, relations) is None:
            raise BgpAuditError(
                f"announcement {announcement_id!r} hop {hop}: no relationship "
                f"declared between AS {a} and AS {b}",
                code="as_relation_unknown",
            )
        if b in seen:
            return "as_loop", None
        seen.add(b)

    violation = _first_valley_free_violation(announcement_id, folded, relations)
    return ("invalid_path", violation) if violation is not None else ("valid", None)


@dataclass
class _Audited:
    id: str
    network: ipaddress.IPv4Network
    folded: list[int]
    status: str  # "valid" | "as_loop" | "invalid_path"
    violating_hop: dict | None = None
    flags: list[str] = field(default_factory=list)

    @property
    def origin(self) -> int:
        return self.folded[-1]


def audit(relationships, announcements) -> dict:
    """Run the full audit and comparison; pure computation, no I/O."""

    relations = build_relation_map(relationships)

    seen_ids: set[str] = set()
    audited: list[_Audited] = []
    for ann in announcements:
        if ann.id in seen_ids:
            raise BgpAuditError(
                f"duplicate announcement id {ann.id!r}",
                code="duplicate_announcement_id",
            )
        seen_ids.add(ann.id)

        try:
            network = parse_network(ann.prefix)
        except ValueError as exc:
            raise BgpAuditError(
                f"announcement {ann.id!r} has invalid prefix {ann.prefix!r}: {exc}",
                code="invalid_prefix",
            )

        folded = fold_as_path(list(ann.as_path))
        if not folded:
            raise BgpAuditError(
                f"announcement {ann.id!r} has an empty as_path",
                code="invalid_as_path",
            )

        status, violation = _path_loop_or_violation(ann.id, folded, relations)
        audited.append(_Audited(ann.id, network, folded, status, violation))

    _compare(audited)

    audited.sort(
        key=lambda a: (int(a.network.network_address), a.network.prefixlen, a.id)
    )
    return {"results": [_serialize(a) for a in audited]}


def _compare(audited: list[_Audited]) -> None:
    """Attach ``moas`` / ``origin_change`` flags to valid announcements."""

    valid = [a for a in audited if a.status == "valid"]

    # MOAS: announcements of the exact same prefix with more than one origin.
    by_prefix: dict[tuple[int, int], list[_Audited]] = {}
    for a in valid:
        key = (int(a.network.network_address), a.network.prefixlen)
        by_prefix.setdefault(key, []).append(a)
    for group in by_prefix.values():
        if len({a.origin for a in group}) > 1:
            for a in group:
                a.flags.append("moas")

    # Origin change: the nearest (longest, strictly less specific) covering
    # announcement is originated by a different AS.  When that covering prefix
    # is itself MOAS, the flag is withheld only if the more-specific origin
    # matches one of the covering origins.
    for a in valid:
        covering = [
            other
            for other in valid
            if other.network.prefixlen < a.network.prefixlen
            and a.network.subnet_of(other.network)
        ]
        if not covering:
            continue
        nearest = max(covering, key=lambda o: o.network.prefixlen)
        cover_key = (
            int(nearest.network.network_address),
            nearest.network.prefixlen,
        )
        nearest_origins = {o.origin for o in by_prefix[cover_key]}
        if a.origin not in nearest_origins:
            a.flags.append("origin_change")


def _serialize(a: _Audited) -> dict:
    return {
        "id": a.id,
        "prefix": str(a.network),
        "as_path": a.folded,
        "origin": a.origin,
        "status": a.status,
        "flags": a.flags,
        "violating_hop": a.violating_hop,
    }
