"""IPv4 CIDR set arithmetic used by the allocator.

All functions operate on :class:`ipaddress.IPv4Network` objects.  Networks
passed to these helpers are always treated as *canonical* (host bits ignored)
and the returned networks are canonical as well.
"""

from __future__ import annotations

import ipaddress


def parse_network(value: str) -> ipaddress.IPv4Network:
    """Parse ``value`` as a strict IPv4 network.

    ``strict=True`` rejects strings that carry host bits, e.g.
    ``10.0.0.5/24``.
    """

    net = ipaddress.ip_network(value, strict=True)
    if not isinstance(net, ipaddress.IPv4Network):
        raise ValueError("only IPv4 networks are supported")
    return net


def subtract_block(
    network: ipaddress.IPv4Network,
    block: ipaddress.IPv4Network,
) -> list[ipaddress.IPv4Network]:
    """Return the parts of ``network`` that are not inside ``block``.

    ``block`` must be contained in (or equal to) ``network``.  The result is
    the minimal, disjoint list of CIDR networks covering ``network - block``.
    """

    if block == network:
        return []
    return list(network.address_exclude(block))


def compute_free(
    pool: ipaddress.IPv4Network,
    blocked: list[ipaddress.IPv4Network],
) -> list[ipaddress.IPv4Network]:
    """Compute the free space inside ``pool``.

    ``blocked`` contains the already-allocated subnets plus declared
    exclusions; it may be disjoint and does not need to be sorted.  The
    returned list is the minimal representation of the remaining space,
    ordered by start address.
    """

    free: list[ipaddress.IPv4Network] = [pool]
    # Cut larger pieces first so that address_exclude always receives a
    # sub-block of the current piece.
    for block in sorted(set(blocked), key=lambda n: (n.prefixlen, int(n.network_address))):
        if not (block.subnet_of(pool)):
            # Stored data is always pool-scoped; this is a defensive guard.
            continue
        next_free: list[ipaddress.IPv4Network] = []
        for piece in free:
            if block == piece:
                continue
            if block.subnet_of(piece):
                next_free.extend(subtract_block(piece, block))
            else:
                next_free.append(piece)
        free = next_free
    # Merge adjacent blocks wherever they form a single CIDR.
    return _merge(free)


def _merge(networks: list[ipaddress.IPv4Network]) -> list[ipaddress.IPv4Network]:
    """Collapse adjacent networks into the minimal covering CIDR set."""

    return list(
        ipaddress.collapse_addresses(
            sorted(set(networks), key=lambda n: int(n.network_address))
        )
    )


def lowest_aligned(
    free: list[ipaddress.IPv4Network],
    prefix_length: int,
) -> ipaddress.IPv4Network | None:
    """Find the lowest-address subnet of ``prefix_length`` fitting in ``free``.

    ``free`` must be a sorted list of disjoint, canonical networks (the
    output of :func:`compute_free`).  Returns the network with the smallest
    start address, or ``None`` when no free block is large enough.
    """

    for block in sorted(free, key=lambda n: int(n.network_address)):
        if prefix_length < block.prefixlen:
            # The requested network would be larger than this free piece.
            continue
        candidate = next(block.subnets(new_prefix=prefix_length))
        return candidate
    return None


# Octet-aligned reverse-zone boundaries (/8, /16, /24).
_REVERSE_BOUNDARIES = (8, 16, 24)


def delegation_fragments(
    network: ipaddress.IPv4Network,
) -> list[ipaddress.IPv4Network]:
    """Split ``network`` into the minimal fragments delegable in reverse DNS.

    RFC 2317 delegation can only attach at an octet boundary:

    * a network already aligned to an octet boundary (prefix 8, 16 or 24)
      delegates as a single whole reverse zone;
    * a network smaller than a /24 (prefix > 24) lives entirely inside one
      /24 and is delegated as one RFC 2317 tagged zone;
    * any other network straddles an octet boundary and is split into the
      minimal set of covering, disjoint CIDRs aligned to the next octet
      boundary below it (e.g. a /23 becomes two /24 fragments, a /15 two
      /16 fragments).

    Canonical networks are prefix-aligned by construction, so a CIDR with
    a non-boundary prefix between two boundaries always spans a whole number
    of blocks at the next boundary down.
    """

    prefix = network.prefixlen
    if prefix >= 24 or prefix in _REVERSE_BOUNDARIES:
        return [network]
    boundary = min(b for b in _REVERSE_BOUNDARIES if b > prefix)
    return list(network.subnets(new_prefix=boundary))
