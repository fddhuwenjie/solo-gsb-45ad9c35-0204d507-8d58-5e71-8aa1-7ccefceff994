"""RFC 2317 reverse-DNS delegation name arithmetic.

Reverse zones are aligned to IPv4 octet boundaries: ``x.in-addr.arpa``
(/8), ``y.x.in-addr.arpa`` (/16) and ``z.y.x.in-addr.arpa`` (/24).
Networks smaller than a /24 cannot be delegated by plain NS records;
RFC 2317 works around that by placing a CNAME per delegated address in
the enclosing /24 zone and delegating an artificial "tagged" zone name
to the subnet's authoritative servers.

These helpers perform only pure name/record construction.  Input
validation and orchestration live in :mod:`app.service`.
"""

from __future__ import annotations

import ipaddress
import re

ARPA_SUFFIX = "in-addr.arpa"

# A single DNS label: letters/digits/hyphen, no leading/trailing hyphen.
_LABEL_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")


class ReverseDnsError(Exception):
    """Invalid reverse-DNS plan input, carrying a stable error code."""

    def __init__(self, detail: str, code: str = "invalid_reverse_input"):
        super().__init__(detail)
        self.detail = detail
        self.code = code


def normalize_name(value: str) -> str:
    """Lowercase ``value`` and strip a single trailing dot.

    Keeps the form relative to ``in-addr.arpa`` out of every emitted
    record name, matching the project convention of canonical,
    dot-less zone names.
    """

    if not isinstance(value, str) or not value.strip():
        raise ReverseDnsError("DNS name must be a non-empty string", code="invalid_dns_name")
    name = value.strip().lower().rstrip(".")
    if name.endswith("."):
        # More than one trailing dot is never valid.
        raise ReverseDnsError(f"invalid DNS name {value!r}", code="invalid_dns_name")
    return name


def _valid_labels(name: str) -> bool:
    if not name or len(name) > 253:
        return False
    return all(_LABEL_RE.match(label) for label in name.split("."))


def validate_hostname(value: str, code: str = "invalid_dns_name") -> str:
    """Normalize and validate an absolute hostname (at least two labels)."""

    name = normalize_name(value)
    labels = name.split(".")
    if len(labels) < 2 or not _valid_labels(name):
        raise ReverseDnsError(f"invalid hostname {value!r}", code=code)
    if labels[-1].isdigit():
        raise ReverseDnsError(
            f"hostname {value!r} must not have an all-numeric top-level label",
            code=code,
        )
    return name


def parse_parent_zone(
    value: str,
) -> tuple[ipaddress.IPv4Network, str]:
    """Parse an ``in-addr.arpa`` parent zone into its network and name.

    Accepts octet-aligned /8, /16 and /24 reverse zones only.  Returns the
    covered canonical network and the normalized zone name.
    """

    try:
        name = normalize_name(value)
    except ReverseDnsError:
        raise ReverseDnsError(
            f"parent_zone {value!r} must be an in-addr.arpa reverse zone",
            code="invalid_parent_zone",
        ) from None
    labels = name.split(".")
    if len(labels) < 3 or labels[-2:] != ARPA_SUFFIX.split("."):
        raise ReverseDnsError(
            f"parent_zone {value!r} must be an in-addr.arpa reverse zone",
            code="invalid_parent_zone",
        )
    octets = labels[:-2]
    if not 1 <= len(octets) <= 3:
        raise ReverseDnsError(
            "parent_zone must be an octet-aligned /8, /16 or /24 reverse zone",
            code="invalid_parent_zone",
        )
    if any(not (part.isdigit() and 0 <= int(part) <= 255) for part in octets):
        raise ReverseDnsError(
            f"parent_zone {value!r} contains a non-octet label",
            code="invalid_parent_zone",
        )
    padded = (list(reversed(octets)) + ["0", "0", "0"])[:4]
    prefixlen = 8 * len(octets)
    cidr = f"{'.'.join(padded)}/{prefixlen}"
    try:
        network = ipaddress.IPv4Network(cidr, strict=True)
    except ValueError:
        raise ReverseDnsError(
            f"parent_zone {value!r} is not octet aligned ({cidr} has host bits)",
            code="invalid_parent_zone",
        ) from None
    return network, name


def reverse_zone_name(network: ipaddress.IPv4Network) -> str:
    """Return the canonical reverse zone name for an /8, /16 or /24 network."""

    if network.prefixlen not in (8, 16, 24):
        raise ReverseDnsError(
            f"{network} is not aligned to an octet boundary",
            code="invalid_parent_zone",
        )
    octets = str(network.network_address).split(".")
    take = network.prefixlen // 8
    return ".".join(list(reversed(octets[:take])) + [ARPA_SUFFIX])


def enclosing_24_name(network: ipaddress.IPv4Network) -> str:
    """Return the /24 reverse zone enclosing an inside-a-/24 network."""

    third = list(network.network_address.packed[:3])
    return f"{third[2]}.{third[1]}.{third[0]}.{ARPA_SUFFIX}"


def resolve_tag_zone(child_zone: str, enclosing_zone: str) -> str:
    """Resolve an RFC 2317 child-zone name.

    A single label (e.g. ``64-127``) is interpreted relative to the
    enclosing /24 zone; a multi-label name must be a strict descendant of
    that zone.  An equal or unrelated name raises ``ReverseDnsError``.
    """

    name = child_zone.strip().lower().rstrip(".")
    if not name:
        raise ReverseDnsError(
            "child_zone must not be empty",
            code="invalid_child_zone",
        )
    labels = name.split(".")
    if not all(_LABEL_RE.match(label) for label in labels):
        raise ReverseDnsError(
            f"child_zone {child_zone!r} is not a valid DNS name",
            code="invalid_child_zone",
        )
    if len(labels) == 1:
        return f"{name}.{enclosing_zone}"
    if name == enclosing_zone or not name.endswith(f".{enclosing_zone}"):
        raise ReverseDnsError(
            f"child_zone {child_zone!r} must be a sub-zone of {enclosing_zone}",
            code="invalid_child_zone",
        )
    return name


def pointer_name(address: ipaddress.IPv4Address) -> str:
    """Return the full reverse pointer name of ``address`` (no trailing dot)."""

    octets = str(address).split(".")
    return f"{octets[3]}.{octets[2]}.{octets[1]}.{octets[0]}.{ARPA_SUFFIX}"


def rfc2317_records(
    fragment: ipaddress.IPv4Network,
    child_zone: str,
    nameservers: list[str],
    ptrs: dict[str, str],
) -> list[dict]:
    """Build NS, per-address CNAME and PTR records for one tagged fragment.

    ``ptrs`` maps an address inside the fragment to an FQDN target.  The
    records are returned in deterministic order: NS records first (ordered
    by target), then CNAMEs ordered by address, then PTRs ordered by
    address.
    """

    records: list[dict] = [
        {"type": "NS", "name": child_zone, "target": server}
        for server in sorted(nameservers)
    ]
    # Every address covered by the fragment (including network and
    # broadcast addresses) receives a CNAME into the tagged zone.
    for address_int in range(
        int(fragment.network_address), int(fragment.broadcast_address) + 1
    ):
        address = ipaddress.IPv4Address(address_int)
        records.append(
            {
                "type": "CNAME",
                "name": pointer_name(address),
                "target": f"{str(address).split('.')[-1]}.{child_zone}",
            }
        )
    for address in sorted(
        (ipaddress.IPv4Address(raw) for raw in ptrs),
        key=int,
    ):
        records.append(
            {
                "type": "PTR",
                "name": f"{str(address).split('.')[-1]}.{child_zone}",
                "target": ptrs[str(address)],
            }
        )
    return records


def direct_records(
    zone_name: str,
    nameservers: list[str],
    ptrs: dict[str, str],
) -> list[dict]:
    """Build NS and PTR records for a whole octet-aligned zone delegation."""

    records: list[dict] = [
        {"type": "NS", "name": zone_name, "target": server}
        for server in sorted(nameservers)
    ]
    for address in sorted(
        (ipaddress.IPv4Address(raw) for raw in ptrs),
        key=int,
    ):
        records.append(
            {
                "type": "PTR",
                "name": pointer_name(address),
                "target": ptrs[str(address)],
            }
        )
    return records
