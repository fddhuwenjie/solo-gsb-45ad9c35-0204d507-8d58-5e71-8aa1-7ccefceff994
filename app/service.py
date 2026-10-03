"""Domain logic: pools, exclusions, allocation, release and status queries."""

from __future__ import annotations

import ipaddress
import sqlite3

from .bgpaudit import BgpAuditError, audit
from .cidrmath import compute_free, delegation_fragments, lowest_aligned, parse_network
from .cidrpolicy import PolicyError, compile_policy
from .db import read_transaction, write_transaction
from .reversedns import (
    ReverseDnsError,
    direct_records,
    enclosing_24_name,
    parse_parent_zone,
    resolve_tag_zone,
    reverse_zone_name,
    rfc2317_records,
    validate_hostname,
)


class ApiError(Exception):
    """Error carrying an HTTP status code and a JSON body."""

    def __init__(self, status_code: int, detail: str, code: str | None = None):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail
        self.code = code or "error"


def utc_now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


def _row_pool(conn: sqlite3.Connection, pool_id: int) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM pools WHERE id = ?", (pool_id,)).fetchone()
    if row is None:
        raise ApiError(404, f"pool {pool_id} not found", code="pool_not_found")
    return row


def _pool_allocations(conn: sqlite3.Connection, pool_id: int) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM allocations WHERE pool_id = ? ORDER BY id",
        (pool_id,),
    ).fetchall()


def _pool_exclusions(conn: sqlite3.Connection, pool_id: int) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM exclusions WHERE pool_id = ? ORDER BY id",
        (pool_id,),
    ).fetchall()


def _free_networks(
    pool: ipaddress.IPv4Network,
    exclusions: list[ipaddress.IPv4Network],
    allocations: list[ipaddress.IPv4Network],
) -> list[ipaddress.IPv4Network]:
    return compute_free(pool, exclusions + allocations)


def create_pool(cidr: str, exclusions: list[str]) -> dict:
    try:
        pool_net = parse_network(cidr)
    except ValueError as exc:
        raise ApiError(422, f"invalid pool CIDR: {exc}", code="invalid_cidr")

    exclusion_nets: list[ipaddress.IPv4Network] = []
    for raw in exclusions:
        try:
            net = parse_network(raw)
        except ValueError as exc:
            raise ApiError(422, f"invalid exclusion CIDR {raw!r}: {exc}", code="invalid_cidr")
        if not net.subnet_of(pool_net):
            raise ApiError(
                422,
                f"exclusion {raw} is not inside pool {cidr}",
                code="exclusion_outside_pool",
            )
        if any(net.overlaps(other) for other in exclusion_nets):
            raise ApiError(
                422,
                f"exclusion {raw} overlaps another declared exclusion",
                code="exclusion_overlap",
            )
        exclusion_nets.append(net)

    now = utc_now()
    with write_transaction() as conn:
        try:
            cursor = conn.execute(
                "INSERT INTO pools (cidr, created_at) VALUES (?, ?)",
                (str(pool_net), now),
            )
        except sqlite3.IntegrityError:
            raise ApiError(
                409,
                f"pool {pool_net} already exists",
                code="pool_exists",
            )
        pool_id = cursor.lastrowid
        for net in exclusion_nets:
            conn.execute(
                "INSERT INTO exclusions (pool_id, cidr, created_at) VALUES (?, ?, ?)",
                (pool_id, str(net), now),
            )
        pool = _row_pool(conn, pool_id)
        exc_rows = _pool_exclusions(conn, pool_id)

    return {
        "id": pool["id"],
        "cidr": pool["cidr"],
        "exclusions": [row["cidr"] for row in exc_rows],
        "created_at": pool["created_at"],
    }


def add_exclusion(pool_id: int, cidr: str) -> dict:
    try:
        net = parse_network(cidr)
    except ValueError as exc:
        raise ApiError(422, f"invalid exclusion CIDR: {exc}", code="invalid_cidr")

    with write_transaction() as conn:
        pool = _row_pool(conn, pool_id)
        pool_net = parse_network(pool["cidr"])
        if not net.subnet_of(pool_net):
            raise ApiError(
                422,
                f"exclusion {net} is not inside pool {pool_net}",
                code="exclusion_outside_pool",
            )

        existing_excl = [parse_network(r["cidr"]) for r in _pool_exclusions(conn, pool_id)]
        if any(net == other for other in existing_excl):
            raise ApiError(409, f"exclusion {net} already declared", code="exclusion_exists")
        if any(net.overlaps(other) for other in existing_excl):
            raise ApiError(409, f"exclusion {net} overlaps another exclusion", code="exclusion_overlap")

        allocs = [parse_network(r["cidr"]) for r in _pool_allocations(conn, pool_id)]
        if any(net.overlaps(a) for a in allocs):
            raise ApiError(
                409,
                f"exclusion {net} overlaps an existing allocation",
                code="exclusion_overlap",
            )

        now = utc_now()
        conn.execute(
            "INSERT INTO exclusions (pool_id, cidr, created_at) VALUES (?, ?, ?)",
            (pool_id, str(net), now),
        )

    return {"id": pool_id, "excluded": str(net)}


def allocate(pool_id: int, request_id: str, prefix_length: int) -> dict:
    if not 0 <= prefix_length <= 32:
        raise ApiError(
            422,
            "prefix_length must be between 0 and 32",
            code="invalid_prefix",
        )

    # The whole check-and-insert runs inside one immediate write transaction.
    # SQLite serialises writers, so concurrent requests with different
    # request_ids cannot observe the same free space twice; the UNIQUE
    # constraint on request_id additionally guards idempotency retries.
    with write_transaction() as conn:
        pool = _row_pool(conn, pool_id)
        pool_net = parse_network(pool["cidr"])

        idempotent = conn.execute(
            "SELECT * FROM allocations WHERE request_id = ?",
            (request_id,),
        ).fetchone()
        if idempotent is not None:
            if idempotent["pool_id"] != pool_id:
                raise ApiError(
                    409,
                    f"request_id {request_id!r} already used against pool "
                    f"{idempotent['pool_id']}",
                    code="request_id_conflict",
                )
            if idempotent["prefix_length"] != prefix_length:
                raise ApiError(
                    409,
                    f"request_id {request_id!r} already allocated prefix_length "
                    f"{idempotent['prefix_length']}, not {prefix_length}",
                    code="request_id_conflict",
                )
            return {
                "id": idempotent["id"],
                "pool_id": pool_id,
                "cidr": idempotent["cidr"],
                "request_id": request_id,
                "prefix_length": idempotent["prefix_length"],
                "created_at": idempotent["created_at"],
                "replayed": True,
            }

        exclusions = [parse_network(r["cidr"]) for r in _pool_exclusions(conn, pool_id)]
        allocations = [parse_network(r["cidr"]) for r in _pool_allocations(conn, pool_id)]
        free = _free_networks(pool_net, exclusions, allocations)
        chosen = lowest_aligned(free, prefix_length)
        if chosen is None:
            raise ApiError(
                409,
                f"no contiguous free /{prefix_length} subnet in pool {pool_net}",
                code="pool_exhausted",
            )

        now = utc_now()
        cursor = conn.execute(
            "INSERT INTO allocations (pool_id, cidr, request_id, prefix_length, created_at)"
            " VALUES (?, ?, ?, ?, ?)",
            (pool_id, str(chosen), request_id, prefix_length, now),
        )
        allocation_id = cursor.lastrowid

    return {
        "id": allocation_id,
        "pool_id": pool_id,
        "cidr": str(chosen),
        "request_id": request_id,
        "prefix_length": prefix_length,
        "created_at": now,
        "replayed": False,
    }


def release(pool_id: int, request_id: str) -> dict:
    with write_transaction() as conn:
        _row_pool(conn, pool_id)
        row = conn.execute(
            "SELECT * FROM allocations WHERE pool_id = ? AND request_id = ?",
            (pool_id, request_id),
        ).fetchone()
        if row is None:
            raise ApiError(
                404,
                f"request_id {request_id!r} not found in pool {pool_id}",
                code="allocation_not_found",
            )
        conn.execute("DELETE FROM allocations WHERE id = ?", (row["id"],))
        freed = row["cidr"]

    return {"released": freed, "request_id": request_id, "pool_id": pool_id}


def pool_status(pool_id: int) -> dict:
    with read_transaction() as conn:
        pool = _row_pool(conn, pool_id)
        pool_net = parse_network(pool["cidr"])
        exclusion_rows = _pool_exclusions(conn, pool_id)
        allocation_rows = _pool_allocations(conn, pool_id)

    exclusions = [parse_network(row["cidr"]) for row in exclusion_rows]
    allocations = [parse_network(row["cidr"]) for row in allocation_rows]
    free = _free_networks(pool_net, exclusions, allocations)

    pairs = sorted(
        zip(allocation_rows, allocations),
        key=lambda pair: int(pair[1].network_address),
    )
    allocated = [
        {
            "cidr": str(net),
            "request_id": row["request_id"],
            "prefix_length": row["prefix_length"],
            "created_at": row["created_at"],
        }
        for row, net in pairs
    ]

    return {
        "id": pool_id,
        "cidr": pool["cidr"],
        "exclusions": [
            str(net) for net in sorted(set(exclusions), key=lambda x: int(x.network_address))
        ],
        "allocated": allocated,
        "free_cidrs": [str(net) for net in free],
        "free_addresses": sum(net.num_addresses for net in free),
    }


def list_pools() -> list[dict]:
    with read_transaction() as conn:
        rows = conn.execute("SELECT * FROM pools ORDER BY id").fetchall()
    return [{"id": r["id"], "cidr": r["cidr"], "created_at": r["created_at"]} for r in rows]


def compile_cidr_policy(scope: str, default_action: str, rules: list) -> dict:
    """Compile priority rules into disjoint scope-covering segments.

    Pure, read-only computation: it never touches the database, so pools,
    exclusions and allocations are unaffected.  ``rules`` is a list of
    objects exposing ``cidr`` and ``action``.
    """

    try:
        scope_net, segments = compile_policy(
            scope, default_action, [(rule.cidr, rule.action) for rule in rules]
        )
    except PolicyError as exc:
        raise ApiError(422, exc.detail, code=exc.code)

    return {
        "scope": str(scope_net),
        "default_action": default_action,
        "segments": [
            {"cidr": str(network), "action": action} for network, action in segments
        ],
    }


def audit_bgp_announcements(relationships: list, announcements: list) -> dict:
    """Audit AS paths and compare valid announcements.

    Pure, stateless computation: no pool, exclusion or allocation data is
    read or written.  ``relationships`` and ``announcements`` are pydantic
    objects exposing the request fields.
    """

    try:
        return audit(relationships, announcements)
    except BgpAuditError as exc:
        raise ApiError(422, exc.detail, code=exc.code)


def _plan_error(detail: str, code: str) -> ApiError:
    return ApiError(422, detail, code=code)


def reverse_dns_plan(pool_id: int, parent_zone: str, entries: list) -> dict:
    """Build a read-only RFC 2317 reverse-delegation plan for current allocations.

    Every input check runs before any record is emitted and the plan never
    writes to the database.  ``entries`` is a list of objects exposing
    ``cidr``, ``child_zone``, ``nameservers`` and ``ptr``.
    """

    try:
        parent_net, parent_name = parse_parent_zone(parent_zone)
    except ReverseDnsError as exc:
        raise _plan_error(exc.detail, exc.code)

    # Read allocations first (also verifies the pool exists).
    with read_transaction() as conn:
        pool = _row_pool(conn, pool_id)
        allocation_rows = _pool_allocations(conn, pool_id)
    pool_net = parse_network(pool["cidr"])

    if not allocation_rows:
        raise _plan_error(
            f"pool {pool_id} has no allocations to delegate",
            code="reverse_no_allocations",
        )
    allocated = {parse_network(row["cidr"]): row for row in allocation_rows}

    if not parent_net.supernet_of(pool_net) and parent_net != pool_net:
        raise _plan_error(
            f"parent reverse zone {parent_name} ({parent_net}) does not cover "
            f"pool {pool_net}",
            code="reverse_parent_outside_pool",
        )

    seen_cidrs: set[ipaddress.IPv4Network] = set()
    parsed_entries: list[tuple[ipaddress.IPv4Network, object]] = []
    for entry in entries:
        try:
            net = parse_network(entry.cidr)
        except ValueError as exc:
            raise _plan_error(
                f"invalid entry CIDR {entry.cidr!r}: {exc}",
                code="invalid_cidr",
            )
        if net in seen_cidrs:
            raise _plan_error(
                f"duplicate delegation entry for {net}",
                code="reverse_duplicate_entry",
            )
        seen_cidrs.add(net)
        if net not in allocated:
            raise _plan_error(
                f"{net} is not a current allocation in pool {pool_id}",
                code="reverse_not_allocated",
            )
        if not net.subnet_of(parent_net):
            raise _plan_error(
                f"allocation {net} is outside parent zone {parent_name}",
                code="reverse_outside_parent",
            )
        parsed_entries.append((net, entry))

    missing = set(allocated) - seen_cidrs
    if missing:
        smallest = sorted(missing, key=lambda n: int(n.network_address))[0]
        raise _plan_error(
            f"allocation {smallest} is missing from the delegation plan; "
            "every current allocation must be covered",
            code="reverse_allocation_omitted",
        )

    # Normalise nameservers and PTR targets per entry.
    normalised: list[dict] = []
    for net, entry in parsed_entries:
        servers: list[str] = []
        seen_servers: set[str] = set()
        try:
            for raw in entry.nameservers:
                server = validate_hostname(raw, code="invalid_nameserver")
                if server in seen_servers:
                    continue
                seen_servers.add(server)
                servers.append(server)
        except ReverseDnsError as exc:
            raise _plan_error(exc.detail, exc.code)
        if len(servers) < 2:
            raise _plan_error(
                f"allocation {net} must name at least two distinct authoritative "
                "nameservers",
                code="nameserver_insufficient",
            )

        ptrs: dict[str, str] = {}
        try:
            for raw_addr, raw_target in entry.ptr.items():
                try:
                    address = ipaddress.IPv4Address(raw_addr)
                except ValueError:
                    raise ReverseDnsError(
                        f"PTR key {raw_addr!r} is not a valid IPv4 address",
                        code="invalid_ptr",
                    )
                if address not in net:
                    raise ReverseDnsError(
                        f"PTR address {address} is not inside {net}",
                        code="invalid_ptr",
                    )
                key = str(address)
                if key in ptrs:
                    raise ReverseDnsError(
                        f"duplicate PTR record for {key}",
                        code="invalid_ptr",
                    )
                ptrs[key] = validate_hostname(raw_target, code="invalid_ptr")
        except ReverseDnsError as exc:
            raise _plan_error(exc.detail, exc.code)

        normalised.append(
            {"net": net, "servers": servers, "ptrs": ptrs, "entry": entry}
        )

    # Resolve every fragment before any record is built so naming conflicts
    # fail atomically and no partial plan is returned.
    planned: list[dict] = []
    claimed_zones: dict[str, str] = {}
    for item in normalised:
        net: ipaddress.IPv4Network = item["net"]
        fragments = delegation_fragments(net)
        tagged = net.prefixlen > 24
        child_zone: str | None = None
        try:
            if tagged:
                if not item["entry"].child_zone:
                    raise ReverseDnsError(
                        f"allocation {net} smaller than /24 requires a child_zone",
                        code="missing_child_zone",
                    )
                child_zone = resolve_tag_zone(
                    item["entry"].child_zone,
                    enclosing_24_name(net),
                )
        except ReverseDnsError as exc:
            raise _plan_error(exc.detail, exc.code)

        for fragment in fragments:
            if tagged:
                zone = child_zone
                mode = "rfc2317"
                enclosing = enclosing_24_name(fragment)
            else:
                zone = reverse_zone_name(fragment)
                mode = "direct"
                enclosing = zone
            if zone != parent_name and not zone.endswith(f".{parent_name}"):
                raise _plan_error(
                    f"delegated zone {zone} is not inside parent zone {parent_name}",
                    code="reverse_outside_parent",
                )
            owner = claimed_zones.get(zone)
            if owner is not None and owner != str(net):
                raise _plan_error(
                    f"child zone {zone} claimed by both {owner} and {net}",
                    code="reverse_name_conflict",
                )
            claimed_zones[zone] = str(net)
            planned.append(
                {
                    "fragment": fragment,
                    "source": net,
                    "mode": mode,
                    "enclosing": enclosing,
                    "zone": zone,
                    "servers": item["servers"],
                    "ptrs": item["ptrs"] if len(fragments) == 1 else {
                        addr: target
                        for addr, target in item["ptrs"].items()
                        if ipaddress.IPv4Address(addr) in fragment
                    },
                }
            )

    planned.sort(
        key=lambda p: (
            int(p["fragment"].network_address),
            p["fragment"].prefixlen,
            p["zone"],
        )
    )

    delegations = []
    records: list[dict] = []
    for p in planned:
        fragment: ipaddress.IPv4Network = p["fragment"]
        delegations.append(
            {
                "cidr": str(fragment),
                "source_cidr": str(p["source"]),
                "mode": p["mode"],
                "enclosing_zone": p["enclosing"],
                "child_zone": p["zone"] if p["mode"] == "rfc2317" else None,
                "nameservers": p["servers"],
            }
        )
        if p["mode"] == "rfc2317":
            records.extend(
                rfc2317_records(
                    fragment, p["zone"], p["servers"], p["ptrs"]
                )
            )
        else:
            records.extend(direct_records(p["zone"], p["servers"], p["ptrs"]))

    # Records are already deterministic: delegations were sorted by fragment
    # address above, and each builder emits NS (alpha), then CNAME/PTR in
    # numeric address order.  A global lexicographic sort would mis-order
    # address labels ("10" before "2"), so the fragment order is preserved.
    return {
        "pool_id": pool_id,
        "parent_zone": parent_name,
        "delegations": delegations,
        "records": records,
    }
