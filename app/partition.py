"""Pool partition migration: atomically replace one pool with covering sub-pools.

``POST /pools/{id}/partitions`` retires a source pool and replaces it with a
set of new sub-pools whose CIDRs are pairwise non-overlapping and exactly
cover the source pool.  Every exclusion and allocation of the source pool
must fall completely inside exactly one sub-pool; the rows are then moved to
that sub-pool (row ids preserved), the source pool row is removed and a
migration record is written -- all inside a single SQLite write transaction,
so a failed validation leaves no partial sub-pools behind and never touches
the source pool.

``operation_id`` is the idempotency key: retrying with the same parameters
replays the original result (even though the source pool is already gone);
the same key with different parameters is a 409 conflict.
"""

from __future__ import annotations

import ipaddress
import json
import sqlite3

from .cidrmath import parse_network
from .db import write_transaction
from .service import (
    ApiError,
    _pool_allocations,
    _pool_exclusions,
    _row_pool,
    utc_now,
)


def _partition_error(detail: str, code: str) -> ApiError:
    return ApiError(422, detail, code=code)


def _replay_result(previous: sqlite3.Row, sub_pools: list[dict]) -> dict:
    return {
        "operation_id": previous["operation_id"],
        "migration_id": previous["id"],
        "source_pool_id": previous["source_pool_id"],
        "source_cidr": previous["source_cidr"],
        "sub_pools": sub_pools,
        "created_at": previous["created_at"],
        "replayed": True,
    }


def partition_pool(pool_id: int, operation_id: str, subnets: list[str]) -> dict:
    """Partition ``pool_id`` into new sub-pools covering it exactly.

    Everything -- validation, sub-pool creation, row migration, source-pool
    removal and the migration record -- runs inside one ``BEGIN IMMEDIATE``
    write transaction, so concurrent requests are serialised and any failure
    rolls the whole partition back.
    """

    # Parse and canonicalise the requested sub-pool networks; sorted by
    # network address so creation order (and the stored mapping) is
    # deterministic regardless of request order.
    sub_nets: list[ipaddress.IPv4Network] = []
    for raw in subnets:
        try:
            net = parse_network(raw)
        except ValueError as exc:
            raise _partition_error(
                f"invalid subnet CIDR {raw!r}: {exc}", "invalid_cidr"
            )
        sub_nets.append(net)
    sub_nets.sort(key=lambda n: int(n.network_address))
    canonical = [str(net) for net in sub_nets]

    with write_transaction() as conn:
        # Idempotency first: a completed migration deleted its source pool,
        # so the operation_id must be consulted before pool existence.
        # A matching record with the same source pool and the same canonical
        # subnets replays the original result; any parameter change is a
        # conflict.  This wins over every other check.
        previous = conn.execute(
            "SELECT * FROM pool_migrations WHERE operation_id = ?",
            (operation_id,),
        ).fetchone()
        if previous is not None:
            stored = json.loads(previous["sub_pools"])
            if (
                previous["source_pool_id"] != pool_id
                or [sp["cidr"] for sp in stored] != canonical
            ):
                raise ApiError(
                    409,
                    f"operation_id {operation_id!r} was already used for a "
                    "different partition",
                    code="operation_id_conflict",
                )
            return _replay_result(previous, stored)

        pool = _row_pool(conn, pool_id)
        pool_net = parse_network(pool["cidr"])

        # Shape checks: every subnet inside the source pool, pairwise
        # non-overlapping, and together covering the pool exactly.  Sorted
        # by address, an overlap always shows up between neighbours; with
        # containment and disjointness established, equal address counts
        # mean exact coverage.
        for net in sub_nets:
            if not net.subnet_of(pool_net):
                raise _partition_error(
                    f"subnet {net} is not inside pool {pool_net}",
                    "partition_outside_pool",
                )
        for earlier, later in zip(sub_nets, sub_nets[1:]):
            if earlier.overlaps(later):
                raise _partition_error(
                    f"subnet {later} overlaps {earlier}",
                    "partition_overlap",
                )
        covered = sum(net.num_addresses for net in sub_nets)
        if covered != pool_net.num_addresses:
            raise _partition_error(
                f"subnets cover {covered} addresses but pool {pool_net} "
                f"has {pool_net.num_addresses}",
                "partition_incomplete",
            )

        # Every exclusion/allocation must fall completely inside exactly one
        # sub-pool.  The sub-pools are disjoint and cover the pool, so a row
        # either fits a single sub-pool or straddles a boundary.
        def owner(net: ipaddress.IPv4Network, kind: str) -> ipaddress.IPv4Network:
            matches = [sub for sub in sub_nets if net.subnet_of(sub)]
            if len(matches) != 1:
                raise _partition_error(
                    f"{kind} {net} does not fall completely inside a single "
                    "sub-pool",
                    f"partition_{kind}_unmapped",
                )
            return matches[0]

        exclusion_moves = [
            (row, owner(parse_network(row["cidr"]), "exclusion"))
            for row in _pool_exclusions(conn, pool_id)
        ]
        allocation_moves = [
            (row, owner(parse_network(row["cidr"]), "allocation"))
            for row in _pool_allocations(conn, pool_id)
        ]

        # Sub-pool CIDRs must not conflict with any other existing pool
        # (the source pool itself is being retired, so it is excluded).
        others = conn.execute(
            "SELECT id, cidr FROM pools WHERE id != ?",
            (pool_id,),
        ).fetchall()
        for other in others:
            other_net = parse_network(other["cidr"])
            for net in sub_nets:
                if net.overlaps(other_net):
                    raise ApiError(
                        409,
                        f"subnet {net} conflicts with existing pool "
                        f"{other['id']} ({other_net})",
                        code="partition_pool_conflict",
                    )

        # All checks passed: replace the source pool.  Deleting it cascades
        # to its exclusions/allocations (and historical restore records);
        # the rows are re-inserted below under their new sub-pools with
        # their exported identity (row id, created_at) preserved.  Deleting
        # first also frees the source CIDR, so a sub-pool may legally reuse
        # it (the degenerate single-subnet partition).
        now = utc_now()
        try:
            conn.execute("DELETE FROM pools WHERE id = ?", (pool_id,))

            sub_pool_ids: dict[ipaddress.IPv4Network, int] = {}
            sub_pools: list[dict] = []
            for net in sub_nets:
                cursor = conn.execute(
                    "INSERT INTO pools (cidr, created_at) VALUES (?, ?)",
                    (str(net), now),
                )
                sub_pool_ids[net] = cursor.lastrowid
                sub_pools.append({"pool_id": cursor.lastrowid, "cidr": str(net)})

            for row, sub in exclusion_moves:
                conn.execute(
                    "INSERT INTO exclusions (id, pool_id, cidr, created_at) "
                    "VALUES (?, ?, ?, ?)",
                    (row["id"], sub_pool_ids[sub], row["cidr"], row["created_at"]),
                )
            for row, sub in allocation_moves:
                conn.execute(
                    "INSERT INTO allocations "
                    "(id, pool_id, cidr, request_id, prefix_length, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        row["id"],
                        sub_pool_ids[sub],
                        row["cidr"],
                        row["request_id"],
                        row["prefix_length"],
                        row["created_at"],
                    ),
                )

            cursor = conn.execute(
                "INSERT INTO pool_migrations "
                "(operation_id, source_pool_id, source_cidr, sub_pools, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (operation_id, pool_id, str(pool_net), json.dumps(sub_pools), now),
            )
            migration_id = cursor.lastrowid
        except sqlite3.IntegrityError:
            raise ApiError(
                409,
                f"partition of pool {pool_id} conflicts with existing data",
                code="partition_conflict",
            )

    return {
        "operation_id": operation_id,
        "migration_id": migration_id,
        "source_pool_id": pool_id,
        "source_cidr": str(pool_net),
        "sub_pools": sub_pools,
        "created_at": now,
        "replayed": False,
    }
