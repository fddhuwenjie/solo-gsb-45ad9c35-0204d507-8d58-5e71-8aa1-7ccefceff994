"""Policy-driven batch reservations: reserve several subnets atomically.

``POST /pools/{id}/reservations`` reserves a whole batch of subnets in one
call.  The caller submits a ``batch_id`` (idempotency key), a
``default_action``, priority-ordered CIDR allow/deny rules and the
reservation items (each a ``request_id`` plus a ``prefix_length``).

Everything runs inside a single ``BEGIN IMMEDIATE`` write transaction:

* the rules are compiled over the pool CIDR with the same compiler as
  ``/cidr-policy/compile``, yielding disjoint allow/deny segments that
  partition the pool;
* the pool's exclusions and allocations are read as one consistent
  snapshot under the write lock;
* each item, in input order, is placed at the lowest aligned free CIDR
  that lies completely inside an allow segment -- free space is the pool
  minus exclusions, existing allocations, deny segments and the CIDRs
  already placed earlier in the batch;
* an item with no free space at all fails with ``pool_exhausted``; an
  item whose remaining free space all hits deny segments fails with
  ``policy_denied``.  Either way the whole batch rolls back and the pool
  is left untouched.

Successful reservations are written to the ordinary allocations table, so
they behave exactly like single allocations afterwards (they show up in
the pool status and can be released individually).  ``batch_id`` is the
idempotency key: replaying the same batch with the same parameters
returns the stored result; the same key with different parameters is a
409 conflict.  Items whose ``request_id`` already exists keep the
single-allocation idempotency semantics: the same pool and prefix length
resolves to the existing allocation, anything else conflicts.
"""

from __future__ import annotations

import ipaddress
import json
import sqlite3

from .cidrmath import compute_free, lowest_aligned, parse_network
from .cidrpolicy import PolicyError, compile_policy
from .db import write_transaction
from .service import (
    ApiError,
    _pool_allocations,
    _pool_exclusions,
    _row_pool,
    utc_now,
)


def _canonical_params(default_action: str, rules, items) -> str:
    """Order-sensitive parameter fingerprint of a batch request.

    Rule order is the matching priority and item order is the placement
    order, so both are preserved as submitted; rule CIDRs are
    canonicalised (they were already validated by the policy compiler).
    """

    return json.dumps(
        {
            "default_action": default_action,
            "rules": [
                {"cidr": str(parse_network(rule.cidr)), "action": rule.action}
                for rule in rules
            ],
            "items": [
                {"request_id": item.request_id, "prefix_length": item.prefix_length}
                for item in items
            ],
        },
        separators=(",", ":"),
    )


def _replay_result(row: sqlite3.Row) -> dict:
    return {
        "batch_id": row["batch_id"],
        "pool_id": row["pool_id"],
        "reservations": json.loads(row["result"]),
        "created_at": row["created_at"],
        "replayed": True,
    }


def reserve_batch(pool_id: int, batch_id: str, default_action: str, rules, items) -> dict:
    """Reserve every item atomically under the allow/deny policy.

    The policy compilation, the consistent pool snapshot, the placement
    of every item and all writes happen inside one immediate write
    transaction, so concurrent batches are serialised and any failure
    rolls the whole batch back.
    """

    for item in items:
        if not 0 <= item.prefix_length <= 32:
            raise ApiError(
                422,
                "prefix_length must be between 0 and 32",
                code="invalid_prefix",
            )

    with write_transaction() as conn:
        pool = _row_pool(conn, pool_id)
        pool_net = parse_network(pool["cidr"])

        # Compile the policy over the pool itself; the segments partition
        # the pool into allow and deny ranges.
        try:
            _, segments = compile_policy(
                pool["cidr"],
                default_action,
                [(rule.cidr, rule.action) for rule in rules],
            )
        except PolicyError as exc:
            raise ApiError(422, exc.detail, code=exc.code)
        deny_segments = [net for net, action in segments if action == "deny"]

        params_json = _canonical_params(default_action, rules, items)

        # Idempotency: a stored batch with the same key replays when the
        # parameters match and conflicts when anything changed.
        previous = conn.execute(
            "SELECT * FROM reservation_batches WHERE batch_id = ?",
            (batch_id,),
        ).fetchone()
        if previous is not None:
            if previous["pool_id"] != pool_id or previous["params"] != params_json:
                raise ApiError(
                    409,
                    f"batch_id {batch_id!r} was already used with different "
                    "parameters",
                    code="batch_id_conflict",
                )
            return _replay_result(previous)

        # Consistent snapshot of the pool under the write lock.  The
        # request_id lookup is global (the column is UNIQUE across pools),
        # mirroring the single-allocation idempotency check.
        exclusions = [parse_network(r["cidr"]) for r in _pool_exclusions(conn, pool_id)]
        allocated = [parse_network(r["cidr"]) for r in _pool_allocations(conn, pool_id)]
        request_ids = [item.request_id for item in items]
        existing_rows = (
            conn.execute(
                "SELECT * FROM allocations WHERE request_id IN "
                f"({','.join('?' for _ in request_ids)})",
                request_ids,
            ).fetchall()
            if request_ids
            else []
        )
        existing_by_request = {row["request_id"]: row for row in existing_rows}

        now = utc_now()
        reservations: list[dict] = []
        chosen: list[ipaddress.IPv4Network] = []
        batch_seen: dict[str, dict] = {}

        for item in items:
            # Original request_id idempotency semantics: same pool and
            # prefix length resolves to the existing allocation; any
            # parameter change is a conflict.
            existing = existing_by_request.get(item.request_id)
            if existing is not None:
                if existing["pool_id"] != pool_id:
                    raise ApiError(
                        409,
                        f"request_id {item.request_id!r} already used against "
                        f"pool {existing['pool_id']}",
                        code="request_id_conflict",
                    )
                if existing["prefix_length"] != item.prefix_length:
                    raise ApiError(
                        409,
                        f"request_id {item.request_id!r} already allocated "
                        f"prefix_length {existing['prefix_length']}, not "
                        f"{item.prefix_length}",
                        code="request_id_conflict",
                    )
                reservations.append(
                    {
                        "id": existing["id"],
                        "request_id": item.request_id,
                        "cidr": existing["cidr"],
                        "prefix_length": existing["prefix_length"],
                        "created_at": existing["created_at"],
                        "replayed": True,
                    }
                )
                continue

            # A repeated request_id inside the same batch follows the same
            # semantics against the reservation placed earlier.
            seen = batch_seen.get(item.request_id)
            if seen is not None:
                if seen["prefix_length"] != item.prefix_length:
                    raise ApiError(
                        409,
                        f"request_id {item.request_id!r} already reserved "
                        f"prefix_length {seen['prefix_length']}, not "
                        f"{item.prefix_length}, in this batch",
                        code="request_id_conflict",
                    )
                reservations.append({**seen, "replayed": True})
                continue

            blocked = exclusions + allocated + chosen
            free = compute_free(pool_net, blocked)
            if lowest_aligned(free, item.prefix_length) is None:
                raise ApiError(
                    409,
                    f"no contiguous free /{item.prefix_length} subnet in pool "
                    f"{pool_net} for request_id {item.request_id!r}",
                    code="pool_exhausted",
                )
            # Eligible space additionally excludes every deny segment, so
            # any CIDR picked here lies completely inside an allow segment.
            eligible = compute_free(pool_net, blocked + deny_segments)
            picked = lowest_aligned(eligible, item.prefix_length)
            if picked is None:
                raise ApiError(
                    409,
                    f"request_id {item.request_id!r}: every free "
                    f"/{item.prefix_length} subnet in pool {pool_net} hits a "
                    "deny segment",
                    code="policy_denied",
                )
            chosen.append(picked)

            try:
                cursor = conn.execute(
                    "INSERT INTO allocations "
                    "(pool_id, cidr, request_id, prefix_length, created_at)"
                    " VALUES (?, ?, ?, ?, ?)",
                    (pool_id, str(picked), item.request_id, item.prefix_length, now),
                )
            except sqlite3.IntegrityError:
                raise ApiError(
                    409,
                    f"request_id {item.request_id!r} conflicts with an "
                    "existing allocation",
                    code="request_id_conflict",
                )
            reservation = {
                "id": cursor.lastrowid,
                "request_id": item.request_id,
                "cidr": str(picked),
                "prefix_length": item.prefix_length,
                "created_at": now,
                "replayed": False,
            }
            batch_seen[item.request_id] = reservation
            reservations.append(reservation)

        try:
            conn.execute(
                "INSERT INTO reservation_batches "
                "(batch_id, pool_id, params, result, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (batch_id, pool_id, params_json, json.dumps(reservations), now),
            )
        except sqlite3.IntegrityError:
            raise ApiError(
                409,
                f"batch_id {batch_id!r} conflicts with an existing batch",
                code="batch_id_conflict",
            )

    return {
        "batch_id": batch_id,
        "pool_id": pool_id,
        "reservations": reservations,
        "created_at": now,
        "replayed": False,
    }
