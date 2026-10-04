"""Policy-gated batch reservations against one address pool.

``POST /pools/{id}/reservations`` reserves several subnets in one atomic
batch.  The caller submits a ``batch_id`` (idempotency key), a
``default_action``, priority-ordered CIDR allow/deny rules and a list of
items, each carrying a ``request_id`` and a ``prefix_length``.

Everything happens inside a single ``BEGIN IMMEDIATE`` write transaction:

* the batch idempotency check (same ``batch_id`` + same parameters replays
  the stored result; different parameters conflict);
* compilation of the allow/deny rules over the pool CIDR (the policy scope
  is the pool itself);
* a consistent snapshot read of the pool's exclusions and allocations;
* for every item, in input order: the original ``request_id`` idempotency
  semantics (an existing allocation with the same pool and prefix length is
  replayed into the mapping, a mismatch conflicts), otherwise the lowest
  aligned free segment outside exclusions and existing allocations is
  chosen -- and it must lie completely inside an ``allow`` segment.

Any failure -- a chosen segment hitting deny space, an item without space,
a ``request_id`` conflict -- raises and rolls the whole batch back: no
allocation is written and the pool is left unchanged.  On success every
reservation is inserted as a regular allocation (visible to every other
endpoint) and the batch result is recorded for replay.
"""

from __future__ import annotations

import ipaddress
import json

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


def _canonical_params(
    pool_id: int,
    default_action: str,
    parsed_rules: list[tuple[ipaddress.IPv4Network, str]],
    items: list,
) -> str:
    """Build the parameter fingerprint of a batch request.

    Rule order is the matching priority and item order is the allocation
    order, so both are significant: replaying with a different order is a
    different batch.  Rule CIDRs are stored in canonical form.
    """

    params = {
        "pool_id": pool_id,
        "default_action": default_action,
        "rules": [[str(net), action] for net, action in parsed_rules],
        "items": [[item.request_id, item.prefix_length] for item in items],
    }
    return json.dumps(params, separators=(",", ":"))


def _response(
    batch_id: str, pool_id: int, reservations: list[dict], created_at: str, replayed: bool
) -> dict:
    return {
        "batch_id": batch_id,
        "pool_id": pool_id,
        "reservations": reservations,
        "created_at": created_at,
        "replayed": replayed,
    }


def reserve_batch(
    pool_id: int,
    batch_id: str,
    default_action: str,
    rules: list,
    items: list,
) -> dict:
    """Reserve every item in one atomic, policy-gated batch.

    ``rules`` and ``items`` are pydantic objects exposing ``cidr``/``action``
    and ``request_id``/``prefix_length`` respectively.
    """

    # Parse rule CIDRs up-front so malformed input fails before the
    # transaction opens and the stored fingerprint is canonical.
    parsed_rules: list[tuple[ipaddress.IPv4Network, str]] = []
    for rule in rules:
        try:
            net = parse_network(rule.cidr)
        except ValueError as exc:
            raise ApiError(
                422, f"invalid rule CIDR {rule.cidr!r}: {exc}", code="invalid_cidr"
            )
        parsed_rules.append((net, rule.action))

    params_json = _canonical_params(pool_id, default_action, parsed_rules, items)

    # The whole batch -- idempotency check, policy compilation, consistent
    # snapshot read, per-item selection and every insert -- runs inside one
    # immediate write transaction.  SQLite serialises writers, so concurrent
    # batches cannot observe the same free space twice, and any raised error
    # rolls every insert of the batch back.
    with write_transaction() as conn:
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
            return _response(
                batch_id,
                pool_id,
                json.loads(previous["result"]),
                previous["created_at"],
                replayed=True,
            )

        pool = _row_pool(conn, pool_id)
        pool_net = parse_network(pool["cidr"])

        # Compile the allow/deny rules over the pool CIDR inside the same
        # transaction that holds the consistent pool snapshot.
        try:
            _, segments = compile_policy(
                pool["cidr"],
                default_action,
                [(str(net), action) for net, action in parsed_rules],
            )
        except PolicyError as exc:
            raise ApiError(422, exc.detail, code=exc.code)
        allow_segments = [net for net, action in segments if action == "allow"]

        exclusions = [parse_network(r["cidr"]) for r in _pool_exclusions(conn, pool_id)]
        allocations = [parse_network(r["cidr"]) for r in _pool_allocations(conn, pool_id)]
        # Grows with every segment reserved below, so later items in the
        # batch never overlap earlier ones.
        blocked = exclusions + allocations

        now = utc_now()
        reservations: list[dict] = []
        for item in items:
            # Original request_id idempotency semantics: an existing
            # allocation with the same pool and prefix length is replayed
            # into the mapping; any parameter change conflicts and rolls
            # the whole batch back.
            existing = conn.execute(
                "SELECT * FROM allocations WHERE request_id = ?",
                (item.request_id,),
            ).fetchone()
            if existing is not None:
                if existing["pool_id"] != pool_id:
                    raise ApiError(
                        409,
                        f"request_id {item.request_id!r} already used against pool "
                        f"{existing['pool_id']}",
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
                        "request_id": item.request_id,
                        "prefix_length": item.prefix_length,
                        "cidr": existing["cidr"],
                        "allocation_id": existing["id"],
                        "replayed": True,
                    }
                )
                continue

            free = compute_free(pool_net, blocked)
            chosen = lowest_aligned(free, item.prefix_length)
            if chosen is None:
                raise ApiError(
                    409,
                    f"no contiguous free /{item.prefix_length} subnet in pool "
                    f"{pool_net}",
                    code="pool_exhausted",
                )
            if not any(chosen.subnet_of(allow) for allow in allow_segments):
                raise ApiError(
                    409,
                    f"lowest free /{item.prefix_length} segment {chosen} for "
                    f"request_id {item.request_id!r} is not completely inside "
                    "an allow segment",
                    code="reservation_denied",
                )

            cursor = conn.execute(
                "INSERT INTO allocations "
                "(pool_id, cidr, request_id, prefix_length, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (pool_id, str(chosen), item.request_id, item.prefix_length, now),
            )
            blocked.append(chosen)
            reservations.append(
                {
                    "request_id": item.request_id,
                    "prefix_length": item.prefix_length,
                    "cidr": str(chosen),
                    "allocation_id": cursor.lastrowid,
                    "replayed": False,
                }
            )

        conn.execute(
            "INSERT INTO reservation_batches "
            "(batch_id, pool_id, params, result, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (batch_id, pool_id, params_json, json.dumps(reservations), now),
        )

    return _response(batch_id, pool_id, reservations, now, replayed=False)
