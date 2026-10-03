"""Verifiable pool snapshot export and restore.

A snapshot is a canonical JSON document describing one pool's full state:
the pool itself, its exclusions and its allocations.  ``GET .../snapshot``
exports it with a SHA-256 digest; ``POST .../snapshot/restore`` verifies
that digest (plus full structural validation) and replaces the pool's state
inside a single SQLite write transaction.

Canonical form
--------------
* object keys in a fixed order (never ``sort_keys`` -- addresses sort
  lexicographically wrong, e.g. "10.0.0.0" before "2.0.0.0");
* compact separators (``,`` / ``:``, no whitespace), UTF-8, no trailing
  newline;
* exclusions and allocations ordered by their numeric network address so
  the digest does not depend on insertion/input order.  Each record keeps
  its exported database ``id`` and ``pool_id`` alongside the address, so
  the row identity is never lost while the arrays are reordered.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import sqlite3

from .cidrmath import parse_network
from .db import read_transaction, write_transaction
from .schemas import DIGEST_ALGORITHM, SNAPSHOT_VERSION, SnapshotDocument
from .service import ApiError, _row_pool, utc_now


def _snapshot_error(detail: str, code: str) -> ApiError:
    return ApiError(422, detail, code=code)


def _net(raw: str, what: str) -> ipaddress.IPv4Network:
    try:
        return parse_network(raw)
    except ValueError as exc:
        raise _snapshot_error(f"invalid {what} CIDR {raw!r}: {exc}", "invalid_cidr")


def _normalise(doc: SnapshotDocument, pool_id: int) -> dict:
    """Validate the snapshot contents and return canonical (ordered) data.

    Checks performed here (no database access):

    * ``digest_algorithm`` is SHA-256 (enforced by the Pydantic model);
    * ``snapshot.pool.id`` matches the pool in the URL (foreign-key target);
    * every exported exclusion/allocation ``pool_id`` matches the pool in
      the URL (records must belong to the pool they are restored into);
    * exported exclusion/allocation ``id`` values are unique per table;
    * every CIDR parses strictly; exclusions/allocations are inside the pool;
    * no exclusion overlaps another exclusion or an allocation;
    * no two allocations overlap;
    * each allocation's ``prefix_length`` matches its CIDR;
    * ``request_id`` values are unique within the snapshot.

    Lists are sorted by numeric network address, which gives the digest a
    stable value independent of how the arrays were ordered by the client.
    The exported ``id`` / ``pool_id`` travel with each record through the
    sort, so a reordered record keeps the identity it was exported with.
    """

    if doc.pool.id != pool_id:
        raise ApiError(
            422,
            f"snapshot is for pool {doc.pool.id}, not pool {pool_id}",
            code="snapshot_pool_mismatch",
        )

    pool_net = _net(doc.pool.cidr, "pool")

    exclusion_pairs = sorted(
        ((_net(e.cidr, "exclusion"), e) for e in doc.exclusions),
        key=lambda p: int(p[0].network_address),
    )
    seen_excl: set[ipaddress.IPv4Network] = set()
    seen_excl_ids: set[int] = set()
    exclusion_nets: list[ipaddress.IPv4Network] = []
    for net, entry in exclusion_pairs:
        if entry.pool_id != pool_id:
            raise _snapshot_error(
                f"exclusion id {entry.id} belongs to pool {entry.pool_id}, "
                f"not pool {pool_id}",
                "snapshot_record_pool_mismatch",
            )
        if entry.id in seen_excl_ids:
            raise _snapshot_error(
                f"exclusion id {entry.id} appears more than once in the snapshot",
                "snapshot_duplicate_record_id",
            )
        seen_excl_ids.add(entry.id)
        if not net.subnet_of(pool_net):
            raise _snapshot_error(
                f"exclusion {net} is not inside pool {pool_net}",
                "exclusion_outside_pool",
            )
        if net in seen_excl or any(net.overlaps(other) for other in exclusion_nets):
            raise _snapshot_error(
                f"exclusion {net} overlaps another exclusion in the snapshot",
                "exclusion_overlap",
            )
        seen_excl.add(net)
        exclusion_nets.append(net)

    allocation_pairs = sorted(
        ((_net(a.cidr, "allocation"), a) for a in doc.allocations),
        key=lambda p: int(p[0].network_address),
    )
    seen_request_ids: set[str] = set()
    seen_alloc_ids: set[int] = set()
    allocation_nets: list[ipaddress.IPv4Network] = []
    for net, entry in allocation_pairs:
        if entry.pool_id != pool_id:
            raise _snapshot_error(
                f"allocation id {entry.id} belongs to pool {entry.pool_id}, "
                f"not pool {pool_id}",
                "snapshot_record_pool_mismatch",
            )
        if entry.id in seen_alloc_ids:
            raise _snapshot_error(
                f"allocation id {entry.id} appears more than once in the snapshot",
                "snapshot_duplicate_record_id",
            )
        seen_alloc_ids.add(entry.id)
        if not net.subnet_of(pool_net):
            raise _snapshot_error(
                f"allocation {net} is not inside pool {pool_net}",
                "snapshot_allocation_outside_pool",
            )
        if net.prefixlen != entry.prefix_length:
            raise _snapshot_error(
                f"allocation {net} has prefix_length {entry.prefix_length} in the "
                f"snapshot but its CIDR is /{net.prefixlen}",
                "snapshot_prefix_mismatch",
            )
        if entry.request_id in seen_request_ids:
            raise _snapshot_error(
                f"request_id {entry.request_id!r} appears more than once in the snapshot",
                "snapshot_duplicate_request_id",
            )
        seen_request_ids.add(entry.request_id)
        if any(net.overlaps(ex) for ex in exclusion_nets):
            raise _snapshot_error(
                f"allocation {net} overlaps an exclusion in the snapshot",
                "snapshot_allocation_overlap",
            )
        if net in allocation_nets or any(net.overlaps(other) for other in allocation_nets):
            raise _snapshot_error(
                f"allocation {net} overlaps another allocation in the snapshot",
                "snapshot_allocation_overlap",
            )
        allocation_nets.append(net)

    return {
        "version": doc.version,
        "digest_algorithm": doc.digest_algorithm,
        "pool": {
            "id": doc.pool.id,
            "cidr": str(pool_net),
            "created_at": doc.pool.created_at,
        },
        "exclusions": [
            {
                "id": entry.id,
                "pool_id": entry.pool_id,
                "cidr": str(net),
                "created_at": entry.created_at,
            }
            for net, entry in exclusion_pairs
        ],
        "allocations": [
            {
                "id": entry.id,
                "pool_id": entry.pool_id,
                "cidr": str(net),
                "request_id": entry.request_id,
                "prefix_length": entry.prefix_length,
                "created_at": entry.created_at,
            }
            for net, entry in allocation_pairs
        ],
    }


def canonical_bytes(data: dict) -> bytes:
    """Serialise a normalised snapshot dict to canonical JSON bytes."""

    return json.dumps(
        data,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def digest_header(digest_hex: str) -> str:
    """RFC 3230 ``Digest`` header value for the SHA-256 hex digest."""

    return "sha-256=" + base64.b64encode(bytes.fromhex(digest_hex)).decode("ascii")


def get_snapshot(pool_id: int) -> dict:
    """Export one pool as a canonical snapshot plus its SHA-256 digest."""

    with read_transaction() as conn:
        pool = _row_pool(conn, pool_id)
        exclusions = conn.execute(
            "SELECT id, pool_id, cidr, created_at FROM exclusions WHERE pool_id = ?",
            (pool_id,),
        ).fetchall()
        allocations = conn.execute(
            "SELECT id, pool_id, cidr, request_id, prefix_length, created_at "
            "FROM allocations WHERE pool_id = ?",
            (pool_id,),
        ).fetchall()

    data = {
        "version": SNAPSHOT_VERSION,
        "digest_algorithm": DIGEST_ALGORITHM,
        "pool": {
            "id": pool["id"],
            "cidr": pool["cidr"],
            "created_at": pool["created_at"],
        },
        "exclusions": sorted(
            (
                {
                    "id": row["id"],
                    "pool_id": row["pool_id"],
                    "cidr": row["cidr"],
                    "created_at": row["created_at"],
                }
                for row in exclusions
            ),
            key=lambda e: int(_net(e["cidr"], "exclusion").network_address),
        ),
        "allocations": sorted(
            (
                {
                    "id": row["id"],
                    "pool_id": row["pool_id"],
                    "cidr": row["cidr"],
                    "request_id": row["request_id"],
                    "prefix_length": row["prefix_length"],
                    "created_at": row["created_at"],
                }
                for row in allocations
            ),
            key=lambda a: int(_net(a["cidr"], "allocation").network_address),
        ),
    }
    digest = hashlib.sha256(canonical_bytes(data)).hexdigest()
    return {"pool_id": pool_id, "digest": digest, "snapshot": data}


def _replay_result(restore_id: str, pool_id: int, digest_hex: str) -> dict:
    return {
        "restore_id": restore_id,
        "pool_id": pool_id,
        "digest": digest_hex,
        "replayed": True,
        "replaced": False,
    }


def restore_snapshot(pool_id: int, restore_id: str, digest: str, doc: SnapshotDocument) -> dict:
    """Verify and restore a snapshot for ``pool_id``.

    The cheap, failure-prone checks run before the write transaction so a
    rejection never opens a transaction that must be rolled back:

    1. digest is well-formed (64 hex chars);
    2. the pool exists (foreign-key target);
    3. this ``restore_id`` already completed -> replay the original result,
       or 409 if it targeted a different pool/digest (idempotency wins over
       every other check);
    4. the snapshot digest matches and its contents validate (CIDR
       containment, no overlaps, prefix lengths, request_id uniqueness,
       record ``pool_id`` ownership and per-table ``id`` uniqueness);
    5. inside one ``BEGIN IMMEDIATE`` transaction: authoritative replay
       check, cross-pool request_id collision check, then full state
       replacement plus the restore record.  Any error rolls everything
       back, leaving the pool's previous data untouched.
    """

    # 1. Digest format.
    try:
        expected = bytes.fromhex(digest)
        valid_hex = len(expected) == 32
    except ValueError:
        valid_hex = False
    if not valid_hex:
        raise ApiError(
            422,
            "digest must be a 64-character SHA-256 hex string",
            code="snapshot_bad_digest",
        )
    digest = digest.lower()

    # 2 + 3. Pool existence and a fast replay check on a read transaction.
    with read_transaction() as conn:
        _row_pool(conn, pool_id)
        previous = conn.execute(
            "SELECT * FROM snapshot_restores WHERE restore_id = ?",
            (restore_id,),
        ).fetchone()
    if previous is not None:
        if previous["pool_id"] != pool_id or previous["digest"] != digest:
            raise ApiError(
                409,
                f"restore_id {restore_id!r} was already used for a different "
                "restore",
                code="restore_id_conflict",
            )
        return _replay_result(restore_id, pool_id, digest)

    # 4. Structural/content validation; also normalises the canonical bytes.
    data = _normalise(doc, pool_id)
    actual = hashlib.sha256(canonical_bytes(data)).hexdigest()
    if actual != digest:
        raise ApiError(
            422,
            f"snapshot digest mismatch: expected {actual}, got {digest}",
            code="snapshot_digest_mismatch",
        )

    # 5. Atomic replacement.
    with write_transaction() as conn:
        # Authoritative replay check: a concurrent restore with the same
        # restore_id may have committed while we validated.
        previous = conn.execute(
            "SELECT * FROM snapshot_restores WHERE restore_id = ?",
            (restore_id,),
        ).fetchone()
        if previous is not None:
            if previous["pool_id"] != pool_id or previous["digest"] != digest:
                raise ApiError(
                    409,
                    f"restore_id {restore_id!r} was already used for a different "
                    "restore",
                    code="restore_id_conflict",
                )
            return _replay_result(restore_id, pool_id, digest)

        # request_id is globally unique (UNIQUE column across all pools).
        snapshot_ids = [a["request_id"] for a in data["allocations"]]
        if snapshot_ids:
            placeholders = ",".join("?" for _ in snapshot_ids)
            clash = conn.execute(
                f"SELECT request_id, pool_id FROM allocations "
                f"WHERE request_id IN ({placeholders}) AND pool_id != ? LIMIT 1",
                (*snapshot_ids, pool_id),
            ).fetchone()
            if clash is not None:
                raise ApiError(
                    409,
                    f"request_id {clash['request_id']!r} already exists in pool "
                    f"{clash['pool_id']}",
                    code="request_id_conflict",
                )

        # Replace this pool's state.  UPDATE first (the cidr UNIQUE
        # constraint may collide with another pool), then delete/reinsert
        # the dependent rows using the exported row ids/pool_ids so each
        # record is written back under the identity it was exported with.
        # Any failure rolls back the whole transaction.
        now = utc_now()
        try:
            conn.execute(
                "UPDATE pools SET cidr = ?, created_at = ? WHERE id = ?",
                (data["pool"]["cidr"], data["pool"]["created_at"], pool_id),
            )
            conn.execute("DELETE FROM exclusions WHERE pool_id = ?", (pool_id,))
            conn.execute("DELETE FROM allocations WHERE pool_id = ?", (pool_id,))
            conn.executemany(
                "INSERT INTO exclusions (id, pool_id, cidr, created_at) "
                "VALUES (?, ?, ?, ?)",
                [
                    (
                        e["id"],
                        e["pool_id"],
                        e["cidr"],
                        e["created_at"],
                    )
                    for e in data["exclusions"]
                ],
            )
            conn.executemany(
                "INSERT INTO allocations "
                "(id, pool_id, cidr, request_id, prefix_length, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                [
                    (
                        a["id"],
                        a["pool_id"],
                        a["cidr"],
                        a["request_id"],
                        a["prefix_length"],
                        a["created_at"],
                    )
                    for a in data["allocations"]
                ],
            )
            conn.execute(
                "INSERT INTO snapshot_restores (restore_id, pool_id, digest, created_at)"
                " VALUES (?, ?, ?, ?)",
                (restore_id, pool_id, digest, now),
            )
        except sqlite3.IntegrityError:
            raise ApiError(
                409,
                f"restore for pool {pool_id} conflicts with existing data",
                code="snapshot_restore_conflict",
            )

    return {
        "restore_id": restore_id,
        "pool_id": pool_id,
        "digest": digest,
        "replayed": False,
        "replaced": True,
    }
