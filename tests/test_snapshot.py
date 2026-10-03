"""Tests for verifiable pool snapshot export and restore."""

from __future__ import annotations

import base64
import hashlib
import json
import threading

from fastapi.testclient import TestClient

from app.snapshot import canonical_bytes


def _create_pool(client, cidr="10.0.0.0/24", exclusions=None):
    resp = client.post("/pools", json={"cidr": cidr, "exclusions": exclusions or []})
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


def _allocate(client, pool_id, request_id, prefix_length):
    resp = client.post(
        f"/pools/{pool_id}/allocations",
        json={"request_id": request_id, "prefix_length": prefix_length},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["cidr"]


def _get_snapshot(client, pool_id):
    resp = client.get(f"/pools/{pool_id}/snapshot")
    assert resp.status_code == 200, resp.text
    return resp


def _canonical(doc: dict) -> bytes:
    # Canonical form: compact separators, fixed field order, UTF-8.
    return json.dumps(doc, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _restore(client, pool_id, body):
    return client.post(f"/pools/{pool_id}/snapshot/restore", json=body)


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------


def test_snapshot_export_structure_and_fixed_field_order(client):
    pid = _create_pool(client, exclusions=["10.0.0.128/25"])
    _allocate(client, pid, "a", 26)  # 10.0.0.0/26

    resp = _get_snapshot(client, pid)
    body = resp.json()
    assert body["pool_id"] == pid
    assert list(body.keys()) == ["pool_id", "digest", "snapshot"]

    snap = body["snapshot"]
    assert list(snap.keys()) == [
        "version", "digest_algorithm", "pool", "exclusions", "allocations"
    ]
    assert snap["version"] == 1
    assert snap["digest_algorithm"] == "SHA-256"
    assert list(snap["pool"].keys()) == ["id", "cidr", "created_at"]
    assert snap["pool"] == {
        "id": pid,
        "cidr": "10.0.0.0/24",
        "created_at": snap["pool"]["created_at"],
    }
    assert [list(e.keys()) for e in snap["exclusions"]] == [
        ["id", "pool_id", "cidr", "created_at"]
    ]
    excl = snap["exclusions"][0]
    assert excl["pool_id"] == pid
    assert excl["id"] >= 1
    assert excl["cidr"] == "10.0.0.128/25"
    assert [list(a.keys()) for a in snap["allocations"]] == [
        ["id", "pool_id", "cidr", "request_id", "prefix_length", "created_at"]
    ]
    alloc = snap["allocations"][0]
    assert alloc["pool_id"] == pid
    assert alloc["id"] >= 1
    assert alloc["cidr"] == "10.0.0.0/26"
    assert alloc["request_id"] == "a"
    assert alloc["prefix_length"] == 26


def test_snapshot_digest_is_recomputable_with_identities(client):
    # Pool with at least one exclusion and one allocation: the exported
    # digest must be reproducible from the document, including the
    # digest_algorithm marker and every record's id/pool_id.
    pid = _create_pool(client, exclusions=["10.0.0.128/25"])
    _allocate(client, pid, "a", 26)  # 10.0.0.0/26

    body = _get_snapshot(client, pid).json()
    expected = hashlib.sha256(_canonical(body["snapshot"])).hexdigest()
    assert body["digest"] == expected
    assert len(body["digest"]) == 64

    # Dropping any exported field must change the digest: the identities
    # and algorithm marker actually participate in the canonical bytes.
    snap = body["snapshot"]
    del snap["digest_algorithm"]
    assert hashlib.sha256(_canonical(snap)).hexdigest() != body["digest"]
    snap = body["snapshot"]
    del snap["exclusions"][0]["id"]
    assert hashlib.sha256(_canonical(snap)).hexdigest() != body["digest"]
    snap = body["snapshot"]
    del snap["allocations"][0]["pool_id"]
    assert hashlib.sha256(_canonical(snap)).hexdigest() != body["digest"]


def test_snapshot_digest_header(client):
    pid = _create_pool(client)
    resp = _get_snapshot(client, pid)
    header = resp.headers["digest"]
    assert header.startswith("sha-256=")
    decoded = base64.b64decode(header[len("sha-256=") :])
    assert decoded.hex() == resp.json()["digest"]


def test_snapshot_lists_sorted_by_address(client):
    # Exclusions/allocations get created in non-sorted address order.
    pid = _create_pool(client, cidr="10.0.0.0/24", exclusions=["10.0.0.192/26"])
    _allocate(client, pid, "z", 27)  # 10.0.0.0/27
    _allocate(client, pid, "y", 27)  # 10.0.0.32/27

    snap = _get_snapshot(client, pid).json()["snapshot"]
    assert [a["cidr"] for a in snap["allocations"]] == [
        "10.0.0.0/27",
        "10.0.0.32/27",
    ]
    assert [e["cidr"] for e in snap["exclusions"]] == ["10.0.0.192/26"]


def test_snapshot_is_deterministic(client):
    pid = _create_pool(client, exclusions=["10.0.0.128/26"])
    _allocate(client, pid, "a", 27)
    first = _get_snapshot(client, pid).json()
    second = _get_snapshot(client, pid).json()
    assert first == second


def test_canonical_bytes_uses_fixed_key_order_not_sorted():
    assert canonical_bytes({"b": 1, "a": 2}) == b'{"b":1,"a":2}'
    assert canonical_bytes({"x": [1, 2]}) == b'{"x":[1,2]}'


def test_snapshot_pool_not_found(client):
    resp = client.get("/pools/999/snapshot")
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "pool_not_found"


# ---------------------------------------------------------------------------
# Restore: happy paths
# ---------------------------------------------------------------------------


def test_restore_roundtrip_replaces_pool_state(client):
    pid = _create_pool(client, exclusions=["10.0.0.240/28"])
    _allocate(client, pid, "old-1", 26)  # 10.0.0.0/26
    snap = _get_snapshot(client, pid).json()

    # Drift the state: new allocation + new exclusion.
    _allocate(client, pid, "old-2", 26)  # 10.0.0.64/26
    client.post(f"/pools/{pid}/exclusions", json={"cidr": "10.0.0.128/26"})
    drifted = client.get(f"/pools/{pid}").json()
    assert len(drifted["allocated"]) == 2
    assert len(drifted["exclusions"]) == 2

    resp = _restore(
        client,
        pid,
        {"restore_id": "mig-1", "digest": snap["digest"], "snapshot": snap["snapshot"]},
    )
    assert resp.status_code == 200, resp.text
    result = resp.json()
    assert result["replayed"] is False
    assert result["replaced"] is True
    assert result["digest"] == snap["digest"]

    status = client.get(f"/pools/{pid}").json()
    assert len(status["allocated"]) == 1
    assert status["allocated"][0]["request_id"] == "old-1"
    assert status["allocated"][0]["cidr"] == "10.0.0.0/26"
    assert status["exclusions"] == ["10.0.0.240/28"]

    # A fresh export of the restored state matches the original snapshot.
    again = _get_snapshot(client, pid).json()
    assert again["snapshot"] == snap["snapshot"]
    assert again["digest"] == snap["digest"]


def test_restore_empty_snapshot_clears_state(client):
    pid = _create_pool(client)
    _allocate(client, pid, "a", 24)
    pool_created_at = _get_snapshot(client, pid).json()["snapshot"]["pool"]["created_at"]
    empty = {
        "version": 1,
        "digest_algorithm": "SHA-256",
        "pool": {
            "id": pid,
            "cidr": "10.0.0.0/24",
            "created_at": pool_created_at,
        },
        "exclusions": [],
        "allocations": [],
    }
    digest = hashlib.sha256(_canonical(empty)).hexdigest()
    resp = _restore(
        client, pid, {"restore_id": "wipe", "digest": digest, "snapshot": empty}
    )
    assert resp.status_code == 200, resp.text

    status = client.get(f"/pools/{pid}").json()
    assert status["allocated"] == []
    assert status["exclusions"] == []
    assert status["free_cidrs"] == ["10.0.0.0/24"]


def test_restore_accepts_arrays_in_any_order(client):
    pid = _create_pool(client)
    _allocate(client, pid, "a", 27)  # .0/27
    _allocate(client, pid, "b", 27)  # .32/27
    snap = _get_snapshot(client, pid).json()

    # Reverse both arrays but keep the original digest: server-side
    # normalisation sorts by address, so verification still succeeds.
    # The exported ids must travel with their records through the sort.
    doc = snap["snapshot"]
    alloc_identities = {a["cidr"]: a["id"] for a in doc["allocations"]}
    doc["allocations"] = list(reversed(doc["allocations"]))
    doc["exclusions"] = list(reversed(doc["exclusions"]))
    resp = _restore(
        client,
        pid,
        {"restore_id": "unordered", "digest": snap["digest"], "snapshot": doc},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["replaced"] is True

    again = _get_snapshot(client, pid).json()
    assert {a["cidr"]: a["id"] for a in again["snapshot"]["allocations"]} == alloc_identities


def test_restore_replays_same_result_without_changing_state(client):
    pid = _create_pool(client)
    _allocate(client, pid, "a", 28)
    snap = _get_snapshot(client, pid).json()
    body = {"restore_id": "idem-restore", "digest": snap["digest"],
            "snapshot": snap["snapshot"]}

    first = _restore(client, pid, body)
    assert first.status_code == 200, first.text
    assert first.json() == {
        "restore_id": "idem-restore",
        "pool_id": pid,
        "digest": snap["digest"],
        "replayed": False,
        "replaced": True,
    }

    # Drift state, then replay: the original result must come back and the
    # drift must survive untouched (no second replacement).
    _allocate(client, pid, "b", 28)
    second = _restore(client, pid, body)
    assert second.status_code == 200, second.text
    assert second.json() == {
        "restore_id": "idem-restore",
        "pool_id": pid,
        "digest": snap["digest"],
        "replayed": True,
        "replaced": False,
    }
    request_ids = [a["request_id"] for a in client.get(f"/pools/{pid}").json()["allocated"]]
    assert request_ids == ["a", "b"]


def test_concurrent_restores_same_restore_id_apply_once(client):
    pid = _create_pool(client)
    snap = _get_snapshot(client, pid).json()
    body = {"restore_id": "once", "digest": snap["digest"],
            "snapshot": snap["snapshot"]}
    outcomes: list[dict] = []
    barrier = threading.Barrier(8)
    lock = threading.Lock()

    from app.main import app

    def worker():
        local = TestClient(app)
        barrier.wait()
        resp = local.post(f"/pools/{pid}/snapshot/restore", json=body)
        with lock:
            outcomes.append(resp.json())

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    replaced = [o for o in outcomes if o.get("replaced") is True]
    replayed = [o for o in outcomes if o.get("replayed") is True]
    assert len(replaced) == 1
    assert len(replayed) == 7
    assert all(o["digest"] == snap["digest"] for o in outcomes)


# ---------------------------------------------------------------------------
# Restore: validation failures (must be atomic, never mutate existing data)
# ---------------------------------------------------------------------------


def test_restore_bad_digest_format(client):
    pid = _create_pool(client)
    snap = _get_snapshot(client, pid).json()
    body = {"restore_id": "x", "digest": "not-hex", "snapshot": snap["snapshot"]}
    resp = _restore(client, pid, body)
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "snapshot_bad_digest"


def test_restore_digest_mismatch_on_tampered_snapshot(client):
    pid = _create_pool(client)
    _allocate(client, pid, "a", 28)
    before = client.get(f"/pools/{pid}").json()
    snap = _get_snapshot(client, pid).json()

    doc = snap["snapshot"]
    doc["allocations"][0]["request_id"] = "tampered"  # still structurally valid
    body = {"restore_id": "t", "digest": snap["digest"], "snapshot": doc}
    resp = _restore(client, pid, body)
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "snapshot_digest_mismatch"

    after = client.get(f"/pools/{pid}").json()
    assert after == before


def test_restore_wrong_digest_value(client):
    pid = _create_pool(client)
    snap = _get_snapshot(client, pid).json()
    fake = hashlib.sha256(b"something else").hexdigest()
    body = {"restore_id": "t", "digest": fake, "snapshot": snap["snapshot"]}
    resp = _restore(client, pid, body)
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "snapshot_digest_mismatch"


def test_restore_pool_id_mismatch(client):
    pid = _create_pool(client)
    snap = _get_snapshot(client, pid).json()
    doc = snap["snapshot"]
    doc["pool"]["id"] = pid + 100
    digest = hashlib.sha256(_canonical(doc)).hexdigest()
    resp = _restore(
        client, pid, {"restore_id": "t", "digest": digest, "snapshot": doc}
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "snapshot_pool_mismatch"


def test_restore_allocation_outside_pool(client):
    pid = _create_pool(client)
    snap = _get_snapshot(client, pid).json()
    doc = snap["snapshot"]
    doc["allocations"] = [
        {"id": 10, "pool_id": pid, "cidr": "10.1.0.0/24", "request_id": "x",
         "prefix_length": 24, "created_at": "2026-01-01T00:00:00+00:00"}
    ]
    digest = hashlib.sha256(_canonical(doc)).hexdigest()
    resp = _restore(
        client, pid, {"restore_id": "t", "digest": digest, "snapshot": doc}
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "snapshot_allocation_outside_pool"


def test_restore_exclusion_outside_pool(client):
    pid = _create_pool(client)
    snap = _get_snapshot(client, pid).json()
    doc = snap["snapshot"]
    doc["exclusions"] = [
        {"id": 10, "pool_id": pid, "cidr": "10.1.0.0/24",
         "created_at": "2026-01-01T00:00:00+00:00"}
    ]
    digest = hashlib.sha256(_canonical(doc)).hexdigest()
    resp = _restore(
        client, pid, {"restore_id": "t", "digest": digest, "snapshot": doc}
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "exclusion_outside_pool"


def test_restore_rejects_overlapping_allocations(client):
    pid = _create_pool(client)
    snap = _get_snapshot(client, pid).json()
    doc = snap["snapshot"]
    doc["allocations"] = [
        {"id": 10, "pool_id": pid, "cidr": "10.0.0.0/24", "request_id": "x",
         "prefix_length": 24, "created_at": "2026-01-01T00:00:00+00:00"},
        {"id": 11, "pool_id": pid, "cidr": "10.0.0.0/25", "request_id": "y",
         "prefix_length": 25, "created_at": "2026-01-01T00:00:00+00:00"},
    ]
    digest = hashlib.sha256(_canonical(doc)).hexdigest()
    resp = _restore(
        client, pid, {"restore_id": "t", "digest": digest, "snapshot": doc}
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "snapshot_allocation_overlap"


def test_restore_rejects_allocation_overlapping_exclusion(client):
    pid = _create_pool(client)
    snap = _get_snapshot(client, pid).json()
    doc = snap["snapshot"]
    doc["exclusions"] = [
        {"id": 10, "pool_id": pid, "cidr": "10.0.0.0/25",
         "created_at": "2026-01-01T00:00:00+00:00"}
    ]
    doc["allocations"] = [
        {"id": 10, "pool_id": pid, "cidr": "10.0.0.0/26", "request_id": "x",
         "prefix_length": 26, "created_at": "2026-01-01T00:00:00+00:00"}
    ]
    digest = hashlib.sha256(_canonical(doc)).hexdigest()
    resp = _restore(
        client, pid, {"restore_id": "t", "digest": digest, "snapshot": doc}
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "snapshot_allocation_overlap"


def test_restore_rejects_overlapping_exclusions(client):
    pid = _create_pool(client)
    snap = _get_snapshot(client, pid).json()
    doc = snap["snapshot"]
    doc["exclusions"] = [
        {"id": 10, "pool_id": pid, "cidr": "10.0.0.0/24",
         "created_at": "2026-01-01T00:00:00+00:00"},
        {"id": 11, "pool_id": pid, "cidr": "10.0.0.0/25",
         "created_at": "2026-01-01T00:00:00+00:00"},
    ]
    digest = hashlib.sha256(_canonical(doc)).hexdigest()
    resp = _restore(
        client, pid, {"restore_id": "t", "digest": digest, "snapshot": doc}
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "exclusion_overlap"


def test_restore_rejects_duplicate_request_id_in_snapshot(client):
    pid = _create_pool(client)
    snap = _get_snapshot(client, pid).json()
    doc = snap["snapshot"]
    doc["allocations"] = [
        {"id": 10, "pool_id": pid, "cidr": "10.0.0.0/25", "request_id": "dup",
         "prefix_length": 25, "created_at": "2026-01-01T00:00:00+00:00"},
        {"id": 11, "pool_id": pid, "cidr": "10.0.0.128/25", "request_id": "dup",
         "prefix_length": 25, "created_at": "2026-01-02T00:00:00+00:00"},
    ]
    digest = hashlib.sha256(_canonical(doc)).hexdigest()
    resp = _restore(
        client, pid, {"restore_id": "t", "digest": digest, "snapshot": doc}
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "snapshot_duplicate_request_id"


def test_restore_rejects_prefix_length_mismatch(client):
    pid = _create_pool(client)
    snap = _get_snapshot(client, pid).json()
    doc = snap["snapshot"]
    doc["allocations"] = [
        {"id": 10, "pool_id": pid, "cidr": "10.0.0.0/25", "request_id": "x",
         "prefix_length": 26, "created_at": "2026-01-01T00:00:00+00:00"}
    ]
    digest = hashlib.sha256(_canonical(doc)).hexdigest()
    resp = _restore(
        client, pid, {"restore_id": "t", "digest": digest, "snapshot": doc}
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "snapshot_prefix_mismatch"


def test_restore_rejects_invalid_cidr(client):
    pid = _create_pool(client)
    snap = _get_snapshot(client, pid).json()
    doc = snap["snapshot"]
    doc["allocations"] = [
        {"id": 10, "pool_id": pid, "cidr": "10.0.0.5/24", "request_id": "x",
         "prefix_length": 24, "created_at": "2026-01-01T00:00:00+00:00"}
    ]
    digest = hashlib.sha256(_canonical(doc)).hexdigest()
    resp = _restore(
        client, pid, {"restore_id": "t", "digest": digest, "snapshot": doc}
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "invalid_cidr"


def test_restore_cross_pool_request_id_conflict(client):
    pid1 = _create_pool(client, cidr="10.0.0.0/24")
    pid2 = _create_pool(client, cidr="10.1.0.0/24")
    _allocate(client, pid1, "shared", 24)

    # Snapshot of pool 2 that tries to claim the globally-used request_id.
    snap2 = _get_snapshot(client, pid2).json()
    doc = snap2["snapshot"]
    doc["allocations"] = [
        {"id": 10, "pool_id": pid2, "cidr": "10.1.0.0/24", "request_id": "shared",
         "prefix_length": 24, "created_at": "2026-01-01T00:00:00+00:00"}
    ]
    digest = hashlib.sha256(_canonical(doc)).hexdigest()
    resp = _restore(
        client, pid2, {"restore_id": "t", "digest": digest, "snapshot": doc}
    )
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "request_id_conflict"

    # Neither pool changed.
    status2 = client.get(f"/pools/{pid2}").json()
    assert status2["allocated"] == []
    status1 = client.get(f"/pools/{pid1}").json()
    assert [a["request_id"] for a in status1["allocated"]] == ["shared"]


def test_restore_replay_with_different_digest_conflicts(client):
    pid = _create_pool(client)
    _allocate(client, pid, "a", 28)
    snap = _get_snapshot(client, pid).json()
    body = {"restore_id": "r", "digest": snap["digest"], "snapshot": snap["snapshot"]}
    assert _restore(client, pid, body).status_code == 200

    # A genuinely different (but otherwise valid) snapshot under the same
    # restore_id: the idempotency key wins -> 409, state is not replaced.
    doc = json.loads(_canonical(snap["snapshot"]))
    doc["allocations"] = []
    other_digest = hashlib.sha256(_canonical(doc)).hexdigest()
    resp = _restore(
        client,
        pid,
        {"restore_id": "r", "digest": other_digest, "snapshot": doc},
    )
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "restore_id_conflict"

    status = client.get(f"/pools/{pid}").json()
    assert [a["request_id"] for a in status["allocated"]] == ["a"]


def test_restore_replay_with_different_pool_conflicts(client):
    pid1 = _create_pool(client, cidr="10.0.0.0/24")
    pid2 = _create_pool(client, cidr="10.1.0.0/24")
    snap1 = _get_snapshot(client, pid1).json()
    assert _restore(
        client,
        pid1,
        {"restore_id": "r", "digest": snap1["digest"], "snapshot": snap1["snapshot"]},
    ).status_code == 200

    snap2 = _get_snapshot(client, pid2).json()
    resp = _restore(
        client,
        pid2,
        {"restore_id": "r", "digest": snap2["digest"], "snapshot": snap2["snapshot"]},
    )
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "restore_id_conflict"


def test_restore_pool_not_found(client):
    pid = 999
    doc = {
        "version": 1,
        "digest_algorithm": "SHA-256",
        "pool": {"id": pid, "cidr": "10.0.0.0/24",
                 "created_at": "2026-01-01T00:00:00+00:00"},
        "exclusions": [],
        "allocations": [],
    }
    digest = hashlib.sha256(_canonical(doc)).hexdigest()
    resp = _restore(
        client, pid, {"restore_id": "t", "digest": digest, "snapshot": doc}
    )
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "pool_not_found"


def test_failed_restore_does_not_touch_existing_rows(client):
    import copy

    pid = _create_pool(client, exclusions=["10.0.0.128/25"])
    _allocate(client, pid, "keep", 26)
    before = client.get(f"/pools/{pid}").json()
    snap = _get_snapshot(client, pid).json()

    # An invalid snapshot (overlap) must not delete/replace existing rows.
    doc = copy.deepcopy(snap["snapshot"])
    doc["allocations"] = [
        {"id": 10, "pool_id": pid, "cidr": "10.0.0.0/25", "request_id": "x",
         "prefix_length": 25, "created_at": "2026-01-01T00:00:00+00:00"},
        {"id": 11, "pool_id": pid, "cidr": "10.0.0.0/26", "request_id": "y",
         "prefix_length": 26, "created_at": "2026-01-01T00:00:00+00:00"},
    ]
    digest = hashlib.sha256(_canonical(doc)).hexdigest()
    resp = _restore(
        client, pid, {"restore_id": "t", "digest": digest, "snapshot": doc}
    )
    assert resp.status_code == 422

    after = client.get(f"/pools/{pid}").json()
    assert after == before
    # And the failed restore_id must not have been recorded: a valid
    # restore with the same restore_id succeeds.
    ok = _restore(
        client,
        pid,
        {"restore_id": "t", "digest": snap["digest"], "snapshot": snap["snapshot"]},
    )
    assert ok.status_code == 200, ok.text
    assert ok.json()["replayed"] is False


# ---------------------------------------------------------------------------
# Exported identities: id / pool_id round-trip and record ownership
# ---------------------------------------------------------------------------


def _table_rows(table: str) -> list[dict]:
    from app.db import read_transaction

    assert table in {"exclusions", "allocations"}
    columns = (
        "id, pool_id, cidr, request_id"
        if table == "allocations"
        else "id, pool_id, cidr"
    )
    with read_transaction() as conn:
        return [
            dict(r)
            for r in conn.execute(
                f"SELECT {columns} FROM {table} ORDER BY id"
            ).fetchall()
        ]


def test_snapshot_export_digest_recomputable_with_exclusion_and_allocation(client):
    # The migration acceptance scenario: a pool with at least one exclusion
    # and one allocation exports a digest that can be recomputed from the
    # canonical document bytes.
    pid = _create_pool(client, exclusions=["10.0.0.128/25"])
    _allocate(client, pid, "mig-a", 26)  # 10.0.0.0/26
    _allocate(client, pid, "mig-b", 27)  # 10.0.0.64/27

    body = _get_snapshot(client, pid).json()
    canonical = _canonical(body["snapshot"])
    assert hashlib.sha256(canonical).hexdigest() == body["digest"]
    assert body["snapshot"]["digest_algorithm"] == "SHA-256"
    assert {e["cidr"] for e in body["snapshot"]["exclusions"]} == {
        "10.0.0.128/25"
    }
    assert {a["cidr"] for a in body["snapshot"]["allocations"]} == {
        "10.0.0.0/26",
        "10.0.0.64/27",
    }
    assert all(e["pool_id"] == pid for e in body["snapshot"]["exclusions"])
    assert all(a["pool_id"] == pid for a in body["snapshot"]["allocations"])


def test_restore_writes_back_exported_ids_and_pool_foreign_keys(client):
    pid = _create_pool(client, exclusions=["10.0.0.128/25"])
    _allocate(client, pid, "keep-1", 26)  # 10.0.0.0/26
    _allocate(client, pid, "keep-2", 27)  # 10.0.0.64/27

    snap = _get_snapshot(client, pid).json()
    expected_exclusions = {
        (e["id"], e["pool_id"], e["cidr"]) for e in snap["snapshot"]["exclusions"]
    }
    expected_allocations = {
        (a["id"], a["pool_id"], a["cidr"], a["request_id"])
        for a in snap["snapshot"]["allocations"]
    }
    assert expected_exclusions
    assert len(expected_allocations) == 2

    # Drift the state so deletes + autoincrement-assigned ids would
    # normally renumber the surviving rows.
    _allocate(client, pid, "drift", 28)  # 10.0.0.96/28
    client.post(f"/pools/{pid}/exclusions", json={"cidr": "10.0.0.112/28"})

    resp = _restore(
        client,
        pid,
        {"restore_id": "fk-mig", "digest": snap["digest"],
         "snapshot": snap["snapshot"]},
    )
    assert resp.status_code == 200, resp.text

    # The restored rows keep exactly the exported (id, pool_id) values,
    # i.e. the same foreign-key relationship to the pool.
    exclusions = _table_rows("exclusions")
    assert {(r["id"], r["pool_id"], r["cidr"]) for r in exclusions} == expected_exclusions
    allocations = _table_rows("allocations")
    assert {
        (r["id"], r["pool_id"], r["cidr"]) for r in allocations
    } == {(i, p, c) for i, p, c, _ in expected_allocations}
    assert {(r["id"], r["request_id"]) for r in allocations} == {
        (i, rid) for i, _, _, rid in expected_allocations
    }
    assert all(r["pool_id"] == pid for r in exclusions + allocations)

    # Re-exporting the restored state reproduces the document and digest.
    again = _get_snapshot(client, pid).json()
    assert again["snapshot"] == snap["snapshot"]
    assert again["digest"] == snap["digest"]


def test_restore_rejects_exclusion_belonging_to_another_pool(client):
    pid1 = _create_pool(client, cidr="10.0.0.0/24", exclusions=["10.0.0.128/25"])
    pid2 = _create_pool(client, cidr="10.1.0.0/24")
    snap = _get_snapshot(client, pid1).json()
    doc = snap["snapshot"]
    doc["exclusions"][0]["pool_id"] = pid2
    digest = hashlib.sha256(_canonical(doc)).hexdigest()

    resp = _restore(
        client, pid1, {"restore_id": "t", "digest": digest, "snapshot": doc}
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "snapshot_record_pool_mismatch"
    assert _table_rows("exclusions")[0]["pool_id"] == pid1


def test_restore_rejects_allocation_belonging_to_another_pool(client):
    pid1 = _create_pool(client, cidr="10.0.0.0/24")
    pid2 = _create_pool(client, cidr="10.1.0.0/24")
    _allocate(client, pid1, "a", 28)
    snap = _get_snapshot(client, pid1).json()
    doc = snap["snapshot"]
    doc["allocations"][0]["pool_id"] = pid2
    digest = hashlib.sha256(_canonical(doc)).hexdigest()

    resp = _restore(
        client, pid1, {"restore_id": "t", "digest": digest, "snapshot": doc}
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "snapshot_record_pool_mismatch"
    assert _table_rows("allocations")[0]["pool_id"] == pid1


def test_restore_rejects_duplicate_exported_exclusion_id(client):
    pid = _create_pool(client)
    snap = _get_snapshot(client, pid).json()
    doc = snap["snapshot"]
    doc["exclusions"] = [
        {"id": 5, "pool_id": pid, "cidr": "10.0.0.0/26",
         "created_at": "2026-01-01T00:00:00+00:00"},
        {"id": 5, "pool_id": pid, "cidr": "10.0.0.64/26",
         "created_at": "2026-01-02T00:00:00+00:00"},
    ]
    digest = hashlib.sha256(_canonical(doc)).hexdigest()
    resp = _restore(
        client, pid, {"restore_id": "t", "digest": digest, "snapshot": doc}
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "snapshot_duplicate_record_id"
    assert _table_rows("exclusions") == []


def test_restore_rejects_duplicate_exported_allocation_id(client):
    pid = _create_pool(client)
    snap = _get_snapshot(client, pid).json()
    doc = snap["snapshot"]
    doc["allocations"] = [
        {"id": 7, "pool_id": pid, "cidr": "10.0.0.0/26", "request_id": "x",
         "prefix_length": 26, "created_at": "2026-01-01T00:00:00+00:00"},
        {"id": 7, "pool_id": pid, "cidr": "10.0.0.64/26", "request_id": "y",
         "prefix_length": 26, "created_at": "2026-01-02T00:00:00+00:00"},
    ]
    digest = hashlib.sha256(_canonical(doc)).hexdigest()
    resp = _restore(
        client, pid, {"restore_id": "t", "digest": digest, "snapshot": doc}
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "snapshot_duplicate_record_id"
    assert _table_rows("allocations") == []


def test_restore_rejects_non_sha256_digest_algorithm(client):
    pid = _create_pool(client)
    snap = _get_snapshot(client, pid).json()
    doc = snap["snapshot"]
    doc["digest_algorithm"] = "SHA-512"
    digest = hashlib.sha256(_canonical(doc)).hexdigest()

    resp = _restore(
        client, pid, {"restore_id": "t", "digest": digest, "snapshot": doc}
    )
    assert resp.status_code == 422
    assert "digest_algorithm" in str(resp.json()["detail"])


def test_exported_identity_survives_record_reordering_on_restore(client):
    # Two records out of address order in the request body: after the
    # server sorts them for the canonical digest, each must still be
    # written back under the id it was exported with.
    pid = _create_pool(client)
    _allocate(client, pid, "low", 27)   # 10.0.0.0/27
    _allocate(client, pid, "high", 27)  # 10.0.0.32/27
    snap = _get_snapshot(client, pid).json()
    doc = snap["snapshot"]

    identities = {a["request_id"]: a["id"] for a in doc["allocations"]}
    doc["allocations"] = sorted(
        doc["allocations"], key=lambda a: a["id"], reverse=True
    )
    # Reordering alone keeps the same digest; normalisation re-sorts.
    resp = _restore(
        client,
        pid,
        {"restore_id": "reorder", "digest": snap["digest"], "snapshot": doc},
    )
    assert resp.status_code == 200, resp.text

    rows = {r["request_id"]: r["id"] for r in _table_rows("allocations")}
    assert rows == identities
