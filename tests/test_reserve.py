"""API integration tests for policy-gated batch reservations."""

from __future__ import annotations

import ipaddress
import threading

from fastapi.testclient import TestClient


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


def _reserve(client, pool_id, batch_id="batch-1", default_action="allow",
             rules=None, items=None):
    body = {
        "batch_id": batch_id,
        "default_action": default_action,
        "rules": rules if rules is not None else [],
        "items": items if items is not None else [
            {"request_id": "r1", "prefix_length": 26},
        ],
    }
    return client.post(f"/pools/{pool_id}/reservations", json=body)


def test_batch_reserves_in_input_order(client):
    pid = _create_pool(client)
    resp = _reserve(
        client,
        pid,
        items=[
            {"request_id": "r2", "prefix_length": 27},
            {"request_id": "r1", "prefix_length": 26},
            {"request_id": "r3", "prefix_length": 27},
        ],
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["batch_id"] == "batch-1"
    assert body["pool_id"] == pid
    assert body["replayed"] is False
    # Mapping follows input order, each item taking the lowest aligned free
    # segment left by the previous ones.
    assert [(r["request_id"], r["cidr"]) for r in body["reservations"]] == [
        ("r2", "10.0.0.0/27"),
        ("r1", "10.0.0.64/26"),
        ("r3", "10.0.0.32/27"),
    ]
    assert all(r["replayed"] is False for r in body["reservations"])

    # Reservations are ordinary allocations, visible in pool status.
    status = client.get(f"/pools/{pid}").json()
    assert sorted(a["cidr"] for a in status["allocated"]) == [
        "10.0.0.0/27",
        "10.0.0.32/27",
        "10.0.0.64/26",
    ]


def test_batch_skips_exclusions_and_existing_allocations(client):
    pid = _create_pool(client, cidr="10.0.0.0/24", exclusions=["10.0.0.0/26"])
    _allocate(client, pid, "pre", 26)  # 10.0.0.64/26
    resp = _reserve(client, pid, items=[{"request_id": "r1", "prefix_length": 26}])
    assert resp.status_code == 201, resp.text
    assert resp.json()["reservations"][0]["cidr"] == "10.0.0.128/26"


def test_batch_replay_returns_original_result(client):
    pid = _create_pool(client)
    items = [
        {"request_id": "r1", "prefix_length": 26},
        {"request_id": "r2", "prefix_length": 26},
    ]
    first = _reserve(client, pid, items=items)
    assert first.status_code == 201

    second = _reserve(client, pid, items=items)
    assert second.status_code == 200
    assert second.json()["replayed"] is True
    assert second.json()["reservations"] == first.json()["reservations"]
    assert second.json()["created_at"] == first.json()["created_at"]

    # Nothing was reserved twice.
    status = client.get(f"/pools/{pid}").json()
    assert len(status["allocated"]) == 2


def test_batch_id_with_changed_params_conflicts(client):
    pid = _create_pool(client)
    _reserve(client, pid, items=[{"request_id": "r1", "prefix_length": 26}])

    # Different items.
    resp = _reserve(client, pid, items=[{"request_id": "r1", "prefix_length": 27}])
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "batch_id_conflict"

    # Different rules.
    resp = _reserve(
        client,
        pid,
        rules=[{"cidr": "10.0.0.0/25", "action": "allow"}],
        items=[{"request_id": "r1", "prefix_length": 26}],
    )
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "batch_id_conflict"

    # Same batch_id against another pool.
    pid2 = _create_pool(client, cidr="10.1.0.0/24")
    resp = _reserve(client, pid2, items=[{"request_id": "r1", "prefix_length": 26}])
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "batch_id_conflict"


def test_batch_item_order_is_significant(client):
    pid = _create_pool(client)
    items = [
        {"request_id": "r1", "prefix_length": 26},
        {"request_id": "r2", "prefix_length": 27},
    ]
    first = _reserve(client, pid, items=items)
    assert first.status_code == 201

    # Same items in a different order are different parameters.
    resp = _reserve(client, pid, items=list(reversed(items)))
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "batch_id_conflict"


def test_deny_segment_rolls_back_whole_batch(client):
    pid = _create_pool(client)
    rules = [
        {"cidr": "10.0.0.0/26", "action": "allow"},
        {"cidr": "10.0.0.64/26", "action": "deny"},
    ]
    items = [
        {"request_id": "ok", "prefix_length": 27},    # lands in the allow /26
        {"request_id": "denied", "prefix_length": 26},  # lowest free is the deny /26
    ]
    resp = _reserve(client, pid, default_action="deny", rules=rules, items=items)
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "reservation_denied"

    # The whole batch rolled back: no allocation, and the batch_id is free
    # to be reused after fixing the request.
    status = client.get(f"/pools/{pid}").json()
    assert status["allocated"] == []
    assert status["free_cidrs"] == ["10.0.0.0/24"]

    rules = [
        {"cidr": "10.0.0.0/26", "action": "allow"},
        {"cidr": "10.0.0.64/26", "action": "allow"},
    ]
    retry = _reserve(client, pid, default_action="deny", rules=rules, items=items)
    assert retry.status_code == 201, retry.text


def test_default_deny_without_allow_rule_rejects(client):
    pid = _create_pool(client)
    resp = _reserve(client, pid, default_action="deny")
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "reservation_denied"
    assert client.get(f"/pools/{pid}").json()["allocated"] == []


def test_exhaustion_rolls_back_earlier_items(client):
    pid = _create_pool(client, cidr="10.0.0.0/29")
    items = [{"request_id": f"r{i}", "prefix_length": 30} for i in range(3)]
    resp = _reserve(client, pid, items=items)
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "pool_exhausted"

    # The two items that would have fitted were rolled back too.
    status = client.get(f"/pools/{pid}").json()
    assert status["allocated"] == []
    assert status["free_cidrs"] == ["10.0.0.0/29"]


def test_existing_request_id_is_replayed_into_batch(client):
    pid = _create_pool(client)
    existing = _allocate(client, pid, "r1", 26)  # 10.0.0.0/26

    resp = _reserve(
        client,
        pid,
        items=[
            {"request_id": "r1", "prefix_length": 26},
            {"request_id": "r2", "prefix_length": 26},
        ],
    )
    assert resp.status_code == 201, resp.text
    reservations = resp.json()["reservations"]
    # The existing allocation is replayed under the original idempotency
    # semantics; the new item takes the next lowest segment.
    assert reservations[0]["cidr"] == existing
    assert reservations[0]["replayed"] is True
    assert reservations[1]["cidr"] == "10.0.0.64/26"
    assert reservations[1]["replayed"] is False

    status = client.get(f"/pools/{pid}").json()
    assert len(status["allocated"]) == 2


def test_existing_request_id_with_changed_prefix_conflicts(client):
    pid = _create_pool(client)
    _allocate(client, pid, "r1", 26)

    resp = _reserve(
        client,
        pid,
        items=[
            {"request_id": "r0", "prefix_length": 27},
            {"request_id": "r1", "prefix_length": 27},
        ],
    )
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "request_id_conflict"

    # The batch rolled back: only the pre-existing allocation remains.
    status = client.get(f"/pools/{pid}").json()
    assert [a["request_id"] for a in status["allocated"]] == ["r1"]


def test_request_id_used_in_another_pool_conflicts(client):
    pid1 = _create_pool(client, cidr="10.0.0.0/24")
    pid2 = _create_pool(client, cidr="10.1.0.0/24")
    _allocate(client, pid1, "shared", 26)

    resp = _reserve(client, pid2, items=[{"request_id": "shared", "prefix_length": 26}])
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "request_id_conflict"


def test_duplicate_request_id_within_batch_follows_idempotency(client):
    pid = _create_pool(client)
    items = [
        {"request_id": "r1", "prefix_length": 26},
        {"request_id": "r1", "prefix_length": 26},
    ]
    resp = _reserve(client, pid, items=items)
    assert resp.status_code == 201, resp.text
    reservations = resp.json()["reservations"]
    # The second occurrence replays the allocation made by the first.
    assert [r["cidr"] for r in reservations] == ["10.0.0.0/26", "10.0.0.0/26"]
    assert [r["replayed"] for r in reservations] == [False, True]
    assert len(client.get(f"/pools/{pid}").json()["allocated"]) == 1

    # Same id with a different prefix inside one batch conflicts and rolls back.
    resp = _reserve(
        client,
        pid,
        batch_id="batch-2",
        items=[
            {"request_id": "r2", "prefix_length": 26},
            {"request_id": "r2", "prefix_length": 27},
        ],
    )
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "request_id_conflict"
    assert len(client.get(f"/pools/{pid}").json()["allocated"]) == 1


def test_rule_outside_pool_rejected(client):
    pid = _create_pool(client)
    resp = _reserve(
        client,
        pid,
        rules=[{"cidr": "10.1.0.0/24", "action": "allow"}],
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "rule_outside_scope"


def test_invalid_rule_cidr_rejected(client):
    pid = _create_pool(client)
    resp = _reserve(
        client,
        pid,
        rules=[{"cidr": "10.0.0.5/24", "action": "allow"}],
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "invalid_cidr"


def test_first_match_rule_priority(client):
    pid = _create_pool(client)
    # Narrow allow first, broader deny second: only 10.0.0.0/26 is usable.
    rules = [
        {"cidr": "10.0.0.0/26", "action": "allow"},
        {"cidr": "10.0.0.0/24", "action": "deny"},
    ]
    resp = _reserve(
        client,
        pid,
        default_action="deny",
        rules=rules,
        items=[{"request_id": "r1", "prefix_length": 26}],
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["reservations"][0]["cidr"] == "10.0.0.0/26"

    # The next /26 falls in the denied remainder of the pool.
    resp = _reserve(
        client,
        pid,
        batch_id="batch-2",
        default_action="deny",
        rules=rules,
        items=[{"request_id": "r2", "prefix_length": 26}],
    )
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "reservation_denied"


def test_batch_pool_not_found(client):
    resp = _reserve(client, 999)
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "pool_not_found"


def test_batch_never_overlaps_and_stays_aligned(client):
    pid = _create_pool(client, cidr="10.0.0.0/24", exclusions=["10.0.0.64/26"])
    items = [{"request_id": f"r{i}", "prefix_length": 27} for i in range(6)]
    resp = _reserve(client, pid, items=items)
    assert resp.status_code == 201, resp.text

    cidrs = [r["cidr"] for r in resp.json()["reservations"]]
    nets = [ipaddress.ip_network(c) for c in cidrs]
    assert len(set(cidrs)) == 6
    for i, a in enumerate(nets):
        for b in nets[i + 1:]:
            assert not a.overlaps(b)
        assert not a.overlaps(ipaddress.ip_network("10.0.0.64/26"))
    # Every reservation is the lowest aligned segment available at its turn.
    assert cidrs[0] == "10.0.0.0/27"


def test_concurrent_batches_are_serialised_and_distinct(client):
    pid = _create_pool(client)
    results: list[str] = []
    errors: list[int] = []
    barrier = threading.Barrier(16)

    from app.main import app

    def worker(i: int):
        local = TestClient(app)
        barrier.wait()  # maximise contention
        resp = local.post(
            f"/pools/{pid}/reservations",
            json={
                "batch_id": f"batch-{i}",
                "default_action": "allow",
                "rules": [],
                "items": [{"request_id": f"r-{i}", "prefix_length": 27}],
            },
        )
        if resp.status_code == 201:
            results.append(resp.json()["reservations"][0]["cidr"])
        else:
            errors.append(resp.status_code)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # /24 holds exactly eight /27s; the losing batches rolled back cleanly.
    assert len(results) == 8
    assert set(errors) == {409}
    assert len(set(results)) == 8
    nets = [ipaddress.ip_network(c) for c in results]
    for i, a in enumerate(nets):
        for b in nets[i + 1:]:
            assert not a.overlaps(b)


def test_concurrent_same_batch_id_reserves_once(client):
    pid = _create_pool(client)
    statuses: list[int] = []
    cidrs: list[str] = []
    barrier = threading.Barrier(10)
    lock = threading.Lock()

    from app.main import app

    body = {
        "batch_id": "same",
        "default_action": "allow",
        "rules": [],
        "items": [{"request_id": "r1", "prefix_length": 26}],
    }

    def worker():
        local = TestClient(app)
        barrier.wait()
        resp = local.post(f"/pools/{pid}/reservations", json=body)
        with lock:
            statuses.append(resp.status_code)
            cidrs.append(resp.json()["reservations"][0]["cidr"])

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Exactly one batch was recorded; every concurrent retry replayed it.
    assert sorted(statuses) == [200] * 9 + [201]
    assert set(cidrs) == {"10.0.0.0/26"}
    assert len(client.get(f"/pools/{pid}").json()["allocated"]) == 1
