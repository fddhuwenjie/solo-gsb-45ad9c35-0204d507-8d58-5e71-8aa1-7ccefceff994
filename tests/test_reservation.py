"""Policy-driven batch reservation tests: placement, rollback, idempotency."""

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
    return resp.json()


def _reserve(client, pool_id, batch_id, items, default_action="allow", rules=None):
    return client.post(
        f"/pools/{pool_id}/reservations",
        json={
            "batch_id": batch_id,
            "default_action": default_action,
            "rules": rules or [],
            "items": items,
        },
    )


def _allocated_cidrs(client, pool_id):
    return [a["cidr"] for a in client.get(f"/pools/{pool_id}").json()["allocated"]]


def test_batch_reserves_lowest_aligned_in_input_order(client):
    pid = _create_pool(client)
    resp = _reserve(
        client,
        pid,
        "b1",
        [
            {"request_id": "r1", "prefix_length": 26},
            {"request_id": "r2", "prefix_length": 25},
            {"request_id": "r3", "prefix_length": 26},
        ],
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["batch_id"] == "b1"
    assert body["pool_id"] == pid
    assert body["replayed"] is False
    # Mapping comes back in input order; each pick is the lowest aligned
    # free CIDR given the items placed before it.
    assert [r["request_id"] for r in body["reservations"]] == ["r1", "r2", "r3"]
    assert [r["cidr"] for r in body["reservations"]] == [
        "10.0.0.0/26",
        "10.0.0.128/25",
        "10.0.0.64/26",
    ]
    assert all(r["replayed"] is False for r in body["reservations"])

    # Reservations are ordinary allocations afterwards.
    assert _allocated_cidrs(client, pid) == [
        "10.0.0.0/26",
        "10.0.0.64/26",
        "10.0.0.128/25",
    ]


def test_batch_input_order_changes_placement(client):
    pid = _create_pool(client)
    resp = _reserve(
        client,
        pid,
        "b1",
        [
            {"request_id": "big", "prefix_length": 25},
            {"request_id": "small", "prefix_length": 26},
        ],
    )
    assert resp.status_code == 201, resp.text
    assert {r["request_id"]: r["cidr"] for r in resp.json()["reservations"]} == {
        "big": "10.0.0.0/25",
        "small": "10.0.0.128/26",
    }


def test_batch_skips_deny_segments(client):
    pid = _create_pool(client)
    resp = _reserve(
        client,
        pid,
        "b1",
        [{"request_id": "r1", "prefix_length": 26}],
        default_action="allow",
        rules=[{"cidr": "10.0.0.0/26", "action": "deny"}],
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["reservations"][0]["cidr"] == "10.0.0.64/26"


def test_batch_default_deny_with_allow_rule(client):
    pid = _create_pool(client)
    resp = _reserve(
        client,
        pid,
        "b1",
        [{"request_id": "r1", "prefix_length": 25}],
        default_action="deny",
        rules=[{"cidr": "10.0.0.128/25", "action": "allow"}],
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["reservations"][0]["cidr"] == "10.0.0.128/25"


def test_batch_respects_exclusions_and_existing_allocations(client):
    pid = _create_pool(client, exclusions=["10.0.0.0/26"])
    _allocate(client, pid, "pre", 26)  # 10.0.0.64/26
    resp = _reserve(client, pid, "b1", [{"request_id": "r1", "prefix_length": 26}])
    assert resp.status_code == 201, resp.text
    assert resp.json()["reservations"][0]["cidr"] == "10.0.0.128/26"


def test_batch_policy_denied_rolls_back_everything(client):
    pid = _create_pool(client)
    # Only the lower /25 is allowed; the second item cannot be placed.
    resp = _reserve(
        client,
        pid,
        "b1",
        [
            {"request_id": "r1", "prefix_length": 25},
            {"request_id": "r2", "prefix_length": 25},
        ],
        default_action="deny",
        rules=[{"cidr": "10.0.0.0/25", "action": "allow"}],
    )
    assert resp.status_code == 409, resp.text
    assert resp.json()["error"]["code"] == "policy_denied"

    # The whole batch rolled back: no allocations, no batch record, so the
    # same batch_id with fixed parameters starts fresh instead of
    # conflicting or replaying.
    assert _allocated_cidrs(client, pid) == []
    ok = _reserve(
        client,
        pid,
        "b1",
        [{"request_id": "r1", "prefix_length": 25}],
        default_action="deny",
        rules=[{"cidr": "10.0.0.0/25", "action": "allow"}],
    )
    assert ok.status_code == 201, ok.text
    assert ok.json()["reservations"][0]["cidr"] == "10.0.0.0/25"


def test_batch_exhaustion_rolls_back_everything(client):
    pid = _create_pool(client, cidr="10.0.0.0/30")
    resp = _reserve(
        client,
        pid,
        "b1",
        [
            {"request_id": "r1", "prefix_length": 30},
            {"request_id": "r2", "prefix_length": 30},
        ],
    )
    assert resp.status_code == 409, resp.text
    assert resp.json()["error"]["code"] == "pool_exhausted"
    assert _allocated_cidrs(client, pid) == []


def test_batch_replay_returns_stored_result(client):
    pid = _create_pool(client)
    payload = [
        {"request_id": "r1", "prefix_length": 28},
        {"request_id": "r2", "prefix_length": 28},
    ]
    first = _reserve(client, pid, "b1", payload)
    assert first.status_code == 201, first.text

    second = _reserve(client, pid, "b1", payload)
    assert second.status_code == 200, second.text
    assert second.json()["replayed"] is True
    # The stored mapping is returned verbatim, ids and timestamps included.
    assert second.json()["reservations"] == first.json()["reservations"]
    assert second.json()["created_at"] == first.json()["created_at"]

    # Replaying did not reserve anything twice.
    assert _allocated_cidrs(client, pid) == ["10.0.0.0/28", "10.0.0.16/28"]


def test_batch_replay_survives_pool_changes(client):
    pid = _create_pool(client)
    first = _reserve(client, pid, "b1", [{"request_id": "r1", "prefix_length": 28}])
    assert first.status_code == 201, first.text
    _allocate(client, pid, "other", 28)

    replay = _reserve(client, pid, "b1", [{"request_id": "r1", "prefix_length": 28}])
    assert replay.status_code == 200
    assert replay.json()["reservations"] == first.json()["reservations"]


def test_batch_id_with_changed_params_conflicts(client):
    pid = _create_pool(client)
    first = _reserve(client, pid, "b1", [{"request_id": "r1", "prefix_length": 28}])
    assert first.status_code == 201, first.text

    # Different items.
    resp = _reserve(client, pid, "b1", [{"request_id": "r2", "prefix_length": 28}])
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "batch_id_conflict"

    # Different policy.
    resp = _reserve(
        client,
        pid,
        "b1",
        [{"request_id": "r1", "prefix_length": 28}],
        rules=[{"cidr": "10.0.0.0/25", "action": "deny"}],
    )
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "batch_id_conflict"

    # Same parameters against another pool.
    other = _create_pool(client, cidr="10.1.0.0/24")
    resp = _reserve(client, other, "b1", [{"request_id": "r1", "prefix_length": 28}])
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "batch_id_conflict"


def test_batch_item_reuses_existing_request_id(client):
    pid = _create_pool(client)
    mine = _allocate(client, pid, "mine", 27)  # 10.0.0.0/27

    resp = _reserve(
        client,
        pid,
        "b1",
        [
            {"request_id": "mine", "prefix_length": 27},
            {"request_id": "fresh", "prefix_length": 27},
        ],
    )
    assert resp.status_code == 201, resp.text
    reservations = resp.json()["reservations"]
    # The existing request_id resolves to its original allocation...
    assert reservations[0]["cidr"] == mine["cidr"] == "10.0.0.0/27"
    assert reservations[0]["id"] == mine["id"]
    assert reservations[0]["replayed"] is True
    # ...and only the genuinely new item reserves new space.
    assert reservations[1]["cidr"] == "10.0.0.32/27"
    assert reservations[1]["replayed"] is False
    assert _allocated_cidrs(client, pid) == ["10.0.0.0/27", "10.0.0.32/27"]


def test_batch_item_request_id_conflict_rolls_back(client):
    pid = _create_pool(client)
    _allocate(client, pid, "mine", 27)

    # Same request_id, different prefix length -> conflict, and the fresh
    # item in the same batch is rolled back too.
    resp = _reserve(
        client,
        pid,
        "b1",
        [
            {"request_id": "fresh", "prefix_length": 27},
            {"request_id": "mine", "prefix_length": 28},
        ],
    )
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "request_id_conflict"
    assert _allocated_cidrs(client, pid) == ["10.0.0.0/27"]


def test_batch_item_request_id_used_in_other_pool_conflicts(client):
    pid1 = _create_pool(client, cidr="10.0.0.0/24")
    pid2 = _create_pool(client, cidr="10.1.0.0/24")
    _allocate(client, pid1, "shared", 27)

    resp = _reserve(client, pid2, "b1", [{"request_id": "shared", "prefix_length": 27}])
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "request_id_conflict"


def test_batch_duplicate_request_id_within_batch(client):
    pid = _create_pool(client)
    resp = _reserve(
        client,
        pid,
        "b1",
        [
            {"request_id": "dup", "prefix_length": 28},
            {"request_id": "dup", "prefix_length": 28},
        ],
    )
    assert resp.status_code == 201, resp.text
    reservations = resp.json()["reservations"]
    # The repeat resolves to the same reservation instead of reserving twice.
    assert reservations[0]["cidr"] == reservations[1]["cidr"] == "10.0.0.0/28"
    assert reservations[0]["id"] == reservations[1]["id"]
    assert _allocated_cidrs(client, pid) == ["10.0.0.0/28"]

    # Same key, different prefix length inside one batch -> conflict.
    resp = _reserve(
        client,
        pid,
        "b2",
        [
            {"request_id": "flip", "prefix_length": 28},
            {"request_id": "flip", "prefix_length": 29},
        ],
    )
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "request_id_conflict"


def test_batch_reservations_can_be_released(client):
    pid = _create_pool(client)
    resp = _reserve(
        client,
        pid,
        "b1",
        [
            {"request_id": "r1", "prefix_length": 28},
            {"request_id": "r2", "prefix_length": 28},
        ],
    )
    assert resp.status_code == 201, resp.text

    released = client.delete(f"/pools/{pid}/allocations/r1")
    assert released.status_code == 200
    assert released.json()["released"] == "10.0.0.0/28"
    assert _allocated_cidrs(client, pid) == ["10.0.0.16/28"]


def test_batch_rule_validation(client):
    pid = _create_pool(client)

    resp = _reserve(
        client,
        pid,
        "b1",
        [{"request_id": "r1", "prefix_length": 28}],
        rules=[{"cidr": "10.0.0.5/24", "action": "allow"}],
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "invalid_cidr"

    resp = _reserve(
        client,
        pid,
        "b1",
        [{"request_id": "r1", "prefix_length": 28}],
        rules=[{"cidr": "10.1.0.0/24", "action": "allow"}],
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "rule_outside_scope"

    # Bad action / prefix length / empty items are rejected by validation.
    resp = _reserve(
        client,
        pid,
        "b1",
        [{"request_id": "r1", "prefix_length": 28}],
        rules=[{"cidr": "10.0.0.0/24", "action": "permit"}],
    )
    assert resp.status_code == 422
    resp = _reserve(client, pid, "b1", [{"request_id": "r1", "prefix_length": 33}])
    assert resp.status_code == 422
    resp = _reserve(client, pid, "b1", [])
    assert resp.status_code == 422


def test_batch_pool_not_found(client):
    resp = _reserve(client, 999, "b1", [{"request_id": "r1", "prefix_length": 28}])
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "pool_not_found"


def test_concurrent_batches_are_serialised_and_distinct(client):
    pid = _create_pool(client)
    results: list[str] = []
    errors: list[int] = []
    barrier = threading.Barrier(10)

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

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # /24 holds exactly eight /27s; the other two batches see exhaustion.
    assert len(results) == 8
    assert set(errors) == {409}
    nets = [ipaddress.ip_network(c) for c in results]
    assert len(set(results)) == 8
    for i, a in enumerate(nets):
        for b in nets[i + 1 :]:
            assert not a.overlaps(b)


def test_concurrent_same_batch_id_reserves_once(client):
    pid = _create_pool(client)
    bodies: list[dict] = []
    barrier = threading.Barrier(6)

    from app.main import app

    payload = {
        "batch_id": "same",
        "default_action": "allow",
        "rules": [],
        "items": [
            {"request_id": "r1", "prefix_length": 28},
            {"request_id": "r2", "prefix_length": 28},
        ],
    }

    def worker():
        local = TestClient(app)
        barrier.wait()
        resp = local.post(f"/pools/{pid}/reservations", json=payload)
        assert resp.status_code in (200, 201), resp.text
        bodies.append(resp.json())

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Exactly one real reservation happened; every response carries the
    # same stored mapping.
    assert len(bodies) == 6
    first = bodies[0]["reservations"]
    assert all(body["reservations"] == first for body in bodies)
    assert len(_allocated_cidrs(client, pid)) == 2
