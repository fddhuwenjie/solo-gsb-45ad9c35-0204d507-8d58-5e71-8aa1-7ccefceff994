"""API integration tests for confirmable BGP announcement plans."""

from __future__ import annotations

import threading

from fastapi.testclient import TestClient


def _create_pool(client, cidr="203.0.113.0/24", exclusions=None):
    resp = client.post(
        "/pools", json={"cidr": cidr, "exclusions": exclusions or []}
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


def _allocate(client, pool_id, request_id, prefix_length):
    resp = client.post(
        f"/pools/{pool_id}/allocations",
        json={"request_id": request_id, "prefix_length": prefix_length},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["cidr"]


RELATIONSHIPS = [
    {"type": "customer_provider", "customer": 10, "provider": 100},
    {"type": "peer", "a": 100, "b": 50},
    {"type": "customer_provider", "customer": 60, "provider": 50},
]

# One valid announcement per /25, origins 100 (via 10) and 60 (via 50).
ANNOUNCEMENTS = [
    {"id": "a0", "prefix": "203.0.113.0/25", "as_path": [10, 100]},
    {"id": "a128", "prefix": "203.0.113.128/25", "as_path": [100, 50, 60]},
]


def _plan_body(plan_id="plan-1", relationships=None, announcements=None):
    return {
        "plan_id": plan_id,
        "relationships": RELATIONSHIPS if relationships is None else relationships,
        "announcements": ANNOUNCEMENTS if announcements is None else announcements,
    }


def _create_plan(client, pool_id, **body_overrides):
    body = _plan_body(**body_overrides)
    return client.post(f"/pools/{pool_id}/bgp-plans", json=body)


def _activate(client, pool_id, plan_id):
    return client.post(f"/pools/{pool_id}/bgp-plans/{plan_id}/activate")


def test_create_and_activate_plan(client):
    pid = _create_pool(client)
    cidr = _allocate(client, pid, "order-1", 25)
    assert cidr == "203.0.113.0/25"

    resp = _create_plan(client, pid, announcements=ANNOUNCEMENTS[:1])
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["plan_id"] == "plan-1"
    assert data["pool_id"] == pid
    assert data["status"] == "planned"
    assert data["replayed"] is False
    assert data["activated_at"] is None
    assert len(data["results"]) == 1
    assert data["results"][0]["status"] == "valid"
    assert data["state_digest"] and len(data["state_digest"]) == 64
    assert data["pool_state"]["cidr"] == "203.0.113.0/24"
    assert data["pool_state"]["exclusions"] == []
    assert [a["cidr"] for a in data["pool_state"]["allocations"]] == [
        "203.0.113.0/25"
    ]

    resp = _activate(client, pid, "plan-1")
    assert resp.status_code == 200, resp.text
    activated = resp.json()
    assert activated["status"] == "active"
    assert activated["replayed"] is False
    assert activated["activated_at"] is not None
    assert activated["state_digest"] == data["state_digest"]


def test_create_pins_exclusions(client):
    pid = _create_pool(client, exclusions=["203.0.113.0/26"])
    _allocate(client, pid, "order-1", 26)  # lands at 203.0.113.64/26
    ann = [
        # /26 covering the allocation, avoiding the excluded /26.
        {"id": "a64", "prefix": "203.0.113.64/26", "as_path": [10, 100]},
        {"id": "a128", "prefix": "203.0.113.128/25", "as_path": [10, 100]},
    ]
    resp = _create_plan(
        client,
        pid,
        announcements=ann,
        relationships=[
            {"type": "customer_provider", "customer": 10, "provider": 100}
        ],
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["pool_state"]["exclusions"] == ["203.0.113.0/26"]


def test_create_replay_same_params(client):
    pid = _create_pool(client)
    _allocate(client, pid, "order-1", 25)
    first = _create_plan(client, pid, announcements=ANNOUNCEMENTS[:1])
    assert first.status_code == 201

    # Reordered relationships and repeated identical declarations are equal.
    body = _plan_body(
        relationships=list(reversed(RELATIONSHIPS))
        + [{"type": "peer", "a": 50, "b": 100}],
        announcements=ANNOUNCEMENTS[:1],
    )
    second = client.post(f"/pools/{pid}/bgp-plans", json=body)
    assert second.status_code == 200, second.text
    replay = second.json()
    assert replay["replayed"] is True
    assert replay["status"] == "planned"
    assert replay["created_at"] == first.json()["created_at"]


def test_create_replay_after_activation_returns_active(client):
    pid = _create_pool(client)
    _allocate(client, pid, "order-1", 25)
    _create_plan(client, pid, announcements=ANNOUNCEMENTS[:1])
    assert _activate(client, pid, "plan-1").json()["status"] == "active"

    replay = _create_plan(client, pid, announcements=ANNOUNCEMENTS[:1])
    assert replay.status_code == 200
    assert replay.json()["status"] == "active"
    assert replay.json()["replayed"] is True


def test_create_same_plan_id_different_params_conflicts(client):
    pid = _create_pool(client)
    _allocate(client, pid, "order-1", 25)
    assert _create_plan(client, pid, announcements=ANNOUNCEMENTS[:1]).status_code == 201

    changed = client.post(
        f"/pools/{pid}/bgp-plans",
        json=_plan_body(announcements=ANNOUNCEMENTS),
    )
    assert changed.status_code == 409
    assert changed.json()["error"]["code"] == "bgp_plan_id_conflict"

    changed_rel = client.post(
        f"/pools/{pid}/bgp-plans",
        json=_plan_body(
            announcements=ANNOUNCEMENTS[:1],
            relationships=[
                {"type": "customer_provider", "customer": 10, "provider": 100}
            ],
        ),
    )
    assert changed_rel.status_code == 409
    assert changed_rel.json()["error"]["code"] == "bgp_plan_id_conflict"


def test_same_plan_id_on_other_pool_conflicts(client):
    p1 = _create_pool(client)
    p2 = _create_pool(client, cidr="203.0.114.0/24")
    _allocate(client, p1, "order-1", 25)
    _allocate(client, p2, "order-2", 25)
    ann1 = [{"id": "a", "prefix": "203.0.113.0/25", "as_path": [10, 100]}]
    ann2 = [{"id": "a", "prefix": "203.0.114.0/25", "as_path": [10, 100]}]
    rels = [{"type": "customer_provider", "customer": 10, "provider": 100}]

    assert (
        client.post(
            f"/pools/{p1}/bgp-plans",
            json={"plan_id": "plan-1", "relationships": rels, "announcements": ann1},
        ).status_code
        == 201
    )
    resp = client.post(
        f"/pools/{p2}/bgp-plans",
        json={"plan_id": "plan-1", "relationships": rels, "announcements": ann2},
    )
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "bgp_plan_id_conflict"


def test_announcement_outside_pool_rejected(client):
    pid = _create_pool(client)
    _allocate(client, pid, "order-1", 25)
    ann = [
        {"id": "a", "prefix": "203.0.113.0/25", "as_path": [10, 100]},
        {"id": "other", "prefix": "198.51.100.0/24", "as_path": [10, 100]},
    ]
    resp = _create_plan(
        client,
        pid,
        announcements=ann,
        relationships=[
            {"type": "customer_provider", "customer": 10, "provider": 100}
        ],
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "bgp_announcement_outside_pool"


def test_announcement_overlapping_exclusion_rejected(client):
    pid = _create_pool(client, exclusions=["203.0.113.128/25"])
    _allocate(client, pid, "order-1", 25)
    ann = [{"id": "whole", "prefix": "203.0.113.0/24", "as_path": [10, 100]}]
    resp = _create_plan(
        client,
        pid,
        announcements=ann,
        relationships=[
            {"type": "customer_provider", "customer": 10, "provider": 100}
        ],
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "bgp_announcement_overlaps_exclusion"


def test_uncovered_allocation_rejected(client):
    pid = _create_pool(client)
    _allocate(client, pid, "order-1", 25)  # 203.0.113.0/25
    _allocate(client, pid, "order-2", 25)  # 203.0.113.128/25
    resp = _create_plan(client, pid, announcements=ANNOUNCEMENTS[:1])
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "bgp_allocation_uncovered"


def test_allocation_covered_by_different_origins_rejected(client):
    pid = _create_pool(client)
    _allocate(client, pid, "order-1", 25)  # 203.0.113.0/25
    ann = [
        # Both announcements cover the /25 allocation but from different
        # origins: the coarse /24 originates 50, the exact /25 originates 100.
        {"id": "whole", "prefix": "203.0.113.0/24", "as_path": [50]},
        {"id": "exact", "prefix": "203.0.113.0/25", "as_path": [10, 100]},
    ]
    resp = _create_plan(client, pid, announcements=ann)
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "bgp_allocation_origin_conflict"


def test_same_origin_covering_twice_is_allowed(client):
    pid = _create_pool(client)
    _allocate(client, pid, "order-1", 25)
    ann = [
        {"id": "whole", "prefix": "203.0.113.0/24", "as_path": [10, 100]},
        {"id": "exact", "prefix": "203.0.113.0/25", "as_path": [20, 100]},
    ]
    rels = [
        {"type": "customer_provider", "customer": 10, "provider": 100},
        {"type": "customer_provider", "customer": 20, "provider": 100},
    ]
    resp = _create_plan(
        client,
        pid,
        announcements=ann,
        relationships=rels,
    )
    assert resp.status_code == 201, resp.text


def test_invalid_path_announcement_cannot_cover(client):
    pid = _create_pool(client)
    _allocate(client, pid, "order-1", 25)
    # [100, 50, 60] is valid; [100, 50, 70] is invalid (up after a peer), so
    # the sole covering announcement does not pass the audit.
    ann = [{"id": "bad", "prefix": "203.0.113.0/25", "as_path": [100, 50, 70]}]
    rels = [
        {"type": "peer", "a": 100, "b": 50},
        {"type": "customer_provider", "customer": 50, "provider": 70},
    ]
    resp = _create_plan(client, pid, announcements=ann, relationships=rels)
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "bgp_allocation_uncovered"


def test_path_audit_422_is_preserved(client):
    pid = _create_pool(client)
    _allocate(client, pid, "order-1", 25)
    ann = [{"id": "a", "prefix": "203.0.113.0/25", "as_path": [10, 999]}]
    resp = _create_plan(
        client,
        pid,
        announcements=ann,
        relationships=[
            {"type": "customer_provider", "customer": 10, "provider": 100}
        ],
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "as_relation_unknown"


def test_moas_over_free_space_does_not_block_plan(client):
    pid = _create_pool(client)
    _allocate(client, pid, "order-1", 25)
    ann = [
        {"id": "v10", "prefix": "203.0.113.0/25", "as_path": [10, 100]},
        {"id": "v50", "prefix": "203.0.113.128/25", "as_path": [100, 50, 60]},
    ]
    resp = _create_plan(client, pid, announcements=ann)
    assert resp.status_code == 201, resp.text
    flags = {r["id"]: r["flags"] for r in resp.json()["results"]}
    assert flags["v10"] == []
    # Two distinct covering announcements, single origin per allocation.
    assert _activate(client, pid, "plan-1").status_code == 200


def test_activation_conflicts_after_new_allocation(client):
    pid = _create_pool(client)
    _allocate(client, pid, "order-1", 25)
    assert _create_plan(client, pid, announcements=ANNOUNCEMENTS[:1]).status_code == 201

    # Pool grew a second allocation no announcement covers.
    _allocate(client, pid, "order-2", 25)
    resp = _activate(client, pid, "plan-1")
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "bgp_plan_state_conflict"
    # Still planned: no partial effect.
    replay = _create_plan(client, pid, announcements=ANNOUNCEMENTS[:1])
    assert replay.json()["status"] == "planned"


def test_activation_conflicts_after_release_and_reallocate(client):
    pid = _create_pool(client)
    _allocate(client, pid, "order-1", 25)  # .0/25
    _allocate(client, pid, "order-2", 25)  # .128/25
    assert _create_plan(client, pid).status_code == 201

    client.delete(f"/pools/{pid}/allocations/order-1")
    # A fresh request takes the freed /25: same CIDRs but a changed
    # request_id is part of the pinned identity.
    _allocate(client, pid, "order-3", 25)
    resp = _activate(client, pid, "plan-1")
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "bgp_plan_state_conflict"


def test_activation_conflicts_after_exclusion_added(client):
    # /26 allocations leave 203.0.113.192/26 free, which can later be excluded.
    pid = _create_pool(client)
    _allocate(client, pid, "order-1", 26)  # .0/26
    _allocate(client, pid, "order-2", 26)  # .64/26
    _allocate(client, pid, "order-3", 26)  # .128/26
    ann = [
        {"id": "lo", "prefix": "203.0.113.0/25", "as_path": [10, 100]},
        {"id": "hi", "prefix": "203.0.113.128/26", "as_path": [10, 100]},
    ]
    rels = [{"type": "customer_provider", "customer": 10, "provider": 100}]
    created = client.post(
        f"/pools/{pid}/bgp-plans",
        json={"plan_id": "plan-1", "relationships": rels, "announcements": ann},
    )
    assert created.status_code == 201, created.text

    add = client.post(
        f"/pools/{pid}/exclusions", json={"cidr": "203.0.113.192/26"}
    )
    assert add.status_code == 201, add.text
    resp = _activate(client, pid, "plan-1")
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "bgp_plan_state_conflict"


def test_activation_replay_is_idempotent(client):
    pid = _create_pool(client)
    _allocate(client, pid, "order-1", 25)
    _create_plan(client, pid, announcements=ANNOUNCEMENTS[:1])
    first = _activate(client, pid, "plan-1")
    assert first.json()["replayed"] is False

    # Changing the pool after activation does not alter the replay.
    client.delete(f"/pools/{pid}/allocations/order-1")
    second = _activate(client, pid, "plan-1")
    assert second.status_code == 200
    assert second.json()["replayed"] is True
    assert second.json()["status"] == "active"
    assert second.json()["activated_at"] == first.json()["activated_at"]


def test_activate_unknown_plan_404(client):
    pid = _create_pool(client)
    resp = _activate(client, pid, "nope")
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "bgp_plan_not_found"


def test_activate_plan_of_other_pool_404(client):
    p1 = _create_pool(client)
    p2 = _create_pool(client, cidr="203.0.114.0/24")
    _allocate(client, p1, "order-1", 25)
    rels = [{"type": "customer_provider", "customer": 10, "provider": 100}]
    ann = [{"id": "a", "prefix": "203.0.113.0/25", "as_path": [10, 100]}]
    client.post(
        f"/pools/{p1}/bgp-plans",
        json={"plan_id": "plan-1", "relationships": rels, "announcements": ann},
    )
    resp = _activate(client, p2, "plan-1")
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "bgp_plan_not_found"


def test_create_plan_for_missing_pool_404(client):
    resp = _create_plan(client, 999)
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "pool_not_found"


def test_plan_is_immutable_across_failed_activation(client):
    pid = _create_pool(client)
    _allocate(client, pid, "order-1", 25)
    created = _create_plan(client, pid, announcements=ANNOUNCEMENTS[:1]).json()

    client.delete(f"/pools/{pid}/allocations/order-1")
    assert _activate(client, pid, "plan-1").status_code == 409

    status = client.get(f"/pools/{pid}").json()
    assert status["allocated"] == []
    # Re-creating with the same params replays the stored, unchanged plan.
    replay = _create_plan(client, pid, announcements=ANNOUNCEMENTS[:1]).json()
    assert replay["state_digest"] == created["state_digest"]
    assert replay["results"] == created["results"]
    assert replay["status"] == "planned"


def test_concurrent_same_plan_id_creates_one_plan(client):
    pid = _create_pool(client)
    _allocate(client, pid, "order-1", 25)
    barrier = threading.Barrier(8)
    statuses: list[int] = []
    lock = threading.Lock()

    from app.main import app

    body = _plan_body(announcements=ANNOUNCEMENTS[:1])

    def worker():
        local = TestClient(app)
        barrier.wait()
        resp = local.post(f"/pools/{pid}/bgp-plans", json=body)
        with lock:
            statuses.append(resp.status_code)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Exactly one 201, all other identical requests replay with 200.
    assert statuses.count(201) == 1
    assert statuses.count(200) == 7
    rows = client.get(f"/pools/{pid}")
    assert rows.status_code == 200


def test_concurrent_activation_and_allocation(client):
    pid = _create_pool(client)
    _allocate(client, pid, "order-1", 25)
    _create_plan(client, pid, announcements=ANNOUNCEMENTS[:1])
    barrier = threading.Barrier(2)
    outcomes: list[int] = []
    lock = threading.Lock()

    from app.main import app

    def activator():
        local = TestClient(app)
        barrier.wait()
        resp = local.post(f"/pools/{pid}/bgp-plans/plan-1/activate")
        with lock:
            outcomes.append(resp.status_code)

    def allocator():
        local = TestClient(app)
        barrier.wait()
        # A second allocation the plan does not cover.
        resp = local.post(
            f"/pools/{pid}/allocations",
            json={"request_id": "order-2", "prefix_length": 25},
        )
        with lock:
            outcomes.append(resp.status_code)

    threads = [threading.Thread(target=activator), threading.Thread(target=allocator)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Both write transactions are serialised by BEGIN IMMEDIATE: the
    # allocation always lands (201), and the activation either ran first
    # (200, plan active) or second and saw the new allocation (409, plan
    # still planned).  Never a partial state.
    assert 201 in outcomes
    activation = outcomes[0] if outcomes[0] != 201 else outcomes[1]
    assert activation in (200, 409)

    # Final state is self-consistent.  The pool has both allocations and the
    # plan status matches whichever outcome the serialisation chose: an
    # already-active plan replays, a planned one now definitely conflicts.
    status = client.get(f"/pools/{pid}").json()
    assert len(status["allocated"]) == 2
    again = _activate(client, pid, "plan-1")
    if activation == 200:
        assert again.status_code == 200
        assert again.json()["status"] == "active"
        assert again.json()["replayed"] is True
    else:
        assert again.status_code == 409
        assert again.json()["error"]["code"] == "bgp_plan_state_conflict"
