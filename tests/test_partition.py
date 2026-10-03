"""Pool partition migration: atomic split into exactly covering sub-pools."""

from __future__ import annotations

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


def _partition(client, pool_id, operation_id, subnets):
    return client.post(
        f"/pools/{pool_id}/partitions",
        json={"operation_id": operation_id, "subnets": subnets},
    )


def _pool_ids(client):
    return [p["id"] for p in client.get("/pools").json()]


def test_partition_moves_state_and_replaces_source(client):
    pid = _create_pool(client, cidr="10.0.0.0/24", exclusions=["10.0.0.192/26"])
    a = _allocate(client, pid, "req-a", 26)  # 10.0.0.0/26
    b = _allocate(client, pid, "req-b", 26)  # 10.0.0.64/26
    c = _allocate(client, pid, "req-c", 26)  # 10.0.0.128/26

    resp = _partition(client, pid, "op-1", ["10.0.0.128/25", "10.0.0.0/25"])
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["operation_id"] == "op-1"
    assert body["source_pool_id"] == pid
    assert body["source_cidr"] == "10.0.0.0/24"
    assert body["replayed"] is False
    assert isinstance(body["migration_id"], int)

    # Sub-pools are reported in network-address order regardless of request
    # order, each mapped to its own new pool id.
    sub_pools = body["sub_pools"]
    assert [sp["cidr"] for sp in sub_pools] == ["10.0.0.0/25", "10.0.0.128/25"]
    low_id, high_id = (sp["pool_id"] for sp in sub_pools)
    assert pid not in (low_id, high_id)

    # The source pool is gone; exactly the two sub-pools replaced it.
    assert client.get(f"/pools/{pid}").status_code == 404
    assert _pool_ids(client) == [low_id, high_id]

    # Allocations moved to the sub-pool that contains them.
    low = client.get(f"/pools/{low_id}").json()
    assert low["cidr"] == "10.0.0.0/25"
    assert [x["request_id"] for x in low["allocated"]] == ["req-a", "req-b"]
    assert low["exclusions"] == []
    assert low["free_cidrs"] == []

    high = client.get(f"/pools/{high_id}").json()
    assert high["cidr"] == "10.0.0.128/25"
    assert [x["request_id"] for x in high["allocated"]] == ["req-c"]
    assert high["exclusions"] == ["10.0.0.192/26"]
    assert high["free_cidrs"] == []

    # Row identity survived the move: the same request_id replays the same
    # allocation id against the new sub-pool.
    replay = client.post(
        f"/pools/{high_id}/allocations",
        json={"request_id": "req-c", "prefix_length": 26},
    )
    assert replay.status_code == 201
    assert replay.json()["replayed"] is True
    assert replay.json()["id"] == c["id"]
    assert replay.json()["cidr"] == "10.0.0.128/26"

    # And a release targets the new sub-pool now.
    freed = client.delete(f"/pools/{low_id}/allocations/req-a")
    assert freed.status_code == 200
    assert freed.json()["released"] == a["cidr"]


def test_partition_multiway_cover(client):
    pid = _create_pool(client, cidr="10.0.0.0/24")
    for i in range(4):
        _allocate(client, pid, f"req-{i}", 26)  # one /26 per quarter

    quarters = [f"10.0.0.{i * 64}/26" for i in range(4)]
    resp = _partition(client, pid, "op-quad", quarters)
    assert resp.status_code == 201, resp.text
    sub_pools = resp.json()["sub_pools"]
    assert [sp["cidr"] for sp in sub_pools] == quarters
    for i, sp in enumerate(sub_pools):
        status = client.get(f"/pools/{sp['pool_id']}").json()
        assert [x["request_id"] for x in status["allocated"]] == [f"req-{i}"]
        assert status["free_cidrs"] == []


def test_partition_single_subnet_equal_to_pool(client):
    # Degenerate but valid exact cover: the pool is replaced by one new pool
    # with the same CIDR (the source row is retired, the id changes).
    pid = _create_pool(client, cidr="10.0.0.0/24")
    _allocate(client, pid, "req-a", 26)

    resp = _partition(client, pid, "op-same", ["10.0.0.0/24"])
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert [sp["cidr"] for sp in body["sub_pools"]] == ["10.0.0.0/24"]
    new_id = body["sub_pools"][0]["pool_id"]
    assert new_id != pid
    assert client.get(f"/pools/{pid}").status_code == 404
    status = client.get(f"/pools/{new_id}").json()
    assert [x["request_id"] for x in status["allocated"]] == ["req-a"]


def test_partition_replay_returns_original_result(client):
    pid = _create_pool(client, cidr="10.0.0.0/24")
    _allocate(client, pid, "req-a", 26)

    first = _partition(client, pid, "op-idem", ["10.0.0.0/25", "10.0.0.128/25"])
    assert first.status_code == 201, first.text

    # Same operation_id and same subnets (even reordered): the source pool
    # is already gone, yet the original result is replayed.
    second = _partition(client, pid, "op-idem", ["10.0.0.128/25", "10.0.0.0/25"])
    assert second.status_code == 201, second.text
    assert second.json()["replayed"] is True
    assert second.json()["migration_id"] == first.json()["migration_id"]
    assert second.json()["sub_pools"] == first.json()["sub_pools"]
    assert second.json()["source_pool_id"] == pid

    # No extra pools were created by the retry.
    assert _pool_ids(client) == [sp["pool_id"] for sp in first.json()["sub_pools"]]


def test_partition_operation_id_conflict_on_changed_subnets(client):
    pid = _create_pool(client, cidr="10.0.0.0/24")
    ok = _partition(client, pid, "op-x", ["10.0.0.0/25", "10.0.0.128/25"])
    assert ok.status_code == 201

    resp = _partition(client, pid, "op-x", [f"10.0.0.{i * 64}/26" for i in range(4)])
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "operation_id_conflict"


def test_partition_operation_id_conflict_across_pools(client):
    pid1 = _create_pool(client, cidr="10.0.0.0/24")
    pid2 = _create_pool(client, cidr="10.1.0.0/24")
    ok = _partition(client, pid1, "op-shared", ["10.0.0.0/25", "10.0.0.128/25"])
    assert ok.status_code == 201

    resp = _partition(client, pid2, "op-shared", ["10.1.0.0/25", "10.1.0.128/25"])
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "operation_id_conflict"
    # The second pool is untouched.
    assert client.get(f"/pools/{pid2}").status_code == 200


def test_partition_pool_not_found(client):
    resp = _partition(client, 999, "op-404", ["10.0.0.0/25", "10.0.0.128/25"])
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "pool_not_found"


def test_partition_invalid_cidr_rejected(client):
    pid = _create_pool(client)
    resp = _partition(client, pid, "op-bad", ["10.0.0.0/25", "10.0.0.129/25"])
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "invalid_cidr"
    assert client.get(f"/pools/{pid}").status_code == 200


def test_partition_subnet_outside_pool_rejected(client):
    pid = _create_pool(client, cidr="10.0.0.0/24")
    resp = _partition(client, pid, "op-out", ["10.0.0.0/25", "10.0.0.128/25", "10.1.0.0/24"])
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "partition_outside_pool"


def test_partition_overlap_rejected(client):
    pid = _create_pool(client, cidr="10.0.0.0/24")
    resp = _partition(client, pid, "op-ovl", ["10.0.0.0/24", "10.0.0.0/25"])
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "partition_overlap"

    # Exact duplicates are overlaps too.
    resp = _partition(client, pid, "op-dup", ["10.0.0.0/25", "10.0.0.0/25"])
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "partition_overlap"


def test_partition_incomplete_cover_rejected(client):
    pid = _create_pool(client, cidr="10.0.0.0/24")
    resp = _partition(client, pid, "op-part", ["10.0.0.0/25"])
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "partition_incomplete"


def test_partition_exclusion_straddling_boundary_rejected(client):
    pid = _create_pool(client, cidr="10.0.0.0/24", exclusions=["10.0.0.0/25"])
    quarters = [f"10.0.0.{i * 64}/26" for i in range(4)]
    resp = _partition(client, pid, "op-excl", quarters)
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "partition_exclusion_unmapped"

    # A boundary-aligned split of the same pool succeeds.
    ok = _partition(client, pid, "op-excl2", ["10.0.0.0/25", "10.0.0.128/25"])
    assert ok.status_code == 201, ok.text
    low_id = ok.json()["sub_pools"][0]["pool_id"]
    assert client.get(f"/pools/{low_id}").json()["exclusions"] == ["10.0.0.0/25"]


def test_partition_allocation_straddling_boundary_rejected(client):
    pid = _create_pool(client, cidr="10.0.0.0/24")
    _allocate(client, pid, "req-half", 25)  # 10.0.0.0/25

    quarters = [f"10.0.0.{i * 64}/26" for i in range(4)]
    resp = _partition(client, pid, "op-alloc", quarters)
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "partition_allocation_unmapped"

    # Nothing changed: the source pool and its allocation are intact and no
    # sub-pool was left behind.
    status = client.get(f"/pools/{pid}").json()
    assert [a["request_id"] for a in status["allocated"]] == ["req-half"]
    assert _pool_ids(client) == [pid]


def test_partition_conflicts_with_other_pool(client):
    pid = _create_pool(client, cidr="10.0.0.0/24")
    other = _create_pool(client, cidr="10.0.0.128/25")  # overlapping pools coexist

    resp = _partition(client, pid, "op-conf", ["10.0.0.0/25", "10.0.0.128/25"])
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "partition_pool_conflict"

    # Both pools are unchanged and no sub-pool leaked through.
    assert client.get(f"/pools/{pid}").status_code == 200
    assert client.get(f"/pools/{other}").status_code == 200
    assert sorted(_pool_ids(client)) == sorted([pid, other])


def test_partition_failure_leaves_no_partial_state(client):
    pid = _create_pool(client, cidr="10.0.0.0/24", exclusions=["10.0.0.192/26"])
    _allocate(client, pid, "req-a", 26)
    before = client.get(f"/pools/{pid}").json()

    for subnets, code in (
        (["10.0.0.0/25"], "partition_incomplete"),
        (["10.0.0.0/25", "10.0.0.0/26", "10.0.0.128/25"], "partition_overlap"),
        # The 10.0.0.192/26 exclusion straddles the two /27 sub-pools.
        (
            ["10.0.0.0/25", "10.0.0.128/26", "10.0.0.192/27", "10.0.0.224/27"],
            "partition_exclusion_unmapped",
        ),
    ):
        resp = _partition(client, pid, f"op-{code}", subnets)
        assert resp.status_code == 422, (subnets, resp.text)
        assert resp.json()["error"]["code"] == code

    after = client.get(f"/pools/{pid}").json()
    assert after == before
    assert _pool_ids(client) == [pid]


def test_concurrent_partitions_are_serialised(client):
    pid = _create_pool(client, cidr="10.0.0.0/24")
    subnets = ["10.0.0.0/25", "10.0.0.128/25"]
    results: list[tuple[int, dict]] = []
    barrier = threading.Barrier(6)

    from app.main import app

    def worker(i: int):
        local = TestClient(app)
        barrier.wait()
        resp = _partition(local, pid, f"op-conc-{i}", subnets)
        results.append((resp.status_code, resp.json()))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    statuses = sorted(code for code, _ in results)
    # Exactly one partition wins; the rest observe the retired source pool.
    assert statuses == [201, 404, 404, 404, 404, 404]
    winner = next(body for code, body in results if code == 201)
    assert _pool_ids(client) == [sp["pool_id"] for sp in winner["sub_pools"]]


def test_concurrent_same_operation_id_replays(client):
    pid = _create_pool(client, cidr="10.0.0.0/24")
    subnets = ["10.0.0.0/25", "10.0.0.128/25"]
    bodies: list[dict] = []
    barrier = threading.Barrier(6)

    from app.main import app

    def worker():
        local = TestClient(app)
        barrier.wait()
        resp = _partition(local, pid, "op-same", subnets)
        assert resp.status_code == 201, resp.text
        bodies.append(resp.json())

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # One real migration, every concurrent retry replayed the same record.
    assert sum(1 for b in bodies if not b["replayed"]) == 1
    assert {b["migration_id"] for b in bodies} == {bodies[0]["migration_id"]}
    assert len(_pool_ids(client)) == 2
