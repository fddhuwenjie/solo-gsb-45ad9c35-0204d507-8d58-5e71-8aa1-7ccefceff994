"""API integration tests including concurrency and idempotency."""

from __future__ import annotations

import ipaddress
import threading

from fastapi.testclient import TestClient


def _create_pool(client, cidr="10.0.0.0/24", exclusions=None):
    resp = client.post("/pools", json={"cidr": cidr, "exclusions": exclusions or []})
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_create_pool_and_status(client):
    pid = _create_pool(client)
    status = client.get(f"/pools/{pid}").json()
    assert status["cidr"] == "10.0.0.0/24"
    assert status["free_cidrs"] == ["10.0.0.0/24"]
    assert status["free_addresses"] == 256
    assert status["allocated"] == []


def test_pool_with_exclusion_splits_free_space(client):
    pid = _create_pool(client, exclusions=["10.0.0.128/25"])
    status = client.get(f"/pools/{pid}").json()
    assert status["free_cidrs"] == ["10.0.0.0/25"]


def test_exclusion_outside_pool_rejected(client):
    resp = client.post("/pools", json={"cidr": "10.0.0.0/24", "exclusions": ["10.1.0.0/24"]})
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "exclusion_outside_pool"


def test_overlapping_exclusions_rejected(client):
    pid = _create_pool(client, exclusions=["10.0.0.128/25"])
    resp = client.post(f"/pools/{pid}/exclusions", json={"cidr": "10.0.0.192/26"})
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "exclusion_overlap"


def test_invalid_cidr_rejected(client):
    resp = client.post("/pools", json={"cidr": "10.0.0.5/24", "exclusions": []})
    assert resp.status_code == 422


def test_allocate_lowest_aligned(client):
    pid = _create_pool(client, exclusions=["10.0.0.0/27"])
    resp = client.post(
        f"/pools/{pid}/allocations",
        json={"request_id": "req-1", "prefix_length": 27},
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["cidr"] == "10.0.0.32/27"
    assert resp.json()["replayed"] is False


def test_idempotent_retry_returns_same_result(client):
    pid = _create_pool(client)
    payload = {"request_id": "idem", "prefix_length": 28}
    first = client.post(f"/pools/{pid}/allocations", json=payload).json()
    second = client.post(f"/pools/{pid}/allocations", json=payload).json()
    assert first["cidr"] == second["cidr"] == "10.0.0.0/28"
    assert first["id"] == second["id"]
    assert second["replayed"] is True

    status = client.get(f"/pools/{pid}").json()
    assert len(status["allocated"]) == 1


def test_retry_with_changed_prefix_conflicts(client):
    pid = _create_pool(client)
    client.post(f"/pools/{pid}/allocations", json={"request_id": "idem", "prefix_length": 28})
    resp = client.post(
        f"/pools/{pid}/allocations",
        json={"request_id": "idem", "prefix_length": 29},
    )
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "request_id_conflict"


def test_request_id_across_pools_conflicts(client):
    pid1 = _create_pool(client, cidr="10.0.0.0/24")
    pid2 = _create_pool(client, cidr="10.1.0.0/24")
    client.post(f"/pools/{pid1}/allocations", json={"request_id": "x", "prefix_length": 30})
    resp = client.post(f"/pools/{pid2}/allocations", json={"request_id": "x", "prefix_length": 30})
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "request_id_conflict"


def test_exhaustion_returns_409(client):
    pid = _create_pool(client, cidr="10.0.0.0/30")
    ok = client.post(f"/pools/{pid}/allocations", json={"request_id": "a", "prefix_length": 30})
    assert ok.status_code == 201
    full = client.post(f"/pools/{pid}/allocations", json={"request_id": "b", "prefix_length": 30})
    assert full.status_code == 409
    assert full.json()["error"]["code"] == "pool_exhausted"


def test_release_merges_free_cidrs(client):
    pid = _create_pool(client, cidr="10.0.0.0/28")
    for i, prefix in enumerate((30, 30)):
        resp = client.post(
            f"/pools/{pid}/allocations",
            json={"request_id": f"r{i}", "prefix_length": prefix},
        )
        assert resp.status_code == 201, resp.text

    # Two /30 allocations at .0 and .4
    release = client.delete(f"/pools/{pid}/allocations/r0")
    assert release.status_code == 200
    assert release.json()["released"] == "10.0.0.0/30"

    status = client.get(f"/pools/{pid}").json()
    assert [a["cidr"] for a in status["allocated"]] == ["10.0.0.4/30"]
    # .0/30 hole before an allocated .4/30 stays its own piece; .8..15 is /29
    assert status["free_cidrs"] == ["10.0.0.0/30", "10.0.0.8/29"]

    # release the second -> whole pool collapses back
    client.delete(f"/pools/{pid}/allocations/r1")
    status = client.get(f"/pools/{pid}").json()
    assert status["free_cidrs"] == ["10.0.0.0/28"]
    assert status["allocated"] == []


def test_release_unknown_request_id_404(client):
    pid = _create_pool(client)
    resp = client.delete(f"/pools/{pid}/allocations/nope")
    assert resp.status_code == 404


def test_allocations_never_overlap(client):
    pid = _create_pool(client, exclusions=["10.0.0.64/26"])
    cidrs = []
    for i in range(10):
        resp = client.post(
            f"/pools/{pid}/allocations",
            json={"request_id": f"req-{i}", "prefix_length": 27},
        )
        if resp.status_code == 201:
            cidrs.append(ipaddress.ip_network(resp.json()["cidr"]))
        else:
            assert resp.json()["error"]["code"] == "pool_exhausted"

    # /24 minus /26 leaves 3 * /26 = 6 * /27 blocks
    assert len(cidrs) == 6
    for i, a in enumerate(cidrs):
        for b in cidrs[i + 1 :]:
            assert not a.overlaps(b)
        assert not a.overlaps(ipaddress.ip_network("10.0.0.64/26"))

    # lowest-address-first order
    assert cidrs == sorted(cidrs, key=lambda n: int(n.network_address))
    assert str(cidrs[0]) == "10.0.0.0/27"


def test_concurrent_allocations_are_serialised_and_distinct(client):
    pid = _create_pool(client)
    results: list[str] = []
    errors: list[int] = []
    barrier = threading.Barrier(16)

    from app.main import app

    def worker(i: int):
        local = TestClient(app)
        barrier.wait()  # maximise contention
        resp = local.post(
            f"/pools/{pid}/allocations",
            json={"request_id": f"c-{i}", "prefix_length": 27},
        )
        if resp.status_code == 201:
            results.append(resp.json()["cidr"])
        else:
            errors.append(resp.status_code)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # /24 holds exactly eight /27s
    assert len(results) == 8
    assert set(errors) == {409}
    nets = [ipaddress.ip_network(c) for c in results]
    assert len(set(results)) == 8
    for i, a in enumerate(nets):
        for b in nets[i + 1 :]:
            assert not a.overlaps(b)

    # The lowest, aligned block must be first
    assert min(results, key=lambda c: int(ipaddress.ip_network(c).network_address)) == "10.0.0.0/27"


def test_concurrent_same_request_id_returns_single_allocation(client):
    pid = _create_pool(client)
    cidrs: list[str] = []
    statuses: list[int] = []
    barrier = threading.Barrier(10)
    lock = threading.Lock()

    from app.main import app

    def worker():
        local = TestClient(app)
        barrier.wait()
        resp = local.post(
            f"/pools/{pid}/allocations",
            json={"request_id": "same", "prefix_length": 30},
        )
        with lock:
            statuses.append(resp.status_code)
            cidrs.append(resp.json().get("cidr", ""))

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert set(statuses) == {201}
    assert set(cidrs) == {"10.0.0.0/30"}
    status = client.get(f"/pools/{pid}").json()
    assert len(status["allocated"]) == 1


def test_pool_not_found(client):
    assert client.get("/pools/999").status_code == 404


# ---------------------------------------------------------------------------
# RFC 2317 reverse-DNS delegation plans
# ---------------------------------------------------------------------------


def _allocate(client, pool_id, request_id, prefix_length):
    resp = client.post(
        f"/pools/{pool_id}/allocations",
        json={"request_id": request_id, "prefix_length": prefix_length},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["cidr"]


def _plan(client, pool_id, body):
    return client.post(f"/pools/{pool_id}/reverse-dns-plan", json=body)


def test_reverse_dns_plan_tagged_subnet_records(client):
    pid = _create_pool(client, cidr="192.0.2.0/24")
    cidr = _allocate(client, pid, "small", 26)  # 192.0.2.0/26

    resp = _plan(
        client,
        pid,
        {
            "parent_zone": "2.0.192.in-addr.arpa",
            "entries": [
                {
                    "cidr": cidr,
                    "child_zone": "0-63",
                    "nameservers": ["ns2.example.com", "ns1.example.com"],
                    "ptr": {"192.0.2.5": "host5.example.com"},
                }
            ],
        },
    )
    assert resp.status_code == 200, resp.text
    plan = resp.json()
    assert plan["pool_id"] == pid
    assert plan["parent_zone"] == "2.0.192.in-addr.arpa"

    delegations = plan["delegations"]
    assert len(delegations) == 1
    assert delegations[0] == {
        "cidr": "192.0.2.0/26",
        "source_cidr": "192.0.2.0/26",
        "mode": "rfc2317",
        "enclosing_zone": "2.0.192.in-addr.arpa",
        "child_zone": "0-63.2.0.192.in-addr.arpa",
        "nameservers": ["ns2.example.com", "ns1.example.com"],
    }

    records = plan["records"]
    # 2 NS + 64 per-address CNAMEs + 1 PTR, in deterministic order:
    # NS (alpha) first, then CNAMEs in numeric address order, then PTRs.
    assert len(records) == 67
    ns = [r for r in records if r["type"] == "NS"]
    assert [r["target"] for r in ns] == ["ns1.example.com", "ns2.example.com"]
    cnames = [r for r in records if r["type"] == "CNAME"]
    assert [r["name"] for r in cnames] == [
        f"{i}.2.0.192.in-addr.arpa" for i in range(64)
    ]
    assert cnames[0]["target"] == "0.0-63.2.0.192.in-addr.arpa"
    assert [r for r in records if r["type"] == "PTR"] == [
        {
            "type": "PTR",
            "name": "5.0-63.2.0.192.in-addr.arpa",
            "target": "host5.example.com",
        }
    ]


def test_reverse_dns_plan_splits_octet_straddling_subnet(client):
    pid = _create_pool(client, cidr="192.0.2.0/23")
    _allocate(client, pid, "big", 23)  # whole pool: two /24 fragments

    resp = _plan(
        client,
        pid,
        {
            "parent_zone": "0.192.in-addr.arpa",
            "entries": [
                {
                    "cidr": "192.0.2.0/23",
                    "nameservers": ["ns1.example.com", "ns2.example.com"],
                    "ptr": {
                        "192.0.2.9": "a.example.com",
                        "192.0.3.9": "b.example.com",
                    },
                }
            ],
        },
    )
    assert resp.status_code == 200, resp.text
    plan = resp.json()
    assert [d["cidr"] for d in plan["delegations"]] == [
        "192.0.2.0/24",
        "192.0.3.0/24",
    ]
    assert all(d["mode"] == "direct" for d in plan["delegations"])
    assert [d["source_cidr"] for d in plan["delegations"]] == [
        "192.0.2.0/23",
        "192.0.2.0/23",
    ]
    ptrs = sorted(
        (r["name"], r["target"]) for r in plan["records"] if r["type"] == "PTR"
    )
    assert ptrs == [
        ("9.2.0.192.in-addr.arpa", "a.example.com"),
        ("9.3.0.192.in-addr.arpa", "b.example.com"),
    ]
    ns = [r for r in plan["records"] if r["type"] == "NS"]
    assert {r["name"] for r in ns} == {
        "2.0.192.in-addr.arpa",
        "3.0.192.in-addr.arpa",
    }


def test_reverse_dns_plan_is_read_only(client):
    pid = _create_pool(client, cidr="192.0.2.0/25")
    cidr = _allocate(client, pid, "small", 25)
    before = client.get(f"/pools/{pid}").json()
    _plan(
        client,
        pid,
        {
            "parent_zone": "2.0.192.in-addr.arpa",
            "entries": [
                {
                    "cidr": cidr,
                    "child_zone": "0-127",
                    "nameservers": ["ns1.example.com", "ns2.example.com"],
                }
            ],
        },
    )
    after = client.get(f"/pools/{pid}").json()
    assert after["allocated"] == before["allocated"]
    assert after["free_cidrs"] == before["free_cidrs"]


def test_reverse_dns_plan_rejects_out_of_bounds_subnet(client):
    pid = _create_pool(client, cidr="192.0.2.0/23")
    _allocate(client, pid, "a", 25)  # 192.0.2.0/25
    _allocate(client, pid, "b", 24)  # 192.0.3.0/24

    # /24 parent cannot cover the 192.0.3.0/24 allocation.
    resp = _plan(
        client,
        pid,
        {
            "parent_zone": "2.0.192.in-addr.arpa",
            "entries": [
                {"cidr": "192.0.2.0/25", "child_zone": "x",
                 "nameservers": ["ns1.example.com", "ns2.example.com"]},
                {"cidr": "192.0.3.0/24",
                 "nameservers": ["ns1.example.com", "ns2.example.com"]},
            ],
        },
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "reverse_outside_parent"


def test_reverse_dns_plan_rejects_parent_not_covering_pool(client):
    pid = _create_pool(client, cidr="192.0.2.0/23")
    _allocate(client, pid, "a", 24)
    resp = _plan(
        client,
        pid,
        {
            "parent_zone": "1.10.in-addr.arpa",
            "entries": [
                {"cidr": "192.0.2.0/24",
                 "nameservers": ["ns1.example.com", "ns2.example.com"]},
            ],
        },
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "reverse_parent_outside_pool"


def test_reverse_dns_plan_rejects_invalid_parent_zone(client):
    pid = _create_pool(client)
    _allocate(client, pid, "a", 24)
    for bad in ("example.com", "64.2.0.192.in-addr.arpa", "x.0.192.in-addr.arpa"):
        resp = _plan(
            client,
            pid,
            {
                "parent_zone": bad,
                "entries": [
                    {"cidr": "10.0.0.0/24",
                     "nameservers": ["ns1.example.com", "ns2.example.com"]},
                ],
            },
        )
        assert resp.status_code == 422, (bad, resp.text)
        assert resp.json()["error"]["code"] == "invalid_parent_zone"


def test_reverse_dns_plan_rejects_unknown_and_omitted_allocations(client):
    pid = _create_pool(client, cidr="192.0.2.0/24")
    _allocate(client, pid, "a", 25)  # 192.0.2.0/25

    # A CIDR that is not a current allocation is rejected.
    resp = _plan(
        client,
        pid,
        {
            "parent_zone": "2.0.192.in-addr.arpa",
            "entries": [
                {
                    "cidr": "192.0.2.128/25",
                    "child_zone": "128-255",
                    "nameservers": ["ns1.example.com", "ns2.example.com"],
                }
            ],
        },
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "reverse_not_allocated"

    # The real allocation on its own is accepted: every current allocation
    # must appear, and here there is exactly one.
    ok = _plan(
        client,
        pid,
        {
            "parent_zone": "2.0.192.in-addr.arpa",
            "entries": [
                {
                    "cidr": "192.0.2.0/25",
                    "child_zone": "0-127",
                    "nameservers": ["ns1.example.com", "ns2.example.com"],
                }
            ],
        },
    )
    assert ok.status_code == 200, ok.text


def test_reverse_dns_plan_rejects_duplicate_and_uncovered(client):
    pid = _create_pool(client, cidr="192.0.2.0/24")
    _allocate(client, pid, "a", 25)
    resp = _plan(
        client,
        pid,
        {
            "parent_zone": "2.0.192.in-addr.arpa",
            "entries": [
                {"cidr": "192.0.2.0/25", "child_zone": "z1",
                 "nameservers": ["ns1.example.com", "ns2.example.com"]},
                {"cidr": "192.0.2.0/25", "child_zone": "z2",
                 "nameservers": ["ns1.example.com", "ns2.example.com"]},
            ],
        },
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "reverse_duplicate_entry"


def test_reverse_dns_plan_rejects_omitted_allocation(client):
    pid = _create_pool(client, cidr="192.0.2.0/24")
    _allocate(client, pid, "a", 25)  # .0/25
    _allocate(client, pid, "b", 25)  # .128/25
    resp = _plan(
        client,
        pid,
        {
            "parent_zone": "2.0.192.in-addr.arpa",
            "entries": [
                {
                    "cidr": "192.0.2.0/25",
                    "child_zone": "0-127",
                    "nameservers": ["ns1.example.com", "ns2.example.com"],
                }
            ],
        },
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "reverse_allocation_omitted"

    # Covering both allocations succeeds.
    ok = _plan(
        client,
        pid,
        {
            "parent_zone": "2.0.192.in-addr.arpa",
            "entries": [
                {"cidr": "192.0.2.0/25", "child_zone": "0-127",
                 "nameservers": ["ns1.example.com", "ns2.example.com"]},
                {"cidr": "192.0.2.128/25", "child_zone": "128-255",
                 "nameservers": ["ns1.example.com", "ns2.example.com"]},
            ],
        },
    )
    assert ok.status_code == 200, ok.text


def test_reverse_dns_plan_rejects_too_few_nameservers(client):
    pid = _create_pool(client, cidr="192.0.2.0/24")
    cidr = _allocate(client, pid, "a", 25)
    resp = _plan(
        client,
        pid,
        {
            "parent_zone": "2.0.192.in-addr.arpa",
            "entries": [
                {"cidr": cidr, "child_zone": "z", "nameservers": ["only.ns.example"]},
            ],
        },
    )
    # Pydantic min_length=2 rejects a single nameserver before the service runs.
    assert resp.status_code == 422

    # Two equal servers normalise to one distinct server -> service rejects.
    resp = _plan(
        client,
        pid,
        {
            "parent_zone": "2.0.192.in-addr.arpa",
            "entries": [
                {
                    "cidr": cidr,
                    "child_zone": "z",
                    "nameservers": ["NS1.example.com", "ns1.example.com"],
                },
            ],
        },
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "nameserver_insufficient"


def test_reverse_dns_plan_rejects_child_zone_conflict(client):
    pid = _create_pool(client, cidr="192.0.2.0/24")
    _allocate(client, pid, "a", 26)  # .0/26
    _allocate(client, pid, "b", 26)  # .64/26
    resp = _plan(
        client,
        pid,
        {
            "parent_zone": "2.0.192.in-addr.arpa",
            "entries": [
                {"cidr": "192.0.2.0/26", "child_zone": "shared",
                 "nameservers": ["ns1.example.com", "ns2.example.com"]},
                {"cidr": "192.0.2.64/26", "child_zone": "shared",
                 "nameservers": ["ns1.example.com", "ns2.example.com"]},
            ],
        },
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "reverse_name_conflict"


def test_reverse_dns_plan_requires_child_zone_below_24(client):
    pid = _create_pool(client, cidr="192.0.2.0/24")
    cidr = _allocate(client, pid, "a", 26)
    resp = _plan(
        client,
        pid,
        {
            "parent_zone": "2.0.192.in-addr.arpa",
            "entries": [
                {"cidr": cidr, "nameservers": ["ns1.example.com", "ns2.example.com"]},
            ],
        },
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "missing_child_zone"


def test_reverse_dns_plan_rejects_ptr_outside_subnet(client):
    pid = _create_pool(client, cidr="192.0.2.0/24")
    cidr = _allocate(client, pid, "a", 26)
    resp = _plan(
        client,
        pid,
        {
            "parent_zone": "2.0.192.in-addr.arpa",
            "entries": [
                {
                    "cidr": cidr,
                    "child_zone": "z",
                    "nameservers": ["ns1.example.com", "ns2.example.com"],
                    "ptr": {"192.0.2.200": "host.example.com"},
                },
            ],
        },
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "invalid_ptr"


def test_reverse_dns_plan_no_allocations(client):
    pid = _create_pool(client, cidr="192.0.2.0/24")
    resp = _plan(
        client,
        pid,
        {
            "parent_zone": "2.0.192.in-addr.arpa",
            "entries": [
                {
                    "cidr": "192.0.2.0/25",
                    "child_zone": "z",
                    "nameservers": ["ns1.example.com", "ns2.example.com"],
                },
            ],
        },
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "reverse_no_allocations"


def test_reverse_dns_plan_pool_not_found(client):
    resp = _plan(
        client,
        999,
        {
            "parent_zone": "2.0.192.in-addr.arpa",
            "entries": [
                {
                    "cidr": "192.0.2.0/25",
                    "child_zone": "z",
                    "nameservers": ["ns1.example.com", "ns2.example.com"],
                },
            ],
        },
    )
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "pool_not_found"


def test_reverse_dns_plan_absolute_child_zone_and_order_independence(client):
    pid = _create_pool(client, cidr="192.0.2.0/24")
    _allocate(client, pid, "a", 26)  # .0/26
    _allocate(client, pid, "b", 26)  # .64/26
    common_servers = ["ns1.example.com", "ns2.example.com"]

    def build(first: str):
        entries = [
            {"cidr": "192.0.2.0/26", "child_zone": "0-63",
             "nameservers": common_servers},
            {"cidr": "192.0.2.64/26",
             "child_zone": "64-127.2.0.192.in-addr.arpa.",
             "nameservers": common_servers},
        ]
        if first == "b":
            entries.reverse()
        return _plan(
            client,
            pid,
            {"parent_zone": "2.0.192.in-addr.arpa", "entries": entries},
        )

    first = build("a").json()
    second = build("b").json()
    # Output order is determined by fragment address, not request order.
    assert first == second
    assert [d["cidr"] for d in first["delegations"]] == [
        "192.0.2.0/26",
        "192.0.2.64/26",
    ]
    assert first["delegations"][1]["child_zone"] == "64-127.2.0.192.in-addr.arpa"


# ---------------------------------------------------------------------------
# POST /cidr-policy/compile
# ---------------------------------------------------------------------------


def _compile(client, payload):
    return client.post("/cidr-policy/compile", json=payload)


def test_cidr_policy_compile_basic(client):
    resp = _compile(
        client,
        {
            "scope": "10.0.0.0/24",
            "default_action": "deny",
            "rules": [
                {"cidr": "10.0.0.0/26", "action": "allow"},
                {"cidr": "10.0.0.192/26", "action": "allow"},
            ],
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["scope"] == "10.0.0.0/24"
    assert body["default_action"] == "deny"
    assert body["segments"] == [
        {"cidr": "10.0.0.0/26", "action": "allow"},
        {"cidr": "10.0.0.64/26", "action": "deny"},
        {"cidr": "10.0.0.128/26", "action": "deny"},
        {"cidr": "10.0.0.192/26", "action": "allow"},
    ]


def test_cidr_policy_compile_empty_rules_uses_default(client):
    resp = _compile(client, {"scope": "10.0.0.0/22", "default_action": "allow", "rules": []})
    assert resp.status_code == 200, resp.text
    assert resp.json()["segments"] == [{"cidr": "10.0.0.0/22", "action": "allow"}]


def test_cidr_policy_compile_merges_equal_action_siblings(client):
    resp = _compile(
        client,
        {
            "scope": "10.0.0.0/24",
            "default_action": "deny",
            "rules": [
                {"cidr": "10.0.0.64/27", "action": "allow"},
                {"cidr": "10.0.0.96/27", "action": "allow"},
            ],
        },
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["segments"] == [
        {"cidr": "10.0.0.0/26", "action": "deny"},
        {"cidr": "10.0.0.64/26", "action": "allow"},
        {"cidr": "10.0.0.128/25", "action": "deny"},
    ]


def test_cidr_policy_compile_first_match_order(client):
    # Narrow /30 deny first wins inside it; the broader /26 allow applies to
    # the rest of the /26; everywhere else falls through to default deny.
    resp = _compile(
        client,
        {
            "scope": "10.0.0.0/24",
            "default_action": "deny",
            "rules": [
                {"cidr": "10.0.0.0/30", "action": "deny"},
                {"cidr": "10.0.0.0/26", "action": "allow"},
            ],
        },
    )
    assert resp.status_code == 200, resp.text
    segments = resp.json()["segments"]
    assert segments[0] == {"cidr": "10.0.0.0/30", "action": "deny"}
    assert {"cidr": "10.0.0.4/30", "action": "allow"} in segments
    assert {"cidr": "10.0.0.64/26", "action": "deny"} in segments


def test_cidr_policy_compile_is_read_only(client):
    pid = _create_pool(client, cidr="10.0.0.0/24")
    client.post(f"/pools/{pid}/allocations", json={"request_id": "a", "prefix_length": 27})
    before = client.get(f"/pools/{pid}").json()

    resp = _compile(
        client,
        {
            "scope": "10.0.0.0/24",
            "default_action": "deny",
            "rules": [{"cidr": "10.0.0.0/26", "action": "allow"}],
        },
    )
    assert resp.status_code == 200, resp.text
    after = client.get(f"/pools/{pid}").json()
    assert after == before
    # Pools are untouched as well.
    assert [p["id"] for p in client.get("/pools").json()] == [pid]


def test_cidr_policy_compile_invalid_scope(client):
    resp = _compile(
        client,
        {"scope": "10.0.0.5/24", "default_action": "deny", "rules": []},
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "invalid_cidr"


def test_cidr_policy_compile_invalid_rule_cidr(client):
    resp = _compile(
        client,
        {
            "scope": "10.0.0.0/24",
            "default_action": "deny",
            "rules": [{"cidr": "not-a-cidr", "action": "allow"}],
        },
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "invalid_cidr"


def test_cidr_policy_compile_rule_outside_scope(client):
    resp = _compile(
        client,
        {
            "scope": "10.0.0.0/24",
            "default_action": "deny",
            "rules": [{"cidr": "10.1.0.0/24", "action": "allow"}],
        },
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "rule_outside_scope"


def test_cidr_policy_compile_bad_action_rejected(client):
    resp = _compile(
        client,
        {
            "scope": "10.0.0.0/24",
            "default_action": "permit",
            "rules": [],
        },
    )
    assert resp.status_code == 422

    resp = _compile(
        client,
        {
            "scope": "10.0.0.0/24",
            "default_action": "deny",
            "rules": [{"cidr": "10.0.0.0/26", "action": "block"}],
        },
    )
    assert resp.status_code == 422
