"""API integration tests for POST /bgp/announcements/audit."""

from __future__ import annotations


def _audit(client, body):
    return client.post("/bgp/announcements/audit", json=body)


# Relationships reused across tests:
#   10/20 are customers of 100; 100 peers 50; 60 is a customer of 50;
#   70 is a provider of 50 (so 50->70 is customer->provider, an "up" edge).
RELATIONSHIPS = [
    {"type": "customer_provider", "customer": 10, "provider": 100},
    {"type": "customer_provider", "customer": 20, "provider": 100},
    {"type": "peer", "a": 100, "b": 50},
    {"type": "customer_provider", "customer": 60, "provider": 50},
    {"type": "customer_provider", "customer": 50, "provider": 70},
]


def test_audit_valid_paths(client):
    resp = _audit(
        client,
        {
            "relationships": [
                {"type": "customer_provider", "customer": 10, "provider": 100},
                {"type": "peer", "a": 100, "b": 50},
                {"type": "customer_provider", "customer": 60, "provider": 50},
            ],
            "announcements": [
                {"id": "a", "prefix": "203.0.113.0/24", "as_path": [10, 10, 100]},
                {"id": "b", "prefix": "198.51.100.0/24", "as_path": [100, 50, 60]},
            ],
        },
    )
    assert resp.status_code == 200, resp.text
    results = {r["id"]: r for r in resp.json()["results"]}
    assert results["a"]["as_path"] == [10, 100]
    assert results["a"]["origin"] == 100
    assert results["a"]["status"] == "valid"
    assert results["a"]["violating_hop"] is None
    assert results["b"]["status"] == "valid"


def test_audit_as_loop(client):
    resp = _audit(
        client,
        {
            "relationships": RELATIONSHIPS,
            "announcements": [
                {"id": "a", "prefix": "203.0.113.0/24", "as_path": [10, 100, 100, 10]}
            ],
        },
    )
    assert resp.status_code == 200, resp.text
    result = resp.json()["results"][0]
    assert result["as_path"] == [10, 100, 10]
    assert result["status"] == "as_loop"
    assert result["flags"] == []
    assert result["violating_hop"] is None


def test_audit_invalid_path_locates_hop(client):
    resp = _audit(
        client,
        {
            "relationships": RELATIONSHIPS,
            "announcements": [
                # 100->50 peer then 50->70 up: first violation at hop 1.
                {"id": "a", "prefix": "203.0.113.0/24", "as_path": [100, 50, 70]}
            ],
        },
    )
    assert resp.status_code == 200, resp.text
    result = resp.json()["results"][0]
    assert result["status"] == "invalid_path"
    assert result["violating_hop"] == {"hop": 1, "from_asn": 50, "to_asn": 70}


def test_audit_unknown_relationship_is_422(client):
    resp = _audit(
        client,
        {
            "relationships": [
                {"type": "customer_provider", "customer": 10, "provider": 100}
            ],
            "announcements": [
                {"id": "a", "prefix": "203.0.113.0/24", "as_path": [10, 100, 999]}
            ],
        },
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "as_relation_unknown"


def test_audit_conflicting_relationship_is_422(client):
    resp = _audit(
        client,
        {
            "relationships": [
                {"type": "peer", "a": 100, "b": 50},
                {"type": "customer_provider", "customer": 100, "provider": 50},
            ],
            "announcements": [
                {"id": "a", "prefix": "203.0.113.0/24", "as_path": [100, 50]}
            ],
        },
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "as_relation_conflict"


def test_audit_self_relationship_is_422(client):
    for rel in (
        {"type": "peer", "a": 100, "b": 100},
        {"type": "customer_provider", "customer": 100, "provider": 100},
    ):
        resp = _audit(
            client,
            {
                "relationships": [rel],
                "announcements": [
                    {"id": "a", "prefix": "203.0.113.0/24", "as_path": [100]}
                ],
            },
        )
        assert resp.status_code == 422, (rel, resp.text)
        assert resp.json()["error"]["code"] == "invalid_as_relation"


def test_audit_invalid_prefix_is_422(client):
    resp = _audit(
        client,
        {
            "relationships": [],
            "announcements": [
                {"id": "a", "prefix": "203.0.113.5/24", "as_path": [100]}
            ],
        },
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "invalid_prefix"


def test_audit_ipv6_prefix_is_422(client):
    resp = _audit(
        client,
        {
            "relationships": [],
            "announcements": [
                {"id": "a", "prefix": "2001:db8::/32", "as_path": [100]}
            ],
        },
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "invalid_prefix"


def test_audit_duplicate_id_is_422(client):
    resp = _audit(
        client,
        {
            "relationships": [{"type": "peer", "a": 100, "b": 50}],
            "announcements": [
                {"id": "x", "prefix": "203.0.113.0/24", "as_path": [100, 50]},
                {"id": "x", "prefix": "203.0.113.1/32", "as_path": [100]},
            ],
        },
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "duplicate_announcement_id"


def test_audit_request_validation_failures(client):
    # ASN 0 is outside 1..4294967294.
    resp = _audit(
        client,
        {
            "relationships": [],
            "announcements": [
                {"id": "a", "prefix": "203.0.113.0/24", "as_path": [0]}
            ],
        },
    )
    assert resp.status_code == 422

    # Empty as_path.
    resp = _audit(
        client,
        {
            "relationships": [],
            "announcements": [
                {"id": "a", "prefix": "203.0.113.0/24", "as_path": []}
            ],
        },
    )
    assert resp.status_code == 422

    # Unknown discriminator value.
    resp = _audit(
        client,
        {
            "relationships": [{"type": "sibling", "a": 1, "b": 2}],
            "announcements": [
                {"id": "a", "prefix": "203.0.113.0/24", "as_path": [1]}
            ],
        },
    )
    assert resp.status_code == 422


def test_audit_moas_and_origin_change_flags(client):
    # m1 and m2 announce the exact prefix from different origins (MOAS); the
    # /25 origin 60 differs from the /24 origins and is an origin_change.
    resp = _audit(
        client,
        {
            "relationships": RELATIONSHIPS,
            "announcements": [
                {"id": "m1", "prefix": "203.0.113.0/24", "as_path": [10, 100]},
                {"id": "m2", "prefix": "203.0.113.0/24", "as_path": [50]},
                {"id": "spec", "prefix": "203.0.113.128/25", "as_path": [100, 50, 60]},
            ],
        },
    )
    assert resp.status_code == 200, resp.text
    by_id = {r["id"]: r for r in resp.json()["results"]}
    assert by_id["m1"]["flags"] == ["moas"]
    assert by_id["m2"]["flags"] == ["moas"]
    assert by_id["spec"]["flags"] == ["origin_change"]


def test_audit_same_origin_duplicate_is_not_moas(client):
    resp = _audit(
        client,
        {
            "relationships": RELATIONSHIPS,
            "announcements": [
                {"id": "m1", "prefix": "203.0.113.0/24", "as_path": [10, 100]},
                {"id": "m2", "prefix": "203.0.113.0/24", "as_path": [20, 100]},
            ],
        },
    )
    assert resp.status_code == 200, resp.text
    assert all(r["flags"] == [] for r in resp.json()["results"])


def test_audit_results_are_sorted(client):
    resp = _audit(
        client,
        {
            "relationships": [],
            "announcements": [
                {"id": "z", "prefix": "10.0.1.0/24", "as_path": [1]},
                {"id": "a", "prefix": "10.0.0.0/24", "as_path": [1]},
                {"id": "a2", "prefix": "10.0.0.0/24", "as_path": [2]},
            ],
        },
    )
    assert resp.status_code == 200, resp.text
    assert [(r["prefix"], r["id"]) for r in resp.json()["results"]] == [
        ("10.0.0.0/24", "a"),
        ("10.0.0.0/24", "a2"),
        ("10.0.1.0/24", "z"),
    ]


def test_audit_does_not_touch_existing_pools(client):
    # A pool created before the audit must be byte-for-byte identical after it.
    create = client.post(
        "/pools",
        json={"cidr": "10.0.0.0/24", "exclusions": []},
    )
    assert create.status_code == 201
    pid = create.json()["id"]
    before = client.get(f"/pools/{pid}").json()

    resp = _audit(
        client,
        {
            "relationships": [{"type": "peer", "a": 100, "b": 50}],
            "announcements": [
                {"id": "a", "prefix": "203.0.113.0/24", "as_path": [100, 50]}
            ],
        },
    )
    assert resp.status_code == 200, resp.text

    after = client.get(f"/pools/{pid}").json()
    assert after == before
