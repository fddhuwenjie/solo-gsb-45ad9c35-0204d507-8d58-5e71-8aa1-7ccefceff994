"""Unit tests for RFC 2317 reverse-zone name arithmetic and record building."""

from __future__ import annotations

import ipaddress

import pytest

from app.cidrmath import parse_network
from app.reversedns import (
    ReverseDnsError,
    direct_records,
    enclosing_24_name,
    parse_parent_zone,
    pointer_name,
    resolve_tag_zone,
    reverse_zone_name,
    rfc2317_records,
    validate_hostname,
)


def n(value: str):
    return parse_network(value)


@pytest.mark.parametrize(
    "raw,cidr,name",
    [
        ("2.0.192.in-addr.arpa", "192.0.2.0/24", "2.0.192.in-addr.arpa"),
        ("2.0.192.in-addr.arpa.", "192.0.2.0/24", "2.0.192.in-addr.arpa"),
        ("0.192.in-addr.arpa", "192.0.0.0/16", "0.192.in-addr.arpa"),
        ("10.in-addr.arpa", "10.0.0.0/8", "10.in-addr.arpa"),
    ],
)
def test_parse_parent_zone(raw, cidr, name):
    network, zone = parse_parent_zone(raw)
    assert network == n(cidr)
    assert zone == name


@pytest.mark.parametrize(
    "raw",
    [
        "example.com",
        "in-addr.arpa",
        "2.0.192.in-addr.arpa.com",
        "3.2.0.192.in-addr.arpa",  # four octet labels = /32, not a zone
        "64.2.0.192.in-addr.arpa",  # /32 name
        "x.0.192.in-addr.arpa",
        "300.0.192.in-addr.arpa",
        "",
    ],
)
def test_parse_parent_zone_rejects_invalid(raw):
    with pytest.raises(ReverseDnsError) as exc:
        parse_parent_zone(raw)
    assert exc.value.code == "invalid_parent_zone"


def test_reverse_zone_and_pointer_names():
    assert reverse_zone_name(n("192.0.2.0/24")) == "2.0.192.in-addr.arpa"
    assert reverse_zone_name(n("192.0.0.0/16")) == "0.192.in-addr.arpa"
    assert reverse_zone_name(n("10.0.0.0/8")) == "10.in-addr.arpa"
    assert enclosing_24_name(n("192.0.2.64/26")) == "2.0.192.in-addr.arpa"
    assert (
        pointer_name(ipaddress.ip_address("192.0.2.5"))
        == "5.2.0.192.in-addr.arpa"
    )


def test_resolve_tag_zone_relative_and_absolute():
    enclosing = "2.0.192.in-addr.arpa"
    assert (
        resolve_tag_zone("64-127", enclosing)
        == "64-127.2.0.192.in-addr.arpa"
    )
    assert (
        resolve_tag_zone("ns.64-127.2.0.192.in-addr.arpa.", enclosing)
        == "ns.64-127.2.0.192.in-addr.arpa"
    )


@pytest.mark.parametrize(
    "raw",
    ["", "..", "-bad", "bad-", "x.3.0.192.in-addr.arpa", "2.0.192.in-addr.arpa"],
)
def test_resolve_tag_zone_rejects_invalid(raw):
    with pytest.raises(ReverseDnsError) as exc:
        resolve_tag_zone(raw, "2.0.192.in-addr.arpa")
    assert exc.value.code == "invalid_child_zone"


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("NS1.Example.COM.", "ns1.example.com"),
        ("a.b.example", "a.b.example"),
    ],
)
def test_validate_hostname_normalises(raw, expected):
    assert validate_hostname(raw) == expected


@pytest.mark.parametrize(
    "raw",
    ["nodot", "ns..example.com", "1234", "ns.example.123", "-x.example.com", ""],
)
def test_validate_hostname_rejects_invalid(raw):
    with pytest.raises(ReverseDnsError):
        validate_hostname(raw)


def test_rfc2317_records_for_26():
    fragment = n("192.0.2.64/26")
    records = rfc2317_records(
        fragment,
        "64-127.2.0.192.in-addr.arpa",
        ["ns2.example.com", "ns1.example.com"],
        {"192.0.2.65": "host1.example.com"},
    )
    # Two NS records, sorted by target, come first.
    assert records[0] == {
        "type": "NS",
        "name": "64-127.2.0.192.in-addr.arpa",
        "target": "ns1.example.com",
    }
    assert records[1] == {
        "type": "NS",
        "name": "64-127.2.0.192.in-addr.arpa",
        "target": "ns2.example.com",
    }
    cnames = [r for r in records if r["type"] == "CNAME"]
    assert len(cnames) == 64  # every address 64..127
    assert cnames[0] == {
        "type": "CNAME",
        "name": "64.2.0.192.in-addr.arpa",
        "target": "64.64-127.2.0.192.in-addr.arpa",
    }
    assert cnames[-1] == {
        "type": "CNAME",
        "name": "127.2.0.192.in-addr.arpa",
        "target": "127.64-127.2.0.192.in-addr.arpa",
    }
    # PTR lives inside the tagged zone.
    assert [r for r in records if r["type"] == "PTR"] == [
        {
            "type": "PTR",
            "name": "65.64-127.2.0.192.in-addr.arpa",
            "target": "host1.example.com",
        }
    ]


def test_rfc2317_records_for_32_emits_single_cname():
    fragment = n("192.0.2.7/32")
    records = rfc2317_records(
        fragment, "7.2.0.192.in-addr.arpa", ["a.ns.example", "b.ns.example"], {}
    )
    cnames = [r for r in records if r["type"] == "CNAME"]
    assert len(cnames) == 1
    assert cnames[0]["name"] == "7.2.0.192.in-addr.arpa"
    assert cnames[0]["target"] == "7.7.2.0.192.in-addr.arpa"


def test_rfc2317_records_are_deterministic():
    fragment = n("192.0.2.0/28")
    args = (fragment, "0-15.2.0.192.in-addr.arpa",
            ["ns2.example", "ns1.example"], {})
    assert rfc2317_records(*args) == rfc2317_records(*args)


def test_direct_records_for_whole_zone():
    records = direct_records(
        "2.0.192.in-addr.arpa",
        ["b.ns.example", "a.ns.example"],
        {"192.0.2.9": "h.example.com"},
    )
    assert records[0] == {
        "type": "NS",
        "name": "2.0.192.in-addr.arpa",
        "target": "a.ns.example",
    }
    assert records[1] == {
        "type": "NS",
        "name": "2.0.192.in-addr.arpa",
        "target": "b.ns.example",
    }
    assert records[-1] == {
        "type": "PTR",
        "name": "9.2.0.192.in-addr.arpa",
        "target": "h.example.com",
    }
