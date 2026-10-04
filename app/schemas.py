"""Pydantic request/response models."""

from __future__ import annotations

from typing import Annotated, Literal, Union

from pydantic import BaseModel, Field

from .bgpaudit import MAX_ASN

# Snapshot format version.  Only version 1 is understood by this service.
SNAPSHOT_VERSION = 1

# Only SHA-256 digests are produced or accepted; exported verbatim in the
# snapshot document's ``digest_algorithm`` field.
DIGEST_ALGORITHM = "SHA-256"


class PoolCreateRequest(BaseModel):
    cidr: str = Field(..., description="Pool network, e.g. 10.0.0.0/16")
    exclusions: list[str] = Field(
        default_factory=list,
        description="CIDRs inside the pool that must never be allocated",
    )


class PoolResponse(BaseModel):
    id: int
    cidr: str
    exclusions: list[str]
    created_at: str


class ExclusionCreateRequest(BaseModel):
    cidr: str


class ExclusionResponse(BaseModel):
    id: int
    excluded: str


class AllocateRequest(BaseModel):
    request_id: str = Field(..., min_length=1, description="Client-generated idempotency key")
    prefix_length: int = Field(..., ge=0, le=32)


class AllocationResponse(BaseModel):
    id: int
    pool_id: int
    cidr: str
    request_id: str
    prefix_length: int
    created_at: str
    replayed: bool


class ReleaseResponse(BaseModel):
    released: str
    request_id: str
    pool_id: int


class AllocationItem(BaseModel):
    cidr: str
    request_id: str
    prefix_length: int
    created_at: str


class PoolStatusResponse(BaseModel):
    id: int
    cidr: str
    exclusions: list[str]
    allocated: list[AllocationItem]
    free_cidrs: list[str]
    free_addresses: int


class ReverseDnsEntryRequest(BaseModel):
    cidr: str = Field(..., description="An existing allocation, e.g. 192.0.2.64/26")
    child_zone: str | None = Field(
        default=None,
        description=(
            "RFC 2317 tagged zone name for a subnet smaller than /24; either a "
            "single label (relative to the enclosing /24) or an absolute name. "
            "Ignored for octet-aligned whole-zone delegations."
        ),
    )
    nameservers: list[str] = Field(
        ...,
        min_length=2,
        description=(
            "Authoritative server FQDNs (at least two); duplicates are "
            "ignored after normalisation, so two identical names still fails"
        ),
    )
    ptr: dict[str, str] = Field(
        default_factory=dict,
        description="Optional address -> hostname PTR records for this subnet",
    )


class ReverseDnsPlanRequest(BaseModel):
    parent_zone: str = Field(
        ...,
        description="Octet-aligned parent reverse zone, e.g. 2.0.192.in-addr.arpa",
    )
    entries: list[ReverseDnsEntryRequest] = Field(..., min_length=1)


class DnsRecord(BaseModel):
    type: str
    name: str
    target: str


class DelegationFragmentResponse(BaseModel):
    cidr: str = Field(..., description="The fragment this delegation covers")
    source_cidr: str = Field(..., description="The allocation that produced it")
    mode: str = Field(..., description="'rfc2317' for tagged zones, 'direct' otherwise")
    enclosing_zone: str = Field(
        ...,
        description="Reverse zone that must host the NS/CNAME records",
    )
    child_zone: str | None = Field(
        default=None,
        description="Delegated zone name (RFC 2317 tag, or the whole zone itself)",
    )
    nameservers: list[str]


class ReverseDnsPlanResponse(BaseModel):
    pool_id: int
    parent_zone: str
    delegations: list[DelegationFragmentResponse]
    records: list[DnsRecord] = Field(
        ...,
        description="All NS, CNAME and PTR records in deterministic order",
    )


class CidrPolicyRuleRequest(BaseModel):
    cidr: str = Field(
        ...,
        min_length=1,
        description="IPv4 CIDR contained in the policy scope, e.g. 10.0.0.0/24",
    )
    action: Literal["allow", "deny"]


class CidrPolicyCompileRequest(BaseModel):
    scope: str = Field(
        ...,
        min_length=1,
        description="IPv4 CIDR the policy is compiled over, e.g. 10.0.0.0/16",
    )
    default_action: Literal["allow", "deny"]
    rules: list[CidrPolicyRuleRequest] = Field(
        default_factory=list,
        description=(
            "Priority-ordered rules; the first rule whose CIDR contains an "
            "address decides its action. Rules may overlap."
        ),
    )


class CidrPolicySegment(BaseModel):
    cidr: str
    action: Literal["allow", "deny"]


class CidrPolicyCompileResponse(BaseModel):
    scope: str
    default_action: Literal["allow", "deny"]
    segments: list[CidrPolicySegment] = Field(
        ...,
        description=(
            "Non-overlapping CIDR segments covering the whole scope, ordered "
            "by network address"
        ),
    )


# ---------------------------------------------------------------------------
# Policy-gated batch reservations
# ---------------------------------------------------------------------------


class ReservationItemRequest(BaseModel):
    request_id: str = Field(
        ..., min_length=1, description="Client-generated idempotency key"
    )
    prefix_length: int = Field(..., ge=0, le=32)


class BatchReserveRequest(BaseModel):
    batch_id: str = Field(
        ...,
        min_length=1,
        description="Client-generated idempotency key for the whole batch",
    )
    default_action: Literal["allow", "deny"] = Field(
        ...,
        description="Action for pool addresses matched by no rule",
    )
    rules: list[CidrPolicyRuleRequest] = Field(
        default_factory=list,
        description=(
            "Priority-ordered allow/deny rules compiled over the pool CIDR; "
            "the first rule containing an address decides its action"
        ),
    )
    items: list[ReservationItemRequest] = Field(
        ...,
        min_length=1,
        description="Reservations to place, processed in input order",
    )


class ReservationItemResponse(BaseModel):
    request_id: str
    prefix_length: int
    cidr: str
    allocation_id: int = Field(..., description="Row id of the allocation")
    replayed: bool = Field(
        ...,
        description="True when request_id matched an existing allocation",
    )


class BatchReserveResponse(BaseModel):
    batch_id: str
    pool_id: int
    reservations: list[ReservationItemResponse] = Field(
        ..., description="request_id -> reserved CIDR mapping, in input order"
    )
    created_at: str
    replayed: bool = Field(
        ..., description="True when a stored batch result was returned"
    )


# ---------------------------------------------------------------------------
# Pool snapshot export / restore
# ---------------------------------------------------------------------------


class SnapshotPool(BaseModel):
    id: int
    cidr: str = Field(..., min_length=1)
    created_at: str = Field(..., min_length=1)


class SnapshotExclusion(BaseModel):
    id: int = Field(..., ge=1, description="Database row id, preserved on restore")
    pool_id: int = Field(
        ..., ge=1, description="Owning pool; must equal the pool in the URL"
    )
    cidr: str = Field(..., min_length=1)
    created_at: str = Field(..., min_length=1)


class SnapshotAllocation(BaseModel):
    id: int = Field(..., ge=1, description="Database row id, preserved on restore")
    pool_id: int = Field(
        ..., ge=1, description="Owning pool; must equal the pool in the URL"
    )
    cidr: str = Field(..., min_length=1)
    request_id: str = Field(..., min_length=1)
    prefix_length: int = Field(..., ge=0, le=32)
    created_at: str = Field(..., min_length=1)


class SnapshotDocument(BaseModel):
    """Canonical, verifiable export of one pool's full state."""

    version: Literal[SNAPSHOT_VERSION]
    digest_algorithm: Literal[DIGEST_ALGORITHM]
    pool: SnapshotPool
    exclusions: list[SnapshotExclusion]
    allocations: list[SnapshotAllocation]


class RestoreRequest(BaseModel):
    restore_id: str = Field(
        ...,
        min_length=1,
        description="Client-generated idempotency key for the restore operation",
    )
    digest: str = Field(
        ...,
        min_length=1,
        description="SHA-256 hex digest of the canonical snapshot document",
    )
    snapshot: SnapshotDocument


class SnapshotResponse(BaseModel):
    pool_id: int
    digest: str = Field(..., description="SHA-256 hex of the canonical snapshot bytes")
    snapshot: SnapshotDocument


class RestoreResponse(BaseModel):
    restore_id: str
    pool_id: int
    digest: str
    replayed: bool
    replaced: bool = Field(
        ...,
        description="True when pool state was replaced; false on an idempotent replay",
    )


# ---------------------------------------------------------------------------
# Pool partition migration
# ---------------------------------------------------------------------------


class PartitionRequest(BaseModel):
    operation_id: str = Field(
        ...,
        min_length=1,
        description="Client-generated idempotency key for the partition operation",
    )
    subnets: list[str] = Field(
        ...,
        min_length=1,
        description=(
            "New sub-pool CIDRs: pairwise non-overlapping and exactly "
            "covering the source pool"
        ),
    )


class SubPoolMapping(BaseModel):
    pool_id: int = Field(..., description="Id of the newly created sub-pool")
    cidr: str = Field(..., description="CIDR now owned by this sub-pool")


class PartitionResponse(BaseModel):
    operation_id: str
    migration_id: int = Field(..., description="Migration record id")
    source_pool_id: int
    source_cidr: str
    sub_pools: list[SubPoolMapping] = Field(
        ...,
        description=(
            "Mapping from the retired source pool to its replacement "
            "sub-pools, ordered by network address"
        ),
    )
    created_at: str
    replayed: bool


# ---------------------------------------------------------------------------
# Stateless BGP announcement auditing
# ---------------------------------------------------------------------------

# 32-bit AS number.  AS 0 (reserved) and AS 4294967295 (AS_TRANS/reserved) are
# outside this range and rejected at request validation.
Asn = Annotated[int, Field(ge=1, le=MAX_ASN - 1)]


class CustomerProviderRelation(BaseModel):
    """Transit relationship: ``customer`` buys connectivity from ``provider``."""

    type: Literal["customer_provider"]
    customer: Asn
    provider: Asn


class PeerRelation(BaseModel):
    a: Asn
    b: Asn
    type: Literal["peer"] = "peer"


AsRelation = Annotated[
    Union[CustomerProviderRelation, PeerRelation],
    Field(discriminator="type"),
]


class BgpAnnouncement(BaseModel):
    id: str = Field(..., min_length=1, description="Unique id within this request")
    prefix: str = Field(
        ...,
        min_length=1,
        description="Strict IPv4 CIDR, e.g. 203.0.113.0/24",
    )
    as_path: list[Asn] = Field(
        ...,
        min_length=1,
        description="ASNs from the vantage point toward the origin",
    )


class BgpAuditRequest(BaseModel):
    relationships: list[AsRelation] = Field(
        default_factory=list,
        description=(
            "AS relationships used to validate every adjacent AS_PATH pair"
        ),
    )
    announcements: list[BgpAnnouncement] = Field(
        ...,
        min_length=1,
        description="Batch of announcements to audit; ids must be unique",
    )


class ViolatingHop(BaseModel):
    hop: int = Field(
        ...,
        description=(
            "Zero-based index of the first violating hop in the folded path, "
            "i.e. the edge as_path[hop] -> as_path[hop + 1]"
        ),
    )
    from_asn: Asn
    to_asn: Asn


class BgpAuditResult(BaseModel):
    id: str
    prefix: str
    as_path: list[Asn] = Field(
        ...,
        description="The folded path (consecutive duplicate ASNs collapsed)"
    )
    origin: Asn = Field(..., description="Last ASN of the folded path")
    status: Literal["valid", "as_loop", "invalid_path"]
    flags: list[Literal["moas", "origin_change"]] = Field(
        ...,
        description="Comparison flags; only announcements with status 'valid' "
        "are compared, so other statuses always carry an empty list",
    )
    violating_hop: ViolatingHop | None = Field(
        default=None,
        description="First hop breaking the customer-provider/peer shape; "
        "set only when status is 'invalid_path'",
    )


class BgpAuditResponse(BaseModel):
    results: list[BgpAuditResult] = Field(
        ...,
        description=(
            "Sorted by network address, then prefix length, then announcement id"
        ),
    )


# ---------------------------------------------------------------------------
# Confirmable BGP announcement plans
# ---------------------------------------------------------------------------


class BgpPlanCreateRequest(BaseModel):
    plan_id: str = Field(
        ...,
        min_length=1,
        description="Client-generated idempotency key for the announcement plan",
    )
    relationships: list[AsRelation] = Field(
        default_factory=list,
        description="AS relationships used to audit every announcement path",
    )
    announcements: list[BgpAnnouncement] = Field(
        ...,
        min_length=1,
        description="Announcements the network team intends to publish; ids unique",
    )


class BgpPlanAllocationState(BaseModel):
    cidr: str
    request_id: str
    prefix_length: int
    created_at: str


class BgpPlanPoolState(BaseModel):
    """Immutable summary of the pool state the plan was pinned against."""

    cidr: str
    exclusions: list[str] = Field(
        ..., description="Exclusion CIDRs, sorted by numeric network address"
    )
    allocations: list[BgpPlanAllocationState] = Field(
        ..., description="Current allocations, sorted by numeric network address"
    )


class BgpPlanResponse(BaseModel):
    plan_id: str
    pool_id: int
    status: Literal["planned", "active"]
    results: list[BgpAuditResult] = Field(
        ...,
        description="Audit results produced at creation time and stored with the plan"
    )
    state_digest: str = Field(
        ...,
        description=(
            "SHA-256 hex digest of the canonical pool-state summary "
            "(pool CIDR, exclusions, allocations) fixed at creation"
        ),
    )
    pool_state: BgpPlanPoolState
    created_at: str
    activated_at: str | None = None
    replayed: bool = Field(
        ...,
        description="True when a stored plan was returned instead of creating one",
    )
