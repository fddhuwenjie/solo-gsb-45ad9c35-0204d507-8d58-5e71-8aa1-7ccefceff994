"""FastAPI application entrypoint.

Run locally:
    uvicorn app.main:app --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from . import bgpplan, partition, reserve, service, snapshot
from .db import init_db
from .schemas import (
    AllocateRequest,
    AllocationResponse,
    AllocationItem,
    BatchReserveRequest,
    BatchReserveResponse,
    BgpAuditRequest,
    BgpAuditResponse,
    BgpPlanCreateRequest,
    BgpPlanResponse,
    CidrPolicyCompileRequest,
    CidrPolicyCompileResponse,
    ExclusionCreateRequest,
    ExclusionResponse,
    PartitionRequest,
    PartitionResponse,
    PoolCreateRequest,
    PoolResponse,
    PoolStatusResponse,
    ReleaseResponse,
    RestoreRequest,
    RestoreResponse,
    ReverseDnsPlanRequest,
    ReverseDnsPlanResponse,
    SnapshotResponse,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="IPv4 Subnet Allocation API",
    version="1.5.0",
    description=(
        "Allocate non-overlapping, aligned IPv4 subnets from address pools, "
        "reserve policy-gated batches of subnets atomically, "
        "partition pools into exactly covering sub-pools, "
        "build RFC 2317 reverse-DNS delegation plans for current allocations, "
        "statelessly audit BGP announcements against AS relationships, "
        "and record confirmable BGP announcement plans pinned to pool state."
    ),
    lifespan=lifespan,
)


@app.exception_handler(service.ApiError)
async def api_error_handler(request: Request, exc: service.ApiError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": {"code": exc.code, "detail": exc.detail}},
    )


@app.get("/health", tags=["meta"])
def health() -> dict:
    return {"status": "ok"}


@app.post(
    "/cidr-policy/compile",
    response_model=CidrPolicyCompileResponse,
    tags=["cidr-policy"],
)
def compile_cidr_policy(body: CidrPolicyCompileRequest) -> CidrPolicyCompileResponse:
    result = service.compile_cidr_policy(body.scope, body.default_action, body.rules)
    return CidrPolicyCompileResponse(**result)


@app.post(
    "/bgp/announcements/audit",
    response_model=BgpAuditResponse,
    tags=["bgp"],
)
def audit_bgp_announcements(body: BgpAuditRequest) -> BgpAuditResponse:
    result = service.audit_bgp_announcements(body.relationships, body.announcements)
    return BgpAuditResponse(**result)


@app.post(
    "/pools/{pool_id}/bgp-plans",
    response_model=BgpPlanResponse,
    status_code=201,
    tags=["bgp"],
)
def create_bgp_plan(pool_id: int, body: BgpPlanCreateRequest, response: Response) -> BgpPlanResponse:
    result = bgpplan.create_bgp_plan(
        pool_id, body.plan_id, body.relationships, body.announcements
    )
    # 201 for a newly stored plan, 200 for an idempotent replay.
    response.status_code = 200 if result["replayed"] else 201
    return BgpPlanResponse(**result)


@app.post(
    "/pools/{pool_id}/bgp-plans/{plan_id}/activate",
    response_model=BgpPlanResponse,
    tags=["bgp"],
)
def activate_bgp_plan(pool_id: int, plan_id: str) -> BgpPlanResponse:
    result = bgpplan.activate_bgp_plan(pool_id, plan_id)
    return BgpPlanResponse(**result)


@app.post("/pools", response_model=PoolResponse, status_code=201, tags=["pools"])
def create_pool(body: PoolCreateRequest) -> PoolResponse:
    result = service.create_pool(body.cidr, body.exclusions)
    return PoolResponse(**result)


@app.get("/pools", tags=["pools"])
def list_pools() -> list[dict]:
    return service.list_pools()


@app.get("/pools/{pool_id}", response_model=PoolStatusResponse, tags=["pools"])
def get_pool(pool_id: int) -> PoolStatusResponse:
    return PoolStatusResponse(**service.pool_status(pool_id))


@app.post(
    "/pools/{pool_id}/exclusions",
    response_model=ExclusionResponse,
    status_code=201,
    tags=["pools"],
)
def add_exclusion(pool_id: int, body: ExclusionCreateRequest) -> ExclusionResponse:
    return ExclusionResponse(**service.add_exclusion(pool_id, body.cidr))


@app.post(
    "/pools/{pool_id}/partitions",
    response_model=PartitionResponse,
    status_code=201,
    tags=["pools"],
)
def partition_pool(pool_id: int, body: PartitionRequest) -> PartitionResponse:
    result = partition.partition_pool(pool_id, body.operation_id, body.subnets)
    return PartitionResponse(**result)


@app.post(
    "/pools/{pool_id}/allocations",
    response_model=AllocationResponse,
    status_code=201,
    tags=["allocations"],
)
def allocate(pool_id: int, body: AllocateRequest) -> AllocationResponse:
    result = service.allocate(pool_id, body.request_id, body.prefix_length)
    return AllocationResponse(**result)


@app.delete(
    "/pools/{pool_id}/allocations/{request_id}",
    response_model=ReleaseResponse,
    tags=["allocations"],
)
def release(pool_id: int, request_id: str) -> ReleaseResponse:
    return ReleaseResponse(**service.release(pool_id, request_id))


@app.post(
    "/pools/{pool_id}/reservations",
    response_model=BatchReserveResponse,
    status_code=201,
    tags=["reservations"],
)
def reserve_batch(pool_id: int, body: BatchReserveRequest, response: Response) -> BatchReserveResponse:
    result = reserve.reserve_batch(
        pool_id, body.batch_id, body.default_action, body.rules, body.items
    )
    # 201 for a newly recorded batch, 200 for an idempotent replay.
    response.status_code = 200 if result["replayed"] else 201
    return BatchReserveResponse(**result)


@app.post(
    "/pools/{pool_id}/reverse-dns-plan",
    response_model=ReverseDnsPlanResponse,
    tags=["reverse-dns"],
)
def reverse_dns_plan(
    pool_id: int, body: ReverseDnsPlanRequest
) -> ReverseDnsPlanResponse:
    result = service.reverse_dns_plan(pool_id, body.parent_zone, body.entries)
    return ReverseDnsPlanResponse(**result)


@app.get(
    "/pools/{pool_id}/snapshot",
    response_model=SnapshotResponse,
    tags=["snapshots"],
)
def get_pool_snapshot(pool_id: int, response: Response) -> SnapshotResponse:
    result = snapshot.get_snapshot(pool_id)
    # RFC 3230: Digest: sha-256=<base64>; mirrors the hex digest in the body.
    response.headers["Digest"] = snapshot.digest_header(result["digest"])
    return SnapshotResponse(**result)


@app.post(
    "/pools/{pool_id}/snapshot/restore",
    response_model=RestoreResponse,
    tags=["snapshots"],
)
def restore_pool_snapshot(pool_id: int, body: RestoreRequest) -> RestoreResponse:
    result = snapshot.restore_snapshot(
        pool_id, body.restore_id, body.digest, body.snapshot
    )
    return RestoreResponse(**result)
