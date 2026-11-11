"""MSSP-level portfolio overview — cross-customer roll-up dashboard."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select

from app.api.deps import TenantPrincipal, require_perm
from app.core.rbac import Permission
from app.db.base import AsyncSessionLocal
from app.db.tenant import set_tenant
from app.models.public import Customer, CustomerStatus
from app.services.coverage import DenominatorKind, compute_score

router = APIRouter(prefix="/portfolio", tags=["portfolio"])


class PortfolioCustomer(BaseModel):
    id: str
    codename: str
    name: str
    sector: Optional[str]
    status: str
    denominator_size: int
    covered_count: int
    deployed_count: int
    breadth_pct: float
    breadth_grade: str
    depth_grade: str
    posture_grade: str
    state_counts: dict[str, int]
    error: Optional[str] = None


class PortfolioOverview(BaseModel):
    mssp_org_id: str
    denominator_kind: str
    denominator_ref: Optional[str]
    customer_count: int
    posture_distribution: dict[str, int]
    customers: list[PortfolioCustomer]


def _parse_kind(s: str) -> DenominatorKind:
    try:
        return DenominatorKind(s)
    except ValueError as exc:
        raise HTTPException(422, f"invalid denominator: {s!r}") from exc


@router.get("/overview", response_model=PortfolioOverview)
async def overview(
    domain: str = Query("enterprise"),
    denominator: str = Query("full"),
    ref: Optional[str] = Query(None),
    principal: TenantPrincipal = Depends(
        require_perm(Permission.CUSTOMER_PORTFOLIO)
    ),
) -> PortfolioOverview:
    """Compute posture for every customer in the caller's MSSP org.

    Customer schemas are evaluated sequentially because each call swaps the
    tenant ContextVar; running them concurrently would require an explicit
    ContextVar copy per task. The customer count is small (tens, not
    thousands), so serial is fine.
    """
    kind = _parse_kind(denominator)
    if principal.user.mssp_org_id is None:
        raise HTTPException(
            403,
            "User has no MSSP org — only MSSP-scoped users can view portfolio",
        )
    if principal.deployment.mode == "single":
        raise HTTPException(403, "Portfolio is available in multi-tenant mode.")

    async with AsyncSessionLocal() as session:
        customers = (
            await session.execute(
                select(Customer)
                .where(Customer.mssp_org_id == principal.user.mssp_org_id, principal.deployment.customer_filter())
                .order_by(Customer.name)
            )
        ).scalars().all()

    rows: list[PortfolioCustomer] = []
    distribution: dict[str, int] = {"A": 0, "B": 0, "C": 0, "D": 0}

    for cust in customers:
        # Skip customers that aren't fully provisioned — their schema may not
        # exist yet, which would crash compute_score.
        if cust.status == CustomerStatus.PROVISIONING:
            rows.append(
                PortfolioCustomer(
                    id=str(cust.id),
                    codename=cust.codename,
                    name=cust.name,
                    sector=cust.sector,
                    status=cust.status.value,
                    denominator_size=0,
                    covered_count=0,
                    deployed_count=0,
                    breadth_pct=0.0,
                    breadth_grade="D",
                    depth_grade="D",
                    posture_grade="D",
                    state_counts={},
                    error="customer is still provisioning",
                )
            )
            continue

        # Swap tenant for this customer just long enough to score them.
        set_tenant(cust.codename)
        try:
            score = await compute_score(domain, kind, ref)
            rows.append(
                PortfolioCustomer(
                    id=str(cust.id),
                    codename=cust.codename,
                    name=cust.name,
                    sector=cust.sector,
                    status=cust.status.value,
                    denominator_size=score.denominator_size,
                    covered_count=score.covered_count,
                    deployed_count=score.deployed_count,
                    breadth_pct=score.breadth_pct,
                    breadth_grade=score.breadth_grade,
                    depth_grade=score.depth_grade,
                    posture_grade=score.posture_grade,
                    state_counts=score.state_counts,
                )
            )
            distribution[score.posture_grade] = distribution.get(score.posture_grade, 0) + 1
        except Exception as exc:
            rows.append(
                PortfolioCustomer(
                    id=str(cust.id),
                    codename=cust.codename,
                    name=cust.name,
                    sector=cust.sector,
                    status=cust.status.value,
                    denominator_size=0,
                    covered_count=0,
                    deployed_count=0,
                    breadth_pct=0.0,
                    breadth_grade="D",
                    depth_grade="D",
                    posture_grade="D",
                    state_counts={},
                    error=f"{type(exc).__name__}: {exc}",
                )
            )
        finally:
            # CRITICAL: clear the swap before the next customer / next request.
            set_tenant(None)

    return PortfolioOverview(
        mssp_org_id=str(principal.user.mssp_org_id),
        denominator_kind=kind.value,
        denominator_ref=ref,
        customer_count=len(rows),
        posture_distribution=distribution,
        customers=rows,
    )


class CompareCustomer(BaseModel):
    codename: str
    name: str
    sector: Optional[str]
    denominator_size: int
    covered_count: int
    deployed_count: int
    breadth_pct: float
    depth_avg: float
    breadth_grade: str
    depth_grade: str
    posture_grade: str
    state_counts: dict[str, int]
    error: Optional[str] = None


class CompareResponse(BaseModel):
    denominator_kind: str
    denominator_ref: Optional[str]
    customers: list[CompareCustomer]
    # cross-customer aggregates for quick reference
    best_breadth: Optional[str]
    worst_breadth: Optional[str]


@router.get("/compare", response_model=CompareResponse)
async def compare_customers(
    customers: str = Query(..., description="comma-separated codenames (2-6)"),
    domain: str = Query("enterprise"),
    denominator: str = Query("full"),
    ref: Optional[str] = Query(None),
    principal: TenantPrincipal = Depends(
        require_perm(Permission.CUSTOMER_PORTFOLIO)
    ),
) -> CompareResponse:
    """Side-by-side score for up to 6 customers. Used by the comparison page."""
    kind = _parse_kind(denominator)
    if principal.user.mssp_org_id is None:
        raise HTTPException(403, "User has no MSSP org")
    if principal.deployment.mode == "single":
        raise HTTPException(403, "Comparison is available in multi-tenant mode.")

    codenames = [c.strip() for c in customers.split(",") if c.strip()]
    if not 2 <= len(codenames) <= 6:
        raise HTTPException(422, "pass 2–6 customer codenames")

    async with AsyncSessionLocal() as session:
        rows = (
            await session.execute(
                select(Customer)
                .where(
                    Customer.mssp_org_id == principal.user.mssp_org_id,
                    Customer.codename.in_(codenames),
                    principal.deployment.customer_filter(),
                )
            )
        ).scalars().all()

    out: list[CompareCustomer] = []
    for cust in rows:
        if cust.status == CustomerStatus.PROVISIONING:
            out.append(
                CompareCustomer(
                    codename=cust.codename,
                    name=cust.name,
                    sector=cust.sector,
                    denominator_size=0,
                    covered_count=0,
                    deployed_count=0,
                    breadth_pct=0.0,
                    depth_avg=0.0,
                    breadth_grade="D",
                    depth_grade="D",
                    posture_grade="D",
                    state_counts={},
                    error="customer is still provisioning",
                )
            )
            continue
        set_tenant(cust.codename)
        try:
            score = await compute_score(domain, kind, ref)
            out.append(
                CompareCustomer(
                    codename=cust.codename,
                    name=cust.name,
                    sector=cust.sector,
                    denominator_size=score.denominator_size,
                    covered_count=score.covered_count,
                    deployed_count=score.deployed_count,
                    breadth_pct=score.breadth_pct,
                    depth_avg=score.depth_avg,
                    breadth_grade=score.breadth_grade,
                    depth_grade=score.depth_grade,
                    posture_grade=score.posture_grade,
                    state_counts=score.state_counts,
                )
            )
        except Exception as exc:  # noqa: BLE001
            out.append(
                CompareCustomer(
                    codename=cust.codename,
                    name=cust.name,
                    sector=cust.sector,
                    denominator_size=0,
                    covered_count=0,
                    deployed_count=0,
                    breadth_pct=0.0,
                    depth_avg=0.0,
                    breadth_grade="D",
                    depth_grade="D",
                    posture_grade="D",
                    state_counts={},
                    error=f"{type(exc).__name__}: {exc}",
                )
            )
        finally:
            set_tenant(None)

    scored = [c for c in out if not c.error and c.denominator_size > 0]
    best = max(scored, key=lambda c: c.breadth_pct).codename if scored else None
    worst = min(scored, key=lambda c: c.breadth_pct).codename if scored else None

    return CompareResponse(
        denominator_kind=kind.value,
        denominator_ref=ref,
        customers=out,
        best_breadth=best,
        worst_breadth=worst,
    )


__all__ = ["router"]
