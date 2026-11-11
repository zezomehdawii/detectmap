"""Global search endpoint for the Cmd+K palette."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from app.api.deps import TenantPrincipal, current_tenant_user
from app.models.public import Role
from app.services.search import global_search

router = APIRouter(prefix="/search", tags=["search"])


class SearchHitOut(BaseModel):
    kind: str
    id: str
    label: str
    sub: Optional[str] = None
    href: Optional[str] = None


class SearchOut(BaseModel):
    query: str
    hits: list[SearchHitOut]


@router.get("", response_model=SearchOut)
async def search(
    q: str = Query("", min_length=0),
    principal: TenantPrincipal = Depends(current_tenant_user),
) -> SearchOut:
    """Search techniques, mitigations, APT groups, customers, detections.

    Auth: any tenant-audience JWT. Customer rows are scoped to the
    caller's MSSP org; non-MSSP users will simply get no customer hits.
    """
    org_id = (
        str(principal.user.mssp_org_id)
        if principal.user.mssp_org_id is not None and principal.user.role != Role.CUSTOMER_USER
        else None
    )
    results = await global_search(
        q,
        has_tenant=principal.customer is not None,
        mssp_org_id=org_id,
        deployment=principal.deployment,
    )
    return SearchOut(
        query=results.query,
        hits=[
            SearchHitOut(
                kind=h.kind, id=h.id, label=h.label, sub=h.sub, href=h.href
            )
            for h in results.hits
        ],
    )


__all__ = ["router"]
