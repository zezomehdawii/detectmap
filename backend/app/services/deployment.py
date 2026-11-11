"""Workspace selection and managed sample data for each installation's org."""
from __future__ import annotations

import uuid
from dataclasses import dataclass

from sqlalchemy import select, text, true
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.tenant import schema_for
from app.models.public import Customer, CustomerStatus, DeploymentMode, MSSPOrg
from app.services.provisioning import provisioned_customer


SAMPLE_DISABLED_FEATURES = {"connector_tests", "grc_editing"}


@dataclass(frozen=True)
class DeploymentScope:
    mode: DeploymentMode = "multi_tenant"
    sample_data_enabled: bool = False
    active_customer: str | None = None

    @classmethod
    def from_org(cls, org: MSSPOrg) -> DeploymentScope:
        return cls(
            mode=org.deployment_mode,
            sample_data_enabled=org.sample_data_enabled,
            active_customer=org.single_customer if org.deployment_mode == "single" else None,
        )

    def customer_filter(self):
        """SQL filter for workspaces available for normal data access."""
        sample_filter = true() if self.sample_data_enabled else Customer.sample_dataset.is_(None)
        if self.mode == "single":
            return sample_filter & (Customer.codename == self.active_customer)
        return sample_filter

    def permits(self, customer: Customer) -> bool:
        return (
            (self.sample_data_enabled or customer.sample_dataset is None)
            and (self.mode != "single" or customer.codename == self.active_customer)
        )


async def get_org(session: AsyncSession, org_id: uuid.UUID | None, *, for_update: bool = False) -> MSSPOrg | None:
    if org_id is None:
        return None
    stmt = select(MSSPOrg).where(MSSPOrg.id == org_id)
    return await session.scalar(stmt.with_for_update() if for_update else stmt)


async def load_scope(session: AsyncSession, org_id: uuid.UUID | None) -> DeploymentScope:
    org = await get_org(session, org_id)
    return DeploymentScope.from_org(org) if org is not None else DeploymentScope()


async def codename_available(session: AsyncSession, codename: str) -> bool:
    """Schema names are shared across orgs. Lock the name until commit."""
    await session.execute(
        text("SELECT pg_advisory_xact_lock(741225032, hashtext(:codename))"),
        {"codename": codename},
    )
    return not await session.scalar(
        text(
            "SELECT EXISTS (SELECT 1 FROM public.customers WHERE codename = :codename) "
            "OR EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = :schema)"
        ),
        {"codename": codename, "schema": schema_for(codename)},
    )


async def _new_workspace(session: AsyncSession, org: MSSPOrg, dataset: str | None = None) -> Customer:
    from app.scripts.seed_demo import CUSTOMERS
    from app.scripts.seed_dummy_data import BRANDING, seed_tenant_fixtures

    customer_id = uuid.uuid4()
    prefix = f"sample_{dataset}" if dataset else "environment"
    codename = f"{prefix}_{customer_id.hex[:16]}"
    if not await codename_available(session, codename):
        raise RuntimeError("Could not allocate a workspace codename")
    spec = next((row for row in CUSTOMERS if row["codename"] == dataset), None)
    branding = (
        {**BRANDING[dataset], "logo_url": None, "display_name": f"{spec['name']} (sample)"}
        if spec else {}
    )
    customer = Customer(
        id=customer_id,
        mssp_org_id=org.id,
        codename=codename,
        name=f"{spec['name']} (sample)" if spec else "My environment",
        sector=spec["sector"] if spec else None,
        status=CustomerStatus.ACTIVE,
        branding=branding,
        features={key: False for key in SAMPLE_DISABLED_FEATURES} if spec else {},
        sample_dataset=dataset,
    )
    session.add(customer)
    await session.flush()
    async with provisioned_customer(session, codename):
        if dataset:
            await seed_tenant_fixtures(session, dataset, codename, offline=True)
    return customer


async def list_workspaces(session: AsyncSession, org_id: uuid.UUID) -> list[Customer]:
    rows = await session.scalars(
        select(Customer).where(Customer.mssp_org_id == org_id).order_by(Customer.created_at, Customer.codename)
    )
    return list(rows)


async def configure(
    session: AsyncSession,
    org: MSSPOrg,
    *,
    mode: DeploymentMode | None = None,
    sample_data_enabled: bool | None = None,
    primary_customer: str | None = None,
    initializing: bool = False,
) -> list[Customer]:
    """Update a locked org and its workspaces in the caller's transaction."""
    mode = mode or org.deployment_mode
    enabled = org.sample_data_enabled if sample_data_enabled is None else sample_data_enabled
    workspaces = await list_workspaces(session, org.id)
    if enabled:
        from app.scripts.seed_demo import CUSTOMERS

        present = {customer.sample_dataset for customer in workspaces}
        for spec in CUSTOMERS:
            if spec["codename"] not in present:
                workspaces.append(await _new_workspace(session, org, spec["codename"]))

    if mode == "single":
        visible = {
            customer.codename: customer for customer in workspaces
            if customer.status == CustomerStatus.ACTIVE and (enabled or customer.sample_dataset is None)
        }
        if primary_customer is not None and primary_customer not in visible:
            raise ValueError("Choose an active environment available for single environment mode.")
        selected = visible.get(primary_customer or org.single_customer)
        if selected is None:
            selected = visible.get(org.single_real_customer)
        if selected is None and initializing and enabled:
            selected = next(customer for customer in visible.values() if customer.sample_dataset == "acme")
        if selected is None:
            real = [customer for customer in visible.values() if customer.sample_dataset is None]
            if not real:
                # Enabling samples later should not put a working install into a
                # sample workspace without an explicit choice.
                selected = await _new_workspace(session, org)
                workspaces.append(selected)
            elif len(real) == 1 or org.deployment_mode == "single":
                selected = real[0]
            else:
                raise ValueError("Choose the active environment before switching to single environment mode.")
        org.single_customer = selected.codename
        if selected.sample_dataset is None:
            org.single_real_customer = selected.codename

    org.deployment_mode = mode
    org.sample_data_enabled = enabled
    return workspaces
