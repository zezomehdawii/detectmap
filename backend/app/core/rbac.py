"""Role-based access control matrix.

Permissions are coarse-grained verbs over object types. The matrix below is
the source of truth — endpoints declare a required Permission via
require_perm() dependency rather than hard-coding role checks.
"""
from __future__ import annotations

import enum

from app.models.public import Role


class Permission(str, enum.Enum):
    # Customer-scoped detection ops
    DETECTION_READ = "detection:read"
    DETECTION_WRITE = "detection:write"
    DETECTION_DELETE = "detection:delete"

    # Customer-scoped coverage / reporting
    COVERAGE_READ = "coverage:read"
    REPORT_EXPORT = "report:export"

    # Customer lifecycle (MSSP)
    CUSTOMER_PROVISION = "customer:provision"
    CUSTOMER_READ = "customer:read"
    CUSTOMER_PORTFOLIO = "customer:portfolio"

    # Connector configuration
    CONNECTOR_READ = "connector:read"
    CONNECTOR_WRITE = "connector:write"

    # Customer profile (assets, contacts, network diagrams)
    ASSET_READ = "asset:read"
    ASSET_WRITE = "asset:write"

    # Product-level admin
    CATALOG_MANAGE = "catalog:manage"  # MITRE / SigmaHQ syncs
    MSSP_MANAGE = "mssp:manage"
    USER_MANAGE = "user:manage"  # create/edit/deactivate MSSP + customer users
    AUDIT_READ = "audit:read"  # view the settings/admin audit log


# Permission grants by role. Anything not listed = denied.
_GRANTS: dict[Role, set[Permission]] = {
    Role.PRODUCT_SUPER_ADMIN: {
        Permission.CATALOG_MANAGE,
        Permission.MSSP_MANAGE,
        Permission.CUSTOMER_READ,
        Permission.CUSTOMER_PROVISION,
    },
    Role.MSSP_ADMIN: {
        Permission.DETECTION_READ,
        Permission.DETECTION_WRITE,
        Permission.DETECTION_DELETE,
        Permission.COVERAGE_READ,
        Permission.REPORT_EXPORT,
        Permission.CUSTOMER_PROVISION,
        Permission.CUSTOMER_READ,
        Permission.CUSTOMER_PORTFOLIO,
        Permission.CONNECTOR_READ,
        Permission.CONNECTOR_WRITE,
        Permission.ASSET_READ,
        Permission.ASSET_WRITE,
        Permission.USER_MANAGE,
        Permission.AUDIT_READ,
    },
    Role.MSSP_ANALYST: {
        Permission.DETECTION_READ,
        Permission.DETECTION_WRITE,
        Permission.COVERAGE_READ,
        Permission.REPORT_EXPORT,
        Permission.CUSTOMER_READ,
        Permission.CUSTOMER_PORTFOLIO,
        Permission.CONNECTOR_READ,
        Permission.ASSET_READ,
        Permission.ASSET_WRITE,
    },
    Role.MSSP_READONLY: {
        Permission.DETECTION_READ,
        Permission.COVERAGE_READ,
        Permission.REPORT_EXPORT,
        Permission.CUSTOMER_READ,
        Permission.CUSTOMER_PORTFOLIO,
        Permission.CONNECTOR_READ,
        Permission.ASSET_READ,
    },
    Role.CUSTOMER_USER: {
        # Customer users have full read+edit of THEIR OWN tenant data.
        # Tenant isolation is enforced separately via schema scoping +
        # customer_id pin in the JWT.
        Permission.DETECTION_READ,
        Permission.DETECTION_WRITE,
        Permission.DETECTION_DELETE,
        Permission.COVERAGE_READ,
        Permission.REPORT_EXPORT,
        Permission.CONNECTOR_READ,
        Permission.ASSET_READ,
        Permission.ASSET_WRITE,
    },
}


def role_has(role: Role, perm: Permission) -> bool:
    return perm in _GRANTS.get(role, set())


def builtin_grants(role: Role) -> set[Permission]:
    """The full permission set for a built-in role (read-only baseline)."""
    return set(_GRANTS.get(role, set()))


# Human-readable metadata for the Permission catalog — surfaced by the
# /roles/permissions endpoint so the admin UI can render a meaningful
# permission picker instead of bare enum keys.
PERMISSION_METADATA: dict[Permission, dict[str, str]] = {
    Permission.DETECTION_READ: {
        "category": "Detections",
        "label": "Read detections",
        "description": "View Sigma detections, tags, and mapped techniques in the active tenant.",
    },
    Permission.DETECTION_WRITE: {
        "category": "Detections",
        "label": "Edit detections",
        "description": "Create or modify detections; edits to global rules flip them to customised.",
    },
    Permission.DETECTION_DELETE: {
        "category": "Detections",
        "label": "Delete detections",
        "description": "Permanently remove detections from the tenant.",
    },
    Permission.COVERAGE_READ: {
        "category": "Coverage",
        "label": "View coverage",
        "description": "Read the coverage matrix, posture scores, gaps, APT views, snapshots.",
    },
    Permission.REPORT_EXPORT: {
        "category": "Coverage",
        "label": "Export reports",
        "description": "Download PDF/CSV/JSON evidence packs and Navigator layers.",
    },
    Permission.CUSTOMER_PROVISION: {
        "category": "Customers (MSSP)",
        "label": "Provision customers",
        "description": "Create new customer tenants, manage branding, edit AI config.",
    },
    Permission.CUSTOMER_READ: {
        "category": "Customers (MSSP)",
        "label": "List customers",
        "description": "List MSSP-owned customers and switch between them.",
    },
    Permission.CUSTOMER_PORTFOLIO: {
        "category": "Customers (MSSP)",
        "label": "Portfolio roll-up",
        "description": "Access the cross-customer portfolio dashboard and comparison views.",
    },
    Permission.CONNECTOR_READ: {
        "category": "Connectors",
        "label": "View connectors",
        "description": "See SIEM/Sentinel/Elastic/LogRhythm connector configuration.",
    },
    Permission.CONNECTOR_WRITE: {
        "category": "Connectors",
        "label": "Edit connectors",
        "description": "Configure connector credentials (Fernet-encrypted at rest) and toggles.",
    },
    Permission.ASSET_READ: {
        "category": "Customer profile",
        "label": "Read assets & contacts",
        "description": "View the customer's asset inventory, network diagrams, and emergency contacts.",
    },
    Permission.ASSET_WRITE: {
        "category": "Customer profile",
        "label": "Edit assets & contacts",
        "description": "Create/edit/delete assets, link detections to assets, upload network diagrams, manage emergency contacts.",
    },
    Permission.CATALOG_MANAGE: {
        "category": "Platform",
        "label": "Manage catalog",
        "description": "Trigger ATT&CK / SigmaHQ / D3FEND refreshes (super-admin territory).",
    },
    Permission.MSSP_MANAGE: {
        "category": "Platform",
        "label": "Manage MSSP",
        "description": "Edit MSSP organisation-level settings (super-admin territory).",
    },
    Permission.USER_MANAGE: {
        "category": "Users & Roles",
        "label": "Manage users",
        "description": "Create, modify, deactivate users and assign roles within the MSSP org.",
    },
    Permission.AUDIT_READ: {
        "category": "Users & Roles",
        "label": "View audit log",
        "description": "Read the audit log of admin/settings/user-management actions.",
    },
}


__all__ = [
    "Permission",
    "role_has",
    "builtin_grants",
    "PERMISSION_METADATA",
]
