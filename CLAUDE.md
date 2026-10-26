# detectmap — project context for Claude Code

You are working on **detectmap** (display name "The Detection Map"), a
multi-tenant MSSP platform for MITRE ATT&CK-driven detection coverage, gap
analysis, and threat-informed defense. Read this file in full before
starting any task.

---

## What this product is

An MSSP runs detectmap as a single instance. Inside it:
- One **MSSP org** owns N **customers**.
- Each customer is a security tenant living in its own Postgres **schema**
  `cust_<codename>`. Detections, coverage snapshots, and customer-scoped
  data are per-schema; the catalog (ATT&CK techniques, MSSP/customer/user
  registry) is in `public`.
- The MSSP's analysts use the UI to review each customer's **detection
  posture**: which ATT&CK techniques are covered, by which Sigma rules,
  to what depth, against which APT groups, with what gaps.
- Output: coverage matrices in MITRE Navigator style, branded executive
  PDFs, ATT&CK Navigator layer JSON, Sigma rule packs converted via
  pySigma to Splunk SPL / Elastic Lucene / Sentinel KQL, and GRC
  crosswalks (NIST CSF, ISO 27001, NCA ECC).

This is **not** a SIEM. It's a detection coverage analysis layer that
sits above SIEMs. Phase 8 adds optional read-only connectors to Splunk,
Sentinel, Elastic for posture verification — that's the only outbound
integration.

---

## Stack

| Layer | Tech | Pinned |
|---|---|---|
| API | FastAPI · SQLAlchemy 2.0 async · Pydantic v2 · Alembic | see `backend/requirements.txt` |
| DB | Postgres 15 | `postgres:15-alpine` |
| Queue | Redis 7 + Celery 5 | `redis:7-alpine`, celery 5.4.0 |
| Sigma | pySigma + splunk/elasticsearch/kusto backends | pysigma 0.11.18 |
| ATT&CK | mitreattack-python + stix2 | see requirements |
| Frontend | Next.js 14 App Router · MUI v6 (`cssVariables`) · axios | next 14.2.16, @mui 6.1.6 |
| Fonts | Manrope (body), JetBrains Mono (technique IDs) | Google Fonts, loaded in `layout.tsx` |
| Deploy | Docker Compose (db · redis · backend · worker · frontend) | `docker-compose.yml` |

Don't change pinned versions without a stated reason.

---

## Architecture invariants — **never break these**

These are load-bearing. Breaking any of them is a security incident or a
data-loss incident. If a task seems to require breaking one, stop and
flag it instead.

### 1. Tenant isolation via `search_path`
- Tenant resolution: `app/api/deps.py::current_tenant_user` reads
  `X-Customer` header (MSSP roles) or pins to user's customer (customer
  role), validates membership, calls `set_tenant(codename)`.
- `app/db/tenant.py::tenant_session()` opens a transaction and runs
  `SET LOCAL search_path TO "cust_<codename>", public`. **LOCAL** is
  required — the setting resets when the connection returns to the pool.
- Middleware in `main.py` calls `set_tenant(None)` in a `finally` block
  after every request. Never bypass this.
- **Never** interpolate the codename into SQL. Always go through
  `schema_for()` which validates against `^[a-z][a-z0-9_]{1,30}$`.

### 2. Two Alembic trees
- `migrations/public/` — shared tables: orgs, customers, users, super
  admins, ATT&CK catalog. Version table: `public.alembic_version`.
- `migrations/customer/` — per-tenant tables: detections, coverage
  snapshots. Reads `DETECTMAP_TARGET_SCHEMA` env var, sets `search_path`
  in `env.py`, tracks version in
  `<target_schema>.alembic_version_customer` so each tenant has its own
  migration head.
- Run via `alembic -n public upgrade head` or
  `alembic -n customer upgrade head` (see `alembic.ini`).
- `services/provisioning.py` runs the customer tree via subprocess
  (NOT programmatic Alembic) because the async engine and Alembic's
  sync runtime don't compose cleanly.
- When you add a customer-scoped table: new revision in
  `migrations/customer/versions/`. When you add a public table: new
  revision in `migrations/public/versions/`. Never mix them.

### 3. Two JWT signing secrets
- `JWT_TENANT_SECRET` signs tokens for regular users
  (`product_super_admin` is the exception — see below).
- `JWT_SUPERADMIN_SECRET` signs tokens for the product super admin only.
- They are **different secrets** in `.env`. A leaked tenant secret must
  not grant super-admin access.
- `app/core/security.py::TokenAudience` enforces `aud` claim and routes
  to the correct secret. Tests in `tests/test_security.py::TestJWTAudienceSeparation`
  verify this; do not weaken them.

### 4. Connector secrets
- Phase 8 connectors (Splunk/Sentinel/Elastic creds) MUST be
  Fernet-encrypted at rest via `app/core/crypto.py`. Never store plain.
- Key rotation requires re-encryption under the new key.

### 5. RBAC source of truth
- All permissions in `app/core/rbac.py`. Endpoints declare
  `Depends(require_perm(Permission.X))`. Don't inline role checks.
- Five roles: `product_super_admin`, `mssp_admin`, `mssp_analyst`,
  `mssp_readonly`, `customer_user`. Customer users are pinned to their
  own `customer_id` — they cannot use `X-Customer` to reach other
  customers even if the header is sent.

### 6. Detection source semantics
- A detection has `source ∈ {global, customized, custom}` and an
  `upstream_global_id`.
- `global` = a row pointing to (or cloned from) the SigmaHQ public ruleset.
- When a user edits a `global` detection, it **flips to `customized`**
  with `upstream_global_id` set to the original. Original stays intact.
- `custom` = written from scratch for this customer.
- Re-syncing SigmaHQ never touches `customized` or `custom` rows.

---

## Repo layout

```
detectmap/
├── docker-compose.yml
├── .env.example
├── CLAUDE.md                     ← you are here
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── alembic.ini               (two named sections: [public], [customer])
│   ├── migrations/
│   │   ├── public/versions/      shared schema migrations
│   │   └── customer/versions/    per-tenant schema migrations
│   ├── app/
│   │   ├── config.py             pydantic-settings
│   │   ├── main.py               FastAPI app + tenant-clearing middleware
│   │   ├── worker.py             Celery
│   │   ├── db/
│   │   │   ├── base.py           async engine, PublicBase, CustomerBase
│   │   │   └── tenant.py         ContextVar + tenant_session() + schema_for()
│   │   ├── models/
│   │   │   ├── public.py         MSSPOrg, Customer, User, SuperAdmin,
│   │   │   │                     AttackCatalogVersion, AttackTechnique
│   │   │   └── customer.py       Detection, DetectionTechnique, CoverageSnapshot
│   │   ├── core/
│   │   │   ├── security.py       bcrypt + dual-secret JWT
│   │   │   ├── crypto.py         Fernet wrapper
│   │   │   └── rbac.py           Role → set[Permission] grants
│   │   ├── api/
│   │   │   ├── deps.py           tenant resolution + require_perm
│   │   │   ├── auth.py
│   │   │   └── customers.py
│   │   ├── services/
│   │   │   └── provisioning.py   CREATE SCHEMA + alembic upgrade + seed stub
│   │   └── scripts/
│   │       └── bootstrap.py      CLI: seed MSSP + admin + super admin
│   └── tests/
│       └── test_security.py      schema validation, password, JWT audience, RBAC
└── frontend/
    ├── Dockerfile · package.json · next.config.js · tsconfig.json
    ├── app/
    │   ├── theme.ts              indigo MUI v6 theme + coverage tokens
    │   ├── layout.tsx · providers.tsx · page.tsx (redirect)
    │   ├── login/page.tsx
    │   └── dashboard/
    │       ├── layout.tsx        sidebar + topbar + customer switcher
    │       └── page.tsx          posture hero + breakdown + gaps placeholders
    └── lib/
        ├── auth.ts               localStorage token + active customer
        └── api.ts                axios instance, attaches Authorization + X-Customer
```

---

## Working agreement

### Always
- **Plan before coding.** State the plan in 3–8 bullets, get acknowledgement,
  then implement. Don't dive into edits on a non-trivial task.
- **Read existing patterns before adding new ones.** This codebase has
  conventions (async session, Depends-based RBAC, theme tokens). Match them.
- **Run tests after every change.** `docker compose exec backend pytest -q`.
  Add tests for every new module that has logic (not just import wiring).
- **Migrations are immutable once committed.** Add a new revision; never
  edit a past one that's been applied.
- **Use the theme tokens.** Don't hardcode `#4f46e5` in components —
  reference `theme.palette.primary.main` or the `coverage`/`gradients`
  exports from `frontend/app/theme.ts`.
- **Reuse, don't refactor.** Don't touch files outside the task scope
  unless required and stated.
- **Sentence case for UI labels and copy.**

### Never
- Don't add new top-level dependencies without justifying the choice.
- Don't introduce ORMs, query builders, or HTTP clients beyond what's
  pinned. SQLAlchemy 2.0 async, axios, FastAPI's TestClient.
- Don't add `position: fixed` or DOCTYPE/html/head in React components.
- Don't add `localStorage` writes in components — go through `lib/auth.ts`.
- Don't write `.execute(text("SET search_path ..."))` outside
  `tenant_session()`. Tenancy has one entrypoint.
- Don't bypass `require_perm()` with inline role string comparisons.

### Communication style
- Be terse in status updates. "Done. 3 files. Tests pass." beats prose.
- Surface risks explicitly. If something is half-done or stubbed, say so.
- Flag scope creep. If a task starts pulling in adjacent work, stop and ask.

---

## Roadmap

Phase 1 (foundation) is complete and on disk. Phases 2–9 below.
**Implement one phase at a time.** After finishing a phase, stop, summarize
what changed, run the full test suite, and wait for confirmation before
starting the next.

### Phase 2 — MITRE ATT&CK catalog ingest *(do this first)*

**Goal:** populate `public.attack_techniques` with the current ATT&CK
catalog across Enterprise, ICS, and Mobile domains. Track catalog
versions. Support manual refresh by super admin and scheduled refresh.

**Acceptance criteria:**
- `app/services/attack_ingest.py` — fetches STIX 2.1 data for Enterprise,
  ICS, and Mobile (use `mitreattack-python` or fetch from
  `mitre/cti` repo via raw GitHub). Parses techniques + sub-techniques.
- Upserts to `attack_techniques` keyed on `(technique_id, domain)`.
  Idempotent — re-running on the same version is a no-op.
- Tracks version in `attack_catalog_versions` (already in public schema):
  domain, attack_spec_version, ingested_at, technique_count.
- Includes for each technique: name, description, tactic(s), platform(s),
  is_subtechnique, parent_technique_id, deprecated, revoked, url.
- `app/services/attack_diff.py` — compares two ingested versions, returns
  added / removed / renamed / deprecated technique lists.
- Celery task `tasks.refresh_attack_catalog` — runs all three domains
  and writes a diff log entry.
- Endpoint `POST /catalog/attack/refresh` (super admin only) — triggers
  the Celery task, returns task ID.
- Endpoint `GET /catalog/attack/techniques` — paginated list with
  filtering by domain, tactic, platform. Used by Phase 4's matrix.
- Endpoint `GET /catalog/attack/versions` — version history with diffs.
- New public Alembic revision **only if** existing schema doesn't fit.
  (It mostly does — `attack_techniques` exists. May need to add
  `tactics JSON[]`, `platforms JSON[]`, `is_subtechnique`, etc. — check
  first.)
- Tests:
  - Idempotent upsert (run twice, no duplicates, version row count = 1).
  - Diff: insert v1, ingest v2 mock with one added + one deprecated,
    assert diff payload.
  - RBAC: refresh endpoint rejects non-super-admin.
- Also ingest: **mitigations** (STIX `course-of-action`) and
  **technique→mitigation relationships** (STIX `mitigates`). Add new
  public tables `attack_mitigations`, `attack_technique_mitigations`
  via Alembic.
- D3FEND: out of scope for Phase 2. Defer to Phase 7 (GRC).

**Done when:** running
`docker compose exec backend python -c "from app.services.attack_ingest
import refresh_all; import asyncio; asyncio.run(refresh_all())"`
populates ~800 Enterprise techniques + ICS + Mobile, second run is a
no-op, diff endpoint returns sensible data.

---

### Phase 3 — Detection catalog + SigmaHQ sync

- Clone/pull SigmaHQ public ruleset (`SigmaHQ/sigma` on GitHub).
- New public table `default_detections` storing the canonical Sigma YAML.
- On customer provisioning, copy `default_detections` rows into the
  tenant's `detections` table with `source='global'` and
  `upstream_global_id` set.
- Auto-parse `tags: [attack.tXXXX]` to populate `detection_techniques`.
- CRUD endpoints: list/get/update/delete detections (tenant-scoped).
- "Edit a global flips to customized" — `PATCH /detections/{id}` on a
  `global` row clones into a new `customized` row, preserves upstream link.
- Sigma YAML import/export (single + bulk).
- Validate YAML via pySigma on write.

### Phase 4 — Coverage matrix + DeTT&CT scoring

- Denominator sets: full ATT&CK in scope, sector profile, APT-scoped
  (direct TTPs + software TTPs).
- DeTT&CT A-B (breadth = % techniques with ≥1 detection) and A-D
  (depth = detection analytics + deployment maturity).
- Posture grade from breadth × depth.
- Coverage matrix UI: tactic columns, technique cells colored by state
  (use `coverage` tokens from `theme.ts`), sub-technique indicators,
  selected cell outlined indigo.
- Right side pane: view/add use-case, load Sigma, inline-edit
  status/severity/depth, delete.
- See the matrix preview in chat history for the visual target.

### Phase 5 — APT coverage, gap analysis, posture screens

- APT screen: per-adversary scope coverage (Mitre Groups ingested in Phase 2
  if you added groups; otherwise add now).
- Gap analysis: top gaps ranked by APT prevalence in your scope.
- Posture screen: trend over time using `coverage_snapshots`.

### Phase 6 — Reports + pySigma exports

- Coverage exports: JSON / CSV / XLSX.
- Branded executive PDF via reportlab (customer logo from
  `customers.branding`).
- ATT&CK Navigator layer JSON (compatible with
  `mitre-attack/attack-navigator`).
- Sigma rule pack bulk YAML export.
- pySigma conversion: Splunk SPL / Elastic Lucene / Sentinel KQL.
- Persist point-in-time `coverage_snapshots`.

### Phase 7 — GRC crosswalk

- Crosswalk tables: NIST CSF, ISO 27001, NCA ECC (Saudi NCA Essential
  Cybersecurity Controls — the deployment context is KSA).
- Map ATT&CK techniques + mitigations to controls.
- Optional: D3FEND ingestion for technique → defensive-technique mapping.
- Compliance-evidence exports.

### Phase 8 — Portfolio, connectors, settings

- Portfolio: MSSP cross-customer roll-up dashboard.
- Connectors CRUD: Splunk / Sentinel / Elastic configuration with
  Fernet-encrypted creds.
- Settings: product branding, ATT&CK catalog refresh schedule,
  account management, legend customization.
- ATT&CK release diff notifications (uses Phase 2's diff data).

### Phase 9 — Workflow & cross-tenant features *(shipped)*

A grab-bag of analyst-loop features that compose on top of Phases 1–8.

**Global search.** `GET /search?q=…` ranks techniques, mitigations, APT
groups, customers (MSSP-org-scoped), and tenant detections. Frontend
palette mounted in `dashboard/layout.tsx` listens for `Ctrl/⌘+K`.

**Saved filter views.** Customer-schema table `saved_views (id, name,
kind, payload JSONB, author_email, …)`. `kind` namespaces views by page
(`coverage_matrix`, etc.). CRUD at `/views`. UI is a small dropdown
in the coverage page filter card.

**Live connector tests.** `POST /connectors/{id}/test` now executes a
read-only ping per connector kind. Decrypts secrets in memory, hits
the platform's smallest auth endpoint:
- Splunk → `/services/server/info` (or `/services/collector/health` for HEC)
- Elastic → `/_cluster/health`
- Sentinel → AAD client-credentials token, then ARM workspace lookup

6-second per-call timeout, no retries. Outcome persisted to
`connectors.last_test_*`. Service: `app/services/connector_tests.py`.

**Snapshot delta + diff page.** `save_snapshot` now writes a
`technique_states: {tid: state}` map into `coverage_snapshots.payload`
so `GET /coverage/matrix-delta?snapshot_id=…` can compute per-cell
change classes (`improved | regressed | unchanged | new | removed`).
Dedicated UI at `/dashboard/posture/diff`. Snapshots created before
this feature lack `technique_states` and the endpoint returns a 422
on those.

**Detection effectiveness loop.** Customer-schema table
`detection_outcomes (id, detection_id FK, kind in {tp,fp,unsure},
summary, reference_url, author_email, observed_at)`. Endpoints
`/detections/{id}/outcomes` (CRUD) + `/detections/{id}/effectiveness`
(precision summary). Surfaced as a panel in the detection drawer.

**Detection unit tests (event samples).** Customer-schema table
`detection_event_samples (id, detection_id FK, label, kind in
{positive,negative}, event JSONB, expected_match, last_run_*)`.
Endpoints under `/detections/{id}/samples` + `/run`. The pragmatic
Sigma matcher lives at `app/services/detection_samples.py::match_event`
— pure function, returns `(True | False | None, reason)`. Indeterminate
results (aggregations, unsupported modifiers, malformed conditions)
return `None` rather than guessing. Matcher has 25 unit tests under
`tests/test_sigma_matcher.py` (marker: `matcher`).

**Customer comparison.** `GET /portfolio/compare?customers=a,b,c`
(MSSP-org-scoped) returns side-by-side scores for 2–6 customers. Page
at `/dashboard/portfolio/compare`.

**ATT&CK release notifications.** `GET /settings/attack-notifications`
filters the global `attack_catalog_versions` diffs down to entries
that touch the active tenant's detection_techniques. Topbar bell +
menu component (`AttackNotificationsMenu`) shows only when the result
set is non-empty.

**Custom denominator builder.** `POST /coverage/denominator/custom`
takes `{sectors[], apt_groups[], platforms[], operator: union|intersection}`
and returns the resolved technique ID set. `POST /coverage/matrix-custom`
and `/score-custom` run the full matrix/score pipeline against that
set (via `compute_matrix(..., precomputed_denominator=...)`). Dialog
on coverage page; "custom" is a fourth value of the denominator picker.

**Cross-customer rule promotion.** `GET /detections/suggestions`
returns sibling-tenant custom/customized rules the active tenant
doesn't have, ranked by `(same_sector, status, technique_count)`.
`POST /detections/promote` copies a rule into the active tenant: new
UUID, `sigma_id` suffixed `-from-<src>`, title prefixed `[src]`,
source set to `custom`, status reset to `idea`, technique mappings
copied. Read-only across the boundary — full YAML is copied but the
source row is never modified. UI strip at the top of
`/dashboard/detections`.

**Per-technique notes.** Customer-schema table `technique_notes (id,
technique_id, domain, body, author_email, …)` — one note per
`(technique_id, domain)`. Endpoints `PUT/DELETE
/coverage/techniques/{technique_id}/note`. Surfaced in the matrix
drawer alongside detections/APT/mitigations.

**Consolidated technique drawer.** `GET
/coverage/techniques/{technique_id}` returns the technique catalog
record + mitigations + APT groups (direct ∪ via software) + tenant
detections + the per-technique note in one round-trip. Used by the
matrix drawer.

**AI-assisted authoring** — *was* a mockup in Phase 9, **wired up for
real in Phase 10**. See `AiAuthorPanel` in `DetectionExtras.tsx` and
the Phase 10 section below.

---

### Phase 10 — AI authoring, D3FEND, scheduled refresh *(shipped)*

**AI-assisted Sigma authoring.** Each MSSP brings its own Anthropic
Claude API key, configured at Settings → AI authoring. The key is
Fernet-encrypted at rest in `mssp_orgs.ai_api_key_encrypted`, never
returned to the client (only the masked tail). Pipeline:

  1. *Input refinement* — `app/services/ai_sigma_prompt.py` composes a
     strict, schema-aware prompt from the structured brief (intent,
     techniques, log source, severity, FP notes, references). The user
     never types into the system prompt directly.
  2. *Model call* — `app/services/ai_sigma.py` decrypts the key in
     memory and calls Anthropic with the prompt. 45s timeout.
  3. *Output refinement* — `app/services/ai_sigma_validate.py` extracts
     the YAML fenced block, parses it via the existing pySigma path
     (`sigma_validate.parse_sigma_yaml`), and runs cheap shape checks
     (UUID id, valid level/status, attack.tNNNN tag format, logsource
     completeness).
  4. *Retry loop* — up to 2 correction round-trips when validation
     fails; each retry includes the prior YAML + the parser errors.

Endpoints: `GET/PATCH /settings/ai-config`, `POST /settings/ai-config/test`,
`POST /detections/ai-draft`. The draft is NOT auto-persisted — the
analyst hits "Save as new detection" in the UI, which goes through the
normal `POST /detections` path (so `source` lands as `custom` and the
detection-techniques mapping is re-derived from tags).

The AI panel lives in the detection drawer alongside Effectiveness and
Unit tests. If the MSSP has no key configured, the panel shows a link
to Settings → AI authoring instead of erroring opaquely.

**D3FEND ingestion.** Three new public tables: `d3fend_techniques`,
`attack_technique_d3fend` (with `relation` for `d3f:detects` /
`d3f:hardens` / etc.), and `d3fend_ingest_runs`. Source is the
D3FEND inferred mappings CSV (`d3fend.mitre.org/api/ontology/inferred/
d3fend-full-mappings.csv` by default — overrideable via
`D3FEND_MAPPINGS_URL`). Parser tolerates column-name drift between
upstream revisions. Endpoints under `/catalog/d3fend/*` mirror the
ATT&CK + SigmaHQ catalog endpoints. D3FEND mappings are joined into
the consolidated `/coverage/techniques/{tid}` response and surfaced as
a new "D3FEND defenses" section in the matrix drawer alongside
mitigations.

**Scheduled catalog refresh.** Three flags on `app_settings`:
`attack_refresh_enabled`, `sigmahq_refresh_enabled`,
`d3fend_refresh_enabled`. A new `celerybeat` service in docker-compose
runs every container start; the `scheduled_refresh_*` tasks
(`app/tasks/scheduled.py`) fire on a fixed cadence (daily for ATT&CK +
SigmaHQ, weekly for D3FEND) and short-circuit when the corresponding
flag is False. The cron columns on `app_settings` are informational
only — celerybeat uses a fixed interval, not cron-expression parsing.
UI at Settings → Schedule (super-admin only — non-super-admin gets a
403 from the backend; the UI shows "schedule unavailable").

**Matcher hardening.** The pragmatic Sigma matcher now supports
`|windash`, `|cidr` (IPv4/IPv6 network membership), `|fieldref`
(compare a field to another event field), `|base64`, and
`|base64offset` (the 3-offset embedded-base64 search, mirroring
pySigma). Bare scalar selections (`sel: 4625`) and mixed scalar lists
are treated as free-text keywords instead of erroring. The
`tools/matcher_corpus_eval.py` script runs the matcher against the
seeded `default_detections` catalog with a synthetic match-anything
event and tallies indeterminate causes. Against the full SigmaHQ
ruleset (~3.1k rules) the indeterminate rate is **~0%** — only
`|expand` (placeholder pipelines) and aggregation/timeframe
conditions remain indeterminate by design.

---

### Phase 10.1 — D3FEND crosswalk, schedule history *(shipped)*

**D3FEND → GRC crosswalk.** A control's defensive countermeasures are
derived transitively: control → mapped ATT&CK techniques →
`attack_technique_d3fend`. `control_coverage` now returns a
`d3fend_count` per control, and `GET /grc/controls/{uuid}/d3fend`
returns the distinct D3FEND techniques (with relation predicates +
which ATT&CK techniques surfaced each). Surfaced as a "Defensive
countermeasures · D3FEND" section + a D3FEND stat tile in the GRC
control drawer. Read-only — D3FEND mappings come from the catalog, not
user edits.

**D3FEND in reports.** `to_navigator_layer` adds a `d3fend_defenses`
metadata entry per technique; `to_pdf` adds a "Defensive countermeasures
(D3FEND)" table ranking defenses by how many in-scope ATT&CK techniques
they address. Both fed by `d3fend_ingest.d3fend_for_techniques(...)`.

**Schedule run history.** New `public.scheduled_job_runs` table
(migration `0009`). The `scheduled_*` celerybeat tasks append one row
per fire (`ok` / `skipped` / `error` + detail) — all DB work on a single
event loop after one `engine.dispose()` (the asyncpg loop-pinning
hazard). `GET/PATCH /settings/catalog` returns `last_runs` (latest row
per job), shown as a status chip + timestamp under each toggle in
Settings → Schedule.

---

## What's in each customer schema (cumulative)

After migration `0004_views_outcomes` the per-tenant schema contains:

- `detections` + `detection_techniques` *(Phase 3)*
- `coverage_snapshots` *(Phase 4)* — `payload.technique_states` added by Phase 9
- `connectors` *(Phase 8)*
- `technique_notes` *(Phase 9 prelim — migration 0003)*
- `saved_views`, `detection_outcomes`, `detection_event_samples` *(Phase 9)*

Phase 10 touches **public** only: new columns on `mssp_orgs`
(`ai_provider`, `ai_api_key_encrypted`, `ai_model`, `ai_last_used_at`,
`ai_last_status`), new columns on `app_settings`
(`d3fend_refresh_enabled`, `d3fend_refresh_cron`), and three new tables
(`d3fend_techniques`, `attack_technique_d3fend`, `d3fend_ingest_runs`)
under migration `0008_ai_and_d3fend`; plus `scheduled_job_runs` under
`0009_scheduled_job_runs`.

---

## Testing

Default `pytest -q` runs **only non-destructive tests** (108+ as of
Phase 9). Destructive tests are marked `wipes_db` and excluded by
default via `pytest.ini`'s `addopts = -m "not wipes_db"`. Run them
explicitly with `pytest -m wipes_db` — but be aware they delete the
seeded ATT&CK catalog / sector profiles / GRC controls before and
after each test. After running them, re-seed via the full pipeline
documented in earlier sessions (ATT&CK refresh_all → sectors → GRC
seed → SigmaHQ sync → provision_customer → seed_dummy_data).

When adding a new test that wipes any public/reference table, mark
the module:

```python
import pytest
pytestmark = pytest.mark.wipes_db
```

For non-destructive tests that mutate tenant-scoped rows, follow the
pattern in `tests/test_new_endpoints.py`: clean up explicitly inside
the test, and use `pytest.skip` if a precondition (e.g. seeded
detections) isn't met.

The pure Sigma matcher tests use marker `matcher` and run as part of
the default suite — they don't touch the DB at all.

---

## Code patterns to follow

### Async DB session in an endpoint
```python
@router.get("/things")
async def list_things(
    principal: TenantPrincipal = Depends(current_tenant_user),
    _: None = Depends(require_perm(Permission.DETECTION_READ)),
):
    async with tenant_session() as session:
        result = await session.execute(select(Thing).order_by(Thing.created_at.desc()))
        return [ThingOut.model_validate(t) for t in result.scalars()]
```

### New migration
```bash
# inside backend container
alembic -n public revision -m "add foo to bar"            # public schema
DETECTMAP_TARGET_SCHEMA=cust_dummy alembic -n customer revision -m "add x" \
  # customer schema — use cust_dummy as a stand-in for the template
```
Then edit the generated file in `migrations/{public,customer}/versions/`.

### Front-end card matching theme
```tsx
<Card>
  <CardContent sx={{ p: { xs: 2.5, md: 3 } }}>
    {/* uses theme overrides for radius, border, shadow */}
  </CardContent>
</Card>
```
Gradient CTA: `<Button variant="contained">…</Button>` — the gradient is
already wired in `theme.ts`.

### Coverage cell color
Import `coverage` from `app/theme.ts`. Use `coverage.green` etc., not
hex literals.

---

## Where the brief lives

The original product spec from the customer is in this CLAUDE.md
implicitly (architecture invariants + roadmap). If you need more detail
on a specific feature, ask before guessing. Don't invent requirements.
