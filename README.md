# detectmap

**The Detection Map** — a multi-tenant MSSP platform for MITRE ATT&CK–driven
detection coverage, gap analysis, and threat-informed defense.

One MSSP runs detectmap as a single instance. Inside it, the MSSP's analysts
review every customer's detection posture: which ATT&CK techniques are
covered, by which Sigma rules, at what depth, against which APT groups,
with what gaps. Outputs include MITRE Navigator–style coverage matrices,
branded executive PDFs, Sigma rule packs converted to Splunk SPL / Elastic
Lucene / Sentinel KQL, and GRC crosswalks against NIST CSF, ISO 27001, and
the Saudi NCA controls.

It is **not** a SIEM — it sits one layer above one, optionally reading
posture back from Splunk / Sentinel / Elastic via connectors.

---

## Status

Phases 1 through 10.1 are shipped, plus the customer-profile feature that
sits on top of them.

| Area | What's live |
|---|---|
| **Foundation** | Multi-tenant Postgres (schema-per-customer), dual JWT audiences, RBAC (5 built-in roles + custom roles), two-tree Alembic migrations, Docker Compose stack with optional TLS overlay (Caddy), interactive `setup.py`. |
| **Catalog** | ATT&CK STIX ingest (Enterprise · ICS · Mobile) with version diffs, mitigations + technique→mitigation relationships, ATT&CK Groups + Software + relationships, D3FEND inferred mappings, scheduled refresh via celerybeat. |
| **Detections** | SigmaHQ public ruleset sync, "edit a global flips to customized" semantics, per-tenant CRUD, Sigma YAML import/export, pySigma → SPL / Lucene / KQL exports, AI-assisted Sigma authoring (bring-your-own Anthropic key), unit-test event samples, effectiveness loop (TP/FP/unsure), cross-tenant rule promotion. |
| **Coverage** | DeTT&CT A-B (breadth) × A-D (depth) scoring, posture grade, full/sector/APT/custom denominators, Navigator-style matrix with consolidated technique drawer, per-technique notes, saved filter views, snapshot delta + diff page. |
| **Analyst workflow** | APT coverage, gap analysis (rank by APT prevalence in scope, ignore-with-reason, comments), portfolio roll-up, customer comparison, global search (Ctrl/⌘+K), ATT&CK release notifications. |
| **GRC** | NIST CSF · ISO 27001 · NCA ECC / CSCC / CCC-CSP / CCC-CST / OTCC crosswalks; technique→control mapping; D3FEND defensive countermeasures per control; control-coverage view; compliance-evidence exports. |
| **Reports** | Branded executive PDF (with D3FEND defenses table), ATT&CK Navigator layer JSON, Sigma rule pack export, JSON / CSV / XLSX. |
| **Connectors** | Splunk / Sentinel / Elastic CRUD; Fernet-encrypted secrets; live read-only ping per connector kind; ingest of *deployed* use-cases for posture verification. |
| **Settings** | AI authoring config, scheduled-refresh toggles (with run history), product branding, MSSP-portal user management, per-customer feature toggles, per-customer user management. |
| **Collection management** | Requirements, collection plans, implemented-source links, validation notes, retention and data-quality inventory, ATT&CK visibility, JSON/CSV submissions, and tenant-pinned student access at `/portal/cmf`. See [CMF classroom setup](docs/CMF_CLASSROOM.md). |
| **Customer profile** | Per-tenant assets (with criticality + compliance scope), asset↔detection linkage (search-and-multi-select picker), network/topology diagrams (image / PDF inline preview · binary download), emergency contacts. Read-only mirror at `/portal/organization` for customer users. |

---

## Screenshots

<!-- Drop PNG/JPG files into docs/screenshots/ with the filenames below.
     The README references them once they exist; placeholder notes are
     left in the meantime so the layout still reads cleanly. -->

| Surface | Path |
|---|---|
| Login | `docs/screenshots/login.png` *(TODO: capture from `/login`)* |
| Dashboard overview | `docs/screenshots/dashboard.png` *(TODO: capture from `/dashboard`)* |
| Coverage matrix | `docs/screenshots/coverage-matrix.png` *(TODO: capture from `/dashboard/coverage`)* |
| Technique drawer (detections + mitigations + D3FEND + note) | `docs/screenshots/technique-drawer.png` |
| Detection library + drawer (effectiveness + samples + AI authoring) | `docs/screenshots/detection-drawer.png` |
| APT coverage | `docs/screenshots/apt-coverage.png` |
| Gap analysis | `docs/screenshots/gap-analysis.png` |
| GRC crosswalk + control drawer | `docs/screenshots/grc-control.png` |
| Reports & exports | `docs/screenshots/reports.png` |
| Customer profile (assets · diagrams · contacts) | `docs/screenshots/customer-profile.png` |
| Detection linker (search + multi-select) | `docs/screenshots/detection-linker.png` |
| Portal — customer view (`/portal`) | `docs/screenshots/portal-overview.png` |
| Portal — organization mirror | `docs/screenshots/portal-organization.png` |
| Settings — AI authoring | `docs/screenshots/settings-ai.png` |
| Settings — schedule | `docs/screenshots/settings-schedule.png` |

> Screenshots are not embedded yet. Drop the PNGs into the paths above and
> the next README pass will inline them — or replace each line with
> `![label](docs/screenshots/<file>.png)` directly.

---

## Quickstart

### Recommended: interactive installer

Install **Python 3.10+** first, then run this command from the repository root:

```bash
python3 setup.py
```

The wizard checks dependencies before changing application configuration. It
shows each proposed installation/start command and asks before running it.
An internet connection is needed to download packages and container images.

| Host | Missing Docker / Compose installation |
|---|---|
| Windows | Offers Docker Desktop through `winget` when available. |
| macOS | Offers Docker Desktop through Homebrew when available. |
| Ubuntu / Debian | Offers Docker Engine, CLI, Buildx and Compose from Docker's signed apt repository. |
| Other systems / no supported package manager | Shows the official installation guide and how to resume setup. |

Docker Desktop first-start setup, license prompts, virtualization/WSL setup,
administrator approval, and any requested restart remain with the operator.
After completing them, rerun the same command. The wizard checks again and
reuses installed dependencies. It can offer to start an installed Docker
service/Desktop and wait for Linux containers to become ready.

Node.js, PostgreSQL, Redis, the backend Python dependencies, and frontend npm
dependencies are installed **inside Docker**. Self-signed TLS generation also
uses the backend container, so setup does not install packages into system
Python. Python itself must already be available to run the installer.

The configuration prompts provide suggested values; press **Enter** to accept:

1. **Hostname/IP:** a detected LAN IPv4 address; the detected hostname is also shown.
2. **Transport:** HTTP, HTTPS with a generated certificate, or HTTPS with your certificate.
3. **Listen port:** HTTP defaults to **8080**, HTTPS to **8443**. The chosen port drives the actual frontend/proxy mapping.
4. **Administrator identities:** `admin@detectmap.local` and `super@detectmap.local`.

Setup builds and starts the stack, waits for the API, and initializes the two
administrators **only when the deployment is empty**. Random temporary
passwords are printed once, after commit, and must be changed on first login.
Existing deployments, accounts, and customer data remain unchanged.

An existing `.env` is kept by default. Choosing to reconfigure updates only
network settings, retaining database credentials, encryption keys, and other
operator settings. `--keep-env` skips that choice. `--skip-reset` remains a
compatible explicit way to retain data:

```bash
python3 setup.py --keep-env --skip-reset
```

A factory reset is available only with `--reset`, and setup asks for confirmation
before dependency installation or deployment changes. Do not use it for an upgrade.

Dependency instructions are based on [Docker's Ubuntu](https://docs.docker.com/engine/install/ubuntu/),
[Debian](https://docs.docker.com/engine/install/debian/), and
[Windows](https://docs.docker.com/desktop/setup/install/windows-install/) guides,
the [Microsoft winget package manifest](https://github.com/microsoft/winget-pkgs/tree/master/manifests/d/Docker/DockerDesktop),
and the [Homebrew Docker Desktop cask](https://formulae.brew.sh/cask/docker-desktop).

### Manual path (CI / scripted)

```bash
cp .env.example .env          # fill JWT_TENANT_SECRET, JWT_SUPERADMIN_SECRET,
                              # FERNET_KEY, INTERNAL_API_KEY
docker compose up --build -d
docker compose exec backend python -m app.scripts.bootstrap \
  --mssp-name "Demo MSSP" \
  --admin-email admin@demo.local --admin-password change-me \
  --super-email super@demo.local --super-password change-me
```

The bootstrap script is idempotent.

### Generating secrets by hand

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"   # FERNET_KEY
python -c "import secrets; print(secrets.token_urlsafe(64))"                                # JWT_TENANT_SECRET
python -c "import secrets; print(secrets.token_urlsafe(64))"                                # JWT_SUPERADMIN_SECRET
python -c "import secrets; print(secrets.token_urlsafe(32))"                                # INTERNAL_API_KEY
```

> `JWT_TENANT_SECRET` and `JWT_SUPERADMIN_SECRET` must be **different**.
> Token forgery against the tenant API does not grant super-admin access.

### Where things land

- Frontend: `http://<host>:<port>` (or `https://` when TLS is on, default `8443`).
- Backend: same host on port `8000` for direct HTTP, or behind Caddy when TLS is on.
- Swagger: `<backend>/docs`.

---

## Architecture

| Layer | Stack | Pins |
|---|---|---|
| API | FastAPI · SQLAlchemy 2.0 async · Pydantic v2 · Alembic | `backend/requirements.txt` |
| DB | Postgres 15 | `postgres:15-alpine` |
| Queue | Redis 7 + Celery 5 + celerybeat | `redis:7-alpine`, `celery 5.4.0` |
| Sigma | pySigma + splunk / elasticsearch / kusto backends | `pysigma 0.11.18` |
| ATT&CK / D3FEND | `mitreattack-python`, `stix2`, D3FEND CSV ingest | see requirements |
| Frontend | Next.js 14 App Router · MUI v6 (`cssVariables`) · axios | `next 14.2.16`, `@mui 6.1.6` |
| Fonts | Manrope (body), JetBrains Mono (technique IDs) | Google Fonts |
| Deploy | Docker Compose (`db · redis · backend · worker · beat · frontend` + optional `caddy`) | `docker-compose.yml`, `docker-compose.tls.yml` |

### Tenancy

- **MSSP org** owns N **customers**.
- Each customer = a Postgres **schema** `cust_<codename>` (validated against `^[a-z][a-z0-9_]{1,30}$`).
- Tenant resolves per request:
  - `customer_user` → pinned to `user.customer_id` from the JWT; `X-Customer` header is ignored unless it matches.
  - `mssp_*` → reads `X-Customer` header; the customer must belong to the user's MSSP org.
  - `product_super_admin` → separate JWT audience, operates against `public` schema endpoints.
- `app/db/tenant.py::tenant_session()` opens a transaction and runs `SET LOCAL search_path TO "cust_<codename>", public`. `LOCAL` ensures the setting resets when the connection returns to the pool. Middleware in `main.py` clears the `ContextVar` in a `finally` after every request.

### Two Alembic trees

- `migrations/public/` — shared tables (orgs, customers, users, super admins, ATT&CK catalog, D3FEND, GRC, app settings, scheduled-job runs).
- `migrations/customer/` — per-tenant tables (detections, coverage snapshots, connectors, technique notes, saved views, detection outcomes / samples, gap workflow, assets + asset_detections + customer_contacts + customer_diagrams).
- Customer migrations run via subprocess on customer provisioning, with `DETECTMAP_TARGET_SCHEMA=<schema>` in the env.

### Detection source semantics

A detection row has `source ∈ {global, customized, custom}` plus an
`upstream_global_id`. Editing a `global` row clones it into a new
`customized` row (preserving the link); re-syncing SigmaHQ never touches
`customized` or `custom` rows.

---

## Feature tour

### Coverage matrix

Navigator-style table — tactic columns, technique cells coloured by state
(covered · partial · gap · not-applicable, plus deployed/idea/tuning
shades). Right side pane on cell click → consolidated technique drawer:
the technique's catalog record, its mitigations, the APT groups that use
it (direct ∪ via software), the tenant's linked detections, the
per-technique note, and D3FEND defensive countermeasures.

Denominators: full ATT&CK · sector profile · APT-scoped · custom
(operator-built union/intersection of sectors × APT groups × platforms).

### APT coverage & gap analysis

Per-adversary view of in-scope TTPs (direct + via software) and what the
tenant covers vs. doesn't. Gap analysis ranks gaps by APT prevalence in
scope, supports per-gap comments and document-and-ignore-until decisions
that re-surface on a chosen date.

### Detections

A unified Sigma library per tenant: SigmaHQ-derived `global` rules,
analyst-edited `customized` rows that retain a link back to the
upstream, and from-scratch `custom` rules. The detection drawer surfaces:

- **Effectiveness** — analyst-logged TP/FP/unsure outcomes feed a precision summary.
- **Unit tests (event samples)** — positive/negative sample events the pragmatic Sigma matcher evaluates on rule save. Matcher supports `|windash`, `|cidr`, `|fieldref`, `|base64`, `|base64offset` (with the 3-offset variants), bare scalars, and produces deterministic results on ~100% of the seeded SigmaHQ ruleset.
- **AI authoring** — bring-your-own Anthropic API key, configured at *Settings → AI authoring* and Fernet-encrypted at rest. The pipeline composes a strict schema-aware prompt, calls Claude, validates the YAML via pySigma, retries up to twice on validation failures, and surfaces the draft for "Save as new detection."

### GRC crosswalk

Frameworks shipped: NIST CSF, ISO 27001, NCA ECC, NCA CSCC, NCA CCC-CSP,
NCA CCC-CST, NCA OTCC. The control drawer shows the technique mappings
(and which detections cover each) plus the D3FEND defensive
countermeasures derived transitively through the mapped ATT&CK
techniques.

### Reports

- Coverage exports: JSON / CSV / XLSX.
- Branded executive PDF with the customer's logo (set on the customer record).
- ATT&CK Navigator layer JSON (compatible with `mitre-attack/attack-navigator`), with a `d3fend_defenses` metadata entry per technique.
- Sigma rule pack bulk YAML.
- pySigma conversions: Splunk SPL · Elastic Lucene · Sentinel KQL.
- Point-in-time `coverage_snapshots`; snapshot delta + diff page calls out improved / regressed / new / removed cells.

### Connectors

Splunk · Sentinel · Elastic configurations with Fernet-encrypted
credentials. The Test endpoint executes a read-only ping per kind
(Splunk `/services/server/info`, Elastic `/_cluster/health`, Sentinel
AAD client-creds → ARM workspace lookup), 6 s timeout, no retries.
Outcome persisted to `connectors.last_test_*`.

### Customer profile

Per-tenant view (under the customer drawer on the MSSP dashboard, mirrored read-only at `/portal/organization` for customer users):

- **Assets** — kind, environment, criticality (low/medium/high/critical, with a critical-count chip), business function, owner, compliance scope (PCI · HIPAA · SOX · GDPR · ISO 27001 · NIST CSF · NIST 800-53 · NCA ECC / CSCC / CCC-CSP / CCC-CST / OTCC), tags, free notes. Coverage rollup per asset (linked rules · deployed rules · techniques covered) computed at read time from the asset↔detection linkage.
- **Asset ↔ detection linkage** — search-and-multi-select picker over the tenant's full Sigma catalog with debounced title search and status/source filters; wholesale-replace save.
- **Diagrams** — image / PDF / binary uploads (default cap 50 MB). Images and PDFs render inline; Visio / Packet Tracer / draw.io / zip and friends become download links. One "primary" diagram per tenant; uploading or patching with `is_primary=true` automatically clears the previous primary.
- **Emergency contacts** — primary-first ordering, click-to-email / click-to-call, free-text office address + notes.

### AI-assisted authoring

Per-MSSP configuration at *Settings → AI authoring*. The MSSP brings
its own Anthropic API key, Fernet-encrypted at rest. The draft is not
auto-persisted — the analyst hits *Save as new detection* in the UI,
which goes through the normal `POST /detections` path so `source` lands
as `custom` and the technique mappings re-derive from the rule's tags.

### Scheduled catalog refresh

Three toggles on `app_settings` (ATT&CK · SigmaHQ · D3FEND). A
celerybeat service in compose fires the refresh tasks on a fixed
cadence (daily for ATT&CK + SigmaHQ, weekly for D3FEND), short-circuits
when the flag is False, and appends a row to `scheduled_job_runs` per
fire. *Settings → Schedule* shows the last-run status chip + timestamp
under each toggle.

---

## Testing

Installer checks use temporary files and mocked system commands; they do not
install software, start services, or access a database:

```bash
python3 -m unittest discover -s tests -v
```

The backend suite uses the configured environment:

```bash
docker compose exec backend pytest -q
```

Run endpoint and integration tests only against a disposable test database.
Some fixtures delete shared tenant/reference records. Although `pytest.ini`
excludes tests marked `wipes_db` by default, that filter does not guarantee
that the remaining suite leaves existing data untouched.

Run the destructive set explicitly with:

```bash
docker compose exec backend pytest -m wipes_db
```

After that, re-seed via: ATT&CK `refresh_all` → sector profiles → GRC
seed → SigmaHQ sync → `provision_customer` → `seed_dummy_data`.

The pragmatic Sigma matcher has its own marker (`matcher`, 25 unit
tests, no DB). Customer-profile tests cover assets CRUD + linkage + RBAC
(18 tests), diagrams upload/list/download/RBAC/single-primary invariant
+ file-on-disk cleanup (12 tests).

---

## CMF classroom and student portal

Use [the classroom setup guide](docs/CMF_CLASSROOM.md) for tenant migration,
dedicated student accounts, synthetic ICS starter data, source validation,
JSON/CSV submissions, and scoped starter restoration.

MSSP users work at `/dashboard/cmf`. Students sign in using a `customer_user`
account assigned to one customer and open `/portal/cmf`. Create these users
under **Customers → select customer → Users**. Each student/team should have
its own customer so its collection inventory and plan remain separate.

Existing tenants must apply migration `0013_cmf_validation_fields`; restarting
the containers alone does not apply customer migrations. The guide includes
an explicit upgrade command that preserves the current inventory and accounts.

CMF integration tests in `tests/test_cmf_classroom_integration.py` run only
against the explicitly isolated `localhost:15432/cmf_test` database. They
skip elsewhere. Pure submission/starter-data tests can run with:

```bash
docker compose exec backend pytest --confcutdir=tests/cmf_unit tests/cmf_unit -q
```

---

## Project layout

```
detectmap/
├── docker-compose.yml          # db · redis · backend · worker · beat · frontend
├── docker-compose.tls.yml      # optional Caddy overlay
├── setup.py                    # interactive installer (TLS, port, factory-reset)
├── .env.example
├── CLAUDE.md                   # design contract + roadmap
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── alembic.ini             # two named sections: [public], [customer]
│   ├── migrations/
│   │   ├── public/             # shared catalog, orgs, users, super admins,
│   │   │                       # ATT&CK + D3FEND, GRC, app settings, job runs
│   │   └── customer/           # per-tenant: detections, coverage, connectors,
│   │                           # saved views, technique notes, gaps,
│   │                           # assets + diagrams + contacts
│   ├── app/
│   │   ├── config.py
│   │   ├── main.py
│   │   ├── worker.py           # Celery
│   │   ├── tasks/scheduled.py  # celerybeat-fired refresh tasks
│   │   ├── db/
│   │   │   ├── base.py         # async engine, PublicBase + CustomerBase
│   │   │   └── tenant.py       # ContextVar + tenant_session() + schema_for()
│   │   ├── models/
│   │   │   ├── public.py
│   │   │   └── customer.py
│   │   ├── core/
│   │   │   ├── security.py     # bcrypt + dual-secret JWT
│   │   │   ├── crypto.py       # Fernet wrapper
│   │   │   └── rbac.py
│   │   ├── api/                # auth · customers · catalog · detections ·
│   │   │                       # coverage · apt · gaps · posture · reports ·
│   │   │                       # grc · connectors · portfolio · settings ·
│   │   │                       # search · saved_views · roles ·
│   │   │                       # assets · diagrams
│   │   ├── services/           # provisioning, attack_ingest, sigmahq_sync,
│   │   │                       # d3fend_ingest, coverage, reports,
│   │   │                       # detection_samples, ai_sigma, connector_tests,
│   │   │                       # diagram_storage, …
│   │   └── scripts/            # bootstrap, pass-reset, seed_demo, …
│   ├── storage/diagrams/       # bind-mounted host directory for diagram bytes
│   └── tests/                  # 262 non-destructive + wipes_db marked set
└── frontend/
    ├── Dockerfile              # production: `next build` then `next start`
    ├── package.json
    ├── app/
    │   ├── theme.ts            # MUI v6 theme + coverage / gradient tokens
    │   ├── ColorModeContext.tsx
    │   ├── PreferencesProvider.tsx
    │   ├── layout.tsx · providers.tsx
    │   ├── login/ · change-password/
    │   ├── dashboard/          # MSSP surface
    │   │   ├── customers/      # incl. ProfileTab.tsx (profile drawer)
    │   │   ├── coverage/ · detections/ · apt/ · gaps/ · posture/ ·
    │   │   ├── reports/ · grc/ · connectors/ · portfolio/ · settings/
    │   └── portal/             # customer-user surface
    │       ├── organization/   # read-only profile mirror
    │       └── profile/        # user's own account + password change
    └── lib/
        ├── auth.ts             # token + active customer (localStorage + event bus)
        └── api.ts              # axios; per-call X-Customer override; blob helpers
```

---

## Security notes

- **Two JWT secrets.** `JWT_TENANT_SECRET` and `JWT_SUPERADMIN_SECRET` are different. The `aud` claim routes the token to the correct verifier. Tests in `tests/test_security.py::TestJWTAudienceSeparation` lock this contract in.
- **Codename validation.** `schema_for(codename)` validates against `^[a-z][a-z0-9_]{1,30}$` before any SQL interpolation; tenant SQL never receives an unvalidated identifier.
- **Tenancy single entrypoint.** Never `.execute(text("SET search_path …"))` outside `tenant_session()`. Customer-scoped models have no schema qualifier so cross-tenant access is structurally impossible without a tenant set.
- **Customer users hard-pinned.** A `customer_user`'s JWT carries their `customer_id`; the `X-Customer` header is rejected if it disagrees. No way to reach another tenant from a customer login.
- **Secrets at rest.** Connector credentials, AI API keys, LDAP/SMTP credentials are Fernet-encrypted via `app/core/crypto.py`. Key rotation requires re-encryption under the new key — don't rotate without it.
- **Initial admin.** `setup.py` generates a random initial password, prints it once, and sets `must_change_password=True`. The login flow routes through `/change-password` until the user rotates it.
- **Diagram uploads.** Mime allow-list rejects HTML / JavaScript / executable types outright; binaries are always served with `Content-Disposition: attachment` so the browser won't execute them. Stored-path resolution checks the result stays under the storage root (path-traversal defence).
- **Tokens.** Bearer tokens currently live in `localStorage` for development convenience — migrate to HttpOnly cookies before going to production. Noted in `frontend/lib/auth.ts`.

---

## Container reset / fresh start

The explicit factory-reset option (`python3 setup.py --reset`) asks for confirmation before wiping the
database back to a single-admin slate, preserving reference data
(ATT&CK catalog, frameworks, sector profiles, D3FEND, SigmaHQ defaults)
where the seeding pipeline can rebuild it. After a wipe:

1. ATT&CK `refresh_all` (Enterprise + ICS + Mobile).
2. Sector-profile seed.
3. GRC framework seed (NIST CSF · ISO 27001 · NCA family).
4. D3FEND ingest.
5. SigmaHQ sync.
6. `provision_customer` for each customer + `seed_dummy_data`.

---

## Where to look next

- **CLAUDE.md** at the repo root — architecture invariants and the
  full roadmap including phase acceptance criteria.
- **`backend/app/services/`** — the meat of every feature lives here
  (ingest, coverage, reports, AI, connector tests, diagram storage).
- **`backend/tests/`** — read these alongside the services; they
  document the contracts.
- **`frontend/app/dashboard/`** vs. **`frontend/app/portal/`** — the
  MSSP analyst surface vs. the customer-facing portal mirror.
