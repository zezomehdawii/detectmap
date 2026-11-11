# CMF classroom setup

The CMF workspace follows requirements → collection plan → implementation → validation → plan revision. Use a dedicated customer per student/team and the customer-pinned `/portal/cmf` workspace. Accounts with the built-in `customer_user` role can edit their own CMF records without selecting another customer. MSSP analyst accounts can select other customers in their MSSP and should be reserved for instructors.

## Prepare the runtime and student customers

1. Start Detect Map and select **Multi-tenant** during setup or under **Settings → Deployment**. You can choose **Start fresh**. The general Acme and Globex samples are separate from the classroom starter data. Do not run `setup.py --reset` or `factory_reset` on an existing deployment to prepare this lab.
2. Create a dedicated customer for each student/team through the existing administration UI, then create a customer user pinned to that customer. Choose globally unique codenames such as `cmf_team01`, `cmf_team02`. Existing tenant schema names are derived from codenames.
3. New customers receive current tenant migrations, and the standard Compose backend upgrades existing customers at startup. For a custom deployment, use these commands to preview and upgrade selected classroom customers:

```sh
docker compose exec backend python -m app.scripts.upgrade_tenants --customer cmf_team01 --customer cmf_team02
docker compose exec backend python -m app.scripts.upgrade_tenants --customer cmf_team01 --customer cmf_team02 --apply
```

The command validates all requested tenants before applying migrations. Schema migrations run sequentially per tenant; a failure does not roll back tenants already upgraded. Back up the deployment through the normal operational process before schema upgrades.

4. Preview and seed the teaching inventory in each dedicated classroom tenant:

```sh
docker compose exec backend python -m app.scripts.cmf_classroom show --customer cmf_team01
docker compose exec backend python -m app.scripts.cmf_classroom seed --customer cmf_team01 --apply
```

The seed requires an existing active customer. It does not create users, change passwords, connect to devices, run discovery, or change the global ATT&CK catalog. Repeating `seed` preserves existing starter edits and creates only missing starter records.

## Starter dataset

The dataset is synthetic training inventory, not captured telemetry or historical incident evidence. It includes:

| Site | Asset | Source | Storage | Declared retention | Follow-on collection |
|---|---|---|---|---|---|
| Control Center | Windows HMI | Windows Event Logs | Enterprise SIEM / windows-security | 60 days | Registry Keys |
| Data Center | Network Monitoring Appliance | Alerts | Enterprise SIEM / ics-alerts | 30 days | Packet Capture |
| Transmission Substation | RTU | Syslog | Local / RTU ring buffer | 7 days | Controller Logic |

The requirement asks students to investigate unauthorized controller changes with 30 days of RTU Syslog plus controller-logic evidence. The starter has two proposed plan items: close the 7-versus-30-day retention gap and arrange controller-logic collection. Source quality remains unscored. Students must justify quality from supplied sample evidence before choosing ratings. Starter ATT&CK labels are inventory mappings; no particular technique is claimed observable until evaluated against the loaded catalog.

## Restore the starter safely

```sh
docker compose exec backend python -m app.scripts.cmf_classroom reset --customer cmf_team01 --apply --confirm cmf_team01
```

`reset` restores only the deterministic `cmf-classroom-v1` starter records in the selected tenant, in place. It checks ownership markers before writing and refuses ID collisions with non-classroom records. It preserves record IDs and does not delete unrelated assets, student-added sources/requirements/plans, users, or global catalogs. Student-created additions therefore remain visible after restoration. For a completely clean exercise, start with a newly provisioned dedicated classroom customer; this command deliberately does not wipe a tenant.

Reset is an instructor CLI action and has no student-facing endpoint. Export student work before restoring starter values.

## Student workflow and submissions

- To discover assets from a supplied training capture, open **Collection register → Discover assets**, choose a PCAP or PCAPNG, and preview the endpoints. Select and import only devices that belong to the lab inventory. An observed IP is a clue; confirm the device role, site, and source capabilities before filling in the collection plan.
- Enter the source/component mapping, site/asset context, kill-chain phase, follow-on collection, storage location, and retention in the CMF collection register.
- Link each plan item to its requirement and target asset. Implementation means creating/updating the actual source record and linking it, not just selecting a status.
- Record validation evidence in plan notes: test/date, evidence reference, expected and observed result, and remaining gaps. Selecting “Validated” requires an enabled linked source and nonblank validation notes; it is a record of the student's assessment, not an automated SIEM validation.
- Material changes to a linked source (including mapping, storage, retention, or availability), or deletion of that source/asset, return completed plans to “In progress.” Existing evidence notes remain with a revalidation notice. Narrative-only edits do not reopen a completed plan.
- Download the CMF JSON submission for requirements, plan, inventory, and links. Download the register CSV for a flat collection table. Exports include only the active tenant and never include connector configurations or credentials. CSV contains assets with no sources so collection gaps remain visible.

Endpoints are `GET /cmf/export.json` and `GET /cmf/export.csv`, protected by the existing CMF read permission and active-customer checks. JSON schema version 1 is a submission snapshot, not an automatic backup/restore format. The existing asset JSON import is additive and cannot restore requirements or plans from this export.

## Pre-class acceptance check

1. Sign in as two customer users. Verify each sees and edits only their own customer.
2. Add the same mapped component in the central CMF and profile editor; reopen and compare stored values and visibility.
3. Clear optional retention/mapping/quality values and verify the cleared values persist.
4. Complete a requirement → plan → linked source → recorded validation → revised plan flow.
5. Export JSON and CSV, reopen them, and confirm both submissions contain the student's work without connector secrets.
6. Restore one customer's starter rows and verify another customer's records are unchanged.

Collection visibility scores summarize inventory across the tenant. They do not prove every individual controller/site is covered or that an attack would be detected. A full CMF teaching exercise can use inventories and sample logs; a PCAP or live SIEM is optional.
