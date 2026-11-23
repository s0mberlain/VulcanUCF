# CLAUDE.md

Guidance for working in this repository. Read this first; `README.md` (operations, env vars,
feature details) and `docs/PLAN.md` (original design and decisions) go deeper.

## What this app is

**Vulcan UCF** (repository and technical names: MagmaGUI / `magma`; renamed in the UI on 2026-11-21) is a self-hosted web app that replaces the FI-ISAC
**MaGMa Use Case Framework (UCF) Excel tool** (v1.0, 2017). It is used by a SOC to manage its
security-monitoring (SIEM) use cases. The source is the short framework paper:
https://www.betaalvereniging.nl/wp-content/uploads/2026/03/FI-ISAC-use-case-framework-verkorte-versie.pdf

### The framework (domain background)

MaGMa = **Ma**nagement, **G**rowth, **M**etrics & **a**ssessment. A *use case* is "a security
monitoring scenario aimed at detecting manifestations of a cyber threat". It has three layers:

| Framework layer | Tool level | ID format | In the app |
|---|---|---|---|
| Business layer | — | `BD-01`, compliance refs | Business drivers and compliance drivers (grouped by compliance *source*, e.g. "Internal Security Policy", "External Regulator #1") |
| Threat layer, strategic | **L1** | 2 chars, e.g. `AO` | 12 L1s + "Weaponization" (not applicable). The 7 Lockheed Martin kill-chain steps plus 6 others (Fraud, DDoS, Physical, Blacklisting, Sabotage, Policy Violations) |
| Threat layer, tactical | **L2** | `L1-XXX`, e.g. `AO-CRE` | 62 L2s; linked to threat actors, business drivers, compliance drivers |
| Implementation layer | **L3** ("rule") | `L2-NN`, e.g. `AO-CRE-01` (extra segments allowed: `XX-YYY-WIN-AD-01`) | 169 seeded rules, mostly MITRE ATT&CK techniques. Each rule has log sources, detection technologies, scopes, ATT&CK IDs, SIEM rule IDs, a JSON config |

The parent is derived from the ID prefix. The seed catalogue is `backend/app/seed/catalogue.json`.

Framework concepts and where they live in the app:

- **Management = lifecycle**: Onboarding → Operational → Maintenance → Offloading (+ Retired).
  Becoming *Operational* requires the **definition of done** (log sources deliver data, scope
  implemented, incident response documented, roles documented, rules implemented/tested/documented);
  admins can override (logged). Status changes record a **change driver**: environmental (threat
  landscape, business, regulation, IT infrastructure) or operational (red teaming, incident
  lessons, threat hunting, tuning). `backend/app/lifecycle.py`.
- **Growth**: capability (framework completeness, use case completeness) and the risk-based
  approach (risk level per use case → required implementation level). In the app: risk level 1–5
  and target implementation on L2 (rules inherit), the **Priorities** page. CMMI maturity
  self-assessment was built and then **removed on 2026-11-14** (migration 0012) — do not re-add it
  without being asked.
- **Metrics & assessment**:
  - *Embedded metrics* per L3: effectiveness, implementation, coverage (0..1, nullable).
    `weight = eff × impl × cov`, `potential = eff − weight`.
  - *Control metrics* over time: snapshots and trends (**History & trends**).
  - *Output metrics* per rule per month: alerts, incidents, false positives, false negatives
    (**Output metrics**, CSV import, SIEM push).

### Scoring (deliberately differs from the Excel)

`backend/app/scoring.py`. Numbers differ from the classic Excel on purpose:
- A rule is *scored* only if all three metrics are set **and** status is Operational or
  Maintenance (`SCORED_STATES`). *Active* = Onboarding/Operational/Maintenance (`ACTIVE_STATES`).
- L2 = average over its scored rules (null if none → shown as a **detection gap**, not 0).
  L1 = average of its non-null L2s; overall = average of non-null applicable L1s. Every L2 counts
  equally in its L1.
- **SOC detection score** = average weight; **detection gap** = 1 − score; **growth potential** =
  average potential. **Catalogue coverage** = same average but an applicable L2 without scored
  rules counts as 0. Also: framework completeness, assessment coverage, verification health.
- **Driver coverage** = average weight of linked L2s (unscored L2 = 0); below
  `DRIVER_LOW_COVERAGE` (30 %) is "low".
- **Priority** (`growth.py`) = gap to target × risk level ÷ 5 × driver boost (+10 % per linked
  driver, max +50 %). Missing implementation counts the whole target as gap. Default targets per
  risk level come from `RISK_TARGETS` (40 % … 90 %).
- **Verification**: operational rules re-verify every 180 days (per-rule override); never
  verified = overdue. "Verify now" also tags the current config `verified-<date>`.

### Threat modelling (the app's own extension, not in the framework paper)

Sidebar "Threat modelling" → `/systems`. Code: `backend/app/interviews.py` (logic, long module
docstring explains the data shape), `backend/app/api/systems.py`, `api/evidence.py`,
`interview_report.py` (PDF), frontend `pages/Systems.tsx`, `SystemDetail.tsx`, `Interview.tsx`,
`components/RiskCoverage.tsx`, `lib/stride.ts`.

Flow:
1. A **System** (business application) has a business owner (a contact, not a user),
   criticality 1–5, internet-facing, data classification, review interval (months).
2. An analyst runs a **business-owner interview** (at most one draft per system). Step 1 context
   + evidence files (stored in the DB); step 2 **components**, each with the log sources it
   delivers and the six **STRIDE** categories (applies / does not apply / not discussed),
   rated likelihood × impact = risk score 1–25 (risk level = ceil(score/5)). **Custom threats**
   link to MITRE ATT&CK techniques (T1110 matches its sub-techniques both ways). Step 3 risks and
   use cases.
3. Proposals: the admin-maintained **STRIDE mapping** (STRIDE category → L2 list, `/stride-mapping`,
   defaults in `DEFAULT_MAPPING`) proposes L2s for threats at or above the **proposal threshold**
   (default 8). Custom threats propose L2s whose rules cover the technique. With the **log source
   filter** on (default), an L2 is held back when none of its active rules' log sources meet the
   component's (no log sources on either side = not filtered, shown as a gap instead).
   The analyst can remove proposals (whole L2 or per risk), add L2s or single L3 rules by hand,
   and record *detection requests*.
4. Each risk gets a coverage: covered / partly covered / gap / below threshold / unrated, from the
   detection state of its use cases (ok "Detects", partial "Some log sources missing", blind,
   no active rule, unknown). Shown as a component × STRIDE heat grid plus a risk list.
5. **Complete** freezes the evaluated view into `Interview.result` and replaces the system's
   `SystemLink`s. Drafts are re-evaluated on every read. Then optional **owner confirmation**
   (name + date, sign-off file). Re-interviews start from the previous one and can be compared.
6. Effects elsewhere: system links show on use cases (filter "All systems"), and a linked
   system's risk level raises the rule's risk level in Priorities (`SystemRisks`, highest wins).

Interviews use optimistic locking (`expected_version`); a stale save gets 409.

### Purple teaming (VECTR-style, the app's own extension)

Sidebar "Purple teaming" → `/purple` (+ `/purple/library`, `/purple/trends`). Code:
`backend/app/purple.py` (pure logic: outcome order, metrics, trend, rule suggestions, Navigator
layer; module docstring explains the data shape), `api/purple.py` (assessments, campaigns, test
cases, red/blue saves, evidence, queue, exports), `api/purple_library.py` (templates, campaign
templates, bundled Atomic Red Team index, import), `purple_import.py` (ART YAML, SRA/VECTR
Threat Simulation Index YAML, CSV), `purple_report.py` (PDF), migration 0021; frontend
`pages/Purple*.tsx`, `lib/purple.tsx`, `components/PurpleTestsPanel.tsx`, shared
`components/EvidenceFiles.tsx` and `TechniquePicker.tsx` (also used by `Interview.tsx`).

- Assessment → campaigns → test cases. A test case has a **red side** (start/stop times,
  targets, notes) and a **blue side** (detections, findings notes), each saved separately with
  its own `red_version` / `blue_version` (plan fields: `plan_version`); stale → 409.
- **Detections** (`PtDetection`): `kind` "rule" (an L3, `rule_code` kept if the rule is deleted)
  or "tool" (any other defense, e.g. "Defender alert", "only in the logs"). Outcomes in VECTR
  priority: blocked > alerted > logged_central > logged_local > none > not_applicable > tbd.
  The test outcome is derived on read (never stored) unless `outcome_override`.
- **Evidence only**: blue → done (with `record_verification`, default on) records a
  `Verification` per linked L3 (`scores.record_verification`, ok for blocked/alerted, issues for
  logged/none). It never changes eff/impl/cov or scores. Priorities rows carry
  `last_test_outcome`; `GET /api/purple/rules/{code}/tests` feeds the rule page.
- `lineage_key` (`tpl:<id>` or `tc:<uuid>`) links runs of the same procedure across assessments;
  `POST …/rerun` copies an assessment with empty results; `/api/purple/trends` classifies
  improved / regressed / unchanged / new.
- Evidence of interviews and test cases share `app/uploads.py` and one storage limit.
- `app/attack_data/atomics.json` is generated by `backend/scripts/build_atomics.py` (ART, MIT).
- Findings are notes on the test case + the assessment summary by decision (no tracker).
- **Quick tests** (`api/purple_quick.py`, `pages/PurpleQuick.tsx`, migration 0022): one form records
  a single executed test with its defenses and finding. Stored as ordinary test cases in one hidden
  assessment with `kind == "quick"` (created on first use), excluded from the assessments list and
  the trends; deleting or re-running that container → 409.
- Demo data adds two demo assessments (`created_by == "demo"`) and demo procedures
  (`source == "demo"`).

### Other features (see README for details)

- **JSON config per L3 rule**, git-like: immutable commits (sha, author, message), history, diff,
  restore, tags; concurrent save → refused with diff. L2s have no config. Optional push to a real
  git repo, optional two-way pull (`gitsync.py`).
- **SIEM name** of a rule from an admin-defined format (`$companyName:$ucID:$ucName`), Settings page.
- **ATT&CK coverage** heatmap from a bundled offline Enterprise dataset
  (`attack_data/enterprise.json`), Navigator layer export, remapping of revoked 2017 IDs.
- **Excel import/export** in the classic UCF layout (with formulas), preview + merge/replace;
  JSON export (not re-importable).
- **SIEM integration** is push-only: API tokens (`mgm_…`, scopes siem/read), rule inventory and
  alert counts endpoints; samples in `deploy/siem/`.
- PDF management report, audit log, local login + OIDC SSO, TOTP 2FA, roles, EN/DE/NL UI.

### Roles

`admin` everything; `analyst` read and edit use cases, drivers, reference lists, interviews;
`auditor` read-only incl. audit log. Enforced in the API via dependencies in `api/deps.py`, not
only in the UI.

## Architecture

```
backend/app/
  main.py            FastAPI app, mounts routers under /api, serves the built SPA (static/)
  api/               one router per area (usecases, business, systems, evidence, configs,
                     lifecycle, growth, scores, output, attack_api, integrations, transfer,
                     snapshots, gitsync_api, auth, oidc, users, admin, app_settings, audit_log)
  models.py          SQLAlchemy 2 models (all tables)       schemas.py  Pydantic I/O
  scoring.py growth.py lifecycle.py interviews.py attack.py siem.py excel.py report.py
  configs.py gitsync.py snapshots.py audit.py security.py totp.py ratelimit.py middleware.py
  migrations/versions/  Alembic, numbered 0001…0022 (next is 0023)
  seed/catalogue.json   default MaGMa catalogue      demo.py  reproducible demo data (seed 42)
  cli.py             `magma` CLI: migrate, demo-data, reset-password, rotate-secret, db-copy
backend/tests/       pytest; files often named after issue numbers (test_issues_55_60.py)
frontend/src/        React 18 + TypeScript + Vite SPA
  pages/             one file per route (see App.tsx, nav.ts for the sidebar)
  components/ lib/   shared UI (ui.tsx), Markdown, charts, RiskCoverage, stride helpers
  api.ts             typed fetch client     auth.tsx  session context
  i18n.ts locales/{de,nl}.json serverTexts.ts   translations keyed by the English text
deploy/              keycloak realm, gitea init, SIEM push samples
docs/PLAN.md         original plan; docs/design/  approved design drafts
```

Database: SQLite by default (`/data/magma.db`), PostgreSQL optional; CI tests both and checks that
migrations match the models. Everything is one container on port 8080.

## Running it locally

On this machine there is **no Node/npm**, so run via Docker. Port 8080 is already in use locally;
use another host port:

```bash
docker build -t magmagui:local .
docker run -d --name magma-dev -p 127.0.0.1:8090:8080 \
  -e SECRET_KEY=$(python3 -c 'import secrets;print(secrets.token_urlsafe(48))') \
  -e ADMIN_PASSWORD='<choose one>' -e DEMO_DATA=true -e ALLOW_DEMO_DATA=true magmagui:local
# http://127.0.0.1:8090  (user admin), API docs at /api/docs after sign-in
```

Demo data fills metrics, statuses, verifications, configs, output metrics and 12 snapshots, but
**creates no systems or interviews** — create one by hand to see Threat modelling. It does create
two purple team assessments (a run and a re-run) for the Purple teaming pages.
`POST /api/auth/login` with `{"username","password"}` sets the session cookie. Cookie-authenticated
writes are refused (403) when `Origin`/`Referer` names a different site than `BASE_URL`; requests
without either header (curl, scripts) pass.

Without Docker: backend `cd backend && pip install -e ".[dev]" && uvicorn app.main:app --reload
--port 8000` (needs `SECRET_KEY` or `ALLOW_WEAK_SECRET_KEY=true`); frontend `npm run dev` (5173,
proxies `/api`).

## Observed behaviour (API functional test, 2026-11-18)

Verified against a running container (demo data) through the HTTP API, which is the same API
the SPA calls. These are the actual contracts; check them before writing scripts or tests.

**UI map** (`frontend/src/nav.ts`, grouped by domain since 2026-11-21): Daily work: Dashboard `/`,
Use cases `/usecases` (views Tree, L2 table, L3 rules `?view=rules` with bulk actions),
Verification `/verification`, Priorities `/priorities`. Threat modelling: Systems `/systems`,
STRIDE mapping. Purple teaming: Assessments `/purple`, Trends, Library. Analysis: ATT&CK coverage
`/attack`, Output metrics `/output`, History & trends `/history`. Setup: Business drivers
`/drivers`, Reference lists, Import / Export, Integrations, Audit log (admin+auditor), Users and
Settings (admin only). `/` focuses the page search (`data-hotkey-search`). Visual rules live in
`DESIGN.md`, product context in `PRODUCT.md`.

**Catalogue / demo data**: the seed has 169 L3 rules. Demo data adds about 67 generated rules
(description = `DEMO_MARK`) to L2s that had none, so a demo DB shows about 236 L3s.
`GET /api/catalogue/summary` gives the counts. Reference kinds are singular:
`/api/references/{threat_actor|detection_technology|log_source|scope}`.

**Use cases (L3)**
- `GET /api/l3/next-code/{l2}` → `{"code": "AO-CRE-10"}`. New rules start in **onboarding**.
  An unknown parent or a duplicate code is refused. Log sources etc. are passed **by name**
  (`"log_sources": ["OS logging"]`).
- `GET /api/l3/{code}` also returns calculated fields: `weight`, `potential`, `assessed`
  (all 3 metrics set), `scored` (assessed + Operational/Maintenance), `effective_risk` with
  `risk_source` (`rule|l2|system`) and `risk_system`, `effective_target`, `priority`,
  `siem_name`, `verification_overdue`. Metrics > 1 → 422.
- Lifecycle: `POST /api/l3/{code}/lifecycle {to_status, driver_type, driver, note, override}`.
  Going to operational with an incomplete DoD → 422 listing the missing items. DoD is set with
  `PUT /api/l3/{code}/dod {"items": {"log_sources": true, …}}`. `override: true` (admin)
  skips the DoD. Transitions are free **except** from retired: retired → operational /
  maintenance / offloading is blocked (must go back to onboarding first, 422). Operational →
  retired directly is allowed. `GET …/lifecycle` returns `allowed` targets and the DoD state.
- Verification: `POST /api/l3/{code}/verify {"result": "ok"|"issues", "note"}`. It tags the
  current config head `verified-YYYY-MM-DD` (`config_tag` in the response).
- Output metrics: `PUT /api/l3/{code}/output-metrics/YYYY-MM {alerts, incidents,
  false_positives, false_negatives?}`; the response shows `fp_rate` and `source` (`manual`,
  `demo`, SIEM).

**Config versioning (L3 JSON)**
- `PUT /api/l3/{code}/config {content, message, base_sha}` → 201. `base_sha` must equal the
  current head sha (`null` for the first commit). Otherwise you get **409 with `{detail, head,
  diff}`** like a rejected git push. This check runs *before* JSON validation, so a commit
  without `base_sha` on an existing config gets 409, not 422. Invalid JSON → 422 with
  line and column.
- Diff: `GET …/config/diff?from=<ref>&to=<ref>`. Refs can be a sha, `r<rev>` or a tag name.
  Restore: `POST …/config/restore/{ref}` **needs a JSON body** (`{"message": ""}`) and creates
  a new commit. Tags: `POST …/config/tags {name, ref?}`; a duplicate name → 409.

**Roles (all verified)**: auditor reads everything incl. `/api/audit`, gets 403 on every
write. Analyst edits use cases but gets 403 on the audit log, users and the STRIDE mapping
(the mapping is admin-only). Unauthenticated → 401. A cookie write with a foreign `Origin`
→ 403. The audit log records old and new values per field (`changes: {field: [old, new]}`)
plus the IP.

**Settings**: `PUT /api/settings/rule-name {format, variables: [{name, value}]}`. Built-ins
are `ucID ucName l2ID l1ID`. A changed format changes `siem_name` immediately (e.g.
`ACME:AO-CRE-10:…`).

**SIEM push** (Bearer `mgm_…` token, scope `siem`; a siem token gets 403 on `/api/scores` and
on use case edits):
- Inventory `PUT /api/integrations/siem/{source}/rules {"rules": [{"id", "name", "enabled",
  "severity", "techniques"}]}`. The field is **`id`**, not `rule_id`. The source name has to match
  `^[a-z0-9][a-z0-9_.-]{0,31}$`.
- Alerts `POST …/alerts[?dry_run=true] {mode: replace|add, batch_id?, items: [{rule, period,
  alerts, …}]}`. `rule` matches an L3 by `siem_rule_ids`, by the L3 code or by the SIEM name.
  A full date is cut to its month. Repeating a `batch_id` → `duplicate: true`, nothing applied.
- `GET /api/integrations/siem` reports `unlinked` SIEM rules (with ATT&CK-based `suggestions`),
  `disabled_but_operational` and `missing_in_siem`.

**Threat modelling**
- `POST /api/systems` (name, owner_name, criticality required). `PATCH /api/systems/{id}`
  **requires the full `SystemIn` body** (it behaves like a PUT; `{"archived": true}` alone
  → 422).
- `POST /api/systems/{id}/interviews` starts a draft (a second draft → 409). A re-interview
  copies the previous components and sets `previous_id`. `GET /api/interviews/{id}/compare`
  lists the added, removed and re-rated items.
- `PUT /api/interviews/{id}` needs `expected_version` + `interview_date`; a stale version → 409.
  The response has the evaluated **`view`**: `threshold, mapping_empty, log_source_filter,
  log_source_mismatch` (L2s held back by the filter), `components` (threats with `score`,
  `complete`), `incomplete, proposals, removed, below_threshold, added, removed_ids, requests,
  log_source_gaps, no_detection, components_without_log_sources, risks` (one row per risk with
  `level`, `above_threshold`, `coverage`, `use_cases[].detection`).
- `POST /api/interviews/{id}/complete` → 422 unless every *applies* threat has a description,
  likelihood and impact. After completion the system shows `linked`, `coverage`, `gaps`,
  `next_due` (date + review interval) and `can_delete: false`.
- Owner confirmation (`PUT …/confirmation`) works only after completion. Only drafts can be
  deleted. A system with a completed interview cannot be deleted (409, "archive it
  instead"). An L3 rule linked through a system *can* still be deleted.
- A rule's `effective_risk` takes the highest risk level among linked systems' risks that its
  L2 covers (`risk_source: "system"`).

**Exports**: `/api/export/excel` (xlsx), `/api/report.pdf`, `/api/interviews/{id}/pdf` and
`/api/attack/navigator.json` all return 200 with valid content.

## Checks before committing

```bash
cd backend && pytest -q && ruff check . && ruff format --check .
cd frontend && npm run build && npm run i18n:check
```

## Conventions

- **Name**: the product is **Vulcan UCF** in everything people see (UI, titles, reports, file names,
  docs). "MaGMa" is the framework and stays. Technical identifiers keep `magma` (CLI, `MAGMA_*`,
  cookie, `magma.db`, Docker names, `Magma-Token`, the JSON export `format` id) for compatibility.
- **Motion** uses GSAP through `frontend/src/lib/motion.ts` only (count-up, bar fill, rise-in,
  open-in, Flip rows, the sign-in strike). Content renders final first; every effect has a
  `prefers-reduced-motion` path. See DESIGN.md (Overview → Motion).
- **Every new UI string** goes through `t("English text")` and needs entries in
  `frontend/src/locales/de.json` and `nl.json` (CI fails otherwise; keep `{placeholders}`).
  Labels sent by the API must be listed in `serverTexts.ts`.
- **Schema changes** need a new Alembic migration in `backend/app/migrations/versions/` that
  works on SQLite and PostgreSQL (enums are stored as plain strings, `native_enum=False`).
- **Every change** to data is written to the audit log (`app/audit.py`) with old and new values.
- Permissions are enforced per endpoint; auditors must get 403 on writes.
- Scores are calculated, never stored (except inside snapshots).
- Work is tracked as numbered GitHub issues (`s0mberlain/MagmaGUI`); commits and tests reference
  them, e.g. "Threat modelling: … (#55 #57)". Docstrings often cite the issue number.
- User-facing docs live in `README.md`; update it when behaviour changes.
