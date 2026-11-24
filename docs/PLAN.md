# MaGMa Use Case Framework Webapp: Implementation Plan

> **Historical document.** This is the original plan from November 2026; milestones M0 to M7 are built. Some parts were changed or removed later (the maturity self-assessment, YAML configurations, L2 configurations); the README and the code are the current reference, and later features are specified in `features/`. Code comments still point to its sections.

Status at the time: **draft v2 for review** (no code written yet). v2 adds your decisions from 13.11.2026: local login + SSO, the roles admin / analyst / auditor, more than one data source per rule, new scoring without the Excel quirks, onboarded / last verified dates, and generated random test data.
Target repo: https://github.com/s0mberlain/MagmaGUI (currently only an initial README)
Sources analysed:
- FI-ISAC "MaGMa: a framework and tool for use case management" (short version, PDF)
- `Magma-UCF-Tool.xlsx` (MaGMa UCF Tool v1.0, 15.11.2017), the reference implementation

---

## 1. Goal

A self-hosted web application, shipped as a Docker image, that replaces the MaGMa UCF Excel tool. It must:

1. Reproduce the Excel tool's content: the same layers, identifiers, reference lists and metrics. Results are calculated with a cleaned-up scoring model (section 2.5), **not** the Excel quirks, so numbers will differ from Excel on purpose.
2. Import an existing filled-in UCF Excel workbook, and export back to Excel.
3. Add what the framework describes but the Excel cannot do well: lifecycle management, history over time (control metrics), output metrics, maturity assessment, multi-user editing with an audit trail.

---

## 2. What the reference Excel contains

### 2.1 Sheets and their framework layer

| Sheet | Framework layer | Content |
|---|---|---|
| Introduction / Model / Usage | (docs) | Version info, explanation of layers, identifiers and metrics |
| **Drivers** | Business layer | 6 business drivers (BD-01 … BD-06, name + description); compliance drivers (ID = policy rule ref, grouped as "Internal Security Policy", "External Regulator #1", "External Regulator #2", 5 slots each) |
| **L1 UC** | Threat layer (strategic) | 12 L1 use cases + 1 "N/A" (Weaponization). Columns: threat category (Cyber killchain / Other threats), ID (2 chars), name, purpose, stakeholders, description, and calculated counts and metrics. Also the "Overall Performance" block and 3 charts |
| **L2 UC** | Threat layer (tactical) | 62 L2 use cases. Columns: ID (`XX-YYY`), name, description, actors, business driver, internal policy ref, external regulator #1 ref, external regulator #2 ref, plus calculated L1 name/ID, #L3 and average metrics |
| **L3 UC** | Implementation layer (operational) | 169 L3 use cases (rules), mostly mapped to MITRE ATT&CK techniques (description column holds an ATT&CK URL, e.g. T1001). Columns: rule ID (`XX-YYY-NN`), technical name, description, Effectiveness %, Implementation %, Coverage %, Weight, Potential, log source type, detection technology, scope, comments |
| **References** | Implementation layer | Reference lists: 7 threat actors (CSAN 2017), detection technologies (SIEM, Big data analytics, NIDS/NIPS, HIPS, Anti-malware, Network anomaly detection, Email protection, …), log sources (Firewall, Network traffic, OS logging, Application log, Web application logging, Database log, Proxy log, …), 18 scope values (All users, VIPs, Administrators, Business critical assets, …) |
| **Results** | Reporting | Overall KPIs and counts (see 2.3) |

Dropdowns (data validation) tie the sheets together: L2 Actors ← threat actors, L2 business driver ← business drivers, L2 policy/regulator refs ← compliance driver IDs, L3 log source / detection technology / scope ← References lists. Each L3 field takes **one** value in Excel.

The shipped workbook has all L3 metrics at 0 and no actors/drivers/log sources filled in, so it serves as the **seed catalogue**, not as sample data.

### 2.2 Identifiers (the glue between layers)

- L1: exactly 2 characters, e.g. `DE`
- L2: L1 ID + `-` + 3 characters, e.g. `DE-WEB`
- L3: L2 ID + `-` + sequence number, e.g. `DE-WEB-01`
- The parent is derived from the ID prefix (`LEFT(id,2)`, `LEFT(id,6)`). Duplicate IDs or descriptions are highlighted red.

### 2.3 Formulas to reproduce (the scoring engine)

All metrics are fractions 0..1, shown as percentages.

**L3 (entered per rule)**
- `effectiveness`, `implementation`, `coverage`: entered, 0–100 %
- `weight = effectiveness × implementation × coverage`
- `potential = effectiveness − weight`

**L2 (calculated)**
- `#L3 = count of L3 whose ID starts with this L2 ID`
- each of eff / impl / cov / weight / potential = **plain average over its L3s**; **0 if it has no L3s** (`IFERROR(SUMIF/COUNT, 0)`)

**L1 (calculated)**
- `#L2`, `#L3` = counts by prefix
- each metric = `AVERAGEIF` over **its L2 rows**, i.e. the average of the L2 averages (not weighted by number of L3s). L2s without any L3 count as **0** and pull the L1 average down. An L1 with no L2s gives `#DIV/0!` in Excel; the webapp will show "n/a" and leave it out.

**Overall ("Overall Performance" and Results sheet)**
- `Average Effectiveness / Implementation / Coverage ("Scope") / Weight / Growth Potential` = average over L1 rows (the N/A row is skipped)
- `SOC Detection Average (SOC Score) = average(avg effectiveness, avg implementation, avg coverage)`
- `SOC Detection Gap = 1 − average weight`
- Counts: business drivers, compliance drivers, L1, L2, L3, **distinct** detection technologies used in L3, **distinct** log source types used in L3

**Charts on L1 sheet** (per L1, bar charts): (1) effectiveness / implementation / coverage, (2) #L2 / #L3, (3) weight / potential.

**Conditional formatting**: colour scale on metric cells, red on duplicate IDs, highlight on L2s with 0 L3s.

### 2.4 What the framework PDF adds beyond the Excel

- **Lifecycle** with 4 phases: Onboarding (plan/build), Operational (run), Maintenance (change), Offloading (decommission). "Operational" has a definition of done: log sources delivering data, scope implemented, incident response documented, roles documented, rules implemented/tested/documented.
- **Change drivers** for maintenance: environmental (threat landscape, business, regulation, IT infrastructure) and operational (red teaming, incident lessons learned, threat hunting).
- **Growth**: capability (framework completeness = number of use cases; use case completeness = more assets/log sources/rules) and **maturity** on CMMI levels 1 Initial, 2 Managed, 3 Defined, 4 Quantitatively Managed, 5 Optimizing. Risk-based approach: risk level per use case drives the required implementation level.
- **Control metrics** (over time): framework changes, growth in number of use cases, change in monitoring scope, growth in weight, change in potential.
- **Output metrics** (per use case): number of alerts, incidents, false positive ratio, false negatives.

The short PDF gives no numeric scales or formulas; those come from the Excel (2.3).

### 2.5 Scoring model for the webapp (decided: no Excel quirks)

The per-rule formulas stay. The aggregation is fixed:

| Excel quirk | Webapp behaviour |
|---|---|
| A rule with no metrics entered counts as 0 % | Metrics are nullable. A rule is **assessed** only when all three metrics are set. Rules that are not assessed are left out of averages and shown as "not assessed" |
| An L2 without any L3 counts as 0 in the L1 average | Such an L2 is left out of the averages and shown as a **detection gap** in a separate completeness KPI |
| Rules in any state count | Only rules with lifecycle status **Operational** or **Maintenance** count for scores. Onboarding, Offloading and Retired rules are shown but not scored |
| L1 = average of L2 averages, overall = average of L1 averages | Same hierarchy (every threat counts equally, so 31 persistence rules don't outweigh a single-rule threat), but only over children that have a score |
| SOC score = avg(eff, impl, cov), gap = 1 − avg weight (two different bases) | **SOC Detection Score = average weight**, **Growth potential = average potential**, **Detection gap = 1 − SOC Detection Score**. All on the same basis |

Formulas:

```
rule (L3), if assessed and status in {Operational, Maintenance}:
  weight    = eff × impl × cov            (all 0..1)
  potential = eff − weight

L2: avg of eff, impl, cov, weight, potential over its scored rules
    → null if it has no scored rules
L1: avg of the same values over its L2s that are not null
Overall: avg over L1s that are not null (N/A L1s like Weaponization are skipped)

New KPIs:
  Framework completeness = L2s with ≥1 scored rule / applicable L2s
  Assessment coverage    = assessed rules / active rules
  Verification health    = rules verified within their interval / operational rules (see 3, item 9)
```

Optional later: a configurable "risk weight" per L2 so averages can be risk-weighted (ties in with the risk-based approach from the PDF).

---

## 3. Feature scope

### Core: Excel parity (MVP)
1. **Business layer**: CRUD for business drivers and compliance drivers (grouped by source: internal policy, regulator 1..n, with any number of sources instead of fixed 3).
2. **Threat layer**: L1 tree with threat category; L2 with actors, business drivers, compliance refs.
3. **Implementation layer**: L3 rules with the 3 metric sliders/inputs, live weight and potential, **one or more** data/log sources, one or more detection technologies, one or more scopes, comments, ATT&CK technique(s).
4. **Reference lists** editable in the UI: threat actors, detection technologies, log sources, scopes.
5. **Identifier rules** enforced: format validation, uniqueness, parent derived from the prefix, suggested next L3 sequence number.
6. **Scoring engine** as in 2.5, recalculated on every change.
6a. **Onboarding and verification dates** on L2 and L3: `onboarded_at`, `last_verified_at`, `last_verified_by`, verification note, and a verification interval (default for the workspace, overridable per rule). A "Verify now" button records a verification (date, user, result OK / issues found, note) in the history. Overview lists: overdue verifications, never verified, recently onboarded. L2 shows the oldest verification of its rules.
6b. **Users and roles** (see section 5a): local login and SSO, profiles admin / analyst / auditor.
6c. **YAML configuration per use case, versioned like git** (see section 4a). Every use case (L1, L2, L3; mainly used on L3 rules) can hold a YAML document, e.g. the detection rule as code (Sigma or SIEM-specific), tuning parameters, thresholds, exclusions, playbook links. In-browser editor with YAML highlighting and syntax check. Every save is a **commit** with message, author and timestamp. A history view lists commits like `git log`, shows a side-by-side or unified **diff** between any two versions, and can **restore** an old version (as a new commit, like `git revert`, so nothing is lost). Download the current or any old version as `.yaml`, upload a `.yaml` file as a new commit, and bulk export of all configs as a folder tree (`L1/L2/L3-ID.yaml`).
7. **Dashboard** = Results sheet + L1 Overall Performance + the 3 charts, plus a drill-down tree L1 → L2 → L3 with colour-coded metrics.
8. **Excel import** (the UCF workbook format) and **Excel export** (same layout, so it can still be opened as the classic tool).

### Framework extensions (phase 2+)
9. **Lifecycle status** per use case (Onboarding / Operational / Maintenance / Offloading / Retired) with the "Operational" definition-of-done checklist, and a change log with driver type.
10. **History & control metrics**: automatic snapshots (on demand and scheduled), trend charts for #use cases, avg weight, avg potential, scope changes; compare two snapshots.
11. **Risk-based prioritisation**: risk level and target implementation per L2/L3; "gap to target" view sorted by gap to target × risk (see README, Priorities).
12. ~~**Maturity self-assessment** (CMMI 1–5) with notes and history.~~ Built in M5, removed again on 2026-11-14 (migration 0012 drops the table).
13. **Output metrics** per L3: alerts, incidents, false positives, false negatives per period (manual entry first, CSV/API import later).
14. **MITRE ATT&CK view**: parse technique IDs from the old wiki URLs, map to current ATT&CK (techniques were renumbered/split into sub-techniques since 2017), heatmap of coverage per tactic/technique, export as ATT&CK Navigator layer JSON.
15. **Audit trail** on every change (who, when, old → new), visible to admin and auditor.
16. **Reports**: PDF/HTML management report and CSV exports.

### Explicitly out of scope (for now)
- Live connection to a SIEM (Splunk, Sentinel, QRadar …) to pull rules or alert counts. Can be added later via the API.

---

## 4. Data model

Relational, IDs from the framework kept as business keys, real foreign keys underneath (so renaming an ID cascades cleanly).

```
workspace            (id, name)                       -- optional multi-tenancy, 1 by default

business_driver      (id, workspace_id, code 'BD-01', name, description)
compliance_source    (id, workspace_id, name 'Internal Security Policy' | 'External Regulator #1' ...)
compliance_driver    (id, source_id, ref, name, description)

threat_actor         (id, workspace_id, name, description)
detection_technology (id, workspace_id, name, description)
log_source           (id, workspace_id, name, description)
scope                (id, workspace_id, name, description)

l1_use_case          (id, workspace_id, code CHAR(2) UNIQUE, name, threat_category, purpose,
                      stakeholders, description, applicable BOOL, sort_order)
l2_use_case          (id, l1_id, code 'XX-YYY' UNIQUE, name, description,
                      lifecycle_status, risk_level, target_implementation,
                      onboarded_at DATE, last_verified_at DATE, last_verified_by)
l2_actor             (l2_id, threat_actor_id)              -- many-to-many
l2_business_driver   (l2_id, business_driver_id)           -- Excel: 1, webapp: many
l2_compliance_driver (l2_id, compliance_driver_id)         -- Excel: 1 per source

l3_use_case          (id, l2_id, code 'XX-YYY-NN' UNIQUE, name, description,
                      effectiveness NUMERIC(0..1) NULL, implementation NULL, coverage NULL,
                      lifecycle_status, comments, attack_technique_ids TEXT[],
                      onboarded_at DATE, last_verified_at DATE, last_verified_by,
                      verification_interval_days NULL,      -- NULL = workspace default
                      created_at, updated_at)
l3_log_source        (l3_id, log_source_id)                -- many data sources per rule
l3_detection_tech    (l3_id, detection_technology_id)
l3_scope             (l3_id, scope_id)

config_commit        (id, use_case_level, use_case_id, revision_no,      -- 1, 2, 3 … per use case
                      parent_id NULL, sha256 (content hash, shown short like a git hash),
                      content TEXT (full YAML), message, author_user_id, committed_at,
                      restored_from_id NULL, tag NULL)                     -- immutable, append-only
config_head          (use_case_level, use_case_id, commit_id)            -- current version
verification         (id, use_case_level, use_case_id, verified_at, user_id,
                      result 'ok' | 'issues', note)        -- history behind last_verified_at
lifecycle_event      (id, use_case_level, use_case_id, from_status, to_status,
                      driver_type, driver, note, user_id, at)
output_metric        (id, l3_id, period_start, period_end, alerts, incidents,
                      false_positives, false_negatives)
maturity_assessment  (id, workspace_id, level 1..5, notes, assessed_by, at) -- removed 2026-11-14
snapshot             (id, workspace_id, label, taken_at, data JSONB)  -- full computed results
audit_log            (id, user_id, entity, entity_id, action, diff JSONB, at)
user                 (id, username, email, display_name, role 'admin'|'analyst'|'auditor',
                      auth_source 'local'|'sso', password_hash NULL, sso_subject NULL,
                      mfa_secret NULL, active BOOL, last_login_at)
workspace_settings   (workspace_id, default_verification_interval_days DEFAULT 180, ...)
```

Weight, potential and all L2/L1/overall aggregates are **calculated, not stored** (one scoring module, unit tested against Excel), except inside snapshots.

## 4a. YAML configuration and its history

How it works like git, without making users learn git:
- **Commits are immutable.** Each save stores the full YAML text, a SHA-256 hash, parent commit, author, time and a commit message (required, with a suggested default such as "Update threshold"). Nothing is ever overwritten or deleted, which also suits the auditor role.
- **Log, diff, blame-light**: commit list per use case; diff between any two commits (unified or side by side); each line of the current version can show the commit that last changed it (optional, later).
- **Restore** = new commit with the old content (`restored_from` points to the source), like `git revert`.
- **Tags**: mark a commit, e.g. `verified-2026-11` or `prod`. "Verify now" (6a) can automatically tag the current config version, so you can see exactly which config was verified.
- **No lost updates**: saving sends the commit the user started from. If someone else committed in between, the save is refused with a diff, and the user merges by hand (like a rejected `git push`).
- **Free-form YAML**: any structure is allowed; the only check before commit is that it parses as valid YAML (the error line is shown in the editor).
- **Storage**: in the app database, always (simple backup, works with SQLite and Postgres; YAML files are small, full copies are fine). Diffs are computed when viewed. The app works fully without any git server.
- **Optional git repository connection** (off by default, set up by an admin in the UI or via env `GIT_REMOTE_URL`, `GIT_BRANCH`, `GIT_AUTH` = SSH deploy key or HTTPS token):
  - Every app commit becomes a real git commit (same message, author name/email, time) in a working copy on the data volume, file layout `usecases/<L1>/<L2>/<L3-ID>.yaml`, then pushed to the remote (GitHub, GitLab, Gitea, Bitbucket, Azure DevOps).
  - App tags become git tags.
  - Push runs in the background with retry; a status page shows the last sync, errors and the commit hash. If the remote is down, the app keeps working and syncs later.
  - One-time "initial export" pushes the full history of existing configs.
  - Direction is app → git only in v1. Pulling changes made directly in git back into the app (two-way sync) is an option for later.
  - Implemented with `dulwich` (pure-Python git) or the `git` CLI inside the image.

API: `GET/PUT /api/usecases/{id}/config`, `GET …/config/history`, `GET …/config/commits/{sha}`, `GET …/config/diff?from=&to=`, `POST …/config/restore/{sha}`, `POST …/config/tags`.

---

## 5. Architecture and tech stack

Recommendation (one container, simple to run):

| Part | Choice | Why |
|---|---|---|
| Backend | **Python 3.12, FastAPI, SQLAlchemy 2, Alembic, Pydantic** | `openpyxl` makes Excel import/export straightforward in Python; FastAPI gives an OpenAPI spec for free (useful for later SIEM integration) |
| Database | **SQLite** by default (file on a volume); **PostgreSQL** optional via env var | Zero-config single container for small teams; Postgres for multi-user production |
| Frontend | **React + TypeScript + Vite**, TanStack Query/Table, a component library (Mantine or shadcn/ui), **ECharts** for charts, **Monaco editor** (YAML highlighting + diff view) | Rich editable tables (169+ rows), dashboards, config editing |
| YAML & git | `ruamel.yaml` (syntax check, keeps comments), `difflib` for diffs, `dulwich` for the optional git connection | |
| Auth | Local users (argon2 hashes) **and** SSO via **OpenID Connect** (Entra ID, Keycloak, Okta, ADFS, Authentik …) with Authlib; server-side sessions in secure cookies | Both requested; see 5a |
| Testing | pytest (scoring + import parity), Playwright for UI smoke tests | |

Structure:

```
MagmaGUI/
  backend/   app/{api,models,scoring,importers,exporters,auth}, alembic/, tests/
  frontend/  src/{pages,components,api}
  seed/      magma_ucf_default.json   (catalogue extracted from the Excel: 12 L1, 62 L2, 169 L3, reference lists)
  Dockerfile, docker-compose.yml, .env.example, README.md
```

Main screens: Dashboard · Business drivers · Use case tree (L1/L2/L3) with inline-editable table · Use case detail (metrics, lifecycle, history, ATT&CK) · Reference lists · ATT&CK heatmap · History/trends · Import/Export · Admin (users).

---

## 5a. Users, login and roles

**Login methods** (both can be active at the same time):
- **Local accounts**: username + password (argon2id), password policy, lockout after failed attempts, optional TOTP second factor. The first admin is created from env vars on first start. Local login can be switched off once SSO works (admin keeps a break-glass account).
- **SSO via OIDC**: "Sign in with SSO" button. Users are created on first login (just-in-time). Role comes from an IdP **group claim mapping** set in env/admin UI (e.g. group `SOC-Admins` → admin, `SOC-Analysts` → analyst, `Audit` → auditor). Without a matching group: no access (or a configurable default role).

**Profiles (permissions)**

| Action | admin | analyst | auditor |
|---|---|---|---|
| View dashboard, use cases, history, reports | ✓ | ✓ | ✓ |
| Export (Excel, CSV, PDF, ATT&CK layer) | ✓ | ✓ | ✓ |
| View audit log | ✓ | – | ✓ |
| Create / edit L1, L2, L3, metrics, verifications, lifecycle | ✓ | ✓ | – |
| View YAML configs, history and diffs, download `.yaml` | ✓ | ✓ | ✓ |
| Commit, restore and tag YAML configs | ✓ | ✓ | – |
| Edit drivers and reference lists | ✓ | ✓ | – |
| Delete use cases | ✓ | ✓ (soft delete / offloading only) | – |
| Excel import (merge) | ✓ | ✓ | – |
| Excel import (replace all), restore backup | ✓ | – | – |
| Manage users, roles, SSO and app settings | ✓ | – | – |

Permissions are enforced in the API (one dependency per endpoint), not only by hiding buttons. Auditor sessions are fully read-only. Each change goes to the audit log with the user.

---

## 6. Docker setup

- **Multi-stage `Dockerfile`**: stage 1 `node:22-alpine` builds the frontend; stage 2 `python:3.12-slim` installs the backend, copies the built static files, runs as non-root, serves both the API (`/api`) and the SPA from one **uvicorn** process on port 8080. Healthcheck on `/api/health`.
- On start: run Alembic migrations, and if the database is empty, load the default MaGMa catalogue (seed) and create the first admin from env vars.
- **`docker-compose.yml`**:
  - default: one service `magma`, volume `magma-data:/data` (SQLite)
  - profile `postgres`: adds a `postgres:16` service, `DATABASE_URL` points to it
- Config via env: `DATABASE_URL`, `SECRET_KEY`, `ADMIN_USER`, `ADMIN_PASSWORD`, `LOCAL_LOGIN_ENABLED`, `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_ROLE_CLAIM`, `OIDC_ROLE_MAP` (e.g. `SOC-Admins=admin,SOC-Analysts=analyst,Audit=auditor`), `BASE_URL`, `SNAPSHOT_CRON` (optional), `DEMO_DATA=true` (optional, see 7a).
- Compose profile `keycloak` for local SSO testing (a Keycloak with three preconfigured test users, one per role).
- GitHub Actions: lint, tests, build image, push to **GHCR** (`ghcr.io/s0mberlain/magmagui`) on tag.
- Run: `docker compose up -d` → http://localhost:8080. Backup = copy the volume or use the JSON/Excel export.

---

## 7. Excel import / export

Import (`POST /api/import/excel`, with a preview step before committing):
1. Detect the UCF layout by sheet names (`Drivers`, `L1 UC`, `L2 UC`, `L3 UC`, `References`) and header texts, not fixed cell positions, so rows added by users are found.
2. Read **input columns only**; recompute all calculated columns ourselves (with `openpyxl` formulas are not evaluated anyway).
3. Order: References → Drivers → L1 → L2 → L3. Parents are resolved from the ID prefix, like Excel.
4. Validate and report: bad ID formats, duplicates, orphan L2/L3 (no parent), values that are not in the reference lists (offer "add to list"), percentages given as 0–100 instead of 0–1.
5. Modes: **replace** workspace or **merge** (upsert by ID).
6. Parse ATT&CK technique IDs from L3 description URLs (`.../Technique/T1001` → `T1001`).

Export: write the same 9-sheet layout including formulas, so the export still works as the classic Excel tool, plus a JSON full backup.

On import, a single value in a log source / detection technology / scope cell becomes one entry; values separated by `;` or `,` become several. On export, several values are joined with `;`. Onboarded / last verified dates get their own extra columns in the export (the classic tool ignores them).

## 7a. Random demo and test data

There is no filled-in workbook, so the app gets a **demo data generator** (`magma demo-data --seed 42`, also via `DEMO_DATA=true` on first start, and an admin button "reset to demo data"):
- Starts from the real catalogue (12 L1 / 62 L2 / 169 L3).
- Random but realistic values: about 70 % of rules Operational, 10 % Maintenance, 15 % Onboarding, 5 % Offloading; about 10 % not assessed; metrics drawn per detection technology (e.g. EDR rules higher, DNS rules lower); 1–3 data sources, 1–2 detection technologies and 1–2 scopes per rule; onboarded dates over the last 3 years; last verified dates so that some are overdue and some never verified; a few L2s with no rules (to show gaps); actors and drivers on L2; verification and lifecycle history; 12 months of output metrics; 3 users (one per role); several snapshots for trend charts.
- A fixed seed makes it reproducible, so the same data is used in automated tests.

Tests: unit tests of the scoring rules in 2.5 with small hand-made cases (including null metrics, empty L2s, non-scored lifecycle states), property tests on random data (all scores between 0 and 1, potential ≤ effectiveness), and an import → export → import round trip on a generated workbook.

---

## 8. Milestones

| # | Milestone | Content | Done when |
|---|---|---|---|
| M0 | Skeleton | Repo layout, FastAPI + React hello world, Dockerfile, compose, CI | `docker compose up` serves the app |
| M1 | Data model, catalogue, local login | DB schema, migrations, seed catalogue (12/62/169 + reference lists), CRUD API, ID validation, local accounts, roles admin / analyst / auditor enforced in the API, audit log | API returns the catalogue; auditor gets 403 on writes |
| M2 | Scoring, core UI, demo data | Scoring module (2.5) with tests, demo data generator, use case tree and editable L3 table (multi data sources), onboarded / verified fields and "Verify now", drivers and reference list screens | Editing a metric updates L2/L1/overall; demo data looks realistic |
| M3 | Dashboard, Excel I/O, SSO, YAML configs | KPIs incl. completeness and verification health, L1 charts, overdue-verification list, Excel import with preview + export, OIDC login with group → role mapping, user admin screen, YAML editor with commit / history / diff / restore / tags and `.yaml` download/upload; demo data includes sample configs with a few commits each | **MVP release v1.0** |
| M4 | Lifecycle, history, git | Lifecycle status, change log with drivers, definition-of-done checklist, snapshots, control-metric trends, optional git repository connection for YAML configs (compose profile `gitea` for local testing) | Trend charts; configs show up in a connected git repo |
| M5 | Growth | Risk level / target implementation, gap-to-target view, maturity assessment (removed 2026-11-14), TOTP for local accounts | v1.1 |
| M6 | ATT&CK & output metrics | ATT&CK remapping and heatmap, Navigator export, output metrics entry/CSV import, PDF report | v1.2 |
| M7 | Optional | Postgres hardening, two-way git sync, SIEM integrations, i18n (DE/NL/EN) | as needed (done: SIEM as push API + API tokens) |

---

## 9. Decisions and open questions

Decided (13.11.2026):
- Local login **and** SSO; multi-user with profiles admin, analyst (day-to-day work), auditor (read-only). → 5a
- Rules can have more than one data source (also more than one detection technology and scope). → 4
- Excel scoring quirks are not kept. → 2.5
- No real workbook available; random demo data is generated. → 7a
- Track when a use case was onboarded and last verified. → 3 (6a), 4
- Each use case can store a `.yaml` configuration with git-like change history. → 3 (6c), 4a
- YAML is **free-form** (only checked for valid YAML syntax, no schema).
- Connecting to a real git repository is **optional**, switched on per installation. → 4a

Still open (I'll go with the **default** unless you say otherwise):
1. **SSO protocol and IdP**: OIDC covers Entra ID, Keycloak, Okta, ADFS. Do you also need SAML? Which IdP do you use? *Default: OIDC only.*
2. **Database**: SQLite in a volume, or PostgreSQL as default? *Default: SQLite, Postgres optional.*
3. **Verification interval**: *Default: 180 days, changeable globally and per rule.* Does "verified" need a result (OK / issues found) and note, as planned?
4. **Scoring hierarchy**: every L2 threat counts equally in its L1 (as planned), or should L1 average all its rules directly? *Default: every L2 equal.*
5. **Analyst permissions**: may analysts edit reference lists and drivers and do merge imports, as in the table in 5a? *Default: yes.*
6. **ATT&CK**: map the 2017 technique IDs to the current ATT&CK version? *Default: yes, in M6.*
7. **UI language**: *Default: English.* Also German/Dutch?
8. **Hosting**: *Default: behind your reverse proxy, which does TLS.*
9. **Stack**: *Default: Python/FastAPI + React.*
