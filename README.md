# Vulcan UCF

**Vulcan UCF** (formerly MagmaGUI / "Magma UCF") is a web application for the FI-ISAC **MaGMa Use Case Framework**: manage SIEM / SOC use cases across the business, threat (L1/L2) and implementation (L3) layers, score them, track verification and keep versioned YAML configs per use case.

Status: **M7**: MVP (catalogue, scoring, verification, JSON configs with history, Excel import/export, local login and SSO) plus lifecycle change log, history and trends, optional git sync, risk-based priorities, two-factor login, ATT&CK coverage, output metrics, PostgreSQL support, German and Dutch UI, two-way git sync and a SIEM push API. See [docs/PLAN.md](docs/PLAN.md) for the full plan and milestones, and [docs/design/](docs/design/) for the approved desktop design draft.

## Run with Docker

```bash
cp .env.example .env
# required: the app refuses to start without a strong SECRET_KEY
echo "SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')" >> .env
docker compose up -d --build
```

Open http://localhost:8080 and sign in as `admin`. Set `ADMIN_PASSWORD` in `.env` before the first start, or read the generated password from the log: `docker compose logs magma | grep "generated password"`.

On first start the database is created, migrated and filled with the default MaGMa catalogue (12 L1 + Weaponization (not applicable), 62 L2, 169 L3, reference lists, business drivers). Data is stored in the `magma-data` volume (`/data` in the container). API docs (signed-in users): http://localhost:8080/api/docs

`ADMIN_PASSWORD` is only used on the very first start, to create the first admin; changing it
later has no effect. To set a new password (it also unlocks the account and signs it out):

```bash
docker compose exec magma magma reset-password                # asks for the new password
docker compose exec magma magma reset-password --from-env     # takes ADMIN_PASSWORD from .env
docker compose exec magma magma reset-password alice --disable-totp   # lost authenticator too
docker compose exec magma magma reset-password alice --enable         # also re-enable a disabled account
```

A disabled account stays disabled unless you pass `--enable`.

Behind a reverse proxy, set `FORWARDED_ALLOW_IPS` to the proxy's address so the audit log records
the real client address (the image trusts only `127.0.0.1` by default; never use `*` when the
port is reachable directly). Without it every user appears to come from the proxy's address, so the
per-address sign-in limit counts all users together; the app logs a warning once when it sees
this.

## PostgreSQL

SQLite (one file in the volume) is fine for a small team. For more users or several app
replicas, use PostgreSQL:

```bash
echo "POSTGRES_PASSWORD=$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')" >> .env
docker compose -f docker-compose.yml -f docker-compose.postgres.yml up -d --build
```

Or point `DATABASE_URL` at your own server (`postgresql+psycopg://user:pw@host:5432/db`;
`postgres://` URLs work too). What the app does on PostgreSQL:

- Waits up to `DB_WAIT_SECONDS` (60) for the database on startup, then migrates.
- Several replicas can share one database: migrations and seeding run under an advisory lock,
  and the scheduled snapshot and the git sync run on one replica at a time.
- Connection pool with health checks (`DB_POOL_SIZE`, `DB_MAX_OVERFLOW`, `DB_POOL_RECYCLE`), all
  sessions in UTC, optional `DB_STATEMENT_TIMEOUT_MS`.
- Two saves of the same rule config at the same moment cannot get the same revision; the loser
  gets a 409 and reloads.
- `GET /api/ready` checks the database (503 when it is down), `GET /api/health` only the process.
- CI runs the full test suite on SQLite and on PostgreSQL 16, and checks that the migrations
  match the models on both.

**Moving from SQLite to PostgreSQL.** Start the Postgres stack once so the database exists, stop the
app (`docker compose … stop magma`), then copy everything (users, history, configs, snapshots …)
from the old volume:

```bash
docker compose -f docker-compose.yml -f docker-compose.postgres.yml run --rm magma \
  magma db-copy --source sqlite:////data/magma.db \
  --target "postgresql+psycopg://magma:$POSTGRES_PASSWORD@postgres:5432/magma" --replace
```

`--replace` is needed because the first start already seeded the catalogue and the first admin.
Ids are kept and the sequences are moved past them. An empty or
mistyped source is refused, so `--replace` cannot wipe the target by accident. Other commands: `magma migrate` and
`magma demo-data --seed 42`.

## Develop

Backend (Python 3.12+, FastAPI):

```bash
cd backend
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
uvicorn app.main:app --reload --port 8000
pytest && ruff check . && ruff format --check .
# the same tests on PostgreSQL (the database is emptied before each test):
TEST_DATABASE_URL=postgresql+psycopg://user:pw@localhost/magma_test pytest
```

Frontend (Node 22, React + Vite + TypeScript), proxies `/api` to port 8000:

```bash
cd frontend
npm install
npm run dev        # http://localhost:5173
npm run build
```

## Scoring and demo data

- Rule weight = effectiveness × implementation × coverage, potential = effectiveness − weight.
- Only operational and maintenance rules with all three metrics count. Empty L2 use cases are shown
  as detection gaps instead of counting as zero, and every L2 counts equally in its L1.
- Next to the SOC detection score the dashboard shows **catalogue coverage**: the same average,
  but an applicable L2 without scored rules counts as 0 (the rule driver coverage uses). One
  perfect rule in one of ten L2s gives a 100 % SOC score but 10 % catalogue coverage.
- Verification: operational rules must be re-verified every `DEFAULT_VERIFICATION_DAYS` (180) days
  unless the rule sets its own interval. Never verified counts as overdue.
- Demo data: start with `DEMO_DATA=true`, or run `python -m app.demo --seed 42` in `backend/`.
  With `ALLOW_DEMO_DATA=true` (or `DEMO_DATA=true`) admins can also load it from
  *Import / Export*. Loading deletes the verification, lifecycle and configuration history, so
  leave both off in production.

## JSON configurations

Every L3 rule can keep a free-form JSON configuration (query, thresholds, owner …). L2 use cases
only group rules and have no configuration.
It works like git without needing git: each save is an immutable commit (sha, author, message),
with history, diff between any two versions, restore (a new commit with the old content) and tags.
"Verify now" tags the current version as `verified-<date>`. If someone else saved in between,
your save is refused with a diff and you merge by hand. The only check is that the text is valid JSON
(an empty text means no configuration). Upload and download use `.json` files.

Configurations were YAML before; on upgrade (migration 0014) the latest YAML version of each rule
gets a JSON commit with the same data on top (author `system`, YAML comments are dropped). The
YAML versions stay in the history. Old L2 configurations stay in the database and the JSON
backup but are no longer shown.

### SIEM name of rules

Each rule page shows the rule's name as it should appear in the SIEM, with a Copy button. Admins
set the format under *Setup → Settings*, e.g. `$companyName:$ucID:$ucName` with the variable
`companyName = MYCORP` gives `MYCORP:IA-CMT-LOG-02:Failed Login Monitoring`. `$ucID`, `$ucName`,
`$l2ID` and `$l1ID` come from the rule; unknown `$names` stay as they are. The default format is
`$ucID:$ucName`. Settings are stored in the database (`app_settings`, migration 0015).

### Git repository (optional)

Set `GIT_REMOTE_URL` plus `GIT_TOKEN` (HTTPS) or `GIT_SSH_KEY_FILE` (SSH) and the app pushes every
configuration commit to that repository as a real git commit with the same author, date and
message, on `usecases/<L1>/<L2>/<L3>.json` (a `.yaml` file written by older versions is replaced
by the `.json` file at the rule's next export). Tags
become `<code>/<tag>`, e.g. `AO-CRE-01/verified-2026-11-13`. Sync runs in the background after each
commit (`GIT_AUTO_SYNC`) and at startup; admins see the state and can sync by hand under
*Import / Export*. To try it locally: `docker compose --profile gitea up -d` starts Gitea on port
3000 with user magma / magma-password and an empty repository `magma/usecases`; use the Gitea
values from `.env.example`.

**Two-way sync** (`GIT_PULL=true`, off by default): commits that people push to the branch and
that change one of these files are read back into the app as new config commits, with the git
author, date and message and a *from git* badge in the history. The app checks the repository
every `GIT_PULL_INTERVAL_MINUTES` (5) and at every sync; set `GIT_WEBHOOK_SECRET` and add a push
webhook to `<BASE_URL>/api/git/webhook` to pick changes up at once (GitHub and Gitea/Forgejo
signatures, GitLab token header, or `X-Magma-Token: <secret>`). Rules:

- Only valid JSON in a `.json` file of an existing rule is taken over; deleting the file clears the config.
- If the same config was also changed in the app and that change is not in git yet, the app
  version wins and is pushed on top. The git change stays in the repository history.
- What was not taken over (conflict, invalid JSON, unknown path) is listed under
  *Import / Export → Git repository* and in the audit log as `config_import`.
- The local working copy is a cache: it is reset to the remote branch before every sync, so
  force-pushes or edits in the repository never block the sync.

## Lifecycle, history and trends

Status changes go through *Change status* on the rule or L2 page and are logged with a change
driver (environmental: threat landscape, business, regulation, IT infrastructure; operational:
red teaming, incident lessons, threat hunting, tuning) and a note. A use case can only become
*Operational* when its definition-of-done checklist is complete (log sources, scope, incident
response, roles, rules); an admin can skip it, which is logged. *History & trends* shows control
metrics over time from snapshots (taken manually or by `SNAPSHOT_SCHEDULE`, monthly by default),
compares any two snapshots, and lists all status changes. Demo data includes twelve monthly
snapshots and a matching change log.

*Use cases → L3 rules* lists every rule in one table with search and filters (status, log
source, not scored, metrics missing, verification overdue). Tick rules there, or on
*Verification*, to verify them together or to change their status together. Each rule goes
through the same check as on its own page: the definition of done still applies (no override in
bulk), every change is in the audit log, and rules that could not be changed are listed. Press
`/` anywhere to jump to the search of the page, or to the rule list when the page has none.

When someone else saved a rule, an interview or a purple team test case while you were editing,
the save is refused and you choose: keep your changes (the next save overwrites theirs) or load
their version.

## Priorities

Every L2 use case has a risk level (1–5) and an optional target implementation; a rule follows
its L2 unless it sets its own. Without an explicit target the risk level gives one
(`RISK_TARGETS`, default 40 % for risk 1 up to 90 % for risk 5). *Priorities* lists the active
rules with the gap between implementation and target, sorted by priority = gap to target × risk ÷ 5
× driver boost, so the biggest shortfalls on the riskiest use cases come first. A rule that meets
its target has priority 0; a rule without an implementation score counts its whole target as gap,
so unassessed high-risk rules show up at the top instead of disappearing. Next to the number a
band says how urgent it is: *High* from 0.5, *Medium* from 0.2, otherwise *Low* (the scale tops out
at 1.35); the tooltip shows the calculation.

## Business and compliance drivers

Each L2 use case links to any number of business drivers and compliance drivers (from any
compliance source) as plain links without a weight; its L3 rules and its L1 inherit them
read-only. Analysts and admins set them on the L2 detail or in the table view of *Use cases*,
which can be filtered by business driver, compliance source and compliance driver. Every change
is in the audit log with the old and new links.

Driver coverage = average weight of the linked L2 use cases, where an L2 without scored rules
counts as 0. A driver without any linked use case is a gap; one below `DRIVER_LOW_COVERAGE`
(default 30 %) has low coverage. *Business drivers*, the dashboard, *Priorities* and the PDF
report show the coverage. Each linked driver raises the priority of the L2's rules by 10 %, at
most 50 %. Deleting a linked driver asks first and lists the use cases that lose the link.

## ATT&CK coverage

The app ships a compact copy of MITRE ATT&CK Enterprise (`backend/app/attack_data/enterprise.json`), so the
coverage page works offline. Each technique is coloured by the best weight of an operational rule mapped to it;
a rule on a sub-technique also counts for its parent. **Download Navigator layer** exports the same view as an
[ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) layer (score = weight × 100).

The original MaGMa catalogue uses 2017 technique IDs. Most were later revoked and replaced, or deprecated. The
page lists them, and an admin can replace revoked IDs by their successor in one step (**Review update**, audited).
Deprecated IDs without a successor stay on the rule until someone maps it by hand.

To refresh the bundled data from a newer ATT&CK release:

```bash
cd backend && python -m app.attack_data.update            # downloads the latest enterprise-attack.json
python -m app.attack_data.update path/to/enterprise-attack.json
```

## Output metrics and report

Each rule can record per month: alerts, incidents, false positives and (optionally) false negatives. Enter them on
the rule page or import a CSV file on **Output metrics** (columns `rule, period, alerts, incidents,
false_positives, false_negatives, note`; period `YYYY-MM`; comma or semicolon separated; **Check** runs a dry run,
and a file with any error imports nothing). The page shows monthly totals and the rules with the most false
positives.

**Download PDF report** on the dashboard creates a management report: KPIs, the SOC score trend, detection per
L1, top priorities, ATT&CK coverage per tactic, the noisiest rules and overdue verifications.

## SIEM integration

There is no live SIEM connector; instead the SIEM side pushes data to the app (see
[deploy/siem/](deploy/siem/) for a small client and Splunk / Sentinel searches):

- **API tokens** (*Integrations*, admin): each token is its own service account with the analyst
  or auditor role, sent as `Authorization: Bearer mgm_…`. Its access limits what it may call:
  *SIEM push only* (the default) reaches only the SIEM endpoints below, *Read only* any `GET`,
  or both. So a leaked SIEM token cannot change the catalogue. Revoking it disables the account;
  what it did stays in the audit log.
- **Rule inventory** `PUT /api/integrations/siem/<source>/rules`: the SIEM's full rule list. The
  *Integrations* page shows SIEM rules without a use case (with suggestions by ATT&CK technique),
  rules disabled in the SIEM but operational in the app, and linked ids no SIEM reports.
- **Alert counts** `POST /api/integrations/siem/<source>/alerts`: alerts, incidents and false
  positives per SIEM rule and month become the output metrics of the linked L3 rules
  (`mode: replace` for month totals, `add` for daily pushes, `?dry_run=true` to check). Send a
  `batch_id` with `add` pushes: a retry with the same id is not counted twice.

A SIEM rule is linked through the field *SIEM rule IDs* on the rule page, or by using the L3 code
as the SIEM rule id.

## Purple teaming

*Purple teaming* in the sidebar brings the workflow of tools like VECTR into the app, so test
results sit next to the use cases they prove or disprove.

- **Assessment → campaigns → test cases.** An assessment is one exercise (scope, environment,
  dates, a summary of the findings). Campaigns group test cases, e.g. by adversary or kill chain
  phase. A test case is one procedure: ATT&CK techniques, command, cleanup, operator guidance.
- **Red team side.** A run control like VECTR's: the status (*Not performed*, *In progress*,
  *Paused*, *Completed*, *Abandoned*) with a run clock and *Start* / *Pause* / *Resume* /
  *Complete* / *Abandon* / *Run again*, which record the attack times. The operator notes
  targets, sources, tools, what was run, and adds evidence. When the attack ran, the test goes
  to the blue team (*In review*). Who works on the red and blue side is picked from the app's
  analysts and admins (or typed, e.g. an external operator), also right in the campaign table.
- **Blue team side.** One row per defense: an **L3 use case rule** of the catalogue (the rules
  whose ATT&CK techniques cover the test are suggested) or **any other detection**, e.g. a
  Defender/EDR alert, a firewall block or "only in the logs". Each row has an outcome:
  *Blocked*, *Alerted*, *Logged (central)*, *Logged (local only)*, *Not detected*, *N/A*,
  *TBD*. The test outcome is the best one in that order (as in VECTR) unless set by hand. The
  **findings** (what was seen, what is missing, what to fix), detection and prevention steps and
  blue evidence (PDF, images, text/log, `.evtx`, `.pcap`) complete the review.
- The red and blue sides are saved separately, each with its own version, so both teams can work
  on the same test at once; a stale save gets 409. *My queue* lists the tests to run or review.
- **Link to the use cases (evidence only).** Marking the blue side *done* records a verification
  of each linked L3 rule (blocked/alerted = OK, logged/not detected = issues; can be switched
  off), which also tags the rule's config `verified-<date>`. The rule page lists its purple team
  tests and *Priorities* shows the last result. The embedded metrics and scores are not changed.
- **Metrics.** Defense success = blocked or alerted ÷ executed tests with a result; visibility =
  at least logged; mean time to detect = attack start to the first block or alert.
- **Library.** Reusable test procedures (with expected defenses, which become blue team rows) and
  campaign templates; assessments and campaigns can start from them. *Atomic Red Team* tests are
  bundled offline (`backend/app/attack_data/atomics.json`, MIT license, rebuilt with
  `python backend/scripts/build_atomics.py index.yaml <commit>`) and can be added to the library.
  **Import**: SRA/VECTR *Threat Simulation Index* YAML (each campaign becomes a campaign
  template, controls become expected defenses), Atomic Red Team YAML (a technique file or
  `index.yaml`) and the app's own CSV export, with a preview first.
- **Re-run** copies an assessment with empty results. Runs of the same procedure are linked, so
  *Purple team trends* shows defense success over assessments and which procedures improved or
  regressed (VECTR's resilience trending).
- **Exports**: PDF report (EN/DE/NL, "Draft" until completed), ATT&CK Navigator layer coloured
  by the weakest outcome per technique, CSV.
- **Quick tests** (*+ Quick test*, tab *Quick tests*). Test one detection or script without
  planning an assessment: one form takes what was tested (optionally from the library), the
  ATT&CK techniques, the script or command, targets and time, what each defense did (suggested
  use case rules or any other detection), and the finding. Saving records the test as executed
  and, unless unticked, the blue review as done with a verification of the linked rules. A quick
  test is an ordinary test case, so its page adds evidence or changes it later, and the rule
  page and *Priorities* show its result. Quick tests live in one hidden container (not listed
  with the assessments, cannot be deleted or re-run as a whole) and stay out of *Purple team
  trends*. API: `GET/POST /api/purple/quick-tests`.

## Excel import / export

*Import / Export* writes the classic MaGMa UCF Tool layout (L1 UC, L2 UC, L3 UC, Drivers,
References) with its formulas, plus extra columns for app fields. Import reads the same layout,
including the original tool, with a preview before anything is saved. The L2 business driver and policy /
regulator columns hold one value each, as in the classic tool: export writes the first link
there and every link in the app columns *All business drivers* and *All compliance drivers*;
import links both, and an unknown code is a warning in the preview. *Merge* adds and updates by
ID; *Replace* (admin) also removes what is not in the file. A JSON export includes
verifications, the change log, output metrics and the configuration history. It is meant for
reporting and other tools and cannot be imported again; back up the database itself.

Import follows the same rules as the app: a use case only becomes *Operational* through the import
when its definition of done is complete (admins may skip it, which is logged), every status change
is written to the change log, verification dates in the future are refused, and the importing user
is recorded as the verifier. Workbooks that unpack to more than 200 MB are refused. In the export,
text that starts with `=` is written as text, never as a live formula.

## Single sign-on (OIDC)

Set `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` and `OIDC_ROLE_MAP` (see `.env.example`)
and register `<BASE_URL>/api/auth/oidc/callback` as redirect URI at your IdP. Users are created on
first login; their role follows the mapped IdP group on every login, and users without a matching
group are refused (or get `OIDC_DEFAULT_ROLE`). Local login keeps working unless
`LOCAL_LOGIN_ENABLED=false`.

To try it locally: `docker compose --profile keycloak up -d` starts a Keycloak on port 8081 with
the users alice / bob / carol (admin / analyst / auditor, password `<name>-password`); use the
Keycloak values from `.env.example`.

## Two-factor login

Local accounts can turn on a TOTP second factor under *Account* (click your name in the
sidebar): scan the QR code with any authenticator app, confirm a code, and save the eight
one-time recovery codes. The secret is stored encrypted with `SECRET_KEY`. To change that key,
set the new one and run `magma rotate-secret --old <previous key>` once, otherwise existing
second factors stop working (an admin can also reset them under *Users*). SSO accounts use the
second factor of the identity provider.

## Security notes

- `SECRET_KEY` is required (at least 32 characters); `ALLOW_WEAK_SECRET_KEY=true` is for local
  development only.
- Changing a password, turning on two-factor login, or an admin resetting either signs the
  account out everywhere else.
- Wrong passwords and codes count toward the account lockout (`MAX_FAILED_LOGINS`,
  `LOCKOUT_MINUTES`), also on the *Account* page. Failed sign-ins per client address are limited
  too (`LOGIN_IP_MAX_FAILURES` per `LOGIN_IP_WINDOW_MINUTES`, in memory per process).
- Every response carries a strict Content-Security-Policy, `X-Frame-Options: DENY`, `nosniff`
  and, with an `https://` `BASE_URL`, HSTS. The audit log records the client address.
- **Two-way git sync is a trust boundary**: anyone who can push to the branch can change configs
  in the app. Protect the branch like you would the analyst role. Imported commits are shown with
  a `git:` prefix before the git author name (it is self-asserted), and a `Magma-Commit` trailer
  in someone else's commit is only trusted when the content matches the app's commit.
- SSO sessions last `SSO_SESSION_HOURS` (8) instead of `SESSION_HOURS`, and the role of an SSO
  account is set by the identity provider only.
- Requests larger than `MAX_BODY_MB` (25) are refused with 413, and text fields have length
  limits.
- Changes made with the session cookie (POST, PUT, PATCH, DELETE) are refused with 403 when the
  browser sends an `Origin` or `Referer` of another site; API tokens are not affected.
- Viewing and downloading interview and purple team evidence and exporting an interview or
  assessment PDF are written to the audit log (once per user, file and hour). All evidence together is limited by
  `EVIDENCE_MAX_TOTAL_MB` (2048); it is stored in the database, so only a database backup (or
  `magma db-copy`) keeps it, not the JSON export.
- The API docs load their assets from the app itself, not from a CDN.
- The SSO login page shows fixed texts only; IdP error details go to the log.

## Languages

The interface is available in English, German and Dutch. Pick the language at the bottom of the
sidebar (or on the sign-in page); it is saved on your account and follows you to other browsers.
Without a choice the browser language is used. The data itself (use case names, descriptions, the
ATT&CK catalogue) stays as entered; the Excel export keeps the classic English sheet layout.

Texts live in `frontend/src/locales/{de,nl}.json`, keyed by the English text used in
`t("...")`. `npm run i18n:check` (also in CI) fails when a text has no German or Dutch entry or a
`{placeholder}` got lost. Labels sent by the API (definition of done, change drivers, CMMI levels,
trend metrics) are listed in `frontend/src/serverTexts.ts` so they are translated too.

## Roles

| Role | Can |
|---|---|
| admin | everything, incl. users and deletes |
| analyst | read and edit use cases, drivers, reference lists, interviews and purple team assessments |
| auditor | read everything incl. the audit log, no changes |

The audit log can be filtered by user, action, object type, object (part of the key) and date
range (`GET /api/audit?user=&action=&entity=&search=&since=&until=`).

## Layout

```
backend/    FastAPI app (API under /api, serves the built SPA)
frontend/   React single-page app
docs/       plan and design draft
Dockerfile  multi-stage build: frontend → Python runtime, one container on port 8080
```

Motion in the UI uses [GSAP](https://gsap.com/) 3.13 (free "Standard" license, including commercial
use), only through `frontend/src/lib/motion.ts`; it respects the operating system's
reduced-motion setting.
