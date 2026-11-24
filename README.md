# Vulcan UCF

Web application for the FI-ISAC **MaGMa Use Case Framework** (UCF). It keeps the SIEM / SOC use
case catalogue of a security operations team in one place: the business and threat layers
(L1 / L2) and the implementation layer (L3 detection rules), how well each rule works, when it was
last verified, which business risks and compliance duties it serves, and where detection is still
missing.

![Dashboard](docs/screenshots/dashboard.png)

One Docker container, SQLite or PostgreSQL, English, German and Dutch interface.

**New to the app?** The [user guide](docs/user-guide.md) explains the concepts and the main
workflows step by step: use cases and rules, status changes, priorities, threat modelling
interviews, purple team tests, output metrics and reports. This README covers installation,
configuration and operations.

## Contents

- [User guide](docs/user-guide.md)
- [Features at a glance](#features-at-a-glance)
- [Screenshots](#screenshots)
- [Quick start with Docker](#quick-start-with-docker)
- [Configuration](#configuration)
- [Features in detail](#features-in-detail)
- [Users, roles and sign-in](#users-roles-and-sign-in)
- [Integrations](#integrations)
- [Languages](#languages)
- [Operations](#operations)
- [Security notes](#security-notes)
- [Development](#development)
- [API](#api)
- [Project layout](#project-layout)

## Features at a glance

| Area | What you get |
|---|---|
| **Use case catalogue** | The MaGMa L1 / L2 / L3 hierarchy with effectiveness, implementation and coverage per rule, weights, potential, SOC detection score and catalogue coverage; reference lists (threat actors, log sources, detection technologies, scopes) with usage links |
| **Rules** | Free-form JSON configuration per rule with git-like history (diff, restore, tags), SIEM name template, ATT&CK techniques, SIEM rule IDs, lifecycle with definition of done; bulk edit of L2 use cases from the tree |
| **Verification** | Re-verification interval per rule, *Verify now*, overdue list on the dashboard; log source checks (intake, configuration, filtering, responsibilities) with owner and interval, flagged on the rules that use the log source |
| **Tasks** | Review, tuning and settings tasks on use cases and rules with Markdown text, due date and assignee; central task list |
| **Priorities** | Risk level and target implementation per use case; rules sorted by gap to target × risk × driver boost |
| **Drivers** | Business and compliance drivers linked to L2 use cases, driver coverage and gaps |
| **Threat modelling** | Systems with their business owner, STRIDE interviews per component, risk / coverage matrix, detection requests, evidence and owner sign-off |
| **Purple team tests** | Campaigns, quick tests and a test library; multi-round red / blue team results that verify rules and turn misses into detection gaps; limited red team accounts |
| **ATT&CK coverage** | Bundled MITRE ATT&CK Enterprise data, coverage heatmap, Navigator layer export, remap of revoked IDs |
| **Output metrics** | Alerts, incidents, false positives and false negatives per rule and month; CSV import, Microsoft Sentinel / Defender XDR incident export import, SIEM push API |
| **History and reports** | Snapshots and trends, lifecycle change log, management PDF report |
| **Import / export** | Classic MaGMa UCF Tool Excel layout (import and export), JSON export |
| **Access** | Roles admin / analyst / auditor / red team, local login with TOTP two-factor, OIDC single sign-on, audit log, API tokens |
| **Integrations** | Optional two-way git sync of rule configurations, SIEM rule inventory and alert count push |

## Screenshots

All screenshots use the generated demo data.

| | |
|---|---|
| **Use cases**: tree of L1 / L2 use cases with the L2 detail and its rules<br>![Use cases](docs/screenshots/use-cases.png) | **Rule detail**: metrics, weight, test coverage per scope, drivers and details<br>![Rule detail](docs/screenshots/rule-detail.png) |
| **Priorities**: gap to target per rule and driver coverage<br>![Priorities](docs/screenshots/priorities.png) | **Threat modelling**: STRIDE risks per component and the use cases that cover them<br>![Threat modelling](docs/screenshots/threat-modelling.png) |
| **Purple team campaign**: tests with red team execution and blue team outcome<br>![Purple team campaign](docs/screenshots/purple-team-campaign.png) | **ATT&CK coverage**: techniques coloured by the best rule weight<br>![ATT&CK coverage](docs/screenshots/attack-coverage.png) |
| **Output metrics**: alerts and false positives per month, incident export import<br>![Output metrics](docs/screenshots/output-metrics.png) | |

## Quick start with Docker

```bash
cp .env.example .env
# required: the app refuses to start without a strong SECRET_KEY
echo "SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')" >> .env
docker compose up -d --build
```

Open http://localhost:8080 and sign in as `admin`. Set `ADMIN_PASSWORD` in `.env` before the first
start, or read the generated password from the log:
`docker compose logs magma | grep "generated password"`.

On first start the database is created, migrated and filled with the default MaGMa catalogue
(12 L1 + Weaponization (not applicable), 62 L2, 169 L3, reference lists, business drivers). Data is
stored in the `magma-data` volume (`/data` in the container).

To look around with sample content, add `DEMO_DATA=true` to `.env` before the first start (see
[Demo data](#demo-data)).

Release images are built for version tags and published as `ghcr.io/s0mberlain/magmagui`.

## Configuration

All settings are environment variables, read from `.env` by Docker Compose.
[.env.example](.env.example) lists every variable with its default and an explanation. The most
important ones:

| Variable | Default | Purpose |
|---|---|---|
| `SECRET_KEY` | – (required) | At least 32 characters. Encrypts TOTP secrets and signs the SSO state cookie |
| `BASE_URL` | `http://localhost:8080` | Public URL (SSO redirect, webhook, HSTS with `https://`) |
| `MAGMA_PORT` | `8080` | Host port for Docker Compose |
| `DATABASE_URL` | `sqlite:////data/magma.db` | SQLite file or `postgresql+psycopg://…` |
| `ADMIN_USER` / `ADMIN_PASSWORD` | `admin` / generated | First admin, created only when no users exist |
| `LOCAL_LOGIN_ENABLED` | `true` | Turn off local passwords when SSO is used |
| `SESSION_HOURS` / `SSO_SESSION_HOURS` | `12` / `8` | Session length |
| `MAX_FAILED_LOGINS` / `LOCKOUT_MINUTES` | `5` / `15` | Account lockout |
| `LOGIN_IP_MAX_FAILURES` / `LOGIN_IP_WINDOW_MINUTES` | `20` / `15` | Failed sign-ins per client address |
| `MIN_PASSWORD_LENGTH` | `12` | Local passwords |
| `DEFAULT_VERIFICATION_DAYS` | `180` | Re-verification interval of operational rules |
| `RISK_TARGETS` | `1=0.4,2=0.5,3=0.6,4=0.75,5=0.9` | Target implementation per risk level |
| `DRIVER_LOW_COVERAGE` | `0.3` | Threshold for "low coverage" of a driver |
| `SNAPSHOT_SCHEDULE` | `monthly` | Automatic snapshots: `off`, `daily`, `weekly`, `monthly` |
| `DEMO_DATA` / `ALLOW_DEMO_DATA` / `DEMO_SEED` | `false` / `false` / `42` | Demo data on first start / offer it under *Import / Export* |
| `MAX_BODY_MB` | `25` | Largest request body |
| `EVIDENCE_MAX_TOTAL_MB` | `2048` | Total size of interview evidence files (0 = no limit) |
| `OIDC_*` | off | Single sign-on, see [Single sign-on](#single-sign-on-oidc) |
| `GIT_*` | off | Git repository for rule configurations, see [Git repository](#git-repository-optional) |
| `DB_*` | see below | PostgreSQL pool and timeouts, see [PostgreSQL](#postgresql) |

## Features in detail

### Use case catalogue and scoring

The catalogue follows the MaGMa UCF: **L1** use cases (attack phases such as Reconnaissance or
Delivery, plus business-specific ones) group **L2** use cases (threat scenarios), which are
implemented by **L3** rules. Codes follow the framework (`AO`, `AO-ACC`, `AO-ACC-01`). *Use cases*
shows the catalogue as a tree with the L2 detail on the right, or as a filterable table (status,
risk, drivers, ATT&CK technique, system …). Admins and analysts create, edit and delete use cases.

- Rule weight = effectiveness × implementation × coverage, potential = effectiveness − weight.
- Only operational and maintenance rules with all three metrics count. Empty L2 use cases are shown
  as detection gaps instead of counting as zero, and every L2 counts equally in its L1.
- Next to the **SOC detection score** the dashboard shows **catalogue coverage**: the same average,
  but an applicable L2 without scored rules counts as 0 (the rule driver coverage uses). One
  perfect rule in one of ten L2s gives a 100 % SOC score but 10 % catalogue coverage.
- **Verification**: operational rules must be re-verified every `DEFAULT_VERIFICATION_DAYS` (180)
  days unless the rule sets its own interval. Never verified counts as overdue. *Verify now* on
  the rule page records a verification; a successful purple team test does the same.
- **Log source verification** (*Verification → Log sources*): each log source is checked for log
  intake, configuration, filtering and responsibilities, by default every 180 days (admin setting,
  per log source override). Overdue or failed log sources are flagged on the rules that use them.

**Reference lists** (*Setup → Reference lists*) hold the threat actors (assigned to L2), log
sources, detection technologies and scopes (assigned to L3). Each entry shows where it is used,
and the rule page links to the other rules that use the same entries.

### Rules and JSON configurations

Every L3 rule can keep a free-form JSON configuration (query, thresholds, owner …). L2 use cases
only group rules and have no configuration.
It works like git without needing git: each save is an immutable commit (sha, author, message),
with history, diff between any two versions, restore (a new commit with the old content) and tags.
"Verify now" tags the current version as `verified-<date>`. If someone else saved in between,
your save is refused with a diff and you merge by hand. The only check is that the text is valid
JSON (an empty text means no configuration). Upload and download use `.json` files.

Configurations were YAML before; on upgrade (migration 0014) the latest YAML version of each rule
gets a JSON commit with the same data on top (author `system`, YAML comments are dropped). The
YAML versions stay in the history. Old L2 configurations stay in the database and the JSON
backup but are no longer shown.

**SIEM name.** Each rule page shows the rule's name as it should appear in the SIEM, with a Copy
button. Admins set the format under *Setup → Settings*, e.g. `$companyName:$ucID:$ucName` with
the variable `companyName = MYCORP` gives `MYCORP:IA-CMT-LOG-02:Failed Login Monitoring`.
`$ucID`, `$ucName`, `$l2ID` and `$l1ID` come from the rule; unknown `$names` stay as they are. The
default format is `$ucID:$ucName`. Settings are stored in the database (`app_settings`).

### Lifecycle, history and trends

Status changes go through *Change status* on the rule or L2 page and are logged with a change
driver (environmental: threat landscape, business, regulation, IT infrastructure; operational:
red teaming, incident lessons, threat hunting, tuning) and a note. A use case can only become
*Operational* when its definition-of-done checklist is complete (log sources, scope, incident
response, roles, rules); an admin can skip it, which is logged. *History & trends* shows control
metrics over time from snapshots (taken manually or by `SNAPSHOT_SCHEDULE`, monthly by default),
compares any two snapshots, and lists all status changes.

### Priorities

Every L2 use case has a risk level (1–5) and an optional target implementation; a rule follows
its L2 unless it sets its own. Without an explicit target the risk level gives one
(`RISK_TARGETS`, default 40 % for risk 1 up to 90 % for risk 5). *Priorities* lists the active
rules with the gap between implementation and target, sorted by
priority = gap to target × risk ÷ 5 × driver boost, so the biggest shortfalls on the riskiest use
cases come first. A rule that meets its target has priority 0; a rule without an implementation
score counts its whole target as gap, so unassessed high-risk rules show up at the top instead of
disappearing. A completed threat modelling interview can raise the risk level of the rules that
cover a system's risks.

### Business and compliance drivers

Each L2 use case links to any number of business drivers and compliance drivers (from any
compliance source, e.g. DORA, NIS2 or an internal policy) as plain links without a weight; its L3
rules and its L1 inherit them read-only. Analysts and admins set them on the L2 detail or in the
table view of *Use cases*, which can be filtered by business driver, compliance source and
compliance driver. Every change is in the audit log with the old and new links.

Driver coverage = average weight of the linked L2 use cases, where an L2 without scored rules
counts as 0. A driver without any linked use case is a gap; one below `DRIVER_LOW_COVERAGE`
(default 30 %) has low coverage. *Business drivers*, the dashboard, *Priorities* and the PDF
report show the coverage. Each linked driver raises the priority of the L2's rules by 10 %, at
most 50 %. Deleting a linked driver asks first and lists the use cases that lose the link.

### Threat modelling and business owner interviews

*Threat modelling* lists the business applications and platforms (**systems**) with their
business owner, criticality, detection coverage, gaps and interview status.

- An analyst interviews the business owner per system: the system's **components** and the log
  sources they deliver, and per component the six **STRIDE** threats with likelihood × impact
  (risk 1–25). Threats beyond STRIDE can be added as custom threats with ATT&CK techniques.
- An admin-maintained **STRIDE mapping** (*Setup → STRIDE mapping*) proposes the L2 use cases for
  each threat above a threshold; with the log source filter on, an L2 is held back when its rules
  need log sources the component does not deliver. Analysts can add use cases (a whole L2 or a
  single rule) or remove proposals with a reason.
- The **risk / coverage matrix** shows each component × threat as covered, partly covered, gap or
  below threshold; the system page lists the gaps (use cases without rules, rules that get none of
  their log sources).
- Completing an interview links the system to those use cases (system coverage, *Use cases* filter
  by system, risk boost in *Priorities*) and turns what is missing into **detection requests**.
  Requests have a status (open, in progress, implemented, rejected, not feasible) and are listed
  for all systems under *Use cases → Detection requests*.
- Interviews go Draft → Completed → Confirmed: export the interview as PDF, send it to the owner
  and record the owner's sign-off. Evidence files can be attached. A re-interview starts as a copy
  of the previous one; systems are due again after their review interval (12 months by default).

### Purple team tests

*Verification* checks rules with tests of an ATT&CK technique, linked to one or more rules and the
scopes they cover.

- **Campaigns** (planned → running → closed) group the tests of a scenario; tests can be proposed
  from the ATT&CK techniques of chosen use cases or taken from the **test library**. **Quick
  tests** cover a single test without planning.
- Each test runs in **rounds**: the red team records the execution (what, when), the blue team the
  result (*Blocked*, *Alerted*, *Logged*, *Not detected*) with detection time and detecting rules.
  Time to detect is shown per test.
- *Blocked* and *Alerted* verify the covered scopes of each linked rule for the rule's
  verification interval. *Logged* and *Not detected* become **detection gaps** until a later round
  succeeds or someone accepts the gap with a reason.
- The rule page shows its test history and which scopes are covered.
- **Red team accounts** are local accounts with an end date that see only the campaigns they are
  assigned to. With collaboration *Hidden* they see the blue team's results only after the
  campaign is closed; *Open* shows them at once.

### ATT&CK coverage

The app ships a compact copy of MITRE ATT&CK Enterprise
(`backend/app/attack_data/enterprise.json`), so the coverage page works offline. Each technique is
coloured by the best weight of an operational rule mapped to it; a rule on a sub-technique also
counts for its parent. **Download Navigator layer** exports the same view as an
[ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) layer (score = weight × 100).

The original MaGMa catalogue uses 2017 technique IDs. Most were later revoked and replaced, or
deprecated. The page lists them, and an admin can replace revoked IDs by their successor in one
step (**Review update**, audited). Deprecated IDs without a successor stay on the rule until
someone maps it by hand.

To refresh the bundled data from a newer ATT&CK release:

```bash
cd backend && python -m app.attack_data.update            # downloads the latest enterprise-attack.json
python -m app.attack_data.update path/to/enterprise-attack.json
```

### Output metrics and PDF report

Each rule can record per month: alerts, incidents, false positives and (optionally) false
negatives. *Output metrics* shows monthly totals and the rules with the most false positives.
There are three ways to fill them:

1. **By hand** on the rule page.
2. **CSV import** on *Output metrics*: columns `rule, period, alerts, incidents, false_positives,
   false_negatives, note`; period `YYYY-MM`; comma or semicolon separated. **Check** runs a dry
   run, and a file with any error imports nothing.
3. **Import incident export**: the incident list exported from Microsoft Sentinel or Defender XDR
   (one row per incident; columns `Name`, `Incident ID`, `Created on`, `Classification` are used,
   the others are ignored). Each incident is matched to a rule by its name: the whole name is the
   rule's code, a SIEM rule ID or its SIEM name; or a part of the name
   (`ACME:IA-LNX-01:Password Spray`) is the code or a SIEM rule ID; or the name starts with the
   rule's SIEM name. Incidents that match no rule are ignored and listed in the preview.
   - Per rule and month (of `Created on`, UTC): alerts = matched incidents, incidents = classified
     true positive, false positives = classified false positive; benign positives and
     unclassified incidents count as alerts only. False negatives and notes stay as they are.
   - The incident ID is the key: importing the same or an overlapping export again recounts the
     month instead of adding twice, and later classifications correct earlier numbers. A month
     that was entered by hand is replaced by the recount (the preview shows before and after).
     Imported incidents are not part of the JSON export.

The SIEM can also push the counts itself, see [SIEM integration](#siem-integration).

**Download PDF report** on the dashboard creates a management report: KPIs, the SOC score trend,
detection per L1, top priorities, driver coverage, ATT&CK coverage per tactic, the noisiest rules
and overdue verifications.

### Import / export

*Import / Export* writes the classic MaGMa UCF Tool layout (L1 UC, L2 UC, L3 UC, Drivers,
References) with its formulas, plus extra columns for app fields. Import reads the same layout,
including the original tool, with a preview before anything is saved. *Merge* adds and updates by
ID; *Replace* (admin) also removes what is not in the file.

- The L2 business driver and policy / regulator columns hold one value each, as in the classic
  tool: export writes the first link there and every link in the app columns *All business
  drivers* and *All compliance drivers*; import links both, and an unknown code is a warning in
  the preview.
- Import follows the same rules as the app: a use case only becomes *Operational* through the
  import when its definition of done is complete (admins may skip it, which is logged), every
  status change is written to the change log, verification dates in the future are refused, and
  the importing user is recorded as the verifier.
- Workbooks that unpack to more than 200 MB are refused. In the export, text that starts with `=`
  is written as text, never as a live formula.
- A **JSON export** includes verifications, the change log, output metrics and the configuration
  history. It is meant for reporting and other tools and cannot be imported again; back up the
  database itself (see [Backup](#backup)).

### Demo data

Generated, reproducible sample data (random but fixed per seed, with fictitious names) fills
metrics, verifications, drivers, twelve monthly snapshots, a matching change log and output
metrics. Start with `DEMO_DATA=true`, or run `magma demo-data --seed 42` (or
`python -m app.demo --seed 42` in `backend/`). With `ALLOW_DEMO_DATA=true` (or `DEMO_DATA=true`)
admins can also load it from *Import / Export*. Loading deletes the verification, lifecycle and
configuration history, so leave both off in production.

## Users, roles and sign-in

### Roles

| Role | Can |
|---|---|
| admin | everything, incl. users, settings, mappings and deletes |
| analyst | read and edit use cases, drivers, reference lists, systems and interviews; run purple team tests (blue team) |
| auditor | read everything incl. the audit log, no changes |
| red_team | local accounts with an end date: only the purple team campaigns they are assigned to; they record the execution of tests and see the blue team's results once the campaign is closed (or at once when the campaign is open for collaboration) |

Admins manage local accounts under *Administration → Users* (create, disable, reset password or
second factor). The **audit log** (*Administration → Audit log*, admins and auditors) records
sign-ins, every change with old and new values, imports, settings changes and the client address.

### Single sign-on (OIDC)

Set `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` and `OIDC_ROLE_MAP` (see
`.env.example`) and register `<BASE_URL>/api/auth/oidc/callback` as redirect URI at your IdP
(Entra ID, Keycloak, Okta, ADFS, Authentik …). Users are created on first login; their role follows
the mapped IdP group on every login, and users without a matching group are refused (or get
`OIDC_DEFAULT_ROLE`). Local login keeps working unless `LOCAL_LOGIN_ENABLED=false`.

To try it locally: `docker compose --profile keycloak up -d` starts a Keycloak on port 8081 with
the users alice / bob / carol (admin / analyst / auditor, password `<name>-password`); use the
Keycloak values from `.env.example`.

### Two-factor login

Local accounts can turn on a TOTP second factor under *Account* (click your name in the
sidebar): scan the QR code with any authenticator app, confirm a code, and save the eight
one-time recovery codes. The secret is stored encrypted with `SECRET_KEY`. To change that key,
set the new one and run `magma rotate-secret --old <previous key>` once, otherwise existing
second factors stop working (an admin can also reset them under *Users*). SSO accounts use the
second factor of the identity provider.

### Resetting a password

`ADMIN_PASSWORD` is only used on the very first start, to create the first admin; changing it
later has no effect. To set a new password (it also unlocks the account and signs it out):

```bash
docker compose exec magma magma reset-password                # asks for the new password
docker compose exec magma magma reset-password --from-env     # takes ADMIN_PASSWORD from .env
docker compose exec magma magma reset-password alice --disable-totp   # lost authenticator too
docker compose exec magma magma reset-password alice --enable         # also re-enable a disabled account
```

A disabled account stays disabled unless you pass `--enable`.

## Integrations

### SIEM integration

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

### Git repository (optional)

Set `GIT_REMOTE_URL` plus `GIT_TOKEN` (HTTPS) or `GIT_SSH_KEY_FILE` (SSH) and the app pushes every
configuration commit to that repository as a real git commit with the same author, date and
message, on `usecases/<L1>/<L2>/<L3>.json` (a `.yaml` file written by older versions is replaced
by the `.json` file at the rule's next export). Tags become `<code>/<tag>`, e.g.
`AO-CRE-01/verified-2026-11-13`. Sync runs in the background after each commit
(`GIT_AUTO_SYNC`) and at startup; admins see the state and can sync by hand under
*Import / Export*. To try it locally: `docker compose --profile gitea up -d` starts Gitea on port
3000 with user magma / magma-password and an empty repository `magma/usecases`; use the Gitea
values from `.env.example`.

**Two-way sync** (`GIT_PULL=true`, off by default): commits that people push to the branch and
that change one of these files are read back into the app as new config commits, with the git
author, date and message and a *from git* badge in the history. The app checks the repository
every `GIT_PULL_INTERVAL_MINUTES` (5) and at every sync; set `GIT_WEBHOOK_SECRET` and add a push
webhook to `<BASE_URL>/api/git/webhook` to pick changes up at once (GitHub and Gitea/Forgejo
signatures, GitLab token header, or `X-Magma-Token: <secret>`). Rules:

- Only valid JSON in a `.json` file of an existing rule is taken over; deleting the file clears
  the config.
- If the same config was also changed in the app and that change is not in git yet, the app
  version wins and is pushed on top. The git change stays in the repository history.
- What was not taken over (conflict, invalid JSON, unknown path) is listed under
  *Import / Export → Git repository* and in the audit log as `config_import`.
- The local working copy is a cache: it is reset to the remote branch before every sync, so
  force-pushes or edits in the repository never block the sync.

## Languages

The interface is available in English, German and Dutch. Pick the language at the bottom of the
sidebar (or on the sign-in page); it is saved on your account and follows you to other browsers.
Without a choice the browser language is used. The data itself (use case names, descriptions, the
ATT&CK catalogue) stays as entered; the Excel export keeps the classic English sheet layout.

Texts live in `frontend/src/locales/{de,nl}.json`, keyed by the English text used in
`t("...")`. `npm run i18n:check` (also in CI) fails when a text has no German or Dutch entry or a
`{placeholder}` got lost. Labels sent by the API (definition of done, change drivers, trend
metrics) are listed in `frontend/src/serverTexts.ts` so they are translated too.

## Operations

### PostgreSQL

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

**Moving from SQLite to PostgreSQL.** Start the Postgres stack once so the database exists, stop
the app (`docker compose … stop magma`), then copy everything (users, history, configs,
snapshots …) from the old volume:

```bash
docker compose -f docker-compose.yml -f docker-compose.postgres.yml run --rm magma \
  magma db-copy --source sqlite:////data/magma.db \
  --target "postgresql+psycopg://magma:$POSTGRES_PASSWORD@postgres:5432/magma" --replace
```

`--replace` is needed because the first start already seeded the catalogue and the first admin.
Ids are kept and the sequences are moved past them. An empty or mistyped source is refused, so
`--replace` cannot wipe the target by accident.

### Command line

The container has a `magma` command (`docker compose exec magma magma <command>`):

| Command | Does |
|---|---|
| `magma migrate` | apply database migrations and seed an empty database (also runs on every start) |
| `magma demo-data --seed 42` | replace the data with generated demo data |
| `magma db-copy --target <url> [--source <url>] [--replace]` | copy all data to another database |
| `magma reset-password [user] [--from-env] [--disable-totp] [--enable]` | set a new password for a local account and unlock it |
| `magma rotate-secret --old <key>` | re-encrypt stored TOTP secrets with the current `SECRET_KEY` |

### Backup

Back up the database: the SQLite file in the `magma-data` volume (`/data/magma.db`), or your
PostgreSQL database with the usual tools. `magma db-copy` also copies everything into another
database. Interview evidence is stored in the database, so it is only in a database backup, not in
the JSON export.

### Reverse proxy and health checks

Behind a reverse proxy, set `FORWARDED_ALLOW_IPS` to the proxy's address so the audit log records
the real client address (the image trusts only `127.0.0.1` by default; never use `*` when the
port is reachable directly). Without it every user appears to come from the proxy's address, so
the per-address sign-in limit counts all users together; the app logs a warning once when it sees
this. Set `BASE_URL` to the public `https://` URL.

`GET /api/ready` checks the database (503 when it is down), `GET /api/health` only the process.

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
- Red team accounts may only call the sign-in and purple team endpoints they need; every other
  endpoint answers 403, so new endpoints are closed to them by default.
- Requests larger than `MAX_BODY_MB` (25) are refused with 413, and text fields have length
  limits.
- Changes made with the session cookie (POST, PUT, PATCH, DELETE) are refused with 403 when the
  browser sends an `Origin` or `Referer` of another site; API tokens are not affected.
- Viewing and downloading interview evidence and exporting an interview PDF are written to the
  audit log (once per user, file and hour). All evidence together is limited by
  `EVIDENCE_MAX_TOTAL_MB` (2048).
- The API docs load their assets from the app itself, not from a CDN.
- The SSO login page shows fixed texts only; IdP error details go to the log.

## Development

Backend (Python 3.12+, FastAPI, SQLAlchemy, Alembic):

```bash
cd backend
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
uvicorn app.main:app --reload --port 8000
```

Frontend (Node 22, React + Vite + TypeScript), proxies `/api` to port 8000:

```bash
cd frontend
npm install
npm run dev        # http://localhost:5173
npm run build      # type check and production build into dist/
```

For local development without a strong key, start the backend with
`ALLOW_WEAK_SECRET_KEY=true` or set a `SECRET_KEY`; add `DEMO_DATA=true` for sample content.

### Tests and checks

```bash
cd backend
pytest && ruff check . && ruff format --check .
# the same tests on PostgreSQL (the database is emptied before each test):
TEST_DATABASE_URL=postgresql+psycopg://user:pw@localhost/magma_test pytest

cd frontend
npm run typecheck
npm run i18n:check
```

CI ([.github/workflows/ci.yml](.github/workflows/ci.yml)) runs ruff, the full test suite on
SQLite and on PostgreSQL 16 (including a check that the migrations match the models), `pip-audit`,
`npm audit`, the i18n check and the frontend build, and builds the Docker image. Version tags
(`v*`) push the image to GHCR.

Database changes need an Alembic migration in `backend/app/migrations/`.

## API

The frontend uses a JSON API under `/api`, which can also be used directly:

- Interactive API docs at `/api/docs` and the OpenAPI schema at `/api/openapi.json`, for signed-in
  users.
- Authentication: the session cookie of a signed-in user, or an API token from *Integrations* as
  `Authorization: Bearer mgm_…` (see [SIEM integration](#siem-integration) for what a token may
  call).
- Imports have a dry run (`?dry_run=true` or a *Check* step) that shows the result without
  saving.
- Concurrent edits are detected with a version number: a stale save gets 409 and the client
  reloads.
- `GET /api/health` (process) and `GET /api/ready` (database) need no sign-in.
- Git push webhook: `POST /api/git/webhook` (see [Git repository](#git-repository-optional)).

## Project layout

```
backend/      FastAPI app (API under /api, serves the built SPA), migrations, tests
frontend/     React single-page app, locales in src/locales/
deploy/       Keycloak realm and Gitea init for local testing, SIEM push client and searches
docs/         user guide, screenshots, original plan with milestones M0 to M7 (historical)
features/     feature specifications (PROJ-1 to PROJ-4)
Dockerfile    multi-stage build: frontend → Python runtime, one container on port 8080
```

[docs/PLAN.md](docs/PLAN.md) is the original plan (historical); later features are specified in
[features/](features/INDEX.md).
