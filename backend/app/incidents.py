"""Output metrics from a SIEM incident export (Microsoft Sentinel / Defender XDR "Export" CSV).

The export has one row per incident with, among others, `Name`, `Incident ID`, `Created on` and
`Classification`. Each incident is matched to the L3 rules of this app; incidents that match no
rule are ignored (reported, never an error). The matched incidents are kept in
`imported_incidents` with the incident id as key, and the output metrics of every touched rule
and month are recounted from all incidents known for them:

- alerts           = incidents raised by the rule in that month
- incidents        = of those, classified true positive
- false_positives  = of those, classified false positive
- false_negatives and the note of the month stay as they are (the export cannot tell them)

"Benign positive" (Defender: "informational, expected activity") and unclassified incidents
count as alerts only. Because the months are recounted from the stored incidents, importing the
same or an overlapping export again does not count anything twice, and a later export with
updated classifications corrects the earlier numbers.

Matching an incident name to a rule, first hit wins:
1. the whole name is a rule's L3 code, one of its SIEM rule ids or its SIEM name (issue #50);
2. a part of the name is a rule's L3 code or SIEM rule id: `FESTO:IA-LNX-01:Password Spray`
   or `ion:AO-IMP-AZ-01: Suspicious ...` match IA-LNX-01 and AO-IMP-AZ-01;
3. the name starts with a rule's SIEM name (Sentinel appends "involving one user" and the like).
"""

import csv
import io
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import UTC, date, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import ImportedIncident, L3UseCase, OutputMetric

SOURCE = "incidents"  # OutputMetric.source of recounted months

# header name (lower case) -> key; Sentinel and Defender XDR spell a few of them differently
COLUMNS = {
    "name": "name",
    "title": "name",
    "incident name": "name",
    "incident id": "id",
    "incidentid": "id",
    "id": "id",
    "created on": "created",
    "created time": "created",
    "createdtime": "created",
    "creation time": "created",
    "classification": "classification",
}
REQUIRED = ("name", "id", "created")

_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*[A-Za-z0-9]")
_DATE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})")
_DMY = re.compile(r"^(\d{1,2})[./](\d{1,2})[./](\d{4})")
_AMPM = re.compile(r"\d\s*[AP]\.?M\.?\b", re.IGNORECASE)

VERDICTS = ("true_positive", "false_positive", "benign", "unknown")


class FormatError(ValueError):
    """The file is not an incident export (missing columns, empty)."""


def verdict(classification: str) -> str:
    c = re.sub(r"[\s_-]", "", classification.lower())
    if c == "truepositive":
        return "true_positive"
    if c == "falsepositive":
        return "false_positive"
    if c in ("benignpositive", "informationalexpectedactivity"):
        return "benign"
    return "unknown"


def date_order(values: list[str]) -> str:
    """Order of day and month ("dmy" or "mdy") in the dates of one file that are not ISO.

    A file saved again by a spreadsheet has 18.09.2026 or 18/09/2026, an export with US settings
    9/18/2026 1:00 PM. A first part above 12 means day first, a second part above 12 month first;
    without such a date, a time with AM/PM means month first (US), anything else day first.
    """
    dmy = mdy = ampm = False
    for v in values:
        m = _DMY.match(v.strip())
        if not m:
            continue
        a, b = int(m.group(1)), int(m.group(2))
        dmy |= a > 12
        mdy |= b > 12
        ampm |= bool(_AMPM.search(v))
    if mdy and not dmy:
        return "mdy"
    if dmy:
        return "dmy"
    return "mdy" if ampm else "dmy"


def parse_created(value: str, order: str = "dmy") -> date:
    v = value.strip()
    m = _DATE.match(v)
    if m:
        return date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
    m = _DMY.match(v)
    if m:
        a, b, y = int(m.group(1)), int(m.group(2)), int(m.group(3))
        day, month = (b, a) if order == "mdy" else (a, b)
        return date(y, month, day)
    raise ValueError(f"'{v[:40]}' is not a date")


@dataclass
class Row:
    line: int
    incident_id: str
    name: str
    period: date
    verdict: str


def read(text: str) -> tuple[list[Row], list[str], int]:
    """Rows of the export, messages for rows that cannot be read, and the number of data rows."""
    lines = text.splitlines()
    if not lines or not lines[0].strip():
        raise FormatError("The file is empty")
    try:
        delim = csv.Sniffer().sniff(lines[0], delimiters=",;\t").delimiter
    except csv.Error:
        delim = ","
    rows = csv.reader(io.StringIO(text), delimiter=delim)
    try:
        head = [h.strip().lower() for h in next(rows)]
    except csv.Error as e:
        raise FormatError(f"The file cannot be read as CSV: {e}") from None
    col: dict[str, int] = {}
    for i, h in enumerate(head):
        key = COLUMNS.get(h)
        if key and key not in col:
            col[key] = i
    missing = [k for k in REQUIRED if k not in col]
    if missing:
        names = {"name": "Name", "id": "Incident ID", "created": "Created on"}
        raise FormatError(
            "Not an incident export: missing column(s) " + ", ".join(names[k] for k in missing)
        )

    def cell(row: list[str], key: str) -> str:
        i = col.get(key)
        return row[i].strip() if i is not None and i < len(row) else ""

    try:
        body = [(n, row) for n, row in enumerate(rows, start=2) if any(c.strip() for c in row)]
    except csv.Error as e:  # e.g. a field longer than the csv module allows
        raise FormatError(f"The file cannot be read as CSV: {e}") from None
    order = date_order([cell(row, "created") for _, row in body])
    out, problems, total = [], [], 0
    for n, row in body:
        total += 1
        iid = cell(row, "id")
        if not iid:
            problems.append(f"Row {n}: no incident id")
            continue
        try:
            created = parse_created(cell(row, "created"), order)
        except ValueError as e:
            problems.append(f"Row {n}: {e}")
            continue
        out.append(
            Row(
                line=n,
                incident_id=iid[:64],
                name=cell(row, "name"),
                period=created.replace(day=1),
                verdict=verdict(cell(row, "classification")),
            )
        )
    return out, problems, total


class Matcher:
    """Incident name -> L3 rules (see the module docstring for the order)."""

    def __init__(self, db: Session):
        from app import rulename

        siem_name = rulename.formatter(db)
        self.exact: dict[str, list[L3UseCase]] = defaultdict(list)  # full name
        self.part: dict[str, list[L3UseCase]] = defaultdict(list)  # code or SIEM rule id
        self.prefixes: list[tuple[str, L3UseCase]] = []
        for r in db.scalars(select(L3UseCase)):
            keys = {r.code.lower(), *(s.lower() for s in r.siem_rule_ids or [] if s)}
            for k in keys:
                self.part[k].append(r)
            name = siem_name(r).strip().lower()
            for k in keys | {name}:
                if r not in self.exact[k]:
                    self.exact[k].append(r)
            if len(name) >= 8:
                self.prefixes.append((name, r))
        self.prefixes.sort(key=lambda x: -len(x[0]))  # the longest (most specific) name first

    def match(self, name: str) -> list[L3UseCase]:
        n = name.strip().lower()
        if not n:
            return []
        if n in self.exact:
            return self.exact[n]
        for part in n.split(":"):
            p = part.strip()
            if p in self.part:
                return self.part[p]
        hits: list[L3UseCase] = []
        for tok in _TOKEN.findall(n):
            for r in self.part.get(tok, []):
                if r not in hits:
                    hits.append(r)
        if hits:
            return hits
        for prefix, r in self.prefixes:
            if n.startswith(prefix) and (len(n) == len(prefix) or not n[len(prefix)].isalnum()):
                return [r]
        return []


@dataclass
class Counts:
    alerts: int = 0
    incidents: int = 0
    false_positives: int = 0

    def add(self, v: str) -> None:
        self.alerts += 1
        self.incidents += v == "true_positive"
        self.false_positives += v == "false_positive"

    def as_dict(self) -> dict:
        return {
            "alerts": self.alerts,
            "incidents": self.incidents,
            "false_positives": self.false_positives,
        }


@dataclass
class Change:
    code: str
    name: str
    period: str
    before: dict | None
    after: dict
    changed: bool


@dataclass
class Report:
    rows: int = 0
    matched_rows: int = 0
    new_incidents: int = 0
    updated_incidents: int = 0
    unchanged_incidents: int = 0
    duplicate_rows: int = 0
    future_rows: int = 0
    ignored_rows: int = 0
    ignored: list[dict] = field(default_factory=list)  # [{name, count}]
    problems: list[str] = field(default_factory=list)
    changes: list[Change] = field(default_factory=list)
    created: int = 0
    updated: int = 0
    unchanged: int = 0


def apply(db: Session, text: str, user: str, today: date | None = None) -> Report:
    """Match, store and recount. The caller commits or rolls back (dry run)."""
    today = today or datetime.now(UTC).date()
    rows, problems, total = read(text)
    rep = Report(rows=total, problems=problems)
    matcher = Matcher(db)
    ignored: Counter[str] = Counter()
    seen: set[str] = set()
    wanted: dict[str, tuple[Row, list[L3UseCase]]] = {}
    for row in rows:
        if row.incident_id in seen:
            rep.duplicate_rows += 1
            continue
        seen.add(row.incident_id)
        if row.period > today:
            rep.future_rows += 1
            problems.append(f"Row {row.line}: created in the future, skipped")
            continue
        rules = matcher.match(row.name)
        if not rules:
            ignored[row.name or "(no name)"] += 1
            continue
        rep.matched_rows += 1
        wanted[row.incident_id] = (row, rules)
    rep.ignored_rows = sum(ignored.values())
    rep.ignored = [{"name": k, "count": v} for k, v in ignored.most_common(100)]

    existing: dict[str, list[ImportedIncident]] = defaultdict(list)
    ids = list(wanted)
    for i in range(0, len(ids), 500):
        q = select(ImportedIncident).where(ImportedIncident.incident_id.in_(ids[i : i + 500]))
        for rec in db.scalars(q):
            existing[rec.incident_id].append(rec)

    touched: set[tuple[int, date]] = set()
    for iid, (row, rules) in wanted.items():
        old = {rec.l3_id: rec for rec in existing.get(iid, [])}
        new_ids = {r.id for r in rules}
        if not old:
            rep.new_incidents += 1
        elif set(old) == new_ids and all(
            rec.period == row.period and rec.verdict == row.verdict for rec in old.values()
        ):
            rep.unchanged_incidents += 1
            continue
        else:
            rep.updated_incidents += 1
        for l3_id, rec in old.items():
            touched.add((l3_id, rec.period))
            if l3_id not in new_ids:
                db.delete(rec)
        for r in rules:
            rec = old.get(r.id)
            if rec is None:
                rec = ImportedIncident(incident_id=iid, l3_id=r.id)
                db.add(rec)
            rec.period, rec.verdict = row.period, row.verdict
            rec.title, rec.imported_by = row.name[:300], user
            touched.add((r.id, row.period))
    db.flush()
    _recount(db, touched, user, rep)
    return rep


def _recount(db: Session, touched: set[tuple[int, date]], user: str, rep: Report) -> None:
    if not touched:
        return
    l3_ids = {t[0] for t in touched}
    counts: dict[tuple[int, date], Counts] = defaultdict(Counts)
    q = select(ImportedIncident.l3_id, ImportedIncident.period, ImportedIncident.verdict).where(
        ImportedIncident.l3_id.in_(l3_ids)
    )
    for l3_id, period, v in db.execute(q):
        if (l3_id, period) in touched:
            counts[(l3_id, period)].add(v)
    rules = {r.id: r for r in db.scalars(select(L3UseCase).where(L3UseCase.id.in_(l3_ids)))}
    metrics = {
        (m.l3_id, m.period): m
        for m in db.scalars(select(OutputMetric).where(OutputMetric.l3_id.in_(l3_ids)))
    }
    for key in sorted(touched, key=lambda k: (rules[k[0]].code, k[1])):
        c = counts.get(key, Counts())
        m = metrics.get(key)
        before = (
            {"alerts": m.alerts, "incidents": m.incidents, "false_positives": m.false_positives}
            if m
            else None
        )
        after = c.as_dict()
        changed = before != after
        r = rules[key[0]]
        rep.changes.append(Change(r.code, r.name, f"{key[1]:%Y-%m}", before, after, changed))
        if m is None:
            if not c.alerts:
                continue
            m = OutputMetric(l3_id=key[0], period=key[1], note="", false_negatives=None)
            db.add(m)
            rep.created += 1
        elif changed:
            rep.updated += 1
        else:
            rep.unchanged += 1
            continue
        m.alerts, m.incidents, m.false_positives = c.alerts, c.incidents, c.false_positives
        m.source, m.updated_by = SOURCE, user
