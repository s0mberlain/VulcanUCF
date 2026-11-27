"""Output metrics per rule and month: alerts, incidents, false positives and negatives."""

import csv
import io
import math
import re
from datetime import date
from typing import Annotated

from fastapi import APIRouter, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from app import audit
from app.api.deps import DB, SettingsDep
from app.dates import months_back
from app.models import L3UseCase, OutputMetric
from app.security import Editor, Reader

router = APIRouter(tags=["output metrics"])

PERIOD_RE = re.compile(r"^(\d{4})-(\d{1,2})(?:-\d{1,2})?$")
Count = Annotated[int, Field(ge=0, le=10_000_000)]


def csv_safe(value: str) -> str:
    """Text for a CSV cell: a spreadsheet would run a cell starting with = + - @ as a formula."""
    return "'" + value if value[:1] in ("=", "+", "-", "@", "\t", "\r") else value


def csv_plain(value: str) -> str:
    """Undo csv_safe when an exported file is imported again."""
    return value[1:] if value[:1] == "'" and value[1:2] in ("=", "+", "-", "@") else value


def parse_period(s: str) -> date:
    m = PERIOD_RE.match(s.strip())
    if not m or not 1 <= int(m.group(2)) <= 12:
        raise ValueError(f"period '{s}' is not YYYY-MM")
    return date(int(m.group(1)), int(m.group(2)), 1)


class MetricIn(BaseModel):
    alerts: Count = 0
    incidents: Count = 0
    false_positives: Count = 0
    false_negatives: Count | None = None
    note: Annotated[str, Field(max_length=1000)] = ""


class MetricOut(BaseModel):
    period: str
    alerts: int
    incidents: int
    false_positives: int
    false_negatives: int | None
    fp_rate: float | None
    note: str
    source: str
    updated_by: str


def _out(m: OutputMetric) -> MetricOut:
    return MetricOut(
        period=m.period.strftime("%Y-%m"),
        alerts=m.alerts,
        incidents=m.incidents,
        false_positives=m.false_positives,
        false_negatives=m.false_negatives,
        fp_rate=round(m.false_positives / m.alerts, 4) if m.alerts else None,
        note=m.note,
        source=m.source,
        updated_by=m.updated_by,
    )


def _rule(db, code: str) -> L3UseCase:
    r = db.scalar(select(L3UseCase).where(L3UseCase.code == code))
    if r is None:
        raise HTTPException(404, "L3 rule not found")
    return r


@router.get("/l3/{code}/output-metrics", response_model=list[MetricOut])
def rule_metrics(code: str, _: Reader, db: DB, months: int = Query(12, ge=1, le=120)):
    r = _rule(db, code)
    since = months_back(months)[0]
    q = (
        select(OutputMetric)
        .where(OutputMetric.l3_id == r.id, OutputMetric.period >= since)
        .order_by(OutputMetric.period.desc())
    )
    return [_out(m) for m in db.scalars(q)]


def upsert(db, rule: L3UseCase, period: date, body: MetricIn, user: str, source: str) -> bool:
    m = db.scalar(
        select(OutputMetric).where(OutputMetric.l3_id == rule.id, OutputMetric.period == period)
    )
    created = m is None
    if created:
        m = OutputMetric(l3_id=rule.id, period=period)
        db.add(m)
    m.alerts, m.incidents = body.alerts, body.incidents
    m.false_positives, m.false_negatives = body.false_positives, body.false_negatives
    m.note, m.source, m.updated_by = body.note, source, user
    return created


def _check(body: MetricIn) -> None:
    if body.false_positives > body.alerts:
        raise ValueError("false positives cannot exceed alerts")


@router.put("/l3/{code}/output-metrics/{period}", response_model=MetricOut)
def set_metric(code: str, period: str, body: MetricIn, user: Editor, db: DB) -> MetricOut:
    r = _rule(db, code)
    try:
        p = parse_period(period)
        _check(body)
    except ValueError as e:
        raise HTTPException(422, str(e)) from None
    if p > date.today():
        raise HTTPException(422, "Period is in the future")
    upsert(db, r, p, body, user.username, "manual")
    audit.record(db, user, "output_metrics", "l3", code, {"period": period} | body.model_dump())
    db.commit()
    m = db.scalar(select(OutputMetric).where(OutputMetric.l3_id == r.id, OutputMetric.period == p))
    return _out(m)


@router.delete("/l3/{code}/output-metrics/{period}", status_code=204)
def delete_metric(code: str, period: str, user: Editor, db: DB) -> None:
    r = _rule(db, code)
    try:
        p = parse_period(period)
    except ValueError as e:
        raise HTTPException(422, str(e)) from None
    m = db.scalar(select(OutputMetric).where(OutputMetric.l3_id == r.id, OutputMetric.period == p))
    if m is None:
        raise HTTPException(404, "No output metrics for that month")
    audit.record(db, user, "delete_output_metrics", "l3", code, {"period": period})
    db.delete(m)
    db.commit()


# ---------------------------------------------------------------- summary


class MonthTotal(BaseModel):
    period: str
    rules: int
    alerts: int
    incidents: int
    false_positives: int
    false_negatives: int
    fp_rate: float | None


class RuleTotal(BaseModel):
    code: str
    name: str
    months: int
    alerts: int
    incidents: int
    false_positives: int
    false_negatives: int
    fp_rate: float | None


class SummaryOut(BaseModel):
    months: list[MonthTotal]
    rules: list[RuleTotal]
    rules_reporting: int
    totals: MonthTotal


def _rate(fp: int, alerts: int) -> float | None:
    return round(fp / alerts, 4) if alerts else None


@router.get("/output-metrics/summary", response_model=SummaryOut)
def summary(_: Reader, db: DB, months: int = Query(12, ge=1, le=60)) -> SummaryOut:
    periods = months_back(months)
    since = periods[0]
    s = OutputMetric
    agg = (
        func.count(func.distinct(s.l3_id)),
        func.coalesce(func.sum(s.alerts), 0),
        func.coalesce(func.sum(s.incidents), 0),
        func.coalesce(func.sum(s.false_positives), 0),
        func.coalesce(func.sum(s.false_negatives), 0),
    )
    by_month = {
        p: row
        for p, *row in db.execute(
            select(s.period, *agg).where(s.period >= since).group_by(s.period)
        )
    }
    month_rows = []
    for p in periods:
        n, a, i, fp, fn = by_month.get(p, (0, 0, 0, 0, 0))
        month_rows.append(
            MonthTotal(
                period=p.strftime("%Y-%m"),
                rules=n,
                alerts=a,
                incidents=i,
                false_positives=fp,
                false_negatives=fn,
                fp_rate=_rate(fp, a),
            )
        )
    rule_rows = []
    q = (
        select(
            L3UseCase.code,
            L3UseCase.name,
            func.count(s.id),
            func.sum(s.alerts),
            func.sum(s.incidents),
            func.sum(s.false_positives),
            func.coalesce(func.sum(s.false_negatives), 0),
        )
        .join(L3UseCase, L3UseCase.id == s.l3_id)
        .where(s.period >= since)
        .group_by(L3UseCase.code, L3UseCase.name)
    )
    for code, name, n, a, i, fp, fn in db.execute(q):
        rule_rows.append(
            RuleTotal(
                code=code,
                name=name,
                months=n,
                alerts=a,
                incidents=i,
                false_positives=fp,
                false_negatives=fn,
                fp_rate=_rate(fp, a),
            )
        )
    rule_rows.sort(key=lambda r: (-r.false_positives, -r.alerts, r.code))
    t = [
        sum(getattr(m, f) for m in month_rows)
        for f in ("alerts", "incidents", "false_positives", "false_negatives")
    ]
    return SummaryOut(
        months=month_rows,
        rules=rule_rows,
        rules_reporting=len(rule_rows),
        totals=MonthTotal(
            period=f"{periods[0]:%Y-%m}..{periods[-1]:%Y-%m}",
            rules=len(rule_rows),
            alerts=t[0],
            incidents=t[1],
            false_positives=t[2],
            false_negatives=t[3],
            fp_rate=_rate(t[2], t[0]),
        ),
    )


# ---------------------------------------------------------------- CSV

CSV_FIELDS = ["rule", "period", "alerts", "incidents", "false_positives", "false_negatives", "note"]


@router.get("/export/output-metrics.csv")
def export_csv(_: Reader, db: DB) -> Response:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(CSV_FIELDS)
    q = (
        select(L3UseCase.code, OutputMetric)
        .join(L3UseCase, L3UseCase.id == OutputMetric.l3_id)
        .order_by(L3UseCase.code, OutputMetric.period)
    )
    for code, m in db.execute(q):
        w.writerow(
            [
                code,
                f"{m.period:%Y-%m}",
                m.alerts,
                m.incidents,
                m.false_positives,
                "" if m.false_negatives is None else m.false_negatives,
                csv_safe(m.note),
            ]
        )
    return Response(
        buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="output-metrics.csv"'},
    )


class CsvReport(BaseModel):
    dry_run: bool
    rows: int
    created: int
    updated: int
    errors: list[str]


ALIASES = {
    "rule": ("rule", "code", "l3", "rule id", "use case"),
    "period": ("period", "month"),
    "alerts": ("alerts",),
    "incidents": ("incidents",),
    "false_positives": ("false_positives", "false positives", "fp"),
    "false_negatives": ("false_negatives", "false negatives", "fn"),
    "note": ("note", "notes", "comment"),
}


@router.post("/import/output-metrics", response_model=CsvReport)
async def import_csv(
    user: Editor,
    db: DB,
    file: UploadFile = File(...),
    dry_run: bool = Form(True),
) -> CsvReport:
    """CSV with a header: rule, period (YYYY-MM), alerts, incidents, false_positives,
    false_negatives (optional), note (optional). `,` or `;` as separator."""
    raw = await file.read(5_000_001)
    if len(raw) > 5_000_000:
        raise HTTPException(413, "File is larger than 5 MB")
    text = raw.decode("utf-8-sig", errors="replace")
    try:
        dialect = csv.Sniffer().sniff(text.splitlines()[0] if text else ",", delimiters=",;\t")
    except csv.Error:
        dialect = csv.excel
    # only the separator is taken from the guess: its quoting rules break notes with quotes
    try:
        rows = list(csv.reader(io.StringIO(text), delimiter=dialect.delimiter))
    except csv.Error as e:  # e.g. a field longer than the csv module allows
        raise HTTPException(422, f"The file cannot be read as CSV: {e}") from None
    if not rows:
        raise HTTPException(422, "The file is empty")
    head = [h.strip().lower() for h in rows[0]]
    col = {}
    for key, names in ALIASES.items():
        for n in names:
            if n in head:
                col[key] = head.index(n)
                break
    missing = [k for k in ("rule", "period", "alerts") if k not in col]
    if missing:
        raise HTTPException(422, f"Missing column(s): {', '.join(missing)}")
    rules = {r.code: r for r in db.scalars(select(L3UseCase))}
    rep = CsvReport(dry_run=dry_run, rows=0, created=0, updated=0, errors=[])
    seen = set()

    def cell(row, key, default=""):
        i = col.get(key)
        return row[i].strip() if i is not None and i < len(row) else default

    def num(row, key, optional=False):
        v = cell(row, key)
        if v == "":
            return None if optional else 0
        f = float(v)
        if not math.isfinite(f):
            raise ValueError(f"'{v}' is not a number")
        return int(f)

    for n, row in enumerate(rows[1:], start=2):
        if not any(c.strip() for c in row):
            continue
        rep.rows += 1
        code = cell(row, "rule").upper()
        try:
            rule = rules.get(code)
            if rule is None:
                raise ValueError(f"unknown rule '{code}'")
            p = parse_period(cell(row, "period"))
            if p > date.today():
                raise ValueError(f"period {p:%Y-%m} is in the future")
            if (code, p) in seen:
                raise ValueError(f"{code} {p:%Y-%m} appears twice")
            seen.add((code, p))

            body = MetricIn(
                alerts=num(row, "alerts"),
                incidents=num(row, "incidents"),
                false_positives=num(row, "false_positives"),
                false_negatives=num(row, "false_negatives", optional=True),
                note=csv_plain(cell(row, "note"))[:1000],
            )
            _check(body)
        except (ValueError, TypeError) as e:
            msg = str(e).splitlines()[0]
            rep.errors.append(f"Row {n}: {msg}")
            continue
        if upsert(db, rule, p, body, user.username, "csv"):
            rep.created += 1
        else:
            rep.updated += 1
    if dry_run or rep.errors:
        db.rollback()
    else:
        audit.record(
            db,
            user,
            "import_output_metrics",
            "l3",
            "csv",
            {"file": file.filename, "created": rep.created, "updated": rep.updated},
        )
        db.commit()
    return rep


class MetricCounts(BaseModel):
    alerts: int
    incidents: int
    false_positives: int


class IncidentChange(BaseModel):
    code: str
    name: str
    period: str
    before: MetricCounts | None
    after: MetricCounts
    changed: bool


class IgnoredName(BaseModel):
    name: str
    count: int


class IncidentReport(BaseModel):
    dry_run: bool
    rows: int
    matched_rows: int
    new_incidents: int
    updated_incidents: int
    unchanged_incidents: int
    duplicate_rows: int
    ignored_rows: int
    ignored: list[IgnoredName]
    problems: list[str]
    changes: list[IncidentChange]
    created: int
    updated: int
    unchanged: int


@router.post("/import/output-metrics/incidents", response_model=IncidentReport)
async def import_incidents(
    user: Editor,
    db: DB,
    file: UploadFile = File(...),
    dry_run: bool = Form(True),
) -> IncidentReport:
    """Incident export of Microsoft Sentinel / Defender XDR (one row per incident). Incidents
    are matched to L3 rules by name; unmatched ones are ignored. See app/incidents.py."""
    from app import incidents

    raw = await file.read(20_000_001)
    if len(raw) > 20_000_000:
        raise HTTPException(413, "File is larger than 20 MB")
    text = raw.decode("utf-8-sig", errors="replace")
    try:
        rep = incidents.apply(db, text, user.username)
    except incidents.FormatError as e:
        db.rollback()
        raise HTTPException(422, str(e)) from None
    if dry_run:
        db.rollback()
    else:
        audit.record(
            db,
            user,
            "import_incidents",
            "l3",
            "csv",
            {
                "file": file.filename,
                "matched": rep.matched_rows,
                "ignored": rep.ignored_rows,
                "new_incidents": rep.new_incidents,
                "months_created": rep.created,
                "months_updated": rep.updated,
            },
        )
        db.commit()
    return IncidentReport(
        dry_run=dry_run,
        rows=rep.rows,
        matched_rows=rep.matched_rows,
        new_incidents=rep.new_incidents,
        updated_incidents=rep.updated_incidents,
        unchanged_incidents=rep.unchanged_incidents,
        duplicate_rows=rep.duplicate_rows,
        ignored_rows=rep.ignored_rows,
        ignored=[IgnoredName(**i) for i in rep.ignored],
        problems=rep.problems[:50],
        changes=[IncidentChange(**vars(c)) for c in rep.changes],
        created=rep.created,
        updated=rep.updated,
        unchanged=rep.unchanged,
    )


@router.get("/report.pdf")
def report_pdf(_: Reader, db: DB, settings: SettingsDep) -> Response:
    """Management report as PDF: KPIs, trend, priorities, ATT&CK, output metrics, overdue."""
    from app import report

    data = report.build(db, settings)
    name = f"magma-report-{date.today():%Y-%m-%d}.pdf"
    return Response(
        data,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{name}"'},
    )
