"""Excel import and export in the layout of the classic MaGMa UCF Tool (docs/PLAN.md section 7).

Export writes the classic sheets (L1 UC, L2 UC, L3 UC, Drivers, References) with the same
column order and the Excel formulas for the calculated columns, so the file still works as the
classic tool. App-only fields (lifecycle, dates, risk ...) go into extra columns on the right.

Import finds sheets by name and columns by their header text, reads input columns only and
recomputes everything else. Several values in one cell are split on ';' or ','.
"""

import io
import re
import zipfile
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any

from openpyxl import Workbook, load_workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app import lifecycle, rulename
from app.models import (
    BusinessDriver,
    ComplianceDriver,
    ComplianceSource,
    L1UseCase,
    L2UseCase,
    L3UseCase,
    Lifecycle,
    ReferenceItem,
    RefKind,
)
from app.schemas import L3_CODE_MAX, L3_CODE_PATTERN

MAX_UNPACKED_BYTES = 200 * 2**20

L1_RE = re.compile(r"^[A-Z]{2}$")
L2_RE = re.compile(r"^[A-Z]{2}-[A-Z0-9]{3}$")
L3_RE = re.compile(L3_CODE_PATTERN)
ATTACK_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

# App-only L2 columns with every linked driver (the classic columns hold one value each)
ALL_BD = "All business drivers"
ALL_CD = "All compliance drivers"

REF_SECTIONS = [
    (RefKind.threat_actor, "Threat Actors", "Actor"),
    (RefKind.detection_technology, "Detection Technologies", "Technology"),
    (RefKind.log_source, "Log Sources", "Log source"),
    (RefKind.scope, "Scope", "Scope"),
]

HEAD_FONT = Font(bold=True, color="FFFFFF")
HEAD_FILL = PatternFill("solid", fgColor="16181D")
EXTRA_FILL = PatternFill("solid", fgColor="C2410C")
TITLE_FONT = Font(bold=True, size=14)


# --------------------------------------------------------------------------- export


def _header(ws, row: int, headers: list[str], extra_from: int | None = None) -> None:
    for i, h in enumerate(headers, start=1):
        c = ws.cell(row=row, column=i, value=h)
        c.font = HEAD_FONT
        c.fill = EXTRA_FILL if extra_from and i >= extra_from else HEAD_FILL
        c.alignment = Alignment(wrap_text=True, vertical="center")


def _widths(ws, widths: dict[str, int]) -> None:
    for col, w in widths.items():
        ws.column_dimensions[col].width = w


def _join(values) -> str:
    return "; ".join(values)


def export_workbook(db: Session) -> bytes:
    wb = Workbook()
    wb.remove(wb.active)

    l1s = list(db.scalars(select(L1UseCase).order_by(L1UseCase.sort_order, L1UseCase.code)))
    l2s = list(
        db.scalars(
            select(L2UseCase)
            .options(
                selectinload(L2UseCase.actors),
                selectinload(L2UseCase.business_drivers),
                selectinload(L2UseCase.compliance_drivers),
            )
            .order_by(L2UseCase.code)
        )
    )
    l3s = list(
        db.scalars(
            select(L3UseCase).options(selectinload(L3UseCase.references)).order_by(L3UseCase.code)
        )
    )
    sources = list(db.scalars(select(ComplianceSource).order_by(ComplianceSource.id)))

    # ---- Introduction
    ws = wb.create_sheet("Introduction")
    ws["A1"] = "MaGMa UCF Tool"
    ws["A1"].font = TITLE_FONT
    ws["A3"], ws["B3"] = "Exported from", "Vulcan UCF web app"
    ws["A4"], ws["B4"] = "Date", date.today().isoformat()
    ws["A6"] = (
        "Classic layout with Excel formulas. Orange columns are extra fields of the web app "
        "and are ignored by the classic tool. Scores in the web app follow its own rules "
        "(see docs/PLAN.md 2.5) and can differ from the Excel formulas."
    )
    _widths(ws, {"A": 16, "B": 40})

    # ---- L1 UC
    ws = wb.create_sheet("L1 UC")
    ws["C1"] = "Strategic Overview"
    ws["C1"].font = TITLE_FONT
    _header(
        ws,
        2,
        [
            "Threat category",
            "",
            "L1 Use Case Identifier",
            "Use Case Name",
            "Purpose",
            "Stakeholders",
            "#L2 UC related",
            "#L3 UC related",
            "Effectiveness",
            "Implementation",
            "Coverage",
            "Weight",
            "Potential",
            "Description",
            "Applicable",
        ],
        extra_from=15,
    )
    for i, x in enumerate(l1s, start=3):
        ws.cell(i, 1, x.threat_category)
        ws.cell(i, 3, x.code if x.applicable else "N/A")
        ws.cell(i, 4, x.name)
        ws.cell(i, 5, x.purpose)
        ws.cell(i, 6, x.stakeholders)
        if x.applicable:
            ws.cell(i, 7, f"=COUNTIF('L2 UC'!B:B,C{i})")
            ws.cell(i, 8, f"=COUNTIF('L3 UC'!C:C,C{i})")
            for col, src in zip("IJKLM", "HIJKL", strict=True):
                ws[f"{col}{i}"] = f"=IFERROR(AVERAGEIF('L2 UC'!B:B,C{i},'L2 UC'!{src}:{src}),0)"
                ws[f"{col}{i}"].number_format = "0%"
        ws.cell(i, 14, x.description)
        ws.cell(i, 15, "yes" if x.applicable else "no")
    _widths(ws, {"A": 18, "C": 12, "D": 28, "E": 30, "F": 22, "N": 60})

    # ---- L2 UC
    ws = wb.create_sheet("L2 UC")
    base = [
        "L1 Use Case Name",
        "L1 Use Case Identifier",
        "L2 Use Case Identifier",
        "Use Case Name",
        "Use Case Description",
        "Actors",
        "#L3 UC related",
        "Avg Effectiveness",
        "Avg Implementation",
        "Avg Coverage",
        "Avg Weight",
        "Avg Potential",
        "Business Drivers",
    ]
    comp_cols = [s.name for s in sources]
    extras = [
        "Lifecycle status",
        "Risk level",
        "Target implementation",
        "Onboarded",
        "Last verified",
        ALL_BD,
        ALL_CD,
    ]
    _header(ws, 1, base + comp_cols + extras, extra_from=len(base) + len(comp_cols) + 1)
    order = {src.id: j for j, src in enumerate(sources)}
    for i, x in enumerate(l2s, start=2):
        ws.cell(i, 1, f"=VLOOKUP(LEFT(C{i},2),'L1 UC'!C:D,2,FALSE)")
        ws.cell(i, 2, f"=LEFT(C{i},2)")
        ws.cell(i, 3, x.code)
        ws.cell(i, 4, x.name)
        ws.cell(i, 5, x.description)
        ws.cell(i, 6, _join(sorted(a.name for a in x.actors)))
        ws.cell(i, 7, f"=COUNTIF('L3 UC'!E:E,C{i})")
        for col, src in zip("HIJKL", "IJKLM", strict=True):
            ws[f"{col}{i}"] = f"=IFERROR(AVERAGEIF('L3 UC'!E:E,C{i},'L3 UC'!{src}:{src}),0)"
            ws[f"{col}{i}"].number_format = "0%"
        # The classic tool takes one value per cell: write the first link there and every link
        # in the app columns on the right, so nothing is lost on the way back.
        bds = sorted(b.code for b in x.business_drivers)
        ws.cell(i, 13, bds[0] if bds else None)
        for j, src in enumerate(sources):
            refs = sorted(c.ref for c in x.compliance_drivers if c.source_id == src.id)
            ws.cell(i, 14 + j, refs[0] if refs else None)
        e = 14 + len(sources)
        ws.cell(i, e, x.lifecycle_status.value)
        ws.cell(i, e + 1, x.risk_level)
        ws.cell(i, e + 2, x.target_implementation)
        ws.cell(i, e + 3, x.onboarded_at)
        ws.cell(i, e + 4, x.last_verified_at)
        ws.cell(i, e + 5, _join(bds) if len(bds) > 1 else None)
        cds = sorted(x.compliance_drivers, key=lambda c: (order.get(c.source_id, 0), c.ref))
        multi = any(sum(1 for c in cds if c.source_id == src.id) > 1 for src in sources)
        ws.cell(i, e + 6, _join(f"{c.source.name}: {c.ref}" for c in cds) if multi else None)
    _widths(ws, {"A": 22, "C": 12, "D": 30, "E": 50, "F": 28, "M": 18})

    # ---- L3 UC
    ws = wb.create_sheet("L3 UC")
    _header(
        ws,
        1,
        [
            "# L3 use cases per L2",
            "L1 Use Case Name",
            "L1 Use Case Identifier",
            "L2 Use Case Name",
            "L2 Use Case Identifier",
            "Rule Identifier",
            "Technical Use Case Name",
            "Use Case Description",
            "Effectiveness %",
            "Implementation %",
            "Coverage %",
            "Weight\n(eff*impl*cvrge)",
            "Potential\n(eff-weight)",
            "Log source type",
            "Detection Technology",
            "Scope",
            "comments",
            "Lifecycle status",
            "Onboarded",
            "Last verified",
            "Last verified by",
            "Verify every (days)",
            "ATT&CK techniques",
            "Risk level",
            "Target implementation",
            "SIEM name",
        ],
        extra_from=18,
    )
    siem_name = rulename.formatter(db)
    for i, x in enumerate(l3s, start=2):
        refs = {k: sorted(r.name for r in x.references if r.kind == k) for k in RefKind}
        ws.cell(i, 1, f"=COUNTIF(E:E,E{i})")
        ws.cell(i, 2, f"=VLOOKUP(LEFT(F{i},2),'L1 UC'!C:D,2,FALSE)")
        ws.cell(i, 3, f"=LEFT(E{i},2)")
        ws.cell(i, 4, f"=VLOOKUP(LEFT(F{i},6),'L2 UC'!C:D,2,FALSE)")
        ws.cell(i, 5, f"=LEFT(F{i},6)")
        ws.cell(i, 6, x.code)
        ws.cell(i, 7, x.name)
        ws.cell(i, 8, x.description)
        for col, v in zip(
            (9, 10, 11), (x.effectiveness, x.implementation, x.coverage), strict=True
        ):
            c = ws.cell(i, col, v)
            c.number_format = "0%"
        ws.cell(i, 12, f'=IF(COUNT(I{i}:K{i})=3,I{i}*J{i}*K{i},"")').number_format = "0%"
        ws.cell(i, 13, f'=IF(COUNT(I{i}:K{i})=3,I{i}-L{i},"")').number_format = "0%"
        ws.cell(i, 14, _join(refs[RefKind.log_source]))
        ws.cell(i, 15, _join(refs[RefKind.detection_technology]))
        ws.cell(i, 16, _join(refs[RefKind.scope]))
        ws.cell(i, 17, x.comments)
        ws.cell(i, 18, x.lifecycle_status.value)
        ws.cell(i, 19, x.onboarded_at)
        ws.cell(i, 20, x.last_verified_at)
        ws.cell(i, 21, x.last_verified_by)
        ws.cell(i, 22, x.verification_interval_days)
        ws.cell(i, 23, _join(x.attack_techniques))
        ws.cell(i, 24, x.risk_level)
        ws.cell(i, 25, x.target_implementation).number_format = "0%"
        ws.cell(i, 26, siem_name(x))  # issue #50, export only
    _widths(ws, {"F": 12, "G": 40, "H": 40, "N": 26, "O": 22, "P": 22, "Q": 30})
    ws.freeze_panes = "G2"

    # ---- Drivers
    ws = wb.create_sheet("Drivers")
    ws["B2"] = "Business Drivers"
    ws["B2"].font = TITLE_FONT
    _header(ws, 7, ["", "ID", "Business Drivers", "Description"])
    row = 8
    for d in db.scalars(select(BusinessDriver).order_by(BusinessDriver.code)):
        ws.cell(row, 2, d.code)
        ws.cell(row, 3, d.name)
        ws.cell(row, 4, d.description)
        row += 1
    row += 1
    ws.cell(row, 2, "Compliance Drivers").font = TITLE_FONT
    row += 1
    _header(ws, row, ["", "ID", "Compliance Driver", "Description", "Name"], extra_from=5)
    row += 1
    for s in sources:
        for c in sorted(s.drivers, key=lambda d: d.ref):
            ws.cell(row, 2, c.ref)
            ws.cell(row, 3, s.name)
            ws.cell(row, 4, c.description)
            ws.cell(row, 5, c.name)
            row += 1
    _widths(ws, {"B": 14, "C": 34, "D": 70, "E": 40})

    # ---- References
    ws = wb.create_sheet("References")
    row = 2
    for kind, title, col in REF_SECTIONS:
        ws.cell(row, 2, title).font = TITLE_FONT
        _header(ws, row + 1, ["", col, "Description"])
        row += 2
        q = select(ReferenceItem).where(ReferenceItem.kind == kind).order_by(ReferenceItem.name)
        for item in db.scalars(q):
            ws.cell(row, 2, item.name)
            ws.cell(row, 3, item.description)
            row += 1
        row += 1
    _widths(ws, {"B": 34, "C": 80})

    _neutralise_formulas(wb)
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


# Columns where the export itself writes formulas (classic layout). Any other cell whose value
# starts with "=" holds user text that openpyxl would otherwise store as a live formula.
_FORMULA_COLUMNS = {
    "L1 UC": set("GHIJKLM"),
    "L2 UC": set("ABGHIJKL"),
    "L3 UC": set("ABCDELM"),
}


def _neutralise_formulas(wb: Workbook) -> None:
    for ws in wb.worksheets:
        allowed = _FORMULA_COLUMNS.get(ws.title, set())
        for row in ws.iter_rows():
            for cell in row:
                if cell.data_type == "f" and (cell.row == 1 or cell.column_letter not in allowed):
                    cell.data_type = "s"


# --------------------------------------------------------------------------- import


@dataclass
class Report:
    mode: str
    dry_run: bool
    sheets: list[str] = field(default_factory=list)
    counts: dict[str, dict[str, int]] = field(default_factory=dict)
    warnings: list[dict] = field(default_factory=list)
    errors: list[dict] = field(default_factory=list)

    def count(self, entity: str, what: str) -> None:
        c = self.counts.setdefault(
            entity, {"created": 0, "updated": 0, "unchanged": 0, "deleted": 0}
        )
        c[what] += 1

    def warn(self, sheet: str, row: int | None, msg: str) -> None:
        if len(self.warnings) < 300:
            self.warnings.append({"sheet": sheet, "row": row, "message": msg})

    def error(self, sheet: str, row: int | None, msg: str) -> None:
        if len(self.errors) < 300:
            self.errors.append({"sheet": sheet, "row": row, "message": msg})


class ImportFailed(Exception):
    pass


def _norm(v: Any) -> str:
    return re.sub(r"\s+", " ", str(v or "")).strip().lower().rstrip(" %").strip()


def _text(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, float) and v.is_integer():
        v = int(v)
    s = str(v).strip()
    return "" if s.startswith("=") or s in {"…", "..."} else s


def _split(v: Any) -> list[str]:
    s = _text(v)
    return list(dict.fromkeys(p.strip() for p in re.split(r"[;,\n]", s) if p.strip()))


def _date(v: Any) -> date | None:
    if v in (None, ""):
        return None
    if isinstance(v, datetime):
        return v.date()
    if isinstance(v, date):
        return v
    s = str(v).strip()
    for fmt in ("%Y-%m-%d", "%d.%m.%Y", "%d/%m/%Y", "%m/%d/%Y"):
        try:
            return datetime.strptime(s, fmt).date()
        except ValueError:
            continue
    raise ValueError(f"'{s}' is not a date (use YYYY-MM-DD)")


def _past_date(v: Any) -> date | None:
    d = _date(v)
    if d is not None and d > date.today():
        raise ValueError(f"{d.isoformat()} is in the future")
    return d


def _source_for_header(header: str, sources: dict[str, ComplianceSource]):
    """Compliance source for an L2 column header: 'Internal Security Policy', 'Policy reference',
    'External Regulator #1 ref' ... A header that fits no source or several is not a source."""
    h = re.sub(r"\s*\b(refs?|references?|ids?)$", "", header).strip()
    h = {"internal policy": "internal security policy"}.get(h, h)
    if h in sources:
        return sources[h]
    if len(h) < 4:
        return None
    hits = [s for name, s in sources.items() if h in name]
    return hits[0] if len(hits) == 1 else None


def _sheet(wb, name: str):
    for ws in wb.worksheets:
        if ws.title.strip().lower() == name.lower():
            return ws
    return None


def _find_header(ws, keys: list[str], max_row: int = 15) -> tuple[int, dict[str, int]] | None:
    """Row number and {normalized header: column} of the first row that has all `keys`."""
    for row in ws.iter_rows(min_row=1, max_row=max_row):
        cols = {_norm(c.value): c.column for c in row if c.value is not None}
        if all(k in cols for k in keys):
            return row[0].row, cols
    return None


def _col(cols: dict[str, int], *prefixes: str) -> int | None:
    for p in prefixes:
        for name, col in cols.items():
            if name == p or name.startswith(p):
                return col
    return None


class _Importer:
    def __init__(self, db: Session, report: Report, replace: bool, username: str, is_admin: bool):
        self.db = db
        self.r = report
        self.replace = replace
        self.username = username
        self.is_admin = is_admin
        # (use case, old status, new status, definition of done skipped) for the change log
        self.status_changes: list[tuple[Any, Lifecycle | None, Lifecycle, bool]] = []
        self.refs: dict[tuple[RefKind, str], ReferenceItem] = {
            (x.kind, x.name.lower()): x for x in db.scalars(select(ReferenceItem))
        }

    # -- helpers
    def ref(self, kind: RefKind, name: str, sheet: str, row: int) -> ReferenceItem:
        key = (kind, name.lower())
        if key not in self.refs:
            item = ReferenceItem(kind=kind, name=name, description="")
            self.db.add(item)
            self.refs[key] = item
            self.r.count("references", "created")
            self.r.warn(sheet, row, f"Added '{name}' to the {kind.value.replace('_', ' ')} list")
        return self.refs[key]

    def upsert(self, entity: str, obj, values: dict[str, Any], created: bool) -> None:
        changed = False
        for k, v in values.items():
            old = getattr(obj, k)
            if isinstance(old, str) and isinstance(v, str) and old.strip() == v.strip():
                continue
            if old != v:
                setattr(obj, k, v)
                changed = True
        self.r.count(entity, "created" if created else ("updated" if changed else "unchanged"))

    def delete_missing(self, entity: str, model, keep: set, key=lambda o: o.code) -> None:
        if not self.replace:
            return
        for obj in list(self.db.scalars(select(model))):
            if key(obj) not in keep:
                self.db.delete(obj)
                self.r.count(entity, "deleted")
        self.db.flush()

    def ref_names(self, kind: RefKind, value: Any) -> list[str]:
        """Split a cell into list entries. ';' and line breaks always separate; ',' only when
        the text is not a known entry (names like 'Hacktivists, Cyber vandals ...' exist)."""
        out: list[str] = []
        for token in re.split(r"[;\n]", _text(value)):
            token = token.strip()
            if not token:
                continue
            if (kind, token.lower()) in self.refs or "," not in token:
                out.append(token)
            else:
                out += [p.strip() for p in token.split(",") if p.strip()]
        return list(dict.fromkeys(out))

    # -- sheets
    def references(self, ws) -> None:
        sheet = ws.title
        seen: dict[RefKind, set[str]] = {k: set() for k, *_ in REF_SECTIONS}
        current: RefKind | None = None
        header_next = False
        titles = {t.lower(): k for k, t, _ in REF_SECTIONS}
        titles |= {
            "threat actors (csan 2017)": RefKind.threat_actor,
            "log sources": RefKind.log_source,
        }
        for row in ws.iter_rows(min_row=1):
            b = next((c for c in row if c.value is not None), None)
            if b is None:
                continue
            label = _norm(b.value)
            kind = next((k for t, k in titles.items() if label.startswith(t)), None)
            if kind is not None and len([c for c in row if c.value is not None]) == 1:
                current, header_next = kind, True
                continue
            if header_next:  # the column header line below the title
                header_next = False
                continue
            if current is None:
                continue
            name = _text(b.value)
            if not name:
                continue
            desc_cell = ws.cell(b.row, b.column + 1).value
            desc = _text(desc_cell)
            key = (current, name.lower())
            item = self.refs.get(key)
            created = item is None
            if created:
                item = ReferenceItem(kind=current, name=name, description=desc)
                self.db.add(item)
                self.refs[key] = item
                self.r.count("references", "created")
            else:
                self.upsert("references", item, {"description": desc} if desc else {}, False)
            seen[current].add(name.lower())
        self.db.flush()
        if self.replace:
            for (kind, lname), item in list(self.refs.items()):
                if seen[kind] and lname not in seen[kind]:
                    self.db.delete(item)
                    del self.refs[(kind, lname)]
                    self.r.count("references", "deleted")
            self.db.flush()
        if not any(seen.values()):
            self.r.warn(sheet, None, "No reference list entries found")

    def drivers(self, ws) -> None:
        sheet = ws.title
        bd_head = _find_header(ws, ["id", "business drivers"], max_row=40)
        cd_head = None
        for row in ws.iter_rows(min_row=1, max_row=ws.max_row):
            cols = {_norm(c.value): c.column for c in row if c.value is not None}
            if "id" in cols and "compliance driver" in cols:
                cd_head = row[0].row, cols
                break
        keep_bd: set[str] = set()
        if bd_head:
            hrow, cols = bd_head
            cid, cname, cdesc = cols["id"], cols["business drivers"], _col(cols, "description")
            existing = {d.code: d for d in self.db.scalars(select(BusinessDriver))}
            r = hrow + 1
            while r <= ws.max_row:
                code = _text(ws.cell(r, cid).value)
                if not code:
                    break
                name = _text(ws.cell(r, cname).value) or code
                desc = _text(ws.cell(r, cdesc).value) if cdesc else ""
                obj = existing.get(code)
                if obj is None:
                    obj = BusinessDriver(code=code, name=name, description=desc)
                    self.db.add(obj)
                    existing[code] = obj
                    self.r.count("business_drivers", "created")
                else:
                    self.upsert("business_drivers", obj, {"name": name, "description": desc}, False)
                keep_bd.add(code)
                r += 1
            self.db.flush()
            self.delete_missing("business_drivers", BusinessDriver, keep_bd)
        else:
            self.r.warn(sheet, None, "Business driver table not found")

        if cd_head:
            hrow, cols = cd_head
            cid, csrc = cols["id"], cols["compliance driver"]
            cdesc, cname = _col(cols, "description"), _col(cols, "name")
            sources = {s.name: s for s in self.db.scalars(select(ComplianceSource))}
            keep: set[tuple[str, str]] = set()
            for r in range(hrow + 1, ws.max_row + 1):
                ref, src_name = _text(ws.cell(r, cid).value), _text(ws.cell(r, csrc).value)
                if not src_name:
                    continue
                src = sources.get(src_name)
                if src is None:
                    src = ComplianceSource(name=src_name)
                    self.db.add(src)
                    sources[src_name] = src
                    self.r.count("compliance_sources", "created")
                if not ref or ref.upper() == "REF":  # empty template row
                    continue
                desc = _text(ws.cell(r, cdesc).value) if cdesc else ""
                name = _text(ws.cell(r, cname).value) if cname else ""
                obj = next((d for d in src.drivers if d.ref == ref), None)
                if obj is None:
                    src.drivers.append(ComplianceDriver(ref=ref, name=name, description=desc))
                    self.r.count("compliance_drivers", "created")
                else:
                    vals = {"description": desc} | ({"name": name} if cname else {})
                    self.upsert("compliance_drivers", obj, vals, False)
                keep.add((src_name, ref))
            self.db.flush()
            if self.replace:
                for src in sources.values():
                    for d in list(src.drivers):
                        if (src.name, d.ref) not in keep:
                            src.drivers.remove(d)
                            self.r.count("compliance_drivers", "deleted")
                self.db.flush()

    def l1(self, ws) -> None:
        sheet = ws.title
        found = _find_header(ws, ["l1 use case identifier", "use case name"])
        if not found:
            raise ImportFailed(f"{sheet}: header row with 'L1 Use Case Identifier' not found")
        hrow, cols = found
        c_code, c_name = cols["l1 use case identifier"], cols["use case name"]
        c_cat = _col(cols, "threat category")
        c_purpose, c_stake = _col(cols, "purpose"), _col(cols, "stakeholders")
        c_desc, c_app = _col(cols, "description"), _col(cols, "applicable")
        existing = {x.code: x for x in self.db.scalars(select(L1UseCase))}
        keep: set[str] = set()
        category = ""
        for order, r in enumerate(range(hrow + 1, ws.max_row + 1)):
            raw, name = _text(ws.cell(r, c_code).value), _text(ws.cell(r, c_name).value)
            if c_cat and _text(ws.cell(r, c_cat).value):
                category = _text(ws.cell(r, c_cat).value)
            if not raw and not name:
                continue
            if len(raw) > 4:  # summary block below the table in the classic sheet
                break
            applicable = True
            code = raw.upper()
            if code in ("N/A", "NA", "-"):
                applicable, code = False, re.sub(r"[^A-Z]", "", name.upper())[:2]
            if c_app is not None and _text(ws.cell(r, c_app).value):
                applicable = _norm(ws.cell(r, c_app).value) in ("yes", "y", "true", "1", "x")
            if not L1_RE.fullmatch(code):
                self.r.error(sheet, r, f"'{raw}' is not a valid L1 identifier (two letters)")
                continue
            vals: dict[str, Any] = {
                "name": name or code,
                "threat_category": category,
                "applicable": applicable,
                "sort_order": order,
            }
            if c_purpose:
                vals["purpose"] = _text(ws.cell(r, c_purpose).value)
            if c_stake:
                vals["stakeholders"] = _text(ws.cell(r, c_stake).value)
            if c_desc:
                vals["description"] = _text(ws.cell(r, c_desc).value)
            obj = existing.get(code)
            if obj is None:
                obj = L1UseCase(code=code, **vals)
                self.db.add(obj)
                existing[code] = obj
                self.r.count("l1", "created")
            else:
                self.upsert("l1", obj, vals, False)
            keep.add(code)
        self.db.flush()
        self.keep_l1 = keep

    def l2(self, ws) -> None:
        sheet = ws.title
        found = _find_header(ws, ["l2 use case identifier", "use case name"])
        if not found:
            raise ImportFailed(f"{sheet}: header row with 'L2 Use Case Identifier' not found")
        hrow, cols = found
        c_code, c_name = cols["l2 use case identifier"], cols["use case name"]
        c_desc, c_actors = _col(cols, "use case description"), _col(cols, "actors")
        c_bd = _col(cols, "business driver")
        c_all_bd, c_all_cd = cols.get(ALL_BD.lower()), cols.get(ALL_CD.lower())
        c_status, c_risk = _col(cols, "lifecycle status"), _col(cols, "risk level")
        c_target = _col(cols, "target implementation")
        c_onb, c_ver = _col(cols, "onboarded"), cols.get("last verified")
        sources = {s.name.lower(): s for s in self.db.scalars(select(ComplianceSource))}
        taken = {c_code, c_name, c_desc, c_actors, c_bd, c_all_bd, c_all_cd}
        taken |= {c_status, c_risk, c_target, c_onb, c_ver}
        comp_cols = {
            col: src
            for name, col in cols.items()
            if col not in taken and (src := _source_for_header(name, sources))
        }
        l1s = {x.code: x for x in self.db.scalars(select(L1UseCase))}
        bds = {x.code: x for x in self.db.scalars(select(BusinessDriver))}
        existing = {x.code: x for x in self.db.scalars(select(L2UseCase))}
        keep: set[str] = set()
        for r in range(hrow + 1, ws.max_row + 1):
            raw = _text(ws.cell(r, c_code).value)
            if not raw:
                continue
            code = raw.upper()
            if not L2_RE.fullmatch(code):
                self.r.error(sheet, r, f"'{raw}' is not a valid L2 identifier (XX-YYY)")
                continue
            parent = l1s.get(code[:2])
            if parent is None:
                self.r.error(sheet, r, f"{code}: no L1 use case {code[:2]}")
                continue
            vals: dict[str, Any] = {"name": _text(ws.cell(r, c_name).value) or code}
            if c_desc:
                vals["description"] = _text(ws.cell(r, c_desc).value)
            try:
                if c_status and (s := _norm(ws.cell(r, c_status).value)):
                    vals["lifecycle_status"] = Lifecycle(s)
                if c_risk and (v := ws.cell(r, c_risk).value) not in (None, ""):
                    risk = int(float(v))
                    if not 1 <= risk <= 5:
                        raise ValueError("risk level must be 1 to 5")
                    vals["risk_level"] = risk
                if c_target and (v := ws.cell(r, c_target).value) not in (None, ""):
                    vals["target_implementation"] = self.metric(v, sheet, r, "target")
                if c_onb:
                    vals["onboarded_at"] = _past_date(ws.cell(r, c_onb).value)
                if c_ver:
                    vals["last_verified_at"] = _past_date(ws.cell(r, c_ver).value)
            except ValueError as e:
                self.r.error(sheet, r, f"{code}: {e}")
                continue
            obj = existing.get(code)
            change = self.check_status(sheet, r, code, obj, vals)
            if change is False:
                continue
            self.verification(obj, vals)
            created = obj is None
            if created:
                obj = L2UseCase(code=code, parent=parent, name=vals["name"])
                self.db.add(obj)
                existing[code] = obj
            self.upsert("l2", obj, vals, created)
            if c_actors:
                obj.actors = [
                    self.ref(RefKind.threat_actor, a, sheet, r)
                    for a in self.ref_names(RefKind.threat_actor, ws.cell(r, c_actors).value)
                ]
            if c_bd or c_all_bd:
                chosen = []
                codes = _split(ws.cell(r, c_bd).value) if c_bd else []
                codes += _split(ws.cell(r, c_all_bd).value) if c_all_bd else []
                for b in dict.fromkeys(codes):
                    if b in bds:
                        chosen.append(bds[b])
                    else:
                        self.r.warn(sheet, r, f"{code}: unknown business driver '{b}' not linked")
                obj.business_drivers = chosen
            if comp_cols or c_all_cd:
                wanted: list[tuple[ComplianceSource | None, str, str]] = []
                for col, src in comp_cols.items():
                    wanted += [(src, src.name, ref) for ref in _split(ws.cell(r, col).value)]
                if c_all_cd:
                    for token in re.split(r"[;\n]", _text(ws.cell(r, c_all_cd).value)):
                        src_name, sep, ref = token.rpartition(":")
                        if not sep or not ref.strip():
                            if token.strip():
                                self.r.warn(
                                    sheet, r, f"{code}: '{token.strip()}' is not 'Source: ref'"
                                )
                            continue
                        name = src_name.strip()
                        wanted.append((sources.get(name.lower()), name, ref.strip()))
                chosen_cd: dict[int, ComplianceDriver] = {}
                for src, src_name, ref in wanted:
                    d = next((x for x in src.drivers if x.ref == ref), None) if src else None
                    if d is None:
                        self.r.warn(
                            sheet,
                            r,
                            f"{code}: unknown compliance driver {src_name} {ref} not linked",
                        )
                        continue
                    chosen_cd[id(d)] = d
                obj.compliance_drivers = list(chosen_cd.values())
            self.queue_status(obj, change)
            keep.add(code)
        self.db.flush()
        self.log_status()
        self.keep_l2 = keep

    def check_status(self, sheet: str, row: int, code: str, obj, vals: dict[str, Any]):
        """Same rules as a status change in the app: Operational needs the definition of done
        (admins may skip it). Returns False when the row is refused, else the pending change
        (old, new, skipped definition of done) or None; see log_status()."""
        old = obj.lifecycle_status if obj is not None else None
        new = vals.get("lifecycle_status")
        if new is None or new == old:
            return None
        missing: list[str] = []
        if new == Lifecycle.operational:
            missing = lifecycle.dod_missing(obj) if obj is not None else list(lifecycle.DOD_KEYS)
        if missing and not self.is_admin:
            self.r.error(
                sheet,
                row,
                f"{code}: cannot become operational, the definition of done is not complete "
                "(tick the checklist in the app or ask an admin)",
            )
            return False
        if new == Lifecycle.operational and not vals.get("onboarded_at"):
            if obj is None or obj.onboarded_at is None:
                vals["onboarded_at"] = date.today()
        return (old, new, bool(missing))

    def queue_status(self, obj, change) -> None:
        if change:
            self.status_changes.append((obj, *change))

    def log_status(self) -> None:
        """Write the queued changes to the lifecycle change log (after the flush, ids exist)."""
        for obj, old, new, override in self.status_changes:
            lifecycle.record_change(
                self.db, obj, old, new, self.username, note="Excel import", override=override
            )
        self.status_changes = []

    def verification(self, obj, vals: dict[str, Any]) -> None:
        """Whoever imports a new verification date is recorded as the verifier."""
        vals.pop("last_verified_by", None)
        if "last_verified_at" in vals:
            old = obj.last_verified_at if obj is not None else None
            if vals["last_verified_at"] != old:
                vals["last_verified_by"] = self.username if vals["last_verified_at"] else None

    def metric(self, v: Any, sheet: str, row: int, what: str) -> float | None:
        if v is None or (isinstance(v, str) and not v.strip()):
            return None
        if isinstance(v, str):
            s = v.strip().rstrip("%").strip().replace(",", ".")
            f = float(s)
            if v.strip().endswith("%"):
                f /= 100
        else:
            f = float(v)
        if f > 1:
            if f <= 100:
                self.r.warn(sheet, row, f"{what} {f:g} read as {f / 100:g} (0-100 scale)")
                f /= 100
            else:
                raise ValueError(f"{what} {f:g} is out of range")
        if f < 0:
            raise ValueError(f"{what} {f:g} is out of range")
        return round(f, 4)

    def l3(self, ws) -> None:
        sheet = ws.title
        found = _find_header(ws, ["rule identifier"])
        if not found:
            raise ImportFailed(f"{sheet}: header row with 'Rule Identifier' not found")
        hrow, cols = found
        c_code = cols["rule identifier"]
        c_name = _col(cols, "technical use case name", "rule name", "name")
        c_desc = _col(cols, "use case description", "description")
        c_eff, c_impl = _col(cols, "effectiveness"), _col(cols, "implementation")
        c_cov = _col(cols, "coverage")
        c_log, c_tech = _col(cols, "log source"), _col(cols, "detection technolog")
        c_scope, c_comm = _col(cols, "scope"), _col(cols, "comments")
        c_status, c_onb = _col(cols, "lifecycle status"), _col(cols, "onboarded")
        c_ver, c_verby = cols.get("last verified"), cols.get("last verified by")
        c_int, c_attack = _col(cols, "verify every", "verification interval"), _col(cols, "att&ck")
        c_risk, c_target = _col(cols, "risk level"), _col(cols, "target implementation")
        l2s = {x.code: x for x in self.db.scalars(select(L2UseCase))}
        existing = {
            x.code: x
            for x in self.db.scalars(select(L3UseCase).options(selectinload(L3UseCase.references)))
        }
        keep: set[str] = set()
        for r in range(hrow + 1, ws.max_row + 1):
            raw = _text(ws.cell(r, c_code).value)
            if not raw:
                continue
            code = raw.upper()
            if len(code) > L3_CODE_MAX or not L3_RE.fullmatch(code):
                self.r.error(
                    sheet, r, f"'{raw}' is not a valid rule identifier (XX-YYY-NN or XX-YYY-...-NN)"
                )
                continue
            parent = l2s.get(code[:6])
            if parent is None:
                self.r.error(sheet, r, f"{code}: no L2 use case {code[:6]}")
                continue
            vals: dict[str, Any] = {}
            name = _text(ws.cell(r, c_name).value) if c_name else ""
            vals["name"] = name or code
            desc = _text(ws.cell(r, c_desc).value) if c_desc else ""
            if c_desc:
                vals["description"] = desc
            try:
                for key, col in (
                    ("effectiveness", c_eff),
                    ("implementation", c_impl),
                    ("coverage", c_cov),
                ):
                    if col:
                        vals[key] = self.metric(ws.cell(r, col).value, sheet, r, f"{code} {key}")
                if c_status and (s := _norm(ws.cell(r, c_status).value)):
                    vals["lifecycle_status"] = Lifecycle(s)
                if c_onb:
                    vals["onboarded_at"] = _past_date(ws.cell(r, c_onb).value)
                if c_ver:
                    vals["last_verified_at"] = _past_date(ws.cell(r, c_ver).value)
                if c_verby:
                    vals["last_verified_by"] = _text(ws.cell(r, c_verby).value) or None
                if c_int:
                    v = ws.cell(r, c_int).value
                    vals["verification_interval_days"] = (
                        int(float(v)) if v not in (None, "") else None
                    )
                if c_risk:  # empty = inherit from the L2 use case
                    v = ws.cell(r, c_risk).value
                    risk = int(float(v)) if v not in (None, "") else None
                    if risk is not None and not 1 <= risk <= 5:
                        raise ValueError("risk level must be 1 to 5")
                    vals["risk_level"] = risk
                if c_target:
                    v = ws.cell(r, c_target).value
                    vals["target_implementation"] = (
                        self.metric(v, sheet, r, f"{code} target") if v not in (None, "") else None
                    )
            except ValueError as e:
                self.r.error(sheet, r, f"{code}: {e}")
                continue
            if c_comm:
                vals["comments"] = _text(ws.cell(r, c_comm).value)
            attack_src = _text(ws.cell(r, c_attack).value) if c_attack else ""
            techniques = ATTACK_RE.findall(attack_src) or ATTACK_RE.findall(desc)
            if c_attack or techniques:
                vals["attack_techniques"] = list(dict.fromkeys(techniques))

            obj = existing.get(code)
            change = self.check_status(sheet, r, code, obj, vals)
            if change is False:
                continue
            self.verification(obj, vals)
            created = obj is None
            if created:
                obj = L3UseCase(code=code, parent=parent, name=vals["name"], references=[])
                self.db.add(obj)
                existing[code] = obj
            self.upsert("l3", obj, vals, created)
            refs = list(obj.references)
            for kind, col in (
                (RefKind.log_source, c_log),
                (RefKind.detection_technology, c_tech),
                (RefKind.scope, c_scope),
            ):
                if col:
                    refs = [x for x in refs if x.kind != kind] + [
                        self.ref(kind, n, sheet, r)
                        for n in self.ref_names(kind, ws.cell(r, col).value)
                    ]
            obj.references = refs
            self.queue_status(obj, change)
            keep.add(code)
        self.db.flush()
        self.log_status()
        self.keep_l3 = keep


def import_workbook(
    db: Session,
    data: bytes,
    replace: bool,
    dry_run: bool,
    username: str = "import",
    is_admin: bool = False,
) -> Report:
    """Apply the workbook to the session. The caller commits or rolls back."""
    report = Report(mode="replace" if replace else "merge", dry_run=dry_run)
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            unpacked = sum(i.file_size for i in z.infolist())
    except zipfile.BadZipFile as e:
        raise ImportFailed(f"Not a readable .xlsx file: {e}") from e
    if unpacked > MAX_UNPACKED_BYTES:
        # a small upload can unpack to gigabytes in memory ("zip bomb")
        raise ImportFailed(
            f"The workbook unpacks to {unpacked // 2**20} MB, more than the "
            f"{MAX_UNPACKED_BYTES // 2**20} MB allowed"
        )
    try:
        wb = load_workbook(io.BytesIO(data), data_only=False)
    except Exception as e:  # noqa: BLE001 - any parse error is a user error here
        raise ImportFailed(f"Not a readable .xlsx file: {e}") from e

    imp = _Importer(db, report, replace, username, is_admin)
    sheets = {n: _sheet(wb, n) for n in ("References", "Drivers", "L1 UC", "L2 UC", "L3 UC")}
    report.sheets = [ws.title for ws in sheets.values() if ws is not None]
    if not any(sheets[n] for n in ("L1 UC", "L2 UC", "L3 UC")):
        raise ImportFailed("No 'L1 UC', 'L2 UC' or 'L3 UC' sheet found; is this a MaGMa workbook?")
    for name, ws in sheets.items():
        if ws is None:
            report.warn(name, None, "Sheet not found, skipped")

    with db.no_autoflush:
        if sheets["References"] is not None:
            imp.references(sheets["References"])
        if sheets["Drivers"] is not None:
            imp.drivers(sheets["Drivers"])
        if sheets["L1 UC"] is not None:
            imp.l1(sheets["L1 UC"])
        if sheets["L2 UC"] is not None:
            imp.l2(sheets["L2 UC"])
        if sheets["L3 UC"] is not None:
            imp.l3(sheets["L3 UC"])

    # replace mode: remove use cases that are not in the file (children first)
    if replace:
        if sheets["L3 UC"] is not None:
            imp.delete_missing("l3", L3UseCase, imp.keep_l3)
        if sheets["L2 UC"] is not None:
            for l2 in list(db.scalars(select(L2UseCase))):
                if l2.code not in imp.keep_l2:
                    if l2.children:
                        report.error(
                            "L2 UC", None, f"{l2.code} is not in the file but has rules; kept"
                        )
                        continue
                    db.delete(l2)
                    report.count("l2", "deleted")
            db.flush()
        if sheets["L1 UC"] is not None:
            for l1 in list(db.scalars(select(L1UseCase))):
                if l1.code not in imp.keep_l1:
                    if l1.children:
                        report.error(
                            "L1 UC", None, f"{l1.code} is not in the file but has L2; kept"
                        )
                        continue
                    db.delete(l1)
                    report.count("l1", "deleted")
            db.flush()
    return report


def column_letter(i: int) -> str:
    return get_column_letter(i)
