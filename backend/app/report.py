"""PDF management report (PLAN 2.16), built from the same functions as the API."""

import re
import unicodedata
from datetime import UTC, date, datetime
from pathlib import Path

from fpdf import FPDF
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import Settings
from app.models import LifecycleEvent

INK = (22, 24, 29)
INK2 = (58, 63, 74)
MUTED = (91, 97, 112)
BORDER = (226, 228, 233)
TRACK = (238, 240, 243)
ACCENT = (194, 65, 12)
DATA1 = (29, 78, 216)
DATA2 = (147, 197, 253)
DATA3 = (234, 88, 12)

FONT_DIR = Path(__file__).parent / "fonts"
FONT = "DejaVu"  # Unicode TTF bundled with the app (issue #44); the core fonts are latin-1 only


def _t(s: object) -> str:
    """Text for the PDF: DejaVu Sans covers Latin, Greek, Cyrillic, arrows and common symbols.
    Control characters are dropped; glyphs the font lacks (e.g. CJK, emoji) are replaced."""
    out = []
    for ch in str(s):
        if ch in "\n\t\u200b":  # zero-width space keeps fpdf2 markers apart (md_text)
            out.append(ch)
        elif unicodedata.category(ch)[0] == "C":
            continue
        elif ord(ch) > 0xFFFF or unicodedata.east_asian_width(ch) in ("W", "F"):
            out.append("?")
        else:
            out.append(ch)
    return "".join(out)


_LINK = re.compile(r"\[([^\]]+)\]\(([^)\s]+)\)")
_CODE = re.compile(r"`([^`]+)`")
_ITALIC = re.compile(r"(?<![*\w])[*_]([^*_\n]+)[*_](?![*\w])")


_FENCE = re.compile(r"^\s{0,3}(`{3,}|~{3,})")


def md_blocks(src: str) -> list[tuple[bool, str]]:
    """Splits Markdown into (is_code, text) parts at fenced code blocks (``` or ~~~).
    An unclosed fence runs to the end, as in the app."""
    parts: list[tuple[bool, str]] = []
    buf: list[str] = []
    fence = ""
    for line in str(src).splitlines():
        m = _FENCE.match(line)
        if not fence and m:
            parts.append((False, "\n".join(buf)))
            buf, fence = [], m.group(1)
        elif (
            fence
            and m
            and m.group(1)[0] == fence[0]
            and len(m.group(1)) >= len(fence)
            and not line.strip()[len(m.group(1)) :].strip()
        ):
            parts.append((True, "\n".join(buf)))
            buf, fence = [], ""
        else:
            buf.append(line)
    parts.append((bool(fence), "\n".join(buf)))
    return [(c, p) for c, p in parts if c or p.strip()]


def md_text(src: str) -> str:
    """Markdown (as typed in the app) to the small markup fpdf2 understands: **bold** stays,
    lists get bullets, headings become bold lines, links show their address, other markers go
    (issue #44). fpdf2's own markers for italics and underline are neutralised first."""
    lines = []
    src = re.sub(r"__(\S(?:.*?\S)?)__", r"**\1**", str(src))  # __bold__ is bold too
    for raw in src.replace("__", "_\u200b_").replace("--", "-\u200b-").splitlines():
        line = raw.rstrip()
        stripped = line.lstrip()
        indent = "    " * ((len(line) - len(stripped)) // 2)
        m = re.match(r"^(#{1,6})\s+(.*)$", stripped)
        if m:
            line = f"**{m.group(2).strip('* ')}**"
        elif re.match(r"^[-*+]\s+", stripped):
            line = indent + "\u2022 " + re.sub(r"^[-*+]\s+", "", stripped)
        elif re.match(r"^\d+[.)]\s+", stripped):
            line = indent + stripped
        elif stripped.startswith(">"):
            line = "    " + stripped.lstrip("> ")
        line = _LINK.sub(lambda x: f"{x.group(1)} ({x.group(2)})", line)
        line = _CODE.sub(r"\1", line)
        line = _ITALIC.sub(r"\1", line)
        lines.append(line)
    return _t("\n".join(lines))


def pct(v: float | None, digits: int = 0) -> str:
    return "-" if v is None else f"{v * 100:.{digits}f} %"


def num(v: float | None) -> str:
    return "-" if v is None else f"{v:.2f}"


class Report(FPDF):
    def __init__(self, title: str):
        super().__init__(format="A4")
        self.title_text = title
        self.set_margins(16, 16, 16)
        self.set_auto_page_break(True, margin=16)
        self.set_title(title)
        self.set_creator("MaGMa UCF")
        self.add_font(FONT, "", str(FONT_DIR / "DejaVuSans.ttf"))
        self.add_font(FONT, "B", str(FONT_DIR / "DejaVuSans-Bold.ttf"))

    def set_font(self, family=None, style="", size=0):
        # every caller asks for Helvetica; the bundled Unicode font replaces it (issue #44)
        if family and family.lower() in ("helvetica", "arial"):
            family = FONT
        style = (style or "").replace("I", "")  # no italic face bundled
        super().set_font(family, style, size)

    def footer(self) -> None:
        self.set_y(-11)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(*MUTED)
        self.cell(0, 5, _t(f"{self.title_text} - page {self.page_no()}"), align="R")

    # ---- building blocks
    def h1(self, text: str) -> None:
        self.set_font("Helvetica", "B", 20)
        self.set_text_color(*INK)
        self.cell(0, 10, _t(text), new_x="LMARGIN", new_y="NEXT")

    def h2(self, text: str, space: float = 6, need: float = 45) -> None:
        """Section heading; starts a new page unless `need` mm fit below it."""
        if self.get_y() + space + need > self.h - self.b_margin:
            self.add_page()
            space = 0
        self.ln(space)
        self.set_font("Helvetica", "B", 12.5)
        self.set_text_color(*INK)
        self.cell(0, 7, _t(text), new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(*BORDER)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.ln(2.5)

    def p(self, text: str, size: float = 9.5, color=INK2) -> None:
        self.set_font("Helvetica", "", size)
        self.set_text_color(*color)
        self.multi_cell(0, 4.8, _t(text), align="L", new_x="LMARGIN", new_y="NEXT")

    def md(self, text: str, size: float = 9.5, color=INK2) -> None:
        """A paragraph of Markdown text from the app (bold, lists, links). Fenced code blocks
        (```) are printed as they are, on a grey box (#84)."""
        for is_code, part in md_blocks(text):
            if is_code:
                self.code(part, size=max(7.0, size - 1.5))
                continue
            if not part.strip():
                continue
            self.set_font("Helvetica", "", size)
            self.set_text_color(*color)
            self.multi_cell(
                0, 4.8, md_text(part), align="L", new_x="LMARGIN", new_y="NEXT", markdown=True
            )

    def code(self, text: str, size: float = 8) -> None:
        """A code block: the text unchanged (no Markdown), on a grey box."""
        self.set_font("Helvetica", "", size)
        self.set_text_color(*INK)
        self.set_fill_color(*TRACK)
        self.ln(0.8)
        self.multi_cell(
            0,
            size * 0.48,
            _t(text.rstrip("\n") or " "),
            align="L",
            fill=True,
            padding=1.5,
            new_x="LMARGIN",
            new_y="NEXT",
        )
        self.ln(0.8)

    def bar(
        self, x: float, y: float, w: float, v: float | None, color=DATA1, h: float = 2.2
    ) -> None:
        self.set_fill_color(*TRACK)
        self.rect(x, y, w, h, style="F")
        if v:
            self.set_fill_color(*color)
            self.rect(x, y, max(0.4, w * min(1.0, v)), h, style="F")

    def tiles(self, items: list[tuple[str, str, str, float | None]]) -> None:
        """Up to three tiles per row: label, value, sub text, bar value."""
        gap, per = 4, 3
        w = (self.w - self.l_margin - self.r_margin - gap * (per - 1)) / per
        h = 25
        for row in range(0, len(items), per):
            y = self.get_y()
            for i, (label, value, sub, v) in enumerate(items[row : row + per]):
                x = self.l_margin + i * (w + gap)
                self.set_draw_color(*BORDER)
                self.rect(x, y, w, h)
                self.set_xy(x + 4, y + 3)
                self.set_font("Helvetica", "", 8.5)
                self.set_text_color(*MUTED)
                self.cell(w - 8, 4, _t(label))
                self.set_xy(x + 4, y + 7.5)
                self.set_font("Helvetica", "B", 16)
                self.set_text_color(*INK)
                self.cell(w - 8, 7, _t(value))
                self.bar(x + 4, y + 15.5, w - 8, v)
                self.set_xy(x + 4, y + 19)
                self.set_font("Helvetica", "", 7.5)
                self.set_text_color(*MUTED)
                self.cell(w - 8, 4, _t(sub))
            self.set_y(y + h + gap)

    def table(self, cols: list[tuple[str, float, str]], rows: list[list], bars: dict | None = None):
        """cols: (title, width in mm, align L/R). bars: {col index: (value index, color)}."""
        bars = bars or {}
        self.set_font("Helvetica", "B", 8.5)
        self.set_text_color(*MUTED)
        self.set_fill_color(244, 245, 247)
        for title, w, align in cols:
            self.cell(w, 6.5, _t(title), align=align, fill=True)
        self.ln()
        self.set_font("Helvetica", "", 8.5)
        for row in rows:
            if self.get_y() > self.h - 24:
                self.add_page()
            y = self.get_y()
            x = self.l_margin
            for i, (_title, w, align) in enumerate(cols):
                if i in bars:
                    vi, color = bars[i]
                    self.bar(x + 1, y + 2.3, w - 2, row[vi], color)
                else:
                    self.set_text_color(*(MUTED if i == 0 else INK))
                    self.set_xy(x, y)
                    text = _t(row[i])
                    while self.get_string_width(text) > w - 1.5 and len(text) > 3:
                        text = text[:-2]
                        text = text.rstrip() + "."
                    self.cell(w, 6.2, text, align=align)
                x += w
            self.set_xy(self.l_margin, y + 6.2)
            self.set_draw_color(*TRACK)
            self.line(
                self.l_margin, self.get_y(), self.l_margin + sum(c[1] for c in cols), self.get_y()
            )

    def line_chart(self, points: list[tuple[str, float | None]], h: float = 38, unit: str = "pct"):
        x0, y0 = self.l_margin + 10, self.get_y() + 2
        w = self.w - self.r_margin - x0
        vals = [v for _, v in points if v is not None]
        if len(vals) < 2:
            self.p("Not enough snapshots yet for a trend line.", color=MUTED)
            return
        lo = 0.0
        hi = (
            max(0.25, min(1.0, (int(max(vals) * 4) + 1) / 4)) if unit == "pct" else max(vals) * 1.15
        )
        self.set_font("Helvetica", "", 7)
        self.set_text_color(*MUTED)
        for t in (lo, (lo + hi) / 2, hi):
            yy = y0 + h - (t - lo) / (hi - lo) * h
            self.set_draw_color(*TRACK)
            self.line(x0, yy, x0 + w, yy)
            self.set_xy(self.l_margin - 2, yy - 2)
            label = pct(t, 0 if round(t * 100, 1).is_integer() else 1)
            self.cell(11, 4, label if unit == "pct" else f"{t:.0f}", align="R")
        n = len(points)

        def xy(i, v):
            return x0 + (i * w / (n - 1)), y0 + h - (v - lo) / (hi - lo) * h

        self.set_draw_color(*DATA1)
        self.set_line_width(0.6)
        prev = None
        for i, (_, v) in enumerate(points):
            if v is None:
                prev = None
                continue
            cur = xy(i, v)
            if prev:
                self.line(*prev, *cur)
            prev = cur
        self.set_line_width(0.2)
        self.set_fill_color(*DATA1)
        for i, (_, v) in enumerate(points):
            if v is not None:
                cx, cy = xy(i, v)
                self.ellipse(cx - 0.9, cy - 0.9, 1.8, 1.8, style="F")
        self.set_xy(x0 - 5, y0 + h + 1)
        self.cell(20, 4, _t(points[0][0]))
        self.set_xy(x0 + w - 20, y0 + h + 1)
        self.cell(20, 4, _t(points[-1][0]), align="R")
        self.set_y(y0 + h + 7)


def build(db: Session, settings: Settings) -> bytes:
    from app import drivers
    from app.api import attack_api, output, priorities, scores, snapshots

    s = scores.scores(None, db, settings)
    k = s.kpis
    trends = snapshots.trends(None, db, settings)
    gaps = priorities.gaps(None, db, settings, None, 1, True)
    due = scores.verification_due(None, db, settings, 0)
    cov = attack_api.coverage(None, db, settings)
    out = output.summary(None, db, 12)
    dcov = drivers.coverage(db, settings.default_verification_days, settings.driver_low_coverage)
    today = date.today()
    changes_month = db.scalar(
        select(func.count())
        .select_from(LifecycleEvent)
        .where(
            LifecycleEvent.at >= datetime.combine(today.replace(day=1), datetime.min.time(), UTC)
        )
    )

    title = f"{settings.app_name} - SOC use case report"
    pdf = Report(title)
    pdf.add_page()
    pdf.set_fill_color(*ACCENT)
    pdf.rect(pdf.l_margin, 14, 14, 1.6, style="F")
    pdf.ln(2)
    pdf.h1("SOC use case report")
    pdf.p(
        f"{today:%d %B %Y} - {len(s.l1)} L1, {len(s.l2)} L2, "
        f"{sum(x.rules for x in s.l1)} L3 rules. "
        "Scores follow the MaGMa Use Case Framework: weight = effectiveness x implementation x "
        "coverage of operational rules.",
        color=MUTED,
    )
    pdf.ln(4)
    pdf.tiles(
        [
            (
                "SOC detection score",
                pct(k.soc_detection_score),
                f"Catalogue coverage {pct(k.catalogue_coverage)} (empty L2 = 0)",
                k.soc_detection_score,
            ),
            (
                "Growth potential",
                pct(k.growth_potential),
                "Effectiveness not yet realised",
                k.growth_potential,
            ),
            (
                "Framework completeness",
                pct(k.framework_completeness),
                f"{k.l2_with_scored_rules} of {k.applicable_l2} L2 with scored rules",
                k.framework_completeness,
            ),
            (
                "Assessment coverage",
                pct(k.assessment_coverage),
                f"{k.assessed_rules} of {k.active_rules} active rules assessed",
                k.assessment_coverage,
            ),
            (
                "Verification health",
                pct(k.verification_health),
                f"{k.verification_overdue} of {k.operational_rules} rules overdue",
                k.verification_health,
            ),
        ]
    )

    pdf.h2("SOC detection score over time", 2)
    pts = [
        ("Now" if p.kind == "live" else f"{p.taken_at:%b %Y}", p.kpis.get("soc_detection_score"))
        for p in trends.points
    ]
    pdf.line_chart(pts)
    if len(trends.points) > 1:
        first, last = trends.points[0].kpis, trends.points[-1].kpis
        pdf.p(
            f"Since {trends.points[0].taken_at:%d %b %Y}: L3 rules {first.get('rules')} -> "
            f"{last.get('rules')}, operational {first.get('operational_rules')} -> "
            f"{last.get('operational_rules')}, status changes this month: {changes_month or 0}.",
            size=8.5,
            color=MUTED,
        )

    pdf.h2("Detection per L1 use case")
    pdf.table(
        [
            ("Code", 14, "L"),
            ("L1 use case", 62, "L"),
            ("L2", 16, "R"),
            ("Rules", 16, "R"),
            ("Weight", 18, "R"),
            ("", 34, "L"),
            ("Potential", 18, "R"),
        ],
        [
            [
                x.code,
                x.name + ("" if x.applicable else " (n/a)"),
                f"{x.scored_l2}/{x.l2_count}",
                x.rules,
                num(x.weight),
                x.weight,
                num(x.potential),
            ]
            for x in s.l1
        ],
        bars={5: (5, DATA1)},
    )

    def flag(gap: bool, low: bool) -> str:
        return "no use case" if gap else ("low" if low else "")

    pdf.h2("Coverage per business driver")
    pdf.p(
        "Average weight of the L2 use cases linked to each driver; L2 use cases without scored "
        f"rules count as 0. Below {pct(dcov.low_threshold)} is low coverage.",
        size=8.5,
        color=MUTED,
    )
    pdf.ln(1)
    pdf.table(
        [
            ("ID", 16, "L"),
            ("Business driver", 56, "L"),
            ("L2", 12, "R"),
            ("L3", 12, "R"),
            ("Coverage", 20, "R"),
            ("", 38, "L"),
            ("Gap", 24, "L"),
        ],
        [
            [
                d.code,
                d.name,
                d.l2_count,
                d.l3_count,
                pct(d.coverage),
                d.coverage,
                flag(d.gap, d.low),
            ]
            for d in dcov.business
        ],
        bars={5: (5, DATA1)},
    )

    pdf.h2("Coverage per compliance source")
    pdf.table(
        [
            ("Source", 56, "L"),
            ("Linked", 22, "R"),
            ("L2", 12, "R"),
            ("L3", 12, "R"),
            ("Coverage", 20, "R"),
            ("", 38, "L"),
        ],
        [
            [
                x.name,
                f"{x.linked_drivers}/{x.drivers}",
                x.l2_count,
                x.l3_count,
                pct(x.coverage),
                x.coverage,
            ]
            for x in dcov.sources
        ],
        bars={5: (5, DATA1)},
    )
    uncovered = [d for d in dcov.business + dcov.compliance if d.gap]
    if uncovered:
        pdf.ln(2)
        names = ", ".join((f"{d.source} {d.code}" if d.source else d.code) for d in uncovered)
        pdf.p(f"Drivers without any linked use case: {names}", size=8, color=MUTED)

    pdf.h2("Top priorities: gap to target")
    pdf.p(
        f"{gaps.summary.below_target} of {gaps.summary.with_target} active rules are below their "
        f"target implementation (average gap {pct(gaps.summary.avg_gap)}). Priority = potential x "
        "risk / 5, raised by 10 % for each driver linked to the L2 use case (at most 50 %).",
        size=8.5,
        color=MUTED,
    )
    pdf.ln(1)
    pdf.table(
        [
            ("Rule", 24, "L"),
            ("Name", 74, "L"),
            ("Risk", 12, "R"),
            ("Impl.", 16, "R"),
            ("Target", 16, "R"),
            ("Gap", 16, "R"),
            ("Priority", 20, "R"),
        ],
        [
            [
                r.code,
                r.name,
                r.risk or "-",
                pct(r.implementation),
                pct(r.target),
                pct(r.gap),
                num(r.priority),
            ]
            for r in gaps.rows[:12]
        ],
    )

    pdf.h2("ATT&CK coverage per tactic")
    pdf.p(
        f"{cov.techniques_with_rules} of {cov.techniques_total} techniques have at least one rule, "
        f"{cov.techniques_scored} with a scored rule (ATT&CK data {cov.version}). "
        f"{len(cov.outdated)} technique IDs in the rules are outdated.",
        size=8.5,
        color=MUTED,
    )
    pdf.ln(1)
    pdf.table(
        [("Tactic", 52, "L"), ("Covered", 24, "R"), ("", 80, "L"), ("Share", 22, "R")],
        [
            [
                t.name,
                f"{t.covered}/{t.total}",
                t.covered / t.total if t.total else 0,
                pct(t.covered / t.total if t.total else None),
            ]
            for t in cov.tactics
        ],
        bars={2: (2, DATA1)},
    )

    pdf.h2("Output metrics, last 12 months")
    tot = out.totals
    pdf.p(
        f"{out.rules_reporting} rules reported {tot.alerts} alerts, {tot.incidents} incidents and "
        f"{tot.false_positives} false positives (false positive rate {pct(tot.fp_rate)}).",
        size=8.5,
        color=MUTED,
    )
    pdf.ln(1)
    pdf.table(
        [
            ("Rule", 24, "L"),
            ("Noisiest rules", 82, "L"),
            ("Alerts", 18, "R"),
            ("Incidents", 18, "R"),
            ("FP", 16, "R"),
            ("FP rate", 20, "R"),
        ],
        [
            [r.code, r.name, r.alerts, r.incidents, r.false_positives, pct(r.fp_rate)]
            for r in out.rules[:8]
        ],
    )

    pdf.h2("Verification overdue")
    never = [d for d in due if d.due is None]
    late = sorted((d for d in due if d.overdue and d.due), key=lambda d: d.days_left or 0)
    pdf.p(
        f"{len(late)} operational rules are overdue and {len(never)} were never verified "
        f"(default interval {settings.default_verification_days} days). Most overdue first.",
        size=8.5,
        color=MUTED,
    )
    pdf.ln(1)
    pdf.table(
        [("Rule", 24, "L"), ("Name", 100, "L"), ("Last verified", 28, "R"), ("Overdue", 26, "R")],
        [
            [
                d.code,
                d.name,
                f"{d.last_verified_at:%d %b %Y}" if d.last_verified_at else "never",
                f"{-(d.days_left or 0)} days",
            ]
            for d in late[:12]
        ],
    )
    if never:
        pdf.ln(2)
        codes = ", ".join(d.code for d in never[:30]) + (" ..." if len(never) > 30 else "")
        pdf.p(f"Never verified: {codes}", size=8, color=MUTED)
    return bytes(pdf.output())
