"""PDF of a business owner interview (issue #17), in English, German or Dutch.

The business owner receives it and confirms it to the analyst; a draft carries a "Draft"
watermark on every page.
"""

from app.report import ACCENT, BORDER, INK, MUTED, Report, _t

TEXTS: dict[str, dict[str, str]] = {
    "title": {"en": "Threat interview", "de": "Bedrohungsinterview", "nl": "Dreigingsinterview"},
    "page": {"en": "page", "de": "Seite", "nl": "pagina"},
    "draft": {"en": "DRAFT", "de": "ENTWURF", "nl": "CONCEPT"},
    "status": {"en": "Status", "de": "Status", "nl": "Status"},
    "draft_s": {"en": "Draft", "de": "Entwurf", "nl": "Concept"},
    "completed": {"en": "Completed", "de": "Abgeschlossen", "nl": "Afgerond"},
    "confirmed": {"en": "Confirmed", "de": "Bestätigt", "nl": "Bevestigd"},
    "system": {"en": "System", "de": "System", "nl": "Systeem"},
    "owner": {"en": "Business owner", "de": "Business Owner", "nl": "Business owner"},
    "department": {"en": "Department", "de": "Abteilung", "nl": "Afdeling"},
    "email": {"en": "E-mail", "de": "E-Mail", "nl": "E-mail"},
    "criticality": {"en": "Criticality", "de": "Kritikalität", "nl": "Kritikaliteit"},
    "internet": {
        "en": "Internet-facing",
        "de": "Aus dem Internet erreichbar",
        "nl": "Bereikbaar vanaf internet",
    },
    "yes": {"en": "yes", "de": "ja", "nl": "ja"},
    "no": {"en": "no", "de": "nein", "nl": "nee"},
    "classification": {
        "en": "Data classification",
        "de": "Datenklassifizierung",
        "nl": "Dataclassificatie",
    },
    "date": {"en": "Interview date", "de": "Interviewdatum", "nl": "Interviewdatum"},
    "analyst": {"en": "Analyst", "de": "Analyst", "nl": "Analist"},
    "participants": {"en": "Participants", "de": "Teilnehmende", "nl": "Deelnemers"},
    "notes": {"en": "Notes", "de": "Notizen", "nl": "Notities"},
    "components": {
        "en": "Components and threats",
        "de": "Komponenten und Bedrohungen",
        "nl": "Componenten en dreigingen",
    },
    "log_sources": {"en": "Log sources", "de": "Logquellen", "nl": "Logbronnen"},
    "none": {"en": "none", "de": "keine", "nl": "geen"},
    "category": {"en": "STRIDE category", "de": "STRIDE-Kategorie", "nl": "STRIDE-categorie"},
    "likelihood": {"en": "Likelihood", "de": "Wahrscheinlichkeit", "nl": "Waarschijnlijkheid"},
    "impact": {"en": "Impact", "de": "Auswirkung", "nl": "Impact"},
    "score": {"en": "Risk score", "de": "Risk Score", "nl": "Risicoscore"},
    "not_apply": {"en": "Does not apply", "de": "Trifft nicht zu", "nl": "Niet van toepassing"},
    "not_discussed": {"en": "Not discussed", "de": "Nicht besprochen", "nl": "Niet besproken"},
    "no_threats": {
        "en": "No threat applies.",
        "de": "Keine Bedrohung trifft zu.",
        "nl": "Geen dreiging van toepassing.",
    },
    "accepted": {
        "en": "Accepted use cases",
        "de": "Angenommene Use Cases",
        "nl": "Geaccepteerde use cases",
    },
    "no_accepted": {
        "en": "No use cases accepted: the system has no linked use cases.",
        "de": "Keine Use Cases angenommen: das System hat keine verknüpften Use Cases.",
        "nl": "Geen use cases geaccepteerd: het systeem heeft geen gekoppelde use cases.",
    },
    "use_case": {"en": "Use case", "de": "Use Case", "nl": "Use case"},
    "from": {"en": "From threats", "de": "Aus Bedrohungen", "nl": "Uit dreigingen"},
    "deleted": {"en": "deleted", "de": "gelöscht", "nl": "verwijderd"},
    "gaps": {"en": "Log source gaps", "de": "Logquellen-Lücken", "nl": "Logbron-hiaten"},
    "no_gaps": {
        "en": "No log source gaps.",
        "de": "Keine Logquellen-Lücken.",
        "nl": "Geen logbron-hiaten.",
    },
    "rule": {"en": "Rule", "de": "Regel", "nl": "Regel"},
    "missing": {"en": "Log source missing", "de": "Logquelle fehlt", "nl": "Logbron ontbreekt"},
    "requests": {"en": "Detection requests", "de": "Detection Requests", "nl": "Detectieverzoeken"},
    "no_requests": {
        "en": "No detection requests.",
        "de": "Keine Detection Requests.",
        "nl": "Geen detectieverzoeken.",
    },
    "note": {"en": "Note", "de": "Notiz", "nl": "Notitie"},
    "implemented_by": {"en": "Implemented by", "de": "Umgesetzt mit", "nl": "Uitgevoerd met"},
    "open": {"en": "Open", "de": "Offen", "nl": "Open"},
    "in_progress": {"en": "In progress", "de": "In Bearbeitung", "nl": "In behandeling"},
    "implemented": {"en": "Implemented", "de": "Umgesetzt", "nl": "Uitgevoerd"},
    "rejected": {"en": "Rejected", "de": "Abgelehnt", "nl": "Afgewezen"},
    "not_feasible": {"en": "Not feasible", "de": "Nicht umsetzbar", "nl": "Niet haalbaar"},
    "evidence": {"en": "Evidence", "de": "Nachweise", "nl": "Bewijsstukken"},
    "file": {"en": "File", "de": "Datei", "nl": "Bestand"},
    "uploaded": {"en": "Added", "de": "Hinzugefügt", "nl": "Toegevoegd"},
    "threat": {"en": "Threat", "de": "Bedrohung", "nl": "Dreiging"},
    "signoff": {"en": "Confirmation", "de": "Bestätigung", "nl": "Bevestiging"},
    "signoff_text": {
        "en": "I confirm that this record reflects the interview.",
        "de": "Ich bestätige, dass dieses Protokoll das Interview wiedergibt.",
        "nl": "Ik bevestig dat dit verslag het interview weergeeft.",
    },
    "confirmed_by": {"en": "Confirmed by", "de": "Bestätigt von", "nl": "Bevestigd door"},
    "on": {"en": "Date", "de": "Datum", "nl": "Datum"},
    "signature": {"en": "Signature", "de": "Unterschrift", "nl": "Handtekening"},
    "spoofing": {"en": "Spoofing", "de": "Spoofing", "nl": "Spoofing"},
    "tampering": {
        "en": "Tampering",
        "de": "Manipulation (Tampering)",
        "nl": "Manipulatie (Tampering)",
    },
    "repudiation": {
        "en": "Repudiation",
        "de": "Abstreitbarkeit (Repudiation)",
        "nl": "Onweerlegbaarheid (Repudiation)",
    },
    "information_disclosure": {
        "en": "Information disclosure",
        "de": "Informationspreisgabe",
        "nl": "Openbaarmaking van informatie",
    },
    "denial_of_service": {
        "en": "Denial of service",
        "de": "Denial of Service",
        "nl": "Denial of service",
    },
    "elevation_of_privilege": {
        "en": "Elevation of privilege",
        "de": "Rechteausweitung",
        "nl": "Verhoging van rechten",
    },
    "public": {"en": "Public", "de": "Öffentlich", "nl": "Openbaar"},
    "internal": {"en": "Internal", "de": "Intern", "nl": "Intern"},
    "confidential": {"en": "Confidential", "de": "Vertraulich", "nl": "Vertrouwelijk"},
    "restricted": {"en": "Restricted", "de": "Streng vertraulich", "nl": "Strikt vertrouwelijk"},
}


class _Pdf(Report):
    def __init__(self, title: str, watermark: str | None, page_word: str):
        super().__init__(title)
        self.watermark = watermark
        self.page_word = page_word

    def header(self) -> None:
        if not self.watermark:
            return
        self.set_font("Helvetica", "B", 90)
        self.set_text_color(236, 238, 241)
        with self.rotation(45, self.w / 2, self.h / 2):
            w = self.get_string_width(self.watermark)
            self.text(self.w / 2 - w / 2, self.h / 2 + 12, self.watermark)
        self.set_text_color(*INK)

    def footer(self) -> None:
        self.set_y(-11)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(*MUTED)
        self.cell(0, 5, _t(f"{self.title_text} - {self.page_word} {self.page_no()}"), align="R")

    def kv(self, rows: list[tuple[str, str]]) -> None:
        for k, v in rows:
            self.set_font("Helvetica", "", 9)
            self.set_text_color(*MUTED)
            self.cell(48, 5.2, _t(k))
            self.set_text_color(*INK)
            self.multi_cell(0, 5.2, _t(v or "-"), new_x="LMARGIN", new_y="NEXT")

    def h3(self, text: str) -> None:
        if self.get_y() > self.h - 40:
            self.add_page()
        self.ln(2)
        self.set_font("Helvetica", "B", 10.5)
        self.set_text_color(*INK)
        self.cell(0, 6, _t(text), new_x="LMARGIN", new_y="NEXT")


def build(out, system, lang: str, app_name: str) -> bytes:
    """`out` is the InterviewOut of app/api/systems.py, `system` the System row."""

    view = out.view or {}
    # custom ATT&CK threats (#60) are labelled with their title and techniques
    custom = {
        t["category"]: f"{t.get('title') or t['category']} ({', '.join(t.get('techniques', []))})"
        for c in view.get("components", [])
        for t in c.get("threats", [])
        if t.get("custom")
    }

    def tr(key: str) -> str:
        if key in custom:
            return custom[key]
        entry = TEXTS.get(key)
        return entry.get(lang, entry["en"]) if entry else key

    status = str(out.status)
    title = f"{tr('title')} - {out.system_name}"
    pdf = _Pdf(f"{app_name} - {title}", tr("draft") if status == "draft" else None, tr("page"))
    pdf.add_page()
    pdf.set_fill_color(*ACCENT)
    pdf.rect(pdf.l_margin, 14, 14, 1.6, style="F")
    pdf.ln(2)
    pdf.h1(title)
    status_text = {"draft": tr("draft_s"), "completed": tr("completed")}.get(
        status, tr("confirmed")
    )
    pdf.p(f"{tr('date')}: {out.interview_date.isoformat()} - {tr('status')}: {status_text}")

    pdf.h2(tr("system"), need=30)
    pdf.kv(
        [
            (tr("system"), out.system_name),
            (tr("owner"), system.owner_name),
            (tr("department"), system.owner_department),
            (tr("email"), system.owner_email or ""),
            (tr("criticality"), f"{system.criticality}/5"),
            (tr("internet"), tr("yes") if system.internet_facing else tr("no")),
            (tr("classification"), tr(system.data_classification)),
            (tr("analyst"), out.analyst),
            (tr("participants"), out.participants),
        ]
    )
    if system.description:
        pdf.ln(1)
        pdf.md(system.description)
    if out.notes:
        pdf.h3(tr("notes"))
        pdf.md(out.notes)

    pdf.h2(tr("components"), need=30)
    for c in view.get("components", []):
        pdf.h3(c["name"])
        if c.get("description"):
            pdf.md(c["description"], color=MUTED)
        names = ", ".join(s["name"] for s in c.get("log_sources", [])) or tr("none")
        pdf.p(f"{tr('log_sources')}: {names}", size=9)
        applies = [t for t in c["threats"] if t["state"] == "applies"]
        if applies:
            pdf.ln(1)
            pdf.table(
                [
                    (tr("category"), 62, "L"),
                    (tr("likelihood"), 38, "R"),
                    (tr("impact"), 38, "R"),
                    (tr("score"), 40, "R"),
                ],
                [
                    [
                        tr(t["category"]),
                        t["likelihood"] or "-",
                        t["impact"] or "-",
                        t["score"] or "-",
                    ]
                    for t in applies
                ],
            )
            for t in applies:
                if t.get("description"):
                    pdf.set_font("Helvetica", "B", 8.5)
                    pdf.set_text_color(*INK)
                    pdf.cell(0, 5, _t(tr(t["category"])), new_x="LMARGIN", new_y="NEXT")
                    pdf.md(t["description"], size=8.5)
        else:
            pdf.p(tr("no_threats"), size=9, color=MUTED)
        rest = [
            (tr("not_apply"), [t for t in c["threats"] if t["state"] == "does_not_apply"]),
            (tr("not_discussed"), [t for t in c["threats"] if t["state"] == "not_discussed"]),
        ]
        for label, items in rest:
            if items:
                pdf.p(f"{label}: " + ", ".join(tr(t["category"]) for t in items), 8.5, MUTED)

    pdf.h2(tr("accepted"), need=30)
    proposals = view.get("proposals", [])
    gone = tr("deleted")
    if proposals:
        pdf.table(
            [(tr("use_case"), 70, "L"), (tr("from"), 88, "L"), (tr("score"), 20, "R")],
            [
                [
                    f"{p['code']} {p['name']}" + (f" ({gone})" if p.get("deleted") else ""),
                    "; ".join(f"{s['component_name']}: {tr(s['category'])}" for s in p["sources"]),
                    p["risk_score"] or "-",
                ]
                for p in proposals
            ],
        )
    else:
        pdf.p(tr("no_accepted"), color=MUTED)

    pdf.h2(tr("gaps"), need=25)
    gaps = view.get("log_source_gaps", [])
    if gaps:
        pdf.table(
            [(tr("rule"), 70, "L"), (tr("missing"), 108, "L")],
            [[f"{g['rule_code']} {g['rule_name']}", ", ".join(g["missing"])] for g in gaps],
        )
    else:
        pdf.p(tr("no_gaps"), color=MUTED)

    pdf.h2(tr("requests"), need=25)
    requests = view.get("requests", [])
    if requests:
        for r in requests:
            pdf.set_font("Helvetica", "B", 9.5)
            pdf.set_text_color(0, 0, 0)
            pdf.multi_cell(0, 5, _t(r["title"]), new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "B", 8.5)
            pdf.set_text_color(*MUTED)
            label = f"{tr('threat')}: {r['component_name']} - {tr(r['category'])}"
            pdf.cell(0, 5, _t(label), new_x="LMARGIN", new_y="NEXT")
            state = f"{tr('status')}: {tr(r.get('status', 'open'))}"
            if r.get("link"):
                state += f" - {tr('implemented_by')}: {r['link']['code']}"
            pdf.cell(0, 5, _t(state), new_x="LMARGIN", new_y="NEXT")
            if r.get("status_note"):
                pdf.p(f"{tr('note')}: {r['status_note']}", size=8.5, color=MUTED)
            if r.get("description"):
                pdf.md(r["description"], size=9)
    else:
        pdf.p(tr("no_requests"), color=MUTED)

    if out.attachments:  # evidence files (#34): listed, not embedded
        pdf.h2(tr("evidence"), need=25)
        pdf.table(
            [(tr("file"), 118, "L"), (tr("uploaded"), 60, "L")],
            [
                [
                    f"{a.filename} ({max(1, round(a.size / 1024))} KB)",
                    f"{a.uploaded_at.date().isoformat()} {a.uploaded_by}",
                ]
                for a in out.attachments
            ],
        )

    pdf.h2(tr("signoff"), need=45)
    pdf.p(tr("signoff_text"))
    pdf.ln(4)
    y = pdf.get_y()
    col = (pdf.w - pdf.l_margin - pdf.r_margin - 8) / 3
    values = [
        out.confirmed_by or "",
        out.confirmed_at.isoformat() if out.confirmed_at else "",
        "",
    ]
    for n, label in enumerate((tr("confirmed_by"), tr("on"), tr("signature"))):
        x = pdf.l_margin + n * (col + 4)
        pdf.set_xy(x, y + 4)
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(*INK)
        pdf.cell(col, 6, _t(values[n]))
        pdf.set_draw_color(*BORDER)
        pdf.line(x, y + 12, x + col, y + 12)
        pdf.set_xy(x, y + 13)
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(*MUTED)
        pdf.cell(col, 4, _t(label))
    return bytes(pdf.output())
