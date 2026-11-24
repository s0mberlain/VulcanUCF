"""Business owner interviews (issue #17): STRIDE threats per component -> proposed L2 use cases.

An analyst interviews the business owner of a system. Each component of the system gets the six
STRIDE categories; a category that applies is rated likelihood x impact (risk score 1..25).
The admin-maintained STRIDE -> L2 mapping turns threats at or above the proposal threshold into
proposed L2 use cases. With the log source filter on (issue #36, default), an L2 is held back for
a threat when its active L3 rules use log sources and the threatened component delivers log
sources, but none of them meet (issue #38: an L2 without rules or without recorded log sources,
and a component without log sources, are not filtered, because that is a gap to show). The
analyst can remove proposals, add L2 use cases or single L3 rules by hand and record detection
requests. Completing the interview freezes it and replaces the system's links.

Stored draft (`Interview.data`):
    components: [{key, name, description, log_source_ids, threats: [{category, state,
                  description, likelihood, impact}],
                  custom_threats: [{key, title, description, techniques, likelihood, impact}]}]

Custom threats (issue #60) refine STRIDE with MITRE ATT&CK: they always apply, are referred to as
category `custom:<key>` and propose the L2 use cases whose rules cover one of their techniques
(T1110 also matches its sub-techniques and the other way round). In the evaluated view they are
listed in a component's `threats` after the six STRIDE categories, with `custom`, `title` and
`techniques`.
    added:      [{l2_id | l3_id, threats: [{component: key, category}]}]  (one of the two ids)
    removed:    [{l2_id, reason, threats?: [{component: key, category}]}]  (without threats the
                whole L2 is removed; with threats it is only taken off those risks, issue #57)
    requests:   [{key, title, description, threat: {component: key, category}}]

A detection request (PROJ-1) is identified by its `key`, which a re-interview copies, so all
interviews of a system share one request. Title (up to 200 characters) and description are
frozen with the interview; the implementation status is not: it lives in
`DetectionRequestState` and is attached on read (`attach_status`). Requests written before
PROJ-1 hold a single `text` and often no key; `upgrade_requests` turns them into title,
description and a key that is the same in every interview.

`evaluate()` resolves ids to names and works out the proposals; for a draft this runs on every
read (so mapping, threshold, renamed or deleted use cases and log sources take effect), for a
completed interview its output is frozen in `Interview.result`. `risk_overview()` turns the
evaluated threats and accepted use cases into one row per risk with its coverage.
"""

import hashlib
from datetime import date
from typing import Any

from sqlalchemy import and_, delete, or_, select
from sqlalchemy.orm import Session, defer, selectinload, undefer

from app import attack
from app.models import (
    AppSetting,
    DetectionRequestState,
    Interview,
    InterviewStatus,
    L2UseCase,
    L3UseCase,
    ReferenceItem,
    RefKind,
    RequestStatus,
    StrideMapping,
    System,
    SystemLink,
)
from app.scoring import ACTIVE_STATES

STRIDE = (
    "spoofing",
    "tampering",
    "repudiation",
    "information_disclosure",
    "denial_of_service",
    "elevation_of_privilege",
)
STATES = ("applies", "does_not_apply", "not_discussed")
CUSTOM = "custom:"  # category prefix of a custom ATT&CK threat (#60)


def is_custom(category: str) -> bool:
    return category.startswith(CUSTOM)


def category_order(category: str) -> int:
    """Sort key: the STRIDE categories in their order, custom threats after them."""
    return STRIDE.index(category) if category in STRIDE else len(STRIDE)


def techniques_match(threat: str, rule: str) -> bool:
    """T1110 matches T1110.001 and the other way round; T1110.001 does not match T1110.002."""
    return threat == rule or rule.startswith(threat + ".") or threat.startswith(rule + ".")


# ---------------------------------------------------------------- detection requests

TITLE_MAX = 200
NOTE_MAX = 2000
# the statuses that need a reason
NOTE_REQUIRED = (RequestStatus.rejected, RequestStatus.not_feasible)
# the statuses of requests that are still to do (they count as gaps)
UNRESOLVED = (RequestStatus.open, RequestStatus.in_progress)


def split_text(text: str) -> tuple[str, str]:
    """A request written before PROJ-1: a one-line text up to the title length is the title;
    otherwise the first line (cut) is the title and the whole text the description."""
    text = (text or "").strip()
    first = text.splitlines()[0].strip() if text else ""
    if "\n" not in text and len(text) <= TITLE_MAX:
        return text, ""
    return first[:TITLE_MAX], text


def request_key(ref: tuple[str, str], text: str, taken: set[str]) -> str:
    """A key for a request that has none (written before PROJ-1): the same text on the same
    threat gets the same key in every interview, equal ones are told apart by a counter."""
    base = "r" + hashlib.sha1(f"{ref[0]}|{ref[1]}|{text}".encode()).hexdigest()[:12]  # noqa: S324
    key, n = base, 1
    while key in taken:
        n += 1
        key = f"{base}-{n}"
    return key


def upgrade_requests(raw: list[dict]) -> list[dict]:
    """Requests of a draft (`threat: {...}`) or of a frozen result (`component`, `category`) with
    title, description and a key, also when they were written before PROJ-1."""
    out: list[dict] = []
    taken = {r["key"] for r in raw if r.get("key")}
    for r in raw:
        r = dict(r)
        text = r.pop("text", None)
        if "title" not in r:
            r["title"], r["description"] = split_text(text or "")
        r.setdefault("description", "")
        if not r.get("key"):
            ref = (
                (r["threat"]["component"], r["threat"]["category"])
                if "threat" in r
                else (r.get("component", ""), r.get("category", ""))
            )
            r["key"] = request_key(ref, text or r["title"], taken)
            taken.add(r["key"])
        out.append(r)
    return out


def states_of(db: Session, system_id: int) -> dict[str, DetectionRequestState]:
    return {
        x.key: x
        for x in db.scalars(
            select(DetectionRequestState).where(DetectionRequestState.system_id == system_id)
        )
    }


def existing_links(db: Session, states) -> tuple[set[int], set[int]]:
    """(L2 ids, L3 ids) that still exist among the links of these request states, in two
    queries; pass to state_view so a list of requests does not look each one up."""
    l2 = {x.link_l2_id for x in states if x.link_l2_id is not None and x.link_l3_id is None}
    l3 = {x.link_l3_id for x in states if x.link_l3_id is not None}
    return (
        set(db.scalars(select(L2UseCase.id).where(L2UseCase.id.in_(l2)))) if l2 else set(),
        set(db.scalars(select(L3UseCase.id).where(L3UseCase.id.in_(l3)))) if l3 else set(),
    )


def state_view(
    db: Session,
    state: DetectionRequestState | None,
    known: tuple[set[int], set[int]] | None = None,
) -> dict:
    """Status, reason, what implemented it and who changed it last, as the API shows it.
    `known` = existing_links(...) for many states at once."""
    if state is None:
        return {
            "status": RequestStatus.open.value,
            "status_note": "",
            "link": None,
            "status_by": None,
            "status_at": None,
        }
    link = None
    if state.link_l2_id is not None or state.link_l3_id is not None:
        if known is not None:
            exists = (
                state.link_l3_id in known[1]
                if state.link_l3_id is not None
                else state.link_l2_id in known[0]
            )
        elif state.link_l3_id is not None:
            exists = db.get(L3UseCase, state.link_l3_id) is not None
        else:
            exists = db.get(L2UseCase, state.link_l2_id) is not None
        link = {
            "l2_id": state.link_l2_id,
            "l3_id": state.link_l3_id,
            "code": state.link_code or "",
            "deleted": not exists,
        }
    return {
        "status": state.status.value,
        "status_note": state.note,
        "link": link,
        "status_by": state.updated_by,
        "status_at": state.updated_at,
    }


def attach_status(db: Session, system_id: int, view: dict) -> dict:
    """Adds the current implementation status to the requests of an evaluated interview and
    to the requests of its risk rows. The status is read now, also for a completed interview."""
    states = states_of(db, system_id)
    known = existing_links(db, states.values())
    now = {k: state_view(db, x, known) for k, x in states.items()}
    open_view = state_view(db, None)
    view["requests"] = [r | now.get(r["key"], open_view) for r in view.get("requests", [])]
    for row in view.get("risks", []):
        row["requests"] = [
            r | {"status": now.get(r["key"], open_view)["status"]} for r in row["requests"]
        ]
    return view


CLASSIFICATIONS = ("public", "internal", "confidential", "restricted")
COMPLETED = (InterviewStatus.completed, InterviewStatus.confirmed)

DEFAULT_MAPPING: dict[str, list[str]] = {
    "spoofing": ["RE-BRU", "EX-BRU", "AO-BRU", "AO-CRE", "AO-ACC", "AO-CSC", "PH-AAT", "FE-CEO"],
    "tampering": ["AO-FIL", "AO-DBC", "IN-MAL", "SD-WEB", "SD-CYS", "PV-POL"],
    "repudiation": ["AO-EVA", "PV-ACC"],
    "information_disclosure": ["AO-COL", "AO-EXF", "AO-DBC", "CC-SNC", "CC-CCH", "PV-COM"],
    "denial_of_service": ["DD-VOL", "DD-PRO", "DD-APP", "AO-FIL", "SD-CYS"],
    "elevation_of_privilege": ["AO-PRI", "PV-ACC", "EX-APP", "IN-RAT", "AO-PER"],
}

SETTINGS_KEY = "interviews"
DEFAULT_THRESHOLD = 8


# ---------------------------------------------------------------- settings and mapping


def load_settings(db: Session) -> dict[str, Any]:
    row = db.get(AppSetting, SETTINGS_KEY)
    value = dict(row.value) if row else {}
    value.setdefault("proposal_threshold", DEFAULT_THRESHOLD)
    value.setdefault("mapping_seeded", False)
    value.setdefault("log_source_filter", True)
    return value


def save_settings(db: Session, value: dict[str, Any], username: str) -> None:
    row = db.get(AppSetting, SETTINGS_KEY)
    if row is None:
        db.add(AppSetting(key=SETTINGS_KEY, value=value, updated_by=username))
    else:
        row.value, row.updated_by = dict(value), username


def threshold(db: Session) -> int:
    return int(load_settings(db)["proposal_threshold"])


def log_source_filter(db: Session) -> bool:
    return bool(load_settings(db)["log_source_filter"])


def apply_default_mapping(db: Session) -> int:
    """Replace the mapping with the shipped default (codes that do not exist are skipped)."""
    db.execute(delete(StrideMapping))
    by_code = dict(db.execute(select(L2UseCase.code, L2UseCase.id)).all())
    n = 0
    for cat, codes in DEFAULT_MAPPING.items():
        for code in codes:
            if code in by_code:
                db.add(StrideMapping(category=cat, l2_id=by_code[code]))
                n += 1
    return n


def ensure_default_mapping(db: Session) -> None:
    """Once per installation: fill an empty mapping with the default. An admin who later removes
    every entry keeps an empty mapping (it is not filled again)."""
    s = load_settings(db)
    if s["mapping_seeded"]:
        return
    if db.scalar(select(StrideMapping.l2_id).limit(1)) is None:
        if db.scalar(select(L2UseCase.id).limit(1)) is None:
            return  # no catalogue yet; try again on the next start
        apply_default_mapping(db)
    s["mapping_seeded"] = True
    save_settings(db, s, "system")
    db.commit()


def mapping(db: Session) -> dict[str, list[int]]:
    out: dict[str, list[int]] = {c: [] for c in STRIDE}
    for cat, l2_id in db.execute(select(StrideMapping.category, StrideMapping.l2_id)):
        if cat in out:
            out[cat].append(l2_id)
    return out


# ---------------------------------------------------------------- small rules


def risk_level(score: int | None) -> int | None:
    """Risk score 1..25 -> risk level 1..5 (1-5 -> 1, 6-10 -> 2, ... 21-25 -> 5)."""
    if not score or score < 1:
        return None
    return min(5, (score - 1) // 5 + 1)


def add_months(d: date, months: int) -> date:
    y, m = divmod(d.month - 1 + months, 12)
    year, month = d.year + y, m + 1
    for day in (d.day, 30, 29, 28):
        try:
            return date(year, month, day)
        except ValueError:
            continue
    raise ValueError("invalid date")  # pragma: no cover


def interview_state(system: System, last: date | None, today: date | None = None) -> str:
    """none (never interviewed) | due (review interval passed) | ok."""
    if last is None:
        return "none"
    if add_months(last, system.review_interval_months) < (today or date.today()):
        return "due"
    return "ok"


def threat_score(t: dict) -> int | None:
    if t.get("state") != "applies":
        return None
    lk, im = t.get("likelihood"), t.get("impact")
    return lk * im if lk and im else None


def threat_complete(t: dict) -> bool:
    if t.get("state") != "applies":
        return True
    return bool((t.get("description") or "").strip()) and threat_score(t) is not None


# ---------------------------------------------------------------- evaluation


def attack_targets(l2s: dict[int, L2UseCase], techniques: list[str]) -> list[int]:
    """L2 use cases with a rule that covers one of the techniques (#60). Retired or offloading
    rules count too, so that a use case without active rule shows up as a gap."""
    wanted = [attack.resolve(x) or x for x in techniques]
    out = []
    for l2_id, l2 in sorted(l2s.items(), key=lambda x: x[1].code):
        rule_ids = {x for r in l2.children for x in attack.remap(r.attack_techniques or [])}
        if any(techniques_match(w, r) for w in wanted for r in rule_ids):
            out.append(l2_id)
    return out


def _l2_index(db: Session) -> dict[int, L2UseCase]:
    q = select(L2UseCase).options(
        selectinload(L2UseCase.parent),
        selectinload(L2UseCase.children).selectinload(L3UseCase.references),
    )
    return {x.id: x for x in db.scalars(q)}


def _rule_ls(rule: L3UseCase) -> dict[int, str]:
    """Log sources a rule needs: id -> name."""
    return {x.id: x.name for x in rule.references if x.kind == RefKind.log_source}


def is_active(rule: L3UseCase) -> bool:
    """Only rules that are onboarded or running count as detection (issue #40); offloading and
    retired rules are shown, but neither filter nor gaps use them."""
    return rule.lifecycle_status in ACTIVE_STATES


def rule_coverage(needed: set[int], delivered: set[int]) -> str:
    """unknown (no log source recorded) | blind (none delivered) | partial | ok (issue #41)."""
    if not needed:
        return "unknown"
    have = needed & delivered
    if not have:
        return "blind"
    return "ok" if have == needed else "partial"


def detection_state(l2: L2UseCase, delivered: set[int]) -> str:
    """How well the active rules of an L2 see a component that delivers the given log sources:
    no_rules | unknown (no rule records a log source) | blind (no rule gets any of its log
    sources) | partial | ok (at least one rule gets everything it needs)."""
    active = [r for r in l2.children if is_active(r)]
    if not active:
        return "no_rules"
    states = {rule_coverage(set(_rule_ls(r)), delivered) for r in active}
    if "ok" in states:
        return "ok"
    if "partial" in states:
        return "partial"
    if "blind" in states:
        return "blind"
    return "unknown"


def rule_detection(rule: L3UseCase, delivered: set[int]) -> str:
    """detection_state() for a single selected L3 rule (no_rules = the rule is not active)."""
    if not is_active(rule):
        return "no_rules"
    return rule_coverage(set(_rule_ls(rule)), delivered)


def _rule_views(l2: L2UseCase, delivered: set[int], only: L3UseCase | None = None) -> list[dict]:
    rules = []
    for r in [only] if only is not None else l2.children:
        ls = _rule_ls(r)
        active = is_active(r)
        cov = rule_coverage(set(ls), delivered) if active else "inactive"
        rules.append(
            {
                "code": r.code,
                "name": r.name,
                "lifecycle_status": str(r.lifecycle_status),
                "active": active,
                "log_sources": sorted(ls.values()),
                "missing": sorted(n for i, n in ls.items() if i not in delivered) if active else [],
                "unknown": not ls,
                "coverage": cov,
            }
        )
    return rules


def _l2_log_sources(l2: L2UseCase) -> dict[int, str]:
    """Log sources (id -> name) any active L3 rule of the L2 uses."""
    out: dict[int, str] = {}
    for r in l2.children:
        if is_active(r):
            out |= _rule_ls(r)
    return out


def evaluate(
    db: Session, data: dict, threshold_value: int, filter_log_sources: bool | None = None
) -> dict:
    """Resolve a stored draft and work out proposals, removals, gaps (see module docstring)."""
    if filter_log_sources is None:
        filter_log_sources = log_source_filter(db)
    ls_names = dict(
        db.execute(
            select(ReferenceItem.id, ReferenceItem.name).where(
                ReferenceItem.kind == RefKind.log_source
            )
        ).all()
    )
    l2s = _l2_index(db)
    mapped = mapping(db)

    components: list[dict] = []
    threats: dict[tuple[str, str], dict] = {}
    comp_ls: dict[str, set[int]] = {}  # component key -> log source ids
    incomplete: list[dict] = []
    for c in data.get("components", []):
        sources = [
            {"id": i, "name": ls_names[i]} for i in c.get("log_source_ids", []) if i in ls_names
        ]
        comp_ls[c["key"]] = {s["id"] for s in sources}
        tviews = []
        by_cat = {t["category"]: t for t in c.get("threats", [])}
        for cat in STRIDE:
            t = by_cat.get(cat, {"category": cat, "state": "not_discussed"})
            view = {
                "category": cat,
                "state": t.get("state", "not_discussed"),
                "description": t.get("description", "") or "",
                "likelihood": t.get("likelihood"),
                "impact": t.get("impact"),
                "score": threat_score(t),
                "complete": threat_complete(t),
            }
            tviews.append(view)
            threats[(c["key"], cat)] = view | {"component_name": c["name"]}
            if not view["complete"]:
                incomplete.append({"component": c["name"], "category": cat})
        for ct in c.get("custom_threats", []):
            cat = CUSTOM + ct["key"]
            t = {"state": "applies"} | ct
            view = {
                "category": cat,
                "custom": True,
                "title": ct.get("title") or "",
                "techniques": list(ct.get("techniques", [])),
                "state": "applies",
                "description": ct.get("description", "") or "",
                "likelihood": ct.get("likelihood"),
                "impact": ct.get("impact"),
                "score": threat_score(t),
                "complete": threat_score(t) is not None
                and bool((ct.get("title") or "").strip())
                and bool(ct.get("techniques")),
            }
            tviews.append(view)
            threats[(c["key"], cat)] = view | {"component_name": c["name"]}
            if not view["complete"]:
                incomplete.append(
                    {"component": c["name"], "category": cat, "title": ct.get("title") or ""}
                )
        components.append(
            {
                "key": c["key"],
                "name": c["name"],
                "description": c.get("description", "") or "",
                "log_sources": sources,
                "threats": tviews,
            }
        )

    proposals: dict[int, dict] = {}

    def source_views(pairs) -> tuple[list[dict], set[int]]:
        delivered: set[int] = set()
        srcs = []
        for key, cat in pairs:
            delivered |= comp_ls.get(key, set())
            srcs.append(
                {
                    "component": key,
                    "component_name": threats[(key, cat)]["component_name"],
                    "category": cat,
                    "score": threats[(key, cat)]["score"],
                }
            )
        srcs.sort(
            key=lambda s: (-(s["score"] or 0), s["component_name"], category_order(s["category"]))
        )
        return srcs, delivered

    def propose(l2_id: int, key: str, cat: str, auto: bool) -> None:
        p = proposals.setdefault(
            l2_id, {"sources": {}, "auto": False, "manual": False, "auto_refs": set()}
        )
        p["sources"][(key, cat)] = threats[(key, cat)]["score"]
        p["auto" if auto else "manual"] = True
        if auto:
            p["auto_refs"].add((key, cat))

    # issue #57: a removal either drops a whole L2 (no threats) or only takes it off some risks
    removed_reason: dict[int, str] = {}
    excluded: dict[int, dict] = {}  # l2 id -> {"reason", "pairs": {(component key, category)}}
    for r in data.get("removed", []):
        pairs = {(x["component"], x["category"]) for x in r.get("threats") or []}
        if pairs:
            excluded[r["l2_id"]] = {"reason": r.get("reason", "") or "", "pairs": pairs}
        else:
            removed_reason[r["l2_id"]] = r.get("reason", "") or ""

    below: list[dict] = []
    # L2s held back by the log source filter (#36): l2 id -> {(component key, category): score}
    filtered: dict[int, dict[tuple[str, str], int | None]] = {}
    l2_ls: dict[int, dict[int, str]] = {}
    for (key, cat), t in threats.items():
        if t["score"] is None:
            continue
        if is_custom(cat):
            targets = attack_targets(l2s, t["techniques"])
        else:
            targets = [i for i in mapped.get(cat, []) if i in l2s]
        if t["score"] >= threshold_value:
            for i in targets:
                if not l2s[i].parent.applicable:
                    continue
                if filter_log_sources:
                    if i not in l2_ls:
                        l2_ls[i] = _l2_log_sources(l2s[i])
                    # issue #38: only hold back when both sides are known and do not meet;
                    # an L2 without (logged) rules or a component without log sources is
                    # proposed, because that is a gap the interview has to show
                    needed, have = set(l2_ls[i]), comp_ls.get(key, set())
                    if needed and have and not (needed & have):
                        filtered.setdefault(i, {})[(key, cat)] = t["score"]
                        continue
                if (key, cat) in excluded.get(i, {}).get("pairs", ()):
                    continue  # taken off this risk by hand (#57)
                propose(i, key, cat, auto=True)
        else:
            below.append(
                {
                    "component": key,
                    "component_name": t["component_name"],
                    "category": cat,
                    "score": t["score"],
                    "l2s": [_l2_brief(l2s[i]) for i in targets],
                }
            )

    added_l3 = [a for a in data.get("added", []) if a.get("l3_id")]
    l3s = _l3_index(db, [a["l3_id"] for a in added_l3])
    for a in data.get("added", []):
        if a.get("l3_id") or a.get("l2_id") not in l2s:
            continue  # L3 picks below; deleted since (EC-1)
        refs = [(r["component"], r["category"]) for r in a.get("threats", [])]
        for key, cat in refs:
            if (key, cat) in threats:
                propose(a["l2_id"], key, cat, auto=False)

    accepted, removed = [], []
    for l2_id, p in proposals.items():
        l2 = l2s[l2_id]
        srcs, delivered = source_views(p["sources"])
        for s in srcs:
            s["auto"] = (s["component"], s["category"]) in p["auto_refs"]
        scores = [s["score"] for s in srcs if s["score"] is not None]
        view = _l2_brief(l2) | {
            "risk_score": max(scores) if scores else None,
            "sources": srcs,
            "auto": p["auto"],
            "manual": p["manual"],
            "rules": _rule_views(l2, delivered),
            "detection": detection_state(l2, delivered),
        }
        if l2_id in removed_reason:
            removed.append(view | {"reason": removed_reason[l2_id]})
        else:
            accepted.append(view)
    # single L3 rules chosen by hand: always accepted (removing one deletes the choice)
    for a in added_l3:
        rule = l3s.get(a["l3_id"])
        if rule is None:
            continue  # deleted since (EC-1)
        pairs = [
            (r["component"], r["category"])
            for r in a.get("threats", [])
            if (r["component"], r["category"]) in threats
        ]
        if not pairs:
            continue
        srcs, delivered = source_views(pairs)
        for s in srcs:
            s["auto"] = False
        scores = [s["score"] for s in srcs if s["score"] is not None]
        accepted.append(
            _l3_brief(rule)
            | {
                "risk_score": max(scores) if scores else None,
                "sources": srcs,
                "auto": False,
                "manual": True,
                "rules": _rule_views(rule.parent, delivered, only=rule),
                "detection": rule_detection(rule, delivered),
            }
        )
    # a removal of something that is no longer proposed is still listed (with its reason)
    for l2_id, reason in removed_reason.items():
        if l2_id not in proposals and l2_id in l2s:
            removed.append(
                _l2_brief(l2s[l2_id])
                | {"risk_score": None, "sources": [], "auto": False, "manual": False}
                | {"rules": [], "reason": reason}
            )

    # an L2 taken off single risks (#57): listed with the risks it no longer covers
    for l2_id, ex in excluded.items():
        if l2_id not in l2s:
            continue
        pairs = sorted(
            (p for p in ex["pairs"] if p in threats),
            key=lambda p: (threats[p]["component_name"], category_order(p[1])),
        )
        if not pairs:
            continue
        removed.append(
            _l2_brief(l2s[l2_id])
            | {"risk_score": None, "sources": [], "auto": False, "manual": False}
            | {"rules": [], "reason": ex["reason"]}
            | {
                "threats": [
                    {"component": k, "component_name": threats[(k, c)]["component_name"]}
                    | {"category": c}
                    for k, c in pairs
                ]
            }
        )

    not_matching = []
    for l2_id, srcs_by in filtered.items():
        if l2_id in proposals or l2_id in removed_reason:
            continue  # proposed through another component, or already handled by hand
        srcs = sorted(
            (
                {
                    "component": key,
                    "component_name": threats[(key, cat)]["component_name"],
                    "category": cat,
                    "score": score,
                    "component_log_sources": sorted(
                        ls_names[i] for i in comp_ls.get(key, set()) if i in ls_names
                    ),
                }
                for (key, cat), score in srcs_by.items()
            ),
            key=lambda s: (-(s["score"] or 0), s["component_name"], category_order(s["category"])),
        )
        not_matching.append(
            _l2_brief(l2s[l2_id])
            | {
                "risk_score": max((s["score"] or 0) for s in srcs) or None,
                "sources": srcs,
                "log_sources": sorted(l2_ls.get(l2_id, {}).values()),
            }
        )

    order = lambda v: (-(v["risk_score"] or 0), v["code"])  # noqa: E731
    accepted.sort(key=order)
    removed.sort(key=order)
    not_matching.sort(key=order)
    below.sort(key=lambda b: (-b["score"], b["component_name"], category_order(b["category"])))

    requests = []
    for r in upgrade_requests(data.get("requests", [])):
        ref = (r["threat"]["component"], r["threat"]["category"])
        t = threats.get(ref)
        requests.append(
            {
                "key": r["key"],
                "title": r["title"],
                "description": r["description"],
                "component": ref[0],
                "component_name": t["component_name"] if t else "",
                "category": ref[1],
            }
        )

    added = [
        {"l3_id": a["l3_id"], "threats": a.get("threats", [])}
        if a.get("l3_id")
        else {"l2_id": a["l2_id"], "threats": a.get("threats", [])}
        for a in data.get("added", [])
        if (a["l3_id"] in l3s if a.get("l3_id") else a.get("l2_id") in l2s)
    ]
    out = {
        "threshold": threshold_value,
        "mapping_empty": not any(mapped.values()),
        "log_source_filter": filter_log_sources,
        "log_source_mismatch": not_matching,
        "components": components,
        "incomplete": incomplete,
        "proposals": accepted,
        "removed": removed,
        "below_threshold": below,
        "added": added,
        "removed_ids": [l2_id for l2_id in removed_reason if l2_id in l2s],
        "requests": requests,
        # issue #41: a rule is a gap when it gets none (blind) or only some (partial) of its
        # log sources; inactive rules and rules without recorded log sources are not
        "log_source_gaps": [
            {"l2_code": p["code"], "rule_code": r["code"], "rule_name": r["name"]}
            | {"missing": r["missing"], "partial": r["coverage"] == "partial"}
            for p in accepted
            for r in p["rules"]
            if r["coverage"] in ("blind", "partial")
        ],
        # issue #38: accepted use cases without any active rule (nothing detects the threat)
        "no_detection": [p["code"] for p in accepted if p["detection"] == "no_rules"],
        # issue #38: components whose threats apply but that deliver no log source yet
        "components_without_log_sources": [
            c["name"]
            for c in components
            if not c["log_sources"] and any(t["state"] == "applies" for t in c["threats"])
        ],
    }
    out["risks"] = risk_overview(out)
    return out


def _l3_index(db: Session, ids: list[int]) -> dict[int, L3UseCase]:
    if not ids:
        return {}
    q = (
        select(L3UseCase)
        .where(L3UseCase.id.in_(ids))
        .options(
            selectinload(L3UseCase.references),
            selectinload(L3UseCase.parent).selectinload(L2UseCase.parent),
        )
    )
    return {x.id: x for x in db.scalars(q)}


def _l3_brief(rule: L3UseCase) -> dict:
    l2 = rule.parent
    return {
        "level": "L3",
        "l2_id": l2.id,
        "l3_id": rule.id,
        "code": rule.code,
        "name": rule.name,
        "l2_code": l2.code,
        "l2_name": l2.name,
        "l1_code": l2.parent.code,
        "l1_applicable": l2.parent.applicable,
    }


def _l2_brief(l2: L2UseCase) -> dict:
    return {
        "level": "L2",
        "l3_id": None,
        "l2_id": l2.id,
        "code": l2.code,
        "name": l2.name,
        "l1_code": l2.parent.code,
        "l1_applicable": l2.parent.applicable,
    }


def mark_deleted(db: Session, result: dict) -> dict:
    """A completed interview keeps code and name as recorded; flag use cases deleted since
    (EC-1/2). Results completed before the risk overview existed get it here."""
    items = result.get("proposals", []) + result.get("removed", [])
    ids = {p["l2_id"] for p in items}
    rule_ids = {p["l3_id"] for p in items if p.get("l3_id")}
    existing = set(db.scalars(select(L2UseCase.id).where(L2UseCase.id.in_(ids)))) if ids else set()
    rules = (
        set(db.scalars(select(L3UseCase.id).where(L3UseCase.id.in_(rule_ids))))
        if rule_ids
        else set()
    )
    for p in items:
        p["deleted"] = p["l3_id"] not in rules if p.get("l3_id") else p["l2_id"] not in existing
    result["requests"] = upgrade_requests(result.get("requests", []))
    result["risks"] = risk_overview(result)
    return result


# ---------------------------------------------------------------- risk overview

# how far an accepted use case covers a threat, from its detection state
UC_STATE = {
    "ok": "ok",
    "partial": "partial",
    "unknown": "partial",
    "blind": "gap",
    "no_rules": "gap",
}


def risk_coverage(score: int | None, threshold_value: int, states: list[str]) -> str:
    """Coverage of one threat: unrated (no score yet) | covered (a use case sees it) | partial |
    gap (nothing that works addresses it) | below (under the threshold, no use case: accepted)."""
    if score is None:
        return "unrated"
    if "ok" in states:
        return "covered"
    if "partial" in states:
        return "partial"
    if not states and score < threshold_value:
        return "below"
    return "gap"


def risk_overview(view: dict) -> list[dict]:
    """One row per applying threat with the accepted L2/L3 use cases that address it, highest
    risk first. `view` is an evaluated interview (or the same shape built from system links);
    proposals refer to threats by component key."""
    thr = int(view.get("threshold") or DEFAULT_THRESHOLD)
    by_threat: dict[tuple[str, str], list[dict]] = {}
    for p in view.get("proposals", []):
        for s in p.get("sources", []):
            by_threat.setdefault((s["component"], s["category"]), []).append(p)
    reqs: dict[tuple[str, str], list[dict]] = {}
    for r in upgrade_requests(view.get("requests", [])):
        reqs.setdefault((r["component"], r["category"]), []).append(
            {"key": r["key"], "title": r["title"]}
        )
    rows = []
    for c in view.get("components", []):
        for t in c.get("threats", []):
            if t.get("state") != "applies":
                continue
            ref = (c["key"], t["category"])
            ucs = []
            for p in by_threat.get(ref, []):
                det = p.get("detection")
                src = next(
                    (s for s in p.get("sources", []) if (s["component"], s["category"]) == ref),
                    {},
                )
                ucs.append(
                    {
                        "level": p.get("level", "L2"),
                        "l2_id": p["l2_id"],
                        "l3_id": p.get("l3_id"),
                        "code": p["code"],
                        "name": p["name"],
                        "l2_code": p.get("l2_code"),
                        "detection": det,
                        "state": "gap" if p.get("deleted") else UC_STATE.get(det or "", "partial"),
                        "weight": p.get("weight"),
                        "manual": p.get("manual", False),
                        # #57: proposed for this risk by the mapping (not only added by hand)
                        "auto": bool(src.get("auto", p.get("auto", False))),
                        "deleted": p.get("deleted", False),
                    }
                )
            order = {"ok": 0, "partial": 1, "gap": 2}
            ucs.sort(key=lambda u: (order[u["state"]], u["level"], u["code"]))
            score = t.get("score")
            rows.append(
                {
                    "component": c["key"],
                    "component_name": c["name"],
                    "category": t["category"],
                    # custom ATT&CK threat (#60)
                    "custom": bool(t.get("custom")),
                    "title": t.get("title"),
                    "techniques": t.get("techniques", []),
                    "description": t.get("description", ""),
                    "likelihood": t.get("likelihood"),
                    "impact": t.get("impact"),
                    "score": score,
                    "level": risk_level(score),
                    "above_threshold": score is not None and score >= thr,
                    "coverage": risk_coverage(score, thr, [u["state"] for u in ucs]),
                    "use_cases": ucs,
                    "requests": reqs.get(ref, []),
                }
            )
    rows.sort(
        key=lambda r: (-(r["score"] or 0), r["component_name"], category_order(r["category"]))
    )
    return rows


# ---------------------------------------------------------------- interviews of a system


def completed(system: System) -> list[Interview]:
    """Completed (or confirmed) interviews, oldest first."""
    done = [i for i in system.interviews if i.status in COMPLETED]
    # a re-interview is always created after the interview it starts from
    return sorted(done, key=lambda i: (i.interview_date, i.id))


def light_interviews():
    """Loader option: a system's interviews without their notes and JSON (load_full adds them)."""
    return selectinload(System.interviews).options(
        defer(Interview.data), defer(Interview.result), defer(Interview.notes)
    )


def load_full(db: Session, interviews: list[Interview]) -> None:
    """Load the deferred columns of these interviews with one query."""
    ids = [i.id for i in interviews]
    if ids:
        db.scalars(
            select(Interview)
            .where(Interview.id.in_(ids))
            .options(undefer(Interview.data), undefer(Interview.result), undefer(Interview.notes))
        ).all()


def latest_completed(system: System) -> Interview | None:
    done = completed(system)
    return done[-1] if done else None


def draft_of(system: System) -> Interview | None:
    return next((i for i in system.interviews if i.status == InterviewStatus.draft), None)


def copy_for_reinterview(previous: Interview, existing_ls: set[int]) -> dict:
    """The data of a completed interview as the start of the next one (notes stay empty)."""
    data = previous.data or {}
    comps = []
    for c in data.get("components", []):
        comps.append(
            c | {"log_source_ids": [i for i in c.get("log_source_ids", []) if i in existing_ls]}
        )
    return {
        "components": comps,
        "added": list(data.get("added", [])),
        "removed": list(data.get("removed", [])),
        "requests": upgrade_requests(data.get("requests", [])),
    }


def replace_links(db: Session, system: System, interview: Interview, result: dict) -> None:
    db.execute(delete(SystemLink).where(SystemLink.system_id == system.id))
    db.flush()
    for p in result["proposals"]:
        db.add(
            SystemLink(
                system_id=system.id,
                l2_id=p["l2_id"],
                l3_id=p.get("l3_id"),
                interview_id=interview.id,
                risk_score=p["risk_score"] or 0,
                sources=[
                    {"component": s["component_name"], "category": s["category"]}
                    | {"score": s["score"]}
                    for s in p["sources"]
                ],
            )
        )


def compare(old: dict, new: dict) -> dict:
    """What changed between two evaluated interviews (by component name and STRIDE category)."""
    oc = {c["name"]: c for c in old.get("components", [])}
    nc = {c["name"]: c for c in new.get("components", [])}

    def applying(comps: dict) -> dict[tuple[str, str], dict]:
        return {
            (name, t["category"]): t
            for name, c in comps.items()
            for t in c["threats"]
            if t["state"] == "applies"
        }

    ot, nt = applying(oc), applying(nc)
    rerated = []
    for k in sorted(set(ot) & set(nt)):
        a, b = ot[k], nt[k]
        if (a["likelihood"], a["impact"]) != (b["likelihood"], b["impact"]):
            rerated.append(
                {"component": k[0], "category": k[1], "old_score": a["score"]}
                | {"new_score": b["score"]}
            )
    ol = {p["code"]: p["name"] for p in old.get("proposals", [])}
    nl = {p["code"]: p["name"] for p in new.get("proposals", [])}
    return {
        "components_added": sorted(set(nc) - set(oc)),
        "components_removed": sorted(set(oc) - set(nc)),
        "threats_added": [{"component": k[0], "category": k[1]} for k in sorted(set(nt) - set(ot))],
        "threats_removed": [
            {"component": k[0], "category": k[1]} for k in sorted(set(ot) - set(nt))
        ],
        "threats_rerated": rerated,
        "use_cases_added": [{"code": c, "name": nl[c]} for c in sorted(set(nl) - set(ol))],
        "use_cases_removed": [{"code": c, "name": ol[c]} for c in sorted(set(ol) - set(nl))],
    }


# ---------------------------------------------------------------- effects elsewhere


class SystemRisks:
    """System risk levels from links of non-archived systems: an L2 link raises every rule of
    the L2, an L3 link only that rule. When several links apply, the highest level wins."""

    def __init__(self, db: Session, rule: L3UseCase | None = None):
        self.l2: dict[int, tuple[int, str]] = {}
        self.l3: dict[int, tuple[int, str]] = {}
        q = (
            select(SystemLink.l2_id, SystemLink.l3_id, SystemLink.risk_score, System.name)
            .join(System, System.id == SystemLink.system_id)
            .where(System.archived.is_(False))
            .order_by(System.name)
        )
        if rule is not None:  # only the links that can apply to this rule
            q = q.where(
                or_(
                    SystemLink.l3_id == rule.id,
                    and_(SystemLink.l3_id.is_(None), SystemLink.l2_id == rule.l2_id),
                )
            )
        for l2_id, l3_id, score, name in db.execute(q):
            lvl = risk_level(score)
            target, key = (self.l3, l3_id) if l3_id else (self.l2, l2_id)
            if lvl and (key not in target or lvl > target[key][0]):
                target[key] = (lvl, name)

    def for_rule(self, rule: L3UseCase) -> tuple[int, str] | None:
        """(system risk level 1..5, system name) for a rule, or None."""
        options = [x for x in (self.l2.get(rule.l2_id), self.l3.get(rule.id)) if x]
        return max(options, key=lambda x: x[0]) if options else None


def system_risks(db: Session, rule: L3UseCase | None = None) -> SystemRisks:
    return SystemRisks(db, rule)


def log_source_users(db: Session) -> dict[int, list[str]]:
    """Log source id -> names of the systems whose draft or latest completed interview lists it
    on a component (issue #39: shown before a log source is deleted)."""
    out: dict[int, set[str]] = {}
    systems = list(db.scalars(select(System).options(light_interviews())))
    load_full(
        db,
        [x for s in systems for x in (draft_of(s), latest_completed(s)) if x is not None],
    )
    for system in systems:
        ids: set[int] = set()
        draft = draft_of(system)
        if draft is not None:
            for c in (draft.data or {}).get("components", []):
                ids |= set(c.get("log_source_ids", []))
        last = latest_completed(system)
        if last is not None:
            for c in (last.result or {}).get("components", []):
                ids |= {s["id"] for s in c.get("log_sources", []) if s.get("id") is not None}
        for i in ids:
            out.setdefault(i, set()).add(system.name)
    return {i: sorted(names) for i, names in out.items()}
