"""ATT&CK coverage heatmap, ATT&CK Navigator layer and remapping of outdated technique IDs."""

from datetime import date

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import attack, audit
from app.api.deps import DB, SettingsDep
from app.models import L3UseCase, Lifecycle
from app.scoring import RuleInput, score_rule
from app.security import Admin, Reader

router = APIRouter(prefix="/attack", tags=["att&ck"])

INACTIVE = (Lifecycle.retired,)


class HitOut(BaseModel):
    code: str
    name: str
    weight: float | None
    direct: bool


class TechOut(BaseModel):
    id: str
    name: str
    best: float | None
    rules: list[HitOut]
    subs: list["TechOut"] = []


class TacticOut(BaseModel):
    id: str
    short: str
    name: str
    techniques: list[TechOut]
    covered: int
    total: int


class Outdated(BaseModel):
    code: str
    name: str
    id: str
    status: str
    replacement: str | None


class CoverageOut(BaseModel):
    version: str
    tactics: list[TacticOut]
    techniques_total: int
    techniques_with_rules: int
    techniques_scored: int
    rules_total: int
    rules_mapped: int
    outdated: list[Outdated]


def _rule_hits(db: Session, default_interval: int) -> tuple[dict[str, list], list, int, int]:
    """technique id -> hits (direct and via sub-techniques), outdated IDs, rule counts."""
    hits: dict[str, list[attack.Hit]] = {}
    outdated, total, mapped = [], 0, 0
    q = select(L3UseCase).where(L3UseCase.lifecycle_status.not_in(INACTIVE))
    for r in db.scalars(q.order_by(L3UseCase.code)):
        total += 1
        s = score_rule(
            RuleInput(
                r.code, "", r.lifecycle_status, r.effectiveness, r.implementation, r.coverage
            ),
            date.today(),
            default_interval,
        )
        w = s.weight if s.scored else None
        seen = set()
        for tid in r.attack_techniques or []:
            st, new = attack.status(tid)
            if st != "current":
                outdated.append(
                    Outdated(code=r.code, name=r.name, id=tid, status=st, replacement=new)
                )
            cur = attack.resolve(tid)
            if not cur or cur in seen:
                continue
            seen.add(cur)
            hits.setdefault(cur, []).append(attack.Hit(r.code, r.name, w, True))
            if "." in cur:
                hits.setdefault(attack.parent(cur), []).append(attack.Hit(r.code, r.name, w, False))
        if seen:
            mapped += 1
    return hits, outdated, total, mapped


def _tech(tid: str, info: dict, hits: dict, subs: list) -> TechOut:
    cell = attack.Cell(tid, info["name"], hits.get(tid, []))
    # one entry per rule; a direct mapping wins over "via sub-technique"
    by_rule: dict[str, attack.Hit] = {}
    for h in cell.rules:
        if h.code not in by_rule or h.direct:
            by_rule[h.code] = h
    return TechOut(
        id=tid,
        name=info["name"],
        best=cell.best,
        rules=[HitOut(**vars(h)) for h in by_rule.values()],
        subs=subs,
    )


@router.get("/coverage", response_model=CoverageOut)
def coverage(_: Reader, db: DB, settings: SettingsDep) -> CoverageOut:
    d = attack.data()
    hits, outdated, total, mapped = _rule_hits(db, settings.default_verification_days)
    techs = d["techniques"]
    tactics = []
    for t in d["tactics"]:
        parents = [k for k, v in techs.items() if "." not in k and t["short"] in v["tactics"]]
        out = []
        for p in sorted(parents, key=lambda k: techs[k]["name"]):
            subs = [
                _tech(k, techs[k], hits, [])
                for k in sorted(techs)
                if k.startswith(p + ".") and t["short"] in techs[k]["tactics"]
            ]
            out.append(_tech(p, techs[p], hits, subs))
        tactics.append(
            TacticOut(
                id=t["id"],
                short=t["short"],
                name=t["name"],
                techniques=out,
                covered=sum(1 for x in out if x.rules),
                total=len(out),
            )
        )
    parents_all = [k for k in techs if "." not in k]
    return CoverageOut(
        version=d["version"],
        tactics=tactics,
        techniques_total=len(parents_all),
        techniques_with_rules=sum(1 for k in parents_all if hits.get(k)),
        techniques_scored=sum(1 for k in parents_all if attack.Cell(k, "", hits.get(k, [])).best),
        rules_total=total,
        rules_mapped=mapped,
        outdated=outdated,
    )


@router.get("/navigator.json")
def navigator(_: Reader, db: DB, settings: SettingsDep) -> JSONResponse:
    """Layer for the MITRE ATT&CK Navigator: score = best rule weight in %."""
    hits, _o, _t, _m = _rule_hits(db, settings.default_verification_days)
    techniques = []
    for tid, hs in sorted(hits.items()):
        direct = [h for h in hs if h.direct]
        if not direct:
            continue  # parents only covered through sub-techniques stay uncoloured
        best = attack.Cell(tid, "", direct).best
        entry = {
            "techniqueID": tid,
            "comment": "; ".join(
                f"{h.code} {h.name}"
                + (f" (weight {h.weight:.2f})" if h.weight is not None else " (not scored)")
                for h in direct
            ),
            "enabled": True,
            "showSubtechniques": False,
        }
        if best is not None:
            entry["score"] = round(best * 100)
        else:
            entry["color"] = "#d5d8de"
        techniques.append(entry)
    layer = {
        "name": f"{settings.app_name} detection coverage",
        "versions": {"layer": "4.5", "navigator": "5.1.0"},
        "domain": "enterprise-attack",
        "description": (
            "Generated by Vulcan UCF (MaGMa Use Case Framework). Score = best weight "
            "(effectiveness x implementation x coverage) of the operational rules for the "
            "technique. Grey = rules exist but are not scored."
        ),
        "sorting": 3,
        "layout": {"layout": "side", "showName": True, "showID": False},
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {"colors": ["#eef2ff", "#93c5fd", "#1d4ed8"], "minValue": 0, "maxValue": 100},
        "legendItems": [{"label": "Rules, not scored", "color": "#d5d8de"}],
        "showTacticRowBackground": False,
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }
    return JSONResponse(
        layer,
        headers={"Content-Disposition": 'attachment; filename="vulcan-attack-layer.json"'},
    )


class RemapChange(BaseModel):
    code: str
    name: str
    before: list[str]
    after: list[str]
    kept: list[str]  # deprecated or unknown IDs without a replacement


class RemapOut(BaseModel):
    version: str
    rules: int
    ids_replaced: int
    applied: bool
    changes: list[RemapChange]


def _plan(db: Session) -> list[tuple[L3UseCase, RemapChange]]:
    out = []
    for r in db.scalars(select(L3UseCase).order_by(L3UseCase.code)):
        before = list(r.attack_techniques or [])
        after = attack.remap(before)
        if after != before:
            kept = [t for t in after if attack.status(t)[0] in ("deprecated", "unknown")]
            out.append(
                (r, RemapChange(code=r.code, name=r.name, before=before, after=after, kept=kept))
            )
    return out


def _out(plan, applied: bool) -> RemapOut:
    return RemapOut(
        version=attack.data()["version"],
        rules=len(plan),
        ids_replaced=sum(
            sum(1 for t in c.before if attack.status(t)[0] == "revoked") for _, c in plan
        ),
        applied=applied,
        changes=[c for _, c in plan],
    )


class TechniqueBrief(BaseModel):
    id: str
    name: str


@router.get("/techniques", response_model=list[TechniqueBrief])
def techniques(_: Reader) -> list[TechniqueBrief]:
    """All current ATT&CK techniques (pickers, e.g. custom threats of an interview, #60)."""
    return [
        TechniqueBrief(id=k, name=v["name"]) for k, v in sorted(attack.data()["techniques"].items())
    ]


@router.get("/remap", response_model=RemapOut)
def remap_preview(_: Admin, db: DB) -> RemapOut:
    return _out(_plan(db), False)


@router.post("/remap", response_model=RemapOut)
def remap_apply(user: Admin, db: DB) -> RemapOut:
    plan = _plan(db)
    for r, c in plan:
        r.attack_techniques = c.after
    res = _out(plan, True)
    audit.record(
        db,
        user,
        "attack_remap",
        "l3",
        "all",
        {"version": res.version, "rules": res.rules, "ids_replaced": res.ids_replaced},
    )
    db.commit()
    return res
