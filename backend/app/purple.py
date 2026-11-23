"""Purple teaming (VECTR-style): outcome derivation, metrics and resilience trending.

Pure functions, no database access (like app/scoring.py), so the rules can be tested on their
own and the API, the PDF and the trends page all count the same way.

Data shape (app/models.py, Pt*): an assessment holds campaigns, a campaign holds test cases.
A test case has a red side (execution: status, attack start/stop, targets, notes) and a blue
side (detections, findings notes). Each detection is what one defense did about the test:

- kind "rule": an L3 rule of the catalogue, so the result shows on the rule (evidence only,
  the embedded metrics stay manual; marking the blue side done can record a verification);
- kind "tool": any other defense or observation, e.g. "Microsoft Defender alert" or
  "only visible in the logs" (custom detections).

The outcome of a test is the best outcome of its detections, in VECTR's order of priority
(blocked > alerted > logged > none > n/a > tbd), unless the analyst overrides it. It is
calculated on read, never stored.
"""

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime

from app import attack
from app.interviews import techniques_match

# best first
OUTCOME_ORDER = (
    "blocked",
    "alerted",
    "logged_central",
    "logged_local",
    "none",
    "not_applicable",
    "tbd",
)
OUTCOME_LABEL = {
    "blocked": "Blocked",
    "alerted": "Alerted",
    "logged_central": "Logged (central)",
    "logged_local": "Logged (local only)",
    "none": "Not detected",
    "not_applicable": "N/A",
    "tbd": "TBD",
}
# outcomes that count as a defended (prevented or detected) test
SUCCESS = frozenset({"blocked", "alerted"})
VISIBLE = frozenset({"blocked", "alerted", "logged_central", "logged_local"})
# outcomes that say something about the defenses (n/a and tbd do not)
RESULT = frozenset({"blocked", "alerted", "logged_central", "logged_local", "none"})
# for resilience trending: higher is better
RANK = {"blocked": 4, "alerted": 3, "logged_central": 2, "logged_local": 1, "none": 0}

SEVERITIES = ("info", "low", "medium", "high", "critical")


def _value(x) -> str | None:
    if x is None:
        return None
    return getattr(x, "value", x)


def derive_outcome(detections: Iterable[str], override: str | None = None) -> str:
    """The outcome of a test case: the override, else the best detection outcome, else tbd."""
    if override:
        return _value(override)
    found = {_value(d) for d in detections}
    return next((o for o in OUTCOME_ORDER if o in found), "tbd")


@dataclass
class CaseInput:
    """What the metrics need from a test case."""

    outcome: str
    red_status: str
    blue_status: str
    attack_start: datetime | None = None
    # times at which a defense blocked or alerted (detections with outcome blocked / alerted)
    detected_at: list[datetime] = field(default_factory=list)


@dataclass
class Metrics:
    total: int = 0
    executed: int = 0
    not_executed: int = 0
    blue_done: int = 0
    counts: dict[str, int] = field(default_factory=lambda: dict.fromkeys(OUTCOME_ORDER, 0))
    # share of executed tests with a result that were blocked or alerted
    defense_success: float | None = None
    # ... that were at least logged
    visibility: float | None = None
    # mean seconds from attack start to the first block or alert
    mean_time_to_detect: float | None = None

    def as_dict(self) -> dict:
        return {
            "total": self.total,
            "executed": self.executed,
            "not_executed": self.not_executed,
            "blue_done": self.blue_done,
            "counts": dict(self.counts),
            "defense_success": self.defense_success,
            "visibility": self.visibility,
            "mean_time_to_detect": self.mean_time_to_detect,
        }


def metrics(cases: Sequence[CaseInput]) -> Metrics:
    m = Metrics(total=len(cases))
    with_result, delays = 0, []
    for c in cases:
        red = _value(c.red_status)
        if red == "not_executed":
            m.not_executed += 1
        if red != "executed":
            continue
        m.executed += 1
        if _value(c.blue_status) == "done":
            m.blue_done += 1
        outcome = _value(c.outcome)
        m.counts[outcome] = m.counts.get(outcome, 0) + 1
        if outcome in RESULT:
            with_result += 1
        if c.attack_start and c.detected_at:
            first = min(c.detected_at)
            delays.append(max(0.0, (first - c.attack_start).total_seconds()))
    if with_result:
        ok = sum(m.counts[o] for o in SUCCESS)
        seen = sum(m.counts[o] for o in VISIBLE)
        m.defense_success = round(ok / with_result, 4)
        m.visibility = round(seen / with_result, 4)
    if delays:
        m.mean_time_to_detect = round(sum(delays) / len(delays), 1)
    return m


def trend(outcomes: Sequence[str | None]) -> str:
    """Resilience of one procedure over its runs (oldest first): improved / regressed /
    unchanged between the last two runs with a result, or new with only one."""
    ranked = [RANK[o] for o in (_value(x) for x in outcomes) if o in RANK]
    if not ranked:
        return "untested"
    if len(ranked) == 1:
        return "new"
    if ranked[-1] > ranked[-2]:
        return "improved"
    if ranked[-1] < ranked[-2]:
        return "regressed"
    return "unchanged"


@dataclass
class RuleCandidate:
    id: int
    code: str
    name: str
    status: str
    techniques: list[str]


def suggest_rules(techniques: Sequence[str], rules: Iterable[RuleCandidate]) -> list[dict]:
    """L3 rules whose ATT&CK techniques cover one of the test's techniques (sub-techniques match
    both ways, revoked IDs are remapped), active rules first."""
    wanted = [attack.resolve(t) or t for t in techniques if t]
    if not wanted:
        return []
    out = []
    for r in rules:
        ids = attack.remap(r.techniques or [])
        hits = sorted({x for x in ids for w in wanted if techniques_match(w, x)})
        if hits:
            out.append(
                {"id": r.id, "code": r.code, "name": r.name, "status": r.status, "matched": hits}
            )
    active = ("operational", "maintenance", "onboarding")
    out.sort(key=lambda x: (x["status"] not in active, x["code"]))
    return out


def navigator_layer(name: str, cells: dict[str, str], version: str) -> dict:
    """An ATT&CK Navigator layer: one entry per technique, coloured by the worst outcome seen
    (a technique that was missed once is not covered)."""
    colors = {
        "blocked": "#1a7f37",
        "alerted": "#4cae4f",
        "logged_central": "#e3b341",
        "logged_local": "#f0883e",
        "none": "#d1242f",
    }
    return {
        "name": name,
        "versions": {"attack": version.split(".")[0] if version else "", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Purple team test outcomes (Vulcan UCF)",
        "techniques": [
            {
                "techniqueID": tid,
                "color": colors.get(outcome, "#cccccc"),
                "comment": OUTCOME_LABEL.get(outcome, outcome),
                "enabled": True,
            }
            for tid, outcome in sorted(cells.items())
        ],
        "legendItems": [{"label": OUTCOME_LABEL[k], "color": v} for k, v in colors.items()],
    }


def worst(outcomes: Iterable[str]) -> str | None:
    """The weakest result among outcomes (for heatmaps: one miss means not covered)."""
    ranked = [o for o in outcomes if o in RANK]
    return min(ranked, key=lambda o: RANK[o]) if ranked else None
