"""Issues #84 (Markdown with code blocks in detection request descriptions) and #85 (detection
request on a custom ATT&CK threat could not be saved)."""

import pytest

from app.report import md_blocks
from tests.test_interviews import complete, new_system, save, start, threat
from tests.test_issues_55_60 import comp_with, custom

DESCRIPTION = (
    "Detect **password spraying** from one source.\n\n"
    "```kql\n"
    "SigninLogs\n"
    "| where ResultType == 50126\n"
    "- not a list item\n"
    "```\n"
    "Tune after a week."
)


@pytest.fixture
def analyst(make_user):
    return make_user("analyst")


def test_request_on_custom_threat_saves(analyst):
    """#85: the request names the custom threat as `custom:<key>` of the component."""
    s = new_system(analyst)
    iv = save(analyst, start(analyst, s["id"]), components=[comp_with(custom())])
    req = {
        "key": "r1",
        "title": "Spraying against the portal",
        "description": DESCRIPTION,
        "threat": {"component": "web", "category": "custom:brute"},
    }
    iv = save(analyst, iv, requests=[req])
    (r,) = iv["view"]["requests"]
    assert (r["component"], r["category"], r["description"]) == ("web", "custom:brute", DESCRIPTION)


def test_request_with_split_custom_ref_is_refused(analyst):
    """The form the interview page sent before the fix: split at the last colon."""
    s = new_system(analyst)
    iv = save(analyst, start(analyst, s["id"]), components=[comp_with(custom())])
    req = {
        "key": "r1",
        "title": "Spraying",
        "threat": {"component": "web:custom", "category": "brute"},
    }
    save(analyst, iv, 422, requests=[req])


def test_md_blocks_splits_fenced_code():
    parts = md_blocks(DESCRIPTION)
    assert parts == [
        (False, "Detect **password spraying** from one source.\n"),
        (True, "SigninLogs\n| where ResultType == 50126\n- not a list item"),
        (False, "Tune after a week."),
    ]
    # an unclosed fence runs to the end; ~~~ fences work too
    assert md_blocks("a\n~~~\nx\n```\ny") == [(False, "a"), (True, "x\n```\ny")]
    assert md_blocks("plain") == [(False, "plain")]


def test_pdf_renders_request_with_code_block(analyst):
    s = new_system(analyst)
    iv = save(
        analyst,
        start(analyst, s["id"]),
        components=[comp_with(custom(), threats=[threat("spoofing")])],
    )
    iv = save(
        analyst,
        iv,
        requests=[
            {
                "key": "r1",
                "title": "Spraying",
                "description": DESCRIPTION,
                "threat": {"component": "web", "category": "custom:brute"},
            }
        ],
    )
    iv = complete(analyst, iv)
    pdf = analyst.get(f"/api/interviews/{iv['id']}/pdf")
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")
