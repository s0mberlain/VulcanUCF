"""Evidence files on business owner interviews (issue #34).

Accepted: PDF, JPEG/PNG images, diagrams (Visio .vsd/.vsdx, Dia .dia, Excalidraw .excalidraw)
and Microsoft Threat Modeling Tool files (.tm7). The extension decides the type; the first bytes
must fit it, so a renamed file of another kind is refused. PDFs and images can be shown in the
app (served inline); every other type is only offered as a download.

Files can be added and removed while the interview is a draft; a completed interview keeps its
evidence as it was (read-only, like the rest of the interview). The business owner's sign-off
(issue #42, a PDF or image) can be added and removed after completion until the confirmation is
recorded. All evidence together is limited by EVIDENCE_MAX_TOTAL_MB (issue #47). Viewing and
downloading a file is written to the audit log (issue #46).
"""

import hashlib
import json
import re
import unicodedata
from datetime import datetime
from typing import Literal
from urllib.parse import quote

from fastapi import APIRouter, File, HTTPException, Query, UploadFile, status
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy import func, select

from app import audit
from app.api.deps import DB, SettingsDep
from app.models import Interview, InterviewAttachment, InterviewStatus, TestAttachment
from app.security import Admin, Editor, Reader

router = APIRouter(tags=["systems & interviews"])

MAX_FILE = 20 * 1024 * 1024
MAX_FILES = 50

ZIP = (b"PK\x03\x04",)
OLE = (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",)

# extension -> (content type, magic prefixes or a check name, viewable in the app)
TYPES: dict[str, tuple[str, tuple[bytes, ...] | str, bool]] = {
    "pdf": ("application/pdf", (b"%PDF-",), True),
    "png": ("image/png", (b"\x89PNG\r\n\x1a\n",), True),
    "jpg": ("image/jpeg", (b"\xff\xd8\xff",), True),
    "jpeg": ("image/jpeg", (b"\xff\xd8\xff",), True),
    "vsdx": ("application/vnd.ms-visio.drawing", ZIP, False),
    "vsd": ("application/vnd.visio", OLE, False),
    # Dia saves gzip-compressed XML by default, uncompressed XML on request
    "dia": ("application/x-dia-diagram", "dia", False),
    "excalidraw": ("application/vnd.excalidraw+json", "json", False),
    "tm7": ("application/vnd.ms-threatmodel+xml", "xml", False),
}
ACCEPT = sorted(TYPES)


class AttachmentOut(BaseModel):
    id: int
    interview_id: int
    filename: str
    content_type: str
    size: int
    sha256: str
    uploaded_by: str
    uploaded_at: datetime
    viewable: bool
    kind: Literal["pdf", "image", "diagram", "threat_model"]
    signoff: bool = False


def _ext(name: str) -> str:
    return name.rsplit(".", 1)[-1].lower() if "." in name else ""


def _kind(ext: str) -> str:
    if ext == "pdf":
        return "pdf"
    if ext in ("png", "jpg", "jpeg"):
        return "image"
    if ext == "tm7":
        return "threat_model"
    return "diagram"


def out(a: InterviewAttachment) -> AttachmentOut:
    ext = _ext(a.filename)
    return AttachmentOut(
        id=a.id,
        interview_id=a.interview_id,
        filename=a.filename,
        content_type=a.content_type,
        size=a.size,
        sha256=a.sha256,
        uploaded_by=a.uploaded_by,
        uploaded_at=a.uploaded_at,
        viewable=TYPES.get(ext, ("", (), False))[2],
        kind=_kind(ext),  # type: ignore[arg-type]
        signoff=bool(a.signoff),
    )


def _text_start(data: bytes) -> str:
    """The start of a text file without byte order mark and leading white space."""
    head = data[:4096]
    if head.startswith((b"\xff\xfe", b"\xfe\xff")):  # UTF-16 (Threat Modeling Tool)
        text = head.decode("utf-16", "ignore")
    else:
        text = head.decode("utf-8-sig", "ignore")
    return text.lstrip()


def _content_ok(ext: str, data: bytes) -> bool:
    check = TYPES[ext][1]
    if isinstance(check, tuple):
        return data.startswith(check)
    if check == "dia":
        return data.startswith(b"\x1f\x8b") or _text_start(data).startswith("<")
    if check == "xml":
        return _text_start(data).startswith("<")
    if check == "json":
        try:
            doc = json.loads(data.decode("utf-8-sig"))
        except (UnicodeDecodeError, ValueError):
            return False
        return isinstance(doc, dict)
    return False  # pragma: no cover


def _safe_name(name: str) -> str:
    """The file name as shown and offered for download: no path, no control characters."""
    name = unicodedata.normalize("NFC", name).replace("\\", "/").rsplit("/", 1)[-1]
    name = "".join(ch for ch in name if unicodedata.category(ch)[0] != "C").strip(" .")
    if len(name) > 200:
        stem, _, ext = name.rpartition(".")
        name = stem[: 200 - len(ext) - 1] + "." + ext
    return name


def _interview(db, interview_id: int) -> Interview:
    i = db.get(Interview, interview_id)
    if i is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Interview not found")
    return i


def _attachment(db, attachment_id: int) -> InterviewAttachment:
    a = db.get(InterviewAttachment, attachment_id)
    if a is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "File not found")
    return a


def _key(i: Interview) -> str:
    return f"{i.system.name} {i.interview_date.isoformat()}"


@router.get("/interviews/{interview_id}/attachments", response_model=list[AttachmentOut])
def list_attachments(interview_id: int, _: Reader, db: DB) -> list[AttachmentOut]:
    return [out(a) for a in _interview(db, interview_id).attachments]


@router.post(
    "/interviews/{interview_id}/attachments", response_model=AttachmentOut, status_code=201
)
async def upload_attachment(
    interview_id: int,
    user: Editor,
    db: DB,
    settings: SettingsDep,
    file: UploadFile = File(...),
    signoff: bool = Query(False, description="The business owner's sign-off (PDF or image)"),
) -> AttachmentOut:
    i = _interview(db, interview_id)
    if signoff:
        if i.status != InterviewStatus.completed:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "A sign-off can be added after completion and before the confirmation",
            )
        if any(a.signoff for a in i.attachments):
            raise HTTPException(
                status.HTTP_409_CONFLICT, "This interview has a sign-off file already"
            )
    elif i.status != InterviewStatus.draft:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Evidence can only be added while the interview is a draft"
        )
    name = _safe_name(file.filename or "")
    ext = _ext(name)
    if ext not in TYPES or not name[: -len(ext) - 1]:
        raise HTTPException(
            422,
            "This file type is not accepted. Allowed: PDF, JPG, PNG, Visio (.vsd, .vsdx), "
            "Dia, Excalidraw and Threat Modeling Tool (.tm7) files",
        )
    data = await file.read(MAX_FILE + 1)
    if len(data) > MAX_FILE:
        raise HTTPException(413, "The file is larger than 20 MB")
    if not data:
        raise HTTPException(422, "The file is empty")
    if signoff and not TYPES[ext][2]:
        raise HTTPException(422, "A sign-off must be a PDF, JPG or PNG file")
    if not _content_ok(ext, data):
        raise HTTPException(422, f"The file content does not match a .{ext} file")
    limit = settings.evidence_max_total_mb * 1024 * 1024
    if limit and used_bytes(db) + len(data) > limit:
        raise HTTPException(
            413,
            f"The evidence storage is full ({settings.evidence_max_total_mb} MB); "
            "ask an admin to remove old files or raise EVIDENCE_MAX_TOTAL_MB",
        )
    if len(i.attachments) >= MAX_FILES:
        raise HTTPException(422, f"An interview can have at most {MAX_FILES} files")
    a = InterviewAttachment(
        interview_id=i.id,
        filename=name,
        content_type=TYPES[ext][0],
        size=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        data=data,
        uploaded_by=user.username,
        signoff=signoff,
    )
    db.add(a)
    changes = {"file": name, "size": len(data)} | ({"signoff": True} if signoff else {})
    audit.record(db, user, "upload", "interview_evidence", _key(i), changes)
    db.commit()
    return out(a)


_UNSAFE = re.compile(r"[^A-Za-z0-9._ -]")


@router.get("/interview-attachments/{attachment_id}/content")
def attachment_content(
    attachment_id: int, user: Reader, db: DB, download: bool = False
) -> Response:
    a = _attachment(db, attachment_id)
    viewable = TYPES.get(_ext(a.filename), ("", (), False))[2]
    inline = viewable and not download
    audit.record_access(
        db,
        user,
        "view" if inline else "download",
        "interview_evidence",
        _key(a.interview),
        {"file": a.filename},
    )
    ascii_name = _UNSAFE.sub("_", a.filename) or "evidence"
    disposition = (
        f'{"inline" if inline else "attachment"}; filename="{ascii_name}"; '
        f"filename*=UTF-8''{quote(a.filename)}"
    )
    return Response(
        a.data,
        media_type=a.content_type if viewable else "application/octet-stream",
        headers={
            "Content-Disposition": disposition,
            # shown inside the interview page (same origin) but never able to run anything
            "Content-Security-Policy": "default-src 'none'; img-src 'self'; "
            "style-src 'unsafe-inline'; object-src 'self'; frame-ancestors 'self'",
            "X-Frame-Options": "SAMEORIGIN",
            "Cache-Control": "private, no-store",
        },
    )


@router.delete("/interview-attachments/{attachment_id}", status_code=204)
def delete_attachment(attachment_id: int, user: Editor, db: DB) -> None:
    a = _attachment(db, attachment_id)
    i = a.interview
    if a.signoff and i.status == InterviewStatus.completed:
        pass  # a sign-off can be replaced until the confirmation is recorded (#42)
    elif i.status != InterviewStatus.draft:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "Evidence of a completed interview cannot be removed",
        )
    audit.record(db, user, "delete", "interview_evidence", _key(i), {"file": a.filename})
    db.delete(a)
    db.commit()


def used_bytes(db) -> int:
    """Interview evidence and test attachments together (PROJ-3 shares the storage limit)."""
    iv = int(db.scalar(select(func.coalesce(func.sum(InterviewAttachment.size), 0))) or 0)
    tests = int(db.scalar(select(func.coalesce(func.sum(TestAttachment.size), 0))) or 0)
    return iv + tests


class StorageOut(BaseModel):
    files: int
    used_bytes: int
    limit_bytes: int


@router.get("/evidence/storage", response_model=StorageOut)
def evidence_storage(_: Admin, db: DB, settings: SettingsDep) -> StorageOut:
    """Space used by interview evidence files (#47), shown on the Settings page."""
    return StorageOut(
        files=int(db.scalar(select(func.count(InterviewAttachment.id))) or 0),
        used_bytes=used_bytes(db),
        limit_bytes=settings.evidence_max_total_mb * 1024 * 1024,
    )
