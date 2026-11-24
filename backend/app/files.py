"""Uploaded files: interview evidence (issue #34) and test attachments (PROJ-3).

The extension decides the type; the first bytes must fit it, so a renamed file of another kind is
refused. PDFs and images can be shown in the app (served inline); every other type is only
offered as a download. Both kinds of files share one storage limit (EVIDENCE_MAX_TOTAL_MB).
"""

import hashlib
import json
import re
import unicodedata
from urllib.parse import quote

from fastapi import HTTPException, UploadFile
from fastapi.responses import Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import Settings
from app.models import InterviewAttachment, TestAttachment

MAX_FILE = 20 * 1024 * 1024

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

# a file shown inside the app (same origin) can never run anything
SANDBOX_CSP = (
    "default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; object-src 'self'; "
    "frame-ancestors 'self'"
)
_UNSAFE = re.compile(r"[^A-Za-z0-9._ -]")


def ext(name: str) -> str:
    return name.rsplit(".", 1)[-1].lower() if "." in name else ""


def viewable(name: str) -> bool:
    return TYPES.get(ext(name), ("", (), False))[2]


def _text_start(data: bytes) -> str:
    """The start of a text file without byte order mark and leading white space."""
    head = data[:4096]
    if head.startswith((b"\xff\xfe", b"\xfe\xff")):  # UTF-16 (Threat Modeling Tool)
        text = head.decode("utf-16", "ignore")
    else:
        text = head.decode("utf-8-sig", "ignore")
    return text.lstrip()


def content_ok(kind: str, data: bytes) -> bool:
    check = TYPES[kind][1]
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


def safe_name(name: str) -> str:
    """The file name as shown and offered for download: no path, no control characters."""
    name = unicodedata.normalize("NFC", name).replace("\\", "/").rsplit("/", 1)[-1]
    name = "".join(ch for ch in name if unicodedata.category(ch)[0] != "C").strip(" .")
    if len(name) > 200:
        stem, _, suffix = name.rpartition(".")
        name = stem[: 200 - len(suffix) - 1] + "." + suffix
    return name


def used_bytes(db: Session) -> int:
    """Interview evidence and test attachments together (PROJ-3 shares the storage limit)."""
    iv = int(db.scalar(select(func.coalesce(func.sum(InterviewAttachment.size), 0))) or 0)
    tests = int(db.scalar(select(func.coalesce(func.sum(TestAttachment.size), 0))) or 0)
    return iv + tests


async def read_upload(
    file: UploadFile,
    db: Session,
    settings: Settings,
    *,
    types_message: str,
    full_hint: str = "",
    viewable_message: str | None = None,
) -> tuple[str, str, bytes, str]:
    """Check an upload and read it: (clean name, extension, bytes, sha256).

    `viewable_message`: only PDFs and images are accepted (with this error otherwise);
    `full_hint` follows the "storage is full" error."""
    name = safe_name(file.filename or "")
    kind = ext(name)
    if kind not in TYPES or not name[: -len(kind) - 1]:
        raise HTTPException(422, types_message)
    data = await file.read(MAX_FILE + 1)
    if len(data) > MAX_FILE:
        raise HTTPException(413, "The file is larger than 20 MB")
    if not data:
        raise HTTPException(422, "The file is empty")
    if viewable_message and not TYPES[kind][2]:
        raise HTTPException(422, viewable_message)
    if not content_ok(kind, data):
        raise HTTPException(422, f"The file content does not match a .{kind} file")
    limit = settings.evidence_max_total_mb * 1024 * 1024
    if limit and used_bytes(db) + len(data) > limit:
        raise HTTPException(
            413, f"The evidence storage is full ({settings.evidence_max_total_mb} MB){full_hint}"
        )
    return name, kind, data, hashlib.sha256(data).hexdigest()


def file_response(data: bytes, filename: str, content_type: str, inline: bool) -> Response:
    """A stored file, shown in the app (PDF, image) or as a download, never able to run code."""
    ascii_name = _UNSAFE.sub("_", filename) or "evidence"
    disposition = (
        f"{'inline' if inline else 'attachment'}; "
        f"filename=\"{ascii_name}\"; filename*=UTF-8''{quote(filename)}"
    )
    return Response(
        data,
        media_type=content_type if viewable(filename) else "application/octet-stream",
        headers={
            "Content-Disposition": disposition,
            "Content-Security-Policy": SANDBOX_CSP,
            "X-Frame-Options": "SAMEORIGIN",
            "Cache-Control": "private, no-store",
        },
    )
