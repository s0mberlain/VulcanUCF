"""TOTP second factor (RFC 6238, SHA-1, 6 digits, 30 s) and recovery codes for local accounts."""

import base64
import hashlib
import hmac
import io
import secrets
import struct
import time
from urllib.parse import quote

import segno
from cryptography.fernet import Fernet, InvalidToken

STEP = 30
DIGITS = 6
WINDOW = 1  # accept one step before and after for clock drift


def new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _fernet(secret_key: str) -> Fernet:
    key = hashlib.sha256(b"magma-totp:" + secret_key.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def encrypt(secret: str, secret_key: str) -> str:
    return _fernet(secret_key).encrypt(secret.encode()).decode()


def decrypt(token: str, secret_key: str) -> str | None:
    try:
        return _fernet(secret_key).decrypt(token.encode()).decode()
    except InvalidToken:
        return None


def reencrypt_all(db, old_key: str, new_key: str) -> tuple[int, list[str]]:
    """Re-encrypt every stored TOTP seed after SECRET_KEY changed. Returns (done, failed users).
    Seeds already readable with the new key are left as they are (the command can be re-run)."""
    from sqlalchemy import select

    from app.models import User

    done, failed = 0, []
    for user in db.scalars(select(User).where(User.totp_secret.is_not(None))):
        if decrypt(user.totp_secret, new_key) is not None:
            continue
        secret = decrypt(user.totp_secret, old_key)
        if secret is None:
            failed.append(user.username)
            continue
        user.totp_secret = encrypt(secret, new_key)
        done += 1
    return done, failed


def code_at(secret: str, step: int) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    mac = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    n = struct.unpack(">I", mac[off : off + 4])[0] & 0x7FFFFFFF
    return str(n % 10**DIGITS).zfill(DIGITS)


def verify(secret: str, code: str, last_step: int | None, now: float | None = None) -> int | None:
    """The matching time step, or None. Steps at or before `last_step` are refused (no replay)."""
    code = "".join(ch for ch in code if ch.isdigit())
    if len(code) != DIGITS:
        return None
    current = int((now if now is not None else time.time()) // STEP)
    for step in range(current - WINDOW, current + WINDOW + 1):
        if last_step is not None and step <= last_step:
            continue
        if hmac.compare_digest(code_at(secret, step), code):
            return step
    return None


def otpauth_uri(secret: str, username: str, issuer: str) -> str:
    label = quote(f"{issuer}:{username}")
    return f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer)}&digits={DIGITS}&period={STEP}"


def qr_svg(uri: str) -> str:
    buf = io.BytesIO()
    segno.make(uri, error="m").save(buf, kind="svg", scale=5, border=2, xmldecl=False, svgns=True)
    return buf.getvalue().decode()


def new_recovery_codes(n: int = 8) -> list[str]:
    alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
    return [
        "-".join("".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(3))
        for _ in range(n)
    ]


def hash_code(code: str) -> str:
    return hashlib.sha256(code.strip().lower().replace(" ", "").encode()).hexdigest()


def clear_totp(user) -> None:
    """Turn two-factor login off for a user (own choice, admin reset or the recovery CLI)."""
    user.totp_enabled = False
    user.totp_secret = None
    user.totp_last_step = None
    user.recovery_codes = []
