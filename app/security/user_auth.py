from __future__ import annotations

import base64
import hashlib
import hmac
import os
from datetime import datetime, timedelta, timezone

from app.config import settings

PBKDF2_ROUNDS = 120_000


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS)
    return f"{PBKDF2_ROUNDS}${base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"


def verify_password(password: str, password_hash: str) -> bool:
    try:
        rounds_str, salt_b64, digest_b64 = password_hash.split("$", 2)
        rounds = int(rounds_str)
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
    except (ValueError, TypeError):
        return False

    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, rounds)
    return hmac.compare_digest(actual, expected)


def make_session_token(login: str, ttl_hours: int = 24) -> str:
    issued_at = datetime.now(timezone.utc)
    expires_at = issued_at + timedelta(hours=ttl_hours)
    payload = f"{login}|{int(expires_at.timestamp())}"
    signature = hmac.new(settings.auth_secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(f"{payload}|{signature}".encode("utf-8")).decode("utf-8")


def decode_session_token(token: str) -> str | None:
    try:
        decoded = base64.urlsafe_b64decode(token.encode("utf-8")).decode("utf-8")
        login, expires_at_raw, signature = decoded.rsplit("|", 2)
        payload = f"{login}|{expires_at_raw}"
    except Exception:
        return None

    expected_signature = hmac.new(
        settings.auth_secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(signature, expected_signature):
        return None

    try:
        expires_at = int(expires_at_raw)
    except ValueError:
        return None

    if expires_at < int(datetime.now(timezone.utc).timestamp()):
        return None

    return login
