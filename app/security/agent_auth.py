from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timezone

from fastapi import HTTPException, Request, status
from sqlalchemy.orm import Session

from app.models.agent import Agent

logger = logging.getLogger(__name__)

ALLOWED_TIMESTAMP_SKEW_SECONDS = 600


@dataclass
class AuthenticatedAgent:
    agent_id: str


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def generate_agent_credentials() -> tuple[str, str]:
    return secrets.token_urlsafe(18), secrets.token_urlsafe(48)


def validate_agent_request(request: Request, db: Session) -> AuthenticatedAgent:
    agent_id = request.headers.get("X-Agent-ID", "").strip()
    timestamp_raw = request.headers.get("X-Timestamp", "").strip()
    signature = request.headers.get("X-Signature", "").strip()

    if not agent_id or not timestamp_raw or not signature:
        _log_auth_failure("missing headers", agent_id=agent_id or "unknown")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Agent authentication headers are required")

    try:
        timestamp = int(timestamp_raw)
    except ValueError as exc:
        _log_auth_failure("invalid timestamp format", agent_id=agent_id)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication timestamp") from exc

    now_ts = int(time.time())
    if abs(now_ts - timestamp) > ALLOWED_TIMESTAMP_SKEW_SECONDS:
        _log_auth_failure("timestamp outside allowed window", agent_id=agent_id)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication timestamp is outside allowed window")

    agent = db.query(Agent).filter(Agent.agent_id == agent_id).first()
    if agent is None:
        _log_auth_failure("unknown agent", agent_id=agent_id)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unknown agent")

    if not agent.enabled:
        _log_auth_failure("agent disabled", agent_id=agent_id)
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Agent is disabled")

    raw_body = getattr(request.state, "raw_body", None)
    if raw_body is None:
        _log_auth_failure("raw body is not available", agent_id=agent_id)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Request body is unavailable for signature validation")

    canonical_payload = (
        f"{request.method}\n{request.url.path}\n{timestamp_raw}\n".encode("utf-8")
        + raw_body
    )
    expected_signature = hmac.new(agent.secret.encode("utf-8"), canonical_payload, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(expected_signature, signature):
        _log_auth_failure("signature mismatch", agent_id=agent_id)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid signature")

    agent.last_seen = _utcnow()
    agent.updated_at = _utcnow()
    db.commit()

    return AuthenticatedAgent(agent_id=agent_id)


def register_agent(db: Session) -> tuple[str, str]:
    for _ in range(10):
        agent_id, secret = generate_agent_credentials()
        exists = db.query(Agent.agent_id).filter(Agent.agent_id == agent_id).first()
        if exists is not None:
            continue
        now = _utcnow()
        db.add(
            Agent(
                agent_id=agent_id,
                secret=secret,
                enabled=True,
                created_at=now,
                updated_at=now,
            )
        )
        db.commit()
        return agent_id, secret
    raise RuntimeError("Failed to generate unique agent_id")


def rotate_agent_secret(db: Session, agent: Agent) -> str:
    new_secret = secrets.token_urlsafe(48)
    agent.secret = new_secret
    agent.updated_at = _utcnow()
    db.commit()
    return new_secret


def _log_auth_failure(reason: str, *, agent_id: str) -> None:
    logger.warning("Agent authentication failed: %s (agent_id=%s)", reason, agent_id)
