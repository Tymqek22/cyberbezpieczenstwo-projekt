"""Server-side sessions.

The client gets a random token in an HttpOnly cookie, and the database stores
only its SHA-256 hash (a database leak does not allow hijacking sessions).
"""
import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import Request, Response
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.config import settings
from app.models import User, UserSession


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _as_utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def create_session(db: Session, user: User, request: Request) -> str:
    token = secrets.token_urlsafe(32)
    db.add(
        UserSession(
            token_hash=_hash_token(token),
            user_id=user.id,
            csrf_token=secrets.token_urlsafe(32),
            ip=request.client.host if request.client else "",
            user_agent=request.headers.get("user-agent", "")[:255],
        )
    )
    db.commit()
    return token


def get_session(db: Session, token: str | None) -> UserSession | None:
    if not token:
        return None
    sess = db.scalar(select(UserSession).where(UserSession.token_hash == _hash_token(token)))
    if sess is None or sess.revoked_at is not None:
        return None
    return sess


def is_idle_expired(sess: UserSession, idle_minutes: int) -> bool:
    return datetime.now(timezone.utc) - _as_utc(sess.last_activity) > timedelta(minutes=idle_minutes)


def touch(db: Session, sess: UserSession) -> None:
    sess.last_activity = datetime.now(timezone.utc)
    db.commit()


def revoke(db: Session, sess: UserSession) -> None:
    sess.revoked_at = datetime.now(timezone.utc)
    db.commit()


def revoke_all_for_user(db: Session, user_id: int, except_session_id: int | None = None) -> None:
    stmt = update(UserSession).where(UserSession.user_id == user_id, UserSession.revoked_at.is_(None))
    if except_session_id is not None:
        stmt = stmt.where(UserSession.id != except_session_id)
    db.execute(stmt.values(revoked_at=datetime.now(timezone.utc)))
    db.commit()


def set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        settings.session_cookie_name,
        token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        path="/",
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(settings.session_cookie_name, path="/")


def csrf_matches(sess: UserSession, token: str) -> bool:
    return secrets.compare_digest(sess.csrf_token, token or "")
