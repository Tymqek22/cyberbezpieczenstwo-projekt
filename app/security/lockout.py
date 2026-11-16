"""Account lockout after N consecutive failed logins (module 2).

N is set by the administrator (AppSettings.max_failed_logins); the lockout
lasts LOCKOUT_MINUTES. While an account is locked the password is NOT checked,
so the lockout cannot be used as an oracle revealing a correct password.
"""
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.config import LOCKOUT_MINUTES
from app.models import User


def _as_utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def lock_remaining(db: Session, user: User, now: datetime | None = None) -> timedelta | None:
    """Remaining lockout time, or None. An expired lockout is cleared (counter reset)."""
    if user.locked_until is None:
        return None
    now = now or datetime.now(timezone.utc)
    remaining = _as_utc(user.locked_until) - now
    if remaining > timedelta(0):
        return remaining
    reset(db, user)
    return None


def register_failure(db: Session, user: User, max_attempts: int) -> bool:
    """Counts a failed login. Returns True when this attempt locked the account."""
    user.failed_login_count += 1
    locked = user.failed_login_count >= max_attempts
    if locked:
        user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=LOCKOUT_MINUTES)
    db.commit()
    return locked


def reset(db: Session, user: User) -> None:
    if user.failed_login_count or user.locked_until is not None:
        user.failed_login_count = 0
        user.locked_until = None
        db.commit()
