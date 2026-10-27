"""FastAPI dependencies: authentication, forced password change, authorization (RBAC), CSRF.

Every protected endpoint declares its required permission on the server side -
hiding a button in a template is not an authorization mechanism.
"""
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from fastapi import Depends, Form, Request
from sqlalchemy.orm import Session

from app.config import settings
from app.db import get_db
from app.models import AppSettings, User, UserSession
from app.security import sessions


class NotAuthenticated(Exception):
    def __init__(self, reason: str = ""):
        self.reason = reason


class PasswordChangeRequired(Exception):
    pass


class PermissionDenied(Exception):
    pass


class CsrfError(Exception):
    pass


@dataclass
class AuthContext:
    user: User
    session: UserSession
    app_settings: AppSettings

    @property
    def csrf_token(self) -> str:
        return self.session.csrf_token

    def can(self, permission: str) -> bool:
        return self.user.has_permission(permission)


def get_app_settings(db: Session) -> AppSettings:
    app_settings = db.get(AppSettings, 1)
    if app_settings is None:
        app_settings = AppSettings(id=1)
        db.add(app_settings)
        db.commit()
    return app_settings


def password_change_required(user: User, app_settings: AppSettings) -> bool:
    if user.must_change_password:
        return True
    if app_settings.password_max_age_days > 0 and user.password_changed_at is not None:
        changed = user.password_changed_at
        if changed.tzinfo is None:
            changed = changed.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) - changed > timedelta(days=app_settings.password_max_age_days)
    return False


def get_session_context(request: Request, db: Session = Depends(get_db)) -> AuthContext:
    """Logged-in user - without checking for a forced password change."""
    sess = sessions.get_session(db, request.cookies.get(settings.session_cookie_name))
    if sess is None:
        raise NotAuthenticated()
    app_settings = get_app_settings(db)
    if sess.user.is_blocked:
        sessions.revoke(db, sess)
        raise NotAuthenticated()
    if sessions.is_idle_expired(sess, app_settings.session_idle_minutes):
        sessions.revoke(db, sess)
        raise NotAuthenticated("expired")
    sessions.touch(db, sess)
    return AuthContext(user=sess.user, session=sess, app_settings=app_settings)


def get_auth_context(ctx: AuthContext = Depends(get_session_context)) -> AuthContext:
    """Logged-in user who is not required to change their password."""
    if password_change_required(ctx.user, ctx.app_settings):
        raise PasswordChangeRequired()
    return ctx


def require_permission(permission: str):
    def dependency(ctx: AuthContext = Depends(get_auth_context)) -> AuthContext:
        if not ctx.can(permission):
            raise PermissionDenied()
        return ctx

    return dependency


def verify_csrf(
    ctx: AuthContext = Depends(get_session_context),
    csrf_token: str = Form(""),
) -> None:
    if not sessions.csrf_matches(ctx.session, csrf_token):
        raise CsrfError()
