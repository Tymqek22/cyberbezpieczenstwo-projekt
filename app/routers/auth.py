import math
from dataclasses import dataclass
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import settings
from app.db import get_db
from app.deps import AuthContext, get_app_settings, get_session_context, verify_csrf
from app.models import User
from app.security import captcha, honeytoken, lockout, sessions
from app.security.audit import log_event
from app.security.passwords import DUMMY_HASH, hash_password, needs_rehash, verify_password
from app.templating import templates

router = APIRouter()

LOGIN_ERROR = "Login lub hasło niepoprawne"
CAPTCHA_ERROR = "Weryfikacja CAPTCHA nie powiodła się. Spróbuj ponownie."
HONEYPOT_FIELD = "website"  # hidden from humans by CSS; bots filling every field reveal themselves


@dataclass
class LoginResult:
    status: str  # "ok" | "invalid" | "locked"
    user: User | None = None
    lock_seconds: int = 0
    just_locked: bool = False  # this attempt triggered the lockout


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else ""


def find_user(db: Session, login: str) -> User | None:
    return db.scalar(select(User).where(func.lower(User.login) == login.strip().lower()))


def authenticate(db: Session, user: User | None, password: str, max_attempts: int) -> LoginResult:
    if user is None:
        verify_password(DUMMY_HASH, password)  # equalize response time
        return LoginResult("invalid")

    # While locked the password is not checked at all - otherwise a different
    # answer for the correct password would tell the attacker it was guessed.
    remaining = lockout.lock_remaining(db, user)
    if remaining is not None:
        return LoginResult("locked", user, math.ceil(remaining.total_seconds()))

    if not verify_password(user.password_hash, password):
        if lockout.register_failure(db, user, max_attempts):
            seconds = math.ceil(lockout.lock_remaining(db, user).total_seconds())
            return LoginResult("locked", user, seconds, just_locked=True)
        return LoginResult("invalid", user)

    lockout.reset(db, user)
    if user.is_blocked:
        return LoginResult("invalid", user)
    if user.otp_expires_at is not None and datetime.now(timezone.utc) > user.otp_expires_at:
        return LoginResult("invalid", user)  # one-time password expired
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
        db.commit()
    return LoginResult("ok", user)


def _render_login(request: Request, status_code: int = 200, **context):
    context.setdefault("turnstile_site_key", settings.turnstile_site_key)
    return templates.TemplateResponse(request, "login.html", context, status_code=status_code)


@router.get("/login")
def login_form(request: Request, expired: int = 0):
    info = "Sesja wygasła z powodu bezczynności. Zaloguj się ponownie." if expired else None
    return _render_login(request, info=info)


@router.post("/login")
def login(
    request: Request,
    background: BackgroundTasks,
    login: str = Form(...),
    password: str = Form(...),
    captcha_token: str = Form("", alias=captcha.TOKEN_FIELD),
    honeypot: str = Form("", alias=HONEYPOT_FIELD),
    db: Session = Depends(get_db),
):
    ip = _client_ip(request)
    user_agent = request.headers.get("user-agent", "")
    invalid = lambda: _render_login(request, 401, error=LOGIN_ERROR, login=login)  # noqa: E731

    # 1. Honeypot - a human never sees this field. Generic answer, so the bot does not learn it was caught.
    if honeypot:
        log_event("BOT_HONEYPOT", login, ip, field_value=honeypot[:100], ua=user_agent)
        return invalid()

    # 2. Decoy account - any attempt (even before CAPTCHA) is an incident.
    user = find_user(db, login)
    if user is not None and user.is_honeytoken:
        verify_password(DUMMY_HASH, password)  # same timing as a normal attempt
        log_event("HONEYTOKEN", user.login, ip, ua=user_agent)
        background.add_task(honeytoken.trigger_account_canary, user.login, ip, user_agent)
        return invalid()

    # 3. CAPTCHA - checked before touching the account, so failures do not lock anyone out.
    if not captcha.verify_turnstile(captcha_token, ip):
        log_event("CAPTCHA_FAIL", login, ip, token_present=bool(captcha_token))
        return _render_login(request, 400, error=CAPTCHA_ERROR, login=login)

    # 4-5. Lockout and password
    app_settings = get_app_settings(db)
    result = authenticate(db, user, password, app_settings.max_failed_logins)

    if result.status == "locked":
        event = "LOCKOUT" if result.just_locked else "LOGIN_WHILE_LOCKED"
        log_event(event, result.user.login, ip, remaining_s=result.lock_seconds)
        response = _render_login(request, 429, login=login, lock_seconds=result.lock_seconds)
        response.headers["Retry-After"] = str(result.lock_seconds)
        return response
    if result.status == "invalid":
        log_event("LOGIN_FAIL", login, ip, failed_count=result.user.failed_login_count if result.user else None)
        return invalid()

    user = result.user
    log_event("LOGIN_OK", user.login, ip)
    # New token on every login (protection against session fixation)
    old = sessions.get_session(db, request.cookies.get(settings.session_cookie_name))
    if old is not None:
        sessions.revoke(db, old)
    token = sessions.create_session(db, user, request)
    response = RedirectResponse("/", status_code=303)
    sessions.set_session_cookie(response, token)
    return response


@router.post("/logout", dependencies=[Depends(verify_csrf)])
def logout(ctx: AuthContext = Depends(get_session_context), db: Session = Depends(get_db)):
    sessions.revoke(db, ctx.session)
    response = RedirectResponse("/login", status_code=303)
    sessions.clear_session_cookie(response)
    return response


@router.get("/session/expired")
def session_expired(request: Request, db: Session = Depends(get_db)):
    """Called by idle.js. The server decides whether the session has actually expired
    (the user may have been active in another tab)."""
    sess = sessions.get_session(db, request.cookies.get(settings.session_cookie_name))
    if sess is not None and not sessions.is_idle_expired(sess, get_app_settings(db).session_idle_minutes):
        return RedirectResponse("/", status_code=303)
    if sess is not None:
        sessions.revoke(db, sess)
    response = RedirectResponse("/login?expired=1", status_code=303)
    sessions.clear_session_cookie(response)
    return response
