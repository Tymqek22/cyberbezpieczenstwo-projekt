from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import settings
from app.db import get_db
from app.deps import AuthContext, get_app_settings, get_session_context, verify_csrf
from app.models import User
from app.security import sessions
from app.security.passwords import DUMMY_HASH, hash_password, needs_rehash, verify_password
from app.templating import templates

router = APIRouter()

LOGIN_ERROR = "Login lub hasło niepoprawne"


def authenticate(db: Session, login: str, password: str) -> User | None:
    user = db.scalar(select(User).where(func.lower(User.login) == login.strip().lower()))
    if user is None:
        verify_password(DUMMY_HASH, password)  # equalize response time
        return None
    if not verify_password(user.password_hash, password):
        return None
    if user.is_blocked:
        return None
    if user.otp_expires_at is not None and datetime.now(timezone.utc) > user.otp_expires_at:
        return None  # one-time password expired
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
        db.commit()
    return user


@router.get("/login")
def login_form(request: Request, expired: int = 0):
    info = "Sesja wygasła z powodu bezczynności. Zaloguj się ponownie." if expired else None
    return templates.TemplateResponse(request, "login.html", {"info": info})


@router.post("/login")
def login(
    request: Request,
    login: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    user = authenticate(db, login, password)
    if user is None:
        return templates.TemplateResponse(
            request, "login.html", {"error": LOGIN_ERROR, "login": login}, status_code=401
        )
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
