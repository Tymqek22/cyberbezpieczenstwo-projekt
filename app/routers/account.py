from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.db import get_db
from app.deps import AuthContext, get_session_context, password_change_required, verify_csrf
from app.models import PasswordHistory, User
from app.security import sessions
from app.security.passwords import hash_password, verify_password
from app.security.policy import validate_password
from app.templating import templates

router = APIRouter(prefix="/account")


def previous_hashes(user: User, history_count: int) -> list[str]:
    """Current password + the N previous ones from history."""
    hashes = [user.password_hash]
    hashes += [h.password_hash for h in user.password_history[:history_count]]
    return hashes


def set_new_password(db: Session, user: User, new_password: str, history_count: int) -> None:
    # The old password goes into history - unless it was a one-time password.
    if user.otp_expires_at is None:
        user.password_history.insert(0, PasswordHistory(password_hash=user.password_hash))
        # keep only as much history as the policy requires
        del user.password_history[history_count:]
    user.password_hash = hash_password(new_password)
    user.must_change_password = False
    user.otp_expires_at = None
    user.password_changed_at = datetime.now(timezone.utc)
    db.commit()


def _render(request: Request, ctx: AuthContext, forced: bool, errors: list[str] | None = None, status: int = 200):
    return templates.TemplateResponse(
        request,
        "account/change_password.html",
        {"ctx": ctx, "forced": forced, "errors": errors or [], "date_rule": ctx.app_settings.date_rule_enabled},
        status_code=status,
    )


@router.get("/change-password")
def change_password_form(request: Request, ctx: AuthContext = Depends(get_session_context)):
    return _render(request, ctx, forced=password_change_required(ctx.user, ctx.app_settings))


@router.post("/change-password", dependencies=[Depends(verify_csrf)])
def change_password(
    request: Request,
    old_password: str = Form(""),
    new_password: str = Form(...),
    new_password_repeat: str = Form(...),
    ctx: AuthContext = Depends(get_session_context),
    db: Session = Depends(get_db),
):
    user = ctx.user
    forced = password_change_required(user, ctx.app_settings)
    errors: list[str] = []

    # On a forced change the user has just entered their password at login.
    if not forced and not verify_password(user.password_hash, old_password):
        errors.append("Stare hasło jest niepoprawne.")
    if new_password != new_password_repeat:
        errors.append("Podane nowe hasła nie są identyczne.")
    if not errors:
        errors = validate_password(
            new_password,
            date_rule_enabled=ctx.app_settings.date_rule_enabled,
            previous_hashes=previous_hashes(user, ctx.app_settings.password_history_count),
        )
    if errors:
        return _render(request, ctx, forced, errors, status=400)

    set_new_password(db, user, new_password, ctx.app_settings.password_history_count)
    sessions.revoke_all_for_user(db, user.id, except_session_id=ctx.session.id)
    return RedirectResponse("/?password_changed=1", status_code=303)
