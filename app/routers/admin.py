import re

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import rbac
from app.db import get_db
from app.deps import AuthContext, require_permission, verify_csrf
from app.models import Role, User
from app.security import sessions
from app.security.otp import generate_otp, otp_expiry
from app.security.passwords import hash_password
from app.templating import templates

router = APIRouter(prefix="/admin")

LOGIN_RE = re.compile(r"^[A-Za-z0-9._-]{3,64}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

can_read_users = require_permission(rbac.USERS_READ)
can_manage_users = require_permission(rbac.USERS_MANAGE)
can_manage_settings = require_permission(rbac.SETTINGS_MANAGE)


def _get_user(db: Session, user_id: int) -> User:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(404, "Nie znaleziono użytkownika")
    return user


def _validate_user_fields(first_name: str, last_name: str, email: str, role: Role | None) -> list[str]:
    errors = []
    if not first_name.strip() or not last_name.strip():
        errors.append("Imię i nazwisko są wymagane.")
    if not EMAIL_RE.match(email.strip()):
        errors.append("Niepoprawny adres e-mail.")
    if role is None:
        errors.append("Wybierz poprawną rolę.")
    return errors


def _assign_otp(db: Session, user: User) -> str:
    """Issues a one-time password: forces a change at login and invalidates sessions."""
    otp = generate_otp()
    user.password_hash = hash_password(otp)
    user.must_change_password = True
    user.otp_expires_at = otp_expiry()
    db.commit()
    sessions.revoke_all_for_user(db, user.id)
    return otp


def _show_otp(request: Request, ctx: AuthContext, user: User, otp: str, action: str):
    return templates.TemplateResponse(
        request, "admin/otp.html", {"ctx": ctx, "target": user, "otp": otp, "action": action}
    )


# --- User list ---------------------------------------------------------------

@router.get("/users")
def users_list(request: Request, ctx: AuthContext = Depends(can_read_users), db: Session = Depends(get_db)):
    users = db.scalars(select(User).order_by(User.id)).all()
    return templates.TemplateResponse(request, "admin/users.html", {"ctx": ctx, "users": users})


# --- Create ------------------------------------------------------------------

@router.get("/users/new")
def user_new_form(request: Request, ctx: AuthContext = Depends(can_manage_users), db: Session = Depends(get_db)):
    roles = db.scalars(select(Role).order_by(Role.id)).all()
    return templates.TemplateResponse(
        request, "admin/user_form.html", {"ctx": ctx, "roles": roles, "target": None, "form": {}, "errors": []}
    )


@router.post("/users/new", dependencies=[Depends(verify_csrf)])
def user_create(
    request: Request,
    login: str = Form(...),
    first_name: str = Form(""),
    last_name: str = Form(""),
    email: str = Form(""),
    role_id: int = Form(...),
    ctx: AuthContext = Depends(can_manage_users),
    db: Session = Depends(get_db),
):
    role = db.get(Role, role_id)
    errors = _validate_user_fields(first_name, last_name, email, role)
    if not LOGIN_RE.match(login):
        errors.append("Login: 3–64 znaki (litery, cyfry, . _ -).")
    elif db.scalar(select(User).where(func.lower(User.login) == login.lower())):
        errors.append("Użytkownik o takim loginie już istnieje.")
    if errors:
        roles = db.scalars(select(Role).order_by(Role.id)).all()
        form = {"login": login, "first_name": first_name, "last_name": last_name, "email": email, "role_id": role_id}
        return templates.TemplateResponse(
            request,
            "admin/user_form.html",
            {"ctx": ctx, "roles": roles, "target": None, "form": form, "errors": errors},
            status_code=400,
        )

    user = User(
        login=login,
        first_name=first_name.strip(),
        last_name=last_name.strip(),
        email=email.strip(),
        role=role,
        password_hash="!",
    )
    db.add(user)
    db.flush()
    otp = _assign_otp(db, user)
    return _show_otp(request, ctx, user, otp, "utworzenie konta")


# --- Edit --------------------------------------------------------------------

@router.get("/users/{user_id}/edit")
def user_edit_form(
    request: Request, user_id: int, ctx: AuthContext = Depends(can_manage_users), db: Session = Depends(get_db)
):
    user = _get_user(db, user_id)
    roles = db.scalars(select(Role).order_by(Role.id)).all()
    form = {"first_name": user.first_name, "last_name": user.last_name, "email": user.email, "role_id": user.role_id}
    return templates.TemplateResponse(
        request, "admin/user_form.html", {"ctx": ctx, "roles": roles, "target": user, "form": form, "errors": []}
    )


@router.post("/users/{user_id}/edit", dependencies=[Depends(verify_csrf)])
def user_update(
    request: Request,
    user_id: int,
    first_name: str = Form(""),
    last_name: str = Form(""),
    email: str = Form(""),
    role_id: int = Form(...),
    ctx: AuthContext = Depends(can_manage_users),
    db: Session = Depends(get_db),
):
    user = _get_user(db, user_id)
    role = db.get(Role, role_id)
    errors = _validate_user_fields(first_name, last_name, email, role)
    if user.is_system and role is not None and role.id != user.role_id:
        errors.append("Nie można zmienić roli konta ADMIN.")
    if errors:
        roles = db.scalars(select(Role).order_by(Role.id)).all()
        form = {"first_name": first_name, "last_name": last_name, "email": email, "role_id": role_id}
        return templates.TemplateResponse(
            request,
            "admin/user_form.html",
            {"ctx": ctx, "roles": roles, "target": user, "form": form, "errors": errors},
            status_code=400,
        )
    user.first_name = first_name.strip()
    user.last_name = last_name.strip()
    user.email = email.strip()
    user.role = role
    db.commit()
    return RedirectResponse("/admin/users", status_code=303)


# --- Block / reset / delete --------------------------------------------------

def _forbid_system(user: User) -> None:
    if user.is_system:
        raise HTTPException(400, "Operacja niedozwolona dla konta ADMIN")


@router.post("/users/{user_id}/block", dependencies=[Depends(verify_csrf)])
def user_block(user_id: int, ctx: AuthContext = Depends(can_manage_users), db: Session = Depends(get_db)):
    user = _get_user(db, user_id)
    _forbid_system(user)
    user.is_blocked = True
    db.commit()
    sessions.revoke_all_for_user(db, user.id)
    return RedirectResponse("/admin/users", status_code=303)


@router.post("/users/{user_id}/unblock", dependencies=[Depends(verify_csrf)])
def user_unblock(user_id: int, ctx: AuthContext = Depends(can_manage_users), db: Session = Depends(get_db)):
    user = _get_user(db, user_id)
    user.is_blocked = False
    db.commit()
    return RedirectResponse("/admin/users", status_code=303)


@router.post("/users/{user_id}/reset-password", dependencies=[Depends(verify_csrf)])
def user_reset_password(
    request: Request, user_id: int, ctx: AuthContext = Depends(can_manage_users), db: Session = Depends(get_db)
):
    user = _get_user(db, user_id)
    otp = _assign_otp(db, user)
    return _show_otp(request, ctx, user, otp, "reset hasła")


@router.post("/users/{user_id}/delete", dependencies=[Depends(verify_csrf)])
def user_delete(user_id: int, ctx: AuthContext = Depends(can_manage_users), db: Session = Depends(get_db)):
    user = _get_user(db, user_id)
    _forbid_system(user)
    db.delete(user)
    db.commit()
    return RedirectResponse("/admin/users", status_code=303)


# --- Security settings -------------------------------------------------------

@router.get("/settings")
def settings_form(request: Request, ctx: AuthContext = Depends(can_manage_settings)):
    return templates.TemplateResponse(
        request, "admin/settings.html", {"ctx": ctx, "s": ctx.app_settings, "errors": [], "saved": False}
    )


@router.post("/settings", dependencies=[Depends(verify_csrf)])
def settings_save(
    request: Request,
    date_rule_enabled: bool = Form(False),
    password_max_age_days: int = Form(...),
    session_idle_minutes: int = Form(...),
    password_history_count: int = Form(...),
    ctx: AuthContext = Depends(can_manage_settings),
    db: Session = Depends(get_db),
):
    errors = []
    if not 0 <= password_max_age_days <= 3650:
        errors.append("Ważność hasła: 0–3650 dni (0 = bez wygasania).")
    if not 1 <= session_idle_minutes <= 1440:
        errors.append("Czas bezczynności: 1–1440 minut.")
    if not 1 <= password_history_count <= 24:
        errors.append("Liczba pamiętanych haseł: 1–24.")
    s = ctx.app_settings
    if not errors:
        s.date_rule_enabled = date_rule_enabled
        s.password_max_age_days = password_max_age_days
        s.session_idle_minutes = session_idle_minutes
        s.password_history_count = password_history_count
        db.commit()
    return templates.TemplateResponse(
        request,
        "admin/settings.html",
        {"ctx": ctx, "s": s, "errors": errors, "saved": not errors},
        status_code=400 if errors else 200,
    )
