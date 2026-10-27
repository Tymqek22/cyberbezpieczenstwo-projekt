"""Data initialization: roles, permissions, settings, the ADMIN account and 8 test users.

Usage:  pipenv run python -m scripts.seed [--reset-otp]
The script is idempotent - existing accounts are not overwritten (unless --reset-otp).
"""
import argparse

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import rbac
from app.db import SessionLocal
from app.deps import get_app_settings
from app.models import Article, Permission, Role, User
from app.security.otp import generate_otp, otp_expiry
from app.security.passwords import hash_password

TEST_USERS = [
    # login, first name, last name, role
    ("audytor1", "Anna", "Kowalska", rbac.ROLE_AUDITOR),
    ("audytor2", "Bartosz", "Nowak", rbac.ROLE_AUDITOR),
    ("redaktor1", "Celina", "Wiśniewska", rbac.ROLE_EDITOR),
    ("redaktor2", "Damian", "Wójcik", rbac.ROLE_EDITOR),
    ("redaktor3", "Ewa", "Kamińska", rbac.ROLE_EDITOR),
    ("czytelnik1", "Filip", "Lewandowski", rbac.ROLE_READER),
    ("czytelnik2", "Grażyna", "Zielińska", rbac.ROLE_READER),
    ("czytelnik3", "Henryk", "Szymański", rbac.ROLE_READER),
]

SAMPLE_ARTICLES = [
    ("Witamy w systemie", "Przykładowy artykuł. Redaktorzy mogą go edytować, czytelnicy tylko czytać."),
    ("Polityka haseł", "Liczy się długość hasła (min. 15 znaków), a nie jego złożoność - zgodnie z NIST SP 800-63B-4."),
]


def seed_rbac(db: Session) -> dict[str, Role]:
    perms = {p.code: p for p in db.scalars(select(Permission))}
    for code, description in rbac.PERMISSIONS.items():
        if code not in perms:
            perms[code] = Permission(code=code, description=description)
            db.add(perms[code])
        else:
            perms[code].description = description

    roles = {r.name: r for r in db.scalars(select(Role))}
    for name, codes in rbac.ROLE_PERMISSIONS.items():
        role = roles.get(name) or Role(name=name)
        role.permissions = [perms[c] for c in sorted(codes)]
        db.add(role)
        roles[name] = role
    db.commit()
    return roles


def ensure_user(db: Session, login: str, first: str, last: str, role: Role, *, is_system: bool, reset: bool) -> str | None:
    """Creates an account with a one-time password. Returns the OTP, or None if the account already exists."""
    user = db.scalar(select(User).where(User.login == login))
    if user is not None and not reset:
        return None
    if user is None:
        user = User(
            login=login,
            first_name=first,
            last_name=last,
            email=f"{login.lower()}@example.com",
            role=role,
            is_system=is_system,
        )
        db.add(user)
    otp = generate_otp()
    user.password_hash = hash_password(otp)
    user.must_change_password = True
    user.otp_expires_at = otp_expiry()
    db.commit()
    return otp


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reset-otp", action="store_true", help="wygeneruj nowe hasła jednorazowe dla kont z seeda")
    args = parser.parse_args()

    with SessionLocal() as db:
        roles = seed_rbac(db)
        get_app_settings(db)

        accounts = [("ADMIN", "Administrator", "Systemu", rbac.ROLE_ADMIN, True)]
        accounts += [(login, first, last, role, False) for login, first, last, role in TEST_USERS]

        print(f"{'Login':<12} {'Rola':<14} Hasło jednorazowe (ważne 24 h)")
        print("-" * 60)
        for login, first, last, role_name, is_system in accounts:
            otp = ensure_user(db, login, first, last, roles[role_name], is_system=is_system, reset=args.reset_otp)
            print(f"{login:<12} {role_name:<14} {otp or '(konto istnieje - bez zmian)'}")

        if not db.scalar(select(Article).limit(1)):
            admin = db.scalar(select(User).where(User.login == "ADMIN"))
            for title, body in SAMPLE_ARTICLES:
                db.add(Article(title=title, body=body, author_id=admin.id))
            db.commit()


if __name__ == "__main__":
    main()
