import re
from datetime import datetime, timedelta, timezone

from app import rbac
from app.models import User, UserSession
from app.security.passwords import verify_password

from .conftest import PASSWORD, csrf_from, login

LOGIN_ERROR = "Login lub hasło niepoprawne"
NEW_PASSWORD = "nowe bardzo dlugie haslo"


# --- Login -------------------------------------------------------------------

def test_login_success(client, admin):
    r = login(client, "ADMIN")
    assert r.status_code == 303 and r.headers["location"] == "/"
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=lax" in cookie
    assert client.get("/").status_code == 200


def test_login_error_does_not_reveal_user(client, make_user):
    make_user("jan", rbac.ROLE_READER)
    make_user("zablokowany", rbac.ROLE_READER, is_blocked=True)
    for user_login, pwd in [("jan", "zle haslo zle haslo"), ("nieistnieje", PASSWORD), ("zablokowany", PASSWORD)]:
        r = login(client, user_login, pwd)
        assert r.status_code == 401
        assert LOGIN_ERROR in r.text


def test_password_stored_as_argon2id(db, make_user):
    user = make_user("jan", rbac.ROLE_READER)
    assert user.password_hash.startswith("$argon2id$")
    assert PASSWORD not in user.password_hash


# --- One-time password and forced change --------------------------------------

def _create_user_as_admin(client) -> str:
    login(client, "ADMIN")
    token = csrf_from(client, "/admin/users/new")
    r = client.post(
        "/admin/users/new",
        data={"login": "nowy", "first_name": "Jan", "last_name": "Nowy", "email": "nowy@example.com",
              "role_id": 4, "csrf_token": token},
    )
    assert r.status_code == 200
    return re.search(r'class="otp">([^<]+)<', r.text).group(1)


def test_otp_forces_password_change(client, admin, db):
    otp = _create_user_as_admin(client)
    assert len(otp) == 12

    client.cookies.clear()
    r = login(client, "nowy", otp)
    assert r.status_code == 303
    # every page redirects to the password change
    r = client.get("/articles")
    assert r.status_code == 303 and r.headers["location"] == "/account/change-password"

    token = csrf_from(client)
    r = client.post("/account/change-password",
                    data={"new_password": NEW_PASSWORD, "new_password_repeat": "inne", "csrf_token": token})
    assert r.status_code == 400 and "nie są identyczne" in r.text

    r = client.post("/account/change-password",
                    data={"new_password": NEW_PASSWORD, "new_password_repeat": NEW_PASSWORD, "csrf_token": token})
    assert r.status_code == 303
    assert client.get("/articles").status_code == 200


def test_expired_otp_rejected(client, make_user, db):
    user = make_user("jan", rbac.ROLE_READER, must_change_password=True)
    user.otp_expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    db.commit()
    r = login(client, "jan")
    assert r.status_code == 401 and LOGIN_ERROR in r.text


def test_expired_password_forces_change(client, make_user, db):
    from app.models import AppSettings

    user = make_user("jan", rbac.ROLE_READER)
    user.password_changed_at = datetime.now(timezone.utc) - timedelta(days=31)
    s = db.get(AppSettings, 1) or AppSettings(id=1)
    s.password_max_age_days = 30
    db.add(s)
    db.commit()
    login(client, "jan")
    assert client.get("/").headers["location"] == "/account/change-password"


# --- Password change ---------------------------------------------------------

def test_change_password_requires_old_and_policy(client, make_user):
    make_user("jan", rbac.ROLE_READER)
    login(client, "jan")
    token = csrf_from(client)

    def change(old, new):
        return client.post("/account/change-password",
                           data={"old_password": old, "new_password": new, "new_password_repeat": new,
                                 "csrf_token": token})

    assert "Stare hasło jest niepoprawne" in change("zle stare haslo", NEW_PASSWORD).text
    assert "15 znaków" in change(PASSWORD, "za krotkie").text
    assert "poprzednio" in change(PASSWORD, PASSWORD).text
    assert change(PASSWORD, NEW_PASSWORD).status_code == 303
    # reverting to a previous password is blocked by the history
    assert "poprzednio" in change(NEW_PASSWORD, PASSWORD).text


def test_change_password_date_rule(client, admin, db):
    from app.models import AppSettings

    s = db.get(AppSettings, 1) or AppSettings(id=1)
    s.date_rule_enabled = True
    db.add(s)
    db.commit()
    login(client, "ADMIN")
    token = csrf_from(client)
    r = client.post("/account/change-password",
                    data={"old_password": PASSWORD, "new_password": "moje haslo 1990 ok",
                          "new_password_repeat": "moje haslo 1990 ok", "csrf_token": token})
    assert r.status_code == 400 and "1950–2030" in r.text


# --- Autoryzacja (RBAC) -------------------------------------------------------

def test_reader_gets_403_on_admin(client, make_user):
    make_user("czytelnik", rbac.ROLE_READER)
    login(client, "czytelnik")
    assert client.get("/articles").status_code == 200
    for url in ["/admin/users", "/admin/users/new", "/admin/settings", "/articles/new"]:
        assert client.get(url).status_code == 403, url


def test_auditor_read_only(client, make_user):
    make_user("audytor", rbac.ROLE_AUDITOR)
    login(client, "audytor")
    assert client.get("/admin/users").status_code == 200
    assert client.get("/admin/users/new").status_code == 403
    token = csrf_from(client)
    assert client.post("/admin/users/1/block", data={"csrf_token": token}).status_code == 403
    assert client.post("/articles/new", data={"title": "x", "csrf_token": token}).status_code == 403


def test_editor_can_create_article(client, make_user):
    make_user("redaktor", rbac.ROLE_EDITOR)
    login(client, "redaktor")
    token = csrf_from(client)
    r = client.post("/articles/new", data={"title": "Test", "body": "Treść", "csrf_token": token})
    assert r.status_code == 303
    assert client.get("/admin/users").status_code == 403


def test_csrf_required(client, admin):
    login(client, "ADMIN")
    r = client.post("/admin/settings", data={"password_max_age_days": 0, "session_idle_minutes": 5,
                                             "password_history_count": 5, "csrf_token": "zly"})
    assert r.status_code == 403


def test_admin_account_protected(client, admin):
    login(client, "ADMIN")
    token = csrf_from(client)
    assert client.post(f"/admin/users/{admin.id}/delete", data={"csrf_token": token}).status_code == 400
    assert client.post(f"/admin/users/{admin.id}/block", data={"csrf_token": token}).status_code == 400


def test_blocking_revokes_sessions(client, admin, make_user, db):
    user = make_user("jan", rbac.ROLE_READER)
    from fastapi.testclient import TestClient
    from app.main import app

    user_client = TestClient(app, follow_redirects=False)
    login(user_client, "jan")
    assert user_client.get("/articles").status_code == 200

    login(client, "ADMIN")
    token = csrf_from(client)
    client.post(f"/admin/users/{user.id}/block", data={"csrf_token": token})
    assert user_client.get("/articles").status_code == 303


# --- Session -----------------------------------------------------------------

def test_logout_revokes_session(client, admin):
    login(client, "ADMIN")
    cookie = client.cookies.get("session")
    token = csrf_from(client)
    r = client.post("/logout", data={"csrf_token": token})
    assert r.status_code == 303
    client.cookies.set("session", cookie)  # attempt to reuse the old token
    assert client.get("/").status_code == 303


def test_idle_timeout(client, admin, db):
    login(client, "ADMIN")
    sess = db.query(UserSession).one()
    sess.last_activity = datetime.now(timezone.utc) - timedelta(minutes=16)  # 15 min by default
    db.commit()
    r = client.get("/")
    assert r.status_code == 303 and r.headers["location"] == "/login?expired=1"
    db.refresh(sess)
    assert sess.revoked_at is not None


def test_session_token_hashed_in_db(client, admin, db):
    login(client, "ADMIN")
    token = client.cookies.get("session")
    sess = db.query(UserSession).one()
    assert sess.token_hash != token and len(sess.token_hash) == 64


def test_admin_reset_password_gives_new_otp(client, admin, make_user, db):
    user = make_user("jan", rbac.ROLE_READER)
    login(client, "ADMIN")
    token = csrf_from(client)
    r = client.post(f"/admin/users/{user.id}/reset-password", data={"csrf_token": token})
    otp = re.search(r'class="otp">([^<]+)<', r.text).group(1)
    db.expire_all()
    user = db.get(User, user.id)
    assert user.must_change_password and user.otp_expires_at is not None
    assert verify_password(user.password_hash, otp) and otp not in user.password_hash
