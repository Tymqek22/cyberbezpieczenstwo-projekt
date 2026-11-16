"""Module 2 - protection against bots: lockout, CAPTCHA, honeypot, honeytoken."""
from datetime import datetime, timedelta, timezone

import httpx2 as httpx
import pytest

from app import rbac
from app.models import AppSettings, User
from app.routers import auth
from app.security import captcha
from app.security.captcha import verify_turnstile as real_verify  # original, before the autouse fake

from .conftest import CAPTCHA, PASSWORD, csrf_from, login

LOGIN_ERROR = "Login lub hasło niepoprawne"
WRONG = "zle haslo zle haslo zle"
NEW_PASSWORD = "nowe bardzo dlugie haslo"


def _set_limit(db, n: int) -> None:
    s = db.get(AppSettings, 1) or AppSettings(id=1)
    s.max_failed_logins = n
    db.add(s)
    db.commit()


def _reload(db, user: User) -> User:
    db.expire_all()
    return db.get(User, user.id)


# --- Failed-login lockout ------------------------------------------------------

def test_lockout_after_limit_shows_remaining_time(client, db, make_user):
    user = make_user("jan", rbac.ROLE_READER)
    _set_limit(db, 3)
    for _ in range(2):
        assert login(client, "jan", WRONG).status_code == 401
    r = login(client, "jan", WRONG)  # 3rd failure locks the account
    assert r.status_code == 429
    assert "Pozostały czas blokady" in r.text and "15:00" in r.text
    assert 0 < int(r.headers["retry-after"]) <= 15 * 60
    user = _reload(db, user)
    assert user.failed_login_count == 3 and user.locked_until is not None


def test_locked_account_rejects_correct_password_without_checking_it(client, db, make_user, monkeypatch):
    user = make_user("jan", rbac.ROLE_READER)
    user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=10)
    db.commit()

    checked = []
    monkeypatch.setattr(auth, "verify_password", lambda *a: checked.append(a) or True)
    r = login(client, "jan", PASSWORD)
    assert r.status_code == 429 and "Pozostały czas blokady" in r.text
    assert checked == []  # no password oracle while locked
    assert "session" not in r.cookies


def test_lockout_expires_after_15_minutes(client, db, make_user):
    user = make_user("jan", rbac.ROLE_READER, failed_login_count=5)
    user.locked_until = datetime.now(timezone.utc) - timedelta(seconds=1)
    db.commit()
    assert login(client, "jan").status_code == 303
    user = _reload(db, user)
    assert user.failed_login_count == 0 and user.locked_until is None


def test_successful_login_resets_counter(client, db, make_user):
    user = make_user("jan", rbac.ROLE_READER)
    _set_limit(db, 3)
    login(client, "jan", WRONG)
    login(client, "jan", WRONG)
    assert login(client, "jan").status_code == 303
    assert _reload(db, user).failed_login_count == 0
    # counter starts from zero again - two more failures do not lock
    client.cookies.clear()
    login(client, "jan", WRONG)
    assert login(client, "jan", WRONG).status_code == 401


def test_admin_sets_limit(client, db, admin):
    login(client, "ADMIN")
    token = csrf_from(client, "/admin/settings")
    base = {"password_max_age_days": 0, "session_idle_minutes": 15, "password_history_count": 5,
            "csrf_token": token}
    assert client.post("/admin/settings", data={**base, "max_failed_logins": 0}).status_code == 400
    assert client.post("/admin/settings", data={**base, "max_failed_logins": 21}).status_code == 400
    assert client.post("/admin/settings", data={**base, "max_failed_logins": 3}).status_code == 200
    db.expire_all()
    assert db.get(AppSettings, 1).max_failed_logins == 3


def test_admin_unblock_lifts_lockout(client, db, admin, make_user):
    user = make_user("jan", rbac.ROLE_READER, failed_login_count=5)
    user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=10)
    db.commit()
    login(client, "ADMIN")
    token = csrf_from(client, "/admin/users")
    assert client.post(f"/admin/users/{user.id}/unblock", data={"csrf_token": token}).status_code == 303
    user = _reload(db, user)
    assert user.locked_until is None and user.failed_login_count == 0


def test_unknown_login_gets_generic_error(client, db):
    _set_limit(db, 1)
    for _ in range(3):
        r = login(client, "nieistnieje", WRONG)
        assert r.status_code == 401 and LOGIN_ERROR in r.text


# --- CAPTCHA (login) -------------------------------------------------------------

@pytest.mark.parametrize("token", ["", "zly-token"])
def test_login_without_valid_captcha_rejected(client, db, make_user, token):
    user = make_user("jan", rbac.ROLE_READER)
    r = client.post("/login", data={"login": "jan", "password": PASSWORD, captcha.TOKEN_FIELD: token})
    assert r.status_code == 400 and "CAPTCHA" in r.text
    assert "session" not in r.cookies
    assert _reload(db, user).failed_login_count == 0  # CAPTCHA failures do not lock accounts


def test_login_page_contains_turnstile_widget(client):
    html = client.get("/login").text
    assert 'class="cf-turnstile"' in html and "challenges.cloudflare.com/turnstile" in html


# --- CAPTCHA (password change) -----------------------------------------------------

@pytest.mark.parametrize("token", [None, "zly-token"])
def test_password_change_without_valid_captcha_rejected(client, db, make_user, token):
    user = make_user("jan", rbac.ROLE_READER)
    old_hash = user.password_hash
    login(client, "jan")
    data = {"old_password": PASSWORD, "new_password": NEW_PASSWORD, "new_password_repeat": NEW_PASSWORD,
            "csrf_token": csrf_from(client)}
    if token is not None:
        data[captcha.TOKEN_FIELD] = token
    r = client.post("/account/change-password", data=data)
    assert r.status_code == 400 and "CAPTCHA" in r.text
    assert _reload(db, user).password_hash == old_hash


def test_password_change_with_captcha_succeeds(client, make_user):
    make_user("jan", rbac.ROLE_READER)
    login(client, "jan")
    html = client.get("/account/change-password").text
    assert 'class="cf-turnstile"' in html
    r = client.post("/account/change-password",
                    data={"old_password": PASSWORD, "new_password": NEW_PASSWORD,
                          "new_password_repeat": NEW_PASSWORD, "csrf_token": csrf_from(client), **CAPTCHA})
    assert r.status_code == 303


# --- Honeypot --------------------------------------------------------------------

def test_honeypot_field_rejects_bot(client, db, make_user, fake_turnstile):
    user = make_user("jan", rbac.ROLE_READER)
    r = login(client, "jan", PASSWORD, website="http://spam.example")
    assert r.status_code == 401 and LOGIN_ERROR in r.text  # bot is not told it was detected
    assert "session" not in r.cookies
    assert _reload(db, user).failed_login_count == 0
    assert fake_turnstile == []  # rejected before anything else


def test_honeypot_hidden_from_humans(client):
    html = client.get("/login").text
    assert 'name="website"' in html and 'class="hp" aria-hidden="true"' in html and 'tabindex="-1"' in html


# --- Honeytoken (decoy account) -------------------------------------------------------

def test_honeytoken_login_triggers_canary(client, db, make_user, canary_calls):
    make_user("backup_admin", rbac.ROLE_READER, is_honeytoken=True)
    # even with the correct password and without CAPTCHA the attempt raises the alarm
    r = client.post("/login", data={"login": "backup_admin", "password": PASSWORD})
    assert r.status_code == 401 and LOGIN_ERROR in r.text
    assert "session" not in r.cookies
    assert len(canary_calls) == 1 and canary_calls[0][0] == "backup_admin"


def test_normal_login_does_not_trigger_canary(client, make_user, canary_calls):
    make_user("jan", rbac.ROLE_READER)
    login(client, "jan")
    login(client, "jan", WRONG)
    assert canary_calls == []


# --- Turnstile verification (unit) ------------------------------------------------------

def test_turnstile_empty_token_rejected_without_request(monkeypatch):
    monkeypatch.setattr(httpx, "post", lambda *a, **k: pytest.fail("no request expected"))
    assert real_verify("") is False


def test_turnstile_network_error_fails_closed(monkeypatch):
    def boom(*a, **k):
        raise httpx.ConnectError("down")

    monkeypatch.setattr(httpx, "post", boom)
    assert real_verify("token") is False


@pytest.mark.parametrize("payload, expected", [
    ({"success": True}, True),
    ({"success": False, "error-codes": ["timeout-or-duplicate"]}, False),
])
def test_turnstile_siteverify_result(monkeypatch, payload, expected):
    sent = {}

    def fake_post(url, data, timeout):
        sent.update(data)
        return httpx.Response(200, json=payload, request=httpx.Request("POST", url))

    monkeypatch.setattr(httpx, "post", fake_post)
    assert real_verify("token", "1.2.3.4") is expected
    assert sent["response"] == "token" and sent["remoteip"] == "1.2.3.4" and sent["secret"]
