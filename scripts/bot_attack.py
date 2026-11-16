"""Automated-client simulation for the module 2 test harness.

Runs ONLY against your own local instance of this application. Testing any system
you do not own, without the owner's written consent, may be unlawful.

The script drives the running app over HTTP and reports which of the module 2
protections responded. Scenarios:
  1. honeypot    - a naive client fills every input of the login form, including the
                   hidden decoy field; the app should answer with the generic error.
  2. honeytoken  - a client reads the credentials left in an HTML comment on the login
                   page and uses them; the app should answer with the generic error and
                   raise a Canarytokens alert server-side.
  3. pwd-change  - a client with a valid session submits the password change form with
                   no CAPTCHA token; the app should reject it.
  4. repeated    - repeated failed logins against one account; after the admin limit the
                   app should return the lockout screen with the remaining time.

Usage (app running at http://127.0.0.1:8000):
  Run A - real Turnstile keys, client sends no CAPTCHA token (CAPTCHA stops it):
    pipenv run python -m scripts.bot_attack --target redaktor1 \
        --valid-login czytelnik1 --valid-password "<password>"
  Run B - test keys "always passes" (simulates a CAPTCHA-solving service), Cloudflare
          dummy token lets the client past CAPTCHA so the lockout can be shown:
    pipenv run python -m scripts.bot_attack --target redaktor1 \
        --valid-login czytelnik1 --valid-password "<password>" \
        --captcha-token "XXXX.DUMMY.TOKEN.XXXX"
"""
import argparse
import re
from dataclasses import dataclass
from pathlib import Path

import httpx2 as httpx

TOKEN_FIELD = "cf-turnstile-response"
CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')
INPUT_RE = re.compile(r'<input[^>]*name="([^"]+)"', re.I)
COMMENT_CREDS_RE = re.compile(r"<!--[^>]*?([A-Za-z0-9._-]+)\s*/\s*(\S+?)\s*-->", re.S)
LOCK_RE = re.compile(r'id="lockout-time">([0-9:]+)<')
WORDLIST = Path(__file__).resolve().parent.parent / "data" / "common_passwords.txt"


@dataclass
class Row:
    protection: str
    scenario: str
    outcome: str
    stopped: bool | None  # True = protection responded, False = request got through, None = skipped


def classify(r: httpx.Response) -> str:
    """Turns a login response into a short human-readable outcome."""
    if r.status_code == 303 and "session" in r.cookies:
        return "zalogowano"
    if r.status_code == 400 and "CAPTCHA" in r.text:
        return "odrzucone przez CAPTCHA"
    if r.status_code == 429:
        m = LOCK_RE.search(r.text)
        return f"konto zablokowane (pozostalo {m.group(1) if m else '?'})"
    if r.status_code == 401:
        return "ogolny blad logowania"
    return f"HTTP {r.status_code}"


def make_client(base_url: str) -> httpx.Client:
    return httpx.Client(
        base_url=base_url,
        follow_redirects=False,
        timeout=10.0,
        headers={"User-Agent": "module2-test-client/1.0 (own-app)"},
    )


def submit_login(c: httpx.Client, login: str, password: str, token: str, **extra) -> httpx.Response:
    data = {"login": login, "password": password, **extra}
    if token:
        data[TOKEN_FIELD] = token
    return c.post("/login", data=data)


def load_passwords(limit: int) -> list[str]:
    try:
        lines = WORDLIST.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        lines = []
    words = [w.strip() for w in lines if w.strip()][:limit]
    return words or [f"guess-{i}" for i in range(limit)]


# --- Scenarios -----------------------------------------------------------------

def run_honeypot(base: str, login: str, password: str, token: str) -> Row:
    with make_client(base) as c:
        page = c.get("/login").text
        # A naive client fills every input field it sees on the form, decoy included.
        payload = {name: "x" for name in INPUT_RE.findall(page)}
        payload.update({"login": login, "password": password, "website": "http://example.invalid"})
        r = submit_login(c, login, payload["password"], token, website=payload["website"])
        got_in = r.status_code == 303
        return Row("Honeypot (ukryte pole)", "klient wypelnia wszystkie pola",
                   classify(r), stopped=not got_in)


def run_honeytoken(base: str, token: str) -> Row:
    with make_client(base) as c:
        page = c.get("/login").text
        m = COMMENT_CREDS_RE.search(page)
        if not m:
            return Row("Honeytoken (konto-pulapka)", "odczyt danych z komentarza HTML",
                       "nie znaleziono danych w komentarzu", stopped=None)
        decoy_login, decoy_password = m.group(1), m.group(2)
        r = submit_login(c, decoy_login, decoy_password, token)
        got_in = r.status_code == 303
        return Row("Honeytoken (konto-pulapka)", f"logowanie na {decoy_login}",
                   classify(r) + " + alert Canarytokens (serwer)", stopped=not got_in)


def run_password_change(base: str, login: str, password: str, token: str) -> Row:
    with make_client(base) as c:
        r = submit_login(c, login, password, token)
        if r.status_code != 303:
            return Row("CAPTCHA przy zmianie hasla", "wyslanie formularza bez tokenu",
                       f"nie udalo sie zalogowac ({classify(r)})", stopped=None)
        form = c.get("/account/change-password").text
        csrf = CSRF_RE.search(form)
        if not csrf:
            return Row("CAPTCHA przy zmianie hasla", "wyslanie formularza bez tokenu",
                       "brak tokenu CSRF na stronie", stopped=None)
        new = "nowe dlugie haslo bota 123"
        # Deliberately omit the CAPTCHA token.
        r = c.post("/account/change-password", data={
            "old_password": password, "new_password": new,
            "new_password_repeat": new, "csrf_token": csrf.group(1),
        })
        rejected = r.status_code == 400 and "CAPTCHA" in r.text
        return Row("CAPTCHA przy zmianie hasla", "wyslanie formularza bez tokenu",
                   "odrzucone (brak tokenu)" if rejected else classify(r), stopped=rejected)


def run_repeated_logins(base: str, target: str, token: str, attempts: int) -> Row:
    passwords = load_passwords(attempts)
    with make_client(base) as c:
        last = None
        locked_at = None
        for i, pwd in enumerate(passwords, start=1):
            r = submit_login(c, target, pwd, token)
            last = r
            if r.status_code == 400 and "CAPTCHA" in r.text:
                # Without a valid token every attempt stops at CAPTCHA - no point continuing.
                return Row("CAPTCHA przy logowaniu", f"{i} prob na konto {target}",
                           "odrzucone przez CAPTCHA (nie dochodzi do hasla)", stopped=True)
            if r.status_code == 303 and "session" in r.cookies:
                return Row("Limit prob logowania", f"{i} prob na konto {target}",
                           "zalogowano - haslo trafione", stopped=False)
            if r.status_code == 429 and locked_at is None:
                locked_at = i
        if locked_at is not None:
            m = LOCK_RE.search(last.text)
            return Row("Limit prob logowania", f"blokada po {locked_at} probach na {target}",
                       f"konto zablokowane (pozostalo {m.group(1) if m else '?'})", stopped=True)
        return Row("Limit prob logowania", f"{len(passwords)} prob na konto {target}",
                   f"brak blokady ({classify(last)})", stopped=False)


# --- Reporting -----------------------------------------------------------------

def print_report(rows: list[Row]) -> None:
    def mark(s: bool | None) -> str:
        return "ZADZIALALO" if s else ("NIE" if s is False else "-")

    widths = (28, 36, 42, 12)
    header = ("Zabezpieczenie", "Scenariusz", "Wynik", "Status")
    line = "+".join("-" * (w + 2) for w in widths)
    print(line)
    print("| " + " | ".join(h.ljust(w) for h, w in zip(header, widths)) + " |")
    print(line)
    for row in rows:
        cells = (row.protection, row.scenario, row.outcome, mark(row.stopped))
        print("| " + " | ".join(str(c)[:w].ljust(w) for c, w in zip(cells, widths)) + " |")
    print(line)


def main() -> None:
    p = argparse.ArgumentParser(description="Module 2 test client - own app only.")
    p.add_argument("--base-url", default="http://127.0.0.1:8000")
    p.add_argument("--target", default="redaktor1", help="account attacked by repeated logins")
    p.add_argument("--valid-login", help="a working account (for the password-change scenario)")
    p.add_argument("--valid-password", help="password for --valid-login")
    p.add_argument("--captcha-token", default="",
                   help="CAPTCHA token; empty = no token (run A), dummy token = run B with test keys")
    p.add_argument("--attempts", type=int, default=12, help="max repeated logins")
    args = p.parse_args()

    token = args.captcha_token
    mode = "B (token CAPTCHA podany)" if token else "A (bez tokenu CAPTCHA)"
    print(f"Cel: {args.base_url} | tryb: {mode}\n")

    rows = [
        run_honeypot(args.base_url, args.valid_login or args.target, args.valid_password or "x", token),
        run_honeytoken(args.base_url, token),
        run_repeated_logins(args.base_url, args.target, token, args.attempts),
    ]
    if args.valid_login and args.valid_password:
        rows.append(run_password_change(args.base_url, args.valid_login, args.valid_password, token))
    else:
        rows.append(Row("CAPTCHA przy zmianie hasla", "wyslanie formularza bez tokenu",
                        "pominieto (podaj --valid-login/--valid-password)", stopped=None))

    print_report(rows)


if __name__ == "__main__":
    main()
