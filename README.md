# Moduł 1 – Identyfikacja, uwierzytelnianie i autoryzacja (wariant 9)

FastAPI + Jinja2 (SSR) · PostgreSQL + SQLAlchemy 2 + Alembic · Argon2id · sesje po stronie serwera · RBAC.

**Wariant 9:** min. długość hasła 15 · reguła (włączana przez admina): hasło nie może być datą ani zawierać
roku 1950–2030 · 8 użytkowników testowych · role: Administrator, Audytor, Redaktor, Czytelnik ·
hasło jednorazowe: 12 znaków bez znaków mylących (0/O/o, 1/l/I), ważne 24 h.

## Uruchomienie

Wymagania: Python 3.12, pipenv, Docker Desktop.

```bash
pipenv install --dev                    # zależności z Pipfile.lock
docker compose up -d                    # PostgreSQL 16 na porcie 5433 (baza authapp)
pipenv run alembic upgrade head         # schemat bazy
pipenv run python -m scripts.seed       # role, uprawnienia, ADMIN + 8 kont testowych (wypisuje hasła jednorazowe)
pipenv run uvicorn app.main:app --reload
```

Aplikacja: http://127.0.0.1:8000 · Testy: `pipenv run pytest` (testcontainers uruchamia na czas testów osobny kontener PostgreSQL – wymaga działającego Dockera)

Konfiguracja przez zmienne środowiskowe lub plik `.env`: `DATABASE_URL`, `COOKIE_SECURE` oraz zmienne
modułu 2 (patrz niżej). `python -m scripts.seed --reset-otp` generuje nowe hasła jednorazowe dla kont z seeda.

## Konta testowe

| Login | Rola |
|---|---|
| ADMIN (konto systemowe – nie można go usunąć, zablokować ani zmienić mu roli) | Administrator |
| audytor1, audytor2 | Audytor |
| redaktor1, redaktor2, redaktor3 | Redaktor |
| czytelnik1, czytelnik2, czytelnik3 | Czytelnik |

Każde konto startuje z hasłem jednorazowym – przy pierwszym logowaniu wymuszana jest zmiana hasła.

## Macierz uprawnień (`app/rbac.py`)

| Uprawnienie | Administrator | Audytor | Redaktor | Czytelnik |
|---|---|---|---|---|
| articles:read | ✔ | ✔ | ✔ | ✔ |
| articles:create / edit / delete | ✔ | – | ✔ | – |
| users:read | ✔ | ✔ | – | – |
| users:manage | ✔ | – | – | – |
| settings:manage | ✔ | – | – | – |
| audit:read (moduł 2) | ✔ | ✔ | – | – |

## Struktura

```
app/
  config.py           ustawienia + stałe wariantu
  models.py           User, Role, Permission, PasswordHistory, UserSession, AppSettings, Article
  rbac.py             uprawnienia i role
  deps.py             uwierzytelnienie, wymuszona zmiana hasła, require_permission, CSRF
  security/
    passwords.py      Argon2id (argon2-cffi)
    policy.py         polityka haseł (długość, blocklista, historia, reguła dat)
    otp.py            hasło jednorazowe
    sessions.py       sesje (token w cookie HttpOnly, w bazie SHA-256), idle timeout
  routers/            auth, account, admin, articles
  templates/, static/
  security/
    captcha.py        weryfikacja tokenu Cloudflare Turnstile (siteverify)
    lockout.py        blokada konta po N błędnych logowaniach (15 min)
    honeytoken.py     alert Canarytokens przy użyciu konta-pułapki
    audit.py          log zdarzeń bezpieczeństwa (logs/security.log)
data/common_passwords.txt   lista zakazanych haseł (SecLists, 100k NCSC)
scripts/seed.py
scripts/bot_attack.py       skrypt testowy modułu 2 (tylko własna aplikacja)
tests/
```

---

# Moduł 2 – Zabezpieczenia przed botami, ruchem automatycznym i wyciekiem danych

Rozbudowa modułu 1 o ochronę logowania przed ruchem automatycznym. Zadanie dodatkowe
(limit prób z jednego adresu IP) nie wchodzi w zakres.

## Wdrożone elementy

| Wymaganie | Realizacja |
|---|---|
| Limit błędnych logowań | Licznik `users.failed_login_count`; po `AppSettings.max_failed_logins` (ustawia admin w `/admin/settings`, domyślnie 5) konto jest blokowane na 15 min (`users.locked_until`). Ekran logowania pokazuje pozostały czas z odliczaniem (`static/lockout.js`). Podczas blokady hasło nie jest sprawdzane (brak wyroczni hasła). Udane logowanie zeruje licznik. |
| CAPTCHA przy logowaniu | Cloudflare Turnstile. Token jednorazowy, ważny 300 s, weryfikowany po stronie serwera (`siteverify`). Nieudana CAPTCHA nie podbija licznika blokady. |
| CAPTCHA przy zmianie hasła | Turnstile w formularzu `/account/change-password`; żądanie bez poprawnego tokenu jest odrzucane (400) przed sprawdzeniem starego hasła. |
| Pułapka na boty (honeypot) | Ukryte pole `website` (schowane CSS-em, `tabindex="-1"`, `aria-hidden`). Jego wypełnienie → ogólny błąd 401 i wpis `BOT_HONEYPOT`; licznik konta bez zmian. |
| Canarytoken 1 – konto-pułapka | Konto `backup_admin` (`is_honeytoken`), dane „wyciekają” w komentarzu HTML na stronie logowania. Każda próba logowania → ogólny błąd + wpis `HONEYTOKEN` + wywołanie URL tokenu Canarytokens (alert e-mail). |
| Canarytoken 2 – klucze AWS | Plik-przynęta z kluczami AWS wygenerowanymi na canarytokens.org (patrz niżej). |
| Log zdarzeń | `logs/security.log` (moduł `app/security/audit.py`): `LOGIN_OK/FAIL`, `LOCKOUT`, `LOGIN_WHILE_LOCKED`, `CAPTCHA_FAIL`, `BOT_HONEYPOT`, `HONEYTOKEN`, `PASSWORD_CHANGE*`. |

Kolejność sprawdzeń przy logowaniu: honeypot → konto-pułapka (alert) → CAPTCHA → blokada konta → hasło.

## Konfiguracja (`.env`)

```bash
# Cloudflare Turnstile (dash.cloudflare.com → Turnstile → Add widget).
# Puste = oficjalne klucze testowe "always passes":
#   site 1x00000000000000000000AA / secret 1x0000000000000000000000000000000AA
TURNSTILE_SITE_KEY=
TURNSTILE_SECRET_KEY=
# Canarytokens.org "Web bug / URL token" dla konta-pułapki backup_admin
CANARY_ACCOUNT_URL=
SECURITY_LOG_FILE=logs/security.log
```

Bez skonfigurowanych kluczy aplikacja używa testowych kluczy Turnstile (widget zawsze przechodzi) –
wygodne do testów, ale do zrzutów ekranu z realnym wyzwaniem ustaw własne klucze z panelu Cloudflare.

## Canarytokens – konfiguracja ręczna

1. **Konto-pułapka:** na canarytokens.org utwórz token *Web bug / URL*, wklej jego URL do `CANARY_ACCOUNT_URL`.
   Alert uruchamia każda próba logowania na `backup_admin` (hasło z komentarza HTML, dowolne i tak odrzucone).
2. **Klucze AWS:** utwórz token *AWS keys*, wygenerowane klucze zapisz w pliku-przynęcie (np. `deploy/aws/credentials`).
   Alert wywołuje np. `aws sts get-caller-identity`. Uwaga: push protection GitHub może blokować wysyłkę kluczy do repo.

## Skrypt testowy (bot)

> Uruchamiać **wyłącznie na własnej aplikacji**. Atak na cudzy system bez zgody właściciela może być przestępstwem.

```bash
# Tryb A – realne klucze Turnstile, bot bez tokenu (CAPTCHA zatrzymuje atak):
pipenv run python -m scripts.bot_attack --target redaktor1 \
    --valid-login czytelnik1 --valid-password "<hasło>"

# Tryb B – testowe klucze "always passes" (symulacja farmy CAPTCHA), token testowy
#          przepuszcza bota, więc widać blokadę konta:
pipenv run python -m scripts.bot_attack --target redaktor1 \
    --valid-login czytelnik1 --valid-password "<hasło>" \
    --captcha-token "XXXX.DUMMY.TOKEN.XXXX"
```

Skrypt sprawdza honeypot, konto-pułapkę, limit prób i zmianę hasła bez tokenu, a na końcu wypisuje
tabelę zestawienia (zabezpieczenie / scenariusz / wynik / status).
