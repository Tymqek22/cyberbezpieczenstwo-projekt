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

Konfiguracja przez zmienne środowiskowe lub plik `.env` (wzór: `.env.example`): `DATABASE_URL`,
`COOKIE_SECURE`. `python -m scripts.seed --reset-otp` generuje nowe hasła jednorazowe dla kont z seeda.

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
data/common_passwords.txt   lista zakazanych haseł (SecLists, 100k NCSC)
scripts/seed.py
tests/
```
