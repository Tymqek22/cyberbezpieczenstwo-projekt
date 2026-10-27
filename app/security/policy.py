"""Password policy compliant with NIST SP 800-63B-4 + the variant 9 rule.

- length >= 15 (no complexity requirements),
- check against a blocklist of passwords (common / breached),
- new password different from the current one and the N previous ones,
- (enabled by the admin) the password must not be a date or contain a year 1950-2030.
"""
import re
from datetime import date
from functools import lru_cache
from pathlib import Path

from app.config import MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH
from app.security.passwords import normalize, verify_password

BLOCKLIST_PATH = Path(__file__).resolve().parents[2] / "data" / "common_passwords.txt"

YEAR_RE = re.compile(r"19[5-9]\d|20[0-2]\d|2030")

_SEP = r"[-./ ]"
# The lookahead also finds overlapping matches.
DATE_PATTERNS = [
    # YYYY-MM-DD
    (re.compile(rf"(?=(?<!\d)(\d{{4}})({_SEP})(\d{{1,2}})\2(\d{{1,2}})(?!\d))"), ("y", "m", "d")),
    # DD-MM-YYYY
    (re.compile(rf"(?=(?<!\d)(\d{{1,2}})({_SEP})(\d{{1,2}})\2(\d{{4}})(?!\d))"), ("d", "m", "y")),
    # DD-MM-YY
    (re.compile(rf"(?=(?<!\d)(\d{{1,2}})({_SEP})(\d{{1,2}})\2(\d{{2}})(?!\d))"), ("d", "m", "yy")),
]


@lru_cache(maxsize=1)
def load_blocklist() -> frozenset[str]:
    if not BLOCKLIST_PATH.exists():
        return frozenset()
    with BLOCKLIST_PATH.open(encoding="utf-8", errors="ignore") as f:
        return frozenset(line.strip().lower() for line in f if line.strip())


def _is_valid_date(year: int, month: int, day: int) -> bool:
    try:
        date(year, month, day)
        return True
    except ValueError:
        return False


def contains_date(password: str) -> bool:
    for pattern, order in DATE_PATTERNS:
        for m in pattern.finditer(password):
            first, _sep, second, third = m.groups()
            parts = dict(zip(order, (int(first), int(second), int(third))))
            if "yy" in parts:
                # Two-digit year - the date is valid in the 20th or 21st century
                years = (1900 + parts["yy"], 2000 + parts["yy"])
            else:
                years = (parts["y"],)
            if any(_is_valid_date(y, parts["m"], parts["d"]) for y in years):
                return True
    return False


def contains_year(password: str) -> bool:
    return YEAR_RE.search(password) is not None


def check_date_rule(password: str) -> list[str]:
    errors = []
    if contains_year(password):
        errors.append("Hasło nie może zawierać roku z zakresu 1950–2030.")
    if contains_date(password):
        errors.append("Hasło nie może być datą ani zawierać daty.")
    return errors


def validate_password(
    password: str,
    *,
    date_rule_enabled: bool,
    previous_hashes: list[str] = (),
) -> list[str]:
    """Returns a list of errors (empty list = the password meets the policy)."""
    password = normalize(password)
    errors: list[str] = []

    if len(password) < MIN_PASSWORD_LENGTH:
        errors.append(f"Hasło musi mieć co najmniej {MIN_PASSWORD_LENGTH} znaków.")
    if len(password) > MAX_PASSWORD_LENGTH:
        errors.append(f"Hasło może mieć najwyżej {MAX_PASSWORD_LENGTH} znaków.")
    if password.lower() in load_blocklist():
        errors.append("Hasło znajduje się na liście popularnych/wyciekłych haseł.")
    if date_rule_enabled:
        errors.extend(check_date_rule(password))
    if any(verify_password(h, password) for h in previous_hashes):
        errors.append("Nowe hasło musi różnić się od poprzednio używanych haseł.")

    return errors
