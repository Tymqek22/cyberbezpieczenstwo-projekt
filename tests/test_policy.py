import pytest

from app.security.otp import OTP_ALPHABET, generate_otp
from app.security.passwords import hash_password
from app.security.policy import contains_date, contains_year, validate_password

GOOD = "zielony slon jedzie tramwajem"


def test_min_length():
    assert validate_password("a" * 14 + "x", date_rule_enabled=False) == []
    assert any("15" in e for e in validate_password("krotkie haslo", date_rule_enabled=False))


def test_blocklist_case_insensitive():
    assert any("popularnych" in e for e in validate_password("QWERTYUIOPASDFGHJKL", date_rule_enabled=False))


@pytest.mark.parametrize("pwd", ["haslo1950haslohaslo", "haslo2030haslohaslo", "abc19900xyz-dlugie-haslo"])
def test_year_in_range_rejected(pwd):
    assert contains_year(pwd)
    assert validate_password(pwd, date_rule_enabled=True)


@pytest.mark.parametrize("pwd", ["haslo1949haslohaslo", "haslo2031haslohaslo"])
def test_year_out_of_range_accepted(pwd):
    assert not contains_year(pwd)
    assert validate_password(pwd, date_rule_enabled=True) == []


@pytest.mark.parametrize(
    "pwd",
    ["kot 12.05.1890 i pies", "1890-05-12 dlugie haslo", "dlugie haslo 12.05.90", "dlugie/12/05/99/haslo", "29.02.24 dlugie haslo"],
)
def test_dates_rejected(pwd):
    assert contains_date(pwd)
    assert validate_password(pwd, date_rule_enabled=True)


@pytest.mark.parametrize("pwd", ["dlugie haslo 32.13.90", "dlugie haslo 12.05-90", "wersja 1.2.3 programu xyz"])
def test_invalid_dates_accepted(pwd):
    assert not contains_date(pwd)
    assert validate_password(pwd, date_rule_enabled=True) == []


def test_date_rule_disabled():
    assert validate_password("urodziny 12.05.1990 kota", date_rule_enabled=False) == []
    assert validate_password("urodziny 12.05.1990 kota", date_rule_enabled=True)


def test_password_history():
    errors = validate_password(GOOD, date_rule_enabled=True, previous_hashes=[hash_password(GOOD)])
    assert any("poprzednio" in e for e in errors)
    assert validate_password(GOOD, date_rule_enabled=True, previous_hashes=[hash_password("inne haslo calkiem")]) == []


def test_otp_format():
    for _ in range(200):
        otp = generate_otp()
        assert len(otp) == 12
        assert set(otp) <= set(OTP_ALPHABET)
    assert not set("0Oo1lI") & set(OTP_ALPHABET)
