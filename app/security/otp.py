"""One-time password - variant 9: 12 characters without ambiguous ones, valid for 24 h."""
import secrets
import string
from datetime import datetime, timedelta, timezone

from app.config import OTP_LENGTH, OTP_VALIDITY_HOURS

CONFUSING_CHARS = set("0Oo1lI")
OTP_ALPHABET = "".join(
    c for c in string.ascii_uppercase + string.ascii_lowercase + string.digits if c not in CONFUSING_CHARS
)


def generate_otp() -> str:
    return "".join(secrets.choice(OTP_ALPHABET) for _ in range(OTP_LENGTH))


def otp_expiry() -> datetime:
    return datetime.now(timezone.utc) + timedelta(hours=OTP_VALIDITY_HOURS)
