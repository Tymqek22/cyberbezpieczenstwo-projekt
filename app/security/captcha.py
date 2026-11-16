"""Cloudflare Turnstile - server-side token verification.

Each token is single-use and valid for 300 s; Cloudflare enforces both
(a reused or expired token returns the error code `timeout-or-duplicate`).
A form submitted without a valid token is rejected.
"""
import httpx2 as httpx

from app.config import TURNSTILE_VERIFY_URL, settings
from app.security.audit import logger

TOKEN_FIELD = "cf-turnstile-response"  # field name added to the form by the Turnstile widget
MAX_TOKEN_LENGTH = 2048  # per Cloudflare docs


def verify_turnstile(token: str, remote_ip: str | None = None) -> bool:
    if not token or len(token) > MAX_TOKEN_LENGTH:
        return False
    data = {"secret": settings.turnstile_secret_key, "response": token}
    if remote_ip:
        data["remoteip"] = remote_ip
    try:
        r = httpx.post(TURNSTILE_VERIFY_URL, data=data, timeout=5.0)
        r.raise_for_status()
        result = r.json()
    except (httpx.HTTPError, ValueError) as exc:
        # Fail closed: when verification is impossible the request is rejected
        logger.error("event=CAPTCHA_VERIFY_ERROR error=%r", str(exc))
        return False
    if not result.get("success"):
        logger.info("event=CAPTCHA_REJECTED codes=%r", result.get("error-codes", []))
        return False
    return True
