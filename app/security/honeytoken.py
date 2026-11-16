"""Decoy account (honeytoken) - no legitimate user ever logs in to it,
so every use is an incident. The alert is delivered by Canarytokens:
the app requests the token's URL ("Web bug / URL token") and Canarytokens
sends an e-mail.
"""
import httpx2 as httpx

from app.config import settings
from app.security.audit import logger


def trigger_account_canary(login: str, ip: str, user_agent: str) -> None:
    """Runs as a background task so the response time does not reveal the trap."""
    if not settings.canary_account_url:
        return
    try:
        httpx.get(
            settings.canary_account_url,
            params={"login": login, "src": ip},
            # Canarytokens shows the User-Agent in the alert - pass the attacker's one
            headers={"User-Agent": f"honeytoken-login from {ip} | {user_agent}"[:255]},
            timeout=5.0,
        )
    except httpx.HTTPError as exc:
        logger.error("event=CANARY_ERROR error=%r", str(exc))
