"""Security event log (module 2).

Events go to a rotating text file - one line per event, key=value pairs,
easy to grep and to quote in the report.
"""
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from app.config import settings

logger = logging.getLogger("security")


def _configure() -> None:
    if logger.handlers:
        return
    path = Path(settings.security_log_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    handler = RotatingFileHandler(path, maxBytes=1_000_000, backupCount=5, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False


_configure()

# Events that indicate an attack (logged at WARNING level)
ALERT_EVENTS = {"LOCKOUT", "LOGIN_WHILE_LOCKED", "CAPTCHA_FAIL", "BOT_HONEYPOT", "HONEYTOKEN",
                "PASSWORD_CHANGE_CAPTCHA_FAIL"}


def _clean(value: object) -> str:
    # Neutralize CR/LF so attacker-controlled input cannot forge log lines
    return str(value).replace("\r", "\r").replace("\n", "\n")


def log_event(event: str, login: str = "", ip: str = "", **details: object) -> None:
    parts = [f"event={event}", f"login={_clean(login)!r}", f"ip={_clean(ip)}"]
    parts += [f"{key}={_clean(val)!r}" for key, val in details.items()]
    logger.log(logging.WARNING if event in ALERT_EVENTS else logging.INFO, " ".join(parts))
