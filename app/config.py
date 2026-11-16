from pydantic_settings import BaseSettings, SettingsConfigDict

# Official Cloudflare Turnstile test keys ("always passes") - used when no real keys are configured.
# https://developers.cloudflare.com/turnstile/troubleshooting/testing/
TURNSTILE_TEST_SITE_KEY = "1x00000000000000000000AA"
TURNSTILE_TEST_SECRET_KEY = "1x0000000000000000000000000000000AA"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "postgresql+psycopg://appuser:apppassword@localhost:5433/authapp"
    cookie_secure: bool = False
    session_cookie_name: str = "session"

    # Module 2 - bot protection
    turnstile_site_key: str = TURNSTILE_TEST_SITE_KEY
    turnstile_secret_key: str = TURNSTILE_TEST_SECRET_KEY
    canary_account_url: str = ""  # Canarytokens "Web bug / URL" token for the decoy account
    security_log_file: str = "logs/security.log"


settings = Settings()

# Variant 9 - fixed policy values
MIN_PASSWORD_LENGTH = 15
MAX_PASSWORD_LENGTH = 128
OTP_LENGTH = 12
OTP_VALIDITY_HOURS = 24

# Module 2 - fixed lockout duration (the attempt limit is set by the administrator)
LOCKOUT_MINUTES = 15
TURNSTILE_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
