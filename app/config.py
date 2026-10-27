from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "postgresql+psycopg://appuser:apppassword@localhost:5433/authapp"
    cookie_secure: bool = False
    session_cookie_name: str = "session"


settings = Settings()

# Variant 9 - fixed policy values
MIN_PASSWORD_LENGTH = 15
MAX_PASSWORD_LENGTH = 128
OTP_LENGTH = 12
OTP_VALIDITY_HOURS = 24
