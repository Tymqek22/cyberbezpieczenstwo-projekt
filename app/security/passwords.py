"""Password hashing with Argon2id (argon2-cffi).

The library generates a random salt for every hash and stores it together
with the parameters in PHC format, e.g. $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>.
"""
import unicodedata

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

_hasher = PasswordHasher()  # Argon2id by default, parameters in line with RFC 9106 / OWASP


def normalize(password: str) -> str:
    return unicodedata.normalize("NFKC", password)


def hash_password(password: str) -> str:
    return _hasher.hash(normalize(password))


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(password_hash, normalize(password))
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)


# Hash used when the login does not exist - verification takes just as long,
# so the response time does not reveal whether the account exists.
DUMMY_HASH = hash_password("dummy-password-for-timing-equalization")
