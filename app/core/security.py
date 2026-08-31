from pwdlib import PasswordHash


# Password hashing configuration
password_hash = PasswordHash.recommended()


# Hash a plain-text password
def hash_password(password: str) -> str:
    return password_hash.hash(password)


# Verify a password against its hash
def verify_password(
    password: str,
    hashed_password: str,
) -> bool:
    return password_hash.verify(password, hashed_password)


from datetime import datetime, timedelta, timezone

import jwt
from pwdlib import PasswordHash

from app.core.config import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    ALGORITHM,
    SECRET_KEY,
)


# Password hashing
password_hash = PasswordHash.recommended()


def hash_password(password: str) -> str:
    return password_hash.hash(password)


def verify_password(
    password: str,
    hashed_password: str,
) -> bool:
    return password_hash.verify(
        password,
        hashed_password,
    )


# Create JWT access token
def create_access_token(user_id: str) -> str:

    expire = datetime.now(timezone.utc) + timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES
    )

    payload = {
        "sub": user_id,
        "exp": expire,
    }

    token = jwt.encode(
        payload,
        SECRET_KEY,
        algorithm=ALGORITHM,
    )

    return token
